//! IKEv1 Informational exchange (RFC 2408 §4.8 / RFC 2409 §5.7) — two things
//! built on the same encrypted-Informational framing:
//!
//! **Graceful-disconnect Delete**: [`build_delete`] builds a message telling
//! the gateway this side is tearing down its ISAKMP SA (and, implicitly,
//! every Quick Mode SA under it) instead of just vanishing and leaving the
//! gateway to notice via DPD/lifetime expiry; [`peek`] checks for the same
//! notification arriving unprompted from the gateway (e.g. an admin
//! disconnecting the dialup session from the FortiGate side) so this side can
//! tear down immediately too. Fire-and-forget: RFC 2408 defines no
//! acknowledgement for a Delete notification in either direction.
//!
//! ```text
//! I → HDR*, HASH(1), D(ESP, our inbound SPI)      -- own message/M-ID
//! I → HDR*, HASH(1), D(ISAKMP, cky_i | cky_r)     -- own message/M-ID
//! ```
//!
//! Two separate Informational messages, not one carrying both Delete
//! payloads chained together — confirmed against strongSwan's own IKEv1 task
//! manager (`task_manager_v1.c::initiate`, `IKE_ESTABLISHED` case): it
//! activates `TASK_QUICK_DELETE` and `TASK_ISAKMP_DELETE` as two separate
//! `INFORMATIONAL_V1` exchanges (each its own `break` arm, each getting its
//! own fresh message-id via `new_mid = TRUE`), never combining them into one
//! message. Confirmed live against a real FortiGate that combining them the
//! way this module originally did was silently only half-effective: the
//! CHILD SA/data plane went away, but the dialup *session itself* (the
//! ISAKMP SA) stayed listed as connected — consistent with a peer that reads
//! at most one Delete purpose out of an Informational message and ignores
//! any chained payload after it, rather than a peer bug in an unusual
//! encoding. Splitting into two exchanges matches the proven-interoperable
//! shape instead of a technically-RFC-legal but untested one.
//!
//! **Dead Peer Detection** (RFC 3706): [`probe`] sends an R-U-THERE Notify
//! carrying a sequence number and waits for a peer's R-U-THERE-ACK echoing
//! the same sequence number — the active liveness check IKEv1 otherwise
//! lacks entirely (unlike IKEv2's `crate::ikev2::session::LivenessSession::probe`).
//! Unlike Delete, R-U-THERE/-ACK *are* a real request/response pair, but per
//! RFC 3706 (confirmed against isakmpd's `dpd.c`: `message_send_dpd_notify`
//! always opens a brand-new Phase-2 exchange, for both the request and the
//! reply) correlation is via the 4-byte sequence number carried in the Notify
//! payload's data, not via a shared message-id — each of [`build_r_u_there`]/
//! [`build_r_u_there_ack`] gets its own fresh random message-id, same as
//! every `build_delete` message. [`peek`] and [`probe`] both watch for and
//! auto-answer an incoming R-U-THERE from the peer (RFC 3706 requires
//! answering one whenever seen, regardless of which side happens to notice
//! it first) — see [`watch`]'s doc for the shared three-way classification.
//! DPD is only ever attempted once the peer has advertised support via
//! [`super::phase1::DPD_VENDOR_ID`] (recorded as
//! [`Phase1State::peer_supports_dpd`]) — gating that on the caller side
//! (typically once per connection, before deciding whether to ever call
//! [`probe`]), not inside this module.
//!
//! `HASH(1) = prf(SKEYID_a, M-ID | payload)` (RFC 2409 §5.7) — the same
//! "HASH covers M-ID | payloads-after-hash" shape
//! [`super::phase2::build_encrypted`] already implements for
//! Mode-Config/Xauth, reused as-is here for every Informational message this
//! module builds, Delete or Notify alike.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::crypto1;
use super::exchange::{self as table, Attribution, Classified};
use super::isakmp::{exchange, payload, IsakmpHeader};
use super::msgid::MidKind;
use super::payloads::{protocol, IPSEC_DOI};
use super::phase1::Phase1State;
use super::phase2;
use crate::debug::ike_debug;
use crate::entropy::Entropy;
use crate::error::IkeError;
use crate::ikev2::natt::{unwrap_ike_4500, wrap_ike_4500};
use crate::transport::{DriverError, IkeSocket};

/// RFC 2408 §3.15 Delete payload body: `DOI(4) | Protocol-Id(1) | SPI-Size(1)
/// | #SPIs(2, always 1 here) | SPI`.
fn delete_body(protocol_id: u8, spi: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + spi.len());
    out.extend_from_slice(&IPSEC_DOI.to_be_bytes());
    out.push(protocol_id);
    out.push(spi.len() as u8);
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(spi);
    out
}

fn info_header(cky_i: [u8; 8], cky_r: [u8; 8], msgid: u32) -> IsakmpHeader {
    IsakmpHeader {
        init_cookie: cky_i,
        resp_cookie: cky_r,
        next_payload: payload::NONE,
        version: IsakmpHeader::VERSION_1_0,
        exchange_type: exchange::INFORMATIONAL,
        flags: 0,
        message_id: msgid,
        length: 0,
    }
}

/// RFC 2408 §3.14 Notification Payload body: `DOI(4) | Protocol-Id(1) |
/// SPI-Size(1) | Notify-Msg-Type(2) | SPI | Notification-Data`.
pub(super) fn notify_body(protocol_id: u8, spi: &[u8], msg_type: u16, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + spi.len() + data.len());
    out.extend_from_slice(&IPSEC_DOI.to_be_bytes());
    out.push(protocol_id);
    out.push(spi.len() as u8);
    out.extend_from_slice(&msg_type.to_be_bytes());
    out.extend_from_slice(spi);
    out.extend_from_slice(data);
    out
}

/// The inverse of [`notify_body`]: pull `(msg_type, notification_data)` back
/// out of a parsed Notify payload's body. `None` on anything too short to be
/// well-formed.
pub(crate) fn parse_notify(body: &[u8]) -> Option<(u16, &[u8])> {
    let spi_size = *body.get(5)? as usize;
    let msg_type = u16::from_be_bytes([*body.get(6)?, *body.get(7)?]);
    let data = body.get(8 + spi_size..)?;
    Some((msg_type, data))
}

/// The inverse of [`delete_body`]: pull `(protocol_id, spi)` back out of a
/// parsed Delete payload's body. `None` on anything too short to be
/// well-formed.
pub(crate) fn parse_delete(body: &[u8]) -> Option<(u8, &[u8])> {
    let protocol_id = *body.get(4)?;
    let spi_size = *body.get(5)? as usize;
    let spi = body.get(8..8 + spi_size)?;
    Some((protocol_id, spi))
}

/// RFC 3706 §5.2 Notify Message Types.
pub(crate) mod notify_type {
    pub const R_U_THERE: u16 = 36136;
    pub const R_U_THERE_ACK: u16 = 36137;
}

/// Build one encrypted Informational message carrying a single payload, with
/// its own fresh random message-id (RFC 2409 Appendix B: the IV for a new
/// message-id is `HASH(phase1_iv | M-ID)`, computed via
/// [`crypto1::phase2_iv`]) and its own `HASH(1)` covering just that payload.
/// Shared by [`build_delete`], [`build_r_u_there`] and
/// [`build_r_u_there_ack`] — every Informational message this module ever
/// sends is exactly one of these, fire-and-forget with a brand-new message-id
/// each time (RFC 3706's ACK included — see this module's doc for why that
/// one *looks* like a reply but isn't correlated via message-id).
fn build_single_informational(st: &Phase1State, entropy: &mut impl Entropy, payload_type: u8, body: Vec<u8>) -> Result<Vec<u8>, IkeError> {
    let msgid = st.fresh_message_id(MidKind::Informational, entropy)?;
    build_informational_under(st, msgid, payload_type, body)
}

/// [`build_single_informational`] under the Message ID `msgid` the caller drew.
fn build_informational_under(st: &Phase1State, msgid: u32, payload_type: u8, body: Vec<u8>) -> Result<Vec<u8>, IkeError> {
    let iv0 = crypto1::phase2_iv(st.prf, &st.phase1_iv, msgid, st.enc_block);
    let hdr = info_header(st.cky_i, st.cky_r, msgid);
    let (msg, _next) = phase2::build_encrypted(hdr, st.prf, &st.skeyid_a, &st.enc_key, st.enc_block, &iv0, &[(payload_type, body)])?;
    Ok(msg)
}

/// This ISAKMP SA's cookie pair, in the `SPI` shape RFC 2408 §3.15 uses to
/// identify the whole Phase-1 SA in a Delete payload and RFC 3706 §5.3 gives
/// a DPD Notify (SPI Size 16, one SPI = `cky_i | cky_r`).
fn isakmp_spi(st: &Phase1State) -> Vec<u8> {
    [st.cky_i.as_slice(), st.cky_r.as_slice()].concat()
}

/// Build an RFC 3706 R-U-THERE Notify carrying `seq` — the active half of a
/// DPD probe. Only meaningful to send once [`Phase1State::peer_supports_dpd`]
/// is `true`; see this module's doc.
pub fn build_r_u_there(st: &Phase1State, entropy: &mut impl Entropy, seq: u32) -> Result<Vec<u8>, IkeError> {
    let body = notify_body(protocol::ISAKMP, &isakmp_spi(st), notify_type::R_U_THERE, &seq.to_be_bytes());
    build_single_informational(st, entropy, payload::NOTIFY, body)
}

/// Build an RFC 3706 R-U-THERE-ACK Notify echoing `seq` — the reply owed to
/// an incoming [`build_r_u_there`] from the peer.
pub fn build_r_u_there_ack(st: &Phase1State, entropy: &mut impl Entropy, seq: u32) -> Result<Vec<u8>, IkeError> {
    let body = notify_body(protocol::ISAKMP, &isakmp_spi(st), notify_type::R_U_THERE_ACK, &seq.to_be_bytes());
    build_single_informational(st, entropy, payload::NOTIFY, body)
}

/// Build the pair of graceful-disconnect Informational messages a caller
/// should send, in order: first the negotiated ESP CHILD SA (`esp_spi` — our
/// own inbound SPI, the value [`crate::esp::ChildSa::inbound`]'s
/// [`crate::esp::EspSa::spi`] holds; per-vendor convention each side reports
/// the SPI *it* generated, since that's the value the peer uses when sending
/// ESP to us), then the whole ISAKMP (Phase 1) SA, identified by the cookie
/// pair (RFC 2408 §3.15 — SPI Size 16, one SPI = `cky_i | cky_r`) — same
/// order and same two-separate-exchanges shape strongSwan's IKEv1 task
/// manager uses (see this module's doc comment). The ESP delete is
/// technically redundant on its own (deleting the ISAKMP SA is taken to tear
/// down every Phase-2 SA under it -- RFC 7296 §1.4.1 says so for an IKE SA,
/// while RFC 2408 §3.15 and §5.15 speak only of the SAs a Delete lists, so for
/// IKEv1 it is practice, not RFC text) but sent anyway, matching
/// real-world implementations, for compatibility with gateways that key
/// teardown logging/policy off the explicit ESP delete directly.
pub fn build_delete(st: &Phase1State, entropy: &mut impl Entropy, esp_spi: u32) -> Result<(Vec<u8>, Vec<u8>), IkeError> {
    let esp_msg = build_esp_delete(st, entropy, esp_spi)?;
    let isakmp_msg = build_isakmp_delete(st, entropy)?;
    Ok((esp_msg, isakmp_msg))
}

/// Just the ESP half of [`build_delete`] -- for tearing down one CHILD SA
/// among several under the same Phase 1 (`esp_spi`: our own inbound SPI, same
/// convention as [`build_delete`]). A tunnel with a second, IPv6 CHILD SA
/// sends this for it ahead of the ISAKMP delete.
pub fn build_esp_delete(st: &Phase1State, entropy: &mut impl Entropy, esp_spi: u32) -> Result<Vec<u8>, IkeError> {
    build_single_informational(st, entropy, payload::DELETE, delete_body(protocol::ESP, &esp_spi.to_be_bytes()))
}

/// Just the ISAKMP-SA half of [`build_delete`] — for a caller with no CHILD
/// SA to name because Phase 1 itself never got that far (see
/// [`super::phase1::AuthFailure`]: an initiator that rejects the responder's
/// Main-Mode AUTH still holds a real SKEYID_a/SKEYID_e, derived from the DH
/// exchange alone before either side's identity was checked, so it can still
/// send this gateway a properly authenticated-and-encrypted teardown instead
/// of silently vanishing and leaving the gateway's own DPD timer to notice).
pub fn build_isakmp_delete(st: &Phase1State, entropy: &mut impl Entropy) -> Result<Vec<u8>, IkeError> {
    build_single_informational(st, entropy, payload::DELETE, delete_body(protocol::ISAKMP, &isakmp_spi(st)))
}

/// Send `msg` to `peer` exactly as given, prefixed with the non-ESP marker
/// when `st` floated to UDP 4500 (RFC 3947 §4, RFC 3948 §2.2): a datagram on 4500
/// without it reads as ESP to the gateway, which drops it -- so an unmarked
/// R-U-THERE or ACK never arrived and the gateway's DPD tore the tunnel down.
/// `peer` is the caller's already-correct destination (the 4500 address once
/// floated), so only the framing is decided here.
fn send_ike(sock: &dyn IkeSocket, st: &Phase1State, peer: SocketAddr, msg: &[u8]) -> std::io::Result<()> {
    if st.floated {
        let wire = wrap_ike_4500(msg);
        crate::debug::dump(">>>", peer, &wire);
        sock.send_to(&wire, peer)?;
    } else {
        crate::debug::dump(">>>", peer, msg);
        sock.send_to(msg, peer)?;
    }
    Ok(())
}

/// Which of the tunnel's Quick Mode (Phase 2) SAs an ESP Delete named --
/// IKEv1 has no `IKE_AUTH`-time "unified" CHILD SA the way IKEv2 can: a
/// dual-stack tunnel is the primary (IPv4) Quick Mode SA plus, if the
/// gateway assigned an IPv6 address, a second independent IPv6 Quick Mode SA
/// negotiated separately (`ryke::ikev1::quick::create_child_ipv6`), both
/// under the same Phase 1. Mirrors [`crate::ikev2::session::ChildKind`]'s
/// shape, kept as its own type since this module doesn't otherwise depend on
/// ikev2's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildFamily {
    Primary,
    Ipv6,
}

/// Result of [`peek`]/[`probe`] — mirrors
/// [`crate::ikev2::session::Liveness`]'s shape, kept as its own local type
/// rather than shared across the ikev1/ikev2 modules (they don't otherwise
/// depend on each other).
#[derive(Debug, PartialEq, Eq)]
pub enum Liveness {
    /// [`probe`]: the peer answered with a matching R-U-THERE-ACK. [`peek`]:
    /// nothing pending — IKEv1 defines no periodic liveness ping of its own,
    /// so silence here is the ordinary, expected result on every passive
    /// check, same as [`crate::ikev2::session::LivenessSession::peek`]'s own
    /// "silence is alive" stance when it sent nothing itself.
    Alive,
    /// The peer sent an unsolicited Informational carrying a Delete payload
    /// that actually tears this tunnel down — either a Delete for the whole
    /// ISAKMP SA (e.g. an admin disconnected the dialup session on the
    /// gateway), or an ESP Delete naming the primary CHILD SA's SPI while
    /// there is no separate IPv6 Quick Mode SA to fall back on (so there is
    /// nothing left to keep the tunnel usable). A Delete for some other ESP
    /// SPI — most commonly the just-superseded SPI from a CHILD SA rekey the
    /// peer initiated — does not tear anything down and is silently ignored;
    /// see [`watch`]'s doc.
    PeerTornDown,
    /// The peer deleted just one Quick Mode SA outright (no rekey, no
    /// replacement offered) while the ISAKMP SA -- and, for
    /// [`ChildFamily::Primary`], the separate IPv6 Quick Mode SA -- stayed
    /// up. This code reads Phase 2 SAs as independent of Phase 1 and of each
    /// other (an inference, not RFC text: RFC 2408 §3.15 and §5.15 have a Delete
    /// cover only the SAs it lists, and no sentence links the end of a Phase 2
    /// SA to the ISAKMP SA's; only a Delete naming Protocol-ID ISAKMP is taken
    /// to take down the parent and everything under it, never the reverse), so
    /// this does not tear down the tunnel: the caller drops its own local state
    /// for that family and renegotiates a replacement from scratch. Only
    /// possible when the caller passed a `current_peer_spi_ipv6` to
    /// [`peek`]/[`probe`] (i.e.
    /// the tunnel actually has a separate IPv6 Quick Mode SA) -- a
    /// single-stack tunnel's primary Delete is [`Liveness::PeerTornDown`],
    /// unchanged.
    ChildDeleted(ChildFamily),
    /// [`probe`] only: no R-U-THERE-ACK arrived within the timeout. Could be
    /// transient packet loss rather than a dead peer — callers should
    /// require a few consecutive misses before concluding the tunnel is
    /// actually down, same as any DPD implementation.
    NoReply,
}

/// Outcome [`watch`] classifies an incoming datagram into.
#[derive(Debug, PartialEq, Eq)]
enum Seen {
    /// Nothing decisive arrived before the deadline (possibly after
    /// auto-acking one or more incoming R-U-THERE probes along the way).
    Nothing,
    PeerTornDown,
    /// See [`Liveness::ChildDeleted`].
    ChildDeleted(ChildFamily),
    /// An R-U-THERE-ACK matching the sequence number `watch` was told to
    /// expect (only possible when called from [`probe`]).
    AckMatched,
}

/// What an authenticated ESP Delete from the peer naming `spi` means for the
/// CHILD SAs in use, and the trace line that says so. The peer names its own
/// inbound SPI (the convention `build_delete` follows for ours), which is the
/// SPI we send ESP to: `current_peer_spi` and
/// `current_peer_spi_ipv6` are those, so the line calls them `spi_out`, as the
/// "complete" lines of Quick Mode do, never `spi_in` (our own inbound SPI).
fn peer_esp_delete(spi: &[u8], current_peer_spi: u32, current_peer_spi_ipv6: Option<u32>) -> (Option<Seen>, String) {
    let named = <[u8; 4]>::try_from(spi).ok().map(u32::from_be_bytes);
    if named == Some(current_peer_spi) {
        if current_peer_spi_ipv6.is_some() {
            let note = format!("INFORMATIONAL: peer deleted the primary CHILD SA (spi_out={current_peer_spi:08x}) while the IPv6 one is still up -- renegotiating it instead of tearing down");
            (Some(Seen::ChildDeleted(ChildFamily::Primary)), note)
        } else {
            let note = format!("INFORMATIONAL: peer sent an ESP Delete for the CHILD SA in use (spi_out={current_peer_spi:08x}) -- tunnel torn down by the gateway");
            (Some(Seen::PeerTornDown), note)
        }
    } else if let Some(v6) = current_peer_spi_ipv6.filter(|v6| named == Some(*v6)) {
        let note = format!("INFORMATIONAL: peer deleted the IPv6 CHILD SA (spi_out={v6:08x}) while the primary is still up -- renegotiating it instead of tearing down");
        (Some(Seen::ChildDeleted(ChildFamily::Ipv6)), note)
    } else {
        let note = format!(
            "INFORMATIONAL: ignoring peer ESP Delete for spi={} (the CHILD SA(s) in use are spi_out={current_peer_spi:08x}{})",
            named.map_or_else(|| "<malformed>".to_string(), |v| format!("{v:08x}")),
            current_peer_spi_ipv6.map_or_else(String::new, |v| format!("/{v:08x}"))
        );
        (None, note)
    }
}

/// Bounded (by `timeout`) watch of `sock` for encrypted Informational
/// traffic tied to `st`'s ISAKMP SA (cookie pair) — shared by [`peek`]
/// (`expect_ack_seq: None`) and [`probe`] (`Some(seq)` for the sequence
/// number it just sent), mirroring
/// [`crate::ikev2::session::LivenessSession::recv_and_classify`]'s shape.
/// Classification: a Delete for the whole ISAKMP SA ends the wait
/// immediately as [`Seen::PeerTornDown`], always. An ESP Delete naming
/// `current_peer_spi` (the primary CHILD SA currently in use) ends the wait
/// as [`Seen::PeerTornDown`] when `current_peer_spi_ipv6` is `None` (a
/// single-stack tunnel has nothing left to fall back on), or as
/// [`Seen::ChildDeleted(ChildFamily::Primary)`](Seen::ChildDeleted) when the
/// tunnel also has a separate IPv6 Quick Mode SA still up. An ESP Delete
/// naming `current_peer_spi_ipv6` (when `Some`) ends the wait as
/// [`Seen::ChildDeleted(ChildFamily::Ipv6)`](Seen::ChildDeleted). An ESP
/// Delete naming any other SPI (most commonly one just superseded by a
/// CHILD SA rekey the peer initiated) does *not* tear anything down and the
/// wait continues, same as an unrelated message; an incoming R-U-THERE from
/// the peer is always auto-ack'd via [`build_r_u_there_ack`] (RFC 3706
/// requires answering one whenever seen, regardless of whether this call is
/// a passive `peek` or an active `probe`) and the wait continues; an
/// R-U-THERE-ACK matching `expect_ack_seq` ends the wait as
/// [`Seen::AckMatched`]; a peer message that one of our final messages
/// answered, repeated bit for bit (the gateway re-sending its Quick Mode
/// message 2 because our message 3 never arrived), gets that final message
/// sent again ([`super::quick::resend_final_if_repeat`]) and the wait
/// continues; anything else (garbage, a message for a different
/// exchange/SA, a decrypt/HASH failure, a stale/mismatched ack, a failed
/// auto-ack send) is silently skipped rather than surfaced as an error, same
/// best-effort stance this module has always taken for Delete detection. A
/// UDP datagram the peer already sent sits in the kernel's receive buffer
/// regardless of how long ago it arrived, so even a short `timeout`
/// reliably catches anything already pending.
///
/// All of the above is what a **passive** exchange table gets, which every
/// state starts with: once the table is on
/// ([`Phase1State::enable_gateway_quick_mode`]) the wait is
/// [`watch_enabled`]'s instead, and the SPIs given here are not looked at.
fn watch(
    sock: &dyn IkeSocket,
    st: &Phase1State,
    entropy: &mut impl Entropy,
    peer: SocketAddr,
    timeout: Duration,
    expect_ack_seq: Option<u32>,
    current_peer_spi: u32,
    current_peer_spi_ipv6: Option<u32>,
) -> std::io::Result<Seen> {
    if st.exchanges.is_enabled() {
        return watch_enabled(sock, st, entropy, peer, timeout, expect_ack_seq);
    }
    // A `timeout` too long for the clock to count is not one the clock can end.
    let deadline = Instant::now().checked_add(timeout);
    let mut buf = [0u8; 8192];
    loop {
        let remaining = deadline.map_or(timeout, |deadline| deadline.saturating_duration_since(Instant::now()));
        if remaining.is_zero() {
            return Ok(Seen::Nothing);
        }
        sock.set_read_timeout(Some(remaining))?;
        let (n, from) = match sock.recv_from(&mut buf) {
            Ok(r) => r,
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
                return Ok(Seen::Nothing);
            }
            Err(e) => return Err(e),
        };
        crate::debug::dump("<<<", from, &buf[..n]);
        // On a floated tunnel (UDP 4500) IKE is the marked datagrams; an
        // unmarked one is ESP or a NAT keepalive, never ours to parse.
        let datagram: &[u8] = if st.floated {
            match unwrap_ike_4500(&buf[..n]) {
                Some(ike) => ike,
                None => continue,
            }
        } else {
            &buf[..n]
        };
        let Ok(header) = IsakmpHeader::parse(datagram) else { continue };
        if header.init_cookie != st.cky_i || header.resp_cookie != st.cky_r {
            continue; // not for this ISAKMP SA -- ignore, keep waiting out the timeout
        }
        if header.exchange_type != exchange::INFORMATIONAL {
            // A repeat of the message a final message of ours answered (the
            // gateway never got our Quick Mode message 3): send that again.
            super::quick::resend_final_if_repeat(sock, st, peer, datagram);
            continue;
        }
        let iv0 = crypto1::phase2_iv(st.prf, &st.phase1_iv, header.message_id, st.enc_block);
        let Ok((_h, payloads, _next)) = phase2::parse_encrypted(datagram, st.prf, &st.skeyid_a, &st.enc_key, st.enc_block, &iv0) else {
            continue;
        };
        if let Some(del) = payloads.iter().find(|p| p.payload_type == payload::DELETE) {
            let outcome = match parse_delete(&del.data) {
                Some((proto, _spi)) if proto == protocol::ISAKMP => {
                    ike_debug!("INFORMATIONAL: peer sent an ISAKMP SA Delete -- tunnel torn down by the gateway");
                    Some(Seen::PeerTornDown)
                }
                Some((proto, spi)) if proto == protocol::ESP => {
                    let (seen, note) = peer_esp_delete(spi, current_peer_spi, current_peer_spi_ipv6);
                    ike_debug!("{note}");
                    seen
                }
                _ => None,
            };
            if let Some(seen) = outcome {
                return Ok(seen);
            }
            continue;
        }
        let Some(notify) = payloads.iter().find(|p| p.payload_type == payload::NOTIFY) else { continue };
        let Some((msg_type, data)) = parse_notify(&notify.data) else { continue };
        match msg_type {
            notify_type::R_U_THERE => {
                if let Ok(seq_bytes) = <[u8; 4]>::try_from(data) {
                    let seq = u32::from_be_bytes(seq_bytes);
                    ike_debug!("DPD: peer sent R-U-THERE seq={seq} -- answering with R-U-THERE-ACK");
                    match build_r_u_there_ack(st, entropy, seq) {
                        Ok(ack) => {
                            if let Err(e) = send_ike(sock, st, peer, &ack) {
                                ike_debug!("DPD: failed to send R-U-THERE-ACK seq={seq}: {e}");
                            }
                        }
                        Err(e) => ike_debug!("DPD: failed to build R-U-THERE-ACK seq={seq}: {e}"),
                    }
                }
            }
            notify_type::R_U_THERE_ACK => {
                if let Ok(seq_bytes) = <[u8; 4]>::try_from(data) {
                    let seq = u32::from_be_bytes(seq_bytes);
                    if expect_ack_seq == Some(seq) {
                        ike_debug!("DPD: R-U-THERE-ACK seq={seq} received -- peer is alive");
                        return Ok(Seen::AckMatched);
                    }
                    ike_debug!("DPD: ignoring R-U-THERE-ACK seq={seq} (expecting {expect_ack_seq:?})");
                }
            }
            _ => {}
        }
    }
}

/// Whether `datagram` (already stripped of the UDP-4500 non-ESP marker, if
/// any) is an encrypted Informational for `st`'s ISAKMP SA carrying a Delete
/// naming Protocol-Id ISAKMP -- i.e. the peer tearing down the whole tunnel,
/// not just one Quick Mode SA. Factored out of [`watch`]'s per-datagram
/// classification so [`super::quick::quick_exchange`] can run the same check
/// on a datagram that doesn't match the Quick Mode response it's waiting for,
/// instead of silently discarding it the way a message for some other
/// exchange normally would be: an ISAKMP SA Delete arriving mid-exchange
/// still means the tunnel is gone, and losing that notification here left
/// [`super::quick::rekey_child`] retrying a from-scratch recreate forever
/// against a peer that no longer has any Phase 1 SA to answer under
/// (confirmed live against a real FortiGate -- see [`crate::error::IkeError::PeerTornDown`]'s doc).
/// Anything else (a different SA, a message that doesn't decrypt or fails
/// HASH(1), a Notify, an ESP Delete) is `false`, same best-effort stance
/// [`watch`] takes. Only the wait of a passive exchange table asks it: with
/// the table on, [`table::classify`] reads every Delete payload of the
/// message, and any of them of Protocol-Id ISAKMP, whatever SPI it names,
/// ends the wait.
pub(crate) fn is_isakmp_sa_delete(st: &Phase1State, datagram: &[u8]) -> bool {
    let Ok(header) = IsakmpHeader::parse(datagram) else { return false };
    if header.exchange_type != exchange::INFORMATIONAL || header.init_cookie != st.cky_i || header.resp_cookie != st.cky_r {
        return false;
    }
    let iv0 = crypto1::phase2_iv(st.prf, &st.phase1_iv, header.message_id, st.enc_block);
    let Ok((_h, payloads, _next)) = phase2::parse_encrypted(datagram, st.prf, &st.skeyid_a, &st.enc_key, st.enc_block, &iv0) else {
        return false;
    };
    let Some(del) = payloads.iter().find(|p| p.payload_type == payload::DELETE) else { return false };
    matches!(parse_delete(&del.data), Some((proto, _spi)) if proto == protocol::ISAKMP)
}

/// If `msg` is an encrypted Informational for `st`'s ISAKMP SA carrying an
/// **error** Notify (RFC 2408 §3.14.1: types 1..=16383), its type and name.
/// A responder that rejects a Quick Mode proposal it cannot accept answers with
/// one of these instead of a Quick Mode message 2 (e.g. NO-PROPOSAL-CHOSEN, or
/// INVALID-ID-INFORMATION for a traffic selector it has no policy for), so a
/// caller waiting on message 2 can fail at once with the real reason instead
/// of running out its timeout. Anything else -- a different SA, a message that
/// doesn't decrypt or fails HASH(1), a status Notify, a Delete -- is `None`.
/// Only the wait of a passive exchange table asks it, and takes any error
/// Notify for the verdict on its own exchange: with the table on, the wait
/// takes only one that is about it ([`table::ExchangeTable::attribute_error_notify`]).
pub(crate) fn peer_error_notify(st: &Phase1State, msg: &[u8]) -> Option<(u16, &'static str)> {
    let header = IsakmpHeader::parse(msg).ok()?;
    if header.exchange_type != exchange::INFORMATIONAL || header.init_cookie != st.cky_i || header.resp_cookie != st.cky_r {
        return None;
    }
    let iv0 = crypto1::phase2_iv(st.prf, &st.phase1_iv, header.message_id, st.enc_block);
    let (_h, payloads, _next) = phase2::parse_encrypted(msg, st.prf, &st.skeyid_a, &st.enc_key, st.enc_block, &iv0).ok()?;
    let notify = payloads.iter().find(|p| p.payload_type == payload::NOTIFY)?;
    let (msg_type, _data) = parse_notify(&notify.data)?;
    (1..16384).contains(&msg_type).then(|| (msg_type, error_notify_name(msg_type)))
}

/// The error Notify types this side sends to refuse a message of the peer's (RFC 2408 §3.14.1 numbers them):
/// these five, and no other. They are ISAKMP's own; the codes IKEv2 added for refusing a CHILD SA
/// (NO_ADDITIONAL_SAS 35 and TEMPORARY_FAILURE 43, RFC 7296) are not ISAKMP Notify types and are never sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefusalNotify {
    /// INVALID-FLAGS (8): a copy of a message whose header has the Commit bit set, which this side does not
    /// support. RFC 2408 §5.2 step 5: a message whose Flags field fails validation is discarded and an
    /// INVALID-FLAGS Notify "MAY be sent"; the Commit bit is a defined value, so taking it for a failed
    /// validation is this side's reading (POLICY).
    InvalidFlags,
    /// NO-PROPOSAL-CHOSEN (14): an offer that names no SA this side accepts (RFC 2408 §5.4).
    NoProposalChosen,
    /// BAD-PROPOSAL-SYNTAX (15): an SA payload whose proposals or transforms are not formed as RFC 2408
    /// §3.5, §3.6 and §4.2 say (§5.5 step 3, §5.6 step 2).
    BadProposalSyntax,
    /// PAYLOAD-MALFORMED (16): a message whose payloads are not those RFC 2409 §5.5 gives a Quick Mode message,
    /// or one whose content cannot be used as it stands.
    PayloadMalformed,
    /// INVALID-ID-INFORMATION (18): client identities this side does not accept (RFC 2409 §5.5: one "SHOULD"
    /// be sent then; RFC 2408 §5.8).
    InvalidIdInformation,
}

impl RefusalNotify {
    /// Its Notify Message Type (RFC 2408 §3.14.1).
    pub fn notify_type(self) -> u16 {
        match self {
            RefusalNotify::InvalidFlags => 8,
            RefusalNotify::NoProposalChosen => 14,
            RefusalNotify::BadProposalSyntax => 15,
            RefusalNotify::PayloadMalformed => 16,
            RefusalNotify::InvalidIdInformation => 18,
        }
    }
}

/// What a refusal names besides its type: the Protocol-Id and SPI of its Notify payload (RFC 2408 §3.14,
/// "The receiving entity's SPI"). DOI 1, the IPsec DOI, either way, as for every Notify this module builds (RFC
/// 3706 §5.3 has its ISAKMP Notifies carry it too: "SHOULD be set to IPSEC-DOI").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RefusalSubject {
    /// The message as such, not an SA it proposes (a header-level refusal): Protocol-Id ISAKMP, SPI size 0 (RFC
    /// 2408 §3.14: for ISAKMP the SPI size "MAY be from zero (0) to sixteen (16)" and its content is ignored).
    Message,
    /// The ESP SA a proposal of the peer's would have made: Protocol-Id ESP, SPI size 4, and `spi`, the SPI the
    /// peer proposed for its own inbound side -- the SPI of the entity receiving the Notify.
    Proposal { spi: u32 },
}

/// An authenticated Informational (`HDR*, HASH(1), N`, RFC 2409 §5.7) that refuses the peer's exchange
/// `refused_msgid` with an error Notify of `notify` about `subject` (no Notification Data), and the Message
/// ID it goes under: a fresh one of ours, recorded as such by an enabled exchange table, and never
/// `refused_msgid`, whether or not the ledger holds that one -- RFC 2409 §5.7 has the Informational's Message ID
/// "MUST NOT be the same as the message ID of another phase 2 exchange which generated this informational
/// exchange".
pub(crate) fn build_error_notify(
    st: &Phase1State,
    entropy: &mut impl Entropy,
    notify: RefusalNotify,
    subject: RefusalSubject,
    refused_msgid: u32,
) -> Result<(u32, Vec<u8>), IkeError> {
    let msgid = st.exchanges.fresh_message_id_other_than(MidKind::Informational, entropy, refused_msgid)?;
    let body = match subject {
        RefusalSubject::Message => notify_body(protocol::ISAKMP, &[], notify.notify_type(), &[]),
        RefusalSubject::Proposal { spi } => notify_body(protocol::ESP, &spi.to_be_bytes(), notify.notify_type(), &[]),
    };
    Ok((msgid, build_informational_under(st, msgid, payload::NOTIFY, body)?))
}

/// RFC 2408 §3.14.1 names for the error Notify types a Quick Mode rejection
/// realistically carries; everything else reads as a generic error.
pub(crate) fn error_notify_name(t: u16) -> &'static str {
    match t {
        14 => "NO_PROPOSAL_CHOSEN",
        15 => "BAD_PROPOSAL_SYNTAX",
        16 => "PAYLOAD_MALFORMED",
        17 => "INVALID_KEY_INFORMATION",
        18 => "INVALID_ID_INFORMATION",
        23 => "INVALID_HASH_INFORMATION",
        24 => "AUTHENTICATION_FAILED",
        _ => "error notification",
    }
}

/// Passive check: has the peer said anything unprompted (a Delete, or its
/// own R-U-THERE probe, which gets auto-ack'd) since the last check? Safe to
/// call on every routine status poll instead of [`probe`]'s full round trip
/// — see [`watch`]'s doc for the shared classification and
/// [`Liveness::Alive`]'s doc for why silence here means alive, not unknown.
/// `current_peer_spi` is the primary CHILD SA's currently-in-use inbound
/// SPI; `current_peer_spi_ipv6` is the same for the separate IPv6 Quick Mode
/// SA, when the tunnel has one (`None` for a single-stack tunnel) — an ESP
/// Delete naming any other SPI (e.g. one just superseded by a rekey) is
/// ignored rather than misread as a full teardown, and one naming a family
/// on its own is [`Liveness::ChildDeleted`] rather than
/// [`Liveness::PeerTornDown`] whenever the other family (or, for the
/// primary, none at all) is still up.
///
/// With the exchange table on ([`Phase1State::enable_gateway_quick_mode`]) no
/// Delete is a verdict here: what the peer's Informationals name is kept as
/// raw events for the caller to read against the SPIs it holds
/// ([`Phase1State::drain_peer_events`]), the SPIs given here are not looked
/// at, and the answer is [`Liveness::Alive`].
pub fn peek(
    sock: &dyn IkeSocket,
    st: &Phase1State,
    entropy: &mut impl Entropy,
    peer: SocketAddr,
    timeout: Duration,
    current_peer_spi: u32,
    current_peer_spi_ipv6: Option<u32>,
) -> Result<Liveness, DriverError> {
    match watch(sock, st, entropy, peer, timeout, None, current_peer_spi, current_peer_spi_ipv6)? {
        Seen::Nothing | Seen::AckMatched => Ok(Liveness::Alive),
        Seen::PeerTornDown => Ok(Liveness::PeerTornDown),
        Seen::ChildDeleted(fam) => Ok(Liveness::ChildDeleted(fam)),
    }
}

/// Active DPD check (RFC 3706): send an R-U-THERE carrying `seq` and wait up
/// to `timeout` for the matching R-U-THERE-ACK. Only ever call this once
/// [`Phase1State::peer_supports_dpd`] is `true` — RFC 3706 requires the peer
/// to have advertised support first; a caller that never confirmed that
/// should keep using [`peek`] only, exactly as before this function existed.
/// `current_peer_spi`/`current_peer_spi_ipv6` are the same as [`peek`]'s.
/// With the exchange table on, the answer is [`Liveness::Alive`] (the ACK came)
/// or [`Liveness::NoReply`]: a Delete is kept for the caller as for [`peek`].
pub fn probe(
    sock: &dyn IkeSocket,
    st: &Phase1State,
    entropy: &mut impl Entropy,
    peer: SocketAddr,
    seq: u32,
    timeout: Duration,
    current_peer_spi: u32,
    current_peer_spi_ipv6: Option<u32>,
) -> Result<Liveness, DriverError> {
    let msg = build_r_u_there(st, entropy, seq)?;
    ike_debug!("DPD: sending R-U-THERE seq={seq} to {peer}");
    send_ike(sock, st, peer, &msg)?;
    match watch(sock, st, entropy, peer, timeout, Some(seq), current_peer_spi, current_peer_spi_ipv6)? {
        Seen::Nothing => {
            ike_debug!("DPD: no R-U-THERE-ACK for seq={seq} within {timeout:?}");
            Ok(Liveness::NoReply)
        }
        Seen::PeerTornDown => Ok(Liveness::PeerTornDown),
        Seen::ChildDeleted(fam) => Ok(Liveness::ChildDeleted(fam)),
        Seen::AckMatched => Ok(Liveness::Alive),
    }
}

// ---- Once the exchange table is on: one classification for every reader ----

/// What [`serve_classified`] did with one datagram.
#[derive(Default)]
pub(crate) struct Served {
    ack_matched: bool,
    acked: usize,
    new_quick: usize,
    events_pushed: usize,
    answered_again: usize,
}

/// Sends the R-U-THERE-ACK owed for the peer's R-U-THERE `seq` (RFC 3706 §6.1: "A responder to an
/// R-U-THERE message MUST send an R-U-THERE-ACK with the same sequence number"); whether it went.
fn answer_r_u_there(sock: &dyn IkeSocket, st: &Phase1State, entropy: &mut impl Entropy, peer: SocketAddr, seq: u32) -> bool {
    ike_debug!("DPD: peer sent R-U-THERE seq={seq} -- answering with R-U-THERE-ACK");
    match build_r_u_there_ack(st, entropy, seq) {
        Ok(ack) => match send_ike(sock, st, peer, &ack) {
            Ok(()) => true,
            Err(e) => {
                ike_debug!("DPD: failed to send R-U-THERE-ACK seq={seq}: {e}");
                false
            }
        },
        Err(e) => {
            ike_debug!("DPD: failed to build R-U-THERE-ACK seq={seq}: {e}");
            false
        }
    }
}

/// One datagram read by a reader of an enabled table, through [`table::classify`], and the only
/// answers sent on the way: the R-U-THERE-ACKs an Informational asked for, a final message of ours
/// again for a bit-exact repeat of what it answered, and what a gateway Quick Mode this side answered or
/// refused gets for a copy of its message 1 (its message 2, or its refusal, again). Everything else it
/// found is kept in the table or dropped there; a Quick Mode message for an exchange of ours that nobody
/// waits on here is dropped. An error Notify about a gateway Quick Mode this side answers is recorded on
/// it ([`table::ExchangeTable::attribute_error_notify`] with no exchange of ours waited on): a fact for
/// its caller, never acted on here.
fn serve_datagram(sock: &dyn IkeSocket, st: &Phase1State, entropy: &mut impl Entropy, peer: SocketAddr, datagram: &[u8], expect_ack_seq: Option<u32>) -> Served {
    let classified = table::classify(st, datagram, expect_ack_seq);
    let served = serve_classified(sock, st, entropy, peer, &classified);
    if let Classified::Informational(seen) = &classified {
        for notice in &seen.error_notifies {
            if let Attribution::Responder(msgid) = st.exchanges.attribute_error_notify(notice, seen.read_before, None) {
                if st.exchanges.note_responder_rejected(msgid, notice.msg_type) {
                    ike_debug!(
                        "INFORMATIONAL: error Notify {} ({}) is about gateway Quick Mode msgid={msgid:08x} -- recorded on it",
                        error_notify_name(notice.msg_type),
                        notice.msg_type
                    );
                }
            }
        }
    }
    served
}

/// The answers [`serve_datagram`] sends for a datagram [`table::classify`] read as `classified`, for a
/// reader that looks at what it is first: the wait of a Quick Mode of ours takes the messages under its
/// own id out before it hands the rest here.
pub(crate) fn serve_classified(sock: &dyn IkeSocket, st: &Phase1State, entropy: &mut impl Entropy, peer: SocketAddr, classified: &Classified) -> Served {
    let mut served = Served::default();
    match classified {
        Classified::ResendFinal(final_message) => super::quick::send_final_again(sock, st, peer, final_message),
        Classified::RouteToOwn { msgid, .. } => {
            ike_debug!("QUICK: a message under msgid={msgid:08x}, an exchange of ours that nothing waits on here -- dropped");
        }
        Classified::PeerQuick { .. } => served.new_quick += 1,
        Classified::AnswerAgain { msgid, message } => match super::quick::send_framed(sock, st.floated, peer, message) {
            Ok(()) => served.answered_again += 1,
            Err(e) => ike_debug!("QUICK: failed to send message 2 of gateway Quick Mode msgid={msgid:08x} again: {e}"),
        },
        Classified::RefusalAgain { msgid, message } => match send_ike(sock, st, peer, message) {
            Ok(()) => served.answered_again += 1,
            Err(e) => ike_debug!("QUICK: failed to send the refusal of gateway message 1 msgid={msgid:08x} again: {e}"),
        },
        Classified::Informational(seen) => {
            for &seq in &seen.r_u_there {
                if answer_r_u_there(sock, st, entropy, peer, seq) {
                    served.acked += 1;
                }
            }
            served.ack_matched = seen.ack_matched;
            served.events_pushed = seen.events_pushed;
        }
        Classified::CommitNoted { .. } | Classified::Message3 { .. } | Classified::Foreign | Classified::Ignored(_) => {}
    }
    served
}

/// [`watch`] once the exchange table is on: the same bounded wait, each datagram read through
/// [`table::classify`] ([`serve_datagram`]). It ends only with an R-U-THERE-ACK of `expect_ack_seq`
/// ([`Seen::AckMatched`]) or at the deadline ([`Seen::Nothing`]): a Delete or an error Notify the peer
/// sends is kept as a raw event in the table's mailbox
/// ([`Phase1State::drain_peer_events`]) for the caller to read against the SPIs it holds, and is
/// never a verdict of the wait.
fn watch_enabled(sock: &dyn IkeSocket, st: &Phase1State, entropy: &mut impl Entropy, peer: SocketAddr, timeout: Duration, expect_ack_seq: Option<u32>) -> std::io::Result<Seen> {
    // A `timeout` too long for the clock to count is not one the clock can end.
    let deadline = Instant::now().checked_add(timeout);
    let mut buf = [0u8; 8192];
    loop {
        let remaining = deadline.map_or(timeout, |deadline| deadline.saturating_duration_since(Instant::now()));
        if remaining.is_zero() {
            return Ok(Seen::Nothing);
        }
        sock.set_read_timeout(Some(remaining))?;
        let (n, from) = match sock.recv_from(&mut buf) {
            Ok(r) => r,
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
                return Ok(Seen::Nothing);
            }
            Err(e) => return Err(e),
        };
        crate::debug::dump("<<<", from, &buf[..n]);
        if serve_datagram(sock, st, entropy, peer, &buf[..n], expect_ack_seq).ack_matched {
            return Ok(Seen::AckMatched);
        }
    }
}

/// What one [`serve_turn`] did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TurnReport {
    /// Datagrams read off the socket, whatever they were.
    pub datagrams_read: usize,
    /// R-U-THERE-ACKs sent.
    pub acked_dpd: usize,
    /// Authenticated message-1 copies of gateway Quick Modes put in the inbox
    /// ([`Phase1State::take_peer_quick_modes`]).
    pub new_quick: usize,
    /// Events added to the mailbox ([`Phase1State::drain_peer_events`]).
    pub events_pushed: usize,
    /// Messages sent again for copies of a gateway message 1 this side answered or refused: its message 2, or
    /// its refusal.
    pub answered_again: usize,
}

/// One turn of attention to the IKEv1 socket between the commands of whoever owns it: the reader
/// that keeps the gateway answered while nothing else reads. It reads at most `max_datagrams`
/// datagrams, waiting at most `slice` for each and ending at the first wait that runs out, so it
/// never waits longer than `max_datagrams` times `slice` in all (a zero `slice` is no time to wait:
/// nothing is read). Each datagram goes through the same classification as the liveness checks'
/// ([`peek`], [`probe`]): an R-U-THERE is answered, a bit-exact repeat of a message a final message of
/// ours answered gets that final message again, an authenticated message 1 of a gateway Quick Mode
/// goes to the inbox -- it is never answered here: the caller answers it ([`crate::ikev1::answer_quick`]) --,
/// a copy of the message 1 of a gateway Quick Mode this side answered gets its message 2 again and its
/// message 3 is checked and recorded, a copy of one this side refused gets the refusal again, Deletes and
/// error Notifies go to the mailbox (an error Notify about a gateway Quick Mode this side answers is also
/// recorded on it), and an R-U-THERE-ACK -- nobody waits for one here -- is dropped. It never starts an
/// exchange of its own.
///
/// While the exchange table is passive -- in every mode but the ones that turned it on
/// ([`Phase1State::enable_gateway_quick_mode`]) -- it does nothing and does not touch the socket.
pub fn serve_turn(
    sock: &dyn IkeSocket,
    st: &Phase1State,
    entropy: &mut impl Entropy,
    peer: SocketAddr,
    max_datagrams: usize,
    slice: Duration,
) -> Result<TurnReport, DriverError> {
    let mut report = TurnReport::default();
    if !st.exchanges.is_enabled() || slice.is_zero() {
        return Ok(report);
    }
    let mut buf = [0u8; 8192];
    while report.datagrams_read < max_datagrams {
        sock.set_read_timeout(Some(slice))?;
        let (n, from) = match sock.recv_from(&mut buf) {
            Ok(r) => r,
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => break,
            Err(e) => return Err(e.into()),
        };
        report.datagrams_read += 1;
        crate::debug::dump("<<<", from, &buf[..n]);
        let served = serve_datagram(sock, st, entropy, peer, &buf[..n], None);
        report.acked_dpd += served.acked;
        report.new_quick += served.new_quick;
        report.events_pushed += served.events_pushed;
        report.answered_again += served.answered_again;
    }
    Ok(report)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::crypto::DhGroup;
    use crate::entropy::SeedEntropy;
    use crate::ikev1::isakmp::flags;
    use crate::ikev1::payloads::Id;
    use crate::ikev1::phase1::{
        initiate_aggressive, respond_aggressive, Ikev1ExchangeMode, Ikev1LocalAuth, InitiatorConfig, Phase1Config,
    };
    use crate::ikev2::sk::SkCipher;

    /// A peer's ESP Delete names the peer's inbound SPI -- the one we send to --
    /// and the trace line calls it that (`spi_out`), whichever SA it names; the
    /// classification is unchanged.
    #[test]
    fn a_peer_esp_delete_is_traced_by_the_spi_we_send_to() {
        let (primary, v6, ours) = (0x1111_1111u32, 0x2222_2222u32, 0x3333_3333u32);
        let cases: [(u32, Option<u32>, Option<Seen>, &str); 4] = [
            (primary, None, Some(Seen::PeerTornDown), "spi_out=11111111"),
            (primary, Some(v6), Some(Seen::ChildDeleted(ChildFamily::Primary)), "spi_out=11111111"),
            (v6, Some(v6), Some(Seen::ChildDeleted(ChildFamily::Ipv6)), "spi_out=22222222"),
            (ours, Some(v6), None, "spi_out=11111111/22222222"),
        ];
        for (named, ipv6, want, label) in cases {
            let (seen, note) = peer_esp_delete(&named.to_be_bytes(), primary, ipv6);
            assert_eq!(seen, want, "{note}");
            assert!(note.contains(label), "{note}");
            assert!(!note.contains("spi_in"), "the SPI a peer's Delete names is not ours: {note}");
        }
        let (seen, note) = peer_esp_delete(&[1, 2, 3], primary, None);
        assert_eq!(seen, None);
        assert!(note.contains("<malformed>") && !note.contains("spi_in"), "{note}");
    }

    pub(crate) fn phase1_pair() -> (Phase1State, Phase1State) {
        let psk = b"correct horse battery staple".to_vec();
        let icfg = InitiatorConfig {
            local_auth: Ikev1LocalAuth::Psk(psk.clone()),
            trusted_cas: Vec::new(),
            now_unix: 0,
            key_len: 32,
            our_id: Id::ipv4([10, 1, 1, 1]),
            group: DhGroup::Modp1024,
            xauth: false,
            xauth_creds: None,
            ts_local: ([0, 0, 0, 0], [0, 0, 0, 0]),
            ts_remote: ([0, 0, 0, 0], [0, 0, 0, 0]),
            esp_cipher: SkCipher::Aes256Gcm,
            pfs_group: None,
            mode_cfg: false,
            ipv6: false,
            mode: Ikev1ExchangeMode::Aggressive,
            p1_lifetime_secs: 28800,
            p2_lifetime_secs: 3600,
            force_natt: false,
        };
        let rcfg = Phase1Config {
            local_auth: Ikev1LocalAuth::Psk(psk),
            trusted_cas: Vec::new(),
            now_unix: 0,
            our_id: Id::ipv4([192, 168, 0, 1]),
        };
        let mut ie = SeedEntropy::new(0xAAAA);
        let mut re = SeedEntropy::new(0xBBBB);
        let (msg1, ai) = initiate_aggressive(&icfg, &mut ie, "10.1.1.1:500".parse().unwrap(), "192.168.0.1:500".parse().unwrap());
        let (msg2, rstate) = respond_aggressive(&rcfg, &msg1, &mut re, "192.168.0.1:500".parse().unwrap(), "10.1.1.1:500".parse().unwrap()).unwrap();
        let (msg3, istate) = ai.complete(&msg2, "10.1.1.1:500".parse().unwrap(), "192.168.0.1:500".parse().unwrap()).unwrap();
        rstate.verify_hash_i(&msg3).unwrap();
        (istate, rstate)
    }

    /// Decrypts one `build_delete` message on the gateway side using its own
    /// `Phase1State` -- same `phase2_iv` seeding `build_delete` used -- and
    /// returns its single Delete payload.
    fn decrypt_one(gw_st: &Phase1State, msg: &[u8]) -> crate::ikev1::isakmp::Payload {
        let hdr = IsakmpHeader::parse(msg).unwrap();
        assert_eq!(hdr.exchange_type, exchange::INFORMATIONAL);
        assert!(hdr.flags & flags::ENCRYPTION != 0);
        let iv0 = crypto1::phase2_iv(gw_st.prf, &gw_st.phase1_iv, hdr.message_id, gw_st.enc_block);
        let (_h, payloads, _next) = phase2::parse_encrypted(msg, gw_st.prf, &gw_st.skeyid_a, &gw_st.enc_key, gw_st.enc_block, &iv0).unwrap();
        let deletes: Vec<_> = payloads.into_iter().filter(|p| p.payload_type == payload::DELETE).collect();
        assert_eq!(deletes.len(), 1);
        deletes.into_iter().next().unwrap()
    }

    #[test]
    fn build_delete_returns_two_separate_messages_esp_then_isakmp() {
        let (client_st, gw_st) = phase1_pair();
        let mut e = SeedEntropy::new(0xC0FFEE);
        let (esp_msg, isakmp_msg) = build_delete(&client_st, &mut e, 0xDEAD_BEEF).unwrap();

        // Distinct message-ids -- each is its own Informational exchange.
        let esp_hdr = IsakmpHeader::parse(&esp_msg).unwrap();
        let isakmp_hdr = IsakmpHeader::parse(&isakmp_msg).unwrap();
        assert_ne!(esp_hdr.message_id, isakmp_hdr.message_id);

        let esp_del = decrypt_one(&gw_st, &esp_msg);
        assert_eq!(esp_del.data[4], protocol::ESP);
        assert_eq!(esp_del.data[5], 4); // SPI size
        assert_eq!(&esp_del.data[8..12], &0xDEAD_BEEFu32.to_be_bytes());

        let isakmp_del = decrypt_one(&gw_st, &isakmp_msg);
        assert_eq!(isakmp_del.data[4], protocol::ISAKMP);
        assert_eq!(isakmp_del.data[5], 16); // SPI size
        let expected_isakmp_spi = [client_st.cky_i.as_slice(), client_st.cky_r.as_slice()].concat();
        assert_eq!(&isakmp_del.data[8..24], &expected_isakmp_spi[..]);
    }

    #[test]
    fn build_delete_rejects_a_wrong_key_on_decrypt() {
        let (client_st, gw_st) = phase1_pair();
        let mut e = SeedEntropy::new(0xC0FFEE);
        let (esp_msg, _isakmp_msg) = build_delete(&client_st, &mut e, 0x1234_5678).unwrap();
        let hdr = IsakmpHeader::parse(&esp_msg).unwrap();
        let iv0 = crypto1::phase2_iv(gw_st.prf, &gw_st.phase1_iv, hdr.message_id, gw_st.enc_block);
        let bad_key = vec![0x99u8; gw_st.skeyid_a.len()];
        assert!(phase2::parse_encrypted(&esp_msg, gw_st.prf, &bad_key, &gw_st.enc_key, gw_st.enc_block, &iv0).is_err());
    }

    #[test]
    fn peek_reports_alive_when_no_datagram_is_pending() {
        let (client_st, _gw_st) = phase1_pair();
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
        let mut e = SeedEntropy::new(0x1);
        let got = peek(&sock, &client_st, &mut e, peer, std::time::Duration::from_millis(20), 0, None).unwrap();
        assert_eq!(got, Liveness::Alive);
    }

    #[test]
    fn peek_classifies_an_unsolicited_delete_from_the_peer() {
        let (client_st, gw_st) = phase1_pair();
        let client_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let client_addr = client_sock.local_addr().unwrap();
        let gw_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let gw_addr = gw_sock.local_addr().unwrap();

        let mut e = SeedEntropy::new(0xFEED);
        let (esp_msg, _isakmp_msg) = build_delete(&gw_st, &mut e, 0xAAAA_BBBB).unwrap();
        gw_sock.send_to(&esp_msg, client_addr).unwrap();

        let got = peek(&client_sock, &client_st, &mut e, gw_addr, std::time::Duration::from_millis(200), 0xAAAA_BBBB, None).unwrap();
        assert_eq!(got, Liveness::PeerTornDown);
    }

    #[test]
    fn peek_ignores_an_unrelated_message_and_times_out_to_alive() {
        let (client_st, gw_st) = phase1_pair();
        let client_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let client_addr = client_sock.local_addr().unwrap();
        let gw_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let gw_addr = gw_sock.local_addr().unwrap();

        // A Quick Mode message (not Informational) sharing the same cookies
        // -- peek must not misclassify it as a Delete.
        let hdr = IsakmpHeader {
            init_cookie: gw_st.cky_i,
            resp_cookie: gw_st.cky_r,
            next_payload: payload::NONE,
            version: IsakmpHeader::VERSION_1_0,
            exchange_type: exchange::QUICK,
            flags: 0,
            message_id: 0x1111_2222,
            length: 0,
        };
        let msg = super::super::isakmp::build_message(hdr, &[(payload::HASH, vec![0xAB; 20])]);
        gw_sock.send_to(&msg, client_addr).unwrap();

        let mut e = SeedEntropy::new(0x2);
        let got = peek(&client_sock, &client_st, &mut e, gw_addr, std::time::Duration::from_millis(100), 0, None).unwrap();
        assert_eq!(got, Liveness::Alive);
    }

    #[test]
    fn peek_auto_acks_an_incoming_r_u_there_and_reports_alive() {
        // The peer (gateway) probes us; we must answer with a matching ACK
        // even on a passive `peek`, per RFC 3706.
        let (client_st, gw_st) = phase1_pair();
        let client_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let client_addr = client_sock.local_addr().unwrap();
        let gw_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let gw_addr = gw_sock.local_addr().unwrap();

        let mut ge = SeedEntropy::new(0x3);
        let probe_msg = build_r_u_there(&gw_st, &mut ge, 7).unwrap();
        gw_sock.send_to(&probe_msg, client_addr).unwrap();

        let mut ce = SeedEntropy::new(0x4);
        let got = peek(&client_sock, &client_st, &mut ce, gw_addr, std::time::Duration::from_millis(200), 0, None).unwrap();
        assert_eq!(got, Liveness::Alive);

        // The gateway should now have our ACK sitting on its own socket.
        gw_sock.set_read_timeout(Some(std::time::Duration::from_millis(200))).unwrap();
        let mut buf = [0u8; 8192];
        let n = gw_sock.recv(&mut buf).unwrap();
        let hdr = IsakmpHeader::parse(&buf[..n]).unwrap();
        let iv0 = crypto1::phase2_iv(gw_st.prf, &gw_st.phase1_iv, hdr.message_id, gw_st.enc_block);
        let (_h, payloads, _next) = phase2::parse_encrypted(&buf[..n], gw_st.prf, &gw_st.skeyid_a, &gw_st.enc_key, gw_st.enc_block, &iv0).unwrap();
        let notify = payloads.into_iter().find(|p| p.payload_type == payload::NOTIFY).unwrap();
        let (msg_type, data) = parse_notify(&notify.data).unwrap();
        assert_eq!(msg_type, notify_type::R_U_THERE_ACK);
        assert_eq!(data, &7u32.to_be_bytes());
    }

    #[test]
    fn probe_reports_alive_on_a_matching_ack() {
        let (client_st, gw_st) = phase1_pair();
        let client_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let client_addr = client_sock.local_addr().unwrap();
        let gw_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let gw_addr = gw_sock.local_addr().unwrap();

        // Simulate the gateway answering: read whatever probe() sends and
        // reply with its ACK, on a background thread so probe()'s own
        // blocking recv has something to see.
        let responder = std::thread::spawn(move || {
            gw_sock.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
            let mut buf = [0u8; 8192];
            let n = gw_sock.recv(&mut buf).unwrap();
            let hdr = IsakmpHeader::parse(&buf[..n]).unwrap();
            let iv0 = crypto1::phase2_iv(gw_st.prf, &gw_st.phase1_iv, hdr.message_id, gw_st.enc_block);
            let (_h, payloads, _next) = phase2::parse_encrypted(&buf[..n], gw_st.prf, &gw_st.skeyid_a, &gw_st.enc_key, gw_st.enc_block, &iv0).unwrap();
            let notify = payloads.into_iter().find(|p| p.payload_type == payload::NOTIFY).unwrap();
            let (msg_type, data) = parse_notify(&notify.data).unwrap();
            assert_eq!(msg_type, notify_type::R_U_THERE);
            let seq = u32::from_be_bytes(<[u8; 4]>::try_from(data).unwrap());
            let mut ge = SeedEntropy::new(0x5);
            let ack = build_r_u_there_ack(&gw_st, &mut ge, seq).unwrap();
            gw_sock.send_to(&ack, client_addr).unwrap();
        });

        let mut ce = SeedEntropy::new(0x6);
        let got = probe(&client_sock, &client_st, &mut ce, gw_addr, 42, std::time::Duration::from_secs(2), 0, None).unwrap();
        assert_eq!(got, Liveness::Alive);
        responder.join().unwrap();
    }

    /// A timeout too long for the clock to count is no panic on adding it to the time now:
    /// the acknowledgement that comes is taken.
    #[test]
    fn probe_with_the_largest_timeout_there_is_takes_the_ack_without_panicking() {
        let (client_st, gw_st) = phase1_pair();
        let client_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let client_addr = client_sock.local_addr().unwrap();
        let gw_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let gw_addr = gw_sock.local_addr().unwrap();
        let responder = std::thread::spawn(move || {
            gw_sock.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
            let mut buf = [0u8; 8192];
            let n = gw_sock.recv(&mut buf).unwrap();
            let hdr = IsakmpHeader::parse(&buf[..n]).unwrap();
            let iv0 = crypto1::phase2_iv(gw_st.prf, &gw_st.phase1_iv, hdr.message_id, gw_st.enc_block);
            let (_h, payloads, _next) = phase2::parse_encrypted(&buf[..n], gw_st.prf, &gw_st.skeyid_a, &gw_st.enc_key, gw_st.enc_block, &iv0).unwrap();
            let notify = payloads.into_iter().find(|p| p.payload_type == payload::NOTIFY).unwrap();
            let (_msg_type, data) = parse_notify(&notify.data).unwrap();
            let seq = u32::from_be_bytes(<[u8; 4]>::try_from(data).unwrap());
            let ack = build_r_u_there_ack(&gw_st, &mut SeedEntropy::new(0x5), seq).unwrap();
            gw_sock.send_to(&ack, client_addr).unwrap();
        });
        let got = probe(&client_sock, &client_st, &mut SeedEntropy::new(0x6), gw_addr, 42, std::time::Duration::MAX, 0, None).unwrap();
        assert_eq!(got, Liveness::Alive);
        responder.join().unwrap();
    }

    #[test]
    fn probe_times_out_to_no_reply_when_nothing_answers() {
        let (client_st, _gw_st) = phase1_pair();
        let client_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        // A bound socket that never reads or answers: a *closed* port would
        // make Windows reply with ICMP Port Unreachable and surface it as
        // WSAECONNRESET on the next recv, which isn't what's under test.
        let silent_peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let dead_peer = silent_peer.local_addr().unwrap();
        let mut e = SeedEntropy::new(0x7);
        let got = probe(&client_sock, &client_st, &mut e, dead_peer, 1, std::time::Duration::from_millis(50), 0, None).unwrap();
        assert_eq!(got, Liveness::NoReply);
    }

    #[test]
    fn probe_reports_peer_torn_down_if_a_delete_arrives_instead_of_an_ack() {
        let (client_st, gw_st) = phase1_pair();
        let client_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let client_addr = client_sock.local_addr().unwrap();
        let gw_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let gw_addr = gw_sock.local_addr().unwrap();

        let responder = std::thread::spawn(move || {
            gw_sock.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
            let mut buf = [0u8; 8192];
            let _n = gw_sock.recv(&mut buf).unwrap(); // the R-U-THERE itself
            let mut ge = SeedEntropy::new(0x8);
            let (esp_msg, _isakmp_msg) = build_delete(&gw_st, &mut ge, 0x1234).unwrap();
            gw_sock.send_to(&esp_msg, client_addr).unwrap();
        });

        let mut ce = SeedEntropy::new(0x9);
        let got = probe(&client_sock, &client_st, &mut ce, gw_addr, 99, std::time::Duration::from_secs(2), 0x1234, None).unwrap();
        assert_eq!(got, Liveness::PeerTornDown);
        responder.join().unwrap();
    }

    /// Regression test for the misclassification bug this module used to
    /// have: any Delete at all -- even an ESP Delete naming a CHILD SA SPI
    /// that isn't the one currently in use, e.g. because the peer just
    /// rekeyed it -- used to be read as a full tunnel teardown. It must now
    /// be silently ignored, since it doesn't affect the CHILD SA `peek`'s
    /// caller actually cares about.
    #[test]
    fn peek_ignores_an_esp_delete_for_a_superseded_child_sa() {
        let (client_st, gw_st) = phase1_pair();
        let client_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let client_addr = client_sock.local_addr().unwrap();
        let gw_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let gw_addr = gw_sock.local_addr().unwrap();

        // The peer deletes the *old* SPI (0x1111_1111) after rekeying, but
        // our currently-in-use SPI is 0x2222_2222 -- this must not tear down.
        let mut e = SeedEntropy::new(0xFEED2);
        let (esp_msg, _isakmp_msg) = build_delete(&gw_st, &mut e, 0x1111_1111).unwrap();
        gw_sock.send_to(&esp_msg, client_addr).unwrap();

        let got = peek(&client_sock, &client_st, &mut e, gw_addr, std::time::Duration::from_millis(100), 0x2222_2222, None).unwrap();
        assert_eq!(got, Liveness::Alive);
    }

    /// Regression test for a real bug found live against a FortiGate: the
    /// gateway deleted just the IPv6 Quick Mode SA (the primary IPv4 one and
    /// the ISAKMP SA both stayed up), and this side used to silently ignore
    /// it entirely -- `current_peer_spi` only ever compared against the
    /// primary's SPI, so an ESP Delete naming the IPv6 one matched nothing
    /// and IPv6 stayed permanently dead with no recovery. This code reads
    /// Phase 2 SAs as independent (an inference from RFC 2408 §3.15 and §5.15,
    /// where a Delete covers only the SAs it lists: deleting one never implies
    /// deleting the ISAKMP SA or any other Phase 2 SA under it), so this must be
    /// [`Liveness::ChildDeleted`], not ignored and not a full teardown.
    #[test]
    fn peek_reports_child_deleted_when_only_the_ipv6_sa_is_deleted() {
        let (client_st, gw_st) = phase1_pair();
        let client_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let client_addr = client_sock.local_addr().unwrap();
        let gw_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let gw_addr = gw_sock.local_addr().unwrap();

        let mut e = SeedEntropy::new(0xFEED3);
        let (esp_msg, _isakmp_msg) = build_delete(&gw_st, &mut e, 0x6666_6666).unwrap();
        gw_sock.send_to(&esp_msg, client_addr).unwrap();

        let got = peek(&client_sock, &client_st, &mut e, gw_addr, std::time::Duration::from_millis(100), 0x4444_4444, Some(0x6666_6666)).unwrap();
        assert_eq!(got, Liveness::ChildDeleted(ChildFamily::Ipv6));
    }

    /// Same real bug, the other family: the gateway deleted just the primary
    /// (IPv4) Quick Mode SA while the IPv6 one and the ISAKMP SA both stayed
    /// up. This side used to misread `current_peer_spi` matching as "the
    /// tunnel is down" and tore down everything, including the still-good
    /// IPv6 CHILD SA and the ISAKMP SA itself -- wrong, since a Delete covers only
    /// the SAs it lists (RFC 2408 §3.15, §5.15), and
    /// worse than the IPv6 case since it killed a working tunnel instead of
    /// just leaving one family dead.
    #[test]
    fn peek_reports_child_deleted_when_only_the_primary_sa_is_deleted_and_ipv6_survives() {
        let (client_st, gw_st) = phase1_pair();
        let client_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let client_addr = client_sock.local_addr().unwrap();
        let gw_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let gw_addr = gw_sock.local_addr().unwrap();

        let mut e = SeedEntropy::new(0xFEED4);
        let (esp_msg, _isakmp_msg) = build_delete(&gw_st, &mut e, 0x4444_4444).unwrap();
        gw_sock.send_to(&esp_msg, client_addr).unwrap();

        let got = peek(&client_sock, &client_st, &mut e, gw_addr, std::time::Duration::from_millis(100), 0x4444_4444, Some(0x6666_6666)).unwrap();
        assert_eq!(got, Liveness::ChildDeleted(ChildFamily::Primary));
    }

    /// A single-stack tunnel (no IPv6 Quick Mode SA, `current_peer_spi_ipv6:
    /// None`) has nothing to fall back on: deleting the only CHILD SA still
    /// tears down the whole tunnel, unchanged from before this fix.
    #[test]
    fn peek_still_tears_down_a_single_stack_tunnel_on_its_only_child_sa_delete() {
        let (client_st, gw_st) = phase1_pair();
        let client_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let client_addr = client_sock.local_addr().unwrap();
        let gw_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let gw_addr = gw_sock.local_addr().unwrap();

        let mut e = SeedEntropy::new(0xFEED5);
        let (esp_msg, _isakmp_msg) = build_delete(&gw_st, &mut e, 0x4444_4444).unwrap();
        gw_sock.send_to(&esp_msg, client_addr).unwrap();

        let got = peek(&client_sock, &client_st, &mut e, gw_addr, std::time::Duration::from_millis(100), 0x4444_4444, None).unwrap();
        assert_eq!(got, Liveness::PeerTornDown);
    }

    /// Same non-teardown expectation as
    /// [`peek_ignores_an_esp_delete_for_a_superseded_child_sa`], but via
    /// [`probe`]: the stray ESP Delete for a superseded SPI must not be
    /// mistaken for the R-U-THERE-ACK reply, so `probe` should simply time
    /// out to [`Liveness::NoReply`].
    #[test]
    fn probe_ignores_an_esp_delete_for_a_superseded_child_sa_and_times_out() {
        let (client_st, gw_st) = phase1_pair();
        let client_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let client_addr = client_sock.local_addr().unwrap();
        let gw_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let gw_addr = gw_sock.local_addr().unwrap();

        let responder = std::thread::spawn(move || {
            gw_sock.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
            let mut buf = [0u8; 8192];
            let _n = gw_sock.recv(&mut buf).unwrap(); // the R-U-THERE itself
            let mut ge = SeedEntropy::new(0xA);
            let (esp_msg, _isakmp_msg) = build_delete(&gw_st, &mut ge, 0x1111_1111).unwrap();
            gw_sock.send_to(&esp_msg, client_addr).unwrap();
        });

        let mut ce = SeedEntropy::new(0xB);
        let got = probe(&client_sock, &client_st, &mut ce, gw_addr, 100, std::time::Duration::from_millis(200), 0x2222_2222, None).unwrap();
        assert_eq!(got, Liveness::NoReply);
        responder.join().unwrap();
    }

    // --- NAT-T (RFC 3947/3948): once the tunnel floated to UDP 4500 every IKE
    // datagram carries the 4-byte non-ESP marker in both directions; without it
    // a gateway reads ours as ESP and we read its DPD probes as garbage -- so it
    // never got an R-U-THERE-ACK and tore the tunnel down (confirmed live on a
    // FortiGate with a floated IKEv1 tunnel).

    pub(crate) fn floated_pair() -> (Phase1State, Phase1State) {
        let (mut c, mut g) = phase1_pair();
        c.floated = true;
        g.floated = true;
        (c, g)
    }

    /// Strips the marker off a datagram the client sent and decrypts its single
    /// Notify -- what a floated gateway does with our DPD traffic.
    fn gateway_reads_notify(gw_st: &Phase1State, datagram: &[u8]) -> (u16, Vec<u8>) {
        let ike = crate::ikev2::natt::unwrap_ike_4500(datagram).expect("the client must send IKE on 4500 with the non-ESP marker");
        let hdr = IsakmpHeader::parse(ike).unwrap();
        let iv0 = crypto1::phase2_iv(gw_st.prf, &gw_st.phase1_iv, hdr.message_id, gw_st.enc_block);
        let (_h, payloads, _next) = phase2::parse_encrypted(ike, gw_st.prf, &gw_st.skeyid_a, &gw_st.enc_key, gw_st.enc_block, &iv0).unwrap();
        let notify = payloads.into_iter().find(|p| p.payload_type == payload::NOTIFY).unwrap();
        let (t, d) = parse_notify(&notify.data).unwrap();
        (t, d.to_vec())
    }

    #[test]
    fn floated_peek_acks_a_marker_wrapped_r_u_there_with_a_marker_wrapped_ack() {
        let (client_st, gw_st) = floated_pair();
        let client_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let client_addr = client_sock.local_addr().unwrap();
        let gw_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let gw_addr = gw_sock.local_addr().unwrap();

        let mut ge = SeedEntropy::new(0x31);
        let probe_msg = build_r_u_there(&gw_st, &mut ge, 7).unwrap();
        gw_sock.send_to(&crate::ikev2::natt::wrap_ike_4500(&probe_msg), client_addr).unwrap();

        let mut ce = SeedEntropy::new(0x32);
        let got = peek(&client_sock, &client_st, &mut ce, gw_addr, std::time::Duration::from_millis(200), 0, None).unwrap();
        assert_eq!(got, Liveness::Alive);

        gw_sock.set_read_timeout(Some(std::time::Duration::from_millis(200))).unwrap();
        let mut buf = [0u8; 8192];
        let n = gw_sock.recv(&mut buf).expect("the R-U-THERE-ACK never arrived");
        let (msg_type, data) = gateway_reads_notify(&gw_st, &buf[..n]);
        assert_eq!(msg_type, notify_type::R_U_THERE_ACK);
        assert_eq!(data, 7u32.to_be_bytes());
    }

    #[test]
    fn floated_peek_classifies_a_marker_wrapped_delete_as_torn_down() {
        let (client_st, gw_st) = floated_pair();
        let client_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let client_addr = client_sock.local_addr().unwrap();
        let gw_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let gw_addr = gw_sock.local_addr().unwrap();

        let mut e = SeedEntropy::new(0x33);
        let (_esp_msg, isakmp_msg) = build_delete(&gw_st, &mut e, 0xAAAA_BBBB).unwrap();
        gw_sock.send_to(&crate::ikev2::natt::wrap_ike_4500(&isakmp_msg), client_addr).unwrap();

        let got = peek(&client_sock, &client_st, &mut e, gw_addr, std::time::Duration::from_millis(200), 0, None).unwrap();
        assert_eq!(got, Liveness::PeerTornDown);
    }

    #[test]
    fn floated_peek_skips_datagrams_without_the_marker() {
        // On UDP 4500 an unmarked datagram is ESP (or a keepalive), never IKE:
        // it must be skipped, not parsed as an ISAKMP header.
        let (client_st, gw_st) = floated_pair();
        let client_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let client_addr = client_sock.local_addr().unwrap();
        let gw_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let gw_addr = gw_sock.local_addr().unwrap();

        let mut e = SeedEntropy::new(0x34);
        let (_esp_msg, isakmp_msg) = build_delete(&gw_st, &mut e, 1).unwrap();
        gw_sock.send_to(&isakmp_msg, client_addr).unwrap(); // a Delete, but no marker
        gw_sock.send_to(&[0xFF], client_addr).unwrap(); // NAT keepalive

        let got = peek(&client_sock, &client_st, &mut e, gw_addr, std::time::Duration::from_millis(100), 0, None).unwrap();
        assert_eq!(got, Liveness::Alive);
    }

    #[test]
    fn floated_probe_sends_a_marker_wrapped_r_u_there_and_accepts_a_marker_wrapped_ack() {
        let (client_st, gw_st) = floated_pair();
        let client_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let client_addr = client_sock.local_addr().unwrap();
        let gw_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let gw_addr = gw_sock.local_addr().unwrap();

        let responder = std::thread::spawn(move || {
            gw_sock.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
            let mut buf = [0u8; 8192];
            let n = gw_sock.recv(&mut buf).unwrap();
            let (msg_type, data) = gateway_reads_notify(&gw_st, &buf[..n]);
            assert_eq!(msg_type, notify_type::R_U_THERE);
            let seq = u32::from_be_bytes(<[u8; 4]>::try_from(data.as_slice()).unwrap());
            let mut ge = SeedEntropy::new(0x35);
            let ack = build_r_u_there_ack(&gw_st, &mut ge, seq).unwrap();
            gw_sock.send_to(&crate::ikev2::natt::wrap_ike_4500(&ack), client_addr).unwrap();
        });

        let mut ce = SeedEntropy::new(0x36);
        let got = probe(&client_sock, &client_st, &mut ce, gw_addr, 42, std::time::Duration::from_secs(2), 0, None).unwrap();
        assert_eq!(got, Liveness::Alive);
        responder.join().unwrap();
    }
    /// A host that runs its own `recv_from` loop on the IKE port (an ESP pump)
    /// would otherwise swallow the gateway's ACK: with the pump forwarding IKE
    /// datagrams through a [`ChannelIo`], the probe still gets its answer even
    /// though ESP and keepalives arrive on the same socket in between.
    #[test]
    fn floated_probe_gets_its_ack_through_a_channel_while_a_pump_owns_the_socket() {
        use crate::transport::{spawn_pump_reader, ChannelIo};
        let (client_st, gw_st) = floated_pair();
        let client_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let client_addr = client_sock.local_addr().unwrap();
        let gw_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let gw_addr = gw_sock.local_addr().unwrap();
        let (rx, _pump) = spawn_pump_reader(&client_sock, true);
        let io = ChannelIo::new(client_sock, rx, gw_addr);

        let responder = std::thread::spawn(move || {
            gw_sock.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
            let mut buf = [0u8; 8192];
            let n = gw_sock.recv(&mut buf).unwrap();
            let (_, data) = gateway_reads_notify(&gw_st, &buf[..n]);
            let seq = u32::from_be_bytes(<[u8; 4]>::try_from(data.as_slice()).unwrap());
            gw_sock.send_to(&[0xFF], client_addr).unwrap(); // NAT keepalive
            gw_sock.send_to(&[0x5a; 96], client_addr).unwrap(); // ESP
            let mut ge = SeedEntropy::new(0x37);
            let ack = build_r_u_there_ack(&gw_st, &mut ge, seq).unwrap();
            gw_sock.send_to(&crate::ikev2::natt::wrap_ike_4500(&ack), client_addr).unwrap();
        });

        let mut ce = SeedEntropy::new(0x38);
        let got = probe(&io, &client_st, &mut ce, gw_addr, 43, std::time::Duration::from_secs(2), 0, None).unwrap();
        assert_eq!(got, Liveness::Alive);
        responder.join().unwrap();
    }

    /// The passive check, over the same arrangement: a Delete the gateway sends
    /// unprompted reaches `peek` through the channel.
    #[test]
    fn floated_peek_sees_the_gateways_delete_through_a_channel_while_a_pump_owns_the_socket() {
        use crate::transport::{spawn_pump_reader, ChannelIo};
        let (client_st, gw_st) = floated_pair();
        let client_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let client_addr = client_sock.local_addr().unwrap();
        let gw_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let gw_addr = gw_sock.local_addr().unwrap();
        let (rx, _pump) = spawn_pump_reader(&client_sock, true);
        let io = ChannelIo::new(client_sock, rx, gw_addr);

        let mut e = SeedEntropy::new(0x39);
        assert_eq!(peek(&io, &client_st, &mut e, gw_addr, std::time::Duration::from_millis(50), 0x77, None).unwrap(), Liveness::Alive);
        let (esp_msg, _isakmp_msg) = build_delete(&gw_st, &mut e, 0x77).unwrap();
        gw_sock.send_to(&crate::ikev2::natt::wrap_ike_4500(&esp_msg), client_addr).unwrap();
        assert_eq!(peek(&io, &client_st, &mut e, gw_addr, std::time::Duration::from_secs(2), 0x77, None).unwrap(), Liveness::PeerTornDown);
    }

    // --- Quick Mode message 3 recovery (RFC 2408 §3.1, Commit Bit NOTE: a proposal). The liveness checks are what
    // reads the socket between the exchanges we start -- the daemon's own upkeep sends them, with or
    // without anyone asking for statistics -- so a message 2 the gateway repeats while nothing else is
    // going on must get our message 3 again from here, and nothing else must.

    /// A Quick Mode message of `st`'s ISAKMP SA with `message_id`, standing for the gateway's message 2,
    /// and the message 3 we answered it with, as [`Phase1State::finals`] keeps such a pair. The bytes are
    /// not a real exchange's: what these tests pin is which datagrams the resend answers, and that it
    /// sends the retained bytes untouched.
    fn quick_mode_pair(st: &Phase1State, message_id: u32) -> (Vec<u8>, Vec<u8>) {
        let hdr = IsakmpHeader {
            init_cookie: st.cky_i,
            resp_cookie: st.cky_r,
            next_payload: payload::NONE,
            version: IsakmpHeader::VERSION_1_0,
            exchange_type: exchange::QUICK,
            flags: 0,
            message_id,
            length: 0,
        };
        let message_2 = super::super::isakmp::build_message(hdr, &[(payload::HASH, vec![0xAB; 20])]);
        let message_3 = [b"our Quick Mode message 3 for ".as_slice(), &message_id.to_be_bytes()].concat();
        (message_2, message_3)
    }

    /// A client socket and a gateway socket on loopback, the gateway's read timeout `wait`.
    fn loopback_pair(wait: std::time::Duration) -> (std::net::UdpSocket, SocketAddr, std::net::UdpSocket, SocketAddr) {
        let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let client_addr = client.local_addr().unwrap();
        let gateway = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        gateway.set_read_timeout(Some(wait)).unwrap();
        let gateway_addr = gateway.local_addr().unwrap();
        (client, client_addr, gateway, gateway_addr)
    }

    /// Like [`loopback_pair`] for a floated tunnel: a floated final message is sent to port 4500 of the
    /// peer's address (`quick::send_ike`), so the gateway takes that port on an address of its own,
    /// which `host` names, so that tests in parallel never share it.
    fn floated_loopback_pair(host: [u8; 4], wait: std::time::Duration) -> (std::net::UdpSocket, SocketAddr, std::net::UdpSocket, SocketAddr) {
        let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let client_addr = client.local_addr().unwrap();
        let gateway = std::net::UdpSocket::bind((std::net::Ipv4Addr::from(host), crate::natt_port())).unwrap();
        gateway.set_read_timeout(Some(wait)).unwrap();
        let gateway_addr = gateway.local_addr().unwrap();
        (client, client_addr, gateway, gateway_addr)
    }

    /// The passive check answers each repeat of the gateway's message 2 with message 3, the same bytes
    /// every time -- a gateway that never got it may ask more than once -- and still reports the tunnel
    /// alive: the repeat is neither processed as a new exchange nor a reason to end the wait.
    #[test]
    fn peek_sends_message_3_again_each_time_the_gateway_repeats_message_2() {
        let (client_st, _gw_st) = phase1_pair();
        let (client_sock, client_addr, gw_sock, gw_addr) = loopback_pair(std::time::Duration::from_secs(2));
        let (message_2, message_3) = quick_mode_pair(&client_st, 0x1111_2222);
        client_st.finals.retain(&message_2, &message_3);

        let mut e = SeedEntropy::new(0x40);
        for round in 1..=3 {
            gw_sock.send_to(&message_2, client_addr).unwrap();
            let got = peek(&client_sock, &client_st, &mut e, gw_addr, std::time::Duration::from_millis(50), 0, None).unwrap();
            assert_eq!(got, Liveness::Alive, "repeat {round}");
            let mut buf = [0u8; 256];
            let n = gw_sock.recv(&mut buf).unwrap_or_else(|e| panic!("message 3 was not sent again for repeat {round}: {e}"));
            assert_eq!(&buf[..n], &message_3[..], "repeat {round}");
        }
    }

    /// Only the exact message a final message answered is answered: another Quick Mode exchange's message
    /// (another Message ID) and the same bytes under another ISAKMP SA's cookies get nothing.
    #[test]
    fn peek_sends_nothing_for_another_exchange_or_another_sa() {
        let (client_st, _gw_st) = phase1_pair();
        let (client_sock, client_addr, gw_sock, gw_addr) = loopback_pair(std::time::Duration::from_millis(300));
        let (message_2, message_3) = quick_mode_pair(&client_st, 0x1111_2222);
        client_st.finals.retain(&message_2, &message_3);

        let (other_exchange, _) = quick_mode_pair(&client_st, 0x3333_4444);
        let mut other_sa = message_2.clone();
        other_sa[..8].copy_from_slice(&[0x5A; 8]);
        gw_sock.send_to(&other_exchange, client_addr).unwrap();
        gw_sock.send_to(&other_sa, client_addr).unwrap();

        let mut e = SeedEntropy::new(0x41);
        let got = peek(&client_sock, &client_st, &mut e, gw_addr, std::time::Duration::from_millis(50), 0, None).unwrap();
        assert_eq!(got, Liveness::Alive);
        let mut buf = [0u8; 256];
        assert!(gw_sock.recv(&mut buf).is_err(), "nothing answered either datagram, so nothing may be sent");

        // Control: the datagram the final message answered still is answered.
        gw_sock.send_to(&message_2, client_addr).unwrap();
        peek(&client_sock, &client_st, &mut e, gw_addr, std::time::Duration::from_millis(50), 0, None).unwrap();
        gw_sock.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
        let n = gw_sock.recv(&mut buf).expect("the control repeat must be answered");
        assert_eq!(&buf[..n], &message_3[..]);
    }

    /// The active check waits for its ACK through the same reads, so a repeat that arrives first is
    /// answered on the way and the ACK behind it still ends the wait.
    #[test]
    fn probe_sends_message_3_again_and_still_takes_its_ack() {
        let (client_st, gw_st) = phase1_pair();
        let (client_sock, client_addr, gw_sock, gw_addr) = loopback_pair(std::time::Duration::from_secs(2));
        let (message_2, message_3) = quick_mode_pair(&client_st, 0x1111_2222);
        client_st.finals.retain(&message_2, &message_3);

        gw_sock.send_to(&message_2, client_addr).unwrap();
        let ack = build_r_u_there_ack(&gw_st, &mut SeedEntropy::new(0x42), 5).unwrap();
        gw_sock.send_to(&ack, client_addr).unwrap();

        let got = probe(&client_sock, &client_st, &mut SeedEntropy::new(0x43), gw_addr, 5, std::time::Duration::from_secs(2), 0, None).unwrap();
        assert_eq!(got, Liveness::Alive);
        let mut buf = [0u8; 2048];
        gw_sock.recv(&mut buf).expect("the R-U-THERE itself");
        let n = gw_sock.recv(&mut buf).expect("message 3 must have been sent again while the probe waited");
        assert_eq!(&buf[..n], &message_3[..]);
    }

    /// On UDP 4500 the repeat is a marked datagram and message 3 goes back marked; an unmarked datagram
    /// with the same bytes is ESP or a keepalive as far as that port is concerned, and is not answered.
    #[test]
    fn floated_peek_sends_message_3_again_marked_and_ignores_an_unmarked_repeat() {
        let (client_st, _gw_st) = floated_pair();
        let (client_sock, client_addr, gw_sock, gw_addr) = floated_loopback_pair([127, 79, 1, 1], std::time::Duration::from_millis(300));
        let (message_2, message_3) = quick_mode_pair(&client_st, 0x1111_2222);
        client_st.finals.retain(&message_2, &message_3);

        let mut e = SeedEntropy::new(0x44);
        gw_sock.send_to(&message_2, client_addr).unwrap(); // no marker
        peek(&client_sock, &client_st, &mut e, gw_addr, std::time::Duration::from_millis(50), 0, None).unwrap();
        let mut buf = [0u8; 256];
        assert!(gw_sock.recv(&mut buf).is_err(), "an unmarked datagram on 4500 is not IKE");

        gw_sock.send_to(&crate::ikev2::natt::wrap_ike_4500(&message_2), client_addr).unwrap();
        peek(&client_sock, &client_st, &mut e, gw_addr, std::time::Duration::from_millis(50), 0, None).unwrap();
        gw_sock.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
        let n = gw_sock.recv(&mut buf).expect("message 3 was not sent again");
        assert_eq!(crate::ikev2::natt::unwrap_ike_4500(&buf[..n]), Some(&message_3[..]), "message 3 must go back with the non-ESP marker");
    }

    /// With a pump owning the socket (Windows) the repeat arrives through the channel and message 3 goes
    /// out on the pump's socket -- the same single reader as for every other IKE datagram.
    #[test]
    fn floated_peek_sends_message_3_again_through_a_channel_while_a_pump_owns_the_socket() {
        use crate::transport::{spawn_pump_reader, ChannelIo};
        let (client_st, _gw_st) = floated_pair();
        let (client_sock, client_addr, gw_sock, gw_addr) = floated_loopback_pair([127, 79, 2, 1], std::time::Duration::from_secs(2));
        let (message_2, message_3) = quick_mode_pair(&client_st, 0x1111_2222);
        client_st.finals.retain(&message_2, &message_3);
        let (rx, _pump) = spawn_pump_reader(&client_sock, true);
        let io = ChannelIo::new(client_sock, rx, gw_addr);

        gw_sock.send_to(&[0xFF], client_addr).unwrap(); // NAT keepalive, kept by the pump
        gw_sock.send_to(&[0x5a; 96], client_addr).unwrap(); // ESP, kept by the pump
        gw_sock.send_to(&crate::ikev2::natt::wrap_ike_4500(&message_2), client_addr).unwrap();
        let got = peek(&io, &client_st, &mut SeedEntropy::new(0x45), gw_addr, std::time::Duration::from_millis(500), 0, None).unwrap();
        assert_eq!(got, Liveness::Alive);
        let mut buf = [0u8; 256];
        let n = gw_sock.recv(&mut buf).expect("message 3 was not sent again");
        assert_eq!(crate::ikev2::natt::unwrap_ike_4500(&buf[..n]), Some(&message_3[..]));
    }

    /// The retained final message has a time to live: within it a repeat of message 2 is answered, after
    /// it the repeat is a stray datagram like any other. Told by a clock the test moves.
    #[test]
    fn peek_stops_answering_a_repeat_once_the_final_message_has_outlived_its_time() {
        use crate::ikev1::phase1::{RetainedFinals, TestClock};
        let (mut client_st, _gw_st) = phase1_pair();
        let clock = TestClock::new();
        client_st.finals = clock.finals();
        let (client_sock, client_addr, gw_sock, gw_addr) = loopback_pair(std::time::Duration::from_millis(300));
        let (message_2, message_3) = quick_mode_pair(&client_st, 0x1111_2222);
        client_st.finals.retain(&message_2, &message_3);
        let mut e = SeedEntropy::new(0x46);
        let mut buf = [0u8; 256];

        clock.advance(RetainedFinals::KEPT_FOR - std::time::Duration::from_secs(1));
        gw_sock.send_to(&message_2, client_addr).unwrap();
        peek(&client_sock, &client_st, &mut e, gw_addr, std::time::Duration::from_millis(50), 0, None).unwrap();
        let n = gw_sock.recv(&mut buf).expect("still inside its time: message 3 must be sent again");
        assert_eq!(&buf[..n], &message_3[..]);

        clock.advance(std::time::Duration::from_secs(1));
        gw_sock.send_to(&message_2, client_addr).unwrap();
        let got = peek(&client_sock, &client_st, &mut e, gw_addr, std::time::Duration::from_millis(50), 0, None).unwrap();
        assert_eq!(got, Liveness::Alive);
        assert!(gw_sock.recv(&mut buf).is_err(), "past its time to live nothing is answered");
    }

    /// While the exchange table is passive, every Informational message we build draws its
    /// Message ID as it did before the table existed (four octets of entropy, `| 1`, and no
    /// other draw), and its bytes are unchanged (the digests were taken from the code before
    /// the Message-ID ledger).
    #[test]
    fn a_passive_table_leaves_our_informational_messages_as_they_were() {
        use sha2::{Digest, Sha256};
        type Build = fn(&Phase1State, &mut SeedEntropy) -> Vec<u8>;
        let (client_st, _gw_st) = phase1_pair();
        let builds: [(&str, Build, &str); 4] = [
            ("R-U-THERE", |st, e| build_r_u_there(st, e, 7).unwrap(), "58cb3e894c22525834736c5d3b2e51a7d478e6e6accdabe35131ef9f29744421"),
            ("R-U-THERE-ACK", |st, e| build_r_u_there_ack(st, e, 7).unwrap(), "76011f27d7a7e8639ecca7225dd10ba66e3017ea641732dd9b4250ca26bfe1c3"),
            ("ESP Delete", |st, e| build_esp_delete(st, e, 0xDEAD_BEEF).unwrap(), "876ec04ec00b87fd00ff87978bb07f8b043762e38d57ae97a4d6cb6facbefe5f"),
            ("ISAKMP Delete", |st, e| build_isakmp_delete(st, e).unwrap(), "607f685459a90f473f37b12cb63439870a13bfd1b0e484685c22d8b2c769513c"),
        ];
        for (what, build, digest) in builds {
            let mut entropy = SeedEntropy::new(0x5EED);
            let msg = build(&client_st, &mut entropy);
            let mut before = SeedEntropy::new(0x5EED);
            let mut mid = [0u8; 4];
            before.fill(&mut mid);
            assert_eq!(IsakmpHeader::parse(&msg).unwrap().message_id, u32::from_be_bytes(mid) | 1, "{what}");
            assert_eq!(entropy.next_u64(), before.next_u64(), "{what}: the entropy was drawn as before, and no more");
            let got: String = Sha256::digest(&msg).iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(got, digest, "{what}");
        }
    }

    /// With the table on, every Informational of ours is recorded as ours and over at once, and
    /// one is built even when every id the table holds is an exchange in progress -- under an id
    /// it does not hold, left unrecorded -- so neither a Delete nor a DPD answer is ever refused
    /// for room.
    #[test]
    fn an_enabled_table_records_our_informationals_and_never_refuses_one() {
        use crate::ikev1::msgid::{Admission, MidState, Origin, MID_CAP};
        let (client_st, gw_st) = phase1_pair();
        client_st.enable_gateway_quick_mode();
        let mut e = SeedEntropy::new(0x5EED);
        let ack = build_r_u_there_ack(&client_st, &mut e, 7).unwrap();
        let id = IsakmpHeader::parse(&ack).unwrap().message_id;
        let record = client_st.exchanges.id_record(id).expect("recorded");
        assert_eq!((record.origin, record.kind, record.state), (Origin::Local, MidKind::Informational, MidState::Done));
        let at = Instant::now();
        for n in 1..=MID_CAP as u32 {
            assert_eq!(client_st.exchanges.record_authenticated(n * 2, MidKind::Quick, [1; 32], at, at + Duration::from_secs(3600)), Admission::New);
        }
        assert_eq!(client_st.exchanges.id_record(id), None, "our finished Informational made room");
        let delete = build_esp_delete(&client_st, &mut e, 0xDEAD_BEEF).expect("a Delete is never refused for room");
        let id = IsakmpHeader::parse(&delete).unwrap().message_id;
        assert_eq!(id % 2, 1);
        assert_eq!(client_st.exchanges.id_record(id), None, "built, not recorded");
        assert_eq!(client_st.exchanges.ids_held(), MID_CAP);
        let named = decrypt_one(&gw_st, &delete);
        assert_eq!(&named.data[8..12], &0xDEAD_BEEFu32.to_be_bytes(), "and the gateway reads it");
    }

    // --- The exchange table: what a passive one leaves as it was, and the readers once it is on.

    use crate::ikev1::exchange::{ExchangeTable, PeerEvent};
    use crate::ikev1::phase1::TestClock;
    use crate::ikev1::quick;
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// An `IkeSocket` that hands out the datagrams it was given, in order, and then answers every read with
    /// an error of kind `end` -- `WouldBlock` by default, what a read that timed out gives -- recording what
    /// was asked of it. No network, no waiting.
    struct Scripted {
        incoming: RefCell<VecDeque<Vec<u8>>>,
        end: std::io::ErrorKind,
        timeouts: RefCell<Vec<Option<Duration>>>,
        sent: RefCell<Vec<(Vec<u8>, SocketAddr)>>,
        reads: Cell<usize>,
    }

    impl Scripted {
        fn with(datagrams: impl IntoIterator<Item = Vec<u8>>) -> Self {
            Self::ending(datagrams, std::io::ErrorKind::WouldBlock)
        }

        fn ending(datagrams: impl IntoIterator<Item = Vec<u8>>, end: std::io::ErrorKind) -> Self {
            Self { incoming: RefCell::new(datagrams.into_iter().collect()), end, timeouts: RefCell::default(), sent: RefCell::default(), reads: Cell::new(0) }
        }

        fn sent(&self) -> Vec<Vec<u8>> {
            self.sent.borrow().iter().map(|(datagram, _)| datagram.clone()).collect()
        }
    }

    impl IkeSocket for Scripted {
        fn send_to(&self, buf: &[u8], dest: SocketAddr) -> std::io::Result<usize> {
            self.sent.borrow_mut().push((buf.to_vec(), dest));
            Ok(buf.len())
        }
        fn set_read_timeout(&self, dur: Option<Duration>) -> std::io::Result<()> {
            self.timeouts.borrow_mut().push(dur);
            Ok(())
        }
        fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
            self.reads.set(self.reads.get() + 1);
            let Some(datagram) = self.incoming.borrow_mut().pop_front() else { return Err(self.end.into()) };
            buf[..datagram.len()].copy_from_slice(&datagram);
            Ok((datagram.len(), gateway_addr()))
        }
    }

    /// An `IkeSocket` that nothing may touch.
    struct Untouchable;

    impl IkeSocket for Untouchable {
        fn send_to(&self, _buf: &[u8], _dest: SocketAddr) -> std::io::Result<usize> {
            panic!("the socket was written to");
        }
        fn set_read_timeout(&self, _dur: Option<Duration>) -> std::io::Result<()> {
            panic!("the socket's timeout was set");
        }
        fn recv_from(&self, _buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
            panic!("the socket was read");
        }
    }

    /// The gateway's address as these tests give it (TEST-NET-1, RFC 5737): nothing is sent anywhere.
    fn gateway_addr() -> SocketAddr {
        "192.0.2.1:500".parse().unwrap()
    }

    /// Turns `client`'s exchange table on, telling the time by the clock returned.
    fn enable(client: &mut Phase1State) -> TestClock {
        let clock = TestClock::new();
        client.exchanges = clock.exchanges();
        client.enable_gateway_quick_mode();
        clock
    }

    fn gateway_qm1(gw_st: &Phase1State, entropy: &mut SeedEntropy) -> Vec<u8> {
        quick::initiate_quick(gw_st, entropy, SkCipher::Aes256Gcm, ([10, 9, 0, 0], [255, 255, 0, 0]), ([0; 4], [0; 4]), 3600).unwrap().0
    }

    /// An Informational of the gateway's with one ESP Delete payload naming `spis`, in that order.
    fn delete_naming(gw_st: &Phase1State, entropy: &mut SeedEntropy, spis: &[u32]) -> Vec<u8> {
        let mut body = IPSEC_DOI.to_be_bytes().to_vec();
        body.extend_from_slice(&[protocol::ESP, 4]);
        body.extend_from_slice(&(spis.len() as u16).to_be_bytes());
        for spi in spis {
            body.extend_from_slice(&spi.to_be_bytes());
        }
        build_single_informational(gw_st, entropy, payload::DELETE, body).unwrap()
    }

    fn esp_named(events: &[PeerEvent]) -> Vec<u32> {
        events.iter().filter_map(|event| match event {
            PeerEvent::Delete { protocol: protocol::ESP, spi, .. } => spi.esp(),
            _ => None,
        }).collect()
    }

    /// With the table passive, ten thousand authentic gateway Quick Mode messages 1 read by `peek` are dropped
    /// undecrypted as they always were: the check reports the tunnel alive, sends nothing, records nothing and
    /// never asks the table's clock, which every enabled reading does.
    #[test]
    fn a_passive_table_lets_peek_drop_ten_thousand_gateway_message_1s_as_before() {
        let (mut client_st, gw_st) = phase1_pair();
        let clock_reads = Arc::new(AtomicUsize::new(0));
        let counted = clock_reads.clone();
        let at = Instant::now();
        client_st.exchanges = ExchangeTable::with_clock(Box::new(move || {
            counted.fetch_add(1, Ordering::Relaxed);
            at
        }));
        let mut ge = SeedEntropy::new(0x6001);
        let sock = Scripted::with((0..10_000).map(|_| gateway_qm1(&gw_st, &mut ge)));
        let got = peek(&sock, &client_st, &mut SeedEntropy::new(0x6002), gateway_addr(), Duration::from_secs(60), 0x1234_5678, None).unwrap();
        assert_eq!(got, Liveness::Alive);
        assert_eq!(sock.reads.get(), 10_001, "every datagram read, then the read that found none");
        assert!(sock.sent().is_empty(), "nothing answered");
        assert_eq!((client_st.exchanges.ids_held(), client_st.exchanges.inbox_held()), (0, 0), "nothing recorded");
        assert_eq!(clock_reads.load(Ordering::Relaxed), 0, "nothing was classified");
        client_st.enable_gateway_quick_mode();
        assert!(client_st.take_peer_quick_modes().is_empty() && client_st.drain_peer_events().is_empty());
    }

    /// A Delete naming two SPIs: with the table passive `peek` acts on the first alone, as before (the
    /// SA in use named first tears the tunnel down; named second it goes unseen); with the table on the wait
    /// gives no verdict and both SPIs are kept, in order, for the reader.
    #[test]
    fn a_passive_table_reads_the_first_spi_of_a_delete_only_and_an_enabled_one_keeps_every_spi() {
        let (current, other) = (0xAAAA_0001u32, 0xBBBB_0002u32);
        for (spis, passive) in [([current, other], Liveness::PeerTornDown), ([other, current], Liveness::Alive)] {
            let (client_st, gw_st) = phase1_pair();
            let sock = Scripted::with([delete_naming(&gw_st, &mut SeedEntropy::new(0x6101), &spis)]);
            let got = peek(&sock, &client_st, &mut SeedEntropy::new(0x6102), gateway_addr(), Duration::from_secs(5), current, None).unwrap();
            assert_eq!(got, passive, "passive, {spis:08x?}");
            let (mut client_st, gw_st) = phase1_pair();
            enable(&mut client_st);
            let sock = Scripted::with([delete_naming(&gw_st, &mut SeedEntropy::new(0x6101), &spis)]);
            let got = peek(&sock, &client_st, &mut SeedEntropy::new(0x6102), gateway_addr(), Duration::from_secs(5), current, None).unwrap();
            assert_eq!(got, Liveness::Alive, "enabled, {spis:08x?}");
            assert_eq!(esp_named(&client_st.drain_peer_events()), spis, "enabled, {spis:08x?}");
        }
    }

    /// With the table on, `probe` waits for its own ACK past a Delete of the ISAKMP SA and an ACK of another
    /// probe -- the Delete is kept, not a verdict -- and without its ACK it is `NoReply`, the Delete kept the same.
    #[test]
    fn an_enabled_probe_keeps_a_delete_for_the_reader_and_waits_for_its_own_ack() {
        let (mut client_st, gw_st) = phase1_pair();
        enable(&mut client_st);
        let mut ge = SeedEntropy::new(0x6201);
        let (_esp, isakmp) = build_delete(&gw_st, &mut ge, 1).unwrap();
        let wrong_ack = build_r_u_there_ack(&gw_st, &mut ge, 76).unwrap();
        let ack = build_r_u_there_ack(&gw_st, &mut ge, 77).unwrap();
        let sock = Scripted::with([isakmp.clone(), wrong_ack.clone(), ack]);
        let got = probe(&sock, &client_st, &mut SeedEntropy::new(0x6202), gateway_addr(), 77, Duration::from_secs(5), 0x1234, None).unwrap();
        assert_eq!(got, Liveness::Alive);
        assert_eq!(sock.sent().len(), 1, "the R-U-THERE, and nothing else");
        let events = client_st.drain_peer_events();
        assert!(matches!(events.as_slice(), [PeerEvent::Delete { protocol: protocol::ISAKMP, .. }]), "{events:?}");
        let sock = Scripted::with([isakmp, wrong_ack]);
        let got = probe(&sock, &client_st, &mut SeedEntropy::new(0x6203), gateway_addr(), 77, Duration::from_secs(5), 0x1234, None).unwrap();
        assert_eq!(got, Liveness::NoReply);
        assert_eq!(client_st.drain_peer_events().len(), 1, "the Delete again, kept again");
    }

    /// With the table on, every R-U-THERE is answered, a repeat of one answered before included, and on a
    /// floated tunnel the ACK goes back marked.
    #[test]
    fn an_enabled_peek_answers_a_repeated_r_u_there_every_time() {
        let (mut client_st, gw_st) = floated_pair();
        enable(&mut client_st);
        let probe_msg = wrap_ike_4500(&build_r_u_there(&gw_st, &mut SeedEntropy::new(0x6301), 7).unwrap());
        let sock = Scripted::with([probe_msg.clone(), probe_msg]);
        let got = peek(&sock, &client_st, &mut SeedEntropy::new(0x6302), gateway_addr(), Duration::from_secs(5), 0, None).unwrap();
        assert_eq!(got, Liveness::Alive);
        let sent = sock.sent();
        assert_eq!(sent.len(), 2, "one ACK per R-U-THERE");
        for ack in &sent {
            assert_eq!(gateway_reads_notify(&gw_st, ack), (notify_type::R_U_THERE_ACK, 7u32.to_be_bytes().to_vec()));
        }
        assert_ne!(sent[0], sent[1], "two ACKs, each under an id of its own");
    }

    /// With the table on, the reads between exchanges still send message 3 again for each repeat of the message 2
    /// it answered -- to the port the tunnel uses -- and send nothing for any other Quick Mode message.
    #[test]
    fn an_enabled_peek_sends_message_3_again_for_a_repeated_message_2() {
        for floated in [false, true] {
            let (mut client_st, gw_st) = if floated { floated_pair() } else { phase1_pair() };
            enable(&mut client_st);
            let (message_2, message_3) = quick_mode_pair(&client_st, 0x1111_2222);
            client_st.finals.retain(&message_2, &message_3);
            let (other, _) = quick_mode_pair(&client_st, 0x3333_4444);
            let frame = |m: &[u8]| if floated { wrap_ike_4500(m) } else { m.to_vec() };
            let sock = Scripted::with([frame(&message_2), frame(&other), frame(&message_2)]);
            let got = peek(&sock, &client_st, &mut SeedEntropy::new(0x6401), gateway_addr(), Duration::from_secs(5), 0, None).unwrap();
            assert_eq!(got, Liveness::Alive, "floated: {floated}");
            let port = if floated { crate::natt_port() } else { gateway_addr().port() };
            let sent = sock.sent.borrow().clone();
            assert_eq!(sent, vec![(frame(&message_3), SocketAddr::new(gateway_addr().ip(), port)); 2], "floated: {floated}");
            assert_eq!(client_st.exchanges.inbox_held(), 0, "floated: {floated}: no message 1 among them");
            let _ = gw_st;
        }
    }

    /// While the table is passive the serving turn does nothing at all: the socket is not touched, whatever the
    /// bounds; with the table on, no datagram to read or no time to wait for one touches it neither.
    #[test]
    fn a_serving_turn_does_not_touch_the_socket_while_the_table_is_passive() {
        let (mut client_st, _gw_st) = phase1_pair();
        for (max, slice) in [(8, Duration::from_millis(20)), (1, Duration::from_secs(1)), (0, Duration::ZERO)] {
            let report = serve_turn(&Untouchable, &client_st, &mut SeedEntropy::new(0x6501), gateway_addr(), max, slice).unwrap();
            assert_eq!(report, TurnReport::default(), "passive, {max} x {slice:?}");
        }
        enable(&mut client_st);
        for (max, slice) in [(0, Duration::from_millis(20)), (8, Duration::ZERO)] {
            let report = serve_turn(&Untouchable, &client_st, &mut SeedEntropy::new(0x6502), gateway_addr(), max, slice).unwrap();
            assert_eq!(report, TurnReport::default(), "enabled, {max} x {slice:?}");
        }
    }

    /// A serving turn reads at most `max_datagrams`, each read bounded by `slice`, and ends at the first read that
    /// finds nothing; what it leaves is the next turn's.
    #[test]
    fn a_serving_turn_reads_at_most_its_count_each_wait_bounded_by_its_slice() {
        let (mut client_st, gw_st) = phase1_pair();
        enable(&mut client_st);
        let mut ge = SeedEntropy::new(0x6601);
        let sock = Scripted::with((1..=10).map(|seq| build_r_u_there(&gw_st, &mut ge, seq).unwrap()));
        let slice = Duration::from_millis(20);
        let mut e = SeedEntropy::new(0x6602);
        let turns: [(TurnReport, usize); 3] = [
            (TurnReport { datagrams_read: 8, acked_dpd: 8, new_quick: 0, events_pushed: 0, answered_again: 0 }, 8),
            (TurnReport { datagrams_read: 2, acked_dpd: 2, new_quick: 0, events_pushed: 0, answered_again: 0 }, 11),
            (TurnReport::default(), 12),
        ];
        for (n, (expected, reads)) in turns.into_iter().enumerate() {
            assert_eq!(serve_turn(&sock, &client_st, &mut e, gateway_addr(), 8, slice).unwrap(), expected, "turn {n}");
            assert_eq!(sock.reads.get(), reads, "turn {n}: reads so far");
        }
        assert!(sock.timeouts.borrow().iter().all(|t| *t == Some(slice)), "every wait is one slice");
        assert_eq!(sock.timeouts.borrow().len(), 12, "one per read");
        assert_eq!(sock.sent().len(), 10, "every R-U-THERE answered");
    }

    /// A read that runs out of time, by either kind the OS gives it, ends the turn quietly; any other error of
    /// the socket is the caller's.
    #[test]
    fn a_serving_turn_ends_quietly_on_a_timeout_and_reports_any_other_socket_error() {
        let (mut client_st, _gw_st) = phase1_pair();
        enable(&mut client_st);
        for end in [std::io::ErrorKind::WouldBlock, std::io::ErrorKind::TimedOut] {
            let sock = Scripted::ending([], end);
            assert_eq!(serve_turn(&sock, &client_st, &mut SeedEntropy::new(0x6701), gateway_addr(), 8, Duration::from_millis(5)).unwrap(), TurnReport::default(), "{end:?}");
        }
        let sock = Scripted::ending([], std::io::ErrorKind::ConnectionReset);
        let got = serve_turn(&sock, &client_st, &mut SeedEntropy::new(0x6702), gateway_addr(), 8, Duration::from_millis(5));
        assert!(matches!(got, Err(DriverError::Io(ref e)) if e.kind() == std::io::ErrorKind::ConnectionReset), "{got:?}");
    }

    /// What one turn does with each kind of datagram: a gateway message 1 goes to the inbox, a Delete naming more
    /// SPIs than the mailbox holds fills it and sets the overflow flag, an ACK nobody waits for and a message
    /// for an exchange of ours nobody waits on here are dropped -- and none of it is answered.
    #[test]
    fn a_serving_turn_keeps_what_it_reads_and_answers_none_of_it() {
        let (mut client_st, gw_st) = phase1_pair();
        enable(&mut client_st);
        let mut ge = SeedEntropy::new(0x6801);
        let msg1 = gateway_qm1(&gw_st, &mut ge);
        let spis: Vec<u32> = (1..=300).collect();
        let many = delete_naming(&gw_st, &mut ge, &spis);
        let late_ack = build_r_u_there_ack(&gw_st, &mut ge, 5).unwrap();
        let ours = client_st.fresh_message_id(crate::ikev1::msgid::MidKind::Quick, &mut SeedEntropy::new(0x6802)).unwrap();
        let (for_ours, _) = quick_mode_pair(&client_st, ours);
        let sock = Scripted::with([msg1.clone(), many, late_ack, for_ours]);
        let report = serve_turn(&sock, &client_st, &mut SeedEntropy::new(0x6803), gateway_addr(), 8, Duration::from_millis(20)).unwrap();
        assert_eq!(report, TurnReport { datagrams_read: 4, acked_dpd: 0, new_quick: 1, events_pushed: crate::ikev1::exchange::MAILBOX_CAP, answered_again: 0 });
        assert!(sock.sent().is_empty(), "nothing answered");
        assert_eq!(client_st.take_peer_quick_modes().iter().map(|q| q.datagram.clone()).collect::<Vec<_>>(), [msg1]);
        assert_eq!(esp_named(&client_st.drain_peer_events()), spis[..crate::ikev1::exchange::MAILBOX_CAP]);
        assert!(client_st.take_peer_event_overflow(), "the mailbox says it is incomplete");
        assert!(!client_st.take_peer_event_overflow(), "once");
    }

    /// On a floated tunnel a turn reads the marked datagrams only: a marked message 1 and a marked R-U-THERE,
    /// whose ACK goes back marked; the unmarked copy of the message 1 is ESP as far as that port is concerned.
    #[test]
    fn a_floated_serving_turn_reads_marked_datagrams_only() {
        let (mut client_st, gw_st) = floated_pair();
        enable(&mut client_st);
        let mut ge = SeedEntropy::new(0x6901);
        let msg1 = gateway_qm1(&gw_st, &mut ge);
        let probe_msg = build_r_u_there(&gw_st, &mut ge, 9).unwrap();
        let sock = Scripted::with([msg1.clone(), wrap_ike_4500(&msg1), wrap_ike_4500(&probe_msg), vec![0xFF]]);
        let report = serve_turn(&sock, &client_st, &mut SeedEntropy::new(0x6902), gateway_addr(), 8, Duration::from_millis(20)).unwrap();
        assert_eq!(report, TurnReport { datagrams_read: 4, acked_dpd: 1, new_quick: 1, events_pushed: 0, answered_again: 0 });
        let sent = sock.sent();
        assert_eq!(sent.len(), 1);
        assert_eq!(gateway_reads_notify(&gw_st, &sent[0]), (notify_type::R_U_THERE_ACK, 9u32.to_be_bytes().to_vec()));
        assert_eq!(client_st.take_peer_quick_modes().iter().map(|q| q.datagram.clone()).collect::<Vec<_>>(), [msg1]);
    }
}
