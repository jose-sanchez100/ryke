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
use super::isakmp::{exchange, payload, IsakmpHeader};
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
fn notify_body(protocol_id: u8, spi: &[u8], msg_type: u16, data: &[u8]) -> Vec<u8> {
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

/// RFC 3706 §2 Notify Message Types.
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
    let mut mid_b = [0u8; 4];
    entropy.fill(&mut mid_b);
    let msgid = u32::from_be_bytes(mid_b) | 1; // non-zero

    let iv0 = crypto1::phase2_iv(st.prf, &st.phase1_iv, msgid, st.enc_block);
    let hdr = info_header(st.cky_i, st.cky_r, msgid);
    let (msg, _next) = phase2::build_encrypted(hdr, st.prf, &st.skeyid_a, &st.enc_key, st.enc_block, &iv0, &[(payload_type, body)])?;
    Ok(msg)
}

/// This ISAKMP SA's cookie pair, in the `SPI` shape RFC 2408 §2.5.3 uses to
/// identify the whole Phase-1 SA in a Delete or Notify payload (SPI Size 16,
/// one SPI = `cky_i | cky_r`).
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
/// pair (RFC 2408 §2.5.3 — SPI Size 16, one SPI = `cky_i | cky_r`) — same
/// order and same two-separate-exchanges shape strongSwan's IKEv1 task
/// manager uses (see this module's doc comment). The ESP delete is
/// technically redundant on its own (deleting the ISAKMP SA implicitly tears
/// down every Phase-2 SA under it, RFC 2408 §1.4) but sent anyway, matching
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
/// when `st` floated to UDP 4500 (RFC 3947/3948 §2.2): a datagram on 4500
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
    /// up. RFC 2408 treats Phase 2 SAs as independent of Phase 1 and of each
    /// other (only a Delete naming Protocol-ID ISAKMP takes down the parent
    /// and everything under it, never the reverse), so this does not tear
    /// down the tunnel: the caller drops its own local state for that family
    /// and renegotiates a replacement from scratch. Only possible when the
    /// caller passed a `current_peer_spi_ipv6` to [`peek`]/[`probe`] (i.e.
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
    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; 8192];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
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
                    let named = <[u8; 4]>::try_from(spi).ok().map(u32::from_be_bytes);
                    if named == Some(current_peer_spi) {
                        if current_peer_spi_ipv6.is_some() {
                            ike_debug!("INFORMATIONAL: peer deleted the primary CHILD SA (spi_in={current_peer_spi:08x}) while the IPv6 one is still up -- renegotiating it instead of tearing down");
                            Some(Seen::ChildDeleted(ChildFamily::Primary))
                        } else {
                            ike_debug!("INFORMATIONAL: peer sent an ESP Delete for the CHILD SA in use (spi_in={current_peer_spi:08x}) -- tunnel torn down by the gateway");
                            Some(Seen::PeerTornDown)
                        }
                    } else if current_peer_spi_ipv6.is_some() && named == current_peer_spi_ipv6 {
                        ike_debug!("INFORMATIONAL: peer deleted the IPv6 CHILD SA (spi_in={:08x}) while the primary is still up -- renegotiating it instead of tearing down", named.unwrap());
                        Some(Seen::ChildDeleted(ChildFamily::Ipv6))
                    } else {
                        ike_debug!(
                            "INFORMATIONAL: ignoring peer ESP Delete for spi={} (the CHILD SA(s) in use are spi_in={current_peer_spi:08x}{})",
                            named.map_or_else(|| "<malformed>".to_string(), |v| format!("{v:08x}")),
                            current_peer_spi_ipv6.map_or_else(String::new, |v| format!("/{v:08x}"))
                        );
                        None
                    }
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
/// [`watch`] takes.
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

/// Test double for a peer's rejection: an encrypted Informational carrying an
/// error Notify of `msg_type` (the shape [`peer_error_notify`] recognizes).
#[cfg(test)]
pub(crate) fn build_error_notify(st: &Phase1State, entropy: &mut impl Entropy, msg_type: u16) -> Result<Vec<u8>, IkeError> {
    build_single_informational(st, entropy, payload::NOTIFY, notify_body(protocol::ISAKMP, &isakmp_spi(st), msg_type, &[]))
}

/// RFC 2408 §3.14.1 names for the error Notify types a Quick Mode rejection
/// realistically carries; everything else reads as a generic error.
fn error_notify_name(t: u16) -> &'static str {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::DhGroup;
    use crate::entropy::SeedEntropy;
    use crate::ikev1::isakmp::flags;
    use crate::ikev1::payloads::Id;
    use crate::ikev1::phase1::{
        initiate_aggressive, respond_aggressive, Ikev1ExchangeMode, Ikev1LocalAuth, InitiatorConfig, Phase1Config,
    };
    use crate::ikev2::sk::SkCipher;

    fn phase1_pair() -> (Phase1State, Phase1State) {
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
    /// and IPv6 stayed permanently dead with no recovery. RFC 2408 treats
    /// Phase 2 SAs as independent (deleting one never implies deleting the
    /// ISAKMP SA or any other Phase 2 SA under it), so this must be
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
    /// IPv6 CHILD SA and the ISAKMP SA itself -- wrong per RFC 2408, and
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

    fn floated_pair() -> (Phase1State, Phase1State) {
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

    // --- Quick Mode message 3 recovery (RFC 2408 §3.1, Commit Bit NOTE). The liveness checks are what
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
}
