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

use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use super::crypto1::{self, AES_BLOCK};
use super::isakmp::{exchange, payload, IsakmpHeader};
use super::payloads::{protocol, IPSEC_DOI};
use super::phase1::Phase1State;
use super::phase2;
use crate::entropy::Entropy;
use crate::error::IkeError;
use crate::transport::DriverError;

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
fn parse_notify(body: &[u8]) -> Option<(u16, &[u8])> {
    let spi_size = *body.get(5)? as usize;
    let msg_type = u16::from_be_bytes([*body.get(6)?, *body.get(7)?]);
    let data = body.get(8 + spi_size..)?;
    Some((msg_type, data))
}

/// RFC 3706 §2 Notify Message Types.
mod notify_type {
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

    let iv0 = crypto1::phase2_iv(st.prf, &st.phase1_iv, msgid, AES_BLOCK);
    let hdr = info_header(st.cky_i, st.cky_r, msgid);
    let (msg, _next) = phase2::build_encrypted(hdr, st.prf, &st.skeyid_a, &st.enc_key, &iv0, &[(payload_type, body)])?;
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
    let esp_msg = build_single_informational(st, entropy, payload::DELETE, delete_body(protocol::ESP, &esp_spi.to_be_bytes()))?;
    let isakmp_msg = build_single_informational(st, entropy, payload::DELETE, delete_body(protocol::ISAKMP, &isakmp_spi(st)))?;
    Ok((esp_msg, isakmp_msg))
}

/// Result of [`peek`]/[`probe`] — mirrors
/// [`crate::ikev2::session::Liveness`]'s three-variant shape, kept as its own
/// local type rather than shared across the ikev1/ikev2 modules (they don't
/// otherwise depend on each other).
#[derive(Debug, PartialEq, Eq)]
pub enum Liveness {
    /// [`probe`]: the peer answered with a matching R-U-THERE-ACK. [`peek`]:
    /// nothing pending — IKEv1 defines no periodic liveness ping of its own,
    /// so silence here is the ordinary, expected result on every passive
    /// check, same as [`crate::ikev2::session::LivenessSession::peek`]'s own
    /// "silence is alive" stance when it sent nothing itself.
    Alive,
    /// The peer sent an unsolicited Informational carrying a Delete payload
    /// — it tore the tunnel down on its own initiative (e.g. an admin
    /// disconnected the dialup session on the gateway).
    PeerTornDown,
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
    /// An R-U-THERE-ACK matching the sequence number `watch` was told to
    /// expect (only possible when called from [`probe`]).
    AckMatched,
}

/// Bounded (by `timeout`) watch of `sock` for encrypted Informational
/// traffic tied to `st`'s ISAKMP SA (cookie pair) — shared by [`peek`]
/// (`expect_ack_seq: None`) and [`probe`] (`Some(seq)` for the sequence
/// number it just sent), mirroring
/// [`crate::ikev2::session::LivenessSession::recv_and_classify`]'s shape.
/// Three-way classification: a Delete ends the wait immediately as
/// [`Seen::PeerTornDown`]; an incoming R-U-THERE from the peer is always
/// auto-ack'd via [`build_r_u_there_ack`] (RFC 3706 requires answering one
/// whenever seen, regardless of whether this call is a passive `peek` or an
/// active `probe`) and the wait continues; an R-U-THERE-ACK matching
/// `expect_ack_seq` ends the wait as [`Seen::AckMatched`]; anything else
/// (garbage, a message for a different exchange/SA, a decrypt/HASH failure,
/// a stale/mismatched ack, a failed auto-ack send) is silently skipped
/// rather than surfaced as an error, same best-effort stance this module
/// has always taken for Delete detection. A UDP datagram the peer already
/// sent sits in the kernel's receive buffer regardless of how long ago it
/// arrived, so even a short `timeout` reliably catches anything already
/// pending.
fn watch(sock: &UdpSocket, st: &Phase1State, entropy: &mut impl Entropy, peer: SocketAddr, timeout: Duration, expect_ack_seq: Option<u32>) -> std::io::Result<Seen> {
    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; 8192];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(Seen::Nothing);
        }
        sock.set_read_timeout(Some(remaining))?;
        let n = match sock.recv(&mut buf) {
            Ok(n) => n,
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
                return Ok(Seen::Nothing);
            }
            Err(e) => return Err(e),
        };
        let Ok(header) = IsakmpHeader::parse(&buf[..n]) else { continue };
        if header.exchange_type != exchange::INFORMATIONAL || header.init_cookie != st.cky_i || header.resp_cookie != st.cky_r {
            continue; // not an Informational for this ISAKMP SA -- ignore, keep waiting out the timeout
        }
        let iv0 = crypto1::phase2_iv(st.prf, &st.phase1_iv, header.message_id, AES_BLOCK);
        let Ok((_h, payloads, _next)) = phase2::parse_encrypted(&buf[..n], st.prf, &st.skeyid_a, &st.enc_key, &iv0) else {
            continue;
        };
        if payloads.iter().any(|p| p.payload_type == payload::DELETE) {
            return Ok(Seen::PeerTornDown);
        }
        let Some(notify) = payloads.iter().find(|p| p.payload_type == payload::NOTIFY) else { continue };
        let Some((msg_type, data)) = parse_notify(&notify.data) else { continue };
        match msg_type {
            notify_type::R_U_THERE => {
                if let Ok(seq_bytes) = <[u8; 4]>::try_from(data) {
                    if let Ok(ack) = build_r_u_there_ack(st, entropy, u32::from_be_bytes(seq_bytes)) {
                        let _ = sock.send_to(&ack, peer);
                    }
                }
            }
            notify_type::R_U_THERE_ACK => {
                if let (Some(want), Ok(seq_bytes)) = (expect_ack_seq, <[u8; 4]>::try_from(data)) {
                    if u32::from_be_bytes(seq_bytes) == want {
                        return Ok(Seen::AckMatched);
                    }
                }
            }
            _ => {}
        }
    }
}

/// Passive check: has the peer said anything unprompted (a Delete, or its
/// own R-U-THERE probe, which gets auto-ack'd) since the last check? Safe to
/// call on every routine status poll instead of [`probe`]'s full round trip
/// — see [`watch`]'s doc for the shared classification and
/// [`Liveness::Alive`]'s doc for why silence here means alive, not unknown.
pub fn peek(sock: &UdpSocket, st: &Phase1State, entropy: &mut impl Entropy, peer: SocketAddr, timeout: Duration) -> Result<Liveness, DriverError> {
    match watch(sock, st, entropy, peer, timeout, None)? {
        Seen::Nothing | Seen::AckMatched => Ok(Liveness::Alive),
        Seen::PeerTornDown => Ok(Liveness::PeerTornDown),
    }
}

/// Active DPD check (RFC 3706): send an R-U-THERE carrying `seq` and wait up
/// to `timeout` for the matching R-U-THERE-ACK. Only ever call this once
/// [`Phase1State::peer_supports_dpd`] is `true` — RFC 3706 requires the peer
/// to have advertised support first; a caller that never confirmed that
/// should keep using [`peek`] only, exactly as before this function existed.
pub fn probe(sock: &UdpSocket, st: &Phase1State, entropy: &mut impl Entropy, peer: SocketAddr, seq: u32, timeout: Duration) -> Result<Liveness, DriverError> {
    let msg = build_r_u_there(st, entropy, seq)?;
    sock.send_to(&msg, peer)?;
    match watch(sock, st, entropy, peer, timeout, Some(seq))? {
        Seen::Nothing => Ok(Liveness::NoReply),
        Seen::PeerTornDown => Ok(Liveness::PeerTornDown),
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
            mode: Ikev1ExchangeMode::Aggressive,
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
        let iv0 = crypto1::phase2_iv(gw_st.prf, &gw_st.phase1_iv, hdr.message_id, AES_BLOCK);
        let (_h, payloads, _next) = phase2::parse_encrypted(msg, gw_st.prf, &gw_st.skeyid_a, &gw_st.enc_key, &iv0).unwrap();
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
        let iv0 = crypto1::phase2_iv(gw_st.prf, &gw_st.phase1_iv, hdr.message_id, AES_BLOCK);
        let bad_key = vec![0x99u8; gw_st.skeyid_a.len()];
        assert!(phase2::parse_encrypted(&esp_msg, gw_st.prf, &bad_key, &gw_st.enc_key, &iv0).is_err());
    }

    #[test]
    fn peek_reports_alive_when_no_datagram_is_pending() {
        let (client_st, _gw_st) = phase1_pair();
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
        let mut e = SeedEntropy::new(0x1);
        let got = peek(&sock, &client_st, &mut e, peer, std::time::Duration::from_millis(20)).unwrap();
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

        let got = peek(&client_sock, &client_st, &mut e, gw_addr, std::time::Duration::from_millis(200)).unwrap();
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
        let got = peek(&client_sock, &client_st, &mut e, gw_addr, std::time::Duration::from_millis(100)).unwrap();
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
        let got = peek(&client_sock, &client_st, &mut ce, gw_addr, std::time::Duration::from_millis(200)).unwrap();
        assert_eq!(got, Liveness::Alive);

        // The gateway should now have our ACK sitting on its own socket.
        gw_sock.set_read_timeout(Some(std::time::Duration::from_millis(200))).unwrap();
        let mut buf = [0u8; 8192];
        let n = gw_sock.recv(&mut buf).unwrap();
        let hdr = IsakmpHeader::parse(&buf[..n]).unwrap();
        let iv0 = crypto1::phase2_iv(gw_st.prf, &gw_st.phase1_iv, hdr.message_id, AES_BLOCK);
        let (_h, payloads, _next) = phase2::parse_encrypted(&buf[..n], gw_st.prf, &gw_st.skeyid_a, &gw_st.enc_key, &iv0).unwrap();
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
            let iv0 = crypto1::phase2_iv(gw_st.prf, &gw_st.phase1_iv, hdr.message_id, AES_BLOCK);
            let (_h, payloads, _next) = phase2::parse_encrypted(&buf[..n], gw_st.prf, &gw_st.skeyid_a, &gw_st.enc_key, &iv0).unwrap();
            let notify = payloads.into_iter().find(|p| p.payload_type == payload::NOTIFY).unwrap();
            let (msg_type, data) = parse_notify(&notify.data).unwrap();
            assert_eq!(msg_type, notify_type::R_U_THERE);
            let seq = u32::from_be_bytes(<[u8; 4]>::try_from(data).unwrap());
            let mut ge = SeedEntropy::new(0x5);
            let ack = build_r_u_there_ack(&gw_st, &mut ge, seq).unwrap();
            gw_sock.send_to(&ack, client_addr).unwrap();
        });

        let mut ce = SeedEntropy::new(0x6);
        let got = probe(&client_sock, &client_st, &mut ce, gw_addr, 42, std::time::Duration::from_secs(2)).unwrap();
        assert_eq!(got, Liveness::Alive);
        responder.join().unwrap();
    }

    #[test]
    fn probe_times_out_to_no_reply_when_nothing_answers() {
        let (client_st, _gw_st) = phase1_pair();
        let client_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let dead_peer: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
        let mut e = SeedEntropy::new(0x7);
        let got = probe(&client_sock, &client_st, &mut e, dead_peer, 1, std::time::Duration::from_millis(50)).unwrap();
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
        let got = probe(&client_sock, &client_st, &mut ce, gw_addr, 99, std::time::Duration::from_secs(2)).unwrap();
        assert_eq!(got, Liveness::PeerTornDown);
        responder.join().unwrap();
    }
}
