//! IKEv1 Informational exchange (RFC 2408 §4.8 / RFC 2409 §5.7) — both
//! directions of a graceful-disconnect Delete notification: [`build_delete`]
//! builds one telling the gateway this side is tearing down its ISAKMP SA
//! (and, implicitly, every Quick Mode SA under it) instead of just vanishing
//! and leaving the gateway to notice via DPD/lifetime expiry; [`peek`] checks
//! for the same notification arriving unprompted from the gateway (e.g. an
//! admin disconnecting the dialup session from the FortiGate side) so this
//! side can tear down immediately too, instead of leaving a dead kernel XFRM
//! SA up until *our* DPD/lifetime would have noticed. Fire-and-forget: RFC
//! 2408 defines no acknowledgement for a Delete notification in either
//! direction — mirrors
//! [`crate::ikev2::session::LivenessSession::close`]/[`crate::ikev2::session::LivenessSession::peek`]'s
//! own "best-effort, no ack expected" IKEv2 counterparts (IKEv2's variant
//! *does* ack, since its INFORMATIONAL is a real request/response exchange —
//! IKEv1's Delete notification is fire-and-forget on both ends, so `peek`
//! sends nothing back).
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
//! `HASH(1) = prf(SKEYID_a, M-ID | D-payload)` (RFC 2409 §5.7) — the same
//! "HASH covers M-ID | payloads-after-hash" shape
//! [`super::phase2::build_encrypted`] already implements for
//! Mode-Config/Xauth, reused as-is here.

use super::crypto1::{self, AES_BLOCK};
use super::isakmp::{exchange, payload, IsakmpHeader};
use super::payloads::{protocol, IPSEC_DOI};
use super::phase1::Phase1State;
use super::phase2;
use crate::entropy::Entropy;
use crate::error::IkeError;

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

/// Build one encrypted Informational message carrying a single Delete
/// payload, with its own fresh random message-id (RFC 2409 Appendix B: the
/// IV for a new message-id is `HASH(phase1_iv | M-ID)`, computed via
/// [`crypto1::phase2_iv`]) and its own `HASH(1)` covering just that payload.
fn build_single_delete(st: &Phase1State, entropy: &mut impl Entropy, protocol_id: u8, spi: &[u8]) -> Result<Vec<u8>, IkeError> {
    let mut mid_b = [0u8; 4];
    entropy.fill(&mut mid_b);
    let msgid = u32::from_be_bytes(mid_b) | 1; // non-zero

    let del = delete_body(protocol_id, spi);
    let iv0 = crypto1::phase2_iv(st.prf, &st.phase1_iv, msgid, AES_BLOCK);
    let hdr = info_header(st.cky_i, st.cky_r, msgid);
    let (msg, _next) = phase2::build_encrypted(hdr, st.prf, &st.skeyid_a, &st.enc_key, &iv0, &[(payload::DELETE, del)])?;
    Ok(msg)
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
    let esp_msg = build_single_delete(st, entropy, protocol::ESP, &esp_spi.to_be_bytes())?;
    let isakmp_spi = [st.cky_i.as_slice(), st.cky_r.as_slice()].concat();
    let isakmp_msg = build_single_delete(st, entropy, protocol::ISAKMP, &isakmp_spi)?;
    Ok((esp_msg, isakmp_msg))
}

/// Result of [`peek`]: whether an unsolicited Informational Delete from the
/// peer was found sitting on the socket.
#[derive(Debug, PartialEq, Eq)]
pub enum Peek {
    /// Nothing pending — IKEv1 defines no periodic liveness ping of its own
    /// (unlike IKEv2's empty-INFORMATIONAL DPD), so this is the ordinary,
    /// expected result on every check; it does not by itself confirm the
    /// peer is still alive, only that it hasn't said anything unprompted.
    /// Detecting a *silent* drop (no Delete ever sent) needs an active probe
    /// this module doesn't implement yet — see the module doc.
    Nothing,
    /// The peer sent an unsolicited Informational carrying a Delete payload
    /// — it tore the tunnel down on its own initiative (e.g. an admin
    /// disconnected the dialup session on the gateway).
    PeerTornDown,
}

/// Bounded (by `timeout`) check of `sock` for a pending, unsolicited
/// encrypted Informational message from the peer identified by `st`'s
/// cookie pair, decrypting it under `st`'s Phase-1 keys and classifying it.
/// Anything that isn't a well-formed encrypted Informational for this
/// ISAKMP SA (garbage, a message for a different exchange/SA, a decrypt/HASH
/// failure) is silently skipped rather than surfaced as an error — mirrors
/// [`crate::ikev2::session::LivenessSession::peek`]'s own "best-effort,
/// ignore anything that can't be cleanly attributed" stance. A UDP datagram
/// the peer already sent sits in the kernel's receive buffer regardless of
/// how long ago it arrived, so even a short `timeout` reliably catches
/// anything already pending — this never *waits* for something new to
/// arrive the way an active probe would.
pub fn peek(sock: &std::net::UdpSocket, st: &Phase1State, timeout: std::time::Duration) -> std::io::Result<Peek> {
    sock.set_read_timeout(Some(timeout))?;
    let mut buf = [0u8; 8192];
    loop {
        let n = match sock.recv(&mut buf) {
            Ok(n) => n,
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
                return Ok(Peek::Nothing);
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
            return Ok(Peek::PeerTornDown);
        }
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
        let (msg1, ai) = initiate_aggressive(&icfg, &mut ie);
        let (msg2, rstate) = respond_aggressive(&rcfg, &msg1, &mut re).unwrap();
        let (msg3, istate) = ai.complete(&msg2).unwrap();
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
    fn peek_reports_nothing_when_no_datagram_is_pending() {
        let (client_st, _gw_st) = phase1_pair();
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let got = peek(&sock, &client_st, std::time::Duration::from_millis(20)).unwrap();
        assert_eq!(got, Peek::Nothing);
    }

    #[test]
    fn peek_classifies_an_unsolicited_delete_from_the_peer() {
        let (client_st, gw_st) = phase1_pair();
        let client_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let client_addr = client_sock.local_addr().unwrap();
        let gw_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();

        let mut e = SeedEntropy::new(0xFEED);
        let (esp_msg, _isakmp_msg) = build_delete(&gw_st, &mut e, 0xAAAA_BBBB).unwrap();
        gw_sock.send_to(&esp_msg, client_addr).unwrap();

        let got = peek(&client_sock, &client_st, std::time::Duration::from_millis(200)).unwrap();
        assert_eq!(got, Peek::PeerTornDown);
    }

    #[test]
    fn peek_ignores_an_unrelated_message_and_times_out_to_nothing() {
        let (client_st, gw_st) = phase1_pair();
        let client_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let client_addr = client_sock.local_addr().unwrap();
        let gw_sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();

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

        let got = peek(&client_sock, &client_st, std::time::Duration::from_millis(100)).unwrap();
        assert_eq!(got, Peek::Nothing);
    }
}
