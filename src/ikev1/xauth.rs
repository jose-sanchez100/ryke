//! IKEv1 XAUTH (draft-beaulieu-ike-xauth) — an ISAKMP Transaction exchange
//! (RFC 2408 exchange type 6) run after Phase 1 and before Quick Mode, when
//! the negotiated auth method was XAUTH-PSK (`InitiatorConfig::xauth`). Unlike
//! Phase 1 / Quick Mode, the **gateway** drives this exchange — it sends the
//! first message asking for credentials, not the client:
//!
//! ```text
//! R (gateway)  →  HDR*, ATTR(REQUEST, [XAUTH_TYPE, XAUTH_USER_NAME, XAUTH_USER_PASSWORD])
//! I (client)   →  HDR*, ATTR(REPLY, [XAUTH_TYPE, XAUTH_USER_NAME=user, XAUTH_USER_PASSWORD=pass])
//! R (gateway)  →  HDR*, ATTR(SET, [XAUTH_STATUS])
//! I (client)   →  HDR*, ATTR(ACK, [])
//! ```
//!
//! Each REQUEST/SET is its own message-id, chosen by the gateway; its IV seeds
//! fresh from `phase1_iv` (RFC 2409 App. B, same as [`super::quick`]'s
//! `phase2_iv`), and the paired REPLY/ACK chains forward from it. The HASH each
//! message carries is the generic `prf(SKEYID_a, M-ID | payloads)` form —
//! exactly what [`super::phase2::parse_encrypted`]/`build_encrypted` already
//! implement, so this module only supplies the XAUTH-specific payload content.

use super::crypto1::{self, AES_BLOCK};
use super::isakmp::{exchange, payload, IsakmpHeader};
use super::modecfg::{cfg, cfg_attr, xauth_status, xauth_type, ConfigPayload};
use super::payloads::Attribute;
use super::phase1::Phase1State;
use super::phase2;
use crate::debug::ike_debug;
use crate::error::IkeError;

/// Hex-format technical (non-secret) protocol values for diagnostics --
/// IVs and message-ids, never decrypted payload content (see `crate::debug`'s
/// own "wire bytes only" policy, which this follows in spirit: these values
/// are derived-but-not-secret coordination state, not credential material).
fn hexfmt(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn xauth_header(cky_i: [u8; 8], cky_r: [u8; 8], msgid: u32) -> IsakmpHeader {
    IsakmpHeader {
        init_cookie: cky_i,
        resp_cookie: cky_r,
        next_payload: payload::NONE,
        version: IsakmpHeader::VERSION_1_0,
        exchange_type: exchange::TRANSACTION,
        flags: 0,
        message_id: msgid,
        length: 0,
    }
}

fn attribute_payload(ps: &[super::isakmp::Payload]) -> Result<&super::isakmp::Payload, IkeError> {
    ps.iter().find(|p| p.payload_type == payload::ATTRIBUTE).ok_or(IkeError::MissingPayload("ATTRIBUTE"))
}

/// Client-side: process the gateway's Transaction REQUEST (asking for
/// credentials) and build the REPLY carrying `user`/`password`.
pub fn build_xauth_reply(st: &Phase1State, request: &[u8], user: &[u8], password: &[u8]) -> Result<Vec<u8>, IkeError> {
    let hdr = IsakmpHeader::parse(request)?;
    if hdr.exchange_type != exchange::TRANSACTION {
        return Err(IkeError::Crypto("expected a Transaction (XAUTH) message"));
    }
    let iv0 = crypto1::phase2_iv(st.prf, &st.phase1_iv, hdr.message_id, AES_BLOCK);
    ike_debug!(
        "XAUTH: request msg-id={:08x}, phase1_iv={}, computed iv0={}, ciphertext_len={}",
        hdr.message_id,
        hexfmt(&st.phase1_iv),
        hexfmt(&iv0),
        request.len().saturating_sub(IsakmpHeader::LEN)
    );
    let (_h, ps, iv1) = phase2::parse_encrypted(request, st.prf, &st.skeyid_a, &st.enc_key, &iv0)?;
    let got = ConfigPayload::parse(&attribute_payload(&ps)?.data)?;
    if got.cfg_type != cfg::REQUEST {
        return Err(IkeError::Crypto("expected an XAUTH REQUEST"));
    }

    let reply = ConfigPayload::new(
        cfg::REPLY,
        got.identifier,
        vec![
            Attribute::short(cfg_attr::XAUTH_TYPE, xauth_type::GENERIC),
            Attribute::long_bytes(cfg_attr::XAUTH_USER_NAME, user.to_vec()),
            Attribute::long_bytes(cfg_attr::XAUTH_USER_PASSWORD, password.to_vec()),
        ],
    );
    let out_hdr = xauth_header(st.cky_i, st.cky_r, hdr.message_id);
    let (msg, _next) = phase2::build_encrypted(out_hdr, st.prf, &st.skeyid_a, &st.enc_key, &iv1, &[(payload::ATTRIBUTE, reply.to_bytes())])?;
    Ok(msg)
}

/// Client-side: process the gateway's Transaction SET (carrying
/// `XAUTH_STATUS`) and build the ACK. Returns the ACK bytes and whether the
/// gateway reported success (`XAUTH_STATUS == OK`) — a caller must check this
/// before proceeding to Quick Mode; a `FAIL` status means the credentials
/// were rejected even though this ISAKMP exchange itself completed cleanly.
pub fn build_xauth_ack(st: &Phase1State, set_message: &[u8]) -> Result<(Vec<u8>, bool), IkeError> {
    let hdr = IsakmpHeader::parse(set_message)?;
    if hdr.exchange_type != exchange::TRANSACTION {
        return Err(IkeError::Crypto("expected a Transaction (XAUTH) message"));
    }
    let iv0 = crypto1::phase2_iv(st.prf, &st.phase1_iv, hdr.message_id, AES_BLOCK);
    ike_debug!(
        "XAUTH: set msg-id={:08x}, phase1_iv={}, computed iv0={}, ciphertext_len={}",
        hdr.message_id,
        hexfmt(&st.phase1_iv),
        hexfmt(&iv0),
        set_message.len().saturating_sub(IsakmpHeader::LEN)
    );
    let (_h, ps, iv1) = phase2::parse_encrypted(set_message, st.prf, &st.skeyid_a, &st.enc_key, &iv0)?;
    let got = ConfigPayload::parse(&attribute_payload(&ps)?.data)?;
    if got.cfg_type != cfg::SET {
        return Err(IkeError::Crypto("expected an XAUTH SET"));
    }
    let ok = got.attr(cfg_attr::XAUTH_STATUS).and_then(Attribute::as_u16) == Some(xauth_status::OK);

    let ack = ConfigPayload::new(cfg::ACK, got.identifier, Vec::new());
    let out_hdr = xauth_header(st.cky_i, st.cky_r, hdr.message_id);
    let (msg, _next) = phase2::build_encrypted(out_hdr, st.prf, &st.skeyid_a, &st.enc_key, &iv1, &[(payload::ATTRIBUTE, ack.to_bytes())])?;
    Ok((msg, ok))
}

/// Gateway-side test double (not a real responder implementation — `ryke`'s
/// `ikev1::Server` doesn't drive XAUTH; this exists only so this module's
/// client-side logic can be round-trip tested without a real gateway).
#[cfg(test)]
pub(crate) mod test_gateway {
    use super::*;

    /// Build the gateway's opening REQUEST for a fresh XAUTH exchange.
    /// Returns the message plus the IV the paired REPLY (same message-id)
    /// chains from — the caller must hand that to [`handle_reply`], not
    /// recompute a fresh `phase2_iv` for the same message-id.
    pub fn build_request(st: &Phase1State, msgid: u32) -> (Vec<u8>, Vec<u8>) {
        let req = ConfigPayload::new(
            cfg::REQUEST,
            0x2222,
            vec![
                Attribute::short(cfg_attr::XAUTH_TYPE, xauth_type::GENERIC),
                Attribute::long_bytes(cfg_attr::XAUTH_USER_NAME, Vec::new()),
                Attribute::long_bytes(cfg_attr::XAUTH_USER_PASSWORD, Vec::new()),
            ],
        );
        let iv0 = crypto1::phase2_iv(st.prf, &st.phase1_iv, msgid, AES_BLOCK);
        let hdr = xauth_header(st.cky_i, st.cky_r, msgid);
        let (msg, next) = phase2::build_encrypted(hdr, st.prf, &st.skeyid_a, &st.enc_key, &iv0, &[(payload::ATTRIBUTE, req.to_bytes())]).unwrap();
        (msg, next)
    }

    /// Process the client's REPLY (using `req_next_iv` from [`build_request`],
    /// chained per RFC 2409 App. B — the REPLY shares the REQUEST's
    /// message-id), returning the extracted (user, password) and the SET
    /// message granting/denying `accept`.
    pub fn handle_reply(st: &Phase1State, reply: &[u8], req_next_iv: &[u8], msgid: u32, accept: bool) -> ((Vec<u8>, Vec<u8>), Vec<u8>) {
        let (_h, ps, _iv1) = phase2::parse_encrypted(reply, st.prf, &st.skeyid_a, &st.enc_key, req_next_iv).unwrap();
        let got = ConfigPayload::parse(&attribute_payload(&ps).unwrap().data).unwrap();
        assert_eq!(got.cfg_type, cfg::REPLY);
        let user = got.attr(cfg_attr::XAUTH_USER_NAME).unwrap().bytes();
        let password = got.attr(cfg_attr::XAUTH_USER_PASSWORD).unwrap().bytes();

        // A fresh message-id for SET (a new Transaction conversation, not
        // chained from REPLY) -- must differ from `msgid`, but doesn't need to
        // be adjacent; wrapping_add(1) is just a convenient distinct value.
        let set_msgid = msgid.wrapping_add(1);
        let status = if accept { xauth_status::OK } else { xauth_status::FAIL };
        let set = ConfigPayload::new(cfg::SET, 0x3333, vec![Attribute::short(cfg_attr::XAUTH_STATUS, status)]);
        let iv0_set = crypto1::phase2_iv(st.prf, &st.phase1_iv, set_msgid, AES_BLOCK);
        let set_hdr = xauth_header(st.cky_i, st.cky_r, set_msgid);
        let (set_msg, _next) = phase2::build_encrypted(set_hdr, st.prf, &st.skeyid_a, &st.enc_key, &iv0_set, &[(payload::ATTRIBUTE, set.to_bytes())]).unwrap();
        ((user, password), set_msg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::DhGroup;
    use crate::entropy::SeedEntropy;
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
            xauth: true,
            xauth_creds: None,
            ts_local: ([0, 0, 0, 0], [0, 0, 0, 0]),
            ts_remote: ([0, 0, 0, 0], [0, 0, 0, 0]),
            esp_cipher: SkCipher::Aes256Gcm,
            pfs_group: None,
            mode_cfg: false,
            mode: Ikev1ExchangeMode::Aggressive,
            p1_lifetime_secs: 28800,
            p2_lifetime_secs: 3600,
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

    #[test]
    fn xauth_round_trip_succeeds_with_correct_status() {
        let (client_st, gw_st) = phase1_pair();
        let (request, req_next_iv) = test_gateway::build_request(&gw_st, 0x1000_0001);
        let reply = build_xauth_reply(&client_st, &request, b"alice", b"s3cret").unwrap();
        let ((user, password), set_msg) = test_gateway::handle_reply(&gw_st, &reply, &req_next_iv, 0x1000_0001, true);
        assert_eq!(user, b"alice");
        assert_eq!(password, b"s3cret");
        let (_ack, ok) = build_xauth_ack(&client_st, &set_msg).unwrap();
        assert!(ok, "gateway granted XAUTH_STATUS=OK");
    }

    #[test]
    fn xauth_reports_failure_status_without_erroring() {
        // A rejected status is a valid, well-formed exchange -- the caller
        // must check the returned bool, not treat every completed exchange
        // as a successful login.
        let (client_st, gw_st) = phase1_pair();
        let (request, req_next_iv) = test_gateway::build_request(&gw_st, 0x2000_0001);
        let reply = build_xauth_reply(&client_st, &request, b"alice", b"wrong").unwrap();
        let (_creds, set_msg) = test_gateway::handle_reply(&gw_st, &reply, &req_next_iv, 0x2000_0001, false);
        let (_ack, ok) = build_xauth_ack(&client_st, &set_msg).unwrap();
        assert!(!ok, "gateway denied XAUTH_STATUS=FAIL must surface as false");
    }
}
