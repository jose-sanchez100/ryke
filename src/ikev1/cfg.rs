//! IKEv1 Mode-Config (draft-dukes-ike-mode-cfg) address assignment — an
//! ISAKMP Transaction exchange (RFC 2408 exchange type 6, same framing as
//! [`super::xauth`]) run after XAUTH (if any) and before Quick Mode, when the
//! caller wants an assigned inner IPv4. Unlike XAUTH, the **client** drives
//! this exchange:
//!
//! ```text
//! I (client)   →  HDR*, ATTR(REQUEST, [INTERNAL_IP4_ADDRESS, ...])
//! R (gateway)  →  HDR*, ATTR(REPLY, [INTERNAL_IP4_ADDRESS=addr, ...])
//! ```
//!
//! REQUEST and REPLY share one message-id, the same IV-chaining convention
//! [`super::xauth`]'s own REQUEST/REPLY pair uses (the paired SET/ACK is a
//! separate, later Transaction with its own fresh message-id — this
//! exchange has no such second round).
//!
//! Confirmed live against a real FortiGate: an IKEv1 dialup policy that
//! requires this round rejects the following Quick Mode proposal outright
//! ("peer has not completed Configuration Method") if it's skipped.

use super::crypto1::{self, AES_BLOCK};
use super::isakmp::{exchange, payload, IsakmpHeader, Payload};
use super::modecfg::{cfg, ConfigPayload};
use super::phase1::Phase1State;
use super::phase2;
use crate::error::IkeError;

fn cfg_header(cky_i: [u8; 8], cky_r: [u8; 8], msgid: u32) -> IsakmpHeader {
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

fn attribute_payload(ps: &[Payload]) -> Result<&Payload, IkeError> {
    ps.iter().find(|p| p.payload_type == payload::ATTRIBUTE).ok_or(IkeError::MissingPayload("ATTRIBUTE"))
}

/// Build a fresh CFG_REQUEST for `msgid` (caller-chosen, must be non-zero and
/// distinct from any other in-flight exchange's message-id on this Phase 1 —
/// same convention as [`super::quick::initiate_quick`]'s own SPI/msgid).
/// Returns the request bytes and the IV the paired CFG_REPLY (same
/// message-id) chains from — pass it to [`parse_cfg_reply`].
pub fn build_cfg_request(st: &Phase1State, msgid: u32) -> Result<(Vec<u8>, Vec<u8>), IkeError> {
    build_cfg_request_with(st, msgid, false)
}

/// [`build_cfg_request`], optionally also asking for an inner IPv6 address /
/// DNS / split-tunnel subnet ([`ConfigPayload::request_dual_stack`]) in the
/// same round. `ipv6: false` is byte-for-byte the IPv4-only request.
pub fn build_cfg_request_with(st: &Phase1State, msgid: u32, ipv6: bool) -> Result<(Vec<u8>, Vec<u8>), IkeError> {
    let req = if ipv6 { ConfigPayload::request_dual_stack(msgid as u16) } else { ConfigPayload::request_ipv4(msgid as u16) };
    let iv0 = crypto1::phase2_iv(st.prf, &st.phase1_iv, msgid, AES_BLOCK);
    let hdr = cfg_header(st.cky_i, st.cky_r, msgid);
    let (msg, next_iv) = phase2::build_encrypted(hdr, st.prf, &st.skeyid_a, &st.enc_key, &iv0, &[(payload::ATTRIBUTE, req.to_bytes())])?;
    Ok((msg, next_iv))
}

/// Decrypt and parse the gateway's CFG_REPLY, chained from `req_next_iv`
/// (returned by [`build_cfg_request`]).
pub fn parse_cfg_reply(st: &Phase1State, reply: &[u8], req_next_iv: &[u8]) -> Result<ConfigPayload, IkeError> {
    let hdr = IsakmpHeader::parse(reply)?;
    if hdr.exchange_type != exchange::TRANSACTION {
        return Err(IkeError::Crypto("expected a Transaction (Mode-Config) message"));
    }
    let (_h, ps, _next) = phase2::parse_encrypted(reply, st.prf, &st.skeyid_a, &st.enc_key, req_next_iv)?;
    let got = ConfigPayload::parse(&attribute_payload(&ps)?.data)?;
    if got.cfg_type != cfg::REPLY {
        return Err(IkeError::Crypto("expected a Mode-Config REPLY"));
    }
    Ok(got)
}

/// Gateway-side test double (not a real responder implementation — mirrors
/// [`super::xauth::test_gateway`]'s role: this exists only so the
/// client-side logic above can be round-trip tested without a real gateway).
#[cfg(test)]
pub(crate) mod test_gateway {
    use super::*;
    use crate::ikev1::modecfg::cfg_attr;
    use crate::ikev1::payloads::Attribute;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// [`handle_request`]'s dual-stack twin: same IPv4 grant, plus `addr6`
    /// (17-octet address+prefix form), one IPv6 DNS server and one split
    /// subnet -- what a gateway with IPv6 configured answers a
    /// [`build_cfg_request_with`]`(.., true)` with.
    pub fn handle_request_dual_stack(st: &Phase1State, request: &[u8], msgid: u32, addr: Ipv4Addr, addr6: (Ipv6Addr, u8)) -> Vec<u8> {
        let iv0 = crypto1::phase2_iv(st.prf, &st.phase1_iv, msgid, AES_BLOCK);
        let (_h, ps, iv1) = phase2::parse_encrypted(request, st.prf, &st.skeyid_a, &st.enc_key, &iv0).unwrap();
        let got = ConfigPayload::parse(&attribute_payload(&ps).unwrap().data).unwrap();
        assert_eq!(got.cfg_type, cfg::REQUEST);

        let mut a6 = addr6.0.octets().to_vec();
        a6.push(addr6.1);
        let mut subnet6 = "fd00:0:0:10::".parse::<Ipv6Addr>().unwrap().octets().to_vec();
        subnet6.push(60);
        let reply = ConfigPayload::new(
            cfg::REPLY,
            got.identifier,
            vec![
                Attribute::long_bytes(cfg_attr::INTERNAL_IP4_ADDRESS, addr.octets().to_vec()),
                Attribute::long_bytes(cfg_attr::INTERNAL_IP4_NETMASK, [255, 255, 255, 0]),
                Attribute::long_bytes(cfg_attr::INTERNAL_IP6_ADDRESS, a6),
                Attribute::long_bytes(cfg_attr::INTERNAL_IP6_DNS, "2001:db8::53".parse::<Ipv6Addr>().unwrap().octets().to_vec()),
                Attribute::long_bytes(cfg_attr::INTERNAL_IP6_SUBNET, subnet6),
            ],
        );
        let hdr = cfg_header(st.cky_i, st.cky_r, msgid);
        let (msg, _next) = phase2::build_encrypted(hdr, st.prf, &st.skeyid_a, &st.enc_key, &iv1, &[(payload::ATTRIBUTE, reply.to_bytes())]).unwrap();
        msg
    }

    /// Decrypt the client's REQUEST (using `iv0` computed the same way
    /// [`build_cfg_request`] did) and build a REPLY granting `addr` (plus a
    /// fixed /24 netmask and one DNS server) on the same message-id.
    pub fn handle_request(st: &Phase1State, request: &[u8], msgid: u32, addr: Ipv4Addr) -> Vec<u8> {
        let iv0 = crypto1::phase2_iv(st.prf, &st.phase1_iv, msgid, AES_BLOCK);
        let (_h, ps, iv1) = phase2::parse_encrypted(request, st.prf, &st.skeyid_a, &st.enc_key, &iv0).unwrap();
        let got = ConfigPayload::parse(&attribute_payload(&ps).unwrap().data).unwrap();
        assert_eq!(got.cfg_type, cfg::REQUEST);

        let reply = ConfigPayload::new(
            cfg::REPLY,
            got.identifier,
            vec![
                Attribute::long_bytes(cfg_attr::INTERNAL_IP4_ADDRESS, addr.octets().to_vec()),
                Attribute::long_bytes(cfg_attr::INTERNAL_IP4_NETMASK, [255, 255, 255, 0]),
                Attribute::long_bytes(cfg_attr::INTERNAL_IP4_DNS, [8, 8, 8, 8]),
            ],
        );
        let hdr = cfg_header(st.cky_i, st.cky_r, msgid);
        let (msg, _next) = phase2::build_encrypted(hdr, st.prf, &st.skeyid_a, &st.enc_key, &iv1, &[(payload::ATTRIBUTE, reply.to_bytes())]).unwrap();
        msg
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
    use std::net::{Ipv4Addr, Ipv6Addr};

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
        let mut ie = SeedEntropy::new(0xCCCC);
        let mut re = SeedEntropy::new(0xDDDD);
        let (msg1, ai) = initiate_aggressive(&icfg, &mut ie, "10.1.1.1:500".parse().unwrap(), "192.168.0.1:500".parse().unwrap());
        let (msg2, rstate) = respond_aggressive(&rcfg, &msg1, &mut re, "192.168.0.1:500".parse().unwrap(), "10.1.1.1:500".parse().unwrap()).unwrap();
        let (msg3, istate) = ai.complete(&msg2, "10.1.1.1:500".parse().unwrap(), "192.168.0.1:500".parse().unwrap()).unwrap();
        rstate.verify_hash_i(&msg3).unwrap();
        (istate, rstate)
    }

    #[test]
    fn cfg_round_trip_yields_the_gateways_assigned_address() {
        let (client_st, gw_st) = phase1_pair();
        let msgid = 0x5000_0001;
        let (request, next_iv) = build_cfg_request(&client_st, msgid).unwrap();
        let reply = test_gateway::handle_request(&gw_st, &request, msgid, Ipv4Addr::new(10, 212, 134, 202));
        let got = parse_cfg_reply(&client_st, &reply, &next_iv).unwrap();
        assert_eq!(got.assigned_ipv4(), Some(Ipv4Addr::new(10, 212, 134, 202)));
        assert_eq!(got.assigned_netmask(), Some(Ipv4Addr::new(255, 255, 255, 0)));
        assert_eq!(got.assigned_dns(), vec![Ipv4Addr::new(8, 8, 8, 8)]);
    }

    #[test]
    fn dual_stack_cfg_round_trip_yields_the_gateways_ipv6_grant_too() {
        let (client_st, gw_st) = phase1_pair();
        let msgid = 0x5000_0011;
        let (request, next_iv) = build_cfg_request_with(&client_st, msgid, true).unwrap();
        let addr6: Ipv6Addr = "fd00::abcd".parse().unwrap();
        let reply = test_gateway::handle_request_dual_stack(&gw_st, &request, msgid, Ipv4Addr::new(10, 212, 134, 202), (addr6, 64));
        let got = parse_cfg_reply(&client_st, &reply, &next_iv).unwrap();
        assert_eq!(got.assigned_ipv4(), Some(Ipv4Addr::new(10, 212, 134, 202)));
        assert_eq!(got.assigned_ipv6(), Some((addr6, 64)));
        assert_eq!(got.assigned_ipv6_dns(), vec!["2001:db8::53".parse::<Ipv6Addr>().unwrap()]);
        assert_eq!(got.assigned_ipv6_subnets(), vec![("fd00:0:0:10::".parse::<Ipv6Addr>().unwrap(), 60)]);
    }

    /// A v4-only gateway answering the dual-stack request just leaves the IPv6
    /// attributes out -- `assigned_ipv6` reads `None`, which is what keeps the
    /// caller from ever starting an IPv6 CHILD SA.
    #[test]
    fn dual_stack_request_against_an_ipv4_only_gateway_yields_no_ipv6() {
        let (client_st, gw_st) = phase1_pair();
        let msgid = 0x5000_0021;
        let (request, next_iv) = build_cfg_request_with(&client_st, msgid, true).unwrap();
        let reply = test_gateway::handle_request(&gw_st, &request, msgid, Ipv4Addr::new(10, 212, 134, 202));
        let got = parse_cfg_reply(&client_st, &reply, &next_iv).unwrap();
        assert_eq!(got.assigned_ipv4(), Some(Ipv4Addr::new(10, 212, 134, 202)));
        assert_eq!(got.assigned_ipv6(), None);
        assert!(got.assigned_ipv6_dns().is_empty());
        assert!(got.assigned_ipv6_subnets().is_empty());
    }

    /// `ipv6: false` must stay the exact request it always was.
    #[test]
    fn ipv4_only_request_is_unchanged_by_the_ipv6_option() {
        let (client_st, _gw_st) = phase1_pair();
        let msgid = 0x5000_0031;
        // Same message-id => same IV and same plaintext => identical bytes,
        // as the encryption is deterministic and there is no random padding.
        let plain = build_cfg_request(&client_st, msgid).unwrap();
        let off = build_cfg_request_with(&client_st, msgid, false).unwrap();
        assert_eq!(plain, off);
        let on = build_cfg_request_with(&client_st, msgid, true).unwrap();
        assert_ne!(plain.0, on.0);
    }

    #[test]
    fn cfg_request_carries_the_expected_empty_attrs() {
        let (client_st, _gw_st) = phase1_pair();
        let (_request, _next_iv) = build_cfg_request(&client_st, 0x6000_0001).unwrap();
        let req = ConfigPayload::request_ipv4(0x1234);
        assert!(req.attr(crate::ikev1::modecfg::cfg_attr::INTERNAL_IP4_ADDRESS).is_some());
        assert!(req.attr(crate::ikev1::modecfg::cfg_attr::INTERNAL_IP4_NETMASK).is_some());
        assert!(req.attr(crate::ikev1::modecfg::cfg_attr::INTERNAL_IP4_DNS).is_some());
        assert!(req.attr(crate::ikev1::modecfg::cfg_attr::INTERNAL_IP4_SUBNET).is_some());
    }

    #[test]
    fn parse_cfg_reply_rejects_a_non_transaction_message() {
        let (client_st, _gw_st) = phase1_pair();
        let (request, next_iv) = build_cfg_request(&client_st, 0x7000_0001).unwrap();
        // Feeding the REQUEST back in as if it were the REPLY: still a
        // Transaction message, so this exercises the cfg_type check instead
        // -- use a clearly-wrong exchange type to hit the exchange check.
        let mut bad = request.clone();
        bad[18] = 0xFF; // exchange type byte
        assert!(parse_cfg_reply(&client_st, &bad, &next_iv).is_err());
    }
}
