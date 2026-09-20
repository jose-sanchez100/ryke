//! ISAKMP Configuration Method — the body of an ATTRIBUTE (type 14) payload used
//! by XAUTH (draft-beaulieu-ike-xauth) and Mode-Config (draft-dukes-ike-mode-cfg).
//!
//! Body layout: `[cfg-type(1)][RESERVED(1)][identifier(2)][attributes…]`, where
//! each attribute is a TV/TLV using the same AF-bit encoding as SA attributes.

use super::payloads::{self, Attribute};
use crate::error::IkeError;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Configuration exchange types (the `cfg-type` octet).
pub mod cfg {
    pub const REQUEST: u8 = 1;
    pub const REPLY: u8 = 2;
    pub const SET: u8 = 3;
    pub const ACK: u8 = 4;
}

/// Configuration attribute types (Mode-Config + XAUTH).
pub mod cfg_attr {
    // Mode-Config (draft-dukes-ike-mode-cfg).
    pub const INTERNAL_IP4_ADDRESS: u16 = 1;
    pub const INTERNAL_IP4_NETMASK: u16 = 2;
    pub const INTERNAL_IP4_DNS: u16 = 3;
    pub const INTERNAL_IP4_NBNS: u16 = 4;
    pub const INTERNAL_ADDRESS_EXPIRY: u16 = 5;
    pub const INTERNAL_IP4_DHCP: u16 = 6;
    pub const APPLICATION_VERSION: u16 = 7;
    // The IPv6 half of the same registry (draft-dukes-ike-mode-cfg-02 §3.2;
    // the numbers RFC 7296 §3.15.1 later kept for IKEv2, minus NETMASK which
    // IKEv2 folded into INTERNAL_IP6_ADDRESS's own prefix-length octet).
    pub const INTERNAL_IP6_ADDRESS: u16 = 8;
    pub const INTERNAL_IP6_NETMASK: u16 = 9;
    pub const INTERNAL_IP6_DNS: u16 = 10;
    pub const INTERNAL_IP6_NBNS: u16 = 11;
    pub const INTERNAL_IP6_DHCP: u16 = 12;
    pub const INTERNAL_IP4_SUBNET: u16 = 13;
    pub const INTERNAL_IP6_SUBNET: u16 = 15;
    // XAUTH (draft-beaulieu-ike-xauth). Type 16520..16529.
    pub const XAUTH_TYPE: u16 = 16520;
    pub const XAUTH_USER_NAME: u16 = 16521;
    pub const XAUTH_USER_PASSWORD: u16 = 16522;
    pub const XAUTH_PASSCODE: u16 = 16523;
    pub const XAUTH_MESSAGE: u16 = 16524;
    pub const XAUTH_CHALLENGE: u16 = 16525;
    pub const XAUTH_DOMAIN: u16 = 16526;
    pub const XAUTH_STATUS: u16 = 16527;
    pub const XAUTH_NEXT_PIN: u16 = 16528;
    pub const XAUTH_ANSWER: u16 = 16529;
}

/// XAUTH authentication types (the value of an `XAUTH_TYPE` attribute).
pub mod xauth_type {
    pub const GENERIC: u16 = 0;
    pub const RADIUS_CHAP: u16 = 1;
    pub const OTP: u16 = 2;
    pub const SKEY: u16 = 3;
}

/// XAUTH_STATUS values.
pub mod xauth_status {
    pub const FAIL: u16 = 0;
    pub const OK: u16 = 1;
}

/// The body of an ISAKMP Configuration (ATTRIBUTE) payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigPayload {
    pub cfg_type: u8,
    pub identifier: u16,
    pub attributes: Vec<Attribute>,
}

impl ConfigPayload {
    pub fn new(cfg_type: u8, identifier: u16, attributes: Vec<Attribute>) -> Self {
        ConfigPayload { cfg_type, identifier, attributes }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![self.cfg_type, 0];
        out.extend_from_slice(&self.identifier.to_be_bytes());
        for a in &self.attributes {
            out.extend_from_slice(&a.to_bytes());
        }
        out
    }

    pub fn parse(body: &[u8]) -> Result<ConfigPayload, IkeError> {
        if body.len() < 4 {
            return Err(IkeError::Truncated { need: 4, have: body.len() });
        }
        Ok(ConfigPayload {
            cfg_type: body[0],
            identifier: u16::from_be_bytes([body[2], body[3]]),
            attributes: payloads::parse_attributes(&body[4..])?,
        })
    }

    /// Find the first attribute of a given type.
    pub fn attr(&self, attr_type: u16) -> Option<&Attribute> {
        self.attributes.iter().find(|a| a.attr_type == attr_type)
    }

    /// A CFG_REQUEST asking the responder to assign an inner IPv4 (address,
    /// netmask, DNS, split-tunnel subnet) -- the IKEv1 Mode-Config
    /// counterpart to `crate::ikev2::payload::Configuration::request_ipv4`.
    /// All value-less (empty), a classic dialup client's request. Confirmed
    /// live against a real FortiGate: an IKEv1 dialup policy that requires
    /// this round rejects the following Quick Mode proposal outright ("peer
    /// has not completed Configuration Method") if it's skipped.
    pub fn request_ipv4(identifier: u16) -> Self {
        ConfigPayload::new(
            cfg::REQUEST,
            identifier,
            vec![
                Attribute::long_bytes(cfg_attr::INTERNAL_IP4_ADDRESS, Vec::new()),
                Attribute::long_bytes(cfg_attr::INTERNAL_IP4_NETMASK, Vec::new()),
                Attribute::long_bytes(cfg_attr::INTERNAL_IP4_DNS, Vec::new()),
                Attribute::long_bytes(cfg_attr::INTERNAL_IP4_SUBNET, Vec::new()),
            ],
        )
    }

    /// [`Self::request_ipv4`] plus the IPv6 counterparts (address, netmask,
    /// DNS, split-tunnel subnet), all empty -- one dual-stack CFG_REQUEST
    /// rather than a second Transaction exchange, the way strongSwan asks for
    /// both families at once. A responder that has no IPv6 to give simply
    /// leaves those attributes out of its reply (or, as a FortiGate with IPv6
    /// unconfigured does over IKEv2, answers with an all-zero placeholder --
    /// see [`Self::assigned_ipv6`]/[`Self::assigned_ipv6_subnets`], which
    /// both ignore such junk).
    pub fn request_dual_stack(identifier: u16) -> Self {
        let mut req = Self::request_ipv4(identifier);
        req.attributes.extend([
            Attribute::long_bytes(cfg_attr::INTERNAL_IP6_ADDRESS, Vec::new()),
            Attribute::long_bytes(cfg_attr::INTERNAL_IP6_NETMASK, Vec::new()),
            Attribute::long_bytes(cfg_attr::INTERNAL_IP6_DNS, Vec::new()),
            Attribute::long_bytes(cfg_attr::INTERNAL_IP6_SUBNET, Vec::new()),
        ]);
        req
    }

    /// The first INTERNAL_IP4_ADDRESS attribute value, if present and well-formed.
    pub fn assigned_ipv4(&self) -> Option<Ipv4Addr> {
        self.attr(cfg_attr::INTERNAL_IP4_ADDRESS)
            .map(Attribute::bytes)
            .filter(|b| b.len() == 4)
            .map(|b| Ipv4Addr::new(b[0], b[1], b[2], b[3]))
    }

    /// The first INTERNAL_IP4_NETMASK attribute value, if present and well-formed.
    pub fn assigned_netmask(&self) -> Option<Ipv4Addr> {
        self.attr(cfg_attr::INTERNAL_IP4_NETMASK)
            .map(Attribute::bytes)
            .filter(|b| b.len() == 4)
            .map(|b| Ipv4Addr::new(b[0], b[1], b[2], b[3]))
    }

    /// Every INTERNAL_IP4_DNS attribute value -- a responder may hand back
    /// more than one resolver. Empty if none were sent.
    pub fn assigned_dns(&self) -> Vec<Ipv4Addr> {
        self.attributes
            .iter()
            .filter(|a| a.attr_type == cfg_attr::INTERNAL_IP4_DNS)
            .map(Attribute::bytes)
            .filter(|b| b.len() == 4)
            .map(|b| Ipv4Addr::new(b[0], b[1], b[2], b[3]))
            .collect()
    }

    /// Every INTERNAL_IP4_SUBNET attribute, as (network, prefix length) -- a
    /// responder may hand back more than one (e.g. one per split-tunnel
    /// range). Each value is network address (4 bytes) + netmask (4 bytes),
    /// the same convention as the IKEv2 CFG_REPLY attribute of the same name.
    pub fn assigned_subnets(&self) -> Vec<(Ipv4Addr, u8)> {
        self.attributes
            .iter()
            .filter(|a| a.attr_type == cfg_attr::INTERNAL_IP4_SUBNET)
            .map(Attribute::bytes)
            .filter(|b| b.len() == 8)
            .map(|b| {
                let net = Ipv4Addr::new(b[0], b[1], b[2], b[3]);
                let mask = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
                (net, mask.count_ones() as u8)
            })
            .collect()
    }
}

impl ConfigPayload {
    /// The first usable INTERNAL_IP6_ADDRESS, as (address, prefix length).
    ///
    /// Two wire shapes exist for this attribute: the IKEv2-style 17 octets
    /// (16-byte address + 1-byte prefix length, RFC 7296 §3.15.1 -- what
    /// gateways that share one Mode-Config codepath across both IKE versions
    /// send) and the original draft's bare 16-byte address, whose prefix then
    /// comes from a separate INTERNAL_IP6_NETMASK attribute (16-byte mask).
    /// With neither prefix source the address is treated as a host (`/128`):
    /// the only claim that is safe without knowing the on-link prefix.
    ///
    /// An all-zero address is not an assignment (it is the placeholder a
    /// gateway with IPv6 left unconfigured sends instead of omitting the
    /// attribute), so it reads as `None` -- callers gate the IPv6 CHILD SA on
    /// this returning `Some`.
    pub fn assigned_ipv6(&self) -> Option<(Ipv6Addr, u8)> {
        let attr = self.attributes.iter().find(|a| a.attr_type == cfg_attr::INTERNAL_IP6_ADDRESS)?;
        let value = attr.bytes();
        let addr = match value.len() {
            16 | 17 => Ipv6Addr::from(<[u8; 16]>::try_from(&value[..16]).ok()?),
            _ => return None,
        };
        if addr.is_unspecified() {
            return None;
        }
        let prefix = if value.len() == 17 {
            value[16]
        } else {
            self.attr(cfg_attr::INTERNAL_IP6_NETMASK)
                .map(Attribute::bytes)
                .and_then(|m| <[u8; 16]>::try_from(m.as_slice()).ok())
                .and_then(|m| contiguous_prefix_len(u128::from_be_bytes(m)))
                .unwrap_or(128)
        };
        (prefix <= 128).then_some((addr, prefix))
    }

    /// Every INTERNAL_IP6_DNS attribute value (16-byte address) -- same
    /// multi-resolver allowance as [`Self::assigned_dns`]. All-zero
    /// placeholders are dropped, same reasoning as [`Self::assigned_ipv6`].
    pub fn assigned_ipv6_dns(&self) -> Vec<Ipv6Addr> {
        self.attributes
            .iter()
            .filter(|a| a.attr_type == cfg_attr::INTERNAL_IP6_DNS)
            .map(Attribute::bytes)
            .filter_map(|b| <[u8; 16]>::try_from(b.as_slice()).ok())
            .map(Ipv6Addr::from)
            .filter(|a| !a.is_unspecified())
            .collect()
    }

    /// Every INTERNAL_IP6_SUBNET attribute (16-byte prefix + 1-byte prefix
    /// length), as (network, prefix length) -- the IPv6 split-tunnel ranges,
    /// same role as [`Self::assigned_subnets`]. A `/0` entry is dropped: it
    /// covers the whole address space whatever the address bytes say, so it
    /// is not a split-tunnel range (a FortiGate with IPv6 unconfigured sends
    /// exactly that placeholder over IKEv2; see
    /// `ikev2::payload::Configuration::assigned_ipv6_subnets`).
    pub fn assigned_ipv6_subnets(&self) -> Vec<(Ipv6Addr, u8)> {
        self.attributes
            .iter()
            .filter(|a| a.attr_type == cfg_attr::INTERNAL_IP6_SUBNET)
            .map(Attribute::bytes)
            .filter(|b| b.len() == 17)
            .filter_map(|b| {
                let prefix_len = b[16];
                (prefix_len != 0 && prefix_len <= 128).then(|| (Ipv6Addr::from(<[u8; 16]>::try_from(&b[..16]).unwrap()), prefix_len))
            })
            .collect()
    }
}

/// The prefix length of a netmask made of leading ones then trailing zeros,
/// `None` for a non-contiguous (malformed) mask.
fn contiguous_prefix_len(mask: u128) -> Option<u8> {
    let ones = mask.leading_ones();
    (mask == (!0u128).checked_shl(128 - ones).unwrap_or(0)).then_some(ones as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xauth_request_roundtrips() {
        let p = ConfigPayload::new(
            cfg::REQUEST,
            0x1234,
            vec![
                Attribute::short(cfg_attr::XAUTH_TYPE, xauth_type::GENERIC),
                Attribute::long_bytes(cfg_attr::XAUTH_USER_NAME, Vec::new()),
                Attribute::long_bytes(cfg_attr::XAUTH_USER_PASSWORD, Vec::new()),
            ],
        );
        let bytes = p.to_bytes();
        let back = ConfigPayload::parse(&bytes).unwrap();
        assert_eq!(back.cfg_type, cfg::REQUEST);
        assert_eq!(back.identifier, 0x1234);
        assert_eq!(back.attr(cfg_attr::XAUTH_TYPE).unwrap().as_u16(), Some(xauth_type::GENERIC));
        assert!(back.attr(cfg_attr::XAUTH_USER_NAME).is_some());
    }

    fn v6(a: &str) -> Ipv6Addr {
        a.parse().unwrap()
    }

    fn reply(attrs: Vec<Attribute>) -> ConfigPayload {
        ConfigPayload::parse(&ConfigPayload::new(cfg::REPLY, 1, attrs).to_bytes()).unwrap()
    }

    #[test]
    fn dual_stack_request_adds_the_ipv6_attributes_to_the_ipv4_ones() {
        let req = ConfigPayload::request_dual_stack(7);
        let v4 = ConfigPayload::request_ipv4(7);
        // The IPv4 half is byte-for-byte what a v4-only request carries.
        assert_eq!(&req.attributes[..v4.attributes.len()], &v4.attributes[..]);
        for t in [cfg_attr::INTERNAL_IP6_ADDRESS, cfg_attr::INTERNAL_IP6_NETMASK, cfg_attr::INTERNAL_IP6_DNS, cfg_attr::INTERNAL_IP6_SUBNET] {
            let a = req.attr(t).unwrap_or_else(|| panic!("attribute {t} missing"));
            assert!(a.bytes().is_empty(), "requests carry empty values");
        }
        // And it survives the wire.
        assert_eq!(ConfigPayload::parse(&req.to_bytes()).unwrap(), req);
    }

    #[test]
    fn assigned_ipv6_reads_the_ikev2_style_17_octet_value() {
        let mut v = v6("fd00::1234").octets().to_vec();
        v.push(64);
        let got = reply(vec![Attribute::long_bytes(cfg_attr::INTERNAL_IP6_ADDRESS, v)]);
        assert_eq!(got.assigned_ipv6(), Some((v6("fd00::1234"), 64)));
    }

    #[test]
    fn assigned_ipv6_takes_the_prefix_from_a_separate_netmask_for_a_bare_16_octet_value() {
        let mask = u128::MAX << 64; // /64
        let got = reply(vec![
            Attribute::long_bytes(cfg_attr::INTERNAL_IP6_ADDRESS, v6("fd00::1234").octets().to_vec()),
            Attribute::long_bytes(cfg_attr::INTERNAL_IP6_NETMASK, mask.to_be_bytes().to_vec()),
        ]);
        assert_eq!(got.assigned_ipv6(), Some((v6("fd00::1234"), 64)));
    }

    #[test]
    fn assigned_ipv6_is_a_host_when_nothing_says_otherwise_or_the_netmask_is_malformed() {
        let bare = reply(vec![Attribute::long_bytes(cfg_attr::INTERNAL_IP6_ADDRESS, v6("fd00::1234").octets().to_vec())]);
        assert_eq!(bare.assigned_ipv6(), Some((v6("fd00::1234"), 128)));

        // Non-contiguous mask: not a prefix, so ignored rather than guessed at.
        let holey = 0xF0F0_0000_0000_0000_0000_0000_0000_0000u128;
        let bad = reply(vec![
            Attribute::long_bytes(cfg_attr::INTERNAL_IP6_ADDRESS, v6("fd00::1234").octets().to_vec()),
            Attribute::long_bytes(cfg_attr::INTERNAL_IP6_NETMASK, holey.to_be_bytes().to_vec()),
        ]);
        assert_eq!(bad.assigned_ipv6(), Some((v6("fd00::1234"), 128)));
    }

    #[test]
    fn assigned_ipv6_ignores_placeholders_and_malformed_values() {
        // The all-zero "nothing to give" placeholder is not an assignment.
        let mut zero17 = vec![0u8; 16];
        zero17.push(0);
        assert_eq!(reply(vec![Attribute::long_bytes(cfg_attr::INTERNAL_IP6_ADDRESS, zero17)]).assigned_ipv6(), None);
        assert_eq!(reply(vec![Attribute::long_bytes(cfg_attr::INTERNAL_IP6_ADDRESS, vec![0u8; 16])]).assigned_ipv6(), None);
        // Wrong length / absent / an impossible prefix length.
        assert_eq!(reply(vec![Attribute::long_bytes(cfg_attr::INTERNAL_IP6_ADDRESS, vec![1u8; 4])]).assigned_ipv6(), None);
        assert_eq!(reply(Vec::new()).assigned_ipv6(), None);
        let mut too_long = v6("fd00::1").octets().to_vec();
        too_long.push(200);
        assert_eq!(reply(vec![Attribute::long_bytes(cfg_attr::INTERNAL_IP6_ADDRESS, too_long)]).assigned_ipv6(), None);
    }

    #[test]
    fn ipv6_dns_and_subnets_are_read_back_and_placeholders_dropped() {
        let mut real_subnet = v6("fd00:0:0:10::").octets().to_vec();
        real_subnet.push(60);
        let mut junk_subnet = vec![0u8; 16];
        junk_subnet.push(0);
        let got = reply(vec![
            Attribute::long_bytes(cfg_attr::INTERNAL_IP6_DNS, v6("2001:db8::1").octets().to_vec()),
            Attribute::long_bytes(cfg_attr::INTERNAL_IP6_DNS, v6("2001:db8::2").octets().to_vec()),
            Attribute::long_bytes(cfg_attr::INTERNAL_IP6_DNS, vec![0u8; 16]),
            Attribute::long_bytes(cfg_attr::INTERNAL_IP6_SUBNET, junk_subnet),
            Attribute::long_bytes(cfg_attr::INTERNAL_IP6_SUBNET, real_subnet),
        ]);
        assert_eq!(got.assigned_ipv6_dns(), vec![v6("2001:db8::1"), v6("2001:db8::2")]);
        assert_eq!(got.assigned_ipv6_subnets(), vec![(v6("fd00:0:0:10::"), 60)]);
    }

    #[test]
    fn contiguous_prefix_len_accepts_only_leading_ones() {
        assert_eq!(contiguous_prefix_len(0), Some(0));
        assert_eq!(contiguous_prefix_len(u128::MAX), Some(128));
        assert_eq!(contiguous_prefix_len(u128::MAX << 64), Some(64));
        assert_eq!(contiguous_prefix_len(u128::MAX << 1), Some(127));
        assert_eq!(contiguous_prefix_len(1), None);
        assert_eq!(contiguous_prefix_len(0x00FF << 100), None);
    }

    #[test]
    fn reply_carries_credentials() {
        let p = ConfigPayload::new(
            cfg::REPLY,
            0x1234,
            vec![
                Attribute::long_bytes(cfg_attr::XAUTH_USER_NAME, b"alice".to_vec()),
                Attribute::long_bytes(cfg_attr::XAUTH_USER_PASSWORD, b"secret".to_vec()),
            ],
        );
        let back = ConfigPayload::parse(&p.to_bytes()).unwrap();
        assert_eq!(back.attr(cfg_attr::XAUTH_USER_NAME).unwrap().bytes(), b"alice");
        assert_eq!(back.attr(cfg_attr::XAUTH_USER_PASSWORD).unwrap().bytes(), b"secret");
    }
}
