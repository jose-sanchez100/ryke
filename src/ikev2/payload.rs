//! Typed IKEv2 payload bodies needed for `IKE_SA_INIT` (M1): the Security
//! Association payload with its Proposal/Transform substructures (RFC 7296
//! §3.3), Key Exchange (§3.4), and Nonce (§3.9).
//!
//! Each type parses/serializes its *body* — the bytes after the 4-byte generic
//! payload header. Chaining payloads into a full message (adding those generic
//! headers) is the message-builder's job.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::IkeError;

/// Transform types (RFC 7296 §3.3.2).
pub mod transform_type {
    pub const ENCR: u8 = 1;
    pub const PRF: u8 = 2;
    pub const INTEG: u8 = 3;
    pub const DH: u8 = 4;
    pub const ESN: u8 = 5;
}

/// A selection of transform IDs we care about at M1.
pub mod transform_id {
    // ENCR (RFC 7296 §3.3.2, IANA "Transform Type 1 - Encryption Algorithm Transform IDs")
    pub const DES_IV64: u16 = 1;
    pub const DES: u16 = 2;
    pub const TRIPLE_DES: u16 = 3;
    pub const AES_CBC: u16 = 12;
    pub const AES_GCM_16: u16 = 20;
    pub const CHACHA20_POLY1305: u16 = 28;
    // PRF
    pub const PRF_HMAC_MD5: u16 = 1;
    pub const PRF_HMAC_SHA1: u16 = 2;
    pub const PRF_HMAC_SHA2_256: u16 = 5;
    pub const PRF_HMAC_SHA2_384: u16 = 6;
    pub const PRF_HMAC_SHA2_512: u16 = 7;
    // INTEG
    pub const AUTH_HMAC_MD5_96: u16 = 1;
    pub const AUTH_HMAC_SHA1_96: u16 = 2;
    pub const AUTH_HMAC_SHA2_256_128: u16 = 12;
    pub const AUTH_HMAC_SHA2_384_192: u16 = 13;
    pub const AUTH_HMAC_SHA2_512_256: u16 = 14;
    // DH
    pub const MODP_768: u16 = 1;
    pub const MODP_1024: u16 = 2;
    pub const MODP_1536: u16 = 5;
    pub const MODP_2048: u16 = 14;
    pub const MODP_3072: u16 = 15;
    pub const MODP_4096: u16 = 16;
    pub const MODP_6144: u16 = 17;
    pub const MODP_8192: u16 = 18;
    pub const ECP256: u16 = 19;
    pub const ECP384: u16 = 20;
    pub const ECP521: u16 = 21;
    pub const X25519: u16 = 31;
    // ESN
    pub const ESN_NONE: u16 = 0;
    pub const ESN_ENABLED: u16 = 1;
    /// What a received transform we cannot take stands for once parsed: one
    /// carrying an attribute this crate does not understand (RFC 7296 §3.3.6,
    /// "unacceptable"). It keeps its place and its Transform Type in the
    /// proposal but names nothing we run -- a private-use ID no candidate list
    /// holds -- so it is never selected, yet still counts as a transform of its
    /// type that was offered (or answered). Never sent.
    pub const UNUSABLE: u16 = 0xFFFF;
}

/// IKEv2 protocol IDs (RFC 7296 §3.3.1).
pub mod protocol_id {
    pub const IKE: u8 = 1;
    pub const AH: u8 = 2;
    pub const ESP: u8 = 3;
}

/// The Key Length transform attribute type (RFC 7296 §3.3.5).
const ATTR_KEY_LENGTH: u16 = 14;
/// Attribute Format bit: set = TV (value inline), clear = TLV.
const ATTR_FORMAT_TV: u16 = 0x8000;

fn u16be(buf: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([buf[off], buf[off + 1]])
}
fn push_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_be_bytes());
}

/// One Transform substructure. We model the single attribute that IKEv2
/// defines -- Key Length. A received transform carrying anything else is not
/// understood, and unacceptable (RFC 7296 §3.3.6): on parse it becomes a
/// transform of its type that names [`transform_id::UNUSABLE`] -- never
/// selected, but not gone either, because what the peer offered or answered
/// is more than the transforms we could use (a type it insisted on, two
/// transforms where one was to be answered).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transform {
    pub transform_type: u8,
    pub transform_id: u16,
    /// Key Length attribute (bits), e.g. `Some(256)` for AES-256.
    pub key_length: Option<u16>,
}

impl Transform {
    /// Parse one transform from the front of `buf`; returns it and the number of
    /// bytes consumed (its declared Transform Length). One that carries an
    /// attribute we do not understand is RFC 7296 §3.3.6's unacceptable
    /// transform: it comes back as [`transform_id::UNUSABLE`] of its type,
    /// while other transforms of the type still count.
    fn parse(buf: &[u8]) -> Result<(Transform, usize), IkeError> {
        if buf.len() < 8 {
            return Err(IkeError::Truncated { need: 8, have: buf.len() });
        }
        let length = u16be(buf, 2) as usize;
        if length < 8 {
            return Err(IkeError::ShortPayload(length as u16));
        }
        if length > buf.len() {
            return Err(IkeError::BadLength { declared: length, available: buf.len() });
        }
        let transform_type = buf[4];
        let transform_id = u16be(buf, 6);
        let transform = match Self::read_attributes(&buf[8..length])? {
            Some(key_length) => Transform { transform_type, transform_id, key_length },
            None => Transform { transform_type, transform_id: transform_id::UNUSABLE, key_length: None },
        };
        Ok((transform, length))
    }

    /// The Key Length in a transform's attribute area (RFC 7296 §3.3.5):
    /// `Some(key_length)` when every attribute there is understood, `None` when
    /// one is not -- an unknown type, a Key Length in the variable-length
    /// encoding (a fixed-length attribute "MUST NOT" use it), or a second Key
    /// Length. Bytes that do not form whole attributes are malformed.
    fn read_attributes(mut attrs: &[u8]) -> Result<Option<Option<u16>>, IkeError> {
        let mut key_length = None;
        let mut understood = true;
        while !attrs.is_empty() {
            if attrs.len() < 4 {
                return Err(IkeError::Truncated { need: 4, have: attrs.len() });
            }
            let header = u16be(attrs, 0);
            let attr_type = header & 0x7fff;
            let size = if header & ATTR_FORMAT_TV != 0 {
                // TV: 2-byte value inline.
                if attr_type == ATTR_KEY_LENGTH && key_length.is_none() {
                    key_length = Some(u16be(attrs, 2));
                } else {
                    understood = false;
                }
                4
            } else {
                // TLV: 2-byte length then value.
                let len = u16be(attrs, 2) as usize;
                if 4 + len > attrs.len() {
                    return Err(IkeError::BadLength { declared: 4 + len, available: attrs.len() });
                }
                understood = false;
                4 + len
            };
            attrs = &attrs[size..];
        }
        Ok(understood.then_some(key_length))
    }

    fn write(&self, out: &mut Vec<u8>, is_last: bool) {
        let mut attrs = Vec::new();
        if let Some(key_length) = self.key_length {
            push_u16(&mut attrs, ATTR_FORMAT_TV | ATTR_KEY_LENGTH);
            push_u16(&mut attrs, key_length);
        }
        let length = 8 + attrs.len();
        out.push(if is_last { 0 } else { 3 }); // Last Substruc
        out.push(0); // RESERVED
        push_u16(out, length as u16);
        out.push(self.transform_type);
        out.push(0); // RESERVED
        push_u16(out, self.transform_id);
        out.extend_from_slice(&attrs);
    }
}

/// One Proposal substructure (RFC 7296 §3.3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    pub num: u8,
    pub protocol_id: u8,
    /// SPI (empty in the initial IKE SA proposal).
    pub spi: Vec<u8>,
    pub transforms: Vec<Transform>,
}

impl Proposal {
    fn parse(buf: &[u8]) -> Result<(Proposal, usize), IkeError> {
        if buf.len() < 8 {
            return Err(IkeError::Truncated { need: 8, have: buf.len() });
        }
        let length = u16be(buf, 2) as usize;
        if length < 8 {
            return Err(IkeError::ShortPayload(length as u16));
        }
        if length > buf.len() {
            return Err(IkeError::BadLength { declared: length, available: buf.len() });
        }
        let num = buf[4];
        let protocol_id = buf[5];
        let spi_size = buf[6] as usize;
        let transform_count = buf[7] as usize;
        if 8 + spi_size > length {
            return Err(IkeError::BadLength { declared: 8 + spi_size, available: length });
        }
        let spi = buf[8..8 + spi_size].to_vec();

        let mut off = 8 + spi_size;
        let mut transforms = Vec::with_capacity(transform_count);
        for _ in 0..transform_count {
            let (transform, consumed) = Transform::parse(&buf[off..length])?;
            transforms.push(transform);
            off += consumed;
        }
        // The transforms fill the proposal: its Length has no room for more.
        if off != length {
            return Err(IkeError::BadLength { declared: length, available: off });
        }
        Ok((Proposal { num, protocol_id, spi, transforms }, length))
    }

    fn write(&self, out: &mut Vec<u8>, is_last: bool) {
        let mut body = Vec::new();
        for (i, transform) in self.transforms.iter().enumerate() {
            transform.write(&mut body, i + 1 == self.transforms.len());
        }
        let length = 8 + self.spi.len() + body.len();
        out.push(if is_last { 0 } else { 2 }); // Last Substruc
        out.push(0); // RESERVED
        push_u16(out, length as u16);
        out.push(self.num);
        out.push(self.protocol_id);
        out.push(self.spi.len() as u8);
        out.push(self.transforms.len() as u8);
        out.extend_from_slice(&self.spi);
        out.extend_from_slice(&body);
    }
}

/// The Security Association payload body: a list of proposals (RFC 7296 §3.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityAssociation {
    pub proposals: Vec<Proposal>,
}

impl SecurityAssociation {
    pub fn parse(body: &[u8]) -> Result<SecurityAssociation, IkeError> {
        let mut off = 0;
        let mut proposals = Vec::new();
        while off < body.len() {
            let (proposal, consumed) = Proposal::parse(&body[off..])?;
            proposals.push(proposal);
            off += consumed;
        }
        Ok(SecurityAssociation { proposals })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for (i, proposal) in self.proposals.iter().enumerate() {
            proposal.write(&mut out, i + 1 == self.proposals.len());
        }
        out
    }
}

/// Key Exchange payload body (RFC 7296 §3.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyExchange {
    pub dh_group: u16,
    pub data: Vec<u8>,
}

impl KeyExchange {
    pub fn parse(body: &[u8]) -> Result<KeyExchange, IkeError> {
        if body.len() < 4 {
            return Err(IkeError::Truncated { need: 4, have: body.len() });
        }
        Ok(KeyExchange { dh_group: u16be(body, 0), data: body[4..].to_vec() })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.data.len());
        push_u16(&mut out, self.dh_group);
        push_u16(&mut out, 0); // RESERVED
        out.extend_from_slice(&self.data);
        out
    }
}

/// Nonce payload body (RFC 7296 §3.9) — just the nonce bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nonce {
    pub data: Vec<u8>,
}

impl Nonce {
    /// RFC 7296 §3.9: a nonce MUST be between 16 and 256 bytes.
    pub fn parse(body: &[u8]) -> Result<Nonce, IkeError> {
        if body.len() < 16 || body.len() > 256 {
            return Err(IkeError::Crypto("nonce length out of range (16-256 bytes)"));
        }
        Ok(Nonce { data: body.to_vec() })
    }
    /// [`Nonce::parse`], for a nonce the peer sent once `prf` is negotiated:
    /// RFC 7296 §2.10 also asks that it be "at least half the key size of
    /// the negotiated pseudorandom function" -- an HMAC PRF's key is its
    /// output (§2.13), so 24 octets for PRF_HMAC_SHA2_384 and 32 for
    /// PRF_HMAC_SHA2_512.
    pub fn parse_for_prf(body: &[u8], prf: crate::crypto::PrfAlgorithm) -> Result<Nonce, IkeError> {
        let nonce = Nonce::parse(body)?;
        if nonce.data.len() < prf.output_len().div_ceil(2) {
            return Err(IkeError::Crypto("nonce shorter than half the negotiated PRF's key"));
        }
        Ok(nonce)
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        self.data.clone()
    }
}

/// Identification types (RFC 7296 §3.5).
pub mod id_type {
    pub const IPV4_ADDR: u8 = 1;
    pub const FQDN: u8 = 2;
    pub const RFC822_ADDR: u8 = 3;
    pub const IPV6_ADDR: u8 = 5;
    pub const DER_ASN1_DN: u8 = 9;
    pub const KEY_ID: u8 = 11;
}

/// Identification payload body (RFC 7296 §3.5). IDi and IDr share this format.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Identification {
    pub id_type: u8,
    pub data: Vec<u8>,
}

impl Identification {
    /// A fully-qualified-domain-name identity (ID_FQDN).
    pub fn fqdn(name: &str) -> Self {
        Identification { id_type: id_type::FQDN, data: name.as_bytes().to_vec() }
    }

    pub fn parse(body: &[u8]) -> Result<Identification, IkeError> {
        if body.len() < 4 {
            return Err(IkeError::Truncated { need: 4, have: body.len() });
        }
        Ok(Identification { id_type: body[0], data: body[4..].to_vec() })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.data.len());
        out.push(self.id_type);
        out.extend_from_slice(&[0, 0, 0]); // RESERVED
        out.extend_from_slice(&self.data);
        out
    }
}

/// Authentication methods (RFC 7296 §3.8, RFC 7427).
pub mod auth_method {
    pub const RSA_SIG: u8 = 1;
    /// Shared Key Message Integrity Code (PSK).
    pub const SHARED_KEY: u8 = 2;
    pub const DSS_SIG: u8 = 3;
    /// ECDSA-256 with SHA-256 on the P-256 curve (RFC 4754) — the *classic*
    /// ECDSA auth, used when the peer does not negotiate RFC 7427 Digital
    /// Signature (e.g. an iOS EAP client sends no SIGNATURE_HASH_ALGORITHMS).
    /// AUTH Data is the raw `r || s` (64 bytes), no algorithm wrapper.
    pub const ECDSA_SHA256_P256: u8 = 9;
    /// Digital Signature (RFC 7427) — the modern cert-auth method.
    pub const DIGITAL_SIGNATURE: u8 = 14;
}

/// Authentication payload body (RFC 7296 §3.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authentication {
    pub method: u8,
    pub data: Vec<u8>,
}

impl Authentication {
    pub fn parse(body: &[u8]) -> Result<Authentication, IkeError> {
        if body.len() < 4 {
            return Err(IkeError::Truncated { need: 4, have: body.len() });
        }
        Ok(Authentication { method: body[0], data: body[4..].to_vec() })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.data.len());
        out.push(self.method);
        out.extend_from_slice(&[0, 0, 0]); // RESERVED
        out.extend_from_slice(&self.data);
        out
    }
}

/// Traffic Selector types (RFC 7296 §3.13.1).
pub mod ts_type {
    pub const IPV4_ADDR_RANGE: u8 = 7;
    pub const IPV6_ADDR_RANGE: u8 = 8;
}

/// One Traffic Selector (RFC 7296 §3.13.1): a protocol + port range + address range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrafficSelector {
    pub ts_type: u8,
    pub ip_protocol: u8,
    pub start_port: u16,
    pub end_port: u16,
    pub start_addr: Vec<u8>,
    pub end_addr: Vec<u8>,
}

impl TrafficSelector {
    /// The "everything" IPv4 selector: any protocol, all ports, 0.0.0.0–255.255.255.255.
    pub fn ipv4_any() -> Self {
        TrafficSelector {
            ts_type: ts_type::IPV4_ADDR_RANGE,
            ip_protocol: 0,
            start_port: 0,
            end_port: 65535,
            start_addr: vec![0, 0, 0, 0],
            end_addr: vec![255, 255, 255, 255],
        }
    }

    /// A single-host IPv4 selector (a /32 range, any protocol/port) — what a
    /// responder narrows TSi to when it assigns the initiator one address.
    pub fn ipv4_host(addr: Ipv4Addr) -> Self {
        TrafficSelector {
            ts_type: ts_type::IPV4_ADDR_RANGE,
            ip_protocol: 0,
            start_port: 0,
            end_port: 65535,
            start_addr: addr.octets().to_vec(),
            end_addr: addr.octets().to_vec(),
        }
    }

    /// The "everything" IPv6 selector: any protocol, all ports, `::`-`ffff:...:ffff`.
    pub fn ipv6_any() -> Self {
        TrafficSelector {
            ts_type: ts_type::IPV6_ADDR_RANGE,
            ip_protocol: 0,
            start_port: 0,
            end_port: 65535,
            start_addr: vec![0; 16],
            end_addr: vec![0xff; 16],
        }
    }

    /// If this selector's address range is exactly one CIDR block, returns it
    /// as `(network, prefix_len)` -- covers both the full-tunnel grant
    /// (`0.0.0.0/0`) and a single narrowed subnet, the two shapes a real
    /// gateway actually sends. `None` for IPv6 selectors, a malformed range,
    /// or a range that isn't CIDR-aligned (some other start/end pair with no
    /// clean network/prefix representation) -- such a range would need more
    /// than one route to express exactly, which isn't needed by any gateway
    /// this has been tested against.
    pub fn to_ipv4_cidr(&self) -> Option<(Ipv4Addr, u8)> {
        if self.ts_type != ts_type::IPV4_ADDR_RANGE {
            return None;
        }
        let start = u32::from_be_bytes(self.start_addr.clone().try_into().ok()?);
        let end = u32::from_be_bytes(self.end_addr.clone().try_into().ok()?);
        if start > end {
            return None;
        }
        for prefix in 0..=32u8 {
            let mask: u32 = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
            let network = start & mask;
            if network == start && (network | !mask) == end {
                return Some((Ipv4Addr::from(network), prefix));
            }
        }
        None
    }

    /// IPv6 counterpart of [`Self::to_ipv4_cidr`]: the selector's address
    /// range as `(network, prefix_len)` when it is exactly one CIDR block --
    /// `::/0` for a full-tunnel grant, or a single narrowed prefix. `None`
    /// for IPv4 selectors, a malformed range, or one that isn't CIDR-aligned.
    pub fn to_ipv6_cidr(&self) -> Option<(Ipv6Addr, u8)> {
        if self.ts_type != ts_type::IPV6_ADDR_RANGE {
            return None;
        }
        let start = u128::from_be_bytes(self.start_addr.clone().try_into().ok()?);
        let end = u128::from_be_bytes(self.end_addr.clone().try_into().ok()?);
        if start > end {
            return None;
        }
        for prefix in 0..=128u32 {
            let mask: u128 = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
            let network = start & mask;
            if network == start && (network | !mask) == end {
                return Some((Ipv6Addr::from(network), prefix as u8));
            }
        }
        None
    }

    /// Whether every packet this selector matches is matched by `outer` too:
    /// the same address family, `outer`'s protocol or any protocol, and a
    /// port and address range inside `outer`'s -- what RFC 7296 §2.9 allows a
    /// responder to answer with, a subset of what was proposed. `ANY` ports
    /// (0-65535) include `OPAQUE` (65535-0, §3.13.1); `OPAQUE` includes
    /// only itself. A selector of a type this crate does not know is inside
    /// nothing.
    pub fn is_within(&self, outer: &TrafficSelector) -> bool {
        const ANY: (u16, u16) = (0, 65535);
        const OPAQUE: (u16, u16) = (65535, 0);
        let (ports, outer_ports) = ((self.start_port, self.end_port), (outer.start_port, outer.end_port));
        let ports_within = outer_ports == ANY
            || if ports == OPAQUE || outer_ports == OPAQUE {
                ports == outer_ports
            } else {
                outer_ports.0 <= ports.0 && ports.0 <= ports.1 && ports.1 <= outer_ports.1
            };
        matches!(self.ts_type, ts_type::IPV4_ADDR_RANGE | ts_type::IPV6_ADDR_RANGE)
            && self.ts_type == outer.ts_type
            && (outer.ip_protocol == 0 || outer.ip_protocol == self.ip_protocol)
            && ports_within
            && self.start_addr.len() == outer.start_addr.len()
            && self.end_addr.len() == outer.end_addr.len()
            && outer.start_addr <= self.start_addr
            && self.start_addr <= self.end_addr
            && self.end_addr <= outer.end_addr
    }

    /// The traffic matched by both this selector and `other`, as one
    /// selector, or `None` when they share none: what a responder narrows a
    /// proposed selector to under a selector of its policy (RFC 7296 §2.9).
    /// The protocol is the one they name, any protocol (0) giving way to
    /// the other's; the ports and addresses the overlap of their ranges,
    /// where `ANY` ports (0-65535) meet `OPAQUE` (65535-0, §3.13.1) in
    /// `OPAQUE` and `OPAQUE` meets nothing else. A selector of a type this
    /// crate does not know shares nothing -- §2.9 has the responder ignore it.
    pub fn intersection(&self, other: &TrafficSelector) -> Option<TrafficSelector> {
        const ANY: (u16, u16) = (0, 65535);
        const OPAQUE: (u16, u16) = (65535, 0);
        if !matches!(self.ts_type, ts_type::IPV4_ADDR_RANGE | ts_type::IPV6_ADDR_RANGE) || self.ts_type != other.ts_type {
            return None;
        }
        let ip_protocol = match (self.ip_protocol, other.ip_protocol) {
            (0, p) | (p, 0) => p,
            (a, b) if a == b => a,
            _ => return None,
        };
        let (a, b) = ((self.start_port, self.end_port), (other.start_port, other.end_port));
        let (start_port, end_port) = match (a, b) {
            (OPAQUE, OPAQUE) | (OPAQUE, ANY) | (ANY, OPAQUE) => OPAQUE,
            (OPAQUE, _) | (_, OPAQUE) => return None,
            _ => {
                let ports = (a.0.max(b.0), a.1.min(b.1));
                if a.0 > a.1 || b.0 > b.1 || ports.0 > ports.1 {
                    return None;
                }
                ports
            }
        };
        let start_addr = self.start_addr.as_slice().max(other.start_addr.as_slice()).to_vec();
        let end_addr = self.end_addr.as_slice().min(other.end_addr.as_slice()).to_vec();
        let lens = [&self.start_addr, &self.end_addr, &other.start_addr, &other.end_addr].map(|a| a.len());
        if lens.iter().any(|&len| len != lens[0]) || start_addr > end_addr {
            return None;
        }
        Some(TrafficSelector { ts_type: self.ts_type, ip_protocol, start_port, end_port, start_addr, end_addr })
    }

    fn parse(buf: &[u8]) -> Result<(TrafficSelector, usize), IkeError> {
        if buf.len() < 8 {
            return Err(IkeError::Truncated { need: 8, have: buf.len() });
        }
        let length = u16be(buf, 2) as usize;
        if length < 8 || length > buf.len() || (length - 8) % 2 != 0 {
            return Err(IkeError::BadLength { declared: length, available: buf.len() });
        }
        let addr_len = (length - 8) / 2;
        // RFC 7296 §3.13.1: the TS Type fixes the address size, and the
        // Starting Address is the smallest address in the range, the Ending
        // Address the largest. A type this crate does not know keeps the
        // generic shape: §2.9 has the responder ignore it, not the message.
        let family_len = match buf[0] {
            ts_type::IPV4_ADDR_RANGE => Some(4),
            ts_type::IPV6_ADDR_RANGE => Some(16),
            _ => None,
        };
        if let Some(family_len) = family_len {
            if addr_len != family_len {
                return Err(IkeError::MalformedPayload("Traffic Selector length does not match its TS Type"));
            }
            if buf[8..8 + addr_len] > buf[8 + addr_len..length] {
                return Err(IkeError::MalformedPayload("Traffic Selector ends before it starts"));
            }
        }
        Ok((
            TrafficSelector {
                ts_type: buf[0],
                ip_protocol: buf[1],
                start_port: u16be(buf, 4),
                end_port: u16be(buf, 6),
                start_addr: buf[8..8 + addr_len].to_vec(),
                end_addr: buf[8 + addr_len..8 + 2 * addr_len].to_vec(),
            },
            length,
        ))
    }

    fn write(&self, out: &mut Vec<u8>) {
        let length = 8 + self.start_addr.len() + self.end_addr.len();
        out.push(self.ts_type);
        out.push(self.ip_protocol);
        push_u16(out, length as u16);
        push_u16(out, self.start_port);
        push_u16(out, self.end_port);
        out.extend_from_slice(&self.start_addr);
        out.extend_from_slice(&self.end_addr);
    }
}

/// A Traffic Selector payload body — TSi or TSr (RFC 7296 §3.13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrafficSelectors {
    pub selectors: Vec<TrafficSelector>,
}

impl TrafficSelectors {
    /// Everything IPv6 (`::/0`), and nothing else -- what an initiator
    /// proposes for a CHILD SA of its own dedicated to IPv6 (see
    /// `rekey::build_child_request`). Kept apart from the IPv4 offer because
    /// some gateways (FortiGate) treat each address family as a separate
    /// Phase 2 selector and grant only one per CHILD SA.
    pub fn ipv6_full_tunnel() -> TrafficSelectors {
        TrafficSelectors { selectors: vec![TrafficSelector::ipv6_any()] }
    }

    /// Everything IPv4 (`0.0.0.0/0`), and nothing else -- the initiator's
    /// long-standing IKE_AUTH offer, and what a per-family peer grants.
    pub fn ipv4_full_tunnel() -> TrafficSelectors {
        TrafficSelectors { selectors: vec![TrafficSelector::ipv4_any()] }
    }

    /// Everything IPv4 *and* everything IPv6 in one payload: the RFC 7296
    /// §2.9 way to ask for a single CHILD SA that carries both families
    /// (`TS_IPV4_ADDR_RANGE` and `TS_IPV6_ADDR_RANGE` may share a payload).
    /// Peers that keep one selector family per policy (FortiGate) answer with
    /// a narrowed reply or reject it; see `Ikev2Session::with_unified_ts`.
    pub fn unified_full_tunnel() -> TrafficSelectors {
        TrafficSelectors { selectors: vec![TrafficSelector::ipv4_any(), TrafficSelector::ipv6_any()] }
    }

    /// Whether any selector is an IPv4 address range.
    pub fn has_ipv4(&self) -> bool {
        self.selectors.iter().any(|s| s.ts_type == ts_type::IPV4_ADDR_RANGE)
    }

    /// Whether any selector is an IPv6 address range.
    pub fn has_ipv6(&self) -> bool {
        self.selectors.iter().any(|s| s.ts_type == ts_type::IPV6_ADDR_RANGE)
    }

    /// Whether these selectors are a subset of `offer` (RFC 7296 §2.9: the
    /// responder narrows "to some subset of the initiator's proposal
    /// (provided the set does not become the null set)"): at least one, and
    /// each inside one of `offer`'s ([`TrafficSelector::is_within`]). A
    /// selector covered only by two of `offer`'s together does not count --
    /// no offer this crate makes has selectors that adjoin.
    pub fn is_within(&self, offer: &TrafficSelectors) -> bool {
        !self.selectors.is_empty() && self.selectors.iter().all(|s| offer.selectors.iter().any(|o| s.is_within(o)))
    }

    /// These selectors narrowed to `policy` (RFC 7296 §2.9): each one's
    /// [`intersection`](TrafficSelector::intersection) with each of
    /// `policy`'s, in the proposal's order -- so a first selector the policy
    /// takes whole, the initiator's "first choice", comes back whole and
    /// first -- or `None` when nothing is left, the case §2.9 answers with
    /// `TS_UNACCEPTABLE` rather than a null set. Selectors of a type this
    /// crate does not know are left out (§2.9: the responder ignores them).
    pub fn narrowed_to(&self, policy: &TrafficSelectors) -> Option<TrafficSelectors> {
        let mut selectors: Vec<TrafficSelector> = Vec::new();
        for proposed in &self.selectors {
            for narrowed in policy.selectors.iter().filter_map(|p| proposed.intersection(p)) {
                if !selectors.contains(&narrowed) {
                    selectors.push(narrowed);
                }
            }
        }
        (!selectors.is_empty()).then_some(TrafficSelectors { selectors })
    }

    pub fn parse(body: &[u8]) -> Result<TrafficSelectors, IkeError> {
        if body.len() < 4 {
            return Err(IkeError::Truncated { need: 4, have: body.len() });
        }
        let count = body[0] as usize;
        // §3.13: the payload holds "one or more individual Traffic Selectors".
        if count == 0 {
            return Err(IkeError::MalformedPayload("TS payload with no Traffic Selector"));
        }
        let mut off = 4; // skip Number of TSs (1) + RESERVED (3)
        let mut selectors = Vec::with_capacity(count);
        for _ in 0..count {
            let (ts, consumed) = TrafficSelector::parse(&body[off..])?;
            selectors.push(ts);
            off += consumed;
        }
        if off != body.len() {
            return Err(IkeError::MalformedPayload("TS payload longer than its Traffic Selectors"));
        }
        Ok(TrafficSelectors { selectors })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.selectors.len() as u8);
        out.extend_from_slice(&[0, 0, 0]); // RESERVED
        for ts in &self.selectors {
            ts.write(&mut out);
        }
        out
    }
}

/// Configuration payload (CP) types (RFC 7296 §3.15.1).
pub mod cfg_type {
    pub const REQUEST: u8 = 1;
    pub const REPLY: u8 = 2;
    pub const SET: u8 = 3;
    pub const ACK: u8 = 4;
}

/// Configuration Attribute types (RFC 7296 §3.15.1 + IANA registry). Only the
/// attributes a client needs to bring up a tunnel interface are named.
pub mod config_attr {
    pub const INTERNAL_IP4_ADDRESS: u16 = 1;
    pub const INTERNAL_IP4_NETMASK: u16 = 2;
    pub const INTERNAL_IP4_DNS: u16 = 3;
    pub const INTERNAL_IP4_SUBNET: u16 = 13;
    pub const INTERNAL_IP6_ADDRESS: u16 = 8;
    pub const INTERNAL_IP6_DNS: u16 = 10;
    pub const INTERNAL_IP6_SUBNET: u16 = 15;
}

/// One IKEv2 Configuration Attribute (RFC 7296 §3.15.1): a 15-bit type (the top
/// "reserved" bit is always clear — the TV/AF short form of IKEv1 is not used in
/// IKEv2), a 2-byte length, then the value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigAttr {
    pub attr_type: u16,
    pub value: Vec<u8>,
}

impl ConfigAttr {
    /// A 4-byte IPv4-valued attribute (address/netmask/DNS).
    pub fn ipv4(attr_type: u16, addr: Ipv4Addr) -> Self {
        ConfigAttr { attr_type, value: addr.octets().to_vec() }
    }

    fn write(&self, out: &mut Vec<u8>) {
        push_u16(out, self.attr_type & 0x7fff); // top bit reserved, MUST be 0
        push_u16(out, self.value.len() as u16);
        out.extend_from_slice(&self.value);
    }

    fn parse(buf: &[u8]) -> Result<(ConfigAttr, usize), IkeError> {
        if buf.len() < 4 {
            return Err(IkeError::Truncated { need: 4, have: buf.len() });
        }
        let attr_type = u16be(buf, 0) & 0x7fff;
        let len = u16be(buf, 2) as usize;
        if 4 + len > buf.len() {
            return Err(IkeError::BadLength { declared: 4 + len, available: buf.len() });
        }
        Ok((ConfigAttr { attr_type, value: buf[4..4 + len].to_vec() }, 4 + len))
    }
}

/// A Configuration payload body — CP (payload type 47, RFC 7296 §3.15). Carries
/// the responder's inner-IP assignment (CFG_REPLY) that a native IKEv2 client
/// (iOS/Android/strongSwan) needs to configure its tunnel interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Configuration {
    pub cfg_type: u8,
    pub attrs: Vec<ConfigAttr>,
}

impl Configuration {
    /// A CFG_REPLY assigning the peer an inner IPv4, with optional netmask + DNS.
    pub fn reply_ipv4(addr: Ipv4Addr, netmask: Option<Ipv4Addr>, dns: Option<Ipv4Addr>) -> Self {
        let mut attrs = vec![ConfigAttr::ipv4(config_attr::INTERNAL_IP4_ADDRESS, addr)];
        if let Some(m) = netmask {
            attrs.push(ConfigAttr::ipv4(config_attr::INTERNAL_IP4_NETMASK, m));
        }
        if let Some(d) = dns {
            attrs.push(ConfigAttr::ipv4(config_attr::INTERNAL_IP4_DNS, d));
        }
        Configuration { cfg_type: cfg_type::REPLY, attrs }
    }

    /// A CFG_REQUEST asking the responder to assign an inner IPv4/IPv6
    /// address and, if it hands out split-tunnel routes, to include them:
    /// empty INTERNAL_IP4_ADDRESS/INTERNAL_IP6_ADDRESS attributes (the
    /// virtual-IP requests) plus empty INTERNAL_IP4_SUBNET/INTERNAL_IP6_SUBNET
    /// attributes (a responder that has split-tunnel subnets to offer
    /// replies with one per range, read back with [`Self::assigned_subnets`]
    /// / [`Self::assigned_ipv6_subnets`]) plus empty INTERNAL_IP4_DNS/
    /// INTERNAL_IP6_DNS attributes (read back with [`Self::assigned_dns`] /
    /// [`Self::assigned_ipv6_dns`]) -- without these, a compliant responder
    /// has no reason to hand back DNS servers at all per RFC 7296 §3.15.1
    /// ("attribute value MAY be omitted...if the value was not requested");
    /// confirmed live against a real FortiGate that INTERNAL_IP4_DNS was
    /// missing from the request, and CFG_REPLY came back with no DNS as a
    /// direct result, same as the IKEv1 Mode-Config counterpart
    /// (`ikev1::modecfg::ConfigPayload::request_ipv4`) already includes for
    /// IPv4. Per RFC 7296 §3.15.1, an attribute a responder doesn't support
    /// or have a value for is simply omitted from CFG_REPLY, so requesting
    /// IPv6 here (address/subnet/DNS alike) is a no-op against an
    /// IPv4-only responder — an initiator that never asks for an IPv6
    /// attribute never gets one back either way.
    pub fn request_ipv4() -> Self {
        Configuration {
            cfg_type: cfg_type::REQUEST,
            attrs: vec![
                ConfigAttr { attr_type: config_attr::INTERNAL_IP4_ADDRESS, value: Vec::new() },
                ConfigAttr { attr_type: config_attr::INTERNAL_IP4_SUBNET, value: Vec::new() },
                ConfigAttr { attr_type: config_attr::INTERNAL_IP4_DNS, value: Vec::new() },
                ConfigAttr { attr_type: config_attr::INTERNAL_IP6_ADDRESS, value: Vec::new() },
                ConfigAttr { attr_type: config_attr::INTERNAL_IP6_SUBNET, value: Vec::new() },
                ConfigAttr { attr_type: config_attr::INTERNAL_IP6_DNS, value: Vec::new() },
            ],
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.cfg_type);
        out.extend_from_slice(&[0, 0, 0]); // RESERVED
        for a in &self.attrs {
            a.write(&mut out);
        }
        out
    }

    pub fn parse(body: &[u8]) -> Result<Configuration, IkeError> {
        if body.len() < 4 {
            return Err(IkeError::Truncated { need: 4, have: body.len() });
        }
        let cfg_type = body[0];
        let mut off = 4; // skip CFG type (1) + RESERVED (3)
        let mut attrs = Vec::new();
        while off < body.len() {
            let (a, consumed) = ConfigAttr::parse(&body[off..])?;
            attrs.push(a);
            off += consumed;
        }
        Ok(Configuration { cfg_type, attrs })
    }

    /// The first INTERNAL_IP4_ADDRESS attribute value, if present and well-formed.
    pub fn assigned_ipv4(&self) -> Option<Ipv4Addr> {
        self.attrs
            .iter()
            .find(|a| a.attr_type == config_attr::INTERNAL_IP4_ADDRESS && a.value.len() == 4)
            .map(|a| Ipv4Addr::new(a.value[0], a.value[1], a.value[2], a.value[3]))
    }

    /// Every INTERNAL_IP4_DNS attribute value — a responder may hand back more
    /// than one resolver. Empty if none were sent.
    pub fn assigned_dns(&self) -> Vec<Ipv4Addr> {
        self.attrs
            .iter()
            .filter(|a| a.attr_type == config_attr::INTERNAL_IP4_DNS && a.value.len() == 4)
            .map(|a| Ipv4Addr::new(a.value[0], a.value[1], a.value[2], a.value[3]))
            .collect()
    }

    /// Every INTERNAL_IP4_SUBNET attribute, as (network, prefix length) --
    /// a responder may hand back more than one (e.g. one per split-tunnel
    /// range), same as [`Self::assigned_dns`] for resolvers. Each value is
    /// network address (4 bytes) + netmask (4 bytes) — the same convention
    /// strongSwan uses.
    pub fn assigned_subnets(&self) -> Vec<(Ipv4Addr, u8)> {
        self.attrs
            .iter()
            .filter(|a| a.attr_type == config_attr::INTERNAL_IP4_SUBNET && a.value.len() == 8)
            .map(|a| {
                let net = Ipv4Addr::new(a.value[0], a.value[1], a.value[2], a.value[3]);
                let mask = u32::from_be_bytes([a.value[4], a.value[5], a.value[6], a.value[7]]);
                (net, mask.count_ones() as u8)
            })
            .collect()
    }

    /// The first INTERNAL_IP6_ADDRESS attribute, as (address, prefix length).
    /// The value is 17 octets -- a 16-byte address plus a 1-byte prefix
    /// length, per RFC 7296 §3.15.1 (unlike the IPv4 attribute, the prefix
    /// length travels with the address itself, not as a separate NETMASK
    /// attribute).
    pub fn assigned_ipv6(&self) -> Option<(Ipv6Addr, u8)> {
        self.attrs
            .iter()
            .find(|a| a.attr_type == config_attr::INTERNAL_IP6_ADDRESS && a.value.len() == 17)
            .map(|a| {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&a.value[..16]);
                (Ipv6Addr::from(octets), a.value[16])
            })
    }

    /// Every INTERNAL_IP6_DNS attribute value (16-byte address, no prefix
    /// length) -- same multi-resolver allowance as [`Self::assigned_dns`].
    pub fn assigned_ipv6_dns(&self) -> Vec<Ipv6Addr> {
        self.attrs
            .iter()
            .filter(|a| a.attr_type == config_attr::INTERNAL_IP6_DNS && a.value.len() == 16)
            .map(|a| {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&a.value);
                Ipv6Addr::from(octets)
            })
            .collect()
    }

    /// Every INTERNAL_IP6_SUBNET attribute, as (network, prefix length) --
    /// same split-tunnel allowance as [`Self::assigned_subnets`]. Each value
    /// is 17 octets: a 16-byte prefix plus a 1-byte prefix length.
    ///
    /// A `/0` entry is dropped regardless of the address bytes alongside
    /// it: a zero prefix length covers the entire address space no matter
    /// what those bytes are, so it isn't a split-tunnel range -- it carries
    /// no more information than the attribute being absent. Confirmed live
    /// against a real FortiGate with IPv6 left unconfigured: rather than
    /// omitting INTERNAL_IP6_SUBNET per RFC 7296 §3.15.1's own guidance for
    /// an attribute it has nothing to offer, it sends one back anyway with
    /// an all-zero value (`::`, prefix `0`) -- and no INTERNAL_IP6_ADDRESS.
    /// Left in the list, that value would read as "subnets were granted" to
    /// a caller checking `is_empty()`. Returning an empty list for it keeps
    /// "no split-tunnel range" distinct from a real one; whether the gateway
    /// offers IPv6 at all is told by [`Self::assigned_ipv6`] (which
    /// `daemon::service::finish_connect` gates the IPv6 CHILD SA on), and how
    /// much of it is tunneled by the `TSr` that CHILD SA is granted.
    pub fn assigned_ipv6_subnets(&self) -> Vec<(Ipv6Addr, u8)> {
        self.attrs
            .iter()
            .filter(|a| a.attr_type == config_attr::INTERNAL_IP6_SUBNET && a.value.len() == 17)
            .filter_map(|a| {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&a.value[..16]);
                let prefix_len = a.value[16];
                (prefix_len != 0).then(|| (Ipv6Addr::from(octets), prefix_len))
            })
            .collect()
    }
}

/// Notify Message Types (RFC 7296 §3.10.1 and later). Types < 16384 are errors;
/// ≥ 16384 are status.
pub mod notify_type {
    // Errors
    /// A request carried a payload of a type the receiver does not know with
    /// the critical flag set; the data is that type, one octet (RFC 7296 §2.5).
    pub const UNSUPPORTED_CRITICAL_PAYLOAD: u16 = 1;
    pub const INVALID_SYNTAX: u16 = 7;
    pub const INVALID_KE_PAYLOAD: u16 = 17;
    pub const NO_PROPOSAL_CHOSEN: u16 = 14;
    pub const AUTHENTICATION_FAILED: u16 = 24;
    /// The responder will only accept a single address pair (one TSi range, one
    /// TSr range) for the CHILD SA -- it can't take a multi-selector offer.
    pub const SINGLE_PAIR_REQUIRED: u16 = 34;
    pub const NO_ADDITIONAL_SAS: u16 = 35;
    pub const INTERNAL_ADDRESS_FAILURE: u16 = 36;
    pub const FAILED_CP_REQUIRED: u16 = 37;
    pub const TS_UNACCEPTABLE: u16 = 38;
    pub const INVALID_SELECTORS: u16 = 39;
    /// The request collided with an exchange still in progress (a rekey, say)
    /// and may be retried once that is done -- not right away (RFC 7296 §2.25).
    pub const TEMPORARY_FAILURE: u16 = 43;
    /// A request named a CHILD SA (a `REKEY_SA` notify, say) this side has no
    /// record of (RFC 7296 §3.10.1).
    pub const CHILD_SA_NOT_FOUND: u16 = 44;
    // Status
    pub const INITIAL_CONTACT: u16 = 16384;
    /// The responder narrowed the offered traffic selectors but would accept
    /// the remainder in a further CHILD SA (RFC 7296 §2.9).
    pub const ADDITIONAL_TS_POSSIBLE: u16 = 16386;
    pub const NAT_DETECTION_SOURCE_IP: u16 = 16388;
    pub const NAT_DETECTION_DESTINATION_IP: u16 = 16389;
    pub const COOKIE: u16 = 16390;
    pub const REKEY_SA: u16 = 16393;
    // MOBIKE (RFC 4555)
    pub const MOBIKE_SUPPORTED: u16 = 16396;
    pub const ADDITIONAL_IP4_ADDRESS: u16 = 16397;
    pub const ADDITIONAL_IP6_ADDRESS: u16 = 16398;
    pub const NO_ADDITIONAL_ADDRESSES: u16 = 16399;
    pub const UPDATE_SA_ADDRESSES: u16 = 16400;
    pub const COOKIE2: u16 = 16401;
    pub const NO_NATS_ALLOWED: u16 = 16402;
    pub const IKEV2_FRAGMENTATION_SUPPORTED: u16 = 16430;
    /// The initiator lists the signature hashes it supports (RFC 7427 §4); a
    /// responder doing Digital Signature auth must answer with a matching one.
    pub const SIGNATURE_HASH_ALGORITHMS: u16 = 16431;

    /// Whether `t` is one of the errors RFC 7296 §1.2 lets a responder return
    /// for the CHILD SA of `IKE_AUTH` *without* failing the IKE SA itself
    /// ("if creating the Child SA during the IKE_AUTH exchange fails for some
    /// reason, the IKE SA is still created as usual"): a rejected CHILD SA
    /// after a successful authentication, as opposed to a failed authentication.
    pub fn is_child_sa_error(t: u16) -> bool {
        matches!(
            t,
            NO_PROPOSAL_CHOSEN | TS_UNACCEPTABLE | SINGLE_PAIR_REQUIRED | INTERNAL_ADDRESS_FAILURE | FAILED_CP_REQUIRED
        )
    }
}

/// Hash Algorithm identifiers for `SIGNATURE_HASH_ALGORITHMS` (RFC 7427 §4).
pub mod sighash {
    pub const SHA1: u16 = 1;
    pub const SHA2_256: u16 = 2;
    pub const SHA2_384: u16 = 3;
    pub const SHA2_512: u16 = 4;
}

/// Certificate encodings (RFC 7296 §3.6, IANA registry).
pub mod cert_encoding {
    /// A DER X.509 certificate whose public key validates the AUTH signature.
    pub const X509_SIGNATURE: u8 = 4;
}

/// Notify payload body (RFC 7296 §3.10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notify {
    pub protocol_id: u8,
    pub spi: Vec<u8>,
    pub notify_type: u16,
    pub data: Vec<u8>,
}

impl Notify {
    /// A status/error notify not tied to a CHILD SA (no protocol, no SPI).
    pub fn status(notify_type: u16, data: Vec<u8>) -> Self {
        Notify { protocol_id: 0, spi: Vec::new(), notify_type, data }
    }

    /// Whether this is an error notify (type < 16384).
    pub fn is_error(&self) -> bool {
        self.notify_type < 16384
    }

    pub fn parse(body: &[u8]) -> Result<Notify, IkeError> {
        if body.len() < 4 {
            return Err(IkeError::Truncated { need: 4, have: body.len() });
        }
        let spi_size = body[1] as usize;
        if 4 + spi_size > body.len() {
            return Err(IkeError::BadLength { declared: 4 + spi_size, available: body.len() });
        }
        Ok(Notify {
            protocol_id: body[0],
            spi: body[4..4 + spi_size].to_vec(),
            notify_type: u16be(body, 2),
            data: body[4 + spi_size..].to_vec(),
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.spi.len() + self.data.len());
        out.push(self.protocol_id);
        out.push(self.spi.len() as u8);
        push_u16(&mut out, self.notify_type);
        out.extend_from_slice(&self.spi);
        out.extend_from_slice(&self.data);
        out
    }
}

/// Best-effort human name for the notify types most likely to show up while
/// debugging interop against a real gateway. Not exhaustive.
pub fn notify_type_name(t: u16) -> &'static str {
    match t {
        notify_type::UNSUPPORTED_CRITICAL_PAYLOAD => "UNSUPPORTED_CRITICAL_PAYLOAD",
        notify_type::INVALID_SYNTAX => "INVALID_SYNTAX",
        notify_type::INVALID_KE_PAYLOAD => "INVALID_KE_PAYLOAD",
        notify_type::NO_PROPOSAL_CHOSEN => "NO_PROPOSAL_CHOSEN",
        notify_type::AUTHENTICATION_FAILED => "AUTHENTICATION_FAILED",
        notify_type::SINGLE_PAIR_REQUIRED => "SINGLE_PAIR_REQUIRED",
        notify_type::NO_ADDITIONAL_SAS => "NO_ADDITIONAL_SAS",
        notify_type::INTERNAL_ADDRESS_FAILURE => "INTERNAL_ADDRESS_FAILURE",
        notify_type::FAILED_CP_REQUIRED => "FAILED_CP_REQUIRED",
        notify_type::TS_UNACCEPTABLE => "TS_UNACCEPTABLE",
        notify_type::INVALID_SELECTORS => "INVALID_SELECTORS",
        notify_type::TEMPORARY_FAILURE => "TEMPORARY_FAILURE",
        notify_type::CHILD_SA_NOT_FOUND => "CHILD_SA_NOT_FOUND",
        notify_type::ADDITIONAL_TS_POSSIBLE => "ADDITIONAL_TS_POSSIBLE",
        _ => "UNKNOWN",
    }
}

/// Delete payload (RFC 7296 §3.11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delete {
    pub protocol_id: u8,
    /// ESP/AH SPIs to delete (4 bytes each). Empty with `protocol_id == IKE`
    /// means "delete this IKE SA" (and thereby all its CHILD SAs).
    pub spis: Vec<u32>,
}

impl Delete {
    /// Delete the whole IKE SA.
    pub fn ike_sa() -> Self {
        Delete { protocol_id: protocol_id::IKE, spis: Vec::new() }
    }

    /// Delete the given ESP CHILD SAs by SPI.
    pub fn esp(spis: Vec<u32>) -> Self {
        Delete { protocol_id: protocol_id::ESP, spis }
    }

    /// A Delete payload's body, checked against RFC 7296 §3.11: the Protocol
    /// ID is IKE, AH or ESP; a Delete of the IKE SA has SPI Size 0 and names
    /// no SPI -- the IKE SA's SPIs are the header's -- and one of AH or ESP
    /// has SPI Size 4; the SPIs fill the rest of the payload exactly. Any
    /// other combination is a malformed payload, never read as a Delete of
    /// something else.
    pub fn parse(body: &[u8]) -> Result<Delete, IkeError> {
        if body.len() < 4 {
            return Err(IkeError::Truncated { need: 4, have: body.len() });
        }
        let protocol_id = body[0];
        let spi_size = usize::from(body[1]);
        let num = usize::from(u16be(body, 2));
        let size_of_its_spis = match protocol_id {
            protocol_id::IKE => 0,
            protocol_id::AH | protocol_id::ESP => 4,
            _ => return Err(IkeError::MalformedPayload("a Delete of a protocol other than IKE, AH or ESP")),
        };
        if spi_size != size_of_its_spis {
            return Err(IkeError::MalformedPayload("a Delete whose SPI Size is not its protocol's"));
        }
        if protocol_id == protocol_id::IKE && num != 0 {
            return Err(IkeError::MalformedPayload("a Delete of the IKE SA naming SPIs"));
        }
        if body.len() != 4 + num * spi_size {
            return Err(IkeError::MalformedPayload("a Delete whose SPIs do not fill it exactly"));
        }
        let spis = body[4..].chunks_exact(4).map(|spi| u32::from_be_bytes(spi.try_into().expect("four bytes"))).collect();
        Ok(Delete { protocol_id, spis })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let spi_size: u8 = if self.protocol_id == protocol_id::IKE { 0 } else { 4 };
        let mut out = Vec::with_capacity(4 + self.spis.len() * 4);
        out.push(self.protocol_id);
        out.push(spi_size);
        push_u16(&mut out, self.spis.len() as u16);
        for spi in &self.spis {
            out.extend_from_slice(&spi.to_be_bytes());
        }
        out
    }
}

/// Certificate payload (RFC 7296 §3.6): a 1-octet encoding + certificate data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    pub encoding: u8,
    pub data: Vec<u8>,
}

impl Certificate {
    /// A DER X.509 certificate (encoding 4).
    pub fn x509(der: Vec<u8>) -> Self {
        Certificate { encoding: cert_encoding::X509_SIGNATURE, data: der }
    }

    pub fn parse(body: &[u8]) -> Result<Certificate, IkeError> {
        let &encoding = body.first().ok_or(IkeError::Truncated { need: 1, have: 0 })?;
        Ok(Certificate { encoding, data: body[1..].to_vec() })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + self.data.len());
        out.push(self.encoding);
        out.extend_from_slice(&self.data);
        out
    }
}

/// Certificate Request payload (RFC 7296 §3.7): a 1-octet encoding + a bare
/// concatenation of 20-byte SHA-1 hashes of trusted CAs' `SubjectPublicKeyInfo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertRequest {
    pub encoding: u8,
    pub ca_hashes: Vec<[u8; 20]>,
}

impl CertRequest {
    /// Ask for an X.509 certificate. An empty list means "send any/your cert".
    pub fn x509(ca_hashes: Vec<[u8; 20]>) -> Self {
        CertRequest { encoding: cert_encoding::X509_SIGNATURE, ca_hashes }
    }

    pub fn parse(body: &[u8]) -> Result<CertRequest, IkeError> {
        let &encoding = body.first().ok_or(IkeError::Truncated { need: 1, have: 0 })?;
        let rest = &body[1..];
        if rest.len() % 20 != 0 {
            return Err(IkeError::BadLength { declared: rest.len(), available: rest.len() });
        }
        let ca_hashes = rest.chunks_exact(20).map(|c| c.try_into().unwrap()).collect();
        Ok(CertRequest { encoding, ca_hashes })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 20 * self.ca_hashes.len());
        out.push(self.encoding);
        for h in &self.ca_hashes {
            out.extend_from_slice(h);
        }
        out
    }
}

/// Proposals built byte by byte, for tests of what a peer can put on the wire
/// that [`Transform`] cannot say: attributes this crate does not understand.
#[cfg(test)]
pub(crate) mod test_wire {
    use super::push_u16;

    pub const KEY_LENGTH_128: [u8; 4] = [0x80, 14, 0x00, 0x80];
    pub const KEY_LENGTH_256: [u8; 4] = [0x80, 14, 0x01, 0x00];
    /// A TV attribute of a type IKEv2 has not defined.
    pub const UNKNOWN_ATTRIBUTE: [u8; 4] = [0x80, 99, 0, 1];

    /// A transform with `attrs` as its attribute area, its "Last Substruc" set by [`proposal`].
    pub fn transform(transform_type: u8, transform_id: u16, attrs: &[u8]) -> Vec<u8> {
        let mut out = vec![3, 0];
        push_u16(&mut out, (8 + attrs.len()) as u16);
        out.extend_from_slice(&[transform_type, 0]);
        push_u16(&mut out, transform_id);
        out.extend_from_slice(attrs);
        out
    }

    /// A proposal of `transforms`, its "Last Substruc" set by [`sa`].
    pub fn proposal(num: u8, protocol_id: u8, spi: &[u8], transforms: &[Vec<u8>]) -> Vec<u8> {
        let mut body = transforms.concat();
        let mut at = 0;
        for (i, t) in transforms.iter().enumerate() {
            if i + 1 == transforms.len() {
                body[at] = 0;
            }
            at += t.len();
        }
        let mut out = vec![2, 0];
        push_u16(&mut out, (8 + spi.len() + body.len()) as u16);
        out.extend_from_slice(&[num, protocol_id, spi.len() as u8, transforms.len() as u8]);
        out.extend_from_slice(spi);
        out.extend_from_slice(&body);
        out
    }

    /// The SA payload body holding `proposals`.
    pub fn sa(proposals: &[Vec<u8>]) -> Vec<u8> {
        let mut out = proposals.concat();
        let mut at = 0;
        for (i, p) in proposals.iter().enumerate() {
            if i + 1 == proposals.len() {
                out[at] = 0;
            }
            at += p.len();
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ike_proposal() -> Proposal {
        Proposal {
            num: 1,
            protocol_id: protocol_id::IKE,
            spi: Vec::new(),
            transforms: vec![
                Transform { transform_type: transform_type::ENCR, transform_id: transform_id::AES_GCM_16, key_length: Some(256) },
                Transform { transform_type: transform_type::PRF, transform_id: transform_id::PRF_HMAC_SHA2_256, key_length: None },
                Transform { transform_type: transform_type::DH, transform_id: transform_id::X25519, key_length: None },
                Transform { transform_type: transform_type::ESN, transform_id: transform_id::ESN_NONE, key_length: None },
            ],
        }
    }

    #[test]
    fn sa_roundtrips() {
        let sa = SecurityAssociation { proposals: vec![ike_proposal()] };
        let bytes = sa.to_bytes();
        assert_eq!(SecurityAssociation::parse(&bytes).unwrap(), sa);
    }

    #[test]
    fn certificate_roundtrips() {
        let c = Certificate::x509(vec![0x30, 0x82, 0x01, 0x02, 0xAB, 0xCD]);
        assert_eq!(c.encoding, cert_encoding::X509_SIGNATURE);
        assert_eq!(Certificate::parse(&c.to_bytes()).unwrap(), c);
        // A bare encoding byte with no cert data still parses (empty data).
        assert_eq!(Certificate::parse(&[4]).unwrap(), Certificate { encoding: 4, data: vec![] });
        assert!(Certificate::parse(&[]).is_err());
    }

    #[test]
    fn cert_request_roundtrips_including_empty() {
        let req = CertRequest::x509(vec![[0xAA; 20], [0x11; 20]]);
        assert_eq!(CertRequest::parse(&req.to_bytes()).unwrap(), req);
        // N == 0 is legal: "send any/your cert".
        let empty = CertRequest::x509(vec![]);
        assert_eq!(empty.to_bytes(), vec![cert_encoding::X509_SIGNATURE]);
        assert_eq!(CertRequest::parse(&empty.to_bytes()).unwrap(), empty);
        // A non-multiple-of-20 CA field is rejected, not truncated.
        assert!(CertRequest::parse(&[4, 0, 1, 2]).is_err());
    }

    #[test]
    fn sa_with_multiple_proposals_roundtrips() {
        let mut second = ike_proposal();
        second.num = 2;
        second.transforms[0] = Transform {
            transform_type: transform_type::ENCR,
            transform_id: transform_id::AES_CBC,
            key_length: Some(128),
        };
        second.transforms.insert(
            2,
            Transform { transform_type: transform_type::INTEG, transform_id: transform_id::AUTH_HMAC_SHA2_256_128, key_length: None },
        );
        let sa = SecurityAssociation { proposals: vec![ike_proposal(), second] };
        let bytes = sa.to_bytes();
        let parsed = SecurityAssociation::parse(&bytes).unwrap();
        assert_eq!(parsed, sa);
        assert_eq!(parsed.proposals[1].transforms[0].key_length, Some(128));
    }

    #[test]
    fn key_length_attribute_survives_roundtrip() {
        let sa = SecurityAssociation { proposals: vec![ike_proposal()] };
        let parsed = SecurityAssociation::parse(&sa.to_bytes()).unwrap();
        let encr = &parsed.proposals[0].transforms[0];
        assert_eq!(encr.transform_id, transform_id::AES_GCM_16);
        assert_eq!(encr.key_length, Some(256));
        assert_eq!(parsed.proposals[0].transforms[1].key_length, None);
    }

    #[test]
    fn ke_roundtrips() {
        let ke = KeyExchange { dh_group: transform_id::X25519, data: vec![0xAB; 32] };
        let bytes = ke.to_bytes();
        assert_eq!(bytes.len(), 4 + 32);
        assert_eq!(KeyExchange::parse(&bytes).unwrap(), ke);
    }

    #[test]
    fn nonce_roundtrips() {
        let nonce = Nonce { data: (0..32).collect() };
        assert_eq!(Nonce::parse(&nonce.to_bytes()).unwrap(), nonce);
    }

    #[test]
    fn nonce_rejects_out_of_range_lengths() {
        assert_eq!(Nonce::parse(&[0xAA; 15]), Err(IkeError::Crypto("nonce length out of range (16-256 bytes)")));
        assert_eq!(Nonce::parse(&[0xAA; 257]), Err(IkeError::Crypto("nonce length out of range (16-256 bytes)")));
        assert!(Nonce::parse(&[0xAA; 16]).is_ok());
        assert!(Nonce::parse(&[0xAA; 256]).is_ok());
    }

    #[test]
    fn identification_roundtrips() {
        let id = Identification::fqdn("gateway.example");
        let bytes = id.to_bytes();
        assert_eq!(bytes[0], id_type::FQDN);
        assert_eq!(&bytes[1..4], &[0, 0, 0]); // RESERVED
        assert_eq!(Identification::parse(&bytes).unwrap(), id);
    }

    #[test]
    fn authentication_roundtrips() {
        let auth = Authentication { method: auth_method::SHARED_KEY, data: vec![0xAB; 32] };
        assert_eq!(Authentication::parse(&auth.to_bytes()).unwrap(), auth);
    }

    #[test]
    fn traffic_selector_to_ipv4_cidr_covers_full_tunnel_and_a_narrowed_subnet() {
        assert_eq!(TrafficSelector::ipv4_any().to_ipv4_cidr(), Some((Ipv4Addr::new(0, 0, 0, 0), 0)));

        let subnet = TrafficSelector {
            ts_type: ts_type::IPV4_ADDR_RANGE,
            ip_protocol: 0,
            start_port: 0,
            end_port: 65535,
            start_addr: vec![10, 0, 99, 0],
            end_addr: vec![10, 0, 99, 255],
        };
        assert_eq!(subnet.to_ipv4_cidr(), Some((Ipv4Addr::new(10, 0, 99, 0), 24)));

        assert_eq!(TrafficSelector::ipv4_host(Ipv4Addr::new(10, 8, 0, 4)).to_ipv4_cidr(), Some((Ipv4Addr::new(10, 8, 0, 4), 32)));

        // Not CIDR-aligned -- no single prefix represents this exactly.
        let odd = TrafficSelector {
            ts_type: ts_type::IPV4_ADDR_RANGE,
            ip_protocol: 0,
            start_port: 0,
            end_port: 65535,
            start_addr: vec![10, 0, 0, 1],
            end_addr: vec![10, 0, 0, 200],
        };
        assert_eq!(odd.to_ipv4_cidr(), None);

        let ipv6 = TrafficSelector {
            ts_type: ts_type::IPV6_ADDR_RANGE,
            ip_protocol: 0,
            start_port: 0,
            end_port: 65535,
            start_addr: vec![0; 16],
            end_addr: vec![0xFF; 16],
        };
        assert_eq!(ipv6.to_ipv4_cidr(), None);
    }

    /// A TS payload body (RFC 7296 §3.13) declaring `count` selectors, followed by `selectors`.
    fn ts_body(count: u8, selectors: &[&[u8]]) -> Vec<u8> {
        let mut body = vec![count, 0, 0, 0];
        for s in selectors {
            body.extend_from_slice(s);
        }
        body
    }

    /// One Traffic Selector substructure (RFC 7296 §3.13.1), its Selector Length computed.
    fn ts_bytes(ts_type: u8, start_port: u16, end_port: u16, start: &[u8], end: &[u8]) -> Vec<u8> {
        let mut out = vec![ts_type, 0];
        out.extend_from_slice(&((8 + start.len() + end.len()) as u16).to_be_bytes());
        out.extend_from_slice(&start_port.to_be_bytes());
        out.extend_from_slice(&end_port.to_be_bytes());
        out.extend_from_slice(start);
        out.extend_from_slice(end);
        out
    }

    #[test]
    fn a_selector_is_within_another_only_when_it_matches_no_more_traffic() {
        let v4 = |proto: u8, ports: (u16, u16), start: [u8; 4], end: [u8; 4]| TrafficSelector {
            ts_type: ts_type::IPV4_ADDR_RANGE,
            ip_protocol: proto,
            start_port: ports.0,
            end_port: ports.1,
            start_addr: start.to_vec(),
            end_addr: end.to_vec(),
        };
        let any = TrafficSelector::ipv4_any();
        let net = v4(0, (0, 65535), [10, 0, 0, 0], [10, 0, 0, 255]);
        let host = TrafficSelector::ipv4_host(Ipv4Addr::new(10, 0, 0, 7));
        let tcp_net = v4(6, (0, 65535), [10, 0, 0, 0], [10, 0, 0, 255]);
        let https = v4(6, (443, 443), [10, 0, 0, 0], [10, 0, 0, 255]);
        let opaque = v4(0, (65535, 0), [10, 0, 0, 0], [10, 0, 0, 255]);
        let within = [
            (&host, &net),
            (&net, &any),
            (&any, &any),
            (&tcp_net, &net),   // any protocol covers TCP
            (&https, &tcp_net), // all ports cover one
            (&opaque, &net),    // ANY includes OPAQUE
            (&opaque, &opaque),
        ];
        for (inner, outer) in within {
            assert!(inner.is_within(outer), "{inner:?} not within {outer:?}");
        }
        let outside = [
            (&net, &host),
            (&any, &net),
            (&net, &tcp_net),   // any protocol is more than TCP
            (&tcp_net, &https), // all ports are more than one
            (&https, &opaque),  // OPAQUE includes only itself
            (&opaque, &https),
        ];
        for (inner, outer) in outside {
            assert!(!inner.is_within(outer), "{inner:?} within {outer:?}");
        }
        assert!(!TrafficSelector::ipv6_any().is_within(&any), "another family");
        let unknown = TrafficSelector { ts_type: 9, ..any.clone() };
        assert!(!unknown.is_within(&TrafficSelector { ts_type: 9, ..any.clone() }), "a type this crate does not know");

        let ipv4 = TrafficSelectors::ipv4_full_tunnel();
        let unified = TrafficSelectors::unified_full_tunnel();
        assert!(ipv4.is_within(&unified));
        assert!(unified.is_within(&unified));
        assert!(TrafficSelectors { selectors: vec![host.clone(), TrafficSelector::ipv6_any()] }.is_within(&unified));
        assert!(!unified.is_within(&ipv4), "IPv6 granted to an IPv4 offer");
        assert!(!TrafficSelectors { selectors: vec![host, unknown] }.is_within(&ipv4), "one selector outside is enough");
        assert!(!TrafficSelectors { selectors: vec![] }.is_within(&ipv4), "the null set");
    }

    #[test]
    fn a_proposal_narrowed_to_a_policy_keeps_only_the_traffic_both_match() {
        let v4 = |proto: u8, ports: (u16, u16), start: [u8; 4], end: [u8; 4]| TrafficSelector {
            ts_type: ts_type::IPV4_ADDR_RANGE,
            ip_protocol: proto,
            start_port: ports.0,
            end_port: ports.1,
            start_addr: start.to_vec(),
            end_addr: end.to_vec(),
        };
        let any = TrafficSelector::ipv4_any();
        let host = TrafficSelector::ipv4_host(Ipv4Addr::new(10, 0, 0, 7));
        let low = v4(0, (0, 65535), [10, 0, 0, 0], [10, 0, 0, 127]);
        let high = v4(0, (0, 65535), [10, 0, 0, 64], [10, 0, 0, 255]);
        let tcp = v4(6, (0, 65535), [0, 0, 0, 0], [255, 255, 255, 255]);
        let web = v4(0, (80, 443), [0, 0, 0, 0], [255, 255, 255, 255]);
        let alt = v4(0, (443, 8443), [0, 0, 0, 0], [255, 255, 255, 255]);
        let opaque = v4(0, (65535, 0), [0, 0, 0, 0], [255, 255, 255, 255]);
        let both = [
            (&any, &host, host.clone()),
            (&low, &high, v4(0, (0, 65535), [10, 0, 0, 64], [10, 0, 0, 127])),
            (&tcp, &any, tcp.clone()), // any protocol gives way to TCP
            (&web, &alt, v4(0, (443, 443), [0, 0, 0, 0], [255, 255, 255, 255])),
            (&opaque, &any, opaque.clone()), // ANY ports include OPAQUE
            (&any, &opaque, opaque.clone()),
            (&opaque, &opaque, opaque.clone()),
        ];
        for (a, b, expected) in both {
            assert_eq!(a.intersection(b), Some(expected.clone()), "{a:?} with {b:?}");
            assert_eq!(b.intersection(a), Some(expected), "{b:?} with {a:?}");
        }
        let udp = v4(17, (0, 65535), [0, 0, 0, 0], [255, 255, 255, 255]);
        let elsewhere = TrafficSelector::ipv4_host(Ipv4Addr::new(10, 0, 1, 1));
        let unknown = TrafficSelector { ts_type: 9, ..any.clone() };
        let none = [
            (&tcp, &udp),         // two protocols
            (&low, &elsewhere),   // disjoint addresses
            (&opaque, &web),      // OPAQUE meets only ANY and itself
            (&web, &v4(0, (8444, 9000), [0, 0, 0, 0], [255, 255, 255, 255])),
            (&any, &TrafficSelector::ipv6_any()),
            (&unknown, &unknown), // a type this crate does not know
        ];
        for (a, b) in none {
            assert_eq!(a.intersection(b), None, "{a:?} with {b:?}");
            assert_eq!(b.intersection(a), None, "{b:?} with {a:?}");
        }

        let set = |selectors: Vec<TrafficSelector>| TrafficSelectors { selectors };
        let ipv4 = TrafficSelectors::ipv4_full_tunnel();
        let unified = TrafficSelectors::unified_full_tunnel();
        // The initiator's first choice, taken whole, stays first.
        assert_eq!(set(vec![host.clone(), low.clone()]).narrowed_to(&ipv4), Some(set(vec![host.clone(), low.clone()])));
        assert_eq!(unified.narrowed_to(&ipv4), Some(ipv4.clone()), "the family the policy has");
        assert_eq!(ipv4.narrowed_to(&unified), Some(ipv4.clone()));
        assert_eq!(unified.narrowed_to(&unified), Some(unified.clone()));
        assert_eq!(ipv4.narrowed_to(&set(vec![host.clone()])), Some(set(vec![host.clone()])), "a wide proposal to a host policy");
        assert_eq!(set(vec![unknown.clone(), any.clone()]).narrowed_to(&ipv4), Some(ipv4.clone()), "an unknown type is ignored");
        assert_eq!(set(vec![low.clone(), low.clone()]).narrowed_to(&ipv4), Some(set(vec![low])), "no selector twice");
        assert_eq!(TrafficSelectors::ipv6_full_tunnel().narrowed_to(&ipv4), None, "nothing left: TS_UNACCEPTABLE");
        assert_eq!(set(vec![unknown]).narrowed_to(&unified), None);
        assert_eq!(set(vec![elsewhere]).narrowed_to(&set(vec![host])), None);
    }

    #[test]
    fn ts_payloads_are_taken_only_with_a_consistent_structure() {
        let v4 = ts_bytes(ts_type::IPV4_ADDR_RANGE, 0, 65535, &[10, 0, 0, 0], &[10, 0, 0, 255]);
        let v6 = ts_bytes(ts_type::IPV6_ADDR_RANGE, 0, 65535, &[0; 16], &[0xff; 16]);
        let rejected: [(&str, Vec<u8>); 7] = [
            // §3.13: "One or more individual Traffic Selectors".
            ("no selector", ts_body(0, &[])),
            ("octets past the last selector", [ts_body(1, &[&v4]), vec![0]].concat()),
            ("fewer selectors than counted", ts_body(2, &[&v4])),
            // §3.13.1: type 7 carries two four-octet addresses, type 8 two sixteen-octet ones.
            ("IPv4 range with IPv6-sized addresses", ts_body(1, &[&ts_bytes(ts_type::IPV4_ADDR_RANGE, 0, 65535, &[0; 16], &[0xff; 16])])),
            ("IPv6 range with IPv4-sized addresses", ts_body(1, &[&ts_bytes(ts_type::IPV6_ADDR_RANGE, 0, 65535, &[0; 4], &[0xff; 4])])),
            // §3.13.1: the Starting Address is the smallest, the Ending Address the largest.
            ("IPv4 range ending before it starts", ts_body(1, &[&ts_bytes(ts_type::IPV4_ADDR_RANGE, 0, 65535, &[10, 0, 0, 9], &[10, 0, 0, 1])])),
            ("IPv6 range ending before it starts", ts_body(1, &[&ts_bytes(ts_type::IPV6_ADDR_RANGE, 0, 65535, &[0xff; 16], &[0; 16])])),
        ];
        for (what, body) in rejected {
            assert!(TrafficSelectors::parse(&body).is_err(), "{what} was taken");
        }

        // Positive controls: what ryke offers, a host range, OPAQUE ports
        // (§3.13.1: start 65535, end 0), and a type this crate does not know,
        // which is kept for the caller to leave out (§2.9) rather than refused.
        for ts in [TrafficSelectors::ipv4_full_tunnel(), TrafficSelectors::unified_full_tunnel()] {
            assert_eq!(TrafficSelectors::parse(&ts.to_bytes()).unwrap(), ts);
        }
        let host = ts_bytes(ts_type::IPV4_ADDR_RANGE, 0, 65535, &[10, 0, 0, 1], &[10, 0, 0, 1]);
        let opaque = ts_bytes(ts_type::IPV4_ADDR_RANGE, 65535, 0, &[10, 0, 0, 0], &[10, 0, 0, 255]);
        let unknown = ts_bytes(9, 0, 65535, &[0, 0, 0, 1, 0, 0, 0, 0], &[0, 0, 0, 1, 0, 0, 0, 0]);
        let got = TrafficSelectors::parse(&ts_body(5, &[&v4, &v6, &host, &opaque, &unknown])).unwrap();
        assert_eq!(got.selectors.len(), 5);
        assert_eq!((got.selectors[3].start_port, got.selectors[3].end_port), (65535, 0));
        assert_eq!(got.selectors[4].ts_type, 9);
    }

    #[test]
    fn request_ipv4_asks_for_both_families_address_and_subnet() {
        let req = Configuration::request_ipv4();
        assert_eq!(req.cfg_type, cfg_type::REQUEST);
        let types: Vec<u16> = req.attrs.iter().map(|a| a.attr_type).collect();
        assert!(types.contains(&config_attr::INTERNAL_IP4_ADDRESS));
        assert!(types.contains(&config_attr::INTERNAL_IP4_SUBNET));
        assert!(types.contains(&config_attr::INTERNAL_IP4_DNS));
        assert!(types.contains(&config_attr::INTERNAL_IP6_ADDRESS));
        assert!(types.contains(&config_attr::INTERNAL_IP6_SUBNET));
        assert!(types.contains(&config_attr::INTERNAL_IP6_DNS));
        assert!(req.attrs.iter().all(|a| a.value.is_empty()), "a CFG_REQUEST asks with empty attribute values");
    }

    #[test]
    fn configuration_reads_back_assigned_ipv6_address_dns_and_subnets() {
        let addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        let mut addr_value = addr.octets().to_vec();
        addr_value.push(64); // prefix length

        let dns = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

        let subnet = Ipv6Addr::new(0xfd00, 0, 0, 0x10, 0, 0, 0, 0);
        let mut subnet_value = subnet.octets().to_vec();
        subnet_value.push(60);

        let cfg = Configuration {
            cfg_type: cfg_type::REPLY,
            attrs: vec![
                ConfigAttr { attr_type: config_attr::INTERNAL_IP6_ADDRESS, value: addr_value },
                ConfigAttr { attr_type: config_attr::INTERNAL_IP6_DNS, value: dns.octets().to_vec() },
                ConfigAttr { attr_type: config_attr::INTERNAL_IP6_SUBNET, value: subnet_value },
            ],
        };

        assert_eq!(cfg.assigned_ipv6(), Some((addr, 64)));
        assert_eq!(cfg.assigned_ipv6_dns(), vec![dns]);
        assert_eq!(cfg.assigned_ipv6_subnets(), vec![(subnet, 60)]);

        // Round-trips through wire encoding too.
        let parsed = Configuration::parse(&cfg.to_bytes()).unwrap();
        assert_eq!(parsed.assigned_ipv6(), Some((addr, 64)));
    }

    /// Real FortiGate behavior with IPv6 left unconfigured: instead of
    /// omitting INTERNAL_IP6_SUBNET, it sends one back with an all-zero
    /// value (`::`, prefix `0`). Must read back as no subnets granted at
    /// all -- a caller (`daemon::service::finish_connect`) gates the IPv6
    /// kill-switch on `is_empty()`, so a `/0` entry surviving here would
    /// silently disable it on every IPv4-only gateway that does this.
    #[test]
    fn assigned_ipv6_subnets_drops_all_zero_slash_zero_entries() {
        let mut junk_value = Ipv6Addr::UNSPECIFIED.octets().to_vec();
        junk_value.push(0); // prefix length

        let real_subnet = Ipv6Addr::new(0xfd00, 0, 0, 0x10, 0, 0, 0, 0);
        let mut real_value = real_subnet.octets().to_vec();
        real_value.push(64);

        let junk_only = Configuration {
            cfg_type: cfg_type::REPLY,
            attrs: vec![ConfigAttr { attr_type: config_attr::INTERNAL_IP6_SUBNET, value: junk_value.clone() }],
        };
        assert_eq!(junk_only.assigned_ipv6_subnets(), Vec::new());

        // A real subnet alongside the junk one still comes through --
        // only the meaningless /0 entry is dropped.
        let mixed = Configuration {
            cfg_type: cfg_type::REPLY,
            attrs: vec![
                ConfigAttr { attr_type: config_attr::INTERNAL_IP6_SUBNET, value: junk_value },
                ConfigAttr { attr_type: config_attr::INTERNAL_IP6_SUBNET, value: real_value },
            ],
        };
        assert_eq!(mixed.assigned_ipv6_subnets(), vec![(real_subnet, 64)]);
    }

    #[test]
    fn notify_roundtrips_and_classifies() {
        let n = Notify::status(notify_type::NAT_DETECTION_SOURCE_IP, vec![0xEE; 20]);
        assert_eq!(Notify::parse(&n.to_bytes()).unwrap(), n);
        assert!(!n.is_error());
        assert!(Notify::status(notify_type::NO_PROPOSAL_CHOSEN, vec![]).is_error());

        // With a CHILD-SA SPI attached (e.g. a REKEY_SA notify).
        let with_spi = Notify { protocol_id: protocol_id::ESP, spi: vec![1, 2, 3, 4], notify_type: notify_type::REKEY_SA, data: vec![] };
        assert_eq!(Notify::parse(&with_spi.to_bytes()).unwrap(), with_spi);
    }

    #[test]
    fn child_sa_notify_values_match_the_iana_registry() {
        // IANA "IKEv2 Notify Message Types" (checked against the registry, not
        // from memory): errors 14/34-39, status 16386.
        assert_eq!(notify_type::NO_PROPOSAL_CHOSEN, 14);
        assert_eq!(notify_type::SINGLE_PAIR_REQUIRED, 34);
        assert_eq!(notify_type::NO_ADDITIONAL_SAS, 35);
        assert_eq!(notify_type::INTERNAL_ADDRESS_FAILURE, 36);
        assert_eq!(notify_type::FAILED_CP_REQUIRED, 37);
        assert_eq!(notify_type::TS_UNACCEPTABLE, 38);
        assert_eq!(notify_type::INVALID_SELECTORS, 39);
        assert_eq!(notify_type::ADDITIONAL_TS_POSSIBLE, 16386);
        // ...and they read as errors/status by the < 16384 rule.
        assert!(Notify::status(notify_type::SINGLE_PAIR_REQUIRED, vec![]).is_error());
        assert!(!Notify::status(notify_type::ADDITIONAL_TS_POSSIBLE, vec![]).is_error());
        assert_eq!(notify_type_name(notify_type::SINGLE_PAIR_REQUIRED), "SINGLE_PAIR_REQUIRED");
        assert_eq!(notify_type_name(notify_type::ADDITIONAL_TS_POSSIBLE), "ADDITIONAL_TS_POSSIBLE");
    }

    #[test]
    fn only_the_rfc_7296_child_sa_errors_leave_the_ike_sa_standing() {
        // RFC 7296 §1.2's list for a CHILD SA that fails inside IKE_AUTH.
        for t in [
            notify_type::NO_PROPOSAL_CHOSEN,
            notify_type::TS_UNACCEPTABLE,
            notify_type::SINGLE_PAIR_REQUIRED,
            notify_type::INTERNAL_ADDRESS_FAILURE,
            notify_type::FAILED_CP_REQUIRED,
        ] {
            assert!(notify_type::is_child_sa_error(t), "{} should be a CHILD SA error", notify_type_name(t));
        }
        // An authentication failure, or a status notify, is not.
        assert!(!notify_type::is_child_sa_error(notify_type::AUTHENTICATION_FAILED));
        assert!(!notify_type::is_child_sa_error(notify_type::INITIAL_CONTACT));
        assert!(!notify_type::is_child_sa_error(notify_type::ADDITIONAL_TS_POSSIBLE));
    }

    #[test]
    fn delete_roundtrips() {
        let ike = Delete::ike_sa();
        assert_eq!(Delete::parse(&ike.to_bytes()).unwrap(), ike);
        assert!(ike.spis.is_empty());

        let esp = Delete::esp(vec![0xDEAD_BEEF, 0x0000_0001]);
        let bytes = esp.to_bytes();
        assert_eq!(bytes[1], 4); // SPI size
        assert_eq!(u16::from_be_bytes([bytes[2], bytes[3]]), 2); // count
        assert_eq!(Delete::parse(&bytes).unwrap(), esp);
    }

    /// RFC 7296 §3.11: SPI Size is 0 for the IKE SA, which names no SPI, and
    /// 4 for AH and ESP, and the SPIs fill the payload exactly. A Delete of
    /// the IKE SA with SPI Size 4 and one SPI used to parse as a Delete of
    /// the IKE SA; one of ESP with SPI Size 0, as a Delete of no CHILD SA;
    /// and SPIs past the count were ignored.
    #[test]
    fn a_delete_whose_protocol_spi_size_count_or_length_disagree_is_malformed() {
        let malformed: [(&str, &[u8]); 9] = [
            ("IKE, SPI Size 4, one SPI", &[1, 4, 0, 1, 0, 0, 0, 1]),
            ("IKE, SPI Size 0, Num 1", &[1, 0, 0, 1]),
            ("IKE, bytes past the header", &[1, 0, 0, 0, 0, 0, 0, 0]),
            ("ESP, SPI Size 0", &[3, 0, 0, 0]),
            ("ESP, SPI Size 8", &[3, 8, 0, 1, 0, 0, 0, 0, 0, 0, 0xAA, 0xAA]),
            ("ESP, two SPIs announced, one there", &[3, 4, 0, 2, 0, 0, 0xAA, 0xAA]),
            ("ESP, one SPI announced, two there", &[3, 4, 0, 1, 0, 0, 0xAA, 0xAA, 0, 0, 0x77, 0x77]),
            ("AH, SPI Size 0", &[2, 0, 0, 0]),
            ("Protocol ID 0", &[0, 4, 0, 1, 0, 0, 0xAA, 0xAA]),
        ];
        for (case, body) in malformed {
            assert!(matches!(Delete::parse(body), Err(IkeError::MalformedPayload(_))), "{case}");
        }
        assert!(matches!(Delete::parse(&[1, 0, 0]), Err(IkeError::Truncated { .. })));

        // Well formed: the IKE SA's, and AH's and ESP's with any number of SPIs.
        assert_eq!(Delete::parse(&[1, 0, 0, 0]).unwrap(), Delete::ike_sa());
        assert_eq!(Delete::parse(&[2, 4, 0, 1, 0, 0, 0xAA, 0xAA]).unwrap(), Delete { protocol_id: protocol_id::AH, spis: vec![0xAAAA] });
        assert_eq!(Delete::parse(&[3, 4, 0, 0]).unwrap(), Delete::esp(Vec::new()));
        assert_eq!(Delete::parse(&[3, 4, 0, 2, 0, 0, 0xAA, 0xAA, 0, 0, 0x77, 0x77]).unwrap(), Delete::esp(vec![0xAAAA, 0x7777]));
    }

    #[test]
    fn ipv6_selector_cidr_conversion() {
        assert_eq!(TrafficSelector::ipv6_any().to_ipv6_cidr(), Some((Ipv6Addr::UNSPECIFIED, 0)));
        assert_eq!(TrafficSelector::ipv6_any().to_ipv4_cidr(), None);
        assert_eq!(TrafficSelector::ipv4_any().to_ipv6_cidr(), None);

        // A /64: start = prefix, end = prefix | host bits.
        let net = Ipv6Addr::new(0x2001, 0x470, 0xda14, 1, 0, 0, 0, 0);
        let sel = TrafficSelector {
            ts_type: ts_type::IPV6_ADDR_RANGE,
            ip_protocol: 0,
            start_port: 0,
            end_port: 65535,
            start_addr: net.octets().to_vec(),
            end_addr: Ipv6Addr::new(0x2001, 0x470, 0xda14, 1, 0xffff, 0xffff, 0xffff, 0xffff).octets().to_vec(),
        };
        assert_eq!(sel.to_ipv6_cidr(), Some((net, 64)));

        // A single host is a /128.
        let host = Ipv6Addr::new(0x2001, 0x470, 0xda14, 0x200, 0, 0, 0, 1);
        let host_sel = TrafficSelector { start_addr: host.octets().to_vec(), end_addr: host.octets().to_vec(), ..sel.clone() };
        assert_eq!(host_sel.to_ipv6_cidr(), Some((host, 128)));

        // Not CIDR-aligned (::1 - ::2) and inverted ranges have no single-prefix form.
        let unaligned = TrafficSelector {
            start_addr: Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1).octets().to_vec(),
            end_addr: Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2).octets().to_vec(),
            ..sel.clone()
        };
        assert_eq!(unaligned.to_ipv6_cidr(), None);
        let inverted = TrafficSelector { start_addr: sel.end_addr.clone(), end_addr: sel.start_addr.clone(), ..sel };
        assert_eq!(inverted.to_ipv6_cidr(), None);
    }

    #[test]
    fn ipv6_full_tunnel_is_a_lone_ipv6_selector() {
        let ts = TrafficSelectors::ipv6_full_tunnel();
        assert_eq!(ts.selectors, vec![TrafficSelector::ipv6_any()]);
        assert_eq!(TrafficSelectors::parse(&ts.to_bytes()).unwrap(), ts);
    }

    #[test]
    fn unified_full_tunnel_mixes_both_families_in_one_payload() {
        let ts = TrafficSelectors::unified_full_tunnel();
        assert_eq!(ts.selectors, vec![TrafficSelector::ipv4_any(), TrafficSelector::ipv6_any()]);
        assert!(ts.has_ipv4() && ts.has_ipv6());
        assert_eq!(TrafficSelectors::parse(&ts.to_bytes()).unwrap(), ts);

        let v4 = TrafficSelectors::ipv4_full_tunnel();
        assert!(v4.has_ipv4() && !v4.has_ipv6());
        let v6 = TrafficSelectors::ipv6_full_tunnel();
        assert!(!v6.has_ipv4() && v6.has_ipv6());
    }

    #[test]
    fn traffic_selectors_roundtrip() {
        let ts = TrafficSelectors { selectors: vec![TrafficSelector::ipv4_any()] };
        let parsed = TrafficSelectors::parse(&ts.to_bytes()).unwrap();
        assert_eq!(parsed, ts);
        assert_eq!(parsed.selectors[0].start_addr, vec![0, 0, 0, 0]);
        assert_eq!(parsed.selectors[0].end_addr, vec![255, 255, 255, 255]);
        assert_eq!(parsed.selectors[0].end_port, 65535);

        // A two-selector set with a specific subnet also roundtrips.
        let ts2 = TrafficSelectors {
            selectors: vec![
                TrafficSelector::ipv4_any(),
                TrafficSelector {
                    ts_type: ts_type::IPV4_ADDR_RANGE,
                    ip_protocol: 6, // TCP
                    start_port: 443,
                    end_port: 443,
                    start_addr: vec![10, 0, 0, 0],
                    end_addr: vec![10, 0, 0, 255],
                },
            ],
        };
        assert_eq!(TrafficSelectors::parse(&ts2.to_bytes()).unwrap(), ts2);
    }

    #[test]
    fn truncated_inputs_are_rejected_not_panicked() {
        assert!(matches!(KeyExchange::parse(&[0, 31, 0]), Err(IkeError::Truncated { .. })));
        assert!(SecurityAssociation::parse(&[0, 0, 0, 4]).is_err());
    }

    /// One raw transform with `attrs` as its attribute area.
    fn raw_transform(transform_type: u8, transform_id: u16, attrs: &[u8], is_last: bool) -> Vec<u8> {
        let mut out = vec![if is_last { 0 } else { 3 }, 0];
        push_u16(&mut out, (8 + attrs.len()) as u16);
        out.extend_from_slice(&[transform_type, 0]);
        push_u16(&mut out, transform_id);
        out.extend_from_slice(attrs);
        out
    }

    /// One raw IKE proposal (a single-proposal SA body) holding `transforms`,
    /// followed by `tail` inside the proposal's own Length.
    fn raw_sa(transforms: &[Vec<u8>], tail: &[u8]) -> Vec<u8> {
        let body: Vec<u8> = transforms.concat();
        let mut out = vec![0, 0];
        push_u16(&mut out, (8 + body.len() + tail.len()) as u16);
        out.extend_from_slice(&[1, protocol_id::IKE, 0, transforms.len() as u8]);
        out.extend_from_slice(&body);
        out.extend_from_slice(tail);
        out
    }

    const KL_256_TV: [u8; 4] = [0x80, 14, 0x01, 0x00];

    #[test]
    fn a_transform_with_an_attribute_we_do_not_understand_is_unacceptable() {
        // RFC 7296 §3.3.6: such a transform MUST be considered unacceptable;
        // other transforms of the same type are processed as usual.
        let cases: [(&str, Vec<u8>); 5] = [
            ("unknown TV attribute", [&KL_256_TV[..], &[0x80, 99, 0, 1]].concat()),
            ("unknown TLV attribute", [&KL_256_TV[..], &[0x00, 99, 0, 2, 0xAB, 0xCD]].concat()),
            // §3.3.5: a fixed-length attribute MUST NOT use the TLV encoding.
            ("Key Length as TLV", vec![0x00, 14, 0, 2, 0x01, 0x00]),
            ("Key Length twice", [&KL_256_TV[..], &[0x80, 14, 0x00, 0x80]].concat()),
            ("Key Length twice, same value", [KL_256_TV, KL_256_TV].concat()),
        ];
        for (what, attrs) in cases {
            let sa = raw_sa(
                &[
                    raw_transform(transform_type::ENCR, transform_id::AES_GCM_16, &attrs, false),
                    raw_transform(transform_type::ENCR, transform_id::AES_GCM_16, &[0x80, 14, 0x00, 0x80], false),
                    raw_transform(transform_type::PRF, transform_id::PRF_HMAC_SHA2_256, &[], true),
                ],
                &[],
            );
            let parsed = SecurityAssociation::parse(&sa).unwrap_or_else(|e| panic!("{what}: {e:?}"));
            // Left out it would leave the peer's offer looking like something
            // else -- a type it insisted on gone, two answered transforms one --
            // so it stays, as one that names nothing we could run.
            assert_eq!(
                parsed.proposals[0].transforms,
                vec![
                    Transform { transform_type: transform_type::ENCR, transform_id: transform_id::UNUSABLE, key_length: None },
                    Transform { transform_type: transform_type::ENCR, transform_id: transform_id::AES_GCM_16, key_length: Some(128) },
                    Transform { transform_type: transform_type::PRF, transform_id: transform_id::PRF_HMAC_SHA2_256, key_length: None },
                ],
                "{what}"
            );
        }
    }

    #[test]
    fn an_unusable_transform_keeps_its_type_whatever_the_type_is() {
        // RFC 7296 §3.3.6: a Transform Type we do not know makes the whole
        // proposal unacceptable -- also when its transform carries an attribute
        // we do not know, which used to make it vanish without a trace.
        use super::test_wire::{proposal, sa, transform, UNKNOWN_ATTRIBUTE};
        let body = sa(&[proposal(
            1,
            protocol_id::IKE,
            &[],
            &[
                transform(transform_type::ENCR, transform_id::AES_GCM_16, &super::test_wire::KEY_LENGTH_256),
                transform(99, 7, &UNKNOWN_ATTRIBUTE),
                transform(transform_type::INTEG, transform_id::AUTH_HMAC_SHA2_256_128, &UNKNOWN_ATTRIBUTE),
                transform(transform_type::ESN, transform_id::ESN_NONE, &UNKNOWN_ATTRIBUTE),
                transform(transform_type::DH, transform_id::X25519, &UNKNOWN_ATTRIBUTE),
            ],
        )]);
        let parsed = SecurityAssociation::parse(&body).unwrap();
        let unusable = |ty: u8| Transform { transform_type: ty, transform_id: transform_id::UNUSABLE, key_length: None };
        assert_eq!(
            parsed.proposals[0].transforms,
            vec![
                Transform { transform_type: transform_type::ENCR, transform_id: transform_id::AES_GCM_16, key_length: Some(256) },
                unusable(99),
                unusable(transform_type::INTEG),
                unusable(transform_type::ESN),
                unusable(transform_type::DH),
            ]
        );
    }

    #[test]
    fn the_transform_count_is_kept_whatever_the_transforms_are() {
        use super::test_wire::{proposal, sa, transform, UNKNOWN_ATTRIBUTE};
        let body = sa(&[proposal(
            1,
            protocol_id::ESP,
            &[1, 2, 3, 4],
            &[
                transform(transform_type::ENCR, transform_id::AES_GCM_16, &UNKNOWN_ATTRIBUTE),
                transform(transform_type::ENCR, transform_id::AES_GCM_16, &UNKNOWN_ATTRIBUTE),
                transform(transform_type::ESN, transform_id::ESN_NONE, &[]),
            ],
        )]);
        assert_eq!(SecurityAssociation::parse(&body).unwrap().proposals[0].transforms.len(), 3);
    }

    #[test]
    fn a_single_tv_key_length_is_understood() {
        let sa = raw_sa(&[raw_transform(transform_type::ENCR, transform_id::AES_CBC, &KL_256_TV, true)], &[]);
        let parsed = SecurityAssociation::parse(&sa).unwrap();
        assert_eq!(
            parsed.proposals[0].transforms,
            vec![Transform { transform_type: transform_type::ENCR, transform_id: transform_id::AES_CBC, key_length: Some(256) }]
        );
    }

    #[test]
    fn attribute_bytes_that_do_not_form_an_attribute_are_malformed() {
        for tail in [&[0x80][..], &[0x80, 14], &[0x80, 14, 0x01]] {
            let attrs = [&KL_256_TV[..], tail].concat();
            let sa = raw_sa(&[raw_transform(transform_type::ENCR, transform_id::AES_CBC, &attrs, true)], &[]);
            assert!(SecurityAssociation::parse(&sa).is_err(), "{} stray attribute byte(s) accepted", tail.len());
        }
    }

    #[test]
    fn bytes_after_a_proposals_transforms_are_malformed() {
        let transforms = [raw_transform(transform_type::ENCR, transform_id::AES_CBC, &KL_256_TV, true)];
        assert!(SecurityAssociation::parse(&raw_sa(&transforms, &[])).is_ok());
        for tail in [&[0u8][..], &[0, 0, 0, 0], &[0; 8]] {
            assert!(SecurityAssociation::parse(&raw_sa(&transforms, tail)).is_err(), "{} trailing byte(s) accepted", tail.len());
        }
    }
}
