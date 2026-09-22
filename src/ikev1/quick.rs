//! IKEv1 Quick Mode (RFC 2409 §5.5) — negotiates an ESP CHILD SA under the
//! Phase-1 SKEYIDs. Both the initiator and responder halves are provided; PSK,
//! no client IDs (the SA protects the tunnel endpoints). PFS is optional (the
//! `_with_pfs` initiator entry point / automatic on the responder side,
//! gated on whether the initiator's ESP proposal carries a GROUP DESCRIPTION
//! attribute) -- see the PFS section below.
//!
//! ```text
//! I → HDR*, HASH(1), SA, Ni, [KE]
//! R → HDR*, HASH(2), SA, Nr, [KE]
//! I → HDR*, HASH(3)
//! ```
//!
//! `HASH(1) = prf(SKEYID_a, M-ID | SA | Ni [| KE])`,
//! `HASH(2) = prf(SKEYID_a, M-ID | Ni_b | SA | Nr [| KE])`,
//! `HASH(3) = prf(SKEYID_a, 0 | M-ID | Ni_b | Nr_b)`.
//!
//! The ESP cipher is algorithm-agile (any [`SkCipher`] the caller picks --
//! AEAD or classic-CBC-with-separate-HMAC), the same cipher catalog
//! [`crate::esp::EspSa`] implements for IKEv2. KEYMAT is a single
//! `enc_key_len + salt_len + integ_key_len`-byte blob per SPI, derived from
//! `SKEYID_d` and the Quick-Mode nonces (no PFS) or additionally the
//! Quick-Mode DH shared secret (PFS, RFC 2409 §5.5's `g(qm)^xy` variant --
//! see [`crypto1::keymat_pfs`]). Unlike IKEv2 (where PFS only ever applies at
//! a later `CREATE_CHILD_SA` rekey -- see [`crate::ikev2::rekey`]), IKEv1
//! Quick Mode negotiates PFS on the *initial* Phase-2 exchange, so it's
//! testable at connect time.

use std::net::{Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use super::crypto1::{self, Prf, AES_BLOCK};
use super::informational;
use super::isakmp::{self, exchange, payload, IsakmpHeader, Payload};
use super::payloads::{
    id_type, protocol, Attribute, Id, Proposal, SaPayload, Transform, IPSEC_DOI, SIT_IDENTITY_ONLY,
};
use super::phase1::Phase1State;
use super::phase2;
use crate::crypto::{DhGroup, IntegAlgorithm};
use crate::debug::ike_debug;
use crate::entropy::Entropy;
use crate::error::IkeError;
use crate::esp::{ChildSa, EspSa};
use crate::ikev2::natt::{unwrap_ike_4500, wrap_ike_4500};
use crate::ikev2::payload::transform_id;
use crate::ikev2::sk::SkCipher;
use crate::transport::{DriverError, IkeSocket};
use zeroize::Zeroize;

/// One direction's derived ESP key material -- cipher-tagged so the caller
/// (e.g. a kernel XFRM installer) knows how to interpret `enc`/`integ`
/// without re-deriving or re-negotiating anything. Zeroized on drop; `Debug`
/// never prints the raw bytes.
#[derive(Clone, PartialEq, Eq, Zeroize)]
pub struct ChildKeyMaterial {
    #[zeroize(skip)]
    pub cipher: SkCipher,
    pub enc: Vec<u8>,
    pub integ: Vec<u8>,
}

impl std::fmt::Debug for ChildKeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChildKeyMaterial")
            .field("cipher", &self.cipher)
            .field("enc", &format_args!("[{} bytes REDACTED]", self.enc.len()))
            .field("integ", &format_args!("[{} bytes REDACTED]", self.integ.len()))
            .finish()
    }
}

/// The result of a completed CHILD SA rekey: the new SPIs plus both
/// directions' fresh key material, ready for a caller to install as the
/// data plane's new SAs (this crate never installs kernel state itself --
/// see [`crate::esp::EspSa`]'s own doc for why).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RekeyedChild {
    pub local_spi: u32,
    pub peer_spi: u32,
    pub key_out: ChildKeyMaterial,
    pub key_in: ChildKeyMaterial,
}

/// IPsec ESP SA attribute types (RFC 2407 §4.5) — a *different* registry from the
/// Phase-1 IKE attributes: here KEY_LENGTH is 6, not 14.
mod esp_attr {
    pub const LIFE_TYPE: u16 = 1;
    pub const LIFE_DURATION: u16 = 2;
    /// PFS group -- present on the ESP proposal transform only when PFS is
    /// wanted; its mere presence is the signal both `initiate_quick_with_pfs`
    /// and `respond_quick` key off of. Same attribute number as the IKE DOI's
    /// own Phase-1 `GROUP_DESC` (see `phase1::attr::GROUP_DESC`) -- RFC 2407
    /// §4.5 and RFC 2409 §5 happen to share attribute type 3 for this.
    pub const GROUP_DESC: u16 = 3;
    pub const ENCAP_MODE: u16 = 4;
    pub const KEY_LENGTH: u16 = 6;
    /// Separate integrity algorithm for a classic (non-AEAD) cipher (RFC 2407
    /// §4.5) -- absent for an AEAD cipher, which needs no separate check.
    pub const AUTH_ALGORITHM: u16 = 5;
}
const ENCAP_TUNNEL: u16 = 1;
/// UDP-encapsulated tunnel mode (RFC 3947 §4.3.1's final IANA value, as
/// opposed to the legacy private-range 61443 some pre-RFC drafts used) --
/// used instead of `ENCAP_TUNNEL` whenever `Phase1State::floated` is `true`,
/// mirroring isakmpd's own `ike_quick_mode.c` switch (confirmed by reading
/// it: it selects the RFC-final value there too, never the draft one, since
/// this crate only advertises the RFC 3947 Vendor ID -- see
/// `phase1::NATT_RFC_VENDOR_ID`'s doc).
const UDP_ENCAP_TUNNEL: u16 = 3;
const LIFE_SECONDS: u16 = 1;

/// This registry (RFC 2407 §4.5's ESP `AUTH_ALGORITHM` attribute values) is
/// numbered independently of IKEv2's own INTEG transform IDs
/// ([`crate::ikev2::payload::transform_id::AUTH_HMAC_SHA2_256_128`] etc.) --
/// e.g. HMAC-SHA2-256 is value 5 here but transform ID 12 there. Confirmed
/// against a real FortiGate's own IKE debug log (`type = AUTH_ALG,
/// val=SHA2_256`, ESP_AES_CBC proposal).
fn esp_auth_algorithm(integ: IntegAlgorithm) -> u16 {
    match integ {
        IntegAlgorithm::HmacMd5_96 => 1,
        IntegAlgorithm::HmacSha1_96 => 2,
        IntegAlgorithm::HmacSha2_256_128 => 5,
        IntegAlgorithm::HmacSha2_384_192 => 6,
        IntegAlgorithm::HmacSha2_512_256 => 7,
    }
}

fn integ_from_esp_auth_algorithm(v: u16) -> Option<IntegAlgorithm> {
    match v {
        1 => Some(IntegAlgorithm::HmacMd5_96),
        2 => Some(IntegAlgorithm::HmacSha1_96),
        5 => Some(IntegAlgorithm::HmacSha2_256_128),
        6 => Some(IntegAlgorithm::HmacSha2_384_192),
        7 => Some(IntegAlgorithm::HmacSha2_512_256),
        _ => None,
    }
}

/// The ESP transform ID for `cipher` -- the same unified IANA "Transform Type
/// 1" numbering [`transform_id`] already uses for IKEv2 (RFC 4835/8221
/// unified the IKEv1 ESP and IKEv2 registries for every algorithm `ryke`
/// implements), just narrowed to `u8` for IKEv1's `Transform::transform_id` field.
fn esp_transform_id(cipher: SkCipher) -> u8 {
    (match cipher {
        SkCipher::Aes128Gcm | SkCipher::Aes192Gcm | SkCipher::Aes256Gcm => transform_id::AES_GCM_16,
        SkCipher::ChaCha20Poly1305 => transform_id::CHACHA20_POLY1305,
        SkCipher::Aes128Cbc(_) | SkCipher::Aes192Cbc(_) | SkCipher::Aes256Cbc(_) => transform_id::AES_CBC,
        SkCipher::TripleDesCbc(_) => transform_id::TRIPLE_DES,
    }) as u8
}

fn find(ps: &[Payload], t: u8) -> Option<&Payload> {
    ps.iter().find(|p| p.payload_type == t)
}

/// RFC 2407 §4.5: the responder isn't bound to the initiator's offered ESP
/// SA lifetime and may unilaterally pick a shorter one -- read whatever the
/// responder actually put on the SA payload's ESP transform (`ps`), falling
/// back to `offered` (what we ourselves proposed) when the responder didn't
/// carry a LIFE_DURATION attribute at all. Mirrors
/// `phase1::negotiated_p1_lifetime`'s exact same RFC rationale, just against
/// the ESP DOI's attribute registry instead of the IKE DOI's.
fn negotiated_p2_lifetime(ps: &[Payload], offered: u32) -> u32 {
    let Some(sa_p) = find(ps, payload::SA) else { return offered };
    let Ok(sa) = SaPayload::parse(&sa_p.data) else { return offered };
    let Some(prop) = sa.proposals.first() else { return offered };
    let Some(transform) = prop.transforms.first() else { return offered };
    transform.attr_u32(esp_attr::LIFE_DURATION).unwrap_or(offered)
}

fn qm_header(cky_i: [u8; 8], cky_r: [u8; 8], msgid: u32) -> IsakmpHeader {
    IsakmpHeader {
        init_cookie: cky_i,
        resp_cookie: cky_r,
        next_payload: payload::NONE,
        version: IsakmpHeader::VERSION_1_0,
        exchange_type: exchange::QUICK,
        flags: 0,
        message_id: msgid,
        length: 0,
    }
}

/// An ESP SA proposal carrying our inbound SPI under `cipher`, tunnel mode --
/// a well-formed proposal a peer like strongSwan (or a real gateway, e.g. a
/// FortiGate demanding ESP_AES_CBC/HMAC-SHA2-256 rather than the AES-GCM this
/// module used to hardcode) will select, given the right `cipher`. Carries a
/// KEY_LENGTH attribute for every cipher except 3DES (fixed-size, no
/// KEY_LENGTH by convention) and, for a classic (non-AEAD) cipher, a separate
/// AUTH_ALGORITHM attribute (an AEAD cipher needs no separate integrity
/// check, so gets none). When `pfs_group` is `Some`, also carries a GROUP
/// DESCRIPTION attribute naming the DH group PFS will use -- the signal the
/// peer keys its own PFS participation off of. `floated` (RFC 3947, see
/// `phase1::Phase1State::floated`'s doc) switches the ENCAP_MODE attribute to
/// [`UDP_ENCAP_TUNNEL`] instead of [`ENCAP_TUNNEL`] -- this is purely a
/// declaration on the wire; the actual UDP-in-ESP framing is entirely a
/// kernel XFRM matter on the `free-vpn-v2` side (`daemon::xfrm::apply_natt`),
/// unaffected by this attribute's value either way.
fn esp_sa(spi: u32, cipher: SkCipher, pfs_group: Option<DhGroup>, floated: bool, life_duration: u32) -> SaPayload {
    let encap_mode = if floated { UDP_ENCAP_TUNNEL } else { ENCAP_TUNNEL };
    let mut attributes = vec![
        Attribute::short(esp_attr::ENCAP_MODE, encap_mode),
        Attribute::short(esp_attr::LIFE_TYPE, LIFE_SECONDS),
        Attribute::long_u32(esp_attr::LIFE_DURATION, life_duration),
    ];
    if !matches!(cipher, SkCipher::TripleDesCbc(_)) {
        attributes.push(Attribute::short(esp_attr::KEY_LENGTH, (cipher.key_len() * 8) as u16));
    }
    if let Some(integ) = cipher.integ_algorithm() {
        attributes.push(Attribute::short(esp_attr::AUTH_ALGORITHM, esp_auth_algorithm(integ)));
    }
    if let Some(group) = pfs_group {
        attributes.push(Attribute::short(esp_attr::GROUP_DESC, group.transform_id()));
    }
    SaPayload {
        doi: IPSEC_DOI,
        situation: SIT_IDENTITY_ONLY,
        proposals: vec![Proposal {
            num: 1,
            protocol_id: protocol::ESP,
            spi: spi.to_be_bytes().to_vec(),
            transforms: vec![Transform { num: 1, transform_id: esp_transform_id(cipher), attributes }],
        }],
    }
}

/// An ID payload body for an IPv4 subnet traffic selector (`IDci`/`IDcr`).
fn ts_id(addr: [u8; 4], mask: [u8; 4]) -> Vec<u8> {
    let mut data = addr.to_vec();
    data.extend_from_slice(&mask);
    Id { id_type: id_type::IPV4_ADDR_SUBNET, protocol: 0, port: 0, data }.to_bytes()
}

/// An ID payload body for an IPv6 subnet traffic selector: network address +
/// netmask, 16 bytes each (RFC 2407 §4.6.2.1) -- the IPv6 twin of [`ts_id`].
/// A host selector is `prefix_len` 128, same convention as the IPv4 side's
/// `/32` narrowing to the assigned address.
fn ts_id_v6(addr: Ipv6Addr, prefix_len: u8) -> Vec<u8> {
    let prefix_len = prefix_len.min(128);
    let mask = if prefix_len == 0 { 0 } else { u128::MAX << (128 - prefix_len) };
    let mut data = (u128::from(addr) & mask).to_be_bytes().to_vec();
    data.extend_from_slice(&mask.to_be_bytes());
    Id { id_type: id_type::IPV6_ADDR_SUBNET, protocol: 0, port: 0, data }.to_bytes()
}

/// Read the peer's inbound ESP SPI from the SA payload of a Quick-Mode message.
fn peer_esp_spi(ps: &[Payload]) -> Result<u32, IkeError> {
    let sa_p = find(ps, payload::SA).ok_or(IkeError::MissingPayload("SA"))?;
    let sa = SaPayload::parse(&sa_p.data)?;
    let prop = sa.proposals.first().ok_or(IkeError::NoProposalChosen)?;
    if prop.spi.len() != 4 {
        return Err(IkeError::NoProposalChosen);
    }
    Ok(u32::from_be_bytes([prop.spi[0], prop.spi[1], prop.spi[2], prop.spi[3]]))
}

/// The PFS DH group named on the SA payload's ESP transform, if any -- the
/// signal that the peer wants PFS for this CHILD SA (see `esp_sa`'s doc).
fn peer_pfs_group(ps: &[Payload]) -> Result<Option<DhGroup>, IkeError> {
    let sa_p = find(ps, payload::SA).ok_or(IkeError::MissingPayload("SA"))?;
    let sa = SaPayload::parse(&sa_p.data)?;
    let prop = sa.proposals.first().ok_or(IkeError::NoProposalChosen)?;
    let transform = prop.transforms.first().ok_or(IkeError::NoProposalChosen)?;
    Ok(transform.attr(esp_attr::GROUP_DESC).and_then(DhGroup::from_transform_id))
}

/// The `SkCipher` named on the SA payload's ESP transform -- the responder's
/// counterpart to knowing what to key its own side with, mirroring
/// `peer_pfs_group`'s auto-detect pattern rather than assuming a fixed
/// cipher. `key_len` falls back to a sensible default (192 bits for 3DES,
/// 256 otherwise) when the peer omitted KEY_LENGTH (a fixed-key cipher, or a
/// lenient peer relying on the transform ID alone).
fn peer_esp_cipher(ps: &[Payload]) -> Result<SkCipher, IkeError> {
    let sa_p = find(ps, payload::SA).ok_or(IkeError::MissingPayload("SA"))?;
    let sa = SaPayload::parse(&sa_p.data)?;
    let prop = sa.proposals.first().ok_or(IkeError::NoProposalChosen)?;
    let transform = prop.transforms.first().ok_or(IkeError::NoProposalChosen)?;
    let encr_id = transform.transform_id as u16;
    let default_bits = if encr_id == transform_id::TRIPLE_DES { 192 } else { 256 };
    let key_bits = transform.attr(esp_attr::KEY_LENGTH).unwrap_or(default_bits);
    let integ_id = transform.attr(esp_attr::AUTH_ALGORITHM).and_then(integ_from_esp_auth_algorithm).map(IntegAlgorithm::transform_id);
    SkCipher::from_encr_integ(encr_id, key_bits, integ_id).ok_or(IkeError::NoProposalChosen)
}

/// `HASH(3) = prf(SKEYID_a, 0 | M-ID | Ni_b | Nr_b)`.
fn hash3(prf: Prf, skeyid_a: &[u8], msgid: u32, ni: &[u8], nr: &[u8]) -> Vec<u8> {
    let mut h = vec![0u8];
    h.extend_from_slice(&msgid.to_be_bytes());
    h.extend_from_slice(ni);
    h.extend_from_slice(nr);
    prf.mac(skeyid_a, &h)
}

/// The `(enc_material, integ_key)` split of a KEYMAT blob for `cipher` --
/// `enc_material` is `cipher.key_len() + cipher.salt_len()` bytes (the shape
/// [`EspSa::new_with_cipher`] wants), `integ_key` the trailing
/// `cipher.integ_algorithm()`'s key length (empty for AEAD).
fn split_esp_keymat(cipher: SkCipher, km: &[u8]) -> (&[u8], &[u8]) {
    km.split_at(cipher.key_len() + cipher.salt_len())
}

fn esp_keymat_len(cipher: SkCipher) -> usize {
    cipher.key_len() + cipher.salt_len() + cipher.integ_algorithm().map(IntegAlgorithm::key_len).unwrap_or(0)
}

/// Derive the ESP CHILD SA under `cipher`. KEYMAT depends only on
/// `SKEYID_d`, the Quick-Mode nonces and the SPI of the *receiving* SA, so
/// the derivation is symmetric: each side stamps outbound packets with the
/// peer's SPI and expects its own inbound.
fn derive_child(prf: Prf, skeyid_d: &[u8], cipher: SkCipher, ni: &[u8], nr: &[u8], local_spi: u32, peer_spi: u32) -> Result<ChildSa, IkeError> {
    let out_len = esp_keymat_len(cipher);
    let km_local = crypto1::keymat(prf, skeyid_d, protocol::ESP, &local_spi.to_be_bytes(), ni, nr, out_len);
    let km_peer = crypto1::keymat(prf, skeyid_d, protocol::ESP, &peer_spi.to_be_bytes(), ni, nr, out_len);
    let (enc_local, integ_local) = split_esp_keymat(cipher, &km_local);
    let (enc_peer, integ_peer) = split_esp_keymat(cipher, &km_peer);
    Ok(ChildSa {
        outbound: EspSa::new_with_cipher(peer_spi, cipher, enc_peer, integ_peer)?,
        inbound: EspSa::new_with_cipher(local_spi, cipher, enc_local, integ_local)?,
    })
}

/// Like [`derive_child`], but folding a PFS `shared_secret` into the KEYMAT
/// (see [`crypto1::keymat_pfs`]).
#[allow(clippy::too_many_arguments)]
fn derive_child_pfs(
    prf: Prf,
    skeyid_d: &[u8],
    cipher: SkCipher,
    shared_secret: &[u8],
    ni: &[u8],
    nr: &[u8],
    local_spi: u32,
    peer_spi: u32,
) -> Result<ChildSa, IkeError> {
    let out_len = esp_keymat_len(cipher);
    let km_local = crypto1::keymat_pfs(prf, skeyid_d, shared_secret, protocol::ESP, &local_spi.to_be_bytes(), ni, nr, out_len);
    let km_peer = crypto1::keymat_pfs(prf, skeyid_d, shared_secret, protocol::ESP, &peer_spi.to_be_bytes(), ni, nr, out_len);
    let (enc_local, integ_local) = split_esp_keymat(cipher, &km_local);
    let (enc_peer, integ_peer) = split_esp_keymat(cipher, &km_peer);
    Ok(ChildSa {
        outbound: EspSa::new_with_cipher(peer_spi, cipher, enc_peer, integ_peer)?,
        inbound: EspSa::new_with_cipher(local_spi, cipher, enc_local, integ_local)?,
    })
}

// ---- initiator ----

/// Post-message-1 Quick-Mode initiator state.
pub struct QuickInitiator {
    prf: Prf,
    skeyid_a: Vec<u8>,
    skeyid_d: Vec<u8>,
    enc_key: Vec<u8>,
    cky_i: [u8; 8],
    cky_r: [u8; 8],
    msgid: u32,
    local_spi: u32,
    ni: Vec<u8>,
    iv1: Vec<u8>,
    /// The ESP cipher we offered -- see `esp_sa`'s doc. A successful
    /// `complete()` implies the peer accepted this exact (sole) proposal, so
    /// this is trusted directly rather than re-parsed from the response, the
    /// same precedent `pfs` below already follows.
    cipher: SkCipher,
    /// Our ephemeral PFS share, if PFS was requested: the DH group plus our
    /// private key, needed once the response's KE payload arrives.
    pfs: Option<(DhGroup, [u8; 32])>,
    /// The ESP SA lifetime we offered -- needed by [`QuickInitiator::complete`]
    /// to read back what the responder actually negotiated (RFC 2407 §4.5;
    /// see `negotiated_p2_lifetime`'s doc).
    life_duration: u32,
}

/// Build Quick-Mode message 1 (`HASH(1), SA, Ni, IDci, IDcr`) as the initiator,
/// choosing a fresh message-id and inbound ESP SPI, offering `cipher` for the
/// ESP CHILD SA. `ts_local`/`ts_remote` are the `(address, netmask)` traffic
/// selectors offered as IDci/IDcr. No PFS -- see [`initiate_quick_with_pfs`].
pub fn initiate_quick(
    st: &Phase1State,
    entropy: &mut impl Entropy,
    cipher: SkCipher,
    ts_local: ([u8; 4], [u8; 4]),
    ts_remote: ([u8; 4], [u8; 4]),
    life_duration: u32,
) -> Result<(Vec<u8>, QuickInitiator), IkeError> {
    initiate_quick_with_pfs(st, entropy, cipher, ts_local, ts_remote, None, life_duration)
}

/// Like [`initiate_quick`], but when `pfs_group` is `Some`, also generates an
/// ephemeral DH key pair in that group, advertises it as a GROUP DESCRIPTION
/// attribute on the ESP proposal, and adds a `KE` payload -- Perfect Forward
/// Secrecy for this CHILD SA (RFC 2409 §5.5's PFS variant). `None` reproduces
/// [`initiate_quick`]'s exact behavior.
#[allow(clippy::too_many_arguments)]
pub fn initiate_quick_with_pfs(
    st: &Phase1State,
    entropy: &mut impl Entropy,
    cipher: SkCipher,
    ts_local: ([u8; 4], [u8; 4]),
    ts_remote: ([u8; 4], [u8; 4]),
    pfs_group: Option<DhGroup>,
    life_duration: u32,
) -> Result<(Vec<u8>, QuickInitiator), IkeError> {
    initiate_quick_with_ids(
        st,
        entropy,
        cipher,
        ts_id(ts_local.0, ts_local.1),
        ts_id(ts_remote.0, ts_remote.1),
        pfs_group,
        life_duration,
    )
}

/// [`initiate_quick_with_pfs`] for an **IPv6** CHILD SA: `ts_local`/`ts_remote`
/// are `(network, prefix length)` selectors offered as IDci/IDcr (typically our
/// assigned address as a `/128` and `::/0`). IKEv1 has no CREATE_CHILD_SA --
/// an additional CHILD SA under the same Phase 1 is simply another Quick Mode
/// exchange, this one with IPv6 identities, exactly as a gateway that keeps its
/// IPv4 and IPv6 Phase 2 selectors separate (a FortiGate does) expects.
#[allow(clippy::too_many_arguments)]
pub fn initiate_quick_ipv6(
    st: &Phase1State,
    entropy: &mut impl Entropy,
    cipher: SkCipher,
    ts_local: (Ipv6Addr, u8),
    ts_remote: (Ipv6Addr, u8),
    pfs_group: Option<DhGroup>,
    life_duration: u32,
) -> Result<(Vec<u8>, QuickInitiator), IkeError> {
    initiate_quick_with_ids(
        st,
        entropy,
        cipher,
        ts_id_v6(ts_local.0, ts_local.1),
        ts_id_v6(ts_remote.0, ts_remote.1),
        pfs_group,
        life_duration,
    )
}

/// The address-family-agnostic body of the initiator entry points above:
/// `id_local`/`id_remote` are the ready-made IDci/IDcr payload bodies.
#[allow(clippy::too_many_arguments)]
fn initiate_quick_with_ids(
    st: &Phase1State,
    entropy: &mut impl Entropy,
    cipher: SkCipher,
    id_local: Vec<u8>,
    id_remote: Vec<u8>,
    pfs_group: Option<DhGroup>,
    life_duration: u32,
) -> Result<(Vec<u8>, QuickInitiator), IkeError> {
    let mut spi_b = [0u8; 4];
    entropy.fill(&mut spi_b);
    let local_spi = u32::from_be_bytes(spi_b);
    let mut mid_b = [0u8; 4];
    entropy.fill(&mut mid_b);
    let msgid = u32::from_be_bytes(mid_b) | 1; // non-zero
    let mut ni = vec![0u8; 16];
    entropy.fill(&mut ni);

    let pfs = pfs_group.map(|group| (group, entropy.next_array32()));

    let iv0 = crypto1::phase2_iv(st.prf, &st.phase1_iv, msgid, AES_BLOCK);
    let mut after = vec![
        (payload::SA, esp_sa(local_spi, cipher, pfs_group, st.floated, life_duration).to_bytes()),
        (payload::NONCE, ni.clone()),
    ];
    if let Some((group, dh_private)) = &pfs {
        after.push((payload::KE, group.public(dh_private)));
    }
    after.push((payload::ID, id_local));
    after.push((payload::ID, id_remote));
    let (msg1, iv1) = phase2::build_encrypted(qm_header(st.cky_i, st.cky_r, msgid), st.prf, &st.skeyid_a, &st.enc_key, &iv0, &after)?;
    Ok((msg1, QuickInitiator {
        prf: st.prf,
        skeyid_a: st.skeyid_a.clone(),
        skeyid_d: st.skeyid_d.clone(),
        enc_key: st.enc_key.clone(),
        cky_i: st.cky_i,
        cky_r: st.cky_r,
        msgid,
        local_spi,
        ni,
        iv1,
        cipher,
        pfs,
        life_duration,
    }))
}

impl QuickInitiator {
    /// Process message 2 (`HASH(2), SA, Nr, [KE]`): verify `HASH(2)`, and
    /// return message 3 (`HASH(3)`), the established ESP CHILD SA, and the
    /// actually-negotiated lifetime (RFC 2407 §4.5 -- see
    /// `negotiated_p2_lifetime`'s doc).
    pub fn complete(self, msg2: &[u8]) -> Result<(Vec<u8>, ChildSa, u32), IkeError> {
        let (_hdr, ps, iv2) = phase2::decrypt_payloads(msg2, &self.enc_key, &self.iv1)?;
        let nr = find(&ps, payload::NONCE).ok_or(IkeError::MissingPayload("NONCE"))?.data.clone();
        isakmp::check_nonce_len(&nr)?;
        let peer_spi = peer_esp_spi(&ps)?;

        // Verify HASH(2) = prf(SKEYID_a, M-ID | Ni_b | <payloads after HASH>).
        let got = find(&ps, payload::HASH).ok_or(IkeError::MissingPayload("HASH"))?.data.clone();
        let after: Vec<(u8, Vec<u8>)> = ps
            .iter()
            .filter(|p| p.payload_type != payload::HASH)
            .map(|p| (p.payload_type, p.data.clone()))
            .collect();
        let (_first, body) = isakmp::encode_payloads(&after);
        let mut hi = self.msgid.to_be_bytes().to_vec();
        hi.extend_from_slice(&self.ni);
        hi.extend_from_slice(&body);
        if got != self.prf.mac(&self.skeyid_a, &hi) {
            return Err(IkeError::AuthFailed);
        }

        let h3 = hash3(self.prf, &self.skeyid_a, self.msgid, &self.ni, &nr);
        let (msg3, _) = phase2::encrypt_payloads(qm_header(self.cky_i, self.cky_r, self.msgid), &self.enc_key, &iv2, &[(payload::HASH, h3)])?;
        let child = match &self.pfs {
            Some((group, dh_private)) => {
                let gxr = find(&ps, payload::KE).ok_or(IkeError::MissingPayload("KE"))?.data.clone();
                let shared = group.shared(dh_private, &gxr)?;
                derive_child_pfs(self.prf, &self.skeyid_d, self.cipher, &shared, &self.ni, &nr, self.local_spi, peer_spi)?
            }
            None => derive_child(self.prf, &self.skeyid_d, self.cipher, &self.ni, &nr, self.local_spi, peer_spi)?,
        };
        let negotiated_lifetime = negotiated_p2_lifetime(&ps, self.life_duration);
        Ok((msg3, child, negotiated_lifetime))
    }
}

// ---- responder ----

/// Post-message-1 Quick-Mode responder state.
pub struct QuickResponder {
    prf: Prf,
    skeyid_a: Vec<u8>,
    skeyid_d: Vec<u8>,
    enc_key: Vec<u8>,
    msgid: u32,
    local_spi: u32,
    peer_spi: u32,
    ni: Vec<u8>,
    nr: Vec<u8>,
    iv2: Vec<u8>,
    /// The cipher named on the initiator's ESP proposal (see
    /// [`peer_esp_cipher`]) -- echoed straight back in message 2 rather than
    /// assuming a fixed cipher, so this responder (used only as `ryke`'s own
    /// client-testing double, see `ikev1::server::Server`) can interoperate
    /// with an initiator offering any cipher this module supports.
    cipher: SkCipher,
    /// The PFS shared secret, if the initiator's proposal asked for PFS (see
    /// [`peer_pfs_group`]) -- computed here so [`Self::complete`] only needs
    /// to fold it into the KEYMAT once `HASH(3)` is verified.
    pfs_shared: Option<Vec<u8>>,
}

/// Process Quick-Mode message 1 (`HASH(1), SA, Ni, [KE]`) and build message 2
/// (`HASH(2), SA, Nr, [KE]`), choosing a fresh inbound ESP SPI. PFS is
/// automatic here (unlike the initiator's explicit `_with_pfs` entry point):
/// whenever the initiator's ESP proposal names a GROUP DESCRIPTION (see
/// [`peer_pfs_group`]), the responder generates its own ephemeral share in
/// that same group and answers in kind -- there's no separate "did the
/// responder want PFS" question, only "did the initiator ask for it".
pub fn respond_quick(st: &Phase1State, msg1: &[u8], entropy: &mut impl Entropy) -> Result<(Vec<u8>, QuickResponder), IkeError> {
    let hdr = IsakmpHeader::parse(msg1)?;
    if hdr.exchange_type != exchange::QUICK {
        return Err(IkeError::Crypto("not a Quick Mode message"));
    }
    let msgid = hdr.message_id;
    if msgid == 0 {
        return Err(IkeError::Crypto("quick mode message_id must not be zero"));
    }
    let iv0 = crypto1::phase2_iv(st.prf, &st.phase1_iv, msgid, AES_BLOCK);
    let (_h, ps, iv1) = phase2::parse_encrypted(msg1, st.prf, &st.skeyid_a, &st.enc_key, &iv0)?; // verifies HASH(1)
    let ni = find(&ps, payload::NONCE).ok_or(IkeError::MissingPayload("NONCE"))?.data.clone();
    isakmp::check_nonce_len(&ni)?;
    let peer_spi = peer_esp_spi(&ps)?;
    let pfs_group = peer_pfs_group(&ps)?;
    let cipher = peer_esp_cipher(&ps)?;
    let life_duration = negotiated_p2_lifetime(&ps, 3600);

    let mut spi_b = [0u8; 4];
    entropy.fill(&mut spi_b);
    let local_spi = u32::from_be_bytes(spi_b);
    let mut nr = vec![0u8; 16];
    entropy.fill(&mut nr);

    let mut after: Vec<(u8, Vec<u8>)> = vec![
        (payload::SA, esp_sa(local_spi, cipher, pfs_group, st.floated, life_duration).to_bytes()),
        (payload::NONCE, nr.clone()),
    ];
    let pfs_shared = match pfs_group {
        Some(group) => {
            let gxi = find(&ps, payload::KE).ok_or(IkeError::MissingPayload("KE"))?.data.clone();
            let dh_private = entropy.next_array32();
            after.push((payload::KE, group.public(&dh_private)));
            Some(group.shared(&dh_private, &gxi)?)
        }
        None => None,
    };
    // Echo the initiator's traffic selectors (IDci, IDcr) back in message 2.
    for p in ps.iter().filter(|p| p.payload_type == payload::ID) {
        after.push((payload::ID, p.data.clone()));
    }
    let (msg2, iv2) = phase2::build_encrypted_prefixed(qm_header(st.cky_i, st.cky_r, msgid), st.prf, &st.skeyid_a, &st.enc_key, &iv1, &ni, &after)?;
    Ok((msg2, QuickResponder {
        prf: st.prf,
        skeyid_a: st.skeyid_a.clone(),
        skeyid_d: st.skeyid_d.clone(),
        enc_key: st.enc_key.clone(),
        msgid,
        local_spi,
        peer_spi,
        ni,
        nr,
        iv2,
        cipher,
        pfs_shared,
    }))
}

impl QuickResponder {
    /// Process message 3 (`HASH(3)`), verify it, and return the established ESP
    /// CHILD SA.
    pub fn complete(self, msg3: &[u8]) -> Result<ChildSa, IkeError> {
        let (_hdr, ps, _iv) = phase2::decrypt_payloads(msg3, &self.enc_key, &self.iv2)?;
        let got = find(&ps, payload::HASH).ok_or(IkeError::MissingPayload("HASH"))?.data.clone();
        if got != hash3(self.prf, &self.skeyid_a, self.msgid, &self.ni, &self.nr) {
            return Err(IkeError::AuthFailed);
        }
        match &self.pfs_shared {
            Some(shared) => derive_child_pfs(self.prf, &self.skeyid_d, self.cipher, shared, &self.ni, &self.nr, self.local_spi, self.peer_spi),
            None => derive_child(self.prf, &self.skeyid_d, self.cipher, &self.ni, &self.nr, self.local_spi, self.peer_spi),
        }
    }
}

// ---- rekey ----

/// Rekey the CHILD SA identified by `old_local_spi` via a fresh Quick Mode
/// exchange (RFC 2409 §5.5) run at any point while the Phase-1 SA (`st`)
/// stays live -- IKEv1's equivalent of IKEv2's CREATE_CHILD_SA rekey (RFC
/// 7296 §2.18). Drives the full three-message exchange over `sock` itself
/// (NAT-T floated per `st.floated`, mirroring
/// `ikev1::client::Client::send_step`/`recv_matching`'s own floating logic),
/// then best-effort sends an explicit Delete (RFC 7296 §3.10 / RFC 2408) for
/// `old_local_spi` -- the SA just superseded -- naming our own inbound SPI,
/// same as `Established::close_message` does at full teardown. A failure to
/// send (or to get any reply to) that closing Delete never fails the rekey
/// itself: the new CHILD SA is already live by that point, and the old one
/// will eventually be reaped by its own lifetime expiry either way.
#[allow(clippy::too_many_arguments)]
pub fn rekey_child(
    sock: &dyn IkeSocket,
    st: &Phase1State,
    entropy: &mut impl Entropy,
    peer: SocketAddr,
    cipher: SkCipher,
    pfs_group: Option<DhGroup>,
    ts_local: ([u8; 4], [u8; 4]),
    ts_remote: ([u8; 4], [u8; 4]),
    life_duration: u32,
    timeout: Duration,
    old_local_spi: u32,
) -> Result<(RekeyedChild, u32), DriverError> {
    let (msg1, qi) = initiate_quick_with_pfs(st, entropy, cipher, ts_local, ts_remote, pfs_group, life_duration)?;
    let out = quick_exchange(sock, st, peer, timeout, msg1, qi, "IPv4 rekey")?;
    delete_superseded(sock, st, entropy, peer, old_local_spi);
    Ok(out)
}

/// Create the tunnel's additional **IPv6** CHILD SA: one more Quick Mode
/// exchange under the live Phase-1 SA (`st`), offering IPv6 selectors
/// (`ts_local`/`ts_remote` as `(network, prefix length)`, see
/// [`initiate_quick_ipv6`]). Same transport handling as [`rekey_child`]
/// (`sock` must be the socket the peer is reachable on, NAT-T floated per
/// `st.floated`), minus the trailing Delete: nothing is being replaced. An
/// error Notify from the peer (typically NO-PROPOSAL-CHOSEN /
/// INVALID-ID-INFORMATION when its Phase 2 has no IPv6 selector) comes back as
/// [`IkeError::PeerRejected`] straight away rather than after `timeout`; the
/// IPv4 CHILD SA and the Phase-1 SA are unaffected either way.
#[allow(clippy::too_many_arguments)]
pub fn create_child_ipv6(
    sock: &dyn IkeSocket,
    st: &Phase1State,
    entropy: &mut impl Entropy,
    peer: SocketAddr,
    cipher: SkCipher,
    pfs_group: Option<DhGroup>,
    ts_local: (Ipv6Addr, u8),
    ts_remote: (Ipv6Addr, u8),
    life_duration: u32,
    timeout: Duration,
) -> Result<(RekeyedChild, u32), DriverError> {
    quick_ipv6(sock, st, entropy, peer, cipher, pfs_group, ts_local, ts_remote, life_duration, timeout, "IPv6 CHILD SA")
}

/// The shared body of [`create_child_ipv6`] and [`rekey_child_ipv6`]; `what`
/// only labels the trace lines.
#[allow(clippy::too_many_arguments)]
fn quick_ipv6(
    sock: &dyn IkeSocket,
    st: &Phase1State,
    entropy: &mut impl Entropy,
    peer: SocketAddr,
    cipher: SkCipher,
    pfs_group: Option<DhGroup>,
    ts_local: (Ipv6Addr, u8),
    ts_remote: (Ipv6Addr, u8),
    life_duration: u32,
    timeout: Duration,
    what: &str,
) -> Result<(RekeyedChild, u32), DriverError> {
    let (msg1, qi) = initiate_quick_ipv6(st, entropy, cipher, ts_local, ts_remote, pfs_group, life_duration)?;
    quick_exchange(sock, st, peer, timeout, msg1, qi, what)
}

/// [`rekey_child`] for the IPv6 CHILD SA created by [`create_child_ipv6`]:
/// renegotiates it with the same selectors and then deletes the superseded SA
/// (`old_local_spi`, our own inbound SPI for it).
#[allow(clippy::too_many_arguments)]
pub fn rekey_child_ipv6(
    sock: &dyn IkeSocket,
    st: &Phase1State,
    entropy: &mut impl Entropy,
    peer: SocketAddr,
    cipher: SkCipher,
    pfs_group: Option<DhGroup>,
    ts_local: (Ipv6Addr, u8),
    ts_remote: (Ipv6Addr, u8),
    life_duration: u32,
    timeout: Duration,
    old_local_spi: u32,
) -> Result<(RekeyedChild, u32), DriverError> {
    let out = quick_ipv6(sock, st, entropy, peer, cipher, pfs_group, ts_local, ts_remote, life_duration, timeout, "IPv6 rekey")?;
    delete_superseded(sock, st, entropy, peer, old_local_spi);
    Ok(out)
}

/// Send `msg` to `peer`, wrapped with the non-ESP marker on port 4500 when
/// `st` floated (RFC 3947/3948) -- the same rule `Client::send_step` applies.
fn send_ike(sock: &dyn IkeSocket, st: &Phase1State, peer: SocketAddr, msg: &[u8]) -> std::io::Result<()> {
    if st.floated {
        let dest = SocketAddr::new(peer.ip(), crate::natt_port());
        let wire = wrap_ike_4500(msg);
        crate::debug::dump(">>>", dest, &wire);
        sock.send_to(&wire, dest)?;
    } else {
        crate::debug::dump(">>>", peer, msg);
        sock.send_to(msg, peer)?;
    }
    Ok(())
}

/// Best-effort Delete for the CHILD SA a rekey just superseded -- a failure to
/// build or send it never fails the rekey (the new SA is already live and the
/// old one will expire on its own lifetime either way).
fn delete_superseded(sock: &dyn IkeSocket, st: &Phase1State, entropy: &mut impl Entropy, peer: SocketAddr, old_local_spi: u32) {
    ike_debug!("INFORMATIONAL: sending ESP Delete for superseded CHILD SA spi_in={old_local_spi:08x} to {peer}");
    match informational::build_esp_delete(st, entropy, old_local_spi) {
        Ok(delete_msg) => {
            if let Err(e) = send_ike(sock, st, peer, &delete_msg) {
                ike_debug!("INFORMATIONAL: failed to send the ESP Delete for spi_in={old_local_spi:08x} (new CHILD SA unaffected): {e}");
            }
        }
        Err(e) => ike_debug!("INFORMATIONAL: failed to build the ESP Delete for spi_in={old_local_spi:08x} (new CHILD SA unaffected): {e}"),
    }
}

/// Drive one initiator Quick Mode exchange to completion over `sock`: send
/// `msg1`, wait (up to `timeout`) for the matching message 2, answer with
/// message 3, and hand back the derived CHILD SA's SPIs/keys plus the
/// negotiated lifetime. Datagrams that aren't this exchange's message 2 are
/// skipped -- except an error Notify from the peer for this ISAKMP SA, which
/// ends the wait at once as [`IkeError::PeerRejected`].
fn quick_exchange(
    sock: &dyn IkeSocket,
    st: &Phase1State,
    peer: SocketAddr,
    timeout: Duration,
    msg1: Vec<u8>,
    qi: QuickInitiator,
    what: &str,
) -> Result<(RekeyedChild, u32), DriverError> {
    let msgid = IsakmpHeader::parse(&msg1)?.message_id;
    ike_debug!("Quick Mode ({what}): sending msg1 to {peer} (msgid={msgid:08x})");
    send_ike(sock, st, peer, &msg1)?;

    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; 8192];
    let msg2 = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            ike_debug!("Quick Mode ({what}): timed out after {timeout:?} waiting for the gateway's reply");
            return Err(IkeError::Crypto("Quick Mode: timed out waiting for the Quick Mode reply").into());
        }
        sock.set_read_timeout(Some(remaining))?;
        let (n, from) = match sock.recv_from(&mut buf) {
            Ok(r) => r,
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
                ike_debug!("Quick Mode ({what}): timed out after {timeout:?} waiting for the gateway's reply");
                return Err(IkeError::Crypto("Quick Mode: timed out waiting for the Quick Mode reply").into());
            }
            Err(e) => return Err(e.into()),
        };
        crate::debug::dump("<<<", from, &buf[..n]);
        let raw = &buf[..n];
        let msg = if st.floated {
            match unwrap_ike_4500(raw) {
                Some(m) => m.to_vec(),
                None => continue,
            }
        } else {
            raw.to_vec()
        };
        let Ok(hdr) = IsakmpHeader::parse(&msg) else { continue };
        if let Some((notify_type, name)) = informational::peer_error_notify(st, &msg) {
            ike_debug!("Quick Mode ({what}): gateway rejected the proposal with {name} (notify type {notify_type})");
            return Err(IkeError::PeerRejected { notify_type, name }.into());
        }
        if hdr.init_cookie != st.cky_i || hdr.resp_cookie != st.cky_r || hdr.exchange_type != exchange::QUICK || hdr.message_id != msgid {
            continue;
        }
        break msg;
    };

    let (msg3, child, negotiated_lifetime) = qi.complete(&msg2)?;
    send_ike(sock, st, peer, &msg3)?;

    let key_out = ChildKeyMaterial {
        cipher: child.outbound.cipher(),
        enc: child.outbound.enc_material(),
        integ: child.outbound.integ_key().to_vec(),
    };
    let key_in = ChildKeyMaterial {
        cipher: child.inbound.cipher(),
        enc: child.inbound.enc_material(),
        integ: child.inbound.integ_key().to_vec(),
    };
    let rekeyed = RekeyedChild { local_spi: child.inbound.spi(), peer_spi: child.outbound.spi(), key_out, key_in };
    ike_debug!(
        "Quick Mode ({what}): complete -- spi_in={:08x} spi_out={:08x}, lifetime {negotiated_lifetime}s",
        rekeyed.local_spi, rekeyed.peer_spi
    );
    Ok((rekeyed, negotiated_lifetime))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use crate::crypto::{DhGroup, IntegAlgorithm};
    use crate::entropy::SeedEntropy;
    use crate::ikev1::payloads::Id;
    use crate::ikev1::phase1::{
        initiate_aggressive, respond_aggressive, Ikev1ExchangeMode, Ikev1LocalAuth, InitiatorConfig, Phase1Config,
    };
    use crate::ikev2::sk::SkCipher;

    #[test]
    fn ikev1_initiator_and_responder_agree_and_esp_roundtrips() {
        let psk = b"correct horse battery staple".to_vec();
        let ts = ([10, 0, 99, 0], [255, 255, 255, 0]);
        let icfg = InitiatorConfig {
            local_auth: Ikev1LocalAuth::Psk(psk.clone()),
            trusted_cas: Vec::new(),
            now_unix: 0,
            key_len: 32,
            our_id: Id::ipv4([10, 1, 1, 1]),
            group: DhGroup::Modp1024,
            xauth: false,
            xauth_creds: None,
            ts_local: ts,
            ts_remote: ts,
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
            local_auth: Ikev1LocalAuth::Psk(psk.clone()),
            trusted_cas: Vec::new(),
            now_unix: 0,
            our_id: Id::ipv4([192, 168, 0, 1]),
        };
        let mut ie = SeedEntropy::new(0x1111);
        let mut re = SeedEntropy::new(0x2222);

        // Phase 1: Aggressive Mode.
        let (msg1, ai) = initiate_aggressive(&icfg, &mut ie, "10.1.1.1:500".parse().unwrap(), "192.168.0.1:500".parse().unwrap());
        let (msg2, rstate) = respond_aggressive(&rcfg, &msg1, &mut re, "192.168.0.1:500".parse().unwrap(), "10.1.1.1:500".parse().unwrap()).unwrap();
        let (msg3, istate) = ai.complete(&msg2, "10.1.1.1:500".parse().unwrap(), "192.168.0.1:500".parse().unwrap()).unwrap();
        rstate.verify_hash_i(&msg3).unwrap();

        // Phase 2: Quick Mode.
        let (qm1, qi) = initiate_quick(&istate, &mut ie, SkCipher::Aes256Gcm, ts, ts, 3600).unwrap();
        let (qm2, qr) = respond_quick(&rstate, &qm1, &mut re).unwrap();
        let (qm3, mut ichild, _lifetime) = qi.complete(&qm2).unwrap();
        let mut rchild = qr.complete(&qm3).unwrap();

        // The two CHILD SAs must interoperate: what one seals, the other opens.
        let pkt: Vec<u8> = (0..40u8).collect();
        let sealed = ichild.outbound.seal(&pkt, 4).unwrap();
        let (got, nh) = rchild.inbound.open(&sealed).unwrap();
        assert_eq!(got, pkt);
        assert_eq!(nh, 4);
        let sealed_r = rchild.outbound.seal(&pkt, 4).unwrap();
        let (got_r, _) = ichild.inbound.open(&sealed_r).unwrap();
        assert_eq!(got_r, pkt);
    }

    #[test]
    fn respond_quick_rejects_a_zero_message_id() {
        let psk = b"correct horse battery staple".to_vec();
        let ts = ([10, 0, 99, 0], [255, 255, 255, 0]);
        let icfg = InitiatorConfig {
            local_auth: Ikev1LocalAuth::Psk(psk.clone()),
            trusted_cas: Vec::new(),
            now_unix: 0,
            key_len: 32,
            our_id: Id::ipv4([10, 1, 1, 1]),
            group: DhGroup::Modp1024,
            xauth: false,
            xauth_creds: None,
            ts_local: ts,
            ts_remote: ts,
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
            local_auth: Ikev1LocalAuth::Psk(psk.clone()),
            trusted_cas: Vec::new(),
            now_unix: 0,
            our_id: Id::ipv4([192, 168, 0, 1]),
        };
        let mut ie = SeedEntropy::new(0x1111);
        let mut re = SeedEntropy::new(0x2222);

        let (msg1, ai) = initiate_aggressive(&icfg, &mut ie, "10.1.1.1:500".parse().unwrap(), "192.168.0.1:500".parse().unwrap());
        let (msg2, rstate) = respond_aggressive(&rcfg, &msg1, &mut re, "192.168.0.1:500".parse().unwrap(), "10.1.1.1:500".parse().unwrap()).unwrap();
        let (msg3, istate) = ai.complete(&msg2, "10.1.1.1:500".parse().unwrap(), "192.168.0.1:500".parse().unwrap()).unwrap();
        rstate.verify_hash_i(&msg3).unwrap();

        let (qm1, _qi) = initiate_quick(&istate, &mut ie, SkCipher::Aes256Gcm, ts, ts, 3600).unwrap();

        // RFC 2408 §3.1: every Phase 2 (Quick Mode) message must carry a
        // nonzero Message-ID -- tamper it down to 0 (the Phase-1 sentinel)
        // and confirm the responder rejects it outright, before touching
        // any crypto.
        let mut hdr = IsakmpHeader::parse(&qm1).unwrap();
        hdr.message_id = 0;
        let mut tampered = hdr.to_bytes();
        tampered.extend_from_slice(&qm1[IsakmpHeader::LEN..]);

        match respond_quick(&rstate, &tampered, &mut re) {
            Err(IkeError::Crypto(_)) => {}
            other => panic!("expected a Crypto error, got {:?}", other.map(|_| ())),
        }
    }

    /// The specific cipher a real FortiGate demanded live (see this crate's
    /// project memory): ESP_AES_CBC/256 + a separate HMAC-SHA2-256 ICV, not
    /// this module's old hardcoded AES-GCM. Confirms the classic (non-AEAD)
    /// path end to end -- `esp_sa`'s AUTH_ALGORITHM attribute, KEYMAT split,
    /// and `EspSa::seal`/`open`'s CBC+HMAC framing all agree.
    #[test]
    fn ikev1_quick_mode_with_classic_cbc_hmac_cipher_agrees_and_esp_roundtrips() {
        let psk = b"correct horse battery staple".to_vec();
        let ts = ([10, 0, 99, 0], [255, 255, 255, 0]);
        let cipher = SkCipher::Aes256Cbc(IntegAlgorithm::HmacSha2_256_128);
        let icfg = InitiatorConfig {
            local_auth: Ikev1LocalAuth::Psk(psk.clone()),
            trusted_cas: Vec::new(),
            now_unix: 0,
            key_len: 32,
            our_id: Id::ipv4([10, 1, 1, 1]),
            group: DhGroup::Modp1024,
            xauth: false,
            xauth_creds: None,
            ts_local: ts,
            ts_remote: ts,
            esp_cipher: cipher,
            pfs_group: None,
            mode_cfg: false,
            ipv6: false,
            mode: Ikev1ExchangeMode::Aggressive,
            p1_lifetime_secs: 28800,
            p2_lifetime_secs: 3600,
            force_natt: false,
        };
        let rcfg = Phase1Config {
            local_auth: Ikev1LocalAuth::Psk(psk.clone()),
            trusted_cas: Vec::new(),
            now_unix: 0,
            our_id: Id::ipv4([192, 168, 0, 1]),
        };
        let mut ie = SeedEntropy::new(0x7777);
        let mut re = SeedEntropy::new(0x8888);

        let (msg1, ai) = initiate_aggressive(&icfg, &mut ie, "10.1.1.1:500".parse().unwrap(), "192.168.0.1:500".parse().unwrap());
        let (msg2, rstate) = respond_aggressive(&rcfg, &msg1, &mut re, "192.168.0.1:500".parse().unwrap(), "10.1.1.1:500".parse().unwrap()).unwrap();
        let (msg3, istate) = ai.complete(&msg2, "10.1.1.1:500".parse().unwrap(), "192.168.0.1:500".parse().unwrap()).unwrap();
        rstate.verify_hash_i(&msg3).unwrap();

        let (qm1, qi) = initiate_quick(&istate, &mut ie, cipher, ts, ts, 3600).unwrap();
        let (qm2, qr) = respond_quick(&rstate, &qm1, &mut re).unwrap();
        let (qm3, mut ichild, _lifetime) = qi.complete(&qm2).unwrap();
        let mut rchild = qr.complete(&qm3).unwrap();

        assert_eq!(ichild.outbound.cipher(), cipher);
        assert_eq!(rchild.outbound.cipher(), cipher);

        let pkt: Vec<u8> = (0..40u8).collect();
        let sealed = ichild.outbound.seal(&pkt, 4).unwrap();
        let (got, nh) = rchild.inbound.open(&sealed).unwrap();
        assert_eq!(got, pkt);
        assert_eq!(nh, 4);
        let sealed_r = rchild.outbound.seal(&pkt, 4).unwrap();
        let (got_r, _) = ichild.inbound.open(&sealed_r).unwrap();
        assert_eq!(got_r, pkt);
    }

    #[test]
    fn ikev1_quick_mode_pfs_agrees_and_esp_roundtrips() {
        let psk = b"correct horse battery staple".to_vec();
        let ts = ([10, 0, 99, 0], [255, 255, 255, 0]);
        let icfg = InitiatorConfig {
            local_auth: Ikev1LocalAuth::Psk(psk.clone()),
            trusted_cas: Vec::new(),
            now_unix: 0,
            key_len: 32,
            our_id: Id::ipv4([10, 1, 1, 1]),
            group: DhGroup::Modp1024,
            xauth: false,
            xauth_creds: None,
            ts_local: ts,
            ts_remote: ts,
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
            local_auth: Ikev1LocalAuth::Psk(psk.clone()),
            trusted_cas: Vec::new(),
            now_unix: 0,
            our_id: Id::ipv4([192, 168, 0, 1]),
        };
        let mut ie = SeedEntropy::new(0x3333);
        let mut re = SeedEntropy::new(0x4444);

        let (msg1, ai) = initiate_aggressive(&icfg, &mut ie, "10.1.1.1:500".parse().unwrap(), "192.168.0.1:500".parse().unwrap());
        let (msg2, rstate) = respond_aggressive(&rcfg, &msg1, &mut re, "192.168.0.1:500".parse().unwrap(), "10.1.1.1:500".parse().unwrap()).unwrap();
        let (msg3, istate) = ai.complete(&msg2, "10.1.1.1:500".parse().unwrap(), "192.168.0.1:500".parse().unwrap()).unwrap();
        rstate.verify_hash_i(&msg3).unwrap();

        // Quick Mode, this time with PFS (a fresh DH group of its own).
        let (qm1, qi) = initiate_quick_with_pfs(&istate, &mut ie, SkCipher::Aes256Gcm, ts, ts, Some(DhGroup::Modp2048), 3600).unwrap();
        let (qm2, qr) = respond_quick(&rstate, &qm1, &mut re).unwrap();
        let (qm3, mut ichild, _lifetime) = qi.complete(&qm2).unwrap();
        let mut rchild = qr.complete(&qm3).unwrap();

        let pkt: Vec<u8> = (0..40u8).collect();
        let sealed = ichild.outbound.seal(&pkt, 4).unwrap();
        let (got, nh) = rchild.inbound.open(&sealed).unwrap();
        assert_eq!(got, pkt);
        assert_eq!(nh, 4);
        let sealed_r = rchild.outbound.seal(&pkt, 4).unwrap();
        let (got_r, _) = ichild.inbound.open(&sealed_r).unwrap();
        assert_eq!(got_r, pkt);
    }

    /// The actual PFS property: two independent PFS Quick-Mode runs off the
    /// same Phase-1 state derive different ESP keys, because each one runs
    /// its own fresh Quick-Mode DH exchange (on top of, not merely because
    /// of, their also-fresh nonces).
    #[test]
    fn pfs_quick_mode_derives_a_fresh_key_each_time() {
        let psk = b"correct horse battery staple".to_vec();
        let ts = ([10, 0, 99, 0], [255, 255, 255, 0]);
        let icfg = InitiatorConfig {
            local_auth: Ikev1LocalAuth::Psk(psk.clone()),
            trusted_cas: Vec::new(),
            now_unix: 0,
            key_len: 32,
            our_id: Id::ipv4([10, 1, 1, 1]),
            group: DhGroup::Modp1024,
            xauth: false,
            xauth_creds: None,
            ts_local: ts,
            ts_remote: ts,
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
            local_auth: Ikev1LocalAuth::Psk(psk.clone()),
            trusted_cas: Vec::new(),
            now_unix: 0,
            our_id: Id::ipv4([192, 168, 0, 1]),
        };
        let mut ie = SeedEntropy::new(0x5555);
        let mut re = SeedEntropy::new(0x6666);
        let (msg1, ai) = initiate_aggressive(&icfg, &mut ie, "10.1.1.1:500".parse().unwrap(), "192.168.0.1:500".parse().unwrap());
        let (msg2, rstate) = respond_aggressive(&rcfg, &msg1, &mut re, "192.168.0.1:500".parse().unwrap(), "10.1.1.1:500".parse().unwrap()).unwrap();
        let (msg3, istate) = ai.complete(&msg2, "10.1.1.1:500".parse().unwrap(), "192.168.0.1:500".parse().unwrap()).unwrap();
        rstate.verify_hash_i(&msg3).unwrap();

        let run = |ie: &mut SeedEntropy, re: &mut SeedEntropy| {
            let (qm1, qi) = initiate_quick_with_pfs(&istate, ie, SkCipher::Aes256Gcm, ts, ts, Some(DhGroup::Modp2048), 3600).unwrap();
            let (qm2, qr) = respond_quick(&rstate, &qm1, re).unwrap();
            let (qm3, ichild, _lifetime) = qi.complete(&qm2).unwrap();
            let _ = qr.complete(&qm3).unwrap();
            ichild.outbound.key_material()
        };
        let km1 = run(&mut ie, &mut re);
        let km2 = run(&mut ie, &mut re);
        assert_ne!(km1, km2, "a fresh Quick-Mode DH exchange must yield a fresh key");
    }

    #[test]
    fn wrong_psk_fails_phase1() {
        let ts = ([0, 0, 0, 0], [0, 0, 0, 0]);
        let icfg = InitiatorConfig {
            local_auth: Ikev1LocalAuth::Psk(b"right".to_vec()),
            trusted_cas: Vec::new(),
            now_unix: 0,
            key_len: 32,
            our_id: Id::ipv4([10, 1, 1, 1]),
            group: DhGroup::Modp1024,
            xauth: false,
            xauth_creds: None,
            ts_local: ts,
            ts_remote: ts,
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
            local_auth: Ikev1LocalAuth::Psk(b"wrong".to_vec()),
            trusted_cas: Vec::new(),
            now_unix: 0,
            our_id: Id::ipv4([192, 168, 0, 1]),
        };
        let mut ie = SeedEntropy::new(1);
        let mut re = SeedEntropy::new(2);
        let (msg1, ai) = initiate_aggressive(&icfg, &mut ie, "10.1.1.1:500".parse().unwrap(), "192.168.0.1:500".parse().unwrap());
        let (msg2, _rstate) = respond_aggressive(&rcfg, &msg1, &mut re, "192.168.0.1:500".parse().unwrap(), "10.1.1.1:500".parse().unwrap()).unwrap();
        assert!(matches!(ai.complete(&msg2, "10.1.1.1:500".parse().unwrap(), "192.168.0.1:500".parse().unwrap()), Err(IkeError::AuthFailed)));
    }

    /// Regression test for the same bug class as `phase1`'s own
    /// `initiator_sa_carries_the_configured_lifetime_not_a_hardcoded_one`,
    /// but for the ESP SA lifetime: `esp_sa` must carry whatever
    /// `life_duration` it's given, not this module's old hardcoded `3600`.
    #[test]
    fn esp_sa_carries_the_configured_lifetime_not_a_hardcoded_one() {
        let sa = esp_sa(0x1234, SkCipher::Aes256Gcm, None, false, 900);
        let life = sa.proposals[0].transforms[0].attr_u32(esp_attr::LIFE_DURATION);
        assert_eq!(life, Some(900), "must carry the configured lifetime, not the old hardcoded 3600");
    }

    /// [`negotiated_p2_lifetime`] must prefer the responder's own chosen
    /// value (RFC 2407 §4.5: the responder may unilaterally shorten the
    /// initiator's offer) and fall back to `offered` only when the
    /// responder's ESP SA payload carries no `LIFE_DURATION` attribute at
    /// all -- the ESP-DOI counterpart to `phase1`'s
    /// `negotiated_p1_lifetime_prefers_the_responders_value_and_falls_back_when_absent`.
    #[test]
    fn negotiated_p2_lifetime_prefers_the_responders_value_and_falls_back_when_absent() {
        let sa_with_lifetime = esp_sa(0x1234, SkCipher::Aes256Gcm, None, false, 900);
        let ps_with = vec![isakmp::Payload { payload_type: payload::SA, data: sa_with_lifetime.to_bytes() }];
        assert_eq!(negotiated_p2_lifetime(&ps_with, 3600), 900, "must prefer the responder's own chosen value");

        let sa_without_lifetime = SaPayload {
            doi: IPSEC_DOI,
            situation: SIT_IDENTITY_ONLY,
            proposals: vec![Proposal {
                num: 1,
                protocol_id: protocol::ESP,
                spi: 0x1234u32.to_be_bytes().to_vec(),
                transforms: vec![Transform { num: 1, transform_id: esp_transform_id(SkCipher::Aes256Gcm), attributes: vec![] }],
            }],
        };
        let ps_without = vec![isakmp::Payload { payload_type: payload::SA, data: sa_without_lifetime.to_bytes() }];
        assert_eq!(negotiated_p2_lifetime(&ps_without, 3600), 3600, "must fall back to the offered value when absent");

        assert_eq!(negotiated_p2_lifetime(&[], 3600), 3600, "must fall back to the offered value when there's no SA payload at all");
    }

    /// End-to-end confirmation that `rekey_child` -- the IKEv1 counterpart to
    /// IKEv2's CREATE_CHILD_SA rekey (RFC 7296 §2.18 / RFC 2409 §5.5's second
    /// Quick Mode exchange) -- interoperates over real loopback sockets with
    /// a live responder: it negotiates a fresh ESP CHILD SA under the
    /// already-established Phase-1 SA, the negotiated lifetime comes back
    /// correctly, the rekeyed key material actually interoperates, and its
    /// trailing best-effort step (an explicit ESP Delete naming the
    /// just-superseded CHILD SA's local SPI -- RFC 7296 §3.10 / RFC 2408)
    /// actually reaches the peer.
    #[test]
    fn rekey_child_over_loopback_interoperates_with_a_live_responder() {
        let psk = b"correct horse battery staple".to_vec();
        let ts = ([10, 0, 99, 0], [255, 255, 255, 0]);
        let icfg = InitiatorConfig {
            local_auth: Ikev1LocalAuth::Psk(psk.clone()),
            trusted_cas: Vec::new(),
            now_unix: 0,
            key_len: 32,
            our_id: Id::ipv4([10, 1, 1, 1]),
            group: DhGroup::Modp1024,
            xauth: false,
            xauth_creds: None,
            ts_local: ts,
            ts_remote: ts,
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
            local_auth: Ikev1LocalAuth::Psk(psk.clone()),
            trusted_cas: Vec::new(),
            now_unix: 0,
            our_id: Id::ipv4([192, 168, 0, 1]),
        };
        let mut ie = SeedEntropy::new(0xAAAA);
        let mut re = SeedEntropy::new(0xBBBB);

        let initiator_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let responder_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        initiator_sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        responder_sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let initiator_addr = initiator_sock.local_addr().unwrap();
        let responder_addr = responder_sock.local_addr().unwrap();

        // Phase 1, plus an initial Quick Mode exchange to get an existing
        // CHILD SA to rekey away from -- both in-process, same as this
        // module's other tests. `rekey_child`'s own job only starts below.
        let (msg1, ai) = initiate_aggressive(&icfg, &mut ie, initiator_addr, responder_addr);
        let (msg2, rstate) = respond_aggressive(&rcfg, &msg1, &mut re, responder_addr, initiator_addr).unwrap();
        let (msg3, istate) = ai.complete(&msg2, initiator_addr, responder_addr).unwrap();
        rstate.verify_hash_i(&msg3).unwrap();

        let (qm1, qi) = initiate_quick(&istate, &mut ie, SkCipher::Aes256Gcm, ts, ts, 3600).unwrap();
        let (qm2, qr) = respond_quick(&rstate, &qm1, &mut re).unwrap();
        let (qm3, old_ichild, _lifetime) = qi.complete(&qm2).unwrap();
        let _old_rchild = qr.complete(&qm3).unwrap();
        let old_local_spi = old_ichild.inbound.spi();

        // A live responder loop for the rekey itself: answer the new Quick
        // Mode exchange, then read the trailing Delete for the
        // just-superseded SPI.
        let rstate2 = rstate.clone();
        let responder = std::thread::spawn(move || {
            let mut re = re;
            let mut buf = [0u8; 8192];
            let n = responder_sock.recv(&mut buf).unwrap();
            let (msg2, qr) = respond_quick(&rstate2, &buf[..n], &mut re).unwrap();
            responder_sock.send_to(&msg2, initiator_addr).unwrap();
            let n = responder_sock.recv(&mut buf).unwrap();
            let new_rchild = qr.complete(&buf[..n]).unwrap();
            let n = responder_sock.recv(&mut buf).unwrap();
            (new_rchild, buf[..n].to_vec(), rstate2)
        });

        let (rekeyed, negotiated_lifetime) = rekey_child(
            &initiator_sock,
            &istate,
            &mut ie,
            responder_addr,
            SkCipher::Aes256Gcm,
            None,
            ts,
            ts,
            1800,
            Duration::from_secs(5),
            old_local_spi,
        )
        .unwrap();
        assert_eq!(negotiated_lifetime, 1800, "both sides offer 1800, so nothing gets shortened");

        let (mut new_rchild, delete_bytes, rstate2) = responder.join().unwrap();

        // The rekeyed key material must actually interoperate: rebuild our
        // own inbound SA from exactly what `rekey_child` handed back (the
        // same shape a caller installing kernel XFRM state would use), and
        // confirm it opens what the responder's freshly rekeyed outbound SA
        // seals.
        let mut new_ichild_in =
            EspSa::new_with_cipher(rekeyed.local_spi, rekeyed.key_in.cipher, &rekeyed.key_in.enc, &rekeyed.key_in.integ).unwrap();
        let pkt: Vec<u8> = (0..40u8).collect();
        let sealed = new_rchild.outbound.seal(&pkt, 4).unwrap();
        let (got, nh) = new_ichild_in.open(&sealed).unwrap();
        assert_eq!(got, pkt);
        assert_eq!(nh, 4);

        // The trailing Delete must name the just-superseded local SPI.
        let hdr = IsakmpHeader::parse(&delete_bytes).unwrap();
        let iv0 = crypto1::phase2_iv(rstate2.prf, &rstate2.phase1_iv, hdr.message_id, AES_BLOCK);
        let (_h, ps, _iv) = phase2::parse_encrypted(&delete_bytes, rstate2.prf, &rstate2.skeyid_a, &rstate2.enc_key, &iv0).unwrap();
        let del = ps.iter().find(|p| p.payload_type == payload::DELETE).unwrap();
        let (proto, spi) = informational::parse_delete(&del.data).unwrap();
        assert_eq!(proto, protocol::ESP);
        assert_eq!(spi, old_local_spi.to_be_bytes());
    }

    // ---- IPv6 CHILD SA ----

    fn v6(a: &str) -> Ipv6Addr {
        a.parse().unwrap()
    }

    /// A completed Phase 1 (Aggressive, PSK) between an initiator and a
    /// responder, as `(initiator state, responder state, initiator entropy,
    /// responder entropy)`.
    fn phase1_pair(seed_i: u64, seed_r: u64, i_addr: SocketAddr, r_addr: SocketAddr) -> (Phase1State, Phase1State, SeedEntropy, SeedEntropy) {
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
            ts_local: ([0; 4], [0; 4]),
            ts_remote: ([0; 4], [0; 4]),
            esp_cipher: SkCipher::Aes256Gcm,
            pfs_group: None,
            mode_cfg: false,
            ipv6: true,
            mode: Ikev1ExchangeMode::Aggressive,
            p1_lifetime_secs: 28800,
            p2_lifetime_secs: 3600,
            force_natt: false,
        };
        let rcfg = Phase1Config { local_auth: Ikev1LocalAuth::Psk(psk), trusted_cas: Vec::new(), now_unix: 0, our_id: Id::ipv4([192, 168, 0, 1]) };
        let mut ie = SeedEntropy::new(seed_i);
        let mut re = SeedEntropy::new(seed_r);
        let (msg1, ai) = initiate_aggressive(&icfg, &mut ie, i_addr, r_addr);
        let (msg2, rstate) = respond_aggressive(&rcfg, &msg1, &mut re, r_addr, i_addr).unwrap();
        let (msg3, istate) = ai.complete(&msg2, i_addr, r_addr).unwrap();
        rstate.verify_hash_i(&msg3).unwrap();
        (istate, rstate, ie, re)
    }

    #[test]
    fn ts_id_v6_encodes_network_and_mask_masking_host_bits() {
        let id = |b: Vec<u8>| Id::parse(&b).unwrap();

        let any = id(ts_id_v6(v6("::"), 0));
        assert_eq!(any.id_type, id_type::IPV6_ADDR_SUBNET);
        assert_eq!(any.data, vec![0u8; 32]);

        let host = id(ts_id_v6(v6("fd00::1234"), 128));
        assert_eq!(&host.data[..16], &v6("fd00::1234").octets());
        assert_eq!(&host.data[16..], &[0xffu8; 16]);

        // Host bits below the prefix are cleared from the network address.
        let net = id(ts_id_v6(v6("2001:db8:1:2:3:4:5:6"), 64));
        assert_eq!(&net.data[..16], &v6("2001:db8:1:2::").octets());
        assert_eq!(&net.data[16..], &(u128::MAX << 64).to_be_bytes());

        // An out-of-range prefix length is clamped, never a shift overflow.
        assert_eq!(id(ts_id_v6(v6("fd00::1"), 250)).data[16..], [0xffu8; 16]);
    }

    /// The IPv6 Quick Mode carries IPv6 subnet identities on the wire, the
    /// responder echoes them, and the two CHILD SAs interoperate.
    #[test]
    fn ikev1_quick_mode_ipv6_carries_ipv6_identities_and_esp_roundtrips() {
        let (istate, rstate, mut ie, mut re) = phase1_pair(0x9101, 0x9102, "10.1.1.1:500".parse().unwrap(), "192.168.0.1:500".parse().unwrap());
        let vip = v6("fd00::abcd");
        let (qm1, qi) = initiate_quick_ipv6(&istate, &mut ie, SkCipher::Aes256Gcm, (vip, 128), (v6("::"), 0), None, 3600).unwrap();

        // What the responder sees: IDci = our VIP/128, IDcr = ::/0, both IPv6 subnets.
        let msgid = IsakmpHeader::parse(&qm1).unwrap().message_id;
        let iv0 = crypto1::phase2_iv(rstate.prf, &rstate.phase1_iv, msgid, AES_BLOCK);
        let (_h, ps, _iv) = phase2::parse_encrypted(&qm1, rstate.prf, &rstate.skeyid_a, &rstate.enc_key, &iv0).unwrap();
        let ids: Vec<Id> = ps.iter().filter(|p| p.payload_type == payload::ID).map(|p| Id::parse(&p.data).unwrap()).collect();
        assert_eq!(ids.len(), 2);
        assert!(ids.iter().all(|i| i.id_type == id_type::IPV6_ADDR_SUBNET && i.data.len() == 32));
        assert_eq!(&ids[0].data[..16], &vip.octets());
        assert_eq!(&ids[0].data[16..], &[0xffu8; 16]);
        assert_eq!(ids[1].data, vec![0u8; 32]);

        let (qm2, qr) = respond_quick(&rstate, &qm1, &mut re).unwrap();
        let (qm3, mut ichild, _lifetime) = qi.complete(&qm2).unwrap();
        let mut rchild = qr.complete(&qm3).unwrap();

        let pkt: Vec<u8> = (0..40u8).collect();
        let sealed = ichild.outbound.seal(&pkt, 41).unwrap();
        let (got, nh) = rchild.inbound.open(&sealed).unwrap();
        assert_eq!((got, nh), (pkt.clone(), 41));
        let sealed_r = rchild.outbound.seal(&pkt, 41).unwrap();
        assert_eq!(ichild.inbound.open(&sealed_r).unwrap().0, pkt);
    }

    /// Two Quick Modes under one Phase 1 -- the IPv4 CHILD SA and the IPv6
    /// one -- are independent: distinct SPIs and distinct keys.
    #[test]
    fn a_second_quick_mode_for_ipv6_yields_an_independent_child_sa() {
        let (istate, rstate, mut ie, mut re) = phase1_pair(0x9201, 0x9202, "10.1.1.1:500".parse().unwrap(), "192.168.0.1:500".parse().unwrap());
        let ts4 = ([10, 212, 134, 202], [255, 255, 255, 255]);
        let (qm1, qi) = initiate_quick(&istate, &mut ie, SkCipher::Aes256Gcm, ts4, ([0; 4], [0; 4]), 3600).unwrap();
        let (qm2, qr) = respond_quick(&rstate, &qm1, &mut re).unwrap();
        let (qm3, child4, _) = qi.complete(&qm2).unwrap();
        qr.complete(&qm3).unwrap();

        let (qm1, qi) = initiate_quick_ipv6(&istate, &mut ie, SkCipher::Aes256Gcm, (v6("fd00::1"), 128), (v6("::"), 0), None, 3600).unwrap();
        let (qm2, qr) = respond_quick(&rstate, &qm1, &mut re).unwrap();
        let (qm3, child6, _) = qi.complete(&qm2).unwrap();
        qr.complete(&qm3).unwrap();

        assert_ne!(child4.inbound.spi(), child6.inbound.spi());
        assert_ne!(child4.outbound.spi(), child6.outbound.spi());
        assert_ne!(child4.outbound.key_material(), child6.outbound.key_material());
    }

    /// A responder loop for the tests below: answers one Quick Mode (msg1 →
    /// msg2, msg3), then optionally reads the trailing Delete.
    fn spawn_quick_responder(
        sock: UdpSocket,
        rstate: Phase1State,
        mut re: SeedEntropy,
        reply_to: SocketAddr,
        expect_delete: bool,
    ) -> std::thread::JoinHandle<(ChildSa, Option<Vec<u8>>, Phase1State)> {
        std::thread::spawn(move || {
            let mut buf = [0u8; 8192];
            let n = sock.recv(&mut buf).unwrap();
            let (msg2, qr) = respond_quick(&rstate, &buf[..n], &mut re).unwrap();
            sock.send_to(&msg2, reply_to).unwrap();
            let n = sock.recv(&mut buf).unwrap();
            let child = qr.complete(&buf[..n]).unwrap();
            let delete = expect_delete.then(|| {
                let n = sock.recv(&mut buf).unwrap();
                buf[..n].to_vec()
            });
            (child, delete, rstate)
        })
    }

    fn loopback_pair() -> (UdpSocket, UdpSocket, SocketAddr, SocketAddr) {
        let a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        a.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        b.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let (aa, ba) = (a.local_addr().unwrap(), b.local_addr().unwrap());
        (a, b, aa, ba)
    }

    #[test]
    fn create_child_ipv6_over_loopback_interoperates_and_sends_no_delete() {
        let (isock, rsock, iaddr, raddr) = loopback_pair();
        let (istate, rstate, mut ie, re) = phase1_pair(0x9301, 0x9302, iaddr, raddr);
        let responder = spawn_quick_responder(rsock, rstate, re, iaddr, false);

        let (rekeyed, lifetime) = create_child_ipv6(
            &isock, &istate, &mut ie, raddr, SkCipher::Aes256Gcm, None, (v6("fd00::1"), 128), (v6("::"), 0), 1800, Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(lifetime, 1800);

        let (mut rchild, delete, _rstate) = responder.join().unwrap();
        assert!(delete.is_none());
        let mut ours = EspSa::new_with_cipher(rekeyed.local_spi, rekeyed.key_in.cipher, &rekeyed.key_in.enc, &rekeyed.key_in.integ).unwrap();
        let pkt: Vec<u8> = (0..40u8).collect();
        let sealed = rchild.outbound.seal(&pkt, 41).unwrap();
        assert_eq!(ours.open(&sealed).unwrap(), (pkt, 41));
    }

    /// The IPv6 rekey renegotiates with IPv6 identities and then deletes the
    /// superseded IPv6 SA -- by its own SPI, leaving the IPv4 SA alone.
    #[test]
    fn rekey_child_ipv6_over_loopback_deletes_the_superseded_ipv6_sa() {
        let (isock, rsock, iaddr, raddr) = loopback_pair();
        let (istate, rstate, mut ie, re) = phase1_pair(0x9401, 0x9402, iaddr, raddr);
        let old_local_spi = 0x0bad_cafe;
        let responder = spawn_quick_responder(rsock, rstate, re, iaddr, true);

        let (rekeyed, _) = rekey_child_ipv6(
            &isock, &istate, &mut ie, raddr, SkCipher::Aes256Gcm, None, (v6("fd00::1"), 128), (v6("::"), 0), 1800, Duration::from_secs(5), old_local_spi,
        )
        .unwrap();
        let (_rchild, delete, rstate) = responder.join().unwrap();
        assert_ne!(rekeyed.local_spi, old_local_spi);

        let delete = delete.unwrap();
        let hdr = IsakmpHeader::parse(&delete).unwrap();
        let iv0 = crypto1::phase2_iv(rstate.prf, &rstate.phase1_iv, hdr.message_id, AES_BLOCK);
        let (_h, ps, _iv) = phase2::parse_encrypted(&delete, rstate.prf, &rstate.skeyid_a, &rstate.enc_key, &iv0).unwrap();
        let del = ps.iter().find(|p| p.payload_type == payload::DELETE).unwrap();
        let (proto, spi) = informational::parse_delete(&del.data).unwrap();
        assert_eq!((proto, spi), (protocol::ESP, &old_local_spi.to_be_bytes()[..]));
    }

    /// A gateway with no IPv6 Phase 2 rejects with an error Notify: the create
    /// fails at once with the real reason instead of running out the timeout.
    #[test]
    fn create_child_ipv6_fails_fast_when_the_peer_answers_with_an_error_notify() {
        let (isock, rsock, iaddr, raddr) = loopback_pair();
        let (istate, rstate, mut ie, mut re) = phase1_pair(0x9501, 0x9502, iaddr, raddr);
        let responder = std::thread::spawn(move || {
            let mut buf = [0u8; 8192];
            rsock.recv(&mut buf).unwrap();
            let reject = informational::build_error_notify(&rstate, &mut re, 18).unwrap();
            rsock.send_to(&reject, iaddr).unwrap();
        });

        let started = Instant::now();
        let err = match create_child_ipv6(
            &isock, &istate, &mut ie, raddr, SkCipher::Aes256Gcm, None, (v6("fd00::1"), 128), (v6("::"), 0), 3600, Duration::from_secs(4),
        ) {
            Err(DriverError::Ike(e)) => e,
            other => panic!("expected an IKE error, got {:?}", other.map(|_| ())),
        };
        responder.join().unwrap();
        assert_eq!(err, IkeError::PeerRejected { notify_type: 18, name: "INVALID_ID_INFORMATION" });
        assert!(started.elapsed() < Duration::from_secs(3), "must not wait out the timeout");
    }

    /// Anything else the peer sends is skipped and the timeout still applies.
    #[test]
    fn create_child_ipv6_times_out_when_the_peer_stays_silent() {
        let (isock, _rsock, iaddr, raddr) = loopback_pair();
        let (istate, _rstate, mut ie, _re) = phase1_pair(0x9601, 0x9602, iaddr, raddr);
        let err = create_child_ipv6(
            &isock, &istate, &mut ie, raddr, SkCipher::Aes256Gcm, None, (v6("fd00::1"), 128), (v6("::"), 0), 3600, Duration::from_millis(300),
        );
        assert!(matches!(err, Err(DriverError::Ike(IkeError::Crypto(m))) if m.contains("timed out")), "got {:?}", err.map(|_| ()));
    }
    /// The reason `IkeSocket` exists: a host whose ESP pump is the only reader
    /// of the IKE socket hands the exchange its IKE datagrams through a
    /// [`ChannelIo`]. A Quick Mode rekey then completes -- reply read from the
    /// channel, both the exchange messages and the trailing Delete sent out
    /// through the shared socket -- although ESP arrives on that socket too.
    #[test]
    fn rekey_child_completes_through_a_channel_while_a_pump_owns_the_socket() {
        use crate::transport::{spawn_pump_reader, ChannelIo};
        let (isock, rsock, iaddr, raddr) = loopback_pair();
        let (istate, rstate, mut ie, re) = phase1_pair(0x9701, 0x9702, iaddr, raddr);
        let old_local_spi = 0x0bad_f00d;
        let responder = spawn_quick_responder(rsock, rstate, re, iaddr, true);
        // Everything is forwarded here (`marked_only: false`): this Phase 1 is
        // not floated, so its datagrams carry no non-ESP marker.
        let (rx, _pump) = spawn_pump_reader(&isock, false);
        let io = ChannelIo::new(isock, rx, raddr);

        let ts = ([10, 212, 134, 202], [255, 255, 255, 255]);
        let (rekeyed, lifetime) =
            rekey_child(&io, &istate, &mut ie, raddr, SkCipher::Aes256Gcm, None, ts, ([0; 4], [0; 4]), 1800, Duration::from_secs(5), old_local_spi).unwrap();
        assert_eq!(lifetime, 1800);
        assert_ne!(rekeyed.local_spi, old_local_spi);

        let (mut rchild, delete, _rstate) = responder.join().unwrap();
        assert!(delete.is_some(), "the Delete for the superseded SA must go out through the channel's socket");
        let mut ours = EspSa::new_with_cipher(rekeyed.local_spi, rekeyed.key_in.cipher, &rekeyed.key_in.enc, &rekeyed.key_in.integ).unwrap();
        let pkt: Vec<u8> = (0..40u8).collect();
        let sealed = rchild.outbound.seal(&pkt, 4).unwrap();
        assert_eq!(ours.open(&sealed).unwrap(), (pkt, 4));
    }

    /// The IPv6 CHILD SA creation takes the same route.
    #[test]
    fn create_child_ipv6_completes_through_a_channel_while_a_pump_owns_the_socket() {
        use crate::transport::{spawn_pump_reader, ChannelIo};
        let (isock, rsock, iaddr, raddr) = loopback_pair();
        let (istate, rstate, mut ie, re) = phase1_pair(0x9801, 0x9802, iaddr, raddr);
        let responder = spawn_quick_responder(rsock, rstate, re, iaddr, false);
        let (rx, _pump) = spawn_pump_reader(&isock, false);
        let io = ChannelIo::new(isock, rx, raddr);

        let (_rekeyed, lifetime) = create_child_ipv6(
            &io, &istate, &mut ie, raddr, SkCipher::Aes256Gcm, None, (v6("fd00::1"), 128), (v6("::"), 0), 1800, Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(lifetime, 1800);
        responder.join().unwrap();
    }

    /// A silent peer still runs out the timeout through the channel, and a
    /// dead channel is an error rather than a hang.
    #[test]
    fn create_child_ipv6_through_a_channel_times_out_and_reports_a_dead_reader() {
        use crate::transport::{spawn_pump_reader, ChannelIo};
        let (isock, _rsock, iaddr, raddr) = loopback_pair();
        let (istate, _rstate, mut ie, _re) = phase1_pair(0x9901, 0x9902, iaddr, raddr);
        let (rx, pump) = spawn_pump_reader(&isock, false);
        let io = ChannelIo::new(isock, rx, raddr);
        let ask = |ie: &mut SeedEntropy| {
            create_child_ipv6(&io, &istate, ie, raddr, SkCipher::Aes256Gcm, None, (v6("fd00::1"), 128), (v6("::"), 0), 3600, Duration::from_millis(300))
        };
        let err = ask(&mut ie);
        assert!(matches!(err, Err(DriverError::Ike(IkeError::Crypto(m))) if m.contains("timed out")), "got {:?}", err.map(|_| ()));

        drop(pump); // the reader is gone, its sender with it
        assert!(matches!(ask(&mut ie), Err(DriverError::Io(e)) if e.kind() == std::io::ErrorKind::BrokenPipe));
    }
}
