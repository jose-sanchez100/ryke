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

use super::crypto1::{self, Prf, AES_BLOCK};
use super::isakmp::{self, exchange, payload, IsakmpHeader, Payload};
use super::payloads::{
    id_type, protocol, Attribute, Id, Proposal, SaPayload, Transform, IPSEC_DOI, SIT_IDENTITY_ONLY,
};
use super::phase1::Phase1State;
use super::phase2;
use crate::crypto::{DhGroup, IntegAlgorithm};
use crate::entropy::Entropy;
use crate::error::IkeError;
use crate::esp::{ChildSa, EspSa};
use crate::ikev2::payload::transform_id;
use crate::ikev2::sk::SkCipher;

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
fn esp_sa(spi: u32, cipher: SkCipher, pfs_group: Option<DhGroup>, floated: bool) -> SaPayload {
    let encap_mode = if floated { UDP_ENCAP_TUNNEL } else { ENCAP_TUNNEL };
    let mut attributes = vec![
        Attribute::short(esp_attr::ENCAP_MODE, encap_mode),
        Attribute::short(esp_attr::LIFE_TYPE, LIFE_SECONDS),
        Attribute::long_u32(esp_attr::LIFE_DURATION, 3600),
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
) -> Result<(Vec<u8>, QuickInitiator), IkeError> {
    initiate_quick_with_pfs(st, entropy, cipher, ts_local, ts_remote, None)
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
        (payload::SA, esp_sa(local_spi, cipher, pfs_group, st.floated).to_bytes()),
        (payload::NONCE, ni.clone()),
    ];
    if let Some((group, dh_private)) = &pfs {
        after.push((payload::KE, group.public(dh_private)));
    }
    after.push((payload::ID, ts_id(ts_local.0, ts_local.1)));
    after.push((payload::ID, ts_id(ts_remote.0, ts_remote.1)));
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
    }))
}

impl QuickInitiator {
    /// Process message 2 (`HASH(2), SA, Nr, [KE]`): verify `HASH(2)`, and
    /// return message 3 (`HASH(3)`) plus the established ESP CHILD SA.
    pub fn complete(self, msg2: &[u8]) -> Result<(Vec<u8>, ChildSa), IkeError> {
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
        Ok((msg3, child))
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

    let mut spi_b = [0u8; 4];
    entropy.fill(&mut spi_b);
    let local_spi = u32::from_be_bytes(spi_b);
    let mut nr = vec![0u8; 16];
    entropy.fill(&mut nr);

    let mut after: Vec<(u8, Vec<u8>)> = vec![
        (payload::SA, esp_sa(local_spi, cipher, pfs_group, st.floated).to_bytes()),
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

#[cfg(test)]
mod tests {
    use super::*;
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
            mode: Ikev1ExchangeMode::Aggressive,
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
        let (qm1, qi) = initiate_quick(&istate, &mut ie, SkCipher::Aes256Gcm, ts, ts).unwrap();
        let (qm2, qr) = respond_quick(&rstate, &qm1, &mut re).unwrap();
        let (qm3, mut ichild) = qi.complete(&qm2).unwrap();
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
            mode: Ikev1ExchangeMode::Aggressive,
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

        let (qm1, _qi) = initiate_quick(&istate, &mut ie, SkCipher::Aes256Gcm, ts, ts).unwrap();

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
            mode: Ikev1ExchangeMode::Aggressive,
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

        let (qm1, qi) = initiate_quick(&istate, &mut ie, cipher, ts, ts).unwrap();
        let (qm2, qr) = respond_quick(&rstate, &qm1, &mut re).unwrap();
        let (qm3, mut ichild) = qi.complete(&qm2).unwrap();
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
            mode: Ikev1ExchangeMode::Aggressive,
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
        let (qm1, qi) = initiate_quick_with_pfs(&istate, &mut ie, SkCipher::Aes256Gcm, ts, ts, Some(DhGroup::Modp2048)).unwrap();
        let (qm2, qr) = respond_quick(&rstate, &qm1, &mut re).unwrap();
        let (qm3, mut ichild) = qi.complete(&qm2).unwrap();
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
            mode: Ikev1ExchangeMode::Aggressive,
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
            let (qm1, qi) = initiate_quick_with_pfs(&istate, ie, SkCipher::Aes256Gcm, ts, ts, Some(DhGroup::Modp2048)).unwrap();
            let (qm2, qr) = respond_quick(&rstate, &qm1, re).unwrap();
            let (qm3, ichild) = qi.complete(&qm2).unwrap();
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
            mode: Ikev1ExchangeMode::Aggressive,
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
}
