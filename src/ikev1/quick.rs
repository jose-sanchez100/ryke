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
//!
//! # SA lifetimes: negotiated here, counted by the caller
//!
//! A lifetime can be stated in seconds and in kilobytes, several pairs at once
//! ("100 MB or 24 hours": RFC 2407 §4.5.2; RFC 2409 App. A for Phase 1; the
//! DOI's §4.5 says of a Duration only that it defines "either a number of
//! seconds, or a number of Kbytes that can be protected" -- that the SA ends at
//! whichever comes first is the usual reading of "either ... or", not a rule the
//! RFCs spell out). This crate does not carry the ESP data plane (the caller runs
//! the traffic; [`crate::esp::EspSa`] only seals and opens what it is handed, and
//! stops at its sequence number, never at a byte count), so it negotiates a limit
//! and **hands it over** without counting against it (test: `esp`'s
//! `an_esp_sa_holds_no_byte_counter_and_no_lifetime`): the limit is a
//! [`SaLifetime`], and renewing the SA ahead of it, and ceasing to use it at it,
//! are the caller's -- each of the two limits on its own, the SA ending at
//! whichever is reached first, and every SA counted separately.
//!
//! **Phase 1** does not accept a volume limit at all, and that is settled: an
//! ISAKMP SA is limited in seconds only. A transform that states a kilobytes pair
//! is passed over by a responder (another transform of the offer is taken if
//! there is one; none is `NoProposalChosen`), and an answer whose transform states
//! one is refused by an initiator (`NoProposalChosen`), in Aggressive and in Main
//! Mode, rather than taken and then ignored (tests: `phase1`'s
//! `..states_a_volume_limit..`). This is a limit of this implementation, not of the
//! RFC: RFC 2409 App. A allows the pair, and the bytes an ISAKMP SA protects are
//! ones this crate does handle -- counting them is future work, not something the
//! protocol rules out. A pair that cannot be read stays `MalformedPayload`.
//!
//! **Phase 2, as an initiator**, offers one seconds pair and nothing else, so it
//! never asks the peer to hold it to a volume. A kilobytes pair in the answer is
//! the peer's own limit on the SA (RFC 2407 §4.5.4: a responder may complete the
//! negotiation "using a shorter lifetime than what was offered"), and it is held,
//! not dropped: [`QuickInitiator::complete_with_lifetime`],
//! [`rekey_child_with_lifetime`] and its IPv6 counterparts, and
//! `Established::p2_lifetime_kilobytes` return it beside the seconds. It is never
//! read as seconds, whatever its position among the pairs; the seconds are still
//! the responder's own, never beyond what was offered (28800, the DOI default,
//! when it states none); and it changes nothing else of the exchange -- message 3
//! and the keys are those of the same answer without it. A pair that is not well
//! formed (Type, then a Duration that is not zero, empty or absurdly wide; no two
//! values for one unit) ends the exchange (tests:
//! `quick_mode_initiator_holds_the_volume_limit_the_answer_states` and
//! `a_rekey_or_a_new_ipv6_child_sa_hands_over_the_volume_limit_the_gateway_states`).
//!
//! **Phase 2, as a responder**, is not changed yet by any of this: what it answers
//! is one seconds pair -- its own limit -- and never a kilobytes pair, so an offer
//! that includes a volume limit is answered as though it had none. That is the
//! gap this section leaves open for the responder, and not RFC-conformant
//! behaviour so much as a policy decision waiting to be taken: the SA it grants
//! may protect more than the initiator was willing to. RFC 2407 §4.5.3 requires
//! aborting on "a defined IPSEC DOI attribute (or attribute value) which it does
//! not support", and a Kilobytes Life Type is a defined one.

use std::net::{Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use super::crypto1::{self, Prf};
use super::informational;
use super::isakmp::{self, exchange, payload, IsakmpHeader, Payload};
use super::payloads::{
    id_type, life, life_duration_value, protocol, AttrValue, Attribute, Id, Proposal, SaPayload, Transform, IPSEC_DOI,
    SIT_IDENTITY_ONLY,
};
use super::phase1::Phase1State;
use super::phase2;
use super::retransmit_waits;
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

/// What a Quick Mode negotiated as the limit of one ESP SA (RFC 2407 §4.5): a
/// lifetime in seconds and, when one was stated, one in kilobytes. The two are
/// independent limits, and the SA ends at whichever is reached first (the usual
/// reading of "100 MB or 24 hours", RFC 2407 §4.5.2). This crate does not carry
/// the data plane, so it cannot count either: it hands them over, and the
/// caller that runs the traffic is the one that renews the SA ahead of them and
/// stops using it at the last (see the module's "SA lifetimes" section).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SaLifetime {
    /// Seconds. The DOI default (28800) when nothing stated a time limit, and
    /// never more than what the initiator offered.
    pub seconds: u32,
    /// Kilobytes protected, when a limit in volume was stated. A kilobyte is
    /// the unit the peer counted in: RFC 2407 does not say whether that is 1000
    /// or 1024 octets, and a caller that must not protect more than the peer's
    /// count reads it as 1000.
    pub kilobytes: Option<u32>,
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
/// RFC 2407 §4.5: the lifetime of an SA that states none.
const DEFAULT_LIFE_SECONDS: u32 = 28_800;
/// What a responder here grants an offer that states no lifetime in seconds --
/// its own policy, and shorter than [`DEFAULT_LIFE_SECONDS`], which RFC 2407
/// §4.5.4 lets it be.
const RESPONDER_LIFE_SECONDS: u32 = 3600;
/// The attributes a responder may change on its own (RFC 2407 §4.5.4), hence
/// the ones an answer is not compared on.
const LIFETIME_ATTRS: [u16; 2] = [esp_attr::LIFE_TYPE, esp_attr::LIFE_DURATION];

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

/// The limits one transform states, each `None` when it states none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StatedLifetime {
    seconds: Option<u32>,
    kilobytes: Option<u32>,
}

/// The SA lifetime, in seconds and in kilobytes, that `t` states -- each `None`
/// when it states no such limit. RFC 2407 §4.5: an SA Life Duration "MUST always
/// follow an SA Life Type which describes the units of duration" (seconds or
/// kilobytes); §4.5.2: a list "MUST" be parsed when it carries several such
/// pairs (e.g. 100 MB *or* 24 hours), so long as they don't conflict; §4.5.3: a
/// Type we don't define aborts the negotiation. Errors are `MalformedPayload`: a
/// Type that is not immediately followed by its Duration, a Duration with no
/// Type, a Type that is not a basic attribute or not seconds/kilobytes, a
/// Duration that is empty, wider than eight octets or zero, and two different
/// durations for one unit. The two limits are independent: neither is ever read
/// as the other, whatever their order -- see the module's "SA lifetimes"
/// section.
fn stated_lifetime(t: &Transform) -> Result<StatedLifetime, IkeError> {
    let (mut seconds, mut kilobytes): (Option<u32>, Option<u32>) = (None, None);
    let mut pending: Option<u16> = None;
    for a in &t.attributes {
        if pending.is_some() && a.attr_type != esp_attr::LIFE_DURATION {
            return Err(IkeError::MalformedPayload("SA Life Type not immediately followed by its SA Life Duration"));
        }
        match a.attr_type {
            esp_attr::LIFE_TYPE => match a.value {
                AttrValue::Short(kind @ (life::SECONDS | life::KILOBYTES)) => pending = Some(kind),
                AttrValue::Short(_) => return Err(IkeError::MalformedPayload("unsupported SA Life Type")),
                AttrValue::Long(_) => return Err(IkeError::MalformedPayload("SA Life Type sent as a variable-length attribute")),
            },
            esp_attr::LIFE_DURATION => {
                let Some(kind) = pending.take() else {
                    return Err(IkeError::MalformedPayload("SA Life Duration with no SA Life Type before it"));
                };
                let value = life_duration_value(&a.value).ok_or(IkeError::MalformedPayload("SA Life Duration of unusable length"))?;
                if value == 0 {
                    return Err(IkeError::MalformedPayload("SA Life Duration of zero"));
                }
                let slot = if kind == life::SECONDS { &mut seconds } else { &mut kilobytes };
                match *slot {
                    Some(previous) if previous != value => return Err(IkeError::MalformedPayload("conflicting SA Life Durations for one unit")),
                    _ => *slot = Some(value),
                }
            }
            _ => {}
        }
    }
    if pending.is_some() {
        return Err(IkeError::MalformedPayload("SA Life Type not immediately followed by its SA Life Duration"));
    }
    Ok(StatedLifetime { seconds, kilobytes })
}

/// The lifetime an already-validated answer (`ps`, see [`check_answer`]) leaves
/// us with. RFC 2407 §4.5.4: the responder may complete the negotiation "using a
/// shorter lifetime than what was offered" -- so its seconds pair (28800
/// seconds, the DOI default, when it states none) counts, but never beyond
/// `offered`: what we offered is our own limit, and a longer answer only says
/// the peer would keep the SA longer. A kilobytes pair is not a number of
/// seconds, and is not lost either: it is the volume limit the SA was granted
/// under, held as stated. What we offer states seconds only, so a volume limit
/// in an answer is one the peer added -- only ever a shorter life for the SA,
/// which is what §4.5.4 lets a responder do. `offered` is also what an answer we
/// can't read leaves us with. `phase1::negotiated_p1_lifetime` is the Phase-1
/// counterpart, which has no default lifetime to fall back on and no volume.
fn negotiated_p2_lifetime(ps: &[Payload], offered: u32) -> SaLifetime {
    let unread = SaLifetime { seconds: offered, kilobytes: None };
    let Ok(sa) = single_sa(ps) else { return unread };
    let Some(transform) = sa.proposals.first().and_then(|p| p.transforms.first()) else { return unread };
    let Ok(stated) = stated_lifetime(transform) else { return unread };
    SaLifetime { seconds: stated.seconds.unwrap_or(DEFAULT_LIFE_SECONDS).min(offered), kilobytes: stated.kilobytes }
}

/// The one SA payload of a Quick Mode message (RFC 2409 §5.5 carries exactly
/// one): a message with none is `MissingPayload`, with several `NoProposalChosen`
/// -- which of them was meant is not ours to guess.
fn single_sa(ps: &[Payload]) -> Result<SaPayload, IkeError> {
    let mut sas = ps.iter().filter(|p| p.payload_type == payload::SA);
    let first = sas.next().ok_or(IkeError::MissingPayload("SA"))?;
    if sas.next().is_some() {
        return Err(IkeError::NoProposalChosen);
    }
    SaPayload::parse(&first.data)
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
    esp_sa_numbered(spi, 1, 1, cipher, pfs_group, encap_mode, life_duration)
}

/// The one ESP transform `esp_sa` proposes (and a responder here answers)
/// for `cipher`, `pfs_group` and `encap_mode`, seconds-lifetime `life_duration`,
/// numbered `num`. It is also what a transform must equal, lifetimes apart, for
/// [`select_offer`] to take it: each attribute once, basic-encoded, and no
/// attribute that isn't part of the suite.
fn esp_transform(num: u8, cipher: SkCipher, pfs_group: Option<DhGroup>, encap_mode: u16, life_duration: u32) -> Transform {
    let mut attributes = vec![
        Attribute::short(esp_attr::ENCAP_MODE, encap_mode),
        Attribute::short(esp_attr::LIFE_TYPE, life::SECONDS),
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
    Transform { num, transform_id: esp_transform_id(cipher), attributes }
}

/// An SA payload with the single ESP proposal `proposal_num` carrying our
/// inbound `spi` and the single transform `transform_num` -- a responder
/// answers with the numbers of the proposal and transform it took (RFC 2408
/// §4.2: it "SHOULD retain the Proposal # and Transform # fields").
fn esp_sa_numbered(
    spi: u32,
    proposal_num: u8,
    transform_num: u8,
    cipher: SkCipher,
    pfs_group: Option<DhGroup>,
    encap_mode: u16,
    life_duration: u32,
) -> SaPayload {
    SaPayload {
        doi: IPSEC_DOI,
        situation: SIT_IDENTITY_ONLY,
        proposals: vec![Proposal {
            num: proposal_num,
            protocol_id: protocol::ESP,
            spi: spi.to_be_bytes().to_vec(),
            transforms: vec![esp_transform(transform_num, cipher, pfs_group, encap_mode, life_duration)],
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

/// The `SkCipher` an ESP transform names -- what a responder keys its own side
/// with, rather than assuming a fixed cipher. `key_len` falls back to a
/// sensible default (192 bits for 3DES, 256 otherwise) when KEY_LENGTH is
/// left out; [`acceptable_transform`] then refuses such a transform, since
/// RFC 2407 §4.5 wants the length stated for a variable-length cipher.
fn transform_cipher(t: &Transform) -> Option<SkCipher> {
    let encr_id = t.transform_id as u16;
    let default_bits = if encr_id == transform_id::TRIPLE_DES { 192 } else { 256 };
    let key_bits = t.attr(esp_attr::KEY_LENGTH).unwrap_or(default_bits);
    let integ_id = t.attr(esp_attr::AUTH_ALGORITHM).and_then(integ_from_esp_auth_algorithm).map(IntegAlgorithm::transform_id);
    SkCipher::from_encr_integ(encr_id, key_bits, integ_id)
}

/// What a responder here takes from one offered ESP transform, if it can honour
/// it (RFC 2407 §4.5.3: a transform with an attribute or value it does not
/// support is not one it can accept).
struct AcceptableTransform {
    cipher: SkCipher,
    pfs_group: Option<DhGroup>,
    encap_mode: u16,
    life_seconds: u32,
}

/// `Some` when `t` is a transform this side can build: tunnel mode, plain or
/// UDP-encapsulated (RFC 2407 §4.5, RFC 3947 §5.1 -- transport mode, unknown
/// modes and a missing mode, which the DOI leaves "host-dependent", are not
/// honoured); a cipher we implement; nothing but the attributes of that
/// suite, each once and basic-encoded (compared with the transform
/// [`esp_transform`] would build, lifetimes apart -- which is also what turns
/// a PFS group we don't implement, dropped from that transform, into a
/// mismatch rather than into "no PFS"); and lifetime pairs that parse (see
/// [`stated_lifetime`]).
fn acceptable_transform(t: &Transform) -> Option<AcceptableTransform> {
    let encap_mode = t.attr(esp_attr::ENCAP_MODE).filter(|m| matches!(*m, ENCAP_TUNNEL | UDP_ENCAP_TUNNEL))?;
    let pfs_group = t.attr(esp_attr::GROUP_DESC).and_then(DhGroup::from_transform_id);
    let cipher = transform_cipher(t)?;
    if !t.matches_offer(&esp_transform(t.num, cipher, pfs_group, encap_mode, 0), &LIFETIME_ATTRS) {
        return None;
    }
    let life_seconds = stated_lifetime(t).ok()?.seconds.unwrap_or(RESPONDER_LIFE_SECONDS);
    Some(AcceptableTransform { cipher, pfs_group, encap_mode, life_seconds })
}

/// The one ESP proposal and transform a responder takes from an initiator's
/// offer.
struct Selection {
    proposal_num: u8,
    transform_num: u8,
    peer_spi: u32,
    cipher: SkCipher,
    pfs_group: Option<DhGroup>,
    encap_mode: u16,
    life_seconds: u32,
}

/// Pick what to answer from the SA payload of Quick Mode message 1. RFC 2408
/// §4.2: the receiver "MUST select a single transform for each protocol" of
/// the proposal it takes -- here the first acceptable transform of the first
/// acceptable proposal, in the initiator's order (its own preference order,
/// as `isakmpd`'s `message_negotiate_sa` reads it). An ESP proposal shares its
/// Proposal # with another one when the initiator asks for both protections
/// together (RFC 2408 §4.2: same number, AND); a suite this side cannot build
/// is passed over. Nothing acceptable is `NoProposalChosen`, and so is an
/// SA in another DOI or situation (RFC 2407 §4.2, §4.6.1).
fn select_offer(ps: &[Payload]) -> Result<Selection, IkeError> {
    let sa = single_sa(ps)?;
    if sa.doi != IPSEC_DOI || sa.situation != SIT_IDENTITY_ONLY {
        return Err(IkeError::NoProposalChosen);
    }
    for proposal in &sa.proposals {
        let Ok(spi) = <[u8; 4]>::try_from(proposal.spi.as_slice()) else { continue };
        if proposal.protocol_id != protocol::ESP || sa.proposals.iter().filter(|q| q.num == proposal.num).count() > 1 {
            continue;
        }
        for transform in &proposal.transforms {
            if let Some(a) = acceptable_transform(transform) {
                return Ok(Selection {
                    proposal_num: proposal.num,
                    transform_num: transform.num,
                    peer_spi: u32::from_be_bytes(spi),
                    cipher: a.cipher,
                    pfs_group: a.pfs_group,
                    encap_mode: a.encap_mode,
                    life_seconds: a.life_seconds,
                });
            }
        }
    }
    Err(IkeError::NoProposalChosen)
}

/// Check the SA payload of Quick Mode message 2 against the one we sent
/// (`offered`) and return the SPI the responder chose for its inbound ESP SA.
/// RFC 2408 §4.2: "The initiator MUST verify that the Security Association
/// payload received from the responder matches one of the proposals sent
/// initially" -- an authentic HASH(2) says the message wasn't altered on the
/// way, not that it names what we proposed. So: one SA payload, in our DOI and
/// situation; one proposal, for ESP, with our Proposal # and a 4-octet SPI; one
/// transform, with our Transform #, transform ID and every attribute -- the
/// encapsulation mode (RFC 3947 §5.1 included), key length, integrity
/// algorithm and PFS group -- exactly as offered, in any order, and nothing we
/// didn't offer; only the lifetime pairs may differ (RFC 2407 §4.5.4), and
/// those must parse ([`stated_lifetime`]). `isakmpd`'s
/// `initiator_recv_HASH_SA_NONCE` leaves "Check that the chosen transform
/// matches an offer" as a comment, so this is stricter than that reference on
/// purpose.
fn check_answer(offered: &SaPayload, ps: &[Payload]) -> Result<u32, IkeError> {
    let refuse = |why: &str| {
        ike_debug!("Quick Mode: the answered SA is not the one offered: {why}");
        IkeError::NoProposalChosen
    };
    let answer = single_sa(ps).map_err(|e| {
        ike_debug!("Quick Mode: no single SA payload in the answer: {e}");
        e
    })?;
    if answer.doi != offered.doi || answer.situation != offered.situation {
        return Err(refuse("DOI or situation differ"));
    }
    let ([answered_p], [offered_p]) = (answer.proposals.as_slice(), offered.proposals.as_slice()) else {
        return Err(refuse("not exactly one proposal"));
    };
    if answered_p.num != offered_p.num || answered_p.protocol_id != offered_p.protocol_id {
        return Err(refuse("Proposal # or protocol differ"));
    }
    let Ok(spi) = <[u8; 4]>::try_from(answered_p.spi.as_slice()) else {
        return Err(refuse("the ESP SPI is not four octets"));
    };
    let ([answered_t], [offered_t]) = (answered_p.transforms.as_slice(), offered_p.transforms.as_slice()) else {
        return Err(refuse("not exactly one transform"));
    };
    if answered_t.num != offered_t.num {
        return Err(refuse("Transform # differs"));
    }
    if !answered_t.matches_offer(offered_t, &LIFETIME_ATTRS) {
        return Err(refuse(&format!("transform {:?} (id {}) against the offered {:?} (id {})", answered_t.attributes, answered_t.transform_id, offered_t.attributes, offered_t.transform_id)));
    }
    stated_lifetime(answered_t)?;
    Ok(u32::from_be_bytes(spi))
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
    enc_block: usize,
    cky_i: [u8; 8],
    cky_r: [u8; 8],
    msgid: u32,
    local_spi: u32,
    ni: Vec<u8>,
    iv1: Vec<u8>,
    /// The SA payload we sent -- the one proposal, one transform that message
    /// 2's answer is checked against ([`check_answer`]).
    offer: SaPayload,
    /// The ESP cipher we offered -- see `esp_sa`'s doc. A successful
    /// `complete()` implies the peer accepted this exact (sole) proposal (see
    /// `offer`), so this is trusted directly rather than re-parsed from the
    /// response, the same precedent `pfs` below already follows.
    cipher: SkCipher,
    /// Our ephemeral PFS share, if PFS was requested: the DH group plus our
    /// private key, needed once the response's KE payload arrives.
    pfs: Option<(DhGroup, [u8; 32])>,
    /// The ESP SA lifetime we offered -- needed by [`QuickInitiator::complete`]
    /// to read back what the responder actually negotiated (RFC 2407 §4.5;
    /// see `negotiated_p2_lifetime`'s doc).
    life_duration: u32,
    /// The IDci/IDcr payload bodies we offered -- [`QuickInitiator::complete`]
    /// checks the responder echoed exactly these back (RFC 2409 §5.5: when
    /// the initiator sends client identities, the responder's message 2
    /// carries them too). An authentic HASH(2) only proves the response
    /// wasn't tampered with, not that it actually named what we offered.
    id_local: Vec<u8>,
    id_remote: Vec<u8>,
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

    let iv0 = crypto1::phase2_iv(st.prf, &st.phase1_iv, msgid, st.enc_block);
    let offer = esp_sa(local_spi, cipher, pfs_group, st.floated, life_duration);
    let mut after = vec![(payload::SA, offer.to_bytes()), (payload::NONCE, ni.clone())];
    if let Some((group, dh_private)) = &pfs {
        after.push((payload::KE, group.public(dh_private)));
    }
    after.push((payload::ID, id_local.clone()));
    after.push((payload::ID, id_remote.clone()));
    let (msg1, iv1) = phase2::build_encrypted(qm_header(st.cky_i, st.cky_r, msgid), st.prf, &st.skeyid_a, &st.enc_key, st.enc_block, &iv0, &after)?;
    Ok((msg1, QuickInitiator {
        prf: st.prf,
        skeyid_a: st.skeyid_a.clone(),
        skeyid_d: st.skeyid_d.clone(),
        enc_key: st.enc_key.clone(),
        enc_block: st.enc_block,
        cky_i: st.cky_i,
        cky_r: st.cky_r,
        msgid,
        local_spi,
        ni,
        iv1,
        offer,
        cipher,
        pfs,
        life_duration,
        id_local,
        id_remote,
    }))
}

impl QuickInitiator {
    /// Process message 2 (`HASH(2), SA, Nr, [KE]`): verify `HASH(2)`, and
    /// return message 3 (`HASH(3)`), the established ESP CHILD SA, and the
    /// actually-negotiated lifetime (RFC 2407 §4.5 -- see
    /// `negotiated_p2_lifetime`'s doc).
    pub fn complete(self, msg2: &[u8]) -> Result<(Vec<u8>, ChildSa, u32), IkeError> {
        self.complete_with_lifetime(msg2).map(|(msg3, child, lifetime)| (msg3, child, lifetime.seconds))
    }

    /// [`Self::complete`], with the whole negotiated lifetime -- the seconds and
    /// the volume limit, when the answer stated one -- instead of the seconds
    /// alone.
    pub fn complete_with_lifetime(self, msg2: &[u8]) -> Result<(Vec<u8>, ChildSa, SaLifetime), IkeError> {
        let (_hdr, ps, iv2) = phase2::decrypt_payloads(msg2, &self.enc_key, self.enc_block, &self.iv1)?;
        let nr = find(&ps, payload::NONCE).ok_or(IkeError::MissingPayload("NONCE"))?.data.clone();
        isakmp::check_nonce_len(&nr)?;

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

        // An authentic HASH(2) only proves message 2 wasn't tampered with in
        // transit -- it doesn't prove the responder actually chose the one
        // ESP transform and traffic selectors we offered, rather than
        // something it merely also supports (see `id_local`'s doc, and
        // `ikev2::negotiate::ChosenSuite::matches_offer`'s identical
        // rationale on the IKEv2 side). `check_answer` compares the whole
        // SA -- cipher, PFS group, encapsulation mode and the rest -- with
        // the one sent.
        let peer_spi = check_answer(&self.offer, &ps)?;
        let peer_ids: Vec<Vec<u8>> = ps.iter().filter(|p| p.payload_type == payload::ID).map(|p| p.data.clone()).collect();
        if peer_ids.len() != 2 || peer_ids[0] != self.id_local || peer_ids[1] != self.id_remote {
            return Err(IkeError::NoProposalChosen);
        }

        let h3 = hash3(self.prf, &self.skeyid_a, self.msgid, &self.ni, &nr);
        let (msg3, _) = phase2::encrypt_payloads(qm_header(self.cky_i, self.cky_r, self.msgid), &self.enc_key, self.enc_block, &iv2, &[(payload::HASH, h3)])?;
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
#[derive(Clone)]
pub struct QuickResponder {
    prf: Prf,
    skeyid_a: Vec<u8>,
    skeyid_d: Vec<u8>,
    enc_key: Vec<u8>,
    enc_block: usize,
    msgid: u32,
    local_spi: u32,
    peer_spi: u32,
    ni: Vec<u8>,
    nr: Vec<u8>,
    iv2: Vec<u8>,
    /// The cipher of the transform this side selected from the initiator's
    /// offer (see [`select_offer`]) -- answered in message 2 rather than
    /// assuming a fixed cipher, so this responder (used only as `ryke`'s own
    /// client-testing double, see `ikev1::server::Server`) can interoperate
    /// with an initiator offering any cipher this module supports.
    cipher: SkCipher,
    /// The PFS shared secret, if the transform selected from the initiator's
    /// offer asked for PFS (see [`select_offer`]) -- computed here so
    /// [`Self::complete`] only needs to fold it into the KEYMAT once
    /// `HASH(3)` is verified.
    pfs_shared: Option<Vec<u8>>,
}

/// Process Quick-Mode message 1 (`HASH(1), SA, Ni, [KE]`) and build message 2
/// (`HASH(2), SA, Nr, [KE]`), choosing a fresh inbound ESP SPI. The SA of
/// message 2 is the one transform [`select_offer`] took from the offer -- its
/// Proposal #, Transform #, cipher and encapsulation mode as offered, with our
/// own lifetime and SPI; nothing acceptable in the offer is
/// [`IkeError::NoProposalChosen`]. PFS is automatic here (unlike the
/// initiator's explicit `_with_pfs` entry point): whenever the selected
/// transform names a GROUP DESCRIPTION, the responder generates its own
/// ephemeral share in that same group and answers in kind -- there's no
/// separate "did the responder want PFS" question, only "did the initiator ask
/// for it".
pub fn respond_quick(st: &Phase1State, msg1: &[u8], entropy: &mut impl Entropy) -> Result<(Vec<u8>, QuickResponder), IkeError> {
    let hdr = IsakmpHeader::parse(msg1)?;
    if hdr.exchange_type != exchange::QUICK {
        return Err(IkeError::Crypto("not a Quick Mode message"));
    }
    let msgid = hdr.message_id;
    if msgid == 0 {
        return Err(IkeError::Crypto("quick mode message_id must not be zero"));
    }
    let iv0 = crypto1::phase2_iv(st.prf, &st.phase1_iv, msgid, st.enc_block);
    let (_h, ps, iv1) = phase2::parse_encrypted(msg1, st.prf, &st.skeyid_a, &st.enc_key, st.enc_block, &iv0)?; // verifies HASH(1)
    let ni = find(&ps, payload::NONCE).ok_or(IkeError::MissingPayload("NONCE"))?.data.clone();
    isakmp::check_nonce_len(&ni)?;
    let Selection { proposal_num, transform_num, peer_spi, cipher, pfs_group, encap_mode, life_seconds } = select_offer(&ps)?;

    let mut spi_b = [0u8; 4];
    entropy.fill(&mut spi_b);
    let local_spi = u32::from_be_bytes(spi_b);
    let mut nr = vec![0u8; 16];
    entropy.fill(&mut nr);

    let answer = esp_sa_numbered(local_spi, proposal_num, transform_num, cipher, pfs_group, encap_mode, life_seconds);
    let mut after: Vec<(u8, Vec<u8>)> = vec![(payload::SA, answer.to_bytes()), (payload::NONCE, nr.clone())];
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
    let (msg2, iv2) = phase2::build_encrypted_prefixed(qm_header(st.cky_i, st.cky_r, msgid), st.prf, &st.skeyid_a, &st.enc_key, st.enc_block, &iv1, &ni, &after)?;
    Ok((msg2, QuickResponder {
        prf: st.prf,
        skeyid_a: st.skeyid_a.clone(),
        skeyid_d: st.skeyid_d.clone(),
        enc_key: st.enc_key.clone(),
        enc_block: st.enc_block,
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
        let (_hdr, ps, _iv) = phase2::decrypt_payloads(msg3, &self.enc_key, self.enc_block, &self.iv2)?;
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
///
/// Message 1 goes out up to three times, the same bytes each time, before the
/// rekey fails as timed out -- with the old CHILD SA left alone, no Delete sent.
/// `timeout` is the wait for each send on average: the waits grow (1 : 2 : 4,
/// RFC 2408 §5.1) and add up to three times `timeout`.
///
/// The lifetime returned is the seconds alone; [`rekey_child_with_lifetime`] is
/// this with the whole of what the exchange negotiated, a volume limit included.
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
    rekey_child_with_lifetime(sock, st, entropy, peer, cipher, pfs_group, ts_local, ts_remote, life_duration, timeout, old_local_spi)
        .map(|(child, lifetime)| (child, lifetime.seconds))
}

/// [`rekey_child`], returning the whole [`SaLifetime`] the exchange negotiated
/// for the new SA -- its seconds and the volume limit the answer stated, if any
/// -- for a caller that counts what the SA protects.
#[allow(clippy::too_many_arguments)]
pub fn rekey_child_with_lifetime(
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
) -> Result<(RekeyedChild, SaLifetime), DriverError> {
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
/// `st.floated`, `timeout` as for [`rekey_child`]), minus the trailing Delete: nothing is
/// being replaced. An error Notify from the peer (typically NO-PROPOSAL-CHOSEN /
/// INVALID-ID-INFORMATION when its Phase 2 has no IPv6 selector) comes back as
/// [`IkeError::PeerRejected`] straight away rather than after the
/// retransmissions; the IPv4 CHILD SA and the Phase-1 SA are unaffected
/// either way.
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
    create_child_ipv6_with_lifetime(sock, st, entropy, peer, cipher, pfs_group, ts_local, ts_remote, life_duration, timeout)
        .map(|(child, lifetime)| (child, lifetime.seconds))
}

/// [`create_child_ipv6`], returning the whole [`SaLifetime`] the exchange
/// negotiated (see [`rekey_child_with_lifetime`]).
#[allow(clippy::too_many_arguments)]
pub fn create_child_ipv6_with_lifetime(
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
) -> Result<(RekeyedChild, SaLifetime), DriverError> {
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
) -> Result<(RekeyedChild, SaLifetime), DriverError> {
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
    rekey_child_ipv6_with_lifetime(sock, st, entropy, peer, cipher, pfs_group, ts_local, ts_remote, life_duration, timeout, old_local_spi)
        .map(|(child, lifetime)| (child, lifetime.seconds))
}

/// [`rekey_child_ipv6`], returning the whole [`SaLifetime`] the exchange
/// negotiated (see [`rekey_child_with_lifetime`]).
#[allow(clippy::too_many_arguments)]
pub fn rekey_child_ipv6_with_lifetime(
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
) -> Result<(RekeyedChild, SaLifetime), DriverError> {
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

/// When `datagram` (already stripped of the non-ESP marker, if any) is, bit for
/// bit, a peer message that one of our final messages answered -- the peer
/// repeating its message 2 because our message 3 never reached it (RFC 2408
/// §3.1, Commit Bit NOTE) -- sends that final message again, untouched. Nothing
/// else moves: the retained bytes are sent as they were, so no IV or exchange
/// state advances for a retransmission (RFC 2409 §5). Any other datagram is left
/// to the caller, and so is a repeat, which it drops like any message that is
/// not the one it waits for (the repeat is another exchange's, by Message ID or
/// by exchange type).
pub(crate) fn resend_final_if_repeat(sock: &dyn IkeSocket, st: &Phase1State, peer: SocketAddr, datagram: &[u8]) {
    let Some(final_message) = st.finals.answer_to(datagram) else { return };
    ike_debug!("the peer repeated a message our final message answered -- sending that final message again ({} bytes) to {peer}", final_message.len());
    if let Err(e) = send_ike(sock, st, peer, &final_message) {
        ike_debug!("failed to send the final message again: {e}");
    }
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

/// How many times [`quick_exchange`] sends message 1: once, then again, the
/// identical bytes, each time the wait for message 2 runs out (RFC 2408 §5.1)
/// -- the same count `LivenessSession` uses for its IKEv2 requests. The waits
/// are `retransmit_waits(3 * timeout, ..)`: growing, and three `timeout`s in all.
const QUICK_MODE_ATTEMPTS: u32 = 3;

/// Drive one initiator Quick Mode exchange to completion over `sock`: send
/// `msg1`, wait for the matching message 2 -- resending `msg1` unchanged when
/// none comes, up to [`QUICK_MODE_ATTEMPTS`] sends in all, after waits that grow
/// and add up to that many `timeout`s -- answer with message 3, and hand back the derived CHILD SA's
/// SPIs/keys plus the negotiated lifetime. Datagrams that aren't this
/// exchange's message 2 are skipped -- except an error Notify from the peer
/// for this ISAKMP SA, which ends the wait at once as
/// [`IkeError::PeerRejected`], and a Delete of the ISAKMP SA
/// ([`IkeError::PeerTornDown`]).
///
/// Message 3 is sent once, since nothing answers it, and kept with the
/// message 2 it answers in [`Phase1State::finals`]: if it is lost, the
/// gateway's retransmitted message 2 arrives after this has returned, and the
/// next look at the socket that sees it ([`await_quick_reply`],
/// [`informational::peek`] / [`informational::probe`]) sends the same message 3
/// again ([`resend_final_if_repeat`]). Until then the gateway has no
/// established Quick Mode SA, and nothing here notices.
fn quick_exchange(
    sock: &dyn IkeSocket,
    st: &Phase1State,
    peer: SocketAddr,
    timeout: Duration,
    msg1: Vec<u8>,
    qi: QuickInitiator,
    what: &str,
) -> Result<(RekeyedChild, SaLifetime), DriverError> {
    let msgid = IsakmpHeader::parse(&msg1)?.message_id;
    let mut msg2 = None;
    for (i, wait) in retransmit_waits(timeout.saturating_mul(QUICK_MODE_ATTEMPTS), QUICK_MODE_ATTEMPTS).into_iter().enumerate() {
        let attempt = i + 1;
        if attempt == 1 {
            ike_debug!("Quick Mode ({what}): sending msg1 to {peer} (msgid={msgid:08x})");
        } else {
            ike_debug!("Quick Mode ({what}): no reply, retransmitting msg1 (attempt {attempt}/{QUICK_MODE_ATTEMPTS})");
        }
        send_ike(sock, st, peer, &msg1)?;
        msg2 = await_quick_reply(sock, st, peer, msgid, wait, what)?;
        if msg2.is_some() {
            break;
        }
    }
    let Some(msg2) = msg2 else {
        ike_debug!("Quick Mode ({what}): no reply to msgid={msgid:08x}, retransmissions included");
        return Err(IkeError::Crypto("Quick Mode: timed out waiting for the Quick Mode reply").into());
    };

    let (msg3, child, negotiated_lifetime) = qi.complete_with_lifetime(&msg2)?;
    st.finals.retain(&msg2, &msg3);
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
        "Quick Mode ({what}): complete -- spi_in={:08x} spi_out={:08x}, lifetime {}s{}",
        rekeyed.local_spi,
        rekeyed.peer_spi,
        negotiated_lifetime.seconds,
        negotiated_lifetime.kilobytes.map(|kb| format!(" / {kb} KB")).unwrap_or_default()
    );
    Ok((rekeyed, negotiated_lifetime))
}

/// Wait up to `timeout` for message 2 of the Quick Mode `msgid`, for
/// [`quick_exchange`]: `None` when none came in time. A peer message that an
/// earlier exchange's final message answered (a repeated message 2 of the last
/// rekey) gets that final message sent again on the way.
fn await_quick_reply(
    sock: &dyn IkeSocket,
    st: &Phase1State,
    peer: SocketAddr,
    msgid: u32,
    timeout: Duration,
    what: &str,
) -> Result<Option<Vec<u8>>, DriverError> {
    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; 8192];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(None);
        }
        sock.set_read_timeout(Some(remaining))?;
        let (n, from) = match sock.recv_from(&mut buf) {
            Ok(r) => r,
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => return Ok(None),
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
        resend_final_if_repeat(sock, st, peer, &msg);
        if let Some((notify_type, name)) = informational::peer_error_notify(st, &msg) {
            ike_debug!("Quick Mode ({what}): gateway rejected the proposal with {name} (notify type {notify_type})");
            return Err(IkeError::PeerRejected { notify_type, name }.into());
        }
        // A full-teardown Delete for the ISAKMP SA itself can legitimately
        // arrive while this exchange is in flight -- e.g. the peer tearing
        // down the whole tunnel sends the CHILD SA's Delete first (which is
        // what started this from-scratch recreate) and the ISAKMP SA's
        // Delete a moment later. Without this check it would just fail the
        // cookie/exchange-type/message-id match below and be silently
        // discarded like any other unrelated datagram, leaving the caller to
        // time out and retry against a peer that no longer has any Phase 1
        // SA to answer under -- confirmed live against a real FortiGate (see
        // `IkeError::PeerTornDown`'s doc).
        if informational::is_isakmp_sa_delete(st, &msg) {
            ike_debug!("Quick Mode ({what}): the peer deleted the ISAKMP SA while this exchange was in flight -- tunnel torn down");
            return Err(IkeError::PeerTornDown.into());
        }
        if hdr.init_cookie != st.cky_i || hdr.resp_cookie != st.cky_r || hdr.exchange_type != exchange::QUICK || hdr.message_id != msgid {
            continue;
        }
        return Ok(Some(msg));
    }
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

    /// Build a Quick-Mode message 2 the way [`respond_quick`] does, but let
    /// the caller substitute the SA and ID payloads actually sent instead of
    /// deriving them from the initiator's own message 1 -- simulating a
    /// responder that answers with an ESP transform or traffic selectors it
    /// was never offered. HASH(2) is still computed correctly over whatever
    /// is substituted, exactly as a genuinely different (or malicious) peer's
    /// authentic-but-unoffered answer would look.
    fn respond_quick_forging_answer(st: &Phase1State, msg1: &[u8], entropy: &mut impl Entropy, sa: &SaPayload, id_payloads: &[Vec<u8>]) -> Vec<u8> {
        forge_answer(st, msg1, entropy, &[sa], id_payloads)
    }

    /// [`respond_quick_forging_answer`] with any number of SA payloads (each
    /// sent as its own payload, in order) -- for the answers that carry more
    /// than the one SA payload a Quick Mode message 2 has.
    fn forge_answer(st: &Phase1State, msg1: &[u8], entropy: &mut impl Entropy, sas: &[&SaPayload], id_payloads: &[Vec<u8>]) -> Vec<u8> {
        let hdr = IsakmpHeader::parse(msg1).unwrap();
        let msgid = hdr.message_id;
        let iv0 = crypto1::phase2_iv(st.prf, &st.phase1_iv, msgid, st.enc_block);
        let (_h, ps, iv1) = phase2::parse_encrypted(msg1, st.prf, &st.skeyid_a, &st.enc_key, st.enc_block, &iv0).unwrap();
        let ni = find(&ps, payload::NONCE).unwrap().data.clone();
        let mut nr = vec![0u8; 16];
        entropy.fill(&mut nr);
        let mut after: Vec<(u8, Vec<u8>)> = sas.iter().map(|sa| (payload::SA, sa.to_bytes())).collect();
        after.push((payload::NONCE, nr));
        for id in id_payloads {
            after.push((payload::ID, id.clone()));
        }
        let (msg2, _iv2) = phase2::build_encrypted_prefixed(qm_header(st.cky_i, st.cky_r, msgid), st.prf, &st.skeyid_a, &st.enc_key, st.enc_block, &iv1, &ni, &after).unwrap();
        msg2
    }

    #[test]
    fn quick_mode_complete_rejects_a_cipher_the_initiator_never_offered() {
        // Finding #9 of the ChatGPT6 Astra ryke audit: `QuickInitiator::complete`
        // never checked message 2's actual ESP transform against what was
        // offered -- it just trusted `self.cipher` (its own proposal)
        // regardless of what the responder's SA payload actually named.
        let (istate, rstate, mut ie, mut re) = phase1_pair(0x1111, 0x2222, "10.1.1.1:500".parse().unwrap(), "192.168.0.1:500".parse().unwrap());
        let ts = ([10, 0, 99, 0], [255, 255, 255, 0]);
        let (qm1, qi) = initiate_quick(&istate, &mut ie, SkCipher::Aes256Gcm, ts, ts, 3600).unwrap();

        let forged_sa = esp_sa(0xAAAA_BBBB, SkCipher::Aes256Cbc(IntegAlgorithm::HmacSha2_256_128), None, rstate.floated, 3600);
        let id = ts_id(ts.0, ts.1);
        let msg2 = respond_quick_forging_answer(&rstate, &qm1, &mut re, &forged_sa, &[id.clone(), id]);

        match qi.complete(&msg2) {
            Err(IkeError::NoProposalChosen) => {}
            other => panic!("expected NoProposalChosen, got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn quick_mode_complete_rejects_traffic_selectors_the_initiator_never_offered() {
        // Same finding, the traffic-selector half: `QuickInitiator::complete`
        // never read the ID payloads (IDci/IDcr) back out of message 2 at
        // all, even though `respond_quick` (this crate's own responder) both
        // echoes them (RFC 2409 §5.5) and the peer offer they're checked
        // against here matches that same echo shape.
        let (istate, rstate, mut ie, mut re) = phase1_pair(0x3333, 0x4444, "10.1.1.1:500".parse().unwrap(), "192.168.0.1:500".parse().unwrap());
        let ts_local = ([10, 0, 99, 0], [255, 255, 255, 0]);
        let ts_remote = ([10, 0, 100, 0], [255, 255, 255, 0]);
        let (qm1, qi) = initiate_quick(&istate, &mut ie, SkCipher::Aes256Gcm, ts_local, ts_remote, 3600).unwrap();

        let sa = esp_sa(0xAAAA_BBBB, SkCipher::Aes256Gcm, None, rstate.floated, 3600);
        let wrong_remote = ts_id([0, 0, 0, 0], [0, 0, 0, 0]);
        let msg2 = respond_quick_forging_answer(&rstate, &qm1, &mut re, &sa, &[ts_id(ts_local.0, ts_local.1), wrong_remote]);

        match qi.complete(&msg2) {
            Err(IkeError::NoProposalChosen) => {}
            other => panic!("expected NoProposalChosen, got {:?}", other.map(|_| ())),
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
        assert_eq!(negotiated_p2_lifetime(&ps_with, 3600), SaLifetime { seconds: 900, kilobytes: None }, "must prefer the responder's own chosen value");

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
        assert_eq!(negotiated_p2_lifetime(&ps_without, 3600), SaLifetime { seconds: 3600, kilobytes: None }, "must fall back to the offered value when absent");

        assert_eq!(
            negotiated_p2_lifetime(&[], 3600),
            SaLifetime { seconds: 3600, kilobytes: None },
            "must fall back to the offered value when there's no SA payload at all"
        );
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
        let iv0 = crypto1::phase2_iv(rstate2.prf, &rstate2.phase1_iv, hdr.message_id, rstate2.enc_block);
        let (_h, ps, _iv) = phase2::parse_encrypted(&delete_bytes, rstate2.prf, &rstate2.skeyid_a, &rstate2.enc_key, rstate2.enc_block, &iv0).unwrap();
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
        let iv0 = crypto1::phase2_iv(rstate.prf, &rstate.phase1_iv, msgid, rstate.enc_block);
        let (_h, ps, _iv) = phase2::parse_encrypted(&qm1, rstate.prf, &rstate.skeyid_a, &rstate.enc_key, rstate.enc_block, &iv0).unwrap();
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
        let iv0 = crypto1::phase2_iv(rstate.prf, &rstate.phase1_iv, hdr.message_id, rstate.enc_block);
        let (_h, ps, _iv) = phase2::parse_encrypted(&delete, rstate.prf, &rstate.skeyid_a, &rstate.enc_key, rstate.enc_block, &iv0).unwrap();
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

    /// A real full-tunnel teardown: the gateway deletes the Quick Mode SA
    /// first (which is what starts a from-scratch recreate through
    /// `rekey_child` in the worker's `check_liveness_ikev1`) and the ISAKMP
    /// SA a moment later, which can race in while that recreate's own
    /// exchange is still waiting for its Quick Mode reply. Confirmed live
    /// against a real FortiGate that this used to be silently discarded as
    /// "not the message we're waiting for", leaving the recreate to time out
    /// and retry forever against a peer with no Phase 1 SA left at all --
    /// this must surface as `IkeError::PeerTornDown` instead, immediately.
    #[test]
    fn rekey_child_reports_peer_torn_down_when_the_isakmp_sa_is_deleted_mid_exchange() {
        let (isock, rsock, iaddr, raddr) = loopback_pair();
        let (istate, rstate, mut ie, mut re) = phase1_pair(0x9511, 0x9512, iaddr, raddr);
        let old_local_spi = 0x0bad_f00d;
        let responder = std::thread::spawn(move || {
            let mut buf = [0u8; 8192];
            rsock.recv(&mut buf).unwrap(); // the recreate's Quick Mode msg1
            let isakmp_delete = informational::build_isakmp_delete(&rstate, &mut re).unwrap();
            rsock.send_to(&isakmp_delete, iaddr).unwrap();
        });

        let ts = ([10, 212, 134, 202], [255, 255, 255, 255]);
        let err = rekey_child(&isock, &istate, &mut ie, raddr, SkCipher::Aes256Gcm, None, ts, ([0; 4], [0; 4]), 3600, Duration::from_secs(4), old_local_spi);
        responder.join().unwrap();
        assert!(matches!(err, Err(DriverError::Ike(IkeError::PeerTornDown))), "got {:?}", err.map(|_| ()));
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

    /// RFC 2408 §5.1: an unanswered message 1 is sent again, byte for byte.
    /// Here the gateway never gets the first one, and its answer to the second
    /// is lost; the third gets that same answer again -- what a responder does
    /// with a request it has already answered -- and the rekey completes as
    /// usual, trailing Delete included.
    #[test]
    fn a_quick_mode_rekey_whose_request_then_reply_is_lost_is_retransmitted_until_answered() {
        let (isock, rsock, iaddr, raddr) = loopback_pair();
        let (istate, rstate, mut ie, mut re) = phase1_pair(0x9a01, 0x9a02, iaddr, raddr);
        let old_local_spi = 0x0bad_beef;
        let responder = std::thread::spawn(move || {
            let mut buf = [0u8; 8192];
            let mut recv = || {
                let n = rsock.recv(&mut buf).unwrap();
                buf[..n].to_vec()
            };
            let first = recv(); // lost on its way
            let second = recv();
            let (msg2, qr) = respond_quick(&rstate, &second, &mut re).unwrap(); // lost on its way back
            let third = recv();
            rsock.send_to(&msg2, iaddr).unwrap();
            let child = qr.complete(&recv()).unwrap();
            let delete = recv();
            ([first, second, third], child, delete, rstate)
        });

        let ts = ([10, 212, 134, 202], [255, 255, 255, 255]);
        let (rekeyed, lifetime) =
            rekey_child(&isock, &istate, &mut ie, raddr, SkCipher::Aes256Gcm, None, ts, ([0; 4], [0; 4]), 1800, Duration::from_millis(300), old_local_spi)
                .unwrap();
        assert_eq!(lifetime, 1800);
        let (requests, mut rchild, delete, rstate) = responder.join().unwrap();
        assert!(requests.iter().all(|r| *r == requests[0]), "a retransmission must be the same bytes");

        let mut ours = EspSa::new_with_cipher(rekeyed.local_spi, rekeyed.key_in.cipher, &rekeyed.key_in.enc, &rekeyed.key_in.integ).unwrap();
        let pkt: Vec<u8> = (0..40u8).collect();
        let sealed = rchild.outbound.seal(&pkt, 4).unwrap();
        assert_eq!(ours.open(&sealed).unwrap(), (pkt, 4));

        let hdr = IsakmpHeader::parse(&delete).unwrap();
        let iv0 = crypto1::phase2_iv(rstate.prf, &rstate.phase1_iv, hdr.message_id, rstate.enc_block);
        let (_h, ps, _iv) = phase2::parse_encrypted(&delete, rstate.prf, &rstate.skeyid_a, &rstate.enc_key, rstate.enc_block, &iv0).unwrap();
        let del = ps.iter().find(|p| p.payload_type == payload::DELETE).unwrap();
        assert_eq!(informational::parse_delete(&del.data).unwrap(), (protocol::ESP, &old_local_spi.to_be_bytes()[..]));
    }

    /// A gateway that never answers gets message 1 three times, the same bytes
    /// each time, and then the rekey fails as timed out -- with no Delete for
    /// the old CHILD SA, which is still the one in use.
    #[test]
    fn a_quick_mode_rekey_never_answered_fails_after_three_attempts_and_deletes_nothing() {
        let (isock, rsock, iaddr, raddr) = loopback_pair();
        let (istate, _rstate, mut ie, _re) = phase1_pair(0x9b01, 0x9b02, iaddr, raddr);
        let ts = ([10, 212, 134, 202], [255, 255, 255, 255]);
        let timeout = Duration::from_millis(200);
        let started = Instant::now();
        let err = rekey_child(&isock, &istate, &mut ie, raddr, SkCipher::Aes256Gcm, None, ts, ([0; 4], [0; 4]), 3600, timeout, 0x0bad_beef);
        let elapsed = started.elapsed();
        assert!(matches!(err, Err(DriverError::Ike(IkeError::Crypto(m))) if m.contains("timed out")), "got {:?}", err.map(|_| ()));
        assert!(elapsed >= timeout * 3, "each attempt gets the whole timeout, took {elapsed:?}");

        rsock.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
        let mut buf = [0u8; 8192];
        let mut sent = Vec::new();
        while let Ok(n) = rsock.recv(&mut buf) {
            sent.push(buf[..n].to_vec());
        }
        assert_eq!(sent.len(), 3, "message 1 and two retransmissions, and no Delete");
        assert!(sent.iter().all(|m| *m == sent[0]), "a retransmission must be the same bytes");
        assert_eq!(IsakmpHeader::parse(&sent[0]).unwrap().exchange_type, exchange::QUICK);
    }

    /// RFC 2408 §5.1: the retransmissions of message 1 are separated by longer and
    /// longer intervals, not by a fixed timer, and the exchange is given up on
    /// after the same time a fixed timer of `timeout` per send would have taken:
    /// the caller's timeout policy for a gateway that is gone is unchanged.
    #[test]
    fn a_quick_mode_rekey_separates_its_retransmissions_by_longer_and_longer_intervals() {
        let (isock, rsock, iaddr, raddr) = loopback_pair();
        let (istate, _rstate, mut ie, _re) = phase1_pair(0x9b11, 0x9b12, iaddr, raddr);
        let ts = ([10, 212, 134, 202], [255, 255, 255, 255]);
        let timeout = Duration::from_millis(500);
        rsock.set_read_timeout(Some(timeout * 5)).unwrap();
        let recorder = std::thread::spawn(move || {
            let mut buf = [0u8; 8192];
            let mut times = Vec::new();
            while rsock.recv(&mut buf).is_ok() {
                times.push(Instant::now());
            }
            times
        });
        let started = Instant::now();
        let err = rekey_child(&isock, &istate, &mut ie, raddr, SkCipher::Aes256Gcm, None, ts, ([0; 4], [0; 4]), 3600, timeout, 0x0bad_beef);
        let elapsed = started.elapsed();
        assert!(matches!(err, Err(DriverError::Ike(IkeError::Crypto(m))) if m.contains("timed out")), "got {:?}", err.map(|_| ()));
        let times = recorder.join().unwrap();
        assert_eq!(times.len() as u32, QUICK_MODE_ATTEMPTS);
        let gaps: Vec<Duration> = times.windows(2).map(|w| w[1] - w[0]).collect();
        assert!(gaps.windows(2).all(|g| g[1] >= g[0] + Duration::from_millis(100)), "the waits between the sends were {gaps:?}");
        let budget = timeout * QUICK_MODE_ATTEMPTS;
        assert!(elapsed >= budget && elapsed < budget + Duration::from_millis(600), "gave up after {elapsed:?}, budget {budget:?}");
    }

    /// A `timeout` of nothing leaves no time to wait anywhere: message 1 still
    /// goes out three times, one after the other, and the rekey fails as timed out
    /// -- no panic, no Delete.
    #[test]
    fn a_quick_mode_rekey_with_a_zero_timeout_sends_three_times_at_once_and_fails_as_timed_out() {
        let (isock, rsock, iaddr, raddr) = loopback_pair();
        let (istate, _rstate, mut ie, _re) = phase1_pair(0x9b21, 0x9b22, iaddr, raddr);
        let ts = ([10, 212, 134, 202], [255, 255, 255, 255]);
        let started = Instant::now();
        let err = rekey_child(&isock, &istate, &mut ie, raddr, SkCipher::Aes256Gcm, None, ts, ([0; 4], [0; 4]), 3600, Duration::ZERO, 0x0bad_beef);
        let elapsed = started.elapsed();
        assert!(matches!(err, Err(DriverError::Ike(IkeError::Crypto(m))) if m.contains("timed out")), "got {:?}", err.map(|_| ()));
        assert!(elapsed < Duration::from_millis(500), "a zero timeout took {elapsed:?}");

        rsock.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
        let mut buf = [0u8; 8192];
        let mut sent = Vec::new();
        while let Ok(n) = rsock.recv(&mut buf) {
            sent.push(buf[..n].to_vec());
        }
        assert_eq!(sent.len() as u32, QUICK_MODE_ATTEMPTS, "message 1 and two retransmissions, and no Delete");
        assert!(sent.iter().all(|m| *m == sent[0]));
    }

    /// The largest `Duration` there is as the timeout: the waits are sevenths of
    /// it (`Duration::MAX` saturates the three-fold total), none of them overflows
    /// the clock, and a gateway that answers at once is still answered. The
    /// longest of the three waits, 4/7 of the largest `Duration`, would overflow
    /// `Instant` -- but only after the first two, some 8e18 seconds, had run out.
    #[test]
    fn a_quick_mode_rekey_with_the_largest_timeout_there_is_completes_when_answered() {
        let (isock, rsock, iaddr, raddr) = loopback_pair();
        let (istate, rstate, mut ie, re) = phase1_pair(0x9b31, 0x9b32, iaddr, raddr);
        let old_local_spi = 0x0bad_f00d;
        let responder = spawn_quick_responder(rsock, rstate, re, iaddr, true);
        let ts = ([10, 212, 134, 202], [255, 255, 255, 255]);
        let (_rekeyed, lifetime) =
            rekey_child(&isock, &istate, &mut ie, raddr, SkCipher::Aes256Gcm, None, ts, ([0; 4], [0; 4]), 1800, Duration::MAX, old_local_spi).unwrap();
        assert_eq!(lifetime, 1800);
        responder.join().unwrap();
    }

    /// However many datagrams for some other exchange reach the socket, the
    /// retransmissions leave when their waits say, and the rekey is given up on
    /// when the timeouts say: what arrives cannot lengthen a wait, and reading it
    /// cannot keep the next send from going out.
    #[test]
    fn a_quick_mode_rekey_keeps_its_schedule_however_many_stray_datagrams_arrive() {
        let (isock, rsock, iaddr, raddr) = loopback_pair();
        let (istate, _rstate, mut ie, _re) = phase1_pair(0x9b41, 0x9b42, iaddr, raddr);
        let ts = ([10, 212, 134, 202], [255, 255, 255, 255]);
        let timeout = Duration::from_millis(400);
        rsock.set_read_timeout(Some(timeout * 5)).unwrap();
        let recorder = std::thread::spawn(move || {
            let mut buf = [0u8; 8192];
            let mut times = Vec::new();
            while rsock.recv(&mut buf).is_ok() {
                times.push(Instant::now());
            }
            times
        });
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = stop.clone();
        let flood = std::thread::spawn(move || {
            let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
            let stray =
                IsakmpHeader { init_cookie: [0x11; 8], resp_cookie: [0x22; 8], next_payload: 0, version: 0x10, exchange_type: exchange::QUICK, flags: 0, message_id: 7, length: 28 }
                    .to_bytes();
            let end = Instant::now() + Duration::from_secs(3);
            while !flag.load(std::sync::atomic::Ordering::Relaxed) && Instant::now() < end {
                let _ = sender.send_to(&stray, iaddr);
            }
        });

        let started = Instant::now();
        let err = rekey_child(&isock, &istate, &mut ie, raddr, SkCipher::Aes256Gcm, None, ts, ([0; 4], [0; 4]), 3600, timeout, 0x0bad_beef);
        let elapsed = started.elapsed();
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        flood.join().unwrap();
        assert!(matches!(err, Err(DriverError::Ike(IkeError::Crypto(m))) if m.contains("timed out")), "got {:?}", err.map(|_| ()));
        let times = recorder.join().unwrap();
        assert_eq!(times.len() as u32, QUICK_MODE_ATTEMPTS);
        let gaps: Vec<Duration> = times.windows(2).map(|w| w[1] - w[0]).collect();
        assert!(gaps.windows(2).all(|g| g[1] >= g[0] + Duration::from_millis(100)), "the waits between the sends were {gaps:?}");
        let budget = timeout * QUICK_MODE_ATTEMPTS;
        assert!(elapsed >= budget && elapsed < budget + Duration::from_millis(600), "gave up after {elapsed:?}, budget {budget:?}");
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

    // ---- What a Quick Mode answer / offer must look like (RFC 2408 §4.2, RFC 2407 §4.5) ----

    const QM_TS: ([u8; 4], [u8; 4]) = ([10, 0, 99, 0], [255, 255, 255, 0]);
    const QM_ADDRS: (&str, &str) = ("10.1.1.1:500", "192.168.0.1:500");

    /// The first proposal's first transform -- the one `esp_sa` builds.
    fn xf(sa: &mut SaPayload) -> &mut Transform {
        &mut sa.proposals[0].transforms[0]
    }

    /// Replace the ENCAP_MODE attribute (`None` = leave it out).
    fn set_encap(sa: &mut SaPayload, mode: Option<u16>) {
        let t = xf(sa);
        t.attributes.retain(|a| a.attr_type != esp_attr::ENCAP_MODE);
        if let Some(m) = mode {
            t.attributes.push(Attribute::short(esp_attr::ENCAP_MODE, m));
        }
    }

    /// Replace every lifetime attribute with `attrs`, in that order.
    fn set_life(sa: &mut SaPayload, attrs: Vec<Attribute>) {
        let t = xf(sa);
        t.attributes.retain(|a| a.attr_type != esp_attr::LIFE_TYPE && a.attr_type != esp_attr::LIFE_DURATION);
        t.attributes.extend(attrs);
    }

    fn life_type(kind: u16) -> Attribute {
        Attribute::short(esp_attr::LIFE_TYPE, kind)
    }

    fn life_dur(v: u32) -> Attribute {
        Attribute::long_u32(esp_attr::LIFE_DURATION, v)
    }

    /// Fail, naming every case, unless each answer was refused with an error
    /// `want` accepts.
    fn assert_all_refused(cases: Vec<(&'static str, Result<u32, IkeError>)>, want: impl Fn(&IkeError) -> bool) {
        let bad: Vec<String> = cases
            .into_iter()
            .filter_map(|(name, r)| match r {
                Err(e) if want(&e) => None,
                other => Some(format!("  {name}: {other:?}")),
            })
            .collect();
        assert!(bad.is_empty(), "these were not refused as they must be:\n{}", bad.join("\n"));
    }

    fn no_proposal(e: &IkeError) -> bool {
        matches!(e, IkeError::NoProposalChosen)
    }

    fn malformed(e: &IkeError) -> bool {
        matches!(e, IkeError::MalformedPayload(_))
    }

    /// What an initiator is left with by [`initiator_holdings_sas`]: the payloads
    /// of its message 3, its CHILD SA, and the lifetime it negotiated.
    type InitiatorHoldings = (Vec<(u8, Vec<u8>)>, ChildSa, SaLifetime);

    /// The initiator's half of a Quick Mode against an authentic message 2
    /// carrying `sas` -- by default the one SA `esp_sa` builds for exactly
    /// what was offered (`offered_life` seconds, NAT-T `floated` or not), which
    /// `edit` may then alter. Yields the negotiated lifetime.
    fn initiator_answer_sas(floated: bool, offered_life: u32, edit: impl FnOnce(&mut Vec<SaPayload>)) -> Result<u32, IkeError> {
        initiator_holdings_sas(floated, offered_life, edit).map(|(_msg3, _child, life)| life.seconds)
    }

    /// [`initiator_answer_sas`], yielding everything the initiator is left with:
    /// the payloads of its message 3 (read back, for the wire bytes of a CBC
    /// message follow from the ciphertext of message 2 and so from its every
    /// byte), the CHILD SA and the lifetime. The entropy is fixed, so two runs
    /// differ only by the answer.
    fn initiator_holdings_sas(floated: bool, offered_life: u32, edit: impl FnOnce(&mut Vec<SaPayload>)) -> Result<InitiatorHoldings, IkeError> {
        let (mut istate, mut rstate, mut ie, mut re) = phase1_pair(0x5101, 0x5102, QM_ADDRS.0.parse().unwrap(), QM_ADDRS.1.parse().unwrap());
        istate.floated = floated;
        rstate.floated = floated;
        let (qm1, qi) = initiate_quick(&istate, &mut ie, SkCipher::Aes256Gcm, QM_TS, QM_TS, offered_life).unwrap();
        let mut sas = vec![esp_sa(0xAAAA_BBBB, SkCipher::Aes256Gcm, None, floated, offered_life)];
        edit(&mut sas);
        let refs: Vec<&SaPayload> = sas.iter().collect();
        let id = ts_id(QM_TS.0, QM_TS.1);
        let msg2 = forge_answer(&rstate, &qm1, &mut re, &refs, &[id.clone(), id]);
        let (msg3, child, life) = qi.complete_with_lifetime(&msg2)?;
        let iv0 = crypto1::phase2_iv(rstate.prf, &rstate.phase1_iv, IsakmpHeader::parse(&qm1).unwrap().message_id, rstate.enc_block);
        let (_h, _ps, iv1) = phase2::parse_encrypted(&qm1, rstate.prf, &rstate.skeyid_a, &rstate.enc_key, rstate.enc_block, &iv0).unwrap();
        let (_h, _ps, iv2) = phase2::decrypt_payloads(&msg2, &rstate.enc_key, rstate.enc_block, &iv1).unwrap();
        let (_h, ps3, _iv) = phase2::decrypt_payloads(&msg3, &rstate.enc_key, rstate.enc_block, &iv2).unwrap();
        Ok((ps3.into_iter().map(|p| (p.payload_type, p.data)).collect(), child, life))
    }

    fn initiator_holdings(offered_life: u32, edit: impl FnOnce(&mut SaPayload)) -> Result<InitiatorHoldings, IkeError> {
        initiator_holdings_sas(false, offered_life, |sas| edit(&mut sas[0]))
    }

    /// Both SAs of `child` as far as this crate lets anyone read them -- SPI,
    /// cipher, keys -- as text.
    fn child_fields(child: &ChildSa) -> Vec<String> {
        [&child.outbound, &child.inbound]
            .iter()
            .map(|sa| format!("spi {:08x}, {:?}, enc {:02x?}, integ {:02x?}", sa.spi(), sa.cipher(), sa.enc_material(), sa.integ_key()))
            .collect()
    }

    fn initiator_answer(floated: bool, offered_life: u32, edit: impl FnOnce(&mut SaPayload)) -> Result<u32, IkeError> {
        initiator_answer_sas(floated, offered_life, |sas| edit(&mut sas[0]))
    }

    /// RFC 2408 §4.2: "The initiator MUST verify that the Security Association
    /// payload received from the responder matches one of the proposals sent
    /// initially" -- and RFC 2407 §4.5 makes ENCAP_MODE one of the attributes
    /// that proposal is made of. An authentic answer selecting TRANSPORT (or
    /// the UDP-encapsulated flavour we didn't ask for, or no mode at all --
    /// "host-dependent", §4.5) for a TUNNEL offer used to be accepted.
    #[test]
    fn quick_mode_initiator_refuses_an_answer_with_another_encapsulation_mode() {
        let mut cases = Vec::new();
        for (name, mode) in [
            ("TRANSPORT answered to a TUNNEL offer", Some(2)),
            ("UDP-Encapsulated-Tunnel answered to a plain TUNNEL offer", Some(3)),
            ("UDP-Encapsulated-Transport answered to a TUNNEL offer", Some(4)),
            ("reserved mode 0", Some(0)),
            ("private-range mode 61443", Some(61443)),
            ("no ENCAP_MODE at all", None),
        ] {
            cases.push((name, initiator_answer(false, 3600, |sa| set_encap(sa, mode))));
        }
        // NAT-T (RFC 3947 §5.1): we offered UDP-Encapsulated-Tunnel.
        for (name, mode) in [
            ("plain TUNNEL answered to a UDP-Encapsulated-Tunnel offer", Some(1)),
            ("TRANSPORT answered to a UDP-Encapsulated-Tunnel offer", Some(2)),
            ("UDP-Encapsulated-Transport answered to a UDP-Encapsulated-Tunnel offer", Some(4)),
            ("no ENCAP_MODE at all, NAT-T", None),
        ] {
            cases.push((name, initiator_answer(true, 3600, |sa| set_encap(sa, mode))));
        }
        assert_all_refused(cases, no_proposal);
    }

    /// The positive controls of the test above: the answer that echoes the
    /// mode offered is accepted, plain and NAT-T.
    #[test]
    fn quick_mode_initiator_accepts_the_encapsulation_mode_it_offered() {
        assert_eq!(initiator_answer(false, 3600, |_| {}).unwrap(), 3600);
        assert_eq!(initiator_answer(true, 3600, |_| {}).unwrap(), 3600);
        // ...whatever order the responder lists the attributes in (a Life
        // Duration still right after its Life Type).
        assert_eq!(initiator_answer(false, 3600, |sa| xf(sa).attributes.rotate_left(1)).unwrap(), 3600);
        assert_eq!(initiator_answer(false, 3600, |sa| xf(sa).attributes.rotate_left(3)).unwrap(), 3600);
    }

    /// The rest of the transform: RFC 2407 §4.5 says KEY_LENGTH "must be
    /// specified" for a variable-length cipher and AUTH_ALGORITHM "MUST NOT"
    /// be for ESP without authentication; §4.5.3 aborts on an attribute or
    /// value that isn't understood. An answer that drops KEY_LENGTH (which
    /// `peer_esp_cipher` silently defaults to the very 256 we offered), adds an
    /// attribute we never offered, or repeats one with another value is not the
    /// transform we sent.
    #[test]
    fn quick_mode_initiator_refuses_an_answer_whose_attributes_differ_from_the_offer() {
        let cases = vec![
            ("KEY_LENGTH left out", initiator_answer(false, 3600, |sa| xf(sa).attributes.retain(|a| a.attr_type != esp_attr::KEY_LENGTH))),
            ("KEY_LENGTH changed", initiator_answer(false, 3600, |sa| {
                let t = xf(sa);
                t.attributes.retain(|a| a.attr_type != esp_attr::KEY_LENGTH);
                t.attributes.push(Attribute::short(esp_attr::KEY_LENGTH, 128));
            })),
            ("an AUTH_ALGORITHM on an AEAD transform", initiator_answer(false, 3600, |sa| xf(sa).attributes.push(Attribute::short(esp_attr::AUTH_ALGORITHM, 5)))),
            ("Key Rounds (7), defined but never offered", initiator_answer(false, 3600, |sa| xf(sa).attributes.push(Attribute::short(7, 1)))),
            ("a private-use attribute", initiator_answer(false, 3600, |sa| xf(sa).attributes.push(Attribute::short(0x7ffe, 1)))),
            ("a GROUP_DESC we never offered", initiator_answer(false, 3600, |sa| xf(sa).attributes.push(Attribute::short(esp_attr::GROUP_DESC, 2)))),
            ("a second, conflicting ENCAP_MODE", initiator_answer(false, 3600, |sa| xf(sa).attributes.push(Attribute::short(esp_attr::ENCAP_MODE, 2)))),
            ("ENCAP_MODE sent as a variable-length attribute (basic attributes MUST NOT)", initiator_answer(false, 3600, |sa| {
                set_encap(sa, None);
                xf(sa).attributes.push(Attribute::long_bytes(esp_attr::ENCAP_MODE, vec![0, 1]));
            })),
        ];
        assert_all_refused(cases, no_proposal);
    }

    /// RFC 2408 §4.2: the answer is one Proposal with one Transform (the
    /// receiver "MUST select a single transform for each protocol"), the ones
    /// we offered (Proposal # and Transform # are retained), in the IPsec DOI
    /// and for ESP -- the protocol we asked about. RFC 2409 §5.5: one SA
    /// payload.
    #[test]
    fn quick_mode_initiator_refuses_an_answer_with_the_wrong_shape() {
        // The control for the whole list: the very same builder, unedited.
        assert!(initiator_answer(false, 3600, |_| {}).is_ok());
        let cases: Vec<(&'static str, Result<u32, IkeError>)> = vec![
            ("DOI 0", initiator_answer(false, 3600, |sa| sa.doi = 0)),
            ("DOI 2", initiator_answer(false, 3600, |sa| sa.doi = 2)),
            ("situation SIT_SECRECY", initiator_answer(false, 3600, |sa| sa.situation = 2)),
            ("proposal for AH", initiator_answer(false, 3600, |sa| sa.proposals[0].protocol_id = 2)),
            ("proposal for ISAKMP", initiator_answer(false, 3600, |sa| sa.proposals[0].protocol_id = protocol::ISAKMP)),
            ("proposal for IPCOMP", initiator_answer(false, 3600, |sa| sa.proposals[0].protocol_id = 4)),
            ("another Proposal #", initiator_answer(false, 3600, |sa| sa.proposals[0].num = 2)),
            ("another Transform #", initiator_answer(false, 3600, |sa| xf(sa).num = 2)),
            ("a second proposal", initiator_answer(false, 3600, |sa| {
                let mut second = sa.proposals[0].clone();
                second.num = 2;
                sa.proposals.push(second);
            })),
            ("a second transform", initiator_answer(false, 3600, |sa| {
                let mut second = xf(sa).clone();
                second.num = 2;
                sa.proposals[0].transforms.push(second);
            })),
            ("an 8-byte SPI", initiator_answer(false, 3600, |sa| sa.proposals[0].spi = vec![1; 8])),
            ("an empty SPI", initiator_answer(false, 3600, |sa| sa.proposals[0].spi = Vec::new())),
            ("two SA payloads", initiator_answer_sas(false, 3600, |sas| {
                let second = sas[0].clone();
                sas.push(second);
            })),
        ];
        assert_all_refused(cases, no_proposal);
    }

    /// RFC 2407 §4.5: "SA Life Duration MUST always follow an SA Life Type
    /// which describes the units"; §4.5.2: a list may carry several
    /// Type/Duration pairs (100 MB *or* 24 h), which MUST be parsed; default
    /// 28800 seconds; §4.5.4: a responder may shorten the lifetime, never
    /// lengthen it. What we use for the rekey schedule is the *seconds* pair --
    /// a kilobytes duration read as seconds (as `negotiated_p2_lifetime` did:
    /// first LIFE_DURATION, whatever its Type) is an SA that "lives" 4.6
    /// million seconds.
    #[test]
    fn quick_mode_initiator_reads_the_lifetime_in_its_own_units() {
        let ok = |offered: u32, attrs: Vec<Attribute>| initiator_answer(false, offered, |sa| set_life(sa, attrs)).unwrap();
        // A shorter lifetime is the responder's to impose.
        assert_eq!(ok(3600, vec![life_type(1), life_dur(900)]), 900);
        // Kilobytes only: no time limit was stated, the offered one applies.
        assert_eq!(ok(3600, vec![life_type(2), life_dur(4_608_000)]), 3600);
        // Both pairs, in either order (the §4.5.2 example has seconds first).
        assert_eq!(ok(3600, vec![life_type(1), life_dur(900), life_type(2), life_dur(100_000)]), 900);
        assert_eq!(ok(3600, vec![life_type(2), life_dur(100_000), life_type(1), life_dur(900)]), 900);
        // Never longer than what we offered.
        assert_eq!(ok(3600, vec![life_type(1), life_dur(86_400)]), 3600);
        // No lifetime at all: the DOI default, 28800 s, capped by our offer.
        assert_eq!(ok(3600, vec![]), 3600);
        assert_eq!(ok(86_400, vec![]), 28_800);
        // The Duration is variable-length: two octets in the basic form, two
        // in the long one, four as we send it.
        assert_eq!(ok(3600, vec![life_type(1), Attribute::short(esp_attr::LIFE_DURATION, 900)]), 900);
        assert_eq!(ok(3600, vec![life_type(1), Attribute::long_bytes(esp_attr::LIFE_DURATION, vec![0x03, 0x84])]), 900);
        assert_eq!(ok(3600, vec![life_type(1), Attribute::long_bytes(esp_attr::LIFE_DURATION, vec![0, 0, 0x03, 0x84])]), 900);
        // The same pair twice does not conflict.
        assert_eq!(ok(3600, vec![life_type(1), life_dur(900), life_type(1), life_dur(900)]), 900);
    }

    /// RFC 2407 §4.5 / §4.5.2 / §4.5.3: a Duration with no Type before it, a
    /// Type with no Duration after it, two different values for the same
    /// unit, a Type we don't define, and an unusable (zero or absurdly wide)
    /// duration all abort the negotiation rather than being read by luck.
    #[test]
    fn quick_mode_initiator_refuses_a_malformed_lifetime() {
        let with = |attrs: Vec<Attribute>| initiator_answer(false, 3600, |sa| set_life(sa, attrs));
        let cases = vec![
            ("a Duration with no Type before it", with(vec![life_dur(900)])),
            ("a Type with no Duration after it", with(vec![life_type(1)])),
            ("two Types in a row", with(vec![life_type(1), life_type(2), life_dur(900)])),
            ("a Duration after some other attribute", initiator_answer(false, 3600, |sa| {
                set_life(sa, vec![life_type(1)]);
                let key_length = xf(sa).attributes.iter().find(|a| a.attr_type == esp_attr::KEY_LENGTH).unwrap().clone();
                xf(sa).attributes.push(key_length);
                xf(sa).attributes.push(life_dur(900));
            })),
            ("two different seconds durations", with(vec![life_type(1), life_dur(900), life_type(1), life_dur(1800)])),
            ("two different kilobytes durations", with(vec![life_type(2), life_dur(100), life_type(2), life_dur(200)])),
            ("a zero-second lifetime", with(vec![life_type(1), life_dur(0)])),
            ("Life Type 3, reserved", with(vec![life_type(3), life_dur(900)])),
            ("Life Type 0, reserved", with(vec![life_type(0), life_dur(900)])),
            ("Life Type as a variable-length attribute", with(vec![Attribute::long_bytes(esp_attr::LIFE_TYPE, vec![0, 1]), life_dur(900)])),
            ("an empty Duration", with(vec![life_type(1), Attribute::long_bytes(esp_attr::LIFE_DURATION, Vec::new())])),
            ("a nine-octet Duration", with(vec![life_type(1), Attribute::long_bytes(esp_attr::LIFE_DURATION, vec![0; 9])])),
        ];
        assert_all_refused(cases, malformed);
    }

    /// A Quick Mode message 1 as `st`'s initiator would send it -- HASH(1),
    /// then one SA payload per entry of `sas` exactly as given, Ni, IDci,
    /// IDcr -- for the offers `initiate_quick` never makes itself.
    fn craft_msg1(st: &Phase1State, sas: &[&SaPayload]) -> Vec<u8> {
        let msgid = 0x0BAD_F00D;
        let iv0 = crypto1::phase2_iv(st.prf, &st.phase1_iv, msgid, st.enc_block);
        let id = ts_id(QM_TS.0, QM_TS.1);
        let mut after: Vec<(u8, Vec<u8>)> = sas.iter().map(|sa| (payload::SA, sa.to_bytes())).collect();
        after.push((payload::NONCE, vec![7u8; 16]));
        after.push((payload::ID, id.clone()));
        after.push((payload::ID, id));
        phase2::build_encrypted(qm_header(st.cky_i, st.cky_r, msgid), st.prf, &st.skeyid_a, &st.enc_key, st.enc_block, &iv0, &after).unwrap().0
    }

    /// Hand `sas` to a responder (NAT-T `floated` or not) as message 1 and
    /// read the SA payload out of its message 2.
    fn responder_answer(floated: bool, sas: &[SaPayload]) -> Result<SaPayload, IkeError> {
        let (mut istate, mut rstate, _ie, mut re) = phase1_pair(0x5201, 0x5202, QM_ADDRS.0.parse().unwrap(), QM_ADDRS.1.parse().unwrap());
        istate.floated = floated;
        rstate.floated = floated;
        let refs: Vec<&SaPayload> = sas.iter().collect();
        let msg1 = craft_msg1(&istate, &refs);
        let (msg2, _qr) = respond_quick(&rstate, &msg1, &mut re)?;
        let hdr = IsakmpHeader::parse(&msg1).unwrap();
        let iv0 = crypto1::phase2_iv(rstate.prf, &rstate.phase1_iv, hdr.message_id, rstate.enc_block);
        let (_h, _ps, iv1) = phase2::parse_encrypted(&msg1, rstate.prf, &rstate.skeyid_a, &rstate.enc_key, rstate.enc_block, &iv0).unwrap();
        let (_h, ps, _iv2) = phase2::decrypt_payloads(&msg2, &rstate.enc_key, rstate.enc_block, &iv1).unwrap();
        Ok(SaPayload::parse(&find(&ps, payload::SA).unwrap().data).unwrap())
    }

    /// An honest ESP offer with the given ENCAP_MODE and lifetime pairs.
    fn offer(edit: impl FnOnce(&mut SaPayload)) -> SaPayload {
        let mut sa = esp_sa(0x1111_2222, SkCipher::Aes256Gcm, None, false, 3600);
        edit(&mut sa);
        sa
    }

    fn responder_refuses(cases: Vec<(&'static str, Result<SaPayload, IkeError>)>) {
        let bad: Vec<String> = cases
            .into_iter()
            .filter_map(|(name, r)| match r {
                Err(IkeError::NoProposalChosen) => None,
                other => Some(format!("  {name}: {:?}", other.map(|sa| sa.proposals))),
            })
            .collect();
        assert!(bad.is_empty(), "these offers were not refused as they must be:\n{}", bad.join("\n"));
    }

    /// The responder counterpart: it only ever builds tunnel-mode SAs, so an
    /// offer whose every transform asks for TRANSPORT, an unknown mode or no
    /// mode (RFC 2407 §4.5: "host-dependent"), in a DOI, situation or
    /// protocol it isn't speaking, or with an attribute or value it doesn't
    /// know (§4.5.3), is answered NO-PROPOSAL-CHOSEN -- not with a tunnel it
    /// was never asked for.
    #[test]
    fn quick_mode_responder_refuses_an_offer_it_cannot_honour() {
        let mut cases: Vec<(&'static str, Result<SaPayload, IkeError>)> = Vec::new();
        for (name, mode) in [
            ("TRANSPORT only", Some(2)),
            ("UDP-Encapsulated-Transport only", Some(4)),
            ("an unknown mode", Some(9)),
            ("no ENCAP_MODE", None),
        ] {
            cases.push((name, responder_answer(false, &[offer(|sa| set_encap(sa, mode))])));
        }
        cases.push(("DOI 0", responder_answer(false, &[offer(|sa| sa.doi = 0)])));
        cases.push(("situation SIT_SECRECY", responder_answer(false, &[offer(|sa| sa.situation = 2)])));
        cases.push(("AH only", responder_answer(false, &[offer(|sa| sa.proposals[0].protocol_id = 2)])));
        cases.push(("IPCOMP only", responder_answer(false, &[offer(|sa| sa.proposals[0].protocol_id = 4)])));
        cases.push(("an attribute it doesn't know", responder_answer(false, &[offer(|sa| xf(sa).attributes.push(Attribute::short(7, 1)))])));
        cases.push(("a PFS group it doesn't know", responder_answer(false, &[offer(|sa| xf(sa).attributes.push(Attribute::short(esp_attr::GROUP_DESC, 99)))])));
        cases.push(("a cipher it doesn't know", responder_answer(false, &[offer(|sa| xf(sa).transform_id = 200)])));
        cases.push(("an 8-byte SPI", responder_answer(false, &[offer(|sa| sa.proposals[0].spi = vec![1u8; 8])])));
        cases.push(("an empty SPI", responder_answer(false, &[offer(|sa| sa.proposals[0].spi = Vec::new())])));
        cases.push(("a malformed lifetime", responder_answer(false, &[offer(|sa| set_life(sa, vec![life_dur(900)]))])));
        cases.push(("conflicting lifetimes", responder_answer(false, &[offer(|sa| set_life(sa, vec![life_type(1), life_dur(900), life_type(1), life_dur(60)]))])));
        cases.push(("two SA payloads", responder_answer(false, &[offer(|_| {}), offer(|_| {})])));
        // RFC 2408 §4.2: proposals sharing a Proposal # are one suite, ANDed
        // -- ESP *and* AH -- and a suite this side can't build is no
        // proposal it can take.
        cases.push(("an AH+ESP suite (one Proposal #)", responder_answer(false, &[offer(|sa| {
            let mut ah = sa.proposals[0].clone();
            ah.protocol_id = 2;
            ah.transforms[0].transform_id = 3;
            ah.transforms[0].attributes = vec![Attribute::short(esp_attr::ENCAP_MODE, 1), Attribute::short(esp_attr::AUTH_ALGORITHM, 2)];
            sa.proposals.insert(0, ah);
        })])));
        // KEY_LENGTH is what says which AES it is (RFC 2407 §4.5).
        cases.push(("no KEY_LENGTH on AES", responder_answer(false, &[offer(|sa| xf(sa).attributes.retain(|a| a.attr_type != esp_attr::KEY_LENGTH))])));
        cases.push(("KEY_LENGTH sent twice with different values", responder_answer(false, &[offer(|sa| xf(sa).attributes.push(Attribute::short(esp_attr::KEY_LENGTH, 128)))])));
        cases.push(("ENCAP_MODE sent as a variable-length attribute", responder_answer(false, &[offer(|sa| {
            set_encap(sa, None);
            xf(sa).attributes.push(Attribute::long_bytes(esp_attr::ENCAP_MODE, vec![0u8, 1]));
        })])));
        responder_refuses(cases);
    }

    /// RFC 2408 §4.2: the responder answers with the mode that was offered
    /// (RFC 3947 §5.1: UDP-Encapsulated-Tunnel to a UDP-Encapsulated-Tunnel
    /// offer, Tunnel to a Tunnel offer) -- not whatever its own transport
    /// happens to be.
    #[test]
    fn quick_mode_responder_answers_the_encapsulation_mode_it_was_offered() {
        let encap = |sa: &SaPayload| sa.proposals[0].transforms[0].attr(esp_attr::ENCAP_MODE);
        assert_eq!(encap(&responder_answer(false, &[offer(|sa| set_encap(sa, Some(1)))]).unwrap()), Some(1));
        assert_eq!(encap(&responder_answer(true, &[offer(|sa| set_encap(sa, Some(3)))]).unwrap()), Some(3));
        assert_eq!(encap(&responder_answer(false, &[offer(|sa| set_encap(sa, Some(3)))]).unwrap()), Some(3), "a UDP-encapsulated offer on a non-floated responder");
        assert_eq!(encap(&responder_answer(true, &[offer(|sa| set_encap(sa, Some(1)))]).unwrap()), Some(1), "a plain tunnel offer on a floated responder");
    }

    /// RFC 2408 §4.2: the receiver picks one transform of one proposal -- not
    /// necessarily the first -- and "SHOULD retain the Proposal # and
    /// Transform # fields" of the offer; here the first transform is
    /// TRANSPORT and the second the tunnel it can honour.
    #[test]
    fn quick_mode_responder_picks_an_acceptable_transform_and_keeps_its_numbers() {
        let transport_first = offer(|sa| {
            let mut transport = xf(sa).clone();
            transport.num = 1;
            transport.attributes.retain(|a| a.attr_type != esp_attr::ENCAP_MODE);
            transport.attributes.push(Attribute::short(esp_attr::ENCAP_MODE, 2));
            let mut tunnel = xf(sa).clone();
            tunnel.num = 2;
            sa.proposals[0].transforms = vec![transport, tunnel];
        });
        let ans = responder_answer(false, &[transport_first]).unwrap();
        assert_eq!(ans.proposals.len(), 1);
        assert_eq!(ans.proposals[0].transforms.len(), 1, "a single transform");
        let t = &ans.proposals[0].transforms[0];
        assert_eq!(t.num, 2, "the acceptable transform's own number");
        assert_eq!(t.attr(esp_attr::ENCAP_MODE), Some(1));

        // Numbers other than 1/1 come back as offered.
        let renumbered = offer(|sa| {
            sa.proposals[0].num = 5;
            xf(sa).num = 3;
        });
        let ans = responder_answer(false, &[renumbered]).unwrap();
        assert_eq!((ans.proposals[0].num, ans.proposals[0].transforms[0].num), (5, 3));
    }

    /// The same across proposals: an AH proposal first and an ESP one second;
    /// an ESP proposal with a PFS group the responder doesn't know (it used to
    /// be silently answered as "no PFS") ahead of one it can take.
    #[test]
    fn quick_mode_responder_picks_an_acceptable_proposal_and_keeps_its_number() {
        let ah = {
            let mut p = offer(|_| {}).proposals.remove(0);
            p.num = 1;
            p.protocol_id = 2;
            p.transforms[0].transform_id = 3;
            p.transforms[0].attributes = vec![Attribute::short(esp_attr::ENCAP_MODE, 1), Attribute::short(esp_attr::AUTH_ALGORITHM, 2)];
            p
        };
        let mut esp = offer(|_| {}).proposals.remove(0);
        esp.num = 2;
        let both = SaPayload { doi: IPSEC_DOI, situation: SIT_IDENTITY_ONLY, proposals: vec![ah, esp.clone()] };
        let ans = responder_answer(false, &[both]).unwrap();
        assert_eq!(ans.proposals.len(), 1);
        assert_eq!((ans.proposals[0].num, ans.proposals[0].protocol_id), (2, protocol::ESP));

        let mut odd_group = esp.clone();
        odd_group.num = 1;
        odd_group.transforms[0].attributes.push(Attribute::short(esp_attr::GROUP_DESC, 99));
        let both = SaPayload { doi: IPSEC_DOI, situation: SIT_IDENTITY_ONLY, proposals: vec![odd_group, esp] };
        let ans = responder_answer(false, &[both]).unwrap();
        assert_eq!(ans.proposals[0].num, 2);
        assert_eq!(ans.proposals[0].transforms[0].attr(esp_attr::GROUP_DESC), None);
    }

    /// The responder's own lifetime handling reads the seconds pair too: a
    /// kilobytes duration is not a number of seconds.
    #[test]
    fn quick_mode_responder_reads_the_offered_lifetime_in_its_own_units() {
        let seconds = |attrs: Vec<Attribute>| {
            let ans = responder_answer(false, &[offer(|sa| set_life(sa, attrs))]).unwrap();
            let t = &ans.proposals[0].transforms[0];
            assert_eq!(t.attr(esp_attr::LIFE_TYPE), Some(1), "the answer states its lifetime in seconds");
            t.attr_u32(esp_attr::LIFE_DURATION).unwrap()
        };
        assert_eq!(seconds(vec![life_type(1), life_dur(900)]), 900);
        assert_eq!(seconds(vec![life_type(2), life_dur(4_608_000)]), 3600, "kilobytes only: its own default, not 4.6 million seconds");
        assert_eq!(seconds(vec![life_type(2), life_dur(100_000), life_type(1), life_dur(900)]), 900);
        assert_eq!(seconds(vec![life_type(1), Attribute::long_bytes(esp_attr::LIFE_DURATION, vec![0x03, 0x84])]), 900);
        assert_eq!(seconds(vec![]), 3600);
    }

    /// The lifetime attributes of every transform of `sa`, in order.
    fn life_attributes(sa: &SaPayload) -> Vec<Attribute> {
        let is_life = |a: &&Attribute| matches!(a.attr_type, esp_attr::LIFE_TYPE | esp_attr::LIFE_DURATION);
        sa.proposals.iter().flat_map(|p| p.transforms.iter()).flat_map(|t| t.attributes.iter().filter(is_life)).cloned().collect()
    }

    /// This side counts no volume, so what it offers and what it answers states
    /// its lifetime as one seconds pair and never as a kilobytes one: it neither
    /// asks the peer to hold it to a volume nor agrees to one it cannot keep (see
    /// the module's "SA lifetimes" section; RFC 2407 §4.5, §4.5.4).
    #[test]
    fn quick_mode_states_seconds_only_in_what_it_offers_and_what_it_answers() {
        let mut wrong = Vec::new();
        let pair = |seconds: u32| vec![life_type(1), life_dur(seconds)];
        for (name, sa) in [
            ("AES-GCM", esp_sa(1, SkCipher::Aes256Gcm, None, false, 900)),
            ("AES-GCM with PFS, UDP-encapsulated", esp_sa(1, SkCipher::Aes128Gcm, Some(DhGroup::Modp2048), true, 900)),
            ("AES-CBC with HMAC", esp_sa(1, SkCipher::Aes256Cbc(IntegAlgorithm::HmacSha2_256_128), None, false, 900)),
        ] {
            if life_attributes(&sa) != pair(900) {
                wrong.push(format!("offer, {name}: {:?}", life_attributes(&sa)));
            }
        }
        let kilobytes = |n: u32| vec![life_type(2), life_dur(n)];
        let cases = [
            ("kilobytes only", kilobytes(100_000), 3600),
            ("seconds, then kilobytes", [pair(900), kilobytes(100_000)].concat(), 900),
            ("kilobytes, then seconds", [kilobytes(100_000), pair(900)].concat(), 900),
            ("the same kilobytes pair twice", [kilobytes(100_000), kilobytes(100_000)].concat(), 3600),
        ];
        for (name, life, granted) in cases {
            let answer = responder_answer(false, &[offer(|sa| set_life(sa, life))]).unwrap();
            if life_attributes(&answer) != pair(granted) {
                wrong.push(format!("answer to {name}: {:?}, wanted a seconds pair of {granted}", life_attributes(&answer)));
            }
        }
        assert!(wrong.is_empty(), "lifetimes stated beyond seconds:\n{}", wrong.join("\n"));
    }

    /// [`responder_answer`], carried on to the end: the initiator's genuine
    /// message 3 completes the exchange, and what comes back is the SA payload of
    /// message 2 with the CHILD SA the responder is left with. The entropy is
    /// fixed, so two runs differ only by the offer.
    fn responder_holdings(sas: &[SaPayload]) -> (SaPayload, ChildSa) {
        let (istate, rstate, _ie, mut re) = phase1_pair(0x5201, 0x5202, QM_ADDRS.0.parse().unwrap(), QM_ADDRS.1.parse().unwrap());
        let refs: Vec<&SaPayload> = sas.iter().collect();
        let msg1 = craft_msg1(&istate, &refs);
        let (msg2, qr) = respond_quick(&rstate, &msg1, &mut re).unwrap();
        let hdr = IsakmpHeader::parse(&msg1).unwrap();
        let iv0 = crypto1::phase2_iv(rstate.prf, &rstate.phase1_iv, hdr.message_id, rstate.enc_block);
        let (_h, ps1, iv1) = phase2::parse_encrypted(&msg1, rstate.prf, &rstate.skeyid_a, &rstate.enc_key, rstate.enc_block, &iv0).unwrap();
        let (_h, ps2, iv2) = phase2::decrypt_payloads(&msg2, &rstate.enc_key, rstate.enc_block, &iv1).unwrap();
        let (ni, nr) = (find(&ps1, payload::NONCE).unwrap().data.clone(), find(&ps2, payload::NONCE).unwrap().data.clone());
        let h3 = hash3(rstate.prf, &rstate.skeyid_a, hdr.message_id, &ni, &nr);
        let (msg3, _) = phase2::encrypt_payloads(qm_header(rstate.cky_i, rstate.cky_r, hdr.message_id), &rstate.enc_key, rstate.enc_block, &iv2, &[(payload::HASH, h3)]).unwrap();
        let child = qr.complete(&msg3).unwrap();
        (SaPayload::parse(&find(&ps2, payload::SA).unwrap().data).unwrap(), child)
    }

    /// A volume limit the answer states is held, not thrown away: RFC 2407 §4.5.2
    /// has a lifetime state seconds and kilobytes together, and the initiator
    /// hands both to whoever runs the traffic ([`SaLifetime`]), which is the one
    /// that can count it. The seconds are what they were (the responder's own,
    /// never beyond what was offered; the DOI default when none is stated), and
    /// the limit changes nothing else -- message 3 and the keys are those of the
    /// same answer without it -- so what is held differs from the no-volume case
    /// in the kilobytes alone.
    #[test]
    fn quick_mode_initiator_holds_the_volume_limit_the_answer_states() {
        let seconds = |n: u32| vec![life_type(1), life_dur(n)];
        let kilobytes = |n: u32| vec![life_type(2), life_dur(n)];
        let two_octets = vec![life_type(2), Attribute::long_bytes(esp_attr::LIFE_DURATION, vec![0x27, 0x10])];
        // (what is answered, the same without its volume limit, the lifetime held)
        let cases: Vec<(&str, Vec<Attribute>, Vec<Attribute>, SaLifetime)> = vec![
            ("1 KB only", kilobytes(1), vec![], SaLifetime { seconds: 3600, kilobytes: Some(1) }),
            ("4608000 KB only (a Cisco gateway's default)", kilobytes(4_608_000), vec![], SaLifetime { seconds: 3600, kilobytes: Some(4_608_000) }),
            ("900 s, then 1 KB", [seconds(900), kilobytes(1)].concat(), seconds(900), SaLifetime { seconds: 900, kilobytes: Some(1) }),
            ("1 KB, then 900 s", [kilobytes(1), seconds(900)].concat(), seconds(900), SaLifetime { seconds: 900, kilobytes: Some(1) }),
            ("900 s, then 4608000 KB", [seconds(900), kilobytes(4_608_000)].concat(), seconds(900), SaLifetime { seconds: 900, kilobytes: Some(4_608_000) }),
            ("the same kilobytes pair twice", [kilobytes(100_000), kilobytes(100_000)].concat(), vec![], SaLifetime { seconds: 3600, kilobytes: Some(100_000) }),
            ("a Duration in the two-octet long form", two_octets, vec![], SaLifetime { seconds: 3600, kilobytes: Some(10_000) }),
        ];
        let hold = |life: Vec<Attribute>| {
            let (msg3, child, held) = initiator_holdings(3600, |sa| set_life(sa, life)).unwrap();
            (msg3, child_fields(&child), held)
        };
        let mut wrong = Vec::new();
        for (name, with_volume, without, wanted) in cases {
            let (a, b) = (hold(with_volume), hold(without));
            if a.2 != wanted {
                wrong.push(format!("{name}: held {:?}, wanted {wanted:?}", a.2));
            }
            if b.2.kilobytes.is_some() {
                wrong.push(format!("{name}: the same answer without a volume limit held {:?}", b.2));
            }
            let differ: Vec<&str> = [("message 3", a.0 != b.0), ("CHILD SA", a.1 != b.1), ("seconds", a.2.seconds != b.2.seconds)]
                .into_iter()
                .filter(|(_, d)| *d)
                .map(|(what, _)| what)
                .collect();
            if !differ.is_empty() {
                wrong.push(format!("{name}: differs from the same answer without the volume limit in {differ:?}"));
            }
        }
        assert!(wrong.is_empty(), "answers whose volume limit was not held as stated:\n{}", wrong.join("\n"));
        let (a, b) = (hold(seconds(900)), hold(seconds(600)));
        assert_eq!((a.0 == b.0, a.1 == b.1, a.2.seconds, b.2.seconds), (true, true, 900, 600), "the comparison must see a different number of seconds");
    }

    /// [`QuickInitiator::complete`], which predates the volume limit, keeps
    /// returning the seconds alone -- the responder's own, 900 here, and not the
    /// kilobytes its answer also states -- so a caller written before
    /// [`QuickInitiator::complete_with_lifetime`] reads what it always read.
    #[test]
    fn the_older_complete_returns_the_seconds_alone_whatever_volume_the_answer_states() {
        let (mut istate, rstate, mut ie, mut re) = phase1_pair(0x5111, 0x5112, QM_ADDRS.0.parse().unwrap(), QM_ADDRS.1.parse().unwrap());
        istate.floated = false;
        let (qm1, qi) = initiate_quick(&istate, &mut ie, SkCipher::Aes256Gcm, QM_TS, QM_TS, 3600).unwrap();
        let msg2 = answer_with_life(&rstate, &qm1, &mut re, vec![life_type(2), life_dur(4_608_000), life_type(1), life_dur(900)]);
        let (_msg3, _child, seconds) = qi.complete(&msg2).unwrap();
        assert_eq!(seconds, 900);
    }

    /// The volume limit reaches the caller of a rekey or of an IPv6 CHILD SA
    /// through the exchange itself (`quick_exchange`), not only through
    /// `QuickInitiator`: a gateway answers 900 s and 4608000 KB, and what comes
    /// back is that pair, from each of the three `_with_lifetime` entry points --
    /// the older ones, which return the seconds alone, agree on those seconds.
    #[test]
    fn a_rekey_or_a_new_ipv6_child_sa_hands_over_the_volume_limit_the_gateway_states() {
        let (kilobytes, seconds) = (4_608_000u32, 900u32);
        let wanted = SaLifetime { seconds, kilobytes: Some(kilobytes) };
        type Run = Box<dyn Fn(&UdpSocket, &Phase1State, &mut SeedEntropy, SocketAddr) -> Result<(RekeyedChild, SaLifetime), DriverError>>;
        let runs: Vec<(&str, usize, Run)> = vec![
            ("rekey_child_with_lifetime", 2, Box::new(|sock, st, ie, peer| {
                rekey_child_with_lifetime(sock, st, ie, peer, SkCipher::Aes256Gcm, None, QM_TS, QM_TS, 3600, Duration::from_secs(5), 0x0102_0304)
            })),
            ("rekey_child_ipv6_with_lifetime", 2, Box::new(|sock, st, ie, peer| {
                rekey_child_ipv6_with_lifetime(sock, st, ie, peer, SkCipher::Aes256Gcm, None, (v6("fd00::1"), 128), (v6("::"), 0), 3600, Duration::from_secs(5), 0x0102_0304)
            })),
            ("create_child_ipv6_with_lifetime", 1, Box::new(|sock, st, ie, peer| {
                create_child_ipv6_with_lifetime(sock, st, ie, peer, SkCipher::Aes256Gcm, None, (v6("fd00::1"), 128), (v6("::"), 0), 3600, Duration::from_secs(5))
            })),
        ];
        for (name, datagrams_after_answer, run) in runs {
            let (initiator, responder, _iaddr, raddr) = loopback_pair();
            let (istate, rstate, mut ie, mut re) = phase1_pair(0x5301, 0x5302, QM_ADDRS.0.parse().unwrap(), QM_ADDRS.1.parse().unwrap());
            let iaddr = initiator.local_addr().unwrap();
            let gateway = std::thread::spawn(move || {
                let mut buf = [0u8; 8192];
                let n = responder.recv(&mut buf).unwrap();
                let msg2 = answer_with_life(&rstate, &buf[..n], &mut re, vec![life_type(1), life_dur(seconds), life_type(2), life_dur(kilobytes)]);
                responder.send_to(&msg2, iaddr).unwrap();
                for _ in 0..datagrams_after_answer {
                    responder.recv(&mut buf).unwrap();
                }
            });
            let (_rekeyed, held) = run(&initiator, &istate, &mut ie, raddr).unwrap_or_else(|e| panic!("{name}: {e}"));
            gateway.join().unwrap();
            assert_eq!(held, wanted, "{name}");
        }

        // The older entry points keep returning the seconds alone, whatever the
        // gateway adds to them.
        type RunSeconds = Box<dyn Fn(&UdpSocket, &Phase1State, &mut SeedEntropy, SocketAddr) -> Result<(RekeyedChild, u32), DriverError>>;
        let older: Vec<(&str, usize, RunSeconds)> = vec![
            ("rekey_child", 2, Box::new(|sock, st, ie, peer| {
                rekey_child(sock, st, ie, peer, SkCipher::Aes256Gcm, None, QM_TS, QM_TS, 3600, Duration::from_secs(5), 0x0102_0304)
            })),
            ("rekey_child_ipv6", 2, Box::new(|sock, st, ie, peer| {
                rekey_child_ipv6(sock, st, ie, peer, SkCipher::Aes256Gcm, None, (v6("fd00::1"), 128), (v6("::"), 0), 3600, Duration::from_secs(5), 0x0102_0304)
            })),
            ("create_child_ipv6", 1, Box::new(|sock, st, ie, peer| {
                create_child_ipv6(sock, st, ie, peer, SkCipher::Aes256Gcm, None, (v6("fd00::1"), 128), (v6("::"), 0), 3600, Duration::from_secs(5))
            })),
        ];
        for (name, datagrams_after_answer, run) in older {
            let (initiator, responder, _iaddr, raddr) = loopback_pair();
            let (istate, rstate, mut ie, mut re) = phase1_pair(0x5303, 0x5304, QM_ADDRS.0.parse().unwrap(), QM_ADDRS.1.parse().unwrap());
            let iaddr = initiator.local_addr().unwrap();
            let gateway = std::thread::spawn(move || {
                let mut buf = [0u8; 8192];
                let n = responder.recv(&mut buf).unwrap();
                let msg2 = answer_with_life(&rstate, &buf[..n], &mut re, vec![life_type(1), life_dur(seconds), life_type(2), life_dur(kilobytes)]);
                responder.send_to(&msg2, iaddr).unwrap();
                for _ in 0..datagrams_after_answer {
                    responder.recv(&mut buf).unwrap();
                }
            });
            let (_rekeyed, seconds_only) = run(&initiator, &istate, &mut ie, raddr).unwrap_or_else(|e| panic!("{name}: {e}"));
            gateway.join().unwrap();
            assert_eq!(seconds_only, seconds, "{name}");
        }
    }

    /// A gateway's message 2 to `msg1` that echoes the offered identities and
    /// states the lifetime attributes `life` (in that order) on an ESP SA of its
    /// own -- what a peer with a volume limit of its own answers.
    fn answer_with_life(st: &Phase1State, msg1: &[u8], entropy: &mut impl Entropy, life: Vec<Attribute>) -> Vec<u8> {
        let hdr = IsakmpHeader::parse(msg1).unwrap();
        let iv0 = crypto1::phase2_iv(st.prf, &st.phase1_iv, hdr.message_id, st.enc_block);
        let (_h, ps, _iv1) = phase2::parse_encrypted(msg1, st.prf, &st.skeyid_a, &st.enc_key, st.enc_block, &iv0).unwrap();
        let ids: Vec<Vec<u8>> = ps.iter().filter(|p| p.payload_type == payload::ID).map(|p| p.data.clone()).collect();
        let mut sa = esp_sa(0xC0FF_EE00, SkCipher::Aes256Gcm, None, false, 3600);
        set_life(&mut sa, life);
        forge_answer(st, msg1, entropy, &[&sa], &ids)
    }

    /// The responder counterpart: an offer that includes a volume limit is taken
    /// as though it had none. The answer (a seconds pair of the responder's own)
    /// and the CHILD SA it is left with are the same as for the offer without it.
    #[test]
    fn quick_mode_responder_accepts_a_volume_limit_in_the_offer_and_keeps_and_applies_none_of_it() {
        let seconds = |n: u32| vec![life_type(1), life_dur(n)];
        let kilobytes = |n: u32| vec![life_type(2), life_dur(n)];
        let cases: Vec<(&str, Vec<Attribute>, Vec<Attribute>)> = vec![
            ("1 KB only", kilobytes(1), vec![]),
            ("4608000 KB only (a Cisco gateway's default)", kilobytes(4_608_000), vec![]),
            ("900 s, then 1 KB", [seconds(900), kilobytes(1)].concat(), seconds(900)),
            ("1 KB, then 900 s", [kilobytes(1), seconds(900)].concat(), seconds(900)),
            ("900 s, then 4608000 KB", [seconds(900), kilobytes(4_608_000)].concat(), seconds(900)),
        ];
        let hold = |life: Vec<Attribute>| {
            let (answer, child) = responder_holdings(&[offer(|sa| set_life(sa, life))]);
            (life_attributes(&answer), child_fields(&child))
        };
        let mut wrong = Vec::new();
        for (name, with_volume, without) in cases {
            if hold(with_volume) != hold(without) {
                wrong.push(format!("{name}: what the responder answers and holds differs from the same offer without the volume limit"));
            }
        }
        assert!(wrong.is_empty(), "offers that left something of their volume limit:\n{}", wrong.join("\n"));
        let (a, b) = (hold(seconds(900)), hold(seconds(600)));
        assert_eq!((a.0 == b.0, a.1 == b.1), (false, true), "the comparison must see a different number of seconds");
    }

    /// What this crate does not do about a volume limit: a CHILD SA negotiated
    /// under a limit of one kilobyte seals far more than that, on either end -- 16
    /// packets of 1400 bytes. `EspSa` stops at the sequence number (2^32 packets,
    /// "rekey required") and at nothing counted in bytes; counting is the
    /// caller's, which runs the data plane, and the limit it counts against is
    /// what [`SaLifetime`] hands it.
    #[test]
    fn a_child_sa_negotiated_under_a_one_kilobyte_limit_carries_on_past_it() {
        let life = || vec![life_type(1), life_dur(900), life_type(2), life_dur(1)];
        let (_msg3, mut initiator, _held) = initiator_holdings(3600, |sa| set_life(sa, life())).unwrap();
        let (_answer, mut responder) = responder_holdings(&[offer(|sa| set_life(sa, life()))]);
        let packet = [0x45u8; 1400];
        for (end, sa) in [("initiator", &mut initiator.outbound), ("responder", &mut responder.outbound)] {
            for n in 1..=16 {
                assert!(sa.seal(&packet, 4).is_ok(), "the {end} could not seal packet {n} ({} bytes in all) under a 1 KB limit", n * packet.len());
            }
        }
    }

    fn message_of(cky_i: [u8; 8], cky_r: [u8; 8], message_id: u32) -> Vec<u8> {
        let mut m = vec![0u8; IsakmpHeader::LEN];
        m[..8].copy_from_slice(&cky_i);
        m[8..16].copy_from_slice(&cky_r);
        m[17] = IsakmpHeader::VERSION_1_0;
        m[18] = exchange::QUICK;
        m[20..24].copy_from_slice(&message_id.to_be_bytes());
        m[24..28].copy_from_slice(&(IsakmpHeader::LEN as u32).to_be_bytes());
        m
    }

    /// While a rekey waits for its message 2, the gateway repeats the message 2
    /// of the exchange before it (our message 3 for that one was lost): that
    /// message 3 is sent again, byte for byte, and the wait goes on for the
    /// message 2 it is really waiting for (RFC 2408 §3.1, RFC 2409 §5).
    #[test]
    fn a_rekey_waiting_for_message_2_answers_a_repeat_of_the_previous_message_2() {
        let (cky_i, cky_r) = ([0xAA; 8], [0xBB; 8]);
        let st = Phase1State::resume(crate::ikev1::crypto1::Prf::Sha256, DhGroup::Modp2048, cky_i, cky_r, vec![], vec![], vec![], vec![], 16, vec![]);
        let previous_msg2 = message_of(cky_i, cky_r, 0x1111);
        let previous_msg3 = [message_of(cky_i, cky_r, 0x1111), b"message 3".to_vec()].concat();
        st.finals.retain(&previous_msg2, &previous_msg3);
        let awaited = message_of(cky_i, cky_r, 0x2222);

        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        let gateway = UdpSocket::bind("127.0.0.1:0").unwrap();
        gateway.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        gateway.send_to(&previous_msg2, client.local_addr().unwrap()).unwrap();
        gateway.send_to(&awaited, client.local_addr().unwrap()).unwrap();

        let got = await_quick_reply(&client, &st, gateway.local_addr().unwrap(), 0x2222, Duration::from_secs(2), "test").unwrap();
        assert_eq!(got, Some(awaited));
        let mut buf = [0u8; 256];
        let (n, _) = gateway.recv_from(&mut buf).expect("the previous exchange's message 3 must have been sent again");
        assert_eq!(&buf[..n], &previous_msg3[..]);
    }
}
