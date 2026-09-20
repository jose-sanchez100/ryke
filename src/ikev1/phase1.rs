//! IKEv1 Phase 1 — Aggressive Mode responder with PSK authentication
//! (RFC 2409 §5.4), the mode Android's "IPSec Xauth PSK" client uses.
//!
//! ```text
//! I → HDR, SA, KE, Ni, IDi
//! R → HDR, SA, KE, Nr, IDr, HASH_R
//! I → HDR, HASH_I
//! ```
//!
//! After this, both sides hold `SKEYID_{d,a,e}`; the Xauth, Mode-Config and
//! Quick-Mode exchanges follow, encrypted under `SKEYID_e`.

use super::crypto1::{self, Prf, AES_BLOCK};
use super::isakmp::{self, exchange, payload, IsakmpHeader};
use super::phase2;
use super::payloads::{
    attr, auth, cert_payload_body, enc, hash, id_type, life, protocol, Attribute, Id, Proposal, SaPayload,
    Transform, IPSEC_DOI, SIT_IDENTITY_ONLY,
};
use crate::crypto::DhGroup;
use crate::entropy::Entropy;
use crate::error::IkeError;
use crate::debug::ike_debug;
use crate::ikev2::sign::{cert_subject_dn, cert_subject_issuer_display, validate_chain, SigningKey, VerifyingKey};
use crate::ikev2::sk::SkCipher;
use std::net::SocketAddr;
use std::sync::Arc;

/// Well-known XAUTH capability Vendor ID (`09002689dfd6b712`, the de-facto marker
/// from draft-beaulieu-ike-xauth). An XAUTH initiator refuses to authenticate a
/// gateway that does not advertise XAUTH support, so the responder must echo this
/// in Aggressive-Mode message 2 whenever an XAUTH auth method was negotiated.
pub const XAUTH_VENDOR_ID: [u8; 8] = [0x09, 0x00, 0x26, 0x89, 0xdf, 0xd6, 0xb7, 0x12];

/// RFC 3706 Dead Peer Detection capability marker
/// (`AFCAD71368A1F1C96B8696FC77570100` — MD5("draft-ietf-ipsec-dpd-00.txt")).
/// Advertised unconditionally by both sides (it costs nothing to offer); a
/// peer that echoes it back is DPD-capable, recorded on
/// [`Phase1State::peer_supports_dpd`].
pub const DPD_VENDOR_ID: [u8; 16] = [
    0xAF, 0xCA, 0xD7, 0x13, 0x68, 0xA1, 0xF1, 0xC9, 0x6B, 0x86, 0x96, 0xFC, 0x77, 0x57, 0x01, 0x00,
];

/// RFC 3947 NAT-Traversal capability marker (`MD5("RFC 3947")`, computed
/// directly rather than recalled from memory, to avoid a transcription
/// error). Confirmed against isakmpd's own `VID_RFC3947`
/// (`nat_traversal.c`): sent unconditionally alongside the SA payload in
/// Main-Mode messages 1/2 (both directions), independent of whether a
/// transform has been chosen yet -- the same "offer unconditionally, record
/// whether the peer echoed it" shape [`DPD_VENDOR_ID`] already uses, just at
/// a different point in the exchange (see [`Phase1State::floated`]'s doc for
/// why the placement here specifically has to match msg1/2, not msg3/4 like
/// DPD: a peer that gates its own NAT-D response in msg2 on having already
/// seen this VID in msg1 would never send one back otherwise). Only the
/// final RFC value is sent -- not the historical
/// draft-ietf-ipsec-nat-t-ike-02/03 VIDs isakmpd also advertises for legacy
/// interop, since this crate's real-world target (a modern FortiGate) is
/// RFC-compliant.
pub const NATT_RFC_VENDOR_ID: [u8; 16] = [
    0x4a, 0x13, 0x1c, 0x81, 0x07, 0x03, 0x58, 0x45, 0x5c, 0x57, 0x28, 0xf2, 0x0e, 0x95, 0x45, 0x2f,
];

/// `HASH(CKY-I | CKY-R | IP | Port)` (RFC 3947 §4.2) -- the NAT-D payload's
/// content, one for the sender's own claimed address, one for the address it
/// believes the peer is at. Uses the *negotiated Phase-1 PRF's plain hash*
/// (not HMAC-keyed, unlike every other `crypto1` formula in this file) --
/// confirmed against isakmpd's `nat_t_generate_nat_d_hash`, which hashes with
/// whatever `ie->hash->type` Phase 1 negotiated rather than a
/// fixed algorithm. This crate's own initiator always offers SHA-256 for
/// Phase 1 (see `initiator_sa`'s doc), so `prf` here is normally
/// [`Prf::Sha256`] in practice, not SHA-1 like RFC 3947's original
/// (SHA-1-only-IKE-era) examples -- if a live gateway turns out to expect
/// SHA-1 specifically for this payload regardless of the negotiated Phase-1
/// hash, that's the first thing to check via `--debug-all` (see this crate's
/// project memory for the established verify-live-then-fix loop).
fn natd_hash(prf: Prf, cky_i: [u8; 8], cky_r: [u8; 8], addr: SocketAddr) -> Vec<u8> {
    let mut data = Vec::with_capacity(16 + 4 + 2);
    data.extend_from_slice(&cky_i);
    data.extend_from_slice(&cky_r);
    match addr.ip() {
        std::net::IpAddr::V4(a) => data.extend_from_slice(&a.octets()),
        std::net::IpAddr::V6(a) => data.extend_from_slice(&a.octets()),
    }
    data.extend_from_slice(&addr.port().to_be_bytes());
    prf.hash(&data)
}

/// The two NAT-D payloads one side sends: the address it believes the
/// *recipient* (`dst`) is at first, then its own (`src`) address second --
/// matching isakmpd's `nat_t_exchange_add_nat_d` order exactly
/// (destination-then-source), confirmed by reading `nat_traversal.c`.
/// [`natd_float_needed`]'s own comparison is order-agnostic on receive, but
/// matching a real implementation's send order is the safer interop choice.
fn natd_payloads(prf: Prf, cky_i: [u8; 8], cky_r: [u8; 8], dst: SocketAddr, src: SocketAddr) -> Vec<(u8, Vec<u8>)> {
    vec![
        (payload::NAT_D, natd_hash(prf, cky_i, cky_r, dst)),
        (payload::NAT_D, natd_hash(prf, cky_i, cky_r, src)),
    ]
}

fn peer_offers_natt(ps: &[isakmp::Payload]) -> bool {
    ps.iter().any(|p| p.payload_type == payload::VENDOR_ID && p.data == NATT_RFC_VENDOR_ID)
}

/// Whether this exchange should float to UDP 4500 (RFC 3947 §5), given the
/// NAT-D payloads seen in `ps` and whether the peer advertised
/// [`NATT_RFC_VENDOR_ID`] at all (`peer_offers_natt` -- a separate parameter,
/// not re-derived from `ps`, because Main Mode carries the VID in messages
/// 1/2 but the NAT-D pair itself in messages 3/4: the gate and the payloads
/// being gated don't always live in the same message, unlike Aggressive
/// Mode's msg1/2 where both do). `false` outright if `peer_offers_natt` is
/// `false` (NAT-D would be meaningless without that) -- also `false` if the
/// peer *did* advertise support but sent no NAT-D payloads in `ps` at all,
/// matching isakmpd's own `nat_t_match_nat_d_payload` fallback ("no payloads
/// present" is treated as "matched", i.e. assume no NAT, rather than as a
/// hard failure). Otherwise: float unless *both* of our own
/// locally-recomputed candidate hashes (our own claimed `our_addr`, the
/// peer's `peer_addr`) appear somewhere among the peer's NAT-D payloads --
/// order-agnostic (checks membership, not position), which is more lenient
/// than strictly required but matches isakmpd's own receive-side behavior
/// and costs nothing. This is a single float-or-not boolean, not a
/// which-side-is-natted attribution -- mirrors
/// `ikev2::exchange::NatStatus::float_to_4500`'s
/// `we_are_natted || peer_is_natted` simplification.
fn natd_float_needed(ps: &[isakmp::Payload], peer_offers_natt: bool, prf: Prf, cky_i: [u8; 8], cky_r: [u8; 8], our_addr: SocketAddr, peer_addr: SocketAddr) -> bool {
    if !peer_offers_natt {
        return false;
    }
    let received: Vec<&[u8]> = ps.iter().filter(|p| p.payload_type == payload::NAT_D).map(|p| p.data.as_slice()).collect();
    if received.is_empty() {
        return false;
    }
    let expect_ours = natd_hash(prf, cky_i, cky_r, our_addr);
    let expect_peer = natd_hash(prf, cky_i, cky_r, peer_addr);
    let ours_seen = received.contains(&expect_ours.as_slice());
    let peer_seen = received.contains(&expect_peer.as_slice());
    !(ours_seen && peer_seen)
}

/// The XAUTH auth methods occupy the private range 65001..=65010
/// (XAUTHInit/Resp × PreShared/DSS/RSA/…).
fn is_xauth_auth(method: u16) -> bool {
    (65001..=65010).contains(&method)
}

/// How this side proves its own identity in Phase 1 (RFC 2409 §5.1/§5.4).
///
/// No `Drop`-based auto-wipe of the `Psk` secret: this is a public, by-value
/// type cloned into every Phase-1 message state (see [`crate::crypto::SessionKeys`]'s
/// doc comment for the general reasoning) -- a caller done with a value can
/// match out the `Psk` buffer and wipe it explicitly with
/// `zeroize::Zeroize::zeroize`.
#[derive(Clone)]
pub enum Ikev1LocalAuth {
    /// Pre-shared key (§5.4) — both sides use the same secret.
    Psk(Vec<u8>),
    /// RSA digital signature (§5.1, Main Mode only — see
    /// [`Ikev1ExchangeMode`]): `chain[0]` is the leaf cert whose key signs
    /// `HASH_I`/`HASH_R`, the rest are intermediates sent alongside it in the
    /// CERT payloads. `Arc` because [`SigningKey`] isn't `Clone` and this
    /// config gets cloned once per Phase-1 message-state transition, same as
    /// `Psk`'s `Vec<u8>` was before it.
    Sig { key: Arc<SigningKey>, chain: Vec<Vec<u8>> },
}

impl Ikev1LocalAuth {
    /// The pre-shared key. Only ever reached from Aggressive-Mode code paths,
    /// which are PSK-only in this crate (RSA-sig needs Main Mode's identity
    /// protection) -- [`Client::connect`](super::client::Client::connect)
    /// rejects a `Sig` config paired with [`Ikev1ExchangeMode::Aggressive`]
    /// before this can be reached from that entry point.
    fn expect_psk(&self) -> &[u8] {
        match self {
            Ikev1LocalAuth::Psk(p) => p,
            Ikev1LocalAuth::Sig { .. } => {
                panic!("Ikev1LocalAuth::Sig is not valid for Aggressive Mode (PSK only)")
            }
        }
    }
}

/// The responder's Phase-1 configuration.
pub struct Phase1Config {
    pub local_auth: Ikev1LocalAuth,
    /// Trusted CA certificates to validate the peer's chain against — only
    /// consulted when `local_auth` is `Sig`.
    pub trusted_cas: Vec<Vec<u8>>,
    /// Wall-clock time (Unix seconds) to check the peer's certificate
    /// validity against — only consulted when `local_auth` is `Sig`.
    pub now_unix: u64,
    /// The identity we assert in `IDr`. Ignored (a DER-encoded cert subject
    /// DN is asserted instead) when `local_auth` is `Sig` — must be the one
    /// the peer's PSK maps to when `local_auth` is `Psk`.
    pub our_id: Id,
}

/// Everything Phase 1 establishes, carried into the encrypted exchanges.
///
/// Implements `Zeroize` over the derived key material (`skeyid*`, `enc_key`)
/// -- see [`crate::crypto::SessionKeys`]'s doc comment for why this is
/// `Zeroize`, not `ZeroizeOnDrop` (this type is public and callers read its
/// fields by value). The other fields (cookies, DH public shares, nonces,
/// SA/ID bodies) aren't secret and are skipped.
#[derive(Clone, zeroize::Zeroize)]
pub struct Phase1State {
    #[zeroize(skip)]
    pub prf: Prf,
    #[zeroize(skip)]
    pub group: DhGroup,
    #[zeroize(skip)]
    pub cky_i: [u8; 8],
    #[zeroize(skip)]
    pub cky_r: [u8; 8],
    pub skeyid: Vec<u8>,
    pub skeyid_d: Vec<u8>,
    pub skeyid_a: Vec<u8>,
    pub skeyid_e: Vec<u8>,
    /// Derived AES-256 key.
    pub enc_key: Vec<u8>,
    /// `HASH(g^xi | g^xr)` — the seed for every post-Phase-1 message IV.
    #[zeroize(skip)]
    pub phase1_iv: Vec<u8>,
    #[zeroize(skip)]
    pub gxi: Vec<u8>,
    #[zeroize(skip)]
    pub gxr: Vec<u8>,
    #[zeroize(skip)]
    pub ni: Vec<u8>,
    #[zeroize(skip)]
    pub nr: Vec<u8>,
    /// The initiator's SA-payload body and ID body — needed to verify `HASH_I`.
    #[zeroize(skip)]
    sai_b: Vec<u8>,
    #[zeroize(skip)]
    idii_b: Vec<u8>,
    /// Whether the peer's own Phase-1 message echoed [`DPD_VENDOR_ID`].
    #[zeroize(skip)]
    pub peer_supports_dpd: bool,
    /// Whether RFC 3947 NAT detection (see [`natd_float_needed`]) decided
    /// this exchange must float to UDP 4500 for everything after the point
    /// it was decided (Main Mode: message 5 onward; Aggressive Mode: message
    /// 3 onward) -- XAUTH, Mode-Config, Quick Mode, and the Informational
    /// exchange (DPD/graceful-disconnect Delete) all have to keep using this
    /// same decision for the life of the SA, since the peer only ever
    /// listens on whichever port it also decided to float to. `false` after
    /// [`Phase1State::resume`] like `peer_supports_dpd` -- see that field's
    /// doc for why (no VID/NAT-D info survives a restart); a genuinely
    /// floated session resumed this way would need its caller to already
    /// know to keep using the port-4500 socket regardless.
    #[zeroize(skip)]
    pub floated: bool,
    /// The Phase-1 SA lifetime actually in force, in seconds -- the
    /// responder's own value if it echoed one (RFC 2407 §4.5: the responder
    /// is never bound to the initiator's offered lifetime and may
    /// unilaterally choose a shorter one), falling back to whatever this
    /// side itself offered if the responder's chosen transform carried no
    /// `LIFE_DURATION` attribute at all. See [`negotiated_p1_lifetime`].
    #[zeroize(skip)]
    pub negotiated_lifetime_secs: u32,
}

/// Pick the first offered transform we support: AES-CBC (128/192/256-bit,
/// per the offered `KEY_LENGTH` attribute), HASH SHA-256 (or SHA-1), DH
/// group 2 (or 14), and -- matching our own configured `local_auth` --
/// either PSK/XAUTH-PSK auth (`want_sig: false`) or RSA-SIG/XAUTH-RSA auth
/// (`want_sig: true`); a real gateway policy only ever offers/accepts the
/// one method it's configured for. Returns the transform to echo plus the
/// mapped primitives (the `usize` is the AES key length in bytes).
fn select_transform(sa: &SaPayload, want_sig: bool) -> Option<(Transform, Prf, DhGroup, usize)> {
    for prop in &sa.proposals {
        for t in &prop.transforms {
            if t.attr(attr::ENCRYPTION) != Some(enc::AES_CBC) {
                continue;
            }
            let key_len = match t.attr(attr::KEY_LENGTH) {
                Some(128) => 16,
                Some(192) => 24,
                Some(256) => 32,
                _ => continue,
            };
            let prf = match t.attr(attr::HASH) {
                Some(hash::SHA2_256) => Prf::Sha256,
                Some(hash::SHA1) => Prf::Sha1,
                _ => continue,
            };
            let group = match t.attr(attr::GROUP_DESC) {
                Some(2) => DhGroup::Modp1024,
                Some(14) => DhGroup::Modp2048,
                _ => continue,
            };
            let auth_ok = if want_sig {
                matches!(t.attr(attr::AUTH_METHOD), Some(auth::RSA_SIG) | Some(auth::XAUTH_INIT_RSA))
            } else {
                matches!(t.attr(attr::AUTH_METHOD), Some(auth::PSK) | Some(auth::XAUTH_INIT_PSK))
            };
            if !auth_ok {
                continue;
            }
            return Some((t.clone(), prf, group, key_len));
        }
    }
    None
}

fn find(payloads: &[isakmp::Payload], t: u8) -> Option<&isakmp::Payload> {
    payloads.iter().find(|p| p.payload_type == t)
}

/// Pull the responder's actually-chosen Phase-1 SA lifetime back out of its
/// SA payload (RFC 2407 §4.5: the responder may unilaterally shorten the
/// initiator's offered lifetime), falling back to `offered` if the chosen
/// transform carried no `LIFE_DURATION` attribute at all.
fn negotiated_p1_lifetime(ps: &[isakmp::Payload], offered: u32) -> u32 {
    find(ps, payload::SA)
        .and_then(|p| SaPayload::parse(&p.data).ok())
        .and_then(|sa| sa.proposals.first().and_then(|prop| prop.transforms.first().and_then(|t| t.attr_u32(attr::LIFE_DURATION))))
        .unwrap_or(offered)
}

/// Collect every CERT payload's DER body (stripping the 1-byte encoding tag),
/// leaf first — the chain order this crate always sends in. Errors if none
/// are present.
fn collect_certs(payloads: &[isakmp::Payload]) -> Result<Vec<Vec<u8>>, IkeError> {
    let certs: Vec<Vec<u8>> = payloads
        .iter()
        .filter(|p| p.payload_type == payload::CERT)
        .map(|p| p.data.get(1..).map(<[u8]>::to_vec).ok_or(IkeError::Crypto("empty CERT payload")))
        .collect::<Result<_, _>>()?;
    if certs.is_empty() {
        return Err(IkeError::MissingPayload("CERT"));
    }
    Ok(certs)
}

/// Process Aggressive-Mode message 1 and build message 2. Returns the response
/// bytes and the Phase-1 state (which then verifies `HASH_I`).
pub fn respond_aggressive(
    cfg: &Phase1Config,
    msg1: &[u8],
    entropy: &mut impl Entropy,
    our_addr: SocketAddr,
    peer_addr: SocketAddr,
) -> Result<(Vec<u8>, Phase1State), IkeError> {
    let hdr = IsakmpHeader::parse(msg1)?;
    if hdr.exchange_type != exchange::AGGRESSIVE {
        return Err(IkeError::Crypto("not an Aggressive Mode message"));
    }
    if hdr.message_id != 0 {
        return Err(IkeError::Crypto("phase 1 message_id must be zero"));
    }
    // Aggressive Mode is PSK-only in this crate -- RSA-sig needs Main Mode's
    // identity protection (IDi/IDr must go out encrypted, which Aggressive
    // Mode's single-round-trip shape can't give a CERT/SIG payload without
    // leaking the certificate identity in the clear).
    let Ikev1LocalAuth::Psk(psk) = &cfg.local_auth else {
        return Err(IkeError::Crypto("Aggressive Mode requires PSK auth (RSA-sig needs Main Mode)"));
    };

    let cky_i = hdr.init_cookie;
    let ps = isakmp::parse_payloads(hdr.next_payload, &msg1[IsakmpHeader::LEN..])?;

    let sa_p = find(&ps, payload::SA).ok_or(IkeError::MissingPayload("SA"))?;
    let ke_p = find(&ps, payload::KE).ok_or(IkeError::MissingPayload("KE"))?;
    let nonce_p = find(&ps, payload::NONCE).ok_or(IkeError::MissingPayload("NONCE"))?;
    isakmp::check_nonce_len(&nonce_p.data)?;
    let id_p = find(&ps, payload::ID).ok_or(IkeError::MissingPayload("ID"))?;

    let sai_b = sa_p.data.clone(); // signed as SAi_b
    let idii_b = id_p.data.clone(); // signed as IDii_b
    let gxi = ke_p.data.clone();
    let ni = nonce_p.data.clone();
    let peer_supports_dpd = ps.iter().any(|p| p.payload_type == payload::VENDOR_ID && p.data == DPD_VENDOR_ID);

    let sa = SaPayload::parse(&sa_p.data)?;
    let (chosen, prf, group, key_len) =
        select_transform(&sa, false).ok_or(IkeError::NoProposalChosen)?;
    if gxi.len() != group.public_len() {
        return Err(IkeError::BadKeyExchange { group: group.transform_id(), len: gxi.len() });
    }

    // Our ephemerals.
    let mut cky_r = [0u8; 8];
    entropy.fill(&mut cky_r);
    let dh_private = entropy.next_array32();
    let mut nr = vec![0u8; 16];
    entropy.fill(&mut nr);

    let gxr = group.public(&dh_private);
    let gxy = group.shared(&dh_private, &gxi)?;

    // Key schedule.
    let skeyid = crypto1::skeyid_psk(prf, psk, &ni, &nr);
    let skeyid_d = crypto1::skeyid_d(prf, &skeyid, &gxy, &cky_i, &cky_r);
    let skeyid_a = crypto1::skeyid_a(prf, &skeyid, &skeyid_d, &gxy, &cky_i, &cky_r);
    let skeyid_e = crypto1::skeyid_e(prf, &skeyid, &skeyid_a, &gxy, &cky_i, &cky_r);
    let enc_key = crypto1::derive_cipher_key(prf, &skeyid_e, key_len);
    let phase1_iv = crypto1::phase1_iv(prf, &gxi, &gxr, AES_BLOCK);

    // HASH_R = prf(SKEYID, g^xr | g^xi | CKY-R | CKY-I | SAi_b | IDir_b).
    let idir_b = cfg.our_id.to_bytes();
    let hash_r = crypto1::hash_r(prf, &skeyid, &gxr, &gxi, &cky_r, &cky_i, &sai_b, &idir_b);

    // Response SA: echo just the chosen transform.
    let chosen_auth = chosen.attr(attr::AUTH_METHOD).unwrap_or(0);
    let initiator_offered_lifetime = chosen.attr_u32(attr::LIFE_DURATION).unwrap_or(0);
    let sar = SaPayload {
        doi: sa.doi,
        situation: sa.situation,
        proposals: vec![Proposal {
            num: 1,
            protocol_id: protocol::ISAKMP,
            spi: Vec::new(),
            transforms: vec![chosen],
        }],
    };

    let mut out_payloads: Vec<(u8, Vec<u8>)> = vec![
        (payload::SA, sar.to_bytes()),
        (payload::KE, gxr.clone()),
        (payload::NONCE, nr.clone()),
        (payload::ID, idir_b.clone()),
        (payload::HASH, hash_r),
    ];
    // An XAUTH client requires the gateway to acknowledge XAUTH support before it
    // will authenticate; otherwise it rejects msg-2 (misleadingly, as a pre-auth
    // SITUATION-NOT-SUPPORTED). The VID is not covered by HASH_R.
    if is_xauth_auth(chosen_auth) {
        out_payloads.push((payload::VENDOR_ID, XAUTH_VENDOR_ID.to_vec()));
    }
    // Advertise our own DPD support unconditionally, independent of whether
    // the initiator advertised theirs -- see `DPD_VENDOR_ID`'s doc.
    out_payloads.push((payload::VENDOR_ID, DPD_VENDOR_ID.to_vec()));
    // RFC 3947 NAT-T: message 1's NAT-D (if any) was necessarily computed by
    // the initiator with CKY-R still all-zero (it doesn't exist yet at that
    // point) -- `hdr.resp_cookie` as parsed from msg1 is exactly that zero
    // value, not our own freshly-chosen `cky_r`, so verification here must
    // use it too. Message 2's own NAT-D pair (added below, dst=initiator
    // first per isakmpd's order) uses the real `cky_r` instead, since both
    // cookies are genuinely known by the time this side sends it.
    let peer_offers_natt_here = peer_offers_natt(&ps);
    let floated = natd_float_needed(&ps, peer_offers_natt_here, prf, cky_i, hdr.resp_cookie, our_addr, peer_addr);
    if peer_offers_natt_here {
        out_payloads.push((payload::VENDOR_ID, NATT_RFC_VENDOR_ID.to_vec()));
        out_payloads.extend(natd_payloads(prf, cky_i, cky_r, peer_addr, our_addr));
    }
    let out_header = IsakmpHeader {
        init_cookie: cky_i,
        resp_cookie: cky_r,
        next_payload: payload::NONE, // set by build_message
        version: IsakmpHeader::VERSION_1_0,
        exchange_type: exchange::AGGRESSIVE,
        flags: 0,
        message_id: 0,
        length: 0,
    };
    let msg2 = isakmp::build_message(out_header, &out_payloads);

    let state = Phase1State {
        prf,
        group,
        cky_i,
        cky_r,
        skeyid,
        skeyid_d,
        skeyid_a,
        skeyid_e,
        enc_key,
        phase1_iv,
        gxi,
        gxr,
        ni,
        nr,
        sai_b,
        idii_b,
        peer_supports_dpd,
        floated,
        negotiated_lifetime_secs: initiator_offered_lifetime,
    };
    Ok((msg2, state))
}

impl Phase1State {
    /// Reconstruct a *post-Phase-1* state from persisted key material — for SA
    /// resumption across a restart. The Phase-1-only transcript fields (`skeyid`,
    /// `g^xi`/`g^xr`, `Ni`/`Nr`, `SAi_b`/`IDii_b`), which exist solely to verify
    /// `HASH_I`, are left empty, so the result MUST NOT be used to verify `HASH_I`
    /// again — only to drive the encrypted phase-2 exchanges.
    #[allow(clippy::too_many_arguments)]
    pub fn resume(
        prf: Prf,
        group: DhGroup,
        cky_i: [u8; 8],
        cky_r: [u8; 8],
        skeyid_a: Vec<u8>,
        skeyid_d: Vec<u8>,
        skeyid_e: Vec<u8>,
        enc_key: Vec<u8>,
        phase1_iv: Vec<u8>,
    ) -> Self {
        Phase1State {
            prf,
            group,
            cky_i,
            cky_r,
            skeyid: Vec::new(),
            skeyid_d,
            skeyid_a,
            skeyid_e,
            enc_key,
            phase1_iv,
            gxi: Vec::new(),
            gxr: Vec::new(),
            ni: Vec::new(),
            nr: Vec::new(),
            sai_b: Vec::new(),
            idii_b: Vec::new(),
            peer_supports_dpd: false,
            floated: false,
            negotiated_lifetime_secs: 0,
        }
    }

    /// Verify the initiator's `HASH_I` from Aggressive-Mode message 3
    /// (`HASH_I = prf(SKEYID, g^xi | g^xr | CKY-I | CKY-R | SAi_b | IDii_b)`).
    /// Handles message 3 whether it arrives in the clear or encrypted.
    pub fn verify_hash_i(&self, msg3: &[u8]) -> Result<(), IkeError> {
        let hdr = IsakmpHeader::parse(msg3)?;
        let body = &msg3[IsakmpHeader::LEN..];
        let decrypted;
        let (first, payload_bytes) = if hdr.encrypted() {
            decrypted = crypto1::aes_cbc_decrypt(&self.enc_key, &self.phase1_iv, body)?;
            (hdr.next_payload, decrypted.as_slice())
        } else {
            (hdr.next_payload, body)
        };
        let ps = isakmp::parse_payloads(first, payload_bytes)?;
        let hash_p = find(&ps, payload::HASH).ok_or(IkeError::MissingPayload("HASH"))?;
        let expected = crypto1::hash_i(
            self.prf,
            &self.skeyid,
            &self.gxi,
            &self.gxr,
            &self.cky_i,
            &self.cky_r,
            &self.sai_b,
            &self.idii_b,
        );
        if hash_p.data == expected {
            Ok(())
        } else {
            Err(IkeError::AuthFailed)
        }
    }
}

/// The initiator's Phase-1 configuration.
pub struct InitiatorConfig {
    pub local_auth: Ikev1LocalAuth,
    /// Trusted CA certificates to validate the peer's chain against — only
    /// consulted when `local_auth` is `Sig`.
    pub trusted_cas: Vec<Vec<u8>>,
    /// Wall-clock time (Unix seconds) to check the peer's certificate
    /// validity against — only consulted when `local_auth` is `Sig`.
    pub now_unix: u64,
    /// AES-CBC key length to offer for Phase 1, in bytes (16/24/32 for
    /// AES-128/192/256 -- any other value is a caller bug, not a wire
    /// error). HASH stays fixed at SHA-256 (see [`initiator_sa`]'s doc);
    /// confirmed live against a real FortiGate IKEv1 gateway policy pinned
    /// to AES-192-CBC that negotiation fails outright ("no SA proposal
    /// chosen") when this app always offered AES-256 regardless of the
    /// profile's own configured cipher.
    pub key_len: usize,
    /// The identity we assert in `IDi`. Ignored (a DER-encoded cert subject
    /// DN is asserted instead) when `local_auth` is `Sig`.
    pub our_id: Id,
    /// DH group to offer (MODP-1024 or MODP-2048).
    pub group: DhGroup,
    /// Offer the XAUTH-PSK auth method — required by gateways that mandate XAUTH
    /// (e.g. Android's native client). With plain PSK, Quick Mode follows directly.
    pub xauth: bool,
    /// `(user, password)` to answer the gateway's XAUTH challenge with, once
    /// Phase 1 completes — see [`super::xauth`]. Only consulted when `xauth`
    /// is set; `None` with `xauth: true` means "offer XAUTH-PSK but don't
    /// actually answer a challenge" (only useful for testing the SA
    /// negotiation itself, not a real connection).
    pub xauth_creds: Option<(Vec<u8>, Vec<u8>)>,
    /// Quick-Mode traffic selectors offered as IDci/IDcr: `(address, netmask)`.
    pub ts_local: ([u8; 4], [u8; 4]),
    pub ts_remote: ([u8; 4], [u8; 4]),
    /// The ESP cipher to offer for the CHILD SA (Quick Mode's own SA
    /// payload) -- unlike Phase 1 (AES-CBC only, key length pluggable via
    /// [`InitiatorConfig::key_len`] but HASH still fixed at SHA-256, see
    /// [`initiator_sa`]'s doc), Phase 2 is fully algorithm-agile: any
    /// [`crate::ikev2::sk::SkCipher`] this crate implements works here,
    /// confirmed live against a real FortiGate that rejects a GCM offer
    /// outright and requires classic AES-CBC + a separate HMAC instead.
    pub esp_cipher: SkCipher,
    /// PFS DH group to request for Quick Mode, if any (RFC 2409 §5.5) --
    /// unlike IKEv2 (where PFS can only ever apply at a later
    /// `CREATE_CHILD_SA` rekey, never the initial tunnel), IKEv1 negotiates
    /// this on the very first Phase-2 exchange. `None` reproduces the
    /// original no-PFS behavior. See [`crate::ikev1::quick::initiate_quick_with_pfs`].
    pub pfs_group: Option<DhGroup>,
    /// Run an IKEv1 Mode-Config (`INTERNAL_IP4_*`) round after XAUTH (if any)
    /// and before Quick Mode -- see [`crate::ikev1::cfg`]. Required by
    /// gateways (confirmed live against a real FortiGate dialup policy) that
    /// reject the following Quick Mode proposal outright ("peer has not
    /// completed Configuration Method") if this round is skipped. `false`
    /// reproduces the original no-Mode-Config behavior.
    pub mode_cfg: bool,
    /// Also ask for IPv6 in the Mode-Config round (`INTERNAL_IP6_ADDRESS`/
    /// `_NETMASK`/`_DNS`/`_SUBNET`, see
    /// [`crate::ikev1::modecfg::ConfigPayload::request_dual_stack`]) and report
    /// what came back in [`crate::ikev1::client::Established::assigned_ip6`] and
    /// friends. Only consulted when `mode_cfg` is set. Off by default so a
    /// caller with no IPv6 data plane (there is no point asking) keeps sending
    /// the exact IPv4-only request it always did; the IPv6 CHILD SA itself is
    /// a separate Quick Mode the caller starts afterwards
    /// ([`crate::ikev1::quick::create_child_ipv6`]).
    pub ipv6: bool,
    /// Which Phase-1 exchange to run -- see [`Ikev1ExchangeMode`].
    pub mode: Ikev1ExchangeMode,
    /// Phase-1 SA lifetime to offer, in seconds (RFC 2407 §4.5 `LIFE_DURATION`,
    /// `LIFE_TYPE` fixed at seconds) -- the responder may echo back a shorter
    /// value; [`Phase1State::negotiated_lifetime_secs`] carries the value
    /// actually in force, not this offered one.
    pub p1_lifetime_secs: u32,
    /// CHILD SA (Quick Mode) lifetime to offer, in seconds -- same
    /// responder-may-shorten caveat, see [`crate::ikev1::quick::negotiated_p2_lifetime`].
    pub p2_lifetime_secs: u32,
}

/// Which IKEv1 Phase-1 exchange the initiator runs: [`initiate_aggressive`]
/// (1 round trip, `IDi` sent in the clear) or [`initiate_main`] (3 round
/// trips, `IDi`/`IDr` protected under `SKEYID_e` -- RFC 2409's "Identity
/// Protection" exchange, needed by gateway policies that specifically
/// require it). `Aggressive` is the default: every existing caller/saved
/// profile keeps behaving exactly as it did before this enum existed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Ikev1ExchangeMode {
    #[default]
    Aggressive,
    Main,
}

/// The initiator's SA offer: AES-CBC (`key_len` bytes) / SHA-256 / `group` /
/// one of PSK, XAUTH-PSK, RSA-SIG, XAUTH-RSA (`want_sig` selects the RSA-SIG
/// pair).
fn initiator_sa(group: DhGroup, xauth: bool, want_sig: bool, key_len: usize, life_duration: u32) -> SaPayload {
    let auth_method = match (want_sig, xauth) {
        (false, false) => auth::PSK,
        (false, true) => auth::XAUTH_INIT_PSK,
        (true, false) => auth::RSA_SIG,
        (true, true) => auth::XAUTH_INIT_RSA,
    };
    SaPayload {
        doi: IPSEC_DOI,
        situation: SIT_IDENTITY_ONLY,
        proposals: vec![Proposal {
            num: 1,
            protocol_id: protocol::ISAKMP,
            spi: Vec::new(),
            transforms: vec![Transform {
                num: 1,
                transform_id: 1,
                attributes: vec![
                    Attribute::short(attr::ENCRYPTION, enc::AES_CBC),
                    Attribute::short(attr::KEY_LENGTH, (key_len * 8) as u16),
                    Attribute::short(attr::HASH, hash::SHA2_256),
                    Attribute::short(attr::GROUP_DESC, group.transform_id()),
                    Attribute::short(attr::AUTH_METHOD, auth_method),
                    Attribute::short(attr::LIFE_TYPE, life::SECONDS),
                    Attribute::long_u32(attr::LIFE_DURATION, life_duration),
                ],
            }],
        }],
    }
}

/// Post-message-1 initiator state, carrying the ephemerals needed to finish
/// Aggressive Mode once the responder's message 2 arrives.
pub struct AggressiveInitiator {
    prf: Prf,
    group: DhGroup,
    psk: Vec<u8>,
    cky_i: [u8; 8],
    dh_private: [u8; 32],
    gxi: Vec<u8>,
    ni: Vec<u8>,
    idi_b: Vec<u8>,
    sai_b: Vec<u8>,
    key_len: usize,
    offered_p1_lifetime: u32,
}

/// Build Aggressive-Mode message 1 (`HDR, SA, KE, Ni, IDi`) as the initiator.
/// Returns the wire bytes and the state that completes the exchange.
/// `our_addr`/`peer_addr` are only used for RFC 3947 NAT-D (see
/// [`natd_payloads`]'s doc): the cookies aren't both known yet at this point
/// (`CKY-R` doesn't exist until the responder picks one), so the pair added
/// here necessarily hashes with `CKY-R` all-zero -- exactly what this
/// message's own header carries at this point, so a responder recomputing
/// the same hash from the raw wire bytes agrees.
pub fn initiate_aggressive(cfg: &InitiatorConfig, entropy: &mut impl Entropy, our_addr: SocketAddr, peer_addr: SocketAddr) -> (Vec<u8>, AggressiveInitiator) {
    let prf = Prf::Sha256;
    let mut cky_i = [0u8; 8];
    entropy.fill(&mut cky_i);
    let dh_private = entropy.next_array32();
    let gxi = cfg.group.public(&dh_private);
    let mut ni = vec![0u8; 16];
    entropy.fill(&mut ni);

    let sa = initiator_sa(cfg.group, cfg.xauth, false, cfg.key_len, cfg.p1_lifetime_secs);
    let sai_b = sa.to_bytes();
    let idi_b = cfg.our_id.to_bytes();

    let hdr = IsakmpHeader {
        init_cookie: cky_i,
        resp_cookie: [0; 8],
        next_payload: payload::NONE,
        version: IsakmpHeader::VERSION_1_0,
        exchange_type: exchange::AGGRESSIVE,
        flags: 0,
        message_id: 0,
        length: 0,
    };
    let mut payloads = vec![
        (payload::SA, sai_b.clone()),
        (payload::KE, gxi.clone()),
        (payload::NONCE, ni.clone()),
        (payload::ID, idi_b.clone()),
        (payload::VENDOR_ID, DPD_VENDOR_ID.to_vec()),
        (payload::VENDOR_ID, NATT_RFC_VENDOR_ID.to_vec()),
    ];
    payloads.extend(natd_payloads(prf, cky_i, [0; 8], peer_addr, our_addr));
    let msg1 = isakmp::build_message(hdr, &payloads);

    let state = AggressiveInitiator {
        prf,
        group: cfg.group,
        psk: cfg.local_auth.expect_psk().to_vec(),
        cky_i,
        dh_private,
        gxi,
        ni,
        idi_b,
        sai_b,
        key_len: cfg.key_len,
        offered_p1_lifetime: cfg.p1_lifetime_secs,
    };
    (msg1, state)
}

impl AggressiveInitiator {
    /// Process message 2 (`HDR, SA, KE, Nr, IDr, HASH_R`): verify the responder's
    /// `HASH_R`, and return message 3 (`HDR, HASH_I`) plus the completed Phase-1
    /// state ready to drive Quick Mode. `our_addr`/`peer_addr` are this
    /// side's own view of both endpoints (RFC 3947 NAT-D, see
    /// [`natd_float_needed`]) -- the resulting [`Phase1State::floated`]
    /// decides whether message 3 (and everything after it) needs to go out
    /// on UDP 4500 instead of 500.
    pub fn complete(self, msg2: &[u8], our_addr: SocketAddr, peer_addr: SocketAddr) -> Result<(Vec<u8>, Phase1State), IkeError> {
        let hdr = IsakmpHeader::parse(msg2)?;
        if hdr.exchange_type != exchange::AGGRESSIVE {
            return Err(IkeError::Crypto("not an Aggressive Mode message"));
        }
        if hdr.init_cookie != self.cky_i {
            return Err(IkeError::Crypto("cookie mismatch"));
        }
        let cky_r = hdr.resp_cookie;
        let ps = isakmp::parse_payloads(hdr.next_payload, &msg2[IsakmpHeader::LEN..])?;
        let gxr = find(&ps, payload::KE).ok_or(IkeError::MissingPayload("KE"))?.data.clone();
        let nr = find(&ps, payload::NONCE).ok_or(IkeError::MissingPayload("NONCE"))?.data.clone();
        isakmp::check_nonce_len(&nr)?;
        let hash_r_got = find(&ps, payload::HASH).ok_or(IkeError::MissingPayload("HASH"))?.data.clone();
        let idr_b = find(&ps, payload::ID).ok_or(IkeError::MissingPayload("ID"))?.data.clone();
        let peer_supports_dpd = ps.iter().any(|p| p.payload_type == payload::VENDOR_ID && p.data == DPD_VENDOR_ID);
        let negotiated_lifetime_secs = negotiated_p1_lifetime(&ps, self.offered_p1_lifetime);
        // By message 2, both cookies are genuinely known, so this uses the
        // real `cky_r` (unlike message 1's own NAT-D, necessarily hashed
        // with CKY-R all-zero -- see `initiate_aggressive`'s doc).
        let floated = natd_float_needed(&ps, peer_offers_natt(&ps), self.prf, self.cky_i, cky_r, our_addr, peer_addr);

        if gxr.len() != self.group.public_len() {
            return Err(IkeError::BadKeyExchange { group: self.group.transform_id(), len: gxr.len() });
        }
        let gxy = self.group.shared(&self.dh_private, &gxr)?;
        let skeyid = crypto1::skeyid_psk(self.prf, &self.psk, &self.ni, &nr);

        // Authenticate the responder: HASH_R = prf(SKEYID, g^xr|g^xi|CKY-R|CKY-I|SAi_b|IDir_b).
        let expect_hr = crypto1::hash_r(self.prf, &skeyid, &gxr, &self.gxi, &cky_r, &self.cky_i, &self.sai_b, &idr_b);
        if hash_r_got != expect_hr {
            return Err(IkeError::AuthFailed);
        }

        // HASH_I = prf(SKEYID, g^xi|g^xr|CKY-I|CKY-R|SAi_b|IDii_b).
        let hash_i = crypto1::hash_i(self.prf, &skeyid, &self.gxi, &gxr, &self.cky_i, &cky_r, &self.sai_b, &self.idi_b);
        let hdr3 = IsakmpHeader {
            init_cookie: self.cky_i,
            resp_cookie: cky_r,
            next_payload: payload::NONE,
            version: IsakmpHeader::VERSION_1_0,
            exchange_type: exchange::AGGRESSIVE,
            flags: 0,
            message_id: 0,
            length: 0,
        };
        let msg3 = isakmp::build_message(hdr3, &[(payload::HASH, hash_i)]);

        let skeyid_d = crypto1::skeyid_d(self.prf, &skeyid, &gxy, &self.cky_i, &cky_r);
        let skeyid_a = crypto1::skeyid_a(self.prf, &skeyid, &skeyid_d, &gxy, &self.cky_i, &cky_r);
        let skeyid_e = crypto1::skeyid_e(self.prf, &skeyid, &skeyid_a, &gxy, &self.cky_i, &cky_r);
        let enc_key = crypto1::derive_cipher_key(self.prf, &skeyid_e, self.key_len);
        let phase1_iv = crypto1::phase1_iv(self.prf, &self.gxi, &gxr, AES_BLOCK);

        let state = Phase1State {
            prf: self.prf,
            group: self.group,
            cky_i: self.cky_i,
            cky_r,
            skeyid,
            skeyid_d,
            skeyid_a,
            skeyid_e,
            enc_key,
            phase1_iv,
            gxi: self.gxi,
            gxr,
            ni: self.ni,
            nr,
            sai_b: self.sai_b,
            idii_b: self.idi_b,
            peer_supports_dpd,
            floated,
            negotiated_lifetime_secs,
        };
        Ok((msg3, state))
    }
}

// ---- Main Mode (RFC 2409 §5.1/5.4, PSK — "Identity Protection") ----
//
// ```text
// I → HDR, SA                          (msg1)
// R → HDR, SA                          (msg2)
// I → HDR, KE, Ni, VID(DPD)            (msg3)
// R → HDR, KE, Nr, VID(DPD)            (msg4)
// I* → HDR, IDi, HASH_I                (msg5, encrypted under SKEYID_e)
// R* → HDR, IDr, HASH_R                (msg6, encrypted under SKEYID_e)
// ```
//
// `HASH_I`/`HASH_R` are the exact formulas Aggressive Mode already computes
// (`crypto1::hash_i`/`hash_r`) — only *when* IDi/IDr become available
// differs. Messages 5/6 reuse [`phase2`]'s IV-chaining helpers: message 5 (the
// first encrypted message of the exchange) seeds its IV from `phase1_iv`
// itself (the same seed `Phase1State::verify_hash_i` already uses for
// Aggressive Mode's optionally-encrypted message 3), and message 6 chains
// from message 5's last ciphertext block — both messages are still
// message-id 0 (Phase 1 itself), not a `phase2_iv`-keyed post-Phase-1
// exchange.
//
// Unlike Aggressive Mode (where the initiator verifies HASH_R from message 2
// *before* ever sending its own HASH_I), Main Mode's ordering has the
// initiator send HASH_I (message 5) *before* it has seen the responder's
// HASH_R (message 6) — that's the point of identity protection: IDi must go
// out before the responder is willing to reveal IDr. So the initiator's chain
// has a fourth step ([`MainIdSent::complete_id`]) the other three don't:
// only once message 6 arrives and its HASH_R verifies does a [`Phase1State`]
// come back, preserving the same "callers only ever get an
// already-authenticated `Phase1State`" contract [`AggressiveInitiator::complete`]
// upholds. (An earlier sketch of this API returned `Phase1State` straight out
// of the message-4 step, before message 6 was even seen — that would have
// handed the caller an unauthenticated tunnel; caught and fixed while
// implementing, not carried through.)

/// Build Main-Mode message 1 (`HDR, SA`) as the initiator.
pub fn initiate_main(cfg: &InitiatorConfig, entropy: &mut impl Entropy) -> (Vec<u8>, MainSaSent) {
    let mut cky_i = [0u8; 8];
    entropy.fill(&mut cky_i);
    let want_sig = matches!(cfg.local_auth, Ikev1LocalAuth::Sig { .. });
    let sa = initiator_sa(cfg.group, cfg.xauth, want_sig, cfg.key_len, cfg.p1_lifetime_secs);
    let sai_b = sa.to_bytes();

    let hdr = IsakmpHeader {
        init_cookie: cky_i,
        resp_cookie: [0; 8],
        next_payload: payload::NONE,
        version: IsakmpHeader::VERSION_1_0,
        exchange_type: exchange::MAIN,
        flags: 0,
        message_id: 0,
        length: 0,
    };
    let msg1 = isakmp::build_message(hdr, &[
        (payload::SA, sai_b.clone()),
        // RFC 3947 NAT-T VID: sent alongside SA in messages 1/2, not 3/4
        // like `DPD_VENDOR_ID` -- matching isakmpd's own placement
        // (`ike_phase_1_initiator_send_SA`) exactly, since a responder that
        // gates its own NAT-D (msg3/4) on having already seen this VID here
        // would otherwise never send one back.
        (payload::VENDOR_ID, NATT_RFC_VENDOR_ID.to_vec()),
    ]);

    let state = MainSaSent {
        group: cfg.group,
        key_len: cfg.key_len,
        local_auth: cfg.local_auth.clone(),
        trusted_cas: cfg.trusted_cas.clone(),
        now_unix: cfg.now_unix,
        our_id: cfg.our_id.clone(),
        cky_i,
        sai_b,
        offered_p1_lifetime: cfg.p1_lifetime_secs,
    };
    (msg1, state)
}

/// Post-message-1 Main-Mode initiator state.
pub struct MainSaSent {
    group: DhGroup,
    key_len: usize,
    local_auth: Ikev1LocalAuth,
    trusted_cas: Vec<Vec<u8>>,
    now_unix: u64,
    our_id: Id,
    cky_i: [u8; 8],
    sai_b: Vec<u8>,
    offered_p1_lifetime: u32,
}

impl MainSaSent {
    /// Process message 2 (`HDR, SA, [VID(RFC 3947)]`) and build message 3
    /// (`HDR, KE, Ni, VID(DPD), [NAT-D, NAT-D]`). `our_addr`/`peer_addr` are
    /// this side's own view of both endpoints, only used to compute the
    /// NAT-D pair added when the responder's message 2 advertised NAT-T
    /// support.
    pub fn complete_sa(self, msg2: &[u8], entropy: &mut impl Entropy, our_addr: SocketAddr, peer_addr: SocketAddr) -> Result<(Vec<u8>, MainKeSent), IkeError> {
        let hdr = IsakmpHeader::parse(msg2)?;
        if hdr.exchange_type != exchange::MAIN {
            return Err(IkeError::Crypto("not a Main Mode message"));
        }
        if hdr.init_cookie != self.cky_i {
            return Err(IkeError::Crypto("cookie mismatch"));
        }
        let cky_r = hdr.resp_cookie;
        let ps = isakmp::parse_payloads(hdr.next_payload, &msg2[IsakmpHeader::LEN..])?;
        find(&ps, payload::SA).ok_or(IkeError::MissingPayload("SA"))?;
        let peer_supports_natt = peer_offers_natt(&ps);
        let negotiated_p1_lifetime_secs = negotiated_p1_lifetime(&ps, self.offered_p1_lifetime);

        let dh_private = entropy.next_array32();
        let gxi = self.group.public(&dh_private);
        let mut ni = vec![0u8; 16];
        entropy.fill(&mut ni);

        let hdr3 = IsakmpHeader {
            init_cookie: self.cky_i,
            resp_cookie: cky_r,
            next_payload: payload::NONE,
            version: IsakmpHeader::VERSION_1_0,
            exchange_type: exchange::MAIN,
            flags: 0,
            message_id: 0,
            length: 0,
        };
        let mut payloads3 = vec![
            (payload::KE, gxi.clone()),
            (payload::NONCE, ni.clone()),
            (payload::VENDOR_ID, DPD_VENDOR_ID.to_vec()),
        ];
        if peer_supports_natt {
            payloads3.extend(natd_payloads(Prf::Sha256, self.cky_i, cky_r, peer_addr, our_addr));
        }
        let msg3 = isakmp::build_message(hdr3, &payloads3);

        let state = MainKeSent {
            group: self.group,
            key_len: self.key_len,
            local_auth: self.local_auth,
            trusted_cas: self.trusted_cas,
            now_unix: self.now_unix,
            our_id: self.our_id,
            cky_i: self.cky_i,
            cky_r,
            sai_b: self.sai_b,
            dh_private,
            gxi,
            ni,
            peer_supports_natt,
            our_addr,
            peer_addr,
            negotiated_p1_lifetime_secs,
        };
        Ok((msg3, state))
    }
}

/// Post-message-3 Main-Mode initiator state.
pub struct MainKeSent {
    group: DhGroup,
    key_len: usize,
    local_auth: Ikev1LocalAuth,
    trusted_cas: Vec<Vec<u8>>,
    now_unix: u64,
    our_id: Id,
    cky_i: [u8; 8],
    cky_r: [u8; 8],
    sai_b: Vec<u8>,
    dh_private: [u8; 32],
    gxi: Vec<u8>,
    ni: Vec<u8>,
    /// Whether the responder's message 2 advertised RFC 3947 support --
    /// decided back in `complete_sa` (message 2, where the VID lives), since
    /// message 4 (processed here) never repeats it -- see
    /// `natd_float_needed`'s doc on why this is threaded through explicitly
    /// rather than re-derived per message.
    peer_supports_natt: bool,
    our_addr: SocketAddr,
    peer_addr: SocketAddr,
    negotiated_p1_lifetime_secs: u32,
}

impl MainKeSent {
    /// Process message 4 (`HDR, KE, Nr, [VID(DPD)], [NAT-D, NAT-D]`), derive
    /// the Phase-1 key schedule, and build message 5 (`HDR*, IDi, HASH_I`,
    /// encrypted). Whether message 5 (and everything after it) needs to go
    /// out floated on UDP 4500 is decided here -- see
    /// [`MainIdSent::floated`]/[`Phase1State::floated`]'s doc.
    pub fn complete_ke(self, msg4: &[u8]) -> Result<(Vec<u8>, MainIdSent), IkeError> {
        let hdr = IsakmpHeader::parse(msg4)?;
        if hdr.exchange_type != exchange::MAIN {
            return Err(IkeError::Crypto("not a Main Mode message"));
        }
        if hdr.init_cookie != self.cky_i || hdr.resp_cookie != self.cky_r {
            return Err(IkeError::Crypto("cookie mismatch"));
        }
        let ps = isakmp::parse_payloads(hdr.next_payload, &msg4[IsakmpHeader::LEN..])?;
        let gxr = find(&ps, payload::KE).ok_or(IkeError::MissingPayload("KE"))?.data.clone();
        let nr = find(&ps, payload::NONCE).ok_or(IkeError::MissingPayload("NONCE"))?.data.clone();
        isakmp::check_nonce_len(&nr)?;
        let peer_supports_dpd = ps.iter().any(|p| p.payload_type == payload::VENDOR_ID && p.data == DPD_VENDOR_ID);
        let floated = natd_float_needed(&ps, self.peer_supports_natt, Prf::Sha256, self.cky_i, self.cky_r, self.our_addr, self.peer_addr);

        if gxr.len() != self.group.public_len() {
            return Err(IkeError::BadKeyExchange { group: self.group.transform_id(), len: gxr.len() });
        }
        let prf = Prf::Sha256;
        let gxy = self.group.shared(&self.dh_private, &gxr)?;
        let skeyid = match &self.local_auth {
            Ikev1LocalAuth::Psk(psk) => crypto1::skeyid_psk(prf, psk, &self.ni, &nr),
            Ikev1LocalAuth::Sig { .. } => crypto1::skeyid_sig(prf, &self.ni, &nr, &gxy),
        };
        let skeyid_d = crypto1::skeyid_d(prf, &skeyid, &gxy, &self.cky_i, &self.cky_r);
        let skeyid_a = crypto1::skeyid_a(prf, &skeyid, &skeyid_d, &gxy, &self.cky_i, &self.cky_r);
        let skeyid_e = crypto1::skeyid_e(prf, &skeyid, &skeyid_a, &gxy, &self.cky_i, &self.cky_r);
        let enc_key = crypto1::derive_cipher_key(prf, &skeyid_e, self.key_len);
        let phase1_iv = crypto1::phase1_iv(prf, &self.gxi, &gxr, AES_BLOCK);

        // §5.1 (Sig): IDii is the DER-encoded subject DN of our own leaf cert,
        // not the configured `our_id` -- matching isakmpd's
        // `x509_cert_get_subjects` and the already-live-confirmed IKEv2 cert
        // convention (`cert_subject_dn`).
        let idi_b = match &self.local_auth {
            Ikev1LocalAuth::Psk(_) => self.our_id.to_bytes(),
            Ikev1LocalAuth::Sig { chain, .. } => Id {
                id_type: id_type::DER_ASN1_DN,
                protocol: 0,
                port: 0,
                data: cert_subject_dn(&chain[0])?,
            }
            .to_bytes(),
        };
        let hash_i = crypto1::hash_i(prf, &skeyid, &self.gxi, &gxr, &self.cky_i, &self.cky_r, &self.sai_b, &idi_b);

        let hdr5 = IsakmpHeader {
            init_cookie: self.cky_i,
            resp_cookie: self.cky_r,
            next_payload: payload::NONE,
            version: IsakmpHeader::VERSION_1_0,
            exchange_type: exchange::MAIN,
            flags: 0,
            message_id: 0,
            length: 0,
        };
        // §5.1 (Sig): CERT (one per chain cert) + SIG (a raw PKCS#1 v1.5
        // signature over `hash_i`, RFC 2409's SIG payload convention) instead
        // of a HASH payload -- see `sign_classic_rsa_raw`'s doc.
        let out_payloads: Vec<(u8, Vec<u8>)> = match &self.local_auth {
            Ikev1LocalAuth::Psk(_) => vec![(payload::ID, idi_b.clone()), (payload::HASH, hash_i)],
            Ikev1LocalAuth::Sig { key, chain } => {
                let sig = key.sign_classic_rsa_raw(&hash_i)?;
                let mut out = vec![(payload::ID, idi_b.clone())];
                out.extend(chain.iter().map(|cert| (payload::CERT, cert_payload_body(cert))));
                out.push((payload::SIG, sig));
                out
            }
        };
        let (msg5, iv_after_msg5) = phase2::encrypt_payloads(hdr5, &enc_key, &phase1_iv, &out_payloads)?;

        let state = MainIdSent {
            prf,
            group: self.group,
            cky_i: self.cky_i,
            cky_r: self.cky_r,
            skeyid,
            skeyid_d,
            skeyid_a,
            skeyid_e,
            enc_key,
            gxi: self.gxi,
            gxr,
            ni: self.ni,
            nr,
            sai_b: self.sai_b,
            idi_b,
            trusted_cas: self.trusted_cas,
            now_unix: self.now_unix,
            is_sig: matches!(self.local_auth, Ikev1LocalAuth::Sig { .. }),
            iv_after_msg5,
            peer_supports_dpd,
            floated,
            negotiated_p1_lifetime_secs: self.negotiated_p1_lifetime_secs,
        };
        Ok((msg5, state))
    }
}

/// Post-message-5 Main-Mode initiator state: the key schedule is derived and
/// message 5 is already sent — only the responder's message 6 (`HASH_R`/`SIG`)
/// remains to be verified before Phase 1 can be trusted.
pub struct MainIdSent {
    prf: Prf,
    group: DhGroup,
    cky_i: [u8; 8],
    cky_r: [u8; 8],
    skeyid: Vec<u8>,
    skeyid_d: Vec<u8>,
    skeyid_a: Vec<u8>,
    skeyid_e: Vec<u8>,
    enc_key: Vec<u8>,
    gxi: Vec<u8>,
    gxr: Vec<u8>,
    ni: Vec<u8>,
    nr: Vec<u8>,
    sai_b: Vec<u8>,
    idi_b: Vec<u8>,
    trusted_cas: Vec<Vec<u8>>,
    now_unix: u64,
    is_sig: bool,
    /// Not the raw `HASH(g^xi|g^xr)` Phase-1 seed -- that's only needed to
    /// encrypt message 5 itself (already consumed by the time this struct
    /// exists). This is the IV chained forward past message 5's own
    /// ciphertext, needed to decrypt message 6.
    iv_after_msg5: Vec<u8>,
    peer_supports_dpd: bool,
    /// Whether NAT-D (message 3/4) decided this exchange must float to UDP
    /// 4500 -- `pub` (unlike this struct's other fields) because the caller
    /// (`Client::connect`) needs to check it *before* sending message 5,
    /// which this struct is returned alongside, same reasoning as
    /// [`Phase1State::floated`]'s own doc.
    pub floated: bool,
    negotiated_p1_lifetime_secs: u32,
}

/// [`MainIdSent::complete_id`]'s error case: the responder's AUTH did not
/// verify, but SKEYID_a/SKEYID_e were already derived from the DH exchange
/// alone (RFC 2409 App. B -- Main Mode's own identity-protection property is
/// that messages 5/6 are encrypted *before* either side's identity is
/// checked), so this side can still send a real, correctly authenticated and
/// encrypted ISAKMP Delete for the cookie pair it just rejected, instead of
/// silently vanishing and leaving the gateway to notice only once its own
/// DPD/lifetime timer expires.
#[derive(Debug)]
pub struct AuthFailure {
    pub error: IkeError,
    /// `None` when even building the Delete itself failed (e.g. the entropy
    /// source is down) — never withheld just because AUTH failed. The caller
    /// should send this best-effort (its own doc: Deletes are fire-and-forget,
    /// no ack expected) before propagating `error`.
    pub teardown: Option<Vec<u8>>,
}

impl From<IkeError> for AuthFailure {
    /// Wraps a hard parse/structural failure (message 6 didn't even decrypt,
    /// or was missing a required payload) that leaves nothing trustworthy to
    /// build a Delete from.
    fn from(error: IkeError) -> Self {
        AuthFailure { error, teardown: None }
    }
}

impl MainIdSent {
    /// Process message 6 (`HDR*, IDr, HASH_R` or `HDR*, IDr, CERT.., SIG`,
    /// encrypted): verify the responder's authentication and return the
    /// completed, authenticated [`Phase1State`]. On an AUTH failure specifically
    /// (as opposed to a malformed message), see [`AuthFailure`]'s doc for why the
    /// error carries a teardown Delete the caller should send.
    pub fn complete_id(self, msg6: &[u8], entropy: &mut impl Entropy) -> Result<Phase1State, AuthFailure> {
        let (_hdr, ps, iv_after_msg6) = phase2::decrypt_payloads(msg6, &self.enc_key, &self.iv_after_msg5)?;
        let idr_b = find(&ps, payload::ID).ok_or(IkeError::MissingPayload("ID"))?.data.clone();
        let expect_hr = crypto1::hash_r(self.prf, &self.skeyid, &self.gxr, &self.gxi, &self.cky_r, &self.cky_i, &self.sai_b, &idr_b);
        let verify: Result<(), IkeError> = (|| {
            if self.is_sig {
                let certs = collect_certs(&ps)?;
                let sig = find(&ps, payload::SIG).ok_or(IkeError::MissingPayload("SIG"))?.data.clone();
                if let Ok((subject, issuer)) = cert_subject_issuer_display(&certs[0]) {
                    ike_debug!(
                        "Main Mode: gateway sent {} certificate(s); leaf subject='{subject}' issuer='{issuer}'",
                        certs.len()
                    );
                }
                if let Err(e) = validate_chain(&certs[0], &certs[1..], &self.trusted_cas, self.now_unix) {
                    ike_debug!(
                        "Main Mode: gateway certificate chain did not validate against the trust store ({} intermediate(s) sent) -- \
                         likely a missing intermediate CA in the gateway's CERT payload, or the leaf's issuer isn't a trusted root: {e}",
                        certs.len().saturating_sub(1)
                    );
                    return Err(e);
                }
                if let Err(e) = VerifyingKey::from_cert_der(&certs[0])?.verify_classic_rsa_raw(&sig, &expect_hr) {
                    ike_debug!("Main Mode: gateway certificate chain is trusted, but its SIG payload did not verify: {e}");
                    return Err(e);
                }
            } else {
                let hash_r_got = find(&ps, payload::HASH).ok_or(IkeError::MissingPayload("HASH"))?.data.clone();
                if hash_r_got != expect_hr {
                    return Err(IkeError::AuthFailed);
                }
            }
            Ok(())
        })();
        let state = Phase1State {
            prf: self.prf,
            group: self.group,
            cky_i: self.cky_i,
            cky_r: self.cky_r,
            skeyid: self.skeyid,
            skeyid_d: self.skeyid_d,
            skeyid_a: self.skeyid_a,
            skeyid_e: self.skeyid_e,
            enc_key: self.enc_key,
            // NOT `self.phase1_iv` (the raw `HASH(g^xi|g^xr)` seed used only
            // to encrypt message 5) -- RFC 2409 App. B seeds the first
            // post-Phase-1 message's IV from the IV *after the last
            // encrypted Phase-1 message*. Main Mode encrypts two messages
            // (5 and 6), so that's the IV chained forward past message 6,
            // not the original seed. (Aggressive Mode's equivalent field
            // happens to equal its own raw seed only because this crate's
            // `AggressiveInitiator` sends message 3 unencrypted -- there is
            // no second encrypted message to chain past. Confirmed live:
            // using the raw seed here made the gateway's very first
            // post-Phase-1 message -- its XAUTH request -- fail to decrypt,
            // even though Phase 1 itself completed and authenticated
            // correctly on both sides.)
            phase1_iv: iv_after_msg6,
            gxi: self.gxi,
            gxr: self.gxr,
            ni: self.ni,
            nr: self.nr,
            sai_b: self.sai_b,
            idii_b: self.idi_b,
            peer_supports_dpd: self.peer_supports_dpd,
            floated: self.floated,
            negotiated_lifetime_secs: self.negotiated_p1_lifetime_secs,
        };
        match verify {
            Ok(()) => Ok(state),
            Err(error) => {
                let teardown = super::informational::build_isakmp_delete(&state, entropy).ok();
                Err(AuthFailure { error, teardown })
            }
        }
    }
}

// ---- Main Mode responder (for self-testing against `ikev1::Client`) ----

/// Process Main-Mode message 1 (`HDR, SA, [VID(RFC 3947)]`) and build
/// message 2 (`HDR, SA, VID(RFC 3947)`), choosing a fresh responder cookie
/// and echoing the selected transform. The RFC 3947 VID is sent
/// unconditionally, independent of whether the initiator advertised
/// support (matching isakmpd's own `ike_phase_1_responder_send_SA` and this
/// crate's existing `DPD_VENDOR_ID` "advertise unconditionally" precedent).
pub fn respond_main(cfg: &Phase1Config, msg1: &[u8], entropy: &mut impl Entropy, our_addr: SocketAddr, peer_addr: SocketAddr) -> Result<(Vec<u8>, MainRespSaSent), IkeError> {
    let hdr = IsakmpHeader::parse(msg1)?;
    if hdr.exchange_type != exchange::MAIN {
        return Err(IkeError::Crypto("not a Main Mode message"));
    }
    if hdr.message_id != 0 {
        return Err(IkeError::Crypto("phase 1 message_id must be zero"));
    }
    let cky_i = hdr.init_cookie;
    let ps = isakmp::parse_payloads(hdr.next_payload, &msg1[IsakmpHeader::LEN..])?;
    let sa_p = find(&ps, payload::SA).ok_or(IkeError::MissingPayload("SA"))?;
    let sai_b = sa_p.data.clone();
    let sa = SaPayload::parse(&sai_b)?;
    let want_sig = matches!(cfg.local_auth, Ikev1LocalAuth::Sig { .. });
    let (chosen, prf, group, key_len) = select_transform(&sa, want_sig).ok_or(IkeError::NoProposalChosen)?;
    let initiator_offered_lifetime = chosen.attr_u32(attr::LIFE_DURATION).unwrap_or(0);
    let peer_supports_natt = peer_offers_natt(&ps);

    let mut cky_r = [0u8; 8];
    entropy.fill(&mut cky_r);

    let sar = SaPayload {
        doi: sa.doi,
        situation: sa.situation,
        proposals: vec![Proposal { num: 1, protocol_id: protocol::ISAKMP, spi: Vec::new(), transforms: vec![chosen] }],
    };
    let hdr2 = IsakmpHeader {
        init_cookie: cky_i,
        resp_cookie: cky_r,
        next_payload: payload::NONE,
        version: IsakmpHeader::VERSION_1_0,
        exchange_type: exchange::MAIN,
        flags: 0,
        message_id: 0,
        length: 0,
    };
    let msg2 = isakmp::build_message(hdr2, &[
        (payload::SA, sar.to_bytes()),
        (payload::VENDOR_ID, NATT_RFC_VENDOR_ID.to_vec()),
    ]);

    let state = MainRespSaSent {
        prf,
        group,
        key_len,
        cky_i,
        cky_r,
        local_auth: cfg.local_auth.clone(),
        trusted_cas: cfg.trusted_cas.clone(),
        now_unix: cfg.now_unix,
        our_id: cfg.our_id.clone(),
        sai_b,
        peer_supports_natt,
        our_addr,
        peer_addr,
        initiator_offered_lifetime,
    };
    Ok((msg2, state))
}

/// Post-message-2 Main-Mode responder state.
pub struct MainRespSaSent {
    prf: Prf,
    group: DhGroup,
    key_len: usize,
    cky_i: [u8; 8],
    cky_r: [u8; 8],
    local_auth: Ikev1LocalAuth,
    trusted_cas: Vec<Vec<u8>>,
    now_unix: u64,
    our_id: Id,
    sai_b: Vec<u8>,
    peer_supports_natt: bool,
    our_addr: SocketAddr,
    peer_addr: SocketAddr,
    initiator_offered_lifetime: u32,
}

impl MainRespSaSent {
    /// Process message 3 (`HDR, KE, Ni, [VID(DPD)], [NAT-D, NAT-D]`) and
    /// build message 4 (`HDR, KE, Nr, VID(DPD), [NAT-D, NAT-D]`).
    pub fn complete_ke(self, msg3: &[u8], entropy: &mut impl Entropy) -> Result<(Vec<u8>, MainRespKeSent), IkeError> {
        let hdr = IsakmpHeader::parse(msg3)?;
        if hdr.exchange_type != exchange::MAIN {
            return Err(IkeError::Crypto("not a Main Mode message"));
        }
        let ps = isakmp::parse_payloads(hdr.next_payload, &msg3[IsakmpHeader::LEN..])?;
        let gxi = find(&ps, payload::KE).ok_or(IkeError::MissingPayload("KE"))?.data.clone();
        let ni = find(&ps, payload::NONCE).ok_or(IkeError::MissingPayload("NONCE"))?.data.clone();
        isakmp::check_nonce_len(&ni)?;
        let peer_supports_dpd = ps.iter().any(|p| p.payload_type == payload::VENDOR_ID && p.data == DPD_VENDOR_ID);
        let floated = natd_float_needed(&ps, self.peer_supports_natt, self.prf, self.cky_i, self.cky_r, self.our_addr, self.peer_addr);

        if gxi.len() != self.group.public_len() {
            return Err(IkeError::BadKeyExchange { group: self.group.transform_id(), len: gxi.len() });
        }
        let dh_private = entropy.next_array32();
        let gxr = self.group.public(&dh_private);
        let mut nr = vec![0u8; 16];
        entropy.fill(&mut nr);

        let hdr4 = IsakmpHeader {
            init_cookie: self.cky_i,
            resp_cookie: self.cky_r,
            next_payload: payload::NONE,
            version: IsakmpHeader::VERSION_1_0,
            exchange_type: exchange::MAIN,
            flags: 0,
            message_id: 0,
            length: 0,
        };
        let mut payloads4 = vec![
            (payload::KE, gxr.clone()),
            (payload::NONCE, nr.clone()),
            (payload::VENDOR_ID, DPD_VENDOR_ID.to_vec()),
        ];
        if self.peer_supports_natt {
            payloads4.extend(natd_payloads(self.prf, self.cky_i, self.cky_r, self.peer_addr, self.our_addr));
        }
        let msg4 = isakmp::build_message(hdr4, &payloads4);

        let state = MainRespKeSent {
            prf: self.prf,
            group: self.group,
            key_len: self.key_len,
            cky_i: self.cky_i,
            cky_r: self.cky_r,
            local_auth: self.local_auth,
            trusted_cas: self.trusted_cas,
            now_unix: self.now_unix,
            our_id: self.our_id,
            sai_b: self.sai_b,
            gxi,
            gxr,
            dh_private,
            ni,
            nr,
            peer_supports_dpd,
            floated,
            initiator_offered_lifetime: self.initiator_offered_lifetime,
        };
        Ok((msg4, state))
    }
}

/// Post-message-4 Main-Mode responder state.
pub struct MainRespKeSent {
    prf: Prf,
    group: DhGroup,
    key_len: usize,
    cky_i: [u8; 8],
    cky_r: [u8; 8],
    local_auth: Ikev1LocalAuth,
    trusted_cas: Vec<Vec<u8>>,
    now_unix: u64,
    our_id: Id,
    sai_b: Vec<u8>,
    gxi: Vec<u8>,
    gxr: Vec<u8>,
    dh_private: [u8; 32],
    ni: Vec<u8>,
    nr: Vec<u8>,
    peer_supports_dpd: bool,
    floated: bool,
    initiator_offered_lifetime: u32,
}

impl MainRespKeSent {
    /// Process message 5 (`HDR*, IDi, HASH_I`, encrypted): derive the
    /// Phase-1 key schedule, verify the initiator's `HASH_I`, and build
    /// message 6 (`HDR*, IDr, HASH_R`, encrypted) plus the completed
    /// [`Phase1State`].
    pub fn complete_id(self, msg5: &[u8]) -> Result<(Vec<u8>, Phase1State), IkeError> {
        let gxy = self.group.shared(&self.dh_private, &self.gxi)?;
        let skeyid = match &self.local_auth {
            Ikev1LocalAuth::Psk(psk) => crypto1::skeyid_psk(self.prf, psk, &self.ni, &self.nr),
            Ikev1LocalAuth::Sig { .. } => crypto1::skeyid_sig(self.prf, &self.ni, &self.nr, &gxy),
        };
        let skeyid_d = crypto1::skeyid_d(self.prf, &skeyid, &gxy, &self.cky_i, &self.cky_r);
        let skeyid_a = crypto1::skeyid_a(self.prf, &skeyid, &skeyid_d, &gxy, &self.cky_i, &self.cky_r);
        let skeyid_e = crypto1::skeyid_e(self.prf, &skeyid, &skeyid_a, &gxy, &self.cky_i, &self.cky_r);
        let enc_key = crypto1::derive_cipher_key(self.prf, &skeyid_e, self.key_len);
        let phase1_iv = crypto1::phase1_iv(self.prf, &self.gxi, &self.gxr, AES_BLOCK);

        let (_hdr, ps, iv_after_msg5) = phase2::decrypt_payloads(msg5, &enc_key, &phase1_iv)?;
        let idii_b = find(&ps, payload::ID).ok_or(IkeError::MissingPayload("ID"))?.data.clone();
        let expect_hi = crypto1::hash_i(self.prf, &skeyid, &self.gxi, &self.gxr, &self.cky_i, &self.cky_r, &self.sai_b, &idii_b);
        if matches!(self.local_auth, Ikev1LocalAuth::Sig { .. }) {
            let certs = collect_certs(&ps)?;
            let sig = find(&ps, payload::SIG).ok_or(IkeError::MissingPayload("SIG"))?.data.clone();
            validate_chain(&certs[0], &certs[1..], &self.trusted_cas, self.now_unix)?;
            VerifyingKey::from_cert_der(&certs[0])?.verify_classic_rsa_raw(&sig, &expect_hi)?;
        } else {
            let hash_i_got = find(&ps, payload::HASH).ok_or(IkeError::MissingPayload("HASH"))?.data.clone();
            if hash_i_got != expect_hi {
                return Err(IkeError::AuthFailed);
            }
        }

        // §5.1 (Sig): IDir is our own leaf cert's subject DN, same convention
        // as IDii above.
        let idir_b = match &self.local_auth {
            Ikev1LocalAuth::Psk(_) => self.our_id.to_bytes(),
            Ikev1LocalAuth::Sig { chain, .. } => Id {
                id_type: id_type::DER_ASN1_DN,
                protocol: 0,
                port: 0,
                data: cert_subject_dn(&chain[0])?,
            }
            .to_bytes(),
        };
        let hash_r = crypto1::hash_r(self.prf, &skeyid, &self.gxr, &self.gxi, &self.cky_r, &self.cky_i, &self.sai_b, &idir_b);
        let hdr6 = IsakmpHeader {
            init_cookie: self.cky_i,
            resp_cookie: self.cky_r,
            next_payload: payload::NONE,
            version: IsakmpHeader::VERSION_1_0,
            exchange_type: exchange::MAIN,
            flags: 0,
            message_id: 0,
            length: 0,
        };
        let out_payloads: Vec<(u8, Vec<u8>)> = match &self.local_auth {
            Ikev1LocalAuth::Psk(_) => vec![(payload::ID, idir_b.clone()), (payload::HASH, hash_r)],
            Ikev1LocalAuth::Sig { key, chain } => {
                let sig = key.sign_classic_rsa_raw(&hash_r)?;
                let mut out = vec![(payload::ID, idir_b.clone())];
                out.extend(chain.iter().map(|cert| (payload::CERT, cert_payload_body(cert))));
                out.push((payload::SIG, sig));
                out
            }
        };
        let (msg6, iv_after_msg6) = phase2::encrypt_payloads(hdr6, &enc_key, &iv_after_msg5, &out_payloads)?;

        let state = Phase1State {
            prf: self.prf,
            group: self.group,
            cky_i: self.cky_i,
            cky_r: self.cky_r,
            skeyid,
            skeyid_d,
            skeyid_a,
            skeyid_e,
            enc_key,
            // Not the local `phase1_iv` (the raw seed, only needed to
            // decrypt message 5 above) -- see the matching comment in
            // `MainIdSent::complete_id`: post-Phase-1 exchanges must seed
            // from the IV after the *last* encrypted Phase-1 message, which
            // for Main Mode is message 6, not the original seed.
            phase1_iv: iv_after_msg6,
            gxi: self.gxi,
            gxr: self.gxr,
            ni: self.ni,
            nr: self.nr,
            sai_b: self.sai_b,
            idii_b,
            peer_supports_dpd: self.peer_supports_dpd,
            floated: self.floated,
            negotiated_lifetime_secs: self.initiator_offered_lifetime,
        };
        Ok((msg6, state))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::payloads::id_type;
    use crate::entropy::SeedEntropy;

    #[test]
    fn phase1_state_zeroize_wipes_the_derived_key_material_but_not_public_fields() {
        let mut state = Phase1State {
            prf: Prf::Sha256,
            group: DhGroup::Modp2048,
            cky_i: [1u8; 8],
            cky_r: [2u8; 8],
            skeyid: vec![0xAAu8; 32],
            skeyid_d: vec![0xAAu8; 32],
            skeyid_a: vec![0xAAu8; 32],
            skeyid_e: vec![0xAAu8; 32],
            enc_key: vec![0xAAu8; 32],
            phase1_iv: vec![3u8; 16],
            gxi: vec![4u8; 16],
            gxr: vec![5u8; 16],
            ni: vec![6u8; 16],
            nr: vec![7u8; 16],
            sai_b: vec![8u8; 4],
            idii_b: vec![9u8; 4],
            peer_supports_dpd: true,
            floated: false,
            negotiated_lifetime_secs: 28800,
        };
        zeroize::Zeroize::zeroize(&mut state);
        assert!(state.skeyid.is_empty());
        assert!(state.skeyid_d.is_empty());
        assert!(state.skeyid_a.is_empty());
        assert!(state.skeyid_e.is_empty());
        assert!(state.enc_key.is_empty());
        // Non-secret fields are `#[zeroize(skip)]`d -- unaffected.
        assert_eq!(state.cky_i, [1u8; 8]);
        assert_eq!(state.gxi, vec![4u8; 16]);
        assert_eq!(state.negotiated_lifetime_secs, 28800);
    }

    #[test]
    fn ikev1_local_auth_psk_can_be_wiped_explicitly() {
        // `Ikev1LocalAuth` is a public, by-value type (clones flow through
        // every Phase-1 message-state transition) so it deliberately doesn't
        // auto-wipe on drop -- a caller that's done with it can still wipe
        // the PSK explicitly, which is what this proves.
        let mut auth = Ikev1LocalAuth::Psk(vec![0xAAu8; 16]);
        if let Ikev1LocalAuth::Psk(psk) = &mut auth {
            zeroize::Zeroize::zeroize(psk);
        }
        match &auth {
            Ikev1LocalAuth::Psk(psk) => assert!(psk.is_empty(), "PSK was not wiped"),
            Ikev1LocalAuth::Sig { .. } => unreachable!(),
        }
    }

    fn android_sa() -> SaPayload {
        use super::super::payloads::{life, Attribute, IPSEC_DOI, SIT_IDENTITY_ONLY};
        // Two transforms: AES256/SHA384 (we skip) then AES256/SHA256/grp2 (chosen).
        let mk = |num, h| Transform {
            num,
            transform_id: 1,
            attributes: vec![
                Attribute::short(attr::ENCRYPTION, enc::AES_CBC),
                Attribute::short(attr::KEY_LENGTH, 256),
                Attribute::short(attr::HASH, h),
                Attribute::short(attr::GROUP_DESC, 2),
                Attribute::short(attr::AUTH_METHOD, auth::XAUTH_INIT_PSK),
                Attribute::short(attr::LIFE_TYPE, life::SECONDS),
                Attribute::long_u32(attr::LIFE_DURATION, 28800),
            ],
        };
        SaPayload {
            doi: IPSEC_DOI,
            situation: SIT_IDENTITY_ONLY,
            proposals: vec![Proposal {
                num: 1,
                protocol_id: protocol::ISAKMP,
                spi: Vec::new(),
                transforms: vec![mk(1, hash::SHA2_384), mk(2, hash::SHA2_256)],
            }],
        }
    }

    /// Build an Aggressive-Mode message 1 the way a client would.
    fn client_msg1(cky_i: [u8; 8], gxi: &[u8], ni: &[u8], idi: &Id) -> Vec<u8> {
        let hdr = IsakmpHeader {
            init_cookie: cky_i,
            resp_cookie: [0; 8],
            next_payload: payload::NONE,
            version: IsakmpHeader::VERSION_1_0,
            exchange_type: exchange::AGGRESSIVE,
            flags: 0,
            message_id: 0,
            length: 0,
        };
        isakmp::build_message(hdr, &[
            (payload::SA, android_sa().to_bytes()),
            (payload::KE, gxi.to_vec()),
            (payload::NONCE, ni.to_vec()),
            (payload::ID, idi.to_bytes()),
        ])
    }

    #[test]
    fn full_aggressive_phase1_against_an_in_process_initiator() {
        // Play both roles: an initiator drives group-2 DH + HASH_I, ryke responds.
        let cfg = Phase1Config {
            local_auth: Ikev1LocalAuth::Psk(b"testpsk".to_vec()),
            trusted_cas: Vec::new(),
            now_unix: 0,
            our_id: Id::ipv4([192, 168, 3, 204]),
        };
        let cky_i = [0xAB; 8];
        let mut ie = SeedEntropy::new(7);
        let i_priv = ie.next_array32();
        let gxi = DhGroup::Modp1024.public(&i_priv);
        let ni = vec![0x11; 16];
        let idi = Id { id_type: id_type::KEY_ID, protocol: 0, port: 0, data: b"grp".to_vec() };

        let msg1 = client_msg1(cky_i, &gxi, &ni, &idi);
        let (msg2, st) = respond_aggressive(&cfg, &msg1, &mut SeedEntropy::new(9), "192.168.0.1:500".parse().unwrap(), "10.1.1.1:500".parse().unwrap()).unwrap();
        assert_eq!(st.group, DhGroup::Modp1024);
        assert_eq!(st.prf, Prf::Sha256); // picked AES256/SHA256, skipped SHA384

        // Initiator parses msg-2 and recomputes the shared key schedule.
        let h2 = IsakmpHeader::parse(&msg2).unwrap();
        let p2 = isakmp::parse_payloads(h2.next_payload, &msg2[IsakmpHeader::LEN..]).unwrap();
        let gxr = find(&p2, payload::KE).unwrap().data.clone();
        let nr = find(&p2, payload::NONCE).unwrap().data.clone();
        let hash_r = find(&p2, payload::HASH).unwrap().data.clone();
        let idr_b = find(&p2, payload::ID).unwrap().data.clone();
        let sai_b = android_sa().to_bytes();

        let gxy = DhGroup::Modp1024.shared(&i_priv, &gxr).unwrap();
        let skeyid = crypto1::skeyid_psk(Prf::Sha256, b"testpsk", &ni, &nr);
        // The initiator verifies the responder's HASH_R.
        let expect_hr = crypto1::hash_r(Prf::Sha256, &skeyid, &gxr, &gxi, &h2.resp_cookie, &cky_i, &sai_b, &idr_b);
        assert_eq!(hash_r, expect_hr, "responder HASH_R must verify");

        // The initiator sends HASH_I; the responder verifies it.
        let hash_i = crypto1::hash_i(Prf::Sha256, &skeyid, &gxi, &gxr, &cky_i, &h2.resp_cookie, &sai_b, &idi.to_bytes());
        let _ = gxy;
        let msg3 = isakmp::build_message(
            IsakmpHeader {
                init_cookie: cky_i,
                resp_cookie: h2.resp_cookie,
                next_payload: payload::NONE,
                version: IsakmpHeader::VERSION_1_0,
                exchange_type: exchange::AGGRESSIVE,
                flags: 0,
                message_id: 0,
                length: 0,
            },
            &[(payload::HASH, hash_i)],
        );
        st.verify_hash_i(&msg3).expect("HASH_I must verify → Phase 1 complete");
    }

    #[test]
    fn respond_aggressive_rejects_a_nonzero_phase1_message_id() {
        let cfg = Phase1Config {
            local_auth: Ikev1LocalAuth::Psk(b"testpsk".to_vec()),
            trusted_cas: Vec::new(),
            now_unix: 0,
            our_id: Id::ipv4([192, 168, 3, 204]),
        };
        let cky_i = [0xAB; 8];
        let mut ie = SeedEntropy::new(7);
        let i_priv = ie.next_array32();
        let gxi = DhGroup::Modp1024.public(&i_priv);
        let ni = vec![0x11; 16];
        let idi = Id { id_type: id_type::KEY_ID, protocol: 0, port: 0, data: b"grp".to_vec() };

        let hdr = IsakmpHeader {
            init_cookie: cky_i,
            resp_cookie: [0; 8],
            next_payload: payload::NONE,
            version: IsakmpHeader::VERSION_1_0,
            exchange_type: exchange::AGGRESSIVE,
            flags: 0,
            message_id: 1, // RFC 2408 §3.1: Phase 1 must use message_id 0
            length: 0,
        };
        let msg1 = isakmp::build_message(hdr, &[
            (payload::SA, android_sa().to_bytes()),
            (payload::KE, gxi.to_vec()),
            (payload::NONCE, ni.to_vec()),
            (payload::ID, idi.to_bytes()),
        ]);
        match respond_aggressive(&cfg, &msg1, &mut SeedEntropy::new(9), "192.168.0.1:500".parse().unwrap(), "10.1.1.1:500".parse().unwrap()) {
            Err(IkeError::Crypto(_)) => {}
            other => panic!("expected a Crypto error, got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn wrong_psk_fails_hash_i() {
        let cfg = Phase1Config {
            local_auth: Ikev1LocalAuth::Psk(b"right".to_vec()),
            trusted_cas: Vec::new(),
            now_unix: 0,
            our_id: Id::ipv4([10, 0, 0, 1]),
        };
        let cky_i = [0x01; 8];
        let mut ie = SeedEntropy::new(3);
        let i_priv = ie.next_array32();
        let gxi = DhGroup::Modp1024.public(&i_priv);
        let idi = Id { id_type: id_type::KEY_ID, protocol: 0, port: 0, data: b"g".to_vec() };
        let msg1 = client_msg1(cky_i, &gxi, &[0x22; 16], &idi);
        let (msg2, st) = respond_aggressive(&cfg, &msg1, &mut SeedEntropy::new(4), "192.168.0.1:500".parse().unwrap(), "10.1.1.1:500".parse().unwrap()).unwrap();
        let h2 = IsakmpHeader::parse(&msg2).unwrap();
        let p2 = isakmp::parse_payloads(h2.next_payload, &msg2[IsakmpHeader::LEN..]).unwrap();
        let nr = find(&p2, payload::NONCE).unwrap().data.clone();
        let gxr = find(&p2, payload::KE).unwrap().data.clone();
        // Initiator computes HASH_I with the WRONG psk.
        let bad_skeyid = crypto1::skeyid_psk(Prf::Sha256, b"wrong", &[0x22; 16], &nr);
        let bad_hash_i = crypto1::hash_i(Prf::Sha256, &bad_skeyid, &gxi, &gxr, &cky_i, &h2.resp_cookie, &android_sa().to_bytes(), &idi.to_bytes());
        let msg3 = isakmp::build_message(
            IsakmpHeader { init_cookie: cky_i, resp_cookie: h2.resp_cookie, next_payload: payload::NONE, version: IsakmpHeader::VERSION_1_0, exchange_type: exchange::AGGRESSIVE, flags: 0, message_id: 0, length: 0 },
            &[(payload::HASH, bad_hash_i)],
        );
        assert_eq!(st.verify_hash_i(&msg3).unwrap_err(), IkeError::AuthFailed);
    }

    #[test]
    fn dpd_vendor_id_is_offered_and_recognized_by_both_sides() {
        // A full initiator/responder round trip (unlike the two tests above,
        // which hand-build msg1) -- `initiate_aggressive` offers
        // `DPD_VENDOR_ID`, `respond_aggressive` echoes it back, and each side
        // should come away with `peer_supports_dpd: true`.
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
            esp_cipher: crate::ikev2::sk::SkCipher::Aes256Gcm,
            pfs_group: None,
            mode_cfg: false,
            ipv6: false,
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
        let mut ie = SeedEntropy::new(0x1111);
        let mut re = SeedEntropy::new(0x2222);
        let (msg1, ai) = initiate_aggressive(&icfg, &mut ie, "10.1.1.1:500".parse().unwrap(), "192.168.0.1:500".parse().unwrap());
        let (msg2, rstate) = respond_aggressive(&rcfg, &msg1, &mut re, "192.168.0.1:500".parse().unwrap(), "10.1.1.1:500".parse().unwrap()).unwrap();
        let (msg3, istate) = ai.complete(&msg2, "10.1.1.1:500".parse().unwrap(), "192.168.0.1:500".parse().unwrap()).unwrap();
        rstate.verify_hash_i(&msg3).unwrap();

        assert!(istate.peer_supports_dpd, "initiator should recognize the responder's echoed DPD VID");
        assert!(rstate.peer_supports_dpd, "responder should recognize the initiator's offered DPD VID");
    }

    fn main_mode_icfg(psk: Vec<u8>) -> InitiatorConfig {
        InitiatorConfig {
            local_auth: Ikev1LocalAuth::Psk(psk),
            trusted_cas: Vec::new(),
            now_unix: 0,
            key_len: 32,
            our_id: Id::ipv4([10, 1, 1, 1]),
            group: DhGroup::Modp1024,
            xauth: false,
            xauth_creds: None,
            ts_local: ([0, 0, 0, 0], [0, 0, 0, 0]),
            ts_remote: ([0, 0, 0, 0], [0, 0, 0, 0]),
            esp_cipher: crate::ikev2::sk::SkCipher::Aes256Gcm,
            pfs_group: None,
            mode_cfg: false,
            ipv6: false,
            mode: Ikev1ExchangeMode::Main,
            p1_lifetime_secs: 28800,
            p2_lifetime_secs: 3600,
        }
    }

    #[test]
    fn full_main_phase1_against_an_in_process_responder() {
        let psk = b"correct horse battery staple".to_vec();
        let icfg = main_mode_icfg(psk.clone());
        let rcfg = Phase1Config {
            local_auth: Ikev1LocalAuth::Psk(psk),
            trusted_cas: Vec::new(),
            now_unix: 0,
            our_id: Id::ipv4([192, 168, 0, 1]),
        };
        let mut ie = SeedEntropy::new(0x3333);
        let mut re = SeedEntropy::new(0x4444);

        let (msg1, sa_sent) = initiate_main(&icfg, &mut ie);
        let (msg2, r1) = respond_main(&rcfg, &msg1, &mut re, "192.168.0.1:500".parse().unwrap(), "10.1.1.1:500".parse().unwrap()).unwrap();
        let (msg3, ke_sent) = sa_sent.complete_sa(&msg2, &mut ie, "10.1.1.1:500".parse().unwrap(), "192.168.0.1:500".parse().unwrap()).unwrap();
        let (msg4, r2) = r1.complete_ke(&msg3, &mut re).unwrap();
        let (msg5, id_sent) = ke_sent.complete_ke(&msg4).unwrap();
        let (msg6, rstate) = r2.complete_id(&msg5).unwrap();
        let istate = id_sent.complete_id(&msg6, &mut ie).unwrap();

        assert_eq!(istate.skeyid_e, rstate.skeyid_e, "both sides must derive the same SKEYID_e");
        assert_eq!(istate.enc_key, rstate.enc_key);
        assert!(istate.peer_supports_dpd, "initiator should recognize the responder's echoed DPD VID (msg4)");
        assert!(rstate.peer_supports_dpd, "responder should recognize the initiator's offered DPD VID (msg3)");
        // Both sides claimed and observed the same addresses -- no NAT on
        // the path, so neither should float. Regression guard: this is the
        // common case and must keep working exactly as before NAT-T existed.
        assert!(!istate.floated, "matching addresses on both sides -- no NAT to detect");
        assert!(!rstate.floated);

        // The returned Phase1State must seed post-Phase-1 IVs (xauth.rs,
        // quick.rs, cfg.rs, informational.rs all read `phase1_iv` for this)
        // from the IV chained forward past message 6 (RFC 2409 App. B's
        // "last Phase-1 IV"), not the raw `HASH(g^xi|g^xr)` seed -- confirmed
        // live against a real FortiGate: using the raw seed here made the
        // gateway's very first post-Phase-1 message (its XAUTH request)
        // fail to decrypt, even though Phase 1 itself authenticated fine on
        // both sides (a bug this in-process round trip alone couldn't catch,
        // since both sides shared the identical wrong assumption -- this
        // asserts against an independent derivation instead). Message 6 is
        // exactly 3 AES blocks (`Id::ipv4` + a 32-byte SHA-256 HASH, no
        // padding needed), so its own last ciphertext block *is* that IV.
        let last_block = &msg6[msg6.len() - AES_BLOCK..];
        assert_eq!(istate.phase1_iv, last_block, "initiator's phase1_iv must chain from message 6's ciphertext");
        assert_eq!(rstate.phase1_iv, last_block, "responder's phase1_iv must chain from message 6's ciphertext");
    }

    #[test]
    fn respond_main_rejects_a_nonzero_phase1_message_id() {
        let psk = b"correct horse battery staple".to_vec();
        let icfg = main_mode_icfg(psk.clone());
        let rcfg = Phase1Config {
            local_auth: Ikev1LocalAuth::Psk(psk),
            trusted_cas: Vec::new(),
            now_unix: 0,
            our_id: Id::ipv4([192, 168, 0, 1]),
        };
        let mut ie = SeedEntropy::new(0x3333);
        let mut re = SeedEntropy::new(0x4444);
        let (msg1, _sa_sent) = initiate_main(&icfg, &mut ie);

        // Reparse and re-serialize msg1 with a nonzero message_id -- Phase 1
        // must always use 0 (RFC 2408 §3.1).
        let mut hdr = IsakmpHeader::parse(&msg1).unwrap();
        hdr.message_id = 1;
        let mut tampered = hdr.to_bytes();
        tampered.extend_from_slice(&msg1[IsakmpHeader::LEN..]);

        match respond_main(&rcfg, &tampered, &mut re, "192.168.0.1:500".parse().unwrap(), "10.1.1.1:500".parse().unwrap()) {
            Err(IkeError::Crypto(_)) => {}
            other => panic!("expected a Crypto error, got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn complete_sa_rejects_a_mismatched_init_cookie() {
        let psk = b"correct horse battery staple".to_vec();
        let icfg = main_mode_icfg(psk.clone());
        let rcfg = Phase1Config {
            local_auth: Ikev1LocalAuth::Psk(psk),
            trusted_cas: Vec::new(),
            now_unix: 0,
            our_id: Id::ipv4([192, 168, 0, 1]),
        };
        let mut ie = SeedEntropy::new(0x3333);
        let mut re = SeedEntropy::new(0x4444);
        let (msg1, sa_sent) = initiate_main(&icfg, &mut ie);
        let (msg2, _r1) = respond_main(&rcfg, &msg1, &mut re, "192.168.0.1:500".parse().unwrap(), "10.1.1.1:500".parse().unwrap()).unwrap();

        // A responder (or an attacker) that echoes back the wrong CKY-I in
        // message 2 must be rejected -- RFC 2408 §3.1 requires both cookies
        // to match on every message, not just the last one seen.
        let mut hdr = IsakmpHeader::parse(&msg2).unwrap();
        hdr.init_cookie[0] ^= 0xff;
        let mut tampered = hdr.to_bytes();
        tampered.extend_from_slice(&msg2[IsakmpHeader::LEN..]);

        match sa_sent.complete_sa(&tampered, &mut ie, "10.1.1.1:500".parse().unwrap(), "192.168.0.1:500".parse().unwrap()) {
            Err(IkeError::Crypto(_)) => {}
            other => panic!("expected a Crypto error, got {:?}", other.map(|_| ())),
        }
    }

    /// The gateway is reachable at a fixed public address both sides agree
    /// on, but the responder *observes* the initiator arriving from a
    /// different address than the initiator itself claims -- simulating a
    /// NAT translating the initiator's outbound traffic (the common case
    /// this feature exists for). Both sides must independently conclude
    /// `floated: true` from RFC 3947 NAT-D alone (each only ever sees its
    /// own recomputed hashes against what the peer sent -- there is no
    /// shared "ground truth" object in a real deployment), and the
    /// handshake must still complete and agree on keys. Also checks that
    /// Quick Mode's ESP proposal declares `UDP_ENCAP_TUNNEL` instead of
    /// plain `ENCAP_TUNNEL` once floated (`quick::esp_sa`'s doc).
    #[test]
    fn full_main_phase1_floats_to_natt_when_a_nat_is_detected() {
        let psk = b"correct horse battery staple".to_vec();
        let icfg = main_mode_icfg(psk.clone());
        let rcfg = Phase1Config { local_auth: Ikev1LocalAuth::Psk(psk), trusted_cas: Vec::new(), now_unix: 0, our_id: Id::ipv4([192, 168, 0, 1]) };
        let mut ie = SeedEntropy::new(0xA5A5);
        let mut re = SeedEntropy::new(0xB6B6);

        let gateway_addr: SocketAddr = "203.0.113.9:500".parse().unwrap();
        // What the initiator itself believes its own address is (e.g. its
        // private LAN address).
        let initiator_claimed_addr: SocketAddr = "10.0.0.5:500".parse().unwrap();
        // What the responder actually observes the initiator's traffic
        // arriving from (post-NAT, translated by the box in between).
        let observed_initiator_addr: SocketAddr = "198.51.100.7:500".parse().unwrap();

        let (msg1, sa_sent) = initiate_main(&icfg, &mut ie);
        let (msg2, r1) = respond_main(&rcfg, &msg1, &mut re, gateway_addr, observed_initiator_addr).unwrap();
        let (msg3, ke_sent) = sa_sent.complete_sa(&msg2, &mut ie, initiator_claimed_addr, gateway_addr).unwrap();
        let (msg4, r2) = r1.complete_ke(&msg3, &mut re).unwrap();
        let (msg5, id_sent) = ke_sent.complete_ke(&msg4).unwrap();
        assert!(id_sent.floated, "initiator must detect the NAT from message 4's NAT-D");
        let (msg6, rstate) = r2.complete_id(&msg5).unwrap();
        let istate = id_sent.complete_id(&msg6, &mut ie).unwrap();

        assert!(istate.floated, "initiator's completed Phase1State must carry the float decision forward");
        assert!(rstate.floated, "responder must independently detect the same NAT from message 3's NAT-D");
        assert_eq!(istate.skeyid_e, rstate.skeyid_e, "NAT-T floating must not affect the key schedule");

        // Quick Mode's own SA proposal must declare the UDP-encap
        // encapsulation mode once floated (`quick::esp_sa`'s doc).
        let ts = ([0, 0, 0, 0], [0, 0, 0, 0]);
        let (qm1, _qi) = crate::ikev1::quick::initiate_quick(&istate, &mut ie, crate::ikev2::sk::SkCipher::Aes256Gcm, ts, ts, 3600).unwrap();
        let iv0 = crypto1::phase2_iv(istate.prf, &istate.phase1_iv, {
            let hdr = IsakmpHeader::parse(&qm1).unwrap();
            hdr.message_id
        }, AES_BLOCK);
        let (_h, ps, _next) = phase2::parse_encrypted(&qm1, istate.prf, &istate.skeyid_a, &istate.enc_key, &iv0).unwrap();
        let sa = SaPayload::parse(&find(&ps, payload::SA).unwrap().data).unwrap();
        let encap_mode = sa.proposals[0].transforms[0].attr(4 /* esp_attr::ENCAP_MODE */).unwrap();
        assert_eq!(encap_mode, 3, "floated Quick Mode must declare UDP_ENCAP_TUNNEL (3), not plain tunnel mode (1)");
    }

    /// The Aggressive Mode analog of the Main Mode NAT-detection test above
    /// -- message 1's own NAT-D necessarily hashes with `CKY-R` still
    /// all-zero (see `initiate_aggressive`'s doc), so this specifically
    /// exercises that path, which the Main-Mode test above cannot.
    #[test]
    fn full_aggressive_phase1_floats_to_natt_when_a_nat_is_detected() {
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
            esp_cipher: crate::ikev2::sk::SkCipher::Aes256Gcm,
            pfs_group: None,
            mode_cfg: false,
            ipv6: false,
            mode: Ikev1ExchangeMode::Aggressive,
            p1_lifetime_secs: 28800,
            p2_lifetime_secs: 3600,
        };
        let rcfg = Phase1Config { local_auth: Ikev1LocalAuth::Psk(psk), trusted_cas: Vec::new(), now_unix: 0, our_id: Id::ipv4([192, 168, 0, 1]) };
        let mut ie = SeedEntropy::new(0xC7C7);
        let mut re = SeedEntropy::new(0xD8D8);

        let gateway_addr: SocketAddr = "203.0.113.9:500".parse().unwrap();
        let initiator_claimed_addr: SocketAddr = "10.0.0.5:500".parse().unwrap();
        let observed_initiator_addr: SocketAddr = "198.51.100.7:500".parse().unwrap();

        let (msg1, ai) = initiate_aggressive(&icfg, &mut ie, initiator_claimed_addr, gateway_addr);
        let (msg2, rstate) = respond_aggressive(&rcfg, &msg1, &mut re, gateway_addr, observed_initiator_addr).unwrap();
        assert!(rstate.floated, "responder must detect the NAT from message 1's NAT-D (hashed with CKY-R all-zero)");
        let (_msg3, istate) = ai.complete(&msg2, initiator_claimed_addr, gateway_addr).unwrap();
        assert!(istate.floated, "initiator must detect the same NAT from message 2's NAT-D (real CKY-R now)");
        assert_eq!(istate.skeyid_e, rstate.skeyid_e);
    }

    /// A profile configured for AES-192 (`InitiatorConfig::key_len: 24`) must
    /// actually offer AES-192 on the wire and complete the handshake with a
    /// 24-byte `enc_key` on both sides -- confirmed live against a real
    /// FortiGate IKEv1 gateway policy pinned to AES-192-CBC that this app
    /// used to fail to negotiate at all ("no SA proposal chosen") because
    /// `initiator_sa` unconditionally offered AES-256 regardless of what a
    /// profile's own Phase-1 proposal configured.
    #[test]
    fn main_mode_offers_and_completes_with_aes_192() {
        let psk = b"correct horse battery staple".to_vec();
        let mut icfg = main_mode_icfg(psk.clone());
        icfg.key_len = 24;
        let rcfg = Phase1Config {
            local_auth: Ikev1LocalAuth::Psk(psk),
            trusted_cas: Vec::new(),
            now_unix: 0,
            our_id: Id::ipv4([192, 168, 0, 1]),
        };
        let mut ie = SeedEntropy::new(0x9191);
        let mut re = SeedEntropy::new(0x9292);

        let (msg1, sa_sent) = initiate_main(&icfg, &mut ie);
        let hdr1 = IsakmpHeader::parse(&msg1).unwrap();
        let ps1 = isakmp::parse_payloads(hdr1.next_payload, &msg1[IsakmpHeader::LEN..]).unwrap();
        let sa = SaPayload::parse(&find(&ps1, payload::SA).unwrap().data).unwrap();
        assert_eq!(sa.proposals[0].transforms[0].attr(attr::KEY_LENGTH), Some(192), "message 1 must offer AES-192, not the old hardcoded AES-256");

        let (msg2, r1) = respond_main(&rcfg, &msg1, &mut re, "192.168.0.1:500".parse().unwrap(), "10.1.1.1:500".parse().unwrap()).unwrap();
        let (msg3, ke_sent) = sa_sent.complete_sa(&msg2, &mut ie, "10.1.1.1:500".parse().unwrap(), "192.168.0.1:500".parse().unwrap()).unwrap();
        let (msg4, r2) = r1.complete_ke(&msg3, &mut re).unwrap();
        let (msg5, id_sent) = ke_sent.complete_ke(&msg4).unwrap();
        let (msg6, rstate) = r2.complete_id(&msg5).unwrap();
        let istate = id_sent.complete_id(&msg6, &mut ie).unwrap();

        assert_eq!(istate.enc_key.len(), 24, "AES-192 key must be 24 bytes");
        assert_eq!(istate.enc_key, rstate.enc_key, "both sides must derive the identical AES-192 key");
    }

    #[test]
    fn wrong_psk_fails_main_mode_hash_i() {
        // Unlike Aggressive Mode's `wrong_psk_fails_hash_i` (whose msg3 can
        // arrive in the clear, so a bad HASH_I is a clean `AuthFailed`), Main
        // Mode's msg5 is *always* encrypted -- a wrong PSK means a wrong
        // SKEYID_e, so the responder decrypts to garbage and typically fails
        // at payload parsing rather than ever reaching the HASH comparison.
        // Either way, the property under test is the same: a wrong PSK must
        // never yield an established Phase1State.
        let icfg = main_mode_icfg(b"right".to_vec());
        let rcfg = Phase1Config {
            local_auth: Ikev1LocalAuth::Psk(b"wrong".to_vec()),
            trusted_cas: Vec::new(),
            now_unix: 0,
            our_id: Id::ipv4([192, 168, 0, 1]),
        };
        let mut ie = SeedEntropy::new(0x5555);
        let mut re = SeedEntropy::new(0x6666);

        let (msg1, sa_sent) = initiate_main(&icfg, &mut ie);
        let (msg2, r1) = respond_main(&rcfg, &msg1, &mut re, "192.168.0.1:500".parse().unwrap(), "10.1.1.1:500".parse().unwrap()).unwrap();
        let (msg3, ke_sent) = sa_sent.complete_sa(&msg2, &mut ie, "10.1.1.1:500".parse().unwrap(), "192.168.0.1:500".parse().unwrap()).unwrap();
        let (msg4, r2) = r1.complete_ke(&msg3, &mut re).unwrap();
        let (msg5, _id_sent) = ke_sent.complete_ke(&msg4).unwrap();
        assert!(r2.complete_id(&msg5).is_err(), "a wrong PSK must never let Main Mode complete");
    }

    #[test]
    fn main_mode_initiator_rejects_a_tampered_hash_r() {
        // The whole reason `MainIdSent::complete_id` is its own step (see
        // this module's Main Mode doc comment) is that the initiator must
        // verify the responder's HASH_R itself -- a tampered message 6 must
        // never produce a `Phase1State`.
        let psk = b"correct horse battery staple".to_vec();
        let icfg = main_mode_icfg(psk.clone());
        let rcfg = Phase1Config {
            local_auth: Ikev1LocalAuth::Psk(psk),
            trusted_cas: Vec::new(),
            now_unix: 0,
            our_id: Id::ipv4([192, 168, 0, 1]),
        };
        let mut ie = SeedEntropy::new(0x9999);
        let mut re = SeedEntropy::new(0xAAAA);

        let (msg1, sa_sent) = initiate_main(&icfg, &mut ie);
        let (msg2, r1) = respond_main(&rcfg, &msg1, &mut re, "192.168.0.1:500".parse().unwrap(), "10.1.1.1:500".parse().unwrap()).unwrap();
        let (msg3, ke_sent) = sa_sent.complete_sa(&msg2, &mut ie, "10.1.1.1:500".parse().unwrap(), "192.168.0.1:500".parse().unwrap()).unwrap();
        let (msg4, r2) = r1.complete_ke(&msg3, &mut re).unwrap();
        let (msg5, id_sent) = ke_sent.complete_ke(&msg4).unwrap();
        let (mut msg6, _rstate) = r2.complete_id(&msg5).unwrap();
        *msg6.last_mut().unwrap() ^= 0xFF; // corrupt the tail of the encrypted HASH_R
        assert!(id_sent.complete_id(&msg6, &mut ie).is_err(), "a tampered HASH_R must never verify");
    }

    /// A self-signed RSA certificate built at test time from the crate's
    /// shared RSA test key (`crate::test_certs::RSA_KEY_PK8`) -- trusted as
    /// its own anchor, so `validate_chain(leaf, [], [leaf], now)` succeeds.
    /// `serial` must be distinct across calls within the same test (it's the
    /// only thing that varies): two certs built with the same key, subject
    /// and serial within the same wall-clock second are byte-identical DER,
    /// which silently defeats an "untrusted cert" test. Returns the cert DER
    /// and the wall-clock time it's valid at.
    fn self_signed_rsa_test_cert(serial: u32) -> (Vec<u8>, u64) {
        use der::Encode;
        use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey};
        use sha2::Sha256;
        use std::str::FromStr;
        use std::time::{Duration, SystemTime, UNIX_EPOCH};
        use x509_cert::builder::{Builder, CertificateBuilder, Profile};
        use x509_cert::name::Name;
        use x509_cert::serial_number::SerialNumber;
        use x509_cert::spki::SubjectPublicKeyInfoOwned;
        use x509_cert::time::Validity;

        let priv_key = rsa::RsaPrivateKey::from_pkcs8_der(crate::test_certs::RSA_KEY_PK8).unwrap();
        let pub_key_der = priv_key.to_public_key().to_public_key_der().unwrap();
        let pub_key = SubjectPublicKeyInfoOwned::try_from(pub_key_der.as_bytes()).unwrap();
        let subject = Name::from_str("CN=ryke-ikev1-sig-test").unwrap();
        let signer = rsa::pkcs1v15::SigningKey::<Sha256>::new(priv_key);
        let validity = Validity::from_now(Duration::new(300, 0)).unwrap();
        let builder = CertificateBuilder::new(
            Profile::Root,
            SerialNumber::from(serial),
            validity,
            subject,
            pub_key,
            &signer,
        )
        .unwrap();
        let cert = builder.build::<rsa::pkcs1v15::Signature>().unwrap();
        let der = cert.to_der().unwrap();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        (der, now)
    }

    /// The RSA-signature analog of `full_main_phase1_against_an_in_process_responder`
    /// -- both sides configured with `Ikev1LocalAuth::Sig` instead of `Psk`,
    /// exercising the real CERT/SIG wire format both directions (§5.1) rather
    /// than a hand-built fixture. This is the highest-value test for the whole
    /// RSA-sig feature: it fails if the SKEYID formula, the CERT/SIG payload
    /// shape, the DER_ASN1_DN identity, or the chain/signature verification
    /// disagree between initiator and responder.
    #[test]
    fn full_main_phase1_sig_auth_against_an_in_process_responder() {
        let (cert_der, now_unix) = self_signed_rsa_test_cert(1);
        let ikey = Arc::new(SigningKey::rsa_from_pkcs8_der(crate::test_certs::RSA_KEY_PK8).unwrap());
        let rkey = Arc::new(SigningKey::rsa_from_pkcs8_der(crate::test_certs::RSA_KEY_PK8).unwrap());

        let icfg = InitiatorConfig {
            local_auth: Ikev1LocalAuth::Sig { key: ikey, chain: vec![cert_der.clone()] },
            trusted_cas: vec![cert_der.clone()],
            now_unix,
            key_len: 32,
            our_id: Id::ipv4([10, 1, 1, 1]), // ignored -- IDi/IDr come from the cert's subject DN
            group: DhGroup::Modp1024,
            xauth: false,
            xauth_creds: None,
            ts_local: ([0, 0, 0, 0], [0, 0, 0, 0]),
            ts_remote: ([0, 0, 0, 0], [0, 0, 0, 0]),
            esp_cipher: crate::ikev2::sk::SkCipher::Aes256Gcm,
            pfs_group: None,
            mode_cfg: false,
            ipv6: false,
            mode: Ikev1ExchangeMode::Main,
            p1_lifetime_secs: 28800,
            p2_lifetime_secs: 3600,
        };
        let rcfg = Phase1Config {
            local_auth: Ikev1LocalAuth::Sig { key: rkey, chain: vec![cert_der.clone()] },
            trusted_cas: vec![cert_der],
            now_unix,
            our_id: Id::ipv4([192, 168, 0, 1]), // ignored, same reason
        };
        let mut ie = SeedEntropy::new(0xBEEF);
        let mut re = SeedEntropy::new(0xCAFE);

        let (msg1, sa_sent) = initiate_main(&icfg, &mut ie);
        let (msg2, r1) = respond_main(&rcfg, &msg1, &mut re, "192.168.0.1:500".parse().unwrap(), "10.1.1.1:500".parse().unwrap()).unwrap();
        let (msg3, ke_sent) = sa_sent.complete_sa(&msg2, &mut ie, "10.1.1.1:500".parse().unwrap(), "192.168.0.1:500".parse().unwrap()).unwrap();
        let (msg4, r2) = r1.complete_ke(&msg3, &mut re).unwrap();
        let (msg5, id_sent) = ke_sent.complete_ke(&msg4).unwrap();
        let (msg6, rstate) = r2.complete_id(&msg5).unwrap();
        let istate = id_sent.complete_id(&msg6, &mut ie).unwrap();

        assert_eq!(istate.skeyid_e, rstate.skeyid_e, "both sides must derive the same SKEYID_e");
        assert_eq!(istate.enc_key, rstate.enc_key);
    }

    /// A wrong/untrusted certificate (self-signed, but not in `trusted_cas`)
    /// must never let Main Mode complete -- the chain-validation branch of
    /// `MainIdSent::complete_id`/`MainRespKeSent::complete_id` must actually
    /// reject, not just skip straight to the signature check.
    #[test]
    fn main_mode_sig_auth_rejects_an_untrusted_responder_cert() {
        let (good_cert, now_unix) = self_signed_rsa_test_cert(1);
        // A valid but unrelated (EC, not RSA) cert -- distinct key pair from
        // `good_cert_r`'s, so it can never validate as its anchor. A second
        // *RSA* self-signed cert from the same shared test key would not
        // work here: its public key would still verify `good_cert_r`'s
        // self-signature, since both certs share the same underlying key
        // pair (only the serial number would differ).
        let bad_cert = crate::test_certs::LEAF_CERT_DER.to_vec();
        let ikey = Arc::new(SigningKey::rsa_from_pkcs8_der(crate::test_certs::RSA_KEY_PK8).unwrap());
        let rkey = Arc::new(SigningKey::rsa_from_pkcs8_der(crate::test_certs::RSA_KEY_PK8).unwrap());

        let (good_cert_r, _) = self_signed_rsa_test_cert(3);
        let icfg = InitiatorConfig {
            local_auth: Ikev1LocalAuth::Sig { key: ikey, chain: vec![good_cert.clone()] },
            // The initiator only trusts `bad_cert` -- the responder's actual
            // (different, freshly self-signed) `good_cert_r` must not validate.
            trusted_cas: vec![bad_cert],
            now_unix,
            key_len: 32,
            our_id: Id::ipv4([10, 1, 1, 1]),
            group: DhGroup::Modp1024,
            xauth: false,
            xauth_creds: None,
            ts_local: ([0, 0, 0, 0], [0, 0, 0, 0]),
            ts_remote: ([0, 0, 0, 0], [0, 0, 0, 0]),
            esp_cipher: crate::ikev2::sk::SkCipher::Aes256Gcm,
            pfs_group: None,
            mode_cfg: false,
            ipv6: false,
            mode: Ikev1ExchangeMode::Main,
            p1_lifetime_secs: 28800,
            p2_lifetime_secs: 3600,
        };
        let rcfg = Phase1Config {
            local_auth: Ikev1LocalAuth::Sig { key: rkey, chain: vec![good_cert_r] },
            // The responder trusts the initiator's real cert, so msg5
            // verifies fine on this side -- only the initiator's verification
            // of msg6 (the thing under test) should fail.
            trusted_cas: vec![good_cert],
            now_unix,
            our_id: Id::ipv4([192, 168, 0, 1]),
        };
        let mut ie = SeedEntropy::new(0x1234);
        let mut re = SeedEntropy::new(0x5678);

        let (msg1, sa_sent) = initiate_main(&icfg, &mut ie);
        let (msg2, r1) = respond_main(&rcfg, &msg1, &mut re, "192.168.0.1:500".parse().unwrap(), "10.1.1.1:500".parse().unwrap()).unwrap();
        let (msg3, ke_sent) = sa_sent.complete_sa(&msg2, &mut ie, "10.1.1.1:500".parse().unwrap(), "192.168.0.1:500".parse().unwrap()).unwrap();
        let (msg4, r2) = r1.complete_ke(&msg3, &mut re).unwrap();
        let (msg5, id_sent) = ke_sent.complete_ke(&msg4).unwrap();
        let (msg6, _rstate) = r2.complete_id(&msg5).unwrap();
        let Err(failure) = id_sent.complete_id(&msg6, &mut ie) else {
            panic!("an untrusted responder cert must never verify");
        };
        assert!(
            failure.teardown.is_some(),
            "SKEYID_a/e come from the DH exchange alone, so a Delete should still be buildable even though AUTH failed"
        );
    }

    fn natd_msg(vid: bool, natd: &[(u8, Vec<u8>)]) -> Vec<isakmp::Payload> {
        let mut ps = Vec::new();
        if vid {
            ps.push(isakmp::Payload { payload_type: payload::VENDOR_ID, data: NATT_RFC_VENDOR_ID.to_vec() });
        }
        for (t, d) in natd {
            ps.push(isakmp::Payload { payload_type: *t, data: d.clone() });
        }
        ps
    }

    #[test]
    fn natd_float_needed_agrees_on_matching_addresses() {
        let cky_i = [0x11; 8];
        let cky_r = [0x22; 8];
        let ours: SocketAddr = "10.0.0.1:500".parse().unwrap();
        let peer: SocketAddr = "203.0.113.1:500".parse().unwrap();
        let payloads = natd_payloads(Prf::Sha256, cky_i, cky_r, peer, ours);
        let ps = natd_msg(true, &payloads);
        assert!(!natd_float_needed(&ps, true, Prf::Sha256, cky_i, cky_r, ours, peer), "identical addresses on both sides -- no NAT");
    }

    #[test]
    fn natd_float_needed_detects_a_mismatched_address() {
        let cky_i = [0x11; 8];
        let cky_r = [0x22; 8];
        let claimed: SocketAddr = "10.0.0.1:500".parse().unwrap();
        let observed: SocketAddr = "198.51.100.1:500".parse().unwrap();
        let peer: SocketAddr = "203.0.113.1:500".parse().unwrap();
        // The peer computed its NAT-D pair using what it actually observed
        // (`observed`), not what the sender itself would claim (`claimed`).
        let payloads = natd_payloads(Prf::Sha256, cky_i, cky_r, peer, observed);
        let ps = natd_msg(true, &payloads);
        assert!(natd_float_needed(&ps, true, Prf::Sha256, cky_i, cky_r, claimed, peer), "our own recomputed hash (from `claimed`) can't be found -- must float");
    }

    #[test]
    fn natd_float_needed_is_false_without_the_vendor_id() {
        let cky_i = [0x11; 8];
        let cky_r = [0x22; 8];
        let ours: SocketAddr = "10.0.0.1:500".parse().unwrap();
        let peer: SocketAddr = "203.0.113.1:500".parse().unwrap();
        // Even with NAT-D payloads present, no float without the peer
        // having advertised RFC 3947 support first.
        let payloads = natd_payloads(Prf::Sha256, cky_i, cky_r, peer, ours);
        let ps = natd_msg(false, &payloads);
        assert!(!natd_float_needed(&ps, false, Prf::Sha256, cky_i, cky_r, ours, peer));
    }

    /// Matches isakmpd's own `nat_t_match_nat_d_payload` fallback: a peer
    /// that advertised NAT-T support but sent no NAT-D payloads at all is
    /// treated as "no NAT", not as a reason to float.
    #[test]
    fn natd_float_needed_is_false_when_no_natd_payloads_are_present() {
        let cky_i = [0x11; 8];
        let cky_r = [0x22; 8];
        let ours: SocketAddr = "10.0.0.1:500".parse().unwrap();
        let peer: SocketAddr = "203.0.113.1:500".parse().unwrap();
        let ps = natd_msg(true, &[]);
        assert!(!natd_float_needed(&ps, true, Prf::Sha256, cky_i, cky_r, ours, peer));
    }

    /// Regression test for the same bug class `main_mode_offers_and_completes_with_aes_192`
    /// guards against, but for the Phase-1 SA lifetime instead of the cipher:
    /// `initiator_sa` must offer whatever `InitiatorConfig::p1_lifetime_secs`
    /// configures, not a hardcoded `28800`.
    #[test]
    fn initiator_sa_carries_the_configured_lifetime_not_a_hardcoded_one() {
        let sa = initiator_sa(DhGroup::Modp1024, false, false, 32, 1234);
        let life = sa.proposals[0].transforms[0].attr_u32(attr::LIFE_DURATION);
        assert_eq!(life, Some(1234), "must carry the configured lifetime, not the old hardcoded 28800");
    }

    /// [`negotiated_p1_lifetime`] must prefer the responder's own chosen
    /// value (RFC 2407 §4.5: the responder may unilaterally shorten the
    /// initiator's offer) and fall back to `offered` only when the
    /// responder's SA payload carries no `LIFE_DURATION` attribute at all.
    #[test]
    fn negotiated_p1_lifetime_prefers_the_responders_value_and_falls_back_when_absent() {
        let sa_with_lifetime = SaPayload {
            doi: IPSEC_DOI,
            situation: SIT_IDENTITY_ONLY,
            proposals: vec![Proposal {
                num: 1,
                protocol_id: protocol::ISAKMP,
                spi: Vec::new(),
                transforms: vec![Transform {
                    num: 1,
                    transform_id: 1,
                    attributes: vec![
                        Attribute::short(attr::LIFE_TYPE, life::SECONDS),
                        Attribute::long_u32(attr::LIFE_DURATION, 900),
                    ],
                }],
            }],
        };
        let ps_with = vec![isakmp::Payload { payload_type: payload::SA, data: sa_with_lifetime.to_bytes() }];
        assert_eq!(negotiated_p1_lifetime(&ps_with, 28800), 900, "must prefer the responder's own chosen value");

        let sa_without_lifetime = SaPayload {
            doi: IPSEC_DOI,
            situation: SIT_IDENTITY_ONLY,
            proposals: vec![Proposal {
                num: 1,
                protocol_id: protocol::ISAKMP,
                spi: Vec::new(),
                transforms: vec![Transform { num: 1, transform_id: 1, attributes: vec![] }],
            }],
        };
        let ps_without = vec![isakmp::Payload { payload_type: payload::SA, data: sa_without_lifetime.to_bytes() }];
        assert_eq!(negotiated_p1_lifetime(&ps_without, 28800), 28800, "must fall back to the offered value when absent");

        assert_eq!(negotiated_p1_lifetime(&[], 28800), 28800, "must fall back to the offered value when there's no SA payload at all");
    }

    /// End-to-end confirmation that a non-default `InitiatorConfig::p1_lifetime_secs`
    /// actually reaches `Phase1State::negotiated_lifetime_secs` on both sides,
    /// in both Aggressive and Main Mode -- not just that the wire attribute
    /// carries the right value (already covered above).
    #[test]
    fn configured_p1_lifetime_reaches_negotiated_lifetime_secs_in_both_modes() {
        let psk = b"correct horse battery staple".to_vec();
        let mut icfg = InitiatorConfig {
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
            esp_cipher: crate::ikev2::sk::SkCipher::Aes256Gcm,
            pfs_group: None,
            mode_cfg: false,
            ipv6: false,
            mode: Ikev1ExchangeMode::Aggressive,
            p1_lifetime_secs: 1200,
            p2_lifetime_secs: 3600,
        };
        let rcfg = Phase1Config {
            local_auth: Ikev1LocalAuth::Psk(psk.clone()),
            trusted_cas: Vec::new(),
            now_unix: 0,
            our_id: Id::ipv4([192, 168, 0, 1]),
        };

        // Aggressive Mode.
        let mut ie = SeedEntropy::new(0xE1E1);
        let mut re = SeedEntropy::new(0xE2E2);
        let (msg1, ai) = initiate_aggressive(&icfg, &mut ie, "10.1.1.1:500".parse().unwrap(), "192.168.0.1:500".parse().unwrap());
        let (msg2, rstate) = respond_aggressive(&rcfg, &msg1, &mut re, "192.168.0.1:500".parse().unwrap(), "10.1.1.1:500".parse().unwrap()).unwrap();
        let (_msg3, istate) = ai.complete(&msg2, "10.1.1.1:500".parse().unwrap(), "192.168.0.1:500".parse().unwrap()).unwrap();
        assert_eq!(istate.negotiated_lifetime_secs, 1200);
        assert_eq!(rstate.negotiated_lifetime_secs, 1200);

        // Main Mode -- same configured lifetime, different exchange.
        icfg.mode = Ikev1ExchangeMode::Main;
        let mut ie = SeedEntropy::new(0xE3E3);
        let mut re = SeedEntropy::new(0xE4E4);
        let (msg1, sa_sent) = initiate_main(&icfg, &mut ie);
        let (msg2, r1) = respond_main(&rcfg, &msg1, &mut re, "192.168.0.1:500".parse().unwrap(), "10.1.1.1:500".parse().unwrap()).unwrap();
        let (msg3, ke_sent) = sa_sent.complete_sa(&msg2, &mut ie, "10.1.1.1:500".parse().unwrap(), "192.168.0.1:500".parse().unwrap()).unwrap();
        let (msg4, r2) = r1.complete_ke(&msg3, &mut re).unwrap();
        let (msg5, id_sent) = ke_sent.complete_ke(&msg4).unwrap();
        let (msg6, rstate) = r2.complete_id(&msg5).unwrap();
        let istate = id_sent.complete_id(&msg6, &mut ie).unwrap();
        assert_eq!(istate.negotiated_lifetime_secs, 1200);
        assert_eq!(rstate.negotiated_lifetime_secs, 1200);
    }
}
