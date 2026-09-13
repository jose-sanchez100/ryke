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
    attr, auth, enc, hash, life, protocol, Attribute, Id, Proposal, SaPayload, Transform, IPSEC_DOI,
    SIT_IDENTITY_ONLY,
};
use crate::crypto::DhGroup;
use crate::entropy::Entropy;
use crate::error::IkeError;
use crate::ikev2::sk::SkCipher;

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

/// The XAUTH auth methods occupy the private range 65001..=65010
/// (XAUTHInit/Resp × PreShared/DSS/RSA/…).
fn is_xauth_auth(method: u16) -> bool {
    (65001..=65010).contains(&method)
}

/// The responder's Phase-1 configuration.
pub struct Phase1Config {
    pub psk: Vec<u8>,
    /// The identity we assert in `IDr` (must be the one the peer's PSK maps to).
    pub our_id: Id,
}

/// Everything Phase 1 establishes, carried into the encrypted exchanges.
#[derive(Clone)]
pub struct Phase1State {
    pub prf: Prf,
    pub group: DhGroup,
    pub cky_i: [u8; 8],
    pub cky_r: [u8; 8],
    pub skeyid: Vec<u8>,
    pub skeyid_d: Vec<u8>,
    pub skeyid_a: Vec<u8>,
    pub skeyid_e: Vec<u8>,
    /// Derived AES-256 key.
    pub enc_key: Vec<u8>,
    /// `HASH(g^xi | g^xr)` — the seed for every post-Phase-1 message IV.
    pub phase1_iv: Vec<u8>,
    pub gxi: Vec<u8>,
    pub gxr: Vec<u8>,
    pub ni: Vec<u8>,
    pub nr: Vec<u8>,
    /// The initiator's SA-payload body and ID body — needed to verify `HASH_I`.
    sai_b: Vec<u8>,
    idii_b: Vec<u8>,
    /// Whether the peer's own Phase-1 message echoed [`DPD_VENDOR_ID`].
    pub peer_supports_dpd: bool,
}

/// Pick the first offered transform we support: AES-256-CBC, HASH SHA-256 (or
/// SHA-1), DH group 2 (or 14), PSK or XAUTH-PSK auth. Returns the transform to
/// echo plus the mapped primitives.
fn select_transform(sa: &SaPayload) -> Option<(Transform, Prf, DhGroup, usize)> {
    for prop in &sa.proposals {
        for t in &prop.transforms {
            if t.attr(attr::ENCRYPTION) != Some(enc::AES_CBC) || t.attr(attr::KEY_LENGTH) != Some(256) {
                continue;
            }
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
            match t.attr(attr::AUTH_METHOD) {
                Some(auth::PSK) | Some(auth::XAUTH_INIT_PSK) => {}
                _ => continue,
            }
            return Some((t.clone(), prf, group, 32));
        }
    }
    None
}

fn find(payloads: &[isakmp::Payload], t: u8) -> Option<&isakmp::Payload> {
    payloads.iter().find(|p| p.payload_type == t)
}

/// Process Aggressive-Mode message 1 and build message 2. Returns the response
/// bytes and the Phase-1 state (which then verifies `HASH_I`).
pub fn respond_aggressive(
    cfg: &Phase1Config,
    msg1: &[u8],
    entropy: &mut impl Entropy,
) -> Result<(Vec<u8>, Phase1State), IkeError> {
    let hdr = IsakmpHeader::parse(msg1)?;
    if hdr.exchange_type != exchange::AGGRESSIVE {
        return Err(IkeError::Crypto("not an Aggressive Mode message"));
    }
    let cky_i = hdr.init_cookie;
    let ps = isakmp::parse_payloads(hdr.next_payload, &msg1[IsakmpHeader::LEN..])?;

    let sa_p = find(&ps, payload::SA).ok_or(IkeError::MissingPayload("SA"))?;
    let ke_p = find(&ps, payload::KE).ok_or(IkeError::MissingPayload("KE"))?;
    let nonce_p = find(&ps, payload::NONCE).ok_or(IkeError::MissingPayload("NONCE"))?;
    let id_p = find(&ps, payload::ID).ok_or(IkeError::MissingPayload("ID"))?;

    let sai_b = sa_p.data.clone(); // signed as SAi_b
    let idii_b = id_p.data.clone(); // signed as IDii_b
    let gxi = ke_p.data.clone();
    let ni = nonce_p.data.clone();
    let peer_supports_dpd = ps.iter().any(|p| p.payload_type == payload::VENDOR_ID && p.data == DPD_VENDOR_ID);

    let sa = SaPayload::parse(&sa_p.data)?;
    let (chosen, prf, group, key_len) =
        select_transform(&sa).ok_or(IkeError::NoProposalChosen)?;
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
    let skeyid = crypto1::skeyid_psk(prf, &cfg.psk, &ni, &nr);
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
            decrypted = crypto1::aes256_cbc_decrypt(&self.enc_key, &self.phase1_iv, body)?;
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
    pub psk: Vec<u8>,
    /// The identity we assert in `IDi`.
    pub our_id: Id,
    /// DH group to offer (MODP-1024 or MODP-2048).
    pub group: DhGroup,
    /// Offer the XAUTH-PSK auth method — required by gateways that mandate XAUTH
    /// (e.g. Android's native client). With plain PSK, Quick Mode follows directly.
    pub xauth: bool,
    /// Quick-Mode traffic selectors offered as IDci/IDcr: `(address, netmask)`.
    pub ts_local: ([u8; 4], [u8; 4]),
    pub ts_remote: ([u8; 4], [u8; 4]),
    /// The ESP cipher to offer for the CHILD SA (Quick Mode's own SA
    /// payload) -- unlike Phase 1 (still fixed AES-256-CBC/SHA-256, see
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
    /// Which Phase-1 exchange to run -- see [`Ikev1ExchangeMode`].
    pub mode: Ikev1ExchangeMode,
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

/// The initiator's SA offer: AES-256-CBC / SHA-256 / `group` / PSK (or XAUTH-PSK).
fn initiator_sa(group: DhGroup, xauth: bool) -> SaPayload {
    let auth_method = if xauth { auth::XAUTH_INIT_PSK } else { auth::PSK };
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
                    Attribute::short(attr::KEY_LENGTH, 256),
                    Attribute::short(attr::HASH, hash::SHA2_256),
                    Attribute::short(attr::GROUP_DESC, group.transform_id()),
                    Attribute::short(attr::AUTH_METHOD, auth_method),
                    Attribute::short(attr::LIFE_TYPE, life::SECONDS),
                    Attribute::long_u32(attr::LIFE_DURATION, 28800),
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
}

/// Build Aggressive-Mode message 1 (`HDR, SA, KE, Ni, IDi`) as the initiator.
/// Returns the wire bytes and the state that completes the exchange.
pub fn initiate_aggressive(cfg: &InitiatorConfig, entropy: &mut impl Entropy) -> (Vec<u8>, AggressiveInitiator) {
    let prf = Prf::Sha256;
    let mut cky_i = [0u8; 8];
    entropy.fill(&mut cky_i);
    let dh_private = entropy.next_array32();
    let gxi = cfg.group.public(&dh_private);
    let mut ni = vec![0u8; 16];
    entropy.fill(&mut ni);

    let sa = initiator_sa(cfg.group, cfg.xauth);
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
    let msg1 = isakmp::build_message(hdr, &[
        (payload::SA, sai_b.clone()),
        (payload::KE, gxi.clone()),
        (payload::NONCE, ni.clone()),
        (payload::ID, idi_b.clone()),
        (payload::VENDOR_ID, DPD_VENDOR_ID.to_vec()),
    ]);

    let state = AggressiveInitiator {
        prf,
        group: cfg.group,
        psk: cfg.psk.clone(),
        cky_i,
        dh_private,
        gxi,
        ni,
        idi_b,
        sai_b,
        key_len: 32,
    };
    (msg1, state)
}

impl AggressiveInitiator {
    /// Process message 2 (`HDR, SA, KE, Nr, IDr, HASH_R`): verify the responder's
    /// `HASH_R`, and return message 3 (`HDR, HASH_I`) plus the completed Phase-1
    /// state ready to drive Quick Mode.
    pub fn complete(self, msg2: &[u8]) -> Result<(Vec<u8>, Phase1State), IkeError> {
        let hdr = IsakmpHeader::parse(msg2)?;
        if hdr.exchange_type != exchange::AGGRESSIVE {
            return Err(IkeError::Crypto("not an Aggressive Mode message"));
        }
        let cky_r = hdr.resp_cookie;
        let ps = isakmp::parse_payloads(hdr.next_payload, &msg2[IsakmpHeader::LEN..])?;
        let gxr = find(&ps, payload::KE).ok_or(IkeError::MissingPayload("KE"))?.data.clone();
        let nr = find(&ps, payload::NONCE).ok_or(IkeError::MissingPayload("NONCE"))?.data.clone();
        let hash_r_got = find(&ps, payload::HASH).ok_or(IkeError::MissingPayload("HASH"))?.data.clone();
        let idr_b = find(&ps, payload::ID).ok_or(IkeError::MissingPayload("ID"))?.data.clone();
        let peer_supports_dpd = ps.iter().any(|p| p.payload_type == payload::VENDOR_ID && p.data == DPD_VENDOR_ID);

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
    let sa = initiator_sa(cfg.group, cfg.xauth);
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
    let msg1 = isakmp::build_message(hdr, &[(payload::SA, sai_b.clone())]);

    let state = MainSaSent { group: cfg.group, psk: cfg.psk.clone(), our_id: cfg.our_id.clone(), cky_i, sai_b };
    (msg1, state)
}

/// Post-message-1 Main-Mode initiator state.
pub struct MainSaSent {
    group: DhGroup,
    psk: Vec<u8>,
    our_id: Id,
    cky_i: [u8; 8],
    sai_b: Vec<u8>,
}

impl MainSaSent {
    /// Process message 2 (`HDR, SA`) and build message 3 (`HDR, KE, Ni, VID(DPD)`).
    pub fn complete_sa(self, msg2: &[u8], entropy: &mut impl Entropy) -> Result<(Vec<u8>, MainKeSent), IkeError> {
        let hdr = IsakmpHeader::parse(msg2)?;
        if hdr.exchange_type != exchange::MAIN {
            return Err(IkeError::Crypto("not a Main Mode message"));
        }
        let cky_r = hdr.resp_cookie;
        let ps = isakmp::parse_payloads(hdr.next_payload, &msg2[IsakmpHeader::LEN..])?;
        find(&ps, payload::SA).ok_or(IkeError::MissingPayload("SA"))?;

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
        let msg3 = isakmp::build_message(hdr3, &[
            (payload::KE, gxi.clone()),
            (payload::NONCE, ni.clone()),
            (payload::VENDOR_ID, DPD_VENDOR_ID.to_vec()),
        ]);

        let state = MainKeSent {
            group: self.group,
            psk: self.psk,
            our_id: self.our_id,
            cky_i: self.cky_i,
            cky_r,
            sai_b: self.sai_b,
            dh_private,
            gxi,
            ni,
        };
        Ok((msg3, state))
    }
}

/// Post-message-3 Main-Mode initiator state.
pub struct MainKeSent {
    group: DhGroup,
    psk: Vec<u8>,
    our_id: Id,
    cky_i: [u8; 8],
    cky_r: [u8; 8],
    sai_b: Vec<u8>,
    dh_private: [u8; 32],
    gxi: Vec<u8>,
    ni: Vec<u8>,
}

impl MainKeSent {
    /// Process message 4 (`HDR, KE, Nr, [VID(DPD)]`), derive the Phase-1 key
    /// schedule, and build message 5 (`HDR*, IDi, HASH_I`, encrypted).
    pub fn complete_ke(self, msg4: &[u8]) -> Result<(Vec<u8>, MainIdSent), IkeError> {
        let hdr = IsakmpHeader::parse(msg4)?;
        if hdr.exchange_type != exchange::MAIN {
            return Err(IkeError::Crypto("not a Main Mode message"));
        }
        let ps = isakmp::parse_payloads(hdr.next_payload, &msg4[IsakmpHeader::LEN..])?;
        let gxr = find(&ps, payload::KE).ok_or(IkeError::MissingPayload("KE"))?.data.clone();
        let nr = find(&ps, payload::NONCE).ok_or(IkeError::MissingPayload("NONCE"))?.data.clone();
        let peer_supports_dpd = ps.iter().any(|p| p.payload_type == payload::VENDOR_ID && p.data == DPD_VENDOR_ID);

        if gxr.len() != self.group.public_len() {
            return Err(IkeError::BadKeyExchange { group: self.group.transform_id(), len: gxr.len() });
        }
        let prf = Prf::Sha256;
        let gxy = self.group.shared(&self.dh_private, &gxr)?;
        let skeyid = crypto1::skeyid_psk(prf, &self.psk, &self.ni, &nr);
        let skeyid_d = crypto1::skeyid_d(prf, &skeyid, &gxy, &self.cky_i, &self.cky_r);
        let skeyid_a = crypto1::skeyid_a(prf, &skeyid, &skeyid_d, &gxy, &self.cky_i, &self.cky_r);
        let skeyid_e = crypto1::skeyid_e(prf, &skeyid, &skeyid_a, &gxy, &self.cky_i, &self.cky_r);
        let enc_key = crypto1::derive_cipher_key(prf, &skeyid_e, 32);
        let phase1_iv = crypto1::phase1_iv(prf, &self.gxi, &gxr, AES_BLOCK);

        let idi_b = self.our_id.to_bytes();
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
        let (msg5, iv_after_msg5) = phase2::encrypt_payloads(
            hdr5,
            &enc_key,
            &phase1_iv,
            &[(payload::ID, idi_b.clone()), (payload::HASH, hash_i)],
        )?;

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
            iv_after_msg5,
            peer_supports_dpd,
        };
        Ok((msg5, state))
    }
}

/// Post-message-5 Main-Mode initiator state: the key schedule is derived and
/// message 5 is already sent — only the responder's message 6 (`HASH_R`)
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
    /// Not the raw `HASH(g^xi|g^xr)` Phase-1 seed -- that's only needed to
    /// encrypt message 5 itself (already consumed by the time this struct
    /// exists). This is the IV chained forward past message 5's own
    /// ciphertext, needed to decrypt message 6.
    iv_after_msg5: Vec<u8>,
    peer_supports_dpd: bool,
}

impl MainIdSent {
    /// Process message 6 (`HDR*, IDr, HASH_R`, encrypted): verify the
    /// responder's `HASH_R` and return the completed, authenticated [`Phase1State`].
    pub fn complete_id(self, msg6: &[u8]) -> Result<Phase1State, IkeError> {
        let (_hdr, ps, iv_after_msg6) = phase2::decrypt_payloads(msg6, &self.enc_key, &self.iv_after_msg5)?;
        let idr_b = find(&ps, payload::ID).ok_or(IkeError::MissingPayload("ID"))?.data.clone();
        let hash_r_got = find(&ps, payload::HASH).ok_or(IkeError::MissingPayload("HASH"))?.data.clone();
        let expect_hr = crypto1::hash_r(self.prf, &self.skeyid, &self.gxr, &self.gxi, &self.cky_r, &self.cky_i, &self.sai_b, &idr_b);
        if hash_r_got != expect_hr {
            return Err(IkeError::AuthFailed);
        }
        Ok(Phase1State {
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
        })
    }
}

// ---- Main Mode responder (for self-testing against `ikev1::Client`) ----

/// Process Main-Mode message 1 (`HDR, SA`) and build message 2 (`HDR, SA`),
/// choosing a fresh responder cookie and echoing the selected transform.
pub fn respond_main(cfg: &Phase1Config, msg1: &[u8], entropy: &mut impl Entropy) -> Result<(Vec<u8>, MainRespSaSent), IkeError> {
    let hdr = IsakmpHeader::parse(msg1)?;
    if hdr.exchange_type != exchange::MAIN {
        return Err(IkeError::Crypto("not a Main Mode message"));
    }
    let cky_i = hdr.init_cookie;
    let ps = isakmp::parse_payloads(hdr.next_payload, &msg1[IsakmpHeader::LEN..])?;
    let sa_p = find(&ps, payload::SA).ok_or(IkeError::MissingPayload("SA"))?;
    let sai_b = sa_p.data.clone();
    let sa = SaPayload::parse(&sai_b)?;
    let (chosen, prf, group, key_len) = select_transform(&sa).ok_or(IkeError::NoProposalChosen)?;

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
    let msg2 = isakmp::build_message(hdr2, &[(payload::SA, sar.to_bytes())]);

    let state = MainRespSaSent { prf, group, key_len, cky_i, cky_r, psk: cfg.psk.clone(), our_id: cfg.our_id.clone(), sai_b };
    Ok((msg2, state))
}

/// Post-message-2 Main-Mode responder state.
pub struct MainRespSaSent {
    prf: Prf,
    group: DhGroup,
    key_len: usize,
    cky_i: [u8; 8],
    cky_r: [u8; 8],
    psk: Vec<u8>,
    our_id: Id,
    sai_b: Vec<u8>,
}

impl MainRespSaSent {
    /// Process message 3 (`HDR, KE, Ni, [VID(DPD)]`) and build message 4
    /// (`HDR, KE, Nr, VID(DPD)`).
    pub fn complete_ke(self, msg3: &[u8], entropy: &mut impl Entropy) -> Result<(Vec<u8>, MainRespKeSent), IkeError> {
        let hdr = IsakmpHeader::parse(msg3)?;
        if hdr.exchange_type != exchange::MAIN {
            return Err(IkeError::Crypto("not a Main Mode message"));
        }
        let ps = isakmp::parse_payloads(hdr.next_payload, &msg3[IsakmpHeader::LEN..])?;
        let gxi = find(&ps, payload::KE).ok_or(IkeError::MissingPayload("KE"))?.data.clone();
        let ni = find(&ps, payload::NONCE).ok_or(IkeError::MissingPayload("NONCE"))?.data.clone();
        let peer_supports_dpd = ps.iter().any(|p| p.payload_type == payload::VENDOR_ID && p.data == DPD_VENDOR_ID);

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
        let msg4 = isakmp::build_message(hdr4, &[
            (payload::KE, gxr.clone()),
            (payload::NONCE, nr.clone()),
            (payload::VENDOR_ID, DPD_VENDOR_ID.to_vec()),
        ]);

        let state = MainRespKeSent {
            prf: self.prf,
            group: self.group,
            key_len: self.key_len,
            cky_i: self.cky_i,
            cky_r: self.cky_r,
            psk: self.psk,
            our_id: self.our_id,
            sai_b: self.sai_b,
            gxi,
            gxr,
            dh_private,
            ni,
            nr,
            peer_supports_dpd,
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
    psk: Vec<u8>,
    our_id: Id,
    sai_b: Vec<u8>,
    gxi: Vec<u8>,
    gxr: Vec<u8>,
    dh_private: [u8; 32],
    ni: Vec<u8>,
    nr: Vec<u8>,
    peer_supports_dpd: bool,
}

impl MainRespKeSent {
    /// Process message 5 (`HDR*, IDi, HASH_I`, encrypted): derive the
    /// Phase-1 key schedule, verify the initiator's `HASH_I`, and build
    /// message 6 (`HDR*, IDr, HASH_R`, encrypted) plus the completed
    /// [`Phase1State`].
    pub fn complete_id(self, msg5: &[u8]) -> Result<(Vec<u8>, Phase1State), IkeError> {
        let gxy = self.group.shared(&self.dh_private, &self.gxi)?;
        let skeyid = crypto1::skeyid_psk(self.prf, &self.psk, &self.ni, &self.nr);
        let skeyid_d = crypto1::skeyid_d(self.prf, &skeyid, &gxy, &self.cky_i, &self.cky_r);
        let skeyid_a = crypto1::skeyid_a(self.prf, &skeyid, &skeyid_d, &gxy, &self.cky_i, &self.cky_r);
        let skeyid_e = crypto1::skeyid_e(self.prf, &skeyid, &skeyid_a, &gxy, &self.cky_i, &self.cky_r);
        let enc_key = crypto1::derive_cipher_key(self.prf, &skeyid_e, self.key_len);
        let phase1_iv = crypto1::phase1_iv(self.prf, &self.gxi, &self.gxr, AES_BLOCK);

        let (_hdr, ps, iv_after_msg5) = phase2::decrypt_payloads(msg5, &enc_key, &phase1_iv)?;
        let idii_b = find(&ps, payload::ID).ok_or(IkeError::MissingPayload("ID"))?.data.clone();
        let hash_i_got = find(&ps, payload::HASH).ok_or(IkeError::MissingPayload("HASH"))?.data.clone();
        let expect_hi = crypto1::hash_i(self.prf, &skeyid, &self.gxi, &self.gxr, &self.cky_i, &self.cky_r, &self.sai_b, &idii_b);
        if hash_i_got != expect_hi {
            return Err(IkeError::AuthFailed);
        }

        let idir_b = self.our_id.to_bytes();
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
        let (msg6, iv_after_msg6) = phase2::encrypt_payloads(hdr6, &enc_key, &iv_after_msg5, &[(payload::ID, idir_b), (payload::HASH, hash_r)])?;

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
        };
        Ok((msg6, state))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::payloads::id_type;
    use crate::entropy::SeedEntropy;

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
        let cfg = Phase1Config { psk: b"testpsk".to_vec(), our_id: Id::ipv4([192, 168, 3, 204]) };
        let cky_i = [0xAB; 8];
        let mut ie = SeedEntropy::new(7);
        let i_priv = ie.next_array32();
        let gxi = DhGroup::Modp1024.public(&i_priv);
        let ni = vec![0x11; 16];
        let idi = Id { id_type: id_type::KEY_ID, protocol: 0, port: 0, data: b"grp".to_vec() };

        let msg1 = client_msg1(cky_i, &gxi, &ni, &idi);
        let (msg2, st) = respond_aggressive(&cfg, &msg1, &mut SeedEntropy::new(9)).unwrap();
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
    fn wrong_psk_fails_hash_i() {
        let cfg = Phase1Config { psk: b"right".to_vec(), our_id: Id::ipv4([10, 0, 0, 1]) };
        let cky_i = [0x01; 8];
        let mut ie = SeedEntropy::new(3);
        let i_priv = ie.next_array32();
        let gxi = DhGroup::Modp1024.public(&i_priv);
        let idi = Id { id_type: id_type::KEY_ID, protocol: 0, port: 0, data: b"g".to_vec() };
        let msg1 = client_msg1(cky_i, &gxi, &[0x22; 16], &idi);
        let (msg2, st) = respond_aggressive(&cfg, &msg1, &mut SeedEntropy::new(4)).unwrap();
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
        let icfg = InitiatorConfig {
            psk: b"correct horse battery staple".to_vec(),
            our_id: Id::ipv4([10, 1, 1, 1]),
            group: DhGroup::Modp1024,
            xauth: false,
            ts_local: ([0, 0, 0, 0], [0, 0, 0, 0]),
            ts_remote: ([0, 0, 0, 0], [0, 0, 0, 0]),
            esp_cipher: crate::ikev2::sk::SkCipher::Aes256Gcm,
            pfs_group: None,
            mode_cfg: false,
            mode: Ikev1ExchangeMode::Aggressive,
        };
        let rcfg = Phase1Config { psk: icfg.psk.clone(), our_id: Id::ipv4([192, 168, 0, 1]) };
        let mut ie = SeedEntropy::new(0x1111);
        let mut re = SeedEntropy::new(0x2222);
        let (msg1, ai) = initiate_aggressive(&icfg, &mut ie);
        let (msg2, rstate) = respond_aggressive(&rcfg, &msg1, &mut re).unwrap();
        let (msg3, istate) = ai.complete(&msg2).unwrap();
        rstate.verify_hash_i(&msg3).unwrap();

        assert!(istate.peer_supports_dpd, "initiator should recognize the responder's echoed DPD VID");
        assert!(rstate.peer_supports_dpd, "responder should recognize the initiator's offered DPD VID");
    }

    fn main_mode_icfg(psk: Vec<u8>) -> InitiatorConfig {
        InitiatorConfig {
            psk,
            our_id: Id::ipv4([10, 1, 1, 1]),
            group: DhGroup::Modp1024,
            xauth: false,
            ts_local: ([0, 0, 0, 0], [0, 0, 0, 0]),
            ts_remote: ([0, 0, 0, 0], [0, 0, 0, 0]),
            esp_cipher: crate::ikev2::sk::SkCipher::Aes256Gcm,
            pfs_group: None,
            mode_cfg: false,
            mode: Ikev1ExchangeMode::Main,
        }
    }

    #[test]
    fn full_main_phase1_against_an_in_process_responder() {
        let icfg = main_mode_icfg(b"correct horse battery staple".to_vec());
        let rcfg = Phase1Config { psk: icfg.psk.clone(), our_id: Id::ipv4([192, 168, 0, 1]) };
        let mut ie = SeedEntropy::new(0x3333);
        let mut re = SeedEntropy::new(0x4444);

        let (msg1, sa_sent) = initiate_main(&icfg, &mut ie);
        let (msg2, r1) = respond_main(&rcfg, &msg1, &mut re).unwrap();
        let (msg3, ke_sent) = sa_sent.complete_sa(&msg2, &mut ie).unwrap();
        let (msg4, r2) = r1.complete_ke(&msg3, &mut re).unwrap();
        let (msg5, id_sent) = ke_sent.complete_ke(&msg4).unwrap();
        let (msg6, rstate) = r2.complete_id(&msg5).unwrap();
        let istate = id_sent.complete_id(&msg6).unwrap();

        assert_eq!(istate.skeyid_e, rstate.skeyid_e, "both sides must derive the same SKEYID_e");
        assert_eq!(istate.enc_key, rstate.enc_key);
        assert!(istate.peer_supports_dpd, "initiator should recognize the responder's echoed DPD VID (msg4)");
        assert!(rstate.peer_supports_dpd, "responder should recognize the initiator's offered DPD VID (msg3)");

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
    fn wrong_psk_fails_main_mode_hash_i() {
        // Unlike Aggressive Mode's `wrong_psk_fails_hash_i` (whose msg3 can
        // arrive in the clear, so a bad HASH_I is a clean `AuthFailed`), Main
        // Mode's msg5 is *always* encrypted -- a wrong PSK means a wrong
        // SKEYID_e, so the responder decrypts to garbage and typically fails
        // at payload parsing rather than ever reaching the HASH comparison.
        // Either way, the property under test is the same: a wrong PSK must
        // never yield an established Phase1State.
        let icfg = main_mode_icfg(b"right".to_vec());
        let rcfg = Phase1Config { psk: b"wrong".to_vec(), our_id: Id::ipv4([192, 168, 0, 1]) };
        let mut ie = SeedEntropy::new(0x5555);
        let mut re = SeedEntropy::new(0x6666);

        let (msg1, sa_sent) = initiate_main(&icfg, &mut ie);
        let (msg2, r1) = respond_main(&rcfg, &msg1, &mut re).unwrap();
        let (msg3, ke_sent) = sa_sent.complete_sa(&msg2, &mut ie).unwrap();
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
        let icfg = main_mode_icfg(b"correct horse battery staple".to_vec());
        let rcfg = Phase1Config { psk: icfg.psk.clone(), our_id: Id::ipv4([192, 168, 0, 1]) };
        let mut ie = SeedEntropy::new(0x9999);
        let mut re = SeedEntropy::new(0xAAAA);

        let (msg1, sa_sent) = initiate_main(&icfg, &mut ie);
        let (msg2, r1) = respond_main(&rcfg, &msg1, &mut re).unwrap();
        let (msg3, ke_sent) = sa_sent.complete_sa(&msg2, &mut ie).unwrap();
        let (msg4, r2) = r1.complete_ke(&msg3, &mut re).unwrap();
        let (msg5, id_sent) = ke_sent.complete_ke(&msg4).unwrap();
        let (mut msg6, _rstate) = r2.complete_id(&msg5).unwrap();
        *msg6.last_mut().unwrap() ^= 0xFF; // corrupt the tail of the encrypted HASH_R
        assert!(id_sent.complete_id(&msg6).is_err(), "a tampered HASH_R must never verify");
    }
}
