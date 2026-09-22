//! Suite negotiation for `IKE_SA_INIT`.
//!
//! From the initiator's Security Association, pick a proposal we support and
//! describe the chosen suite (transforms + key lengths for the schedule).
//! Also used by [`crate::ikev2::exchange::initiator_complete`] to interpret
//! whichever single suite the *responder* echoed back -- so widening the
//! candidate lists here is what lets the initiator (not just a hypothetical
//! `ryke` responder) recognize a broader proposal.
//!
//! ENCR candidates, strongest-first: ChaCha20-Poly1305, AES-GCM-16 (256/192/
//! 128), AES-CBC (256/192/128), 3DES. PRF/INTEG candidates, strongest-first:
//! SHA2-512, SHA2-384, SHA2-256, SHA-1. DH candidates, strongest-first:
//! X25519, ECP-521/384/256, MODP-8192 down to MODP-1024.
//!
//! PRF_HMAC_MD5, AUTH_HMAC_MD5_96 and MODP-768 (group 1) are deliberately
//! absent from these tables: RFC 8247 marks all three MUST NOT for IKEv2, so
//! this crate must neither offer them as an initiator nor accept a peer's
//! echo of them, even though the wire format and `crypto`/`payload` modules
//! can still represent them (IKEv1, governed by different RFCs, still uses
//! them via its own, separate negotiation path).
//!
//! Note: an **IKE** proposal carries ENCR, PRF, (INTEG for non-AEAD), and D-H —
//! but *not* ESN. ESN is only valid for ESP/AH (CHILD SA) proposals
//! (RFC 7296 §3.3.3), so it is neither required nor emitted here.
//!
//! **IKE-level (SK{} payload) cipher support is now complete** (Phase F,
//! `ikev2::sk::SkCipher`): every ENCR/INTEG combination this module can
//! select has a real AES-GCM/ChaCha20-Poly1305/AES-CBC/3DES-CBC
//! implementation. A **responder** (accepting whatever an arbitrary peer
//! offers) can already exercise the full matrix today. An **initiator**
//! (e.g. `ryke`'s own client path) cannot yet, for two remaining reasons:
//! `exchange::default_offer`/`ike_auth::esp_offer` still only ever construct
//! the original AES-GCM-256/SHA256/X25519 proposal (widening that is Phase
//! H, free-vpn-v2's job -- it's what actually lets a *client* request a
//! different combination from a gateway), and the **CHILD SA / ESP data
//! plane** (`esp.rs`) still only implements AES-GCM-256 (Phase G, pending).
//! So: do not widen `default_offer`/`esp_offer`'s ENCR/INTEG choices for the
//! IKE SA before `sk.rs` supports them (already true as of Phase F) -- but
//! also do not widen `esp_offer`'s ENCR/INTEG choices for the CHILD SA
//! before `esp.rs` supports them (still not true; Phase G first).

use crate::crypto::{IntegAlgorithm, KeyLengths, PrfAlgorithm};
use crate::ikev2::payload::{protocol_id, transform_id, transform_type, Proposal, SecurityAssociation, Transform};

/// The concrete suite chosen from an initiator proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChosenSuite {
    pub proposal_num: u8,
    pub encr_id: u16,
    pub encr_key_bits: u16,
    pub prf_id: u16,
    /// `None` for an AEAD cipher (AES-GCM), which needs no separate integrity.
    pub integ_id: Option<u16>,
    pub dh_id: u16,
}

impl ChosenSuite {
    /// The negotiated PRF, as a [`crate::crypto::PrfAlgorithm`] for
    /// `prf`/`prf+`-based key derivation.
    pub fn prf_algorithm(&self) -> PrfAlgorithm {
        PrfAlgorithm::from_transform_id(self.prf_id).expect("prf_id was validated by select_from_proposal")
    }

    /// The negotiated SK{} payload cipher (RFC 7296 §3.14), for
    /// [`crate::ikev2::sk::build_encrypted`]/[`crate::ikev2::sk::open_encrypted`].
    /// Always succeeds: every combination `select_from_proposal` can produce
    /// has a corresponding [`crate::ikev2::sk::SkCipher`] variant.
    pub fn sk_cipher(&self) -> crate::ikev2::sk::SkCipher {
        crate::ikev2::sk::SkCipher::from_chosen_suite(self)
            .expect("select_from_proposal only chooses suites sk::SkCipher implements")
    }

    /// Key lengths this suite implies, for [`crate::derive_session_keys`].
    ///
    /// Both AEAD ciphers (AES-GCM, ChaCha20-Poly1305) carry a 4-byte salt
    /// appended to their `SK_e` key (RFC 5282 §4 / RFC 7634 §2); the classic
    /// ciphers (AES-CBC, 3DES) have no salt. `prf`/`integ` lengths come from
    /// the negotiated algorithms' own key lengths, not a fixed SHA-256 size.
    pub fn key_lengths(&self) -> KeyLengths {
        let salt = match self.encr_id {
            transform_id::AES_GCM_16 | transform_id::CHACHA20_POLY1305 => 4,
            _ => 0,
        };
        let integ = self.integ_id.and_then(IntegAlgorithm::from_transform_id).map(IntegAlgorithm::key_len).unwrap_or(0);
        KeyLengths {
            prf: self.prf_algorithm().output_len(),
            integ,
            encr: (self.encr_key_bits / 8) as usize + salt,
        }
    }

    /// Re-express as a single-transform-per-type proposal to echo in the
    /// `IKE_SA_INIT` response (ENCR, PRF, INTEG when non-AEAD, D-H — no ESN).
    pub fn to_proposal(&self) -> Proposal {
        let mut transforms = vec![
            Transform { transform_type: transform_type::ENCR, transform_id: self.encr_id, key_length: Some(self.encr_key_bits) },
            Transform { transform_type: transform_type::PRF, transform_id: self.prf_id, key_length: None },
        ];
        if let Some(integ) = self.integ_id {
            transforms.push(Transform { transform_type: transform_type::INTEG, transform_id: integ, key_length: None });
        }
        transforms.push(Transform { transform_type: transform_type::DH, transform_id: self.dh_id, key_length: None });
        Proposal { num: self.proposal_num, protocol_id: protocol_id::IKE, spi: Vec::new(), transforms }
    }

    /// Whether every transform this suite names was actually present in
    /// `offer`'s proposal of the matching number. RFC 7296 §2.7: the
    /// responder "MUST select a single suite... from the SA payload" the
    /// initiator sent -- it doesn't get to synthesize a combination from
    /// transforms we'd merely support in general (this crate's own
    /// candidate tables) but never put in this particular offer. Without
    /// this check, a misbehaving or on-path responder could echo back e.g.
    /// AES-CBC-128 in response to an AES-GCM-256-only offer and we'd accept
    /// it as if we'd proposed it -- a silent downgrade.
    pub fn matches_offer(&self, offer: &SecurityAssociation) -> bool {
        let Some(proposal) = offer.proposals.iter().find(|p| p.num == self.proposal_num) else {
            return false;
        };
        // Fixed-key ciphers (ChaCha20-Poly1305, 3DES) carry no key-length
        // attribute on the wire -- same "don't care" shape `has` already
        // uses for them in `select_from_proposal`.
        let encr_key_bits = if fixed_key_bits(self.encr_id).is_some() { None } else { Some(self.encr_key_bits) };
        if !has(proposal, transform_type::ENCR, self.encr_id, encr_key_bits) {
            return false;
        }
        if !has(proposal, transform_type::PRF, self.prf_id, None) {
            return false;
        }
        if let Some(integ) = self.integ_id {
            if !has(proposal, transform_type::INTEG, integ, None) {
                return false;
            }
        }
        has(proposal, transform_type::DH, self.dh_id, None)
    }
}

/// Pick the first initiator proposal we fully support, or `None`.
pub fn select(sa: &SecurityAssociation) -> Option<ChosenSuite> {
    sa.proposals.iter().find_map(select_from_proposal)
}

/// `(transform_id, key_bits, is_aead)`, strongest first. `key_bits: None`
/// means "don't care" (fixed-key ciphers like 3DES/ChaCha20-Poly1305 don't
/// carry a key-length attribute on the wire).
const ENCR_CANDIDATES: &[(u16, Option<u16>, bool)] = &[
    (transform_id::CHACHA20_POLY1305, None, true),
    (transform_id::AES_GCM_16, Some(256), true),
    (transform_id::AES_GCM_16, Some(192), true),
    (transform_id::AES_GCM_16, Some(128), true),
    (transform_id::AES_CBC, Some(256), false),
    (transform_id::AES_CBC, Some(192), false),
    (transform_id::AES_CBC, Some(128), false),
    (transform_id::TRIPLE_DES, None, false),
];

/// The actual crypto key size for a fixed-key cipher (no on-wire key-length
/// attribute) -- ChaCha20-Poly1305 always uses a 256-bit key (RFC 7634 §2);
/// 3DES-EDE3 uses a 192-bit (24-byte) key (three 8-byte DES keys).
fn fixed_key_bits(encr_id: u16) -> Option<u16> {
    match encr_id {
        transform_id::CHACHA20_POLY1305 => Some(256),
        transform_id::TRIPLE_DES => Some(192),
        _ => None,
    }
}

const PRF_CANDIDATES: &[u16] = &[
    transform_id::PRF_HMAC_SHA2_512,
    transform_id::PRF_HMAC_SHA2_384,
    transform_id::PRF_HMAC_SHA2_256,
    transform_id::PRF_HMAC_SHA1,
];

const INTEG_CANDIDATES: &[u16] = &[
    transform_id::AUTH_HMAC_SHA2_512_256,
    transform_id::AUTH_HMAC_SHA2_384_192,
    transform_id::AUTH_HMAC_SHA2_256_128,
    transform_id::AUTH_HMAC_SHA1_96,
];

const DH_CANDIDATES: &[u16] = &[
    transform_id::X25519,
    transform_id::ECP521,
    transform_id::ECP384,
    transform_id::ECP256,
    transform_id::MODP_8192,
    transform_id::MODP_6144,
    transform_id::MODP_4096,
    transform_id::MODP_3072,
    transform_id::MODP_2048,
    transform_id::MODP_1536,
    transform_id::MODP_1024,
];

fn select_from_proposal(proposal: &Proposal) -> Option<ChosenSuite> {
    if proposal.protocol_id != protocol_id::IKE {
        return None;
    }
    let dh_id = DH_CANDIDATES.iter().copied().find(|&g| has(proposal, transform_type::DH, g, None))?;

    for &(encr_id, key_bits, aead) in ENCR_CANDIDATES {
        if !has(proposal, transform_type::ENCR, encr_id, key_bits) {
            continue;
        }
        let encr_key_bits = key_bits.or_else(|| fixed_key_bits(encr_id)).expect("every candidate has a key size");

        if aead {
            let Some(&prf_id) = PRF_CANDIDATES.iter().find(|&&p| has(proposal, transform_type::PRF, p, None)) else {
                continue;
            };
            return Some(ChosenSuite { proposal_num: proposal.num, encr_id, encr_key_bits, prf_id, integ_id: None, dh_id });
        }

        let Some(&prf_id) = PRF_CANDIDATES.iter().find(|&&p| has(proposal, transform_type::PRF, p, None)) else {
            continue;
        };
        let Some(&integ_id) = INTEG_CANDIDATES.iter().find(|&&a| has(proposal, transform_type::INTEG, a, None)) else {
            continue;
        };
        return Some(ChosenSuite {
            proposal_num: proposal.num,
            encr_id,
            encr_key_bits,
            prf_id,
            integ_id: Some(integ_id),
            dh_id,
        });
    }
    None
}

fn has(proposal: &Proposal, ttype: u8, tid: u16, key_bits: Option<u16>) -> bool {
    proposal.transforms.iter().any(|t| {
        t.transform_type == ttype
            && t.transform_id == tid
            && match key_bits {
                Some(bits) => t.key_length == Some(bits),
                None => true,
            }
    })
}

/// The ESP/AH CHILD SA cipher named by an `SAr2`/`SAi2` payload: the
/// ENCR(+INTEG) transform the peer selected from our `esp_offer`. Unlike
/// [`ChosenSuite`] (chosen by *us* from among several offered IKE
/// proposals), this just reads back a single already-resolved transform per
/// type from the peer's answer -- there is no PRF (ESP has none) or DH
/// (unless a PFS group is present, which this doesn't look at yet).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChosenEspSuite {
    pub encr_id: u16,
    pub encr_key_bits: u16,
    pub integ_id: Option<u16>,
    /// Whether the proposal named `ESN_ENABLED` -- an absent ESN transform
    /// (some peers omit it) is taken as `false`, same convention as
    /// [`crate::ikev2::rekey`]'s `choose_child_proposal`. This crate's data
    /// plane ([`crate::esp`]) only implements plain 32-bit sequence numbers,
    /// so `matches_offer` rejects a peer that turns ESN on.
    pub esn: bool,
}

impl ChosenEspSuite {
    /// The cipher this suite implies, for [`crate::esp::ChildSa::derive_with_cipher`].
    /// `None` if the peer named an ENCR/INTEG combination `sk::SkCipher`
    /// doesn't implement.
    pub fn sk_cipher(&self) -> Option<crate::ikev2::sk::SkCipher> {
        crate::ikev2::sk::SkCipher::from_encr_integ(self.encr_id, self.encr_key_bits, self.integ_id)
    }

    /// Whether every transform this suite names was actually present in
    /// `offer`'s ESP/AH proposal. Mirrors [`ChosenSuite::matches_offer`] for
    /// the CHILD SA: RFC 7296 §2.7 requires the peer's SAr2/SAi2 answer to be
    /// built from the ESP proposal *we* sent, not merely a combination
    /// `select_esp`/`sk::SkCipher` knows how to decode. Without this check, a
    /// misbehaving or on-path peer could answer e.g. AES-CBC-128/HMAC-SHA1 to
    /// an AES-GCM-256-only ESP offer (silently downgrading the data-plane
    /// cipher we derive and run), or turn ESN on when we only offered
    /// `ESN_NONE` (this crate's 32-bit ESP sequence counters would then
    /// disagree with what the peer believes it negotiated).
    pub fn matches_offer(&self, offer: &SecurityAssociation) -> bool {
        let Some(proposal) = offer.proposals.iter().find(|p| p.protocol_id == protocol_id::ESP) else {
            return false;
        };
        let encr_key_bits = if fixed_key_bits(self.encr_id).is_some() { None } else { Some(self.encr_key_bits) };
        if !has(proposal, transform_type::ENCR, self.encr_id, encr_key_bits) {
            return false;
        }
        match self.integ_id {
            Some(integ) => {
                if !has(proposal, transform_type::INTEG, integ, None) {
                    return false;
                }
            }
            None => {
                if proposal.transforms.iter().any(|t| t.transform_type == transform_type::INTEG) {
                    return false;
                }
            }
        }
        let wanted_esn = if self.esn { transform_id::ESN_ENABLED } else { transform_id::ESN_NONE };
        esn_matches(proposal, wanted_esn)
    }
}

/// Whether `proposal`'s ESN transform (if any) is `esn_id` -- an altogether
/// absent ESN transform is taken as `ESN_NONE`, same convention
/// [`crate::ikev2::rekey`]'s `choose_child_proposal` already uses.
fn esn_matches(proposal: &Proposal, esn_id: u16) -> bool {
    let mut named = proposal.transforms.iter().filter(|t| t.transform_type == transform_type::ESN).map(|t| t.transform_id);
    match named.next() {
        Some(_) => proposal.transforms.iter().any(|t| t.transform_type == transform_type::ESN && t.transform_id == esn_id),
        None => esn_id == transform_id::ESN_NONE,
    }
}

/// Extract the [`ChosenEspSuite`] from an ESP/AH proposal (`SAr2`/`SAi2`).
/// `None` if `sa` carries no ESP proposal, or that proposal has no ENCR
/// transform (a malformed peer answer).
pub fn select_esp(sa: &SecurityAssociation) -> Option<ChosenEspSuite> {
    let proposal = sa.proposals.iter().find(|p| p.protocol_id == protocol_id::ESP)?;
    let encr = proposal.transforms.iter().find(|t| t.transform_type == transform_type::ENCR)?;
    let encr_key_bits = encr.key_length.or_else(|| fixed_key_bits(encr.transform_id))?;
    let integ_id = proposal
        .transforms
        .iter()
        .find(|t| t.transform_type == transform_type::INTEG)
        .map(|t| t.transform_id);
    let esn = proposal
        .transforms
        .iter()
        .any(|t| t.transform_type == transform_type::ESN && t.transform_id == transform_id::ESN_ENABLED);
    Some(ChosenEspSuite { encr_id: encr.transform_id, encr_key_bits, integ_id, esn })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tf(ttype: u8, id: u16, key_length: Option<u16>) -> Transform {
        Transform { transform_type: ttype, transform_id: id, key_length }
    }

    fn proposal(num: u8, transforms: Vec<Transform>) -> SecurityAssociation {
        SecurityAssociation {
            proposals: vec![Proposal { num, protocol_id: protocol_id::IKE, spi: Vec::new(), transforms }],
        }
    }

    #[test]
    fn selects_aead_suite() {
        let sa = proposal(1, vec![
            tf(transform_type::ENCR, transform_id::AES_GCM_16, Some(256)),
            tf(transform_type::PRF, transform_id::PRF_HMAC_SHA2_256, None),
            tf(transform_type::DH, transform_id::X25519, None),
        ]);
        let chosen = select(&sa).unwrap();
        assert_eq!(chosen.encr_id, transform_id::AES_GCM_16);
        assert_eq!(chosen.integ_id, None);
        assert_eq!(chosen.key_lengths().encr, 36); // AES-256 key (32) + GCM salt (4)
        assert_eq!(chosen.key_lengths().integ, 0);
        // Echoed IKE proposal has neither INTEG (AEAD) nor ESN.
        let echo = chosen.to_proposal();
        assert!(!echo.transforms.iter().any(|t| t.transform_type == transform_type::INTEG));
        assert!(!echo.transforms.iter().any(|t| t.transform_type == transform_type::ESN));
    }

    #[test]
    fn falls_back_to_cbc_hmac() {
        let sa = proposal(1, vec![
            tf(transform_type::ENCR, transform_id::AES_CBC, Some(256)),
            tf(transform_type::INTEG, transform_id::AUTH_HMAC_SHA2_256_128, None),
            tf(transform_type::PRF, transform_id::PRF_HMAC_SHA2_256, None),
            tf(transform_type::DH, transform_id::X25519, None),
        ]);
        let chosen = select(&sa).unwrap();
        assert_eq!(chosen.encr_id, transform_id::AES_CBC);
        assert_eq!(chosen.integ_id, Some(transform_id::AUTH_HMAC_SHA2_256_128));
        assert_eq!(chosen.key_lengths().integ, 32);
    }

    #[test]
    fn rejects_unsupported_dh() {
        let sa = proposal(1, vec![
            tf(transform_type::ENCR, transform_id::AES_GCM_16, Some(256)),
            tf(transform_type::PRF, transform_id::PRF_HMAC_SHA2_256, None),
            tf(transform_type::DH, 9999, None), // not a real DH group
        ]);
        assert!(select(&sa).is_none());
    }

    #[test]
    fn selects_across_the_full_algorithm_matrix() {
        // ChaCha20-Poly1305 + PRF-SHA512 + ECP521, none of which the original
        // narrow matcher recognized.
        let sa = proposal(1, vec![
            tf(transform_type::ENCR, transform_id::CHACHA20_POLY1305, None),
            tf(transform_type::PRF, transform_id::PRF_HMAC_SHA2_512, None),
            tf(transform_type::DH, transform_id::ECP521, None),
        ]);
        let chosen = select(&sa).unwrap();
        assert_eq!(chosen.encr_id, transform_id::CHACHA20_POLY1305);
        assert_eq!(chosen.encr_key_bits, 256);
        assert_eq!(chosen.prf_id, transform_id::PRF_HMAC_SHA2_512);
        assert_eq!(chosen.dh_id, transform_id::ECP521);
        assert_eq!(chosen.key_lengths().prf, 64);
        assert_eq!(chosen.key_lengths().encr, 36); // 32-byte key + 4-byte salt

        // Legacy classic combo, still supported: 3DES + HMAC-SHA1-96 + PRF-SHA1 + MODP-1024.
        let sa2 = proposal(1, vec![
            tf(transform_type::ENCR, transform_id::TRIPLE_DES, None),
            tf(transform_type::INTEG, transform_id::AUTH_HMAC_SHA1_96, None),
            tf(transform_type::PRF, transform_id::PRF_HMAC_SHA1, None),
            tf(transform_type::DH, transform_id::MODP_1024, None),
        ]);
        let chosen2 = select(&sa2).unwrap();
        assert_eq!(chosen2.encr_id, transform_id::TRIPLE_DES);
        assert_eq!(chosen2.encr_key_bits, 192);
        assert_eq!(chosen2.integ_id, Some(transform_id::AUTH_HMAC_SHA1_96));
        assert_eq!(chosen2.dh_id, transform_id::MODP_1024);
        assert_eq!(chosen2.key_lengths().encr, 24); // 3DES key, no salt
    }

    #[test]
    fn rejects_the_rfc8247_must_not_algorithms() {
        // PRF_HMAC_MD5 and AUTH_HMAC_MD5_96 (RFC 8247 §2.3/§2.4) and
        // MODP-768/group 1 (RFC 8247 §2.5) must never be selectable for
        // IKEv2, even though `ikev2::payload`/`crypto` can still represent
        // them (IKEv1 still uses them via its own negotiation path).
        let md5 = proposal(1, vec![
            tf(transform_type::ENCR, transform_id::TRIPLE_DES, None),
            tf(transform_type::INTEG, transform_id::AUTH_HMAC_MD5_96, None),
            tf(transform_type::PRF, transform_id::PRF_HMAC_MD5, None),
            tf(transform_type::DH, transform_id::MODP_2048, None),
        ]);
        assert!(select(&md5).is_none());

        let modp768 = proposal(1, vec![
            tf(transform_type::ENCR, transform_id::AES_GCM_16, Some(256)),
            tf(transform_type::PRF, transform_id::PRF_HMAC_SHA2_256, None),
            tf(transform_type::DH, transform_id::MODP_768, None),
        ]);
        assert!(select(&modp768).is_none());
    }

    #[test]
    fn prefers_the_strongest_available_combination() {
        // Offer both AES-GCM-256 and ChaCha20-Poly1305 -- ChaCha20-Poly1305
        // is preferred (first in ENCR_CANDIDATES); offer both SHA-256 and
        // SHA-512 PRF -- SHA-512 wins.
        let sa = proposal(1, vec![
            tf(transform_type::ENCR, transform_id::AES_GCM_16, Some(256)),
            tf(transform_type::ENCR, transform_id::CHACHA20_POLY1305, None),
            tf(transform_type::PRF, transform_id::PRF_HMAC_SHA2_256, None),
            tf(transform_type::PRF, transform_id::PRF_HMAC_SHA2_512, None),
            tf(transform_type::DH, transform_id::MODP_2048, None),
            tf(transform_type::DH, transform_id::X25519, None),
        ]);
        let chosen = select(&sa).unwrap();
        assert_eq!(chosen.encr_id, transform_id::CHACHA20_POLY1305);
        assert_eq!(chosen.prf_id, transform_id::PRF_HMAC_SHA2_512);
        assert_eq!(chosen.dh_id, transform_id::X25519);
    }

    #[test]
    fn ignores_esn_if_present() {
        // Some initiators erroneously add ESN to the IKE proposal; we ignore it.
        let sa = proposal(1, vec![
            tf(transform_type::ENCR, transform_id::AES_GCM_16, Some(256)),
            tf(transform_type::PRF, transform_id::PRF_HMAC_SHA2_256, None),
            tf(transform_type::DH, transform_id::X25519, None),
            tf(transform_type::ESN, transform_id::ESN_NONE, None),
        ]);
        assert!(select(&sa).is_some());
    }

    #[test]
    fn echoed_proposal_reparses() {
        let sa = proposal(2, vec![
            tf(transform_type::ENCR, transform_id::AES_GCM_16, Some(256)),
            tf(transform_type::PRF, transform_id::PRF_HMAC_SHA2_256, None),
            tf(transform_type::DH, transform_id::X25519, None),
        ]);
        let chosen = select(&sa).unwrap();
        let echo = SecurityAssociation { proposals: vec![chosen.to_proposal()] };
        assert_eq!(SecurityAssociation::parse(&echo.to_bytes()).unwrap(), echo);
        assert_eq!(echo.proposals[0].num, 2);
    }

    fn esp_proposal(transforms: Vec<Transform>) -> SecurityAssociation {
        SecurityAssociation {
            proposals: vec![Proposal { num: 1, protocol_id: protocol_id::ESP, spi: vec![1, 2, 3, 4], transforms }],
        }
    }

    #[test]
    fn select_esp_reads_back_an_aead_answer() {
        let sa = esp_proposal(vec![
            tf(transform_type::ENCR, transform_id::AES_GCM_16, Some(256)),
            tf(transform_type::ESN, transform_id::ESN_NONE, None),
        ]);
        let chosen = select_esp(&sa).unwrap();
        assert_eq!(chosen.encr_id, transform_id::AES_GCM_16);
        assert_eq!(chosen.encr_key_bits, 256);
        assert_eq!(chosen.integ_id, None);
        assert_eq!(chosen.sk_cipher(), Some(crate::ikev2::sk::SkCipher::Aes256Gcm));
    }

    #[test]
    fn select_esp_reads_back_a_classic_answer() {
        let sa = esp_proposal(vec![
            tf(transform_type::ENCR, transform_id::AES_CBC, Some(128)),
            tf(transform_type::INTEG, transform_id::AUTH_HMAC_SHA1_96, None),
            tf(transform_type::ESN, transform_id::ESN_NONE, None),
        ]);
        let chosen = select_esp(&sa).unwrap();
        assert_eq!(chosen.encr_id, transform_id::AES_CBC);
        assert_eq!(chosen.integ_id, Some(transform_id::AUTH_HMAC_SHA1_96));
        assert_eq!(
            chosen.sk_cipher(),
            Some(crate::ikev2::sk::SkCipher::Aes128Cbc(crate::crypto::IntegAlgorithm::HmacSha1_96))
        );
    }

    #[test]
    fn select_esp_ignores_a_non_esp_proposal() {
        let sa = proposal(1, vec![tf(transform_type::ENCR, transform_id::AES_GCM_16, Some(256))]);
        assert_eq!(select_esp(&sa), None);
    }

    #[test]
    fn select_esp_reads_esn_enabled() {
        let sa = esp_proposal(vec![
            tf(transform_type::ENCR, transform_id::AES_GCM_16, Some(256)),
            tf(transform_type::ESN, transform_id::ESN_ENABLED, None),
        ]);
        assert!(select_esp(&sa).unwrap().esn);
    }

    #[test]
    fn select_esp_treats_a_missing_esn_transform_as_none() {
        let sa = esp_proposal(vec![tf(transform_type::ENCR, transform_id::AES_GCM_16, Some(256))]);
        assert!(!select_esp(&sa).unwrap().esn);
    }

    #[test]
    fn esp_suite_matches_offer_accepts_exactly_what_was_offered() {
        let offer = esp_proposal(vec![
            tf(transform_type::ENCR, transform_id::AES_GCM_16, Some(256)),
            tf(transform_type::ESN, transform_id::ESN_NONE, None),
        ]);
        let chosen = select_esp(&offer).unwrap();
        assert!(chosen.matches_offer(&offer));
    }

    #[test]
    fn esp_suite_matches_offer_rejects_a_downgraded_cipher() {
        // We offered AES-GCM-256 only; a peer answering AES-CBC-128/HMAC-SHA1
        // (a combination `sk::SkCipher` can decode fine) must not pass as if
        // we had proposed it.
        let offer = esp_proposal(vec![
            tf(transform_type::ENCR, transform_id::AES_GCM_16, Some(256)),
            tf(transform_type::ESN, transform_id::ESN_NONE, None),
        ]);
        let answer = esp_proposal(vec![
            tf(transform_type::ENCR, transform_id::AES_CBC, Some(128)),
            tf(transform_type::INTEG, transform_id::AUTH_HMAC_SHA1_96, None),
            tf(transform_type::ESN, transform_id::ESN_NONE, None),
        ]);
        let chosen = select_esp(&answer).unwrap();
        assert!(!chosen.matches_offer(&offer));
    }

    #[test]
    fn esp_suite_matches_offer_rejects_esn_turned_on() {
        // We only ever offer ESN_NONE (no ESN implementation in the data
        // plane); a peer flipping it to ESN_ENABLED must be rejected even
        // though the ENCR/INTEG match exactly.
        let offer = esp_proposal(vec![
            tf(transform_type::ENCR, transform_id::AES_GCM_16, Some(256)),
            tf(transform_type::ESN, transform_id::ESN_NONE, None),
        ]);
        let answer = esp_proposal(vec![
            tf(transform_type::ENCR, transform_id::AES_GCM_16, Some(256)),
            tf(transform_type::ESN, transform_id::ESN_ENABLED, None),
        ]);
        let chosen = select_esp(&answer).unwrap();
        assert!(!chosen.matches_offer(&offer));
    }

    #[test]
    fn esp_suite_matches_offer_rejects_integ_forced_onto_an_aead_offer() {
        let offer = esp_proposal(vec![
            tf(transform_type::ENCR, transform_id::AES_GCM_16, Some(256)),
            tf(transform_type::ESN, transform_id::ESN_NONE, None),
        ]);
        let answer = esp_proposal(vec![
            tf(transform_type::ENCR, transform_id::AES_GCM_16, Some(256)),
            tf(transform_type::INTEG, transform_id::AUTH_HMAC_SHA2_256_128, None),
            tf(transform_type::ESN, transform_id::ESN_NONE, None),
        ]);
        let chosen = select_esp(&answer).unwrap();
        assert!(!chosen.matches_offer(&offer));
    }

    #[test]
    fn esp_suite_matches_offer_rejects_a_non_esp_offer() {
        let chosen = ChosenEspSuite { encr_id: transform_id::AES_GCM_16, encr_key_bits: 256, integ_id: None, esn: false };
        let offer = proposal(1, vec![tf(transform_type::ENCR, transform_id::AES_GCM_16, Some(256))]);
        assert!(!chosen.matches_offer(&offer));
    }
}
