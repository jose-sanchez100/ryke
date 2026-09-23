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

use crate::crypto::{DhGroup, IntegAlgorithm, KeyLengths, PrfAlgorithm};
use crate::error::IkeError;
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
    /// A fixed-key cipher (ChaCha20-Poly1305, 3DES) goes without a Key Length:
    /// RFC 7296 §3.3.5, "The Key Length attribute MUST NOT be used with
    /// transforms that use a fixed-length key", and §3.3.6, the attributes of
    /// the selected transform "MUST be returned unmodified" -- it had none.
    pub fn to_proposal(&self) -> Proposal {
        let encr_key_length = if fixed_key_bits(self.encr_id).is_some() { None } else { Some(self.encr_key_bits) };
        let mut transforms = vec![
            Transform { transform_type: transform_type::ENCR, transform_id: self.encr_id, key_length: encr_key_length },
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
        // attribute on the wire (RFC 7296 §3.3.5) -- `has` with `None`.
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

/// The one proposal of `answer`, the SA payload a responder took our `offer`
/// with, provided the answer is "consistent with one of [our] proposals" --
/// RFC 7296 §3.3.6: "The initiator of an exchange MUST check that the
/// accepted offer is consistent with one of its proposals, and if not MUST
/// terminate the exchange." That is:
///
/// - a single proposal: the responder "MUST accept a single proposal or
///   reject them all" (§2.7);
/// - numbered and of the protocol of the one of ours it accepts: "the
///   proposal number in the SA payload MUST match the number on the proposal
///   sent that was accepted" (§3.3.1), "the SA response MUST contain the same
///   protocol" (§2.7);
/// - "exactly one transform of each type included in the proposal" (§2.7),
///   each one we offered in it, attributes and all ("Any attributes of a
///   selected transform MUST be returned unmodified", §3.3.6).
///
/// Two leniencies, both meaning "nothing" in an ESP answer: one that leaves
/// out the ESN transform of a proposal offering `ESN_NONE` is taken as "no
/// ESN" -- some peers omit it, the convention [`select_esp`] and
/// `rekey::choose_child_proposal` follow too; and one that adds a single DH
/// `NONE` to an ESP proposal offered without any DH transform is taken as "no
/// PFS", as asked (`NONE` is what §1.2 lets an `IKE_AUTH` SA carry for DH, and
/// the CHILD SA rekey already took it so). The SPI isn't compared: the answer
/// carries the responder's own.
///
/// `NoProposalChosen` when the answer is anything else.
pub(crate) fn accepted_proposal<'a>(answer: &'a SecurityAssociation, offer: &SecurityAssociation) -> Result<&'a Proposal, IkeError> {
    let [answered] = answer.proposals.as_slice() else {
        return Err(IkeError::NoProposalChosen);
    };
    let offered = offer
        .proposals
        .iter()
        .find(|p| p.num == answered.num && p.protocol_id == answered.protocol_id)
        .ok_or(IkeError::NoProposalChosen)?;
    let answered_of = |ty: u8| answered.transforms.iter().filter(move |t| t.transform_type == ty).count();
    let esn_none = Transform { transform_type: transform_type::ESN, transform_id: transform_id::ESN_NONE, key_length: None };
    let offered_of = |ty: u8| offered.transforms.iter().filter(move |t| t.transform_type == ty).count();
    let dh_none = Transform { transform_type: transform_type::DH, transform_id: 0, key_length: None };
    let no_pfs = |t: &Transform| answered.protocol_id == protocol_id::ESP && *t == dh_none && offered_of(transform_type::DH) == 0;
    let consistent = answered.transforms.iter().all(|t| (offered.transforms.contains(t) || no_pfs(t)) && answered_of(t.transform_type) == 1)
        && offered.transforms.iter().all(|t| {
            answered_of(t.transform_type) == 1 || (t.transform_type == transform_type::ESN && offered.transforms.contains(&esn_none))
        });
    if consistent {
        Ok(answered)
    } else {
        Err(IkeError::NoProposalChosen)
    }
}

/// Pick the first initiator proposal we fully support, or `None`.
pub fn select(sa: &SecurityAssociation) -> Option<ChosenSuite> {
    select_with_proposal(sa).map(|(_, suite)| suite)
}

/// [`select`], also returning the proposal the suite was picked from -- whose
/// SPI is the one the peer wants if that proposal is chosen (RFC 7296 §3.3.1).
pub(crate) fn select_with_proposal(sa: &SecurityAssociation) -> Option<(&Proposal, ChosenSuite)> {
    sa.proposals.iter().find_map(|p| select_from_proposal(p).map(|suite| (p, suite)))
}

/// `(transform_id, key_bits, is_aead)`, strongest first. `key_bits: None`
/// means no Key Length attribute: fixed-key ciphers like 3DES and
/// ChaCha20-Poly1305 must not carry one (RFC 7296 §3.3.5).
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

/// The DH group `id` names, if IKEv2 may run it: one of [`DH_CANDIDATES`], so
/// never MODP-768, which RFC 8247 §2.4 forbids. Transform Type 4 is one
/// registry for the IKE SA and a CHILD SA's PFS alike (RFC 7296 §3.3.2), so
/// the same list holds for both.
pub fn ikev2_dh_group(id: u16) -> Option<DhGroup> {
    DH_CANDIDATES.contains(&id).then(|| DhGroup::from_transform_id(id)).flatten()
}

/// The Transform Types an IKE proposal may carry for us to answer it: ENCR,
/// PRF, INTEG and D-H (RFC 7296 §3.3.3), plus ESN, which some initiators add
/// to it by mistake and is ignored (see `ignores_esn_if_present`).
const IKE_TRANSFORM_TYPES: &[u8] = &[transform_type::ENCR, transform_type::PRF, transform_type::INTEG, transform_type::DH, transform_type::ESN];

fn select_from_proposal(proposal: &Proposal) -> Option<ChosenSuite> {
    if proposal.protocol_id != protocol_id::IKE {
        return None;
    }
    // RFC 7296 §3.3.6: "If the responder receives a proposal that contains a
    // Transform Type it does not understand ... it MUST consider this proposal
    // unacceptable; however, other proposals in the same SA payload are
    // processed as usual" -- answering it would leave that type out (RFC 9370
    // §2.2.2 relies on this for its ADDKE types without IKE_INTERMEDIATE).
    if proposal.transforms.iter().any(|t| !IKE_TRANSFORM_TYPES.contains(&t.transform_type)) {
        return None;
    }
    // §2.7: the accepted suite "MUST contain exactly one transform of each
    // type included in the proposal", so one that lists integrity algorithms
    // needs one of them answered -- which a combined-mode cipher can't take
    // (§3.3: those "MUST either offer no integrity algorithm or a single
    // integrity algorithm of NONE").
    let offers_integ = proposal.transforms.iter().any(|t| t.transform_type == transform_type::INTEG);
    let dh_id = DH_CANDIDATES.iter().copied().find(|&g| has(proposal, transform_type::DH, g, None))?;

    for &(encr_id, key_bits, aead) in ENCR_CANDIDATES {
        if !has(proposal, transform_type::ENCR, encr_id, key_bits) {
            continue;
        }
        let encr_key_bits = key_bits.or_else(|| fixed_key_bits(encr_id)).expect("every candidate has a key size");

        if aead {
            if offers_integ {
                continue;
            }
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

/// Whether `proposal` offers transform `tid` of type `ttype` with the Key
/// Length `key_bits` -- `None` for a transform without one: a fixed-length
/// cipher, PRF, INTEG or D-H group. On those RFC 7296 §3.3.5 says "The Key
/// Length attribute MUST NOT be used", so one that carries it anyway is not a
/// transform we understand, and §3.3.6 makes it unacceptable.
fn has(proposal: &Proposal, ttype: u8, tid: u16, key_bits: Option<u16>) -> bool {
    proposal.transforms.iter().any(|t| t.transform_type == ttype && t.transform_id == tid && t.key_length == key_bits)
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

    /// Whether every transform this suite names was actually present in one
    /// of `offer`'s ESP proposals -- any of them: the answer's proposal
    /// number says which ([`accepted_proposal`] holds it to that). Mirrors [`ChosenSuite::matches_offer`] for
    /// the CHILD SA: RFC 7296 §2.7 requires the peer's SAr2/SAi2 answer to be
    /// built from the ESP proposal *we* sent, not merely a combination
    /// `select_esp`/`sk::SkCipher` knows how to decode. Without this check, a
    /// misbehaving or on-path peer could answer e.g. AES-CBC-128/HMAC-SHA1 to
    /// an AES-GCM-256-only ESP offer (silently downgrading the data-plane
    /// cipher we derive and run), or turn ESN on when we only offered
    /// `ESN_NONE` (this crate's 32-bit ESP sequence counters would then
    /// disagree with what the peer believes it negotiated).
    pub fn matches_offer(&self, offer: &SecurityAssociation) -> bool {
        offer.proposals.iter().filter(|p| p.protocol_id == protocol_id::ESP).any(|p| self.matches_proposal(p))
    }

    fn matches_proposal(&self, proposal: &Proposal) -> bool {
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
    fn a_fixed_key_cipher_is_echoed_without_a_key_length() {
        // RFC 7296 §3.3.5: "The Key Length attribute MUST NOT be used with
        // transforms that use a fixed-length key", and §3.3.6: attributes are
        // "returned unmodified" -- the offer carried none.
        for (encr, integ) in [(transform_id::CHACHA20_POLY1305, None), (transform_id::TRIPLE_DES, Some(transform_id::AUTH_HMAC_SHA1_96))] {
            let mut transforms = vec![tf(transform_type::ENCR, encr, None), tf(transform_type::PRF, transform_id::PRF_HMAC_SHA2_256, None)];
            transforms.extend(integ.map(|id| tf(transform_type::INTEG, id, None)));
            transforms.push(tf(transform_type::DH, transform_id::X25519, None));
            let chosen = select(&proposal(1, transforms)).unwrap();
            let echo = chosen.to_proposal();
            let echoed = echo.transforms.iter().find(|t| t.transform_type == transform_type::ENCR).unwrap();
            assert_eq!(echoed.key_length, None, "ENCR {encr}");
            assert!(chosen.matches_offer(&SecurityAssociation { proposals: vec![echo.clone()] }));
        }
        // A variable-length cipher keeps its Key Length.
        let chosen = select(&proposal(1, vec![
            tf(transform_type::ENCR, transform_id::AES_GCM_16, Some(128)),
            tf(transform_type::PRF, transform_id::PRF_HMAC_SHA2_256, None),
            tf(transform_type::DH, transform_id::X25519, None),
        ]))
        .unwrap();
        assert_eq!(chosen.to_proposal().transforms[0].key_length, Some(128));
    }

    #[test]
    fn a_key_length_on_a_fixed_length_transform_makes_it_unacceptable() {
        // §3.3.5 forbids the attribute there, and §3.3.6: "a transform ...
        // that contains a Transform Attribute it does not understand" is
        // unacceptable -- whatever a Key Length on ChaCha20 or a PRF means,
        // it isn't what we'd run.
        let base = || {
            vec![
                tf(transform_type::ENCR, transform_id::CHACHA20_POLY1305, None),
                tf(transform_type::PRF, transform_id::PRF_HMAC_SHA2_256, None),
                tf(transform_type::DH, transform_id::X25519, None),
            ]
        };
        assert!(select(&proposal(1, base())).is_some());
        for at in 0..3 {
            let mut transforms = base();
            transforms[at].key_length = Some(128);
            assert_eq!(select(&proposal(1, transforms)), None, "Key Length on transform {at}");
        }
        // Another transform of the same type without it is still taken.
        let mut transforms = base();
        transforms[0].key_length = Some(128);
        transforms.push(tf(transform_type::ENCR, transform_id::AES_GCM_16, Some(256)));
        assert_eq!(select(&proposal(1, transforms)).unwrap().encr_id, transform_id::AES_GCM_16);
    }

    #[test]
    fn an_aead_cipher_is_not_picked_from_a_proposal_that_carries_integrity() {
        // §2.7: the accepted suite "MUST contain exactly one transform of each
        // type included in the proposal" -- a proposal with INTEG transforms
        // needs one answered, which a combined-mode cipher cannot take (§3.3:
        // it offers "no integrity algorithm or a single integrity algorithm of
        // NONE").
        let mixed = proposal(1, vec![
            tf(transform_type::ENCR, transform_id::AES_GCM_16, Some(256)),
            tf(transform_type::ENCR, transform_id::AES_CBC, Some(256)),
            tf(transform_type::PRF, transform_id::PRF_HMAC_SHA2_256, None),
            tf(transform_type::INTEG, transform_id::AUTH_HMAC_SHA2_256_128, None),
            tf(transform_type::DH, transform_id::X25519, None),
        ]);
        let chosen = select(&mixed).unwrap();
        assert_eq!((chosen.encr_id, chosen.integ_id), (transform_id::AES_CBC, Some(transform_id::AUTH_HMAC_SHA2_256_128)));

        let aead_with_integ = proposal(1, vec![
            tf(transform_type::ENCR, transform_id::AES_GCM_16, Some(256)),
            tf(transform_type::PRF, transform_id::PRF_HMAC_SHA2_256, None),
            tf(transform_type::INTEG, transform_id::AUTH_HMAC_SHA2_256_128, None),
            tf(transform_type::DH, transform_id::X25519, None),
        ]);
        assert_eq!(select(&aead_with_integ), None);
    }

    #[test]
    fn a_proposal_with_a_transform_type_we_do_not_know_is_skipped() {
        // §3.3.6: "a proposal that contains a Transform Type it does not
        // understand ... MUST [be considered] unacceptable; however, other
        // proposals in the same SA payload are processed as usual" -- e.g.
        // RFC 9370's ADDKE types (6-12) without IKE_INTERMEDIATE.
        let suite = |num: u8, extra: Option<Transform>| {
            let mut transforms = vec![
                tf(transform_type::ENCR, transform_id::AES_GCM_16, Some(256)),
                tf(transform_type::PRF, transform_id::PRF_HMAC_SHA2_256, None),
                tf(transform_type::DH, transform_id::X25519, None),
            ];
            transforms.extend(extra);
            Proposal { num, protocol_id: protocol_id::IKE, spi: Vec::new(), transforms }
        };
        let addke = tf(6, transform_id::ECP256, None);
        let sa = SecurityAssociation { proposals: vec![suite(1, Some(addke.clone())), suite(2, None)] };
        assert_eq!(select(&sa).unwrap().proposal_num, 2);
        let only = SecurityAssociation { proposals: vec![suite(1, Some(addke))] };
        assert_eq!(select(&only), None);
    }

    #[test]
    fn an_esp_answer_picking_the_second_proposal_matches_the_offer() {
        let offer = SecurityAssociation {
            proposals: vec![
                Proposal {
                    num: 1,
                    protocol_id: protocol_id::ESP,
                    spi: vec![1, 2, 3, 4],
                    transforms: vec![tf(transform_type::ENCR, transform_id::CHACHA20_POLY1305, None), tf(transform_type::ESN, transform_id::ESN_NONE, None)],
                },
                Proposal {
                    num: 2,
                    protocol_id: protocol_id::ESP,
                    spi: vec![1, 2, 3, 4],
                    transforms: vec![tf(transform_type::ENCR, transform_id::AES_GCM_16, Some(256)), tf(transform_type::ESN, transform_id::ESN_NONE, None)],
                },
            ],
        };
        let answer = SecurityAssociation { proposals: vec![Proposal { spi: vec![9, 9, 9, 9], ..offer.proposals[1].clone() }] };
        let chosen = select_esp(&answer).unwrap();
        assert!(chosen.matches_offer(&offer));
        assert_eq!(accepted_proposal(&answer, &offer), Ok(&answer.proposals[0]));
    }

    #[test]
    fn an_answer_must_be_one_proposal_of_ours_with_one_transform_of_each_type() {
        let offer = SecurityAssociation {
            proposals: vec![
                Proposal {
                    num: 1,
                    protocol_id: protocol_id::IKE,
                    spi: Vec::new(),
                    transforms: vec![
                        tf(transform_type::ENCR, transform_id::AES_GCM_16, Some(256)),
                        tf(transform_type::ENCR, transform_id::AES_GCM_16, Some(128)),
                        tf(transform_type::PRF, transform_id::PRF_HMAC_SHA2_256, None),
                        tf(transform_type::DH, transform_id::X25519, None),
                        tf(transform_type::DH, transform_id::ECP256, None),
                    ],
                },
                Proposal {
                    num: 2,
                    protocol_id: protocol_id::IKE,
                    spi: Vec::new(),
                    transforms: vec![
                        tf(transform_type::ENCR, transform_id::AES_CBC, Some(256)),
                        tf(transform_type::PRF, transform_id::PRF_HMAC_SHA2_256, None),
                        tf(transform_type::INTEG, transform_id::AUTH_HMAC_SHA2_256_128, None),
                        tf(transform_type::DH, transform_id::X25519, None),
                    ],
                },
            ],
        };
        let answer = |num: u8, transforms: Vec<Transform>| SecurityAssociation {
            proposals: vec![Proposal { num, protocol_id: protocol_id::IKE, spi: Vec::new(), transforms }],
        };
        let gcm = || {
            vec![
                tf(transform_type::ENCR, transform_id::AES_GCM_16, Some(128)),
                tf(transform_type::PRF, transform_id::PRF_HMAC_SHA2_256, None),
                tf(transform_type::DH, transform_id::ECP256, None),
            ]
        };
        let cbc = || {
            vec![
                tf(transform_type::ENCR, transform_id::AES_CBC, Some(256)),
                tf(transform_type::PRF, transform_id::PRF_HMAC_SHA2_256, None),
                tf(transform_type::INTEG, transform_id::AUTH_HMAC_SHA2_256_128, None),
                tf(transform_type::DH, transform_id::X25519, None),
            ]
        };
        assert!(accepted_proposal(&answer(1, gcm()), &offer).is_ok());
        assert!(accepted_proposal(&answer(2, cbc()), &offer).is_ok());

        let mut bad: Vec<(&str, SecurityAssociation)> = vec![
            ("the number of another proposal", answer(2, gcm())),
            ("a number we never sent", answer(3, gcm())),
            ("another protocol", SecurityAssociation { proposals: vec![Proposal { protocol_id: protocol_id::ESP, ..answer(1, gcm()).proposals[0].clone() }] }),
            ("no proposal", SecurityAssociation { proposals: Vec::new() }),
        ];
        let mut two = answer(1, gcm());
        two.proposals.push(answer(2, cbc()).proposals.remove(0));
        bad.push(("two proposals", two));
        let mut both_dh = gcm();
        both_dh.push(tf(transform_type::DH, transform_id::X25519, None));
        bad.push(("two transforms of a type", answer(1, both_dh)));
        let mut no_dh = gcm();
        no_dh.pop();
        bad.push(("a type of the proposal left out", answer(1, no_dh)));
        let mut integ = gcm();
        integ.push(tf(transform_type::INTEG, transform_id::AUTH_HMAC_SHA2_256_128, None));
        bad.push(("a type the proposal doesn't have", answer(1, integ)));
        let mut resized = gcm();
        resized[0].key_length = Some(192);
        bad.push(("an attribute changed", answer(1, resized)));
        let mut other = gcm();
        other[1] = tf(transform_type::PRF, transform_id::PRF_HMAC_SHA2_512, None);
        bad.push(("a transform we never offered", answer(1, other)));
        for (what, sa) in bad {
            assert_eq!(accepted_proposal(&sa, &offer), Err(IkeError::NoProposalChosen), "{what}");
        }
    }

    #[test]
    fn an_esp_answer_may_leave_out_an_esn_none_it_was_offered() {
        // The one leniency, the convention `select_esp` already follows.
        let offer = esp_proposal(vec![
            tf(transform_type::ENCR, transform_id::AES_GCM_16, Some(256)),
            tf(transform_type::ESN, transform_id::ESN_NONE, None),
        ]);
        let answer = esp_proposal(vec![tf(transform_type::ENCR, transform_id::AES_GCM_16, Some(256))]);
        assert!(accepted_proposal(&answer, &offer).is_ok());
        let esn_only = esp_proposal(vec![
            tf(transform_type::ENCR, transform_id::AES_GCM_16, Some(256)),
            tf(transform_type::ESN, transform_id::ESN_ENABLED, None),
        ]);
        assert_eq!(accepted_proposal(&answer, &esn_only), Err(IkeError::NoProposalChosen));
    }

    #[test]
    fn an_esp_answer_may_add_dh_none_to_an_offer_without_pfs() {
        // "No PFS" spelled out, as asked -- but only NONE, only once, only in
        // ESP and only when we offered no DH at all.
        let gcm = || tf(transform_type::ENCR, transform_id::AES_GCM_16, Some(256));
        let none = || tf(transform_type::DH, 0, None);
        let modp2048 = || tf(transform_type::DH, transform_id::MODP_2048, None);
        let no_pfs = esp_proposal(vec![gcm()]);
        assert!(accepted_proposal(&esp_proposal(vec![gcm(), none()]), &no_pfs).is_ok());

        let refused = [
            ("a group we never asked for", esp_proposal(vec![gcm(), modp2048()]), no_pfs.clone()),
            ("NONE twice", esp_proposal(vec![gcm(), none(), none()]), no_pfs.clone()),
            ("NONE for a PFS offer", esp_proposal(vec![gcm(), none()]), esp_proposal(vec![gcm(), modp2048()])),
            ("NONE in an IKE proposal", proposal(1, vec![gcm(), none()]), proposal(1, vec![gcm()])),
        ];
        for (what, answer, offer) in refused {
            assert_eq!(accepted_proposal(&answer, &offer), Err(IkeError::NoProposalChosen), "{what}");
        }
    }

    #[test]
    fn esp_suite_matches_offer_rejects_a_non_esp_offer() {
        let chosen = ChosenEspSuite { encr_id: transform_id::AES_GCM_16, encr_key_bits: 256, integ_id: None, esn: false };
        let offer = proposal(1, vec![tf(transform_type::ENCR, transform_id::AES_GCM_16, Some(256))]);
        assert!(!chosen.matches_offer(&offer));
    }
}
