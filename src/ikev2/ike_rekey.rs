//! IKE-SA rekey (RFC 7296 §2.18) via the `CREATE_CHILD_SA` exchange.
//!
//! ```text
//! Initiator → SK { SA(new IKE SPIi), Ni, KEi }
//! Responder → SK { SA(new IKE SPIr), Nr, KEr }
//! ```
//!
//! A fresh Diffie-Hellman gives a new shared secret; the new IKE keys are
//! `SKEYSEED = prf(SK_d(old), g^ir | Ni | Nr)` then `prf+` over the *new* SPIs
//! (see [`crate::crypto::derive_rekey_session_keys`]). The CHILD SAs are **not**
//! touched — they are inherited by the new IKE SA, which the consumer installs.
//! Without this, a native client (iOS refreshes its IKE SA on its ~1h lifetime)
//! fails the rekey and tears the whole tunnel down.
//!
//! Both halves live here: [`build_ike_rekey_request`] /
//! [`initiator_complete_ike_rekey`] for the side that starts the rekey (a
//! client keeping ahead of its own lifetime), [`responder_process_ike_rekey`]
//! for the side that answers it (a gateway's timer firing first, or a
//! native client rekeying against ryke acting as a server).

use crate::crypto::{self, DhGroup};
use crate::error::IkeError;
use crate::ikev2::exchange::CompletedSaInit;
use crate::ikev2::message::{
    encode_payload_chain, first_payload_type, payloads, ExchangeType, Flags, IkeHeader, PayloadType,
};
use crate::ikev2::negotiate;
use crate::ikev2::payload::{notify_type_name, protocol_id, KeyExchange, Nonce, Notify, SecurityAssociation};
use crate::ikev2::sk::{build_encrypted, open_encrypted};
use crate::role::Role;

fn our_sk_e(sa: &CompletedSaInit) -> &[u8] {
    match sa.role {
        Role::Initiator => &sa.keys.sk_ei,
        Role::Responder => &sa.keys.sk_er,
    }
}
fn our_sk_a(sa: &CompletedSaInit) -> &[u8] {
    match sa.role {
        Role::Initiator => &sa.keys.sk_ai,
        Role::Responder => &sa.keys.sk_ar,
    }
}
fn peer_sk_e(sa: &CompletedSaInit) -> &[u8] {
    match sa.role {
        Role::Initiator => &sa.keys.sk_er,
        Role::Responder => &sa.keys.sk_ei,
    }
}
fn peer_sk_a(sa: &CompletedSaInit) -> &[u8] {
    match sa.role {
        Role::Initiator => &sa.keys.sk_ar,
        Role::Responder => &sa.keys.sk_ai,
    }
}

/// Whether a decrypted CREATE_CHILD_SA is an **IKE-SA** rekey (has a KeyExchange
/// and no Traffic Selectors) rather than a CHILD-SA rekey. The consumer routes on
/// this before calling [`responder_process_ike_rekey`].
pub fn is_ike_sa_rekey(inner: &[(PayloadType, Vec<u8>)]) -> bool {
    let has_ke = inner.iter().any(|(t, _)| *t == PayloadType::KeyExchange);
    let has_ts = inner
        .iter()
        .any(|(t, _)| *t == PayloadType::TrafficSelectorInitiator || *t == PayloadType::TrafficSelectorResponder);
    has_ke && !has_ts
}

/// Initiator: build the request that rekeys `old_sa` (RFC 7296 §1.3.2):
/// `SK { SA(IKE, new SPIi), Ni, KEi }`, protected by the *old* IKE SA. It
/// proposes exactly the suite `old_sa` already runs -- a rekey never
/// renegotiates the algorithms -- with a fresh ephemeral DH share from
/// `dh_private`, for the group that suite names. `message_id` is the next one
/// of the old SA; the new SA's own Message IDs start again at 0.
pub fn build_ike_rekey_request(
    old_sa: &CompletedSaInit,
    message_id: u32,
    new_spi_i: u64,
    ni: &[u8],
    dh_private: &[u8],
    iv: &[u8; 8],
) -> Result<Vec<u8>, IkeError> {
    let group = DhGroup::from_transform_id(old_sa.suite.dh_id).ok_or(IkeError::NoProposalChosen)?;
    let ke = KeyExchange { dh_group: old_sa.suite.dh_id, data: group.public(dh_private) };
    let inner = vec![
        (PayloadType::SecurityAssociation, ike_rekey_offer(old_sa, new_spi_i).to_bytes()),
        (PayloadType::Nonce, ni.to_vec()),
        (PayloadType::KeyExchange, ke.to_bytes()),
    ];
    let header = IkeHeader {
        initiator_spi: old_sa.spi_i,
        responder_spi: old_sa.spi_r,
        next_payload: PayloadType::NoNext,
        major_version: 2,
        minor_version: 0,
        exchange_type: ExchangeType::CreateChildSa,
        flags: Flags { initiator: old_sa.role == Role::Initiator, version: false, response: false },
        message_id,
        length: 0,
    };
    let first = first_payload_type(&inner);
    let bytes = encode_payload_chain(&inner);
    build_encrypted(old_sa.suite.sk_cipher(), header, first, &bytes, our_sk_e(old_sa), our_sk_a(old_sa), iv)
}

/// The SA payload [`build_ike_rekey_request`] sends: a single proposal, the
/// suite `old_sa` runs, carrying `new_spi_i`.
fn ike_rekey_offer(old_sa: &CompletedSaInit, new_spi_i: u64) -> SecurityAssociation {
    let mut prop = old_sa.suite.to_proposal();
    prop.num = 1; // a single-proposal offer: numbered from 1 whatever number the first handshake's pick had
    prop.protocol_id = protocol_id::IKE;
    prop.spi = new_spi_i.to_be_bytes().to_vec();
    SecurityAssociation { proposals: vec![prop] }
}

/// Initiator: finish the rekey from the peer's `response`, deriving the new IKE
/// SA (we are its initiator: `spi_i` is `new_spi_i`, `spi_r` the one the peer
/// put in its SA payload). `ni`, `new_spi_i` and `dh_private` are what
/// [`build_ike_rekey_request`] was given. A response carrying an error notify
/// (`NO_ADDITIONAL_SAS`, `NO_PROPOSAL_CHOSEN`, `INVALID_KE_PAYLOAD`, ...) is
/// [`IkeError::PeerRejected`]; one that picks a different suite than the one
/// offered, or answers with another DH group, is refused rather than trusted.
pub fn initiator_complete_ike_rekey(
    old_sa: &CompletedSaInit,
    ni: &[u8],
    new_spi_i: u64,
    dh_private: &[u8],
    response: &[u8],
) -> Result<CompletedSaInit, IkeError> {
    let (first, inner) = open_encrypted(old_sa.suite.sk_cipher(), response, peer_sk_e(old_sa), peer_sk_a(old_sa))?;
    let (mut sa_bytes, mut nr, mut ke_bytes) = (None, None, None);
    for p in payloads(first, &inner) {
        let p = p?;
        match p.payload_type {
            PayloadType::Notify => {
                if let Ok(n) = Notify::parse(p.data) {
                    if n.is_error() {
                        return Err(IkeError::PeerRejected { notify_type: n.notify_type, name: notify_type_name(n.notify_type) });
                    }
                }
            }
            PayloadType::SecurityAssociation => sa_bytes = Some(p.data.to_vec()),
            PayloadType::Nonce => nr = Some(p.data.to_vec()),
            PayloadType::KeyExchange => ke_bytes = Some(p.data.to_vec()),
            _ => {}
        }
    }
    let sa = SecurityAssociation::parse(&sa_bytes.ok_or(IkeError::MissingPayload("SA"))?)?;
    let nr = nr.ok_or(IkeError::MissingPayload("Nonce"))?;
    let ke = KeyExchange::parse(&ke_bytes.ok_or(IkeError::MissingPayload("KE"))?)?;

    // Our one proposal, by its number, with one transform of each of its types
    // (RFC 7296 §2.7, §3.3.1, §3.3.6); its SPI is the peer's, not ours.
    let proposal = negotiate::accepted_proposal(&sa, &ike_rekey_offer(old_sa, new_spi_i))?;
    if proposal.spi.len() != 8 {
        return Err(IkeError::Crypto("expected an 8-byte IKE SPI"));
    }
    let new_spi_r = u64::from_be_bytes(proposal.spi[..8].try_into().unwrap());
    let suite = negotiate::select(&sa).ok_or(IkeError::NoProposalChosen)?;
    let old = &old_sa.suite;
    if (suite.encr_id, suite.encr_key_bits, suite.prf_id, suite.integ_id, suite.dh_id)
        != (old.encr_id, old.encr_key_bits, old.prf_id, old.integ_id, old.dh_id)
    {
        return Err(IkeError::NoProposalChosen);
    }
    // RFC 7296 §3.9 and §2.10: Nr is 16 to 256 octets and at least half the key
    // of the PRF that makes the new SKEYSEED from it.
    Nonce::parse_for_prf(&nr, suite.prf_algorithm())?;
    let group = DhGroup::from_transform_id(suite.dh_id).ok_or(IkeError::NoProposalChosen)?;
    if ke.dh_group != group.transform_id() {
        return Err(IkeError::DhGroupMismatch { expected: group.transform_id(), got: ke.dh_group });
    }
    let shared = group.shared(dh_private, &ke.data)?;
    let keys = crypto::derive_rekey_session_keys(
        suite.prf_algorithm(),
        &old_sa.keys.sk_d,
        &shared,
        ni,
        &nr,
        new_spi_i,
        new_spi_r,
        suite.key_lengths(),
    );
    Ok(CompletedSaInit {
        role: Role::Initiator,
        spi_i: new_spi_i,
        spi_r: new_spi_r,
        suite,
        keys,
        ni: ni.to_vec(),
        nr,
        // Not an IKE_SA_INIT and AUTH is not re-run for a rekeyed IKE SA.
        init_message: Vec::new(),
        resp_message: Vec::new(),
        peer_signature_hashes: old_sa.peer_signature_hashes.clone(),
        peer_supports_fragmentation: old_sa.peer_supports_fragmentation,
    })
}

/// Responder: process an IKE-SA rekey request (SK-wrapped under the *old* IKE SA),
/// derive the new IKE SA, and build the response. `new_spi_r` is our new IKE SPI,
/// `dh_private` our fresh ephemeral DH secret, `nr` our new nonce. Returns
/// `(response_bytes, new_ike_sa)`; the caller migrates the CHILD SAs onto it and
/// retires the old IKE SA when the peer deletes it.
pub fn responder_process_ike_rekey(
    old_sa: &CompletedSaInit,
    request: &[u8],
    new_spi_r: u64,
    dh_private: &[u8],
    nr: &[u8],
    iv: &[u8; 8],
) -> Result<(Vec<u8>, CompletedSaInit), IkeError> {
    let message_id = IkeHeader::parse(request)?.message_id;
    let (first, inner) = open_encrypted(old_sa.suite.sk_cipher(), request, peer_sk_e(old_sa), peer_sk_a(old_sa))?;

    let (mut sa_bytes, mut ni, mut ke_bytes) = (None, None, None);
    for p in payloads(first, &inner) {
        let p = p?;
        match p.payload_type {
            PayloadType::SecurityAssociation => sa_bytes = Some(p.data.to_vec()),
            PayloadType::Nonce => ni = Some(p.data.to_vec()),
            PayloadType::KeyExchange => ke_bytes = Some(p.data.to_vec()),
            _ => {}
        }
    }
    let sa_bytes = sa_bytes.ok_or(IkeError::MissingPayload("SA"))?;
    let ni = ni.ok_or(IkeError::MissingPayload("Nonce"))?;
    let ke = KeyExchange::parse(&ke_bytes.ok_or(IkeError::MissingPayload("KE"))?)?;

    let sa = SecurityAssociation::parse(&sa_bytes)?;
    // The new SA's SPIi is the one in the proposal we chose (RFC 7296 §3.3.1),
    // not in whichever came first.
    let (proposal, suite) = negotiate::select_with_proposal(&sa).ok_or(IkeError::NoProposalChosen)?;
    if proposal.spi.len() != 8 {
        return Err(IkeError::Crypto("expected an 8-byte IKE SPI"));
    }
    let spi_i = u64::from_be_bytes(proposal.spi[..8].try_into().unwrap());

    // RFC 7296 §3.9 and §2.10, as for Nr in `initiator_complete_ike_rekey`.
    Nonce::parse_for_prf(&ni, suite.prf_algorithm())?;
    let group = DhGroup::from_transform_id(suite.dh_id).ok_or(IkeError::NoProposalChosen)?;
    if ke.dh_group != group.transform_id() {
        return Err(IkeError::DhGroupMismatch { expected: group.transform_id(), got: ke.dh_group });
    }
    let shared = group.shared(dh_private, &ke.data)?;
    let our_public = group.public(dh_private);

    let keys = crypto::derive_rekey_session_keys(
        suite.prf_algorithm(),
        &old_sa.keys.sk_d,
        &shared,
        &ni,
        nr,
        spi_i,
        new_spi_r,
        suite.key_lengths(),
    );

    // Response inner: SA(new IKE proposal carrying our new SPI) | Nr | KEr.
    let mut prop = suite.answer_to(proposal);
    prop.protocol_id = protocol_id::IKE;
    prop.spi = new_spi_r.to_be_bytes().to_vec();
    let sar = SecurityAssociation { proposals: vec![prop] };
    let ke_out = KeyExchange { dh_group: suite.dh_id, data: our_public };
    let inner_out = vec![
        (PayloadType::SecurityAssociation, sar.to_bytes()),
        (PayloadType::Nonce, nr.to_vec()),
        (PayloadType::KeyExchange, ke_out.to_bytes()),
    ];
    // The rekey exchange is protected by the OLD IKE SA (its header SPIs, its keys).
    let header = IkeHeader {
        initiator_spi: old_sa.spi_i,
        responder_spi: old_sa.spi_r,
        next_payload: PayloadType::NoNext,
        major_version: 2,
        minor_version: 0,
        exchange_type: ExchangeType::CreateChildSa,
        flags: Flags { initiator: old_sa.role == Role::Initiator, version: false, response: true },
        message_id,
        length: 0,
    };
    let first_out = first_payload_type(&inner_out);
    let bytes = encode_payload_chain(&inner_out);
    let response = build_encrypted(old_sa.suite.sk_cipher(), header, first_out, &bytes, our_sk_e(old_sa), our_sk_a(old_sa), iv)?;

    let new_sa = CompletedSaInit {
        role: Role::Responder,
        spi_i,
        spi_r: new_spi_r,
        suite,
        keys,
        ni,
        nr: nr.to_vec(),
        // Not an IKE_SA_INIT and AUTH is not re-run for a rekeyed IKE SA.
        init_message: Vec::new(),
        resp_message: Vec::new(),
        peer_signature_hashes: old_sa.peer_signature_hashes.clone(),
        peer_supports_fragmentation: old_sa.peer_supports_fragmentation,
    };
    Ok((response, new_sa))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ikev2::payload::Proposal;
    use crate::ikev2::exchange::{
        default_offer, initiator_complete, initiator_request, responder_respond, LocalSecret,
    };
    use crate::ikev2::sk::{build_encrypted_gcm, open_encrypted_gcm};

    fn sa_pair() -> (CompletedSaInit, CompletedSaInit) {
        sa_pair_with_offer(&default_offer())
    }

    /// The two ends of an `IKE_SA_INIT` whose offer is `offer`.
    fn sa_pair_with_offer(offer: &SecurityAssociation) -> (CompletedSaInit, CompletedSaInit) {
        let init = LocalSecret { dh_private: [7u8; 32], nonce: vec![0x11; 32], spi: 0xA1 };
        let resp = LocalSecret { dh_private: [9u8; 32], nonce: vec![0x22; 32], spi: 0xB2 };
        let request = initiator_request(&init, offer);
        let (response, resp_done) = responder_respond(&request, &resp).unwrap();
        let init_done = initiator_complete(&init, &request, &response).unwrap();
        (init_done, resp_done)
    }

    #[test]
    fn routes_only_a_ke_no_ts_message_as_ike_rekey() {
        assert!(is_ike_sa_rekey(&[
            (PayloadType::SecurityAssociation, vec![]),
            (PayloadType::Nonce, vec![]),
            (PayloadType::KeyExchange, vec![]),
        ]));
        // A CHILD rekey has TS and no KE — must NOT be treated as an IKE rekey.
        assert!(!is_ike_sa_rekey(&[
            (PayloadType::SecurityAssociation, vec![]),
            (PayloadType::Nonce, vec![]),
            (PayloadType::TrafficSelectorInitiator, vec![]),
            (PayloadType::TrafficSelectorResponder, vec![]),
        ]));
    }

    #[test]
    fn ike_rekey_initiator_and_responder_derive_matching_keys() {
        let (init_sa, resp_sa) = sa_pair();
        let suite = negotiate::select(&default_offer()).unwrap();
        let group = DhGroup::from_transform_id(suite.dh_id).unwrap();

        // Initiator builds the IKE-rekey request: SA(IKE, new SPIi) | Ni | KEi.
        let init_dh = [3u8; 32];
        let ni = vec![0x55u8; 32];
        let new_spi_i: u64 = 0xAABB_CCDD_1122_3344;
        let mut prop = suite.to_proposal();
        prop.protocol_id = protocol_id::IKE;
        prop.spi = new_spi_i.to_be_bytes().to_vec();
        let inner = vec![
            (PayloadType::SecurityAssociation, SecurityAssociation { proposals: vec![prop] }.to_bytes()),
            (PayloadType::Nonce, ni.clone()),
            (PayloadType::KeyExchange, KeyExchange { dh_group: suite.dh_id, data: group.public(&init_dh) }.to_bytes()),
        ];
        let header = IkeHeader {
            initiator_spi: init_sa.spi_i,
            responder_spi: init_sa.spi_r,
            next_payload: PayloadType::NoNext,
            major_version: 2,
            minor_version: 0,
            exchange_type: ExchangeType::CreateChildSa,
            flags: Flags { initiator: true, version: false, response: false },
            message_id: 5,
            length: 0,
        };
        let request = build_encrypted_gcm(
            header,
            first_payload_type(&inner),
            &encode_payload_chain(&inner),
            our_sk_e(&init_sa),
            &[1u8; 8],
        )
        .unwrap();

        // Responder processes it and derives the new IKE SA.
        let nr = vec![0x66u8; 32];
        let new_spi_r: u64 = 0x9988_7766_5544_3322;
        let (response, new_resp) =
            responder_process_ike_rekey(&resp_sa, &request, new_spi_r, &[9u8; 32], &nr, &[2u8; 8]).unwrap();
        assert_eq!(new_resp.spi_i, new_spi_i);
        assert_eq!(new_resp.spi_r, new_spi_r);

        // Initiator completes: decrypt response, get KEr, derive the SAME keys.
        let (first, dec) = open_encrypted_gcm(&response, peer_sk_e(&init_sa)).unwrap();
        let mut ker = None;
        for p in payloads(first, &dec) {
            let p = p.unwrap();
            if p.payload_type == PayloadType::KeyExchange {
                ker = Some(KeyExchange::parse(p.data).unwrap());
            }
        }
        let shared = group.shared(&init_dh, &ker.unwrap().data).unwrap();
        let init_keys = crate::crypto::derive_rekey_session_keys(
            suite.prf_algorithm(),
            &init_sa.keys.sk_d,
            &shared,
            &ni,
            &nr,
            new_spi_i,
            new_spi_r,
            suite.key_lengths(),
        );
        assert_eq!(init_keys.sk_d, new_resp.keys.sk_d, "SK_d must match");
        assert_eq!(init_keys.sk_ei, new_resp.keys.sk_ei, "SK_ei must match");
        assert_eq!(init_keys.sk_er, new_resp.keys.sk_er, "SK_er must match");
    }

    #[test]
    fn the_initiator_side_interoperates_with_the_responder_and_the_new_sa_works_both_ways() {
        use crate::ikev2::informational::{build_informational, open_informational};

        let (init_sa, resp_sa) = sa_pair();
        let ni = vec![0x55u8; 32];
        let dh = [3u8; 32];
        let new_spi_i: u64 = 0xAABB_CCDD_1122_3344;
        let request = build_ike_rekey_request(&init_sa, 5, new_spi_i, &ni, &dh, &[1u8; 8]).unwrap();
        assert_eq!(IkeHeader::parse(&request).unwrap().message_id, 5);

        // What the responder decrypts is routed as an IKE rekey, not a CHILD one.
        let (first, inner) =
            open_encrypted(resp_sa.suite.sk_cipher(), &request, peer_sk_e(&resp_sa), peer_sk_a(&resp_sa)).unwrap();
        let seen: Vec<_> = payloads(first, &inner)
            .map(|p| {
                let p = p.unwrap();
                (p.payload_type, p.data.to_vec())
            })
            .collect();
        assert!(is_ike_sa_rekey(&seen));

        let new_spi_r: u64 = 0x9988_7766_5544_3322;
        let (response, new_resp) =
            responder_process_ike_rekey(&resp_sa, &request, new_spi_r, &[9u8; 32], &[0x66u8; 32], &[2u8; 8]).unwrap();
        let new_init = initiator_complete_ike_rekey(&init_sa, &ni, new_spi_i, &dh, &response).unwrap();

        assert_eq!((new_init.role, new_init.spi_i, new_init.spi_r), (Role::Initiator, new_spi_i, new_spi_r));
        assert_eq!(new_init.keys.sk_d, new_resp.keys.sk_d);
        assert_eq!(new_init.keys.sk_ei, new_resp.keys.sk_ei);
        assert_eq!(new_init.keys.sk_er, new_resp.keys.sk_er);
        assert_eq!(new_init.keys.sk_ai, new_resp.keys.sk_ai);
        assert_eq!(new_init.keys.sk_ar, new_resp.keys.sk_ar);
        assert_ne!(new_init.keys.sk_d, init_sa.keys.sk_d, "a rekey must yield fresh keys");

        // The new SA carries traffic both ways; the old keys no longer open it.
        let ping = build_informational(&new_init, 0, false, &[], &[3u8; 8]).unwrap();
        open_informational(&new_resp, &ping).unwrap();
        let pong = build_informational(&new_resp, 0, true, &[], &[4u8; 8]).unwrap();
        open_informational(&new_init, &pong).unwrap();
        assert!(open_informational(&resp_sa, &ping).is_err());
    }

    #[test]
    fn a_peer_refusal_is_peer_rejected() {
        use crate::ikev2::payload::notify_type;

        let (init_sa, resp_sa) = sa_pair();
        let refusal = crate::ikev2::rekey::build_child_refusal(&resp_sa, 5, &[2u8; 8]).unwrap();
        match initiator_complete_ike_rekey(&init_sa, &[0x55u8; 32], 1, &[3u8; 32], &refusal) {
            Err(IkeError::PeerRejected { notify_type: t, .. }) => assert_eq!(t, notify_type::NO_ADDITIONAL_SAS),
            other => panic!("expected PeerRejected(NO_ADDITIONAL_SAS), got {other:?}"),
        }
    }

    #[test]
    fn an_answer_that_switches_the_suite_is_not_trusted() {
        use crate::ikev2::payload::{transform_type, Transform};

        let (init_sa, resp_sa) = sa_pair();
        // The peer picks another DH group than the one we offered.
        let mut prop = init_sa.suite.to_proposal();
        prop.protocol_id = protocol_id::IKE;
        prop.spi = 7u64.to_be_bytes().to_vec();
        for t in prop.transforms.iter_mut().filter(|t: &&mut Transform| t.transform_type == transform_type::DH) {
            t.transform_id = DhGroup::Modp2048.transform_id();
        }
        let inner = vec![
            (PayloadType::SecurityAssociation, SecurityAssociation { proposals: vec![prop] }.to_bytes()),
            (PayloadType::Nonce, vec![0x66u8; 32]),
            (PayloadType::KeyExchange, KeyExchange { dh_group: DhGroup::Modp2048.transform_id(), data: vec![1u8; 256] }.to_bytes()),
        ];
        let header = IkeHeader {
            initiator_spi: resp_sa.spi_i,
            responder_spi: resp_sa.spi_r,
            next_payload: PayloadType::NoNext,
            major_version: 2,
            minor_version: 0,
            exchange_type: ExchangeType::CreateChildSa,
            flags: Flags { initiator: false, version: false, response: true },
            message_id: 5,
            length: 0,
        };
        let response = build_encrypted(
            resp_sa.suite.sk_cipher(),
            header,
            first_payload_type(&inner),
            &encode_payload_chain(&inner),
            our_sk_e(&resp_sa),
            our_sk_a(&resp_sa),
            &[2u8; 8],
        )
        .unwrap();
        assert!(matches!(
            initiator_complete_ike_rekey(&init_sa, &[0x55u8; 32], 1, &[3u8; 32], &response),
            Err(IkeError::NoProposalChosen)
        ));
    }

    /// A `CREATE_CHILD_SA` message from `from` rekeying the IKE SA: the suite
    /// `from` runs with its DH transforms replaced by `dh`, and `ke` as the KE.
    fn ike_rekey_message(from: &CompletedSaInit, response: bool, dh: &[u16], ke: Option<KeyExchange>) -> Vec<u8> {
        use crate::ikev2::payload::{transform_type, Transform};

        let mut prop = from.suite.to_proposal();
        prop.protocol_id = protocol_id::IKE;
        prop.spi = 7u64.to_be_bytes().to_vec();
        prop.transforms.retain(|t| t.transform_type != transform_type::DH);
        prop.transforms.extend(dh.iter().map(|&id| Transform { transform_type: transform_type::DH, transform_id: id, key_length: None }));
        ike_rekey_message_with(from, response, vec![prop], ke)
    }

    /// [`ike_rekey_message`] with the SA payload's `proposals` given as they are.
    fn ike_rekey_message_with(from: &CompletedSaInit, response: bool, proposals: Vec<Proposal>, ke: Option<KeyExchange>) -> Vec<u8> {
        let mut inner = vec![
            (PayloadType::SecurityAssociation, SecurityAssociation { proposals }.to_bytes()),
            (PayloadType::Nonce, vec![0x66u8; 32]),
        ];
        inner.extend(ke.map(|ke| (PayloadType::KeyExchange, ke.to_bytes())));
        let header = IkeHeader {
            initiator_spi: from.spi_i,
            responder_spi: from.spi_r,
            next_payload: PayloadType::NoNext,
            major_version: 2,
            minor_version: 0,
            exchange_type: ExchangeType::CreateChildSa,
            flags: Flags { initiator: from.role == Role::Initiator, version: false, response },
            message_id: 5,
            length: 0,
        };
        let first = first_payload_type(&inner);
        build_encrypted(from.suite.sk_cipher(), header, first, &encode_payload_chain(&inner), our_sk_e(from), our_sk_a(from), &[2u8; 8]).unwrap()
    }

    /// RFC 7296 §1.3.2, §2.18: the IKE SA rekey always runs a fresh DH -- its
    /// KE is mandatory, not optional as a CHILD SA's PFS. So an answer that
    /// drops the KE, the group, or names NONE, a group we don't know or
    /// another one than the suite's, is refused by the initiator; the
    /// untouched answer completes. (Checked apart from the CHILD SA rekey:
    /// the audit's PFS removal doesn't reproduce here.)
    #[test]
    fn an_ike_rekey_answer_cannot_drop_or_swap_the_dh() {
        let (init_sa, resp_sa) = sa_pair();
        let (ni, dh, new_spi_i) = ([0x55u8; 32], [3u8; 32], 0xAABB_CCDD_1122_3344);
        let group = DhGroup::from_transform_id(init_sa.suite.dh_id).unwrap();
        let other = if group == DhGroup::Modp2048 { DhGroup::EcpP256 } else { DhGroup::Modp2048 };
        let ke = |g: DhGroup| Some(KeyExchange { dh_group: g.transform_id(), data: g.public(&[9u8; 32]) });
        let complete = |resp: &[u8]| initiator_complete_ike_rekey(&init_sa, &ni, new_spi_i, &dh, resp).map(|_| ());

        let request = build_ike_rekey_request(&init_sa, 5, new_spi_i, &ni, &dh, &[1u8; 8]).unwrap();
        let (response, _) = responder_process_ike_rekey(&resp_sa, &request, 7, &[9u8; 32], &[0x66u8; 32], &[2u8; 8]).unwrap();
        assert_eq!(complete(&response), Ok(()), "control: the real answer");
        assert_eq!(complete(&ike_rekey_message(&resp_sa, true, &[group.transform_id()], ke(group))), Ok(()), "control: hand-built");

        let unknown = Some(KeyExchange { dh_group: 0x7777, data: vec![9; 256] });
        let cases = [
            ("no KE", ike_rekey_message(&resp_sa, true, &[group.transform_id()], None), IkeError::MissingPayload("KE")),
            ("no DH transform", ike_rekey_message(&resp_sa, true, &[], ke(group)), IkeError::NoProposalChosen),
            ("DH NONE", ike_rekey_message(&resp_sa, true, &[0], None), IkeError::MissingPayload("KE")),
            ("an unknown group", ike_rekey_message(&resp_sa, true, &[0x7777], unknown), IkeError::NoProposalChosen),
            ("another group", ike_rekey_message(&resp_sa, true, &[other.transform_id()], ke(other)), IkeError::NoProposalChosen),
            (
                "the suite's group, a KE of another",
                ike_rekey_message(&resp_sa, true, &[group.transform_id()], ke(other)),
                IkeError::DhGroupMismatch { expected: group.transform_id(), got: other.transform_id() },
            ),
        ];
        for (what, answer, expected) in cases {
            assert_eq!(complete(&answer), Err(expected), "{what}");
        }
    }

    /// The responder side of the same: a peer's IKE SA rekey without a KE,
    /// without a DH group, or on a group IKEv2 may not run (unknown, or
    /// MODP-768, RFC 8247 §2.4) is refused, never answered without a fresh DH.
    #[test]
    fn an_ike_rekey_request_without_a_usable_dh_is_refused() {
        let (init_sa, resp_sa) = sa_pair();
        let group = DhGroup::from_transform_id(init_sa.suite.dh_id).unwrap();
        let ke = |g: DhGroup| Some(KeyExchange { dh_group: g.transform_id(), data: g.public(&[3u8; 32]) });
        let answer = |req: &[u8]| responder_process_ike_rekey(&resp_sa, req, 7, &[9u8; 32], &[0x66u8; 32], &[2u8; 8]).map(|_| ());

        assert_eq!(answer(&ike_rekey_message(&init_sa, false, &[group.transform_id()], ke(group))), Ok(()), "control");
        let cases = [
            ("no KE", ike_rekey_message(&init_sa, false, &[group.transform_id()], None), IkeError::MissingPayload("KE")),
            ("no DH transform", ike_rekey_message(&init_sa, false, &[], ke(group)), IkeError::NoProposalChosen),
            ("DH NONE", ike_rekey_message(&init_sa, false, &[0], None), IkeError::MissingPayload("KE")),
            (
                "an unknown group",
                ike_rekey_message(&init_sa, false, &[0x7777], Some(KeyExchange { dh_group: 0x7777, data: vec![9; 256] })),
                IkeError::NoProposalChosen,
            ),
            ("MODP-768", ike_rekey_message(&init_sa, false, &[1], ke(DhGroup::Modp768)), IkeError::NoProposalChosen),
        ];
        for (what, request, expected) in cases {
            assert_eq!(answer(&request), Err(expected), "{what}");
        }
    }

    /// RFC 7296 §2.7, §3.3.1, §3.3.6: the answer to our rekey is our one
    /// proposal -- by its number, with one transform of each of its types and
    /// nothing else -- whatever SPI it carries. Each forged answer below names
    /// the very suite we offered (so `select` and the suite comparison pass)
    /// and must still be refused; the well-formed one completes.
    #[test]
    fn an_ike_rekey_answer_must_be_our_one_proposal() {
        use crate::ikev2::payload::transform_type;

        let (init_sa, resp_sa) = sa_pair();
        let (ni, dh, new_spi_i) = ([0x55u8; 32], [3u8; 32], 0xAABB_CCDD_1122_3344);
        let group = DhGroup::from_transform_id(init_sa.suite.dh_id).unwrap();
        let ke = || Some(KeyExchange { dh_group: group.transform_id(), data: group.public(&[9u8; 32]) });
        let complete = |resp: &[u8]| initiator_complete_ike_rekey(&init_sa, &ni, new_spi_i, &dh, resp).map(|_| ());

        let mut ours = resp_sa.suite.to_proposal();
        ours.num = 1;
        ours.protocol_id = protocol_id::IKE;
        ours.spi = 7u64.to_be_bytes().to_vec();
        assert_eq!(complete(&ike_rekey_message_with(&resp_sa, true, vec![ours.clone()], ke())), Ok(()), "control");

        let dup_dh = {
            let mut p = ours.clone();
            let t = p.transforms.iter().find(|t| t.transform_type == transform_type::DH).unwrap().clone();
            p.transforms.push(t);
            p
        };
        let cases = [
            ("two proposals", vec![ours.clone(), ours.clone()]),
            ("two DH transforms", vec![dup_dh]),
            ("a proposal number we never sent", vec![Proposal { num: 2, ..ours.clone() }]),
        ];
        for (what, proposals) in cases {
            assert_eq!(complete(&ike_rekey_message_with(&resp_sa, true, proposals, ke())), Err(IkeError::NoProposalChosen), "{what}");
        }
    }

    /// The IKE proposal `from`'s suite is, as a rekey offers it -- with an INTEG
    /// NONE added when `integ_none`, the way a peer may offer a combined-mode cipher.
    fn ike_rekey_proposal(from: &CompletedSaInit, integ_none: bool) -> Proposal {
        use crate::ikev2::payload::{transform_id, transform_type, Transform};

        let mut prop = from.suite.to_proposal();
        prop.num = 1;
        prop.protocol_id = protocol_id::IKE;
        prop.spi = 7u64.to_be_bytes().to_vec();
        if integ_none {
            let at = prop.transforms.iter().position(|t| t.transform_type == transform_type::DH).unwrap();
            prop.transforms.insert(at, Transform { transform_type: transform_type::INTEG, transform_id: transform_id::INTEG_NONE, key_length: None });
        }
        prop
    }

    /// RFC 7296 §3.3: a combined-mode cipher's rekey offered with a single INTEG
    /// NONE is taken, and §2.7 has the answer carry that NONE: one transform of
    /// each type the proposal included. Offered with no INTEG it is answered
    /// with none, the RECOMMENDED form.
    #[test]
    fn an_ike_rekey_offered_with_an_integ_none_is_answered_with_it() {
        use crate::ikev2::payload::{transform_id, transform_type};

        let (init_sa, resp_sa) = sa_pair();
        let group = DhGroup::from_transform_id(init_sa.suite.dh_id).unwrap();
        let ke = || Some(KeyExchange { dh_group: group.transform_id(), data: group.public(&[3u8; 32]) });
        for (integ_none, answered) in [(false, vec![]), (true, vec![transform_id::INTEG_NONE])] {
            let offered = ike_rekey_proposal(&init_sa, integ_none);
            let request = ike_rekey_message_with(&init_sa, false, vec![offered.clone()], ke());
            let (response, new_sa) = responder_process_ike_rekey(&resp_sa, &request, 0x99, &[9u8; 32], &[0x66u8; 32], &[2u8; 8])
                .unwrap_or_else(|e| panic!("INTEG NONE offered: {integ_none}: refused with {e:?}"));
            assert_eq!(new_sa.suite.integ_id, None, "INTEG NONE offered: {integ_none}");
            let (first, inner) = open_encrypted(init_sa.suite.sk_cipher(), &response, peer_sk_e(&init_sa), peer_sk_a(&init_sa)).unwrap();
            let sa = payloads(first, &inner).map(Result::unwrap).find(|p| p.payload_type == PayloadType::SecurityAssociation).unwrap();
            let answer = SecurityAssociation::parse(sa.data).unwrap();
            let [proposal] = answer.proposals.as_slice() else { panic!("INTEG NONE offered: {integ_none}: {answer:?}") };
            let integ: Vec<u16> = proposal.transforms.iter().filter(|t| t.transform_type == transform_type::INTEG).map(|t| t.transform_id).collect();
            assert_eq!(integ, answered, "INTEG NONE offered: {integ_none}");
            assert_eq!(negotiate::accepted_proposal(&answer, &SecurityAssociation { proposals: vec![offered] }).map(|_| ()), Ok(()), "INTEG NONE offered: {integ_none}");
        }
    }

    /// The answer to a rekey we started has our proposal's INTEG transforms and
    /// no others (RFC 7296 §3.3.6): an INTEG NONE we never offered is refused,
    /// though the suite it names is ours. A suite the first exchange took with
    /// an INTEG NONE on offer (it was the peer's) rekeys as any other.
    #[test]
    fn an_ike_rekey_answer_does_not_add_an_integ_none_and_a_suite_taken_with_one_rekeys() {
        let (init_sa, resp_sa) = sa_pair();
        let (ni, dh, new_spi_i) = ([0x55u8; 32], [3u8; 32], 0xAABB_CCDD_1122_3344);
        let group = DhGroup::from_transform_id(init_sa.suite.dh_id).unwrap();
        let ke = || Some(KeyExchange { dh_group: group.transform_id(), data: group.public(&[9u8; 32]) });
        let complete = |resp: &[u8]| initiator_complete_ike_rekey(&init_sa, &ni, new_spi_i, &dh, resp).map(|_| ());
        assert_eq!(complete(&ike_rekey_message_with(&resp_sa, true, vec![ike_rekey_proposal(&resp_sa, false)], ke())), Ok(()), "control");
        assert_eq!(
            complete(&ike_rekey_message_with(&resp_sa, true, vec![ike_rekey_proposal(&resp_sa, true)], ke())),
            Err(IkeError::NoProposalChosen),
            "an INTEG NONE we did not offer"
        );

        // Both ends of an exchange whose offer had an INTEG NONE, then rekeyed.
        let mut offer = default_offer();
        offer.proposals[0].transforms.insert(2, crate::ikev2::payload::Transform {
            transform_type: crate::ikev2::payload::transform_type::INTEG,
            transform_id: crate::ikev2::payload::transform_id::INTEG_NONE,
            key_length: None,
        });
        let (init_none, resp_none) = sa_pair_with_offer(&offer);
        assert_eq!(init_none.suite.integ_id, None);
        let request = build_ike_rekey_request(&init_none, 5, new_spi_i, &ni, &dh, &[1u8; 8]).unwrap();
        let (response, new_resp) = responder_process_ike_rekey(&resp_none, &request, 0x99, &[9u8; 32], &[0x66u8; 32], &[2u8; 8]).unwrap();
        let new_init = initiator_complete_ike_rekey(&init_none, &ni, new_spi_i, &dh, &response).unwrap();
        assert_eq!(new_init.keys.sk_d, new_resp.keys.sk_d);
    }

    /// RFC 7296 §3.3.5, §3.3.6, as `IKE_SA_INIT` has it (`exchange.rs`): a PRF,
    /// DH or INTEG NONE transform takes no Key Length, so one that carries it
    /// is unacceptable in an IKE SA rekey too. The responder passes over the
    /// proposal that has it for the next one (whose SPI keys the new SA) and
    /// answers the plain transform of its type when both are offered; the
    /// initiator takes back no answer that names it.
    #[test]
    fn an_ike_rekey_transform_with_a_key_length_it_must_not_have_is_unacceptable_in_both_directions() {
        use crate::ikev2::payload::{transform_id, transform_type, Transform};

        let (init_sa, resp_sa) = sa_pair();
        let group = DhGroup::from_transform_id(init_sa.suite.dh_id).unwrap();
        let ke = || Some(KeyExchange { dh_group: group.transform_id(), data: group.public(&[3u8; 32]) });
        let with_key_length = |proposal: &Proposal, ty: u8| {
            let mut p = proposal.clone();
            p.transforms.iter_mut().filter(|t| t.transform_type == ty).for_each(|t| t.key_length = Some(128));
            p
        };
        let of_type = |proposal: &Proposal, ty: u8| proposal.transforms.iter().filter(|t| t.transform_type == ty).cloned().collect::<Vec<_>>();
        let (plain, plain_none) = (ike_rekey_proposal(&init_sa, false), ike_rekey_proposal(&init_sa, true));

        // The responder's side.
        let answer = |proposals: Vec<Proposal>| {
            responder_process_ike_rekey(&resp_sa, &ike_rekey_message_with(&init_sa, false, proposals, ke()), 0x99, &[9u8; 32], &[0x66u8; 32], &[2u8; 8])
        };
        let answered = |response: &[u8]| {
            let (first, inner) = open_encrypted(init_sa.suite.sk_cipher(), response, peer_sk_e(&init_sa), peer_sk_a(&init_sa)).unwrap();
            let sa = payloads(first, &inner).map(Result::unwrap).find(|p| p.payload_type == PayloadType::SecurityAssociation).unwrap();
            SecurityAssociation::parse(sa.data).unwrap().proposals.remove(0)
        };
        assert!(answer(vec![plain.clone()]).is_ok(), "control");
        let next_spi = 0x0102_0304_0506_0708u64;
        let next = Proposal { num: 2, spi: next_spi.to_be_bytes().to_vec(), ..plain.clone() };
        let refused = [
            ("a PRF", with_key_length(&plain, transform_type::PRF)),
            ("a DH", with_key_length(&plain, transform_type::DH)),
            ("an INTEG NONE", with_key_length(&plain_none, transform_type::INTEG)),
        ];
        for (what, bad) in &refused {
            assert_eq!(answer(vec![bad.clone()]).map(|_| ()), Err(IkeError::NoProposalChosen), "responder: {what}");
            let (_, new_sa) = answer(vec![bad.clone(), next.clone()]).unwrap_or_else(|e| panic!("responder: {what}, then a proposal that is fine: {e:?}"));
            assert_eq!(new_sa.spi_i, next_spi, "responder: {what}, then a proposal that is fine: the new SA is keyed on that one's SPI");
        }
        for (what, ty, mut both) in [
            ("a PRF", transform_type::PRF, plain.clone()),
            ("an INTEG NONE", transform_type::INTEG, plain_none.clone()),
        ] {
            let at = both.transforms.iter().position(|t| t.transform_type == ty).unwrap();
            let fine = both.transforms[at].clone();
            both.transforms.insert(at, Transform { key_length: Some(128), ..fine.clone() });
            let (response, _) = answer(vec![both]).unwrap_or_else(|e| panic!("responder: {what}, both kinds: {e:?}"));
            assert_eq!(of_type(&answered(&response), ty), [fine], "responder: {what}, both kinds: the plain one is answered");
        }
        assert_eq!(of_type(&plain_none, transform_type::INTEG), [Transform { transform_type: transform_type::INTEG, transform_id: transform_id::INTEG_NONE, key_length: None }], "the fixture offers a plain INTEG NONE");

        // The initiator's side: an answer that names the transform with the Key Length is not our proposal.
        let (ni, dh, new_spi_i) = ([0x55u8; 32], [3u8; 32], 0xAABB_CCDD_1122_3344);
        let ke = || Some(KeyExchange { dh_group: group.transform_id(), data: group.public(&[9u8; 32]) });
        let complete = |proposal: Proposal| initiator_complete_ike_rekey(&init_sa, &ni, new_spi_i, &dh, &ike_rekey_message_with(&resp_sa, true, vec![proposal], ke())).map(|_| ());
        let ours = ike_rekey_proposal(&resp_sa, false);
        assert_eq!(complete(ours.clone()), Ok(()), "initiator: control");
        for ty in [transform_type::PRF, transform_type::DH] {
            assert_eq!(complete(with_key_length(&ours, ty)), Err(IkeError::NoProposalChosen), "initiator: transform type {ty} with a Key Length");
        }
    }

    /// RFC 7296 §3.3.2, §3.3.3: ESN (Transform Type 5) is not an IKE transform, and an IKE SA
    /// rekey is judged as `IKE_SA_INIT` is (`exchange.rs`): an ESN transform in the proposal, with
    /// whatever it carries, is left out of the answer and decides nothing; the initiator takes back
    /// no answer that names one, as it never offers one.
    #[test]
    fn an_esn_transform_in_an_ike_rekey_proposal_is_left_out_whatever_it_carries() {
        use crate::ikev2::payload::{transform_id, transform_type, Transform};

        let (init_sa, resp_sa) = sa_pair();
        let group = DhGroup::from_transform_id(init_sa.suite.dh_id).unwrap();
        let ke = || Some(KeyExchange { dh_group: group.transform_id(), data: group.public(&[3u8; 32]) });
        let plain = ike_rekey_proposal(&init_sa, false);
        let esn = |id: u16, key_length: Option<u16>| Transform { transform_type: transform_type::ESN, transform_id: id, key_length };
        let with = |extra: &[Transform]| Proposal { transforms: [plain.transforms.clone(), extra.to_vec()].concat(), ..plain.clone() };
        let cases = [
            ("ESN NONE", vec![esn(transform_id::ESN_NONE, None)]),
            ("ESN turned on", vec![esn(transform_id::ESN_ENABLED, None)]),
            ("both ESN values", vec![esn(transform_id::ESN_NONE, None), esn(transform_id::ESN_ENABLED, None)]),
            ("an ESN with a Key Length", vec![esn(transform_id::ESN_NONE, Some(128))]),
            ("an ESN we cannot read", vec![esn(transform_id::UNUSABLE, None)]),
        ];

        let answer = |proposal: Proposal| responder_process_ike_rekey(&resp_sa, &ike_rekey_message_with(&init_sa, false, vec![proposal], ke()), 0x99, &[9u8; 32], &[0x66u8; 32], &[2u8; 8]);
        assert!(answer(plain.clone()).is_ok(), "control");
        for (what, extra) in &cases {
            let (response, new_sa) = answer(with(extra)).unwrap_or_else(|e| panic!("responder: {what}: {e:?}"));
            let (first, inner) = open_encrypted(init_sa.suite.sk_cipher(), &response, peer_sk_e(&init_sa), peer_sk_a(&init_sa)).unwrap();
            let sa = payloads(first, &inner).map(Result::unwrap).find(|p| p.payload_type == PayloadType::SecurityAssociation).unwrap();
            let answered = SecurityAssociation::parse(sa.data).unwrap().proposals.remove(0);
            assert!(answered.transforms.iter().all(|t| t.transform_type != transform_type::ESN), "responder: {what}, answered without it");
            assert_eq!(new_sa.suite.proposal_num, plain.num, "responder: {what}");
        }

        let (ni, dh, new_spi_i) = ([0x55u8; 32], [3u8; 32], 0xAABB_CCDD_1122_3344);
        let ke = || Some(KeyExchange { dh_group: group.transform_id(), data: group.public(&[9u8; 32]) });
        let complete = |proposal: Proposal| initiator_complete_ike_rekey(&init_sa, &ni, new_spi_i, &dh, &ike_rekey_message_with(&resp_sa, true, vec![proposal], ke())).map(|_| ());
        let ours = ike_rekey_proposal(&resp_sa, false);
        assert_eq!(complete(ours.clone()), Ok(()), "initiator: control");
        for (what, extra) in &cases {
            let named = Proposal { transforms: [ours.transforms.clone(), extra.clone()].concat(), ..ours.clone() };
            assert_eq!(complete(named), Err(IkeError::NoProposalChosen), "initiator: {what} in the answer");
        }
    }

    /// RFC 7296 §3.3.1: each proposal of an IKE SA rekey carries the SPI the
    /// initiator wants for the new SA *if that proposal is the one chosen*, so
    /// the responder keys the new SA on the SPI of the proposal it picked -- not
    /// on the first one, which it may well have turned down.
    #[test]
    fn an_ike_rekey_responder_keys_the_new_sa_on_the_chosen_proposals_spi() {
        use crate::ikev2::payload::{transform_type, Transform};

        let (init_sa, resp_sa) = sa_pair();
        let group = DhGroup::from_transform_id(init_sa.suite.dh_id).unwrap();
        let ke = Some(KeyExchange { dh_group: group.transform_id(), data: group.public(&[3u8; 32]) });

        let mut good = init_sa.suite.to_proposal();
        good.num = 2;
        good.protocol_id = protocol_id::IKE;
        good.spi = 0x2222_2222_2222_2222u64.to_be_bytes().to_vec();
        let mut refused = good.clone();
        refused.num = 1;
        refused.spi = 0x1111_1111_1111_1111u64.to_be_bytes().to_vec();
        for t in refused.transforms.iter_mut().filter(|t: &&mut Transform| t.transform_type == transform_type::ENCR) {
            t.transform_id = 0x7777; // no cipher we speak: this proposal is turned down
        }
        let request = ike_rekey_message_with(&init_sa, false, vec![refused, good], ke);
        let (_, new_sa) = responder_process_ike_rekey(&resp_sa, &request, 7, &[9u8; 32], &[0x66u8; 32], &[2u8; 8]).unwrap();
        assert_eq!(new_sa.suite.proposal_num, 2);
        assert_eq!(new_sa.spi_i, 0x2222_2222_2222_2222);
    }

    /// [`sa_pair`] on an offer whose PRF is `prf`.
    fn sa_pair_with_prf(prf: u16) -> (CompletedSaInit, CompletedSaInit) {
        let mut offer = default_offer();
        let t = offer.proposals[0].transforms.iter_mut().find(|t| t.transform_type == crate::ikev2::payload::transform_type::PRF).unwrap();
        t.transform_id = prf;
        let init = LocalSecret { dh_private: [7u8; 32], nonce: vec![0x11; 32], spi: 0xA1 };
        let resp = LocalSecret { dh_private: [9u8; 32], nonce: vec![0x22; 32], spi: 0xB2 };
        let request = initiator_request(&init, &offer);
        let (response, resp_done) = responder_respond(&request, &resp).unwrap();
        (initiator_complete(&init, &request, &response).unwrap(), resp_done)
    }

    /// An IKE SA rekey's responder refuses the peer's Ni, and its initiator
    /// the peer's Nr, when `bad`, with `error`; both take them on at `good`
    /// (ours is always 32 octets).
    fn check_ike_rekey_nonces(init_sa: &CompletedSaInit, resp_sa: &CompletedSaInit, bad: &[u8], good: &[u8], error: IkeError) {
        let (ours, dh, new_spi_i, new_spi_r) = ([0x55u8; 32], [3u8; 32], 0xAABB_CCDD_1122_3344u64, 0x9988_7766_5544_3322u64);
        let answer = |ni: &[u8]| {
            let request = build_ike_rekey_request(init_sa, 5, new_spi_i, ni, &dh, &[1u8; 8]).unwrap();
            responder_process_ike_rekey(resp_sa, &request, new_spi_r, &[9u8; 32], &ours, &[2u8; 8]).map(|_| ())
        };
        let complete = |nr: &[u8]| {
            let request = build_ike_rekey_request(init_sa, 5, new_spi_i, &ours, &dh, &[1u8; 8]).unwrap();
            let (response, _) = responder_process_ike_rekey(resp_sa, &request, new_spi_r, &[9u8; 32], nr, &[2u8; 8]).unwrap();
            initiator_complete_ike_rekey(init_sa, &ours, new_spi_i, &dh, &response).map(|_| ())
        };
        assert_eq!(answer(bad), Err(error.clone()), "Ni of {} octets", bad.len());
        assert_eq!(complete(bad), Err(error), "Nr of {} octets", bad.len());
        assert_eq!(answer(good), Ok(()), "Ni of {} octets", good.len());
        assert_eq!(complete(good), Ok(()), "Nr of {} octets", good.len());
    }

    /// RFC 7296 §3.9: an IKE SA rekey's Ni and Nr MUST be 16 to 256 octets,
    /// like every nonce; an empty, 15- or 257-octet one is refused whichever
    /// side receives it.
    #[test]
    fn an_ike_rekey_nonce_out_of_range_is_refused_on_both_sides() {
        let (init_sa, resp_sa) = sa_pair();
        let range = IkeError::Crypto("nonce length out of range (16-256 bytes)");
        check_ike_rekey_nonces(&init_sa, &resp_sa, &[], &[0x33; 16], range.clone());
        check_ike_rekey_nonces(&init_sa, &resp_sa, &[0x33; 15], &[0x33; 16], range.clone());
        check_ike_rekey_nonces(&init_sa, &resp_sa, &[0x33; 257], &[0x33; 256], range);
    }

    /// RFC 7296 §2.10: the new IKE SA's SKEYSEED is its PRF keyed with the
    /// old SK_d over Ni | Nr (§2.18), and each nonce MUST be at least half
    /// that PRF's key.
    #[test]
    fn an_ike_rekey_nonce_shorter_than_half_the_prf_key_is_refused() {
        use crate::ikev2::payload::transform_id::{PRF_HMAC_SHA2_384, PRF_HMAC_SHA2_512};
        let short = IkeError::Crypto("nonce shorter than half the negotiated PRF's key");
        for (prf, half) in [(PRF_HMAC_SHA2_512, 32), (PRF_HMAC_SHA2_384, 24)] {
            let (init_sa, resp_sa) = sa_pair_with_prf(prf);
            check_ike_rekey_nonces(&init_sa, &resp_sa, &vec![0x33; half - 1], &vec![0x33; half], short.clone());
        }
    }
}
