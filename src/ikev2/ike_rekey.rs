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
use crate::ikev2::payload::{notify_type_name, protocol_id, KeyExchange, Notify, SecurityAssociation};
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
    let mut prop = old_sa.suite.to_proposal();
    prop.num = 1; // a single-proposal offer: numbered from 1 whatever number the first handshake's pick had
    prop.protocol_id = protocol_id::IKE;
    prop.spi = new_spi_i.to_be_bytes().to_vec();
    let ke = KeyExchange { dh_group: old_sa.suite.dh_id, data: group.public(dh_private) };
    let inner = vec![
        (PayloadType::SecurityAssociation, SecurityAssociation { proposals: vec![prop] }.to_bytes()),
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

    let proposal = sa.proposals.first().ok_or(IkeError::NoProposalChosen)?;
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
    let proposal = sa.proposals.first().ok_or(IkeError::NoProposalChosen)?;
    if proposal.spi.len() != 8 {
        return Err(IkeError::Crypto("expected an 8-byte IKE SPI"));
    }
    let spi_i = u64::from_be_bytes(proposal.spi[..8].try_into().unwrap());

    let suite = negotiate::select(&sa).ok_or(IkeError::NoProposalChosen)?;
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
    let mut prop = suite.to_proposal();
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
    use crate::ikev2::exchange::{
        default_offer, initiator_complete, initiator_request, responder_respond, LocalSecret,
    };
    use crate::ikev2::sk::{build_encrypted_gcm, open_encrypted_gcm};

    fn sa_pair() -> (CompletedSaInit, CompletedSaInit) {
        let init = LocalSecret { dh_private: [7u8; 32], nonce: vec![0x11; 32], spi: 0xA1 };
        let resp = LocalSecret { dh_private: [9u8; 32], nonce: vec![0x22; 32], spi: 0xB2 };
        let request = initiator_request(&init, &default_offer());
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
        let mut inner = vec![
            (PayloadType::SecurityAssociation, SecurityAssociation { proposals: vec![prop] }.to_bytes()),
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
}
