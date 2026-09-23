//! The INFORMATIONAL exchange (RFC 7296 §1.4): encrypted control messages
//! carrying Notify / Delete payloads — or nothing at all, which is a Dead Peer
//! Detection (DPD) liveness probe that the peer must answer.
//!
//! Direction rule (RFC 7296 §2.14): the original initiator always encrypts with
//! `SK_ei`, the responder with `SK_er`, regardless of who is requesting.

use crate::error::IkeError;
use crate::ikev2::exchange::CompletedSaInit;
use crate::ikev2::message::{
    encode_payload_chain, first_payload_type, payloads, ExchangeType, Flags, IkeHeader, PayloadType,
};
use crate::ikev2::payload::{notify_type, Delete, Notify};
use crate::role::Role;
use crate::ikev2::sk::{build_encrypted, open_encrypted};

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

pub(crate) fn peer_sk_e(sa: &CompletedSaInit) -> &[u8] {
    match sa.role {
        Role::Initiator => &sa.keys.sk_er,
        Role::Responder => &sa.keys.sk_ei,
    }
}

pub(crate) fn peer_sk_a(sa: &CompletedSaInit) -> &[u8] {
    match sa.role {
        Role::Initiator => &sa.keys.sk_ar,
        Role::Responder => &sa.keys.sk_ai,
    }
}

fn informational_header(sa: &CompletedSaInit, message_id: u32, is_response: bool) -> IkeHeader {
    IkeHeader {
        initiator_spi: sa.spi_i,
        responder_spi: sa.spi_r,
        next_payload: PayloadType::NoNext, // set by build_encrypted
        major_version: 2,
        minor_version: 0,
        exchange_type: ExchangeType::Informational,
        // The Initiator (I) flag marks messages from the original initiator.
        flags: Flags { initiator: sa.role == Role::Initiator, version: false, response: is_response },
        message_id,
        length: 0,
    }
}

/// Build an encrypted INFORMATIONAL message carrying the given inner payloads.
pub fn build_informational(
    sa: &CompletedSaInit,
    message_id: u32,
    is_response: bool,
    inner_payloads: &[(PayloadType, Vec<u8>)],
    iv: &[u8; 8],
) -> Result<Vec<u8>, IkeError> {
    let header = informational_header(sa, message_id, is_response);
    let first = first_payload_type(inner_payloads);
    let inner = encode_payload_chain(inner_payloads);
    build_encrypted(sa.suite.sk_cipher(), header, first, &inner, our_sk_e(sa), our_sk_a(sa), iv)
}

/// A DPD liveness check: an empty INFORMATIONAL request. A live peer must reply
/// with an (also empty) INFORMATIONAL response.
pub fn dpd_request(sa: &CompletedSaInit, message_id: u32, iv: &[u8; 8]) -> Result<Vec<u8>, IkeError> {
    build_informational(sa, message_id, false, &[], iv)
}

/// Decrypt an INFORMATIONAL from the peer, returning its inner payloads as
/// `(type, body)` pairs. An empty result is a DPD liveness probe/ack.
pub fn open_informational(sa: &CompletedSaInit, message: &[u8]) -> Result<Vec<(PayloadType, Vec<u8>)>, IkeError> {
    let (first, inner) = open_from_peer(sa, message)?;
    payload_list(first, &inner)
}

/// Decrypt and authenticate `message`, one the peer sent on `sa` in any
/// exchange, returning the first inner payload's type and the SK payload's
/// plaintext. This is the integrity check alone (RFC 7296 §3.14): whether the
/// header's SPIs, flags, exchange type and Message ID are what such a message
/// should carry is the caller's to check -- the keys don't depend on them.
pub fn open_from_peer(sa: &CompletedSaInit, message: &[u8]) -> Result<(PayloadType, Vec<u8>), IkeError> {
    open_encrypted(sa.suite.sk_cipher(), message, peer_sk_e(sa), peer_sk_a(sa))
}

/// The payload chain starting with a `first` payload in `body`, as
/// `(type, body)` pairs.
pub fn payload_list(first: PayloadType, body: &[u8]) -> Result<Vec<(PayloadType, Vec<u8>)>, IkeError> {
    let mut out = Vec::new();
    for payload in payloads(first, body) {
        let payload = payload?;
        out.push((payload.payload_type, payload.data.to_vec()));
    }
    Ok(out)
}

/// The Delete payloads among `payloads`, each checked by [`Delete::parse`]:
/// one malformed Delete makes the message malformed.
pub fn deletes_in(payloads: &[(PayloadType, Vec<u8>)]) -> Result<Vec<Delete>, IkeError> {
    payloads.iter().filter(|(t, _)| *t == PayloadType::Delete).map(|(_, body)| Delete::parse(body)).collect()
}

/// The error notify a request earns when it authenticates and is in the
/// window but its payloads can't be taken, by what `error` went wrong
/// reading them: `UNSUPPORTED_CRITICAL_PAYLOAD` naming the payload type, for
/// a payload of a type we don't know with the critical flag set (RFC 7296
/// §2.5), and `INVALID_SYNTAX` for anything else -- a malformed payload
/// chain, or a payload whose fields don't hold together (§2.21.3).
pub fn request_error_notify(error: &IkeError) -> Notify {
    match error {
        IkeError::UnsupportedCriticalPayload(payload_type) => Notify::status(notify_type::UNSUPPORTED_CRITICAL_PAYLOAD, vec![*payload_type]),
        _ => Notify::status(notify_type::INVALID_SYNTAX, Vec::new()),
    }
}

/// Our response on `sa` to the peer's request with header `request`, in the
/// request's exchange, carrying `notify` alone: the answer to a request with
/// an error (RFC 7296 §2.21.3).
pub fn build_error_response(sa: &CompletedSaInit, request: &IkeHeader, notify: &Notify, iv: &[u8; 8]) -> Result<Vec<u8>, IkeError> {
    let mut header = informational_header(sa, request.message_id, true);
    header.exchange_type = request.exchange_type;
    let inner = encode_payload_chain(&[(PayloadType::Notify, notify.to_bytes())]);
    build_encrypted(sa.suite.sk_cipher(), header, PayloadType::Notify, &inner, our_sk_e(sa), our_sk_a(sa), iv)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ikev2::exchange::{default_offer, initiator_complete, initiator_request, responder_respond, LocalSecret};

    fn sa_pair() -> (CompletedSaInit, CompletedSaInit) {
        let init = LocalSecret { dh_private: [7u8; 32], nonce: vec![0x11; 32], spi: 0xA1 };
        let resp = LocalSecret { dh_private: [9u8; 32], nonce: vec![0x22; 32], spi: 0xB2 };
        let request = initiator_request(&init, &default_offer());
        let (response, resp_done) = responder_respond(&request, &resp).unwrap();
        let init_done = initiator_complete(&init, &request, &response).unwrap();
        (init_done, resp_done)
    }

    #[test]
    fn dpd_liveness_roundtrip() {
        let (init_sa, resp_sa) = sa_pair();
        // Initiator probes; responder decrypts an empty INFORMATIONAL.
        let req = dpd_request(&init_sa, 2, &[1u8; 8]).unwrap();
        assert!(open_informational(&resp_sa, &req).unwrap().is_empty());

        // Responder answers; initiator decrypts the (empty) ack.
        let ack = build_informational(&resp_sa, 2, true, &[], &[2u8; 8]).unwrap();
        assert!(open_informational(&init_sa, &ack).unwrap().is_empty());
    }

    #[test]
    fn delete_message_roundtrips_through_sk() {
        let (init_sa, resp_sa) = sa_pair();
        let del = Delete::esp(vec![0xDEAD_BEEF]);
        let msg = build_informational(&init_sa, 3, false, &[(PayloadType::Delete, del.to_bytes())], &[3u8; 8]).unwrap();

        let got = open_informational(&resp_sa, &msg).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].0, PayloadType::Delete);
        assert_eq!(Delete::parse(&got[0].1).unwrap(), del);
    }

    #[test]
    fn tampered_informational_is_rejected() {
        let (init_sa, resp_sa) = sa_pair();
        let mut msg = dpd_request(&init_sa, 2, &[5u8; 8]).unwrap();
        let last = msg.len() - 1;
        msg[last] ^= 1;
        assert_eq!(open_informational(&resp_sa, &msg).unwrap_err(), IkeError::BadIntegrity);
    }
}
