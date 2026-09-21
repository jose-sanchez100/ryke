//! CHILD SA rekey via the `CREATE_CHILD_SA` exchange (RFC 7296 §1.3.1, §2.8),
//! with optional PFS.
//!
//! ```text
//! Initiator → SK { N(REKEY_SA, old_spi), SA(new_spi), Ni, [KEi,] TSi, TSr }
//! Responder → SK { SA(new_spi), Nr, [KEr,] TSi, TSr }
//! ```
//!
//! Without PFS, the new CHILD-SA keys come from `prf+(SK_d, Ni | Nr)` with the
//! *rekey* nonces (see [`crate::esp::ChildSa::derive`]). With PFS (the
//! `_with_pfs` functions, gated on the caller supplying a DH group + our
//! ephemeral private key), a fresh KE payload is exchanged and its shared
//! secret is folded in per RFC 7296 §2.18's CHILD_SA analog:
//! `KEYMAT = prf+(SK_d, g^ir(new) | Ni | Nr)` (see
//! [`crate::esp::ChildSa::derive_pfs`]). Both sides end up with matching ESP
//! SAs on freshly chosen SPIs.
//!
//! The ESP cipher itself stays the fixed AES-256-GCM `esp_offer` default in
//! both cases -- rekey doesn't renegotiate the CHILD SA's algorithm (that's
//! only wired at initial connect, via Phase G/H), only optionally adds PFS to
//! whatever cipher the tunnel already uses.

use std::net::Ipv4Addr;

use crate::crypto::DhGroup;
use crate::error::IkeError;
use crate::esp::ChildSa;
use crate::ikev2::exchange::CompletedSaInit;
use crate::ikev2::ike_auth::esp_offer_for_cipher;
use crate::ikev2::message::{
    encode_payload_chain, first_payload_type, payloads, ExchangeType, Flags, IkeHeader, PayloadType,
};
use crate::ikev2::payload::{
    notify_type, protocol_id, transform_type, KeyExchange, Notify, SecurityAssociation, Transform, TrafficSelector,
    TrafficSelectors,
};
use crate::role::Role;
use crate::ikev2::sk::{build_encrypted, open_encrypted, SkCipher};

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

fn full_tunnel_ts() -> Vec<u8> {
    TrafficSelectors { selectors: vec![TrafficSelector::ipv4_any()] }.to_bytes()
}

fn create_child_header(sa: &CompletedSaInit, message_id: u32, is_response: bool) -> IkeHeader {
    IkeHeader {
        initiator_spi: sa.spi_i,
        responder_spi: sa.spi_r,
        next_payload: PayloadType::NoNext,
        major_version: 2,
        minor_version: 0,
        exchange_type: ExchangeType::CreateChildSa,
        flags: Flags { initiator: sa.role == Role::Initiator, version: false, response: is_response },
        message_id,
        length: 0,
    }
}

/// The ESP SPI a peer proposed in its SA payload.
fn esp_spi_from_sa(sa_bytes: &[u8]) -> Result<u32, IkeError> {
    let sa = SecurityAssociation::parse(sa_bytes)?;
    let proposal = sa.proposals.first().ok_or(IkeError::NoProposalChosen)?;
    if proposal.spi.len() != 4 {
        return Err(IkeError::Crypto("expected a 4-byte ESP SPI"));
    }
    Ok(u32::from_be_bytes(proposal.spi[..4].try_into().unwrap()))
}

/// Extract the (SA bytes, Nonce bytes) from a decrypted CREATE_CHILD_SA message.
fn find_sa_and_nonce(first: PayloadType, inner: &[u8]) -> Result<(Vec<u8>, Vec<u8>), IkeError> {
    let mut sa = None;
    let mut nonce = None;
    for payload in payloads(first, inner) {
        let payload = payload?;
        match payload.payload_type {
            PayloadType::SecurityAssociation => sa = Some(payload.data.to_vec()),
            PayloadType::Nonce => nonce = Some(payload.data.to_vec()),
            _ => {}
        }
    }
    Ok((sa.ok_or(IkeError::MissingPayload("SA"))?, nonce.ok_or(IkeError::MissingPayload("Nonce"))?))
}

/// The KE payload from a decrypted CREATE_CHILD_SA message, if any.
fn find_ke(first: PayloadType, inner: &[u8]) -> Result<Option<KeyExchange>, IkeError> {
    for payload in payloads(first, inner) {
        let p = payload?;
        if p.payload_type == PayloadType::KeyExchange {
            return Ok(Some(KeyExchange::parse(p.data)?));
        }
    }
    Ok(None)
}

/// The DH transform on an ESP proposal's first alternative, if any -- the
/// PFS-wanted signal (its mere presence, not any negotiation of it) per this
/// module's own doc comment.
pub fn dh_transform_id(sa: &SecurityAssociation) -> Option<u16> {
    sa.proposals.first()?.transforms.iter().find(|t| t.transform_type == transform_type::DH).map(|t| t.transform_id)
}

/// Our ephemeral share of a PFS exchange: the DH group both sides will use,
/// plus our private key to derive the eventual shared secret from the peer's
/// KE payload.
pub type PfsKeyExchange<'a> = (DhGroup, &'a [u8]);

/// Initiator: build a CHILD-SA rekey request for the CHILD SA `rekeyed_spi`
/// (the SPI we expect on inbound ESP for it, RFC 7296 §1.3.3),
/// proposing a new SA on `new_spi` with fresh nonce `ni`.
pub fn build_rekey_request(
    sa: &CompletedSaInit,
    message_id: u32,
    rekeyed_spi: u32,
    new_spi: u32,
    ni: &[u8],
    iv: &[u8; 8],
) -> Result<Vec<u8>, IkeError> {
    build_rekey_request_with_pfs(sa, message_id, rekeyed_spi, new_spi, ni, SkCipher::Aes256Gcm, None, iv)
}

/// Like [`build_rekey_request`], but when `pfs` is `Some((group, our_dh_private))`
/// also advertises `group` as a DH transform on the new ESP proposal and adds a
/// `KeyExchange` payload built from `our_dh_private` -- PFS for the rekeyed
/// CHILD SA. `None` reproduces `build_rekey_request`'s exact behavior.
/// `cipher` is the ESP cipher already running on the tunnel being rekeyed --
/// see [`esp_offer_for_cipher`]'s own doc for why this offer must preserve it
/// rather than always proposing AES-GCM-256.
#[allow(clippy::too_many_arguments)]
pub fn build_rekey_request_with_pfs(
    sa: &CompletedSaInit,
    message_id: u32,
    rekeyed_spi: u32,
    new_spi: u32,
    ni: &[u8],
    cipher: SkCipher,
    pfs: Option<PfsKeyExchange>,
    iv: &[u8; 8],
) -> Result<Vec<u8>, IkeError> {
    let ts = TrafficSelectors { selectors: vec![TrafficSelector::ipv4_any()] };
    build_child_request(sa, message_id, Some(rekeyed_spi), new_spi, ni, cipher, pfs, &ts, iv)
}

/// The `CREATE_CHILD_SA` request behind both a CHILD SA rekey and the
/// creation of an *additional* CHILD SA next to the one `IKE_AUTH` made
/// (RFC 7296 §1.3.1): `rekeyed_spi` is `Some(our inbound SPI of the SA being
/// replaced)` (§1.3.3: the SPI the initiator expects in inbound ESP) for a rekey (adds the `REKEY_SA` notify) and `None` for a
/// brand-new CHILD SA. `ts` is proposed as both TSi and TSr, so a caller
/// negotiating a separate IPv6 CHILD SA passes `::/0` here. Some gateways
/// (FortiGate) keep IPv4 and IPv6 as separate Phase 2 selectors and only ever
/// grant one address family per CHILD SA, so IPv6 can't simply ride along in
/// the `IKE_AUTH` offer.
#[allow(clippy::too_many_arguments)]
pub fn build_child_request(
    sa: &CompletedSaInit,
    message_id: u32,
    rekeyed_spi: Option<u32>,
    new_spi: u32,
    ni: &[u8],
    cipher: SkCipher,
    pfs: Option<PfsKeyExchange>,
    ts: &TrafficSelectors,
    iv: &[u8; 8],
) -> Result<Vec<u8>, IkeError> {
    let mut offer = esp_offer_for_cipher(new_spi, cipher);
    if let Some((group, _)) = pfs {
        offer.proposals[0].transforms.push(Transform { transform_type: transform_type::DH, transform_id: group.transform_id(), key_length: None });
    }
    let mut inner = Vec::new();
    if let Some(rekeyed_spi) = rekeyed_spi {
        let rekey_notify = Notify {
            protocol_id: protocol_id::ESP,
            spi: rekeyed_spi.to_be_bytes().to_vec(),
            notify_type: notify_type::REKEY_SA,
            data: Vec::new(),
        };
        inner.push((PayloadType::Notify, rekey_notify.to_bytes()));
    }
    inner.push((PayloadType::SecurityAssociation, offer.to_bytes()));
    inner.push((PayloadType::Nonce, ni.to_vec()));
    if let Some((group, dh_private)) = pfs {
        let ke = KeyExchange { dh_group: group.transform_id(), data: group.public(dh_private) };
        inner.push((PayloadType::KeyExchange, ke.to_bytes()));
    }
    inner.push((PayloadType::TrafficSelectorInitiator, ts.to_bytes()));
    inner.push((PayloadType::TrafficSelectorResponder, ts.to_bytes()));
    let header = create_child_header(sa, message_id, false);
    let first = first_payload_type(&inner);
    let bytes = encode_payload_chain(&inner);
    build_encrypted(sa.suite.sk_cipher(), header, first, &bytes, our_sk_e(sa), our_sk_a(sa), iv)
}

/// The response to a `CREATE_CHILD_SA` request the *peer* initiated -- its own
/// rekey of the CHILD SA or of the IKE SA, or an extra CHILD SA (RFC 7296
/// §1.3) -- refusing it with `NO_ADDITIONAL_SAS` (§3.10.1). This side only
/// ever initiates rekeys, so it can't take one on; but the refusal must still
/// be a well-formed `CREATE_CHILD_SA` response: an answer of any other
/// exchange type (an empty INFORMATIONAL, say) is a protocol error a gateway
/// such as strongSwan answers by destroying the whole IKE SA, where a plain
/// refusal leaves it standing. `message_id` is the request's own.
pub fn build_child_refusal(sa: &CompletedSaInit, message_id: u32, iv: &[u8; 8]) -> Result<Vec<u8>, IkeError> {
    let inner = vec![(PayloadType::Notify, Notify::status(notify_type::NO_ADDITIONAL_SAS, Vec::new()).to_bytes())];
    let header = create_child_header(sa, message_id, true);
    let first = first_payload_type(&inner);
    let bytes = encode_payload_chain(&inner);
    build_encrypted(sa.suite.sk_cipher(), header, first, &bytes, our_sk_e(sa), our_sk_a(sa), iv)
}

/// The SPI a CHILD SA rekey request names in its `REKEY_SA` notify -- what a
/// responder looks the old SA up by. Test-only: [`responder_process_rekey`]
/// itself does not act on it.
#[cfg(test)]
pub(crate) fn rekey_sa_spi(sa: &CompletedSaInit, request: &[u8]) -> Option<u32> {
    let (first, inner) = open_encrypted(sa.suite.sk_cipher(), request, peer_sk_e(sa), peer_sk_a(sa)).ok()?;
    payloads(first, &inner)
        .filter_map(Result::ok)
        .filter(|p| p.payload_type == PayloadType::Notify)
        .filter_map(|p| Notify::parse(p.data).ok())
        .find(|n| n.notify_type == notify_type::REKEY_SA)
        .and_then(|n| <[u8; 4]>::try_from(n.spi).ok())
        .map(u32::from_be_bytes)
}

/// Responder: process a rekey request, derive the new CHILD SA, and build the
/// response. Returns `(response_bytes, ChildSa)`.
pub fn responder_process_rekey(
    sa: &CompletedSaInit,
    request: &[u8],
    new_spi: u32,
    nr: &[u8],
    iv: &[u8; 8],
    assigned_ip: Option<Ipv4Addr>,
) -> Result<(Vec<u8>, ChildSa), IkeError> {
    responder_process_rekey_with_pfs(sa, request, new_spi, nr, SkCipher::Aes256Gcm, None, iv, assigned_ip)
}

/// Like [`responder_process_rekey`], but honors PFS when the request's ESP
/// proposal carries a DH transform: `dh_private` is our ephemeral private key
/// for that group, required in that case (a `MissingPayload("KE")` error if
/// the peer signaled PFS but we weren't given one, or vice versa) -- the
/// caller is expected to have generated one as soon as it saw the DH
/// transform, mirroring [`crate::ikev2::ike_rekey::responder_process_ike_rekey`]'s
/// `dh_private` parameter for the IKE-SA-rekey analog. `cipher` is the ESP
/// cipher already running on the tunnel being rekeyed -- see
/// [`esp_offer_for_cipher`]'s own doc for why the reply must preserve it.
#[allow(clippy::too_many_arguments)]
pub fn responder_process_rekey_with_pfs(
    sa: &CompletedSaInit,
    request: &[u8],
    new_spi: u32,
    nr: &[u8],
    cipher: SkCipher,
    dh_private: Option<&[u8]>,
    iv: &[u8; 8],
    assigned_ip: Option<Ipv4Addr>,
) -> Result<(Vec<u8>, ChildSa), IkeError> {
    let message_id = IkeHeader::parse(request)?.message_id;
    let (first, inner) = open_encrypted(sa.suite.sk_cipher(), request, peer_sk_e(sa), peer_sk_a(sa))?;
    let (sa_bytes, ni) = find_sa_and_nonce(first, &inner)?;
    let peer_spi = esp_spi_from_sa(&sa_bytes)?;
    let peer_sa = SecurityAssociation::parse(&sa_bytes)?;
    let pfs_group = dh_transform_id(&peer_sa).and_then(DhGroup::from_transform_id);

    // Traffic selectors: mirror exactly what IKE_AUTH did for this client. At AUTH we
    // narrow TSi to the client's assigned /32 and set TSr = full-tunnel; iOS installs
    // that policy. At rekey a native client (iOS) may re-propose a *wide* 0.0.0.0/0
    // TSi and expect the responder to re-narrow — as at AUTH. Echoing the wide TSi
    // back yields a rekeyed child whose selectors disagree with the /32 iOS holds, so
    // iOS deletes the whole IKE SA (~1s after the rekey). When we have an assignment,
    // re-narrow to that /32; with none (local egress), fall back to echoing.
    let (mut echo_tsi, mut echo_tsr) = (None, None);
    for payload in payloads(first, &inner) {
        let p = payload?;
        match p.payload_type {
            PayloadType::TrafficSelectorInitiator => echo_tsi = Some(p.data.to_vec()),
            PayloadType::TrafficSelectorResponder => echo_tsr = Some(p.data.to_vec()),
            _ => {}
        }
    }
    let (tsi, tsr) = match assigned_ip {
        Some(ip) => (
            TrafficSelectors { selectors: vec![TrafficSelector::ipv4_host(ip)] }.to_bytes(),
            full_tunnel_ts(),
        ),
        None => (
            echo_tsi.unwrap_or_else(full_tunnel_ts),
            echo_tsr.unwrap_or_else(full_tunnel_ts),
        ),
    };

    let peer_ke = find_ke(first, &inner)?;
    let pfs_secret = match (pfs_group, peer_ke, dh_private) {
        (Some(group), Some(ke), Some(our_priv)) => {
            if ke.dh_group != group.transform_id() {
                return Err(IkeError::DhGroupMismatch { expected: group.transform_id(), got: ke.dh_group });
            }
            Some(group.shared(our_priv, &ke.data)?)
        }
        (None, _, _) => None,
        _ => return Err(IkeError::MissingPayload("KE")),
    };

    let child = match &pfs_secret {
        Some(secret) => ChildSa::derive_with_cipher_pfs(sa.suite.prf_algorithm(), cipher, secret, &sa.keys.sk_d, &ni, nr, Role::Responder, new_spi, peer_spi),
        None => ChildSa::derive_with_cipher(sa.suite.prf_algorithm(), cipher, &sa.keys.sk_d, &ni, nr, Role::Responder, new_spi, peer_spi),
    };

    let mut sa_out = esp_offer_for_cipher(new_spi, cipher);
    let mut inner_out = Vec::new();
    if let (Some(group), Some(our_priv)) = (pfs_group, dh_private) {
        sa_out.proposals[0].transforms.push(Transform { transform_type: transform_type::DH, transform_id: group.transform_id(), key_length: None });
        inner_out.push((PayloadType::SecurityAssociation, sa_out.to_bytes()));
        inner_out.push((PayloadType::Nonce, nr.to_vec()));
        let ke_out = KeyExchange { dh_group: group.transform_id(), data: group.public(our_priv) };
        inner_out.push((PayloadType::KeyExchange, ke_out.to_bytes()));
    } else {
        inner_out.push((PayloadType::SecurityAssociation, sa_out.to_bytes()));
        inner_out.push((PayloadType::Nonce, nr.to_vec()));
    }
    inner_out.push((PayloadType::TrafficSelectorInitiator, tsi));
    inner_out.push((PayloadType::TrafficSelectorResponder, tsr));
    let header = create_child_header(sa, message_id, true);
    let first_out = first_payload_type(&inner_out);
    let bytes = encode_payload_chain(&inner_out);
    if std::env::var_os("RYKE_REKEY_TRACE").is_some() {
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        eprintln!("[ryke/rekeyresp] first={first_out:?} inner ({} B) = {hex}", bytes.len());
    }
    let response = build_encrypted(sa.suite.sk_cipher(), header, first_out, &bytes, our_sk_e(sa), our_sk_a(sa), iv)?;
    Ok((response, child))
}

/// Initiator: complete the rekey from the response, deriving the new CHILD SA.
/// `ni` and `new_spi` are the values used in [`build_rekey_request`].
pub fn initiator_complete_rekey(
    sa: &CompletedSaInit,
    ni: &[u8],
    new_spi: u32,
    response: &[u8],
) -> Result<ChildSa, IkeError> {
    initiator_complete_rekey_with_pfs(sa, ni, new_spi, SkCipher::Aes256Gcm, None, response)
}

/// Like [`initiator_complete_rekey`], but for a rekey started with
/// [`build_rekey_request_with_pfs`]: `dh_private` must be the same ephemeral
/// private key passed there whenever PFS was requested (`None` otherwise),
/// and `cipher` the same cipher passed there too (preserving the tunnel's
/// already-negotiated algorithm -- see [`esp_offer_for_cipher`]'s own doc).
pub fn initiator_complete_rekey_with_pfs(
    sa: &CompletedSaInit,
    ni: &[u8],
    new_spi: u32,
    cipher: SkCipher,
    dh_private: Option<&[u8]>,
    response: &[u8],
) -> Result<ChildSa, IkeError> {
    initiator_complete_child(sa, ni, new_spi, cipher, dh_private, response).map(|(child, _tsr)| child)
}

/// Like [`initiator_complete_rekey_with_pfs`], for either kind of
/// `CREATE_CHILD_SA` request [`build_child_request`] builds, and also returns
/// the `TSr` the responder granted (`None` if it sent none) -- for a newly
/// created CHILD SA that is what decides what the caller routes into it. A
/// response carrying an error Notify (`NO_PROPOSAL_CHOSEN`, `TS_UNACCEPTABLE`,
/// ...) is [`IkeError::PeerRejected`] rather than a confusing missing-payload
/// error.
pub fn initiator_complete_child(
    sa: &CompletedSaInit,
    ni: &[u8],
    new_spi: u32,
    cipher: SkCipher,
    dh_private: Option<&[u8]>,
    response: &[u8],
) -> Result<(ChildSa, Option<TrafficSelectors>), IkeError> {
    let (first, inner) = open_encrypted(sa.suite.sk_cipher(), response, peer_sk_e(sa), peer_sk_a(sa))?;
    let mut tsr = None;
    for payload in payloads(first, &inner) {
        let p = payload?;
        match p.payload_type {
            PayloadType::Notify => {
                if let Ok(n) = Notify::parse(p.data) {
                    if n.is_error() {
                        return Err(IkeError::PeerRejected {
                            notify_type: n.notify_type,
                            name: crate::ikev2::payload::notify_type_name(n.notify_type),
                        });
                    }
                }
            }
            PayloadType::TrafficSelectorResponder => tsr = Some(TrafficSelectors::parse(p.data)?),
            _ => {}
        }
    }
    let (sa_bytes, nr) = find_sa_and_nonce(first, &inner)?;
    let peer_spi = esp_spi_from_sa(&sa_bytes)?;
    let peer_sa = SecurityAssociation::parse(&sa_bytes)?;
    let pfs_group = dh_transform_id(&peer_sa).and_then(DhGroup::from_transform_id);

    let peer_ke = find_ke(first, &inner)?;
    let pfs_secret = match (pfs_group, peer_ke, dh_private) {
        (Some(group), Some(ke), Some(our_priv)) => {
            if ke.dh_group != group.transform_id() {
                return Err(IkeError::DhGroupMismatch { expected: group.transform_id(), got: ke.dh_group });
            }
            Some(group.shared(our_priv, &ke.data)?)
        }
        (None, _, _) => None,
        _ => return Err(IkeError::MissingPayload("KE")),
    };

    let child = match &pfs_secret {
        Some(secret) => ChildSa::derive_with_cipher_pfs(sa.suite.prf_algorithm(), cipher, secret, &sa.keys.sk_d, ni, &nr, Role::Initiator, new_spi, peer_spi),
        None => ChildSa::derive_with_cipher(sa.suite.prf_algorithm(), cipher, &sa.keys.sk_d, ni, &nr, Role::Initiator, new_spi, peer_spi),
    };
    Ok((child, tsr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::esp::next_header;
    use crate::ikev2::exchange::{default_offer, initiator_complete, initiator_request, responder_respond, LocalSecret};
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
    fn child_rekey_yields_matching_esp_sas() {
        let (init_sa, resp_sa) = sa_pair();
        let ni = [0x33u8; 32];
        let nr = [0x44u8; 32];
        let init_new_spi = 0x1111_1111;
        let resp_new_spi = 0x2222_2222;

        let old_child_spi = 0xDEAD_BEEF;
        let req = build_rekey_request(&init_sa, 2, old_child_spi, init_new_spi, &ni, &[1u8; 8]).unwrap();
        let (resp, mut resp_child) =
            responder_process_rekey(&resp_sa, &req, resp_new_spi, &nr, &[2u8; 8], None).unwrap();
        let mut init_child = initiator_complete_rekey(&init_sa, &ni, init_new_spi, &resp).unwrap();

        // The rekeyed SAs interoperate: initiator seals, responder opens, and back.
        let pkt = init_child.outbound.seal(b"after rekey A->B", next_header::IPV4).unwrap();
        assert_eq!(resp_child.inbound.open(&pkt).unwrap().0, b"after rekey A->B");
        let pkt2 = resp_child.outbound.seal(b"after rekey B->A", next_header::IPV4).unwrap();
        assert_eq!(init_child.inbound.open(&pkt2).unwrap().0, b"after rekey B->A");
    }

    #[test]
    fn child_rekey_with_pfs_yields_matching_esp_sas() {
        let (init_sa, resp_sa) = sa_pair();
        let ni = [0x33u8; 32];
        let nr = [0x44u8; 32];
        let init_new_spi = 0x1111_1111;
        let resp_new_spi = 0x2222_2222;
        let old_child_spi = 0xDEAD_BEEF;
        let group = DhGroup::Modp2048;
        let init_dh = [5u8; 32];
        let resp_dh = [6u8; 32];

        let req = build_rekey_request_with_pfs(&init_sa, 2, old_child_spi, init_new_spi, &ni, SkCipher::Aes256Gcm, Some((group, &init_dh)), &[1u8; 8]).unwrap();
        let (resp, mut resp_child) =
            responder_process_rekey_with_pfs(&resp_sa, &req, resp_new_spi, &nr, SkCipher::Aes256Gcm, Some(&resp_dh), &[2u8; 8], None).unwrap();
        let mut init_child = initiator_complete_rekey_with_pfs(&init_sa, &ni, init_new_spi, SkCipher::Aes256Gcm, Some(&init_dh), &resp).unwrap();

        let pkt = init_child.outbound.seal(b"pfs A->B", next_header::IPV4).unwrap();
        assert_eq!(resp_child.inbound.open(&pkt).unwrap().0, b"pfs A->B");
        let pkt2 = resp_child.outbound.seal(b"pfs B->A", next_header::IPV4).unwrap();
        assert_eq!(init_child.inbound.open(&pkt2).unwrap().0, b"pfs B->A");
    }

    /// The actual PFS property: two rekeys sharing the exact same nonces
    /// still derive different keys, because each one runs a fresh DH
    /// exchange -- without PFS (see `child_rekey_yields_matching_esp_sas`,
    /// which reuses the same nonces across this test's two runs implicitly
    /// via identical `Ni`/`Nr` in spirit) the keys would depend on the nonces
    /// alone and could collide if a peer ever reused a nonce; with PFS the
    /// fresh secret dominates regardless.
    #[test]
    fn pfs_rekey_derives_a_different_key_each_time_even_with_identical_nonces() {
        let (init_sa, resp_sa) = sa_pair();
        let ni = [0x33u8; 32];
        let nr = [0x44u8; 32];
        let group = DhGroup::Modp2048;

        let req1 = build_rekey_request_with_pfs(&init_sa, 2, 0xDEAD_BEEF, 0x1111_1111, &ni, SkCipher::Aes256Gcm, Some((group, &[5u8; 32])), &[1u8; 8]).unwrap();
        let (resp1, _) = responder_process_rekey_with_pfs(&resp_sa, &req1, 0x2222_2222, &nr, SkCipher::Aes256Gcm, Some(&[6u8; 32]), &[2u8; 8], None).unwrap();
        let child1 = initiator_complete_rekey_with_pfs(&init_sa, &ni, 0x1111_1111, SkCipher::Aes256Gcm, Some(&[5u8; 32]), &resp1).unwrap();

        let req2 = build_rekey_request_with_pfs(&init_sa, 4, 0x1111_1111, 0x3333_3333, &ni, SkCipher::Aes256Gcm, Some((group, &[7u8; 32])), &[3u8; 8]).unwrap();
        let (resp2, _) = responder_process_rekey_with_pfs(&resp_sa, &req2, 0x4444_4444, &nr, SkCipher::Aes256Gcm, Some(&[8u8; 32]), &[4u8; 8], None).unwrap();
        let child2 = initiator_complete_rekey_with_pfs(&init_sa, &ni, 0x3333_3333, SkCipher::Aes256Gcm, Some(&[7u8; 32]), &resp2).unwrap();

        assert_ne!(child1.outbound.key_material(), child2.outbound.key_material(), "a fresh DH exchange must yield a fresh key even with identical nonces");
    }

    #[test]
    fn pfs_rekey_without_a_matching_dh_private_is_a_clear_error() {
        let (init_sa, resp_sa) = sa_pair();
        let ni = [0x33u8; 32];
        let nr = [0x44u8; 32];
        let group = DhGroup::Modp2048;

        // Initiator asks for PFS, but the responder wasn't given a private
        // key to answer it with.
        let req = build_rekey_request_with_pfs(&init_sa, 2, 0xDEAD_BEEF, 0x1111_1111, &ni, SkCipher::Aes256Gcm, Some((group, &[5u8; 32])), &[1u8; 8]).unwrap();
        assert!(responder_process_rekey_with_pfs(&resp_sa, &req, 0x2222_2222, &nr, SkCipher::Aes256Gcm, None, &[2u8; 8], None).is_err());
    }

    /// Regression: a rekey must preserve the tunnel's already-negotiated
    /// cipher, not silently switch to the fixed AES-256-GCM default that
    /// [`ChildSa::derive`]/[`esp_offer`] alone would imply -- a profile
    /// configured for e.g. AES-CBC-256/SHA-512 (a compliance-driven gateway)
    /// must still be AES-CBC-256/SHA-512 after a PFS rekey.
    #[test]
    fn rekey_preserves_a_non_default_negotiated_cipher() {
        let (init_sa, resp_sa) = sa_pair();
        let ni = [0x33u8; 32];
        let nr = [0x44u8; 32];
        let cipher = SkCipher::Aes256Cbc(crate::crypto::IntegAlgorithm::HmacSha2_512_256);

        let req = build_rekey_request_with_pfs(&init_sa, 2, 0xDEAD_BEEF, 0x1111_1111, &ni, cipher, None, &[1u8; 8]).unwrap();
        let (resp, mut resp_child) =
            responder_process_rekey_with_pfs(&resp_sa, &req, 0x2222_2222, &nr, cipher, None, &[2u8; 8], None).unwrap();
        let mut init_child = initiator_complete_rekey_with_pfs(&init_sa, &ni, 0x1111_1111, cipher, None, &resp).unwrap();

        assert_eq!(init_child.outbound.cipher(), cipher);
        assert_eq!(resp_child.inbound.cipher(), cipher);
        let pkt = init_child.outbound.seal(b"cbc after rekey", next_header::IPV4).unwrap();
        assert_eq!(resp_child.inbound.open(&pkt).unwrap().0, b"cbc after rekey");
    }

    /// The (REKEY_SA notify present?, TSi, TSr) a responder sees in a
    /// CREATE_CHILD_SA request.
    fn inspect_child_request(req: &[u8], resp_sa: &CompletedSaInit) -> (bool, TrafficSelectors, TrafficSelectors) {
        let (first, dec) = open_encrypted_gcm(req, peer_sk_e(resp_sa)).unwrap();
        let (mut rekey_sa, mut tsi, mut tsr) = (false, None, None);
        for p in payloads(first, &dec) {
            let p = p.unwrap();
            match p.payload_type {
                PayloadType::Notify => {
                    rekey_sa |= Notify::parse(p.data).unwrap().notify_type == notify_type::REKEY_SA;
                }
                PayloadType::TrafficSelectorInitiator => tsi = Some(TrafficSelectors::parse(p.data).unwrap()),
                PayloadType::TrafficSelectorResponder => tsr = Some(TrafficSelectors::parse(p.data).unwrap()),
                _ => {}
            }
        }
        (rekey_sa, tsi.unwrap(), tsr.unwrap())
    }

    /// A brand-new CHILD SA (the IPv6 one, next to the IPv4 one IKE_AUTH made)
    /// is a CREATE_CHILD_SA *without* REKEY_SA, proposing exactly the
    /// selectors it is given -- and a rekey still carries the notify.
    #[test]
    fn new_child_request_has_no_rekey_notify_and_carries_the_given_selectors() {
        let (init_sa, resp_sa) = sa_pair();
        let v6 = TrafficSelectors::ipv6_full_tunnel();
        let new_child =
            build_child_request(&init_sa, 2, None, 0x1111_1111, &[0x33u8; 32], SkCipher::Aes256Gcm, None, &v6, &[1u8; 8]).unwrap();
        assert_eq!(inspect_child_request(&new_child, &resp_sa), (false, v6.clone(), v6.clone()));

        let rekey = build_child_request(&init_sa, 2, Some(0xDEAD_BEEF), 0x1111_1111, &[0x33u8; 32], SkCipher::Aes256Gcm, None, &v6, &[1u8; 8]).unwrap();
        assert_eq!(inspect_child_request(&rekey, &resp_sa), (true, v6.clone(), v6));

        // The IPv4 rekey wrapper keeps proposing IPv4 only.
        let v4_rekey = build_rekey_request(&init_sa, 2, 0xDEAD_BEEF, 0x1111_1111, &[0x33u8; 32], &[1u8; 8]).unwrap();
        let v4 = TrafficSelectors { selectors: vec![TrafficSelector::ipv4_any()] };
        assert_eq!(inspect_child_request(&v4_rekey, &resp_sa), (true, v4.clone(), v4));
    }

    #[test]
    fn new_ipv6_child_yields_matching_esp_sas_and_reports_the_granted_tsr() {
        let (init_sa, resp_sa) = sa_pair();
        let v6 = TrafficSelectors::ipv6_full_tunnel();
        let req = build_child_request(&init_sa, 2, None, 0x1111_1111, &[0x33u8; 32], SkCipher::Aes256Gcm, None, &v6, &[1u8; 8]).unwrap();
        // With no assignment the responder echoes the initiator's selectors.
        let (resp, mut resp_child) = responder_process_rekey(&resp_sa, &req, 0x2222_2222, &[0x44u8; 32], &[2u8; 8], None).unwrap();
        let (mut init_child, granted) =
            initiator_complete_child(&init_sa, &[0x33u8; 32], 0x1111_1111, SkCipher::Aes256Gcm, None, &resp).unwrap();
        assert_eq!(granted, Some(v6));

        let pkt = init_child.outbound.seal(b"v6 child A->B", next_header::IPV6).unwrap();
        assert_eq!(resp_child.inbound.open(&pkt).unwrap().0, b"v6 child A->B");
    }

    /// A gateway with no IPv6 Phase 2 answers the CHILD SA request with an
    /// error notify alone -- that must read as a rejection, not as a
    /// missing-SA-payload parse error.
    #[test]
    fn child_reply_with_an_error_notify_is_peer_rejected() {
        let (init_sa, resp_sa) = sa_pair();
        let inner = vec![(
            PayloadType::Notify,
            Notify { protocol_id: 0, spi: Vec::new(), notify_type: notify_type::TS_UNACCEPTABLE, data: Vec::new() }.to_bytes(),
        )];
        let reply = build_encrypted_gcm(
            create_child_header(&resp_sa, 2, true),
            first_payload_type(&inner),
            &encode_payload_chain(&inner),
            our_sk_e(&resp_sa),
            &[2u8; 8],
        )
        .unwrap();
        let err = initiator_complete_child(&init_sa, &[0x33u8; 32], 0x1111_1111, SkCipher::Aes256Gcm, None, &reply).err().unwrap();
        assert!(
            matches!(err, IkeError::PeerRejected { notify_type: notify_type::TS_UNACCEPTABLE, .. }),
            "expected PeerRejected(TS_UNACCEPTABLE), got {err:?}"
        );
    }

    fn extract_tsi(resp: &[u8], init_sa: &CompletedSaInit) -> Vec<u8> {
        let (first, dec) = open_encrypted_gcm(resp, peer_sk_e(init_sa)).unwrap();
        for p in payloads(first, &dec) {
            let p = p.unwrap();
            if p.payload_type == PayloadType::TrafficSelectorInitiator {
                return p.data.to_vec();
            }
        }
        panic!("no TSi in the rekey response");
    }

    /// Regression (the production iOS drop): a native client narrows TSi to its
    /// assigned `/32` at IKE_AUTH, then re-proposes a *wide* `0.0.0.0/0` at rekey and
    /// expects the responder to re-narrow — exactly as AUTH did. The responder must
    /// re-narrow TSi to the assigned `/32`; echoing the wide selector back makes iOS
    /// delete the whole IKE SA ~1s later. With no assignment it falls back to echoing.
    #[test]
    fn responder_renarrows_tsi_to_assigned_at_rekey() {
        use std::net::Ipv4Addr;
        let (init_sa, resp_sa) = sa_pair();
        let assigned = Ipv4Addr::new(10, 8, 0, 7);
        let narrow =
            TrafficSelectors { selectors: vec![TrafficSelector::ipv4_host(assigned)] }.to_bytes();
        let wide_tsi = full_tunnel_ts();
        assert_ne!(narrow, wide_tsi, "the narrowed /32 must differ from full-tunnel");

        // The initiator (iOS at rekey) proposes a WIDE TSi.
        let inner = vec![
            (
                PayloadType::Notify,
                Notify {
                    protocol_id: protocol_id::ESP,
                    spi: 0xDEAD_BEEFu32.to_be_bytes().to_vec(),
                    notify_type: notify_type::REKEY_SA,
                    data: Vec::new(),
                }
                .to_bytes(),
            ),
            (PayloadType::SecurityAssociation, esp_offer_for_cipher(0xAAAA_AAAA, SkCipher::Aes256Gcm).to_bytes()),
            (PayloadType::Nonce, vec![0x55u8; 32]),
            (PayloadType::TrafficSelectorInitiator, wide_tsi.clone()),
            (PayloadType::TrafficSelectorResponder, full_tunnel_ts()),
        ];
        let header = create_child_header(&init_sa, 2, false);
        let req = build_encrypted_gcm(
            header,
            first_payload_type(&inner),
            &encode_payload_chain(&inner),
            our_sk_e(&init_sa),
            &[1u8; 8],
        )
        .unwrap();

        // With an assignment: TSi comes back as the /32, NOT the wide proposal.
        let (resp, _child) =
            responder_process_rekey(&resp_sa, &req, 0xBBBB_BBBB, &[0x66u8; 32], &[2u8; 8], Some(assigned))
                .unwrap();
        assert_eq!(
            extract_tsi(&resp, &init_sa),
            narrow,
            "responder must re-narrow TSi to the assigned /32 at rekey"
        );

        // With no assignment (local egress): the initiator's TSi is echoed verbatim.
        let (resp_echo, _c) =
            responder_process_rekey(&resp_sa, &req, 0xCCCC_CCCC, &[0x77u8; 32], &[3u8; 8], None).unwrap();
        assert_eq!(
            extract_tsi(&resp_echo, &init_sa),
            wide_tsi,
            "with no assignment the responder echoes the initiator's TSi"
        );
    }
}
