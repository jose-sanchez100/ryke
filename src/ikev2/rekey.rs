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
use crate::debug::ike_debug;
use crate::error::IkeError;
use crate::esp::ChildSa;
use crate::ikev2::exchange::CompletedSaInit;
use crate::ikev2::ike_auth::esp_offer_for_cipher;
use crate::ikev2::negotiate;
use crate::ikev2::message::{
    encode_payload_chain, first_payload_type, payloads, ExchangeType, Flags, IkeHeader, PayloadType,
};
use crate::ikev2::payload::{
    notify_type, protocol_id, transform_type, KeyExchange, Notify, Proposal, SecurityAssociation, Transform, TrafficSelector,
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
    build_child_error(sa, message_id, notify_type::NO_ADDITIONAL_SAS, iv)
}

/// [`build_child_refusal`] with a reason of the caller's choosing -- a peer's
/// rekey this side *would* take on but can't (`NO_PROPOSAL_CHOSEN`,
/// `CHILD_SA_NOT_FOUND`, ...), still answered as a `CREATE_CHILD_SA`.
pub fn build_child_error(sa: &CompletedSaInit, message_id: u32, error: u16, iv: &[u8; 8]) -> Result<Vec<u8>, IkeError> {
    let inner = vec![(PayloadType::Notify, Notify::status(error, Vec::new()).to_bytes())];
    let header = create_child_header(sa, message_id, true);
    let first = first_payload_type(&inner);
    let bytes = encode_payload_chain(&inner);
    build_encrypted(sa.suite.sk_cipher(), header, first, &bytes, our_sk_e(sa), our_sk_a(sa), iv)
}

/// The SPI a CHILD SA rekey request names in its `REKEY_SA` notify -- what a
/// responder looks the old SA up by: the SPI the *sender* expects on inbound
/// ESP (RFC 7296 §1.3.3), so for the receiver the SA's outbound SPI. `None`
/// when the request carries no such notify (a brand-new CHILD SA) or can't be opened.
pub fn rekey_sa_spi(sa: &CompletedSaInit, request: &[u8]) -> Option<u32> {
    let (first, inner) = open_encrypted(sa.suite.sk_cipher(), request, peer_sk_e(sa), peer_sk_a(sa)).ok()?;
    payloads(first, &inner)
        .filter_map(Result::ok)
        .filter(|p| p.payload_type == PayloadType::Notify)
        .filter_map(|p| Notify::parse(p.data).ok())
        .find(|n| n.notify_type == notify_type::REKEY_SA)
        .and_then(|n| <[u8; 4]>::try_from(n.spi).ok())
        .map(u32::from_be_bytes)
}

/// The Nonce payload of a `CREATE_CHILD_SA` message the *peer* sent -- its
/// `Ni` in a request, its `Nr` in a response. Two nodes that rekeyed the same
/// CHILD SA at once settle which new SA survives by comparing the four nonces
/// of the two exchanges (RFC 7296 §2.8.1), and likewise for the IKE SA
/// (§2.8.2). `None` when the message can't be opened or carries no Nonce.
pub fn peer_child_nonce(sa: &CompletedSaInit, msg: &[u8]) -> Option<Vec<u8>> {
    let (first, inner) = open_encrypted(sa.suite.sk_cipher(), msg, peer_sk_e(sa), peer_sk_a(sa)).ok()?;
    payloads(first, &inner).filter_map(Result::ok).find(|p| p.payload_type == PayloadType::Nonce).map(|p| p.data.to_vec())
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

/// Pick the proposal to answer a CHILD SA rekey the peer started with (RFC 7296
/// §2.7): the first one that offers the algorithms of the SA being rekeyed --
/// a rekey keeps the running `cipher` -- and, when the request carries a KE
/// payload (`ke_group`), that KE's DH group among its alternatives, or no
/// mandatory DH when it doesn't (a proposal with no DH transform at all takes
/// either, and is then answered without PFS). Returns the proposal to send back (the
/// chosen one's number, our `new_spi`, one transform per type), the peer's
/// SPI from it, and the DH group PFS runs on, if any.
fn choose_child_proposal(
    peer_sa: &SecurityAssociation,
    cipher: SkCipher,
    new_spi: u32,
    ke_group: Option<u16>,
) -> Result<(Proposal, u32, Option<DhGroup>), IkeError> {
    let ours = esp_offer_for_cipher(new_spi, cipher).proposals.remove(0);
    for p in &peer_sa.proposals {
        if p.protocol_id != protocol_id::ESP || p.spi.len() != 4 {
            continue;
        }
        let of_type = |ty: u8| p.transforms.iter().filter(move |t| t.transform_type == ty);
        // Everything we'd use has to be among what it offers -- but a proposal
        // that leaves ESN out altogether is taken as "no ESN".
        let offers_all = ours.transforms.iter().all(|t| {
            (t.transform_type == transform_type::ESN && of_type(transform_type::ESN).next().is_none())
                || of_type(t.transform_type).any(|o| o.transform_id == t.transform_id && o.key_length == t.key_length)
        });
        // An AEAD cipher takes no integrity algorithm: a proposal that insists on one is another algorithm.
        let integ_forced = !ours.transforms.iter().any(|t| t.transform_type == transform_type::INTEG)
            && of_type(transform_type::INTEG).next().is_some()
            && !of_type(transform_type::INTEG).any(|t| t.transform_id == 0);
        if !offers_all || integ_forced {
            continue;
        }
        let dh_offered: Vec<u16> = of_type(transform_type::DH).map(|t| t.transform_id).collect();
        let group = match ke_group {
            Some(g) if dh_offered.contains(&g) => match DhGroup::from_transform_id(g) {
                Some(group) => Some(group),
                None => continue,
            },
            // A proposal with no DH of its own answers a rekey without PFS: the KE is
            // there for the proposals that do list its group (strongSwan sends
            // both kinds side by side, so a peer that can't do PFS still fits).
            _ if dh_offered.is_empty() || dh_offered.contains(&0) => None,
            _ => continue,
        };
        let mut reply = ours.clone();
        reply.num = p.num;
        if let Some(group) = group {
            reply.transforms.push(Transform { transform_type: transform_type::DH, transform_id: group.transform_id(), key_length: None });
        }
        let peer_spi = u32::from_be_bytes(p.spi[..4].try_into().unwrap());
        return Ok((reply, peer_spi, group));
    }
    ike_debug!(
        "CREATE_CHILD_SA: none of the peer's ESP proposals fits the running cipher {cipher:?} (KE group {ke_group:?}); offered: {:?}",
        peer_sa.proposals
    );
    Err(IkeError::NoProposalChosen)
}

/// Responder side of a CHILD SA rekey the *peer* started (RFC 7296 §1.3.3): a
/// `CREATE_CHILD_SA` request `SK { N(REKEY_SA), SA, Ni, [KEi,] TSi, TSr }`.
/// Selects a proposal ([`choose_child_proposal`] -- the peer may offer several
/// and, for PFS, name a DH group), derives the new CHILD SA from the peer's
/// nonce, ours (`nr`) and, with PFS, a fresh DH secret from `dh_private` (only
/// used when the request carries a KE payload), and builds the response, which
/// accepts the traffic selectors exactly as the peer proposed them: that is
/// what its SA being replaced already carries. `new_spi` is the inbound SPI we
/// choose for the new SA; `cipher` the one running on the SA being rekeyed.
///
/// Which SA is being rekeyed is the caller's to check first ([`rekey_sa_spi`]):
/// this only builds the new one. Returns `(response_bytes, ChildSa)`.
pub fn responder_answer_child_rekey(
    sa: &CompletedSaInit,
    request: &[u8],
    new_spi: u32,
    nr: &[u8],
    cipher: SkCipher,
    dh_private: &[u8],
    iv: &[u8; 8],
) -> Result<(Vec<u8>, ChildSa), IkeError> {
    let message_id = IkeHeader::parse(request)?.message_id;
    let (first, inner) = open_encrypted(sa.suite.sk_cipher(), request, peer_sk_e(sa), peer_sk_a(sa))?;
    let (sa_bytes, ni) = find_sa_and_nonce(first, &inner)?;
    let peer_sa = SecurityAssociation::parse(&sa_bytes)?;
    let peer_ke = find_ke(first, &inner)?;
    let (mut tsi, mut tsr) = (None, None);
    for payload in payloads(first, &inner) {
        let p = payload?;
        match p.payload_type {
            PayloadType::TrafficSelectorInitiator => tsi = Some(p.data.to_vec()),
            PayloadType::TrafficSelectorResponder => tsr = Some(p.data.to_vec()),
            _ => {}
        }
    }
    let tsi = tsi.ok_or(IkeError::MissingPayload("TSi"))?;
    let tsr = tsr.ok_or(IkeError::MissingPayload("TSr"))?;

    let (proposal, peer_spi, group) = choose_child_proposal(&peer_sa, cipher, new_spi, peer_ke.as_ref().map(|k| k.dh_group))?;
    let prf = sa.suite.prf_algorithm();
    let (child, ke_out) = match (group, &peer_ke) {
        (Some(group), Some(ke)) => {
            let secret = group.shared(dh_private, &ke.data)?;
            let child = ChildSa::derive_with_cipher_pfs(prf, cipher, &secret, &sa.keys.sk_d, &ni, nr, Role::Responder, new_spi, peer_spi);
            (child, Some(KeyExchange { dh_group: group.transform_id(), data: group.public(dh_private) }))
        }
        _ => (ChildSa::derive_with_cipher(prf, cipher, &sa.keys.sk_d, &ni, nr, Role::Responder, new_spi, peer_spi), None),
    };

    let mut inner_out = vec![
        (PayloadType::SecurityAssociation, SecurityAssociation { proposals: vec![proposal] }.to_bytes()),
        (PayloadType::Nonce, nr.to_vec()),
    ];
    if let Some(ke) = ke_out {
        inner_out.push((PayloadType::KeyExchange, ke.to_bytes()));
    }
    inner_out.push((PayloadType::TrafficSelectorInitiator, tsi));
    inner_out.push((PayloadType::TrafficSelectorResponder, tsr));
    let header = create_child_header(sa, message_id, true);
    let first_out = first_payload_type(&inner_out);
    let bytes = encode_payload_chain(&inner_out);
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

    // RFC 7296 §2.7: the response's ESP proposal must be built from the offer
    // we actually sent (`esp_offer_for_cipher(_, cipher)` -- `build_child_request`/
    // `build_rekey_request_with_pfs` never send anything else), not merely a
    // combination `select_esp` can decode. Without this, a peer could answer
    // a rekey/new-CHILD-SA request with a different cipher (or turn ESN on)
    // and we'd derive keys for `cipher` while the peer runs something else,
    // or silently disagree about the sequence-number space.
    let peer_esp_suite = negotiate::select_esp(&peer_sa).ok_or(IkeError::NoProposalChosen)?;
    if !peer_esp_suite.matches_offer(&esp_offer_for_cipher(0, cipher)) {
        return Err(IkeError::NoProposalChosen);
    }

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
    use crate::crypto::IntegAlgorithm;
    use crate::esp::next_header;
    use crate::ikev2::payload::transform_id;
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

    /// An ESP proposal as a peer would offer it: `encr`, an optional integrity
    /// algorithm, the DH alternatives (PFS) and ESN off.
    fn esp_proposal(num: u8, spi: u32, encr: (u16, Option<u16>), integ: Option<u16>, dh: &[u16]) -> Proposal {
        let mut transforms = vec![Transform { transform_type: transform_type::ENCR, transform_id: encr.0, key_length: encr.1 }];
        transforms.extend(integ.map(|id| Transform { transform_type: transform_type::INTEG, transform_id: id, key_length: None }));
        transforms.extend(dh.iter().map(|&id| Transform { transform_type: transform_type::DH, transform_id: id, key_length: None }));
        transforms.push(Transform { transform_type: transform_type::ESN, transform_id: transform_id::ESN_NONE, key_length: None });
        Proposal { num, protocol_id: protocol_id::ESP, spi: spi.to_be_bytes().to_vec(), transforms }
    }

    /// A peer's CHILD SA rekey request naming `rekeyed_spi`, offering `proposals`
    /// (with a KE for `ke` when given).
    fn peer_rekey_request(
        peer_sa: &CompletedSaInit,
        proposals: Vec<Proposal>,
        ke: Option<(DhGroup, &[u8])>,
        ts: &TrafficSelectors,
    ) -> Vec<u8> {
        let notify = Notify {
            protocol_id: protocol_id::ESP,
            spi: 0xAAAA_AAAAu32.to_be_bytes().to_vec(),
            notify_type: notify_type::REKEY_SA,
            data: Vec::new(),
        };
        let mut inner = vec![
            (PayloadType::Notify, notify.to_bytes()),
            (PayloadType::SecurityAssociation, SecurityAssociation { proposals }.to_bytes()),
            (PayloadType::Nonce, vec![0x33; 32]),
        ];
        if let Some((group, private)) = ke {
            inner.push((PayloadType::KeyExchange, KeyExchange { dh_group: group.transform_id(), data: group.public(private) }.to_bytes()));
        }
        inner.push((PayloadType::TrafficSelectorInitiator, ts.to_bytes()));
        inner.push((PayloadType::TrafficSelectorResponder, ts.to_bytes()));
        let first = first_payload_type(&inner);
        build_encrypted(
            peer_sa.suite.sk_cipher(),
            create_child_header(peer_sa, 7, false),
            first,
            &encode_payload_chain(&inner),
            our_sk_e(peer_sa),
            our_sk_a(peer_sa),
            &[1u8; 8],
        )
        .unwrap()
    }

    /// The `(proposal, spi, TSi, TSr)` of a rekey response a peer gets back.
    fn read_rekey_response(response: &[u8], peer_sa: &CompletedSaInit) -> (Proposal, TrafficSelectors, TrafficSelectors, bool) {
        let (first, inner) = open_encrypted(peer_sa.suite.sk_cipher(), response, peer_sk_e(peer_sa), peer_sk_a(peer_sa)).unwrap();
        let (mut proposal, mut tsi, mut tsr, mut ke) = (None, None, None, false);
        for p in payloads(first, &inner) {
            let p = p.unwrap();
            match p.payload_type {
                PayloadType::SecurityAssociation => proposal = SecurityAssociation::parse(p.data).unwrap().proposals.into_iter().next(),
                PayloadType::TrafficSelectorInitiator => tsi = Some(TrafficSelectors::parse(p.data).unwrap()),
                PayloadType::TrafficSelectorResponder => tsr = Some(TrafficSelectors::parse(p.data).unwrap()),
                PayloadType::KeyExchange => ke = true,
                _ => {}
            }
        }
        (proposal.unwrap(), tsi.unwrap(), tsr.unwrap(), ke)
    }

    /// The peer (a gateway whose own lifetime timer fired) rekeys, this side
    /// answers, and the two end up with SAs that interoperate -- with and
    /// without PFS.
    #[test]
    fn a_peer_started_child_rekey_is_answered_and_both_sides_derive_the_same_keys() {
        for pfs in [None, Some(DhGroup::Modp2048)] {
            let (our_sa, peer_sa) = sa_pair(); // `our_sa` answers, `peer_sa` asks
            let peer_dh = [5u8; 32];
            let mut offer = esp_offer_for_cipher(0x2222_2222, SkCipher::Aes256Gcm).proposals.remove(0);
            if let Some(group) = pfs {
                offer.transforms.push(Transform { transform_type: transform_type::DH, transform_id: group.transform_id(), key_length: None });
            }
            let ts = TrafficSelectors::ipv4_full_tunnel();
            let req = peer_rekey_request(&peer_sa, vec![offer], pfs.map(|g| (g, &peer_dh[..])), &ts);

            let (resp, mut our_child) =
                responder_answer_child_rekey(&our_sa, &req, 0x1111_1111, &[0x44u8; 32], SkCipher::Aes256Gcm, &[6u8; 32], &[2u8; 8]).unwrap();
            let (mut peer_child, granted) =
                initiator_complete_child(&peer_sa, &[0x33u8; 32], 0x2222_2222, SkCipher::Aes256Gcm, pfs.map(|_| &peer_dh[..]), &resp).unwrap();
            assert_eq!(granted, Some(ts), "the peer's selectors are accepted as proposed");

            let pkt = peer_child.outbound.seal(b"peer -> us", next_header::IPV4).unwrap();
            assert_eq!(our_child.inbound.open(&pkt).unwrap().0, b"peer -> us");
            let pkt = our_child.outbound.seal(b"us -> peer", next_header::IPV4).unwrap();
            assert_eq!(peer_child.inbound.open(&pkt).unwrap().0, b"us -> peer");
            assert_eq!((our_child.inbound.spi(), our_child.outbound.spi()), (0x1111_1111, 0x2222_2222));
        }
    }

    /// A gateway offers every proposal it has configured, best first, and PFS
    /// as a DH transform on each: the answer takes the first one that fits the
    /// running cipher and the KE the peer sent, and echoes *its* number.
    #[test]
    fn the_answer_picks_the_offered_proposal_matching_the_running_cipher_and_the_ke_group() {
        let (our_sa, peer_sa) = sa_pair();
        let peer_dh = [5u8; 32];
        let gcm256 = (transform_id::AES_GCM_16, Some(256));
        let offers = vec![
            // Another cipher, another integrity algorithm, and a DH group we weren't sent a KE for.
            esp_proposal(1, 0x2222_2222, (transform_id::AES_CBC, Some(128)), Some(transform_id::AUTH_HMAC_SHA1_96), &[transform_id::MODP_2048]),
            esp_proposal(2, 0x2222_2222, gcm256, None, &[transform_id::ECP256]),
            // The one: GCM-256 with the group of the KE payload among several.
            esp_proposal(3, 0x2222_2222, gcm256, None, &[transform_id::ECP256, transform_id::MODP_2048]),
        ];
        let req = peer_rekey_request(&peer_sa, offers, Some((DhGroup::Modp2048, &peer_dh)), &TrafficSelectors::ipv4_full_tunnel());
        let (resp, _child) =
            responder_answer_child_rekey(&our_sa, &req, 0x1111_1111, &[0x44u8; 32], SkCipher::Aes256Gcm, &[6u8; 32], &[2u8; 8]).unwrap();
        let (proposal, _, _, ke) = read_rekey_response(&resp, &peer_sa);
        assert_eq!(proposal.num, 3);
        assert_eq!(proposal.spi, 0x1111_1111u32.to_be_bytes());
        assert!(ke, "PFS is answered with our KE");
        let ids = |ty| proposal.transforms.iter().filter(|t| t.transform_type == ty).map(|t| t.transform_id).collect::<Vec<_>>();
        assert_eq!(ids(transform_type::ENCR), [transform_id::AES_GCM_16]);
        assert_eq!(ids(transform_type::DH), [transform_id::MODP_2048], "exactly the group of the KE, not the alternatives");
    }

    /// What strongSwan actually sends (dumped off a live gateway): a KE for its
    /// first DH group, and proposals of every configured cipher -- those with
    /// PFS carry the group, the AEAD ones (no PFS configured for them) carry
    /// none. A tunnel running GCM-256 takes the DH-less GCM proposal and answers
    /// without a KE: no PFS, but the SA is replaced and the peer's keys match.
    #[test]
    fn a_peer_started_rekey_takes_a_dhless_proposal_next_to_a_ke_it_cannot_use() {
        let (our_sa, peer_sa) = sa_pair();
        let peer_dh = [5u8; 32];
        let (cbc, gcm) = ((transform_id::AES_CBC, Some(256)), (transform_id::AES_GCM_16, Some(256)));
        let sha256 = Some(transform_id::AUTH_HMAC_SHA2_256_128);
        let offers = vec![
            esp_proposal(1, 0x2222_2222, cbc, sha256, &[transform_id::MODP_2048]),
            esp_proposal(2, 0x2222_2222, cbc, sha256, &[]),
            esp_proposal(3, 0x2222_2222, gcm, None, &[]),
            esp_proposal(4, 0x2222_2222, (transform_id::AES_GCM_16, Some(128)), None, &[]),
            esp_proposal(5, 0x2222_2222, cbc, sha256, &[transform_id::ECP256]),
        ];
        let req = peer_rekey_request(&peer_sa, offers, Some((DhGroup::Modp2048, &peer_dh)), &TrafficSelectors::ipv4_full_tunnel());
        let (resp, mut our_child) =
            responder_answer_child_rekey(&our_sa, &req, 0x1111_1111, &[0x44u8; 32], SkCipher::Aes256Gcm, &[6u8; 32], &[2u8; 8]).unwrap();
        let (proposal, _, _, ke) = read_rekey_response(&resp, &peer_sa);
        assert_eq!(proposal.num, 3);
        assert!(!ke, "the chosen proposal has no DH, so no KE in the answer");
        assert!(proposal.transforms.iter().all(|t| t.transform_type != transform_type::DH));

        let (mut peer_child, _) =
            initiator_complete_child(&peer_sa, &[0x33u8; 32], 0x2222_2222, SkCipher::Aes256Gcm, None, &resp).unwrap();
        let pkt = peer_child.outbound.seal(b"peer -> us", next_header::IPV4).unwrap();
        assert_eq!(our_child.inbound.open(&pkt).unwrap().0, b"peer -> us");
    }

    /// A rekey of a tunnel running AES-CBC/SHA-256 keeps that pair, even when the
    /// peer lists a stronger-looking one first.
    #[test]
    fn a_peer_started_rekey_keeps_the_running_cipher() {
        let (our_sa, peer_sa) = sa_pair();
        let cbc = SkCipher::Aes256Cbc(IntegAlgorithm::HmacSha2_256_128);
        let offers = vec![
            esp_proposal(1, 0x2222_2222, (transform_id::AES_GCM_16, Some(256)), None, &[]),
            esp_proposal(2, 0x2222_2222, (transform_id::AES_CBC, Some(256)), Some(transform_id::AUTH_HMAC_SHA2_256_128), &[]),
        ];
        let req = peer_rekey_request(&peer_sa, offers, None, &TrafficSelectors::ipv4_full_tunnel());
        let (resp, child) = responder_answer_child_rekey(&our_sa, &req, 0x1111_1111, &[0x44u8; 32], cbc, &[6u8; 32], &[2u8; 8]).unwrap();
        let (proposal, _, _, ke) = read_rekey_response(&resp, &peer_sa);
        assert_eq!(proposal.num, 2);
        assert!(!ke);
        assert_eq!(child.inbound.cipher(), cbc);
    }

    /// Nothing offered fits (no proposal with our cipher; or PFS asked for with a
    /// KE group no proposal lists): `NoProposalChosen`, not a guess.
    #[test]
    fn a_peer_started_rekey_that_offers_nothing_usable_is_refused() {
        let (our_sa, peer_sa) = sa_pair();
        let ts = TrafficSelectors::ipv4_full_tunnel();
        let peer_dh = [5u8; 32];
        let answer = |req: &[u8]| {
            responder_answer_child_rekey(&our_sa, req, 0x1111_1111, &[0x44u8; 32], SkCipher::Aes256Gcm, &[6u8; 32], &[2u8; 8]).err()
        };
        let other_cipher = esp_proposal(1, 0x2222_2222, (transform_id::AES_CBC, Some(128)), Some(transform_id::AUTH_HMAC_SHA1_96), &[]);
        let req = peer_rekey_request(&peer_sa, vec![other_cipher], None, &ts);
        assert!(matches!(answer(&req), Some(IkeError::NoProposalChosen)));

        let gcm_ecp = esp_proposal(1, 0x2222_2222, (transform_id::AES_GCM_16, Some(256)), None, &[transform_id::ECP256]);
        let req = peer_rekey_request(&peer_sa, vec![gcm_ecp], Some((DhGroup::Modp2048, &peer_dh)), &ts);
        assert!(matches!(answer(&req), Some(IkeError::NoProposalChosen)), "the KE's group isn't among the proposal's");
    }

    /// The `REKEY_SA` notify names the SA the sender expects inbound ESP on.
    #[test]
    fn the_rekeyed_sa_is_read_from_the_request() {
        let (our_sa, peer_sa) = sa_pair();
        let gcm = esp_proposal(1, 0x2222_2222, (transform_id::AES_GCM_16, Some(256)), None, &[]);
        let req = peer_rekey_request(&peer_sa, vec![gcm], None, &TrafficSelectors::ipv4_full_tunnel());
        assert_eq!(rekey_sa_spi(&our_sa, &req), Some(0xAAAA_AAAA));
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

    /// We ask `initiator_complete_child` to complete a rekey running
    /// AES-256-GCM. A response whose SA proposal actually names
    /// AES-CBC-128/HMAC-SHA1-96 -- a combination `select_esp`/`sk::SkCipher`
    /// can decode fine -- must be rejected (RFC 7296 §2.7), not accepted
    /// while we go on deriving keys for the cipher we expected.
    #[test]
    fn initiator_rejects_a_create_child_sa_response_with_an_unoffered_cipher() {
        let (init_sa, resp_sa) = sa_pair();
        let downgrade = esp_offer_for_cipher(0x2222_2222, SkCipher::Aes128Cbc(IntegAlgorithm::HmacSha1_96));
        let ts = TrafficSelectors::ipv4_full_tunnel();
        let inner = vec![
            (PayloadType::SecurityAssociation, downgrade.to_bytes()),
            (PayloadType::Nonce, vec![0x44; 32]),
            (PayloadType::TrafficSelectorInitiator, ts.to_bytes()),
            (PayloadType::TrafficSelectorResponder, ts.to_bytes()),
        ];
        let first = first_payload_type(&inner);
        let resp = build_encrypted(
            resp_sa.suite.sk_cipher(),
            create_child_header(&resp_sa, 2, true),
            first,
            &encode_payload_chain(&inner),
            our_sk_e(&resp_sa),
            our_sk_a(&resp_sa),
            &[2u8; 8],
        )
        .unwrap();

        let err = initiator_complete_child(&init_sa, &[0x33u8; 32], 0x1111_1111, SkCipher::Aes256Gcm, None, &resp).err().unwrap();
        assert_eq!(err, IkeError::NoProposalChosen);
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
