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
use crate::ikev2::ike_auth::{assigned_ipv4_policy, check_granted_ts, esp_offer_for_cipher, narrow_requested_ts};
use crate::ikev2::message::{encode_payload_chain, first_payload_type, payloads, ExchangeType, Flags, IkeHeader, PayloadType};
use crate::ikev2::negotiate;
use crate::ikev2::payload::{
    notify_type, protocol_id, transform_id, transform_type, KeyExchange, Nonce, Notify, Proposal, SecurityAssociation, TrafficSelector, TrafficSelectors, Transform,
};
use crate::ikev2::sk::{build_encrypted, open_encrypted, SkCipher};
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

#[cfg(test)]
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

/// Extract the (SA bytes, Nonce bytes) from a decrypted CREATE_CHILD_SA message
/// of the peer's on `sa`. The nonce must be one RFC 7296 allows under `sa`'s
/// PRF, which derives the new SA's keys from it ([`Nonce::parse_for_prf`]).
fn find_sa_and_nonce(sa: &CompletedSaInit, first: PayloadType, inner: &[u8]) -> Result<(Vec<u8>, Vec<u8>), IkeError> {
    let prf = sa.suite.prf_algorithm();
    let mut sa = None;
    let mut nonce = None;
    for payload in payloads(first, inner) {
        let payload = payload?;
        match payload.payload_type {
            PayloadType::SecurityAssociation => sa = Some(payload.data.to_vec()),
            PayloadType::Nonce => nonce = Some(Nonce::parse_for_prf(payload.data, prf)?.data),
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

/// Every DH transform the first proposal of `sa` names, NONE (0) included.
fn first_proposal_dh_ids(sa: &SecurityAssociation) -> Vec<u16> {
    sa.proposals
        .first()
        .map(|p| p.transforms.iter().filter(|t| t.transform_type == transform_type::DH).map(|t| t.transform_id).collect())
        .unwrap_or_default()
}

/// Whether any proposal of `sa` names the DH group `id` -- whatever the transform
/// that names it carries, a KE payload of a group no proposal lists being a
/// malformed request rather than a proposal to weigh. A DH transform we could
/// not read (an attribute we do not understand, RFC 7296 §3.3.6) may name it
/// too: that transform is unacceptable, and the request is not for that reason
/// malformed -- which would be `INVALID_SYNTAX`, fatal to the IKE SA (§2.21.3),
/// instead of `NO_PROPOSAL_CHOSEN`.
fn proposals_name_dh(sa: &SecurityAssociation, id: u16) -> bool {
    sa.proposals
        .iter()
        .any(|p| p.transforms.iter().any(|t| t.transform_type == transform_type::DH && (t.transform_id == id || t.transform_id == transform_id::UNUSABLE)))
}

/// Our ephemeral share of a PFS exchange: the DH group both sides will use,
/// plus our private key to derive the eventual shared secret from the peer's
/// KE payload.
pub type PfsKeyExchange<'a> = (DhGroup, &'a [u8]);

/// Our side's PFS policy for the CHILD SAs a session creates and rekeys with
/// `CREATE_CHILD_SA`. The DH transform is negotiated like any other (RFC 7296
/// §1.3.1, §3.3.6), so which groups one may settle on -- and whether none at
/// all -- is local policy, read off the local ESP offer
/// ([`Self::from_offer`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PfsPolicy {
    /// The groups a PFS exchange may use, ours to offer first. Empty when the
    /// offer asked for no PFS, which then accepts any group a peer's own
    /// rekey insists on (more than we asked for, never less).
    groups: Vec<DhGroup>,
    /// Whether an exchange without PFS is acceptable too.
    optional: bool,
}

impl PfsPolicy {
    /// No PFS configured: our own requests carry no KE, and a peer's rekey is
    /// answered with or without PFS as it asks.
    pub fn none() -> Self {
        PfsPolicy { groups: Vec::new(), optional: true }
    }

    /// The policy an ESP offer states through the DH transforms of its first
    /// proposal -- the one this crate's CHILD SAs are modelled on. None at
    /// all, or just NONE (0), is [`Self::none`]. Groups make PFS required,
    /// the first being the one our own requests offer, unless NONE is listed
    /// next to them (RFC 7296 §3.3.6: PFS left optional). A group IKEv2 may
    /// not run -- unknown to this crate, or MODP-768 (RFC 8247 §2.4) -- is an
    /// error, not skipped: the offer asked for PFS, and dropping the group
    /// would quietly run the tunnel without it.
    pub fn from_offer(sa: &SecurityAssociation) -> Result<Self, IkeError> {
        let ids = first_proposal_dh_ids(sa);
        let mut groups = Vec::new();
        for &id in ids.iter().filter(|&&id| id != 0) {
            let group = negotiate::ikev2_dh_group(id).ok_or(IkeError::Crypto("the ESP offer names a PFS group IKEv2 cannot run"))?;
            if !groups.contains(&group) {
                groups.push(group);
            }
        }
        let optional = groups.is_empty() || ids.contains(&0);
        Ok(PfsPolicy { groups, optional })
    }

    /// The group our own `CREATE_CHILD_SA` requests offer PFS on, if any.
    pub fn proposed(&self) -> Option<DhGroup> {
        self.groups.first().copied()
    }

    /// Whether a peer's rekey may run PFS on the group `id`.
    fn allows_group(&self, id: u16) -> bool {
        self.groups.is_empty() || self.groups.iter().any(|g| g.transform_id() == id)
    }
}

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

/// The SA payload [`build_child_request`] sends: `esp_offer_for_cipher`'s one
/// proposal, plus the DH group `pfs` when PFS is asked for.
fn child_offer(new_spi: u32, cipher: SkCipher, pfs: Option<DhGroup>) -> SecurityAssociation {
    let mut offer = esp_offer_for_cipher(new_spi, cipher);
    if let Some(group) = pfs {
        offer.proposals[0].transforms.push(Transform { transform_type: transform_type::DH, transform_id: group.transform_id(), key_length: None });
    }
    offer
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
    let offer = child_offer(new_spi, cipher, pfs.map(|(group, _)| group));
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
    build_child_error_with_data(sa, message_id, error, Vec::new(), iv)
}

/// [`build_child_error`] with notification data: `INVALID_KE_PAYLOAD` carries
/// the group the responder wants, two octets big-endian (RFC 7296 §1.3).
pub fn build_child_error_with_data(sa: &CompletedSaInit, message_id: u32, error: u16, data: Vec<u8>, iv: &[u8; 8]) -> Result<Vec<u8>, IkeError> {
    let inner = vec![(PayloadType::Notify, Notify::status(error, data).to_bytes())];
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

/// The SPI the peer chose for the CHILD SA a `CREATE_CHILD_SA` answer
/// creates (its SA payload's), if the answer has one.
pub(crate) fn peer_child_spi(sa: &CompletedSaInit, msg: &[u8]) -> Option<u32> {
    let (first, inner) = open_encrypted(sa.suite.sk_cipher(), msg, peer_sk_e(sa), peer_sk_a(sa)).ok()?;
    let (sa_bytes, _) = find_sa_and_nonce(sa, first, &inner).ok()?;
    esp_spi_from_sa(&sa_bytes).ok()
}

/// The TSi and TSr a message of the peer's creating a CHILD SA carries --
/// a `CREATE_CHILD_SA` or `IKE_AUTH` request or response -- both present and
/// well-formed, or `None`.
pub(crate) fn peer_child_ts(sa: &CompletedSaInit, msg: &[u8]) -> Option<(TrafficSelectors, TrafficSelectors)> {
    let (first, inner) = open_encrypted(sa.suite.sk_cipher(), msg, peer_sk_e(sa), peer_sk_a(sa)).ok()?;
    match requested_ts(first, &inner).ok()? {
        (Some(tsi), Some(tsr)) => Some((tsi, tsr)),
        _ => None,
    }
}

/// The TSi and TSr payloads of a CHILD SA request, each parsed whole
/// (RFC 7296 §3.13) -- a malformed one fails the request -- or `None` when absent.
fn requested_ts(first: PayloadType, inner: &[u8]) -> Result<(Option<TrafficSelectors>, Option<TrafficSelectors>), IkeError> {
    let (mut tsi, mut tsr) = (None, None);
    for payload in payloads(first, inner) {
        let p = payload?;
        match p.payload_type {
            PayloadType::TrafficSelectorInitiator => tsi = Some(TrafficSelectors::parse(p.data)?),
            PayloadType::TrafficSelectorResponder => tsr = Some(TrafficSelectors::parse(p.data)?),
            _ => {}
        }
    }
    Ok((tsi, tsr))
}

/// Responder: process a rekey request, derive the new CHILD SA, and build the
/// response. Returns `(response_bytes, ChildSa)`. The request's TSi and TSr,
/// which it must carry, are answered narrowed (RFC 7296 §2.9): with an
/// `assigned_ip`, TSi to that address and TSr to IPv4, as at `IKE_AUTH`;
/// without one, to what they propose of either family. When either comes to
/// nothing the rekey is refused with `TsUnacceptable`, for the caller to
/// answer `TS_UNACCEPTABLE`.
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

/// Like [`responder_process_rekey`], with PFS: `dh_private` is both our
/// ephemeral private key and our policy. `Some` requires PFS: the request's
/// proposal must list a DH group IKEv2 may run and carry a KE of it, or the
/// rekey is refused (`MissingPayload("KE")` without a KE,
/// `NoProposalChosen` for a group not offered or not known). `None` runs
/// without PFS: a proposal that lists no group, or NONE among its groups
/// (PFS left optional), is answered without one; one that insists on a group
/// is refused with `NoProposalChosen`. This mirrors
/// [`crate::ikev2::ike_rekey::responder_process_ike_rekey`]'s `dh_private`
/// parameter for the IKE-SA-rekey analog. `cipher` is the ESP
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
    let (sa_bytes, ni) = find_sa_and_nonce(sa, first, &inner)?;
    let peer_sa = SecurityAssociation::parse(&sa_bytes)?;
    let peer_ke = find_ke(first, &inner)?;

    // The proposal to answer is one the peer offered (RFC 7296 §2.7, §3.3.6), chosen as the
    // session's responder chooses it: our cipher exactly, and the PFS our policy asks -- a key
    // is PFS on any group IKEv2 may run, none is no PFS, whatever KE the peer sent.
    let (pfs_policy, ke_group) = match dh_private {
        Some(_) => (PfsPolicy { groups: Vec::new(), optional: false }, peer_ke.as_ref().map(|ke| ke.dh_group)),
        None => (PfsPolicy::none(), None),
    };
    if ke_group.is_some_and(|g| !proposals_name_dh(&peer_sa, g)) {
        return Err(IkeError::NoProposalChosen);
    }
    // Refusals only (as this function documents): a group we would take on a KE of another is
    // not INVALID_KE_PAYLOAD's retry here, and one with no KE to run it on is the KE missing.
    let (proposal, peer_spi, pfs_group) = choose_child_proposal(&peer_sa, cipher, new_spi, ke_group, &pfs_policy).map_err(|e| match e {
        IkeError::InvalidKeGroup(_) if dh_private.is_some() && peer_ke.is_none() => IkeError::MissingPayload("KE"),
        IkeError::InvalidKeGroup(_) => IkeError::NoProposalChosen,
        e => e,
    })?;

    // Traffic selectors: mirror exactly what IKE_AUTH did for this client. At AUTH we
    // narrow TSi to the client's assigned /32 and set TSr = full-tunnel; iOS installs
    // that policy. At rekey a native client (iOS) may re-propose a *wide* 0.0.0.0/0
    // TSi and expect the responder to re-narrow — as at AUTH. Echoing the wide TSi
    // back yields a rekeyed child whose selectors disagree with the /32 iOS holds, so
    // iOS deletes the whole IKE SA (~1s after the rekey). When we have an assignment,
    // re-narrow to that /32 (and IPv4 on our side); with none (local egress), take
    // what the peer proposes of either family. Either way the answer is a subset of
    // the proposal, or TS_UNACCEPTABLE (RFC 7296 §2.9).
    let (tsi, tsr) = requested_ts(first, &inner)?;
    let (policy_i, policy_r) = match assigned_ip {
        Some(ip) => assigned_ipv4_policy(Some(ip)),
        None => (TrafficSelectors::unified_full_tunnel(), TrafficSelectors::unified_full_tunnel()),
    };
    let (tsi, tsr) = narrow_requested_ts(tsi.as_ref(), tsr.as_ref(), &policy_i, &policy_r)?;

    // `choose_child_proposal` only settles on a group from the KE, with our key in hand.
    let pfs_secret = match (pfs_group, &peer_ke, dh_private) {
        (Some(group), Some(ke), Some(our_priv)) => Some(group.shared(our_priv, &ke.data)?),
        _ => None,
    };

    let child = match &pfs_secret {
        Some(secret) => ChildSa::derive_with_cipher_pfs(sa.suite.prf_algorithm(), cipher, secret, &sa.keys.sk_d, &ni, nr, Role::Responder, new_spi, peer_spi),
        None => ChildSa::derive_with_cipher(sa.suite.prf_algorithm(), cipher, &sa.keys.sk_d, &ni, nr, Role::Responder, new_spi, peer_spi),
    };

    let mut inner_out = vec![
        (PayloadType::SecurityAssociation, SecurityAssociation { proposals: vec![proposal] }.to_bytes()),
        (PayloadType::Nonce, nr.to_vec()),
    ];
    if let (Some(group), Some(our_priv)) = (pfs_group, dh_private) {
        let ke_out = KeyExchange { dh_group: group.transform_id(), data: group.public(our_priv) };
        inner_out.push((PayloadType::KeyExchange, ke_out.to_bytes()));
    }
    inner_out.push((PayloadType::TrafficSelectorInitiator, tsi.to_bytes()));
    inner_out.push((PayloadType::TrafficSelectorResponder, tsr.to_bytes()));
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

/// The transform types an ESP proposal may carry (RFC 7296 §3.3.3): any other
/// makes it unacceptable (§3.3.6).
const ESP_TRANSFORM_TYPES: &[u8] = &[transform_type::ENCR, transform_type::INTEG, transform_type::DH, transform_type::ESN];

/// Pick the proposal to answer a CHILD SA rekey the peer started with (RFC 7296
/// §2.7): the first one that offers the algorithms of the SA being rekeyed --
/// a rekey keeps the running `cipher` -- and, when the request carries a KE
/// payload (`ke_group`), that KE's DH group among its alternatives, or no
/// mandatory DH when it doesn't (a proposal with no DH transform at all takes
/// either, and is then answered without PFS). A KE group IKEv2 may not run
/// ([`negotiate::ikev2_dh_group`]) rules its proposals out rather than turning
/// them into "no PFS".
///
/// `pfs` is our own policy on top of that: PFS only on a group it allows,
/// and no PFS only when it makes PFS optional -- a rekey that would drop the
/// PFS our side runs is refused, even when the peer offers that as an
/// alternative.
///
/// Refused as `NoProposalChosen` when nothing fits -- except that a proposal
/// we'd take on a group other than the KE's is `InvalidKeGroup` naming it
/// (§1.3: the responder MUST reject with INVALID_KE_PAYLOAD and its preferred
/// group, for the peer to retry with), and a KE of a group no proposal names
/// is a malformed request (§3.4), `Crypto`.
///
/// Returns the proposal to send back (the
/// chosen one's number, our `new_spi`, one transform per type), the peer's
/// SPI from it, and the DH group PFS runs on, if any.
pub(crate) fn choose_child_proposal(
    peer_sa: &SecurityAssociation,
    cipher: SkCipher,
    new_spi: u32,
    ke_group: Option<u16>,
    pfs: &PfsPolicy,
) -> Result<(Proposal, u32, Option<DhGroup>), IkeError> {
    if ke_group.is_some_and(|g| !proposals_name_dh(peer_sa, g)) {
        return Err(IkeError::Crypto("CREATE_CHILD_SA: a KE payload of a DH group no proposal names"));
    }
    let ours = esp_offer_for_cipher(new_spi, cipher).proposals.remove(0);
    // The group of the first proposal we'd take, but not on the KE's group.
    let mut wanted_group = None;
    for p in &peer_sa.proposals {
        if p.protocol_id != protocol_id::ESP || p.spi.len() != 4 {
            continue;
        }
        // RFC 7296 §3.3.6: a transform type we don't know makes the whole
        // proposal unacceptable (RFC 9370's ADDKE types included, without
        // IKE_INTERMEDIATE); the others are weighed as usual.
        if !p.transforms.iter().all(|t| ESP_TRANSFORM_TYPES.contains(&t.transform_type)) {
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
        // The NONE that lets it through is the plain one: integrity, DH and ESN transforms take no Key
        // Length (RFC 7296 §3.3.5), so one that carries it is not a transform we understand -- unacceptable
        // (§3.3.6), not a NONE to answer with the attribute dropped ("returned unmodified").
        let integ_forced = !ours.transforms.iter().any(|t| t.transform_type == transform_type::INTEG)
            && of_type(transform_type::INTEG).next().is_some()
            && !of_type(transform_type::INTEG).any(|t| t.transform_id == 0 && t.key_length.is_none());
        if !offers_all || integ_forced {
            continue;
        }
        // Every DH transform it names, an unreadable one (or one with a Key Length) as `UNUSABLE`: the
        // proposal does insist on a group, just not on one we can take.
        let dh_offered: Vec<u16> = of_type(transform_type::DH)
            .map(|t| if t.key_length.is_none() { t.transform_id } else { transform_id::UNUSABLE })
            .collect();
        let group = match ke_group {
            Some(g) if dh_offered.contains(&g) && pfs.allows_group(g) => match negotiate::ikev2_dh_group(g) {
                Some(group) => Some(group),
                None => continue,
            },
            // A proposal with no DH of its own answers a rekey without PFS: the KE is
            // there for the proposals that do list its group (strongSwan sends
            // both kinds side by side, so a peer that can't do PFS still fits).
            _ if pfs.optional && (dh_offered.is_empty() || dh_offered.contains(&0)) => None,
            _ => {
                wanted_group =
                    wanted_group.or_else(|| dh_offered.iter().filter(|&&g| pfs.allows_group(g)).find_map(|&g| negotiate::ikev2_dh_group(g)));
                continue;
            }
        };
        // §2.7: "exactly one transform of each type included in the proposal"
        // -- so no ESN where it left ESN out, and the NONE it spelled out for
        // an integrity algorithm next to an AEAD cipher, or for DH without PFS.
        let mut reply = ours.clone();
        reply.num = p.num;
        if of_type(transform_type::ESN).next().is_none() {
            reply.transforms.retain(|t| t.transform_type != transform_type::ESN);
        }
        if !ours.transforms.iter().any(|t| t.transform_type == transform_type::INTEG) && of_type(transform_type::INTEG).next().is_some() {
            reply.transforms.push(Transform { transform_type: transform_type::INTEG, transform_id: 0, key_length: None });
        }
        match group {
            Some(group) => {
                reply.transforms.push(Transform { transform_type: transform_type::DH, transform_id: group.transform_id(), key_length: None })
            }
            None if !dh_offered.is_empty() => reply.transforms.push(Transform { transform_type: transform_type::DH, transform_id: 0, key_length: None }),
            None => {}
        }
        let peer_spi = u32::from_be_bytes(p.spi[..4].try_into().unwrap());
        return Ok((reply, peer_spi, group));
    }
    ike_debug!(
        "CHILD SA: none of the peer's ESP proposals fits the cipher {cipher:?} (KE group {ke_group:?}, our PFS policy {pfs:?}, group we'd take {wanted_group:?}); offered: {:?}",
        peer_sa.proposals
    );
    Err(wanted_group.map_or(IkeError::NoProposalChosen, |g| IkeError::InvalidKeGroup(g.transform_id())))
}

/// Responder side of a CHILD SA rekey the *peer* started (RFC 7296 §1.3.3): a
/// `CREATE_CHILD_SA` request `SK { N(REKEY_SA), SA, Ni, [KEi,] TSi, TSr }`.
/// Selects a proposal ([`choose_child_proposal`] -- the peer may offer several
/// and, for PFS, name a DH group), derives the new CHILD SA from the peer's
/// nonce, ours (`nr`) and, with PFS, a fresh DH secret from `dh_private` (only
/// used when the request carries a KE payload), and builds the response, which
/// accepts the traffic selectors as the peer proposed them, less any of a type
/// this crate does not know (RFC 7296 §2.9) -- that is what its SA being
/// replaced already carries. A request whose TSi or TSr has none of a known
/// type is refused with `TsUnacceptable`. `new_spi` is the inbound SPI we
/// choose for the new SA; `cipher` the one running on the SA being rekeyed;
/// `pfs` our side's PFS policy, which the rekey must keep (see
/// [`choose_child_proposal`]).
///
/// Which SA is being rekeyed is the caller's to check first ([`rekey_sa_spi`]):
/// this only builds the new one. Returns `(response_bytes, ChildSa)`.
#[allow(clippy::too_many_arguments)]
pub fn responder_answer_child_rekey(
    sa: &CompletedSaInit,
    request: &[u8],
    new_spi: u32,
    nr: &[u8],
    cipher: SkCipher,
    pfs: &PfsPolicy,
    dh_private: &[u8],
    iv: &[u8; 8],
) -> Result<(Vec<u8>, ChildSa), IkeError> {
    let message_id = IkeHeader::parse(request)?.message_id;
    let (first, inner) = open_encrypted(sa.suite.sk_cipher(), request, peer_sk_e(sa), peer_sk_a(sa))?;
    let (sa_bytes, ni) = find_sa_and_nonce(sa, first, &inner)?;
    let peer_sa = SecurityAssociation::parse(&sa_bytes)?;
    let peer_ke = find_ke(first, &inner)?;
    let (tsi, tsr) = requested_ts(first, &inner)?;
    let any = TrafficSelectors::unified_full_tunnel();
    let (tsi, tsr) = narrow_requested_ts(tsi.as_ref(), tsr.as_ref(), &any, &any)?;

    let (proposal, peer_spi, group) = choose_child_proposal(&peer_sa, cipher, new_spi, peer_ke.as_ref().map(|k| k.dh_group), pfs)?;
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
    inner_out.push((PayloadType::TrafficSelectorInitiator, tsi.to_bytes()));
    inner_out.push((PayloadType::TrafficSelectorResponder, tsr.to_bytes()));
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
/// [`build_rekey_request_with_pfs`]: `pfs` must be the same group and
/// ephemeral private key passed there (`None` if PFS wasn't requested), and
/// `cipher` the same cipher passed there too (preserving the tunnel's
/// already-negotiated algorithm -- see [`esp_offer_for_cipher`]'s own doc).
pub fn initiator_complete_rekey_with_pfs(
    sa: &CompletedSaInit,
    ni: &[u8],
    new_spi: u32,
    cipher: SkCipher,
    pfs: Option<PfsKeyExchange>,
    response: &[u8],
) -> Result<ChildSa, IkeError> {
    // `build_rekey_request_with_pfs` proposes 0.0.0.0/0 as both TSi and TSr.
    initiator_complete_child(sa, ni, new_spi, cipher, pfs, &TrafficSelectors::ipv4_full_tunnel(), response).map(|(child, _tsr)| child)
}

/// Like [`initiator_complete_rekey_with_pfs`], for either kind of
/// `CREATE_CHILD_SA` request [`build_child_request`] builds, and also returns
/// the `TSr` the responder granted -- for a newly created CHILD SA that is
/// what decides what the caller routes into it. `offered` is the `ts` the
/// request proposed: the answer must carry TSi and TSr, each a subset of it
/// (RFC 7296 §2.9), or this fails with [`IkeError::MissingPayload`] /
/// [`IkeError::TsOutsideOffer`] -- in the second case the peer has made the
/// SA (on our `new_spi`), which is the caller's to delete. A
/// response carrying an error Notify (`NO_PROPOSAL_CHOSEN`, `TS_UNACCEPTABLE`,
/// ...) is [`IkeError::PeerRejected`] rather than a confusing missing-payload
/// error.
///
/// `pfs` is the group and private key the request offered PFS with. The
/// answer must keep it: name that group and carry a KE of it -- one that
/// leaves them out, or names another group, is refused
/// (`NoProposalChosen`, `MissingPayload("KE")`, `DhGroupMismatch`) rather
/// than taken as a rekey without PFS. With `pfs` `None` the answer must not
/// bring a group or a KE either.
pub fn initiator_complete_child(
    sa: &CompletedSaInit,
    ni: &[u8],
    new_spi: u32,
    cipher: SkCipher,
    pfs: Option<PfsKeyExchange>,
    offered: &TrafficSelectors,
    response: &[u8],
) -> Result<(ChildSa, TrafficSelectors), IkeError> {
    let (first, inner) = open_encrypted(sa.suite.sk_cipher(), response, peer_sk_e(sa), peer_sk_a(sa))?;
    let (mut tsi, mut tsr) = (None, None);
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
            PayloadType::TrafficSelectorInitiator => tsi = Some(TrafficSelectors::parse(p.data)?),
            PayloadType::TrafficSelectorResponder => tsr = Some(TrafficSelectors::parse(p.data)?),
            _ => {}
        }
    }
    let (sa_bytes, nr) = find_sa_and_nonce(sa, first, &inner)?;
    let peer_sa = SecurityAssociation::parse(&sa_bytes)?;
    // Our one proposal, by its number, with one transform of each of its
    // types (RFC 7296 §2.7, §3.3.1, §3.3.6) -- the offer `build_child_request`
    // sent, whose SPI (ours) the answer replaces with the peer's.
    negotiate::accepted_proposal(&peer_sa, &child_offer(new_spi, cipher, pfs.map(|(group, _)| group)))?;
    let peer_spi = esp_spi_from_sa(&sa_bytes)?;

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

    // The same for PFS (§1.3.1, §3.3): the answer is one transform per type
    // picked from our offer, so with PFS offered it names exactly our group
    // and carries a KE of it. Reading the group off the answer instead would
    // let it drop PFS, or swap in a group we never offered, just by leaving
    // the transform out or naming another.
    let answered_dh = first_proposal_dh_ids(&peer_sa);
    let peer_ke = find_ke(first, &inner)?;
    let pfs_secret = match pfs {
        Some((group, our_priv)) => {
            if answered_dh != [group.transform_id()] {
                ike_debug!("CREATE_CHILD_SA: we offered PFS on DH group {} and the answer names {answered_dh:?}", group.transform_id());
                return Err(IkeError::NoProposalChosen);
            }
            let ke = peer_ke.ok_or(IkeError::MissingPayload("KE"))?;
            if ke.dh_group != group.transform_id() {
                return Err(IkeError::DhGroupMismatch { expected: group.transform_id(), got: ke.dh_group });
            }
            Some(group.shared(our_priv, &ke.data)?)
        }
        None => {
            if !(answered_dh.is_empty() || answered_dh == [0]) {
                ike_debug!("CREATE_CHILD_SA: we offered no PFS and the answer names DH {answered_dh:?}");
                return Err(IkeError::NoProposalChosen);
            }
            if peer_ke.is_some() {
                return Err(IkeError::Crypto("CREATE_CHILD_SA: a KE payload answering a request without PFS"));
            }
            None
        }
    };

    let child = match &pfs_secret {
        Some(secret) => ChildSa::derive_with_cipher_pfs(sa.suite.prf_algorithm(), cipher, secret, &sa.keys.sk_d, ni, &nr, Role::Initiator, new_spi, peer_spi),
        None => ChildSa::derive_with_cipher(sa.suite.prf_algorithm(), cipher, &sa.keys.sk_d, ni, &nr, Role::Initiator, new_spi, peer_spi),
    };
    let tsr = tsr.ok_or(IkeError::MissingPayload("TSr"))?;
    check_granted_ts(offered, tsi.as_ref(), Some(&tsr))?;
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
        let mut init_child =
            initiator_complete_rekey_with_pfs(&init_sa, &ni, init_new_spi, SkCipher::Aes256Gcm, Some((group, &init_dh)), &resp).unwrap();

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
        let child1 = initiator_complete_rekey_with_pfs(&init_sa, &ni, 0x1111_1111, SkCipher::Aes256Gcm, Some((group, &[5u8; 32])), &resp1).unwrap();

        let req2 = build_rekey_request_with_pfs(&init_sa, 4, 0x1111_1111, 0x3333_3333, &ni, SkCipher::Aes256Gcm, Some((group, &[7u8; 32])), &[3u8; 8]).unwrap();
        let (resp2, _) = responder_process_rekey_with_pfs(&resp_sa, &req2, 0x4444_4444, &nr, SkCipher::Aes256Gcm, Some(&[8u8; 32]), &[4u8; 8], None).unwrap();
        let child2 = initiator_complete_rekey_with_pfs(&init_sa, &ni, 0x3333_3333, SkCipher::Aes256Gcm, Some((group, &[7u8; 32])), &resp2).unwrap();

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
            initiator_complete_child(&init_sa, &[0x33u8; 32], 0x1111_1111, SkCipher::Aes256Gcm, None, &v6, &resp).unwrap();
        assert_eq!(granted, v6);

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

    /// A peer's CHILD SA rekey request (no PFS) whose TSi/TSr payloads carry
    /// `tsi`/`tsr` as they are, or are left out when `None`.
    fn peer_rekey_request_with_raw_ts(peer_sa: &CompletedSaInit, tsi: Option<Vec<u8>>, tsr: Option<Vec<u8>>) -> Vec<u8> {
        let notify = Notify {
            protocol_id: protocol_id::ESP,
            spi: 0xAAAA_AAAAu32.to_be_bytes().to_vec(),
            notify_type: notify_type::REKEY_SA,
            data: Vec::new(),
        };
        let mut inner = vec![
            (PayloadType::Notify, notify.to_bytes()),
            (PayloadType::SecurityAssociation, esp_offer_for_cipher(0x2222_2222, SkCipher::Aes256Gcm).to_bytes()),
            (PayloadType::Nonce, vec![0x33; 32]),
        ];
        inner.extend(tsi.map(|ts| (PayloadType::TrafficSelectorInitiator, ts)));
        inner.extend(tsr.map(|ts| (PayloadType::TrafficSelectorResponder, ts)));
        let first = first_payload_type(&inner);
        let header = create_child_header(peer_sa, 7, false);
        build_encrypted(peer_sa.suite.sk_cipher(), header, first, &encode_payload_chain(&inner), our_sk_e(peer_sa), our_sk_a(peer_sa), &[1u8; 8])
            .unwrap()
    }

    /// Both rekey responders answer a subset of the TSi/TSr proposed, keeping
    /// the proposal's own ranges where the policy allows them, and refuse with
    /// `TsUnacceptable` what leaves nothing (RFC 7296 §2.9): the gateway one
    /// narrows to the address it assigned and IPv4 when it has one, and takes
    /// either family otherwise; the client one takes either family. Selectors
    /// of an unknown type are dropped; missing or malformed TS fail the request.
    #[test]
    fn rekey_responders_answer_a_subset_of_the_proposal_or_ts_unacceptable() {
        use crate::ikev2::ike_auth::tests::sample_ts;
        let t = sample_ts();
        let (our_sa, peer_sa) = sa_pair(); // `our_sa` answers, `peer_sa` asks
        let assigned = Ipv4Addr::new(10, 8, 0, 4);
        let at_assigned = TrafficSelectors { selectors: vec![TrafficSelector::ipv4_host(assigned)] };
        let gateway = |req: &[u8], assigned_ip| {
            responder_process_rekey_with_pfs(&our_sa, req, 0x1111_1111, &[0x44u8; 32], SkCipher::Aes256Gcm, None, &[2u8; 8], assigned_ip)
                .map(|(r, _)| r)
        };
        let client = |req: &[u8]| {
            responder_answer_child_rekey(&our_sa, req, 0x1111_1111, &[0x44u8; 32], SkCipher::Aes256Gcm, &PfsPolicy::none(), &[6u8; 32], &[2u8; 8])
                .map(|(r, _)| r)
        };
        let ask =
            |tsi: &TrafficSelectors, tsr: &TrafficSelectors| peer_rekey_request_with_raw_ts(&peer_sa, Some(tsi.to_bytes()), Some(tsr.to_bytes()));
        let answer = |resp: Result<Vec<u8>, IkeError>| {
            let (_, tsi, tsr, _) = read_rekey_response(&resp.expect("the rekey is answered"), &peer_sa);
            (tsi, tsr)
        };

        // Without an assignment, and on the client side: the proposal itself, less unknown types.
        let echoed = [
            ("a host and a subnet", &t.host, &t.subnet, &t.host, &t.subnet),
            ("IPv6", &t.v6, &t.v6, &t.v6, &t.v6),
            ("IPv4 and IPv6", &t.unified, &t.unified, &t.unified, &t.unified),
            ("an unknown type ahead of IPv4", &t.unknown_then_v4, &t.unknown_then_v4, &t.v4, &t.v4),
        ];
        for (case, tsi, tsr, want_i, want_r) in echoed {
            let req = ask(tsi, tsr);
            assert_eq!(answer(gateway(&req, None)), (want_i.clone(), want_r.clone()), "gateway without assignment, {case}");
            assert_eq!(answer(client(&req)), (want_i.clone(), want_r.clone()), "client, {case}");
        }
        // With an assignment: the assigned /32 and IPv4, whatever wider the peer proposes.
        for (case, tsi, tsr) in [("IPv4", &t.v4, &t.v4), ("IPv4 and IPv6", &t.unified, &t.unified), ("the assigned host", &at_assigned, &t.unified)] {
            assert_eq!(answer(gateway(&ask(tsi, tsr), Some(assigned))), (at_assigned.clone(), t.v4.clone()), "gateway with assignment, {case}");
        }

        // Nothing left of the proposal: refused.
        for (case, tsi, tsr) in [("IPv6", &t.v6, &t.v6), ("another host", &t.other_host, &t.v4), ("only an unknown TSr", &t.v4, &t.unknown)] {
            assert_eq!(gateway(&ask(tsi, tsr), Some(assigned)), Err(IkeError::TsUnacceptable), "gateway with assignment, {case}");
        }
        let req = ask(&t.v4, &t.unknown);
        assert_eq!(gateway(&req, None), Err(IkeError::TsUnacceptable), "gateway without assignment, only an unknown TSr");
        assert_eq!(client(&req), Err(IkeError::TsUnacceptable), "client, only an unknown TSr");

        // Missing or malformed TS: the request itself fails.
        let v4 = || Some(t.v4.to_bytes());
        let empty = || Some(TrafficSelectors { selectors: vec![] }.to_bytes());
        for (case, tsi, tsr, want) in [
            ("no TSi", None, v4(), IkeError::MissingPayload("TSi")),
            ("no TSr", v4(), None, IkeError::MissingPayload("TSr")),
        ] {
            let req = peer_rekey_request_with_raw_ts(&peer_sa, tsi, tsr);
            assert_eq!(gateway(&req, None), Err(want.clone()), "gateway, {case}");
            assert_eq!(gateway(&req, Some(assigned)), Err(want.clone()), "gateway with assignment, {case}");
            assert_eq!(client(&req), Err(want), "client, {case}");
        }
        let req = peer_rekey_request_with_raw_ts(&peer_sa, v4(), empty());
        assert!(matches!(gateway(&req, None), Err(IkeError::MalformedPayload(_))), "gateway, a TSr with no selector");
        assert!(matches!(client(&req), Err(IkeError::MalformedPayload(_))), "client, a TSr with no selector");
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
                responder_answer_child_rekey(&our_sa, &req, 0x1111_1111, &[0x44u8; 32], SkCipher::Aes256Gcm, &PfsPolicy::none(), &[6u8; 32], &[2u8; 8]).unwrap();
            let (mut peer_child, granted) =
                initiator_complete_child(&peer_sa, &[0x33u8; 32], 0x2222_2222, SkCipher::Aes256Gcm, pfs.map(|g| (g, &peer_dh[..])), &ts, &resp).unwrap();
            assert_eq!(granted, ts, "the peer's selectors are accepted as proposed");

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
            responder_answer_child_rekey(&our_sa, &req, 0x1111_1111, &[0x44u8; 32], SkCipher::Aes256Gcm, &PfsPolicy::none(), &[6u8; 32], &[2u8; 8])
                .unwrap();
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
            responder_answer_child_rekey(&our_sa, &req, 0x1111_1111, &[0x44u8; 32], SkCipher::Aes256Gcm, &PfsPolicy::none(), &[6u8; 32], &[2u8; 8])
                .unwrap();
        let (proposal, _, _, ke) = read_rekey_response(&resp, &peer_sa);
        assert_eq!(proposal.num, 3);
        assert!(!ke, "the chosen proposal has no DH, so no KE in the answer");
        assert!(proposal.transforms.iter().all(|t| t.transform_type != transform_type::DH));

        // The peer's side, derived by hand: `initiator_complete_child` only
        // takes answers to its own one-proposal offer, not to these five.
        let our_spi = u32::from_be_bytes(proposal.spi[..4].try_into().unwrap());
        let prf = peer_sa.suite.prf_algorithm();
        let mut peer_child =
            ChildSa::derive_with_cipher(prf, SkCipher::Aes256Gcm, &peer_sa.keys.sk_d, &[0x33u8; 32], &[0x44u8; 32], Role::Initiator, 0x2222_2222, our_spi);
        let pkt = peer_child.outbound.seal(b"peer -> us", next_header::IPV4).unwrap();
        assert_eq!(our_child.inbound.open(&pkt).unwrap().0, b"peer -> us");
    }

    /// RFC 7296 §3.3.6: a proposal with a transform type we don't know (an
    /// RFC 9370 ADDKE one, say, which peers not running `IKE_INTERMEDIATE`
    /// MUST treat as unknown) is unacceptable -- and the next one is weighed
    /// as usual.
    #[test]
    fn a_peer_started_rekey_skips_a_proposal_with_a_transform_type_we_do_not_know() {
        let (our_sa, peer_sa) = sa_pair();
        let gcm = (transform_id::AES_GCM_16, Some(256));
        let mut addke = esp_proposal(1, 0x2222_2222, gcm, None, &[]);
        addke.transforms.push(Transform { transform_type: 6, transform_id: transform_id::MODP_2048, key_length: None });
        let offers = vec![addke, esp_proposal(2, 0x3333_3333, gcm, None, &[])];
        let req = peer_rekey_request(&peer_sa, offers, None, &TrafficSelectors::ipv4_full_tunnel());
        let (resp, _) =
            responder_answer_child_rekey(&our_sa, &req, 0x1111_1111, &[0x44u8; 32], SkCipher::Aes256Gcm, &PfsPolicy::none(), &[6u8; 32], &[2u8; 8])
                .unwrap();
        let (proposal, _, _, _) = read_rekey_response(&resp, &peer_sa);
        assert_eq!(proposal.num, 2);
    }

    /// RFC 7296 §2.7: the accepted suite "MUST contain exactly one transform
    /// of each type included in the proposal" -- no more, no fewer. A proposal
    /// spelling out INTEG NONE and DH NONE, and leaving ESN out, is answered
    /// with GCM, INTEG NONE and DH NONE, and no ESN.
    #[test]
    fn a_peer_started_rekey_is_answered_with_one_transform_of_each_offered_type() {
        let (our_sa, peer_sa) = sa_pair();
        let t = |transform_type, transform_id, key_length| Transform { transform_type, transform_id, key_length };
        let gcm = t(transform_type::ENCR, transform_id::AES_GCM_16, Some(256));
        let (integ_none, dh_none) = (t(transform_type::INTEG, 0, None), t(transform_type::DH, 0, None));
        let offer = Proposal {
            num: 1,
            protocol_id: protocol_id::ESP,
            spi: 0x2222_2222u32.to_be_bytes().to_vec(),
            transforms: vec![gcm.clone(), integ_none.clone(), dh_none.clone()],
        };
        let req = peer_rekey_request(&peer_sa, vec![offer], None, &TrafficSelectors::ipv4_full_tunnel());
        let (resp, _) =
            responder_answer_child_rekey(&our_sa, &req, 0x1111_1111, &[0x44u8; 32], SkCipher::Aes256Gcm, &PfsPolicy::none(), &[6u8; 32], &[2u8; 8])
                .unwrap();
        let (proposal, _, _, _) = read_rekey_response(&resp, &peer_sa);
        let mut got = proposal.transforms;
        got.sort_by_key(|t| t.transform_type);
        assert_eq!(got, vec![gcm, integ_none, dh_none]);
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
        let (resp, child) =
            responder_answer_child_rekey(&our_sa, &req, 0x1111_1111, &[0x44u8; 32], cbc, &PfsPolicy::none(), &[6u8; 32], &[2u8; 8]).unwrap();
        let (proposal, _, _, ke) = read_rekey_response(&resp, &peer_sa);
        assert_eq!(proposal.num, 2);
        assert!(!ke);
        assert_eq!(child.inbound.cipher(), cbc);
    }

    /// Nothing offered fits: refused, not a guess -- `NoProposalChosen` when no
    /// proposal has our cipher, and the RFC 7296 answers for a KE that fits
    /// no proposal we can take.
    #[test]
    fn a_peer_started_rekey_that_offers_nothing_usable_is_refused() {
        let (our_sa, peer_sa) = sa_pair();
        let ts = TrafficSelectors::ipv4_full_tunnel();
        let peer_dh = [5u8; 32];
        let answer = |req: &[u8]| {
            responder_answer_child_rekey(&our_sa, req, 0x1111_1111, &[0x44u8; 32], SkCipher::Aes256Gcm, &PfsPolicy::none(), &[6u8; 32], &[2u8; 8])
                .err()
        };
        let other_cipher = esp_proposal(1, 0x2222_2222, (transform_id::AES_CBC, Some(128)), Some(transform_id::AUTH_HMAC_SHA1_96), &[]);
        let req = peer_rekey_request(&peer_sa, vec![other_cipher], None, &ts);
        assert!(matches!(answer(&req), Some(IkeError::NoProposalChosen)));

        // A KE of a group no proposal names at all is a malformed request (RFC 7296 §3.4).
        let gcm_ecp = esp_proposal(1, 0x2222_2222, (transform_id::AES_GCM_16, Some(256)), None, &[transform_id::ECP256]);
        let req = peer_rekey_request(&peer_sa, vec![gcm_ecp.clone()], Some((DhGroup::Modp2048, &peer_dh)), &ts);
        assert!(matches!(answer(&req), Some(IkeError::Crypto(_))), "the KE's group isn't among the proposals'");

        // Named by a proposal we can't take, while the one we'd take runs another
        // group: INVALID_KE_PAYLOAD naming that one (§1.3), for the peer to retry.
        let cbc_modp =
            esp_proposal(2, 0x2222_2222, (transform_id::AES_CBC, Some(128)), Some(transform_id::AUTH_HMAC_SHA1_96), &[transform_id::MODP_2048]);
        let req = peer_rekey_request(&peer_sa, vec![gcm_ecp, cbc_modp], Some((DhGroup::Modp2048, &peer_dh)), &ts);
        assert_eq!(answer(&req), Some(IkeError::InvalidKeGroup(transform_id::ECP256)));
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
        let err =
            initiator_complete_child(&init_sa, &[0x33u8; 32], 0x1111_1111, SkCipher::Aes256Gcm, None, &TrafficSelectors::ipv4_full_tunnel(), &reply)
                .err()
                .unwrap();
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

        let err =
            initiator_complete_child(&init_sa, &[0x33u8; 32], 0x1111_1111, SkCipher::Aes256Gcm, None, &TrafficSelectors::ipv4_full_tunnel(), &resp)
                .err()
                .unwrap();
        assert_eq!(err, IkeError::NoProposalChosen);
    }

    #[test]
    fn a_create_child_sa_answer_must_carry_both_ts_within_the_offer() {
        use crate::ikev2::ike_auth::tests::{ts_answers_outside_an_ipv4_offer, with_ts};
        let answer = |resp_sa: &CompletedSaInit, tsi: Option<Vec<u8>>, tsr: Option<Vec<u8>>| {
            let inner = with_ts(
                vec![
                    (PayloadType::SecurityAssociation, esp_offer_for_cipher(0x2222_2222, SkCipher::Aes256Gcm).to_bytes()),
                    (PayloadType::Nonce, vec![0x44; 32]),
                ],
                tsi,
                tsr,
            );
            let header = create_child_header(resp_sa, 2, true);
            build_encrypted(
                resp_sa.suite.sk_cipher(),
                header,
                first_payload_type(&inner),
                &encode_payload_chain(&inner),
                our_sk_e(resp_sa),
                our_sk_a(resp_sa),
                &[2u8; 8],
            )
            .unwrap()
        };
        let complete = |init_sa: &CompletedSaInit, offered: &TrafficSelectors, resp: &[u8]| {
            initiator_complete_child(init_sa, &[0x33u8; 32], 0x1111_1111, SkCipher::Aes256Gcm, None, offered, resp).map(|(_, tsr)| tsr)
        };
        let v4 = TrafficSelectors::ipv4_full_tunnel();
        let v6 = TrafficSelectors::ipv6_full_tunnel();
        for (what, tsi, tsr, expected) in ts_answers_outside_an_ipv4_offer() {
            let (init_sa, resp_sa) = sa_pair();
            assert_eq!(complete(&init_sa, &v4, &answer(&resp_sa, tsi, tsr)).err(), Some(expected), "{what}");
        }
        // A new IPv6 CHILD SA answered with IPv4 selectors.
        let (init_sa, resp_sa) = sa_pair();
        let got = complete(&init_sa, &v6, &answer(&resp_sa, Some(v4.to_bytes()), Some(v4.to_bytes())));
        assert_eq!(got.err(), Some(IkeError::TsOutsideOffer));

        // Positive controls: narrowed IPv4, and IPv6 as proposed.
        let host = TrafficSelectors { selectors: vec![TrafficSelector::ipv4_host(Ipv4Addr::new(10, 8, 0, 4))] };
        let (init_sa, resp_sa) = sa_pair();
        assert_eq!(complete(&init_sa, &v4, &answer(&resp_sa, Some(host.to_bytes()), Some(v4.to_bytes()))), Ok(v4.clone()));
        let (init_sa, resp_sa) = sa_pair();
        assert_eq!(complete(&init_sa, &v6, &answer(&resp_sa, Some(v6.to_bytes()), Some(v6.to_bytes()))), Ok(v6));
    }

    /// A `CREATE_CHILD_SA` answer from `resp_sa` to our GCM-256 request, built
    /// by hand: our offer's proposal with the DH transforms `dh` added, and
    /// `ke` as its KE payload, if any.
    fn hand_built_answer(resp_sa: &CompletedSaInit, dh: &[u16], ke: Option<KeyExchange>) -> Vec<u8> {
        let mut sa = esp_offer_for_cipher(0x2222_2222, SkCipher::Aes256Gcm);
        sa.proposals[0].transforms.extend(dh.iter().map(|&id| Transform { transform_type: transform_type::DH, transform_id: id, key_length: None }));
        hand_built_answer_with(resp_sa, sa, ke)
    }

    /// [`hand_built_answer`] with the SA payload `sa` as it is.
    fn hand_built_answer_with(resp_sa: &CompletedSaInit, sa: SecurityAssociation, ke: Option<KeyExchange>) -> Vec<u8> {
        let ts = TrafficSelectors::ipv4_full_tunnel();
        let mut inner = vec![(PayloadType::SecurityAssociation, sa.to_bytes()), (PayloadType::Nonce, vec![0x44; 32])];
        inner.extend(ke.map(|ke| (PayloadType::KeyExchange, ke.to_bytes())));
        inner.push((PayloadType::TrafficSelectorInitiator, ts.to_bytes()));
        inner.push((PayloadType::TrafficSelectorResponder, ts.to_bytes()));
        let first = first_payload_type(&inner);
        build_encrypted(
            resp_sa.suite.sk_cipher(),
            create_child_header(resp_sa, 2, true),
            first,
            &encode_payload_chain(&inner),
            our_sk_e(resp_sa),
            our_sk_a(resp_sa),
            &[2u8; 8],
        )
        .unwrap()
    }

    /// A KE payload of `group` from the private key `private`.
    fn ke_of(group: DhGroup, private: &[u8]) -> KeyExchange {
        KeyExchange { dh_group: group.transform_id(), data: group.public(private) }
    }

    /// RFC 7296 §1.3.1, §3.3: a rekey we asked PFS for is answered with our
    /// group and a KE of it. An answer that leaves PFS out -- no DH transform
    /// and no KE, NONE, or just no KE -- or that names another group, one we
    /// don't know, or several, is refused, never taken as a rekey without
    /// PFS. The untouched answer of the same shape still completes.
    #[test]
    fn a_pfs_rekey_answer_must_carry_the_offered_group_and_its_ke() {
        let (init_sa, resp_sa) = sa_pair();
        let (ni, init_dh, resp_dh) = ([0x33u8; 32], [5u8; 32], [6u8; 32]);
        let modp2048 = DhGroup::Modp2048;
        let complete =
            |resp: &[u8]| initiator_complete_child(&init_sa, &ni, 0x1111_1111, SkCipher::Aes256Gcm, Some((modp2048, &init_dh)), &TrafficSelectors::ipv4_full_tunnel(), resp).map(|_| ());

        // Positive controls: the real responder's answer, and the hand-built one.
        let req =
            build_rekey_request_with_pfs(&init_sa, 2, 0xDEAD_BEEF, 0x1111_1111, &ni, SkCipher::Aes256Gcm, Some((modp2048, &init_dh)), &[1u8; 8])
                .unwrap();
        let (resp, _) =
            responder_process_rekey_with_pfs(&resp_sa, &req, 0x2222_2222, &[0x44u8; 32], SkCipher::Aes256Gcm, Some(&resp_dh), &[2u8; 8], None)
                .unwrap();
        assert_eq!(complete(&resp), Ok(()));
        assert_eq!(complete(&hand_built_answer(&resp_sa, &[transform_id::MODP_2048], Some(ke_of(modp2048, &resp_dh)))), Ok(()));

        let ecp256 = ke_of(DhGroup::EcpP256, &resp_dh);
        let unknown = KeyExchange { dh_group: 0x7777, data: vec![9; 256] };
        let cases = [
            ("PFS stripped: no DH transform, no KE", hand_built_answer(&resp_sa, &[], None), IkeError::NoProposalChosen),
            ("DH NONE and no KE", hand_built_answer(&resp_sa, &[0], None), IkeError::NoProposalChosen),
            ("our group, but no KE", hand_built_answer(&resp_sa, &[transform_id::MODP_2048], None), IkeError::MissingPayload("KE")),
            ("ECP-256 swapped in", hand_built_answer(&resp_sa, &[transform_id::ECP256], Some(ecp256.clone())), IkeError::NoProposalChosen),
            ("a group nobody knows", hand_built_answer(&resp_sa, &[0x7777], Some(unknown)), IkeError::NoProposalChosen),
            (
                "two DH transforms",
                hand_built_answer(&resp_sa, &[transform_id::MODP_2048, transform_id::ECP256], Some(ke_of(modp2048, &resp_dh))),
                IkeError::NoProposalChosen,
            ),
            (
                "our group, a KE of another",
                hand_built_answer(&resp_sa, &[transform_id::MODP_2048], Some(ecp256)),
                IkeError::DhGroupMismatch { expected: transform_id::MODP_2048, got: transform_id::ECP256 },
            ),
        ];
        for (what, answer, expected) in cases {
            assert_eq!(complete(&answer), Err(expected), "{what}");
        }
    }

    /// The other way round: a rekey we asked no PFS for is answered without
    /// it. DH NONE, or no DH transform at all, completes; a group, or a KE,
    /// is refused rather than half-used.
    #[test]
    fn a_rekey_answer_must_not_bring_pfs_we_did_not_ask_for() {
        let (init_sa, resp_sa) = sa_pair();
        let complete = |resp: &[u8]| {
            initiator_complete_child(&init_sa, &[0x33u8; 32], 0x1111_1111, SkCipher::Aes256Gcm, None, &TrafficSelectors::ipv4_full_tunnel(), resp)
                .map(|_| ())
        };
        let ke = ke_of(DhGroup::Modp2048, &[6u8; 32]);

        assert_eq!(complete(&hand_built_answer(&resp_sa, &[], None)), Ok(()));
        assert_eq!(complete(&hand_built_answer(&resp_sa, &[0], None)), Ok(()));
        assert_eq!(complete(&hand_built_answer(&resp_sa, &[transform_id::MODP_2048], Some(ke.clone()))), Err(IkeError::NoProposalChosen));
        assert!(matches!(complete(&hand_built_answer(&resp_sa, &[], Some(ke))), Err(IkeError::Crypto(_))));
    }

    /// RFC 7296 §2.7, §3.3.1, §3.3.6: the answer to our CHILD SA request is
    /// our one proposal, by its number, with one transform of each of its
    /// types. Each forged answer below carries only transforms we offered --
    /// the ESP suite it names matches our offer -- and must still be refused.
    #[test]
    fn a_child_sa_answer_must_be_our_one_proposal() {
        let (init_sa, resp_sa) = sa_pair();
        let complete = |resp: &[u8]| {
            initiator_complete_child(&init_sa, &[0x33u8; 32], 0x1111_1111, SkCipher::Aes256Gcm, None, &TrafficSelectors::ipv4_full_tunnel(), resp)
                .map(|_| ())
        };
        let ours = esp_offer_for_cipher(0x2222_2222, SkCipher::Aes256Gcm).proposals.remove(0);
        assert_eq!(complete(&hand_built_answer_with(&resp_sa, SecurityAssociation { proposals: vec![ours.clone()] }, None)), Ok(()), "control");

        let dup_encr = {
            let mut p = ours.clone();
            p.transforms.push(p.transforms[0].clone());
            p
        };
        let cases = [
            ("two proposals", vec![ours.clone(), ours.clone()]),
            ("two ENCR transforms", vec![dup_encr]),
            ("a proposal number we never sent", vec![Proposal { num: 2, ..ours.clone() }]),
        ];
        for (what, proposals) in cases {
            let answer = hand_built_answer_with(&resp_sa, SecurityAssociation { proposals }, None);
            assert_eq!(complete(&answer), Err(IkeError::NoProposalChosen), "{what}");
        }
    }

    /// A peer's rekey request with `proposals` and a KE payload `ke` as is --
    /// any group id, even one no [`DhGroup`] stands for.
    fn peer_rekey_request_with_ke(peer_sa: &CompletedSaInit, proposals: Vec<Proposal>, ke: KeyExchange) -> Vec<u8> {
        let ts = TrafficSelectors::ipv4_full_tunnel();
        let inner = vec![
            (PayloadType::SecurityAssociation, SecurityAssociation { proposals }.to_bytes()),
            (PayloadType::Nonce, vec![0x33; 32]),
            (PayloadType::KeyExchange, ke.to_bytes()),
            (PayloadType::TrafficSelectorInitiator, ts.to_bytes()),
            (PayloadType::TrafficSelectorResponder, ts.to_bytes()),
        ];
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

    /// [`responder_process_rekey_with_pfs`] runs the policy its `dh_private`
    /// states. With a key (PFS required) a request without PFS, or on a
    /// group IKEv2 may not run (unknown, or MODP-768 per RFC 8247 §2.4), is
    /// refused; without one, a request insisting on such a group is refused
    /// too instead of being answered as "no PFS". A request that lists NONE
    /// next to its group (RFC 7296 §3.3.6) is answered either way, each
    /// side then deriving the same keys.
    #[test]
    fn the_rekey_responder_keeps_its_pfs_policy() {
        let (init_sa, resp_sa) = sa_pair();
        let (init_dh, resp_dh) = ([5u8; 32], [6u8; 32]);
        let answer = |req: &[u8], dh_private: Option<&[u8]>| {
            responder_process_rekey_with_pfs(&resp_sa, req, 0x2222_2222, &[0x44u8; 32], SkCipher::Aes256Gcm, dh_private, &[2u8; 8], None)
        };
        let gcm = (transform_id::AES_GCM_16, Some(256));

        let no_pfs =
            build_rekey_request_with_pfs(&init_sa, 2, 0xDEAD_BEEF, 0x1111_1111, &[0x33u8; 32], SkCipher::Aes256Gcm, None, &[1u8; 8]).unwrap();
        assert_eq!(answer(&no_pfs, Some(&resp_dh)).err(), Some(IkeError::NoProposalChosen), "PFS required, none offered");
        assert!(answer(&no_pfs, None).is_ok(), "control: no PFS either side");

        let unknown = peer_rekey_request_with_ke(
            &init_sa,
            vec![esp_proposal(1, 0x1111_1111, gcm, None, &[0x7777])],
            KeyExchange { dh_group: 0x7777, data: vec![9; 256] },
        );
        assert_eq!(answer(&unknown, Some(&resp_dh)).err(), Some(IkeError::NoProposalChosen), "unknown group, PFS required");
        assert_eq!(answer(&unknown, None).err(), Some(IkeError::NoProposalChosen), "unknown group, no PFS: not \"no PFS\"");

        let modp768 = peer_rekey_request_with_ke(
            &init_sa,
            vec![esp_proposal(1, 0x1111_1111, gcm, None, &[transform_id::MODP_768])],
            ke_of(DhGroup::Modp768, &init_dh),
        );
        assert_eq!(answer(&modp768, Some(&resp_dh)).err(), Some(IkeError::NoProposalChosen), "MODP-768 (RFC 8247)");

        // [MODP-2048, NONE]: PFS optional. Answered without it by a responder
        // with no key, and with it by one that has one.
        let optional = |order: &[u16]| {
            peer_rekey_request_with_ke(&init_sa, vec![esp_proposal(1, 0x1111_1111, gcm, None, order)], ke_of(DhGroup::Modp2048, &init_dh))
        };
        for (order, dh_private, pfs) in [
            (&[transform_id::MODP_2048, 0][..], None, None),
            (&[0, transform_id::MODP_2048][..], Some(&resp_dh[..]), Some((DhGroup::Modp2048, &init_dh[..]))),
        ] {
            let (resp, mut resp_child) = answer(&optional(order), dh_private).unwrap();
            let (_, _, _, ke) = read_rekey_response(&resp, &init_sa);
            assert_eq!(ke, pfs.is_some(), "{order:?}");
            let (mut init_child, _) = initiator_complete_child(
                &init_sa,
                &[0x33u8; 32],
                0x1111_1111,
                SkCipher::Aes256Gcm,
                pfs,
                &TrafficSelectors::ipv4_full_tunnel(),
                &resp,
            )
            .unwrap();
            let pkt = init_child.outbound.seal(b"optional PFS", next_header::IPV4).unwrap();
            assert_eq!(resp_child.inbound.open(&pkt).unwrap().0, b"optional PFS", "{order:?}");
        }
    }

    /// [`PfsPolicy::from_offer`] reads the local ESP offer's first proposal:
    /// no DH (or just NONE) is no PFS, groups make it required unless NONE
    /// sits next to them, and a group IKEv2 may not run is an error rather
    /// than no PFS.
    #[test]
    fn the_pfs_policy_is_read_off_the_esp_offer() {
        let gcm = (transform_id::AES_GCM_16, Some(256));
        let policy = |dh: &[u16]| PfsPolicy::from_offer(&SecurityAssociation { proposals: vec![esp_proposal(1, 0, gcm, None, dh)] });
        let groups = |g: &[DhGroup], optional| Ok(PfsPolicy { groups: g.to_vec(), optional });

        assert_eq!(policy(&[]), Ok(PfsPolicy::none()));
        assert_eq!(policy(&[0]), Ok(PfsPolicy::none()));
        assert_eq!(policy(&[transform_id::MODP_2048]), groups(&[DhGroup::Modp2048], false));
        assert_eq!(policy(&[transform_id::ECP256, transform_id::MODP_2048, 0]), groups(&[DhGroup::EcpP256, DhGroup::Modp2048], true));
        assert_eq!(policy(&[transform_id::ECP256, 0]).unwrap().proposed(), Some(DhGroup::EcpP256));
        assert!(policy(&[0x7777]).is_err(), "unknown group");
        assert!(policy(&[transform_id::MODP_768]).is_err(), "MODP-768, RFC 8247 §2.4");
        assert!(policy(&[transform_id::MODP_2048, 0x7777]).is_err(), "one bad group among good ones");
    }

    /// [`responder_answer_child_rekey`] (the session's) keeps our PFS policy:
    /// with PFS required, the DH-less proposals strongSwan offers next to its
    /// PFS ones don't do, and neither does a group we don't run; with PFS
    /// optional they do. MODP-768 and unknown groups are never PFS, and never
    /// "no PFS" either.
    #[test]
    fn a_peer_started_rekey_keeps_our_pfs_policy() {
        let (our_sa, peer_sa) = sa_pair();
        let peer_dh = [5u8; 32];
        let (cbc, gcm) = ((transform_id::AES_CBC, Some(256)), (transform_id::AES_GCM_16, Some(256)));
        let sha256 = Some(transform_id::AUTH_HMAC_SHA2_256_128);
        let strongswan_like = || {
            vec![
                esp_proposal(1, 0x2222_2222, cbc, sha256, &[transform_id::MODP_2048]),
                esp_proposal(2, 0x2222_2222, cbc, sha256, &[]),
                esp_proposal(3, 0x2222_2222, gcm, None, &[]),
            ]
        };
        let offer = |dh: &[u16]| SecurityAssociation { proposals: vec![esp_proposal(1, 0, gcm, None, dh)] };
        let required = PfsPolicy::from_offer(&offer(&[transform_id::MODP_2048])).unwrap();
        let optional = PfsPolicy::from_offer(&offer(&[transform_id::MODP_2048, 0])).unwrap();
        let ts = TrafficSelectors::ipv4_full_tunnel();
        let answer = |req: &[u8], pfs: &PfsPolicy| {
            responder_answer_child_rekey(&our_sa, req, 0x1111_1111, &[0x44u8; 32], SkCipher::Aes256Gcm, pfs, &[6u8; 32], &[2u8; 8])
                .map(|(resp, _)| read_rekey_response(&resp, &peer_sa))
        };

        let req = peer_rekey_request(&peer_sa, strongswan_like(), Some((DhGroup::Modp2048, &peer_dh)), &ts);
        assert_eq!(answer(&req, &required).err(), Some(IkeError::NoProposalChosen), "PFS required: the DH-less GCM proposal won't do");
        let (proposal, _, _, ke) = answer(&req, &optional).unwrap();
        assert_eq!((proposal.num, ke), (3, false), "PFS optional: it will");

        let gcm_modp2048 = vec![esp_proposal(1, 0x2222_2222, gcm, None, &[transform_id::MODP_2048])];
        let req = peer_rekey_request(&peer_sa, gcm_modp2048, Some((DhGroup::Modp2048, &peer_dh)), &ts);
        let (_, _, _, ke) = answer(&req, &required).unwrap();
        assert!(ke, "control: our group, answered with our KE");

        let gcm_ecp256 = vec![esp_proposal(1, 0x2222_2222, gcm, None, &[transform_id::ECP256])];
        let req = peer_rekey_request(&peer_sa, gcm_ecp256, Some((DhGroup::EcpP256, &peer_dh)), &ts);
        assert_eq!(answer(&req, &required).err(), Some(IkeError::NoProposalChosen), "a group our policy doesn't run");
        assert!(answer(&req, &PfsPolicy::none()).unwrap().3, "no policy of our own: the peer's group stands");

        // Our group offered, but the KE is of another one: INVALID_KE_PAYLOAD
        // naming ours (§1.3), for the peer to retry with it.
        let gcm_both = vec![esp_proposal(1, 0x2222_2222, gcm, None, &[transform_id::ECP256, transform_id::MODP_2048])];
        let req = peer_rekey_request(&peer_sa, gcm_both, Some((DhGroup::EcpP256, &peer_dh)), &ts);
        assert_eq!(answer(&req, &required).err(), Some(IkeError::InvalidKeGroup(transform_id::MODP_2048)));

        let gcm_modp768 = vec![esp_proposal(1, 0x2222_2222, gcm, None, &[transform_id::MODP_768])];
        let req = peer_rekey_request(&peer_sa, gcm_modp768, Some((DhGroup::Modp768, &peer_dh)), &ts);
        assert_eq!(answer(&req, &PfsPolicy::none()).err(), Some(IkeError::NoProposalChosen), "MODP-768, RFC 8247 §2.4");

        let gcm_unknown = vec![esp_proposal(1, 0x2222_2222, gcm, None, &[0x7777])];
        let req = peer_rekey_request_with_ke(&peer_sa, gcm_unknown, KeyExchange { dh_group: 0x7777, data: vec![9; 256] });
        assert_eq!(answer(&req, &PfsPolicy::none()).err(), Some(IkeError::NoProposalChosen), "unknown group");
    }

    /// A peer's rekey request whose SA payload body is `sa_body` as it went on
    /// the wire -- proposals `SecurityAssociation` cannot express, with an
    /// attribute we don't understand -- and `ke` as its KE payload, if any.
    fn peer_rekey_request_wire(peer_sa: &CompletedSaInit, sa_body: &[u8], ke: Option<KeyExchange>) -> Vec<u8> {
        let ts = TrafficSelectors::ipv4_full_tunnel();
        let mut inner = vec![(PayloadType::SecurityAssociation, sa_body.to_vec()), (PayloadType::Nonce, vec![0x33; 32])];
        inner.extend(ke.map(|ke| (PayloadType::KeyExchange, ke.to_bytes())));
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

    /// RFC 7296 §3.3.6: a transform with an attribute we do not understand is
    /// unacceptable -- not absent. An ESP proposal whose ESN, integrity or DH
    /// transform is one of those was not offered "without" it: the answer would
    /// leave a type out that the proposal has (§2.7), or run without the PFS it
    /// insists on. Its siblings and the peer's other proposals are processed
    /// as usual.
    #[test]
    fn an_esp_proposal_with_a_transform_we_cannot_read_is_not_answered_as_without_it() {
        use crate::ikev2::payload::test_wire::{proposal, sa, transform, KEY_LENGTH_256, UNKNOWN_ATTRIBUTE};
        let (our_sa, peer_sa) = sa_pair();
        let spi = 0x2222_2222u32.to_be_bytes();
        let gcm = || transform(transform_type::ENCR, transform_id::AES_GCM_16, &KEY_LENGTH_256);
        let esn_none = || transform(transform_type::ESN, transform_id::ESN_NONE, &[]);
        let unreadable = |ty: u8, id: u16| transform(ty, id, &UNKNOWN_ATTRIBUTE);
        let esp = |num: u8, transforms: &[Vec<u8>]| proposal(num, protocol_id::ESP, &spi, transforms);
        let answer = |body: Vec<u8>| {
            let req = peer_rekey_request_wire(&peer_sa, &body, None);
            responder_answer_child_rekey(&our_sa, &req, 0x1111_1111, &[0x44u8; 32], SkCipher::Aes256Gcm, &PfsPolicy::none(), &[6u8; 32], &[2u8; 8])
                .map(|(resp, _)| read_rekey_response(&resp, &peer_sa).0)
        };

        assert_eq!(answer(sa(&[esp(1, &[gcm(), esn_none()])])).unwrap().num, 1, "control");
        let refused = [
            ("a DH we cannot read", esp(1, &[gcm(), esn_none(), unreadable(transform_type::DH, transform_id::MODP_2048)])),
            ("an ESN we cannot read, in place of the ESN_NONE", esp(1, &[gcm(), unreadable(transform_type::ESN, transform_id::ESN_NONE)])),
            ("an integrity algorithm we cannot read", esp(1, &[gcm(), unreadable(transform_type::INTEG, transform_id::AUTH_HMAC_SHA2_256_128), esn_none()])),
            ("a transform type nobody knows, unreadable", esp(1, &[gcm(), esn_none(), unreadable(99, 7)])),
        ];
        for (what, p) in refused {
            assert_eq!(answer(sa(std::slice::from_ref(&p))).err(), Some(IkeError::NoProposalChosen), "{what}");
            // ... and the next proposal, which is fine, is the one answered.
            assert_eq!(answer(sa(&[p, esp(2, &[gcm(), esn_none()])])).unwrap().num, 2, "{what}, then a proposal we take");
        }
        // A sibling we cannot read leaves the transform we can: the ENCR here.
        let sibling = esp(1, &[unreadable(transform_type::ENCR, transform_id::AES_GCM_16), gcm(), esn_none()]);
        assert_eq!(answer(sa(&[sibling])).unwrap().num, 1, "an unreadable ENCR next to the one we run");
    }

    /// RFC 7296 §2.7, §3.3.6: what a responder answers is one of the proposals
    /// the peer sent, by its number, and every transform of it is one the peer
    /// sent, as it sent it ("attributes ... returned unmodified"): the check the
    /// peer, as the initiator, makes of the answer to its offer.
    fn assert_answer_is_from_offer(offered: &[Proposal], answered: &Proposal) {
        let proposal = offered.iter().find(|p| p.num == answered.num).expect("the answer names a proposal the peer sent");
        for t in &answered.transforms {
            assert!(proposal.transforms.contains(t), "{t:?} is not a transform of proposal {}, as it was sent: {proposal:?}", answered.num);
        }
        negotiate::accepted_proposal(
            &SecurityAssociation { proposals: vec![answered.clone()] },
            &SecurityAssociation { proposals: offered.to_vec() },
        )
        .expect("the answer is consistent with the offer");
    }

    /// RFC 7296 §3.3.5, §3.3.6: a DH, integrity or ESN transform takes no Key
    /// Length ("MUST NOT be used with transforms that use a fixed-length key"),
    /// so one that carries it is a transform we do not understand --
    /// unacceptable, and its siblings of the type are weighed as usual. It is
    /// not a group, a NONE or an ESN to accept and answer with the attribute
    /// stripped: the answer's transform must be the offered one, "attributes
    /// ... returned unmodified".
    #[test]
    fn a_fixed_length_transform_with_a_key_length_is_not_one_we_take() {
        let (our_sa, peer_sa) = sa_pair();
        let peer_dh = [5u8; 32];
        let tf = |transform_type: u8, transform_id: u16, key_length: Option<u16>| Transform { transform_type, transform_id, key_length };
        let esp = |num: u8, middle: Vec<Transform>| {
            let mut transforms = vec![tf(transform_type::ENCR, transform_id::AES_GCM_16, Some(256))];
            transforms.extend(middle);
            transforms.push(tf(transform_type::ESN, transform_id::ESN_NONE, None));
            Proposal { num, protocol_id: protocol_id::ESP, spi: 0x2222_2222u32.to_be_bytes().to_vec(), transforms }
        };
        let dh = |id: u16, key_length: Option<u16>| tf(transform_type::DH, id, key_length);
        let integ_none = |key_length: Option<u16>| tf(transform_type::INTEG, 0, key_length);
        let (modp, ecp) = (transform_id::MODP_2048, transform_id::ECP256);
        let required = |group: u16| PfsPolicy::from_offer(&SecurityAssociation { proposals: vec![esp(1, vec![dh(group, None)])] }).unwrap();

        // The answer to `proposals` (with a KE of `ke`), which -- when there is
        // one -- is checked against the offer too.
        let answer = |proposals: Vec<Proposal>, ke: Option<DhGroup>, pfs: &PfsPolicy| {
            let req = peer_rekey_request(&peer_sa, proposals.clone(), ke.map(|g| (g, &peer_dh[..])), &TrafficSelectors::ipv4_full_tunnel());
            responder_answer_child_rekey(&our_sa, &req, 0x1111_1111, &[0x44u8; 32], SkCipher::Aes256Gcm, pfs, &[6u8; 32], &[2u8; 8]).map(|(resp, _)| {
                let (answered, ..) = read_rekey_response(&resp, &peer_sa);
                assert_answer_is_from_offer(&proposals, &answered);
                answered
            })
        };
        let dh_of = |p: &Proposal| p.transforms.iter().filter(|t| t.transform_type == transform_type::DH).cloned().collect::<Vec<_>>();
        let integ_of = |p: &Proposal| p.transforms.iter().filter(|t| t.transform_type == transform_type::INTEG).cloned().collect::<Vec<_>>();

        // A group with a Key Length is no group we run; the plain one is.
        let group = Some(DhGroup::Modp2048);
        assert_eq!(dh_of(&answer(vec![esp(1, vec![dh(modp, None)])], group, &required(modp)).unwrap()), [dh(modp, None)], "control: the group as offered");
        assert_eq!(answer(vec![esp(1, vec![dh(modp, Some(2048))])], group, &required(modp)), Err(IkeError::NoProposalChosen), "the group with a Key Length");
        assert_eq!(
            answer(vec![esp(1, vec![dh(modp, Some(2048))]), esp(2, vec![dh(modp, None)])], group, &required(modp)).unwrap().num,
            2,
            "the group with a Key Length, then a proposal with the plain one"
        );
        assert_eq!(
            dh_of(&answer(vec![esp(1, vec![dh(modp, Some(2048)), dh(modp, None)])], group, &required(modp)).unwrap()),
            [dh(modp, None)],
            "the group with a Key Length next to the plain one, in one proposal"
        );

        // Two alternatives of the type: the one we can read is taken, on its own KE; a KE of the other is
        // INVALID_KE_PAYLOAD for the one we can.
        let alternatives = || vec![esp(1, vec![dh(modp, Some(2048)), dh(ecp, None)])];
        assert_eq!(dh_of(&answer(alternatives(), Some(DhGroup::EcpP256), &PfsPolicy::none()).unwrap()), [dh(ecp, None)], "a KE of the group that is fine");
        assert_eq!(
            answer(alternatives(), group, &PfsPolicy::none()),
            Err(IkeError::InvalidKeGroup(ecp)),
            "a KE of the group with the Key Length: retry with the other"
        );

        // DH NONE with a Key Length is not "PFS left optional", and a proposal with only that is not one without DH.
        let none_answer = |middle: Vec<Transform>| answer(vec![esp(1, middle)], None, &PfsPolicy::none());
        assert_eq!(dh_of(&none_answer(vec![dh(0, None)]).unwrap()), [dh(0, None)], "control: DH NONE, no PFS");
        assert_eq!(none_answer(vec![dh(0, Some(128))]), Err(IkeError::NoProposalChosen), "DH NONE with a Key Length");
        assert_eq!(dh_of(&none_answer(vec![dh(0, Some(128)), dh(0, None)]).unwrap()), [dh(0, None)], "the DH NONE with a Key Length next to the plain one");

        // An AEAD cipher with an integrity NONE that carries a Key Length is not the "single NONE" of §3.3: it wants an integrity algorithm.
        assert_eq!(integ_of(&none_answer(vec![integ_none(None)]).unwrap()), [integ_none(None)], "control: INTEG NONE");
        assert_eq!(none_answer(vec![integ_none(Some(128))]), Err(IkeError::NoProposalChosen), "INTEG NONE with a Key Length");
        assert_eq!(
            integ_of(&none_answer(vec![integ_none(Some(128)), integ_none(None)]).unwrap()),
            [integ_none(None)],
            "the INTEG NONE with a Key Length next to the plain one"
        );
        let sha256 = tf(transform_type::INTEG, transform_id::AUTH_HMAC_SHA2_256_128, None);
        assert_eq!(none_answer(vec![sha256.clone(), integ_none(Some(128))]), Err(IkeError::NoProposalChosen), "an integrity algorithm we do not use, and a NONE with a Key Length");
        assert_eq!(integ_of(&none_answer(vec![sha256, integ_none(None)]).unwrap()), [integ_none(None)], "an integrity algorithm we do not use next to the NONE");

        // ESN with a Key Length is not ESN_NONE.
        let esn = |key_length: Option<u16>| tf(transform_type::ESN, transform_id::ESN_NONE, key_length);
        let with_esn = |esns: Vec<Transform>| {
            let mut p = esp(1, vec![]);
            p.transforms.retain(|t| t.transform_type != transform_type::ESN);
            p.transforms.extend(esns);
            answer(vec![p], None, &PfsPolicy::none())
        };
        assert_eq!(with_esn(vec![esn(None)]).unwrap().transforms.last(), Some(&esn(None)), "control: ESN_NONE");
        assert_eq!(with_esn(vec![esn(Some(32))]), Err(IkeError::NoProposalChosen), "ESN_NONE with a Key Length");
        assert_eq!(with_esn(vec![esn(Some(32)), esn(None)]).unwrap().transforms.last(), Some(&esn(None)), "the ESN_NONE with a Key Length next to the plain one");
    }

    /// The responders of a CHILD SA rekey the peer started weigh a Key Length
    /// and an attribute they cannot read alike, whichever entry point a caller
    /// has (RFC 7296 §3.3.5, §3.3.6): the older [`responder_process_rekey`], and
    /// [`responder_process_rekey_with_pfs`] and [`responder_answer_child_rekey`]
    /// with no PFS and with a group. A Key Length on a DH, integrity or ESN
    /// transform -- which take none -- and an attribute we do not understand each
    /// make that transform unacceptable, not absent: the proposal is passed
    /// over for the next one, and the transforms of its type that are fine
    /// are weighed as usual.
    #[test]
    fn every_rekey_responder_takes_no_transform_with_a_key_length_it_must_not_have_or_an_attribute_it_cannot_read() {
        use crate::ikev2::payload::test_wire::{proposal, sa, transform, KEY_LENGTH_128, KEY_LENGTH_256, UNKNOWN_ATTRIBUTE};
        let (our_sa, peer_sa) = sa_pair();
        let (nr, iv, resp_dh, peer_dh) = ([0x44u8; 32], [2u8; 8], [6u8; 32], [5u8; 32]);
        let spi = 0x2222_2222u32.to_be_bytes();
        let gcm = || transform(transform_type::ENCR, transform_id::AES_GCM_16, &KEY_LENGTH_256);
        let esn_none = || transform(transform_type::ESN, transform_id::ESN_NONE, &[]);
        let group = || transform(transform_type::DH, transform_id::MODP_2048, &[]);
        let with_kl = |ty: u8, id: u16| transform(ty, id, &KEY_LENGTH_128);
        let unreadable = |ty: u8, id: u16| transform(ty, id, &UNKNOWN_ATTRIBUTE);
        let esp = |num: u8, transforms: &[Vec<u8>]| proposal(num, protocol_id::ESP, &spi, transforms);
        let ke = || KeyExchange { dh_group: transform_id::MODP_2048, data: DhGroup::Modp2048.public(&peer_dh) };
        let answered = |response: Vec<u8>| read_rekey_response(&response, &peer_sa).0;
        let required = PfsPolicy::from_offer(&SecurityAssociation {
            proposals: vec![esp_proposal(1, 0, (transform_id::AES_GCM_16, Some(256)), None, &[transform_id::MODP_2048])],
        })
        .unwrap();

        let old_api = |req: &[u8]| responder_process_rekey(&our_sa, req, 0x1111_1111, &nr, &iv, None).map(|(r, _)| answered(r));
        let no_key = |req: &[u8]| {
            responder_process_rekey_with_pfs(&our_sa, req, 0x1111_1111, &nr, SkCipher::Aes256Gcm, None, &iv, None).map(|(r, _)| answered(r))
        };
        let no_pfs_policy = |req: &[u8]| {
            responder_answer_child_rekey(&our_sa, req, 0x1111_1111, &nr, SkCipher::Aes256Gcm, &PfsPolicy::none(), &resp_dh, &iv).map(|(r, _)| answered(r))
        };
        let with_key = |req: &[u8]| {
            responder_process_rekey_with_pfs(&our_sa, req, 0x1111_1111, &nr, SkCipher::Aes256Gcm, Some(&resp_dh), &iv, None).map(|(r, _)| answered(r))
        };
        let group_policy = |req: &[u8]| {
            responder_answer_child_rekey(&our_sa, req, 0x1111_1111, &nr, SkCipher::Aes256Gcm, &required, &resp_dh, &iv).map(|(r, _)| answered(r))
        };
        type Entry<'a> = (&'a str, &'a dyn Fn(&[u8]) -> Result<Proposal, IkeError>);
        let without_pfs: [Entry; 3] = [
            ("responder_process_rekey", &old_api),
            ("responder_process_rekey_with_pfs, no key", &no_key),
            ("responder_answer_child_rekey, no PFS policy", &no_pfs_policy),
        ];
        let with_pfs: [Entry; 2] = [("responder_process_rekey_with_pfs, a key", &with_key), ("responder_answer_child_rekey, a PFS group", &group_policy)];
        let transforms_of = |p: &Proposal, ty: u8| p.transforms.iter().filter(|t| t.transform_type == ty).cloned().collect::<Vec<_>>();
        let plain = |ty: u8, id: u16| Transform { transform_type: ty, transform_id: id, key_length: None };

        // No PFS: a proposal is refused for the transform it cannot take, and the next one is answered.
        let refused_without_pfs = [
            ("DH NONE with a Key Length", esp(1, &[gcm(), esn_none(), with_kl(transform_type::DH, 0)])),
            ("INTEG NONE with a Key Length", esp(1, &[gcm(), with_kl(transform_type::INTEG, 0), esn_none()])),
            ("ESN NONE with a Key Length", esp(1, &[gcm(), with_kl(transform_type::ESN, transform_id::ESN_NONE)])),
            ("a DH we cannot read", esp(1, &[gcm(), esn_none(), unreadable(transform_type::DH, transform_id::MODP_2048)])),
            ("an integrity algorithm we cannot read", esp(1, &[gcm(), unreadable(transform_type::INTEG, transform_id::AUTH_HMAC_SHA2_256_128), esn_none()])),
            ("an ESN we cannot read", esp(1, &[gcm(), unreadable(transform_type::ESN, transform_id::ESN_NONE)])),
        ];
        for (name, entry) in &without_pfs {
            let request = |proposals: &[Vec<u8>]| peer_rekey_request_wire(&peer_sa, &sa(proposals), None);
            assert_eq!(entry(&request(&[esp(1, &[gcm(), esn_none()])])).unwrap().num, 1, "{name}: control");
            for (what, refused) in &refused_without_pfs {
                assert_eq!(entry(&request(std::slice::from_ref(refused))), Err(IkeError::NoProposalChosen), "{name}: {what}");
                let next = entry(&request(&[refused.clone(), esp(2, &[gcm(), esn_none()])])).unwrap_or_else(|e| panic!("{name}: {what}, then a proposal that is fine: {e:?}"));
                assert_eq!(next.num, 2, "{name}: {what}, then a proposal that is fine");
            }
            // The transform with the Key Length next to the plain one of its type, in one proposal: the plain one is answered.
            let dh_siblings = esp(1, &[gcm(), esn_none(), with_kl(transform_type::DH, 0), transform(transform_type::DH, 0, &[])]);
            assert_eq!(transforms_of(&entry(&request(&[dh_siblings])).unwrap(), transform_type::DH), [plain(transform_type::DH, 0)], "{name}: DH NONE, both kinds");
            let integ_siblings = esp(1, &[gcm(), with_kl(transform_type::INTEG, 0), transform(transform_type::INTEG, 0, &[]), esn_none()]);
            assert_eq!(transforms_of(&entry(&request(&[integ_siblings])).unwrap(), transform_type::INTEG), [plain(transform_type::INTEG, 0)], "{name}: INTEG NONE, both kinds");
        }

        // PFS: the group has to be one we can read, plain, and the transforms around it too.
        let refused_with_pfs = [
            ("the group with a Key Length", esp(1, &[gcm(), esn_none(), with_kl(transform_type::DH, transform_id::MODP_2048)])),
            ("a group we cannot read", esp(1, &[gcm(), esn_none(), unreadable(transform_type::DH, transform_id::MODP_2048)])),
            ("INTEG NONE with a Key Length", esp(1, &[gcm(), with_kl(transform_type::INTEG, 0), esn_none(), group()])),
            ("ESN NONE with a Key Length", esp(1, &[gcm(), with_kl(transform_type::ESN, transform_id::ESN_NONE), group()])),
        ];
        for (name, entry) in &with_pfs {
            let request = |proposals: &[Vec<u8>]| peer_rekey_request_wire(&peer_sa, &sa(proposals), Some(ke()));
            let control = entry(&request(&[esp(1, &[gcm(), esn_none(), group()])])).unwrap();
            assert_eq!((control.num, transforms_of(&control, transform_type::DH)), (1, vec![plain(transform_type::DH, transform_id::MODP_2048)]), "{name}: control");
            for (what, refused) in &refused_with_pfs {
                assert_eq!(entry(&request(std::slice::from_ref(refused))), Err(IkeError::NoProposalChosen), "{name}: {what}");
                let next = entry(&request(&[refused.clone(), esp(2, &[gcm(), esn_none(), group()])])).unwrap_or_else(|e| panic!("{name}: {what}, then a proposal that is fine: {e:?}"));
                assert_eq!(next.num, 2, "{name}: {what}, then a proposal that is fine");
            }
        }
    }

    /// RFC 7296 §2.7, §3.3.6: [`responder_process_rekey_with_pfs`] answers with
    /// a proposal the peer offered -- the first that has the cipher running on
    /// the tunnel, exactly, and the PFS its own policy asks -- and with the
    /// SPI of that proposal, not with what it would have offered itself to a
    /// first proposal it never looked into. A cipher, or a key length, the peer
    /// did not offer is `NoProposalChosen`, not a rekey the peer would read
    /// back as an answer to something else.
    #[test]
    fn the_rekey_responder_answers_only_with_a_proposal_the_peer_offered() {
        let (init_sa, resp_sa) = sa_pair();
        let (init_dh, resp_dh) = ([5u8; 32], [6u8; 32]);
        let (gcm256, gcm128, cbc256) = ((transform_id::AES_GCM_16, Some(256)), (transform_id::AES_GCM_16, Some(128)), (transform_id::AES_CBC, Some(256)));
        let sha256 = Some(transform_id::AUTH_HMAC_SHA2_256_128);
        let (modp, ecp) = (transform_id::MODP_2048, transform_id::ECP256);
        let (spi_a, spi_b, spi_c) = (0xA0A0_A0A0, 0xB0B0_B0B0, 0xC0C0_C0C0);
        let ts = TrafficSelectors::ipv4_full_tunnel();
        // The answer to `proposals` and a KE of MODP-2048 when `ke`, with the child SA it derived.
        let answer = |proposals: &[Proposal], ke: bool, dh_private: Option<&[u8]>| {
            let req = peer_rekey_request(&init_sa, proposals.to_vec(), ke.then_some((DhGroup::Modp2048, &init_dh[..])), &ts);
            responder_process_rekey_with_pfs(&resp_sa, &req, 0x2222_2222, &[0x44u8; 32], SkCipher::Aes256Gcm, dh_private, &[2u8; 8], None).map(|(resp, child)| {
                let (answered, _, _, ke_back) = read_rekey_response(&resp, &init_sa);
                assert_answer_is_from_offer(proposals, &answered);
                (answered, ke_back, child)
            })
        };
        let refused = |proposals: &[Proposal], ke: bool, dh_private: Option<&[u8]>| answer(proposals, ke, dh_private).err();
        let dh_of = |p: &Proposal| p.transforms.iter().filter(|t| t.transform_type == transform_type::DH).map(|t| t.transform_id).collect::<Vec<_>>();

        // Control: our cipher, offered.
        let (answered, ke, child) = answer(&[esp_proposal(1, spi_a, gcm256, None, &[])], false, None).unwrap();
        assert_eq!((answered.num, ke, child.outbound.spi(), child.inbound.spi()), (1, false, spi_a, 0x2222_2222));

        // The cipher, or its key length, is not offered.
        let cbc = esp_proposal(1, spi_a, cbc256, sha256, &[]);
        assert_eq!(refused(std::slice::from_ref(&cbc), false, None), Some(IkeError::NoProposalChosen), "AES-CBC only");
        assert_eq!(refused(&[esp_proposal(1, spi_a, gcm128, None, &[])], false, None), Some(IkeError::NoProposalChosen), "AES-GCM-128 only");
        assert_eq!(
            refused(&[cbc.clone(), esp_proposal(2, spi_b, gcm128, None, &[])], false, None),
            Some(IkeError::NoProposalChosen),
            "AES-CBC and AES-GCM-128"
        );

        // The proposal that has it is the one answered, whichever it is, and its SPI the one used.
        let (answered, _, child) =
            answer(&[cbc, esp_proposal(2, spi_b, gcm128, None, &[]), esp_proposal(3, spi_c, gcm256, None, &[])], false, None).unwrap();
        assert_eq!((answered.num, child.outbound.spi()), (3, spi_c), "the third of three proposals");

        // PFS required (a key): a proposal with a group and the KE of it; the others do not do.
        let pfs = |proposals: &[Proposal], ke: bool| answer(proposals, ke, Some(&resp_dh));
        let (answered, ke, _) = pfs(&[esp_proposal(1, spi_a, gcm256, None, &[modp])], true).unwrap();
        assert_eq!((dh_of(&answered), ke), (vec![modp], true), "control");
        let (answered, ke, child) =
            pfs(&[esp_proposal(1, spi_a, gcm256, None, &[]), esp_proposal(2, spi_b, gcm256, None, &[modp])], true).unwrap();
        assert_eq!((answered.num, dh_of(&answered), ke, child.outbound.spi()), (2, vec![modp], true, spi_b), "the one with the group, after one without");
        let (answered, ..) = pfs(&[esp_proposal(1, spi_a, gcm128, None, &[modp]), esp_proposal(2, spi_b, gcm256, None, &[ecp, modp])], true).unwrap();
        assert_eq!((answered.num, dh_of(&answered)), (2, vec![modp]), "the group is the KE's, on the proposal with our cipher");
        assert_eq!(pfs(&[esp_proposal(1, spi_a, gcm256, None, &[])], false).err(), Some(IkeError::NoProposalChosen), "no group, no KE");
        assert_eq!(pfs(&[esp_proposal(1, spi_a, gcm256, None, &[modp])], false).err(), Some(IkeError::MissingPayload("KE")), "a group, no KE");
        assert_eq!(pfs(&[esp_proposal(1, spi_a, gcm128, None, &[modp])], true).err(), Some(IkeError::NoProposalChosen), "a group, another key length");
        assert_eq!(pfs(&[esp_proposal(1, spi_a, gcm256, None, &[ecp])], true).err(), Some(IkeError::NoProposalChosen), "a KE of a group no proposal names");
        assert_eq!(
            pfs(&[esp_proposal(1, spi_a, gcm256, None, &[ecp]), esp_proposal(2, spi_b, gcm256, None, &[])], true).err(),
            Some(IkeError::NoProposalChosen),
            "a KE of a group no proposal names, and one without PFS"
        );

        // PFS optional (no key): NONE among the groups, or none at all, is answered without it -- with the NONE
        // where it was offered -- and a proposal that insists on a group is not.
        let no_pfs = |proposals: &[Proposal]| answer(proposals, true, None);
        let (answered, ke, _) = no_pfs(&[esp_proposal(1, spi_a, gcm256, None, &[modp, 0])]).unwrap();
        assert_eq!((dh_of(&answered), ke), (vec![0], false), "a group or NONE");
        let (answered, ke, _) = no_pfs(&[esp_proposal(1, spi_a, gcm256, None, &[])]).unwrap();
        assert_eq!((dh_of(&answered), ke), (vec![], false), "no DH");
        let (answered, ..) = no_pfs(&[esp_proposal(1, spi_a, gcm256, None, &[modp]), esp_proposal(2, spi_b, gcm256, None, &[])]).unwrap();
        assert_eq!(answered.num, 2, "the one that leaves PFS out, after one that insists on it");
        assert_eq!(no_pfs(&[esp_proposal(1, spi_a, gcm256, None, &[modp])]).err(), Some(IkeError::NoProposalChosen), "a group and no key");
        assert_eq!(no_pfs(&[esp_proposal(1, spi_a, gcm128, None, &[modp, 0])]).err(), Some(IkeError::NoProposalChosen), "no PFS, another key length");
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

    /// The three ways the responder answers a peer's `CREATE_CHILD_SA` and the
    /// initiator's completion, each refusing the peer's nonce when it is
    /// `bad`, with `error`, and taking it on at `good` (ours is always 32 octets).
    fn check_child_nonces(init_sa: &CompletedSaInit, resp_sa: &CompletedSaInit, bad: &[u8], good: &[u8], error: IkeError) {
        let ours = [0x44u8; 32];
        let answer = |ni: &[u8]| {
            let req = build_rekey_request(init_sa, 2, 0xDEAD_BEEF, 0x1111_1111, ni, &[1u8; 8]).unwrap();
            let processed = responder_process_rekey(resp_sa, &req, 0x2222_2222, &ours, &[2u8; 8], None).map(|_| ());
            let answered = responder_answer_child_rekey(resp_sa, &req, 0x2222_2222, &ours, SkCipher::Aes256Gcm, &PfsPolicy::none(), &[6u8; 32], &[2u8; 8])
                .map(|_| ());
            (processed, answered)
        };
        let complete = |nr: &[u8]| {
            let req = build_rekey_request(init_sa, 2, 0xDEAD_BEEF, 0x1111_1111, &ours, &[1u8; 8]).unwrap();
            let (resp, _) = responder_process_rekey(resp_sa, &req, 0x2222_2222, nr, &[2u8; 8], None).unwrap();
            initiator_complete_rekey(init_sa, &ours, 0x1111_1111, &resp).map(|_| ())
        };
        assert_eq!(answer(bad), (Err(error.clone()), Err(error.clone())), "Ni of {} octets", bad.len());
        assert_eq!(complete(bad), Err(error), "Nr of {} octets", bad.len());
        assert_eq!(answer(good), (Ok(()), Ok(())), "Ni of {} octets", good.len());
        assert_eq!(complete(good), Ok(()), "Nr of {} octets", good.len());
    }

    /// RFC 7296 §3.9: "The size of the Nonce Data MUST be between 16 and 256
    /// octets, inclusive" -- a `CREATE_CHILD_SA`'s Ni and Nr as much as
    /// `IKE_SA_INIT`'s. An empty, 15- or 257-octet nonce is refused whichever
    /// side receives it; 16 and 256 octets are taken on.
    #[test]
    fn a_child_sa_nonce_out_of_range_is_refused_on_both_sides() {
        let (init_sa, resp_sa) = sa_pair();
        let range = IkeError::Crypto("nonce length out of range (16-256 bytes)");
        check_child_nonces(&init_sa, &resp_sa, &[], &[0x33; 16], range.clone());
        check_child_nonces(&init_sa, &resp_sa, &[0x33; 15], &[0x33; 16], range.clone());
        check_child_nonces(&init_sa, &resp_sa, &[0x33; 257], &[0x33; 256], range);
    }

    /// RFC 7296 §2.10: the nonces of a `CREATE_CHILD_SA` feed the IKE SA's
    /// PRF (KEYMAT = prf+(SK_d, Ni | Nr), §2.17), so each MUST be at least
    /// half its key -- 32 octets under PRF_HMAC_SHA2_512, 24 under
    /// PRF_HMAC_SHA2_384.
    #[test]
    fn a_child_sa_nonce_shorter_than_half_the_prf_key_is_refused() {
        use crate::ikev2::payload::transform_id::{PRF_HMAC_SHA2_384, PRF_HMAC_SHA2_512};
        let short = IkeError::Crypto("nonce shorter than half the negotiated PRF's key");
        for (prf, half) in [(PRF_HMAC_SHA2_512, 32), (PRF_HMAC_SHA2_384, 24)] {
            let (init_sa, resp_sa) = sa_pair_with_prf(prf);
            check_child_nonces(&init_sa, &resp_sa, &vec![0x33; half - 1], &vec![0x33; half], short.clone());
        }
    }
}
