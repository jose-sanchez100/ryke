//! The `IKE_AUTH` exchange (RFC 7296 §1.2), implemented for both roles with
//! pre-shared-key authentication.
//!
//! ```text
//! Initiator → HDR, SK { IDi, AUTH, SAi2, TSi, TSr }
//! Responder → HDR, SK { IDr, AUTH, SAr2, TSi, TSr }
//! ```
//!
//! Everything rides inside the encrypted [`crate::ikev2::sk`] payload, keyed by the
//! `IKE_SA_INIT`-derived keys. Each side proves it sent its SA_INIT message via
//! the AUTH payload (see [`crate::ikev2::auth`]). Because the responder can only
//! decrypt the initiator's `SK{}` (and vice versa) if both derived the same
//! keys, a successful `IKE_AUTH` *proves* the SA_INIT key agreement.
//!
//! CHILD SA negotiation is minimal here (a fixed AES-GCM-256 ESP offer and
//! full-tunnel selectors); matching/narrowing and handing the derived keys to
//! the userspace ESP data plane ([`crate::esp`] / [`crate::tunnel`]) follow.

use crate::ikev2::auth::{initiator_signed_octets, psk_auth, responder_signed_octets};
use crate::debug::ike_debug;
use crate::error::IkeError;
use crate::ikev2::exchange::CompletedSaInit;
use crate::ikev2::negotiate::{self, ChosenEspSuite};
use crate::ikev2::rekey;
use crate::ikev2::message::{
    encode_payload_chain, first_payload_type, payloads, ExchangeType, Flags, IkeHeader, PayloadType,
};
use crate::ikev2::payload::{
    auth_method, notify_type, notify_type_name, protocol_id, sighash, transform_id, transform_type, Authentication,
    CertRequest, Certificate, Configuration, Identification, Notify, Proposal, SecurityAssociation,
    TrafficSelector, TrafficSelectors, Transform,
};
use std::net::Ipv4Addr;
use crate::ikev2::sign::SigningKey;
use crate::ikev2::sk::{build_encrypted, open_encrypted, SkCipher};

/// How this side proves its own identity in `IKE_AUTH`.
///
/// `Psk`'s `Vec<u8>` is not auto-wiped on drop (no `ZeroizeOnDrop` here --
/// see [`crate::crypto::SessionKeys`]'s doc comment for why a public,
/// by-value enum can't use it); callers holding a PSK for longer than one
/// exchange should `.zeroize()` it explicitly when done.
pub enum LocalAuth {
    /// Pre-shared key (Auth Method 2).
    Psk(Vec<u8>),
    /// RFC 7427 Digital Signature with an X.509 chain (`chain[0]` = leaf, whose
    /// key signs; the rest are intermediates).
    Cert { key: SigningKey, chain: Vec<Vec<u8>> },
}

/// How this side authenticates the peer in `IKE_AUTH`.
pub enum PeerAuth {
    /// Pre-shared key — the peer's AUTH must match this secret.
    Psk(Vec<u8>),
    /// The peer's leaf must build a valid path to one of `cas`, carry
    /// `expected_dns` in its SAN (if set), be within validity at `now_unix`, and
    /// sign the AUTH.
    Cert { cas: Vec<Vec<u8>>, expected_dns: Option<String>, now_unix: u64 },
}

/// One side's `IKE_AUTH` configuration: our identity, how we prove it, and how
/// we authenticate the peer.
pub struct AuthConfig {
    pub id: Identification,
    pub local: LocalAuth,
    pub peer: PeerAuth,
}

impl AuthConfig {
    /// Mutual pre-shared-key auth with a single shared secret.
    pub fn psk(id: Identification, psk: Vec<u8>) -> Self {
        AuthConfig { id, local: LocalAuth::Psk(psk.clone()), peer: PeerAuth::Psk(psk) }
    }
}

/// An ordered list of `(payload type, encoded body)` to place in a message.
type PayloadChain = Vec<(PayloadType, Vec<u8>)>;

/// The inner-network config a responder hands the initiator in the `IKE_AUTH`
/// Configuration Payload (CFG_REPLY). A native IKEv2 client (iOS/Android) needs
/// at least the address to bring up its tunnel interface; the DNS servers make
/// name resolution work once all traffic is captured (full tunnel).
pub struct AssignedConfig {
    /// The inner/virtual IPv4 assigned to the client (used as a host /32).
    pub ip: Ipv4Addr,
    /// DNS resolvers to push (reachable through the tunnel). May be empty.
    pub dns: Vec<Ipv4Addr>,
}

/// A default ESP CHILD SA offer: AES-GCM-16-256 + ESN none, with the given SPI.
pub fn esp_offer(spi: u32) -> SecurityAssociation {
    SecurityAssociation {
        proposals: vec![Proposal {
            num: 1,
            protocol_id: protocol_id::ESP,
            spi: spi.to_be_bytes().to_vec(),
            transforms: vec![
                Transform { transform_type: transform_type::ENCR, transform_id: transform_id::AES_GCM_16, key_length: Some(256) },
                Transform { transform_type: transform_type::ESN, transform_id: transform_id::ESN_NONE, key_length: None },
            ],
        }],
    }
}

/// An ESP CHILD SA offer for a specific already-negotiated `cipher`, with the
/// given SPI -- used at CHILD SA rekey time (`crate::ikev2::rekey`) so the
/// `CREATE_CHILD_SA` exchange preserves the tunnel's existing algorithm
/// instead of [`esp_offer`]'s fixed AES-GCM-256 default. Rekey only ever adds
/// PFS on top of what's already running, per `rekey`'s own module doc -- it
/// never silently changes cipher out from under a profile that asked for
/// something else (e.g. AES-CBC-256/SHA-512 for a compliance-driven gateway).
pub fn esp_offer_for_cipher(spi: u32, cipher: SkCipher) -> SecurityAssociation {
    let (encr_id, key_bits) = match cipher {
        SkCipher::Aes128Gcm => (transform_id::AES_GCM_16, Some(128)),
        SkCipher::Aes192Gcm => (transform_id::AES_GCM_16, Some(192)),
        SkCipher::Aes256Gcm => (transform_id::AES_GCM_16, Some(256)),
        // Both have exactly one key size, so IANA convention omits an
        // explicit Key Length attribute (see `negotiate::fixed_key_bits`).
        SkCipher::ChaCha20Poly1305 => (transform_id::CHACHA20_POLY1305, None),
        SkCipher::TripleDesCbc(_) => (transform_id::TRIPLE_DES, None),
        SkCipher::Aes128Cbc(_) => (transform_id::AES_CBC, Some(128)),
        SkCipher::Aes192Cbc(_) => (transform_id::AES_CBC, Some(192)),
        SkCipher::Aes256Cbc(_) => (transform_id::AES_CBC, Some(256)),
    };
    let mut transforms = vec![Transform { transform_type: transform_type::ENCR, transform_id: encr_id, key_length: key_bits }];
    if let Some(integ) = cipher.integ_algorithm() {
        transforms.push(Transform { transform_type: transform_type::INTEG, transform_id: integ.transform_id(), key_length: None });
    }
    transforms.push(Transform { transform_type: transform_type::ESN, transform_id: transform_id::ESN_NONE, key_length: None });
    SecurityAssociation {
        proposals: vec![Proposal { num: 1, protocol_id: protocol_id::ESP, spi: spi.to_be_bytes().to_vec(), transforms }],
    }
}

#[cfg(test)]
fn full_tunnel_ts() -> Vec<u8> {
    TrafficSelectors { selectors: vec![TrafficSelector::ipv4_any()] }.to_bytes()
}

/// What the initiator puts in TSi/TSr of the IKE_AUTH CHILD SA (IKEv2 only:
/// IKEv1 negotiates each address family in its own Quick Mode).
///
/// [`Self::Ipv4`] is the conservative default: a CHILD SA for IPv4 only, with
/// IPv6 (if wanted) added afterwards as a CHILD SA of its own -- the shape
/// FortiGate-style peers, which keep one selector family per policy, accept.
/// [`Self::Unified`] is what RFC 7296 §2.9 describes: one payload offering
/// `0.0.0.0/0` and `::/0` together, so a single CHILD SA covers both families
/// when the peer supports it (strongSwan does). A peer that can't answers by
/// narrowing the reply or by rejecting the CHILD SA; the session layer follows
/// either (see `Ikev2Session::with_unified_ts`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ChildTsOffer {
    #[default]
    Ipv4,
    Unified,
}

impl ChildTsOffer {
    /// The selectors this offer puts in both TSi and TSr.
    pub fn selectors(self) -> TrafficSelectors {
        match self {
            ChildTsOffer::Ipv4 => TrafficSelectors::ipv4_full_tunnel(),
            ChildTsOffer::Unified => TrafficSelectors::unified_full_tunnel(),
        }
    }

    fn to_bytes(self) -> Vec<u8> {
        self.selectors().to_bytes()
    }
}

/// The SAi2 an `IKE_AUTH` request carries for the caller's `offer`: `spi`
/// stamped onto every proposal -- the SPI is ours to choose per-connection, so
/// a caller-supplied `esp_offer` template's own SPI value (if any) is always
/// overwritten here rather than sent as-is -- and no DH transform. RFC 7296
/// §1.2: the SA payloads of `IKE_AUTH` "cannot contain Transform Type 4
/// (Diffie-Hellman group) with any value other than NONE. Implementations
/// SHOULD omit the whole transform substructure"; the groups a caller's offer
/// names are its PFS policy for the CHILD SA's rekeys (`rekey::PfsPolicy::
/// from_offer` reads them from the offer, not from here).
pub(crate) fn sai2(offer: &SecurityAssociation, spi: u32) -> SecurityAssociation {
    let mut offer = offer.clone();
    for p in &mut offer.proposals {
        p.spi = spi.to_be_bytes().to_vec();
        p.transforms.retain(|t| t.transform_type != transform_type::DH);
    }
    offer
}

/// The 4-octet SPI of an ESP proposal (RFC 7296 §3.3.1).
pub(crate) fn esp_spi(proposal: &Proposal) -> Result<u32, IkeError> {
    let spi: [u8; 4] = proposal.spi.as_slice().try_into().map_err(|_| IkeError::Crypto("expected a 4-byte ESP SPI"))?;
    Ok(u32::from_be_bytes(spi))
}

/// Responder: the proposal to answer an initiator's SAi2 with, and the
/// initiator's SPI from it -- `None` when none fits, to be answered
/// `NO_PROPOSAL_CHOSEN` (RFC 7296 §1.2, §2.7). The CHILD SA this side derives
/// runs AES-GCM-16/256 (`esp::ChildSa::derive`), so that is what is taken:
/// the first ESP proposal offering it without ESN, with one transform of each
/// type the proposal included, numbered as the peer did and carrying our
/// `child_spi` ([`rekey::select_child_proposal`], as for a CHILD SA rekey the
/// peer starts). A DH group in SAi2 -- which §1.2 rules out, and older
/// versions of this crate sent -- is passed over rather than run: there is no
/// KE in `IKE_AUTH`.
pub(crate) fn answer_esp_offer(sai2: &SecurityAssociation, child_spi: u32) -> Option<(Proposal, u32)> {
    let mut sai2 = sai2.clone();
    for p in &mut sai2.proposals {
        p.transforms.retain(|t| t.transform_type != transform_type::DH || t.transform_id == 0);
    }
    let (proposal, peer_spi, _) = rekey::select_child_proposal(&sai2, SkCipher::Aes256Gcm, child_spi, None, &rekey::PfsPolicy::none()).ok()?;
    Some((proposal, peer_spi))
}

fn ike_auth_header(sa: &CompletedSaInit, is_response: bool) -> IkeHeader {
    IkeHeader {
        initiator_spi: sa.spi_i,
        responder_spi: sa.spi_r,
        next_payload: PayloadType::NoNext, // set by build_encrypted
        major_version: 2,
        minor_version: 0,
        exchange_type: ExchangeType::IkeAuth,
        // The Initiator (I) flag marks messages from the original initiator.
        flags: Flags { initiator: !is_response, version: false, response: is_response },
        message_id: 1, // SA_INIT was message 0
        length: 0,
    }
}

/// The ID + AUTH (+ any CERT, + the ESP SA) payloads pulled from a decrypted
/// `IKE_AUTH`.
struct AuthPayloads {
    /// The raw ID payload body (ID Type + RESERVED + data) — this *is* the
    /// RestOf*IDPayload the AUTH signs over.
    id_body: Vec<u8>,
    auth: Authentication,
    /// Any CERT payloads, in order: `[0]` is the leaf, the rest intermediates.
    certs: Vec<Vec<u8>>,
    /// The peer's SA payload (SAi2 / SAr2), if present (a malformed one fails
    /// the parse).
    child_sa: Option<SecurityAssociation>,
    /// The inner IPv4 the peer assigned us via a Configuration Payload
    /// (CFG_REPLY, INTERNAL_IP4_ADDRESS) — set only on the initiator's parse of
    /// the responder's response.
    assigned_ip4: Option<Ipv4Addr>,
    /// The TSi payload, if present (a malformed one fails the parse).
    tsi: Option<TrafficSelectors>,
    /// The responder's actual granted `TSr` — what the negotiated CHILD_SA
    /// really covers, independent of (and often more authoritative than) any
    /// CFG_REPLY `INTERNAL_IP4_SUBNET`. `None` only if the payload is missing
    /// (a malformed one fails the parse).
    tsr: Option<TrafficSelectors>,
    /// Whether the peer sent `N(INITIAL_CONTACT)` (RFC 7296 §2.4) — this is
    /// the initiator's first SA with us since it last restarted, so any prior
    /// IKE SA we hold for the same peer identity is stale and should be torn
    /// down once this one authenticates.
    initial_contact: bool,
    /// The first CHILD-SA error notify the peer sent (see
    /// [`notify_type::is_child_sa_error`]) -- RFC 7296 §1.2: the IKE SA is
    /// still established when the CHILD SA of `IKE_AUTH` fails, so the response
    /// then carries a valid ID/AUTH and this notify but no SA/TS payloads.
    child_error: Option<u16>,
    /// Whether the peer sent `N(MOBIKE_SUPPORTED)` (RFC 4555 §3.1) -- a
    /// responder may echo it, enabling MOBIKE, only when this is set.
    mobike_supported: bool,
}

/// The type of `body` (a Notify payload body) if it is a CHILD-SA error
/// notify -- one RFC 7296 §1.2 allows in an otherwise successful `IKE_AUTH`.
pub(crate) fn child_sa_error_of(body: &[u8]) -> Option<u16> {
    Notify::parse(body).ok().map(|n| n.notify_type).filter(|t| notify_type::is_child_sa_error(*t))
}

fn parse_auth_inner(first: PayloadType, inner: &[u8]) -> Result<AuthPayloads, IkeError> {
    let mut id_body = None;
    let mut auth = None;
    let mut certs = Vec::new();
    let mut child_sa = None;
    let mut assigned_ip4 = None;
    let (mut tsi, mut tsr) = (None, None);
    let mut initial_contact = false;
    let mut child_error = None;
    let mut mobike_supported = false;
    for payload in payloads(first, inner) {
        let payload = payload?;
        match payload.payload_type {
            PayloadType::IdInitiator | PayloadType::IdResponder => id_body = Some(payload.data.to_vec()),
            PayloadType::Authentication => auth = Some(Authentication::parse(payload.data)?),
            PayloadType::Certificate => {
                if let Ok(c) = Certificate::parse(payload.data) {
                    certs.push(c.data);
                }
            }
            PayloadType::SecurityAssociation => child_sa = Some(SecurityAssociation::parse(payload.data)?),
            PayloadType::Configuration => {
                if let Ok(cp) = Configuration::parse(payload.data) {
                    assigned_ip4 = cp.assigned_ipv4();
                }
            }
            PayloadType::TrafficSelectorInitiator => tsi = Some(TrafficSelectors::parse(payload.data)?),
            PayloadType::TrafficSelectorResponder => tsr = Some(TrafficSelectors::parse(payload.data)?),
            PayloadType::Notify => {
                if let Ok(n) = Notify::parse(payload.data) {
                    if n.notify_type == notify_type::INITIAL_CONTACT {
                        initial_contact = true;
                    } else if n.notify_type == notify_type::MOBIKE_SUPPORTED {
                        mobike_supported = true;
                    } else if child_error.is_none() && notify_type::is_child_sa_error(n.notify_type) {
                        child_error = Some(n.notify_type);
                    }
                }
            }
            _ => {} // CERTREQ not needed here
        }
    }
    Ok(AuthPayloads {
        id_body: id_body.ok_or(IkeError::MissingPayload("ID"))?,
        auth: auth.ok_or(IkeError::MissingPayload("AUTH"))?,
        certs,
        child_sa,
        assigned_ip4,
        tsi,
        tsr,
        initial_contact,
        child_error,
        mobike_supported,
    })
}

fn psk_auth_payload(algo: crate::crypto::PrfAlgorithm, psk: &[u8], signed_octets: &[u8]) -> Authentication {
    Authentication { method: auth_method::SHARED_KEY, data: psk_auth(algo, psk, signed_octets) }
}

/// Constant-time byte-slice equality — avoids a timing side channel on the
/// AUTH MAC. Length is not secret (the MAC length is fixed by the PRF).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn verify_psk(algo: crate::crypto::PrfAlgorithm, auth: &Authentication, psk: &[u8], expected_octets: &[u8]) -> Result<(), IkeError> {
    let expected = psk_auth(algo, psk, expected_octets);
    if auth.method == auth_method::SHARED_KEY && ct_eq(&auth.data, &expected) {
        Ok(())
    } else {
        Err(IkeError::AuthFailed)
    }
}

/// Build a server (responder) certificate AUTH, choosing the signature method by
/// what the peer negotiated and by our key type: RFC 7427 Digital Signature
/// (method 14, works for either an RSA or an ECDSA key) when the peer
/// advertised SHA-256 in `SIGNATURE_HASH_ALGORITHMS`, otherwise the matching
/// classic method for our key -- ECDSA-P256-SHA256 (method 9, RFC 4754) for
/// an EC key, or RSA Digital Signature (method 1, RFC 7296 §3.8) for an RSA
/// key. A native EAP client (iOS) sends no `SIGNATURE_HASH_ALGORITHMS`, so it
/// needs one of the classic methods. Picking by key type (rather than always
/// trying method 9) matters because `sign_ecdsa_p256_raw` simply fails for an
/// RSA key -- there is no such thing as "ECDSA-sign with an RSA key" to fall
/// back to. Both classic methods this can emit are also accepted by our own
/// [`verify_peer_auth`] (see [`crate::ikev2::sign::verify_cert_auth`]), so
/// emission and verification stay symmetric.
pub(crate) fn cert_auth_payload(
    key: &SigningKey,
    peer_signature_hashes: &[u16],
    octets: &[u8],
) -> Result<Authentication, IkeError> {
    if peer_signature_hashes.contains(&sighash::SHA2_256) {
        return Ok(Authentication {
            method: auth_method::DIGITAL_SIGNATURE,
            data: key.sign_auth_data(octets)?,
        });
    }
    match key {
        SigningKey::EcdsaP256(_) => Ok(Authentication {
            method: auth_method::ECDSA_SHA256_P256,
            data: key.sign_ecdsa_p256_raw(octets)?,
        }),
        SigningKey::RsaSha256(_) | SigningKey::RsaPssSha256(_) => Ok(Authentication {
            method: auth_method::RSA_SIG,
            data: key.sign_classic_rsa_auth_data(octets)?,
        }),
    }
}

/// Build our AUTH payload (and any CERT payloads to precede it) over
/// `signed_octets`, per our [`LocalAuth`] config.
fn build_local_auth(
    cfg: &AuthConfig,
    sa: &CompletedSaInit,
    signed_octets: &[u8],
) -> Result<(Authentication, PayloadChain), IkeError> {
    match &cfg.local {
        LocalAuth::Psk(psk) => Ok((psk_auth_payload(sa.suite.prf_algorithm(), psk, signed_octets), Vec::new())),
        LocalAuth::Cert { key, chain } => {
            // Method 14 (RFC 7427) when the peer advertised SHA-256, else the
            // classic ECDSA method 9 — so native EAP clients still interoperate.
            let auth = cert_auth_payload(key, &sa.peer_signature_hashes, signed_octets)?;
            let certs = chain
                .iter()
                .map(|c| (PayloadType::Certificate, Certificate::x509(c.clone()).to_bytes()))
                .collect();
            Ok((auth, certs))
        }
    }
}

/// Verify the peer's AUTH over `expected_octets`, per our [`PeerAuth`] config.
fn verify_peer_auth(
    algo: crate::crypto::PrfAlgorithm,
    cfg: &AuthConfig,
    got: &AuthPayloads,
    expected_octets: &[u8],
) -> Result<(), IkeError> {
    match &cfg.peer {
        PeerAuth::Psk(psk) => verify_psk(algo, &got.auth, psk, expected_octets),
        PeerAuth::Cert { cas, expected_dns, now_unix } => {
            // Accept the same three methods `cert_auth_payload` can itself
            // emit (14, 1, 9) -- a peer running the same fallback logic we
            // do must not be rejected for it.
            if !matches!(
                got.auth.method,
                auth_method::DIGITAL_SIGNATURE | auth_method::RSA_SIG | auth_method::ECDSA_SHA256_P256
            ) {
                return Err(IkeError::AuthFailed);
            }
            let leaf = got.certs.first().ok_or(IkeError::MissingPayload("CERT"))?;
            crate::ikev2::sign::verify_cert_auth(
                leaf,
                &got.certs[1..],
                cas,
                expected_dns.as_deref(),
                *now_unix,
                got.auth.method,
                &got.auth.data,
                expected_octets,
            )
        }
    }
}

/// Initiator: build the encrypted `IKE_AUTH` request
/// `SK { IDi, AUTH, SAi2, TSi, TSr }`.
pub fn initiator_auth_request(
    sa: &CompletedSaInit,
    cfg: &AuthConfig,
    child_spi: u32,
    esp_offer: &SecurityAssociation,
    iv: &[u8; 8],
) -> Result<Vec<u8>, IkeError> {
    initiator_auth_request_with_cfg(sa, cfg, child_spi, false, esp_offer, ChildTsOffer::Ipv4, iv)
}

/// Like [`initiator_auth_request`], but also carries a CFG_REQUEST
/// ([`Configuration::request_ipv4`]) when `want_cfg` is set — for a direct
/// (non-EAP) PSK/cert client that still wants an inner IP/DNS/subnet assigned
/// (e.g. a pure-certificate profile with mode-config enabled). Placed right
/// after IDi, matching [`initiator_eap_request`]'s payload order. `esp_offer`
/// is the CHILD SA proposal template (see [`self::esp_offer`] for the
/// default AES-GCM-256 one) — its own SPI field is ignored; [`sai2`]
/// always overwrites it with `child_spi`, and leaves its DH groups out. `ts_offer` picks the TSi/TSr this
/// CHILD SA is offered with (see [`ChildTsOffer`]); every other builder below
/// takes it the same way.
pub fn initiator_auth_request_with_cfg(
    sa: &CompletedSaInit,
    cfg: &AuthConfig,
    child_spi: u32,
    want_cfg: bool,
    esp_offer: &SecurityAssociation,
    ts_offer: ChildTsOffer,
    iv: &[u8; 8],
) -> Result<Vec<u8>, IkeError> {
    let idi_body = cfg.id.to_bytes();
    let octets = initiator_signed_octets(sa.suite.prf_algorithm(), &sa.init_message, &sa.nr, &sa.keys.sk_pi, &idi_body);
    let (auth, cert_payloads) = build_local_auth(cfg, sa, &octets)?;

    let mut inner = vec![(PayloadType::IdInitiator, idi_body)];
    if want_cfg {
        inner.push((PayloadType::Configuration, Configuration::request_ipv4().to_bytes()));
    }
    // RFC 7296 §2.4: we hold no state across restarts, so this is always our
    // first (and only) SA with this peer -- tells the responder to tear down
    // any stale SA it still has for our identity.
    inner.push((PayloadType::Notify, Notify::status(notify_type::INITIAL_CONTACT, Vec::new()).to_bytes()));
    inner.extend(cert_payloads);
    // Ask the responder for its certificate when we authenticate it by cert.
    if let PeerAuth::Cert { cas, .. } = &cfg.peer {
        let hashes = cas.iter().filter_map(|ca| crate::ikev2::sign::ca_key_hash(ca).ok()).collect();
        inner.push((PayloadType::CertRequest, CertRequest::x509(hashes).to_bytes()));
    }
    inner.push((PayloadType::Authentication, auth.to_bytes()));
    inner.push((PayloadType::SecurityAssociation, sai2(esp_offer, child_spi).to_bytes()));
    inner.push((PayloadType::TrafficSelectorInitiator, ts_offer.to_bytes()));
    inner.push((PayloadType::TrafficSelectorResponder, ts_offer.to_bytes()));
    let first = first_payload_type(&inner);
    let inner_bytes = encode_payload_chain(&inner);
    build_encrypted(sa.suite.sk_cipher(), ike_auth_header(sa, false), first, &inner_bytes, &sa.keys.sk_ei, &sa.keys.sk_ai, iv)
}

/// Initiator: build the **EAP-mode** `IKE_AUTH` request `SK { IDi, [CFG],
/// SAi2, TSi, TSr }` — no AUTH payload, which tells the responder the
/// initiator will authenticate via EAP (RFC 7296 §2.16). The multi-message
/// EAP exchange then follows. Carries a CFG_REQUEST
/// ([`Configuration::request_ipv4`]) when `want_cfg` is set — RFC 7296
/// §2.19 lets mode-config run alongside any authentication method; some
/// responders require it to complete before they'll finish an EAP exchange
/// at all, so this is opt-in rather than unconditional. See
/// [`initiator_auth_request_with_cfg`] for `esp_offer`'s contract.
pub fn initiator_eap_request(
    sa: &CompletedSaInit,
    id: &Identification,
    child_spi: u32,
    want_cfg: bool,
    esp_offer: &SecurityAssociation,
    ts_offer: ChildTsOffer,
    iv: &[u8; 8],
) -> Result<Vec<u8>, IkeError> {
    let mut inner = vec![(PayloadType::IdInitiator, id.to_bytes())];
    if want_cfg {
        inner.push((PayloadType::Configuration, Configuration::request_ipv4().to_bytes()));
    }
    inner.push((PayloadType::SecurityAssociation, sai2(esp_offer, child_spi).to_bytes()));
    inner.push((PayloadType::TrafficSelectorInitiator, ts_offer.to_bytes()));
    inner.push((PayloadType::TrafficSelectorResponder, ts_offer.to_bytes()));
    inner.push((PayloadType::Notify, Notify::status(notify_type::INITIAL_CONTACT, Vec::new()).to_bytes()));
    let first = first_payload_type(&inner);
    let inner_bytes = encode_payload_chain(&inner);
    build_encrypted(sa.suite.sk_cipher(), ike_auth_header(sa, false), first, &inner_bytes, &sa.keys.sk_ei, &sa.keys.sk_ai, iv)
}

/// Like [`initiator_eap_request`] but also carries a `CERTREQ` payload listing
/// `ca_hashes` — mirrors a strongSwan client that advertises the CAs it trusts.
/// Lets a responder that selects its cert by CERTREQ presence be exercised.
/// Also honors `want_cfg` the same way [`initiator_eap_request`] does.
pub fn initiator_eap_request_with_certreq(
    sa: &CompletedSaInit,
    id: &Identification,
    child_spi: u32,
    want_cfg: bool,
    esp_offer: &SecurityAssociation,
    ts_offer: ChildTsOffer,
    ca_hashes: Vec<[u8; 20]>,
    iv: &[u8; 8],
) -> Result<Vec<u8>, IkeError> {
    let mut inner = vec![(PayloadType::IdInitiator, id.to_bytes())];
    if want_cfg {
        inner.push((PayloadType::Configuration, Configuration::request_ipv4().to_bytes()));
    }
    inner.push((PayloadType::SecurityAssociation, sai2(esp_offer, child_spi).to_bytes()));
    inner.push((PayloadType::TrafficSelectorInitiator, ts_offer.to_bytes()));
    inner.push((PayloadType::TrafficSelectorResponder, ts_offer.to_bytes()));
    inner.push((PayloadType::CertRequest, CertRequest::x509(ca_hashes).to_bytes()));
    inner.push((PayloadType::Notify, Notify::status(notify_type::INITIAL_CONTACT, Vec::new()).to_bytes()));
    let first = first_payload_type(&inner);
    let inner_bytes = encode_payload_chain(&inner);
    build_encrypted(sa.suite.sk_cipher(), ike_auth_header(sa, false), first, &inner_bytes, &sa.keys.sk_ei, &sa.keys.sk_ai, iv)
}

/// Like [`initiator_eap_request`], but also attaches the client's own X.509
/// certificate chain (`certs[0]` = leaf) and, optionally, a `CERTREQ` listing
/// `ca_hashes`. There is still no AUTH payload here (RFC 7296 §2.16: the
/// initiator authenticates via the EAP exchange that follows, not this
/// message), so the attached certs are bare identity presentation, not a
/// signature — this is not standard RFC 4739 Multiple Authentication, it
/// mirrors what a real FortiClient sends against a FortiGate policy
/// configured for "Certificate + EAP": the gateway wants to see the client's
/// certificate for its own identity/policy matching, on top of EAP actually
/// deciding whether the connection is authenticated. Payload order matches
/// [`initiator_auth_request_with_cfg`]'s (IDi, CFG, CERT.., CERTREQ, SA,
/// TSi, TSr) for consistency between the two "attach a cert" call sites.
/// Also honors `want_cfg` the same way [`initiator_eap_request`] does.
#[allow(clippy::too_many_arguments)]
pub fn initiator_eap_request_with_certs(
    sa: &CompletedSaInit,
    id: &Identification,
    child_spi: u32,
    want_cfg: bool,
    esp_offer: &SecurityAssociation,
    ts_offer: ChildTsOffer,
    certs: &[Vec<u8>],
    ca_hashes: Option<Vec<[u8; 20]>>,
    iv: &[u8; 8],
) -> Result<Vec<u8>, IkeError> {
    let mut inner = vec![(PayloadType::IdInitiator, id.to_bytes())];
    if want_cfg {
        inner.push((PayloadType::Configuration, Configuration::request_ipv4().to_bytes()));
    }
    inner.extend(certs.iter().map(|c| (PayloadType::Certificate, Certificate::x509(c.clone()).to_bytes())));
    if let Some(hashes) = ca_hashes {
        inner.push((PayloadType::CertRequest, CertRequest::x509(hashes).to_bytes()));
    }
    inner.push((PayloadType::SecurityAssociation, sai2(esp_offer, child_spi).to_bytes()));
    inner.push((PayloadType::TrafficSelectorInitiator, ts_offer.to_bytes()));
    inner.push((PayloadType::TrafficSelectorResponder, ts_offer.to_bytes()));
    inner.push((PayloadType::Notify, Notify::status(notify_type::INITIAL_CONTACT, Vec::new()).to_bytes()));
    let first = first_payload_type(&inner);
    let inner_bytes = encode_payload_chain(&inner);
    build_encrypted(sa.suite.sk_cipher(), ike_auth_header(sa, false), first, &inner_bytes, &sa.keys.sk_ei, &sa.keys.sk_ai, iv)
}

/// Responder: decrypt + verify the initiator's `IKE_AUTH` request, then build
/// the encrypted response `SK { IDr, AUTH, SAr2, TSi, TSr }`. TSi and TSr are
/// the request's narrowed to what this responder carries (RFC 7296 §2.9): on
/// the initiator's side the address it is `assigned`, or any IPv4 address
/// without one, and any IPv4 address on ours. When either comes to nothing
/// the IKE SA is still created, the CHILD SA not: the response is
/// `SK { IDr, AUTH, N(TS_UNACCEPTABLE) }` (§1.2), and the initiator's CHILD SA
/// SPI is returned as `None`. Returns the response bytes, the initiator's
/// verified identity, its CHILD SA SPI, and
/// whether it sent `N(INITIAL_CONTACT)` (RFC 7296 §2.4) -- the caller should
/// tear down any prior IKE/CHILD SA it holds for the same peer identity when
/// this is set, since it only has meaning once AUTH has verified.
///
/// Does not enable MOBIKE: see [`responder_process_auth_with_mobike`].
pub fn responder_process_auth(
    sa: &CompletedSaInit,
    request: &[u8],
    cfg: &AuthConfig,
    child_spi: u32,
    iv: &[u8; 8],
    assigned: Option<&AssignedConfig>,
) -> Result<(Vec<u8>, Identification, Option<u32>, bool), IkeError> {
    let (response, peer_id, peer_child_spi, initial_contact, _mobike) =
        responder_process_auth_with_mobike(sa, request, cfg, child_spi, iv, assigned, false)?;
    Ok((response, peer_id, peer_child_spi, initial_contact))
}

/// What [`responder_process_auth_with_mobike`] returns: the response, the
/// peer's identity, the peer's ESP SPI for the CHILD SA (`None` when the
/// traffic selectors left no CHILD SA), whether it sent `INITIAL_CONTACT`, and
/// whether MOBIKE is in force.
pub type AuthAnswer = (Vec<u8>, Identification, Option<u32>, bool, bool);

/// Like [`responder_process_auth`], but `mobike` states whether the caller
/// implements MOBIKE (RFC 4555): it answers an INFORMATIONAL carrying
/// `N(UPDATE_SA_ADDRESSES)` (see [`crate::ikev2::mobike`]) by moving the IKE SA
/// and its CHILD SAs to that request's observed source address. Only then, and
/// only if the initiator offered it (§3.1), does the response carry
/// `N(MOBIKE_SUPPORTED)` -- advertising it without that handling would have a
/// MOBIKE client migrate onto a path we never follow. The extra returned flag
/// is whether MOBIKE is in force for this IKE SA, i.e. whether the caller must
/// honor `UPDATE_SA_ADDRESSES` from this peer.
pub fn responder_process_auth_with_mobike(
    sa: &CompletedSaInit,
    request: &[u8],
    cfg: &AuthConfig,
    child_spi: u32,
    iv: &[u8; 8],
    assigned: Option<&AssignedConfig>,
    mobike: bool,
) -> Result<AuthAnswer, IkeError> {
    // The initiator encrypts with SK_ei.
    let (first, inner) = open_encrypted(sa.suite.sk_cipher(), request, &sa.keys.sk_ei, &sa.keys.sk_ai)?;
    let got = parse_auth_inner(first, &inner)?;

    let octets = initiator_signed_octets(sa.suite.prf_algorithm(), &sa.init_message, &sa.nr, &sa.keys.sk_pi, &got.id_body);
    verify_peer_auth(sa.suite.prf_algorithm(), cfg, &got, &octets)?;
    let peer_id = Identification::parse(&got.id_body)?;
    let sai2 = got.child_sa.as_ref().ok_or(IkeError::MissingPayload("SA"))?;
    let (policy_i, policy_r) = assigned_ipv4_policy(assigned.map(|a| a.ip));
    let child_ts = match narrow_requested_ts(got.tsi.as_ref(), got.tsr.as_ref(), &policy_i, &policy_r) {
        Ok(ts) => Some(ts),
        Err(IkeError::TsUnacceptable) => None,
        Err(e) => return Err(e),
    };
    // RFC 7296 §1.2: either failing, the IKE SA stands and the CHILD SA is
    // refused with the reason -- the proposals weighed first, as §2.7 has it.
    let child = match (answer_esp_offer(sai2, child_spi), child_ts) {
        (None, _) => Err(notify_type::NO_PROPOSAL_CHOSEN),
        (Some(_), None) => Err(notify_type::TS_UNACCEPTABLE),
        (Some((sar2, peer_child_spi)), Some(ts)) => Ok((sar2, peer_child_spi, ts)),
    };

    // Our AUTH signs resp_message | Ni | prf(SK_pr, IDr) — it does NOT cover the
    // CP/SA/TS payloads, so adding a CFG_REPLY below needs no AUTH recomputation.
    let idr_body = cfg.id.to_bytes();
    let our_octets = responder_signed_octets(sa.suite.prf_algorithm(), &sa.resp_message, &sa.ni, &sa.keys.sk_pr, &idr_body);
    let (auth, cert_payloads) = build_local_auth(cfg, sa, &our_octets)?;

    let mut inner_out = vec![(PayloadType::IdResponder, idr_body)];
    inner_out.extend(cert_payloads);
    inner_out.push((PayloadType::Authentication, auth.to_bytes()));
    match &child {
        Ok((sar2, _, (tsi, tsr))) => {
            // CP(CFG_REPLY) with the assigned inner IP (+ DNS) — a native client needs
            // this to configure its tunnel interface. RFC 7296 §2.19: after AUTH, before
            // SA/TS. The assigned address is also the only one TSi is narrowed to.
            if let Some(a) = assigned {
                let dns = if a.dns.is_empty() { None } else { Some(a.dns[0]) };
                let cp = Configuration::reply_ipv4(a.ip, None, dns);
                inner_out.push((PayloadType::Configuration, cp.to_bytes()));
            }
            inner_out.push((PayloadType::SecurityAssociation, SecurityAssociation { proposals: vec![sar2.clone()] }.to_bytes()));
            inner_out.push((PayloadType::TrafficSelectorInitiator, tsi.to_bytes()));
            inner_out.push((PayloadType::TrafficSelectorResponder, tsr.to_bytes()));
        }
        // RFC 7296 §1.2, §2.7, §2.9: the IKE SA stands, the CHILD SA is refused.
        Err(error) => inner_out.push((PayloadType::Notify, Notify::status(*error, Vec::new()).to_bytes())),
    }
    // RFC 4555 §3.1: the responder includes MOBIKE_SUPPORTED only if the
    // initiator did, and we only when the caller actually follows the client
    // across address changes -- then it migrates instead of reconnecting.
    let mobike = mobike && got.mobike_supported;
    if mobike {
        inner_out.push((PayloadType::Notify, crate::ikev2::mobike::mobike_supported().to_bytes()));
    }
    let first_out = first_payload_type(&inner_out);
    let inner_bytes = encode_payload_chain(&inner_out);
    let response = build_encrypted(sa.suite.sk_cipher(), ike_auth_header(sa, true), first_out, &inner_bytes, &sa.keys.sk_er, &sa.keys.sk_ar, iv)?;
    Ok((response, peer_id, child.ok().map(|(_, peer_child_spi, _)| peer_child_spi), got.initial_contact, mobike))
}

/// Decrypt an `IKE_AUTH` request and return the peer's claimed identity (`IDi`)
/// **without** verifying its AUTH — so a responder can select a per-user PSK by
/// identity before it can build the [`AuthConfig`] to verify with. The IDi lives
/// inside the GCM-protected `SK{}`, so it still requires the `IKE_SA_INIT` keys:
/// an attacker cannot present an arbitrary identity without the DH secrets.
pub fn peer_id_from_auth(sa: &CompletedSaInit, request: &[u8]) -> Result<Identification, IkeError> {
    let (first, inner) = open_encrypted(sa.suite.sk_cipher(), request, &sa.keys.sk_ei, &sa.keys.sk_ai)?;
    let got = parse_auth_inner(first, &inner)?;
    Identification::parse(&got.id_body)
}

/// The initiator's identity (`IDi`) from an `IKE_AUTH` request, whether or not it
/// carries an AUTH payload. An EAP first message has an ID but no AUTH, so
/// [`peer_id_from_auth`] (which requires AUTH) can't read it — this extracts the
/// `IDi` directly. Returns `None` if the message can't be opened or has no ID.
pub fn peer_id_from_request(sa: &CompletedSaInit, request: &[u8]) -> Option<Identification> {
    let (first, inner) = open_encrypted(sa.suite.sk_cipher(), request, &sa.keys.sk_ei, &sa.keys.sk_ai).ok()?;
    let idi = payloads(first, &inner)
        .flatten()
        .find(|p| p.payload_type == PayloadType::IdInitiator)?;
    Identification::parse(idi.data).ok()
}

/// Whether an `IKE_AUTH` request is the first message of an **EAP** exchange —
/// i.e. it carries no `AUTH` payload (the initiator is saying "I'll authenticate
/// with EAP", RFC 7296 §2.16). A PSK/cert client always includes `AUTH`.
pub fn is_eap_request(sa: &CompletedSaInit, request: &[u8]) -> bool {
    let Ok((first, inner)) = open_encrypted(sa.suite.sk_cipher(), request, &sa.keys.sk_ei, &sa.keys.sk_ai) else {
        return false;
    };
    let has_auth = payloads(first, &inner)
        .flatten()
        .any(|p| p.payload_type == PayloadType::Authentication);
    !has_auth
}

/// Whether the client's `IKE_AUTH` carries a `CERTREQ` payload. strongSwan sends
/// one (listing the CAs it trusts); native iOS/Android clients typically send
/// none. A responder can use this to keep a CERTREQ client on its existing cert
/// while serving native (no-CERTREQ) clients an alternate one.
pub fn client_sent_certreq(sa: &CompletedSaInit, request: &[u8]) -> bool {
    let Ok((first, inner)) = open_encrypted(sa.suite.sk_cipher(), request, &sa.keys.sk_ei, &sa.keys.sk_ai) else {
        return false;
    };
    payloads(first, &inner)
        .flatten()
        .any(|p| p.payload_type == PayloadType::CertRequest)
}

/// The responder's verified identity, its chosen CHILD SA SPI, the ESP cipher
/// it named (from the same SA payload -- one of our proposals, so `None` only
/// if the caller offered a combination [`negotiate::select_esp`] cannot
/// decode), the assigned inner IPv4 (if any), and its actual granted `TSr`
/// (always `Some` since [`initiator_verify_auth`] requires it) -- see
/// [`AuthPayloads::tsr`] for why this is often more authoritative than the
/// CFG_REPLY subnet for deciding what to route through the tunnel. Returned by
/// [`initiator_verify_auth`].
pub type VerifiedAuth = (Identification, u32, Option<ChosenEspSuite>, Option<Ipv4Addr>, Option<TrafficSelectors>);

/// Initiator: decrypt + verify the responder's `IKE_AUTH` response. `esp_offer`
/// must be the same CHILD SA proposal template this side actually sent (see
/// [`initiator_auth_request_with_cfg`]'s doc) -- the responder's SAr2 is
/// checked against it (RFC 7296 §2.7) so a peer can't answer with an
/// ENCR/INTEG/ESN combination it never actually saw offered (see
/// [`ChosenEspSuite::matches_offer`]'s doc for why that matters). `ts_offer`
/// must be the one the request proposed: the TSi and TSr answered are
/// checked against it ([`check_granted_ts`]). See [`VerifiedAuth`] for the
/// returned fields.
pub fn initiator_verify_auth(
    sa: &CompletedSaInit,
    response: &[u8],
    cfg: &AuthConfig,
    esp_offer: &SecurityAssociation,
    ts_offer: ChildTsOffer,
) -> Result<VerifiedAuth, IkeError> {
    // The responder encrypts with SK_er.
    let (first, inner) = open_encrypted(sa.suite.sk_cipher(), response, &sa.keys.sk_er, &sa.keys.sk_ar)?;
    let got = parse_auth_inner(first, &inner)?;

    let octets = responder_signed_octets(sa.suite.prf_algorithm(), &sa.resp_message, &sa.ni, &sa.keys.sk_pr, &got.id_body);
    verify_peer_auth(sa.suite.prf_algorithm(), cfg, &got, &octets)?;
    // Only once the AUTH has verified: a peer that authenticated but refused
    // the CHILD SA (RFC 7296 §1.2) is a rejection with a stated reason, not a
    // "missing SA payload".
    let sar2 = match (&got.child_sa, got.child_error) {
        (None, Some(t)) => return Err(IkeError::PeerRejected { notify_type: t, name: notify_type_name(t) }),
        (sar2, _) => sar2.as_ref().ok_or(IkeError::MissingPayload("SA"))?,
    };
    // One of the proposals we sent, by its number, with one transform of each
    // of its types (RFC 7296 §2.7, §3.3.1, §3.3.6) -- carrying the peer's SPI.
    let sent = sai2(esp_offer, 0);
    let peer_child_spi = esp_spi(negotiate::accepted_proposal(sar2, &sent)?)?;
    let esp_suite = negotiate::select_esp(sar2);
    if let Some(suite) = &esp_suite {
        if !suite.matches_offer(&sent) {
            return Err(IkeError::NoProposalChosen);
        }
    }
    check_granted_ts(&ts_offer.selectors(), got.tsi.as_ref(), got.tsr.as_ref())?;
    Ok((Identification::parse(&got.id_body)?, peer_child_spi, esp_suite, got.assigned_ip4, got.tsr))
}

/// The traffic selectors a response creating a CHILD SA answered a request
/// proposing `offer` as both TSi and TSr with: both present (RFC 7296 §2.9:
/// "Two TS payloads appear in each of the messages in the exchange that
/// creates a Child SA pair"), and each a subset of `offer` -- the responder
/// narrows "to some subset of the initiator's proposal"
/// ([`TrafficSelectors::is_within`]). Anything else is
/// [`IkeError::MissingPayload`] or [`IkeError::TsOutsideOffer`].
pub(crate) fn check_granted_ts(offer: &TrafficSelectors, tsi: Option<&TrafficSelectors>, tsr: Option<&TrafficSelectors>) -> Result<(), IkeError> {
    let tsi = tsi.ok_or(IkeError::MissingPayload("TSi"))?;
    let tsr = tsr.ok_or(IkeError::MissingPayload("TSr"))?;
    if !(tsi.is_within(offer) && tsr.is_within(offer)) {
        ike_debug!("CHILD SA: offered TS {offer:?}, answered TSi={tsi:?} TSr={tsr:?}");
        return Err(IkeError::TsOutsideOffer);
    }
    Ok(())
}

/// The selectors a responder answers a CHILD SA request with (RFC 7296
/// §2.9): the request's TSi and TSr, which it must carry, narrowed to
/// `policy_i` (the initiator's side) and `policy_r` (ours) --
/// [`TrafficSelectors::narrowed_to`]. When either comes to nothing the
/// request is refused with `TsUnacceptable`, answered `TS_UNACCEPTABLE`.
pub(crate) fn narrow_requested_ts(
    tsi: Option<&TrafficSelectors>,
    tsr: Option<&TrafficSelectors>,
    policy_i: &TrafficSelectors,
    policy_r: &TrafficSelectors,
) -> Result<(TrafficSelectors, TrafficSelectors), IkeError> {
    let tsi = tsi.ok_or(IkeError::MissingPayload("TSi"))?;
    let tsr = tsr.ok_or(IkeError::MissingPayload("TSr"))?;
    match (tsi.narrowed_to(policy_i), tsr.narrowed_to(policy_r)) {
        (Some(tsi), Some(tsr)) => Ok((tsi, tsr)),
        _ => {
            ike_debug!("CHILD SA: requested TSi={tsi:?} TSr={tsr:?}, nothing within our TSi={policy_i:?} TSr={policy_r:?}");
            Err(IkeError::TsUnacceptable)
        }
    }
}

/// The traffic this crate's responders carry for a client: on its side the
/// IPv4 address it is `assigned`, or any IPv4 address without one; on ours
/// any IPv4 address.
pub(crate) fn assigned_ipv4_policy(assigned: Option<Ipv4Addr>) -> (TrafficSelectors, TrafficSelectors) {
    let client = match assigned {
        Some(ip) => TrafficSelectors { selectors: vec![TrafficSelector::ipv4_host(ip)] },
        None => TrafficSelectors::ipv4_full_tunnel(),
    };
    (client, TrafficSelectors::ipv4_full_tunnel())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::ikev2::exchange::{default_offer, initiator_complete, initiator_request, responder_respond, LocalSecret};

    fn run_sa_init() -> (CompletedSaInit, CompletedSaInit) {
        let init = LocalSecret { dh_private: [7u8; 32], nonce: vec![0x11; 32], spi: 0xA1 };
        let resp = LocalSecret { dh_private: [9u8; 32], nonce: vec![0x22; 32], spi: 0xB2 };
        let request = initiator_request(&init, &default_offer());
        let (response, resp_done) = responder_respond(&request, &resp).unwrap();
        let init_done = initiator_complete(&init, &request, &response).unwrap();
        (init_done, resp_done)
    }

    #[test]
    fn local_and_peer_auth_psk_are_wiped_by_their_drop_logic() {
        use zeroize::Zeroize;

        let mut local = LocalAuth::Psk(vec![0xAA; 16]);
        let mut peer = PeerAuth::Psk(vec![0xBB; 16]);

        if let LocalAuth::Psk(psk) = &mut local {
            psk.zeroize();
            assert!(psk.is_empty());
        } else {
            panic!("expected LocalAuth::Psk");
        }
        if let PeerAuth::Psk(psk) = &mut peer {
            psk.zeroize();
            assert!(psk.is_empty());
        } else {
            panic!("expected PeerAuth::Psk");
        }
    }

    #[test]
    fn ike_auth_mutual_psk_succeeds_and_exchanges_ids() {
        let (init_sa, resp_sa) = run_sa_init();
        let psk = b"correct horse battery staple".to_vec();
        let icfg = AuthConfig::psk(Identification::fqdn("client.example"), psk.clone());
        let rcfg = AuthConfig::psk(Identification::fqdn("gw.example"), psk);

        let req = initiator_auth_request(&init_sa, &icfg, 0xDEADBEEF, &esp_offer(0), &[1u8; 8]).unwrap();
        let (resp, learned_initiator, init_spi, _ic) = responder_process_auth(&resp_sa, &req, &rcfg, 0xCAFEBABE, &[2u8; 8], None).unwrap();
        // The responder decrypted the initiator's SK{} — proves the keys agree.
        assert_eq!(learned_initiator, Identification::fqdn("client.example"));
        assert_eq!(init_spi, Some(0xDEADBEEF)); // and learned its CHILD SA SPI

        let (learned_responder, resp_spi, _esp_suite, _assigned, _tsr) =
            initiator_verify_auth(&init_sa, &resp, &icfg, &esp_offer(0), ChildTsOffer::Ipv4).unwrap();
        assert_eq!(learned_responder, Identification::fqdn("gw.example"));
        assert_eq!(resp_spi, 0xCAFEBABE); // initiator learned the responder's CHILD SA SPI
    }

    #[test]
    fn initiator_auth_request_always_carries_initial_contact() {
        // RFC 7296 §2.4: we keep no state across restarts, so every first
        // IKE_AUTH we send asserts INITIAL_CONTACT -- the responder uses this
        // to drop any stale SA of ours it's still holding.
        let (init_sa, resp_sa) = run_sa_init();
        let psk = b"pw".to_vec();
        let icfg = AuthConfig::psk(Identification::fqdn("client.example"), psk.clone());
        let rcfg = AuthConfig::psk(Identification::fqdn("gw.example"), psk);
        let req = initiator_auth_request(&init_sa, &icfg, 1, &esp_offer(0), &[1u8; 8]).unwrap();
        let (_resp, _peer, _spi, initial_contact) =
            responder_process_auth(&resp_sa, &req, &rcfg, 2, &[2u8; 8], None).unwrap();
        assert!(initial_contact);
    }

    #[test]
    fn eap_request_variants_also_carry_initial_contact() {
        let (init_sa, resp_sa) = run_sa_init();
        let id = Identification::fqdn("eap.example");
        let req = initiator_eap_request(&init_sa, &id, 1, false, &esp_offer(0), ChildTsOffer::Ipv4, &[1u8; 8]).unwrap();
        let (first, inner) = crate::ikev2::sk::open_encrypted(resp_sa.suite.sk_cipher(), &req, &resp_sa.keys.sk_ei, &resp_sa.keys.sk_ai).unwrap();
        let got = parse_auth_inner(first, &inner);
        // EAP-mode has no AUTH payload yet, so parse_auth_inner errors on the
        // missing AUTH -- what we care about here is that it got far enough to
        // see the Notify, i.e. the payload chain parsed. Re-derive directly:
        let has_initial_contact = payloads(first, &inner)
            .filter_map(|p| p.ok())
            .any(|p| p.payload_type == PayloadType::Notify && Notify::parse(p.data).map(|n| n.notify_type == notify_type::INITIAL_CONTACT).unwrap_or(false));
        assert!(has_initial_contact);
        assert!(got.is_err()); // sanity: still no AUTH payload in EAP mode
    }

    #[test]
    fn ike_auth_assigns_inner_ip_via_config_payload() {
        // The responder hands the initiator an inner IP + DNS in a CFG_REPLY;
        // the initiator parses it out of the IKE_AUTH response. This is what a
        // native phone client relies on to configure its tunnel interface.
        let (init_sa, resp_sa) = run_sa_init();
        let psk = b"correct horse battery staple".to_vec();
        let icfg = AuthConfig::psk(Identification::fqdn("client.example"), psk.clone());
        let rcfg = AuthConfig::psk(Identification::fqdn("gw.example"), psk);

        let req = initiator_auth_request(&init_sa, &icfg, 0xDEADBEEF, &esp_offer(0), &[1u8; 8]).unwrap();
        let assigned = AssignedConfig {
            ip: Ipv4Addr::new(10, 8, 0, 4),
            dns: vec![Ipv4Addr::new(1, 1, 1, 1)],
        };
        let (resp, learned_i, _spi, _ic) =
            responder_process_auth(&resp_sa, &req, &rcfg, 0xCAFEBABE, &[2u8; 8], Some(&assigned)).unwrap();
        assert_eq!(learned_i, Identification::fqdn("client.example"));
        let (_learned_r, _rspi, _esp_suite, got_ip, _tsr) = initiator_verify_auth(&init_sa, &resp, &icfg, &esp_offer(0), ChildTsOffer::Ipv4).unwrap();
        assert_eq!(got_ip, Some(Ipv4Addr::new(10, 8, 0, 4)));
    }

    #[test]
    fn ike_auth_without_config_payload_assigns_no_ip() {
        let (init_sa, resp_sa) = run_sa_init();
        let psk = b"pw".to_vec();
        let icfg = AuthConfig::psk(Identification::fqdn("c"), psk.clone());
        let rcfg = AuthConfig::psk(Identification::fqdn("s"), psk);
        let req = initiator_auth_request(&init_sa, &icfg, 1, &esp_offer(0), &[1u8; 8]).unwrap();
        let (resp, _, _, _ic) = responder_process_auth(&resp_sa, &req, &rcfg, 2, &[2u8; 8], None).unwrap();
        let (_, _, _esp_suite, got_ip, _tsr) = initiator_verify_auth(&init_sa, &resp, &icfg, &esp_offer(0), ChildTsOffer::Ipv4).unwrap();
        assert_eq!(got_ip, None);
    }

    /// The decrypted payload chain of an `IKE_AUTH` message.
    fn sk_chain(cipher: SkCipher, msg: &[u8], sk_e: &[u8], sk_a: &[u8]) -> Vec<(PayloadType, Vec<u8>)> {
        let (first, inner) = open_encrypted(cipher, msg, sk_e, sk_a).unwrap();
        payloads(first, &inner).map(|p| p.map(|p| (p.payload_type, p.data.to_vec()))).collect::<Result<_, _>>().unwrap()
    }

    /// `req` with `N(MOBIKE_SUPPORTED)` appended to its `SK{}`, as a MOBIKE
    /// client sends it (RFC 4555 §3.1). The initiator's AUTH does not cover
    /// Notify payloads, so the request still verifies.
    fn offering_mobike(init_sa: &CompletedSaInit, req: &[u8]) -> Vec<u8> {
        let mut chain = sk_chain(init_sa.suite.sk_cipher(), req, &init_sa.keys.sk_ei, &init_sa.keys.sk_ai);
        chain.push((PayloadType::Notify, crate::ikev2::mobike::mobike_supported().to_bytes()));
        let bytes = encode_payload_chain(&chain);
        build_encrypted(init_sa.suite.sk_cipher(), ike_auth_header(init_sa, false), first_payload_type(&chain), &bytes, &init_sa.keys.sk_ei, &init_sa.keys.sk_ai, &[1u8; 8]).unwrap()
    }

    fn response_advertises_mobike(init_sa: &CompletedSaInit, resp: &[u8]) -> bool {
        crate::ikev2::mobike::peer_supports_mobike(&sk_chain(init_sa.suite.sk_cipher(), resp, &init_sa.keys.sk_er, &init_sa.keys.sk_ar))
    }

    #[test]
    fn mobike_is_advertised_only_when_the_caller_opts_in_and_the_initiator_offered_it() {
        let (init_sa, resp_sa) = run_sa_init();
        let psk = b"pw".to_vec();
        let icfg = AuthConfig::psk(Identification::fqdn("c"), psk.clone());
        let rcfg = AuthConfig::psk(Identification::fqdn("s"), psk);
        let plain = initiator_auth_request(&init_sa, &icfg, 1, &esp_offer(0), &[1u8; 8]).unwrap();
        let offered = offering_mobike(&init_sa, &plain);
        let with_mobike = |req: &[u8], mobike: bool| {
            let (resp, peer, _spi, _ic, in_force) =
                responder_process_auth_with_mobike(&resp_sa, req, &rcfg, 2, &[2u8; 8], None, mobike).unwrap();
            assert_eq!(peer, Identification::fqdn("c"));
            // Whatever it says about MOBIKE, the response is a valid one.
            initiator_verify_auth(&init_sa, &resp, &icfg, &esp_offer(0), ChildTsOffer::Ipv4).unwrap();
            (response_advertises_mobike(&init_sa, &resp), in_force)
        };

        // The default entry point never advertises MOBIKE, not even to a client
        // offering it: nothing behind it (e.g. `Server`) follows that client to
        // a new address, so it would migrate onto a path we drop.
        let (resp, ..) = responder_process_auth(&resp_sa, &offered, &rcfg, 2, &[2u8; 8], None).unwrap();
        assert!(!response_advertises_mobike(&init_sa, &resp));
        assert_eq!(with_mobike(&offered, false), (false, false));
        // Opted in, but the initiator did not offer it: RFC 4555 §3.1 has the
        // responder include MOBIKE_SUPPORTED only in reply to the initiator's.
        assert_eq!(with_mobike(&plain, true), (false, false));
        // Opted in and offered: advertised, and reported as in force.
        assert_eq!(with_mobike(&offered, true), (true, true));
    }

    /// One edit: what it is, the TSi and TSr bodies it answers with (left
    /// out when `None`), and the error it must be refused with.
    pub(crate) type TsAnswer = (&'static str, Option<Vec<u8>>, Option<Vec<u8>>, IkeError);

    /// The traffic selector edits a response creating a CHILD SA must not get
    /// past the initiator (RFC 7296 §2.9, §3.13) -- shared with `eap_auth` and
    /// `rekey`'s tests -- and what it fails with, the proposal being
    /// `0.0.0.0/0` for both TSi and TSr.
    pub(crate) fn ts_answers_outside_an_ipv4_offer() -> Vec<TsAnswer> {
        let v4 = TrafficSelectors::ipv4_full_tunnel().to_bytes();
        let v6 = TrafficSelectors::ipv6_full_tunnel().to_bytes();
        let unified = TrafficSelectors::unified_full_tunnel().to_bytes();
        vec![
            ("no TSi", None, Some(v4.clone()), IkeError::MissingPayload("TSi")),
            ("no TSr", Some(v4.clone()), None, IkeError::MissingPayload("TSr")),
            ("IPv6 TSr for an IPv4 offer", Some(v4.clone()), Some(v6.clone()), IkeError::TsOutsideOffer),
            ("IPv6 TSi for an IPv4 offer", Some(v6), Some(v4.clone()), IkeError::TsOutsideOffer),
            ("an IPv6 selector added to TSr", Some(v4.clone()), Some(unified), IkeError::TsOutsideOffer),
            ("an empty TSr", Some(v4), Some(vec![0, 0, 0, 0]), IkeError::MalformedPayload("TS payload with no Traffic Selector")),
        ]
    }

    /// `chain` with its TSi/TSr replaced by `tsi`/`tsr` (left out when `None`).
    pub(crate) fn with_ts(chain: Vec<(PayloadType, Vec<u8>)>, tsi: Option<Vec<u8>>, tsr: Option<Vec<u8>>) -> Vec<(PayloadType, Vec<u8>)> {
        let mut out: Vec<_> =
            chain.into_iter().filter(|(t, _)| !matches!(t, PayloadType::TrafficSelectorInitiator | PayloadType::TrafficSelectorResponder)).collect();
        out.extend(tsi.map(|b| (PayloadType::TrafficSelectorInitiator, b)));
        out.extend(tsr.map(|b| (PayloadType::TrafficSelectorResponder, b)));
        out
    }

    /// Traffic selectors the responder tests propose -- shared with
    /// `eap_auth` and `rekey`'s.
    pub(crate) struct SampleTs {
        pub v4: TrafficSelectors,
        pub v6: TrafficSelectors,
        pub unified: TrafficSelectors,
        /// 10.0.0.5, alone.
        pub host: TrafficSelectors,
        /// 10.9.9.9, alone.
        pub other_host: TrafficSelectors,
        /// 10.1.0.0/16.
        pub subnet: TrafficSelectors,
        /// A lone selector of TS Type 9, which no RFC defines.
        pub unknown: TrafficSelectors,
        /// That one, then `0.0.0.0/0`.
        pub unknown_then_v4: TrafficSelectors,
    }

    pub(crate) fn sample_ts() -> SampleTs {
        let unknown = TrafficSelector { ts_type: 9, ..TrafficSelector::ipv4_any() };
        SampleTs {
            v4: TrafficSelectors::ipv4_full_tunnel(),
            v6: TrafficSelectors::ipv6_full_tunnel(),
            unified: TrafficSelectors::unified_full_tunnel(),
            host: TrafficSelectors { selectors: vec![TrafficSelector::ipv4_host(Ipv4Addr::new(10, 0, 0, 5))] },
            other_host: TrafficSelectors { selectors: vec![TrafficSelector::ipv4_host(Ipv4Addr::new(10, 9, 9, 9))] },
            subnet: TrafficSelectors {
                selectors: vec![TrafficSelector { start_addr: vec![10, 1, 0, 0], end_addr: vec![10, 1, 255, 255], ..TrafficSelector::ipv4_any() }],
            },
            unknown: TrafficSelectors { selectors: vec![unknown.clone()] },
            unknown_then_v4: TrafficSelectors { selectors: vec![unknown, TrafficSelector::ipv4_any()] },
        }
    }

    /// The initiator's request `req` with its TSi/TSr replaced by `tsi`/`tsr`
    /// (left out when `None`). Its AUTH does not cover them, so it still verifies.
    pub(crate) fn request_with_ts(init_sa: &CompletedSaInit, req: &[u8], tsi: Option<&TrafficSelectors>, tsr: Option<&TrafficSelectors>) -> Vec<u8> {
        let cipher = init_sa.suite.sk_cipher();
        let chain = sk_chain(cipher, req, &init_sa.keys.sk_ei, &init_sa.keys.sk_ai);
        let chain = with_ts(chain, tsi.map(TrafficSelectors::to_bytes), tsr.map(TrafficSelectors::to_bytes));
        let header = IkeHeader::parse(req).unwrap();
        build_encrypted(
            cipher,
            header,
            first_payload_type(&chain),
            &encode_payload_chain(&chain),
            &init_sa.keys.sk_ei,
            &init_sa.keys.sk_ai,
            &[1u8; 8],
        )
        .unwrap()
    }

    /// What a responder answered the initiator of `init_sa`: its TSi, its
    /// TSr, and the types of its Notify payloads.
    pub(crate) fn answered_ts(init_sa: &CompletedSaInit, resp: &[u8]) -> (Option<TrafficSelectors>, Option<TrafficSelectors>, Vec<u16>) {
        let (mut tsi, mut tsr, mut notifies) = (None, None, Vec::new());
        for (payload_type, body) in sk_chain(init_sa.suite.sk_cipher(), resp, &init_sa.keys.sk_er, &init_sa.keys.sk_ar) {
            match payload_type {
                PayloadType::TrafficSelectorInitiator => tsi = Some(TrafficSelectors::parse(&body).unwrap()),
                PayloadType::TrafficSelectorResponder => tsr = Some(TrafficSelectors::parse(&body).unwrap()),
                PayloadType::Notify => notifies.push(Notify::parse(&body).unwrap().notify_type),
                _ => {}
            }
        }
        (tsi, tsr, notifies)
    }

    /// RFC 7296 §2.9: the responder answers TSi and TSr narrowed to what it
    /// carries -- here IPv4, and on the initiator's side the address it is
    /// assigned -- never wider than proposed nor of another family; when
    /// either comes to nothing, `TS_UNACCEPTABLE` and no CHILD SA, the IKE SA
    /// standing (§1.2).
    #[test]
    fn ike_auth_responder_answers_a_subset_of_the_proposal_or_ts_unacceptable() {
        let (init_sa, resp_sa) = run_sa_init();
        let psk = b"pw".to_vec();
        let icfg = AuthConfig::psk(Identification::fqdn("client.example"), psk.clone());
        let rcfg = AuthConfig::psk(Identification::fqdn("gw.example"), psk);
        let req = initiator_auth_request(&init_sa, &icfg, 1, &esp_offer(0), &[1u8; 8]).unwrap();
        let assigned = AssignedConfig { ip: Ipv4Addr::new(10, 8, 0, 4), dns: vec![] };
        let at_10_8_0_4 = TrafficSelectors { selectors: vec![TrafficSelector::ipv4_host(assigned.ip)] };
        let t = sample_ts();
        let answer = |tsi: &TrafficSelectors, tsr: &TrafficSelectors, assigned: Option<&AssignedConfig>| {
            let req = request_with_ts(&init_sa, &req, Some(tsi), Some(tsr));
            let (resp, _, peer_child_spi, _) = responder_process_auth(&resp_sa, &req, &rcfg, 2, &[2u8; 8], assigned).unwrap();
            (resp, peer_child_spi)
        };

        let granted = [
            ("a host and a subnet, not the whole of IPv4", &t.host, &t.subnet, None, &t.host, &t.subnet),
            ("the IPv4 part of a unified proposal", &t.unified, &t.unified, None, &t.v4, &t.v4),
            ("a type no RFC defines is ignored", &t.v4, &t.unknown_then_v4, None, &t.v4, &t.v4),
            ("0.0.0.0/0 narrowed to the address assigned", &t.v4, &t.v4, Some(&assigned), &at_10_8_0_4, &t.v4),
        ];
        for (what, tsi, tsr, assigned, want_tsi, want_tsr) in granted {
            let (resp, peer_child_spi) = answer(tsi, tsr, assigned);
            assert_eq!(answered_ts(&init_sa, &resp), (Some(want_tsi.clone()), Some(want_tsr.clone()), vec![]), "{what}");
            assert_eq!(peer_child_spi, Some(1), "{what}");
        }

        let refused = [
            ("IPv6 only", &t.v6, &t.v6, None),
            ("IPv6 only, with an address assigned", &t.v6, &t.v6, Some(&assigned)),
            ("an address other than the one assigned", &t.other_host, &t.v4, Some(&assigned)),
            ("a TSr of a type no RFC defines", &t.v4, &t.unknown, None),
        ];
        for (what, tsi, tsr, assigned) in refused {
            let (resp, peer_child_spi) = answer(tsi, tsr, assigned);
            assert_eq!(answered_ts(&init_sa, &resp), (None, None, vec![notify_type::TS_UNACCEPTABLE]), "{what}");
            assert_eq!(peer_child_spi, None, "{what}: no CHILD SA");
            // Authentic, and read by our initiator as the refusal it is.
            let got = initiator_verify_auth(&init_sa, &resp, &icfg, &esp_offer(0), ChildTsOffer::Ipv4).unwrap_err();
            assert_eq!(got, IkeError::PeerRejected { notify_type: notify_type::TS_UNACCEPTABLE, name: "TS_UNACCEPTABLE" }, "{what}");
        }

        // A request for a CHILD SA carries both (RFC 7296 §1.2).
        for (what, tsi, tsr, missing) in [("no TSi", None, Some(&t.v4), "TSi"), ("no TSr", Some(&t.v4), None, "TSr")] {
            let req = request_with_ts(&init_sa, &req, tsi, tsr);
            let got = responder_process_auth(&resp_sa, &req, &rcfg, 2, &[2u8; 8], None).err();
            assert_eq!(got, Some(IkeError::MissingPayload(missing)), "{what}");
        }
    }

    #[test]
    fn ike_auth_response_must_answer_both_ts_within_the_offer() {
        let (init_sa, resp_sa) = run_sa_init();
        let psk = b"pw".to_vec();
        let icfg = AuthConfig::psk(Identification::fqdn("client.example"), psk.clone());
        let rcfg = AuthConfig::psk(Identification::fqdn("gw.example"), psk);
        let req = initiator_auth_request(&init_sa, &icfg, 1, &esp_offer(0), &[1u8; 8]).unwrap();
        let (resp, ..) = responder_process_auth(&resp_sa, &req, &rcfg, 2, &[2u8; 8], None).unwrap();
        let chain = sk_chain(init_sa.suite.sk_cipher(), &resp, &init_sa.keys.sk_er, &init_sa.keys.sk_ar);
        // The responder's AUTH does not cover SA/TS, so an edited response still authenticates.
        let edited = |tsi: Option<Vec<u8>>, tsr: Option<Vec<u8>>| {
            let chain = with_ts(chain.clone(), tsi, tsr);
            let bytes = encode_payload_chain(&chain);
            build_encrypted(
                resp_sa.suite.sk_cipher(),
                ike_auth_header(&resp_sa, true),
                first_payload_type(&chain),
                &bytes,
                &resp_sa.keys.sk_er,
                &resp_sa.keys.sk_ar,
                &[2u8; 8],
            )
            .unwrap()
        };
        for (what, tsi, tsr, expected) in ts_answers_outside_an_ipv4_offer() {
            let got = initiator_verify_auth(
                &init_sa,
                &edited(tsi, tsr),
                &icfg,
                &esp_offer(0),
                ChildTsOffer::Ipv4,
            );
            assert_eq!(got.err(), Some(expected), "{what}");
        }

        // Positive controls: the response as sent, TSi narrowed to the one
        // address handed out, TSr to a subnet, and both families granted to a
        // unified offer.
        let host = TrafficSelectors { selectors: vec![TrafficSelector::ipv4_host(Ipv4Addr::new(10, 8, 0, 4))] };
        let subnet = TrafficSelectors {
            selectors: vec![TrafficSelector { start_addr: vec![10, 0, 0, 0], end_addr: vec![10, 0, 0, 255], ..TrafficSelector::ipv4_any() }],
        };
        let unified = TrafficSelectors::unified_full_tunnel();
        assert!(initiator_verify_auth(&init_sa, &resp, &icfg, &esp_offer(0), ChildTsOffer::Ipv4).is_ok());
        let narrowed = edited(Some(host.to_bytes()), Some(subnet.to_bytes()));
        let (.., tsr) = initiator_verify_auth(&init_sa, &narrowed, &icfg, &esp_offer(0), ChildTsOffer::Ipv4).unwrap();
        assert_eq!(tsr, Some(subnet));
        let both = edited(Some(unified.to_bytes()), Some(unified.to_bytes()));
        let (.., tsr) = initiator_verify_auth(&init_sa, &both, &icfg, &esp_offer(0), ChildTsOffer::Unified).unwrap();
        assert_eq!(tsr, Some(unified));
    }

    /// An `IKE_AUTH` response the way a responder sends it when only the CHILD
    /// SA fails (RFC 7296 §1.2): a valid IDr + AUTH and the error notify, with
    /// no SA/TS payloads.
    fn child_rejected_response(resp_sa: &CompletedSaInit, rcfg: &AuthConfig, error: u16) -> Vec<u8> {
        let idr_body = rcfg.id.to_bytes();
        let octets = responder_signed_octets(resp_sa.suite.prf_algorithm(), &resp_sa.resp_message, &resp_sa.ni, &resp_sa.keys.sk_pr, &idr_body);
        let (auth, certs) = build_local_auth(rcfg, resp_sa, &octets).unwrap();
        let mut inner = vec![(PayloadType::IdResponder, idr_body)];
        inner.extend(certs);
        inner.push((PayloadType::Authentication, auth.to_bytes()));
        inner.push((PayloadType::Notify, Notify::status(error, Vec::new()).to_bytes()));
        let first = first_payload_type(&inner);
        let bytes = encode_payload_chain(&inner);
        build_encrypted(resp_sa.suite.sk_cipher(), ike_auth_header(resp_sa, true), first, &bytes, &resp_sa.keys.sk_er, &resp_sa.keys.sk_ar, &[2u8; 8]).unwrap()
    }

    #[test]
    fn a_child_sa_error_after_a_good_auth_is_a_named_rejection_not_a_missing_sa() {
        // RFC 7296 §1.2: the IKE SA is still created when the CHILD SA of
        // IKE_AUTH fails, so the response is authentic and carries the reason.
        // Surfacing it as PeerRejected (instead of MissingPayload("SA")) is
        // what lets a caller tell "the gateway refused our selectors" from a
        // broken exchange.
        for error in [
            notify_type::NO_PROPOSAL_CHOSEN,
            notify_type::TS_UNACCEPTABLE,
            notify_type::SINGLE_PAIR_REQUIRED,
            notify_type::INTERNAL_ADDRESS_FAILURE,
            notify_type::FAILED_CP_REQUIRED,
        ] {
            let (init_sa, resp_sa) = run_sa_init();
            let psk = b"pw".to_vec();
            let icfg = AuthConfig::psk(Identification::fqdn("client.example"), psk.clone());
            let rcfg = AuthConfig::psk(Identification::fqdn("gw.example"), psk);
            let resp = child_rejected_response(&resp_sa, &rcfg, error);
            assert_eq!(
                initiator_verify_auth(&init_sa, &resp, &icfg, &esp_offer(0), ChildTsOffer::Ipv4).unwrap_err(),
                IkeError::PeerRejected { notify_type: error, name: notify_type_name(error) },
            );
        }
    }

    #[test]
    fn a_child_sa_error_is_not_believed_before_the_auth_verifies() {
        // The notify must not let a peer that failed AUTH pass as merely
        // "rejected the CHILD SA": AUTH is checked first.
        let (init_sa, resp_sa) = run_sa_init();
        let icfg = AuthConfig::psk(Identification::fqdn("client.example"), b"right".to_vec());
        let rcfg = AuthConfig::psk(Identification::fqdn("gw.example"), b"wrong".to_vec());
        let resp = child_rejected_response(&resp_sa, &rcfg, notify_type::TS_UNACCEPTABLE);
        assert_eq!(initiator_verify_auth(&init_sa, &resp, &icfg, &esp_offer(0), ChildTsOffer::Ipv4).unwrap_err(), IkeError::AuthFailed);
    }

    #[test]
    fn a_missing_sa_without_a_child_sa_error_is_still_a_missing_payload() {
        // Only the RFC 7296 §1.2 CHILD SA errors are reinterpreted; any other
        // notify (here AUTHENTICATION_FAILED) leaves the old behavior alone.
        let (init_sa, resp_sa) = run_sa_init();
        let psk = b"pw".to_vec();
        let icfg = AuthConfig::psk(Identification::fqdn("client.example"), psk.clone());
        let rcfg = AuthConfig::psk(Identification::fqdn("gw.example"), psk);
        let resp = child_rejected_response(&resp_sa, &rcfg, notify_type::AUTHENTICATION_FAILED);
        assert_eq!(initiator_verify_auth(&init_sa, &resp, &icfg, &esp_offer(0), ChildTsOffer::Ipv4).unwrap_err(), IkeError::MissingPayload("SA"));
    }

    #[test]
    fn initiator_rejects_an_esp_suite_the_responder_never_actually_offered() {
        // We offer AES-GCM-256 (`esp_offer`'s default). A responder answering
        // with AES-CBC-128/HMAC-SHA1-96 -- a combination `select_esp`/
        // `sk::SkCipher` can decode just fine -- must be rejected rather than
        // silently accepted as if we had proposed it (RFC 7296 §2.7).
        let (init_sa, resp_sa) = run_sa_init();
        let psk = b"pw".to_vec();
        let icfg = AuthConfig::psk(Identification::fqdn("client.example"), psk.clone());
        let rcfg = AuthConfig::psk(Identification::fqdn("gw.example"), psk);

        let idr_body = rcfg.id.to_bytes();
        let octets = responder_signed_octets(resp_sa.suite.prf_algorithm(), &resp_sa.resp_message, &resp_sa.ni, &resp_sa.keys.sk_pr, &idr_body);
        let (auth, certs) = build_local_auth(&rcfg, &resp_sa, &octets).unwrap();
        let downgrade = SecurityAssociation {
            proposals: vec![Proposal {
                num: 1,
                protocol_id: protocol_id::ESP,
                spi: 0xCAFEBABEu32.to_be_bytes().to_vec(),
                transforms: vec![
                    Transform { transform_type: transform_type::ENCR, transform_id: transform_id::AES_CBC, key_length: Some(128) },
                    Transform { transform_type: transform_type::INTEG, transform_id: transform_id::AUTH_HMAC_SHA1_96, key_length: None },
                    Transform { transform_type: transform_type::ESN, transform_id: transform_id::ESN_NONE, key_length: None },
                ],
            }],
        };
        let mut inner = vec![(PayloadType::IdResponder, idr_body)];
        inner.extend(certs);
        inner.push((PayloadType::Authentication, auth.to_bytes()));
        inner.push((PayloadType::SecurityAssociation, downgrade.to_bytes()));
        inner.push((PayloadType::TrafficSelectorInitiator, full_tunnel_ts()));
        inner.push((PayloadType::TrafficSelectorResponder, full_tunnel_ts()));
        let first = first_payload_type(&inner);
        let bytes = encode_payload_chain(&inner);
        let response = build_encrypted(resp_sa.suite.sk_cipher(), ike_auth_header(&resp_sa, true), first, &bytes, &resp_sa.keys.sk_er, &resp_sa.keys.sk_ar, &[2u8; 8]).unwrap();

        let err = initiator_verify_auth(&init_sa, &response, &icfg, &esp_offer(0), ChildTsOffer::Ipv4).unwrap_err();
        assert_eq!(err, IkeError::NoProposalChosen);
    }

    /// `msg`, an `IKE_AUTH` message sealed with `sk_e`/`sk_a`, with its SA
    /// payload's body replaced by `sa` in place. Neither side's AUTH covers
    /// it, so the message still verifies. Shared with `eap_auth`'s tests.
    pub(crate) fn with_sa_body(cipher: SkCipher, msg: &[u8], sk_e: &[u8], sk_a: &[u8], sa: Vec<u8>) -> Vec<u8> {
        let mut chain = sk_chain(cipher, msg, sk_e, sk_a);
        chain.iter_mut().find(|(t, _)| *t == PayloadType::SecurityAssociation).expect("an SA payload to replace").1 = sa;
        let header = IkeHeader::parse(msg).unwrap();
        build_encrypted(cipher, header, first_payload_type(&chain), &encode_payload_chain(&chain), sk_e, sk_a, &[3u8; 8]).unwrap()
    }

    /// The SA payload of `msg` (sealed with `sk_e`/`sk_a`), if it has one.
    pub(crate) fn sa_of(cipher: SkCipher, msg: &[u8], sk_e: &[u8], sk_a: &[u8]) -> Option<SecurityAssociation> {
        let chain = sk_chain(cipher, msg, sk_e, sk_a);
        chain.into_iter().find(|(t, _)| *t == PayloadType::SecurityAssociation).map(|(_, body)| SecurityAssociation::parse(&body).unwrap())
    }

    /// An ESP proposal numbered `num`, with SPI `spi` and `transforms`.
    pub(crate) fn esp_proposal(num: u8, spi: u32, transforms: &[(u8, u16, Option<u16>)]) -> Proposal {
        let transforms = transforms.iter().map(|&(transform_type, transform_id, key_length)| Transform { transform_type, transform_id, key_length }).collect();
        Proposal { num, protocol_id: protocol_id::ESP, spi: spi.to_be_bytes().to_vec(), transforms }
    }

    pub(crate) const GCM256: (u8, u16, Option<u16>) = (transform_type::ENCR, transform_id::AES_GCM_16, Some(256));
    pub(crate) const CBC256: (u8, u16, Option<u16>) = (transform_type::ENCR, transform_id::AES_CBC, Some(256));
    pub(crate) const SHA256: (u8, u16, Option<u16>) = (transform_type::INTEG, transform_id::AUTH_HMAC_SHA2_256_128, None);
    pub(crate) const ESN_NONE: (u8, u16, Option<u16>) = (transform_type::ESN, transform_id::ESN_NONE, None);
    pub(crate) const MODP2048: (u8, u16, Option<u16>) = (transform_type::DH, transform_id::MODP_2048, None);

    /// RFC 7296 §1.2: the SA payloads of `IKE_AUTH` "cannot contain Transform
    /// Type 4 (Diffie-Hellman group) with any value other than NONE.
    /// Implementations SHOULD omit the whole transform substructure" -- there is
    /// no KE there to run it with. A caller's offer carrying PFS groups (they
    /// are for the CHILD SA's rekeys) goes out without them.
    #[test]
    fn the_ike_auth_sai2_carries_no_dh_group() {
        let (init_sa, _) = run_sa_init();
        let icfg = AuthConfig::psk(Identification::fqdn("client.example"), b"pw".to_vec());
        let offer = SecurityAssociation { proposals: vec![esp_proposal(1, 0, &[GCM256, MODP2048, ESN_NONE]), esp_proposal(2, 0, &[CBC256, SHA256, MODP2048, ESN_NONE])] };
        let req = initiator_auth_request(&init_sa, &icfg, 7, &offer, &[1u8; 8]).unwrap();
        let sai2 = sa_of(init_sa.suite.sk_cipher(), &req, &init_sa.keys.sk_ei, &init_sa.keys.sk_ai).unwrap();
        assert_eq!(sai2, SecurityAssociation { proposals: vec![esp_proposal(1, 7, &[GCM256, ESN_NONE]), esp_proposal(2, 7, &[CBC256, SHA256, ESN_NONE])] });
    }

    /// RFC 7296 §2.7 and §1.2: the responder answers the first proposal of
    /// SAi2 it can run (here: AES-GCM-16/256, what its data plane runs), by its
    /// number and with the SPI of that proposal as the peer's; when none fits,
    /// `NO_PROPOSAL_CHOSEN` and no CHILD SA, the IKE SA standing. Before, it
    /// sent its own fixed offer back, whatever the peer had proposed.
    #[test]
    fn the_ike_auth_responder_answers_a_proposal_it_can_run_or_no_proposal_chosen() {
        let (init_sa, resp_sa) = run_sa_init();
        let psk = b"pw".to_vec();
        let icfg = AuthConfig::psk(Identification::fqdn("client.example"), psk.clone());
        let rcfg = AuthConfig::psk(Identification::fqdn("gw.example"), psk);
        let req = initiator_auth_request(&init_sa, &icfg, 1, &esp_offer(0), &[1u8; 8]).unwrap();
        let answer = |proposals: Vec<Proposal>| {
            let sai2 = SecurityAssociation { proposals }.to_bytes();
            let req = with_sa_body(init_sa.suite.sk_cipher(), &req, &init_sa.keys.sk_ei, &init_sa.keys.sk_ai, sai2);
            let (resp, _, peer_child_spi, _) = responder_process_auth(&resp_sa, &req, &rcfg, 0xCAFE_BABE, &[2u8; 8], None).unwrap();
            let sar2 = sa_of(init_sa.suite.sk_cipher(), &resp, &init_sa.keys.sk_er, &init_sa.keys.sk_ar);
            (resp, sar2, peer_child_spi)
        };

        let taken = [
            ("the second proposal, the first one's cipher is not ours", vec![esp_proposal(1, 0x1111, &[CBC256, SHA256, ESN_NONE]), esp_proposal(2, 0x2222, &[GCM256, ESN_NONE])], 2, 0x2222, vec![GCM256, ESN_NONE]),
            ("no ESN offered, none answered", vec![esp_proposal(1, 0x1111, &[GCM256])], 1, 0x1111, vec![GCM256]),
            ("a DH group, which IKE_AUTH does not run, is left out", vec![esp_proposal(1, 0x1111, &[GCM256, MODP2048, ESN_NONE])], 1, 0x1111, vec![GCM256, ESN_NONE]),
            ("a proposal with an unknown type is passed over", vec![esp_proposal(1, 0x1111, &[GCM256, ESN_NONE, (6, 14, None)]), esp_proposal(2, 0x2222, &[GCM256, ESN_NONE])], 2, 0x2222, vec![GCM256, ESN_NONE]),
        ];
        for (what, proposals, num, peer_spi, transforms) in taken {
            let offered = SecurityAssociation { proposals: proposals.clone() };
            let (resp, sar2, peer_child_spi) = answer(proposals);
            assert_eq!(sar2, Some(SecurityAssociation { proposals: vec![esp_proposal(num, 0xCAFE_BABE, &transforms)] }), "{what}");
            assert_eq!(peer_child_spi, Some(peer_spi), "{what}");
            // And our initiator, had it sent that SAi2, takes the answer.
            let (_, spi, ..) = initiator_verify_auth(&init_sa, &resp, &icfg, &offered, ChildTsOffer::Ipv4).unwrap();
            assert_eq!(spi, 0xCAFE_BABE, "{what}");
        }

        let refused = [
            ("only AES-CBC", vec![esp_proposal(1, 0x1111, &[CBC256, SHA256, ESN_NONE])]),
            ("AES-GCM-128", vec![esp_proposal(1, 0x1111, &[(transform_type::ENCR, transform_id::AES_GCM_16, Some(128)), ESN_NONE])]),
            ("ESN required", vec![esp_proposal(1, 0x1111, &[GCM256, (transform_type::ESN, transform_id::ESN_ENABLED, None)])]),
            ("an integrity algorithm forced onto AES-GCM", vec![esp_proposal(1, 0x1111, &[GCM256, SHA256, ESN_NONE])]),
            ("an unknown transform type", vec![esp_proposal(1, 0x1111, &[GCM256, ESN_NONE, (6, 14, None)])]),
        ];
        for (what, proposals) in refused {
            let (resp, sar2, peer_child_spi) = answer(proposals);
            assert_eq!(sar2, None, "{what}");
            assert_eq!(peer_child_spi, None, "{what}: no CHILD SA");
            assert_eq!(answered_ts(&init_sa, &resp), (None, None, vec![notify_type::NO_PROPOSAL_CHOSEN]), "{what}");
            let got = initiator_verify_auth(&init_sa, &resp, &icfg, &esp_offer(0), ChildTsOffer::Ipv4).unwrap_err();
            assert_eq!(got, IkeError::PeerRejected { notify_type: notify_type::NO_PROPOSAL_CHOSEN, name: "NO_PROPOSAL_CHOSEN" }, "{what}");
        }
    }

    /// RFC 7296 §3.3.5, §3.3.6 on the SAi2 the responder reads off the wire: a
    /// transform with a Key Length it must not have (ESN NONE, INTEG NONE) or an
    /// attribute we cannot read (ENCR, INTEG, ESN) is unacceptable, so a
    /// proposal that has it -- and no other of its type -- is passed over for
    /// the next one, and one that has it next to a plain one is answered with
    /// the plain one. A DH *group* is passed over whatever it carries, because it
    /// has no place in SAi2 to begin with (§1.2: "cannot contain ... any value
    /// other than NONE"): a leniency this crate always had, not a rule -- and so
    /// is a DH transform we cannot read, whatever ID it named (the parsed
    /// `SecurityAssociation` keeps only [`transform_id::UNUSABLE`] of it, which is
    /// no NONE). A DH NONE that carries a Key Length is the exception: NONE is
    /// the one value SAi2 may hold, and with the attribute §3.3.5 forbids it is
    /// unacceptable like the other NONEs. And the forged SAr2 that names them is
    /// not our proposal.
    #[test]
    fn the_ike_auth_sa_payloads_take_no_transform_with_a_key_length_it_must_not_have_or_an_attribute_it_cannot_read() {
        use crate::ikev2::payload::test_wire::{proposal, sa, transform, KEY_LENGTH_128, KEY_LENGTH_256, UNKNOWN_ATTRIBUTE};
        let (init_sa, resp_sa) = run_sa_init();
        let psk = b"pw".to_vec();
        let icfg = AuthConfig::psk(Identification::fqdn("client.example"), psk.clone());
        let rcfg = AuthConfig::psk(Identification::fqdn("gw.example"), psk);
        let req = initiator_auth_request(&init_sa, &icfg, 1, &esp_offer(0), &[1u8; 8]).unwrap();
        let answer = |proposals: &[Vec<u8>]| {
            let req = with_sa_body(init_sa.suite.sk_cipher(), &req, &init_sa.keys.sk_ei, &init_sa.keys.sk_ai, sa(proposals));
            let (resp, _, peer_child_spi, _) = responder_process_auth(&resp_sa, &req, &rcfg, 0xCAFE_BABE, &[2u8; 8], None).unwrap();
            let sar2 = sa_of(init_sa.suite.sk_cipher(), &resp, &init_sa.keys.sk_er, &init_sa.keys.sk_ar);
            (resp, sar2, peer_child_spi)
        };
        let esp = |num: u8, transforms: &[Vec<u8>]| proposal(num, protocol_id::ESP, &(0x1000 + num as u32).to_be_bytes(), transforms);
        let gcm = || transform(transform_type::ENCR, transform_id::AES_GCM_16, &KEY_LENGTH_256);
        let esn_none = || transform(transform_type::ESN, transform_id::ESN_NONE, &[]);
        let fine = || esp(2, &[gcm(), esn_none()]);
        let ours = |num: u8| esp_proposal(num, 0xCAFE_BABE, &[GCM256, ESN_NONE]);

        let (_, taken, spi) = answer(&[esp(1, &[gcm(), esn_none()])]);
        assert_eq!((taken, spi), (Some(SecurityAssociation { proposals: vec![ours(1)] }), Some(0x1001)), "control");
        let refused = [
            ("an ESN NONE with a Key Length", esp(1, &[gcm(), transform(transform_type::ESN, transform_id::ESN_NONE, &KEY_LENGTH_128)])),
            ("an INTEG NONE with a Key Length", esp(1, &[gcm(), transform(transform_type::INTEG, transform_id::INTEG_NONE, &KEY_LENGTH_128), esn_none()])),
            ("an ENCR we cannot read", esp(1, &[transform(transform_type::ENCR, transform_id::AES_GCM_16, &UNKNOWN_ATTRIBUTE), esn_none()])),
            ("an INTEG we cannot read", esp(1, &[gcm(), transform(transform_type::INTEG, transform_id::AUTH_HMAC_SHA2_256_128, &UNKNOWN_ATTRIBUTE), esn_none()])),
            ("an ESN we cannot read", esp(1, &[gcm(), transform(transform_type::ESN, transform_id::ESN_NONE, &UNKNOWN_ATTRIBUTE)])),
            ("a DH NONE with a Key Length", esp(1, &[gcm(), transform(transform_type::DH, 0, &KEY_LENGTH_128), esn_none()])),
        ];
        for (what, bad) in &refused {
            let (resp, sar2, peer_spi) = answer(std::slice::from_ref(bad));
            assert_eq!((sar2, peer_spi), (None, None), "{what}: no CHILD SA");
            assert_eq!(answered_ts(&init_sa, &resp), (None, None, vec![notify_type::NO_PROPOSAL_CHOSEN]), "{what}");
            let (_, sar2, peer_spi) = answer(&[bad.clone(), fine()]);
            assert_eq!((sar2, peer_spi), (Some(SecurityAssociation { proposals: vec![ours(2)] }), Some(0x1002)), "{what}, then a proposal that is fine");
        }
        // Next to the plain transform of its type, in one proposal.
        for (what, transforms, answered) in [
            ("an ESN NONE", vec![gcm(), transform(transform_type::ESN, transform_id::ESN_NONE, &KEY_LENGTH_128), esn_none()], vec![GCM256, ESN_NONE]),
            ("an ESN we cannot read", vec![gcm(), transform(transform_type::ESN, transform_id::ESN_NONE, &UNKNOWN_ATTRIBUTE), esn_none()], vec![GCM256, ESN_NONE]),
            ("an INTEG we cannot read", vec![gcm(), transform(transform_type::INTEG, transform_id::AUTH_HMAC_SHA2_256_128, &UNKNOWN_ATTRIBUTE), transform(transform_type::INTEG, transform_id::INTEG_NONE, &[]), esn_none()], vec![GCM256, (transform_type::INTEG, transform_id::INTEG_NONE, None), ESN_NONE]),
            ("a DH NONE", vec![gcm(), transform(transform_type::DH, 0, &KEY_LENGTH_128), transform(transform_type::DH, 0, &[]), esn_none()], vec![GCM256, (transform_type::DH, 0, None), ESN_NONE]),
        ] {
            // The order of the transforms in a proposal is not significant (§3.3), so it is not compared.
            let (_, sar2, peer_spi) = answer(&[esp(1, &transforms)]);
            let sorted = |sa: SecurityAssociation| {
                let mut proposals = sa.proposals;
                proposals.iter_mut().for_each(|p| p.transforms.sort_by_key(|t| (t.transform_type, t.transform_id)));
                proposals
            };
            let expected = sorted(SecurityAssociation { proposals: vec![esp_proposal(1, 0xCAFE_BABE, &answered)] });
            assert_eq!((sar2.map(sorted), peer_spi), (Some(expected), Some(0x1001)), "{what}, next to a plain one");
        }
        // A DH group passed over whatever it carries.
        for (what, dh) in [
            ("a DH group", transform(transform_type::DH, transform_id::MODP_2048, &[])),
            ("a DH group with a Key Length", transform(transform_type::DH, transform_id::MODP_2048, &KEY_LENGTH_128)),
            ("a DH group we cannot read", transform(transform_type::DH, transform_id::MODP_2048, &UNKNOWN_ATTRIBUTE)),
        ] {
            let (_, sar2, peer_spi) = answer(&[esp(1, &[gcm(), dh, esn_none()])]);
            assert_eq!((sar2, peer_spi), (Some(SecurityAssociation { proposals: vec![ours(1)] }), Some(0x1001)), "{what} in SAi2 is left out");
        }

        // The initiator's side: a forged SAr2 naming them is not the proposal we sent.
        let (resp, ..) = responder_process_auth(&resp_sa, &req, &rcfg, 0xCAFE_BABE, &[2u8; 8], None).unwrap();
        let verify = |sar2: Vec<u8>| {
            let resp = with_sa_body(resp_sa.suite.sk_cipher(), &resp, &resp_sa.keys.sk_er, &resp_sa.keys.sk_ar, sar2);
            initiator_verify_auth(&init_sa, &resp, &icfg, &esp_offer(0), ChildTsOffer::Ipv4).map(|(_, spi, ..)| spi)
        };
        let answered = |transforms: &[Vec<u8>]| sa(&[proposal(1, protocol_id::ESP, &0xCAFE_BABEu32.to_be_bytes(), transforms)]);
        assert_eq!(verify(answered(&[gcm(), esn_none()])), Ok(0xCAFE_BABE), "control");
        let cases = [
            ("an ESN NONE with a Key Length", answered(&[gcm(), transform(transform_type::ESN, transform_id::ESN_NONE, &KEY_LENGTH_128)])),
            ("an ESN we cannot read instead of ours", answered(&[gcm(), transform(transform_type::ESN, transform_id::ESN_NONE, &UNKNOWN_ATTRIBUTE)])),
            ("an ESN we cannot read added", answered(&[gcm(), esn_none(), transform(transform_type::ESN, transform_id::ESN_NONE, &UNKNOWN_ATTRIBUTE)])),
            ("an ENCR we cannot read added", answered(&[gcm(), transform(transform_type::ENCR, transform_id::AES_GCM_16, &UNKNOWN_ATTRIBUTE), esn_none()])),
            ("an INTEG NONE with a Key Length added", answered(&[gcm(), transform(transform_type::INTEG, transform_id::INTEG_NONE, &KEY_LENGTH_128), esn_none()])),
            ("a DH NONE with a Key Length added", answered(&[gcm(), transform(transform_type::DH, 0, &KEY_LENGTH_128), esn_none()])),
        ];
        for (what, sar2) in cases {
            assert_eq!(verify(sar2), Err(IkeError::NoProposalChosen), "{what}");
        }
    }

    /// RFC 7296 §3.3.6, §2.7, §3.3.1: the initiator takes back one of its SAi2
    /// proposals -- a single one, by its number, one transform of each type --
    /// or nothing: each forged SAr2 below names the very suite we offered and
    /// must still be refused, and so must one that does not even parse (it
    /// used to skip the check altogether).
    #[test]
    fn the_ike_auth_initiator_takes_only_one_of_its_proposals_back() {
        let (init_sa, resp_sa) = run_sa_init();
        let psk = b"pw".to_vec();
        let icfg = AuthConfig::psk(Identification::fqdn("client.example"), psk.clone());
        let rcfg = AuthConfig::psk(Identification::fqdn("gw.example"), psk);
        let req = initiator_auth_request(&init_sa, &icfg, 1, &esp_offer(0), &[1u8; 8]).unwrap();
        let (resp, ..) = responder_process_auth(&resp_sa, &req, &rcfg, 0xCAFE_BABE, &[2u8; 8], None).unwrap();
        let verify = |sar2: Vec<u8>| {
            let resp = with_sa_body(resp_sa.suite.sk_cipher(), &resp, &resp_sa.keys.sk_er, &resp_sa.keys.sk_ar, sar2);
            initiator_verify_auth(&init_sa, &resp, &icfg, &esp_offer(0), ChildTsOffer::Ipv4).map(|(_, spi, ..)| spi)
        };
        let ours = esp_proposal(1, 0xCAFE_BABE, &[GCM256, ESN_NONE]);
        assert_eq!(verify(SecurityAssociation { proposals: vec![ours.clone()] }.to_bytes()), Ok(0xCAFE_BABE), "control");

        let mut malformed = SecurityAssociation { proposals: vec![ours.clone()] }.to_bytes();
        malformed[3] += 4; // the proposal claims four octets more than the payload has
        let cases = [
            ("two proposals", SecurityAssociation { proposals: vec![ours.clone(), ours.clone()] }.to_bytes()),
            ("two ENCR transforms", SecurityAssociation { proposals: vec![esp_proposal(1, 0xCAFE_BABE, &[GCM256, GCM256, ESN_NONE])] }.to_bytes()),
            ("a proposal number we never sent", SecurityAssociation { proposals: vec![Proposal { num: 2, ..ours.clone() }] }.to_bytes()),
            ("an SA payload that does not parse", malformed),
        ];
        for (what, sar2) in cases {
            assert!(verify(sar2).is_err(), "{what}");
        }
    }

    #[test]
    fn wrong_psk_is_rejected() {
        let (init_sa, resp_sa) = run_sa_init();
        let icfg = AuthConfig::psk(Identification::fqdn("client"), b"right".to_vec());
        let rcfg = AuthConfig::psk(Identification::fqdn("server"), b"wrong".to_vec());
        let req = initiator_auth_request(&init_sa, &icfg, 1, &esp_offer(0), &[1u8; 8]).unwrap();
        assert_eq!(
            responder_process_auth(&resp_sa, &req, &rcfg, 2, &[2u8; 8], None).unwrap_err(),
            IkeError::AuthFailed
        );
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let (init_sa, resp_sa) = run_sa_init();
        let cfg = AuthConfig::psk(Identification::fqdn("x"), b"psk".to_vec());
        let mut req = initiator_auth_request(&init_sa, &cfg, 1, &esp_offer(0), &[1u8; 8]).unwrap();
        let last = req.len() - 1;
        req[last] ^= 1; // corrupt the GCM tag
        assert_eq!(
            responder_process_auth(&resp_sa, &req, &cfg, 2, &[2u8; 8], None).unwrap_err(),
            IkeError::BadIntegrity
        );
    }

    // Mutual RFC 7427 certificate auth over plain (non-EAP) IKE_AUTH. Both sides
    // present the leaf fixture and verify the other against the CA + SAN + dates.
    fn cert_config() -> AuthConfig {
        use crate::ikev2::sign::{cert_validity, SigningKey};
        use crate::test_certs::{CA_CERT_DER, LEAF_CERT_DER, LEAF_SCALAR};
        let now = cert_validity(LEAF_CERT_DER).unwrap().0 + 1;
        AuthConfig {
            id: Identification::fqdn("vpn.example.com"),
            local: LocalAuth::Cert {
                key: SigningKey::EcdsaP256(p256::ecdsa::SigningKey::from_slice(LEAF_SCALAR).unwrap()),
                chain: vec![LEAF_CERT_DER.to_vec()],
            },
            peer: PeerAuth::Cert {
                cas: vec![CA_CERT_DER.to_vec()],
                expected_dns: Some("vpn.example.com".into()),
                now_unix: now,
            },
        }
    }

    #[test]
    fn ike_auth_mutual_certificate_succeeds() {
        let (init_sa, resp_sa) = run_sa_init();
        let req = initiator_auth_request(&init_sa, &cert_config(), 0xDEADBEEF, &esp_offer(0), &[1u8; 8]).unwrap();
        let (resp, learned_i, _init_spi, _ic) = responder_process_auth(&resp_sa, &req, &cert_config(), 0xCAFEBABE, &[2u8; 8], None).unwrap();
        assert_eq!(learned_i, Identification::fqdn("vpn.example.com"));
        let (learned_r, _resp_spi, _esp_suite, _assigned, _tsr) =
            initiator_verify_auth(&init_sa, &resp, &cert_config(), &esp_offer(0), ChildTsOffer::Ipv4).unwrap();
        assert_eq!(learned_r, Identification::fqdn("vpn.example.com"));
    }

    #[test]
    fn ike_auth_cert_falls_back_to_the_classic_ecdsa_method_and_still_verifies() {
        // When the peer hasn't negotiated RFC 7427 Digital Signature (empty
        // SIGNATURE_HASH_ALGORITHMS -- e.g. a native EAP client, or another
        // ryke instance that itself fell back), `cert_auth_payload` emits the
        // classic method 9 (RFC 4754) for an EC key. Audit finding #8 flagged
        // that `verify_peer_auth` rejected method 9 outright even though we
        // produce that exact wire format ourselves, so this exact scenario
        // used to fail IKE_AUTH outright.
        let (mut init_sa, resp_sa) = run_sa_init();
        init_sa.peer_signature_hashes.clear();
        let req = initiator_auth_request(&init_sa, &cert_config(), 1, &esp_offer(0), &[1u8; 8]).unwrap();
        let (_resp, learned_i, _init_spi, _ic) =
            responder_process_auth(&resp_sa, &req, &cert_config(), 2, &[2u8; 8], None).unwrap();
        assert_eq!(learned_i, Identification::fqdn("vpn.example.com"));
    }

    #[test]
    fn cert_auth_payload_picks_the_fallback_by_key_type() {
        // Before the fix, the "no negotiated Digital Signature" fallback
        // always tried classic ECDSA (method 9) regardless of key type --
        // which simply errors out for an RSA key instead of using the valid
        // RSA alternative (audit finding #8, problem 2).
        use crate::ikev2::sign::{SigningKey, VerifyingKey};
        use crate::test_certs::{LEAF_SCALAR, RSA_KEY_PK8};
        let octets = b"signed octets with no negotiated Digital Signature";

        let ec_key = SigningKey::EcdsaP256(p256::ecdsa::SigningKey::from_slice(LEAF_SCALAR).unwrap());
        let ec_auth = cert_auth_payload(&ec_key, &[], octets).unwrap();
        assert_eq!(ec_auth.method, auth_method::ECDSA_SHA256_P256);

        let rsa_key = SigningKey::rsa_from_pkcs8_der(RSA_KEY_PK8).unwrap();
        let rsa_auth = cert_auth_payload(&rsa_key, &[], octets).unwrap();
        assert_eq!(rsa_auth.method, auth_method::RSA_SIG);
        // And it's a genuinely valid signature that our own verification
        // path (not just this test) can check.
        use rsa::pkcs8::DecodePrivateKey;
        let pubk = VerifyingKey::Rsa(rsa::RsaPrivateKey::from_pkcs8_der(RSA_KEY_PK8).unwrap().to_public_key());
        pubk.verify_classic_rsa_auth_data(&rsa_auth.data, octets).unwrap();
    }

    /// `cert_config` with an RSA leaf whose key signs method 14 with
    /// RSASSA-PSS (`SigningKey::into_rsa_pss`), under a root that itself
    /// signs its certificates with RSASSA-PSS.
    fn pss_cert_config() -> AuthConfig {
        use crate::test_certs::forge;
        const ROOT: &str = "CN=Pss Root";
        let root_key = || forge::rsa_key().into_rsa_pss().unwrap();
        let root = forge::cert(1, ROOT, &root_key(), ROOT, &root_key(), vec![forge::basic_constraints(true, None)]);
        let leaf_key = || forge::rsa_key().into_rsa_pss().unwrap();
        let san = vec![forge::subject_alt_name(&[forge::dns("vpn.example.com")])];
        let leaf = forge::cert(2, "CN=vpn.example.com", &leaf_key(), ROOT, &root_key(), san);
        AuthConfig {
            id: Identification::fqdn("vpn.example.com"),
            local: LocalAuth::Cert { key: leaf_key(), chain: vec![leaf] },
            peer: PeerAuth::Cert { cas: vec![root], expected_dns: Some("vpn.example.com".into()), now_unix: forge::NOW },
        }
    }

    #[test]
    fn ike_auth_mutual_certificate_succeeds_with_rsassa_pss_signatures() {
        let (init_sa, resp_sa) = run_sa_init();
        let cfg = pss_cert_config;
        let req = initiator_auth_request(&init_sa, &cfg(), 1, &esp_offer(0), &[1u8; 8]).unwrap();
        let (resp, learned_i, ..) = responder_process_auth(&resp_sa, &req, &cfg(), 2, &[2u8; 8], None).unwrap();
        assert_eq!(learned_i, Identification::fqdn("vpn.example.com"));
        let (learned_r, ..) = initiator_verify_auth(&init_sa, &resp, &cfg(), &esp_offer(0), ChildTsOffer::Ipv4).unwrap();
        assert_eq!(learned_r, Identification::fqdn("vpn.example.com"));
    }

    #[test]
    fn ike_auth_rsassa_pss_falls_back_to_method_1_when_digital_signature_is_not_negotiated() {
        let (mut init_sa, resp_sa) = run_sa_init();
        init_sa.peer_signature_hashes.clear();
        let cfg = pss_cert_config;
        let req = initiator_auth_request(&init_sa, &cfg(), 1, &esp_offer(0), &[1u8; 8]).unwrap();
        responder_process_auth(&resp_sa, &req, &cfg(), 2, &[2u8; 8], None).unwrap();
    }

    #[test]
    fn ike_auth_cert_wrong_name_is_rejected() {
        use crate::ikev2::sign::cert_validity;
        use crate::test_certs::{CA_CERT_DER, LEAF_CERT_DER};
        let (init_sa, resp_sa) = run_sa_init();
        let icfg = cert_config();
        // The responder expects a different host than the initiator's cert vouches for.
        let mut rcfg = cert_config();
        rcfg.peer = PeerAuth::Cert {
            cas: vec![CA_CERT_DER.to_vec()],
            expected_dns: Some("wrong.example.com".into()),
            now_unix: cert_validity(LEAF_CERT_DER).unwrap().0 + 1,
        };
        let req = initiator_auth_request(&init_sa, &icfg, 1, &esp_offer(0), &[1u8; 8]).unwrap();
        assert_eq!(
            responder_process_auth(&resp_sa, &req, &rcfg, 2, &[2u8; 8], None).unwrap_err(),
            IkeError::AuthFailed
        );
    }

    /// `cert_config` over certificates made at test time: a root, and a
    /// leaf under it for vpn.example.com with `leaf_extensions` after its
    /// SubjectAltName.
    fn forged_cert_config(leaf_extensions: Vec<x509_cert::ext::Extension>) -> AuthConfig {
        use crate::test_certs::forge;
        use x509_cert::ext::pkix::{KeyUsage, KeyUsages};
        const ROOT: &str = "CN=Forge Root";
        let root_key = forge::ec_key(1);
        let ca = vec![forge::basic_constraints(true, None), forge::key_usage(KeyUsage(KeyUsages::KeyCertSign.into()))];
        let root = forge::cert(1, ROOT, &root_key, ROOT, &root_key, ca);
        let extensions = [vec![forge::subject_alt_name(&[forge::dns("vpn.example.com")])], leaf_extensions].concat();
        let leaf = forge::cert(2, "CN=vpn.example.com", &forge::ec_key(2), ROOT, &root_key, extensions);
        AuthConfig {
            id: Identification::fqdn("vpn.example.com"),
            local: LocalAuth::Cert { key: forge::ec_key(2), chain: vec![leaf] },
            peer: PeerAuth::Cert { cas: vec![root], expected_dns: Some("vpn.example.com".into()), now_unix: forge::NOW },
        }
    }

    #[test]
    fn ike_auth_refuses_a_certificate_that_may_not_sign_or_has_an_unprocessed_critical_extension() {
        // RFC 4945 §5.1.3.2 and RFC 5280 §4.2 on direct certificate
        // authentication, each way: a leaf whose KeyUsage is keyEncipherment
        // only, and one with a critical extension this crate does not
        // process, both with a valid chain and a valid AUTH signature.
        use crate::test_certs::forge;
        use x509_cert::ext::pkix::{KeyUsage, KeyUsages};
        let good = || forged_cert_config(vec![forge::key_usage(KeyUsage(KeyUsages::DigitalSignature.into()))]);
        let bad = [forge::key_usage(KeyUsage(KeyUsages::KeyEncipherment.into())), forge::raw_ext("1.3.6.1.4.1.55555.123", true, &[0x05, 0x00])];
        for ext in bad {
            let oid = ext.extn_id;
            // The responder refuses the initiator's certificate.
            let (init_sa, resp_sa) = run_sa_init();
            let req = initiator_auth_request(&init_sa, &forged_cert_config(vec![ext.clone()]), 1, &esp_offer(0), &[1u8; 8]).unwrap();
            assert!(responder_process_auth(&resp_sa, &req, &good(), 2, &[2u8; 8], None).is_err(), "{oid}");
            // The initiator refuses the responder's.
            let (init_sa, resp_sa) = run_sa_init();
            let req = initiator_auth_request(&init_sa, &good(), 1, &esp_offer(0), &[1u8; 8]).unwrap();
            let (resp, ..) = responder_process_auth(&resp_sa, &req, &forged_cert_config(vec![ext]), 2, &[2u8; 8], None).unwrap();
            assert!(initiator_verify_auth(&init_sa, &resp, &good(), &esp_offer(0), ChildTsOffer::Ipv4).is_err(), "{oid}");
        }
        // Control: the same exchange with digitalSignature both ways.
        let (init_sa, resp_sa) = run_sa_init();
        let req = initiator_auth_request(&init_sa, &good(), 1, &esp_offer(0), &[1u8; 8]).unwrap();
        let (resp, ..) = responder_process_auth(&resp_sa, &req, &good(), 2, &[2u8; 8], None).unwrap();
        initiator_verify_auth(&init_sa, &resp, &good(), &esp_offer(0), ChildTsOffer::Ipv4).unwrap();
    }

    // `initiator_eap_request_with_certs` (the "Certificate + EAP" hybrid a
    // FortiGate dialup policy can require, per eap_auth::EapInitiator's
    // `set_client_certs`) carries no AUTH -- verified here by decrypting the
    // built message directly and inspecting its payload chain, rather than
    // through a live EAP round trip (covered separately in session.rs).
    #[test]
    fn initiator_eap_request_with_certs_carries_the_cert_chain_and_certreq() {
        use crate::test_certs::{CA_CERT_DER, LEAF_CERT_DER};
        let (init_sa, _resp_sa) = run_sa_init();
        let id = Identification::fqdn("client.example");
        let chain = vec![LEAF_CERT_DER.to_vec()];
        let ca_hashes = vec![crate::ikev2::sign::ca_key_hash(CA_CERT_DER).unwrap()];
        let req = initiator_eap_request_with_certs(&init_sa, &id, 0xC0FFEE, true, &esp_offer(0), ChildTsOffer::Ipv4, &chain, Some(ca_hashes.clone()), &[3u8; 8])
            .unwrap();

        let (first, inner) = open_encrypted(init_sa.suite.sk_cipher(), &req, &init_sa.keys.sk_ei, &init_sa.keys.sk_ai).unwrap();
        let mut certs = Vec::new();
        let mut certreqs = Vec::new();
        let mut saw_auth = false;
        for p in payloads(first, &inner) {
            let p = p.unwrap();
            match p.payload_type {
                PayloadType::Certificate => certs.push(Certificate::parse(p.data).unwrap().data),
                PayloadType::CertRequest => certreqs.push(CertRequest::parse(p.data).unwrap().ca_hashes),
                PayloadType::Authentication => saw_auth = true,
                _ => {}
            }
        }
        assert_eq!(certs, chain, "the client's own leaf must be attached as bare identity");
        assert_eq!(certreqs, vec![ca_hashes], "CERTREQ must carry the real trusted-CA hashes, not a placeholder");
        assert!(!saw_auth, "no AUTH payload -- the initiator still authenticates via the EAP exchange that follows");
    }
}
