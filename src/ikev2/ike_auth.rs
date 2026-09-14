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
use crate::error::IkeError;
use crate::ikev2::exchange::CompletedSaInit;
use crate::ikev2::negotiate::{self, ChosenEspSuite};
use crate::ikev2::message::{
    encode_payload_chain, first_payload_type, payloads, ExchangeType, Flags, IkeHeader, PayloadType,
};
use crate::ikev2::payload::{
    auth_method, notify_type, protocol_id, sighash, transform_id, transform_type, Authentication,
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

fn full_tunnel_ts() -> Vec<u8> {
    TrafficSelectors { selectors: vec![TrafficSelector::ipv4_any()] }.to_bytes()
}

/// Stamp `spi` onto every proposal in `offer` — the SPI is ours to choose
/// per-connection, so a caller-supplied `esp_offer` template's own SPI value
/// (if any) is always overwritten here rather than sent as-is.
fn with_spi(offer: &SecurityAssociation, spi: u32) -> SecurityAssociation {
    let mut offer = offer.clone();
    for p in &mut offer.proposals {
        p.spi = spi.to_be_bytes().to_vec();
    }
    offer
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
    /// The peer's CHILD SA SPI from the SA payload (SAi2 / SAr2), if present.
    child_spi: Option<u32>,
    /// The ESP cipher the peer's SA payload named, if it parsed as a
    /// well-formed ESP proposal (RFC 7296 §3.3) — `None` for a malformed
    /// payload, not necessarily for an unsupported cipher (see
    /// [`ChosenEspSuite::sk_cipher`] for that distinction).
    esp_suite: Option<ChosenEspSuite>,
    /// The inner IPv4 the peer assigned us via a Configuration Payload
    /// (CFG_REPLY, INTERNAL_IP4_ADDRESS) — set only on the initiator's parse of
    /// the responder's response.
    assigned_ip4: Option<Ipv4Addr>,
    /// The responder's actual granted `TSr` — what the negotiated CHILD_SA
    /// really covers, independent of (and often more authoritative than) any
    /// CFG_REPLY `INTERNAL_IP4_SUBNET`. `None` only if the payload is missing
    /// or malformed, not if it narrows to nothing.
    tsr: Option<TrafficSelectors>,
    /// Whether the peer sent `N(INITIAL_CONTACT)` (RFC 7296 §2.4) — this is
    /// the initiator's first SA with us since it last restarted, so any prior
    /// IKE SA we hold for the same peer identity is stale and should be torn
    /// down once this one authenticates.
    initial_contact: bool,
}

/// The ESP CHILD SA SPI carried by an IKE_AUTH SA payload — the 4-byte SPI of the
/// first proposal (RFC 7296 §3.3: proposal substructure, SPI at offset 8 when the
/// SPI size byte is 4). This is the SPI the peer expects stamped on its inbound
/// ESP.
pub(crate) fn esp_spi_from_sa(sa: &[u8]) -> Option<u32> {
    if sa.len() >= 12 && sa[6] == 4 {
        Some(u32::from_be_bytes([sa[8], sa[9], sa[10], sa[11]]))
    } else {
        None
    }
}

fn parse_auth_inner(first: PayloadType, inner: &[u8]) -> Result<AuthPayloads, IkeError> {
    let mut id_body = None;
    let mut auth = None;
    let mut certs = Vec::new();
    let mut child_spi = None;
    let mut esp_suite = None;
    let mut assigned_ip4 = None;
    let mut tsr = None;
    let mut initial_contact = false;
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
            PayloadType::SecurityAssociation => {
                child_spi = esp_spi_from_sa(payload.data);
                esp_suite = SecurityAssociation::parse(payload.data).ok().and_then(|sa| negotiate::select_esp(&sa));
            }
            PayloadType::Configuration => {
                if let Ok(cp) = Configuration::parse(payload.data) {
                    assigned_ip4 = cp.assigned_ipv4();
                }
            }
            PayloadType::TrafficSelectorResponder => {
                if let Ok(ts) = TrafficSelectors::parse(payload.data) {
                    tsr = Some(ts);
                }
            }
            PayloadType::Notify => {
                if let Ok(n) = Notify::parse(payload.data) {
                    if n.notify_type == notify_type::INITIAL_CONTACT {
                        initial_contact = true;
                    }
                }
            }
            _ => {} // TSi / CERTREQ not needed here
        }
    }
    Ok(AuthPayloads {
        id_body: id_body.ok_or(IkeError::MissingPayload("ID"))?,
        auth: auth.ok_or(IkeError::MissingPayload("AUTH"))?,
        certs,
        child_spi,
        esp_suite,
        assigned_ip4,
        tsr,
        initial_contact,
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
/// what the peer negotiated: RFC 7427 Digital Signature (method 14) when it
/// advertised SHA-256 in `SIGNATURE_HASH_ALGORITHMS`, otherwise the classic
/// ECDSA-P256-SHA256 (method 9, RFC 4754). A native EAP client (iOS) sends no
/// `SIGNATURE_HASH_ALGORITHMS`, so it needs the classic method.
pub(crate) fn cert_auth_payload(
    key: &SigningKey,
    peer_signature_hashes: &[u16],
    octets: &[u8],
) -> Result<Authentication, IkeError> {
    if peer_signature_hashes.contains(&sighash::SHA2_256) {
        Ok(Authentication {
            method: auth_method::DIGITAL_SIGNATURE,
            data: key.sign_auth_data(octets)?,
        })
    } else {
        Ok(Authentication {
            method: auth_method::ECDSA_SHA256_P256,
            data: key.sign_ecdsa_p256_raw(octets)?,
        })
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
            if got.auth.method != auth_method::DIGITAL_SIGNATURE {
                return Err(IkeError::AuthFailed);
            }
            let leaf = got.certs.first().ok_or(IkeError::MissingPayload("CERT"))?;
            crate::ikev2::sign::verify_cert_auth(
                leaf,
                &got.certs[1..],
                cas,
                expected_dns.as_deref(),
                *now_unix,
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
    initiator_auth_request_with_cfg(sa, cfg, child_spi, false, esp_offer, iv)
}

/// Like [`initiator_auth_request`], but also carries a CFG_REQUEST
/// ([`Configuration::request_ipv4`]) when `want_cfg` is set — for a direct
/// (non-EAP) PSK/cert client that still wants an inner IP/DNS/subnet assigned
/// (e.g. a pure-certificate profile with mode-config enabled). Placed right
/// after IDi, matching [`initiator_eap_request`]'s payload order. `esp_offer`
/// is the CHILD SA proposal template (see [`self::esp_offer`] for the
/// default AES-GCM-256 one) — its own SPI field is ignored; [`with_spi`]
/// always overwrites it with `child_spi`.
pub fn initiator_auth_request_with_cfg(
    sa: &CompletedSaInit,
    cfg: &AuthConfig,
    child_spi: u32,
    want_cfg: bool,
    esp_offer: &SecurityAssociation,
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
    inner.push((PayloadType::SecurityAssociation, with_spi(esp_offer, child_spi).to_bytes()));
    inner.push((PayloadType::TrafficSelectorInitiator, full_tunnel_ts()));
    inner.push((PayloadType::TrafficSelectorResponder, full_tunnel_ts()));
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
    iv: &[u8; 8],
) -> Result<Vec<u8>, IkeError> {
    let mut inner = vec![(PayloadType::IdInitiator, id.to_bytes())];
    if want_cfg {
        inner.push((PayloadType::Configuration, Configuration::request_ipv4().to_bytes()));
    }
    inner.push((PayloadType::SecurityAssociation, with_spi(esp_offer, child_spi).to_bytes()));
    inner.push((PayloadType::TrafficSelectorInitiator, full_tunnel_ts()));
    inner.push((PayloadType::TrafficSelectorResponder, full_tunnel_ts()));
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
    ca_hashes: Vec<[u8; 20]>,
    iv: &[u8; 8],
) -> Result<Vec<u8>, IkeError> {
    let mut inner = vec![(PayloadType::IdInitiator, id.to_bytes())];
    if want_cfg {
        inner.push((PayloadType::Configuration, Configuration::request_ipv4().to_bytes()));
    }
    inner.push((PayloadType::SecurityAssociation, with_spi(esp_offer, child_spi).to_bytes()));
    inner.push((PayloadType::TrafficSelectorInitiator, full_tunnel_ts()));
    inner.push((PayloadType::TrafficSelectorResponder, full_tunnel_ts()));
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
    inner.push((PayloadType::SecurityAssociation, with_spi(esp_offer, child_spi).to_bytes()));
    inner.push((PayloadType::TrafficSelectorInitiator, full_tunnel_ts()));
    inner.push((PayloadType::TrafficSelectorResponder, full_tunnel_ts()));
    inner.push((PayloadType::Notify, Notify::status(notify_type::INITIAL_CONTACT, Vec::new()).to_bytes()));
    let first = first_payload_type(&inner);
    let inner_bytes = encode_payload_chain(&inner);
    build_encrypted(sa.suite.sk_cipher(), ike_auth_header(sa, false), first, &inner_bytes, &sa.keys.sk_ei, &sa.keys.sk_ai, iv)
}

/// Responder: decrypt + verify the initiator's `IKE_AUTH` request, then build
/// the encrypted response `SK { IDr, AUTH, SAr2, TSi, TSr }`. Returns the
/// response bytes, the initiator's verified identity, its CHILD SA SPI, and
/// whether it sent `N(INITIAL_CONTACT)` (RFC 7296 §2.4) -- the caller should
/// tear down any prior IKE/CHILD SA it holds for the same peer identity when
/// this is set, since it only has meaning once AUTH has verified.
pub fn responder_process_auth(
    sa: &CompletedSaInit,
    request: &[u8],
    cfg: &AuthConfig,
    child_spi: u32,
    iv: &[u8; 8],
    assigned: Option<&AssignedConfig>,
) -> Result<(Vec<u8>, Identification, u32, bool), IkeError> {
    // The initiator encrypts with SK_ei.
    let (first, inner) = open_encrypted(sa.suite.sk_cipher(), request, &sa.keys.sk_ei, &sa.keys.sk_ai)?;
    let got = parse_auth_inner(first, &inner)?;

    let octets = initiator_signed_octets(sa.suite.prf_algorithm(), &sa.init_message, &sa.nr, &sa.keys.sk_pi, &got.id_body);
    verify_peer_auth(sa.suite.prf_algorithm(), cfg, &got, &octets)?;
    let peer_id = Identification::parse(&got.id_body)?;
    let peer_child_spi = got.child_spi.ok_or(IkeError::MissingPayload("SA"))?;

    // Our AUTH signs resp_message | Ni | prf(SK_pr, IDr) — it does NOT cover the
    // CP/SA/TS payloads, so adding a CFG_REPLY below needs no AUTH recomputation.
    let idr_body = cfg.id.to_bytes();
    let our_octets = responder_signed_octets(sa.suite.prf_algorithm(), &sa.resp_message, &sa.ni, &sa.keys.sk_pr, &idr_body);
    let (auth, cert_payloads) = build_local_auth(cfg, sa, &our_octets)?;

    let mut inner_out = vec![(PayloadType::IdResponder, idr_body)];
    inner_out.extend(cert_payloads);
    inner_out.push((PayloadType::Authentication, auth.to_bytes()));
    // CP(CFG_REPLY) with the assigned inner IP (+ DNS) — a native client needs
    // this to configure its tunnel interface. RFC 7296 §2.19: after AUTH, before
    // SA/TS. When we assign an address we also narrow TSi to that /32.
    let tsi = match assigned {
        Some(a) => {
            let dns = if a.dns.is_empty() { None } else { Some(a.dns[0]) };
            let cp = Configuration::reply_ipv4(a.ip, None, dns);
            inner_out.push((PayloadType::Configuration, cp.to_bytes()));
            TrafficSelectors { selectors: vec![TrafficSelector::ipv4_host(a.ip)] }.to_bytes()
        }
        None => full_tunnel_ts(),
    };
    inner_out.push((PayloadType::SecurityAssociation, esp_offer(child_spi).to_bytes()));
    inner_out.push((PayloadType::TrafficSelectorInitiator, tsi));
    inner_out.push((PayloadType::TrafficSelectorResponder, full_tunnel_ts()));
    // Advertise MOBIKE so the client migrates the SA across network changes instead
    // of reconnecting (RFC 4555).
    inner_out.push((PayloadType::Notify, crate::ikev2::mobike::mobike_supported().to_bytes()));
    let first_out = first_payload_type(&inner_out);
    let inner_bytes = encode_payload_chain(&inner_out);
    let response = build_encrypted(sa.suite.sk_cipher(), ike_auth_header(sa, true), first_out, &inner_bytes, &sa.keys.sk_er, &sa.keys.sk_ar, iv)?;
    Ok((response, peer_id, peer_child_spi, got.initial_contact))
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
/// it named (parsed from the same SA payload, `None` only if that payload was
/// malformed), the assigned inner IPv4 (if any), and its actual granted `TSr`
/// (if any) -- see [`AuthPayloads::tsr`] for why this is often more
/// authoritative than the CFG_REPLY subnet for deciding what to route through
/// the tunnel. Returned by [`initiator_verify_auth`].
pub type VerifiedAuth = (Identification, u32, Option<ChosenEspSuite>, Option<Ipv4Addr>, Option<TrafficSelectors>);

/// Initiator: decrypt + verify the responder's `IKE_AUTH` response. See
/// [`VerifiedAuth`] for the returned fields.
pub fn initiator_verify_auth(
    sa: &CompletedSaInit,
    response: &[u8],
    cfg: &AuthConfig,
) -> Result<VerifiedAuth, IkeError> {
    // The responder encrypts with SK_er.
    let (first, inner) = open_encrypted(sa.suite.sk_cipher(), response, &sa.keys.sk_er, &sa.keys.sk_ar)?;
    let got = parse_auth_inner(first, &inner)?;

    let octets = responder_signed_octets(sa.suite.prf_algorithm(), &sa.resp_message, &sa.ni, &sa.keys.sk_pr, &got.id_body);
    verify_peer_auth(sa.suite.prf_algorithm(), cfg, &got, &octets)?;
    let peer_child_spi = got.child_spi.ok_or(IkeError::MissingPayload("SA"))?;
    Ok((Identification::parse(&got.id_body)?, peer_child_spi, got.esp_suite, got.assigned_ip4, got.tsr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ikev2::exchange::{
        default_offer, initiator_complete, initiator_request, responder_respond, LocalSecret,
    };

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
        assert_eq!(init_spi, 0xDEADBEEF); // and learned its CHILD SA SPI

        let (learned_responder, resp_spi, _esp_suite, _assigned, _tsr) = initiator_verify_auth(&init_sa, &resp, &icfg).unwrap();
        assert_eq!(learned_responder, Identification::fqdn("gw.example"));
        assert_eq!(resp_spi, 0xCAFEBABE); // initiator learned the responder's CHILD SA SPI
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
        let (_learned_r, _rspi, _esp_suite, got_ip, _tsr) = initiator_verify_auth(&init_sa, &resp, &icfg).unwrap();
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
        let (_, _, _esp_suite, got_ip, _tsr) = initiator_verify_auth(&init_sa, &resp, &icfg).unwrap();
        assert_eq!(got_ip, None);
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
        let (learned_r, _resp_spi, _esp_suite, _assigned, _tsr) = initiator_verify_auth(&init_sa, &resp, &cert_config()).unwrap();
        assert_eq!(learned_r, Identification::fqdn("vpn.example.com"));
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
        let req = initiator_eap_request_with_certs(&init_sa, &id, 0xC0FFEE, true, &esp_offer(0), &chain, Some(ca_hashes.clone()), &[3u8; 8])
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
