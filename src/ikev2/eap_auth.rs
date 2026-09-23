//! The EAP-MSCHAPv2 authentication exchange inside `IKE_AUTH` (RFC 7296 §2.16),
//! both roles. This is the flow stock iOS/Android use.
//!
//! ```text
//! I → SK{ IDi, SAi2, TSi, TSr }                     (no AUTH: "I'll use EAP")
//! R → SK{ IDr, AUTH(psk), EAP-Req/Identity }
//! I → SK{ EAP-Resp/Identity }
//! R → SK{ EAP-Req/MSCHAPv2-Challenge }
//! I → SK{ EAP-Resp/MSCHAPv2-Response }
//! R → SK{ EAP-Req/MSCHAPv2-Success }
//! I → SK{ EAP-Resp/MSCHAPv2-Success }
//! R → SK{ EAP-Success }
//! I → SK{ AUTH(MSK) }
//! R → SK{ AUTH(MSK), SAr2, TSi, TSr }               (CHILD SA established)
//! ```
//!
//! The responder authenticates with a PSK; both final AUTH payloads key off the
//! EAP-derived MSK. This whole sequence is interop-validated against an
//! independent IKEv2 responder.
//!
//! Each side keeps to that order. The initiator answers nothing before the
//! server's AUTH has verified (unless told not to check it), answers
//! Identity and Notification Requests and Naks a method it doesn't run until
//! MSCHAPv2 has begun (RFC 3748 §2.1, §5.2, §5.3.1), answers a duplicate
//! Request with its first Response (§4.1), checks the authenticator response
//! before it acknowledges it (RFC 2759 §8.8), and takes EAP-Success only after
//! that (RFC 3748 §4.2) and the final message only after its own AUTH. The
//! responder takes each Response only for the Request it has outstanding, by
//! EAP Identifier (RFC 3748 §4.1) and step, and the initiator's AUTH only
//! after it sent EAP-Success.
//!
//! In `IKE_AUTH` each EAP message rides in an IKE message the other side
//! answers, so where RFC 3748 has a message "silently discarded" nothing else
//! would come: either side ends the exchange then ([`EapEvent::Failed`]).

use std::collections::HashMap;

use crate::ikev2::auth::{initiator_signed_octets, psk_auth, responder_signed_octets};
use crate::ikev2::eap;
use crate::entropy::Entropy;
use crate::error::IkeError;
use crate::ikev2::exchange::CompletedSaInit;
use crate::ikev2::ike_auth::{
    assigned_ipv4_policy, check_granted_ts, child_sa_error_of, esp_offer, esp_spi_from_sa,
    initiator_eap_request, initiator_eap_request_with_certreq, initiator_eap_request_with_certs,
    narrow_requested_ts, AssignedConfig, ChildTsOffer,
};
use crate::ikev2::message::{
    encode_payload_chain, first_payload_type, payloads, ExchangeType, Flags, IkeHeader, PayloadType,
};
use crate::ikev2::mschapv2;
use crate::ikev2::negotiate::{self, ChosenEspSuite};
use crate::ikev2::payload::{
    auth_method, notify_type, notify_type_name, Authentication, Certificate, Configuration,
    Identification, Notify, SecurityAssociation, TrafficSelectors,
};
use crate::role::Role;
use crate::ikev2::sign::SigningKey;
use crate::ikev2::sk::{build_encrypted, ct_eq, open_encrypted};

/// How the server (responder) authenticates *itself* in the EAP exchange
/// (RFC 7296 §2.16 — its own AUTH, separate from the EAP/MSK exchange).
pub enum ServerAuth {
    /// Pre-shared key (RFC 7296 §2.15). Simple, but native phones want a cert.
    Psk(Vec<u8>),
    /// RFC 7427 Digital Signature with an X.509 chain (`chain[0]` = leaf, whose
    /// key signs the AUTH; the rest are intermediates, any order, no root).
    Cert { key: SigningKey, chain: Vec<Vec<u8>> },
}

/// How the client (initiator) authenticates the *server*.
pub enum ServerVerify {
    /// Do not authenticate the server. Only tolerable with a PSK server in an
    /// already-trusted setting; a real phone-style client must not use this.
    Insecure,
    /// Require the server's `AUTH(psk)` to match what we independently compute
    /// from this pre-shared key over its own signed octets (RFC 7296 §2.15) —
    /// the actual verification `Insecure` skips. Fits gateways (e.g. a
    /// FortiGate PSK+EAP dialup policy) that authenticate themselves via PSK
    /// rather than a certificate.
    Psk(Vec<u8>),
    /// Require the server's leaf certificate to (a) build a valid X.509 path to
    /// one of these trusted CA certificates (DER) — checking each hop's
    /// signature, validity window, and CA status — (b) carry `expected_dns` in
    /// its SubjectAltName when given, and (c) produce a valid AUTH signature:
    /// RFC 7427's (method 14), RSA's (method 1) or ECDSA-P256-SHA256's
    /// (method 9, RFC 4754). Revocation (CRL/OCSP) and EKU are still the
    /// consumer's to add.
    TrustedCas {
        cas: Vec<Vec<u8>>,
        /// The dNSName the client intends to reach, if it wants that bound
        /// to the cert's SAN. `None` skips this check entirely — trusting
        /// any cert that chains to `cas`, regardless of name. Confirmed live
        /// against a real FortiGate dialup policy: the gateway's own TLS
        /// certificate (a public Let's Encrypt-issued cert) legitimately
        /// names its own public hostname, which need not match whatever the
        /// profile's configured connect address happens to be (e.g. an
        /// internal DNS name or IP) — a prior charon/VICI backend's
        /// equivalent check never enforced this either, only chain-to-CA.
        expected_dns: Option<String>,
        /// Current time (Unix seconds) for certificate validity checks.
        now_unix: u64,
    },
}

/// Outcome of feeding one peer message to a state machine.
#[derive(Debug)]
pub enum EapEvent {
    /// Send this message and await the next reply.
    Reply(Vec<u8>),
    /// Handshake complete. If `Some`, send this final message first.
    Established(Option<Vec<u8>>),
    /// The peer failed authentication. `Some` when EAP-MSCHAPv2 gave a
    /// specific, parsed reason (RFC 2759 §4's Failure message); `None` for
    /// a bare EAP-Failure or any other protocol-level abort (unexpected
    /// message, server-auth mismatch, etc) with no stated reason.
    Failed(Option<EapFailureReason>),
}

/// A server-stated EAP-MSCHAPv2 failure reason (RFC 2759 §4:
/// `"E=eeeeeeeeee R=r C=cccccccccccccccccccccccccccccccc V=v M=<msg>"`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EapFailureReason {
    /// The full ASCII message, verbatim, for logging.
    pub raw: String,
    /// `true` for `E=691` (`ERROR_AUTHENTICATION_FAILURE`) — a definitive
    /// "these credentials are wrong", not a transient/protocol failure.
    pub credentials_rejected: bool,
}

impl EapFailureReason {
    fn parse(raw: std::borrow::Cow<'_, str>) -> Self {
        let credentials_rejected = raw
            .split_whitespace()
            .find_map(|tok| tok.strip_prefix("E="))
            .is_some_and(|code| code == "691");
        EapFailureReason { raw: raw.into_owned(), credentials_rejected }
    }
}

/// A decrypted message's payloads, each as `(type, raw body)`.
type Payloads = Vec<(PayloadType, Vec<u8>)>;

fn our_sk_e(sa: &CompletedSaInit) -> &[u8] {
    match sa.role {
        Role::Initiator => &sa.keys.sk_ei,
        Role::Responder => &sa.keys.sk_er,
    }
}
fn peer_sk_e(sa: &CompletedSaInit) -> &[u8] {
    match sa.role {
        Role::Initiator => &sa.keys.sk_er,
        Role::Responder => &sa.keys.sk_ei,
    }
}
fn our_sk_a(sa: &CompletedSaInit) -> &[u8] {
    match sa.role {
        Role::Initiator => &sa.keys.sk_ai,
        Role::Responder => &sa.keys.sk_ar,
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
    TrafficSelectors::ipv4_full_tunnel().to_bytes()
}

fn build_sk(sa: &CompletedSaInit, msg_id: u32, is_response: bool, inner: &[(PayloadType, Vec<u8>)], iv: &[u8; 8]) -> Result<Vec<u8>, IkeError> {
    // (`inner` stays a slice so callers can pass array literals.)
    let header = IkeHeader {
        initiator_spi: sa.spi_i,
        responder_spi: sa.spi_r,
        next_payload: PayloadType::NoNext,
        major_version: 2,
        minor_version: 0,
        exchange_type: ExchangeType::IkeAuth,
        flags: Flags { initiator: sa.role == Role::Initiator, version: false, response: is_response },
        message_id: msg_id,
        length: 0,
    };
    let first = first_payload_type(inner);
    let bytes = encode_payload_chain(inner);
    build_encrypted(sa.suite.sk_cipher(), header, first, &bytes, our_sk_e(sa), our_sk_a(sa), iv)
}

/// Collect a decrypted message's payloads plus its Message ID.
fn decrypt(sa: &CompletedSaInit, message: &[u8]) -> Result<(u32, Payloads), IkeError> {
    let msg_id = IkeHeader::parse(message)?.message_id;
    let (first, inner) = open_encrypted(sa.suite.sk_cipher(), message, peer_sk_e(sa), peer_sk_a(sa))?;
    let mut out = Vec::new();
    for p in payloads(first, &inner) {
        let p = p?;
        out.push((p.payload_type, p.data.to_vec()));
    }
    Ok((msg_id, out))
}

fn find(payloads: &[(PayloadType, Vec<u8>)], want: PayloadType) -> Option<&[u8]> {
    payloads.iter().find(|(t, _)| *t == want).map(|(_, d)| d.as_slice())
}

fn iv(entropy: &mut impl Entropy) -> [u8; 8] {
    let mut iv = [0u8; 8];
    entropy.fill(&mut iv);
    iv
}

/// Where an [`EapInitiator`]'s EAP conversation stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PeerStep {
    /// No method has begun: Identity and Notification Requests are answered,
    /// and a Request for a method we don't run gets a Nak.
    Selecting,
    /// We answered the MSCHAPv2 Challenge, under its MS-CHAPv2-ID: the
    /// Success Request is next.
    Answered { mschap_id: u8, auth_challenge: [u8; 16], peer_challenge: [u8; 16] },
    /// The authenticator response verified and we acknowledged it:
    /// EAP-Success is next.
    ServerProven,
    /// EAP-Success came and our MSK-keyed AUTH went out: the final message
    /// is next.
    AuthSent,
}

/// EAP-MSCHAPv2 **initiator** (client) — the phone's role.
pub struct EapInitiator {
    sa: CompletedSaInit,
    id: Identification,
    user: Vec<u8>,
    password: String,
    child_spi: u32,
    esp_offer: SecurityAssociation,
    nt_response: [u8; 24],
    verify: ServerVerify,
    server_verified: bool,
    step: PeerStep,
    /// The last EAP Request we answered and our Response to it, to answer a
    /// duplicate the same way.
    last_request: Option<(eap::EapPacket, eap::EapPacket)>,
    /// The responder's IDr as its first IKE_AUTH response carried it (payload
    /// body, no generic header), or empty until then. RFC 7296 §2.16 has the
    /// responder send IDr only once: the final message holds just AUTH (+ SA/
    /// TS/CP), yet that AUTH is signed over the same IDr (§2.15), so the final
    /// check must use this remembered value, not whatever the last message
    /// happens to repeat -- a gateway such as strongSwan does not repeat it.
    server_idr: Vec<u8>,
    send_certreq: bool,
    /// The responder's own CHILD SA SPI (from SAr2 in the final message) —
    /// the SPI we must stamp on outbound ESP so the peer's inbound SA accepts
    /// it. `None` until [`EapEvent::Established`].
    peer_child_spi: Option<u32>,
    /// The ESP cipher the responder named in SAr2, once known — set only
    /// after [`EapEvent::Established`].
    peer_esp_suite: Option<ChosenEspSuite>,
    /// The inner IPv4 the responder assigned us (CFG_REPLY), if any.
    assigned_ip4: Option<std::net::Ipv4Addr>,
    /// The responder's actual granted `TSr` from the final message, if any --
    /// see [`crate::ikev2::ike_auth`]'s `AuthPayloads::tsr` doc for why this
    /// is often more authoritative than CFG_REPLY's `INTERNAL_IP4_SUBNET`.
    granted_ts: Option<TrafficSelectors>,
    /// The full CFG_REPLY Configuration payload, if the responder sent one --
    /// a superset of `assigned_ip4`/`granted_ts` for callers that want the
    /// other attributes too (DNS servers, split-tunnel subnets, IPv6).
    configuration: Option<Configuration>,
    /// Whether to carry a CFG_REQUEST in the EAP-triggering first message --
    /// see [`Self::set_want_cfg`].
    want_cfg: bool,
    /// The client's own X.509 chain (`client_certs[0]` = leaf) to attach to
    /// the EAP-triggering first message -- see
    /// [`crate::ikev2::ike_auth::initiator_eap_request_with_certs`]'s doc for
    /// why this exists (a FortiGate "Certificate + EAP" combined round).
    client_certs: Vec<Vec<u8>>,
    /// TSi/TSr offered for the CHILD SA in the first message -- see
    /// [`Self::set_ts_offer`].
    ts_offer: ChildTsOffer,
}

impl EapInitiator {
    pub fn new(
        sa: CompletedSaInit,
        id: Identification,
        user: Vec<u8>,
        password: String,
        child_spi: u32,
        verify: ServerVerify,
    ) -> Self {
        Self::new_with_esp_offer(sa, id, user, password, child_spi, esp_offer(0), verify)
    }

    /// Like [`Self::new`], but with a caller-supplied CHILD SA proposal
    /// template instead of the default AES-GCM-256 one — see
    /// [`crate::ikev2::ike_auth::initiator_auth_request_with_cfg`]'s doc for
    /// `esp_offer`'s contract (its own SPI field is ignored/overwritten).
    pub fn new_with_esp_offer(
        sa: CompletedSaInit,
        id: Identification,
        user: Vec<u8>,
        password: String,
        child_spi: u32,
        esp_offer: SecurityAssociation,
        verify: ServerVerify,
    ) -> Self {
        EapInitiator {
            sa,
            id,
            user,
            password,
            child_spi,
            esp_offer,
            nt_response: [0u8; 24],
            verify,
            server_verified: false,
            step: PeerStep::Selecting,
            last_request: None,
            server_idr: Vec::new(),
            send_certreq: false,
            peer_child_spi: None,
            peer_esp_suite: None,
            assigned_ip4: None,
            granted_ts: None,
            configuration: None,
            want_cfg: false,
            client_certs: Vec::new(),
            ts_offer: ChildTsOffer::default(),
        }
    }

    /// Include a `CERTREQ` in the first message (mirrors a strongSwan client) —
    /// used to exercise a responder's CERTREQ-based cert selection. When
    /// [`Self::verify`] is [`ServerVerify::TrustedCas`], the hashes sent are
    /// real SHA-1(SPKI) hashes of its trusted CAs (RFC 7296 §3.7) so the
    /// responder can pick a matching certificate to present; otherwise a
    /// single all-zero placeholder hash is sent (no CA list is known to
    /// hash), matching this method's behavior before `TrustedCas`-aware
    /// hashing existed.
    pub fn set_send_certreq(&mut self, on: bool) {
        self.send_certreq = on;
    }

    /// Attach the client's own X.509 certificate chain (`chain[0]` = leaf) to
    /// the EAP-triggering first message — for a FortiGate policy configured
    /// for "Certificate + EAP": the gateway wants to see the client's
    /// certificate for its own identity/policy matching, on top of EAP
    /// actually deciding whether the connection is authenticated. An empty
    /// chain (the default) reproduces plain EAP-MSCHAPv2 with no certs
    /// attached at all. See
    /// [`crate::ikev2::ike_auth::initiator_eap_request_with_certs`]'s doc for
    /// the full rationale.
    pub fn set_client_certs(&mut self, chain: Vec<Vec<u8>>) {
        self.client_certs = chain;
    }

    /// Carry a CFG_REQUEST ([`Configuration::request_ipv4`]) in the
    /// EAP-triggering first message -- RFC 7296 §2.19 lets mode-config run
    /// alongside any authentication method; some responders require it to
    /// complete before they'll finish an EAP exchange at all. Off by default,
    /// matching the wire behavior of a plain EAP-MSCHAPv2 client that never
    /// asks for an inner address.
    pub fn set_want_cfg(&mut self, on: bool) {
        self.want_cfg = on;
    }

    /// Choose the TSi/TSr the CHILD SA is offered with in the first message
    /// (default [`ChildTsOffer::Ipv4`]) -- see [`ChildTsOffer`].
    pub fn set_ts_offer(&mut self, offer: ChildTsOffer) {
        self.ts_offer = offer;
    }

    fn certreq_ca_hashes(&self) -> Vec<[u8; 20]> {
        match &self.verify {
            ServerVerify::TrustedCas { cas, .. } => {
                let hashes: Vec<_> = cas.iter().filter_map(|ca| crate::ikev2::sign::ca_key_hash(ca).ok()).collect();
                if hashes.is_empty() { vec![[0u8; 20]] } else { hashes }
            }
            _ => vec![[0u8; 20]],
        }
    }

    /// The completed `IKE_SA_INIT` state — `sk_d`/nonces/role, what
    /// [`crate::esp::ChildSa::derive`] needs to key the data plane. Valid any
    /// time; only meaningful once [`EapEvent::Established`] confirms the
    /// CHILD SA actually exists.
    pub fn ike_sa(&self) -> &CompletedSaInit {
        &self.sa
    }

    /// The SPI we proposed for our own inbound CHILD SA.
    pub fn child_spi(&self) -> u32 {
        self.child_spi
    }

    /// The peer's CHILD SA SPI (from SAr2), once known — set only after
    /// [`EapEvent::Established`].
    pub fn peer_child_spi(&self) -> Option<u32> {
        self.peer_child_spi
    }

    /// The ESP cipher the responder named in SAr2, once known — set only
    /// after [`EapEvent::Established`].
    pub fn peer_esp_suite(&self) -> Option<ChosenEspSuite> {
        self.peer_esp_suite
    }

    /// The inner IPv4 the responder assigned us via CFG_REPLY, if any.
    pub fn assigned_ip4(&self) -> Option<std::net::Ipv4Addr> {
        self.assigned_ip4
    }

    /// The responder's actual granted `TSr` from the final message, if any.
    pub fn granted_ts(&self) -> Option<&TrafficSelectors> {
        self.granted_ts.as_ref()
    }

    /// The full CFG_REPLY Configuration payload, once known -- lets a caller
    /// read attributes [`Self::assigned_ip4`]/[`Self::granted_ts`] don't
    /// surface directly, e.g. `Configuration::assigned_dns`,
    /// `assigned_subnets`, or the IPv6 equivalents.
    pub fn configuration(&self) -> Option<&Configuration> {
        self.configuration.as_ref()
    }

    /// Authenticate the server from its first response (`SK{ IDr, [CERT,] AUTH,
    /// EAP }`): the leaf must chain to a trusted CA, vouch for the expected
    /// dNSName, and sign the responder's signed octets with one of the
    /// methods [`ServerVerify::TrustedCas`] names. Returns `false` on any
    /// failure so the caller can abort.
    fn verify_server(&self, ps: &Payloads) -> bool {
        let (Some(idr), Some(auth_bytes)) =
            (find(ps, PayloadType::IdResponder), find(ps, PayloadType::Authentication))
        else {
            return false;
        };

        let (cas, expected_dns, now) = match &self.verify {
            ServerVerify::Insecure => return true,
            ServerVerify::Psk(psk) => {
                let Ok(auth) = Authentication::parse(auth_bytes) else { return false };
                if auth.method != auth_method::SHARED_KEY {
                    return false;
                }
                let algo = self.sa.suite.prf_algorithm();
                let octets = responder_signed_octets(algo, &self.sa.resp_message, &self.sa.ni, &self.sa.keys.sk_pr, idr);
                return auth.data == psk_auth(algo, psk, &octets);
            }
            ServerVerify::TrustedCas { cas, expected_dns, now_unix } => (cas, expected_dns, *now_unix),
        };
        // Every CERT payload, in order: [0] is the leaf, the rest intermediates.
        let certs: Vec<Vec<u8>> = ps
            .iter()
            .filter(|(t, _)| *t == PayloadType::Certificate)
            .filter_map(|(_, d)| Certificate::parse(d).ok().map(|c| c.data))
            .collect();
        let Some(leaf) = certs.first() else { return false };
        let auth = match Authentication::parse(auth_bytes) {
            Ok(a) => a,
            Err(_) => return false,
        };
        let octets = responder_signed_octets(self.sa.suite.prf_algorithm(), &self.sa.resp_message, &self.sa.ni, &self.sa.keys.sk_pr, idr);
        // Path validation (chain + dates + CA) + SAN binding + signature.
        // `auth.method` selects RFC 7427 method 14, classic RSA method 1 (a
        // real FortiGate "Certificates + EAP" sends method 1, not 14) or
        // ECDSA method 9 (what an EC-keyed server, ours included, sends a
        // client that offered no SIGNATURE_HASH_ALGORITHMS) -- the same
        // three direct certificate authentication takes; `verify_cert_auth`
        // refuses any other.
        crate::ikev2::sign::verify_cert_auth(leaf, &certs[1..], cas, expected_dns.as_deref(), now, auth.method, &auth.data, &octets).is_ok()
    }

    /// First message: `SK{ IDi, SAi2, TSi, TSr }` (no AUTH — request EAP).
    pub fn start(&self, entropy: &mut impl Entropy) -> Result<Vec<u8>, IkeError> {
        if !self.client_certs.is_empty() {
            let ca_hashes = self.send_certreq.then(|| self.certreq_ca_hashes());
            initiator_eap_request_with_certs(
                &self.sa,
                &self.id,
                self.child_spi,
                self.want_cfg,
                &self.esp_offer,
                self.ts_offer,
                &self.client_certs,
                ca_hashes,
                &iv(entropy),
            )
        } else if self.send_certreq {
            initiator_eap_request_with_certreq(
                &self.sa,
                &self.id,
                self.child_spi,
                self.want_cfg,
                &self.esp_offer,
                self.ts_offer,
                self.certreq_ca_hashes(),
                &iv(entropy),
            )
        } else {
            initiator_eap_request(&self.sa, &self.id, self.child_spi, self.want_cfg, &self.esp_offer, self.ts_offer, &iv(entropy))
        }
    }

    /// Process a responder message and produce the next step.
    pub fn handle(&mut self, message: &[u8], entropy: &mut impl Entropy) -> Result<EapEvent, IkeError> {
        let (msg_id, ps) = decrypt(&self.sa, message)?;
        let next_id = msg_id + 1;

        if self.server_idr.is_empty() {
            if let Some(idr) = find(&ps, PayloadType::IdResponder) {
                self.server_idr = idr.to_vec();
            }
        }

        // The server authenticates itself in its first response (the one that
        // also carries IDr). Verify it once, before answering any EAP request —
        // so we never send our EAP credentials to an unauthenticated server.
        if !self.server_verified
            && find(&ps, PayloadType::IdResponder).is_some()
            && find(&ps, PayloadType::Authentication).is_some()
        {
            if !self.verify_server(&ps) {
                return Ok(EapEvent::Failed(None));
            }
            self.server_verified = true;
        }

        // Credential firewall: when we require server authentication, refuse to
        // do *anything* else until the server is verified. Otherwise a rogue peer
        // could send a first message with no IDr/AUTH (skipping verify_server) and
        // walk us through EAP, harvesting the username + a crackable MSCHAPv2
        // response. `Insecure` opts out (only for a PSK server in a trusted path).
        if matches!(self.verify, ServerVerify::TrustedCas { .. } | ServerVerify::Psk(_)) && !self.server_verified {
            return Ok(EapEvent::Failed(None));
        }

        let Some(eap_bytes) = find(&ps, PayloadType::Eap) else {
            // No EAP → the responder's final message, which answers our
            // MSK-keyed AUTH: before that went out there is no MSK to check
            // it with. Key-confirm its MSK-keyed AUTH (mirroring what the
            // responder does to us); presence alone is not enough — it must
            // prove it derived the same EAP MSK.
            if self.step != PeerStep::AuthSent {
                return Ok(EapEvent::Failed(None));
            }
            let Some(auth_bytes) = find(&ps, PayloadType::Authentication) else {
                return Ok(EapEvent::Failed(None));
            };
            let msk = mschapv2::derive_msk(&self.password, &self.nt_response);
            let algo = self.sa.suite.prf_algorithm();
            let expect =
                psk_auth(algo, &msk, &responder_signed_octets(algo, &self.sa.resp_message, &self.sa.ni, &self.sa.keys.sk_pr, &self.server_idr));
            let got = Authentication::parse(auth_bytes)?;
            let verified = got.method == auth_method::SHARED_KEY && ct_eq(&got.data, &expect);
            let Some(sar2) = find(&ps, PayloadType::SecurityAssociation) else {
                // RFC 7296 §1.2: a CHILD SA that fails inside IKE_AUTH leaves the
                // IKE SA established, so this final message is a valid AUTH plus
                // an error notify and no SA/TS. Once the MSK-keyed AUTH has
                // verified, that is a rejection with a stated reason -- not the
                // failed authentication it used to be reported as.
                if verified {
                    let rejected = ps
                        .iter()
                        .filter(|(t, _)| *t == PayloadType::Notify)
                        .find_map(|(_, body)| child_sa_error_of(body));
                    if let Some(t) = rejected {
                        return Err(IkeError::PeerRejected { notify_type: t, name: notify_type_name(t) });
                    }
                }
                return Ok(EapEvent::Failed(None));
            };
            if verified {
                let esp_suite = SecurityAssociation::parse(sar2).ok().and_then(|sa| negotiate::select_esp(&sa));
                // RFC 7296 §2.7: the responder's SAr2 must be built from the
                // ESP proposal we actually offered, not merely one
                // `select_esp` knows how to decode -- see
                // ChosenEspSuite::matches_offer's doc. Once the MSK-keyed
                // AUTH above has verified, a mismatch here is a downgrade
                // attempt, not a malformed message.
                if let Some(suite) = &esp_suite {
                    if !suite.matches_offer(&self.esp_offer) {
                        return Err(IkeError::NoProposalChosen);
                    }
                }
                // RFC 7296 §2.9: both TS payloads, each within what we proposed.
                let tsi = find(&ps, PayloadType::TrafficSelectorInitiator).map(TrafficSelectors::parse).transpose()?;
                let tsr = find(&ps, PayloadType::TrafficSelectorResponder).map(TrafficSelectors::parse).transpose()?;
                check_granted_ts(&self.ts_offer.selectors(), tsi.as_ref(), tsr.as_ref())?;
                self.peer_child_spi = esp_spi_from_sa(sar2);
                self.peer_esp_suite = esp_suite;
                if let Some(cp) = find(&ps, PayloadType::Configuration).and_then(|d| Configuration::parse(d).ok()) {
                    self.assigned_ip4 = cp.assigned_ipv4();
                    self.configuration = Some(cp);
                }
                self.granted_ts = tsr;
            }
            return Ok(if verified { EapEvent::Established(None) } else { EapEvent::Failed(None) });
        };
        if self.step == PeerStep::AuthSent {
            return Ok(EapEvent::Failed(None));
        }

        let eap = eap::EapPacket::parse(eap_bytes)?;
        if eap.code == eap::code::FAILURE {
            return Ok(EapEvent::Failed(None));
        }
        if eap.code == eap::code::SUCCESS {
            // RFC 3748 §4.2: EAP-Success counts only once the method has
            // finished -- here, once the server proved it knows the
            // password. A "canned" one before that is no success.
            if self.step != PeerStep::ServerProven {
                return Ok(EapEvent::Failed(None));
            }
            // It is the reply to the Response we sent last, so it carries
            // that one's Identifier, and no data: its Length is 4 (§4.2).
            // Octets past that Length are padding, which `parse` already
            // left out (§4). An IKE_AUTH response is not sent again in
            // another form, so a Success that does not answer ours ends
            // the exchange rather than being waited past.
            let answers_ours = self.last_request.as_ref().is_some_and(|(_, response)| response.identifier == eap.identifier);
            if !answers_ours || !eap.data.is_empty() {
                return Ok(EapEvent::Failed(None));
            }
            // EAP done: send AUTH keyed by the MSK.
            let msk = mschapv2::derive_msk(&self.password, &self.nt_response);
            let idi = self.id.to_bytes();
            let algo = self.sa.suite.prf_algorithm();
            let octets = initiator_signed_octets(algo, &self.sa.init_message, &self.sa.nr, &self.sa.keys.sk_pi, &idi);
            let auth = Authentication { method: auth_method::SHARED_KEY, data: psk_auth(algo, &msk, &octets) };
            let msg = build_sk(&self.sa, next_id, false, &[(PayloadType::Authentication, auth.to_bytes())], &iv(entropy))?;
            self.step = PeerStep::AuthSent;
            return Ok(EapEvent::Reply(msg));
        }
        if eap.code != eap::code::REQUEST {
            return Ok(EapEvent::Failed(None));
        }

        // RFC 3748 §4.1: a duplicate of the Request we last answered gets
        // the same Response, and is not processed again. Another Request
        // under its Identifier is no duplicate.
        if let Some((request, response)) = &self.last_request {
            if eap.identifier == request.identifier {
                if eap != *request {
                    return Ok(EapEvent::Failed(None));
                }
                let msg = build_sk(&self.sa, next_id, false, &[(PayloadType::Eap, response.to_bytes())], &iv(entropy))?;
                return Ok(EapEvent::Reply(msg));
            }
        }

        let data = match self.answer(&eap, entropy)? {
            Ok(data) => data,
            Err(reason) => return Ok(EapEvent::Failed(reason)),
        };
        let resp = eap::EapPacket { code: eap::code::RESPONSE, identifier: eap.identifier, data };
        let msg = build_sk(&self.sa, next_id, false, &[(PayloadType::Eap, resp.to_bytes())], &iv(entropy))?;
        self.last_request = Some((eap, resp));
        Ok(EapEvent::Reply(msg))
    }

    /// The Type-Data of our Response to a new EAP Request, or `Err` to end
    /// the exchange -- with the server's reason when it gave one. Each
    /// Request is taken only in the step it belongs to.
    fn answer(&mut self, eap: &eap::EapPacket, entropy: &mut impl Entropy) -> Result<Result<Vec<u8>, Option<EapFailureReason>>, IkeError> {
        let op = eap.data.get(1).copied();
        Ok(Ok(match (self.step, eap.eap_type()) {
            (PeerStep::Selecting, Some(eap::eap_type::IDENTITY)) => {
                let mut d = vec![eap::eap_type::IDENTITY];
                d.extend_from_slice(&self.user);
                d
            }
            // RFC 3748 §5.2: a Notification Request gets a Notification
            // Response (no Type-Data), whatever else is going on, and
            // changes nothing.
            (PeerStep::Selecting | PeerStep::Answered { .. } | PeerStep::ServerProven, Some(eap::eap_type::NOTIFICATION)) => {
                vec![eap::eap_type::NOTIFICATION]
            }
            (PeerStep::Selecting, Some(eap::eap_type::MSCHAPV2)) if op == Some(eap::op::CHALLENGE) => {
                let (mschap_id, auth_challenge, _name) = eap::parse_challenge(&eap.data)?;
                let mut peer_challenge = [0u8; 16];
                entropy.fill(&mut peer_challenge);
                self.nt_response = mschapv2::generate_nt_response(&auth_challenge, &peer_challenge, &self.user, &self.password);
                self.step = PeerStep::Answered { mschap_id, auth_challenge, peer_challenge };
                eap::build_response(mschap_id, &auth_challenge, &peer_challenge, &self.user, &self.password)
            }
            (PeerStep::Answered { mschap_id, auth_challenge, peer_challenge }, Some(eap::eap_type::MSCHAPV2)) if op == Some(eap::op::SUCCESS) => {
                // RFC 2759 §8.8, draft-kamath-pppext-eap-mschapv2 §2.3: the
                // server proves it knows the password with the authenticator
                // response; if that is missing or wrong the session ends
                // without an answer -- and so without the MSK-keyed AUTH.
                // It answers our Response, so it carries that one's
                // MS-CHAPv2-ID (RFC 2759 §5 keeps the CHAP Success format,
                // RFC 1994 §4.2).
                let expected = mschapv2::authenticator_response(&self.password, &self.nt_response, &peer_challenge, &auth_challenge, &self.user);
                match eap::parse_success(&eap.data) {
                    Ok(got) if eap.data[2] == mschap_id && ct_eq(&got, &expected) => {}
                    _ => return Ok(Err(None)),
                }
                self.step = PeerStep::ServerProven;
                vec![eap::eap_type::MSCHAPV2, eap::op::SUCCESS]
            }
            (_, Some(eap::eap_type::MSCHAPV2)) if op == Some(eap::op::FAILURE) => {
                // The server's own stated reason, e.g. "E=691 R=1 C=<chal> V=3"
                // (RFC 2759 -- E=691 is ERROR_AUTHENTICATION_FAILURE, a
                // rejected username/password, not a protocol problem). Bytes
                // 5.. are the ASCII message, mirroring `eap::build_success`'s
                // layout for the Success case.
                let reason = eap.data.get(5..).map(String::from_utf8_lossy).unwrap_or_default();
                return Ok(Err(Some(EapFailureReason::parse(reason))));
            }
            // RFC 3748 §5.3.1, §5.3.2: until a method has begun, a Request
            // for one we don't run (Expanded Types included -- we support
            // none) gets a Legacy Nak naming MSCHAPv2. Types 1-3 are no
            // methods, and once MSCHAPv2 has begun no other runs (§2.1).
            (PeerStep::Selecting, Some(t)) if t > eap::eap_type::NAK && t != eap::eap_type::MSCHAPV2 => {
                vec![eap::eap_type::NAK, eap::eap_type::MSCHAPV2]
            }
            _ => return Ok(Err(None)),
        }))
    }
}

/// Where an [`EapResponder`]'s exchange stands: what it takes next and, while
/// EAP runs, the Identifier of the Request it has outstanding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthStep {
    /// The initiator's first `IKE_AUTH` request: no AUTH, no EAP.
    Start,
    /// The Identity Response.
    Identity { id: u8 },
    /// The MSCHAPv2 Response to our Challenge.
    Challenge { id: u8 },
    /// The MSCHAPv2 Success Response acknowledging our Success Request.
    Success { id: u8 },
    /// We sent EAP-Success: the initiator's MSK-keyed AUTH.
    Succeeded,
    /// Established or failed: nothing more is taken.
    Done,
}

/// The MS-CHAPv2-ID of our Challenge and Success Requests.
const MSCHAP_ID: u8 = 1;

/// EAP-MSCHAPv2 **responder** (server): authenticates itself ([`ServerAuth`]),
/// verifies the client's EAP password, then exchanges the MSK-keyed AUTHs.
///
/// It takes each initiator request once, in order; a retransmitted request
/// is the caller's to answer with the response it already gave (see the
/// crate docs), not one to hand back in.
pub struct EapResponder {
    sa: CompletedSaInit,
    id: Identification,
    auth: ServerAuth,
    user: Vec<u8>,
    password: String,
    /// All accepted credentials (username → password). The client's claimed EAP
    /// identity selects one at the Identity step; an unknown identity is rejected.
    users: HashMap<Vec<u8>, String>,
    child_spi: u32,
    step: AuthStep,
    auth_challenge: [u8; 16],
    nt_response: [u8; 24],
    peer_idi: Vec<u8>,
    /// The initiator's ESP SPI (from SAi2 in msg-1), needed to derive the CHILD
    /// SA -- dropped when the final message refuses it (`TS_UNACCEPTABLE`).
    peer_child_spi: Option<u32>,
    /// The TSi and TSr of msg-1, answered narrowed in the final message.
    peer_ts: Option<(TrafficSelectors, TrafficSelectors)>,
    /// Inner-network assignment for this client's Configuration Payload (CFG_REPLY)
    /// in the final message — so the cascade's per-client inner IP is handed out
    /// over EAP just like the PSK path.
    assigned: Option<AssignedConfig>,
    /// Whether the consumer implements MOBIKE -- see [`set_mobike`](Self::set_mobike).
    mobike: bool,
    /// Whether the initiator sent `N(MOBIKE_SUPPORTED)` in any `IKE_AUTH` request.
    peer_mobike: bool,
}

impl EapResponder {
    pub fn new(
        sa: CompletedSaInit,
        id: Identification,
        auth: ServerAuth,
        user: Vec<u8>,
        password: String,
        child_spi: u32,
    ) -> Self {
        let users = HashMap::from([(user, password)]);
        Self::new_multi(sa, id, auth, users, child_spi)
    }

    /// Like [`new`](Self::new) but accepts multiple credentials; the client's EAP
    /// identity picks which password to verify against (an unknown one fails).
    pub fn new_multi(
        sa: CompletedSaInit,
        id: Identification,
        auth: ServerAuth,
        users: HashMap<Vec<u8>, String>,
        child_spi: u32,
    ) -> Self {
        EapResponder {
            sa,
            id,
            auth,
            user: Vec::new(),
            password: String::new(),
            users,
            child_spi,
            step: AuthStep::Start,
            auth_challenge: [0u8; 16],
            nt_response: [0u8; 24],
            peer_idi: Vec::new(),
            peer_child_spi: None,
            peer_ts: None,
            assigned: None,
            mobike: false,
            peer_mobike: false,
        }
    }

    /// Set the inner-network assignment sent in the final message's Configuration
    /// Payload (a native client needs it to configure its tunnel interface).
    pub fn set_assigned(&mut self, assigned: Option<AssignedConfig>) {
        self.assigned = assigned;
    }

    /// Declare that the consumer implements MOBIKE (RFC 4555): it answers an
    /// INFORMATIONAL carrying `N(UPDATE_SA_ADDRESSES)` (see
    /// [`crate::ikev2::mobike`]) by moving the IKE SA and its CHILD SAs to that
    /// request's observed source address. Off by default: only then, and only if
    /// the initiator offered it (§3.1), does the final message carry
    /// `N(MOBIKE_SUPPORTED)` -- see [`mobike_enabled`](Self::mobike_enabled).
    pub fn set_mobike(&mut self, enabled: bool) {
        self.mobike = enabled;
    }

    /// Whether MOBIKE is in force for this IKE SA -- we opted in and the
    /// initiator offered it -- i.e. whether the consumer must honor
    /// `UPDATE_SA_ADDRESSES` from this peer. Meaningful once
    /// [`EapEvent::Established`] has been returned.
    pub fn mobike_enabled(&self) -> bool {
        self.mobike && self.peer_mobike
    }

    /// The initiator's ESP SPI (captured from SAi2), for deriving the CHILD SA
    /// after [`EapEvent::Established`] -- `None` then if the final message
    /// refused the CHILD SA with `TS_UNACCEPTABLE` (the IKE SA stands, RFC
    /// 7296 §1.2): the initiator's selectors left nothing the address it is
    /// assigned, or IPv4 without one, can carry (§2.9).
    pub fn peer_child_spi(&self) -> Option<u32> {
        self.peer_child_spi
    }

    /// The credential (username) selected by the client's EAP identity. Empty
    /// until the Identity step has run; meaningful once authentication succeeds.
    pub fn user(&self) -> &[u8] {
        &self.user
    }

    pub fn handle(&mut self, message: &[u8], entropy: &mut impl Entropy) -> Result<EapEvent, IkeError> {
        let (msg_id, ps) = decrypt(&self.sa, message)?;
        self.peer_mobike |= crate::ikev2::mobike::peer_supports_mobike(&ps);
        let event = self.advance(msg_id, &ps, entropy)?;
        if !matches!(event, EapEvent::Reply(_)) {
            // Established or failed: this exchange takes nothing more.
            self.step = AuthStep::Done;
        }
        Ok(event)
    }

    /// Take the next initiator message, in the step it belongs to.
    fn advance(&mut self, msg_id: u32, ps: &Payloads, entropy: &mut impl Entropy) -> Result<EapEvent, IkeError> {
        // msg-1: IDi + SA + TS, no AUTH, no EAP → authenticate ourselves and
        // start EAP with an Identity request: SK{ IDr, [CERT,] AUTH, EAP }.
        if find(ps, PayloadType::Eap).is_none() && find(ps, PayloadType::Authentication).is_none() {
            if self.step != AuthStep::Start {
                return Ok(EapEvent::Failed(None));
            }
            let Some(sai2) = find(ps, PayloadType::SecurityAssociation) else {
                return Ok(EapEvent::Failed(None));
            };
            // Capture the initiator's ESP SPI (for the CHILD SA) and its IDi
            // verbatim (its final AUTH signs over it).
            self.peer_child_spi = esp_spi_from_sa(sai2);
            // RFC 7296 §1.2, §3.13: the request for a CHILD SA carries TSi and TSr.
            let tsi = find(ps, PayloadType::TrafficSelectorInitiator).ok_or(IkeError::MissingPayload("TSi"))?;
            let tsr = find(ps, PayloadType::TrafficSelectorResponder).ok_or(IkeError::MissingPayload("TSr"))?;
            self.peer_ts = Some((TrafficSelectors::parse(tsi)?, TrafficSelectors::parse(tsr)?));
            self.peer_idi = find(ps, PayloadType::IdInitiator).unwrap_or(&[]).to_vec();
            let idr = self.id.to_bytes();
            let algo = self.sa.suite.prf_algorithm();
            let octets = responder_signed_octets(algo, &self.sa.resp_message, &self.sa.ni, &self.sa.keys.sk_pr, &idr);

            let mut inner: Vec<(PayloadType, Vec<u8>)> = vec![(PayloadType::IdResponder, idr)];
            match &self.auth {
                ServerAuth::Psk(psk) => {
                    let auth = Authentication { method: auth_method::SHARED_KEY, data: psk_auth(algo, psk, &octets) };
                    inner.push((PayloadType::Authentication, auth.to_bytes()));
                }
                ServerAuth::Cert { key, chain } => {
                    // Send the chain (leaf first) unconditionally — iOS often
                    // sends no CERTREQ, so gating on one would break the default.
                    for cert in chain {
                        inner.push((PayloadType::Certificate, Certificate::x509(cert.clone()).to_bytes()));
                    }
                    // Method 14 (RFC 7427) if the peer advertised SHA-256, else
                    // the classic ECDSA method 9 — a native iOS EAP client sends
                    // no SIGNATURE_HASH_ALGORITHMS, so it needs the classic form.
                    let auth = crate::ikev2::ike_auth::cert_auth_payload(
                        key,
                        &self.sa.peer_signature_hashes,
                        &octets,
                    )?;
                    inner.push((PayloadType::Authentication, auth.to_bytes()));
                }
            }
            let id = 1;
            let eap = eap::EapPacket { code: eap::code::REQUEST, identifier: id, data: vec![eap::eap_type::IDENTITY] };
            inner.push((PayloadType::Eap, eap.to_bytes()));
            let msg = build_sk(&self.sa, msg_id, true, &inner, &iv(entropy))?;
            self.step = AuthStep::Identity { id };
            return Ok(EapEvent::Reply(msg));
        }

        // Final: the initiator's MSK-keyed AUTH (no EAP, has AUTH) -- only
        // once EAP has succeeded: before that there is no MSK, and the one
        // computed from nothing is anyone's to compute (RFC 7296 §2.16).
        if let Some(auth_bytes) = find(ps, PayloadType::Authentication) {
            if find(ps, PayloadType::Eap).is_none() {
                if self.step != AuthStep::Succeeded {
                    return Ok(EapEvent::Failed(None));
                }
                let msk = mschapv2::derive_msk(&self.password, &self.nt_response);
                let algo = self.sa.suite.prf_algorithm();
                let expect =
                    psk_auth(algo, &msk, &initiator_signed_octets(algo, &self.sa.init_message, &self.sa.nr, &self.sa.keys.sk_pi, &self.peer_idi));
                let got = crate::ikev2::payload::Authentication::parse(auth_bytes)?;
                // RFC 7296 §2.16: the EAP AUTH is the Shared Key MIC keyed by the MSK.
                if got.method != auth_method::SHARED_KEY || !ct_eq(&got.data, &expect) {
                    return Ok(EapEvent::Failed(None));
                }
                // Send our final AUTH(MSK) + SAr2 + TSi + TSr.
                let idr = self.id.to_bytes();
                let our_auth = Authentication {
                    method: auth_method::SHARED_KEY,
                    data: psk_auth(algo, &msk, &responder_signed_octets(algo, &self.sa.resp_message, &self.sa.ni, &self.sa.keys.sk_pr, &idr)),
                };
                // Assign the client its inner IP via a Configuration Payload
                // (CFG_REPLY) and narrow TSi to that /32, mirroring the PSK path,
                // so the cascade's per-client IP works over EAP too.
                let mut inner: Vec<(PayloadType, Vec<u8>)> = vec![
                    (PayloadType::IdResponder, idr),
                    (PayloadType::Authentication, our_auth.to_bytes()),
                ];
                let (policy_i, policy_r) = assigned_ipv4_policy(self.assigned.as_ref().map(|a| a.ip));
                let (tsi, tsr) = self.peer_ts.as_ref().map(|(tsi, tsr)| (tsi, tsr)).unzip();
                match narrow_requested_ts(tsi, tsr, &policy_i, &policy_r) {
                    Ok((tsi, tsr)) => {
                        if let Some(a) = &self.assigned {
                            let dns = a.dns.first().copied();
                            inner.push((
                                PayloadType::Configuration,
                                Configuration::reply_ipv4(a.ip, None, dns).to_bytes(),
                            ));
                        }
                        inner.push((PayloadType::SecurityAssociation, esp_offer(self.child_spi).to_bytes()));
                        inner.push((PayloadType::TrafficSelectorInitiator, tsi.to_bytes()));
                        inner.push((PayloadType::TrafficSelectorResponder, tsr.to_bytes()));
                    }
                    // RFC 7296 §1.2, §2.9: the IKE SA stands, the CHILD SA is refused.
                    Err(IkeError::TsUnacceptable) => {
                        self.peer_child_spi = None;
                        inner.push((PayloadType::Notify, Notify::status(notify_type::TS_UNACCEPTABLE, Vec::new()).to_bytes()));
                    }
                    Err(e) => return Err(e),
                }
                // Advertise MOBIKE -- so the client migrates the SA across network
                // changes (Wi-Fi↔cellular / NAT rebind) via UPDATE_SA_ADDRESSES
                // instead of reconnecting -- only when the consumer follows it
                // there and the client offered it (RFC 4555 §3.1).
                if self.mobike_enabled() {
                    inner.push((
                        PayloadType::Notify,
                        crate::ikev2::mobike::mobike_supported().to_bytes(),
                    ));
                }
                let msg = build_sk(&self.sa, msg_id, true, &inner, &iv(entropy))?;
                return Ok(EapEvent::Established(Some(msg)));
            }
        }

        // Otherwise an EAP response drives the next step. It must answer
        // the Request we have outstanding, by Identifier (RFC 3748 §4.1) and
        // by step; an initiator's AUTH has no place in it.
        let eap_bytes = find(ps, PayloadType::Eap).ok_or(IkeError::MissingPayload("EAP"))?;
        let id = match self.step {
            AuthStep::Identity { id } | AuthStep::Challenge { id } | AuthStep::Success { id } => id,
            _ => return Ok(EapEvent::Failed(None)),
        };
        if find(ps, PayloadType::Authentication).is_some() {
            return Ok(EapEvent::Failed(None));
        }
        let eap = eap::EapPacket::parse(eap_bytes)?;
        if eap.code != eap::code::RESPONSE || eap.identifier != id {
            return Ok(EapEvent::Failed(None));
        }
        let next = id.wrapping_add(1);
        let op = eap.data.get(1).copied();

        let (out, step) = match (self.step, eap.eap_type()) {
            (AuthStep::Identity { .. }, Some(eap::eap_type::IDENTITY)) => {
                // The claimed identity selects this client's credentials; an
                // unknown username is rejected here, before any challenge.
                let claimed = eap.data.get(1..).unwrap_or(&[]).to_vec();
                match self.users.get(&claimed) {
                    Some(pw) => {
                        self.user = claimed;
                        self.password = pw.clone();
                    }
                    None => return Ok(EapEvent::Failed(None)),
                }
                // Got the identity → send an MSCHAPv2 Challenge.
                entropy.fill(&mut self.auth_challenge);
                (eap::build_challenge(MSCHAP_ID, &self.auth_challenge, b"ryke"), AuthStep::Challenge { id: next })
            }
            (AuthStep::Challenge { .. }, Some(eap::eap_type::MSCHAPV2)) if op == Some(eap::op::RESPONSE) => {
                let resp = eap::parse_response(&eap.data)?;
                // The Response copies its Challenge's identifier (RFC 1994
                // §4.1, which MS-CHAPv2 keeps -- RFC 2759 §4).
                if resp.mschap_id != MSCHAP_ID {
                    return Ok(EapEvent::Failed(None));
                }
                self.nt_response = mschapv2::generate_nt_response(&self.auth_challenge, &resp.peer_challenge, &self.user, &self.password);
                if !ct_eq(&self.nt_response, &resp.nt_response) {
                    return Ok(EapEvent::Failed(None));
                }
                let auth_resp = mschapv2::generate_authenticator_response(&self.password, &self.nt_response, &resp.peer_challenge, &self.auth_challenge, &self.user);
                (eap::build_success(MSCHAP_ID, &auth_resp), AuthStep::Success { id: next })
            }
            (AuthStep::Success { .. }, Some(eap::eap_type::MSCHAPV2)) if op == Some(eap::op::SUCCESS) => {
                // Client acked → send EAP-Success, with the Identifier of
                // the Response it answers (RFC 3748 §4.2).
                self.step = AuthStep::Succeeded;
                return Ok(EapEvent::Reply(build_sk(&self.sa, msg_id, true, &[(
                    PayloadType::Eap,
                    eap::EapPacket { code: eap::code::SUCCESS, identifier: eap.identifier, data: vec![] }.to_bytes(),
                )], &iv(entropy))?));
            }
            _ => return Ok(EapEvent::Failed(None)),
        };
        self.step = step;
        let req = eap::EapPacket { code: eap::code::REQUEST, identifier: next, data: out };
        Ok(EapEvent::Reply(build_sk(&self.sa, msg_id, true, &[(PayloadType::Eap, req.to_bytes())], &iv(entropy))?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::SeedEntropy;
    use crate::ikev2::exchange::{default_offer, initiator_complete, initiator_request, responder_respond, LocalSecret};
    use crate::ikev2::payload::{protocol_id, transform_id, transform_type, Proposal, TrafficSelector, Transform};
    use crate::test_certs::{CA_CERT_DER, LEAF_CERT_DER, LEAF_SCALAR, RSA_KEY_PK8};

    #[derive(PartialEq, Eq, Debug)]
    enum Outcome {
        Established,
        Failed,
    }

    fn sa_pair() -> (CompletedSaInit, CompletedSaInit) {
        let init = LocalSecret { dh_private: [7u8; 32], nonce: vec![0x11; 32], spi: 0xA1 };
        let resp = LocalSecret { dh_private: [9u8; 32], nonce: vec![0x22; 32], spi: 0xB2 };
        let request = initiator_request(&init, &default_offer());
        let (response, resp_done) = responder_respond(&request, &resp).unwrap();
        let init_done = initiator_complete(&init, &request, &response).unwrap();
        (init_done, resp_done)
    }

    /// Run the whole exchange to a terminal state, asserting the initiator and
    /// responder agree on success/failure.
    fn drive(mut initiator: EapInitiator, mut responder: EapResponder) -> Outcome {
        let mut ie = SeedEntropy::new(1);
        let mut re = SeedEntropy::new(2);
        let mut in_flight = initiator.start(&mut ie).unwrap(); // msg-1 (init → resp)
        for _round in 0..12 {
            match responder.handle(&in_flight, &mut re).unwrap() {
                EapEvent::Reply(m) => match initiator.handle(&m, &mut ie).unwrap() {
                    EapEvent::Reply(m2) => in_flight = m2,
                    EapEvent::Established(_) => return Outcome::Established,
                    EapEvent::Failed(_) => return Outcome::Failed,
                },
                EapEvent::Established(Some(final_msg)) => {
                    // The responder is up; the initiator must accept the final message.
                    return match initiator.handle(&final_msg, &mut ie).unwrap() {
                        EapEvent::Established(None) => Outcome::Established,
                        _ => Outcome::Failed,
                    };
                }
                EapEvent::Established(None) => return Outcome::Established,
                EapEvent::Failed(_) => return Outcome::Failed,
            }
        }
        Outcome::Failed
    }

    fn ecdsa_leaf_key() -> SigningKey {
        SigningKey::EcdsaP256(p256::ecdsa::SigningKey::from_slice(LEAF_SCALAR).unwrap())
    }

    /// A Unix time within the leaf fixture's validity window.
    fn valid_now() -> u64 {
        crate::ikev2::sign::cert_validity(LEAF_CERT_DER).unwrap().0 + 1
    }

    /// Trust the given CAs and expect the leaf-fixture's dNSName, at a valid time.
    fn trust(cas: Vec<Vec<u8>>) -> ServerVerify {
        ServerVerify::TrustedCas { cas, expected_dns: Some("vpn.example.com".into()), now_unix: valid_now() }
    }

    fn cert_server() -> ServerAuth {
        ServerAuth::Cert { key: ecdsa_leaf_key(), chain: vec![LEAF_CERT_DER.to_vec()] }
    }

    #[test]
    fn server_psk_verify_succeeds_when_psk_matches() {
        // The gateway shape this variant exists for: no certificate, the
        // responder authenticates itself with a group PSK, and the client can
        // now actually check that (previously only Insecure/TrustedCas
        // existed, so a PSK-authenticated server could only be blindly
        // trusted, never verified).
        let (init_sa, resp_sa) = sa_pair();
        let initiator = EapInitiator::new(init_sa, Identification::fqdn("alice"), b"alice".to_vec(), "s3cret".into(), 0x1111, ServerVerify::Psk(b"group-psk".to_vec()));
        let responder = EapResponder::new(resp_sa, Identification::fqdn("gw"), ServerAuth::Psk(b"group-psk".to_vec()), b"alice".to_vec(), "s3cret".into(), 0x2222);
        assert_eq!(drive(initiator, responder), Outcome::Established);
    }

    #[test]
    fn server_psk_verify_rejects_wrong_psk() {
        // Same responder, but the client was configured with the wrong group
        // PSK -- it must not proceed to EAP (would otherwise disclose the
        // username/password to an unverified peer).
        let (init_sa, resp_sa) = sa_pair();
        let initiator = EapInitiator::new(init_sa, Identification::fqdn("alice"), b"alice".to_vec(), "s3cret".into(), 0x1111, ServerVerify::Psk(b"wrong-psk".to_vec()));
        let responder = EapResponder::new(resp_sa, Identification::fqdn("gw"), ServerAuth::Psk(b"group-psk".to_vec()), b"alice".to_vec(), "s3cret".into(), 0x2222);
        assert_eq!(drive(initiator, responder), Outcome::Failed, "a mismatched PSK must fail server verification");
    }

    #[test]
    fn full_eap_mschapv2_handshake_in_process() {
        let (init_sa, resp_sa) = sa_pair();
        let initiator = EapInitiator::new(init_sa, Identification::fqdn("alice"), b"alice".to_vec(), "s3cret".into(), 0x1111, ServerVerify::Insecure);
        let responder = EapResponder::new(resp_sa, Identification::fqdn("gw"), ServerAuth::Psk(b"psk".to_vec()), b"alice".to_vec(), "s3cret".into(), 0x2222);
        assert_eq!(drive(initiator, responder), Outcome::Established);
    }

    /// Run the EAP exchange up to the responder's final message (the one with
    /// its MSK-keyed AUTH + SA/TS), and return it with both endpoints.
    fn run_to_final_message() -> (EapInitiator, EapResponder, Vec<u8>) {
        run_to_final_message_with_mobike(false, false)
    }

    /// [`run_to_final_message`] with the responder's [`EapResponder::set_mobike`]
    /// set to `opt_in`, and `N(MOBIKE_SUPPORTED)` added to msg-1 when `offer`.
    fn run_to_final_message_with_mobike(offer: bool, opt_in: bool) -> (EapInitiator, EapResponder, Vec<u8>) {
        let (init_sa, resp_sa) = sa_pair();
        let mut initiator = EapInitiator::new(init_sa, Identification::fqdn("alice"), b"alice".to_vec(), "s3cret".into(), 0x1111, ServerVerify::Insecure);
        let mut responder = EapResponder::new(resp_sa, Identification::fqdn("gw"), ServerAuth::Psk(b"psk".to_vec()), b"alice".to_vec(), "s3cret".into(), 0x2222);
        responder.set_mobike(opt_in);
        let mut ie = SeedEntropy::new(1);
        let mut re = SeedEntropy::new(2);
        let mut in_flight = initiator.start(&mut ie).unwrap();
        if offer {
            let (msg_id, mut ps) = decrypt(&responder.sa, &in_flight).unwrap();
            ps.push((PayloadType::Notify, crate::ikev2::mobike::mobike_supported().to_bytes()));
            in_flight = build_sk(&initiator.sa, msg_id, false, &ps, &[4u8; 8]).unwrap();
        }
        let final_msg = loop {
            match responder.handle(&in_flight, &mut re).unwrap() {
                EapEvent::Reply(m) => match initiator.handle(&m, &mut ie).unwrap() {
                    EapEvent::Reply(m2) => in_flight = m2,
                    other => panic!("the initiator ended early: {other:?}"),
                },
                EapEvent::Established(Some(f)) => break f,
                other => panic!("unexpected responder event: {other:?}"),
            }
        };
        (initiator, responder, final_msg)
    }

    /// `final_msg` as a responder sends it when only the CHILD SA failed (RFC
    /// 7296 §1.2): the same IDr + AUTH, then `error` instead of SA/TS/CFG.
    /// `tamper_auth` corrupts the AUTH to model a peer that did not authenticate.
    fn child_rejected_final(initiator: &EapInitiator, responder: &EapResponder, final_msg: &[u8], error: u16, tamper_auth: bool) -> Vec<u8> {
        let (msg_id, ps) = decrypt(&initiator.sa, final_msg).unwrap();
        let mut inner: Payloads = ps
            .into_iter()
            .filter(|(t, _)| matches!(t, PayloadType::IdResponder | PayloadType::Authentication))
            .collect();
        if tamper_auth {
            for (t, body) in &mut inner {
                if *t == PayloadType::Authentication {
                    let last = body.len() - 1;
                    body[last] ^= 1;
                }
            }
        }
        inner.push((PayloadType::Notify, Notify::status(error, Vec::new()).to_bytes()));
        build_sk(&responder.sa, msg_id, true, &inner, &[3u8; 8]).unwrap()
    }

    #[test]
    fn eap_responder_advertises_mobike_only_when_opted_in_and_offered() {
        // (initiator offered, responder opted in) -> MOBIKE advertised + in force.
        for (offer, opt_in, expect) in [(false, false, false), (true, false, false), (false, true, false), (true, true, true)] {
            let (mut initiator, responder, final_msg) = run_to_final_message_with_mobike(offer, opt_in);
            let (_msg_id, ps) = decrypt(&initiator.sa, &final_msg).unwrap();
            // By default nothing behind the responder follows a client to a new
            // address, so it must not invite one to move (RFC 4555); opted in,
            // it still answers only an initiator that offered MOBIKE (§3.1).
            assert_eq!(crate::ikev2::mobike::peer_supports_mobike(&ps), expect, "offer={offer} opt_in={opt_in}");
            assert_eq!(responder.mobike_enabled(), expect, "offer={offer} opt_in={opt_in}");
            assert!(matches!(initiator.handle(&final_msg, &mut SeedEntropy::new(1)), Ok(EapEvent::Established(None))));
        }
    }

    #[test]
    fn eap_final_message_that_does_not_repeat_idr_still_verifies() {
        // RFC 7296 §2.16: IDr travels in the first IKE_AUTH response only; the
        // final one is AUTH + SA + TS (+ CP), and its AUTH is still signed over
        // that first IDr. strongSwan sends it this way; the FortiGate repeats it.
        let (mut initiator, responder, final_msg) = run_to_final_message();
        let (msg_id, ps) = decrypt(&initiator.sa, &final_msg).unwrap();
        assert!(find(&ps, PayloadType::IdResponder).is_some(), "the test responder repeats IDr");
        let inner: Payloads = ps.into_iter().filter(|(t, _)| *t != PayloadType::IdResponder).collect();
        let without_idr = build_sk(&responder.sa, msg_id, true, &inner, &[3u8; 8]).unwrap();
        assert!(matches!(initiator.handle(&without_idr, &mut SeedEntropy::new(1)), Ok(EapEvent::Established(None))));
    }

    #[test]
    fn eap_child_sa_error_after_a_good_auth_is_a_named_rejection() {
        // The FortiGate path: EAP succeeds and AUTH verifies, but the gateway
        // refuses the CHILD SA in that last IKE_AUTH message. That used to be
        // reported as a failed authentication.
        for error in [notify_type::TS_UNACCEPTABLE, notify_type::NO_PROPOSAL_CHOSEN, notify_type::SINGLE_PAIR_REQUIRED] {
            let (mut initiator, responder, final_msg) = run_to_final_message();
            let rejected = child_rejected_final(&initiator, &responder, &final_msg, error, false);
            let err = initiator.handle(&rejected, &mut SeedEntropy::new(1)).unwrap_err();
            assert_eq!(err, IkeError::PeerRejected { notify_type: error, name: notify_type_name(error) });
        }
    }

    #[test]
    fn eap_child_sa_error_is_not_believed_when_the_auth_does_not_verify() {
        let (mut initiator, responder, final_msg) = run_to_final_message();
        let rejected = child_rejected_final(&initiator, &responder, &final_msg, notify_type::TS_UNACCEPTABLE, true);
        assert!(matches!(initiator.handle(&rejected, &mut SeedEntropy::new(1)), Ok(EapEvent::Failed(None))));
    }

    #[test]
    fn eap_final_message_with_an_unoffered_esp_suite_is_rejected() {
        // `EapInitiator` offers AES-GCM-256 by default. A responder whose
        // final message's SAr2 names AES-CBC-128/HMAC-SHA1-96 instead -- a
        // combination `select_esp`/`sk::SkCipher` can decode fine -- must be
        // rejected, not silently accepted as the negotiated cipher (RFC 7296
        // §2.7): the AUTH doesn't cover SA/TS, so a compromised or on-path
        // responder that already knows how to pass EAP could otherwise
        // downgrade the data-plane cipher undetected.
        let (mut initiator, responder, final_msg) = run_to_final_message();
        let (msg_id, ps) = decrypt(&initiator.sa, &final_msg).unwrap();
        let mut inner: Payloads = ps
            .into_iter()
            .filter(|(t, _)| matches!(t, PayloadType::IdResponder | PayloadType::Authentication))
            .collect();
        let downgrade = SecurityAssociation {
            proposals: vec![Proposal {
                num: 1,
                protocol_id: protocol_id::ESP,
                spi: 0x2222u32.to_be_bytes().to_vec(),
                transforms: vec![
                    Transform { transform_type: transform_type::ENCR, transform_id: transform_id::AES_CBC, key_length: Some(128) },
                    Transform { transform_type: transform_type::INTEG, transform_id: transform_id::AUTH_HMAC_SHA1_96, key_length: None },
                    Transform { transform_type: transform_type::ESN, transform_id: transform_id::ESN_NONE, key_length: None },
                ],
            }],
        };
        inner.push((PayloadType::SecurityAssociation, downgrade.to_bytes()));
        inner.push((PayloadType::TrafficSelectorInitiator, full_tunnel_ts()));
        inner.push((PayloadType::TrafficSelectorResponder, full_tunnel_ts()));
        let tampered = build_sk(&responder.sa, msg_id, true, &inner, &[3u8; 8]).unwrap();
        let err = initiator.handle(&tampered, &mut SeedEntropy::new(1)).unwrap_err();
        assert_eq!(err, IkeError::NoProposalChosen);
    }

    #[test]
    fn eap_final_message_must_answer_both_ts_within_the_offer() {
        use crate::ikev2::ike_auth::tests::{ts_answers_outside_an_ipv4_offer, with_ts};
        for (what, tsi, tsr, expected) in ts_answers_outside_an_ipv4_offer() {
            let (mut initiator, responder, final_msg) = run_to_final_message();
            let (msg_id, ps) = decrypt(&initiator.sa, &final_msg).unwrap();
            let edited = build_sk(&responder.sa, msg_id, true, &with_ts(ps, tsi, tsr), &[3u8; 8]).unwrap();
            assert_eq!(initiator.handle(&edited, &mut SeedEntropy::new(1)).err(), Some(expected), "{what}");
        }

        // Positive controls: TSi narrowed to one address, and both families
        // granted to a unified offer.
        let host = TrafficSelectors { selectors: vec![TrafficSelector::ipv4_host(std::net::Ipv4Addr::new(10, 8, 0, 4))] };
        let unified = TrafficSelectors::unified_full_tunnel();
        for (offer, tsi, tsr) in
            [(ChildTsOffer::Ipv4, &host, TrafficSelectors::ipv4_full_tunnel()), (ChildTsOffer::Unified, &unified, unified.clone())]
        {
            let (mut initiator, responder, final_msg) = run_to_final_message();
            initiator.set_ts_offer(offer);
            let (msg_id, ps) = decrypt(&initiator.sa, &final_msg).unwrap();
            let edited = build_sk(&responder.sa, msg_id, true, &with_ts(ps, Some(tsi.to_bytes()), Some(tsr.to_bytes())), &[3u8; 8]).unwrap();
            assert!(matches!(initiator.handle(&edited, &mut SeedEntropy::new(1)), Ok(EapEvent::Established(None))), "{offer:?}");
            assert_eq!(initiator.granted_ts(), Some(&tsr));
        }
    }

    /// EAP run to the responder's final message, msg-1's TSi/TSr replaced by
    /// `tsi`/`tsr` (left out when `None`) and the client `assigned` an
    /// address -- or the error the responder met on the way.
    fn final_message_for_ts(
        tsi: Option<&TrafficSelectors>,
        tsr: Option<&TrafficSelectors>,
        assigned: Option<AssignedConfig>,
    ) -> Result<(EapInitiator, EapResponder, Vec<u8>), IkeError> {
        use crate::ikev2::ike_auth::tests::with_ts;
        let (init_sa, resp_sa) = sa_pair();
        let mut initiator =
            EapInitiator::new(init_sa, Identification::fqdn("alice"), b"alice".to_vec(), "s3cret".into(), 0x1111, ServerVerify::Insecure);
        let mut responder =
            EapResponder::new(resp_sa, Identification::fqdn("gw"), ServerAuth::Psk(b"psk".to_vec()), b"alice".to_vec(), "s3cret".into(), 0x2222);
        responder.set_assigned(assigned);
        let (mut ie, mut re) = (SeedEntropy::new(1), SeedEntropy::new(2));
        let (msg_id, ps) = decrypt(&responder.sa, &initiator.start(&mut ie).unwrap()).unwrap();
        let ps = with_ts(ps, tsi.map(TrafficSelectors::to_bytes), tsr.map(TrafficSelectors::to_bytes));
        let mut in_flight = build_sk(&initiator.sa, msg_id, false, &ps, &[4u8; 8]).unwrap();
        loop {
            match responder.handle(&in_flight, &mut re)? {
                EapEvent::Reply(m) => match initiator.handle(&m, &mut ie).unwrap() {
                    EapEvent::Reply(m2) => in_flight = m2,
                    other => panic!("the initiator ended early: {other:?}"),
                },
                EapEvent::Established(Some(f)) => return Ok((initiator, responder, f)),
                other => panic!("unexpected responder event: {other:?}"),
            }
        }
    }

    /// RFC 7296 §2.9 at the EAP responder: its final message answers msg-1's
    /// TSi and TSr narrowed to IPv4 and the address it assigns, or refuses
    /// the CHILD SA with `TS_UNACCEPTABLE` when either comes to nothing --
    /// the IKE SA standing (§1.2).
    #[test]
    fn eap_responder_answers_a_subset_of_msg1_ts_or_ts_unacceptable() {
        use crate::ikev2::ike_auth::tests::{answered_ts, sample_ts};
        let t = sample_ts();
        let assigned = || AssignedConfig { ip: std::net::Ipv4Addr::new(10, 8, 0, 4), dns: vec![] };
        let at_10_8_0_4 = TrafficSelectors { selectors: vec![TrafficSelector::ipv4_host(assigned().ip)] };

        let granted = [
            ("a host and a subnet, not the whole of IPv4", &t.host, &t.subnet, None, &t.host, &t.subnet),
            ("the IPv4 part of a unified proposal", &t.unified, &t.unified, None, &t.v4, &t.v4),
            ("a type no RFC defines is ignored", &t.v4, &t.unknown_then_v4, None, &t.v4, &t.v4),
            ("0.0.0.0/0 narrowed to the address assigned", &t.v4, &t.v4, Some(assigned()), &at_10_8_0_4, &t.v4),
        ];
        for (what, tsi, tsr, assigned, want_tsi, want_tsr) in granted {
            let (initiator, responder, final_msg) = final_message_for_ts(Some(tsi), Some(tsr), assigned).unwrap();
            assert_eq!(answered_ts(&initiator.sa, &final_msg), (Some(want_tsi.clone()), Some(want_tsr.clone()), vec![]), "{what}");
            assert_eq!(responder.peer_child_spi(), Some(0x1111), "{what}");
        }

        let refused = [
            ("IPv6 only", &t.v6, &t.v6, None),
            ("an address other than the one assigned", &t.other_host, &t.v4, Some(assigned())),
            ("a TSr of a type no RFC defines", &t.v4, &t.unknown, None),
        ];
        for (what, tsi, tsr, assigned) in refused {
            let (mut initiator, responder, final_msg) = final_message_for_ts(Some(tsi), Some(tsr), assigned).unwrap();
            assert_eq!(answered_ts(&initiator.sa, &final_msg), (None, None, vec![notify_type::TS_UNACCEPTABLE]), "{what}");
            assert_eq!(responder.peer_child_spi(), None, "{what}: no CHILD SA");
            let got = initiator.handle(&final_msg, &mut SeedEntropy::new(1)).unwrap_err();
            assert_eq!(got, IkeError::PeerRejected { notify_type: notify_type::TS_UNACCEPTABLE, name: "TS_UNACCEPTABLE" }, "{what}");
        }

        // msg-1 asks for a CHILD SA, so it carries both (RFC 7296 §1.2).
        assert_eq!(final_message_for_ts(None, Some(&t.v4), None).err(), Some(IkeError::MissingPayload("TSi")));
        assert_eq!(final_message_for_ts(Some(&t.v4), None, None).err(), Some(IkeError::MissingPayload("TSr")));
    }

    #[test]
    fn eap_final_message_without_sa_and_without_a_child_error_is_still_a_failure() {
        // Unchanged: no SA and no CHILD SA error notify means we can't say why.
        let (mut initiator, responder, final_msg) = run_to_final_message();
        let rejected = child_rejected_final(&initiator, &responder, &final_msg, notify_type::AUTHENTICATION_FAILED, false);
        assert!(matches!(initiator.handle(&rejected, &mut SeedEntropy::new(1)), Ok(EapEvent::Failed(None))));
    }

    #[test]
    fn wrong_password_is_rejected() {
        let (init_sa, resp_sa) = sa_pair();
        let initiator = EapInitiator::new(init_sa, Identification::fqdn("alice"), b"alice".to_vec(), "wrong".into(), 0x1111, ServerVerify::Insecure);
        let responder = EapResponder::new(resp_sa, Identification::fqdn("gw"), ServerAuth::Psk(b"psk".to_vec()), b"alice".to_vec(), "right".into(), 0x2222);
        assert_eq!(drive(initiator, responder), Outcome::Failed, "a wrong password must fail");
    }

    #[test]
    fn eap_with_certificate_server_auth_succeeds() {
        // The phone path: EAP-MSCHAPv2 client + an RFC 7427 cert-authenticated
        // server whose leaf chains to the CA the client trusts and matches name.
        let (init_sa, resp_sa) = sa_pair();
        let initiator = EapInitiator::new(init_sa, Identification::fqdn("alice"), b"alice".to_vec(), "s3cret".into(), 0x1111, trust(vec![CA_CERT_DER.to_vec()]));
        let responder = EapResponder::new(resp_sa, Identification::fqdn("vpn.example.com"), cert_server(), b"alice".to_vec(), "s3cret".into(), 0x2222);
        assert_eq!(drive(initiator, responder), Outcome::Established);
    }

    // Regression test for a real FortiGate finding: its own certificate
    // legitimately names its public hostname, which need not match whatever
    // the client's configured connect address is (e.g. an internal DNS name
    // or IP) -- `expected_dns: None` must accept a cert with an unrelated
    // SAN as long as it chains to a trusted CA, matching the old charon/VICI
    // backend's equivalent (chain-only, no hostname check).
    #[test]
    fn eap_with_certificate_server_auth_succeeds_without_a_dns_check() {
        let (init_sa, resp_sa) = sa_pair();
        let verify = ServerVerify::TrustedCas { cas: vec![CA_CERT_DER.to_vec()], expected_dns: None, now_unix: valid_now() };
        let initiator = EapInitiator::new(init_sa, Identification::fqdn("alice"), b"alice".to_vec(), "s3cret".into(), 0x1111, verify);
        // The responder's own ID has nothing to do with the leaf's SAN
        // (vpn.example.com) -- proving the check is genuinely skipped, not
        // accidentally still matching.
        let responder = EapResponder::new(resp_sa, Identification::fqdn("totally-unrelated-name"), cert_server(), b"alice".to_vec(), "s3cret".into(), 0x2222);
        assert_eq!(drive(initiator, responder), Outcome::Established);
    }

    #[test]
    fn multi_user_selects_password_by_identity() {
        // Two provisioned users; a client authenticating as the *second* must
        // succeed — proving credentials are keyed by the client's EAP identity.
        let (init_sa, resp_sa) = sa_pair();
        let users = HashMap::from([
            (b"alice".to_vec(), "alice-pw".to_string()),
            (b"bob".to_vec(), "bob-pw".to_string()),
        ]);
        let initiator = EapInitiator::new(init_sa, Identification::fqdn("bob"), b"bob".to_vec(), "bob-pw".into(), 0x1111, ServerVerify::Insecure);
        let responder = EapResponder::new_multi(resp_sa, Identification::fqdn("gw"), ServerAuth::Psk(b"psk".to_vec()), users, 0x2222);
        assert_eq!(drive(initiator, responder), Outcome::Established);
    }

    #[test]
    fn multi_user_rejects_unknown_identity() {
        let (init_sa, resp_sa) = sa_pair();
        let users = HashMap::from([(b"alice".to_vec(), "alice-pw".to_string())]);
        let initiator = EapInitiator::new(init_sa, Identification::fqdn("mallory"), b"mallory".to_vec(), "whatever".into(), 0x1111, ServerVerify::Insecure);
        let responder = EapResponder::new_multi(resp_sa, Identification::fqdn("gw"), ServerAuth::Psk(b"psk".to_vec()), users, 0x2222);
        assert_eq!(drive(initiator, responder), Outcome::Failed, "an unprovisioned identity must fail");
    }

    #[test]
    fn eap_rejects_server_cert_without_a_trust_anchor() {
        // Same valid server, but the client has no trusted CA → must not proceed
        // (and must not have sent EAP credentials to it).
        let (init_sa, resp_sa) = sa_pair();
        let initiator = EapInitiator::new(init_sa, Identification::fqdn("alice"), b"alice".to_vec(), "s3cret".into(), 0x1111, trust(vec![]));
        let responder = EapResponder::new(resp_sa, Identification::fqdn("vpn.example.com"), cert_server(), b"alice".to_vec(), "s3cret".into(), 0x2222);
        assert_eq!(drive(initiator, responder), Outcome::Failed);
    }

    #[test]
    fn eap_rejects_signature_not_matching_the_presented_cert() {
        // The server presents the (CA-signed) ECDSA leaf but signs the AUTH with
        // an unrelated RSA key — the signature must not verify under the leaf's
        // public key, even though the chain checks out.
        use rsa::pkcs8::DecodePrivateKey;
        let wrong_key = SigningKey::RsaSha256(Box::new(rsa::RsaPrivateKey::from_pkcs8_der(RSA_KEY_PK8).unwrap()));
        let (init_sa, resp_sa) = sa_pair();
        let initiator = EapInitiator::new(init_sa, Identification::fqdn("alice"), b"alice".to_vec(), "s3cret".into(), 0x1111, trust(vec![CA_CERT_DER.to_vec()]));
        let responder = EapResponder::new(
            resp_sa, Identification::fqdn("vpn.example.com"),
            ServerAuth::Cert { key: wrong_key, chain: vec![LEAF_CERT_DER.to_vec()] },
            b"alice".to_vec(), "s3cret".into(), 0x2222,
        );
        assert_eq!(drive(initiator, responder), Outcome::Failed);
    }

    #[test]
    fn eap_rejects_valid_cert_for_the_wrong_name() {
        // The leaf chains to the trusted CA and its signature verifies, but its
        // SAN (vpn.example.com) is not the host the client meant to reach — a
        // valid cert for host A must not authenticate host B.
        let (init_sa, resp_sa) = sa_pair();
        let initiator = EapInitiator::new(
            init_sa, Identification::fqdn("alice"), b"alice".to_vec(), "s3cret".into(), 0x1111,
            ServerVerify::TrustedCas { cas: vec![CA_CERT_DER.to_vec()], expected_dns: Some("other.example.com".into()), now_unix: valid_now() },
        );
        let responder = EapResponder::new(resp_sa, Identification::fqdn("vpn.example.com"), cert_server(), b"alice".to_vec(), "s3cret".into(), 0x2222);
        assert_eq!(drive(initiator, responder), Outcome::Failed);
    }

    #[test]
    fn eap_with_intermediate_cert_chain_succeeds() {
        // The server presents leaf + intermediate; the client trusts only the
        // root and must build the path leaf → intermediate → root.
        use crate::test_certs::{CHAIN_INT_DER, CHAIN_LEAF_DER, CHAIN_LEAF_SCALAR, CHAIN_ROOT_DER};
        let (init_sa, resp_sa) = sa_pair();
        let now = crate::ikev2::sign::cert_validity(CHAIN_LEAF_DER).unwrap().0 + 1;
        let initiator = EapInitiator::new(
            init_sa, Identification::fqdn("alice"), b"alice".to_vec(), "s3cret".into(), 0x1111,
            ServerVerify::TrustedCas { cas: vec![CHAIN_ROOT_DER.to_vec()], expected_dns: Some("vpn.example.com".into()), now_unix: now },
        );
        let responder = EapResponder::new(
            resp_sa, Identification::fqdn("vpn.example.com"),
            ServerAuth::Cert {
                key: SigningKey::EcdsaP256(p256::ecdsa::SigningKey::from_slice(CHAIN_LEAF_SCALAR).unwrap()),
                chain: vec![CHAIN_LEAF_DER.to_vec(), CHAIN_INT_DER.to_vec()],
            },
            b"alice".to_vec(), "s3cret".into(), 0x2222,
        );
        assert_eq!(drive(initiator, responder), Outcome::Established);
    }

    #[test]
    fn eap_rejects_expired_server_cert() {
        // A valid, correctly-named, correctly-signed cert — but the client's
        // clock is past its notAfter.
        let (init_sa, resp_sa) = sa_pair();
        let expired = crate::ikev2::sign::cert_validity(LEAF_CERT_DER).unwrap().1 + 1;
        let initiator = EapInitiator::new(
            init_sa, Identification::fqdn("alice"), b"alice".to_vec(), "s3cret".into(), 0x1111,
            ServerVerify::TrustedCas { cas: vec![CA_CERT_DER.to_vec()], expected_dns: Some("vpn.example.com".into()), now_unix: expired },
        );
        let responder = EapResponder::new(resp_sa, Identification::fqdn("vpn.example.com"), cert_server(), b"alice".to_vec(), "s3cret".into(), 0x2222);
        assert_eq!(drive(initiator, responder), Outcome::Failed);
    }

    #[test]
    fn eap_rejects_a_server_cert_that_may_not_sign_or_has_an_unprocessed_critical_extension() {
        // RFC 4945 §5.1.3.2 and RFC 5280 §4.2 on the EAP client's check of
        // the server: a leaf whose KeyUsage is keyEncipherment only, and one
        // with a critical extension this crate does not process, both with a
        // valid chain and a valid AUTH signature. No name is expected, so
        // nothing else can refuse them.
        use crate::test_certs::forge;
        use x509_cert::ext::pkix::{KeyUsage, KeyUsages};
        const ROOT: &str = "CN=Forge Root";
        let root_key = forge::ec_key(1);
        let ca = vec![forge::basic_constraints(true, None), forge::key_usage(KeyUsage(KeyUsages::KeyCertSign.into()))];
        let root = forge::cert(1, ROOT, &root_key, ROOT, &root_key, ca);
        let run = |leaf_extension| {
            let (init_sa, resp_sa) = sa_pair();
            let leaf = forge::cert(2, "CN=vpn.example.com", &forge::ec_key(2), ROOT, &root_key, vec![leaf_extension]);
            let verify = ServerVerify::TrustedCas { cas: vec![root.clone()], expected_dns: None, now_unix: forge::NOW };
            let initiator = EapInitiator::new(init_sa, Identification::fqdn("alice"), b"alice".to_vec(), "s3cret".into(), 0x1111, verify);
            let server = ServerAuth::Cert { key: forge::ec_key(2), chain: vec![leaf] };
            let responder = EapResponder::new(resp_sa, Identification::fqdn("vpn.example.com"), server, b"alice".to_vec(), "s3cret".into(), 0x2222);
            drive(initiator, responder)
        };
        assert_eq!(run(forge::key_usage(KeyUsage(KeyUsages::KeyEncipherment.into()))), Outcome::Failed);
        assert_eq!(run(forge::raw_ext("1.3.6.1.4.1.55555.123", true, &[0x05, 0x00])), Outcome::Failed);
        // Controls: digitalSignature, and the extension not critical.
        assert_eq!(run(forge::key_usage(KeyUsage(KeyUsages::DigitalSignature.into()))), Outcome::Established);
        assert_eq!(run(forge::raw_ext("1.3.6.1.4.1.55555.123", false, &[0x05, 0x00])), Outcome::Established);
    }

    #[test]
    fn cert_server_falls_back_to_classic_ecdsa_without_a_hash_offer() {
        // A native EAP client (iOS) sends no SIGNATURE_HASH_ALGORITHMS. Rather
        // than fail, the ECDSA cert server emits the classic method-9 AUTH
        // (RFC 4754), so it still interoperates.
        let (init_sa, mut resp_sa) = sa_pair();
        resp_sa.peer_signature_hashes.clear(); // client offered none
        let mut responder = EapResponder::new(resp_sa, Identification::fqdn("vpn.example.com"), cert_server(), b"alice".to_vec(), "s3cret".into(), 0x2222);
        let initiator = EapInitiator::new(init_sa, Identification::fqdn("alice"), b"alice".to_vec(), "s3cret".into(), 0x1111, trust(vec![CA_CERT_DER.to_vec()]));
        let msg1 = initiator.start(&mut SeedEntropy::new(1)).unwrap();
        // The responder now produces a reply (its cert + a method-9 AUTH), not an error.
        assert!(matches!(
            responder.handle(&msg1, &mut SeedEntropy::new(2)),
            Ok(EapEvent::Reply(_))
        ));
    }

    #[test]
    fn client_refuses_eap_before_the_server_is_authenticated() {
        // A rogue peer that completed the unauthenticated IKE_SA_INIT sends a
        // first message with ONLY an EAP-Identity request — no IDr, no AUTH —
        // trying to skip server auth. The client must abort, never disclosing
        // its username or any MSCHAPv2 response.
        let (init_sa, resp_sa) = sa_pair();
        let mut initiator = EapInitiator::new(init_sa, Identification::fqdn("alice"), b"alice".to_vec(), "s3cret".into(), 0x1111, trust(vec![CA_CERT_DER.to_vec()]));
        // Craft the rogue SK{ EAP-Req/Identity } with the responder-side keys.
        let eap = eap::EapPacket { code: eap::code::REQUEST, identifier: 1, data: vec![eap::eap_type::IDENTITY] };
        let rogue = build_sk(&resp_sa, 1, true, &[(PayloadType::Eap, eap.to_bytes())], &[0u8; 8]).unwrap();
        let mut ie = SeedEntropy::new(1);
        assert!(matches!(initiator.handle(&rogue, &mut ie).unwrap(), EapEvent::Failed(_)));
    }

    #[test]
    fn eap_failure_reason_flags_e691_as_credentials_rejected() {
        // E=691 is RFC 2759's ERROR_AUTHENTICATION_FAILURE -- a rejected
        // username/password, the one case old charon's EAP_AUTH_HARD_FAILURE
        // grepped its debug log for.
        let r = EapFailureReason::parse("E=691 R=1 C=00112233445566778899AABBCCDDEEFF V=3".into());
        assert!(r.credentials_rejected);

        // Other MSCHAPv2 failure codes (e.g. 648 = ERROR_PASSWD_EXPIRED) are
        // real account states, not "wrong password" -- not the same signal.
        let r = EapFailureReason::parse("E=648 R=1 C=00112233445566778899AABBCCDDEEFF V=3".into());
        assert!(!r.credentials_rejected);

        // No parseable E= field at all -- treated as not a hard failure.
        let r = EapFailureReason::parse("garbage".into());
        assert!(!r.credentials_rejected);
    }

    #[test]
    fn eap_mschapv2_failure_e691_surfaces_as_a_hard_failure_with_the_reason() {
        // The gateway sends an EAP-Req/MSCHAPv2-Failure with E=691 instead of
        // a Challenge/Success -- e.g. a definitively wrong password. The
        // client must surface the parsed, typed reason (not just a bare
        // Failed) so a caller retrying other gateway hosts can tell this
        // apart from a transient/protocol failure.
        let (init_sa, resp_sa) = sa_pair();
        let mut initiator = EapInitiator::new(init_sa, Identification::fqdn("alice"), b"alice".to_vec(), "wrong-password".into(), 0x1111, ServerVerify::Insecure);
        let failure_msg = b"E=691 R=1 C=00112233445566778899AABBCCDDEEFF V=3";
        let mut d = vec![eap::eap_type::MSCHAPV2, eap::op::FAILURE, 1u8];
        d.extend_from_slice(&((4 + failure_msg.len()) as u16).to_be_bytes());
        d.extend_from_slice(failure_msg);
        let eap = eap::EapPacket { code: eap::code::REQUEST, identifier: 1, data: d };
        let msg = build_sk(&resp_sa, 1, true, &[(PayloadType::Eap, eap.to_bytes())], &[0u8; 8]).unwrap();
        let mut ie = SeedEntropy::new(1);
        match initiator.handle(&msg, &mut ie).unwrap() {
            EapEvent::Failed(Some(reason)) => {
                assert!(reason.credentials_rejected);
                assert_eq!(reason.raw, String::from_utf8_lossy(failure_msg));
            }
            other => panic!("expected EapEvent::Failed(Some(_)), got {other:?}"),
        }
    }

    /// Where the real exchange stands, by the message the responder sends next.
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    enum Step {
        Identity,
        Challenge,
        SuccessRequest,
        EapSuccess,
        Final,
    }

    fn step_of(initiator: &EapInitiator, msg: &[u8]) -> Step {
        match eap_from_responder(initiator, msg) {
            None => Step::Final,
            Some(p) if p.code == eap::code::SUCCESS => Step::EapSuccess,
            Some(p) => match (p.data.first().copied(), p.data.get(1).copied()) {
                (Some(eap::eap_type::IDENTITY), _) => Step::Identity,
                (Some(eap::eap_type::MSCHAPV2), Some(eap::op::CHALLENGE)) => Step::Challenge,
                (Some(eap::eap_type::MSCHAPV2), Some(eap::op::SUCCESS)) => Step::SuccessRequest,
                other => panic!("unexpected request {other:?}"),
            },
        }
    }

    /// The EAP packet in a message the responder sent, if any.
    fn eap_from_responder(initiator: &EapInitiator, msg: &[u8]) -> Option<eap::EapPacket> {
        let (_, ps) = decrypt(&initiator.sa, msg).unwrap();
        find(&ps, PayloadType::Eap).map(|b| eap::EapPacket::parse(b).unwrap())
    }

    /// The EAP packet in a message the initiator sent, if any.
    fn eap_from_initiator(responder: &EapResponder, msg: &[u8]) -> Option<eap::EapPacket> {
        let (_, ps) = decrypt(&responder.sa, msg).unwrap();
        find(&ps, PayloadType::Eap).map(|b| eap::EapPacket::parse(b).unwrap())
    }

    /// A message from the responder's side carrying only `eap`.
    fn responder_eap(responder: &EapResponder, eap: &eap::EapPacket) -> Vec<u8> {
        build_sk(&responder.sa, 9, true, &[(PayloadType::Eap, eap.to_bytes())], &[6u8; 8]).unwrap()
    }

    /// A message from the initiator's side carrying `inner`.
    fn initiator_msg(initiator: &EapInitiator, inner: &[(PayloadType, Vec<u8>)]) -> Vec<u8> {
        build_sk(&initiator.sa, 9, false, inner, &[7u8; 8]).unwrap()
    }

    fn psk_pair() -> (EapInitiator, EapResponder) {
        let (init_sa, resp_sa) = sa_pair();
        let psk = b"group-psk".to_vec();
        let initiator =
            EapInitiator::new(init_sa, Identification::fqdn("alice"), b"alice".to_vec(), "s3cret".into(), 0x1111, ServerVerify::Psk(psk.clone()));
        let responder = EapResponder::new(resp_sa, Identification::fqdn("gw"), ServerAuth::Psk(psk), b"alice".to_vec(), "s3cret".into(), 0x2222);
        (initiator, responder)
    }

    /// Run the real exchange until the responder's next message is at `stop`,
    /// and hand that message back undelivered, with the initiator's last one.
    fn run_until(stop: Step) -> (EapInitiator, EapResponder, Vec<u8>, Vec<u8>) {
        let (mut initiator, mut responder) = psk_pair();
        let mut ie = SeedEntropy::new(1);
        let mut re = SeedEntropy::new(2);
        let mut in_flight = initiator.start(&mut ie).unwrap();
        loop {
            let m = match responder.handle(&in_flight, &mut re).unwrap() {
                EapEvent::Reply(m) | EapEvent::Established(Some(m)) => m,
                other => panic!("unexpected responder event: {other:?}"),
            };
            if step_of(&initiator, &m) == stop {
                return (initiator, responder, m, in_flight);
            }
            match initiator.handle(&m, &mut ie).unwrap() {
                EapEvent::Reply(m2) => in_flight = m2,
                other => panic!("the initiator ended early: {other:?}"),
            }
        }
    }

    /// Hand `msg` to the initiator, then play the rest of the exchange out
    /// with the real responder.
    fn finish(mut initiator: EapInitiator, mut responder: EapResponder, msg: &[u8]) -> Outcome {
        let mut ie = SeedEntropy::new(11);
        let mut re = SeedEntropy::new(12);
        let mut in_flight = match initiator.handle(msg, &mut ie).unwrap() {
            EapEvent::Reply(m) => m,
            other => panic!("the initiator ended early: {other:?}"),
        };
        loop {
            match responder.handle(&in_flight, &mut re).unwrap() {
                EapEvent::Reply(m) => match initiator.handle(&m, &mut ie).unwrap() {
                    EapEvent::Reply(m2) => in_flight = m2,
                    EapEvent::Established(_) => return Outcome::Established,
                    EapEvent::Failed(_) => return Outcome::Failed,
                },
                EapEvent::Established(Some(f)) => {
                    return match initiator.handle(&f, &mut ie).unwrap() {
                        EapEvent::Established(None) => Outcome::Established,
                        _ => Outcome::Failed,
                    }
                }
                _ => return Outcome::Failed,
            }
        }
    }

    /// The Success-Request `msg` carries, with its message replaced by `text`.
    fn with_success_message(initiator: &EapInitiator, responder: &EapResponder, msg: &[u8], text: &[u8]) -> Vec<u8> {
        let mut p = eap_from_responder(initiator, msg).unwrap();
        p.data.truncate(5);
        p.data.extend_from_slice(text);
        let ms_len = (p.data.len() - 1) as u16;
        p.data[3..5].copy_from_slice(&ms_len.to_be_bytes());
        responder_eap(responder, &p)
    }

    /// The responder's final message as a gateway that knows the password
    /// would build it from the initiator's current NT-Response.
    fn final_message_now(initiator: &EapInitiator, responder: &EapResponder) -> Vec<u8> {
        let algo = responder.sa.suite.prf_algorithm();
        let msk = mschapv2::derive_msk("s3cret", &initiator.nt_response);
        let idr = responder.id.to_bytes();
        let octets = responder_signed_octets(algo, &responder.sa.resp_message, &responder.sa.ni, &responder.sa.keys.sk_pr, &idr);
        let auth = Authentication { method: auth_method::SHARED_KEY, data: psk_auth(algo, &msk, &octets) };
        let inner = [
            (PayloadType::IdResponder, idr),
            (PayloadType::Authentication, auth.to_bytes()),
            (PayloadType::SecurityAssociation, esp_offer(0x2222).to_bytes()),
            (PayloadType::TrafficSelectorInitiator, full_tunnel_ts()),
            (PayloadType::TrafficSelectorResponder, full_tunnel_ts()),
        ];
        build_sk(&responder.sa, 9, true, &inner, &[8u8; 8]).unwrap()
    }

    #[test]
    fn eap_takes_a_classic_ecdsa_server_auth_method_9() {
        // A client that offers no SIGNATURE_HASH_ALGORITHMS (a native iOS
        // one) gets RFC 4754's ECDSA-P256-SHA256 AUTH, method 9, from an EC
        // key -- which direct certificate authentication already verifies.
        let (mut init_sa, mut resp_sa) = sa_pair();
        init_sa.peer_signature_hashes.clear();
        resp_sa.peer_signature_hashes.clear();
        let initiator =
            EapInitiator::new(init_sa, Identification::fqdn("alice"), b"alice".to_vec(), "s3cret".into(), 0x1111, trust(vec![CA_CERT_DER.to_vec()]));
        let mut responder =
            EapResponder::new(resp_sa, Identification::fqdn("vpn.example.com"), cert_server(), b"alice".to_vec(), "s3cret".into(), 0x2222);
        let first = match responder.handle(&initiator.start(&mut SeedEntropy::new(1)).unwrap(), &mut SeedEntropy::new(2)).unwrap() {
            EapEvent::Reply(m) => m,
            other => panic!("unexpected responder event: {other:?}"),
        };
        let (_, ps) = decrypt(&initiator.sa, &first).unwrap();
        let auth = Authentication::parse(find(&ps, PayloadType::Authentication).unwrap()).unwrap();
        assert_eq!(auth.method, auth_method::ECDSA_SHA256_P256);

        let (mut init_sa, mut resp_sa) = sa_pair();
        init_sa.peer_signature_hashes.clear();
        resp_sa.peer_signature_hashes.clear();
        let initiator =
            EapInitiator::new(init_sa, Identification::fqdn("alice"), b"alice".to_vec(), "s3cret".into(), 0x1111, trust(vec![CA_CERT_DER.to_vec()]));
        let responder =
            EapResponder::new(resp_sa, Identification::fqdn("vpn.example.com"), cert_server(), b"alice".to_vec(), "s3cret".into(), 0x2222);
        assert_eq!(drive(initiator, responder), Outcome::Established);
    }

    #[test]
    fn eap_rejects_a_method_9_signature_that_does_not_verify() {
        let (mut init_sa, mut resp_sa) = sa_pair();
        init_sa.peer_signature_hashes.clear();
        resp_sa.peer_signature_hashes.clear();
        let mut initiator =
            EapInitiator::new(init_sa, Identification::fqdn("alice"), b"alice".to_vec(), "s3cret".into(), 0x1111, trust(vec![CA_CERT_DER.to_vec()]));
        let mut responder =
            EapResponder::new(resp_sa, Identification::fqdn("vpn.example.com"), cert_server(), b"alice".to_vec(), "s3cret".into(), 0x2222);
        let first = match responder.handle(&initiator.start(&mut SeedEntropy::new(1)).unwrap(), &mut SeedEntropy::new(2)).unwrap() {
            EapEvent::Reply(m) => m,
            other => panic!("unexpected responder event: {other:?}"),
        };
        let (msg_id, mut ps) = decrypt(&initiator.sa, &first).unwrap();
        for (t, body) in &mut ps {
            if *t == PayloadType::Authentication {
                let mut auth = Authentication::parse(body).unwrap();
                assert_eq!(auth.method, auth_method::ECDSA_SHA256_P256);
                auth.data[10] ^= 1;
                *body = auth.to_bytes();
            }
        }
        let forged = build_sk(&responder.sa, msg_id, true, &ps, &[3u8; 8]).unwrap();
        assert!(matches!(initiator.handle(&forged, &mut SeedEntropy::new(1)), Ok(EapEvent::Failed(None))));
    }

    #[test]
    fn eap_ends_on_a_wrong_or_missing_authenticator_response() {
        // RFC 2759 §8.8 and the EAP-MSCHAPv2 draft §2.3: the peer MUST check
        // the authenticator response, and when it is missing or wrong end
        // the session without answering.
        let wrong: [&[u8]; 5] =
            [b"S=0000000000000000000000000000000000000000", b"", b"M=welcome", b"S=0000", b"S=ZZ00000000000000000000000000000000000000"];
        for text in wrong {
            let (mut initiator, responder, msg, _) = run_until(Step::SuccessRequest);
            let forged = with_success_message(&initiator, &responder, &msg, text);
            let got = initiator.handle(&forged, &mut SeedEntropy::new(1));
            assert!(matches!(got, Ok(EapEvent::Failed(None))), "{:?}: {got:?}", String::from_utf8_lossy(text));
        }
        // The authenticator response stays wrong with its last digit changed.
        let (mut initiator, responder, msg, _) = run_until(Step::SuccessRequest);
        let p = eap_from_responder(&initiator, &msg).unwrap();
        let mut text = p.data[5..].to_vec();
        let last = 41;
        text[last] = if text[last] == b'0' { b'1' } else { b'0' };
        let forged = with_success_message(&initiator, &responder, &msg, &text);
        assert!(matches!(initiator.handle(&forged, &mut SeedEntropy::new(1)), Ok(EapEvent::Failed(None))));
    }

    #[test]
    fn eap_takes_the_authenticator_response_in_either_case_and_with_a_message() {
        // RFC 2759 §8.7 writes the digits in upper case, but they are a
        // number: lower case names the same one. The message may follow.
        for (lower, message) in [(false, &b""[..]), (true, &b""[..]), (false, &b" M=Welcome"[..]), (true, &b" M=Welcome"[..])] {
            let (initiator, responder, msg, _) = run_until(Step::SuccessRequest);
            let p = eap_from_responder(&initiator, &msg).unwrap();
            let mut text = p.data[5..47].to_vec();
            if lower {
                text.make_ascii_lowercase();
                text[0] = b'S';
            }
            text.extend_from_slice(message);
            let msg = with_success_message(&initiator, &responder, &msg, &text);
            assert_eq!(finish(initiator, responder, &msg), Outcome::Established, "lower={lower} message={message:?}");
        }
    }

    #[test]
    fn eap_discards_a_canned_success() {
        // RFC 3748 §4.2: by default a peer MUST discard an EAP-Success
        // that comes before its method has finished.
        for stop in [Step::Challenge, Step::SuccessRequest] {
            let (mut initiator, responder, msg, _) = run_until(stop);
            let id = eap_from_responder(&initiator, &msg).unwrap().identifier;
            let canned = responder_eap(&responder, &eap::EapPacket { code: eap::code::SUCCESS, identifier: id, data: vec![] });
            let got = initiator.handle(&canned, &mut SeedEntropy::new(1));
            assert!(matches!(got, Ok(EapEvent::Failed(None))), "at {stop:?}: {got:?}");
        }
        // Nor an MSCHAPv2 Success Request before any Challenge: there is no
        // NT-Response yet for it to prove anything about.
        let (mut initiator, responder, msg, _) = run_until(Step::Challenge);
        let id = eap_from_responder(&initiator, &msg).unwrap().identifier;
        let data = eap::build_success(1, "S=0000000000000000000000000000000000000000");
        let early = responder_eap(&responder, &eap::EapPacket { code: eap::code::REQUEST, identifier: id, data });
        let got = initiator.handle(&early, &mut SeedEntropy::new(1));
        assert!(matches!(got, Ok(EapEvent::Failed(None))), "Success Request before the Challenge: {got:?}");
    }

    #[test]
    fn eap_takes_eap_success_only_as_a_bare_reply_to_its_last_response() {
        // RFC 3748 §4.2: EAP-Success carries the Identifier of the Response
        // it answers, and no data -- its Length is 4.
        let (initiator, responder, msg, last) = run_until(Step::EapSuccess);
        let ours = eap_from_initiator(&responder, &last).unwrap().identifier;
        assert_eq!(eap_from_responder(&initiator, &msg).unwrap().identifier, ours);
        assert_eq!(finish(initiator, responder, &msg), Outcome::Established);

        type Forgery = (&'static str, fn(u8) -> u8, Vec<u8>);
        let bad: [Forgery; 3] = [
            ("Identifier + 1", |id| id.wrapping_add(1), vec![]),
            ("Identifier ^ 0x80", |id| id ^ 0x80, vec![]),
            ("data within its Length", |id| id, vec![0, 0, 0, 0]),
        ];
        for (what, identifier, data) in bad {
            let (mut initiator, responder, _, last) = run_until(Step::EapSuccess);
            let identifier = identifier(eap_from_initiator(&responder, &last).unwrap().identifier);
            let forged = responder_eap(&responder, &eap::EapPacket { code: eap::code::SUCCESS, identifier, data });
            let got = initiator.handle(&forged, &mut SeedEntropy::new(1));
            assert!(matches!(got, Ok(EapEvent::Failed(None))), "{what}: {got:?}");
        }

        // Octets past its Length are padding, and MUST be ignored (§4).
        let (initiator, responder, msg, _) = run_until(Step::EapSuccess);
        let mut padded = eap_from_responder(&initiator, &msg).unwrap().to_bytes();
        padded.extend_from_slice(&[0xAA, 0xBB]);
        let padded = build_sk(&responder.sa, 9, true, &[(PayloadType::Eap, padded)], &[6u8; 8]).unwrap();
        assert_eq!(finish(initiator, responder, &padded), Outcome::Established);
    }

    /// A named change to an EAP packet.
    type EapEdit = (&'static str, fn(&mut eap::EapPacket));

    /// `msg`'s EAP packet as the responder's side would send it after `f`.
    fn with_responder_eap(initiator: &EapInitiator, responder: &EapResponder, msg: &[u8], f: impl FnOnce(&mut eap::EapPacket)) -> Vec<u8> {
        let mut p = eap_from_responder(initiator, msg).unwrap();
        f(&mut p);
        responder_eap(responder, &p)
    }

    #[test]
    fn eap_takes_mschapv2_requests_only_with_a_consistent_header() {
        // draft-kamath-pppext-eap-mschapv2-02 §2.1: MS-Length is the EAP
        // Length minus 5 and a Challenge's Value-Size is 16.
        let bad_challenges: [EapEdit; 4] = [
            ("Value-Size 0", |p| p.data[5] = 0),
            ("Value-Size 17", |p| p.data[5] = 17),
            ("MS-Length 4", |p| p.data[3..5].copy_from_slice(&4u16.to_be_bytes())),
            ("MS-Length 65535", |p| p.data[3..5].copy_from_slice(&u16::MAX.to_be_bytes())),
        ];
        for (what, f) in bad_challenges {
            let (mut initiator, responder, msg, _) = run_until(Step::Challenge);
            let forged = with_responder_eap(&initiator, &responder, &msg, f);
            let got = initiator.handle(&forged, &mut SeedEntropy::new(1));
            assert!(!matches!(got, Ok(EapEvent::Reply(_))), "Challenge {what}: {got:?}");
        }

        // The Success Request: MS-Length as above, and the MS-CHAPv2-ID of
        // the Response it answers (RFC 2759 §5 keeps the CHAP Success
        // format, whose Identifier is copied from that Response -- RFC
        // 1994 §4.2).
        let bad_successes: [EapEdit; 4] = [
            ("MS-CHAPv2-ID ^ 0x80", |p| p.data[2] ^= 0x80),
            ("MS-CHAPv2-ID + 1", |p| p.data[2] = p.data[2].wrapping_add(1)),
            ("MS-Length 4", |p| p.data[3..5].copy_from_slice(&4u16.to_be_bytes())),
            ("MS-Length 65535", |p| p.data[3..5].copy_from_slice(&u16::MAX.to_be_bytes())),
        ];
        for (what, f) in bad_successes {
            let (mut initiator, responder, msg, _) = run_until(Step::SuccessRequest);
            let forged = with_responder_eap(&initiator, &responder, &msg, f);
            let got = initiator.handle(&forged, &mut SeedEntropy::new(1));
            assert!(matches!(got, Ok(EapEvent::Failed(None))), "Success Request {what}: {got:?}");
        }

        // The untouched ones go through.
        let (initiator, responder, msg, _) = run_until(Step::Challenge);
        let same = with_responder_eap(&initiator, &responder, &msg, |_| {});
        assert_eq!(finish(initiator, responder, &same), Outcome::Established);
        let (initiator, responder, msg, _) = run_until(Step::SuccessRequest);
        let same = with_responder_eap(&initiator, &responder, &msg, |_| {});
        assert_eq!(finish(initiator, responder, &same), Outcome::Established);
    }

    #[test]
    fn eap_responder_takes_the_mschapv2_response_only_with_a_consistent_header() {
        // draft-kamath-pppext-eap-mschapv2-02 §2.2: MS-Length is the EAP
        // Length minus 5 and a Response's Value-Size is 49.
        let bad: [EapEdit; 5] = [
            ("Value-Size 0", |p| p.data[5] = 0),
            ("Value-Size 48", |p| p.data[5] = 48),
            ("Value-Size 50", |p| p.data[5] = 50),
            ("MS-Length 4", |p| p.data[3..5].copy_from_slice(&4u16.to_be_bytes())),
            ("MS-Length + 1", |p| {
                let ms_len = u16::from_be_bytes([p.data[3], p.data[4]]) + 1;
                p.data[3..5].copy_from_slice(&ms_len.to_be_bytes());
            }),
        ];
        for (what, f) in bad {
            let (mut initiator, mut responder, challenge, _) = run_until(Step::Challenge);
            let EapEvent::Reply(answer) = initiator.handle(&challenge, &mut SeedEntropy::new(1)).unwrap() else { panic!() };
            let forged = with_initiator_eap(&initiator, &responder, &answer, f);
            let got = responder.handle(&forged, &mut SeedEntropy::new(2));
            assert!(!matches!(got, Ok(EapEvent::Reply(_))), "Response {what}: {got:?}");
        }
        // The untouched one goes through.
        let (mut initiator, mut responder, challenge, _) = run_until(Step::Challenge);
        let EapEvent::Reply(answer) = initiator.handle(&challenge, &mut SeedEntropy::new(1)).unwrap() else { panic!() };
        let same = with_initiator_eap(&initiator, &responder, &answer, |_| {});
        assert!(matches!(responder.handle(&same, &mut SeedEntropy::new(2)), Ok(EapEvent::Reply(_))));
    }

    #[test]
    fn eap_takes_no_more_eap_once_its_auth_went_out() {
        // After EAP-Success the method is over and our MSK-keyed AUTH is
        // out: only the final message answers it (RFC 7296 §2.16) -- not
        // EAP-Success again, nor a duplicate of the Request we answered
        // last, nor a new Request.
        for case in 0..3 {
            let (mut initiator, mut responder, success_request, _) = run_until(Step::SuccessRequest);
            let EapEvent::Reply(ack) = initiator.handle(&success_request, &mut SeedEntropy::new(1)).unwrap() else { panic!() };
            let EapEvent::Reply(eap_success) = responder.handle(&ack, &mut SeedEntropy::new(2)).unwrap() else { panic!() };
            assert!(matches!(initiator.handle(&eap_success, &mut SeedEntropy::new(1)), Ok(EapEvent::Reply(_))));
            let late = match case {
                0 => eap_success,
                1 => success_request,
                _ => {
                    let id = eap_from_responder(&initiator, &eap_success).unwrap().identifier.wrapping_add(1);
                    responder_eap(&responder, &eap::EapPacket { code: eap::code::REQUEST, identifier: id, data: vec![eap::eap_type::IDENTITY] })
                }
            };
            let got = initiator.handle(&late, &mut SeedEntropy::new(1));
            assert!(matches!(got, Ok(EapEvent::Failed(None))), "case {case}: {got:?}");
        }
    }

    #[test]
    fn eap_takes_the_final_message_only_after_eap_success() {
        // The final AUTH is keyed by the MSK the finished method gives
        // (RFC 7296 §2.16); before EAP-Success came, nothing has.
        for stop in [Step::Challenge, Step::SuccessRequest, Step::EapSuccess] {
            let (mut initiator, responder, _, _) = run_until(stop);
            let early = final_message_now(&initiator, &responder);
            let got = initiator.handle(&early, &mut SeedEntropy::new(1));
            assert!(matches!(got, Ok(EapEvent::Failed(None))), "at {stop:?}: {got:?}");
        }
        // Positive control: the same message after our AUTH went out.
        let (initiator, responder, msg, _) = run_until(Step::EapSuccess);
        assert_eq!(finish(initiator, responder, &msg), Outcome::Established);
    }

    #[test]
    fn eap_refuses_another_request_once_the_method_began() {
        // RFC 3748 §2.1: once the peer answered the method, a Request of
        // another Type is invalid; so is a second Challenge.
        let requests = [
            vec![eap::eap_type::IDENTITY],
            vec![4, 16, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55],
            eap::build_challenge(7, &[0x33; 16], b"again"),
        ];
        for data in requests {
            let (mut initiator, responder, msg, _) = run_until(Step::SuccessRequest);
            let id = eap_from_responder(&initiator, &msg).unwrap().identifier;
            let other = responder_eap(&responder, &eap::EapPacket { code: eap::code::REQUEST, identifier: id, data: data.clone() });
            let got = initiator.handle(&other, &mut SeedEntropy::new(1));
            assert!(matches!(got, Ok(EapEvent::Failed(None))), "{data:?}: {got:?}");
        }
    }

    #[test]
    fn eap_naks_a_method_it_does_not_run_and_goes_on() {
        // RFC 3748 §5.3.1: a Request for a Type the peer won't run gets a
        // Legacy Nak naming the one it does, and the authenticator may try
        // that one next.
        for method in [4u8, 13, 254] {
            let (mut initiator, responder, challenge, _) = run_until(Step::Challenge);
            let other = responder_eap(&responder, &eap::EapPacket { code: eap::code::REQUEST, identifier: 0x42, data: vec![method, 1, 2, 3] });
            let nak = match initiator.handle(&other, &mut SeedEntropy::new(1)).unwrap() {
                EapEvent::Reply(m) => eap_from_initiator(&responder, &m).unwrap(),
                other => panic!("type {method}: {other:?}"),
            };
            assert_eq!(nak, eap::EapPacket { code: eap::code::RESPONSE, identifier: 0x42, data: vec![eap::eap_type::NAK, eap::eap_type::MSCHAPV2] });
            assert_eq!(finish(initiator, responder, &challenge), Outcome::Established, "type {method}");
        }
    }

    #[test]
    fn eap_answers_a_notification_and_goes_on() {
        // RFC 3748 §5.2: the peer MUST answer a Notification with an empty
        // Notification Response; it changes nothing else.
        for stop in [Step::Challenge, Step::SuccessRequest] {
            let (mut initiator, responder, next, _) = run_until(stop);
            let note = responder_eap(
                &responder,
                &eap::EapPacket { code: eap::code::REQUEST, identifier: 0x51, data: [&[2u8][..], b"maintenance at 22:00"].concat() },
            );
            let answer = match initiator.handle(&note, &mut SeedEntropy::new(1)).unwrap() {
                EapEvent::Reply(m) => eap_from_initiator(&responder, &m).unwrap(),
                other => panic!("at {stop:?}: {other:?}"),
            };
            assert_eq!(answer, eap::EapPacket { code: eap::code::RESPONSE, identifier: 0x51, data: vec![2] });
            assert_eq!(finish(initiator, responder, &next), Outcome::Established, "at {stop:?}");
        }
    }

    #[test]
    fn eap_answers_a_duplicate_request_with_its_first_response() {
        // RFC 3748 §4.1: a duplicate Request gets the original Response,
        // and is not processed again -- a second peer challenge would make
        // the first NT-Response, the one the server holds, a stranger.
        let (mut initiator, responder, challenge, _) = run_until(Step::Challenge);
        let first = match initiator.handle(&challenge, &mut SeedEntropy::new(1)).unwrap() {
            EapEvent::Reply(m) => eap_from_initiator(&responder, &m).unwrap(),
            other => panic!("{other:?}"),
        };
        let nt = initiator.nt_response;
        let again = match initiator.handle(&challenge, &mut SeedEntropy::new(99)).unwrap() {
            EapEvent::Reply(m) => eap_from_initiator(&responder, &m).unwrap(),
            other => panic!("{other:?}"),
        };
        assert_eq!(again, first);
        assert_eq!(initiator.nt_response, nt);

        // The same Identifier on a Request that isn't the same is no
        // duplicate: it is invalid.
        let (mut initiator, responder, challenge, _) = run_until(Step::Challenge);
        let p = eap_from_responder(&initiator, &challenge).unwrap();
        assert!(matches!(initiator.handle(&challenge, &mut SeedEntropy::new(1)), Ok(EapEvent::Reply(_))));
        let other = responder_eap(&responder, &eap::EapPacket { data: eap::build_challenge(1, &[0x77; 16], b"ryke"), ..p });
        assert!(matches!(initiator.handle(&other, &mut SeedEntropy::new(1)), Ok(EapEvent::Failed(None))));
    }

    #[test]
    fn eap_refuses_eap_packets_a_peer_never_receives() {
        for code in [eap::code::RESPONSE, 5] {
            let (mut initiator, responder, msg, _) = run_until(Step::Challenge);
            let p = eap_from_responder(&initiator, &msg).unwrap();
            let odd = responder_eap(&responder, &eap::EapPacket { code, ..p });
            let got = initiator.handle(&odd, &mut SeedEntropy::new(1));
            assert!(matches!(got, Ok(EapEvent::Failed(None))), "code {code}: {got:?}");
        }
    }

    /// An AUTH over the initiator's signed octets keyed by the MSK that an
    /// empty password and an all-zero NT-Response give -- which anyone can
    /// compute.
    fn auth_anyone_can_compute(initiator: &EapInitiator, idi: &[u8]) -> Authentication {
        let algo = initiator.sa.suite.prf_algorithm();
        let msk = mschapv2::derive_msk("", &[0u8; 24]);
        let octets = initiator_signed_octets(algo, &initiator.sa.init_message, &initiator.sa.nr, &initiator.sa.keys.sk_pi, idi);
        Authentication { method: auth_method::SHARED_KEY, data: psk_auth(algo, &msk, &octets) }
    }

    #[test]
    fn eap_responder_takes_no_final_auth_before_eap_succeeded() {
        // Straight after the Identity request.
        let (initiator, mut responder) = psk_pair();
        let msg1 = initiator.start(&mut SeedEntropy::new(1)).unwrap();
        assert!(matches!(responder.handle(&msg1, &mut SeedEntropy::new(2)), Ok(EapEvent::Reply(_))));
        let auth = auth_anyone_can_compute(&initiator, &initiator.id.to_bytes());
        let got = responder.handle(&initiator_msg(&initiator, &[(PayloadType::Authentication, auth.to_bytes())]), &mut SeedEntropy::new(2));
        assert!(matches!(got, Ok(EapEvent::Failed(None))), "{got:?}");

        // In the first message, over an empty IDi.
        let (initiator, mut responder) = psk_pair();
        let auth = auth_anyone_can_compute(&initiator, &[]);
        let msg1 = initiator_msg(
            &initiator,
            &[
                (PayloadType::IdInitiator, initiator.id.to_bytes()),
                (PayloadType::Authentication, auth.to_bytes()),
                (PayloadType::SecurityAssociation, esp_offer(0x1111).to_bytes()),
                (PayloadType::TrafficSelectorInitiator, full_tunnel_ts()),
                (PayloadType::TrafficSelectorResponder, full_tunnel_ts()),
            ],
        );
        let got = responder.handle(&msg1, &mut SeedEntropy::new(2));
        assert!(matches!(got, Ok(EapEvent::Failed(None))), "{got:?}");

        // After the Challenge, with the MSCHAPv2 answer skipped.
        let (initiator, mut responder, _, _) = run_until(Step::Challenge);
        let auth = auth_anyone_can_compute(&initiator, &initiator.id.to_bytes());
        let got = responder.handle(&initiator_msg(&initiator, &[(PayloadType::Authentication, auth.to_bytes())]), &mut SeedEntropy::new(2));
        assert!(matches!(got, Ok(EapEvent::Failed(None))), "{got:?}");
    }

    #[test]
    fn eap_responder_needs_the_identity_before_the_challenge_answer() {
        // An MSCHAPv2 Response in place of the Identity one would be checked
        // against no user's password and a challenge never sent.
        let (initiator, mut responder) = psk_pair();
        let msg1 = initiator.start(&mut SeedEntropy::new(1)).unwrap();
        assert!(matches!(responder.handle(&msg1, &mut SeedEntropy::new(2)), Ok(EapEvent::Reply(_))));
        let data = eap::build_response(1, &[0u8; 16], &[0x44; 16], b"", "");
        let resp = eap::EapPacket { code: eap::code::RESPONSE, identifier: 1, data };
        let got = responder.handle(&initiator_msg(&initiator, &[(PayloadType::Eap, resp.to_bytes())]), &mut SeedEntropy::new(2));
        assert!(matches!(got, Ok(EapEvent::Failed(None))), "{got:?}");
    }

    /// `msg` from the initiator with its EAP packet changed by `f`.
    fn with_initiator_eap(initiator: &EapInitiator, responder: &EapResponder, msg: &[u8], f: impl FnOnce(&mut eap::EapPacket)) -> Vec<u8> {
        let mut p = eap_from_initiator(responder, msg).unwrap();
        f(&mut p);
        initiator_msg(initiator, &[(PayloadType::Eap, p.to_bytes())])
    }

    #[test]
    fn eap_responder_discards_answers_to_requests_it_did_not_send() {
        // RFC 3748 §4.1: a Response whose Identifier is not the outstanding
        // Request's MUST be discarded.
        let (mut initiator, mut responder) = psk_pair();
        let msg1 = initiator.start(&mut SeedEntropy::new(1)).unwrap();
        let EapEvent::Reply(identity) = responder.handle(&msg1, &mut SeedEntropy::new(2)).unwrap() else { panic!() };
        let EapEvent::Reply(answer) = initiator.handle(&identity, &mut SeedEntropy::new(1)).unwrap() else { panic!() };
        let wrong = with_initiator_eap(&initiator, &responder, &answer, |p| p.identifier ^= 0x80);
        let got = responder.handle(&wrong, &mut SeedEntropy::new(2));
        assert!(matches!(got, Ok(EapEvent::Failed(None))), "EAP Identifier: {got:?}");
        // That ended the exchange: the right answer finds nothing to go on.
        let got = responder.handle(&answer, &mut SeedEntropy::new(2));
        assert!(matches!(got, Ok(EapEvent::Failed(None))), "after a failure: {got:?}");

        // Only a Response answers a Request.
        let (mut initiator, mut responder) = psk_pair();
        let msg1 = initiator.start(&mut SeedEntropy::new(1)).unwrap();
        let EapEvent::Reply(identity) = responder.handle(&msg1, &mut SeedEntropy::new(2)).unwrap() else { panic!() };
        let EapEvent::Reply(answer) = initiator.handle(&identity, &mut SeedEntropy::new(1)).unwrap() else { panic!() };
        let wrong = with_initiator_eap(&initiator, &responder, &answer, |p| p.code = eap::code::REQUEST);
        let got = responder.handle(&wrong, &mut SeedEntropy::new(2));
        assert!(matches!(got, Ok(EapEvent::Failed(None))), "EAP Request: {got:?}");

        // The MSCHAPv2 Response must answer our Challenge's MS-CHAPv2-ID.
        let (mut initiator, mut responder, challenge, _) = run_until(Step::Challenge);
        let EapEvent::Reply(answer) = initiator.handle(&challenge, &mut SeedEntropy::new(1)).unwrap() else { panic!() };
        let wrong = with_initiator_eap(&initiator, &responder, &answer, |p| p.data[2] ^= 0x80);
        let got = responder.handle(&wrong, &mut SeedEntropy::new(2));
        assert!(matches!(got, Ok(EapEvent::Failed(None))), "MS-CHAPv2-ID: {got:?}");

        // A Success-Response while our Challenge is outstanding.
        let (initiator, mut responder, challenge, _) = run_until(Step::Challenge);
        let id = eap_from_responder(&initiator, &challenge).unwrap().identifier;
        let early = eap::EapPacket { code: eap::code::RESPONSE, identifier: id, data: vec![eap::eap_type::MSCHAPV2, eap::op::SUCCESS] };
        let got = responder.handle(&initiator_msg(&initiator, &[(PayloadType::Eap, early.to_bytes())]), &mut SeedEntropy::new(2));
        assert!(matches!(got, Ok(EapEvent::Failed(None))), "early Success-Response: {got:?}");

        // An Identity Response while our Challenge is outstanding.
        let (initiator, mut responder, challenge, _) = run_until(Step::Challenge);
        let id = eap_from_responder(&initiator, &challenge).unwrap().identifier;
        let late = eap::EapPacket { code: eap::code::RESPONSE, identifier: id, data: [&[eap::eap_type::IDENTITY][..], b"alice"].concat() };
        let got = responder.handle(&initiator_msg(&initiator, &[(PayloadType::Eap, late.to_bytes())]), &mut SeedEntropy::new(2));
        assert!(matches!(got, Ok(EapEvent::Failed(None))), "late Identity: {got:?}");
    }

    #[test]
    fn eap_responder_takes_each_step_once_and_alone() {
        // The first request once: a second would swap the IDi the final
        // AUTH is checked over, and the CHILD SA's SPI, mid-exchange.
        let (initiator, mut responder) = psk_pair();
        let msg1 = initiator.start(&mut SeedEntropy::new(1)).unwrap();
        assert!(matches!(responder.handle(&msg1, &mut SeedEntropy::new(2)), Ok(EapEvent::Reply(_))));
        let got = responder.handle(&msg1, &mut SeedEntropy::new(2));
        assert!(matches!(got, Ok(EapEvent::Failed(None))), "a second first request: {got:?}");

        // No AUTH rides with an EAP answer: while EAP runs there is no MSK.
        let (mut initiator, mut responder) = psk_pair();
        let msg1 = initiator.start(&mut SeedEntropy::new(1)).unwrap();
        let EapEvent::Reply(identity) = responder.handle(&msg1, &mut SeedEntropy::new(2)).unwrap() else { panic!() };
        let EapEvent::Reply(answer) = initiator.handle(&identity, &mut SeedEntropy::new(1)).unwrap() else { panic!() };
        let p = eap_from_initiator(&responder, &answer).unwrap();
        let auth = auth_anyone_can_compute(&initiator, &initiator.id.to_bytes());
        let both = initiator_msg(&initiator, &[(PayloadType::Authentication, auth.to_bytes()), (PayloadType::Eap, p.to_bytes())]);
        let got = responder.handle(&both, &mut SeedEntropy::new(2));
        assert!(matches!(got, Ok(EapEvent::Failed(None))), "AUTH with the Identity answer: {got:?}");
    }

    #[test]
    fn eap_responder_wants_the_final_auth_as_a_shared_key_mic() {
        // RFC 7296 §2.16: the MSK-keyed AUTH is a Shared Key Message
        // Integrity Code, method 2.
        let (mut initiator, mut responder, eap_success, _) = run_until(Step::EapSuccess);
        let EapEvent::Reply(auth_msg) = initiator.handle(&eap_success, &mut SeedEntropy::new(1)).unwrap() else { panic!() };
        let (_, ps) = decrypt(&responder.sa, &auth_msg).unwrap();
        let mut auth = Authentication::parse(find(&ps, PayloadType::Authentication).unwrap()).unwrap();
        auth.method = auth_method::RSA_SIG;
        let got = responder.handle(&initiator_msg(&initiator, &[(PayloadType::Authentication, auth.to_bytes())]), &mut SeedEntropy::new(2));
        assert!(matches!(got, Ok(EapEvent::Failed(None))), "{got:?}");
    }

    #[test]
    fn eap_responder_answers_the_real_exchange_step_by_step() {
        // Positive control: the requests the responder sends, in order, with
        // the EAP Identifiers moving on and the Success carrying the last
        // Response's.
        let (mut initiator, mut responder) = psk_pair();
        let mut ie = SeedEntropy::new(1);
        let mut re = SeedEntropy::new(2);
        let mut in_flight = initiator.start(&mut ie).unwrap();
        let mut seen = Vec::new();
        loop {
            match responder.handle(&in_flight, &mut re).unwrap() {
                EapEvent::Reply(m) => {
                    let answered = eap_from_initiator(&responder, &in_flight).map(|p| p.identifier);
                    let p = eap_from_responder(&initiator, &m);
                    seen.push((step_of(&initiator, &m), p.map(|p| p.identifier), answered));
                    let EapEvent::Reply(next) = initiator.handle(&m, &mut ie).unwrap() else { panic!() };
                    in_flight = next;
                }
                EapEvent::Established(Some(f)) => {
                    assert!(matches!(initiator.handle(&f, &mut ie).unwrap(), EapEvent::Established(None)));
                    break;
                }
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(
            seen,
            vec![
                (Step::Identity, Some(1), None),
                (Step::Challenge, Some(2), Some(1)),
                (Step::SuccessRequest, Some(3), Some(2)),
                (Step::EapSuccess, Some(3), Some(3)),
            ]
        );
    }
}
