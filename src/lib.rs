//! # ryke
//!
//! A **clean-room** IKEv2 / IKE implementation in Rust — `ryke` = **R**ust + **IKE**.
//!
//! It implements **both sides independently**: a client ([`Role::Initiator`])
//! that starts exchanges and a server ([`Role::Responder`]) that answers them.
//! The protocol is built from the RFCs; it does not wrap OpenSSL or any existing
//! IKE/IPsec daemon, and copies no third-party code.
//!
//! ## Scope & architecture
//!
//! - **Control plane (this crate):** UDP 500/4500, message framing, exchange
//!   state machines, crypto + key schedule, and authentication (certificate and
//!   EAP-MSCHAPv2 for native iOS/Android clients on the server side).
//! - **Data plane:** a **userspace ESP** implementation in Rust (AES-GCM).
//!   `ryke` encrypts/decrypts the tunneled packets itself — it does not use the
//!   OS kernel's IPsec stack, and no external software is involved. The library
//!   moves packets you hand it (via [`Tunnel`], or the lower-level [`EspSa`] /
//!   [`ChildSa`]); capturing a machine's real traffic (e.g. a TUN device) is the
//!   consumer's job, deliberately out of scope.
//!
//! ## What works today
//!
//! - Message framing: header + generic payload chain (RFC 7296 §3.1–3.2).
//! - Payloads: Security Association (proposals/transforms), Key Exchange, Nonce.
//! - Crypto core for `IKE_SA_INIT`: X25519 (RFC 7748), HMAC-SHA256 PRF
//!   (RFC 4231), `prf+`, and the SKEYSEED / SK_* key schedule (§2.13–2.14).
//!
//! See `docs/implementation-plan.md` for the milestone roadmap.

// Shared crypto core (used by both IKEv1 and IKEv2).
pub mod crypto;
pub mod debug;
pub mod entropy;
pub mod error;
pub mod esp;
pub mod role;
pub mod transport;
pub mod tunnel;

// Protocol implementations.
pub mod ikev1;
pub mod ikev2;

#[cfg(test)]
pub(crate) mod test_certs;

/// The well-known NAT-T port (RFC 3947 §1 / RFC 3948 §1): once a NAT is
/// detected between peers, the whole exchange -- Phase 1, Quick Mode/CREATE_CHILD_SA,
/// and the ESP-in-UDP data plane -- floats here from port 500.
pub const fn natt_port() -> u16 {
    4500
}

pub use ikev2::client::Client;
pub use crypto::{
    derive_child_keys, derive_session_keys, prf, prf_plus, ChildKeys, DhGroup, IntegAlgorithm,
    KeyLengths, SessionKeys,
};
pub use ikev1::quick::{ChildKeyMaterial, RekeyedChild};
pub use ikev2::eap_auth::{EapEvent, EapFailureReason, EapInitiator, EapResponder, ServerAuth, ServerVerify};
pub use entropy::{Entropy, SeedEntropy};
pub use error::IkeError;
pub use esp::{ChildSa, EspSa};
pub use ikev2::exchange::{
    default_offer, ike_cookie, initiator_complete, initiator_complete_natt, initiator_request,
    initiator_request_natt, initiator_request_natt_with, responder_respond, responder_respond_natt, CompletedSaInit,
    CookiePolicy, LocalSecret, NatStatus, SaInitResult,
};
pub use ikev2::natt::{
    is_ike_on_4500, unwrap_ike_4500, wrap_ike_4500, NON_ESP_MARKER,
};
pub use ikev2::informational::{build_informational, dpd_request, open_informational};
pub use ikev2::session::{
    default_esp_offer, default_ike_offer, ike_port, ConnectedTunnel, EapCreds, Ikev2Session,
    Ipv6Child, Liveness, LivenessSession,
};
pub use ikev2::rekey::responder_process_rekey;
pub use ikev2::ike_rekey::{is_ike_sa_rekey, responder_process_ike_rekey};
pub use ikev2::ike_auth::{
    client_sent_certreq, esp_offer, initiator_auth_request, initiator_eap_request,
    initiator_verify_auth, is_eap_request, peer_id_from_auth, peer_id_from_request,
    responder_process_auth, AssignedConfig, AuthConfig, ChildTsOffer, LocalAuth, PeerAuth,
};
pub use ikev2::message::{
    payloads, ExchangeType, Flags, IkeHeader, MessageBuilder, PayloadIter, PayloadType, RawPayload,
};
pub use ikev2::negotiate::ChosenSuite;
pub use ikev2::auth::{initiator_signed_octets, psk_auth, responder_signed_octets};
pub use ikev2::payload::{
    cfg_type, config_attr, notify_type, Authentication, CertRequest, Certificate, ConfigAttr,
    Configuration, Delete, Identification, KeyExchange, Nonce, Notify, Proposal,
    SecurityAssociation, TrafficSelector, TrafficSelectors, Transform,
};
pub use ikev2::sign::{SigningKey, VerifyingKey};
pub use role::Role;
pub use ikev2::sk::{build_encrypted_gcm, open_encrypted_gcm, SkCipher};
pub use ikev2::server::{Server, ServerEvent};
pub use transport::{DriverError, UdpTransport};
pub use tunnel::Tunnel;

// `entropy::OsEntropy` itself is genuinely cross-platform (backed by the
// `getrandom` crate: BCryptGenRandom on Windows, getrandom(2)/-urandom on
// Linux) -- this re-export was mistakenly unix-gated even though nothing
// about it is unix-specific.
pub use entropy::OsEntropy;
