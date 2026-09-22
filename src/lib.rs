//! # ryke
//!
//! A **clean-room** IKEv2 / IKE implementation in Rust — `ryke` = **R**ust + **IKE**.
//!
//! It covers IKEv2 (RFC 7296) and IKEv1 (RFC 2409), with code for both sides
//! of the exchanges: [`Role::Initiator`] starts them, [`Role::Responder`]
//! answers them. The protocol is built from the RFCs; it does not wrap
//! OpenSSL or any existing IKE/IPsec daemon, and copies no third-party code.
//!
//! ## What each part guarantees
//!
//! ryke comes in layers, and what holds for one says nothing about another:
//! an RFC requirement a building block meets is met by a session only where
//! the session puts it to use, and neither says anything about the bundled
//! servers.
//!
//! ### Building blocks
//!
//! The per-exchange modules -- [`ikev2::exchange`], [`ikev2::ike_auth`],
//! [`ikev2::eap_auth`], [`ikev2::rekey`], [`ikev2::ike_rekey`],
//! [`ikev2::informational`], [`ikev2::mobike`], [`ikev2::fragment`],
//! [`ikev1::phase1`], [`ikev1::xauth`], [`ikev1::cfg`], [`ikev1::quick`] and
//! [`ikev1::informational`] -- parse, check and build the messages of one
//! exchange. What they know of it is what the caller hands back in: the SA's
//! keys, or a value that carries one exchange from step to step (a Main-Mode
//! responder state, an [`EapResponder`]). Message IDs and the request
//! window, answering a retransmitted request with the same response,
//! retransmitting one's own requests, timers and lifetimes, simultaneous
//! exchanges, and which exchange may come when are up to whoever puts them
//! together.
//!
//! ### Initiator sessions
//!
//! The client side, as a VPN client uses it:
//!
//! - IKEv2: [`Ikev2Session`] connects (IKE_SA_INIT with NAT-T, IKE_AUTH with a
//!   PSK, a certificate or EAP-MSCHAPv2, the first CHILD SA) and yields a
//!   [`LivenessSession`], which runs the IKE SA from then on: Message IDs,
//!   liveness checks, rekeys of the IKE SA and of the CHILD SAs (IPv4 and a
//!   separate IPv6 one), Deletes, and simultaneous rekeys (RFC 7296 §2.8.1,
//!   §2.8.2). It answers the peer's requests too -- liveness checks, Deletes
//!   and rekeys -- repeats its answer to a retransmitted INFORMATIONAL or
//!   CHILD SA rekey request, and refuses a new CHILD SA with
//!   `NO_ADDITIONAL_SAS`.
//! - IKEv1: [`ikev1::Client`] connects (Main Mode with a PSK or an RSA
//!   signature, or Aggressive Mode with a PSK; XAUTH and Mode-Config when
//!   asked for; Quick Mode) and yields an [`ikev1::Established`]. No session
//!   object follows: the caller keeps the Phase-1 state and calls
//!   [`ikev1::informational::peek`] and [`ikev1::informational::probe`]
//!   (which answer the peer's R-U-THERE and report its Deletes),
//!   [`ikev1::quick::rekey_child`] and its IPv6 counterparts, and
//!   [`ikev1::Established::close_message`].
//!
//! Both retransmit their handshake requests, and the IKEv2 session every
//! request of its own after that too. Neither runs in the background: the
//! peer's requests are answered only while the caller is inside one of
//! these calls. Not done in IKEv1: a Quick Mode of its own after `connect`
//! (a rekey, the IPv6 CHILD SA) is sent once, never retransmitted; a Quick
//! Mode or a Phase 1 the gateway starts goes unanswered; and the ISAKMP SA
//! is never rekeyed -- once its lifetime is up, a new `connect` is the way
//! on.
//!
//! ### Bundled servers
//!
//! [`ikev2::server::Server`] and [`ikev1::server::Server`] are minimal
//! responders for tests and examples, not gateways: a PSK or certificates
//! (in IKEv1, Main Mode only), one CHILD SA at a time, no EAP or XAUTH, no
//! NAT-T, and never an exchange of their own. Their module docs list what
//! they do.
//!
//! [`ikev2::client::Client`] is the matching minimal IKEv2 initiator: the
//! handshake, nothing after it.
//!
//! ### What the consumer supplies
//!
//! - **The data plane.** The sessions hand out each CHILD SA's SPIs and keys
//!   ([`ConnectedTunnel`], [`RekeyedChild`], [`ChildSa`]). Installing them
//!   (in the kernel's XFRM, or in ryke's userspace ESP: [`Tunnel`],
//!   [`EspSa`]), swapping them at every rekey, and capturing the traffic to
//!   carry (a TUN device or anything else) are the consumer's.
//! - **The host's configuration.** The addresses, DNS servers and split
//!   routes the gateway assigns come back as data; applying them is the
//!   consumer's.
//! - **The schedule.** When to check liveness, when to rekey (from the
//!   negotiated lifetimes and [`LivenessSession::ike_sa_age`], or at once
//!   when [`LivenessSession::message_ids_exhausted`]), how many
//!   missed checks mean the peer is gone, when to reconnect, and whether to
//!   bring back a CHILD SA the peer deleted
//!   ([`LivenessSession::take_peer_deleted_children`]).
//! - **Credentials and trust.** Pre-shared keys, certificates and private
//!   keys, EAP credentials, the trusted CAs, the name the gateway's
//!   certificate must carry, and the time its validity is checked against.
//! - **Sockets and randomness.** The UDP sockets, if the caller binds them
//!   itself (both 500 and 4500 for NAT-T), and an [`Entropy`] source where
//!   one is asked for ([`OsEntropy`] outside tests).
//!
//! `docs/implementation-plan.md` is the original roadmap, older than most of
//! the above.

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
    default_esp_offer, default_ike_offer, ike_port, ChildKind, ConnectedTunnel, EapCreds, Ikev2Session,
    Ipv6Child, Liveness, LivenessSession, PeerRekeyedChild,
};
pub use ikev2::rekey::responder_process_rekey;
pub use ikev2::ike_rekey::{is_ike_sa_rekey, responder_process_ike_rekey};
pub use ikev2::ike_auth::{
    client_sent_certreq, esp_offer, initiator_auth_request, initiator_eap_request,
    initiator_verify_auth, is_eap_request, peer_id_from_auth, peer_id_from_request,
    responder_process_auth, responder_process_auth_with_mobike, AssignedConfig, AuthConfig,
    ChildTsOffer, LocalAuth, PeerAuth,
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
