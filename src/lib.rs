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
//! Both retransmit their requests: the handshake's, and after it every
//! request of the IKEv2 session's own and each IKEv1 Quick Mode. IKEv1's
//! liveness check, [`ikev1::informational::probe`], sends one R-U-THERE per
//! call: repeating it, with a new sequence number (RFC 3706), is the
//! caller's. Neither runs in the background: the peer's requests are
//! answered only while the caller is inside one of these calls.
//!
//! IKEv1's retransmissions are the same bytes each time, and the waits
//! between them grow (RFC 2408 §5.1: "MUST NOT use a fixed timer"): for a
//! read timeout `T`, a request goes out at 0, 3T/7 and 9T/7 (waits of 3T/7,
//! 6T/7 and 12T/7, 1 : 2 : 4) and is given up on at 3T, which is what a
//! silent gateway was already waited for. That is the schedule until a round
//! trip has been measured; §5.1 also asks for timers "adjusted dynamically
//! based on measured round trip times", and once the ISAKMP SA has one -- from
//! its Phase 1 messages and its Quick Modes, not from XAUTH or Mode-Config,
//! whose replies wait on a backend -- a request that gets no answer is sent
//! again after that round trip's RFC 6298 timer (never under a second, never
//! after more than the 3T/7 above), each wait twice the one before, with up to
//! seven resends inside the same 3T. Only a reply to a request sent once is
//! measured (Karn's rule). The messages that nothing answers -- Aggressive Mode's third, the XAUTH ACK,
//! Quick Mode's third -- are kept, and sent again untouched when the gateway
//! repeats the message before them (RFC 2408 §3.1, Commit Bit NOTE; RFC 2409
//! §5: no IV or state moves for a retransmission), and a gateway's repeat of
//! a message the handshake already took is never read as the next one. An
//! Aggressive Mode third message lost after NAT-T floated is recovered too,
//! within [`ikev1::Client::connect`]: the gateway that never saw it has not
//! floated and repeats its second message to port 500 (RFC 3947 §5.3), so
//! while the handshake waits on the floated port it also looks at port 500
//! every 100 ms, at most eight datagrams at a look, and answers that repeat
//! with the third message again, floated. That last-message recovery has
//! limits: it recognises only a repeat identical to what the gateway sent
//! first (one that is re-encrypted is not recognised) and keeps only the
//! last eight such pairs; the look at port 500 is the handshake's own, so
//! nothing looks there once `connect` has returned; and Quick Mode's third,
//! sent by `connect` or a rekey, is sent again only when the caller next
//! reads the socket ([`ikev1::informational::peek`],
//! [`ikev1::informational::probe`], the next rekey), not in the background --
//! until then a gateway whose Quick Mode second message was answered by
//! nothing has no Quick Mode SA, and nothing here notices. What that
//! recovery is worth is therefore how soon the caller reads: it is not a
//! promise of service between the reads. Not done in IKEv1: a Quick Mode or
//! a Phase 1 the gateway starts goes unanswered (the client is an initiator
//! only; answering one would be a Quick Mode responder driven from the
//! caller's loop, which nothing here does yet); the ISAKMP SA is never
//! rekeyed -- once its lifetime is up, a new `connect` is the way on; and a
//! lifetime in kilobytes is refused in Phase 1, and in Phase 2 handed to the
//! caller ([`ikev1::quick::SaLifetime`], `Established::p2_lifetime_kilobytes`)
//! to count -- this crate carries no data plane, so it counts none itself.
//!
//! IKEv2 fragmentation (RFC 7383), which every `IKE_SA_INIT` advertises:
//! [`Ikev2Session`] and [`LivenessSession`] reassemble each fragmented
//! message the peer sends -- the answers to their requests, in the
//! handshake and after it, and the peer's own requests -- and every
//! fragment is authenticated before it is kept. What they send, requests
//! and answers alike, goes out whole: a large `IKE_AUTH` request (one
//! carrying a certificate chain, say) is left to IP fragmentation, and
//! there is no path MTU discovery.
//!
//! ### Bundled servers
//!
//! [`ikev2::server::Server`] and [`ikev1::server::Server`] are minimal
//! responders for tests and examples, not gateways: a PSK or certificates
//! (in IKEv1, Main Mode only), one CHILD SA at a time, no EAP or XAUTH, no
//! NAT-T, and never an exchange of their own. Their module docs list what
//! they do. The IKEv2 one reassembles a request that comes in fragments and
//! answers it in fragments no larger than the request's.
//!
//! [`ikev2::client::Client`] is the matching minimal IKEv2 initiator: the
//! handshake, nothing after it. It reassembles a fragmented `IKE_AUTH`
//! response, but sends each request once, with no retransmission.
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
//!   [`ikev2::sign::verify_cert_auth`] builds the path to a trusted CA
//!   (unless the certificate is pinned), checks the extensions of each
//!   certificate in it (RFC 5280 §4.2), and checks that the leaf's KeyUsage
//!   allows signing (RFC 4945 §5.1.3.2). A critical extension it does not
//!   process rejects the certificate. It does not check revocation (CRL,
//!   OCSP), ExtendedKeyUsage or certificate policies, and it ties the
//!   peer's ID to the certificate only through the DNS name it is given, if
//!   any. Any of those checks a deployment needs is the consumer's.
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
pub use ikev1::quick::{ChildKeyMaterial, RekeyedChild, SaLifetime};
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
