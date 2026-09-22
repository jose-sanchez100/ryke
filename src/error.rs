use thiserror::Error;

/// Errors from parsing or processing IKEv2 messages.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IkeError {
    // --- wire parsing ---
    /// The buffer ended before a fixed-size field could be read.
    #[error("truncated input: need {need} bytes, have {have}")]
    Truncated { need: usize, have: usize },

    /// A declared length pointed past the end of the buffer.
    #[error("declared length {declared} exceeds available {available} bytes")]
    BadLength { declared: usize, available: usize },

    /// A generic payload header declared a length smaller than the 4-byte header
    /// itself, which would loop forever.
    #[error("payload length {0} is smaller than the 4-byte generic header")]
    ShortPayload(u16),

    /// A payload of unrecognized type arrived with the critical bit set
    /// (RFC 7296 §2.5: "If the critical flag is set and the payload type is
    /// unrecognized, the message MUST be rejected").
    #[error("unrecognized payload type {0} with the critical bit set")]
    UnsupportedCriticalPayload(u8),

    /// The header's major version isn't one this crate speaks (RFC 7296
    /// §3.1: a responder MUST reject a higher major version with
    /// INVALID_MAJOR_VERSION; we reject any non-2 major version outright
    /// since IKEv1 messages have their own parser and shouldn't reach here).
    #[error("unsupported IKE major version {0}")]
    UnsupportedVersion(u8),

    // --- exchange processing ---
    /// A payload required for this exchange was absent.
    #[error("required {0} payload is missing")]
    MissingPayload(&'static str),

    /// None of the offered proposals used a suite we support.
    #[error("no supported proposal in the offered SA")]
    NoProposalChosen,

    /// The peer rejected the exchange via an error Notify (RFC 7296 §3.10.1,
    /// type < 16384) instead of continuing it -- e.g. NO_PROPOSAL_CHOSEN when
    /// our offer doesn't match its policy. Previously this surfaced as a
    /// confusing `MissingPayload("SA")` once the parser fell through looking
    /// for payloads that a rejection response never carries.
    #[error("peer rejected the exchange: {name} (notify type {notify_type})")]
    PeerRejected { notify_type: u16, name: &'static str },

    /// The peer's Key Exchange used a DH group other than the negotiated one.
    #[error("DH group mismatch: expected {expected}, got {got}")]
    DhGroupMismatch { expected: u16, got: u16 },

    /// The `IKE_SA_INIT` responder answered with a bare COOKIE notify (RFC
    /// 7296 §2.6, anti-DoS return-routability check): it kept no half-open
    /// state, so the initiator must resend the identical request with this
    /// cookie echoed back rather than treat the exchange as failed.
    #[error("the responder requires a return-routability cookie before committing state")]
    CookieRequired { cookie: Vec<u8> },

    /// The `IKE_SA_INIT` responder answered with a bare INVALID_KE_PAYLOAD
    /// notify (RFC 7296 §1.2/§2.7): our Key Exchange payload guessed a DH
    /// group the responder didn't select, and it kept no half-open state.
    /// The notify's data names the group the initiator must retry with.
    #[error("the responder wants Diffie-Hellman group {0} instead of our guess")]
    InvalidKeGroup(u16),

    /// The Key Exchange data length is wrong for its DH group.
    #[error("key exchange data for group {group} has wrong length {len}")]
    BadKeyExchange { group: u16, len: usize },

    /// AEAD (GCM) authentication of an SK payload failed — wrong key, wrong
    /// associated data, or tampering.
    #[error("SK payload authentication failed")]
    BadIntegrity,

    /// The peer's AUTH payload did not verify (wrong PSK or altered SA_INIT).
    #[error("peer authentication (AUTH payload) failed")]
    AuthFailed,

    /// EAP authentication was rejected for a definitive, stated reason
    /// (currently: an EAP-MSCHAPv2 Failure message with `E=691`,
    /// RFC 2759's `ERROR_AUTHENTICATION_FAILURE` — "these credentials are
    /// wrong", not a transient/protocol failure). Kept distinct from the
    /// generic `AuthFailed` so a caller retrying other gateway hosts with
    /// the same credentials can tell the two apart and stop immediately
    /// instead of repeating a doomed attempt against every remaining host.
    #[error("EAP authentication rejected: {0}")]
    EapCredentialsRejected(String),

    /// A cryptographic precondition was violated (e.g. bad key length).
    #[error("crypto error: {0}")]
    Crypto(&'static str),

    /// The peer deleted the whole IKE/ISAKMP SA while this side was in the
    /// middle of a request/response exchange that expected something else
    /// back (a CHILD SA rekey, or a from-scratch recreate after the peer
    /// deleted just one family's CHILD SA -- see
    /// `crate::ikev2::session::LivenessSession::create_child_primary` and
    /// `crate::ikev1::quick::rekey_child`). Confirmed live against a real
    /// FortiGate: tearing down the whole tunnel sends the CHILD/Quick-Mode
    /// SA's Delete first and the IKE/ISAKMP SA's Delete a moment later, which
    /// used to arrive while a from-scratch recreate (started off the first
    /// Delete) was blocked waiting for its own response -- silently discarded
    /// as "not the message we're waiting for", so the whole-tunnel teardown
    /// went unnoticed and the recreate just kept retrying forever. Kept
    /// distinct from a plain timeout/`Crypto` error so a caller can declare
    /// the tunnel dead immediately instead of scheduling a retry.
    #[error("the peer deleted the IKE SA while this exchange was in flight")]
    PeerTornDown,

    /// The IKE SA has run through its Message IDs, which never wrap (RFC 7296
    /// §2.2): it must be rekeyed, which starts them over, or closed. The last
    /// few are kept for exactly that -- see
    /// `crate::ikev2::session::LivenessSession::message_ids_exhausted`.
    #[error("the IKE SA has used up its Message IDs; rekey it or close it")]
    MessageIdsExhausted,
}
