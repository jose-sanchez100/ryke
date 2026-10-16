//! The Quick Modes the gateway starts, answered by this side as their responder (RFC 2409 §5.5) -- in the
//! constrained form a client needs: a message 1 that renews a CHILD SA this side holds, offering exactly that
//! SA's suite and selectors, is taken; nothing else is (POLICY, strict). The permissive responder of
//! [`super::quick`] (`respond_quick`, the test double that answers any offer it can build) is not this.
//!
//! [`answer_quick`] takes one message 1 the readers of an enabled exchange table kept in the inbox
//! ([`PeerQuick`], [`Phase1State::take_peer_quick_modes`]) and gives one verdict ([`QuickVerdict`]):
//! - **accept** ([`HeldQuick`]): message 2 is built and the keys of the new SA are derived, but nothing is
//!   sent and nothing installed: the caller has the new SA installed next to the one it replaces first, and
//!   only then sends the message 2 held;
//! - **refuse** ([`Refusal`]): an authenticated Informational carrying the error Notify that says why, ready to
//!   send, within the rate the exchange table allows;
//! - **silence** ([`Silence`]): nothing is sent, and the reason is told.
//!
//! It never touches the socket, never starts an exchange of its own and never acts on a passive table.
//!
//! **Secrets.** The Quick Mode Diffie-Hellman private key and the shared secret `g(qm)^xy` live in
//! zeroizing buffers that are wiped as soon as KEYMAT is derived, before [`answer_quick`] returns (RFC 2409
//! §5.5: the exponential "is irretreivably removed from the current state"); the KEYMAT of both directions is
//! held only inside the [`HeldQuick`], in a wrapper wiped on drop that hands it over once
//! ([`HeldQuick::take_keys`]). No copy of SKEYID_a, SKEYID_d or SKEYID_e is kept: whatever needs them later
//! takes the [`Phase1State`]. No `Debug` here prints key material or nonces.

use std::fmt;
use std::net::Ipv6Addr;
use std::time::Instant;

use zeroize::{Zeroize, Zeroizing};

use super::crypto1;
use super::exchange::{KeptRefusal, PeerQuick, RepeatRefusal, REFUSALS_PER_WINDOW, REFUSAL_RESEND_SPACING, REFUSAL_WINDOW};
use super::informational::{self, ChildFamily, RefusalNotify, RefusalSubject};
use super::isakmp::{self, exchange, flags, payload, IsakmpHeader, Payload};
use super::msgid::{self, MidEnd, MidKind, MidRecord, MidState, Origin};
use super::payloads::{id_type, life, protocol, Attribute, Id, Proposal, SaPayload, Transform, IPSEC_DOI, SIT_IDENTITY_ONLY};
use super::phase1::Phase1State;
use super::phase2;
use super::quick::{
    self, esp_attr, ChildKeyMaterial, RekeyedChild, SaLifetime, StatedLifetime, DEFAULT_LIFE_SECONDS, ENCAP_TUNNEL, LIFETIME_ATTRS, RESPONDER_LIFETIME,
    UDP_ENCAP_TUNNEL,
};
use crate::crypto::DhGroup;
use crate::debug::ike_debug;
use crate::entropy::Entropy;
use crate::error::IkeError;
use crate::ikev2::sk::SkCipher;

/// RFC 2407 §4.6.2.1: ID_IPV4_ADDR_RANGE, a selector this side never accepts.
const ID_IPV4_ADDR_RANGE: u8 = 7;

/// RFC 2407 §4.6.2.1: ID_IPV6_ADDR_RANGE, the same for IPv6.
const ID_IPV6_ADDR_RANGE: u8 = 8;

/// The highest SPI an SA never has here (POLICY): a proposal naming 0 or one of 1 to 255 is not answered, and
/// no inbound SPI of ours is one of them.
const SPI_RESERVED_MAX: u32 = 255;

/// How many random draws this side's inbound SPI of a new SA gets before the answer is given up (POLICY): with
/// a handful of SPIs in use out of 2^32, one draw misses them but for broken entropy.
const SPI_DRAWS: usize = 8;

/// The length of this side's nonce Nr: RFC 2409 §5 has a nonce between 8 and 256 octets, and this side's own
/// message 1 sends 16.
const NR_LEN: usize = 16;

/// One CHILD SA family the tunnel is configured for, which a gateway Quick Mode renewing it must name exactly
/// (POLICY): the suite in force -- ESP transform, key length, integrity algorithm, PFS group -- and the
/// family's selectors, built the way this side builds them for its own offers; and whether the family holds a
/// current SA to renew now ([`Self::answerable`]). The encapsulation mode is not here: it is the ISAKMP SA's
/// ([`Phase1State::floated`], as for this side's own offers). See [`QuickExpectations`] for the whole tunnel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedQuick {
    family: ChildFamily,
    cipher: SkCipher,
    pfs_group: Option<DhGroup>,
    /// The ID payload body the gateway must send as IDci: its side of the family's selectors.
    gateway_selector: Vec<u8>,
    /// The ID payload body it must send as IDcr: this side's.
    our_selector: Vec<u8>,
    explicit_seconds_cap: Option<u32>,
    answerable: bool,
}

impl ExpectedQuick {
    /// The primary (IPv4) family, answerable ([`Self::answerable`]). `cipher` and `pfs_group` are the suite this
    /// side offers for it; `ours` and `gateways` are the `(address, netmask)` selectors this side offers as its
    /// own and as the gateway's (the `ts_local` and `ts_remote` of
    /// [`super::quick::rekey_child_with_lifetime`]). `explicit_seconds_cap` is a lifetime in seconds the
    /// profile sets explicitly, when it sets one: an SA accepted here never lives longer (a cap of 0 is none);
    /// `None` leaves the gateway's offer as the only limit -- a default this side would otherwise fall back on
    /// is no limit the profile set. The encapsulation mode a message 1 must offer is the ISAKMP SA's: 3,
    /// UDP-Encapsulated-Tunnel (RFC 3947 §5.1), once it floated ([`Phase1State::floated`]), 1, Tunnel (RFC 2407
    /// §4.5), before.
    pub fn ipv4(cipher: SkCipher, pfs_group: Option<DhGroup>, ours: ([u8; 4], [u8; 4]), gateways: ([u8; 4], [u8; 4]), explicit_seconds_cap: Option<u32>) -> Self {
        Self {
            family: ChildFamily::Primary,
            cipher,
            pfs_group,
            gateway_selector: quick::ts_id(gateways.0, gateways.1),
            our_selector: quick::ts_id(ours.0, ours.1),
            explicit_seconds_cap,
            answerable: true,
        }
    }

    /// [`Self::ipv4`] for the IPv6 family: `ours` and `gateways` are `(network, prefix length)` selectors, as
    /// [`super::quick::rekey_child_ipv6_with_lifetime`] takes them.
    pub fn ipv6(cipher: SkCipher, pfs_group: Option<DhGroup>, ours: (Ipv6Addr, u8), gateways: (Ipv6Addr, u8), explicit_seconds_cap: Option<u32>) -> Self {
        Self {
            family: ChildFamily::Ipv6,
            cipher,
            pfs_group,
            gateway_selector: quick::ts_id_v6(gateways.0, gateways.1),
            our_selector: quick::ts_id_v6(ours.0, ours.1),
            explicit_seconds_cap,
            answerable: true,
        }
    }

    /// The same family, `answerable` or not: whether it holds a current SA a gateway Quick Mode can renew now
    /// (DESIGN 4.5's `family_has_current_sa`). A family configured but without one -- its SA ended and not made
    /// again yet, or being made by an exchange of ours -- is listed all the same, not answerable: a gateway
    /// message 1 for it is then a passing silence ([`Silence::FamilyNotReady`]), never a refusal that would tell
    /// the gateway its offer is incompatible (D7, D9).
    pub fn answerable(mut self, answerable: bool) -> Self {
        self.answerable = answerable;
        self
    }

    /// The family it describes.
    pub fn family(&self) -> ChildFamily {
        self.family
    }

    /// Whether a gateway message 1 for it may be answered now ([`Self::answerable`]).
    pub fn is_answerable(&self) -> bool {
        self.answerable
    }
}

/// What [`answer_quick`] checks a gateway's message 1 against besides the ISAKMP SA: every CHILD SA family the
/// tunnel is configured for, the SPIs in use, and the caller's time.
#[derive(Clone, Copy, Debug)]
pub struct QuickExpectations<'a> {
    /// Every family the tunnel is configured for, each once (a second entry of a family is never read), whether
    /// or not it holds a current SA now: one without is listed not answerable ([`ExpectedQuick::answerable`]),
    /// never left out. A message 1 for a family that is not here is refused with INVALID-ID-INFORMATION (D7:
    /// this side never creates a family the gateway asks for), so a configured family left out would turn a
    /// passing state into a refusal -- and an offer of this side's for it, sent back, would not be recognized
    /// as one ([`Silence::Reflection`]).
    pub families: &'a [ExpectedQuick],
    /// Every SPI the gateway chose for an SA of the tunnel that this side still holds in any way -- the current,
    /// pending and retired SAs of both families, the SPIs ESP is sent to: a proposal naming one is not answered.
    pub peer_spis_in_use: &'a [u32],
    /// Every SPI this side chose for its inbound side of those SAs: the SPI drawn for a new one is none of them
    /// (nor one of the gateway's).
    pub local_spis_in_use: &'a [u32],
    /// The caller's clock now: when the keys of an accepted SA are derived ([`HeldQuick::t_held`]). Everything
    /// the exchange table records is stamped by the table's own clock.
    pub now: Instant,
}

/// Why [`answer_quick`] sent nothing. In every case the caller sends, installs and keeps nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Silence {
    /// The exchange table is passive: no gateway Quick Mode is ever answered, and nothing was looked at.
    Passive,
    /// The entry holds no authenticated Quick Mode message 1 of this ISAKMP SA under its Message ID: no ISAKMP
    /// header, other cookies or exchange type, Message ID 0 or another than the entry's, no ENCRYPTION flag, or a
    /// HASH(1) that does not verify (RFC 2409 §5.5). Nothing changed.
    Unauthenticated,
    /// The message does not say what the entry was read as (its fingerprint differs). Nothing changed.
    NotTheMessageRead,
    /// The ledger holds the message's Message ID as no exchange of the peer's in progress with this content: an
    /// exchange that is over (answered, refused, timed out), parked, never recorded, or one of ours. Nothing
    /// changed.
    NotInProgress,
    /// The message was answered already, in the exchange the ledger still holds in progress: this side gives
    /// one message 2 per message 1, never a second with another SPI, nonce or keys (owner point 3). The answer
    /// held first is the only one; a copy of the message is answered with it. Nothing changed.
    AlreadyAnswered,
    /// A copy with the Commit bit set of a message whose exchange the ledger holds in progress -- read as a
    /// copy without the bit, answered or about to be. The fact is remembered by the exchange table, so that the
    /// answer says so ([`HeldQuick::commit_seen`]) and its SA is never used; no INVALID-FLAGS is sent against a
    /// message 2 that is, or may be, on its way. Nothing else changed.
    CommitOnHeld,
    /// A copy of a message refused before, read less than 200 ms (`REFUSAL_RESEND_SPACING`) after its refusal
    /// was last handed out (POLICY): the refusal is not sent again so soon, so that a copy replayed at line rate
    /// does not get one Informational per datagram. Nothing changed; a copy read later gets the refusal again.
    RepeatTooSoon,
    /// A family the tunnel is configured for but holds no current SA of now ([`ExpectedQuick::answerable`]):
    /// a passing state, not an incompatible offer (D7, D9). The ledger is left as it was: the exchange stays in
    /// progress until its deadline, and nothing was drawn.
    FamilyNotReady,
    /// One of this side's own messages 1 sent back to it: its IDci is this side's selector and its IDcr the
    /// gateway's, as in an offer of ours, never in one of the gateway's. The ledger ends the exchange as refused.
    Reflection,
    /// The SPI the gateway proposes for its inbound side is 0, one of 1 to 255, or that of an SA of the tunnel
    /// still held ([`QuickExpectations::peer_spis_in_use`]) (POLICY): installing it would collide with what the
    /// tunnel holds, and a gateway that rekeys never names one. The ledger ends the exchange as refused.
    InvalidSpi,
    /// The message was to be refused with the Notify named, but the exchange table's budget of refusals is spent
    /// (POLICY: at most four a minute on an ISAKMP SA). The ledger ends the exchange as refused all the same,
    /// unless the copy refused had the Commit bit set, which the ledger never recorded.
    RateLimited(RefusalNotify),
    /// No inbound SPI of ours could be drawn that the tunnel does not hold already: entropy that is broken. A
    /// passing failure, before anything was sent: the ledger is left as it was.
    NoFreeSpi,
    /// The answer or the refusal could not be built (an error of the encryption underneath, never something the
    /// peer chose). A passing failure: the ledger is left as it was, but for a refusal, which it ends all the same.
    NotBuilt,
}

/// An authenticated refusal of a gateway's message 1: an Informational
/// (`HDR*, HASH(1), N`) under a fresh Message ID of ours, with one error Notify. The caller sends `datagram` to
/// the gateway as it sends any Informational (the non-ESP marker first on a floated tunnel) and does nothing else.
#[derive(Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The Notify it carries.
    pub notify: RefusalNotify,
    /// The Message ID of the refused message 1.
    pub refused_msgid: u32,
    /// The Message ID of the Informational: never `refused_msgid` (RFC 2409 §5.7).
    pub msgid: u32,
    /// The Informational, ready to send.
    pub datagram: Vec<u8>,
    /// `true` when these are the bytes sent before for a copy of the same message (its Message ID, its content
    /// and its Commit bit): sent again unchanged, not counted against the budget of refusals, and at most once
    /// per 200 ms ([`Silence::RepeatTooSoon`] in between).
    pub repeat: bool,
}

impl Refusal {
    fn again(kept: KeptRefusal) -> Self {
        Self { notify: kept.notify, refused_msgid: kept.refused_msgid, msgid: kept.msgid, datagram: kept.datagram, repeat: true }
    }
}

impl fmt::Debug for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Refusal")
            .field("notify", &self.notify)
            .field("refused_msgid", &format_args!("{:08x}", self.refused_msgid))
            .field("msgid", &format_args!("{:08x}", self.msgid))
            .field("datagram", &format_args!("<{} bytes>", self.datagram.len()))
            .field("repeat", &self.repeat)
            .finish()
    }
}

/// What [`answer_quick`] made of one gateway message 1.
#[derive(Debug)]
pub enum QuickVerdict {
    /// Accepted: message 2 built and the keys derived, nothing sent and nothing installed. The caller installs the
    /// new SA beside the one it replaces, then sends [`HeldQuick::qm2`]; if it does neither, it drops the
    /// [`HeldQuick`] and the gateway, unanswered, sends its message 1 again or lets the exchange go.
    Accept(Box<HeldQuick>),
    /// Refused: the caller sends [`Refusal::datagram`]. The ledger holds the exchange as refused, except for
    /// INVALID-FLAGS about a copy with the Commit bit, which the ledger never recorded: a copy without the bit
    /// may still be answered.
    Refuse(Refusal),
    /// Not answered: the caller sends nothing (see [`Silence`] for each reason).
    Silent(Silence),
}

/// The key material of an accepted SA until it is moved out ([`HeldQuick::take_keys`]): wiped if it is dropped
/// before, and nothing left behind once moved.
struct HeldKeys(Option<RekeyedChild>);

impl HeldKeys {
    /// Wipes the key material held, if any, in place.
    fn wipe(&mut self) {
        if let Some(keys) = self.0.as_mut() {
            wipe(keys);
        }
    }
}

impl Drop for HeldKeys {
    fn drop(&mut self) {
        self.wipe();
    }
}

/// Wipes the key material of both directions of `keys` ([`ChildKeyMaterial`] is `Zeroize`: its buffers are
/// zeroed, then emptied).
fn wipe(keys: &mut RekeyedChild) {
    keys.key_out.zeroize();
    keys.key_in.zeroize();
}

/// A gateway's message 1 [`answer_quick`] accepted: the message 2 that answers it, built and not sent, and the
/// keys of the new SA, derived now (RFC 2409 §5.5's KEYMAT), not at message 3. Not `Clone`: its keys are handed
/// over once.
pub struct HeldQuick {
    msgid: u32,
    family: ChildFamily,
    fingerprint: [u8; 32],
    peer_spi: u32,
    local_spi: u32,
    keys: HeldKeys,
    lifetime: SaLifetime,
    responder_lifetime_added: bool,
    qm2: Vec<u8>,
    qm2_plaintext: Vec<u8>,
    qm2_first_payload: u8,
    ni: Vec<u8>,
    nr: Vec<u8>,
    qm1_last_block: Vec<u8>,
    qm2_last_block: Vec<u8>,
    t_held: Instant,
    commit_seen: bool,
}

impl HeldQuick {
    /// The Message ID of the exchange.
    pub fn msgid(&self) -> u32 {
        self.msgid
    }

    /// The family of the SA it renews.
    pub fn family(&self) -> ChildFamily {
        self.family
    }

    /// The fingerprint of the message 1 it answers ([`PeerQuick::fingerprint`]).
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    /// The SPI the gateway proposed for its inbound side: this side's outbound SPI of the new SA.
    pub fn peer_spi(&self) -> u32 {
        self.peer_spi
    }

    /// The SPI this side chose for its inbound side of the new SA, stated in message 2.
    pub fn local_spi(&self) -> u32 {
        self.local_spi
    }

    /// The key material of both directions of the new SA, moved out: `Some` the first time, `None` after. What
    /// is moved out is the caller's to keep and to wipe; nothing of it stays here.
    pub fn take_keys(&mut self) -> Option<RekeyedChild> {
        self.keys.0.take()
    }

    /// Whether the key material is still here ([`Self::take_keys`] not called yet).
    pub fn keys_held(&self) -> bool {
        self.keys.0.is_some()
    }

    /// The limits of the new SA: in seconds the gateway's offer (28800, RFC 2407 §4.5's default, when it states
    /// none) shortened to the cap of [`ExpectedQuick`] when there is one, and the kilobytes the offer states, if
    /// it states any, as they are. Never longer than offered.
    pub fn lifetime(&self) -> SaLifetime {
        self.lifetime
    }

    /// Whether message 2 carries a RESPONDER-LIFETIME Notify (RFC 2407 §4.6.3.1): when a limit is shorter than
    /// the offer's.
    pub fn responder_lifetime_added(&self) -> bool {
        self.responder_lifetime_added
    }

    /// Message 2, encrypted, exactly as built: the ISAKMP message, without the non-ESP marker a floated tunnel
    /// puts before it on the wire.
    pub fn qm2(&self) -> &[u8] {
        &self.qm2
    }

    /// The payload chain message 2 encrypts (HASH(2) first), without padding: what a copy of it under another IV
    /// is encrypted from.
    pub fn qm2_plaintext(&self) -> &[u8] {
        &self.qm2_plaintext
    }

    /// The type of the first payload of that chain (the header's Next Payload).
    pub fn qm2_first_payload(&self) -> u8 {
        self.qm2_first_payload
    }

    /// The gateway's nonce Ni (the body of its Nonce payload, Ni_b).
    pub fn ni(&self) -> &[u8] {
        &self.ni
    }

    /// This side's nonce Nr (Nr_b).
    pub fn nr(&self) -> &[u8] {
        &self.nr
    }

    /// The last cipher block of the message 1 answered: the IV message 2 is encrypted under (RFC 2409 Appendix
    /// B).
    pub fn qm1_last_block(&self) -> &[u8] {
        &self.qm1_last_block
    }

    /// The last cipher block of message 2: the IV the gateway's message 3 is encrypted under.
    pub fn qm2_last_block(&self) -> &[u8] {
        &self.qm2_last_block
    }

    /// When the keys were derived, by the caller's clock ([`QuickExpectations::now`]).
    pub fn t_held(&self) -> Instant {
        self.t_held
    }

    /// Whether a copy of the message 1 answered had the Commit bit set, whichever copy came first: noted on the
    /// entry answered ([`PeerQuick::commit_seen`]) or remembered by the exchange table from a copy read before
    /// -- refused, refused in silence for the budget, or never kept -- or while the entry waited. RFC 2408 §3.1
    /// then has this side wait for the gateway's CONNECTED Notify before it sends encrypted traffic, which this
    /// side does not support: an SA so answered is never to be used. A copy with the bit read after the answer
    /// was given is not reflected here; the exchange table remembers it all the same.
    pub fn commit_seen(&self) -> bool {
        self.commit_seen
    }
}

impl fmt::Debug for HeldQuick {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HeldQuick")
            .field("msgid", &format_args!("{:08x}", self.msgid))
            .field("family", &self.family)
            .field("peer_spi", &format_args!("{:08x}", self.peer_spi))
            .field("local_spi", &format_args!("{:08x}", self.local_spi))
            .field("keys", &format_args!("{}", if self.keys_held() { "<held>" } else { "<taken>" }))
            .field("lifetime", &self.lifetime)
            .field("responder_lifetime_added", &self.responder_lifetime_added)
            .field("qm2", &format_args!("<{} bytes>", self.qm2.len()))
            .field("t_held", &self.t_held)
            .field("commit_seen", &self.commit_seen)
            .finish()
    }
}

/// Answers one message 1 of a Quick Mode the gateway started, `quick` (as the inbox of an enabled exchange table
/// keeps it), for the tunnel `expected` describes: see [`QuickVerdict`]. Sends nothing.
///
/// Each entry is answered at most once. While the exchange is in progress, a second call for a message already
/// accepted is [`Silence::AlreadyAnswered`]: the [`HeldQuick`] given first is the one answer to the message
/// (owner point 3: no new SPI, nonce or keys for a copy), and whoever holds it answers the copies of the
/// message with its message 2. The responder registry that routes those copies past the readers comes with the
/// rest of the responder; until a caller has it, the exchange table remembers the answers outstanding.
///
/// In this order, the first that fails deciding:
/// 1. A passive table: [`Silence::Passive`], nothing looked at.
/// 2. The message is read again: the ISAKMP SA's cookies, Quick Mode, the entry's Message ID (not 0), the
///    ENCRYPTION flag, decrypted with the IV of its Message ID and checked by HASH(1) (RFC 2409 §5.5, Appendix B),
///    its fingerprint the entry's. The readers did it before the entry was kept; it is done again so that an
///    entry nobody authenticated is never answered ([`Silence::Unauthenticated`],
///    [`Silence::NotTheMessageRead`]).
/// 3. The Commit bit set in this copy's header: the exchange table remembers it of the message, refused or not
///    (what answers a copy of the message without the bit, before or after, says so: [`HeldQuick::commit_seen`]);
///    when the ledger holds the message's exchange in progress -- a copy without the bit was read, and is
///    answered or about to be -- that is all ([`Silence::CommitOnHeld`]).
/// 4. A copy of a message refused before (same Message ID, content and Commit bit) gets the same refusal again,
///    not counted ([`Refusal::repeat`]), at most once per 200 ms ([`Silence::RepeatTooSoon`]).
/// 5. The Commit bit set in this copy's header: [`RefusalNotify::InvalidFlags`] about the message, and nothing
///    recorded in the ledger (no HASH covers the header: a later copy without the bit is answered as any other,
///    its SA never used).
/// 6. The ledger must hold the Message ID as the peer's Quick Mode in progress with this content
///    ([`Silence::NotInProgress`]), not answered yet ([`Silence::AlreadyAnswered`]).
/// 7. Structure (RFC 2409 §5.5): a HASH first and an SA right after it; no second HASH; one Nonce of 8 to 256
///    octets; at most one KE; no client identity or two, IDci then IDcr ([`RefusalNotify::PayloadMalformed`]
///    otherwise); one SA payload, not several (RFC 2409 §5.5 allows several; one is this side's rule,
///    [`RefusalNotify::NoProposalChosen`]); identities present (POLICY: a tunnel's SA has selectors,
///    [`RefusalNotify::InvalidIdInformation`]). Any other payload -- a NAT-OA (RFC 3947 §5.2: "SHOULD NOT" in
///    tunnel mode, not MUST NOT), a status or private Notify, a type this side does not know -- is passed over,
///    traced.
/// 8. Our own offer sent back ([`Silence::Reflection`]), for any family the tunnel is configured for.
/// 9. The family, by the types of IDci and IDcr, and one the tunnel is configured for
///    ([`RefusalNotify::InvalidIdInformation`]) and holds a current SA of ([`Silence::FamilyNotReady`]).
/// 10. The proposal: an SA payload that parses, with proposals and transforms in it (RFC 2408 §4.2,
///     [`RefusalNotify::BadProposalSyntax`]); the IPsec DOI and SIT_IDENTITY_ONLY; one proposal, for ESP, with a
///     4-octet SPI; then the SPI ([`Silence::InvalidSpi`]); then a transform equal to the family's suite --
///     transform ID, key length, integrity algorithm, PFS group iff the family has one, encapsulation mode 3 iff
///     the ISAKMP SA floated else 1 (transport mode and anything else refused) -- whose lifetime pairs parse
///     (RFC 2407 §4.5, §4.5.2): the first such is taken, its Proposal # and Transform # kept (RFC 2408 §4.2:
///     "SHOULD retain"). Anything else is [`RefusalNotify::NoProposalChosen`] (RFC 2408 §5.4), but a transform
///     of the suite whose lifetime pairs do not parse, when no other is taken
///     ([`RefusalNotify::BadProposalSyntax`]). With PFS, a KE of the group's length
///     ([`RefusalNotify::NoProposalChosen`] otherwise); a KE without PFS or PFS without a KE is
///     [`RefusalNotify::PayloadMalformed`] (RFC 2409 §5.5: a KE goes with a group attribute).
/// 11. The selectors: IDci, IDcr each a subnet of its family with no host bit set, protocol and port 0, and IDcr
///     alone also as a single address; then `selector_id_matches(expected IDci, IDci)` and the same for IDcr,
///     against the bodies this side builds for its own offers -- which accepts this side's /32 (/128) selector
///     sent as that one address ([`RefusalNotify::InvalidIdInformation`] otherwise, RFC 2409 §5.5).
/// 12. The gateway's KE: a value its group refuses ([`DhGroup::shared`]) is [`RefusalNotify::PayloadMalformed`].
///
/// Then the answer (RFC 2409 §5.5): a fresh inbound SPI (not 0 to 255, none in use), a 16-octet Nr, a fresh KE
/// with PFS; message 2 = `HDR*, HASH(2), SA, Nr, [KE], IDci, IDcr, [N(RESPONDER-LIFETIME)]`, its SA the proposal
/// and transform taken with this side's SPI and the offered attributes unchanged (RFC 2409 §5: "Responders MUST
/// NOT modify attributes of any offer"), the identities echoed byte for byte, `HASH(2) = prf(SKEYID_a, M-ID |
/// Ni_b | SA | Nr [| KE] [| IDci | IDcr] [| N])`, encrypted under the last cipher block of the message 1 answered.
/// The SA's limits ([`HeldQuick::lifetime`]): the offer's, the seconds shortened to the cap; when one is shorter
/// than the offer's, a RESPONDER-LIFETIME Notify (RFC 2407 §4.5.4, choices 2 and 3; layout §4.6.3.1: the IPsec
/// DOI, ESP, this side's inbound SPI) states every limit in force. KEYMAT for each direction is
/// `prf(SKEYID_d, [g(qm)^xy |] protocol | SPI | Ni_b | Nr_b)`, the SPI the one the destination of that direction
/// chose, Ni_b the gateway's nonce and Nr_b this side's.
///
/// A refusal ([`QuickVerdict::Refuse`]) is an Informational under a fresh Message ID of ours with the Notify
/// about the gateway's proposed SPI (ESP) when the message names one, about the message otherwise; INVALID-FLAGS
/// is always about the message (ISAKMP, SPI size 0). The ledger holds the exchange as refused from then on
/// (but for INVALID-FLAGS, whose copy it never recorded), and the table counts the refusal against its budget
/// ([`Silence::RateLimited`] beyond it) and keeps it for a copy of the same message.
pub fn answer_quick(st: &Phase1State, entropy: &mut impl Entropy, expected: &QuickExpectations<'_>, quick: &PeerQuick) -> QuickVerdict {
    if !st.exchanges.is_enabled() {
        return QuickVerdict::Silent(Silence::Passive);
    }
    let msgid = quick.msgid;
    let read = match read_message_1(st, quick) {
        Ok(read) => read,
        Err((silence, why)) => {
            ike_debug!("QUICK: gateway message 1 under msgid={msgid:08x} not answered: {why}");
            return QuickVerdict::Silent(silence);
        }
    };
    st.exchanges.sweep(st.exchanges.now());
    let record = st.exchanges.id_record(msgid);
    let in_progress = matches!(
        record,
        Some(MidRecord { origin: Origin::Peer, kind: MidKind::Quick, state: MidState::Active { .. }, fingerprint: Some(print), .. }) if print == quick.fingerprint
    );
    if read.commit_flag {
        st.exchanges.note_commit(msgid, quick.fingerprint);
        if in_progress {
            ike_debug!(
                "QUICK: a copy of gateway message 1 under msgid={msgid:08x} has the Commit bit set, and the exchange is in progress -- noted, not refused: what answers it is never used"
            );
            return QuickVerdict::Silent(Silence::CommitOnHeld);
        }
    }
    match st.exchanges.repeat_refusal(msgid, &quick.fingerprint, read.commit_flag) {
        Some(RepeatRefusal::Send(kept)) => {
            ike_debug!("QUICK: a copy of gateway message 1 under msgid={msgid:08x}, refused before -- the same refusal again");
            return QuickVerdict::Refuse(Refusal::again(kept));
        }
        Some(RepeatRefusal::TooSoon) => {
            ike_debug!("QUICK: a copy of gateway message 1 under msgid={msgid:08x}, refused less than {REFUSAL_RESEND_SPACING:?} ago -- not answered");
            return QuickVerdict::Silent(Silence::RepeatTooSoon);
        }
        None => {}
    }
    if read.commit_flag {
        return refuse(st, entropy, quick, true, RefusalNotify::InvalidFlags, RefusalSubject::Message, "this copy's header has the Commit bit set, which this side does not support");
    }
    if !in_progress {
        ike_debug!(
            "QUICK: gateway message 1 under msgid={msgid:08x} not answered: the Message-ID ledger holds it as no exchange of the peer's in progress with this content ({:?})",
            record.map(|record| (record.origin, record.kind, record.state))
        );
        return QuickVerdict::Silent(Silence::NotInProgress);
    }
    if st.exchanges.accept_outstanding(msgid, &quick.fingerprint) {
        ike_debug!("QUICK: gateway message 1 under msgid={msgid:08x} not answered again: its message 2 is held already");
        return QuickVerdict::Silent(Silence::AlreadyAnswered);
    }
    let outcome = check_message_1(&read.payloads, expected, st.floated).and_then(|checked| build_answer(st, entropy, expected, quick, &read, checked));
    match outcome {
        Ok(held) => {
            if !st.exchanges.note_accepted(msgid, quick.fingerprint) {
                ike_debug!("QUICK: msgid={msgid:08x} was no longer in progress in the Message-ID ledger");
            }
            ike_debug!(
                "QUICK: gateway message 1 under msgid={msgid:08x} accepted for the {:?} CHILD SA -- message 2 built, not sent (spi_in={:08x} spi_out={:08x}, lifetime {}s{}{})",
                held.family,
                held.local_spi,
                held.peer_spi,
                held.lifetime.seconds,
                held.lifetime.kilobytes.map(|kb| format!(" / {kb} KB")).unwrap_or_default(),
                if held.responder_lifetime_added { ", RESPONDER-LIFETIME stated" } else { "" }
            );
            QuickVerdict::Accept(Box::new(held))
        }
        Err(Turn::Refuse(notify, why)) => refuse(st, entropy, quick, false, notify, subject_of(&read.payloads), why),
        Err(Turn::Silent(silence, why)) => {
            ike_debug!("QUICK: gateway message 1 under msgid={msgid:08x} not answered: {why}");
            if matches!(silence, Silence::Reflection | Silence::InvalidSpi) && !st.exchanges.finish(msgid, st.exchanges.now(), MidEnd::Refused) {
                ike_debug!("QUICK: msgid={msgid:08x} was no longer in progress in the Message-ID ledger");
            }
            QuickVerdict::Silent(silence)
        }
    }
}

/// How a check of [`answer_quick`] ended the answer.
enum Turn {
    /// A refusal with this Notify, for the reason given.
    Refuse(RefusalNotify, &'static str),
    /// Silence, for the reason given.
    Silent(Silence, &'static str),
}

/// A gateway's message 1 read again by [`read_message_1`].
struct ReadMessage1 {
    payloads: Vec<Payload>,
    /// Its last cipher block: the IV of message 2.
    last_block: Vec<u8>,
    /// Whether this copy's header has the Commit bit set.
    commit_flag: bool,
}

/// Step 2 of [`answer_quick`].
fn read_message_1(st: &Phase1State, quick: &PeerQuick) -> Result<ReadMessage1, (Silence, &'static str)> {
    let unauthenticated = |why| (Silence::Unauthenticated, why);
    let header = IsakmpHeader::parse(&quick.datagram).map_err(|_| unauthenticated("no ISAKMP header that parses"))?;
    if header.init_cookie != st.cky_i || header.resp_cookie != st.cky_r {
        return Err(unauthenticated("a message of another ISAKMP SA"));
    }
    if header.exchange_type != exchange::QUICK {
        return Err(unauthenticated("not a Quick Mode message"));
    }
    if header.message_id != quick.msgid {
        return Err(unauthenticated("its Message ID is not the entry's"));
    }
    if header.message_id == 0 {
        return Err(unauthenticated("Message ID 0, which is Phase 1's"));
    }
    if !header.encrypted() {
        return Err(unauthenticated("its payloads are not encrypted"));
    }
    let iv0 = crypto1::phase2_iv(st.prf, &st.phase1_iv, quick.msgid, st.enc_block);
    let (_header, payloads, last_block) = phase2::parse_encrypted(&quick.datagram, st.prf, &st.skeyid_a, &st.enc_key, st.enc_block, &iv0)
        .map_err(|_| unauthenticated("it does not authenticate as a message 1 (HASH(1))"))?;
    if msgid::fingerprint(quick.msgid, &payloads) != quick.fingerprint {
        return Err((Silence::NotTheMessageRead, "its content is not the one the entry was read as"));
    }
    Ok(ReadMessage1 { payloads, last_block, commit_flag: header.flags & flags::COMMIT != 0 })
}

/// What steps 7 to 11 of [`answer_quick`] took from a message 1.
struct Checked<'a> {
    expected: &'a ExpectedQuick,
    doi: u32,
    situation: u32,
    proposal_num: u8,
    /// The transform taken, as offered.
    transform: Transform,
    peer_spi: u32,
    stated: StatedLifetime,
    ni: Vec<u8>,
    /// The gateway's KE, with PFS.
    gxi: Option<Vec<u8>>,
    idci: Vec<u8>,
    idcr: Vec<u8>,
}

/// Steps 7 to 11 of [`answer_quick`], on an ISAKMP SA that `floated` to UDP 4500 or not
/// ([`Phase1State::floated`]).
fn check_message_1<'a>(payloads: &[Payload], expected: &QuickExpectations<'a>, floated: bool) -> Result<Checked<'a>, Turn> {
    let malformed = |why| Turn::Refuse(RefusalNotify::PayloadMalformed, why);
    let no_proposal = |why| Turn::Refuse(RefusalNotify::NoProposalChosen, why);
    let bad_syntax = |why| Turn::Refuse(RefusalNotify::BadProposalSyntax, why);
    let bad_id = |why| Turn::Refuse(RefusalNotify::InvalidIdInformation, why);

    // 7. Structure (RFC 2409 §5.5): "a HASH payload MUST immediately follow the ISAKMP header and a SA payload
    // MUST immediately follow the HASH".
    let [hash, first_sa, rest @ ..] = payloads else { return Err(malformed("fewer payloads than a HASH and an SA")) };
    if hash.payload_type != payload::HASH || first_sa.payload_type != payload::SA {
        return Err(malformed("its first payload is not a HASH followed by an SA"));
    }
    let (mut sas, mut nonces, mut kes, mut ids) = (vec![first_sa], Vec::new(), Vec::new(), Vec::new());
    for p in rest {
        match p.payload_type {
            payload::HASH => return Err(malformed("a second HASH payload, which no HASH covers")),
            payload::SA => sas.push(p),
            payload::NONCE => nonces.push(p),
            payload::KE => kes.push(p),
            payload::ID => ids.push(p),
            other => ike_debug!("QUICK: gateway message 1: a payload of type {other} is passed over"),
        }
    }
    let [ni] = nonces.as_slice() else { return Err(malformed("not exactly one Nonce payload")) };
    if isakmp::check_nonce_len(&ni.data).is_err() {
        return Err(malformed("a nonce shorter than 8 or longer than 256 octets"));
    }
    if kes.len() > 1 {
        return Err(malformed("more than one KE payload"));
    }
    if !matches!(ids.len(), 0 | 2) {
        return Err(malformed("client identities other than an IDci and an IDcr"));
    }
    if sas.len() > 1 {
        return Err(no_proposal("more than one SA payload (POLICY: one SA per Quick Mode)"));
    }
    let [idci, idcr] = ids.as_slice() else { return Err(bad_id("no client identities (POLICY: the SA of a tunnel has selectors)")) };
    let (idci, idcr) = (&idci.data, &idcr.data);

    // 8. Our own offer sent back: IDci ours and IDcr the gateway's.
    if expected.families.iter().any(|e| e.our_selector != e.gateway_selector && *idci == e.our_selector && *idcr == e.gateway_selector) {
        return Err(Turn::Silent(Silence::Reflection, "its IDci is this side's selector and its IDcr the gateway's: an offer of this side's sent back"));
    }

    // 9. The family.
    let Some(family) = id_family(idci) else { return Err(bad_id("IDci is no IPv4 or IPv6 identity")) };
    if id_family(idcr) != Some(family) {
        return Err(bad_id("IDci and IDcr are of different families"));
    }
    let Some(exp) = expected.families.iter().find(|e| e.family == family) else { return Err(bad_id("a family this tunnel is not configured for")) };
    if !exp.answerable {
        return Err(Turn::Silent(Silence::FamilyNotReady, "a family the tunnel is configured for, with no current SA to renew now"));
    }

    // 10. The proposal.
    let sa = SaPayload::parse(&first_sa.data).map_err(|_| bad_syntax("an SA payload that does not parse"))?;
    if sa.proposals.is_empty() || sa.proposals.iter().any(|p| p.transforms.is_empty()) {
        return Err(bad_syntax("an SA payload without a proposal, or a proposal without a transform"));
    }
    if sa.doi != IPSEC_DOI || sa.situation != SIT_IDENTITY_ONLY {
        return Err(no_proposal("an SA in another DOI or situation"));
    }
    let [proposal] = sa.proposals.as_slice() else { return Err(no_proposal("more than one proposal (POLICY: the one suite in force)")) };
    if proposal.protocol_id != protocol::ESP {
        return Err(no_proposal("a proposal for a protocol other than ESP"));
    }
    let Ok(spi) = <[u8; 4]>::try_from(proposal.spi.as_slice()) else { return Err(no_proposal("an ESP SPI that is not four octets")) };
    let peer_spi = u32::from_be_bytes(spi);
    if peer_spi <= SPI_RESERVED_MAX || expected.peer_spis_in_use.contains(&peer_spi) {
        return Err(Turn::Silent(Silence::InvalidSpi, "the SPI proposed is 0 to 255, or one of an SA the tunnel holds"));
    }
    // The ISAKMP SA's encapsulation, as for this side's own offers.
    let encap_mode = if floated { UDP_ENCAP_TUNNEL } else { ENCAP_TUNNEL };
    let suite = quick::esp_transform(0, exp.cipher, exp.pfs_group, encap_mode, 0);
    let mut lifetime_unreadable = false;
    let mut taken = None;
    for transform in &proposal.transforms {
        if !transform.matches_offer(&suite, &LIFETIME_ATTRS) {
            continue;
        }
        match quick::stated_lifetime(transform) {
            Ok(stated) => {
                taken = Some((transform, stated));
                break;
            }
            Err(_) => lifetime_unreadable = true,
        }
    }
    let Some((transform, stated)) = taken else {
        return Err(if lifetime_unreadable {
            bad_syntax("the transform of the suite in force states lifetime pairs that do not parse")
        } else {
            no_proposal("no transform of the suite in force: cipher, key length, integrity, PFS group and encapsulation mode")
        });
    };
    let gxi = match (exp.pfs_group, kes.as_slice()) {
        (Some(group), [ke]) if ke.data.len() == group.public_len() => Some(ke.data.clone()),
        (Some(_), [_]) => return Err(no_proposal("a KE that is not of the PFS group's length")),
        (Some(_), _) => return Err(malformed("a PFS group with no KE")),
        (None, []) => None,
        (None, _) => return Err(malformed("a KE with no PFS group in the transform")),
    };

    // 11. The selectors.
    check_selector(idci, false).map_err(bad_id)?;
    check_selector(idcr, true).map_err(bad_id)?;
    if !quick::selector_id_matches(&exp.gateway_selector, idci) {
        return Err(bad_id("IDci is not the gateway's selector of the family"));
    }
    if !quick::selector_id_matches(&exp.our_selector, idcr) {
        return Err(bad_id("IDcr is not this side's selector of the family"));
    }
    Ok(Checked {
        expected: exp,
        doi: sa.doi,
        situation: sa.situation,
        proposal_num: proposal.num,
        transform: transform.clone(),
        peer_spi,
        stated,
        ni: ni.data.clone(),
        gxi,
        idci: idci.clone(),
        idcr: idcr.clone(),
    })
}

/// The family an ID payload body names by its type (RFC 2407 §4.6.2.1), if it names one.
fn id_family(body: &[u8]) -> Option<ChildFamily> {
    match *body.first()? {
        id_type::IPV4_ADDR | id_type::IPV4_ADDR_SUBNET | ID_IPV4_ADDR_RANGE => Some(ChildFamily::Primary),
        id_type::IPV6_ADDR | id_type::IPV6_ADDR_SUBNET | ID_IPV6_ADDR_RANGE => Some(ChildFamily::Ipv6),
        _ => None,
    }
}

/// Whether an ID payload body is a selector this side can take, whatever selector it names: protocol and port 0,
/// a subnet of its family's length with no host bit set (RFC 2407 §4.6.2.5, §4.6.2.7), or, when
/// `single_allowed`, one address (§4.6.2.2, §4.6.2.6). A range is never one.
fn check_selector(body: &[u8], single_allowed: bool) -> Result<(), &'static str> {
    let Ok(id) = Id::parse(body) else { return Err("an identity shorter than its fixed part") };
    if id.protocol != 0 || id.port != 0 {
        return Err("an identity limited to a protocol or a port");
    }
    let half = match id.id_type {
        id_type::IPV4_ADDR_SUBNET => 4,
        id_type::IPV6_ADDR_SUBNET => 16,
        id_type::IPV4_ADDR | id_type::IPV6_ADDR if !single_allowed => return Err("IDci as a single address, where the gateway's side is a subnet"),
        id_type::IPV4_ADDR | id_type::IPV6_ADDR => {
            let len = if id.id_type == id_type::IPV4_ADDR { 4 } else { 16 };
            return if id.data.len() == len { Ok(()) } else { Err("an address of the wrong length") };
        }
        ID_IPV4_ADDR_RANGE | ID_IPV6_ADDR_RANGE => return Err("an address range"),
        _ => return Err("an identity that is no address"),
    };
    if id.data.len() != 2 * half {
        return Err("a subnet of the wrong length");
    }
    let (address, mask) = id.data.split_at(half);
    if address.iter().zip(mask).any(|(a, m)| a & !m != 0) {
        return Err("a subnet with host bits set");
    }
    Ok(())
}

/// What a refusal of the message whose payloads are `payloads` names: the SPI the gateway proposed (the first
/// proposal of its first SA payload, when that is a 4-octet ESP SPI), or else the message.
fn subject_of(payloads: &[Payload]) -> RefusalSubject {
    payloads
        .iter()
        .find(|p| p.payload_type == payload::SA)
        .and_then(|sa| SaPayload::parse(&sa.data).ok())
        .and_then(|sa| sa.proposals.into_iter().next())
        .filter(|proposal| proposal.protocol_id == protocol::ESP)
        .and_then(|proposal| <[u8; 4]>::try_from(proposal.spi.as_slice()).ok())
        .map_or(RefusalSubject::Message, |spi| RefusalSubject::Proposal { spi: u32::from_be_bytes(spi) })
}

/// Refuses `quick` with `notify` about `subject`, for `why`: the ledger ends its exchange as refused (unless the
/// copy refused, `commit_flag`, is one it never recorded), the refusal is charged to the table's budget, built,
/// and kept for a copy of the same message.
fn refuse(st: &Phase1State, entropy: &mut impl Entropy, quick: &PeerQuick, commit_flag: bool, notify: RefusalNotify, subject: RefusalSubject, why: &str) -> QuickVerdict {
    let msgid = quick.msgid;
    let notify_type = notify.notify_type();
    if !commit_flag && !st.exchanges.finish(msgid, st.exchanges.now(), MidEnd::Refused) {
        ike_debug!("QUICK: msgid={msgid:08x} was no longer in progress in the Message-ID ledger");
    }
    if !st.exchanges.charge_refusal() {
        ike_debug!(
            "QUICK: gateway message 1 under msgid={msgid:08x} refused ({why}) -- its Notify {notify:?} ({notify_type}) not sent: {REFUSALS_PER_WINDOW} refusals in {REFUSAL_WINDOW:?} already"
        );
        return QuickVerdict::Silent(Silence::RateLimited(notify));
    }
    match informational::build_error_notify(st, entropy, notify, subject, msgid) {
        Ok((notify_msgid, datagram)) => {
            ike_debug!("QUICK: gateway message 1 under msgid={msgid:08x} refused with {notify:?} ({notify_type}), msgid={notify_msgid:08x}: {why}");
            st.exchanges.keep_refusal(KeptRefusal {
                refused_msgid: msgid,
                fingerprint: quick.fingerprint,
                commit_flag,
                notify,
                msgid: notify_msgid,
                datagram: datagram.clone(),
                last_sent: st.exchanges.now(),
            });
            QuickVerdict::Refuse(Refusal { notify, refused_msgid: msgid, msgid: notify_msgid, datagram, repeat: false })
        }
        Err(e) => {
            ike_debug!("QUICK: gateway message 1 under msgid={msgid:08x} refused ({why}), but its Notify could not be built: {e}");
            QuickVerdict::Silent(Silence::NotBuilt)
        }
    }
}

/// The answer of [`answer_quick`] to the message 1 `read` of `quick`, which every check took (`checked`).
fn build_answer(st: &Phase1State, entropy: &mut impl Entropy, expected: &QuickExpectations<'_>, quick: &PeerQuick, read: &ReadMessage1, checked: Checked<'_>) -> Result<HeldQuick, Turn> {
    let exp = checked.expected;
    // With PFS: our share and g(qm)^xy, both wiped when this function returns.
    let pfs = match (exp.pfs_group, &checked.gxi) {
        (Some(group), Some(gxi)) => {
            let private = Zeroizing::new(entropy.next_array32());
            let shared = group.shared(private.as_slice(), gxi).map_err(|_| Turn::Refuse(RefusalNotify::PayloadMalformed, "a KE value its group refuses"))?;
            Some((group.public(private.as_slice()), Zeroizing::new(shared)))
        }
        _ => None,
    };
    let Some(local_spi) = draw_spi(entropy, expected) else {
        return Err(Turn::Silent(Silence::NoFreeSpi, "no inbound SPI could be drawn that the tunnel does not hold"));
    };
    let mut nr = vec![0u8; NR_LEN];
    entropy.fill(&mut nr);

    let offered_seconds = checked.stated.seconds.unwrap_or(DEFAULT_LIFE_SECONDS);
    let seconds = exp.explicit_seconds_cap.filter(|cap| *cap > 0).map_or(offered_seconds, |cap| offered_seconds.min(cap));
    let lifetime = SaLifetime { seconds, kilobytes: checked.stated.kilobytes };
    let responder_lifetime_added = seconds < offered_seconds;

    let answer = SaPayload {
        doi: checked.doi,
        situation: checked.situation,
        proposals: vec![Proposal { num: checked.proposal_num, protocol_id: protocol::ESP, spi: local_spi.to_be_bytes().to_vec(), transforms: vec![checked.transform.clone()] }],
    };
    let mut after: Vec<(u8, Vec<u8>)> = vec![(payload::SA, answer.to_bytes()), (payload::NONCE, nr.clone())];
    if let Some((public, _)) = &pfs {
        after.push((payload::KE, public.clone()));
    }
    after.push((payload::ID, checked.idci.clone()));
    after.push((payload::ID, checked.idcr.clone()));
    if responder_lifetime_added {
        after.push((payload::NOTIFY, responder_lifetime_notify(local_spi, lifetime)));
    }
    // HASH(2) = prf(SKEYID_a, M-ID | Ni_b | <the payloads after it, with their headers>).
    let (_first, body) = isakmp::encode_payloads(&after);
    let mut hashed = quick.msgid.to_be_bytes().to_vec();
    hashed.extend_from_slice(&checked.ni);
    hashed.extend_from_slice(&body);
    let mut chain = vec![(payload::HASH, st.prf.mac(&st.skeyid_a, &hashed))];
    chain.extend(after);
    let (qm2_first_payload, qm2_plaintext) = isakmp::encode_payloads(&chain);
    let (qm2, qm2_last_block) =
        seal(st, quick.msgid, qm2_first_payload, &qm2_plaintext, &read.last_block).map_err(|_| Turn::Silent(Silence::NotBuilt, "message 2 could not be encrypted"))?;

    let keys = derive_keys(st, exp.cipher, pfs.as_ref().map(|(_, shared)| shared.as_slice()), &checked.ni, &nr, local_spi, checked.peer_spi);
    Ok(HeldQuick {
        msgid: quick.msgid,
        family: exp.family,
        fingerprint: quick.fingerprint,
        peer_spi: checked.peer_spi,
        local_spi,
        keys: HeldKeys(Some(keys)),
        lifetime,
        responder_lifetime_added,
        qm2,
        qm2_plaintext,
        qm2_first_payload,
        ni: checked.ni,
        nr,
        qm1_last_block: read.last_block.clone(),
        qm2_last_block,
        t_held: expected.now,
        commit_seen: quick.commit_seen || st.exchanges.commit_seen_for(quick.msgid, &quick.fingerprint),
    })
}

/// An inbound SPI for a new SA of ours: random, above [`SPI_RESERVED_MAX`] and none the tunnel holds, of ours or
/// of the gateway's; `None` after [`SPI_DRAWS`] draws that all were.
fn draw_spi(entropy: &mut impl Entropy, expected: &QuickExpectations<'_>) -> Option<u32> {
    (0..SPI_DRAWS)
        .map(|_| {
            let mut spi = [0u8; 4];
            entropy.fill(&mut spi);
            u32::from_be_bytes(spi)
        })
        .find(|spi| *spi > SPI_RESERVED_MAX && !expected.local_spis_in_use.contains(spi) && !expected.peer_spis_in_use.contains(spi))
}

/// The body of the RESPONDER-LIFETIME Notify that states `lifetime` for the SA whose inbound SPI of ours is
/// `local_spi` (RFC 2407 §4.6.3.1: the IPsec DOI, the chosen SA's Protocol ID, SPI size 4 with "the sender's
/// inbound IPSEC SPI", and an attribute list with the responder's lifetimes): every limit in force, seconds first.
fn responder_lifetime_notify(local_spi: u32, lifetime: SaLifetime) -> Vec<u8> {
    let mut attributes = vec![Attribute::short(esp_attr::LIFE_TYPE, life::SECONDS), Attribute::long_u32(esp_attr::LIFE_DURATION, lifetime.seconds)];
    if let Some(kilobytes) = lifetime.kilobytes {
        attributes.push(Attribute::short(esp_attr::LIFE_TYPE, life::KILOBYTES));
        attributes.push(Attribute::long_u32(esp_attr::LIFE_DURATION, kilobytes));
    }
    let data: Vec<u8> = attributes.iter().flat_map(Attribute::to_bytes).collect();
    informational::notify_body(protocol::ESP, &local_spi.to_be_bytes(), RESPONDER_LIFETIME, &data)
}

/// Encrypts the Quick Mode payload chain `plaintext`, whose first payload is of type `first`, under `iv`: the
/// message under `msgid`, and its last cipher block.
fn seal(st: &Phase1State, msgid: u32, first: u8, plaintext: &[u8], iv: &[u8]) -> Result<(Vec<u8>, Vec<u8>), IkeError> {
    let padded = crypto1::pad_to_block(plaintext, st.enc_block);
    let ciphertext = crypto1::cbc_encrypt(st.enc_block, &st.enc_key, iv, &padded)?;
    let last_block = crypto1::next_iv(&ciphertext, st.enc_block);
    let mut header = quick::qm_header(st.cky_i, st.cky_r, msgid);
    header.next_payload = first;
    header.flags |= flags::ENCRYPTION;
    header.length = u32::try_from(IsakmpHeader::LEN + ciphertext.len()).map_err(|_| IkeError::MalformedPayload("a message 2 longer than an ISAKMP message can be"))?;
    let mut message = header.to_bytes();
    message.extend_from_slice(&ciphertext);
    Ok((message, last_block))
}

/// The key material of both directions of the new SA (RFC 2409 §5.5): `KEYMAT = prf(SKEYID_d, [g(qm)^xy |]
/// protocol | SPI | Ni_b | Nr_b)`, the SPI of each direction the one its destination chose -- `local_spi` for the
/// inbound SA, `peer_spi` for the outbound one -- `ni` the gateway's nonce and `nr` this side's. The KEYMAT
/// buffers are wiped once split.
fn derive_keys(st: &Phase1State, cipher: SkCipher, shared: Option<&[u8]>, ni: &[u8], nr: &[u8], local_spi: u32, peer_spi: u32) -> RekeyedChild {
    let len = quick::esp_keymat_len(cipher);
    let keymat = |spi: u32| {
        Zeroizing::new(match shared {
            Some(shared) => crypto1::keymat_pfs(st.prf, &st.skeyid_d, shared, protocol::ESP, &spi.to_be_bytes(), ni, nr, len),
            None => crypto1::keymat(st.prf, &st.skeyid_d, protocol::ESP, &spi.to_be_bytes(), ni, nr, len),
        })
    };
    let material = |keymat: &[u8]| {
        let (enc, integ) = quick::split_esp_keymat(cipher, keymat);
        ChildKeyMaterial { cipher, enc: enc.to_vec(), integ: integ.to_vec() }
    };
    let (inbound, outbound) = (keymat(local_spi), keymat(peer_spi));
    RekeyedChild { local_spi, peer_spi, key_out: material(&outbound), key_in: material(&inbound) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;
    use std::io;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use crate::crypto::IntegAlgorithm;
    use crate::entropy::SeedEntropy;
    use crate::esp::EspSa;
    use crate::ikev1::exchange::{self as table, Classified, ExchangeTable, PEER_QUICK_WAIT};
    use crate::ikev1::informational::tests::phase1_pair;
    use crate::ikev1::msgid::{MID_CAP, RECONSIDER_GAP};
    use crate::ikev1::phase1::TestClock;
    use crate::ikev1::quick::QuickInitiator;
    use crate::ikev2::natt::wrap_ike_4500;
    use crate::transport::IkeSocket;

    /// This side's IPv4 selector (its assigned address) and the gateway's.
    const OURS_V4: ([u8; 4], [u8; 4]) = ([10, 212, 134, 202], [255, 255, 255, 255]);
    const GATEWAYS_V4: ([u8; 4], [u8; 4]) = ([10, 9, 0, 0], [255, 255, 0, 0]);

    fn ours_v6() -> (Ipv6Addr, u8) {
        ("fd00:1::2a".parse().unwrap(), 128)
    }

    fn gateways_v6() -> (Ipv6Addr, u8) {
        ("fd00:9::".parse().unwrap(), 64)
    }

    const GCM: SkCipher = SkCipher::Aes256Gcm;
    const CBC: SkCipher = SkCipher::Aes128Cbc(IntegAlgorithm::HmacSha2_256_128);

    /// The SPI the gateway proposes in the messages 1 these tests build field by field.
    const GATEWAY_SPI: u32 = 0x6A7E_0001;

    /// The private key of the gateway's KE in those messages.
    const GATEWAY_DH: [u8; 32] = [0x5A; 32];

    /// A client whose exchange table is on, telling the time by the clock returned, and its gateway; both
    /// floated to UDP 4500 when `floated`.
    fn pair(floated: bool) -> (Phase1State, Phase1State, TestClock) {
        let (mut client, mut gateway) = phase1_pair();
        client.floated = floated;
        gateway.floated = floated;
        let clock = TestClock::new();
        client.exchanges = clock.exchanges();
        client.finals = clock.finals();
        client.enable_gateway_quick_mode();
        (client, gateway, clock)
    }

    fn v4(cipher: SkCipher, pfs: Option<DhGroup>) -> ExpectedQuick {
        ExpectedQuick::ipv4(cipher, pfs, OURS_V4, GATEWAYS_V4, None)
    }

    fn v6(cipher: SkCipher, pfs: Option<DhGroup>) -> ExpectedQuick {
        ExpectedQuick::ipv6(cipher, pfs, ours_v6(), gateways_v6(), None)
    }

    /// The tunnel as the client holds it: its families and the SPIs in use.
    struct Tunnel {
        families: Vec<ExpectedQuick>,
        peer_spis: Vec<u32>,
        local_spis: Vec<u32>,
    }

    impl Tunnel {
        /// The SPIs in use are none of those the tests propose.
        fn of(families: Vec<ExpectedQuick>) -> Self {
            Self { families, peer_spis: vec![0x1111_0001, 0x2222_0002], local_spis: vec![0x3333_0003] }
        }

        fn expect(&self, now: Instant) -> QuickExpectations<'_> {
            QuickExpectations { families: &self.families, peer_spis_in_use: &self.peer_spis, local_spis_in_use: &self.local_spis, now }
        }
    }

    /// An entropy that counts what is drawn from it.
    struct Counting {
        inner: SeedEntropy,
        fills: usize,
    }

    impl Counting {
        fn new(seed: u64) -> Self {
            Self { inner: SeedEntropy::new(seed), fills: 0 }
        }
    }

    impl Entropy for Counting {
        fn fill(&mut self, out: &mut [u8]) {
            self.fills += 1;
            self.inner.fill(out);
        }
    }

    fn msgid_of(message: &[u8]) -> u32 {
        IsakmpHeader::parse(message).unwrap().message_id
    }

    /// `message` as a datagram of the client's socket: with the non-ESP marker once floated.
    fn on_the_wire(client: &Phase1State, message: &[u8]) -> Vec<u8> {
        if client.floated {
            wrap_ike_4500(message)
        } else {
            message.to_vec()
        }
    }

    /// What the client's readers keep of the gateway's `qm1`: it must go to the inbox, as its one entry.
    fn kept(client: &Phase1State, qm1: &[u8]) -> PeerQuick {
        let msgid = msgid_of(qm1);
        assert_eq!(table::classify(client, &on_the_wire(client, qm1), None), Classified::PeerQuick { msgid }, "the readers keep it");
        let mut entries = client.take_peer_quick_modes();
        assert_eq!(entries.len(), 1);
        entries.remove(0)
    }

    fn answer(client: &Phase1State, tunnel: &Tunnel, clock: &TestClock, quick: &PeerQuick) -> QuickVerdict {
        answer_quick(client, &mut SeedEntropy::new(0xC5A0), &tunnel.expect(clock.now()), quick)
    }

    fn accepted(verdict: QuickVerdict) -> Box<HeldQuick> {
        match verdict {
            QuickVerdict::Accept(held) => held,
            other => panic!("not accepted: {other:?}"),
        }
    }

    fn refused(verdict: QuickVerdict) -> Refusal {
        match verdict {
            QuickVerdict::Refuse(refusal) => refusal,
            other => panic!("not refused: {other:?}"),
        }
    }

    /// The payloads of message 2, as the gateway decrypts it under the last cipher block of `qm1`.
    fn qm2_payloads(gw: &Phase1State, qm1: &[u8], qm2: &[u8]) -> Vec<Payload> {
        let iv = crypto1::next_iv(&qm1[IsakmpHeader::LEN..], gw.enc_block);
        phase2::decrypt_payloads(qm2, &gw.enc_key, gw.enc_block, &iv).unwrap().1
    }

    /// The one SA payload of message 2.
    fn qm2_sa(gw: &Phase1State, qm1: &[u8], qm2: &[u8]) -> SaPayload {
        let payloads = qm2_payloads(gw, qm1, qm2);
        let mut sas = payloads.iter().filter(|p| p.payload_type == payload::SA);
        let sa = SaPayload::parse(&sas.next().unwrap().data).unwrap();
        assert!(sas.next().is_none());
        sa
    }

    /// The Notify of a refusal, as the gateway reads it: the Informational must authenticate (HASH(1) under its
    /// own Message ID, RFC 2409 §5.7) and carry nothing but it.
    fn refusal_notify(gw: &Phase1State, refusal: &Refusal) -> Vec<u8> {
        let header = IsakmpHeader::parse(&refusal.datagram).unwrap();
        assert_eq!((header.exchange_type, header.message_id, header.flags & flags::ENCRYPTION), (exchange::INFORMATIONAL, refusal.msgid, flags::ENCRYPTION));
        let iv0 = crypto1::phase2_iv(gw.prf, &gw.phase1_iv, refusal.msgid, gw.enc_block);
        let (_h, payloads, _) = phase2::parse_encrypted(&refusal.datagram, gw.prf, &gw.skeyid_a, &gw.enc_key, gw.enc_block, &iv0).expect("the refusal authenticates");
        let types: Vec<u8> = payloads.iter().map(|p| p.payload_type).collect();
        assert_eq!(types, [payload::HASH, payload::NOTIFY]);
        payloads[1].data.clone()
    }

    /// An ID payload body.
    fn id(id_type: u8, protocol: u8, port: u16, data: &[u8]) -> Vec<u8> {
        Id { id_type, protocol, port, data: data.to_vec() }.to_bytes()
    }

    /// A message 1 of the gateway's, field by field, for a test to change before it is built.
    #[derive(Clone)]
    struct Qm1 {
        msgid: u32,
        sas: Vec<SaPayload>,
        ni: Vec<u8>,
        ke: Option<Vec<u8>>,
        ids: Vec<Vec<u8>>,
        /// Payloads after the identities.
        extra: Vec<(u8, Vec<u8>)>,
        /// The payloads after the HASH, in place of those the fields above make, when set.
        replaced: Option<Vec<(u8, Vec<u8>)>>,
        /// Header flags besides ENCRYPTION.
        flags: u8,
        /// Whether the ISAKMP SA it goes on floated to UDP 4500: the tests make their pair so.
        floated: bool,
    }

    impl Qm1 {
        /// [`Self::rekeying_on`] an ISAKMP SA that did not float.
        fn rekeying(exp: &ExpectedQuick, seed: u64) -> Self {
            Self::rekeying_on(false, exp, seed)
        }

        /// What a gateway sends to rekey the SA of `exp` on an ISAKMP SA that `floated` or not: its suite, the
        /// encapsulation mode of the ISAKMP SA, 3600 s, its selectors (IDci the gateway's), the SPI
        /// [`GATEWAY_SPI`] and, with PFS, a KE of [`GATEWAY_DH`]; Message ID and nonce drawn from `seed`.
        fn rekeying_on(floated: bool, exp: &ExpectedQuick, seed: u64) -> Self {
            let mut entropy = SeedEntropy::new(seed);
            let msgid = msgid::draw(&mut entropy);
            let mut ni = vec![0u8; 16];
            entropy.fill(&mut ni);
            let encap = if floated { UDP_ENCAP_TUNNEL } else { ENCAP_TUNNEL };
            let transform = quick::esp_transform(1, exp.cipher, exp.pfs_group, encap, 3600);
            let proposal = Proposal { num: 1, protocol_id: protocol::ESP, spi: GATEWAY_SPI.to_be_bytes().to_vec(), transforms: vec![transform] };
            let sa = SaPayload { doi: IPSEC_DOI, situation: SIT_IDENTITY_ONLY, proposals: vec![proposal] };
            let ke = exp.pfs_group.map(|group| group.public(&GATEWAY_DH));
            Self { msgid, sas: vec![sa], ni, ke, ids: vec![exp.gateway_selector.clone(), exp.our_selector.clone()], extra: Vec::new(), replaced: None, flags: 0, floated }
        }

        fn proposal(&mut self) -> &mut Proposal {
            &mut self.sas[0].proposals[0]
        }

        fn transform(&mut self) -> &mut Transform {
            &mut self.proposal().transforms[0]
        }

        fn set_attribute(&mut self, attr_type: u16, value: u16) {
            let attributes = &mut self.transform().attributes;
            attributes.retain(|a| a.attr_type != attr_type);
            attributes.push(Attribute::short(attr_type, value));
        }

        fn payloads(&self) -> Vec<(u8, Vec<u8>)> {
            if let Some(replaced) = &self.replaced {
                return replaced.clone();
            }
            let mut out: Vec<(u8, Vec<u8>)> = self.sas.iter().map(|sa| (payload::SA, sa.to_bytes())).collect();
            out.push((payload::NONCE, self.ni.clone()));
            out.extend(self.ke.iter().map(|ke| (payload::KE, ke.clone())));
            out.extend(self.ids.iter().map(|id| (payload::ID, id.clone())));
            out.extend(self.extra.iter().cloned());
            out
        }

        /// The message under `gw`'s keys, HASH(1) over every payload after it but a HASH -- what the client
        /// verifies (`phase2::parse_encrypted`).
        fn message(&self, gw: &Phase1State) -> Vec<u8> {
            let after = self.payloads();
            let hashed: Vec<(u8, Vec<u8>)> = after.iter().filter(|(t, _)| *t != payload::HASH).cloned().collect();
            let (_first, body) = isakmp::encode_payloads(&hashed);
            let mut input = self.msgid.to_be_bytes().to_vec();
            input.extend_from_slice(&body);
            let mut all = vec![(payload::HASH, gw.prf.mac(&gw.skeyid_a, &input))];
            all.extend(after);
            let mut header = quick::qm_header(gw.cky_i, gw.cky_r, self.msgid);
            header.flags = self.flags;
            let iv0 = crypto1::phase2_iv(gw.prf, &gw.phase1_iv, self.msgid, gw.enc_block);
            phase2::encrypt_payloads(header, &gw.enc_key, gw.enc_block, &iv0, &all).unwrap().0
        }
    }

    // ---- Accepted: message 2 and the keys ----

    /// A gateway's rekey of the SA held -- IPv4 and IPv6, with PFS and without, floated and not, AES-GCM and
    /// AES-CBC with HMAC -- built by the gateway-side initiator, is accepted: message 2 is held, not sent; the
    /// initiator takes it (HASH(2), the SA as offered, the identities echoed); the message 3 it answers with
    /// carries the HASH(3) of the nonces held, under the last cipher block of message 2; and what either side
    /// seals with its keys the other opens, both ways.
    #[test]
    fn a_gateway_rekey_of_the_sa_held_is_answered_and_both_directions_interoperate() {
        let rows: [(&str, bool, SkCipher, Option<DhGroup>, bool); 6] = [
            ("IPv4, AES-GCM, no PFS", false, GCM, None, false),
            ("IPv4, AES-CBC + HMAC-SHA2-256, PFS MODP-1024", false, CBC, Some(DhGroup::Modp1024), false),
            ("IPv4, AES-GCM, PFS X25519, floated", false, GCM, Some(DhGroup::X25519), true),
            ("IPv6, AES-GCM, no PFS, floated", true, GCM, None, true),
            ("IPv6, AES-CBC + HMAC-SHA2-256, PFS ECP-256", true, CBC, Some(DhGroup::EcpP256), false),
            ("IPv6, AES-CBC + HMAC-SHA2-256, no PFS", true, CBC, None, false),
        ];
        for (n, (what, ipv6, cipher, pfs, floated)) in rows.into_iter().enumerate() {
            let (client, gw, clock) = pair(floated);
            clock.advance(Duration::from_secs(3));
            let tunnel = Tunnel::of(vec![v4(cipher, pfs), v6(cipher, pfs)]);
            let mut ge = SeedEntropy::new(0x5000 + n as u64);
            let (qm1, qi) = if ipv6 {
                quick::initiate_quick_ipv6(&gw, &mut ge, cipher, gateways_v6(), ours_v6(), pfs, 3600).unwrap()
            } else {
                quick::initiate_quick_with_pfs(&gw, &mut ge, cipher, GATEWAYS_V4, OURS_V4, pfs, 3600).unwrap()
            };
            let quick = kept(&client, &qm1);
            // The caller's clock, not the table's: what the keys are dated by.
            let now = clock.now() + Duration::from_millis(250);
            let mut held = accepted(answer_quick(&client, &mut SeedEntropy::new(0xC5A0), &tunnel.expect(now), &quick));
            let offered = SaPayload::parse(&quick_payload(&gw, &qm1, payload::SA)).unwrap();
            let offered_spi = u32::from_be_bytes(offered.proposals[0].spi.as_slice().try_into().unwrap());
            assert_eq!((held.msgid(), held.family(), held.peer_spi(), held.t_held()), (msgid_of(&qm1), if ipv6 { ChildFamily::Ipv6 } else { ChildFamily::Primary }, offered_spi, now), "{what}");
            assert!(held.local_spi() > SPI_RESERVED_MAX && !tunnel.local_spis.contains(&held.local_spi()), "{what}");
            assert_eq!((held.lifetime(), held.responder_lifetime_added(), held.commit_seen()), (SaLifetime { seconds: 3600, kilobytes: None }, false, false), "{what}");
            assert_eq!(held.qm1_last_block(), crypto1::next_iv(&qm1[IsakmpHeader::LEN..], client.enc_block).as_slice(), "{what}");
            assert_eq!(held.ni(), quick_payload(&gw, &qm1, payload::NONCE).as_slice(), "{what}");
            assert_eq!(held.nr().len(), NR_LEN, "{what}");
            // The plaintext kept is what message 2 encrypts, padding apart.
            let decrypted = crypto1::cbc_decrypt(client.enc_block, &client.enc_key, held.qm1_last_block(), &held.qm2()[IsakmpHeader::LEN..]).unwrap();
            assert_eq!(&decrypted[..held.qm2_plaintext().len()], held.qm2_plaintext(), "{what}");
            assert_eq!(IsakmpHeader::parse(held.qm2()).unwrap().next_payload, held.qm2_first_payload(), "{what}");
            assert_eq!(client.exchanges.id_record(held.msgid()).map(|r| r.state), Some(MidState::Active { deadline: clock.now() + PEER_QUICK_WAIT }), "{what}: still in progress");

            let (qm3, mut theirs, lifetime) = qi.complete_with_lifetime(held.qm2()).unwrap_or_else(|e| panic!("{what}: the initiator refused message 2: {e}"));
            assert_eq!(lifetime, SaLifetime { seconds: 3600, kilobytes: None }, "{what}");
            let (_h, ps, _) = phase2::decrypt_payloads(&qm3, &client.enc_key, client.enc_block, held.qm2_last_block()).unwrap();
            assert_eq!(ps[0].data, quick::hash3(client.prf, &client.skeyid_a, held.msgid(), held.ni(), held.nr()), "{what}: HASH(3) of the nonces held");

            let keys = held.take_keys().expect("the keys, once");
            assert!(held.take_keys().is_none() && !held.keys_held(), "{what}: moved out once");
            assert_eq!((keys.local_spi, keys.peer_spi), (held.local_spi(), held.peer_spi()), "{what}");
            assert_eq!((theirs.outbound.spi(), theirs.inbound.spi()), (keys.local_spi, keys.peer_spi), "{what}");
            let mut ours_out = EspSa::new_with_cipher(keys.peer_spi, keys.key_out.cipher, &keys.key_out.enc, &keys.key_out.integ).unwrap();
            let mut ours_in = EspSa::new_with_cipher(keys.local_spi, keys.key_in.cipher, &keys.key_in.enc, &keys.key_in.integ).unwrap();
            let packet: Vec<u8> = (0..60u8).collect();
            assert_eq!(theirs.inbound.open(&ours_out.seal(&packet, 4).unwrap()).unwrap(), (packet.clone(), 4), "{what}: ours to theirs");
            assert_eq!(ours_in.open(&theirs.outbound.seal(&packet, 41).unwrap()).unwrap(), (packet, 41), "{what}: theirs to ours");
        }
    }

    /// The body of the first payload of `payload_type` in the gateway's message 1.
    fn quick_payload(gw: &Phase1State, qm1: &[u8], payload_type: u8) -> Vec<u8> {
        let iv0 = crypto1::phase2_iv(gw.prf, &gw.phase1_iv, msgid_of(qm1), gw.enc_block);
        let (_h, payloads, _) = phase2::parse_encrypted(qm1, gw.prf, &gw.skeyid_a, &gw.enc_key, gw.enc_block, &iv0).unwrap();
        payloads.into_iter().find(|p| p.payload_type == payload_type).unwrap().data
    }

    /// This side's /32 (/128) selector sent by the gateway as that one address -- what strongSwan sends -- is
    /// accepted, for IPv4 and IPv6, and both identities are echoed byte for byte: the gateway-side initiator,
    /// which offered them so, takes message 2.
    #[test]
    fn this_sides_selector_sent_as_one_address_is_accepted_and_echoed_as_sent() {
        let rows: [(&str, bool); 2] = [("IPv4", false), ("IPv6", true)];
        for (what, ipv6) in rows {
            let (client, gw, clock) = pair(false);
            let tunnel = Tunnel::of(vec![v4(GCM, None), v6(GCM, None)]);
            let (idci, idcr) = if ipv6 {
                (quick::ts_id_v6(gateways_v6().0, gateways_v6().1), id(id_type::IPV6_ADDR, 0, 0, &ours_v6().0.octets()))
            } else {
                (quick::ts_id(GATEWAYS_V4.0, GATEWAYS_V4.1), id(id_type::IPV4_ADDR, 0, 0, &OURS_V4.0))
            };
            let (qm1, qi) = quick::initiate_quick_with_ids(&gw, &mut SeedEntropy::new(0x5100), GCM, idci.clone(), idcr.clone(), None, 3600).unwrap();
            let held = accepted(answer(&client, &tunnel, &clock, &kept(&client, &qm1)));
            let echoed: Vec<Vec<u8>> = qm2_payloads(&gw, &qm1, held.qm2()).into_iter().filter(|p| p.payload_type == payload::ID).map(|p| p.data).collect();
            assert_eq!(echoed, [idci, idcr], "{what}");
            qi.complete_with_lifetime(held.qm2()).unwrap_or_else(|e| panic!("{what}: {e}"));
        }
    }

    /// The SA of message 2 is the proposal and transform taken, their numbers kept (RFC 2408 §4.2), this side's
    /// SPI, and the attributes of the transform exactly as offered -- the second one here, after one of another
    /// suite.
    #[test]
    fn message_2_keeps_the_numbers_and_the_attributes_of_the_transform_taken() {
        let (client, gw, clock) = pair(false);
        let exp = v4(GCM, None);
        let tunnel = Tunnel::of(vec![exp.clone()]);
        let mut qm1 = Qm1::rekeying(&exp, 0x5200);
        let mut other = quick::esp_transform(3, CBC, None, ENCAP_TUNNEL, 3600);
        other.num = 3;
        qm1.transform().num = 5;
        qm1.transform().attributes.push(Attribute::short(esp_attr::LIFE_TYPE, life::KILOBYTES));
        qm1.transform().attributes.push(Attribute::long_u32(esp_attr::LIFE_DURATION, 4_000_000));
        let offered = qm1.transform().clone();
        qm1.proposal().num = 7;
        qm1.proposal().transforms.insert(0, other);
        let message = qm1.message(&gw);
        let held = accepted(answer(&client, &tunnel, &clock, &kept(&client, &message)));
        let sa = qm2_sa(&gw, &message, held.qm2());
        assert_eq!((sa.doi, sa.situation), (IPSEC_DOI, SIT_IDENTITY_ONLY));
        let [proposal] = sa.proposals.as_slice() else { panic!("one proposal: {sa:?}") };
        assert_eq!((proposal.num, proposal.protocol_id, proposal.spi.as_slice()), (7, protocol::ESP, held.local_spi().to_be_bytes().as_slice()));
        assert_eq!(proposal.transforms, [offered]);
        assert_eq!(held.lifetime(), SaLifetime { seconds: 3600, kilobytes: Some(4_000_000) });
    }

    /// The inbound SPI drawn for the new SA is none the tunnel holds, of ours or of the gateway's: a draw that is
    /// one is drawn again. Entropy that gives nothing but SPIs not to be taken (0 here), [`SPI_DRAWS`] times, is a
    /// silence that leaves the exchange in progress (a passing failure, before anything was sent).
    #[test]
    fn the_inbound_spi_drawn_is_none_in_use_and_the_draws_give_up_after_a_bound() {
        let first_draw = |seed: u64| {
            let mut spi = [0u8; 4];
            SeedEntropy::new(seed).fill(&mut spi);
            u32::from_be_bytes(spi)
        };
        for (what, ours) in [("one of this side's", true), ("one of the gateway's", false)] {
            let (client, gw, clock) = pair(false);
            let mut tunnel = Tunnel::of(vec![plain()]);
            let taken = first_draw(0x5E00);
            assert!(taken > SPI_RESERVED_MAX && taken != GATEWAY_SPI);
            if ours {
                tunnel.local_spis.push(taken);
            } else {
                tunnel.peer_spis.push(taken);
            }
            let message = Qm1::rekeying(&plain(), 0x5E01).message(&gw);
            let held = accepted(answer_quick(&client, &mut SeedEntropy::new(0x5E00), &tunnel.expect(clock.now()), &kept(&client, &message)));
            assert_ne!(held.local_spi(), taken, "{what}");
        }
        struct Zeros(usize);
        impl Entropy for Zeros {
            fn fill(&mut self, out: &mut [u8]) {
                self.0 += 1;
                out.fill(0);
            }
        }
        let (client, gw, clock) = pair(false);
        let message = Qm1::rekeying(&plain(), 0x5E02).message(&gw);
        let quick = kept(&client, &message);
        let mut zeros = Zeros(0);
        let verdict = answer_quick(&client, &mut zeros, &Tunnel::of(vec![plain()]).expect(clock.now()), &quick);
        assert!(matches!(verdict, QuickVerdict::Silent(Silence::NoFreeSpi)), "{verdict:?}");
        assert_eq!(zeros.0, SPI_DRAWS);
        assert!(matches!(client.exchanges.id_record(quick.msgid).map(|record| record.state), Some(MidState::Active { .. })));
    }

    // ---- Refused or not answered ----

    /// What `answer_quick` decided.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Want {
        Accepted,
        Refused(RefusalNotify),
        Silent(Silence),
    }

    type Build = fn() -> (Vec<ExpectedQuick>, Qm1);

    /// The tunnel `exp` holds, and the gateway's rekey of it, changed by `edit`.
    fn rekey_of(exp: ExpectedQuick, edit: impl FnOnce(&mut Qm1)) -> (Vec<ExpectedQuick>, Qm1) {
        rekey_on(false, exp, edit)
    }

    /// [`rekey_of`] on an ISAKMP SA that `floated` or not.
    fn rekey_on(floated: bool, exp: ExpectedQuick, edit: impl FnOnce(&mut Qm1)) -> (Vec<ExpectedQuick>, Qm1) {
        let mut qm1 = Qm1::rekeying_on(floated, &exp, 0x5300);
        edit(&mut qm1);
        (vec![exp], qm1)
    }

    /// The tunnel `held` holds, and a gateway's offer made for `offered` instead.
    fn offer_for(held: ExpectedQuick, offered: ExpectedQuick) -> (Vec<ExpectedQuick>, Qm1) {
        (vec![held], Qm1::rekeying(&offered, 0x5300))
    }

    fn plain() -> ExpectedQuick {
        v4(GCM, None)
    }

    fn with_pfs() -> ExpectedQuick {
        v4(GCM, Some(DhGroup::Modp1024))
    }

    /// Every message 1 the readers keep is accepted, refused with the one Notify its fault calls for, or not
    /// answered, as listed; a refusal leaves the exchange refused in the ledger and the Notify the gateway reads
    /// is of the type given; a silence draws nothing from the entropy (no SPI, no Notify) and leaves the exchange
    /// in progress (a family with no current SA among them), but our own offer sent back and an SPI not to be
    /// taken, which end it as refused.
    #[test]
    fn a_gateway_message_1_is_accepted_refused_or_not_answered_by_what_it_says() {
        use RefusalNotify::*;
        let cases: Vec<(&str, Build, Want)> = vec![
            ("the suite and selectors held", || rekey_of(plain(), |_| {}), Want::Accepted),
            ("the suite and selectors held, PFS", || rekey_of(with_pfs(), |_| {}), Want::Accepted),
            ("the suite and selectors held, IPv6 with PFS", || rekey_of(v6(CBC, Some(DhGroup::Modp1024)), |_| {}), Want::Accepted),
            // The suite (RFC 2408 §5.4).
            ("another cipher", || offer_for(plain(), v4(CBC, None)), Want::Refused(NoProposalChosen)),
            ("another key length", || offer_for(plain(), v4(SkCipher::Aes128Gcm, None)), Want::Refused(NoProposalChosen)),
            ("another integrity algorithm", || offer_for(v4(CBC, None), v4(SkCipher::Aes128Cbc(IntegAlgorithm::HmacSha1_96), None)), Want::Refused(NoProposalChosen)),
            ("PFS held, none offered", || offer_for(with_pfs(), plain()), Want::Refused(NoProposalChosen)),
            ("PFS offered, none held", || offer_for(plain(), with_pfs()), Want::Refused(NoProposalChosen)),
            ("another PFS group", || offer_for(with_pfs(), v4(GCM, Some(DhGroup::Modp2048))), Want::Refused(NoProposalChosen)),
            ("a KE shorter than its group's", || rekey_of(with_pfs(), |q| { q.ke.as_mut().unwrap().pop(); }), Want::Refused(NoProposalChosen)),
            ("transport mode", || rekey_of(plain(), |q| q.set_attribute(esp_attr::ENCAP_MODE, 2)), Want::Refused(NoProposalChosen)),
            // The encapsulation mode is the ISAKMP SA's (RFC 3947 §5.1, RFC 2407 §4.5).
            ("the suite and selectors held, floated", || rekey_on(true, plain(), |_| {}), Want::Accepted),
            ("UDP-Encapsulated-Transport", || rekey_on(true, plain(), |q| q.set_attribute(esp_attr::ENCAP_MODE, 4)), Want::Refused(NoProposalChosen)),
            ("tunnel mode 1 on a floated tunnel", || rekey_on(true, plain(), |q| q.set_attribute(esp_attr::ENCAP_MODE, ENCAP_TUNNEL)), Want::Refused(NoProposalChosen)),
            ("UDP-Encapsulated-Tunnel on a tunnel not floated", || rekey_of(plain(), |q| q.set_attribute(esp_attr::ENCAP_MODE, UDP_ENCAP_TUNNEL)), Want::Refused(NoProposalChosen)),
            ("the drafts' encapsulation mode 61443", || rekey_on(true, plain(), |q| q.set_attribute(esp_attr::ENCAP_MODE, 61443)), Want::Refused(NoProposalChosen)),
            ("no encapsulation mode", || rekey_of(plain(), |q| q.transform().attributes.retain(|a| a.attr_type != esp_attr::ENCAP_MODE)), Want::Refused(NoProposalChosen)),
            ("an attribute the suite does not have", || rekey_of(plain(), |q| q.set_attribute(7, 1)), Want::Refused(NoProposalChosen)),
            // The SA payload.
            ("two SA payloads", || rekey_of(plain(), |q| q.sas.push(q.sas[0].clone())), Want::Refused(NoProposalChosen)),
            ("two proposals", || rekey_of(plain(), |q| { let mut second = q.proposal().clone(); second.num = 2; q.sas[0].proposals.push(second); }), Want::Refused(NoProposalChosen)),
            ("two proposals under one number (ESP and AH)", || rekey_of(plain(), |q| { let mut ah = q.proposal().clone(); ah.protocol_id = 2; q.sas[0].proposals.push(ah); }), Want::Refused(NoProposalChosen)),
            ("a proposal for AH", || rekey_of(plain(), |q| q.proposal().protocol_id = 2), Want::Refused(NoProposalChosen)),
            ("an ESP SPI of eight octets", || rekey_of(plain(), |q| q.proposal().spi = vec![0x6A; 8]), Want::Refused(NoProposalChosen)),
            ("another DOI", || rekey_of(plain(), |q| q.sas[0].doi = 2), Want::Refused(NoProposalChosen)),
            ("another situation", || rekey_of(plain(), |q| q.sas[0].situation = 2), Want::Refused(NoProposalChosen)),
            ("an SA with no proposal", || rekey_of(plain(), |q| q.sas[0].proposals.clear()), Want::Refused(BadProposalSyntax)),
            ("a proposal with no transform", || rekey_of(plain(), |q| q.proposal().transforms.clear()), Want::Refused(BadProposalSyntax)),
            ("an SA payload cut short", || rekey_of(plain(), |q| { let mut p = q.payloads(); p[0].1.truncate(10); q.replaced = Some(p); }), Want::Refused(BadProposalSyntax)),
            ("the suite's transform with a Life Type and no Duration", || rekey_of(plain(), |q| q.transform().attributes.retain(|a| a.attr_type != esp_attr::LIFE_DURATION)), Want::Refused(BadProposalSyntax)),
            ("the suite as the second transform, after another", || rekey_of(plain(), |q| { let other = quick::esp_transform(1, CBC, None, ENCAP_TUNNEL, 3600); q.transform().num = 2; q.proposal().transforms.insert(0, other); }), Want::Accepted),
            ("no lifetime attribute", || rekey_of(plain(), |q| q.transform().attributes.retain(|a| !LIFETIME_ATTRS.contains(&a.attr_type))), Want::Accepted),
            // Structure (RFC 2409 §5.5).
            ("New Group Mode's shape: a HASH and an SA alone", || rekey_of(plain(), |q| q.replaced = Some(vec![(payload::SA, q.sas[0].to_bytes())])), Want::Refused(PayloadMalformed)),
            ("no Nonce", || rekey_of(plain(), |q| { let p = q.payloads().into_iter().filter(|(t, _)| *t != payload::NONCE).collect(); q.replaced = Some(p); }), Want::Refused(PayloadMalformed)),
            ("two Nonces", || rekey_of(plain(), |q| q.extra.push((payload::NONCE, vec![9; 16]))), Want::Refused(PayloadMalformed)),
            ("a nonce of seven octets", || rekey_of(plain(), |q| q.ni.truncate(7)), Want::Refused(PayloadMalformed)),
            ("a nonce of 257 octets", || rekey_of(plain(), |q| q.ni.resize(257, 1)), Want::Refused(PayloadMalformed)),
            ("a second HASH", || rekey_of(plain(), |q| q.extra.push((payload::HASH, vec![0; 32]))), Want::Refused(PayloadMalformed)),
            ("two KEs", || rekey_of(with_pfs(), |q| q.extra.push((payload::KE, DhGroup::Modp1024.public(&[7; 32])))), Want::Refused(PayloadMalformed)),
            ("a KE with no PFS group", || rekey_of(plain(), |q| q.ke = Some(DhGroup::Modp1024.public(&GATEWAY_DH))), Want::Refused(PayloadMalformed)),
            ("a PFS group with no KE", || rekey_of(with_pfs(), |q| q.ke = None), Want::Refused(PayloadMalformed)),
            ("a KE value its group refuses", || rekey_of(with_pfs(), |q| { let mut one = vec![0u8; 128]; one[127] = 1; q.ke = Some(one); }), Want::Refused(PayloadMalformed)),
            ("one client identity", || rekey_of(plain(), |q| q.ids.truncate(1)), Want::Refused(PayloadMalformed)),
            ("three client identities", || rekey_of(plain(), |q| q.ids.push(q.ids[1].clone())), Want::Refused(PayloadMalformed)),
            ("a NAT-OA pair, a status Notify, a Vendor ID and a payload of an unknown type", || rekey_of(plain(), |q| {
                q.extra = vec![
                    (payload::NAT_OA, id(id_type::IPV4_ADDR, 0, 0, &[192, 0, 2, 7])),
                    (payload::NAT_OA, id(id_type::IPV4_ADDR, 0, 0, &[198, 51, 100, 9])),
                    (payload::NOTIFY, informational::notify_body(protocol::ESP, &GATEWAY_SPI.to_be_bytes(), 24578, &[])),
                    (payload::VENDOR_ID, vec![0xAF; 16]),
                    (200, vec![1, 2, 3]),
                ];
            }), Want::Accepted),
            // The identities (RFC 2409 §5.5, RFC 2407 §4.6.2).
            ("no client identities", || rekey_of(plain(), |q| q.ids.clear()), Want::Refused(InvalidIdInformation)),
            ("IDci and IDcr swapped: an offer of this side's sent back", || rekey_of(plain(), |q| q.ids.swap(0, 1)), Want::Silent(Silence::Reflection)),
            ("IDci this side's address as one address, IDcr the gateway's", || rekey_of(plain(), |q| q.ids = vec![id(id_type::IPV4_ADDR, 0, 0, &OURS_V4.0), quick::ts_id(GATEWAYS_V4.0, GATEWAYS_V4.1)]), Want::Refused(InvalidIdInformation)),
            ("a wider IDci", || rekey_of(plain(), |q| q.ids[0] = quick::ts_id([10, 0, 0, 0], [255, 0, 0, 0])), Want::Refused(InvalidIdInformation)),
            ("IDci as one address of the gateway's side", || rekey_of(plain(), |q| q.ids[0] = id(id_type::IPV4_ADDR, 0, 0, &[10, 9, 0, 1])), Want::Refused(InvalidIdInformation)),
            ("IDci as one address, the gateway's side a /32", || {
                let exp = ExpectedQuick::ipv4(GCM, None, OURS_V4, ([10, 9, 0, 1], [255; 4]), None);
                rekey_of(exp, |q| q.ids[0] = id(id_type::IPV4_ADDR, 0, 0, &[10, 9, 0, 1]))
            }, Want::Refused(InvalidIdInformation)),
            ("the gateway's side a /32, as a subnet", || rekey_of(ExpectedQuick::ipv4(GCM, None, OURS_V4, ([10, 9, 0, 1], [255; 4]), None), |_| {}), Want::Accepted),
            ("IDcr this side's address as one address", || rekey_of(plain(), |q| q.ids[1] = id(id_type::IPV4_ADDR, 0, 0, &OURS_V4.0)), Want::Accepted),
            ("IDcr another address", || rekey_of(plain(), |q| q.ids[1] = id(id_type::IPV4_ADDR, 0, 0, &[10, 212, 134, 203])), Want::Refused(InvalidIdInformation)),
            ("IDcr of an address cut short", || rekey_of(plain(), |q| q.ids[1] = id(id_type::IPV4_ADDR, 0, 0, &OURS_V4.0[..3])), Want::Refused(InvalidIdInformation)),
            ("IDcr limited to UDP", || rekey_of(plain(), |q| q.ids[1] = id(id_type::IPV4_ADDR_SUBNET, 17, 0, &[10, 212, 134, 202, 255, 255, 255, 255])), Want::Refused(InvalidIdInformation)),
            ("IDci limited to a port", || rekey_of(plain(), |q| q.ids[0] = id(id_type::IPV4_ADDR_SUBNET, 0, 500, &[10, 9, 0, 0, 255, 255, 0, 0])), Want::Refused(InvalidIdInformation)),
            ("IDci an address range", || rekey_of(plain(), |q| q.ids[0] = id(ID_IPV4_ADDR_RANGE, 0, 0, &[10, 9, 0, 0, 10, 9, 255, 255])), Want::Refused(InvalidIdInformation)),
            ("IDci with host bits set", || rekey_of(plain(), |q| q.ids[0] = quick::ts_id([10, 9, 1, 0], [255, 255, 0, 0])), Want::Refused(InvalidIdInformation)),
            ("IDci with host bits set, as the tunnel's own selector is written", || rekey_of(ExpectedQuick::ipv4(GCM, None, OURS_V4, ([10, 9, 1, 0], [255, 255, 0, 0]), None), |_| {}), Want::Refused(InvalidIdInformation)),
            ("IDci a name", || rekey_of(plain(), |q| q.ids[0] = id(id_type::FQDN, 0, 0, b"gw.example")), Want::Refused(InvalidIdInformation)),
            ("IPv6 identities on a tunnel without IPv6", || { let (_, q) = rekey_of(v6(GCM, None), |_| {}); (vec![plain()], q) }, Want::Refused(InvalidIdInformation)),
            ("IDci IPv4 and IDcr IPv6", || rekey_of(plain(), |q| q.ids[1] = quick::ts_id_v6(ours_v6().0, 128)), Want::Refused(InvalidIdInformation)),
            ("the IPv6 selectors on the IPv4 family's entry", || rekey_of(plain(), |q| q.ids = vec![quick::ts_id_v6(gateways_v6().0, 64), quick::ts_id_v6(ours_v6().0, 128)]), Want::Refused(InvalidIdInformation)),
            ("IPv6: IDci as one address, the gateway's side a /128", || {
                let host: Ipv6Addr = "fd00:9::1".parse().unwrap();
                rekey_of(ExpectedQuick::ipv6(GCM, None, ours_v6(), (host, 128), None), |q| q.ids[0] = id(id_type::IPV6_ADDR, 0, 0, &host.octets()))
            }, Want::Refused(InvalidIdInformation)),
            ("IPv6: the gateway's side a /128, as a subnet", || rekey_of(ExpectedQuick::ipv6(GCM, None, ours_v6(), ("fd00:9::1".parse().unwrap(), 128), None), |_| {}), Want::Accepted),
            ("IPv6: IDcr limited to a port", || rekey_of(v6(GCM, None), |q| {
                let mut idcr = Id::parse(&q.ids[1]).unwrap();
                idcr.port = 500;
                q.ids[1] = idcr.to_bytes();
            }), Want::Refused(InvalidIdInformation)),
            // A family configured with no current SA (D7, D9): a passing silence, never a refusal.
            ("IPv6 configured with no current SA: a rekey of it", || {
                let (_, q) = rekey_of(v6(GCM, None), |_| {});
                (vec![plain(), v6(GCM, None).answerable(false)], q)
            }, Want::Silent(Silence::FamilyNotReady)),
            ("IPv6 configured with no current SA: a rekey of IPv4", || (vec![plain(), v6(GCM, None).answerable(false)], Qm1::rekeying(&plain(), 0x5300)), Want::Accepted),
            ("the family with no current SA, offered in a mode this side would refuse", || rekey_of(plain().answerable(false), |q| q.set_attribute(esp_attr::ENCAP_MODE, 2)), Want::Silent(Silence::FamilyNotReady)),
            // The SPI proposed (POLICY).
            ("the SPI 0", || rekey_of(plain(), |q| q.proposal().spi = vec![0; 4]), Want::Silent(Silence::InvalidSpi)),
            ("the SPI 255", || rekey_of(plain(), |q| q.proposal().spi = 255u32.to_be_bytes().to_vec()), Want::Silent(Silence::InvalidSpi)),
            ("the SPI 256", || rekey_of(plain(), |q| q.proposal().spi = 256u32.to_be_bytes().to_vec()), Want::Accepted),
            ("the SPI of an SA the tunnel holds", || rekey_of(plain(), |q| q.proposal().spi = 0x2222_0002u32.to_be_bytes().to_vec()), Want::Silent(Silence::InvalidSpi)),
        ];
        let mut wrong = Vec::new();
        for (what, build, want) in cases {
            let (families, qm1) = build();
            let (client, gw, clock) = pair(qm1.floated);
            let tunnel = Tunnel::of(families);
            let message = qm1.message(&gw);
            let quick = kept(&client, &message);
            let mut entropy = Counting::new(0x5301);
            let verdict = answer_quick(&client, &mut entropy, &tunnel.expect(clock.now()), &quick);
            let got = match &verdict {
                QuickVerdict::Accept(_) => Want::Accepted,
                QuickVerdict::Refuse(refusal) => Want::Refused(refusal.notify),
                QuickVerdict::Silent(silence) => Want::Silent(*silence),
            };
            if got != want {
                wrong.push(format!("{what}: {verdict:?}, not {want:?}"));
                continue;
            }
            let state = client.exchanges.id_record(qm1.msgid).map(|record| record.state);
            let ended = matches!(want, Want::Refused(_) | Want::Silent(Silence::Reflection | Silence::InvalidSpi));
            if ended != (state == Some(MidState::Refused)) {
                wrong.push(format!("{what}: the ledger holds the exchange as {state:?}"));
            }
            match verdict {
                QuickVerdict::Refuse(refusal) => {
                    let notify = refusal_notify(&gw, &refusal);
                    if notify.get(6..8) != Some(&refusal.notify.notify_type().to_be_bytes()[..]) || refusal.refused_msgid != qm1.msgid || refusal.repeat {
                        wrong.push(format!("{what}: the Notify sent is {notify:?}"));
                    }
                }
                QuickVerdict::Silent(_) if entropy.fills != 0 => wrong.push(format!("{what}: {} draws for a silence", entropy.fills)),
                _ => {}
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }

    /// An entry that holds no authenticated message 1 of this ISAKMP SA under its Message ID, or not the one it
    /// was read as, or one the ledger holds as no exchange in progress, is not answered: nothing is drawn, the
    /// ledger and the refusals kept do not change.
    #[test]
    fn an_entry_that_is_not_an_authenticated_message_1_in_progress_is_not_answered() {
        type Entry = fn(&Phase1State, &Phase1State, &TestClock) -> PeerQuick;
        fn entry(gw: &Phase1State, datagram: Vec<u8>, msgid: u32, clock: &TestClock) -> PeerQuick {
            let fingerprint = phase2::decrypt_payloads(&datagram, &gw.enc_key, gw.enc_block, &crypto1::phase2_iv(gw.prf, &gw.phase1_iv, msgid, gw.enc_block))
                .map(|(_, payloads, _)| msgid::fingerprint(msgid, &payloads))
                .unwrap_or([0; 32]);
            PeerQuick { msgid, datagram, fingerprint, commit_flag: false, commit_seen: false, arrived: clock.now() }
        }
        fn built(gw: &Phase1State, edit: impl FnOnce(&mut Qm1)) -> (Vec<u8>, u32) {
            let mut qm1 = Qm1::rekeying(&plain(), 0x5400);
            edit(&mut qm1);
            (qm1.message(gw), qm1.msgid)
        }
        let cases: Vec<(&str, Entry, Silence)> = vec![
            ("Message ID 0", |_, gw, clock| { let (m, id) = built(gw, |q| q.msgid = 0); entry(gw, m, id, clock) }, Silence::Unauthenticated),
            ("no ENCRYPTION flag", |_, gw, clock| { let (mut m, id) = built(gw, |_| {}); m[19] &= !flags::ENCRYPTION; entry(gw, m, id, clock) }, Silence::Unauthenticated),
            ("HASH(1) under another SKEYID_a", |_, gw, clock| {
                let mut other = gw.clone();
                other.skeyid_a[0] ^= 1;
                let (m, id) = built(&other, |_| {});
                entry(gw, m, id, clock)
            }, Silence::Unauthenticated),
            ("the cookies of another ISAKMP SA", |_, gw, clock| { let (mut m, id) = built(gw, |_| {}); m[0] ^= 1; entry(gw, m, id, clock) }, Silence::Unauthenticated),
            ("an Informational exchange type", |_, gw, clock| { let (mut m, id) = built(gw, |_| {}); m[18] = exchange::INFORMATIONAL; entry(gw, m, id, clock) }, Silence::Unauthenticated),
            ("the entry's Message ID another", |_, gw, clock| { let (m, id) = built(gw, |_| {}); entry(gw, m, id ^ 2, clock) }, Silence::Unauthenticated),
            ("a datagram cut short", |_, gw, clock| { let (mut m, id) = built(gw, |_| {}); m.truncate(40); entry(gw, m, id, clock) }, Silence::Unauthenticated),
            ("a fingerprint that is not the message's", |_, gw, clock| { let (m, id) = built(gw, |_| {}); let mut e = entry(gw, m, id, clock); e.fingerprint[0] ^= 1; e }, Silence::NotTheMessageRead),
            ("a message the ledger never recorded", |_, gw, clock| { let (m, id) = built(gw, |_| {}); entry(gw, m, id, clock) }, Silence::NotInProgress),
            ("a message whose exchange ran out of time", |client, gw, clock| {
                let (m, _) = built(gw, |_| {});
                let quick = kept(client, &m);
                clock.advance(PEER_QUICK_WAIT);
                quick
            }, Silence::NotInProgress),
        ];
        let mut wrong = Vec::new();
        for (what, make, want) in cases {
            let (client, gw, clock) = pair(false);
            let quick = make(&client, &gw, &clock);
            let before = client.exchanges.id_record(quick.msgid).map(|record| record.state);
            let held_before = client.exchanges.ids_held();
            let mut entropy = Counting::new(0x5401);
            let verdict = answer_quick(&client, &mut entropy, &Tunnel::of(vec![plain()]).expect(clock.now()), &quick);
            if !matches!(verdict, QuickVerdict::Silent(got) if got == want) {
                wrong.push(format!("{what}: {verdict:?}, not {want:?}"));
            }
            let after = client.exchanges.id_record(quick.msgid).map(|record| record.state);
            if entropy.fills != 0 || client.exchanges.ids_held() != held_before || (before.is_some() && after == Some(MidState::Refused)) {
                wrong.push(format!("{what}: {} draws, ledger {before:?} -> {after:?}", entropy.fills));
            }
            if client.exchanges.kept_refusal(quick.msgid, &quick.fingerprint, false).is_some() {
                wrong.push(format!("{what}: a refusal was kept"));
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }

    /// One of this side's own messages 1, sent back after the ledger forgot it was ours, is read as a gateway
    /// message 1 by the readers (nothing tells it apart before its identities are read) and is not answered:
    /// no Notify, nothing drawn, the exchange ended as refused -- for the IPv4 family held, and for the IPv6
    /// family configured with no current SA, which an offer of ours was to make (listed, not answerable).
    #[test]
    fn our_own_message_1_sent_back_after_the_ledger_forgot_it_is_not_answered() {
        let rows: [(&str, bool); 2] = [("IPv4, the family held", false), ("IPv6, configured with no current SA", true)];
        for (what, ipv6) in rows {
            let (client, _gateway, clock) = pair(false);
            let (tunnel, made) = if ipv6 {
                (Tunnel::of(vec![plain(), v6(GCM, None).answerable(false)]), quick::initiate_quick_ipv6(&client, &mut SeedEntropy::new(0x5500), GCM, ours_v6(), gateways_v6(), None, 3600))
            } else {
                (Tunnel::of(vec![plain()]), quick::initiate_quick_with_pfs(&client, &mut SeedEntropy::new(0x5500), GCM, OURS_V4, GATEWAYS_V4, None, 3600))
            };
            let (ours, _qi) = made.unwrap();
            let msgid = msgid_of(&ours);
            assert_eq!(client.exchanges.id_record(msgid).map(|record| record.origin), Some(Origin::Local), "{what}");
            assert_eq!(table::classify(&client, &ours, None), Classified::RouteToOwn { msgid, message: ours.clone() }, "{what}: while ours is in progress");
            clock.advance(Duration::from_secs(21));
            let now = clock.now();
            for n in 1..=MID_CAP as u32 {
                client.exchanges.record_authenticated(2 * n, MidKind::Informational, [7; 32], now, now);
            }
            assert_eq!(client.exchanges.id_record(msgid), None, "{what}: the ledger forgot it");
            let quick = kept(&client, &ours);
            let mut entropy = Counting::new(0x5501);
            let verdict = answer_quick(&client, &mut entropy, &tunnel.expect(now), &quick);
            assert!(matches!(verdict, QuickVerdict::Silent(Silence::Reflection)), "{what}: {verdict:?}");
            assert_eq!(entropy.fills, 0, "{what}");
            assert_eq!(client.exchanges.id_record(msgid).map(|record| record.state), Some(MidState::Refused), "{what}");
            assert!(client.exchanges.kept_refusal(msgid, &quick.fingerprint, false).is_none(), "{what}");
        }
    }

    // ---- The refusal Notify ----

    /// The Notify of a refusal (RFC 2408 §3.14, §3.14.1): DOI 1; about the gateway's proposed SPI (ESP, SPI size 4)
    /// when the message proposes one, about the message (ISAKMP, SPI size 0) when it does not or for the Commit
    /// bit; no data; under a fresh Message ID of ours, recorded as ours, never the refused exchange's.
    #[test]
    fn a_refusal_names_the_proposed_spi_or_the_message_under_a_fresh_id_of_ours() {
        let esp = |t: u8| [&[0, 0, 0, 1, protocol::ESP, 4, 0, t][..], &GATEWAY_SPI.to_be_bytes()].concat();
        let message = |t: u8| vec![0, 0, 0, 1, protocol::ISAKMP, 0, 0, t];
        type Edit = fn(&mut Qm1);
        let cases: [(&str, Edit, Vec<u8>); 5] = [
            ("NO-PROPOSAL-CHOSEN", |q| q.set_attribute(esp_attr::ENCAP_MODE, 2), esp(14)),
            ("PAYLOAD-MALFORMED, an SA read", |q| q.extra.push((payload::NONCE, vec![9; 16])), esp(16)),
            ("INVALID-ID-INFORMATION", |q| q.ids.clear(), esp(18)),
            ("BAD-PROPOSAL-SYNTAX, no SA read", |q| { let mut p = q.payloads(); p[0].1.truncate(10); q.replaced = Some(p); }, message(15)),
            ("INVALID-FLAGS", |q| q.flags = flags::COMMIT, message(8)),
        ];
        for (what, edit, body) in cases {
            let (client, gw, clock) = pair(false);
            let mut qm1 = Qm1::rekeying(&plain(), 0x5600);
            edit(&mut qm1);
            let quick = kept(&client, &qm1.message(&gw));
            let refusal = refused(answer(&client, &Tunnel::of(vec![plain()]), &clock, &quick));
            assert_eq!(refusal_notify(&gw, &refusal), body, "{what}");
            assert_ne!(refusal.msgid, qm1.msgid, "{what}");
            let record = client.exchanges.id_record(refusal.msgid).expect("recorded");
            assert_eq!((record.origin, record.kind), (Origin::Local, MidKind::Informational), "{what}");
        }
    }

    /// Even when the first Message ID drawn for it is the refused exchange's -- the id of a copy with the Commit
    /// bit, which the ledger never recorded -- the refusal goes under another (RFC 2409 §5.7), and the refused id
    /// is not made one of ours.
    #[test]
    fn a_refusal_never_takes_the_refused_exchanges_message_id() {
        let (client, gw, clock) = pair(false);
        let mut qm1 = Qm1::rekeying(&plain(), 0x5700);
        qm1.msgid = msgid::draw(&mut SeedEntropy::new(0x5701));
        qm1.flags = flags::COMMIT;
        let quick = kept(&client, &qm1.message(&gw));
        assert_eq!(client.exchanges.id_record(qm1.msgid), None);
        let refusal = refused(answer_quick(&client, &mut SeedEntropy::new(0x5701), &Tunnel::of(vec![plain()]).expect(clock.now()), &quick));
        assert_ne!(refusal.msgid, qm1.msgid);
        assert_eq!(client.exchanges.id_record(qm1.msgid), None, "the refused id is not one of ours");
        assert_eq!(refusal_notify(&gw, &refusal)[6..8], 8u16.to_be_bytes());
    }

    /// The Notify types a refusal can carry are ISAKMP's error types 8, 14, 15, 16 and 18 (RFC 2408 §3.14.1),
    /// never one of IKEv2's (RFC 7296's NO_ADDITIONAL_SAS 35, TEMPORARY_FAILURE 43).
    #[test]
    fn a_refusal_carries_an_isakmp_error_type_and_never_an_ikev2_one() {
        use RefusalNotify::*;
        let every = [InvalidFlags, NoProposalChosen, BadProposalSyntax, PayloadMalformed, InvalidIdInformation];
        // Every variant is in `every`: a new one does not compile here until it is listed.
        for notify in every {
            match notify {
                InvalidFlags | NoProposalChosen | BadProposalSyntax | PayloadMalformed | InvalidIdInformation => {}
            }
        }
        let types: Vec<u16> = every.iter().map(|n| n.notify_type()).collect();
        assert_eq!(types, [8, 14, 15, 16, 18]);
        assert!(types.iter().all(|t| !matches!(t, 35 | 43)));
    }

    /// At most four refusals a minute leave on an ISAKMP SA: the fifth is silence (the exchange refused all the
    /// same). A copy of a refused message 1 -- the same bytes, or the same message with a cipher block appended,
    /// which changes its last block and not what it says -- gets the very refusal again (once the spacing of
    /// repeats allows), uncounted, budget spent or not; a minute after the first, a new refusal leaves again.
    #[test]
    fn refusals_are_four_a_minute_and_a_copy_of_a_refused_message_gets_the_same_one_uncounted() {
        let (client, gw, clock) = pair(false);
        let tunnel = Tunnel::of(vec![plain()]);
        let refuse_next = |seed: u64| {
            let mut qm1 = Qm1::rekeying(&plain(), seed);
            qm1.set_attribute(esp_attr::ENCAP_MODE, 2);
            let message = qm1.message(&gw);
            let quick = kept(&client, &message);
            (message, quick.clone(), answer(&client, &tunnel, &clock, &quick))
        };
        let (first_message, first, first_verdict) = refuse_next(0x5800);
        let first_refusal = refused(first_verdict);
        for n in 1..REFUSALS_PER_WINDOW as u64 {
            clock.advance(Duration::from_secs(1));
            refused(refuse_next(0x5800 + n).2);
        }
        let (_, fifth, fifth_verdict) = refuse_next(0x5810);
        assert!(matches!(fifth_verdict, QuickVerdict::Silent(Silence::RateLimited(RefusalNotify::NoProposalChosen))), "{fifth_verdict:?}");
        assert_eq!(client.exchanges.id_record(fifth.msgid).map(|r| r.state), Some(MidState::Refused));

        let mut appended = first_message.clone();
        appended.extend_from_slice(&[0xEE; 16]);
        let length = appended.len() as u32;
        appended[24..28].copy_from_slice(&length.to_be_bytes());
        let copies = [first.clone(), PeerQuick { datagram: appended, ..first.clone() }];
        for copy in &copies {
            clock.advance(REFUSAL_RESEND_SPACING);
            let again = refused(answer(&client, &tunnel, &clock, copy));
            assert!(again.repeat);
            assert_eq!((again.msgid, again.datagram.as_slice(), again.notify), (first_refusal.msgid, first_refusal.datagram.as_slice(), first_refusal.notify));
        }
        let (_, _, sixth) = refuse_next(0x5811);
        assert!(matches!(sixth, QuickVerdict::Silent(Silence::RateLimited(_))), "the copies took nothing from the budget, and gave none back: {sixth:?}");
        clock.advance(Duration::from_secs(60) - Duration::from_secs(REFUSALS_PER_WINDOW as u64 - 1));
        let (_, _, later) = refuse_next(0x5812);
        assert!(!refused(later).repeat, "a minute after the first");
    }

    // ---- The Commit bit ----

    /// An entry for `message` handed to the responder as the readers would keep it, but without them (which
    /// remember a Commit bit themselves): its fingerprint and Commit bit as the message has them.
    fn unread_entry(gw: &Phase1State, message: &[u8], at: Instant) -> PeerQuick {
        let msgid = msgid_of(message);
        let (_h, payloads, _) = phase2::decrypt_payloads(message, &gw.enc_key, gw.enc_block, &crypto1::phase2_iv(gw.prf, &gw.phase1_iv, msgid, gw.enc_block)).unwrap();
        let commit_flag = IsakmpHeader::parse(message).unwrap().flags & flags::COMMIT != 0;
        PeerQuick { msgid, datagram: message.to_vec(), fingerprint: msgid::fingerprint(msgid, &payloads), commit_flag, commit_seen: commit_flag, arrived: at }
    }

    /// The message of `qm1` under `gw`'s keys, without the Commit bit and with it.
    fn clean_and_flagged(gw: &Phase1State, qm1: &Qm1) -> (Vec<u8>, Vec<u8>) {
        let clean = qm1.message(gw);
        let mut flagged = clean.clone();
        flagged[19] |= flags::COMMIT;
        (clean, flagged)
    }

    /// A copy whose header has the Commit bit set is refused with INVALID-FLAGS about the message and recorded
    /// nowhere in the ledger; a repeat of it gets the same refusal, uncounted; the same message without the bit,
    /// read afterwards, is answered as any other (DESIGN 3.6: "processed normally") -- and what is held says the
    /// bit was seen, though the entry answered never carried it: its SA is never to be used.
    #[test]
    fn a_copy_with_the_commit_bit_is_refused_and_the_same_message_without_it_is_answered_never_to_be_used() {
        let (client, gw, clock) = pair(false);
        let tunnel = Tunnel::of(vec![plain()]);
        let qm1 = Qm1::rekeying(&plain(), 0x5900);
        let (clean, flagged) = clean_and_flagged(&gw, &qm1);
        let flagged_entry = kept(&client, &flagged);
        assert!(flagged_entry.commit_flag);
        let refusal = refused(answer(&client, &tunnel, &clock, &flagged_entry));
        assert_eq!(refusal.notify, RefusalNotify::InvalidFlags);
        assert_eq!(client.exchanges.id_record(qm1.msgid), None, "no record of the message");
        clock.advance(REFUSAL_RESEND_SPACING);
        let again = refused(answer(&client, &tunnel, &clock, &flagged_entry));
        assert!(again.repeat && again.datagram == refusal.datagram);
        let entry = kept(&client, &clean);
        assert!(!entry.commit_flag && !entry.commit_seen, "the entry itself does not carry the bit");
        let held = accepted(answer(&client, &tunnel, &clock, &entry));
        assert!(held.commit_seen(), "the copy refused before is remembered");
    }

    /// A copy with the Commit bit refused in silence -- the budget of refusals spent -- and kept by no reader is
    /// remembered all the same: the message read later without the bit is answered, never to be used.
    #[test]
    fn the_commit_bit_of_a_copy_refused_in_silence_is_held_with_the_later_answer() {
        let (client, gw, clock) = pair(false);
        let tunnel = Tunnel::of(vec![plain()]);
        for n in 0..REFUSALS_PER_WINDOW as u64 {
            let mut other = Qm1::rekeying(&plain(), 0x5A20 + n);
            other.set_attribute(esp_attr::ENCAP_MODE, 2);
            refused(answer(&client, &tunnel, &clock, &kept(&client, &other.message(&gw))));
        }
        let qm1 = Qm1::rekeying(&plain(), 0x5A30);
        let (clean, flagged) = clean_and_flagged(&gw, &qm1);
        let verdict = answer(&client, &tunnel, &clock, &unread_entry(&gw, &flagged, clock.now()));
        assert!(matches!(verdict, QuickVerdict::Silent(Silence::RateLimited(RefusalNotify::InvalidFlags))), "{verdict:?}");
        let entry = kept(&client, &clean);
        assert!(!entry.commit_seen);
        assert!(accepted(answer(&client, &tunnel, &clock, &entry)).commit_seen());
    }

    /// The copy without the bit taken from the inbox, and a copy with it read before that entry is answered --
    /// an entry of its own, since the inbox no longer holds the other: the answer says the bit was seen, and the
    /// flagged entry answered next is silence (no INVALID-FLAGS against the message 2 held, nothing drawn, no
    /// refusal kept, the exchange still in progress).
    #[test]
    fn the_commit_bit_of_a_copy_read_after_the_clean_one_was_taken_is_held_with_the_answer() {
        let (client, gw, clock) = pair(false);
        let tunnel = Tunnel::of(vec![plain()]);
        let qm1 = Qm1::rekeying(&plain(), 0x5A10);
        let (clean, flagged) = clean_and_flagged(&gw, &qm1);
        let entry = kept(&client, &clean);
        let flagged_entry = kept(&client, &flagged);
        assert!(!entry.commit_seen && flagged_entry.commit_flag);
        assert!(accepted(answer(&client, &tunnel, &clock, &entry)).commit_seen());
        let mut entropy = Counting::new(0x5A11);
        let verdict = answer_quick(&client, &mut entropy, &tunnel.expect(clock.now()), &flagged_entry);
        assert!(matches!(verdict, QuickVerdict::Silent(Silence::CommitOnHeld)), "{verdict:?}");
        assert_eq!(entropy.fills, 0);
        assert!(client.exchanges.kept_refusal(qm1.msgid, &flagged_entry.fingerprint, true).is_none());
        assert!(matches!(client.exchanges.id_record(qm1.msgid).map(|record| record.state), Some(MidState::Active { .. })));
    }

    /// A copy with the Commit bit of a message answered already -- its message 2 held -- is not refused: the
    /// exchange table remembers the bit of the message (for what C5b reports), nothing is drawn or kept, and the
    /// exchange stays in progress. Without the bit, the same copy is the message answered already.
    #[test]
    fn a_copy_with_the_commit_bit_of_a_message_answered_is_noted_not_refused() {
        let (client, gw, clock) = pair(false);
        let tunnel = Tunnel::of(vec![plain()]);
        let qm1 = Qm1::rekeying(&plain(), 0x5A60);
        let (clean, flagged) = clean_and_flagged(&gw, &qm1);
        let entry = kept(&client, &clean);
        assert!(!accepted(answer(&client, &tunnel, &clock, &entry)).commit_seen());
        assert!(!client.exchanges.commit_seen_for(qm1.msgid, &entry.fingerprint));
        let flagged_entry = unread_entry(&gw, &flagged, clock.now());
        let mut entropy = Counting::new(0x5A61);
        let verdict = answer_quick(&client, &mut entropy, &tunnel.expect(clock.now()), &flagged_entry);
        assert!(matches!(verdict, QuickVerdict::Silent(Silence::CommitOnHeld)), "{verdict:?}");
        assert_eq!(entropy.fills, 0);
        assert!(client.exchanges.commit_seen_for(qm1.msgid, &entry.fingerprint), "remembered by the table");
        assert!(client.exchanges.kept_refusal(qm1.msgid, &entry.fingerprint, true).is_none());
        assert!(matches!(client.exchanges.id_record(qm1.msgid).map(|record| record.state), Some(MidState::Active { .. })));
    }

    /// Each entry is answered once: while its exchange is in progress, the message answered -- the entry again,
    /// or a copy of it with another last cipher block -- is silence, nothing drawn, no second message 2 with
    /// another SPI, nonce or keys. Parked (the answer held dropped before anything left) and taken up again by
    /// a copy, it is answered anew, once; over, it is not in progress.
    #[test]
    fn a_message_answered_is_not_answered_again_while_its_exchange_is_in_progress() {
        let (client, gw, clock) = pair(false);
        let tunnel = Tunnel::of(vec![plain()]);
        let message = Qm1::rekeying(&plain(), 0x5A40).message(&gw);
        let entry = kept(&client, &message);
        let mut appended = message.clone();
        appended.extend_from_slice(&[0xEE; 16]);
        let length = appended.len() as u32;
        appended[24..28].copy_from_slice(&length.to_be_bytes());
        let copies = [entry.clone(), PeerQuick { datagram: appended, ..entry.clone() }];
        let again = |want: Silence| {
            for copy in &copies {
                let mut entropy = Counting::new(0x5A41);
                let verdict = answer_quick(&client, &mut entropy, &tunnel.expect(clock.now()), copy);
                assert!(matches!(verdict, QuickVerdict::Silent(got) if got == want), "{verdict:?}, not {want:?}");
                assert_eq!(entropy.fills, 0);
            }
        };
        accepted(answer(&client, &tunnel, &clock, &entry));
        again(Silence::AlreadyAnswered);
        let msgid = entry.msgid;
        assert!(client.exchanges.park(msgid, clock.now(), clock.now() + PEER_QUICK_WAIT));
        clock.advance(RECONSIDER_GAP);
        assert!(client.exchanges.reconsider(msgid, clock.now(), clock.now() + PEER_QUICK_WAIT));
        accepted(answer(&client, &tunnel, &clock, &entry));
        again(Silence::AlreadyAnswered);
        assert!(client.exchanges.finish(msgid, clock.now(), MidEnd::Done));
        again(Silence::NotInProgress);
    }

    /// A kept refusal is handed out again at most once per [`REFUSAL_RESEND_SPACING`]: copies read sooner are
    /// silence, with nothing drawn -- for a refused offer, and for a copy with the Commit bit replayed at line
    /// rate (never recorded, so every replay reaches the responder).
    #[test]
    fn a_kept_refusal_is_sent_again_at_most_once_per_spacing() {
        for (what, flagged) in [("NO-PROPOSAL-CHOSEN", false), ("INVALID-FLAGS", true)] {
            let (client, gw, clock) = pair(false);
            let tunnel = Tunnel::of(vec![plain()]);
            let mut qm1 = Qm1::rekeying(&plain(), 0x5A50);
            if flagged {
                qm1.flags = flags::COMMIT;
            } else {
                qm1.set_attribute(esp_attr::ENCAP_MODE, 2);
            }
            let entry = kept(&client, &qm1.message(&gw));
            let first = refused(answer(&client, &tunnel, &clock, &entry));
            let mut sent = Vec::new();
            for n in 1..=9 {
                clock.advance(Duration::from_millis(50));
                let mut entropy = Counting::new(0x5A51);
                match answer_quick(&client, &mut entropy, &tunnel.expect(clock.now()), &entry) {
                    QuickVerdict::Refuse(again) => {
                        assert!(again.repeat && again.datagram == first.datagram && again.msgid == first.msgid, "{what}: {again:?}");
                        sent.push(n);
                    }
                    QuickVerdict::Silent(Silence::RepeatTooSoon) => {}
                    other => panic!("{what}: {other:?}"),
                }
                assert_eq!(entropy.fills, 0, "{what}");
            }
            assert_eq!(sent, [4, 8], "{what}: once per 200 ms, read every 50 ms");
        }
    }

    /// A copy with the Commit bit read while the copy without it waits in the inbox is noted on that entry: the
    /// message is answered, and what is held says the bit was seen, so that the SA is never used.
    #[test]
    fn the_commit_bit_seen_on_another_copy_is_held_with_the_answer() {
        let (client, gw, clock) = pair(false);
        let qm1 = Qm1::rekeying(&plain(), 0x5A00);
        let clean = qm1.message(&gw);
        let mut flagged = clean.clone();
        flagged[19] |= flags::COMMIT;
        assert_eq!(table::classify(&client, &clean, None), Classified::PeerQuick { msgid: qm1.msgid });
        assert_eq!(table::classify(&client, &flagged, None), Classified::CommitNoted { msgid: qm1.msgid });
        let [entry] = client.take_peer_quick_modes().try_into().unwrap();
        assert!(!entry.commit_flag && entry.commit_seen);
        let held = accepted(answer(&client, &Tunnel::of(vec![plain()]), &clock, &entry));
        assert!(held.commit_seen());
    }

    // ---- Lifetimes ----

    /// The SA's limits are the offer's -- 28800 s when it states none in seconds (RFC 2407 §4.5) -- the seconds
    /// shortened to the profile's explicit cap, the kilobytes as offered, nothing lengthened. When a limit is
    /// shorter than the offer's, a RESPONDER-LIFETIME Notify (RFC 2407 §4.6.3.1) states every limit in force,
    /// about this side's inbound SPI; message 2's transform is the offer's all the same; and the initiator's own
    /// reading of message 2 gives the same limits.
    #[test]
    fn the_limits_are_the_offers_shortened_to_the_cap_and_stated_when_shortened() {
        let seconds = |s: u32| vec![Attribute::short(esp_attr::LIFE_TYPE, life::SECONDS), Attribute::long_u32(esp_attr::LIFE_DURATION, s)];
        let kilobytes = |kb: u32| vec![Attribute::short(esp_attr::LIFE_TYPE, life::KILOBYTES), Attribute::long_u32(esp_attr::LIFE_DURATION, kb)];
        let both = |s: u32, kb: u32| [seconds(s), kilobytes(kb)].concat();
        type Case = (&'static str, Vec<Attribute>, Option<u32>, SaLifetime, bool);
        let cases: Vec<Case> = vec![
            ("seconds offered, no cap", seconds(3600), None, SaLifetime { seconds: 3600, kilobytes: None }, false),
            ("nothing offered, no cap: the default", vec![], None, SaLifetime { seconds: 28_800, kilobytes: None }, false),
            ("nothing offered, a cap", vec![], Some(3600), SaLifetime { seconds: 3600, kilobytes: None }, true),
            ("seconds and kilobytes offered, a shorter cap", both(3600, 50_120), Some(1800), SaLifetime { seconds: 1800, kilobytes: Some(50_120) }, true),
            ("kilobytes first, then seconds, a shorter cap", [kilobytes(5120), seconds(3600)].concat(), Some(600), SaLifetime { seconds: 600, kilobytes: Some(5120) }, true),
            ("seconds and kilobytes offered, no cap: the kilobytes untouched", both(3600, 50_120), None, SaLifetime { seconds: 3600, kilobytes: Some(50_120) }, false),
            ("kilobytes alone offered, no cap", kilobytes(5120), None, SaLifetime { seconds: 28_800, kilobytes: Some(5120) }, false),
            ("a cap longer than the offer: never lengthened", seconds(1800), Some(3600), SaLifetime { seconds: 1800, kilobytes: None }, false),
            ("a cap equal to the offer", seconds(1800), Some(1800), SaLifetime { seconds: 1800, kilobytes: None }, false),
            ("a cap of 0 is no cap", seconds(1800), Some(0), SaLifetime { seconds: 1800, kilobytes: None }, false),
        ];
        for (what, life_attributes, cap, want, stated) in cases {
            let (client, gw, clock) = pair(false);
            let exp = ExpectedQuick::ipv4(GCM, None, OURS_V4, GATEWAYS_V4, cap);
            let mut qm1 = Qm1::rekeying(&exp, 0x5B00);
            qm1.transform().attributes.retain(|a| !LIFETIME_ATTRS.contains(&a.attr_type));
            qm1.transform().attributes.extend(life_attributes);
            let offered = qm1.transform().clone();
            let message = qm1.message(&gw);
            let held = accepted(answer(&client, &Tunnel::of(vec![exp]), &clock, &kept(&client, &message)));
            assert_eq!((held.lifetime(), held.responder_lifetime_added()), (want, stated), "{what}");
            let payloads = qm2_payloads(&gw, &message, held.qm2());
            let notifies: Vec<Vec<u8>> = payloads.iter().filter(|p| p.payload_type == payload::NOTIFY).map(|p| p.data.clone()).collect();
            let mut in_force = seconds(want.seconds);
            in_force.extend(want.kilobytes.map(kilobytes).unwrap_or_default());
            let data: Vec<u8> = in_force.iter().flat_map(Attribute::to_bytes).collect();
            let expected_notifies = if stated { vec![informational::notify_body(protocol::ESP, &held.local_spi().to_be_bytes(), RESPONDER_LIFETIME, &data)] } else { vec![] };
            assert_eq!(notifies, expected_notifies, "{what}");
            assert_eq!(payloads.last().map(|p| p.payload_type), Some(if stated { payload::NOTIFY } else { payload::ID }), "{what}: the Notify after the identities");
            assert_eq!(qm2_sa(&gw, &message, held.qm2()).proposals[0].transforms, [offered], "{what}: the transform as offered");
            let (_qm3, _child, read) = QuickInitiator::of_message_1(&gw, &message, GCM, None).complete_with_lifetime(held.qm2()).unwrap_or_else(|e| panic!("{what}: {e}"));
            assert_eq!(read, want, "{what}: as the initiator reads message 2");
        }
    }

    // ---- Secrets ----

    /// No `Debug` of what is held prints a key or a nonce; the keys are moved out once and nothing of them
    /// stays behind; what a `HeldQuick` drops unmoved is wiped first (the wrapper's `Drop` runs its `wipe`, which
    /// zeroes both directions' buffers and empties them).
    #[test]
    fn what_is_held_shows_no_secret_and_gives_its_keys_up_once() {
        let (client, gw, clock) = pair(false);
        let exp = v4(CBC, Some(DhGroup::Modp1024));
        let message = Qm1::rekeying(&exp, 0x5C00).message(&gw);
        let mut held = accepted(answer(&client, &Tunnel::of(vec![exp]), &clock, &kept(&client, &message)));
        let shown = format!("{held:?}");
        let keys = held.take_keys().unwrap();
        let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        for (name, secret) in [("enc out", &keys.key_out.enc), ("integ out", &keys.key_out.integ), ("enc in", &keys.key_in.enc), ("integ in", &keys.key_in.integ)] {
            assert!(!secret.is_empty(), "{name}");
            assert!(!shown.contains(&hex(secret)) && !shown.contains(&format!("{secret:?}")), "{name} in {shown}");
        }
        for (name, nonce) in [("Ni", held.ni()), ("Nr", held.nr())] {
            assert!(!shown.contains(&hex(nonce)) && !shown.contains(&format!("{nonce:?}")), "{name} in {shown}");
        }
        assert!(shown.contains("<held>"), "{shown}");
        assert!(held.take_keys().is_none() && !held.keys_held());
        assert!(format!("{:?}", QuickVerdict::Accept(held)).contains("<taken>"));

        let mut wrapper = HeldKeys(Some(keys));
        wrapper.wipe();
        let wiped = wrapper.0.as_ref().expect("wiped in place");
        assert!(wiped.key_out.enc.is_empty() && wiped.key_out.integ.is_empty() && wiped.key_in.enc.is_empty() && wiped.key_in.integ.is_empty());
    }

    // ---- A passive table ----

    /// An `IkeSocket` that hands out the datagrams it was given and then times out, sending nothing.
    struct Scripted {
        incoming: RefCell<VecDeque<Vec<u8>>>,
        reads: Cell<usize>,
        sent: Cell<usize>,
    }

    impl IkeSocket for Scripted {
        fn send_to(&self, buf: &[u8], _dest: SocketAddr) -> io::Result<usize> {
            self.sent.set(self.sent.get() + 1);
            Ok(buf.len())
        }
        fn set_read_timeout(&self, _dur: Option<Duration>) -> io::Result<()> {
            Ok(())
        }
        fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            self.reads.set(self.reads.get() + 1);
            let Some(datagram) = self.incoming.borrow_mut().pop_front() else { return Err(io::ErrorKind::WouldBlock.into()) };
            buf[..datagram.len()].copy_from_slice(&datagram);
            Ok((datagram.len(), "192.0.2.1:500".parse().unwrap()))
        }
    }

    /// With the table passive the readers keep no gateway message 1 -- the inbox stays empty, so nothing ever
    /// reaches the responder -- and the responder itself, handed one, answers nothing: no draw, no clock read, no
    /// record.
    #[test]
    fn a_passive_table_never_answers_a_gateway_message_1() {
        let (mut client, gw) = phase1_pair();
        let clock_reads = Arc::new(AtomicUsize::new(0));
        let counted = clock_reads.clone();
        let at = Instant::now();
        client.exchanges = ExchangeTable::with_clock(Box::new(move || {
            counted.fetch_add(1, Ordering::Relaxed);
            at
        }));
        let message = Qm1::rekeying(&plain(), 0x5D00).message(&gw);
        let sock = Scripted { incoming: RefCell::new(VecDeque::from([message.clone()])), reads: Cell::new(0), sent: Cell::new(0) };
        let liveness = informational::peek(&sock, &client, &mut SeedEntropy::new(0x5D01), "192.0.2.1:500".parse().unwrap(), Duration::from_millis(50), 0x1111_0001, None).unwrap();
        assert_eq!(liveness, informational::Liveness::Alive);
        assert_eq!((sock.reads.get(), sock.sent.get()), (2, 0));
        let report = informational::serve_turn(&sock, &client, &mut SeedEntropy::new(0x5D02), "192.0.2.1:500".parse().unwrap(), 8, Duration::from_millis(20)).unwrap();
        assert_eq!((report, sock.reads.get()), (informational::TurnReport::default(), 2), "a passive serving turn reads nothing");
        assert!(client.take_peer_quick_modes().is_empty());
        assert_eq!(client.exchanges.inbox_held(), 0);

        let fingerprint = phase2::decrypt_payloads(&message, &gw.enc_key, gw.enc_block, &crypto1::phase2_iv(gw.prf, &gw.phase1_iv, msgid_of(&message), gw.enc_block))
            .map(|(_, payloads, _)| msgid::fingerprint(msgid_of(&message), &payloads))
            .unwrap();
        let quick = PeerQuick { msgid: msgid_of(&message), datagram: message, fingerprint, commit_flag: false, commit_seen: false, arrived: at };
        let mut entropy = Counting::new(0x5D03);
        let verdict = answer_quick(&client, &mut entropy, &Tunnel::of(vec![plain()]).expect(at), &quick);
        assert!(matches!(verdict, QuickVerdict::Silent(Silence::Passive)), "{verdict:?}");
        assert_eq!((entropy.fills, clock_reads.load(Ordering::Relaxed), client.exchanges.ids_held()), (0, 0, 0));
    }
}
