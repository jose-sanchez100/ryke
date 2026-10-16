//! What the responder keeps of the gateway Quick Modes it answers ([`ResponderCache`]), and the states each of
//! them goes through (DESIGN 4):
//!
//! ```text
//! Held --answered--> Answered --proven--> Proven{Qm3|Esp}      (kept RESP_RETAIN for copies of message 1)
//!   |                    |----abandon--> Abandoned(reason)     (dropped at once)
//!   |                    |----cancel---> Cancelled(reason)     (dropped at once)
//!   |                    '----release failed, no message 2 went--> Parked
//!   |----cancel---> Cancelled(reason)
//!   '----park-----> Parked                                     (nothing sent: the ledger may take it up again)
//! ```
//!
//! A hold is legal only for a message never held here, or parked; held, answered, proven, abandoned or cancelled, it
//! is never held again: it is answered already or its exchange ended for good (DESIGN 8.7: once a message 2 left, its
//! Message ID is burned for new answers, and after an abandon its copies get silence).
//!
//! **Held**: message 2 built and the keys derived, nothing sent, for at most [`PEER_QM_HOLD_MAX`]: then it is
//! parked, by the ledger at the same instant ([`super::super::msgid::AtDeadline::Park`]). **Answered**: message 2
//! sent; ended by the caller -- the worker, which hears the daemon -- once it has a proof or gives up, or here after
//! [`ANSWERED_FOR`]. Nothing here decides a proof: the facts the readers see -- an authenticated message 3, a
//! Commit bit on a copy, an error Notify about the exchange, the ISAKMP SA deleted -- are recorded and handed to the
//! caller ([`ResponderEvents`]), never acted on.
//!
//! The cache is the responder's own, apart from the final messages of this side's exchanges
//! ([`RetainedFinals`](super::super::phase1::RetainedFinals)): at most [`CACHE_ENTRIES`] entries and
//! [`CACHE_BYTES`] octets (POLICY). An entry in progress (Held, Answered) is never evicted, and a message 1 that
//! would need room the entries in progress hold is deferred, not admitted. A proven entry gives way to a new one
//! (the oldest first), and is forgotten [`RESP_RETAIN`] after its proof in any case; an abandoned, cancelled or
//! parked one is dropped at once, with the message 2 it retained. Each entry holds what its message 2 is made of
//! -- its plaintext, the nonces, the cipher blocks -- and no key.
//!
//! A Message ID does not name one answer: a message 1 parked with nothing sent may be answered anew under it, with
//! another SPI, nonce and keys (D9). Each hold is therefore its own ([`ResponderId`]), and every move but the hold
//! itself names the hold it is about: one named by an earlier hold of the same message is refused, never applied to
//! the later one.
//!
//! Every time here is the caller's `now` (the exchange table's clock), so a test needs no sleep.

use std::collections::VecDeque;
use std::fmt;
use std::time::{Duration, Instant};

use crate::ikev1::informational::ChildFamily;

/// How long a gateway Quick Mode answered by this side may be held -- message 2 built and the keys derived,
/// nothing sent -- before the daemon releases or refuses it (POLICY, DESIGN 2): 8 s from the moment it is held. It
/// covers the other family's whole proof window, so that a message 1 that merely waits for the daemon is not given
/// up; the usual time from hold to release is about 100 ms. Past it the exchange is parked: nothing was sent, and
/// a copy the gateway sends again may be answered anew (D9).
pub const PEER_QM_HOLD_MAX: Duration = Duration::from_secs(8);

/// How long after message 2 of a gateway Quick Mode left the daemon looks for a proof that the new SA is
/// established -- its message 3, or ESP on the new SA (POLICY, DESIGN 2). Not a bound of the whole proof phase:
/// the last step it admits may start just before the end. This side's unasked resends of message 2 all fall
/// inside it ([`super::AnsweredQuick`]).
pub const PEER_QM_PROOF_WAIT: Duration = Duration::from_secs(3);

/// How long a message 1 of a gateway Quick Mode waits, at the longest from the moment it was read, for its family
/// to be free (POLICY, DESIGN 8.6): an exchange of this side's running for it, an answer of this side's still
/// pending, no current SA to renew yet. One message per family waits, the latest read. The wait is not counted as
/// one of the times the message may be taken up again.
pub const DEFER_MAX: Duration = Duration::from_secs(20);

/// How long the message 2 of a proven gateway Quick Mode is kept to answer a copy of its message 1 with (POLICY):
/// 120 s from the proof, as long as this side keeps a final message of its own
/// (`RetainedFinals::KEPT_FOR`) -- unless newer entries need
/// the room first.
pub const RESP_RETAIN: Duration = Duration::from_secs(120);

/// How long an answered gateway Quick Mode stays in progress here at the longest (POLICY, DESIGN 4: the hold bound,
/// [`PEER_QM_PROOF_WAIT`] and a margin, 15 s after message 2 left): longer than the daemon's proof phase and the
/// commit or abandon after it, so that the caller ends it first. Past it the exchange is abandoned here
/// ([`EndReason::Deadline`]) and its message 2 dropped.
pub(crate) const ANSWERED_FOR: Duration = Duration::from_secs(15);

const _: () = assert!(ANSWERED_FOR.as_nanos() >= PEER_QM_HOLD_MAX.as_nanos() + PEER_QM_PROOF_WAIT.as_nanos());

/// How long a parked gateway Quick Mode may be taken up again by a copy of its message 1, from the moment it was
/// parked (POLICY): as long as a message 1 may wait for its family ([`DEFER_MAX`]). No RFC fixes the gateway's
/// retransmission schedule; this covers a gap of up to 20 s between two of its copies.
pub(crate) const PARKED_FOR: Duration = DEFER_MAX;

/// The shortest time between two sendings of message 2 for one gateway Quick Mode, whatever asks for it -- a copy
/// of message 1, or this side's own resend plan (POLICY, DESIGN 2): a copy read sooner is not answered.
pub(crate) const ANSWER_SPACING: Duration = Duration::from_millis(200);

/// How many encryptions of message 2 an entry keeps (POLICY, review P2): the one sent under the last cipher block
/// of the message 1 answered, and one under the last block of a copy that ended otherwise -- a copy with another
/// last block, the same content. A third is not answered.
pub(crate) const QM2_VARIANTS: usize = 2;

/// How many unasked resends of message 2 the responder makes at most (POLICY, DESIGN 2).
pub(crate) const QM2_RESENDS: usize = 2;

/// The most entries the cache holds (POLICY).
pub(crate) const CACHE_ENTRIES: usize = 4;

/// The most octets the entries of the cache hold together (POLICY): a message 2 is a few hundred octets.
pub(crate) const CACHE_BYTES: usize = 16 * 1024;

/// How many ended exchanges the cache remembers the end of, for a caller that asks about one after the fact.
const ENDS_REMEMBERED: usize = 8;

/// Where a gateway Quick Mode this side answers stands (DESIGN 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponderState {
    /// Message 2 built and the keys of the new SA derived, nothing sent: the daemon installs the SA, then this side
    /// sends message 2 ([`super::HeldQuick::release`]).
    Held,
    /// Message 2 sent; no proof yet.
    Answered,
    /// The new SA is established, by the proof named. Its message 2 is kept for copies of message 1
    /// ([`RESP_RETAIN`]).
    Proven(Proof),
    /// Message 2 sent and no proof came: given up for the reason named. Copies of its message 1 get silence.
    Abandoned(EndReason),
    /// Ended by an event, for the reason named, sent or not. Copies of its message 1 get silence.
    Cancelled(EndReason),
    /// Ended with nothing sent, for a passing reason (the hold ran out, the daemon refused it, message 2 could not
    /// be sent): the ledger may take a copy of its message 1 up again, twice at most in all (D9).
    Parked,
}

impl ResponderState {
    /// Whether it is in progress: held or answered.
    pub fn in_progress(self) -> bool {
        matches!(self, ResponderState::Held | ResponderState::Answered)
    }
}

/// What proved a gateway Quick Mode established (DESIGN 5.1, D11).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proof {
    /// Its message 3, authenticated (RFC 2409 §5.5: HASH(3) is "for liveliness").
    Qm3,
    /// ESP received on the new inbound SA.
    Esp,
}

/// Why a gateway Quick Mode ended without a proof. Nothing here acts on it but to say it; what ends the exchange is
/// the caller's decision, but for [`EndReason::Deadline`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EndReason {
    /// No proof in the time the daemon allows.
    NoProof,
    /// The time an answered exchange stays in progress here ran out (15 s after message 2 left), the caller having
    /// ended nothing.
    Deadline,
    /// The new SA could not be installed, or was removed again.
    NotInstalled,
    /// The gateway deleted the new SA.
    NewDeleted,
    /// A copy of a message of the exchange had the Commit bit set (DESIGN 3.6).
    CommitSeen,
    /// The gateway refused the exchange with an error Notify.
    PeerRejected,
    /// The ISAKMP SA is gone.
    TornDown,
    /// The tunnel is being disconnected.
    Disconnect,
    /// The peer-event mailbox overflowed: what the gateway said is not all known.
    Overflow,
}

/// How the caller ends a gateway Quick Mode in progress ([`super::super::phase1::Phase1State::conclude_responder`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// [`ResponderState::Proven`]: only an answered exchange.
    Proven(Proof),
    /// [`ResponderState::Abandoned`]: only an answered exchange.
    Abandoned(EndReason),
    /// [`ResponderState::Cancelled`]: a held or an answered exchange.
    Cancelled(EndReason),
}

/// A move of the state machine ([`ResponderState`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transition {
    Hold,
    Answer,
    Prove,
    Abandon,
    Cancel,
    Park,
}

/// Which answer of this side's to a gateway Quick Mode a call is about: its Message ID, and which of the times this
/// side held an answer to that message it is (see the module doc). Only the responder makes one
/// ([`super::HeldQuick::id`], [`PendingResponder::id`]); no two holds of one ISAKMP SA share one.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResponderId {
    msgid: u32,
    hold: u64,
}

impl ResponderId {
    /// The id of an answer [`super::answer_quick`] has built and not held yet: no hold is ever given it.
    pub(super) const fn unheld(msgid: u32) -> Self {
        Self { msgid, hold: 0 }
    }

    /// The Message ID of the exchange.
    pub fn msgid(&self) -> u32 {
        self.msgid
    }
}

impl fmt::Debug for ResponderId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ResponderId(msgid={:08x}, hold {})", self.msgid, self.hold)
    }
}

/// A move the state of the exchange does not allow; nothing changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IllegalTransition {
    /// The Message ID of the exchange.
    pub msgid: u32,
    /// The state of the hold the move named, `None` when the cache knows nothing of it (never held, or ended so long
    /// ago it is forgotten). A move named by an earlier hold of a message held again is refused with that earlier
    /// hold's end.
    pub from: Option<ResponderState>,
    /// The move asked for.
    pub to: Transition,
}

impl fmt::Display for IllegalTransition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "gateway Quick Mode msgid={:08x}: {:?} is not allowed from {:?}", self.msgid, self.to, self.from)
    }
}

/// Why a message 1 of a gateway Quick Mode waits instead of being answered ([`super::Silence::Deferred`]): its
/// family is not free. It waits in its family's slot ([`DEFER_MAX`]) and is offered again
/// ([`super::super::phase1::Phase1State::take_peer_quick_modes`]) once nothing here keeps the family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeferReason {
    /// The family holds no current SA to renew now ([`super::ExpectedQuick::answerable`]): its SA ended and is not
    /// made again yet, or an exchange of this side's is making it (DESIGN 8.5).
    NotReady,
    /// Another gateway Quick Mode of the family is held or answered (one at a time per family, DESIGN 8.6).
    Busy,
    /// Less than 200 ms (`ACCEPT_SPACING`) since the family's last gateway Quick Mode ended.
    Spacing,
    /// The cache holds as many exchanges in progress as it can (four entries, 16 KiB).
    CacheFull,
}

/// The facts the readers recorded about a gateway Quick Mode in progress since the caller last took them
/// ([`super::super::phase1::Phase1State::take_responder_events`]): each fact is handed over once. Nothing here acts
/// on any of them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ResponderEvents {
    /// The Message ID of the exchange.
    pub msgid: u32,
    /// Its message 3 authenticated (HASH(3) under the last cipher block of a message 2 sent), without the Commit
    /// bit.
    pub qm3_seen: bool,
    /// A copy of one of its messages had the Commit bit set: its SA must never be used (DESIGN 3.6).
    pub commit_seen: bool,
    /// The gateway refused it with an error Notify of this type.
    pub peer_rejected: Option<u16>,
    /// The ISAKMP SA was deleted while it was in progress.
    pub torn_down: bool,
}

impl ResponderEvents {
    /// Whether no fact is new.
    pub fn is_empty(&self) -> bool {
        !self.qm3_seen && !self.commit_seen && self.peer_rejected.is_none() && !self.torn_down
    }
}

/// A gateway Quick Mode of a family held or answered now ([`super::super::phase1::Phase1State::responder_pending`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingResponder {
    /// Which answer it is: what the caller names to end it
    /// ([`super::super::phase1::Phase1State::conclude_responder`]).
    pub id: ResponderId,
    /// The Message ID of the exchange.
    pub msgid: u32,
    /// [`ResponderState::Held`] or [`ResponderState::Answered`].
    pub state: ResponderState,
    /// This side's inbound SPI of the new SA.
    pub inbound_spi: u32,
}

/// The facts of [`ResponderEvents`], as an entry keeps them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Facts {
    pub qm3: bool,
    pub commit: bool,
    pub peer_rejected: Option<u16>,
    pub torn_down: bool,
}

/// One encryption of message 2: under the last cipher block of a copy of message 1 (RFC 2409 Appendix B: "The IV
/// for subsequent messages within a Quick Mode exchange is the CBC output block from the previous message"), and the
/// last block it ends with, which the gateway's message 3 is encrypted under.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Variant {
    pub qm1_last_block: Vec<u8>,
    /// The ISAKMP message, without the non-ESP marker.
    pub qm2: Vec<u8>,
    pub qm2_last_block: Vec<u8>,
    /// Whether it was sent: only a message 2 sent can be what a message 3 answers.
    pub sent: bool,
}

impl Variant {
    fn size(&self) -> usize {
        self.qm1_last_block.len() + self.qm2.len() + self.qm2_last_block.len()
    }
}

/// What an entry holds of its message 2: the plaintext it is encrypted from (HASH(2) first, no padding) and its
/// first payload's type, the nonces HASH(3) is computed over, and the encryptions of it.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Retained {
    pub plaintext: Vec<u8>,
    pub first_payload: u8,
    pub ni: Vec<u8>,
    pub nr: Vec<u8>,
    /// At most [`QM2_VARIANTS`]: the first is the message 2 held, the one sent on release.
    pub variants: Vec<Variant>,
}

impl Retained {
    fn size(&self) -> usize {
        self.plaintext.len() + self.ni.len() + self.nr.len() + self.variants.iter().map(Variant::size).sum::<usize>()
    }
}

/// One gateway Quick Mode the responder answered (see the module doc).
#[derive(Clone)]
pub(crate) struct ResponderEntry {
    pub msgid: u32,
    /// Which hold of the message it is ([`ResponderId`]): given by [`ResponderCache::hold`].
    pub hold: u64,
    pub family: ChildFamily,
    /// The fingerprint of its message 1 ([`super::super::msgid::fingerprint`]).
    pub fingerprint: [u8; 32],
    /// This side's inbound SPI of the new SA: what an error Notify about message 2 names (RFC 2408 §3.14).
    pub inbound_spi: u32,
    pub state: ResponderState,
    /// When it leaves its state at the latest: Held, the end of its hold; Answered, the end of [`ANSWERED_FOR`];
    /// Proven, the end of [`RESP_RETAIN`].
    pub until: Instant,
    pub retained: Retained,
    /// When message 2 last went, by any path ([`ANSWER_SPACING`]).
    pub last_answer: Option<Instant>,
    /// How many times message 2 was handed out to be sent, by any path: on release, for a copy of message 1, as a
    /// resend.
    pub answers: u32,
    /// Which of [`Retained::variants`] was handed out last: the one a resend sends ([`super::AnsweredQuick`]).
    pub last_variant: usize,
    pub facts: Facts,
    /// The facts already handed to the caller.
    pub taken: Facts,
}

impl ResponderEntry {
    /// A gateway Quick Mode held at `now`, until `now` + [`PEER_QM_HOLD_MAX`].
    pub(crate) fn held(msgid: u32, family: ChildFamily, fingerprint: [u8; 32], inbound_spi: u32, retained: Retained, commit_seen: bool, now: Instant) -> Self {
        Self {
            msgid,
            hold: 0,
            family,
            fingerprint,
            inbound_spi,
            state: ResponderState::Held,
            until: now.checked_add(PEER_QM_HOLD_MAX).unwrap_or(now),
            retained,
            last_answer: None,
            answers: 0,
            last_variant: 0,
            facts: Facts { commit: commit_seen, ..Facts::default() },
            taken: Facts::default(),
        }
    }

    /// Which hold it is.
    pub(crate) fn id(&self) -> ResponderId {
        ResponderId { msgid: self.msgid, hold: self.hold }
    }

    fn size(&self) -> usize {
        self.retained.size()
    }

    /// The facts recorded and not handed over yet, `commit` also when `commit_noted` (the table's memory of Commit
    /// bits); they count as handed over from now on.
    pub(crate) fn take_facts(&mut self, commit_noted: bool) -> ResponderEvents {
        let commit = self.facts.commit || commit_noted;
        let events = ResponderEvents {
            msgid: self.msgid,
            qm3_seen: self.facts.qm3 && !self.taken.qm3,
            commit_seen: commit && !self.taken.commit,
            peer_rejected: self.facts.peer_rejected.filter(|_| self.taken.peer_rejected.is_none()),
            torn_down: self.facts.torn_down && !self.taken.torn_down,
        };
        self.taken = Facts { commit, ..self.facts };
        events
    }
}

impl fmt::Debug for ResponderEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResponderEntry")
            .field("msgid", &format_args!("{:08x}", self.msgid))
            .field("hold", &self.hold)
            .field("family", &self.family)
            .field("inbound_spi", &format_args!("{:08x}", self.inbound_spi))
            .field("state", &self.state)
            .field("variants", &self.retained.variants.len())
            .field("facts", &self.facts)
            .finish()
    }
}

/// Why [`ResponderCache::hold`] did not take an exchange; nothing changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HoldRefused {
    /// The Message ID is held, answered, proven, abandoned or cancelled here ([`ResponderCache::may_hold`]):
    /// [`Transition::Hold`] from that state.
    Illegal(IllegalTransition),
    /// Another exchange of the family is in progress.
    Busy,
    /// No room without evicting an exchange in progress.
    Full,
}

/// How a datagram under the id of a responder exchange was taken, counted since the ISAKMP SA began.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ResponderCounters {
    /// Copies of a message 1 answered with its message 2 again.
    pub answered_again: u64,
    /// Copies of a message 1 not answered: while held, sooner than [`ANSWER_SPACING`] after the last answer, with the
    /// Commit bit set, or under a third last cipher block.
    pub copies_unanswered: u64,
    /// Other messages 1 under the id of a responder exchange (another fingerprint).
    pub other_messages: u64,
    /// Messages 3 that authenticated.
    pub qm3: u64,
    /// Datagrams under the id of a held exchange that are no copy of its message 1: nothing can be its message 3
    /// before message 2 left.
    pub qm3_while_held: u64,
    /// Datagrams under the id of an answered or proven exchange that authenticate neither as a copy of its message 1
    /// nor as its message 3.
    pub qm3_invalid: u64,
}

/// The responder's entries (see the module doc).
pub(crate) struct ResponderCache {
    /// Oldest first.
    entries: VecDeque<ResponderEntry>,
    /// The ends of the latest holds that left the cache, oldest first.
    ended: VecDeque<(ResponderId, ResponderState)>,
    /// The number the next hold gets ([`ResponderId`]): never 0, which [`ResponderId::unheld`] is.
    next_hold: u64,
    max_entries: usize,
    max_bytes: usize,
    pub counters: ResponderCounters,
}

impl Default for ResponderCache {
    fn default() -> Self {
        Self::with_limits(CACHE_ENTRIES, CACHE_BYTES)
    }
}

impl ResponderCache {
    /// A cache of at most `max_entries` entries and `max_bytes` octets.
    pub(crate) fn with_limits(max_entries: usize, max_bytes: usize) -> Self {
        Self { entries: VecDeque::new(), ended: VecDeque::new(), next_hold: 1, max_entries, max_bytes, counters: ResponderCounters::default() }
    }

    fn bytes(&self) -> usize {
        self.entries.iter().map(ResponderEntry::size).sum()
    }

    fn position(&self, id: ResponderId) -> Option<usize> {
        self.entries.iter().position(|entry| entry.id() == id)
    }

    /// The entry of `msgid`, whatever its state and hold.
    pub(crate) fn get(&self, msgid: u32) -> Option<&ResponderEntry> {
        self.entries.iter().find(|entry| entry.msgid == msgid)
    }

    pub(crate) fn get_mut(&mut self, msgid: u32) -> Option<&mut ResponderEntry> {
        self.entries.iter_mut().find(|entry| entry.msgid == msgid)
    }

    /// The entry of the hold `id`: none when its Message ID is held again since, under another hold.
    pub(crate) fn get_hold_mut(&mut self, id: ResponderId) -> Option<&mut ResponderEntry> {
        self.entries.iter_mut().find(|entry| entry.id() == id)
    }

    /// Every entry, oldest first.
    pub(crate) fn entries(&self) -> impl Iterator<Item = &ResponderEntry> {
        self.entries.iter()
    }

    pub(crate) fn entries_mut(&mut self) -> impl Iterator<Item = &mut ResponderEntry> {
        self.entries.iter_mut()
    }

    /// The state of `msgid`: its entry's, or the end its latest hold left the cache with, while that is remembered.
    pub(crate) fn state(&self, msgid: u32) -> Option<ResponderState> {
        self.get(msgid).map(|entry| entry.state).or_else(|| self.ended.iter().rev().find(|(id, _)| id.msgid == msgid).map(|&(_, state)| state))
    }

    /// The state of the hold `id`: its entry's, or the end it left the cache with, while that is remembered --
    /// never that of a later hold of the same message.
    pub(crate) fn state_of(&self, id: ResponderId) -> Option<ResponderState> {
        match self.get(id.msgid) {
            Some(entry) if entry.hold == id.hold => Some(entry.state),
            _ => self.ended.iter().rev().find(|(ended, _)| *ended == id).map(|&(_, state)| state),
        }
    }

    /// The exchange of `family` in progress, if there is one.
    pub(crate) fn pending(&self, family: ChildFamily) -> Option<&ResponderEntry> {
        self.entries.iter().find(|entry| entry.family == family && entry.state.in_progress())
    }

    pub(crate) fn pending_mut(&mut self, family: ChildFamily) -> Option<&mut ResponderEntry> {
        self.entries.iter_mut().find(|entry| entry.family == family && entry.state.in_progress())
    }

    /// Whether one more exchange in progress fits beside those in progress now, by their count.
    pub(crate) fn room_for_one_more(&self) -> bool {
        self.entries.iter().filter(|entry| entry.state.in_progress()).count() < self.max_entries
    }

    /// Whether [`Transition::Hold`] is allowed for `msgid` by what the cache knows of it: never held (or forgotten),
    /// or parked -- nothing was sent. Held, answered, proven, abandoned or cancelled, never: the message is answered,
    /// or its exchange ended for good, and a message 2 that left is never replaced by another (DESIGN 8.7, D9).
    pub(crate) fn may_hold(&self, msgid: u32) -> Result<(), IllegalTransition> {
        match self.state(msgid) {
            None | Some(ResponderState::Parked) => Ok(()),
            from => Err(IllegalTransition { msgid, from, to: Transition::Hold }),
        }
    }

    /// Forgets the oldest entry that is not in progress, other than `keep`; `false` when there is none.
    fn evict_one(&mut self, keep: Option<u32>) -> bool {
        let Some(at) = self.entries.iter().position(|entry| !entry.state.in_progress() && Some(entry.msgid) != keep) else { return false };
        if let Some(gone) = self.entries.remove(at) {
            self.remember_end(gone.id(), gone.state);
        }
        true
    }

    /// Whether `extra` more octets -- and, when `one_more`, one more entry -- would fit once every entry not in
    /// progress but `keep` gave way; nothing changes.
    fn room_for(&self, extra: usize, one_more: bool, keep: Option<u32>) -> bool {
        let stays = |entry: &&ResponderEntry| entry.state.in_progress() || Some(entry.msgid) == keep;
        let count = self.entries.iter().filter(stays).count();
        let bytes: usize = self.entries.iter().filter(stays).map(ResponderEntry::size).sum();
        (!one_more || count < self.max_entries) && bytes.saturating_add(extra) <= self.max_bytes
    }

    /// Makes room for `extra` more octets -- and, when `one_more`, one more entry -- by forgetting as few entries not
    /// in progress (oldest first, never `keep`) as it takes; `false`, and nothing forgotten, when even all of them
    /// would not do ([`Self::room_for`]).
    fn make_room(&mut self, extra: usize, one_more: bool, keep: Option<u32>) -> bool {
        if !self.room_for(extra, one_more, keep) {
            return false;
        }
        loop {
            let count_fits = !one_more || self.entries.len() < self.max_entries;
            if count_fits && self.bytes().saturating_add(extra) <= self.max_bytes {
                return true;
            }
            if !self.evict_one(keep) {
                return false;
            }
        }
    }

    fn remember_end(&mut self, id: ResponderId, state: ResponderState) {
        self.ended.retain(|(ended, _)| *ended != id);
        if self.ended.len() >= ENDS_REMEMBERED {
            self.ended.pop_front();
        }
        self.ended.push_back((id, state));
    }

    /// Removes the entry of the hold `id`, which leaves the cache in `state`.
    fn end(&mut self, id: ResponderId, state: ResponderState) {
        if let Some(at) = self.position(id) {
            self.entries.remove(at);
        }
        self.remember_end(id, state);
    }

    /// [`Transition::Hold`]: takes `entry`, held, as a hold of its own ([`ResponderId`], which it returns). Refused,
    /// with nothing changed, when its Message ID may not be held ([`Self::may_hold`]: only one never held, or parked,
    /// may), when an exchange of its family is in progress, or when it does not fit without evicting one in progress;
    /// otherwise proven entries of other messages give way, the oldest first, as far as it needs.
    pub(crate) fn hold(&mut self, mut entry: ResponderEntry) -> Result<ResponderId, HoldRefused> {
        self.may_hold(entry.msgid).map_err(HoldRefused::Illegal)?;
        if self.pending(entry.family).is_some() {
            return Err(HoldRefused::Busy);
        }
        if !self.make_room(entry.size(), true, None) {
            return Err(HoldRefused::Full);
        }
        entry.hold = self.next_hold;
        self.next_hold = self.next_hold.checked_add(1).unwrap_or(1);
        let id = entry.id();
        self.entries.push_back(entry);
        Ok(id)
    }

    /// The entry of the hold `id` if its state is one of `from`, or the move refused.
    fn in_state(&mut self, id: ResponderId, to: Transition, from: &[ResponderState]) -> Result<&mut ResponderEntry, IllegalTransition> {
        let state = self.state_of(id);
        match self.get_hold_mut(id) {
            Some(entry) if from.contains(&entry.state) => Ok(entry),
            _ => Err(IllegalTransition { msgid: id.msgid, from: state, to }),
        }
    }

    /// [`Transition::Answer`]: held -> answered at `now`, its first message 2 handed out to be sent; in progress until
    /// [`ANSWERED_FOR`] after it.
    pub(crate) fn answered(&mut self, id: ResponderId, now: Instant) -> Result<ResponderState, IllegalTransition> {
        let entry = self.in_state(id, Transition::Answer, &[ResponderState::Held])?;
        entry.state = ResponderState::Answered;
        entry.until = now.checked_add(ANSWERED_FOR).unwrap_or(now);
        entry.last_answer = Some(now);
        entry.answers = entry.answers.saturating_add(1);
        entry.last_variant = 0;
        if let Some(first) = entry.retained.variants.first_mut() {
            first.sent = true;
        }
        Ok(ResponderState::Answered)
    }

    /// The message 2 [`Self::answered`] handed out could not be sent: when nothing else handed message 2 out since --
    /// it never left --, answered -> parked, dropped at once as [`Self::park`] drops a held one (D9: its message 1 may
    /// be answered anew); otherwise it stays answered, a message 2 having gone another way. Refused, nothing changed,
    /// for a hold that is not answered.
    pub(crate) fn release_failed(&mut self, id: ResponderId) -> Result<ResponderState, IllegalTransition> {
        let entry = self.in_state(id, Transition::Park, &[ResponderState::Answered])?;
        if entry.answers > 1 {
            return Ok(ResponderState::Answered);
        }
        self.end(id, ResponderState::Parked);
        Ok(ResponderState::Parked)
    }

    /// [`Transition::Prove`]: answered -> proven by `proof` at `now`; kept [`RESP_RETAIN`] for copies of message 1.
    pub(crate) fn proven(&mut self, id: ResponderId, proof: Proof, now: Instant) -> Result<ResponderState, IllegalTransition> {
        let entry = self.in_state(id, Transition::Prove, &[ResponderState::Answered])?;
        entry.state = ResponderState::Proven(proof);
        entry.until = now.checked_add(RESP_RETAIN).unwrap_or(now);
        Ok(entry.state)
    }

    /// [`Transition::Abandon`]: answered -> abandoned for `reason`; dropped at once with its message 2.
    pub(crate) fn abandon(&mut self, id: ResponderId, reason: EndReason) -> Result<ResponderState, IllegalTransition> {
        self.in_state(id, Transition::Abandon, &[ResponderState::Answered])?;
        let state = ResponderState::Abandoned(reason);
        self.end(id, state);
        Ok(state)
    }

    /// [`Transition::Cancel`]: held or answered -> cancelled for `reason`; dropped at once with its message 2.
    pub(crate) fn cancel(&mut self, id: ResponderId, reason: EndReason) -> Result<ResponderState, IllegalTransition> {
        self.in_state(id, Transition::Cancel, &[ResponderState::Held, ResponderState::Answered])?;
        let state = ResponderState::Cancelled(reason);
        self.end(id, state);
        Ok(state)
    }

    /// [`Transition::Park`]: held -> parked (nothing was sent); dropped at once.
    pub(crate) fn park(&mut self, id: ResponderId) -> Result<ResponderState, IllegalTransition> {
        self.in_state(id, Transition::Park, &[ResponderState::Held])?;
        self.end(id, ResponderState::Parked);
        Ok(ResponderState::Parked)
    }

    /// Ends what has come to its time at `now`: a held exchange past its hold is parked, an answered one past
    /// [`ANSWERED_FOR`] abandoned ([`EndReason::Deadline`]), a proven one past [`RESP_RETAIN`] forgotten. Returns the
    /// families whose exchange in progress ended, and when (the time it came to, not `now`).
    pub(crate) fn sweep(&mut self, now: Instant) -> Vec<(ChildFamily, Instant)> {
        let mut concluded = Vec::new();
        let due: Vec<(ResponderId, ChildFamily, ResponderState, Instant)> =
            self.entries.iter().filter(|entry| entry.until <= now).map(|entry| (entry.id(), entry.family, entry.state, entry.until)).collect();
        for (id, family, state, until) in due {
            let end = match state {
                ResponderState::Held => ResponderState::Parked,
                ResponderState::Answered => ResponderState::Abandoned(EndReason::Deadline),
                other => other,
            };
            if state.in_progress() {
                concluded.push((family, until));
            }
            self.end(id, end);
        }
        concluded
    }

    /// Adds `variant` to the entry of the hold `id` when it keeps fewer than [`QM2_VARIANTS`] and the octets fit
    /// (entries not in progress, but this one, giving way): the index it is kept at; `None`, and nothing added or
    /// forgotten, otherwise.
    pub(crate) fn add_variant(&mut self, id: ResponderId, variant: Variant) -> Option<usize> {
        let held = self.entries.iter().find(|entry| entry.id() == id)?;
        if held.retained.variants.len() >= QM2_VARIANTS || !self.make_room(variant.size(), false, Some(id.msgid)) {
            return None;
        }
        let entry = self.get_hold_mut(id)?;
        entry.retained.variants.push(variant);
        Some(entry.retained.variants.len() - 1)
    }

    /// How many entries it holds, and their octets.
    #[cfg(test)]
    pub(crate) fn held(&self) -> (usize, usize) {
        (self.entries.len(), self.bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0_OFFSET: Duration = Duration::from_secs(1);

    fn retained(size: usize) -> Retained {
        let variant = Variant { qm1_last_block: vec![1; 16], qm2: vec![2; size], qm2_last_block: vec![3; 16], sent: false };
        Retained { plaintext: vec![4; 8], first_payload: 8, ni: vec![5; 16], nr: vec![6; 16], variants: vec![variant] }
    }

    fn entry(msgid: u32, family: ChildFamily, size: usize, now: Instant) -> ResponderEntry {
        ResponderEntry::held(msgid, family, [msgid as u8; 32], 0x1000 + msgid, retained(size), false, now)
    }

    fn states() -> [(&'static str, Option<ResponderState>); 7] {
        [
            ("never held", None),
            ("held", Some(ResponderState::Held)),
            ("answered", Some(ResponderState::Answered)),
            ("proven", Some(ResponderState::Proven(Proof::Qm3))),
            ("abandoned", Some(ResponderState::Abandoned(EndReason::NoProof))),
            ("cancelled", Some(ResponderState::Cancelled(EndReason::Disconnect))),
            ("parked", Some(ResponderState::Parked)),
        ]
    }

    /// A cache whose exchange 7 is in `state` (`None`: never held), reached by legal moves only, and the id of that
    /// hold (`None` when there was none).
    fn reach(state: Option<ResponderState>, now: Instant) -> (ResponderCache, Option<ResponderId>) {
        let mut cache = ResponderCache::default();
        let Some(state) = state else { return (cache, None) };
        let id = cache.hold(entry(7, ChildFamily::Primary, 100, now)).expect("held");
        match state {
            ResponderState::Held => {}
            ResponderState::Parked => assert_eq!(cache.park(id), Ok(ResponderState::Parked)),
            ResponderState::Cancelled(reason) => assert_eq!(cache.cancel(id, reason), Ok(state)),
            _ => {
                assert_eq!(cache.answered(id, now), Ok(ResponderState::Answered));
                match state {
                    ResponderState::Proven(proof) => assert_eq!(cache.proven(id, proof, now), Ok(state)),
                    ResponderState::Abandoned(reason) => assert_eq!(cache.abandon(id, reason), Ok(state)),
                    _ => {}
                }
            }
        }
        assert_eq!((cache.state(7), cache.state_of(id)), (Some(state), Some(state)));
        (cache, Some(id))
    }

    type Move = fn(&mut ResponderCache, ResponderId, Instant) -> Result<ResponderState, IllegalTransition>;

    /// The moves that name a hold, each with what it asks for.
    fn moves() -> [(&'static str, Transition, Move); 5] {
        [
            ("answer", Transition::Answer, |cache, id, now| cache.answered(id, now)),
            ("prove", Transition::Prove, |cache, id, now| cache.proven(id, Proof::Esp, now)),
            ("abandon", Transition::Abandon, |cache, id, _| cache.abandon(id, EndReason::NoProof)),
            ("cancel", Transition::Cancel, |cache, id, _| cache.cancel(id, EndReason::TornDown)),
            ("park", Transition::Park, |cache, id, _| cache.park(id)),
        ]
    }

    /// Every move from every state: the legal ones give the state the machine says, and leave the entry where that
    /// state keeps it (in the cache while held, answered or proven, gone otherwise); the illegal ones are refused with
    /// the state they were asked from, and change nothing. A hold is legal only for a message never held or parked
    /// (nothing sent): once held, answered or ended for good, never again.
    #[test]
    fn every_move_from_every_state_is_taken_or_refused_as_the_state_machine_says() {
        let now = Instant::now() + T0_OFFSET;
        use ResponderState as S;
        let legal = |from: Option<S>, to: Transition| -> Option<S> {
            match (from, to) {
                (None | Some(S::Parked), Transition::Hold) => Some(S::Held),
                (Some(S::Held), Transition::Answer) => Some(S::Answered),
                (Some(S::Answered), Transition::Prove) => Some(S::Proven(Proof::Esp)),
                (Some(S::Answered), Transition::Abandon) => Some(S::Abandoned(EndReason::NoProof)),
                (Some(S::Held | S::Answered), Transition::Cancel) => Some(S::Cancelled(EndReason::TornDown)),
                (Some(S::Held), Transition::Park) => Some(S::Parked),
                _ => None,
            }
        };
        let mut wrong = Vec::new();
        for (from_name, from) in states() {
            let hold: (&str, Transition, Move) = ("hold", Transition::Hold, |cache, _, now| {
                cache.hold(entry(7, ChildFamily::Primary, 100, now)).map(|_| ResponderState::Held).map_err(|refused| match refused {
                    HoldRefused::Illegal(illegal) => illegal,
                    other => panic!("{other:?}"),
                })
            });
            for (move_name, to, apply) in std::iter::once(hold).chain(moves()) {
                let (mut cache, id) = reach(from, now);
                let id = id.unwrap_or(ResponderId { msgid: 7, hold: 1 });
                let before = cache.get(7).map(|entry| (entry.state, entry.until, entry.hold));
                let got = apply(&mut cache, id, now);
                match (legal(from, to), got) {
                    (Some(want), Ok(state)) if state == want => {
                        if cache.state(7) != Some(want) {
                            wrong.push(format!("{move_name} from {from_name}: the cache says {:?}", cache.state(7)));
                        }
                        if cache.get(7).is_some() != matches!(want, S::Held | S::Answered | S::Proven(_)) {
                            wrong.push(format!("{move_name} from {from_name}: the entry is {}kept", if cache.get(7).is_some() { "" } else { "not " }));
                        }
                    }
                    (None, Err(illegal)) if illegal == (IllegalTransition { msgid: 7, from, to }) => {
                        if cache.get(7).map(|entry| (entry.state, entry.until, entry.hold)) != before || cache.state(7) != from {
                            wrong.push(format!("{move_name} from {from_name}: refused, but the entry changed"));
                        }
                    }
                    (want, got) => wrong.push(format!("{move_name} from {from_name}: {got:?}, wanted {want:?}")),
                }
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }

    /// A message parked and held again is a hold of its own: every move named by the earlier hold is refused with
    /// that hold's end -- parked -- and leaves the later one as it was; the later one's moves are taken. An id never
    /// given (an answer built and not held) names nothing.
    #[test]
    fn a_move_named_by_an_earlier_hold_of_a_message_held_again_is_refused() {
        let now = Instant::now() + T0_OFFSET;
        for later in [ResponderState::Held, ResponderState::Answered] {
            let mut cache = ResponderCache::default();
            let first = cache.hold(entry(7, ChildFamily::Primary, 100, now)).unwrap();
            assert_eq!(cache.park(first), Ok(ResponderState::Parked));
            let second = cache.hold(entry(7, ChildFamily::Primary, 100, now)).unwrap();
            assert_ne!(first, second);
            if later == ResponderState::Answered {
                cache.answered(second, now).unwrap();
            }
            let before = cache.get(7).map(|entry| (entry.state, entry.until, entry.answers));
            for (move_name, to, apply) in moves() {
                for stale in [first, ResponderId::unheld(7)] {
                    let want = IllegalTransition { msgid: 7, from: (stale == first).then_some(ResponderState::Parked), to };
                    assert_eq!(apply(&mut cache, stale, now), Err(want), "{move_name} named by {stale:?}, the later one {later:?}");
                    assert_eq!(cache.release_failed(stale).err().map(|illegal| illegal.from), Some(want.from), "{stale:?}");
                    assert_eq!(cache.get(7).map(|entry| (entry.state, entry.until, entry.answers)), before, "{move_name} by {stale:?}: nothing changed");
                }
            }
            assert_eq!((cache.state(7), cache.state_of(second), cache.state_of(first)), (Some(later), Some(later), Some(ResponderState::Parked)));
            assert_eq!(cache.cancel(second, EndReason::Disconnect), Ok(ResponderState::Cancelled(EndReason::Disconnect)), "the later hold's own move");
        }
    }

    /// A hold the cache refuses changes nothing: not for its own Message ID ended or in progress, not for a busy
    /// family, not when it does not fit -- no proven entry gives way for a hold that is not taken.
    #[test]
    fn a_refused_hold_forgets_nothing() {
        let now = Instant::now() + T0_OFFSET;
        let proven = |cache: &mut ResponderCache, msgid: u32, family: ChildFamily, size: usize| {
            let id = cache.hold(entry(msgid, family, size, now)).unwrap();
            cache.answered(id, now).unwrap();
            cache.proven(id, Proof::Qm3, now).unwrap();
        };
        let mut cache = ResponderCache::with_limits(CACHE_ENTRIES, 2048);
        proven(&mut cache, 1, ChildFamily::Primary, 400);
        proven(&mut cache, 2, ChildFamily::Ipv6, 400);
        let busy = cache.hold(entry(3, ChildFamily::Primary, 300, now)).unwrap();
        let held = cache.held();
        assert_eq!(
            cache.hold(entry(1, ChildFamily::Ipv6, 100, now)),
            Err(HoldRefused::Illegal(IllegalTransition { msgid: 1, from: Some(ResponderState::Proven(Proof::Qm3)), to: Transition::Hold })),
            "its own message, proven"
        );
        assert_eq!(cache.hold(entry(4, ChildFamily::Primary, 100, now)), Err(HoldRefused::Busy));
        assert_eq!(cache.hold(entry(4, ChildFamily::Ipv6, 1900, now)), Err(HoldRefused::Full), "no room beside the one in progress");
        assert_eq!(cache.held(), held, "nothing gave way");
        assert!(cache.get(1).is_some() && cache.get(2).is_some() && cache.state_of(busy) == Some(ResponderState::Held));
        assert_eq!(cache.add_variant(busy, Variant { qm1_last_block: vec![9; 16], qm2: vec![9; 1900], qm2_last_block: vec![9; 16], sent: true }), None);
        assert_eq!(cache.held(), held, "nor for a second encryption that does not fit");
    }

    /// A release whose send failed: parked when nothing else handed message 2 out since -- dropped, its message 1 may
    /// be answered anew --, answered still when a copy of message 1 was answered meanwhile; refused for a hold that
    /// is not answered.
    #[test]
    fn a_failed_release_parks_the_exchange_only_when_no_message_2_went() {
        let now = Instant::now() + T0_OFFSET;
        let (mut cache, id) = reach(Some(ResponderState::Answered), now);
        let id = id.unwrap();
        assert_eq!(cache.release_failed(id), Ok(ResponderState::Parked));
        assert_eq!((cache.get(7).is_some(), cache.state(7)), (false, Some(ResponderState::Parked)));
        assert_eq!(cache.may_hold(7), Ok(()), "parked: it may be held again");

        let (mut cache, id) = reach(Some(ResponderState::Answered), now);
        let id = id.unwrap();
        if let Some(entry) = cache.get_hold_mut(id) {
            entry.answers += 1;
        }
        assert_eq!(cache.release_failed(id), Ok(ResponderState::Answered), "a message 2 went for a copy");
        assert_eq!(cache.state(7), Some(ResponderState::Answered));

        let (mut cache, id) = reach(Some(ResponderState::Held), now);
        let id = id.unwrap();
        assert_eq!(cache.release_failed(id), Err(IllegalTransition { msgid: 7, from: Some(ResponderState::Held), to: Transition::Park }));
        assert_eq!(cache.state(7), Some(ResponderState::Held));
    }

    /// Held, an exchange has its hold bound; answered, its wait; proven, its retention: at each the sweep ends it --
    /// parked, abandoned for the deadline, forgotten -- and tells the family of an exchange that was in progress, at the
    /// instant it came to, not the instant of the sweep. A nanosecond before, nothing ends.
    #[test]
    fn the_sweep_ends_each_state_at_its_own_time() {
        let t0 = Instant::now() + T0_OFFSET;
        let late = Duration::from_secs(30);
        type Case = (&'static str, Option<ResponderState>, Duration, ResponderState, bool);
        let cases: [Case; 3] = [
            ("held", Some(ResponderState::Held), PEER_QM_HOLD_MAX, ResponderState::Parked, true),
            ("answered", Some(ResponderState::Answered), ANSWERED_FOR, ResponderState::Abandoned(EndReason::Deadline), true),
            ("proven", Some(ResponderState::Proven(Proof::Qm3)), RESP_RETAIN, ResponderState::Proven(Proof::Qm3), false),
        ];
        for (what, state, bound, end, in_progress) in cases {
            let (mut cache, _) = reach(state, t0);
            assert!(cache.sweep(t0 + bound - Duration::from_nanos(1)).is_empty(), "{what}");
            assert!(cache.get(7).is_some(), "{what}: still there a nanosecond before");
            let concluded = cache.sweep(t0 + bound + late);
            assert_eq!(concluded, if in_progress { vec![(ChildFamily::Primary, t0 + bound)] } else { vec![] }, "{what}");
            assert!(cache.get(7).is_none(), "{what}: gone");
            assert_eq!(cache.state(7), Some(end), "{what}: its end remembered");
        }
    }

    /// At most four entries and 16 KiB: proven entries give way to a new one, oldest first; an entry in progress
    /// never does -- a new exchange that would need its room is refused (the caller defers its message 1); and one
    /// exchange per family is in progress at a time.
    #[test]
    fn the_cache_keeps_its_bounds_and_never_evicts_an_exchange_in_progress() {
        let now = Instant::now() + T0_OFFSET;
        let proven = |cache: &mut ResponderCache, msgid: u32, size: usize| {
            let id = cache.hold(entry(msgid, ChildFamily::Primary, size, now)).expect("held");
            cache.answered(id, now).unwrap();
            cache.proven(id, Proof::Qm3, now).unwrap();
        };
        let mut cache = ResponderCache::default();
        for msgid in 1..=4 {
            proven(&mut cache, msgid, 100);
        }
        assert_eq!(cache.held().0, CACHE_ENTRIES);
        assert!(cache.hold(entry(5, ChildFamily::Primary, 100, now)).is_ok(), "a fifth: the oldest proven gives way");
        assert_eq!((cache.held().0, cache.get(1).is_none(), cache.state(1)), (CACHE_ENTRIES, true, Some(ResponderState::Proven(Proof::Qm3))));
        assert_eq!(cache.hold(entry(6, ChildFamily::Primary, 100, now)), Err(HoldRefused::Busy), "one exchange per family in progress");
        assert!(cache.hold(entry(6, ChildFamily::Ipv6, 100, now)).is_ok(), "the other family is free");
        assert!(cache.get(5).is_some() && cache.get(6).is_some(), "both in progress kept");

        // Octets: proven entries give way, oldest first, as far as a new exchange in progress needs.
        let mut cache = ResponderCache::default();
        proven(&mut cache, 1, 3 * 1024);
        proven(&mut cache, 4, 3 * 1024);
        assert!(cache.hold(entry(2, ChildFamily::Primary, 7 * 1024, now)).is_ok());
        assert!(cache.get(1).is_some() && cache.get(4).is_some(), "13 KiB fit");
        assert!(cache.hold(entry(3, ChildFamily::Ipv6, 7 * 1024, now)).is_ok());
        assert!(cache.get(1).is_none() && cache.get(4).is_none(), "both proven entries gave way: one was not enough");
        assert!(cache.get(2).is_some() && cache.get(3).is_some() && cache.held().1 <= CACHE_BYTES);
        let mut full = ResponderCache::with_limits(2, CACHE_BYTES);
        assert!(full.hold(entry(2, ChildFamily::Primary, 100, now)).is_ok());
        assert!(full.hold(entry(3, ChildFamily::Ipv6, 100, now)).is_ok());
        assert!(!full.room_for_one_more(), "two in progress fill a cache of two");
        let mut tight = ResponderCache::with_limits(CACHE_ENTRIES, 2048);
        assert!(tight.hold(entry(2, ChildFamily::Primary, 1500, now)).is_ok());
        assert_eq!(tight.hold(entry(3, ChildFamily::Ipv6, 1500, now)), Err(HoldRefused::Full), "no octets without evicting one in progress");
        assert!(tight.get(2).is_some() && tight.held().1 <= 2048);
    }

    /// A second encryption of message 2 is kept, a third is not; the octets it needs are made by proven entries
    /// giving way, never the entry itself or one in progress.
    #[test]
    fn an_entry_keeps_two_encryptions_of_its_message_2_at_most() {
        let now = Instant::now() + T0_OFFSET;
        let variant = |n: u8| Variant { qm1_last_block: vec![n; 16], qm2: vec![n; 300], qm2_last_block: vec![n; 16], sent: true };
        // Two entries of 372 octets and a second encryption of 332: 1076 octets, over a bound of 1000.
        let mut cache = ResponderCache::with_limits(CACHE_ENTRIES, 1000);
        let first = cache.hold(entry(1, ChildFamily::Ipv6, 300, now)).unwrap();
        cache.answered(first, now).unwrap();
        cache.proven(first, Proof::Esp, now).unwrap();
        let second = cache.hold(entry(2, ChildFamily::Primary, 300, now)).unwrap();
        cache.answered(second, now).unwrap();
        assert_eq!(cache.add_variant(second, variant(9)), Some(1), "a second, the proven entry giving way");
        assert!(cache.get(1).is_none());
        assert_eq!(cache.get(2).map(|entry| entry.retained.variants.len()), Some(2));
        assert!(cache.held().1 <= 1000);
        assert_eq!(cache.add_variant(second, variant(10)), None, "no third");
        assert_eq!(cache.add_variant(ResponderId { msgid: 3, hold: 9 }, variant(10)), None, "no entry");
        assert_eq!(cache.add_variant(ResponderId { hold: second.hold + 1, ..second }, variant(10)), None, "another hold of its id");

        let mut cache = ResponderCache::with_limits(CACHE_ENTRIES, 1000);
        let mut last = None;
        for (msgid, family) in [(3, ChildFamily::Ipv6), (4, ChildFamily::Primary)] {
            let id = cache.hold(entry(msgid, family, 300, now)).unwrap();
            cache.answered(id, now).unwrap();
            last = Some(id);
        }
        assert_eq!(cache.add_variant(last.unwrap(), variant(9)), None, "no room but what exchanges in progress hold");
        assert!(cache.get(3).is_some() && cache.get(4).map(|entry| entry.retained.variants.len()) == Some(1));
    }

    /// Each fact is handed over once; one recorded later is handed over then; the Commit bit the table remembers of
    /// the message counts as recorded.
    #[test]
    fn the_facts_of_an_exchange_are_handed_over_once_each() {
        let now = Instant::now() + T0_OFFSET;
        let mut held = entry(1, ChildFamily::Primary, 100, now);
        assert!(held.take_facts(false).is_empty());
        held.facts.qm3 = true;
        held.facts.peer_rejected = Some(14);
        let first = held.take_facts(false);
        assert_eq!((first.msgid, first.qm3_seen, first.commit_seen, first.peer_rejected, first.torn_down), (1, true, false, Some(14), false));
        assert!(held.take_facts(false).is_empty(), "nothing new");
        held.facts.peer_rejected = Some(18);
        held.facts.torn_down = true;
        let second = held.take_facts(true);
        assert_eq!((second.qm3_seen, second.commit_seen, second.peer_rejected, second.torn_down), (false, true, None, true));
        assert!(held.take_facts(true).is_empty());
        let flagged = ResponderEntry::held(2, ChildFamily::Ipv6, [2; 32], 3, retained(10), true, now).take_facts(false);
        assert!(flagged.commit_seen, "a Commit bit seen on the message 1 answered");
    }
}
