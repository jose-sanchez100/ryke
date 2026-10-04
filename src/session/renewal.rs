//! The record of one family's renewals: what a consumer has to remember of the CHILD SAs that
//! carry one kind of traffic between the exchanges that renew them, and the queries it asks of it.
//!
//! A family is a line of CHILD SAs, each put in the place of the one before ([`ChildId`] numbers
//! them). Its record ([`FamilyRenewal`]) holds the last renewal attempt (what
//! [`Spacing::schedule`](super::spacing::Spacing::schedule) is fed), a rekey of ours negotiated
//! and not yet committed or abandoned ([`Negotiated`]), the switch of outbound to an SA this side
//! answered for, deferred until the peer is known to have it ([`DeferredSwitch`]), and the SAs no
//! longer the family's, with where each one's Delete stands ([`Retired`]): those whose Delete this
//! side owes apart from the settled ones, within the bounds the caller gives ([`RetiredBounds`]).
//! An SA's clock by age ([`AgeClock`]) is kept beside it, one per SA.
//!
//! The record records facts and answers queries: it decides nothing and does nothing. It retries
//! no Delete -- it says which are owed -- and times nothing out -- it says when a deferred switch
//! has waited as long as the caller allows. Whether an SA is to be renewed by its volume is for
//! [`limits`](super::limits) and [`spacing`](super::spacing) to say, not the record. It checks no
//! event of the peer's against a generation: a Delete names an SA, never just a family, and a
//! Delete of an old SA must never retire its replacement, so the record keeps the SPIs and the
//! generation that tell one SA from the next, and the telling is the caller's.
//!
//! Nothing here reads a clock: every instant is the caller's, and so is every figure -- how long a
//! deferred switch may wait, how many settled retired SAs are kept and how many owed ones there may
//! be.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use super::spacing::LastAttempt;
use super::timing::RenewalTiming;

/// One CHILD SA in its family's line: generation 0 for the first, one more for each SA put in its
/// place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChildId {
    /// Its place in the family's line.
    pub generation: u64,
    /// The SPI this side receives on.
    pub local_spi: u32,
    /// The SPI the peer receives on, which this side sends to.
    pub peer_spi: u32,
}

impl ChildId {
    /// The first SA of a family: generation 0.
    pub fn first(local_spi: u32, peer_spi: u32) -> ChildId {
        ChildId { generation: 0, local_spi, peer_spi }
    }

    /// The SA put in this one's place, with its own SPIs: the next generation (which stops at
    /// `u64::MAX` rather than wrap).
    pub fn successor(self, local_spi: u32, peer_spi: u32) -> ChildId {
        ChildId { generation: self.generation.saturating_add(1), local_spi, peer_spi }
    }

    /// Its SPIs, `(local, peer)`.
    pub fn spis(self) -> (u32, u32) {
        (self.local_spi, self.peer_spi)
    }
}

/// An SA's renewal clock by age; every instant is the caller's. A successful renewal makes a new
/// SA, whose clock is started again: nothing here carries over from one SA to the next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgeClock {
    /// When the SA was made.
    pub born: Instant,
    /// The lifetime in seconds it was granted.
    pub lifetime_secs: u32,
    /// When the last renewal attempt of it failed, if one did.
    pub last_failure: Option<Instant>,
}

impl AgeClock {
    /// The clock of an SA granted `lifetime_secs`, made at `now`, with no failed attempt.
    pub fn started(lifetime_secs: u32, now: Instant) -> Self {
        Self { born: now, lifetime_secs, last_failure: None }
    }

    /// How old the SA is at `now`; zero for a `now` before it was made.
    pub fn age(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.born)
    }

    /// How long ago, at `now`, the last attempt failed; zero for a `now` before that, `None` if
    /// none did.
    pub fn since_failure(&self, now: Instant) -> Option<Duration> {
        self.last_failure.map(|failed| now.saturating_duration_since(failed))
    }

    /// Whether the SA is due for renewal by its age at `now`:
    /// [`RenewalTiming::due_by_age`] of its [`age`](Self::age), its lifetime and the time
    /// [`since_failure`](Self::since_failure), nothing more.
    pub fn due(&self, timing: &RenewalTiming, now: Instant) -> bool {
        timing.due_by_age(self.age(now), self.lifetime_secs, self.since_failure(now))
    }

    /// A renewal attempt of the SA failed at `now`, in place of any earlier failure: the next one
    /// waits [`RenewalTiming::retry_after`] from here.
    pub fn failed(&mut self, now: Instant) {
        self.last_failure = Some(now);
    }
}

/// A rekey of ours negotiated, not yet committed or abandoned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Negotiated {
    /// The SA it is to replace.
    pub replaces: ChildId,
    /// The new SA's SPIs, `(local, peer)`.
    pub new: (u32, u32),
    /// When the attempt that negotiated it started.
    pub started: Instant,
}

/// The switch of outbound to an SA this side answered as the responder (RFC 7296 §2.8), deferred
/// until the peer is known to have it. `T` is the caller's name for the SA in its data plane; the
/// record never looks inside it.
///
/// The responder of a rekey keeps sending on the replaced SA until a valid message comes in on the
/// new one or the peer asks to close the replaced one (RFC 7296 §2.8), while a node with two SAs
/// eligible to receive accepts inbound on either (§2.8.1), so outbound moves only once there is a
/// reason to ([`SwitchProof`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeferredSwitch<T> {
    /// The new SA, as the caller's data plane names it.
    pub id: T,
    /// The SPI this side receives on in the new SA.
    pub local_spi: u32,
    /// The SPIs, `(local, peer)`, of the SA it replaces, outbound still on it.
    pub replaced: (u32, u32),
    /// When this side's answer went.
    pub answered: Instant,
}

/// Why a deferred switch is made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwitchProof {
    /// The caller saw the peer send on the new SA: a valid message came in on it (RFC 7296 §2.8,
    /// its first case).
    PeerSent,
    /// The peer asked to close the replaced SA (RFC 7296 §2.8, its second case). Never returned by
    /// [`FamilyRenewal::switch_proof`]: a reason the caller gives when it switches on that request,
    /// which it knows of as it handles it ([`FamilyRenewal::waits_on_delete_of`]).
    ReplacedDeleted,
    /// Another operation needs the family's next place -- a renewal of ours, another rekey of the
    /// peer's: no proof that the peer has the SA, a reason to switch all the same. Never returned
    /// by [`FamilyRenewal::switch_proof`]: a reason the caller gives when it switches for it.
    SlotNeeded,
    /// No proof came within the wait the caller allows: the switch is made without one.
    Unproven,
}

/// Which end deletes a retired SA.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Party {
    /// This side: it owes the SA's Delete.
    Ours,
    /// The peer, which deleted it or is to: this side owes nothing.
    Peers,
}

/// Where a retired SA's one Delete stands.
///
/// What came of a Delete tried falls in three classes a caller has to tell apart: confirmed
/// (`Sent { acknowledged: true }`: the peer answered it), failed (`Failed`: certainly not sent),
/// and uncertain (`Sent { acknowledged: false }`: sent, with no answer; `Unknown`: not known
/// whether it was sent). `NotSent` is a Delete not tried yet, and `NotOwed` one there is none of.
/// `ConnectionEnded` is a Delete that can no longer be sent because the IKE SA is over: the local
/// record of it is closed, and what the peer still holds is not known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteStand {
    /// Sent; `acknowledged` once the peer's answer to it came in.
    Sent { acknowledged: bool },
    /// Not tried yet.
    NotSent,
    /// None is owed, for the reason named (the peer deleted the SA itself, say, or its SPI names
    /// another SA of ours).
    NotOwed(&'static str),
    /// Tried, and certainly not sent: it could not be built, or it could not be handed to the
    /// socket.
    Failed,
    /// Tried, and whether it was sent is not known: the attempt ended in an error that may have
    /// come after it was handed to the socket.
    Unknown,
    /// The connection ended: the IKE SA it was owed under is over (the protocol's
    /// `NotOwed("ike_sa_gone")`, as the consumer maps it), so there is nothing left to send it on.
    /// That ends only the local record of the debt. It is not a confirmation: no answer of the
    /// peer's to a Delete of this SA came, the end of the IKE SA proves nothing about the SA at the
    /// peer -- this side's Delete of the IKE SA may never have been received -- and what the peer
    /// still holds is not known. Not the peer's to delete either, nor a Delete there never was.
    /// Never tried again.
    ConnectionEnded,
}

/// An SA that is no longer its family's, and its Delete: who owes it and where it stands. It
/// carries the SA's SPIs and, when known, its generation, because a Delete names an SA, never just
/// a family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retired {
    /// Its SPIs, `(local, peer)`.
    pub spis: (u32, u32),
    /// Its generation in the family's line, if the caller knows it.
    pub generation: Option<u64>,
    /// Who deletes it.
    pub deleted_by: Party,
    /// Where its Delete stands.
    pub stand: DeleteStand,
}

impl Retired {
    /// This side owes its Delete and has not had it answered: not tried, failed, not known to have
    /// gone, or sent with no answer yet. Not one whose connection ended
    /// ([`DeleteStand::ConnectionEnded`]): it is not answered either, but it cannot be sent any more.
    fn owed(&self) -> bool {
        self.deleted_by == Party::Ours
            && matches!(
                self.stand,
                DeleteStand::NotSent | DeleteStand::Failed | DeleteStand::Unknown | DeleteStand::Sent { acknowledged: false }
            )
    }

    /// The same SA as `other`: the same SPIs and the same generation, both (a `None` generation is
    /// the same only as another `None`).
    fn same_sa(&self, other: &Retired) -> bool {
        self.spis == other.spis && self.generation == other.generation
    }
}

/// The bounds on the retired SAs a record keeps; both figures are the caller's.
///
/// `settled_kept` bounds the settled entries -- those no longer owed in the local record: its Delete
/// answered, none owed, the peer's to delete, or its connection ended with the peer's outcome not
/// known ([`DeleteStand::ConnectionEnded`]) --: past it, the oldest settled one goes first. `owed_max` bounds nothing the record
/// drops: it is where the caller stops *starting* what may owe another Delete
/// ([`FamilyRenewal::owed_room`], asked before the operation). A Delete owed is kept whatever the
/// count ([`Retirement::OverCapacity`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetiredBounds {
    /// How many settled retired SAs are kept, at most.
    pub settled_kept: usize,
    /// How many retired SAs may stand with their Delete owed before the caller stops starting
    /// what may owe another.
    pub owed_max: usize,
}

/// What became of an SA retired ([`FamilyRenewal::retire_within`]).
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retirement {
    /// Nothing owed for it (or nothing that can still be sent: its connection ended): kept among the
    /// settled ones, within `settled_kept` (the oldest settled one goes first -- with 0, it is not kept
    /// at all).
    Settled,
    /// Its Delete is owed: kept; `room` more may be owed within `owed_max` (0: at capacity).
    Owed {
        /// How many more may be owed within `owed_max`.
        room: usize,
    },
    /// Its Delete is owed and the record already held `owed_max`: kept all the same -- `owed` are
    /// held now. Refusing it would be dropping it.
    OverCapacity {
        /// How many are owed now, this one included.
        owed: usize,
    },
}

/// What became of an update of an owed Delete ([`FamilyRenewal::update`]).
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Update {
    /// No owed entry of that SA, by its SPIs and its generation: nothing changed.
    NoSuchDebt,
    /// Updated, and its Delete still owed: in its place among the owed ones.
    Owed,
    /// Updated, and no longer owed: put last among the settled ones, within `settled_kept`. Its
    /// stand says why -- answered, the peer's, none owed, or the connection ended
    /// ([`DeleteStand::ConnectionEnded`], which is no confirmation).
    Settled,
}

/// The renewal record of one family of CHILD SAs: its last attempt, a rekey of ours negotiated and
/// not yet resolved, a deferred switch, and its retired SAs with their Deletes. Facts the caller
/// reports, kept as given; `T` is the caller's name for an SA in its data plane
/// ([`DeferredSwitch`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FamilyRenewal<T> {
    last_attempt: Option<LastAttempt>,
    negotiated: Option<Negotiated>,
    switch: Option<DeferredSwitch<T>>,
    /// The retired SAs whose Delete this side owes, oldest first; never dropped.
    owed: Vec<Retired>,
    /// The other retired SAs, oldest first; at most what the caller keeps.
    settled: VecDeque<Retired>,
}

impl<T: Copy> Default for FamilyRenewal<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Copy> FamilyRenewal<T> {
    /// A family with nothing recorded: no attempt, nothing pending, nothing retired.
    pub fn new() -> Self {
        Self { last_attempt: None, negotiated: None, switch: None, owed: Vec::new(), settled: VecDeque::new() }
    }

    /// The last renewal attempt, as [`Spacing::schedule`](super::spacing::Spacing::schedule) takes
    /// it; `None` before the first.
    pub fn last_attempt(&self) -> Option<LastAttempt> {
        self.last_attempt
    }

    /// Whether a rekey of ours is negotiated and not yet resolved: from
    /// [`negotiated`](Self::negotiated) to [`resolve`](Self::resolve). An attempt whose exchange is
    /// still under way is not known here until it is negotiated.
    pub fn in_flight(&self) -> bool {
        self.negotiated.is_some()
    }

    /// A renewal attempt started at `now`, in place of the last one, not failed.
    pub fn attempt_started(&mut self, now: Instant) {
        self.last_attempt = Some(LastAttempt { started: now, failed: false });
    }

    /// The last attempt failed. With no attempt recorded, nothing changes.
    pub fn attempt_failed(&mut self) {
        if let Some(last) = &mut self.last_attempt {
            last.failed = true;
        }
    }

    /// A rekey of ours was negotiated. There is at most one: one already pending is displaced and
    /// handed back -- a second one is the caller's error, and what to do with the first is its own.
    pub fn negotiated(&mut self, n: Negotiated) -> Option<Negotiated> {
        self.negotiated.replace(n)
    }

    /// The rekey of ours negotiated and not yet resolved, if there is one.
    pub fn pending(&self) -> Option<Negotiated> {
        self.negotiated
    }

    /// The rekey of ours whose new SA receives on `new_local_spi` was committed or abandoned: it is
    /// no longer pending, and is handed back. One that receives on another SPI is not the one
    /// resolved: nothing changes, and `None`.
    pub fn resolve(&mut self, new_local_spi: u32) -> Option<Negotiated> {
        self.negotiated.take_if(|n| n.new.0 == new_local_spi)
    }

    /// A switch of outbound is deferred. There is at most one: an earlier one is displaced and
    /// handed back, for the caller to make or drop.
    pub fn defer_switch(&mut self, s: DeferredSwitch<T>) -> Option<DeferredSwitch<T>> {
        self.switch.replace(s)
    }

    /// The deferred switch, if there is one.
    pub fn pending_switch(&self) -> Option<DeferredSwitch<T>> {
        self.switch
    }

    /// The deferred switch, taken out: the caller makes it (or drops it), and none is pending.
    pub fn take_switch(&mut self) -> Option<DeferredSwitch<T>> {
        self.switch.take()
    }

    /// Whether the deferred switch may be made at `now`, and why: [`SwitchProof::PeerSent`] if the
    /// caller saw the peer send on the new SA (`peer_sent`), else [`SwitchProof::Unproven`] once
    /// `unproven_after` has passed since the answer went (at that very instant, it has). `None`
    /// with no switch pending, or while it still waits. Never [`SwitchProof::ReplacedDeleted`] nor
    /// [`SwitchProof::SlotNeeded`]: those the caller knows of as they happen.
    ///
    /// Panics if the end of the wait is past what an [`Instant`] can hold, as `Instant + Duration`
    /// does.
    pub fn switch_proof(&self, peer_sent: bool, unproven_after: Duration, now: Instant) -> Option<SwitchProof> {
        let switch = self.switch?;
        if peer_sent {
            Some(SwitchProof::PeerSent)
        } else {
            (now >= switch.answered + unproven_after).then_some(SwitchProof::Unproven)
        }
    }

    /// The instant the deferred switch is made with no proof, if nothing comes first:
    /// `unproven_after` after its answer went. `None` with no switch pending.
    ///
    /// Panics as [`switch_proof`](Self::switch_proof) does.
    pub fn switch_due_at(&self, unproven_after: Duration) -> Option<Instant> {
        self.switch.map(|switch| switch.answered + unproven_after)
    }

    /// Whether the deferred switch waits on the Delete of the SA that receives on `local_spi`: true
    /// only for the SA it replaces ([`DeferredSwitch::replaced`]), never for the new SA nor any
    /// other. A Delete names an SA, never just a family: the peer's Delete of the replaced SA is the
    /// proof [`SwitchProof::ReplacedDeleted`] names, and one of the new SA is not.
    pub fn waits_on_delete_of(&self, local_spi: u32) -> bool {
        self.switch.is_some_and(|switch| switch.replaced.0 == local_spi)
    }

    /// An SA is no longer the family's, kept last among the owed ones or the settled ones, by
    /// whether this side owes its Delete (not tried, failed, not known to have gone, or sent with no
    /// answer yet). The record never drops, refuses or overwrites an owed entry: not at
    /// `bounds.owed_max`, not past it -- an owed Delete is kept whatever the count, and
    /// [`Retirement::OverCapacity`] says so. A settled one is kept within `bounds.settled_kept`:
    /// past it the oldest settled one goes first, even the one just retired (with 0, none is kept).
    /// Walks nothing.
    ///
    /// What settles a debt later ([`update`](Self::update)) is the caller's to know and to have
    /// evidence of: the peer's answer to this side's Delete of that SA, or the peer's own Delete of
    /// it. The end of the IKE SA it was made under is no such evidence: it closes the local record of
    /// the debt ([`DeleteStand::ConnectionEnded`]), what the peer holds not known. Never its age, a
    /// timeout, or another SA put in its place: nothing in the record settles one by itself, and
    /// nothing here sends a Delete again.
    pub fn retire_within(&mut self, r: Retired, bounds: RetiredBounds) -> Retirement {
        if !r.owed() {
            self.keep_settled(r, bounds.settled_kept);
            return Retirement::Settled;
        }
        let before = self.owed.len();
        self.owed.push(r);
        if before >= bounds.owed_max {
            Retirement::OverCapacity { owed: self.owed.len() }
        } else {
            Retirement::Owed { room: bounds.owed_max - self.owed.len() }
        }
    }

    /// Where an owed Delete came to. The SA is named by `r.spis` and `r.generation`, both (a `None`
    /// generation names only an entry with `None`): the oldest owed entry of exactly that SA takes
    /// `r.deleted_by` and `r.stand`. Still owed, it stays in its place ([`Update::Owed`]); no longer
    /// owed, it leaves the owed ones (their order kept) and is put last among the settled ones,
    /// within `bounds.settled_kept` ([`Update::Settled`]). With no owed entry of that SA, nothing
    /// changes ([`Update::NoSuchDebt`]): an update never records an SA, never touches a settled
    /// entry, nor an entry of the same SPIs in another generation, nor another SA. Two owed entries
    /// of the same SA are the caller's error: both are kept, and the oldest is the one updated.
    ///
    /// Only evidence settles a debt, and it is the caller's to have: the peer's answer to this
    /// side's Delete of that SA (`Sent { acknowledged: true }`), the peer's own Delete of it
    /// ([`Party::Peers`]). The end of the IKE SA it was made under
    /// ([`DeleteStand::ConnectionEnded`]) takes it out of the owed ones too, there being nothing
    /// left to send it on, but it finalises the local record only: it is neither an answer nor the
    /// peer's Delete, and says nothing of what the peer holds. `bounds.owed_max` is not looked at.
    pub fn update(&mut self, r: Retired, bounds: RetiredBounds) -> Update {
        let Some(at) = self.owed.iter().position(|owed| owed.same_sa(&r)) else { return Update::NoSuchDebt };
        let entry = &mut self.owed[at];
        entry.deleted_by = r.deleted_by;
        entry.stand = r.stand;
        if entry.owed() {
            return Update::Owed;
        }
        let settled = self.owed.remove(at);
        self.keep_settled(settled, bounds.settled_kept);
        Update::Settled
    }

    /// How many more Deletes may be owed within `owed_max`: 0 at it, and past it. The caller asks it
    /// before it starts what may owe another.
    pub fn owed_room(&self, owed_max: usize) -> usize {
        owed_max.saturating_sub(self.owed.len())
    }

    /// The retired SAs whose Delete this side owes and has not had answered (not tried, failed, not
    /// known to have gone, or sent with no answer yet), oldest first. Nothing here sends one again:
    /// when, and whether, is the caller's.
    pub fn owed(&self) -> &[Retired] {
        &self.owed
    }

    /// The settled retired SAs kept -- their Delete answered, none owed, the peer's to delete, or
    /// their connection ended with the peer's outcome not known ([`DeleteStand::ConnectionEnded`]:
    /// closed in the local record, not confirmed) --, oldest first.
    pub fn settled(&self) -> impl ExactSizeIterator<Item = &Retired> + '_ {
        self.settled.iter()
    }

    /// `r`, settled, kept last among the settled ones; past `kept`, the oldest goes first.
    fn keep_settled(&mut self, r: Retired, kept: usize) {
        self.settled.push_back(r);
        while self.settled.len() > kept {
            self.settled.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::spacing::{Schedule, Spacing};
    use crate::session::{Rounding, Share};
    use DeleteStand::{ConnectionEnded, Failed, NotOwed, NotSent, Sent, Unknown};
    use Party::{Ours, Peers};

    const RETRY_MIN: Duration = Duration::from_secs(5);
    const RETRY_MAX: Duration = Duration::from_secs(30);

    /// The figures of a consumer that renews at 8/10 of a lifetime or a volume, never before half
    /// of a lifetime, keeps 20 s free before the end and retries between 5 and 30 s (those of
    /// `timing`'s tests).
    const TIMING: RenewalTiming = RenewalTiming {
        margin: Share::new(8, 10, Rounding::Down),
        earliest: Share::new(1, 2, Rounding::Down),
        lead: Duration::from_secs(20),
        min_interval: Duration::from_secs(1),
        retry_min: RETRY_MIN,
        retry_max: RETRY_MAX,
        volume_margin: Share::saturating_u64(8, 10, Rounding::Down),
    };

    /// The figures of a consumer that sizes I_min at a quarter of the limit, at 64 MB/s, between 50
    /// and 200 ms, and retries 5 s after a failure (those of `spacing`'s tests).
    const SPACING: Spacing = Spacing {
        floor: Duration::from_millis(50),
        cap: Duration::from_millis(200),
        reference_rate: 64_000_000,
        limit_divisor: 4,
        retry_after_failure: Duration::from_secs(5),
    };

    /// How long a deferred switch waits for a proof, in these tests.
    const WAIT: Duration = Duration::from_secs(5);

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    fn ms(m: u64) -> Duration {
        Duration::from_millis(m)
    }

    /// An instant with an hour of room before it, so the tests can go back from it.
    fn t0() -> Instant {
        Instant::now() + secs(3600)
    }

    fn negotiated(replaces: ChildId, new: (u32, u32), started: Instant) -> Negotiated {
        Negotiated { replaces, new, started }
    }

    fn switch(id: u64, local_spi: u32, replaced: (u32, u32), answered: Instant) -> DeferredSwitch<u64> {
        DeferredSwitch { id, local_spi, replaced, answered }
    }

    fn retired(n: u32, deleted_by: Party, stand: DeleteStand) -> Retired {
        Retired { spis: (n, n + 0x100), generation: Some(n.into()), deleted_by, stand }
    }

    #[test]
    fn a_child_id_counts_its_generations_from_zero_and_takes_the_new_spis() {
        let first = ChildId::first(0x11, 0x12);
        assert_eq!(first, ChildId { generation: 0, local_spi: 0x11, peer_spi: 0x12 });
        assert_eq!(first.spis(), (0x11, 0x12), "(local, peer)");
        let second = first.successor(0x21, 0x22);
        assert_eq!(second, ChildId { generation: 1, local_spi: 0x21, peer_spi: 0x22 });
        assert_eq!(second.successor(0x31, 0x32).generation, 2);
        let last = ChildId { generation: u64::MAX, local_spi: 1, peer_spi: 2 };
        assert_eq!(last.successor(3, 4), ChildId { generation: u64::MAX, local_spi: 3, peer_spi: 4 }, "saturated, never wrapped to 0");
    }

    #[test]
    fn the_age_clock_is_due_exactly_when_due_by_age_says_with_and_without_a_failure() {
        let t0 = t0();
        // (lifetime, age, time since a failure, due): the boundaries of `timing`'s tests.
        for (life, age, since_failure, due) in [
            (120u32, ms(95_999), None, false),
            (120, secs(96), None, true),
            (120, secs(100), Some(ms(9_999)), false),
            (120, secs(100), Some(secs(10)), true),
            (120, secs(140), Some(ms(29_999)), false),
            (120, secs(140), Some(RETRY_MAX), true),
            (120, secs(1), Some(secs(50)), false),
            (3600, secs(2910), Some(secs(31)), true),
            (3600, secs(2910), Some(secs(10)), false),
            (3600, ms(2_879_999), None, false),
            (3600, secs(2880), None, true),
            (0, ms(999), None, false),
            (0, ms(1_000), None, true),
            (1, ms(999), None, false),
            (1, ms(1_000), None, true),
        ] {
            let now = t0 + age;
            let clock = AgeClock { last_failure: since_failure.map(|since| now - since), ..AgeClock::started(life, t0) };
            assert_eq!(clock.age(now), age, "{life} s at {age:?}");
            assert_eq!(clock.since_failure(now), since_failure, "{life} s at {age:?}");
            assert_eq!(clock.due(&TIMING, now), TIMING.due_by_age(age, life, since_failure), "{life} s at {age:?}, {since_failure:?}");
            assert_eq!(clock.due(&TIMING, now), due, "{life} s at {age:?}, {since_failure:?}");
        }
    }

    #[test]
    fn a_failure_is_recorded_at_its_instant_and_replaces_the_one_before() {
        let t0 = t0();
        let mut clock = AgeClock::started(120, t0);
        assert_eq!(clock, AgeClock { born: t0, lifetime_secs: 120, last_failure: None });
        assert_eq!(clock.since_failure(t0 + secs(100)), None);
        assert!(clock.due(&TIMING, t0 + secs(100)));
        clock.failed(t0 + secs(100));
        assert_eq!(clock.last_failure, Some(t0 + secs(100)));
        assert!(!clock.due(&TIMING, t0 + secs(100)), "failed now: retried 10 s later");
        assert!(clock.due(&TIMING, t0 + secs(110)));
        clock.failed(t0 + secs(110));
        assert_eq!(clock.since_failure(t0 + secs(110)), Some(Duration::ZERO), "the later failure counts");
        assert!(!clock.due(&TIMING, t0 + secs(110)));
    }

    #[test]
    fn age_and_time_since_a_failure_saturate_before_the_instants_they_count_from() {
        let t0 = t0();
        let clock = AgeClock { last_failure: Some(t0 + secs(10)), ..AgeClock::started(120, t0) };
        assert_eq!(clock.age(t0 - secs(1)), Duration::ZERO, "before it was made");
        assert_eq!(clock.age(t0), Duration::ZERO);
        assert_eq!(clock.since_failure(t0 + secs(5)), Some(Duration::ZERO), "before the failure");
        assert_eq!(clock.since_failure(t0 + secs(10)), Some(Duration::ZERO));
        assert_eq!(clock.since_failure(t0 + secs(11)), Some(secs(1)));
        assert!(!clock.due(&TIMING, t0 - secs(1)));
    }

    #[test]
    fn attempts_are_recorded_and_fed_to_the_spacing_as_it_takes_them() {
        let t0 = t0();
        let mut f = FamilyRenewal::<u64>::new();
        assert_eq!(f, FamilyRenewal::default());
        assert_eq!((f.last_attempt(), f.in_flight()), (None, false), "nothing at first");
        f.attempt_failed();
        assert_eq!(f.last_attempt(), None, "a failure with no attempt changes nothing");
        f.attempt_started(t0);
        assert_eq!(f.last_attempt(), Some(LastAttempt { started: t0, failed: false }));
        assert!(!f.in_flight(), "started, not negotiated");
        f.attempt_failed();
        assert_eq!(f.last_attempt(), Some(LastAttempt { started: t0, failed: true }));
        let limit = Some(5_120_000);
        assert_eq!(SPACING.schedule(true, f.in_flight(), f.last_attempt(), limit, t0), Schedule::At(t0 + secs(5)), "the retry after a failure");
        f.attempt_started(t0 + secs(5));
        assert_eq!(f.last_attempt(), Some(LastAttempt { started: t0 + secs(5), failed: false }), "a new attempt is not failed");
        let old = ChildId::first(0x11, 0x12);
        assert_eq!(f.negotiated(negotiated(old, (0x21, 0x22), t0 + secs(5))), None);
        assert!(f.in_flight());
        let later = t0 + secs(3600);
        assert_eq!(SPACING.schedule(true, f.in_flight(), f.last_attempt(), limit, later), Schedule::InFlight);
        f.resolve(0x21);
        assert!(!f.in_flight(), "resolved");
        assert_eq!(SPACING.schedule(true, f.in_flight(), f.last_attempt(), limit, later), Schedule::Now);
    }

    #[test]
    fn a_negotiated_rekey_is_resolved_by_its_own_new_spi_only() {
        let t0 = t0();
        let mut f = FamilyRenewal::<u64>::new();
        let old = ChildId::first(0x11, 0x12);
        let n = negotiated(old, (0x21, 0x22), t0);
        assert_eq!(f.resolve(0x21), None, "nothing pending");
        assert_eq!(f.negotiated(n), None);
        assert_eq!(f.pending(), Some(n));
        for wrong in [0x11, 0x12, 0x22, 0] {
            assert_eq!(f.resolve(wrong), None, "{wrong:#x}");
            assert_eq!(f.pending(), Some(n), "{wrong:#x}: nothing changes");
        }
        assert_eq!(f.resolve(0x21), Some(n));
        assert_eq!((f.pending(), f.in_flight()), (None, false));
        assert_eq!(f.resolve(0x21), None, "once");
        // A second one while one is pending displaces it and hands it back.
        let other = negotiated(old, (0x31, 0x32), t0 + secs(1));
        assert_eq!(f.negotiated(n), None);
        assert_eq!(f.negotiated(other), Some(n));
        assert_eq!(f.pending(), Some(other));
        assert_eq!(f.resolve(0x21), None, "the displaced one is not the record's any more");
        assert_eq!(f.resolve(0x31), Some(other));
    }

    #[test]
    fn a_deferred_switch_is_proven_by_the_peer_or_left_unproven_at_the_very_instant() {
        let t0 = t0();
        let ns = Duration::from_nanos;
        let mut f = FamilyRenewal::<u64>::new();
        assert_eq!(f.switch_proof(true, WAIT, t0), None, "no switch pending, whatever the peer sent");
        assert_eq!(f.switch_proof(false, WAIT, t0 + secs(3600)), None);
        assert_eq!(f.switch_due_at(WAIT), None);
        let s = switch(7, 0x21, (0x11, 0x12), t0);
        assert_eq!(f.defer_switch(s), None);
        assert_eq!(f.pending_switch(), Some(s));
        let at = t0 + WAIT;
        assert_eq!(f.switch_due_at(WAIT), Some(at));
        assert_eq!(f.switch_due_at(Duration::ZERO), Some(t0));
        for (peer_sent, now, proof) in [
            (false, t0, None),
            (false, at - ns(1), None),
            (false, at, Some(SwitchProof::Unproven)),
            (false, at + secs(1), Some(SwitchProof::Unproven)),
            (true, t0, Some(SwitchProof::PeerSent)),
            (true, at - ns(1), Some(SwitchProof::PeerSent)),
            (true, at, Some(SwitchProof::PeerSent)),
            (true, at + secs(1), Some(SwitchProof::PeerSent)),
        ] {
            assert_eq!(f.switch_proof(peer_sent, WAIT, now), proof, "{peer_sent} at {:?}", now - t0);
        }
        assert_eq!(f.switch_proof(false, Duration::ZERO, t0), Some(SwitchProof::Unproven), "no wait at all: at once");
        assert_eq!(f.pending_switch(), Some(s), "a query takes nothing");
        assert_eq!(f.take_switch(), Some(s));
        assert_eq!((f.pending_switch(), f.take_switch()), (None, None), "taken once");
        assert_eq!(f.switch_proof(true, WAIT, at), None);
    }

    #[test]
    fn a_second_deferred_switch_hands_back_the_earlier_one() {
        let t0 = t0();
        let mut f = FamilyRenewal::<u64>::new();
        let first = switch(7, 0x21, (0x11, 0x12), t0);
        let second = switch(8, 0x31, (0x21, 0x22), t0 + secs(1));
        assert_eq!(f.defer_switch(first), None);
        assert_eq!(f.defer_switch(second), Some(first));
        assert_eq!(f.pending_switch(), Some(second));
        assert_eq!(f.switch_due_at(WAIT), Some(t0 + secs(1) + WAIT), "the later answer's wait");
    }

    #[test]
    fn a_deferred_switch_waits_on_the_delete_of_the_sa_it_replaces_and_no_other() {
        let t0 = t0();
        let mut f = FamilyRenewal::<u64>::new();
        assert!(!f.waits_on_delete_of(0x11), "no switch pending");
        f.defer_switch(switch(7, 0x21, (0x11, 0x12), t0));
        assert!(f.waits_on_delete_of(0x11), "the replaced SA's local SPI");
        assert!(!f.waits_on_delete_of(0x21), "the new SA's: its Delete proves nothing");
        assert!(!f.waits_on_delete_of(0x12), "the replaced SA's peer SPI is not a local one");
        assert!(!f.waits_on_delete_of(0x99));
        f.take_switch();
        assert!(!f.waits_on_delete_of(0x11), "switched: it waits on nothing");
    }

    /// Bounds keeping `settled_kept` settled entries, with no bound on the owed ones that matters.
    fn kept(settled_kept: usize) -> RetiredBounds {
        RetiredBounds { settled_kept, owed_max: usize::MAX }
    }

    /// An SA on SPIs `(n, n + 0x100)` in generation `generation`.
    fn sa(n: u32, generation: Option<u64>, deleted_by: Party, stand: DeleteStand) -> Retired {
        Retired { spis: (n, n + 0x100), generation, deleted_by, stand }
    }

    fn settled_of(f: &FamilyRenewal<u64>) -> Vec<Retired> {
        f.settled().copied().collect()
    }

    /// Every way of being settled: its Delete answered, none owed, its connection ended (the local
    /// record closed, the peer's outcome not known), or the peer's to delete whatever its stand.
    const SETTLED: [(Party, DeleteStand); 10] = [
        (Ours, Sent { acknowledged: true }),
        (Ours, NotOwed("not_asked")),
        (Ours, ConnectionEnded),
        (Peers, ConnectionEnded),
        (Peers, Sent { acknowledged: true }),
        (Peers, Sent { acknowledged: false }),
        (Peers, NotSent),
        (Peers, NotOwed("the peer deleted it")),
        (Peers, Failed),
        (Peers, Unknown),
    ];

    /// Every way of being owed.
    const OWED: [DeleteStand; 4] = [NotSent, Failed, Unknown, Sent { acknowledged: false }];

    #[test]
    fn settled_sas_are_kept_within_what_is_kept_and_the_oldest_settled_one_goes_first() {
        for kept_n in [0, 1, 2, 3, 20] {
            let mut f = FamilyRenewal::<u64>::new();
            let mut all = Vec::new();
            for (n, (by, stand)) in SETTLED.into_iter().enumerate() {
                let r = retired(n as u32 + 1, by, stand);
                assert_eq!(f.retire_within(r, kept(kept_n)), Retirement::Settled, "{r:?}");
                all.push(r);
                let from = all.len().saturating_sub(kept_n);
                assert_eq!(settled_of(&f), all[from..], "kept {kept_n}: the newest ones, oldest first");
                assert!(f.settled().len() <= kept_n);
            }
            assert!(f.owed().is_empty(), "none owed");
        }
        // The oldest settled one goes first, though an older owed one stays; the one just retired
        // goes too when nothing is kept.
        let mut f = FamilyRenewal::<u64>::new();
        let (a, b, c, d) = (retired(1, Ours, NotSent), retired(2, Ours, Sent { acknowledged: true }), retired(3, Ours, Failed), retired(4, Ours, NotOwed("not_asked")));
        for r in [a, b, c] {
            let _ = f.retire_within(r, kept(1));
        }
        assert_eq!((f.owed(), settled_of(&f)), (&[a, c][..], vec![b]));
        assert_eq!(f.retire_within(d, kept(1)), Retirement::Settled);
        assert_eq!((f.owed(), settled_of(&f)), (&[a, c][..], vec![d]), "past one settled, the oldest settled one went, not the older owed one");
        assert_eq!(f.retire_within(retired(5, Peers, NotOwed("the peer's")), kept(0)), Retirement::Settled);
        assert_eq!((f.owed(), f.settled().len()), (&[a, c][..], 0), "with 0 kept, none: not even the one just retired");
    }

    #[test]
    fn an_owed_sa_is_never_dropped_and_its_room_is_exact_up_to_the_bound_and_past_it() {
        for owed_max in [0, 1, 3, 8] {
            for settled_kept in [0, 2] {
                let bounds = RetiredBounds { settled_kept, owed_max };
                let mut f = FamilyRenewal::<u64>::new();
                let mut owed = Vec::new();
                assert_eq!(f.owed_room(owed_max), owed_max, "nothing owed yet");
                for n in 0..owed_max + 4 {
                    let r = retired(n as u32 + 1, Ours, OWED[n % OWED.len()]);
                    let expected = if n < owed_max { Retirement::Owed { room: owed_max - n - 1 } } else { Retirement::OverCapacity { owed: n + 1 } };
                    assert_eq!(f.retire_within(r, bounds), expected, "{owed_max}: the {}th", n + 1);
                    owed.push(r);
                    assert_eq!(f.owed(), owed, "{owed_max}: every one before still there, in order, as it was");
                    assert_eq!(f.owed_room(owed_max), owed_max.saturating_sub(n + 1), "{owed_max}: saturating past the bound");
                    // A settled one in between drops none of them.
                    assert_eq!(f.retire_within(retired(1000 + n as u32, Ours, Sent { acknowledged: true }), bounds), Retirement::Settled);
                    assert_eq!(f.owed(), owed);
                    assert_eq!(f.settled().len(), settled_kept.min(n + 1));
                }
            }
        }
    }

    #[test]
    fn owed_lists_exactly_ours_not_sent_failed_unknown_or_sent_with_no_answer() {
        let mut f = FamilyRenewal::<u64>::new();
        let all = [
            (retired(1, Ours, Sent { acknowledged: true }), false),
            (retired(2, Ours, Sent { acknowledged: false }), true),
            (retired(3, Ours, NotSent), true),
            (retired(4, Ours, NotOwed("its SPI names another SA")), false),
            (retired(5, Ours, Failed), true),
            (retired(6, Peers, Sent { acknowledged: true }), false),
            (retired(7, Peers, Sent { acknowledged: false }), false),
            (retired(8, Peers, NotSent), false),
            (retired(9, Peers, NotOwed("the peer deleted it")), false),
            (retired(10, Peers, Failed), false),
            (retired(11, Ours, Unknown), true),
            (retired(12, Peers, Unknown), false),
            (retired(13, Ours, ConnectionEnded), false),
            (retired(14, Peers, ConnectionEnded), false),
        ];
        for (r, _) in all {
            let _ = f.retire_within(r, kept(all.len()));
        }
        let expected: Vec<Retired> = all.iter().filter(|(_, owed)| *owed).map(|(r, _)| *r).collect();
        assert_eq!(f.owed(), expected, "oldest first");
        assert_eq!(f.owed().iter().map(|r| r.spis.0).collect::<Vec<_>>(), [2, 3, 5, 11]);
        let expected: Vec<Retired> = all.iter().filter(|(_, owed)| !*owed).map(|(r, _)| *r).collect();
        assert_eq!(settled_of(&f), expected, "oldest first");
        assert_eq!(f.owed().len() + f.settled().len(), all.len(), "a query takes nothing");
    }

    #[test]
    fn an_update_names_an_sa_by_its_spis_and_its_generation_and_reaches_no_other() {
        let bounds = RetiredBounds { settled_kept: 4, owed_max: 8 };
        let mut f = FamilyRenewal::<u64>::new();
        let (a1, a2, b_none, b2) = (sa(1, Some(1), Ours, NotSent), sa(1, Some(2), Ours, Failed), sa(2, None, Ours, Unknown), sa(2, Some(2), Ours, Sent { acknowledged: false }));
        let done = sa(3, Some(3), Ours, Sent { acknowledged: true });
        for r in [a1, a2, b_none, done, b2] {
            let _ = f.retire_within(r, bounds);
        }
        assert_eq!((f.owed(), settled_of(&f)), (&[a1, a2, b_none, b2][..], vec![done]));
        let answered = |r: Retired| Retired { stand: Sent { acknowledged: true }, ..r };
        for (what, r) in [
            ("a settled entry", answered(done)),
            ("a settled entry, still owed by the update", Retired { stand: Failed, ..done }),
            ("an unknown SA", sa(9, Some(9), Ours, Sent { acknowledged: true })),
            ("the right SPIs, a generation none has", answered(sa(1, Some(3), Ours, NotSent))),
            ("the right SPIs, no generation where theirs is known", answered(sa(1, None, Ours, NotSent))),
            ("the right generation, other SPIs", answered(sa(4, Some(2), Ours, NotSent))),
            ("the local SPI right, the peer's not", Retired { spis: (1, 0x999), ..answered(a1) }),
        ] {
            let before = f.clone();
            assert_eq!(f.update(r, bounds), Update::NoSuchDebt, "{what}");
            assert_eq!(f, before, "{what}: nothing changes");
        }
        // Of the same SPIs, only the generation named.
        assert_eq!(f.update(answered(a2), bounds), Update::Settled);
        assert_eq!((f.owed(), settled_of(&f)), (&[a1, b_none, b2][..], vec![done, answered(a2)]), "a1, of the same SPIs, untouched");
        // `None` names only `None`, `Some` only `Some`.
        assert_eq!(f.update(Retired { stand: Unknown, ..b2 }, bounds), Update::Owed);
        assert_eq!(f.owed(), [a1, b_none, Retired { stand: Unknown, ..b2 }], "b2 updated in place, b_none untouched");
        assert_eq!(f.update(Retired { stand: Failed, ..b_none }, bounds), Update::Owed);
        assert_eq!(f.owed(), [a1, Retired { stand: Failed, ..b_none }, Retired { stand: Unknown, ..b2 }]);
    }

    #[test]
    fn an_update_still_owed_stays_in_place_and_one_settled_by_evidence_moves_last_among_the_settled() {
        // Owed to owed: in place, its order kept, by each stand still owed.
        let bounds = RetiredBounds { settled_kept: 2, owed_max: 4 };
        let mut f = FamilyRenewal::<u64>::new();
        let (a, b, c) = (retired(1, Ours, NotSent), retired(2, Ours, NotSent), retired(3, Ours, NotSent));
        for r in [a, b, c] {
            let _ = f.retire_within(r, bounds);
        }
        for stand in OWED {
            assert_eq!(f.update(Retired { stand, ..b }, bounds), Update::Owed, "{stand:?}");
            assert_eq!(f.owed(), [a, Retired { stand, ..b }, c], "{stand:?}: in its place");
            assert_eq!(f.owed_room(4), 1);
        }
        // Owed to settled: by each kind of evidence -- its Delete answered, the peer's own Delete, the
        // peer's to delete --, by a reason none is owed the consumer gave, or by the end of its
        // connection, which closes the local record only.
        let evidence = [
            (Ours, Sent { acknowledged: true }),
            (Peers, NotOwed("gateway_deleted")),
            (Peers, Sent { acknowledged: false }),
            (Ours, NotOwed("ike_sa_gone")),
            (Ours, ConnectionEnded),
        ];
        for settled_kept in [0, 1, 2] {
            for (by, stand) in evidence {
                let bounds = RetiredBounds { settled_kept, owed_max: 4 };
                let mut f = FamilyRenewal::<u64>::new();
                let (s1, s2) = (retired(10, Ours, Sent { acknowledged: true }), retired(11, Peers, NotOwed("peer_deletes")));
                for r in [a, s1, b, s2, c] {
                    let _ = f.retire_within(r, bounds);
                }
                let room = f.owed_room(4);
                let now_settled = Retired { deleted_by: by, stand, ..b };
                assert_eq!(f.update(now_settled, bounds), Update::Settled, "{by:?} {stand:?}");
                assert_eq!(f.owed(), [a, c], "{by:?} {stand:?}: gone from the owed ones, their order kept");
                let mut expected = vec![s1, s2, now_settled];
                expected.drain(..expected.len().saturating_sub(settled_kept));
                assert_eq!(settled_of(&f), expected, "kept {settled_kept}: last among the settled ones, within what is kept");
                assert_eq!(f.owed_room(4), room + 1, "room for one more");
                let before = f.clone();
                assert_eq!(f.update(now_settled, bounds), Update::NoSuchDebt, "settled: no debt any more");
                assert_eq!(f, before);
            }
        }
    }

    #[test]
    fn a_debt_whose_connection_ended_closes_its_local_record_as_ended_neither_confirmed_nor_the_peers_nor_owed_again() {
        let bounds = RetiredBounds { settled_kept: 8, owed_max: 8 };
        let mut f = FamilyRenewal::<u64>::new();
        let confirmed = retired(1, Ours, Sent { acknowledged: true });
        let debts: [Retired; 4] = std::array::from_fn(|k| retired(10 + k as u32, Ours, OWED[k]));
        let _ = f.retire_within(confirmed, bounds);
        for r in debts {
            let _ = f.retire_within(r, bounds);
        }
        assert_eq!(f.owed(), debts);
        // Each debt the end of its IKE SA reached: out of the owed ones, closed as ended -- one stand
        // of its own, which is no answer, not the peer's, not a Delete never owed.
        for (k, r) in debts.into_iter().enumerate() {
            let ended = Retired { stand: ConnectionEnded, ..r };
            assert_eq!(f.update(ended, bounds), Update::Settled, "{r:?}");
            assert_eq!(f.owed(), &debts[k + 1..], "{r:?}: no longer owed, nothing left to send it on");
            assert_eq!(f.owed_room(bounds.owed_max), bounds.owed_max - (debts.len() - k - 1));
            let kept = *f.settled().last().unwrap();
            assert_eq!(kept, ended, "{r:?}: closed as ended, ours");
            assert_ne!(kept.stand, Sent { acknowledged: true }, "not confirmed");
            assert!(!matches!(kept.stand, NotOwed(_)), "not a Delete never owed");
            assert_eq!(kept.deleted_by, Ours, "not the peer's");
            // Closed: a later report changes nothing -- the record does not take a late answer as one.
            let before = f.clone();
            assert_eq!(f.update(Retired { stand: Sent { acknowledged: true }, ..r }, bounds), Update::NoSuchDebt);
            assert_eq!(f, before);
        }
        // The debt confirmed before the end stays confirmed: the end reaches no settled entry.
        let before = f.clone();
        assert_eq!(f.update(Retired { stand: ConnectionEnded, ..confirmed }, bounds), Update::NoSuchDebt);
        assert_eq!(f, before);
        assert_eq!(settled_of(&f)[0], confirmed);
        // Retired as ended at once: kept among the settled ones, never owed.
        let late = retired(30, Ours, ConnectionEnded);
        assert_eq!(f.retire_within(late, bounds), Retirement::Settled);
        assert!(f.owed().is_empty() && f.settled().last() == Some(&late));
    }

    #[test]
    fn of_two_owed_entries_of_the_same_sa_the_oldest_is_updated() {
        let bounds = RetiredBounds { settled_kept: 4, owed_max: 4 };
        let mut f = FamilyRenewal::<u64>::new();
        let (first, other, second) = (retired(1, Ours, NotSent), retired(2, Ours, NotSent), retired(1, Ours, Failed));
        for r in [first, other, second] {
            let _ = f.retire_within(r, bounds);
        }
        assert_eq!(f.update(Retired { stand: Unknown, ..first }, bounds), Update::Owed);
        assert_eq!(f.owed(), [Retired { stand: Unknown, ..first }, other, second], "the oldest, both kept");
        assert_eq!(f.update(Retired { stand: Sent { acknowledged: true }, ..first }, bounds), Update::Settled);
        assert_eq!(f.owed(), [other, second], "the oldest settled; the other stays owed");
        assert_eq!(f.update(Retired { stand: Sent { acknowledged: true }, ..first }, bounds), Update::Settled, "then the other");
        assert_eq!(f.owed(), [other]);
    }

    #[test]
    fn many_settled_sas_with_a_few_owed_ones_in_between_keep_the_settled_ones_bounded_and_every_owed_one() {
        let bounds = RetiredBounds { settled_kept: 8, owed_max: 8 };
        let mut f = FamilyRenewal::<u64>::new();
        let (mut owed, mut settled) = (Vec::new(), Vec::new());
        for n in 0..500u32 {
            let r = if n % 37 == 5 {
                let r = retired(n, Ours, OWED[owed.len() % OWED.len()]);
                owed.push(r);
                r
            } else {
                let (by, stand) = SETTLED[n as usize % SETTLED.len()];
                let r = retired(n, by, stand);
                settled.push(r);
                r
            };
            let _ = f.retire_within(r, bounds);
            assert!(f.settled().len() <= bounds.settled_kept, "after {n}");
            assert_eq!(f.owed(), owed, "after {n}: every owed one");
        }
        assert!(owed.len() > bounds.owed_max, "past the bound: {}", owed.len());
        assert_eq!(settled_of(&f), settled[settled.len() - bounds.settled_kept..], "the newest settled ones, oldest first");
    }

    #[test]
    fn the_parts_of_the_record_are_kept_apart() {
        let t0 = t0();
        let mut f = FamilyRenewal::<u64>::new();
        let old = ChildId::first(0x11, 0x12);
        let n = negotiated(old, (0x21, 0x22), t0);
        let s = switch(7, 0x21, (0x11, 0x12), t0);
        f.attempt_started(t0);
        f.negotiated(n);
        f.defer_switch(s);
        assert_eq!(f.retire_within(retired(1, Ours, NotSent), RetiredBounds { settled_kept: 4, owed_max: 4 }), Retirement::Owed { room: 3 });
        assert_eq!(f.take_switch(), Some(s));
        assert_eq!(f.pending(), Some(n), "taking the switch resolves nothing");
        assert_eq!(f.resolve(0x21), Some(n));
        assert_eq!(f.last_attempt(), Some(LastAttempt { started: t0, failed: false }), "resolving is not a failure, nor a new attempt");
        assert_eq!((f.owed(), f.settled().len()), (&[retired(1, Ours, NotSent)][..], 0));
    }
}
