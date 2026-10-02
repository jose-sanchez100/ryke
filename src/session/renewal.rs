//! The record of one family's renewals: what a consumer has to remember of the CHILD SAs that
//! carry one kind of traffic between the exchanges that renew them, and the queries it asks of it.
//!
//! A family is a line of CHILD SAs, each put in the place of the one before ([`ChildId`] numbers
//! them). Its record ([`FamilyRenewal`]) holds the last renewal attempt (what
//! [`Spacing::schedule`](super::spacing::Spacing::schedule) is fed), a rekey of ours negotiated
//! and not yet committed or abandoned ([`Negotiated`]), the switch of outbound to an SA this side
//! answered for, deferred until the peer is known to have it ([`DeferredSwitch`]), and the SAs no
//! longer the family's, with where each one's Delete stands ([`Retired`]). An SA's clock by age
//! ([`AgeClock`]) is kept beside it, one per SA.
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
//! deferred switch may wait, how many retired SAs are kept.

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteStand {
    /// Sent; `acknowledged` once the peer's answer to it came in.
    Sent { acknowledged: bool },
    /// Not sent yet.
    NotSent,
    /// None is owed, for the reason named (the peer deleted the SA itself, say, or its SPI names
    /// another SA of ours).
    NotOwed(&'static str),
    /// Tried, and not sent: it could not be built, or it could not be handed to the socket.
    Failed,
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
    /// This side owes its Delete and has not had it answered: not sent, failed, or sent with no
    /// answer yet.
    fn owed(&self) -> bool {
        self.deleted_by == Party::Ours
            && matches!(self.stand, DeleteStand::NotSent | DeleteStand::Failed | DeleteStand::Sent { acknowledged: false })
    }
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
    /// Oldest first.
    retired: Vec<Retired>,
}

impl<T: Copy> Default for FamilyRenewal<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Copy> FamilyRenewal<T> {
    /// A family with nothing recorded: no attempt, nothing pending, nothing retired.
    pub fn new() -> Self {
        Self { last_attempt: None, negotiated: None, switch: None, retired: Vec::new() }
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

    /// An SA is no longer the family's. It is kept last, and at most `kept` are kept: past that, the
    /// oldest settled one goes first -- its Delete answered, none owed, or the peer's to delete --
    /// even the one just retired, and with none settled, the oldest. `kept` is the caller's; with 0,
    /// nothing is kept.
    pub fn retire(&mut self, r: Retired, kept: usize) {
        self.retired.push(r);
        while self.retired.len() > kept {
            let oldest_settled = self.retired.iter().position(|r| !r.owed());
            self.retired.remove(oldest_settled.unwrap_or(0));
        }
    }

    /// The retired SAs kept, oldest first.
    pub fn retired(&self) -> &[Retired] {
        &self.retired
    }

    /// The retired SAs whose Delete this side owes and has not had answered (not sent, failed, or
    /// sent with no answer yet), oldest first. Nothing here sends one again: when, and whether, is
    /// the caller's.
    pub fn owed(&self) -> impl Iterator<Item = &Retired> {
        self.retired.iter().filter(|r| r.owed())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::spacing::{Schedule, Spacing};
    use crate::session::{Rounding, Share};
    use DeleteStand::{Failed, NotOwed, NotSent, Sent};
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

    #[test]
    fn retired_sas_are_kept_oldest_first_and_the_oldest_settled_one_goes_first() {
        let mut f = FamilyRenewal::<u64>::new();
        let (a, b, c) = (retired(1, Ours, NotSent), retired(2, Ours, Sent { acknowledged: true }), retired(3, Ours, Failed));
        for r in [a, b, c] {
            f.retire(r, 3);
        }
        assert_eq!(f.retired(), [a, b, c], "in the order retired");
        let d = retired(4, Ours, Sent { acknowledged: false });
        f.retire(d, 3);
        assert_eq!(f.retired(), [a, c, d], "the settled one went, though not the oldest");
        let e = retired(5, Ours, NotSent);
        f.retire(e, 3);
        assert_eq!(f.retired(), [c, d, e], "none settled: the oldest went");
        // Each way of being settled goes before an older entry that is owed.
        for settled in [Sent { acknowledged: true }, NotOwed("the peer deleted it")] {
            let mut f = FamilyRenewal::<u64>::new();
            let (owed, done, new) = (retired(1, Ours, NotSent), retired(2, Ours, settled), retired(3, Ours, Failed));
            for r in [owed, done, new] {
                f.retire(r, 2);
            }
            assert_eq!(f.retired(), [owed, new], "{settled:?}");
        }
        for stand in [NotSent, Failed, Sent { acknowledged: false }] {
            let mut f = FamilyRenewal::<u64>::new();
            let (owed, peers, new) = (retired(1, Ours, NotSent), retired(2, Peers, stand), retired(3, Ours, Failed));
            for r in [owed, peers, new] {
                f.retire(r, 2);
            }
            assert_eq!(f.retired(), [owed, new], "the peer's to delete is settled whatever its stand: {stand:?}");
        }
        // The one just retired goes too, when it is the only one settled.
        let mut f = FamilyRenewal::<u64>::new();
        let (x, y, z) = (retired(1, Ours, NotSent), retired(2, Ours, Failed), retired(3, Peers, NotOwed("the peer's")));
        for r in [x, y, z] {
            f.retire(r, 2);
        }
        assert_eq!(f.retired(), [x, y]);
    }

    #[test]
    fn with_nothing_to_keep_nothing_is_kept() {
        let mut f = FamilyRenewal::<u64>::new();
        for r in [retired(1, Ours, NotSent), retired(2, Peers, Sent { acknowledged: true })] {
            f.retire(r, 0);
            assert!(f.retired().is_empty(), "{r:?}");
        }
        assert_eq!(f.owed().count(), 0);
        f.retire(retired(3, Ours, NotSent), 1);
        f.retire(retired(4, Ours, Failed), 1);
        assert_eq!(f.retired(), [retired(4, Ours, Failed)], "one kept: the newest of two owed");
    }

    #[test]
    fn owed_lists_exactly_ours_not_sent_failed_or_sent_with_no_answer() {
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
        ];
        for (r, _) in all {
            f.retire(r, all.len());
        }
        let owed: Vec<Retired> = f.owed().copied().collect();
        let expected: Vec<Retired> = all.iter().filter(|(_, owed)| *owed).map(|(r, _)| *r).collect();
        assert_eq!(owed, expected, "oldest first");
        assert_eq!(owed.iter().map(|r| r.spis.0).collect::<Vec<_>>(), [2, 3, 5]);
        assert_eq!(f.retired().len(), all.len(), "a query takes nothing");
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
        f.retire(retired(1, Ours, NotSent), 4);
        assert_eq!(f.take_switch(), Some(s));
        assert_eq!(f.pending(), Some(n), "taking the switch resolves nothing");
        assert_eq!(f.resolve(0x21), Some(n));
        assert_eq!(f.last_attempt(), Some(LastAttempt { started: t0, failed: false }), "resolving is not a failure, nor a new attempt");
        assert_eq!(f.retired(), [retired(1, Ours, NotSent)]);
    }
}
