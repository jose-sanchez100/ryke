//! One family's renewals as a machine of events and actions: what a consumer that renews CHILD SAs
//! by volume make-before-break, and switches outbound late where it answered as the responder, does
//! at each point, and in which order -- the record ([`FamilyRenewal`]) kept as it goes.
//!
//! It is the policy of Free VPN's Windows controller (`worker::pump_local`), validated live,
//! transliterated: the same steps, in the same order, with the same ways out. Each flow names the
//! controller function it stands for. Where the controller holds one lock across two operations of
//! its data plane, the machine asks for them as one action, and says so ([`Action::Switch`],
//! [`Action::SwitchAtOnce`]).
//!
//! # The protocol
//!
//! The consumer drives the machine with [`FamilyMachine::step`]. An [`Input`] is either an *event*,
//! which starts an operation and is taken only while the machine is [`idle`](FamilyMachine::idle),
//! or the *answer* to the action the previous step asked for. Each [`Step`] carries the actions the
//! consumer is to carry out, in order, each completely before the next: at most one of them asks
//! for an answer ([`Action::asks`]), and it is the last; then the operation goes on and
//! [`Step::outcome`] is `None`. Otherwise the operation is over, the outcome says how, and the
//! machine is idle again. An input that does not fit where the machine stands is refused
//! ([`Unexpected`]): nothing changes, and nothing panics.
//!
//! The family's current generation ([`ChildId`]) and its clock by age are the consumer's, not the
//! machine's: an event carries the current generation where the operation needs it, and the machine
//! says when to move them ([`Action::BecameCurrent`], [`Action::AgeClockRestart`],
//! [`Action::AgeClockFailed`]).
//!
//! Every line the controller logs in these flows is a [`Note`], emitted at the point in the order
//! where the controller logs it and carrying the data the line prints that the machine knows; the
//! text is the consumer's to render. What only the consumer knows -- the text of an error it
//! answered with, its own figures (the term a replaced SA is still accepted inbound for, the bound
//! of owed Deletes it renders with) -- it adds.
//!
//! # What stays the consumer's
//!
//! Everything that holds keys or touches the wire or the data plane is done by the consumer, as an
//! action says. So are: which family an event is of; whether there is a data plane at all and
//! whether the tunnel is already torn down (the controller's `peer_torn_down`, which an outcome may
//! add to but never clears); the volume figures a renewal signal is computed from
//! ([`limits`](super::limits)); the event inbox and its ordering (`take_peer_children`,
//! `apply_child_events`); the queue of replacements for the daemon, its bound and the order rule
//! (`may_serve`, `SERVED_AHEAD_MAX`); the sequencing of the thread serving on arrival and of the
//! poll (`serve_mark`, `serve_taken`); and the gateway's redundant SAs of crossed rekeys
//! (`keep_redundant_in_pump`, `replace_redundant`, `close_redundant`, `overtaken_move`).
//!
//! Nothing here reads a clock, logs, or does I/O: every instant comes in with an input, and every
//! figure with the [`Policy`].

use std::time::{Duration, Instant};

use super::limits::RenewalSignal;
use super::renewal::{ChildId, DeferredSwitch, DeleteStand, FamilyRenewal, Negotiated, Party, Retired, RetiredBounds, Retirement, SwitchProof, Update};
use super::spacing::{Schedule, Spacing};

/// The consumer's figures the machine runs on. None has a default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// How far apart renewal attempts are kept ([`Spacing::schedule`]).
    pub spacing: Spacing,
    /// The bounds of the retired SAs kept; `owed_max` is where renewals by volume are suspended.
    pub retired: RetiredBounds,
    /// How long a deferred switch waits for a proof before it is made without one.
    pub unproven_after: Duration,
}

/// What came of a Delete of this side's, as the consumer maps its protocol's report onto the
/// record's terms (the controller's `delete_stand`): who deletes the SA, where its Delete stands, and
/// whether the report says the IKE SA is over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeleteCame {
    /// Who deletes the SA.
    pub deleted_by: Party,
    /// Where its Delete stands.
    pub stand: DeleteStand,
    /// The report says the IKE SA is over (the peer tore it down).
    pub ike_sa_over: bool,
}

/// What a commit of a rekey of ours, asked with no Delete ([`Action::Commit`]), came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Committed {
    /// The peer's SA of a crossed rekey was kept, and the peer deletes the replaced one (the
    /// protocol's `NotOwed("peer_deletes")`): this side answered as the responder, its switch is
    /// deferred.
    PeersKept(DeleteCame),
    /// Ours was kept and the replaced SA's Delete is ours, not asked yet (the protocol's
    /// `NotOwed("not_asked")`): it is asked once outbound has moved ([`Action::DeleteChild`]).
    OursDeleteNotAsked,
    /// Any other report, or an error: ours was kept, and this is what the replaced SA's Delete came
    /// to.
    Other(DeleteCame),
}

/// Why an exchange failed: the IKE SA is over (the peer tore it down), or any other error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// The IKE SA is over.
    IkeSaOver,
    /// Any other error.
    Other,
}

/// A rekey of ours negotiated ([`Input::Negotiated`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewChild {
    /// The new SA's SPIs, `(local, peer)`.
    pub new: (u32, u32),
    /// The instant the consumer read once the exchange was over (the controller's `switched_at`,
    /// never before the event's): what the new SA is installed and switched at, and what a switch
    /// deferred for it counts from.
    pub now: Instant,
    /// How long the exchange took, as the consumer timed it: data for [`Note::Renewed`] only.
    pub took: Duration,
}

/// The data plane did not take a new SA as the family's next generation ([`Input::Prepared`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotPrepared {
    /// The family's SA in the session, `(local, peer)`, read right after the refusal and before
    /// anything else: whether the new SA is still the family's there tells whose Delete the abandon
    /// owes.
    pub session_on: Option<(u32, u32)>,
}

/// What the consumer gives the machine: an event, taken only while it is idle, or the answer to the
/// action the last step asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Input<T> {
    /// Event: renew the family's current SA by volume if it is due (the controller's
    /// `renew_family`). `current` is the consumer's current generation of the family, `session_on`
    /// the family's SA in the protocol session, `(local, peer)`.
    RenewByVolume { now: Instant, current: Option<ChildId>, session_on: Option<(u32, u32)> },
    /// Event: the deferred switch is checked at `now` (the controller's `switch_when_proven`, for
    /// this family); `peer_sent` is whether the data plane saw the peer send on the new SA.
    SwitchCheck { now: Instant, peer_sent: bool },
    /// Event: the peer's Delete of the SA that receives on `local_spi` was answered (the
    /// controller's `replaced_closed`).
    PeerDeletedReplaced { now: Instant, local_spi: u32 },
    /// Answer to [`Action::ReadUse`]: `used` is what the SA asked about has moved, `(rx, tx)`, or
    /// `None` when the data plane's current generation of the family is not that SA. `signal` and
    /// `basis` are the consumer's volume policy over those bytes (the renewal signal, and the byte
    /// figure the spacing is sized by); `peer_rekey_held` whether a rekey of the peer's of the family
    /// is held unanswered.
    Use { used: Option<(u64, u64)>, signal: Option<RenewalSignal>, basis: Option<u64>, peer_rekey_held: bool },
    /// Answer to [`Action::Switch`] and [`Action::SwitchAtOnce`]: made, or refused (`Err`, the new
    /// SA then withdrawn).
    Switched(Result<(), ()>),
    /// Answer to [`Action::Negotiate`].
    Negotiated(Result<NewChild, Failure>),
    /// Answer to [`Action::Prepare`]: the new SA's name in the data plane, or the refusal.
    Prepared(Result<T, NotPrepared>),
    /// Answer to [`Action::Abandon`]: what the new SA's Delete came to.
    Abandoned(DeleteCame),
    /// Answer to [`Action::Commit`].
    Committed(Committed),
    /// Answer to [`Action::DeleteChild`]: what the replaced SA's Delete came to.
    Deleted(DeleteCame),
}

impl<T> Input<T> {
    /// The input's name, for [`Unexpected`].
    fn kind(&self) -> &'static str {
        match self {
            Input::RenewByVolume { .. } => "RenewByVolume",
            Input::SwitchCheck { .. } => "SwitchCheck",
            Input::PeerDeletedReplaced { .. } => "PeerDeletedReplaced",
            Input::Use { .. } => "Use",
            Input::Switched(_) => "Switched",
            Input::Negotiated(_) => "Negotiated",
            Input::Prepared(_) => "Prepared",
            Input::Abandoned(_) => "Abandoned",
            Input::Committed(_) => "Committed",
            Input::Deleted(_) => "Deleted",
        }
    }
}

/// What the machine asks the consumer to do, in the order given, each completely before the next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action<T> {
    /// A line the controller logs, for the consumer to render. Asks nothing.
    Note(Note),
    /// Read what the data plane's current generation of the family has moved, if it is the SA of
    /// `spis` `(local, peer)`. Asks [`Input::Use`].
    ReadUse { spis: (u32, u32) },
    /// Make the deferred `switch` at `now`, for `proof`: outbound moves to `switch.id`, the replaced
    /// SA still accepted inbound for the consumer's term; should the data plane refuse, `switch.id`
    /// is withdrawn from it. One operation under the data plane's lock, as the controller's
    /// `switch_in`. Asks [`Input::Switched`].
    Switch { switch: DeferredSwitch<T>, proof: SwitchProof, now: Instant },
    /// Negotiate a rekey of the family's current SA, with no Delete of it. Asks
    /// [`Input::Negotiated`].
    Negotiate,
    /// Put in the data plane, at `now`, the peer's SAs of crossed rekeys the session kept meanwhile,
    /// as redundant generations (the controller's `keep_redundant_in_pump`). Asks nothing.
    KeepRedundant { now: Instant },
    /// Install the new SA of `new` `(local, peer)` as the family's next generation at `now`: inbound
    /// accepted on it from here on. On a refusal, read the family's SA in the session before anything
    /// else ([`NotPrepared`]). Asks [`Input::Prepared`].
    Prepare { new: (u32, u32), now: Instant },
    /// Abandon the rekey whose new SA receives on `new_local_spi`, its Delete asked (`delete`). Asks
    /// [`Input::Abandoned`].
    Abandon { new_local_spi: u32, delete: bool },
    /// Commit the rekey whose new SA receives on `new_local_spi`, no Delete asked (`delete`). Asks
    /// [`Input::Committed`].
    Commit { new_local_spi: u32, delete: bool },
    /// Switch outbound to `id`, the family's next generation, at `now` -- at once, this side being
    /// the initiator --, the replaced SA still accepted inbound for the consumer's term; should the
    /// data plane refuse, `id` is withdrawn from it. One operation under the data plane's lock, as
    /// the switch in the controller's `renew_family`. Not a deferred switch. Asks
    /// [`Input::Switched`].
    SwitchAtOnce { id: T, now: Instant },
    /// Delete the replaced SA of `spis` `(local, peer)`. Asks [`Input::Deleted`].
    DeleteChild { spis: (u32, u32) },
    /// Close the IKE SA: the two ends disagree. The consumer counts the tunnel torn down. Asks
    /// nothing.
    CloseIkeSa,
    /// The family's clock by age counts a failed attempt. Asks nothing.
    AgeClockFailed,
    /// The family's clock by age starts again: its SA is a new one. Asks nothing.
    AgeClockRestart,
    /// The family's current generation is this one from now on. Asks nothing.
    BecameCurrent(ChildId),
}

impl<T> Action<T> {
    /// Whether the action asks for an answer, the next [`Input`].
    pub fn asks(&self) -> bool {
        match self {
            Action::ReadUse { .. }
            | Action::Switch { .. }
            | Action::Negotiate
            | Action::Prepare { .. }
            | Action::Abandon { .. }
            | Action::Commit { .. }
            | Action::SwitchAtOnce { .. }
            | Action::DeleteChild { .. } => true,
            Action::Note(_) | Action::KeepRedundant { .. } | Action::CloseIkeSa | Action::AgeClockFailed | Action::AgeClockRestart | Action::BecameCurrent(_) => {
                false
            }
        }
    }
}

/// A line the controller logs, with the data it prints that the machine knows; each names the
/// controller function that logs it. The family, the consumer's figures and the text of an error
/// the consumer answered with are the consumer's to add.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Note {
    /// A renewal by volume is due but held back `ms` more by the spacing of attempts; the last one
    /// failed, or only started (`renewal_due`).
    HeldBackBySpacing { ms: u128, last_failed: bool },
    /// A renewal by volume is left to the peer's rekey of the family, held for the consumer to serve
    /// (`renewal_due`).
    LeftToPeersHeldRekey,
    /// Renewals by volume of the family are suspended: `owed` Deletes stand owed, at the bound
    /// (`room_to_owe`, a Warning; on entering suspension only).
    Suspended { owed: usize },
    /// Renewals by volume of the family resumed, `owed` Deletes owed now (`room_to_owe`; on leaving
    /// suspension only).
    Resumed { owed: usize },
    /// A deferred switch was made: outbound moved to the SA receiving on `local_spi`, `ms` after its
    /// answer went, for `proof`; the replaced SA (receiving on `replaced_local_spi`) still accepted
    /// inbound (`switch_in`).
    SwitchMade { local_spi: u32, ms: u128, proof: SwitchProof, replaced_local_spi: u32 },
    /// The data plane refused a deferred switch to the SA receiving on `local_spi`: the two ends
    /// disagree, the IKE SA is closed (`switch_pending`; the error is the consumer's).
    SwitchRefused { local_spi: u32 },
    /// A switch to the SA receiving on `local_spi` was still pending when another was deferred: it
    /// is dropped (`defer_switch`).
    SwitchDropped { local_spi: u32 },
    /// A renewal by volume failed; the next may start at `retry_at` (`None`: at once), rendered as
    /// whole seconds after the event's instant (`renew_family`; the error is the consumer's).
    RenewalFailed { retry_at: Option<Instant> },
    /// The record holds `owed` owed Deletes, more than its bound, and keeps them all (`owe_delete`,
    /// a Warning).
    OwedOverCapacity { owed: usize },
    /// A Delete of ours not tried yet was recorded as settled (`owe_delete`, a Warning; the record
    /// never does this).
    OwedRecordedSettled { local_spi: u32 },
    /// The Delete of the SA receiving on `local_spi`, in `generation` (`None`: the new SA), stands
    /// owed at `stand`, not sent again; `owed` are owed now (`delete_came_to`).
    DeleteOwed { local_spi: u32, generation: Option<u64>, stand: DeleteStand, owed: usize },
    /// No owed Delete of that SA to record what it came to: nothing changes (`delete_came_to`).
    NoSuchDebt { local_spi: u32, generation: Option<u64>, stand: DeleteStand },
    /// The renewal's new SA (receiving on `new_local_spi`) could not be put in the data plane: given
    /// up, its own Delete came to `delete`; the SA in use (receiving on `replaced_local_spi`) stays
    /// (`renew_family`; the refusal's and the report's text are the consumer's).
    ReplacementGivenUp { new_local_spi: u32, delete: DeleteCame, replaced_local_spi: u32 },
    /// The replaced SA (receiving on `local_spi`), the peer's to delete, was recorded as owed:
    /// `retirement` (`renew_family`, a Warning; the consumer's mapping never does this).
    PeersDeleteRecordedOwed { local_spi: u32, retirement: Retirement },
    /// The renewal's new SA (receiving on `new_local_spi`), committed, could not be switched to: the
    /// two ends disagree, the IKE SA is closed (`renew_family`; the error is the consumer's).
    SwitchAtOnceRefused { new_local_spi: u32 },
    /// The family's SA renewed by volume, having moved `rx` and `tx` bytes, due at `at_bytes`: its
    /// replacement (receiving on `new_local_spi`) negotiated in `negotiated_ms` and put in the data
    /// plane; outbound moved to it, or, `deferred`, stays on the replaced SA (receiving on
    /// `replaced_local_spi`) until the peer is known to have the new one; the replaced SA's Delete
    /// came to `delete` (`None`: the peer's to delete) (`renew_family`, its last line).
    Renewed { rx: u64, tx: u64, at_bytes: u64, new_local_spi: u32, negotiated_ms: u128, replaced_local_spi: u32, deferred: bool, delete: Option<DeleteCame> },
}

/// How an operation ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Flow A: nothing to renew, or not yet (not due, the spacing, the peer's held rekey, suspended,
    /// the data plane not on the SA); no attempt counted, nothing sent.
    NotDue,
    /// Flow A: the attempt failed; the SA in use stays.
    Failed,
    /// The IKE SA is over, or the machine had it closed ([`Action::CloseIkeSa`]): the consumer counts
    /// the tunnel torn down.
    TornDown,
    /// Flow A: renewed; the new SA's SPIs `(local, peer)`. `deferred`: the peer's SA of a crossed
    /// rekey was kept, outbound waits on a proof. `ike_sa_over`: the replaced SA's Delete reported
    /// the IKE SA over -- renewed all the same, the tunnel torn down.
    Renewed { new: (u32, u32), deferred: bool, ike_sa_over: bool },
    /// Flow B: no switch is proven or due, or none waits on that Delete.
    Nothing,
    /// Flow B: the deferred switch was made.
    Switched,
}

/// One step of the machine: the actions to carry out, in order, and, once the operation is over,
/// how it ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step<T> {
    /// What the consumer is to do, in order. At most one asks for an answer, and it is the last.
    pub actions: Vec<Action<T>>,
    /// `None` while the operation goes on (the last action asks); how it ended once it is over.
    pub outcome: Option<Outcome>,
}

/// An input that does not fit where the machine stands: refused, and nothing changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unexpected {
    /// Where the machine stands.
    pub phase: &'static str,
    /// The input refused.
    pub input: &'static str,
}

/// A renewal by volume under way, once it is due: its event's instant, the SA it replaces, what that
/// SA moved, the signal and the byte figure it was decided on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Renewing {
    now: Instant,
    current: ChildId,
    used: (u64, u64),
    signal: RenewalSignal,
    basis: Option<u64>,
}

/// What follows a deferred switch made to free the family's next slot, or for its own sake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AfterSwitch {
    /// Flow A: the renewal is decided on the new current generation's own counts.
    Renew { now: Instant, current: ChildId },
    /// Flow B: nothing; the switch was the operation.
    Done,
}

/// Where the machine stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase<T> {
    Idle,
    /// Flow A, a switch pending: the replaced SA's use asked for.
    PendingUse { now: Instant, current: ChildId },
    /// A deferred switch asked for ([`Action::Switch`]), for `proof`; `then` follows it.
    Switching { now: Instant, switch: DeferredSwitch<T>, proof: SwitchProof, then: AfterSwitch },
    /// Flow A: the current SA's use asked for.
    Use { now: Instant, current: ChildId },
    /// Flow A: the rekey asked for.
    Negotiating(Renewing),
    /// Flow A: the new SA's install asked for.
    Preparing(Renewing, NewChild),
    /// Flow A: the abandon asked for; the Delete owed is of `owed` (SPIs, generation).
    Abandoning(Renewing, NewChild, ((u32, u32), Option<u64>)),
    /// Flow A: the commit asked for; the new SA is `id` in the data plane.
    Committing(Renewing, NewChild, T),
    /// Flow A: the switch at once asked for; `report` is what the replaced SA's Delete came to
    /// already, `None` while it is still to be asked.
    SwitchingAtOnce(Renewing, NewChild, Option<DeleteCame>),
    /// Flow A: the replaced SA's Delete asked for.
    Deleting(Renewing, NewChild),
}

impl<T> Phase<T> {
    /// The phase's name, for [`Unexpected`].
    fn name(&self) -> &'static str {
        match self {
            Phase::Idle => "idle",
            Phase::PendingUse { .. } => "pending_use",
            Phase::Switching { .. } => "switching",
            Phase::Use { .. } => "use",
            Phase::Negotiating(..) => "negotiating",
            Phase::Preparing(..) => "preparing",
            Phase::Abandoning(..) => "abandoning",
            Phase::Committing(..) => "committing",
            Phase::SwitchingAtOnce(..) => "switching_at_once",
            Phase::Deleting(..) => "deleting",
        }
    }
}

/// Where a step leaves the operation: an action asked for and the phase that waits on its answer, or
/// the operation over.
enum Flow<T> {
    Ask(Action<T>, Phase<T>),
    Done(Outcome),
}

/// The renewals of one family of CHILD SAs: its record ([`FamilyRenewal`]), where the operation
/// under way stands, and whether its renewals by volume are suspended. `T` is the consumer's name
/// for an SA in its data plane, as in [`DeferredSwitch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FamilyMachine<T> {
    record: FamilyRenewal<T>,
    phase: Phase<T>,
    suspended: bool,
}

impl<T: Copy> Default for FamilyMachine<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Copy> FamilyMachine<T> {
    /// A family with nothing recorded, idle, its renewals by volume not suspended.
    pub fn new() -> Self {
        Self { record: FamilyRenewal::new(), phase: Phase::Idle, suspended: false }
    }

    /// The family's record, read-only: only the machine's flows change it.
    pub fn record(&self) -> &FamilyRenewal<T> {
        &self.record
    }

    /// Whether no operation is under way: an event may come.
    pub fn idle(&self) -> bool {
        matches!(self.phase, Phase::Idle)
    }

    /// Whether this side's renewals by volume of the family are suspended, its owed Deletes at the
    /// bound (`room_to_owe`).
    pub fn suspended(&self) -> bool {
        self.suspended
    }

    /// The switch deferred until the peer is known to have the new SA, if one is.
    pub fn pending_switch(&self) -> Option<DeferredSwitch<T>> {
        self.record.pending_switch()
    }

    /// When the deferred switch is due with no proof, if one is pending: `policy.unproven_after`
    /// after its answer went (the controller's `next_switch_due`, for this family).
    ///
    /// Panics as [`FamilyRenewal::switch_due_at`] does.
    pub fn switch_due_at(&self, policy: &Policy) -> Option<Instant> {
        self.record.switch_due_at(policy.unproven_after)
    }

    /// One step: `input` taken where the machine stands, under `policy`. An input that does not fit
    /// -- an event while an operation is under way, an answer to an action not asked for -- is
    /// refused: [`Unexpected`], and nothing changes.
    pub fn step(&mut self, input: Input<T>, policy: &Policy) -> Result<Step<T>, Unexpected> {
        let mut actions = Vec::new();
        let out = &mut actions;
        let flow = match (self.phase, input) {
            (Phase::Idle, Input::RenewByVolume { now, current, session_on }) => self.renew_by_volume(now, current, session_on),
            (Phase::Idle, Input::SwitchCheck { now, peer_sent }) => match self.record.switch_proof(peer_sent, policy.unproven_after, now) {
                Some(proof) => self.switch_first(now, proof, AfterSwitch::Done),
                None => Flow::Done(Outcome::Nothing),
            },
            (Phase::Idle, Input::PeerDeletedReplaced { now, local_spi }) => {
                if self.record.waits_on_delete_of(local_spi) {
                    self.switch_first(now, SwitchProof::ReplacedDeleted, AfterSwitch::Done)
                } else {
                    Flow::Done(Outcome::Nothing)
                }
            }
            (Phase::PendingUse { now, current }, Input::Use { used, signal, basis, peer_rekey_held }) => {
                self.pending_use(now, current, used, signal, basis, peer_rekey_held, policy, out)
            }
            (Phase::Switching { now, switch, proof, then }, Input::Switched(made)) => self.switched(now, switch, proof, then, made, out),
            (Phase::Use { now, current }, Input::Use { used, signal, basis, peer_rekey_held }) => {
                self.current_use(now, current, used, signal, basis, peer_rekey_held, policy, out)
            }
            (Phase::Negotiating(r), Input::Negotiated(negotiated)) => self.negotiated(r, negotiated, policy, out),
            (Phase::Preparing(r, n), Input::Prepared(prepared)) => self.prepared(r, n, prepared, policy, out),
            (Phase::Abandoning(r, n, owed), Input::Abandoned(report)) => self.abandoned(r, n, owed, report, policy, out),
            (Phase::Committing(r, n, id), Input::Committed(committed)) => self.committed(r, n, id, committed, policy, out),
            (Phase::SwitchingAtOnce(r, n, report), Input::Switched(made)) => self.switched_at_once(r, n, report, made, policy, out),
            (Phase::Deleting(r, n), Input::Deleted(report)) => self.delete_reported(r, n, report, policy, out),
            (phase, input) => return Err(Unexpected { phase: phase.name(), input: input.kind() }),
        };
        let outcome = match flow {
            Flow::Ask(action, phase) => {
                actions.push(action);
                self.phase = phase;
                None
            }
            Flow::Done(outcome) => {
                self.phase = Phase::Idle;
                Some(outcome)
            }
        };
        Ok(Step { actions, outcome })
    }

    // Flow A: a renewal of ours by volume (`renew_family`).

    /// The event: due only with a current SA in the consumer's record and in the session, the same
    /// one. A switch pending is decided on the replaced SA's use first -- outbound and the renewal
    /// mark are still on it --, else the current SA's.
    fn renew_by_volume(&mut self, now: Instant, current: Option<ChildId>, session_on: Option<(u32, u32)>) -> Flow<T> {
        let Some(current) = current else { return Flow::Done(Outcome::NotDue) };
        if session_on != Some(current.spis()) {
            return Flow::Done(Outcome::NotDue);
        }
        match self.record.pending_switch() {
            Some(pending) => Flow::Ask(Action::ReadUse { spis: pending.replaced }, Phase::PendingUse { now, current }),
            None => Flow::Ask(Action::ReadUse { spis: current.spis() }, Phase::Use { now, current }),
        }
    }

    /// The replaced SA's use, a switch pending: due on what it moved, and room to owe one more
    /// Delete (no switch made for a renewal that will not start), then the switch is made first,
    /// for the slot: the renewal is decided after it on the new current generation's own counts.
    #[allow(clippy::too_many_arguments)]
    fn pending_use(
        &mut self,
        now: Instant,
        current: ChildId,
        used: Option<(u64, u64)>,
        signal: Option<RenewalSignal>,
        basis: Option<u64>,
        peer_rekey_held: bool,
        policy: &Policy,
        out: &mut Vec<Action<T>>,
    ) -> Flow<T> {
        if used.is_none() || self.renewal_due(now, signal, basis, peer_rekey_held, policy, out).is_none() {
            return Flow::Done(Outcome::NotDue);
        }
        if !self.room_to_owe(policy, out) {
            return Flow::Done(Outcome::NotDue);
        }
        self.switch_first(now, SwitchProof::SlotNeeded, AfterSwitch::Renew { now, current })
    }

    /// The current SA's use: due on what it moved, and room to owe one more Delete; then the attempt
    /// starts, and the rekey is negotiated.
    #[allow(clippy::too_many_arguments)]
    fn current_use(
        &mut self,
        now: Instant,
        current: ChildId,
        used: Option<(u64, u64)>,
        signal: Option<RenewalSignal>,
        basis: Option<u64>,
        peer_rekey_held: bool,
        policy: &Policy,
        out: &mut Vec<Action<T>>,
    ) -> Flow<T> {
        let Some(used) = used else { return Flow::Done(Outcome::NotDue) };
        let Some(signal) = self.renewal_due(now, signal, basis, peer_rekey_held, policy, out) else { return Flow::Done(Outcome::NotDue) };
        if !self.room_to_owe(policy, out) {
            return Flow::Done(Outcome::NotDue);
        }
        self.record.attempt_started(now);
        Flow::Ask(Action::Negotiate, Phase::Negotiating(Renewing { now, current, used, signal, basis }))
    }

    /// The controller's `renewal_due`: a signal, the spacing after the family's last attempt passed
    /// (at the very instant, it has), and no rekey of the peer's of the family held. The signal.
    fn renewal_due(&self, now: Instant, signal: Option<RenewalSignal>, basis: Option<u64>, peer_rekey_held: bool, policy: &Policy, out: &mut Vec<Action<T>>) -> Option<RenewalSignal> {
        let signal = signal?;
        let last = self.record.last_attempt();
        match policy.spacing.schedule(true, self.record.in_flight(), last, basis, now) {
            Schedule::Now => {}
            Schedule::At(at) => {
                let last_failed = last.is_some_and(|last| last.failed);
                out.push(Action::Note(Note::HeldBackBySpacing { ms: at.saturating_duration_since(now).as_millis(), last_failed }));
                return None;
            }
            Schedule::NotDue | Schedule::InFlight => return None,
        }
        // Held all the same: it is the family's renewal, and the session would refuse ours. Not
        // tried, not counted as an attempt.
        if peer_rekey_held {
            out.push(Action::Note(Note::LeftToPeersHeldRekey));
            return None;
        }
        Some(signal)
    }

    /// The controller's `room_to_owe`: room in the record for one more owed Delete, asked once a
    /// renewal is due and before anything is done for it. Suspended without it -- noted on entering
    /// only --, resumed with it again -- noted on leaving only.
    fn room_to_owe(&mut self, policy: &Policy, out: &mut Vec<Action<T>>) -> bool {
        let owed = self.record.owed().len();
        let room = self.record.owed_room(policy.retired.owed_max) > 0;
        let was_suspended = std::mem::replace(&mut self.suspended, !room);
        if room && was_suspended {
            out.push(Action::Note(Note::Resumed { owed }));
        } else if !room && !was_suspended {
            out.push(Action::Note(Note::Suspended { owed }));
        }
        room
    }

    /// The rekey's answer. Over: torn down, the attempt not counted failed. Failed: counted, the SA
    /// in use untouched. Negotiated: recorded, the peer's SAs of crossed rekeys put in, then the new
    /// SA installed as the next generation.
    fn negotiated(&mut self, r: Renewing, negotiated: Result<NewChild, Failure>, policy: &Policy, out: &mut Vec<Action<T>>) -> Flow<T> {
        match negotiated {
            Err(Failure::IkeSaOver) => Flow::Done(Outcome::TornDown),
            Err(Failure::Other) => {
                self.attempt_failed(out);
                out.push(Action::Note(Note::RenewalFailed { retry_at: policy.spacing.ready_at(Some(r.now), true, r.basis) }));
                Flow::Done(Outcome::Failed)
            }
            Ok(n) => {
                // None can be displaced: the spacing said no rekey of the family was in flight, and
                // every way out of this flow resolves the one recorded here.
                let _ = self.record.negotiated(Negotiated { replaces: r.current, new: n.new, started: r.now });
                out.push(Action::KeepRedundant { now: n.now });
                Flow::Ask(Action::Prepare { new: n.new, now: n.now }, Phase::Preparing(r, n))
            }
        }
    }

    /// The install's answer. Refused: the attempt failed, and the abandon's Delete is owed before it
    /// is asked -- of the new SA while it is still the family's in the session, of the replaced SA
    /// once it is not. Installed: committed with no Delete asked, which tells whose SA is kept.
    fn prepared(&mut self, r: Renewing, n: NewChild, prepared: Result<T, NotPrepared>, policy: &Policy, out: &mut Vec<Action<T>>) -> Flow<T> {
        match prepared {
            Err(NotPrepared { session_on }) => {
                self.attempt_failed(out);
                let owed = if session_on == Some(n.new) { (n.new, None) } else { (r.current.spis(), Some(r.current.generation)) };
                self.owe_delete(owed.0, owed.1, policy, out);
                Flow::Ask(Action::Abandon { new_local_spi: n.new.0, delete: true }, Phase::Abandoning(r, n, owed))
            }
            Ok(id) => Flow::Ask(Action::Commit { new_local_spi: n.new.0, delete: false }, Phase::Committing(r, n, id)),
        }
    }

    /// The abandon's answer: the rekey resolved, the owed Delete updated with what it came to, the
    /// renewal given up. Torn down if the report says the IKE SA is over.
    fn abandoned(&mut self, r: Renewing, n: NewChild, owed: ((u32, u32), Option<u64>), report: DeleteCame, policy: &Policy, out: &mut Vec<Action<T>>) -> Flow<T> {
        let _ = self.record.resolve(n.new.0);
        self.delete_came_to(owed.0, owed.1, report, policy, out);
        out.push(Action::Note(Note::ReplacementGivenUp { new_local_spi: n.new.0, delete: report, replaced_local_spi: r.current.local_spi }));
        Flow::Done(if report.ike_sa_over { Outcome::TornDown } else { Outcome::Failed })
    }

    /// The commit's answer: the rekey resolved. The peer's SA kept: its switch deferred, the replaced
    /// SA retired as the peer's to delete, renewed. Ours: switched to at once.
    fn committed(&mut self, r: Renewing, n: NewChild, id: T, committed: Committed, policy: &Policy, out: &mut Vec<Action<T>>) -> Flow<T> {
        let _ = self.record.resolve(n.new.0);
        let report = match committed {
            Committed::PeersKept(report) => {
                self.defer_switch(DeferredSwitch { id, local_spi: n.new.0, replaced: r.current.spis(), answered: n.now }, out);
                let replaced = Retired { spis: r.current.spis(), generation: Some(r.current.generation), deleted_by: report.deleted_by, stand: report.stand };
                match self.record.retire_within(replaced, policy.retired) {
                    Retirement::Settled => {}
                    retirement @ (Retirement::Owed { .. } | Retirement::OverCapacity { .. }) => {
                        out.push(Action::Note(Note::PeersDeleteRecordedOwed { local_spi: r.current.local_spi, retirement }));
                    }
                }
                return Flow::Done(self.renewed(r, n, true, None, out));
            }
            Committed::OursDeleteNotAsked => None,
            Committed::Other(report) => Some(report),
        };
        Flow::Ask(Action::SwitchAtOnce { id, now: n.now }, Phase::SwitchingAtOnce(r, n, report))
    }

    /// The switch at once's answer. Refused: the attempt failed and the IKE SA is closed, the two
    /// ends disagreeing. Made: the replaced SA's Delete is owed before it is asked; asked now if the
    /// commit did not, else what the commit reported is what it came to.
    fn switched_at_once(&mut self, r: Renewing, n: NewChild, report: Option<DeleteCame>, made: Result<(), ()>, policy: &Policy, out: &mut Vec<Action<T>>) -> Flow<T> {
        if made.is_err() {
            self.attempt_failed(out);
            out.push(Action::Note(Note::SwitchAtOnceRefused { new_local_spi: n.new.0 }));
            out.push(Action::CloseIkeSa);
            return Flow::Done(Outcome::TornDown);
        }
        self.owe_delete(r.current.spis(), Some(r.current.generation), policy, out);
        match report {
            None => Flow::Ask(Action::DeleteChild { spis: r.current.spis() }, Phase::Deleting(r, n)),
            Some(report) => self.delete_reported(r, n, report, policy, out),
        }
    }

    /// What the replaced SA's Delete came to, recorded; renewed.
    fn delete_reported(&mut self, r: Renewing, n: NewChild, report: DeleteCame, policy: &Policy, out: &mut Vec<Action<T>>) -> Flow<T> {
        self.delete_came_to(r.current.spis(), Some(r.current.generation), report, policy, out);
        Flow::Done(self.renewed(r, n, false, Some(report), out))
    }

    /// The renewal's end: the family's clock started again, its current generation the new SA, and
    /// the controller's last line.
    fn renewed(&mut self, r: Renewing, n: NewChild, deferred: bool, delete: Option<DeleteCame>, out: &mut Vec<Action<T>>) -> Outcome {
        out.push(Action::AgeClockRestart);
        out.push(Action::BecameCurrent(r.current.successor(n.new.0, n.new.1)));
        out.push(Action::Note(Note::Renewed {
            rx: r.used.0,
            tx: r.used.1,
            at_bytes: r.signal.at_bytes,
            new_local_spi: n.new.0,
            negotiated_ms: n.took.as_millis(),
            replaced_local_spi: r.current.local_spi,
            deferred,
            delete,
        }));
        Outcome::Renewed { new: n.new, deferred, ike_sa_over: delete.is_some_and(|d| d.ike_sa_over) }
    }

    /// The controller's `volume_attempt_failed`: the record and the family's clock count it.
    fn attempt_failed(&mut self, out: &mut Vec<Action<T>>) {
        self.record.attempt_failed();
        out.push(Action::AgeClockFailed);
    }

    /// The controller's `owe_delete`: the Delete of the SA of `spis` in `generation` (`None`: a new SA
    /// the consumer's record never had) is owed, recorded before it is tried, never dropped.
    fn owe_delete(&mut self, spis: (u32, u32), generation: Option<u64>, policy: &Policy, out: &mut Vec<Action<T>>) {
        match self.record.retire_within(Retired { spis, generation, deleted_by: Party::Ours, stand: DeleteStand::NotSent }, policy.retired) {
            Retirement::Owed { .. } => {}
            Retirement::OverCapacity { owed } => out.push(Action::Note(Note::OwedOverCapacity { owed })),
            Retirement::Settled => out.push(Action::Note(Note::OwedRecordedSettled { local_spi: spis.0 })),
        }
    }

    /// The controller's `delete_came_to`: the owed entry of exactly that SA takes what its Delete came
    /// to -- settled on evidence, still owed otherwise, and never sent again. With none, nothing
    /// changes.
    fn delete_came_to(&mut self, spis: (u32, u32), generation: Option<u64>, report: DeleteCame, policy: &Policy, out: &mut Vec<Action<T>>) {
        let stand = report.stand;
        match self.record.update(Retired { spis, generation, deleted_by: report.deleted_by, stand }, policy.retired) {
            Update::Settled => {}
            Update::Owed => out.push(Action::Note(Note::DeleteOwed { local_spi: spis.0, generation, stand, owed: self.record.owed().len() })),
            Update::NoSuchDebt => out.push(Action::Note(Note::NoSuchDebt { local_spi: spis.0, generation, stand })),
        }
    }

    // The deferred switch (`switch_pending`, `switch_in`, `defer_switch`).

    /// The switch pending for the family, if any, asked for at `now` for `proof`, then `then`; with
    /// none pending, `then` at once (the controller's `switch_pending` with none: nothing to do).
    fn switch_first(&mut self, now: Instant, proof: SwitchProof, then: AfterSwitch) -> Flow<T> {
        match self.record.take_switch() {
            Some(switch) => Flow::Ask(Action::Switch { switch, proof, now }, Phase::Switching { now, switch, proof, then }),
            None => self.after_switch(then),
        }
    }

    /// The deferred switch's answer. Made: noted, then what follows. Refused -- the new SA withdrawn,
    /// the answer gone: the two ends disagree, the IKE SA is closed.
    fn switched(&mut self, now: Instant, switch: DeferredSwitch<T>, proof: SwitchProof, then: AfterSwitch, made: Result<(), ()>, out: &mut Vec<Action<T>>) -> Flow<T> {
        if made.is_err() {
            out.push(Action::Note(Note::SwitchRefused { local_spi: switch.local_spi }));
            out.push(Action::CloseIkeSa);
            return Flow::Done(Outcome::TornDown);
        }
        let ms = now.saturating_duration_since(switch.answered).as_millis();
        out.push(Action::Note(Note::SwitchMade { local_spi: switch.local_spi, ms, proof, replaced_local_spi: switch.replaced.0 }));
        self.after_switch(then)
    }

    /// What follows a switch made, or none to make.
    fn after_switch(&mut self, then: AfterSwitch) -> Flow<T> {
        match then {
            AfterSwitch::Renew { now, current } => Flow::Ask(Action::ReadUse { spis: current.spis() }, Phase::Use { now, current }),
            AfterSwitch::Done => Flow::Done(Outcome::Switched),
        }
    }

    /// The controller's `defer_switch`: `switch` deferred; one still pending is dropped, noted.
    fn defer_switch(&mut self, switch: DeferredSwitch<T>, out: &mut Vec<Action<T>>) {
        if let Some(earlier) = self.record.defer_switch(switch) {
            out.push(Action::Note(Note::SwitchDropped { local_spi: earlier.local_spi }));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::limits::Origin;
    use crate::session::spacing::LastAttempt;
    use DeleteStand::{Failed, NotOwed, NotSent, Sent, Unknown};
    use Party::{Ours, Peers};

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    fn ms(m: u64) -> Duration {
        Duration::from_millis(m)
    }

    /// How long a deferred switch waits for a proof, in these tests.
    const WAIT: Duration = Duration::from_secs(5);

    /// The figures of a consumer that sizes I_min at a quarter of the limit, at 64 MB/s, between 50
    /// and 200 ms, retries 5 s after a failure (those of `spacing`'s tests), keeps 4 settled retired
    /// SAs and suspends its renewals at 3 owed Deletes.
    const POLICY: Policy = Policy {
        spacing: Spacing {
            floor: Duration::from_millis(50),
            cap: Duration::from_millis(200),
            reference_rate: 64_000_000,
            limit_divisor: 4,
            retry_after_failure: Duration::from_secs(5),
        },
        retired: RetiredBounds { settled_kept: 4, owed_max: 3 },
        unproven_after: WAIT,
    };

    /// `POLICY` with another bound of owed Deletes.
    fn owing(owed_max: usize) -> Policy {
        Policy { retired: RetiredBounds { owed_max, ..POLICY.retired }, ..POLICY }
    }

    /// The family's current SA in most tests, and the new SA a renewal of it negotiates.
    const CURRENT: ChildId = ChildId { generation: 7, local_spi: 0x11, peer_spi: 0x12 };
    const NEW: (u32, u32) = (0x21, 0x22);
    /// The new SA's name in the consumer's data plane.
    const ID: u64 = 99;
    /// A 5 120 000-byte figure renewed at half of it: I_min is the floor, 50 ms.
    const BASIS: Option<u64> = Some(5_120_000);
    const SIGNAL: RenewalSignal = RenewalSignal { origin: Origin::Configured, at_bytes: 2_560_000 };
    const USED: (u64, u64) = (2_600_000, 1_000);
    /// How long the negotiation takes, in these tests.
    const TOOK: Duration = Duration::from_millis(10);

    const fn came(deleted_by: Party, stand: DeleteStand) -> DeleteCame {
        DeleteCame { deleted_by, stand, ike_sa_over: false }
    }

    const ACKED: DeleteCame = came(Ours, Sent { acknowledged: true });
    const PEERS: DeleteCame = came(Peers, NotOwed("peer_deletes"));

    /// An instant with an hour of room before it; each test takes one and counts from it.
    fn t0() -> Instant {
        Instant::now() + secs(3600)
    }

    fn renew(now: Instant, current: ChildId) -> Input<u64> {
        Input::RenewByVolume { now, current: Some(current), session_on: Some(current.spis()) }
    }

    /// The use of an SA due for renewal by volume.
    fn due() -> Input<u64> {
        Input::Use { used: Some(USED), signal: Some(SIGNAL), basis: BASIS, peer_rekey_held: false }
    }

    /// The use of an SA not due.
    fn not_due() -> Input<u64> {
        Input::Use { used: Some((1, 1)), signal: None, basis: BASIS, peer_rekey_held: false }
    }

    /// A rekey to `new` negotiated, its exchange over `TOOK` after `now`.
    fn negotiated(now: Instant, new: (u32, u32)) -> Input<u64> {
        Input::Negotiated(Ok(NewChild { new, now: now + TOOK, took: TOOK }))
    }

    /// The answers of a renewal of `CURRENT` to `NEW` that is due, from its use on, up to its commit.
    fn up_to_commit(now: Instant) -> Vec<Input<u64>> {
        vec![due(), negotiated(now, NEW), Input::Prepared(Ok(ID))]
    }

    /// A script, and what came of it.
    #[derive(Debug)]
    struct Run {
        /// Every action of every step, in order.
        actions: Vec<Action<u64>>,
        outcome: Outcome,
        /// The asking action of each step but the last, with the owed Deletes the record held right
        /// after that step.
        asked: Vec<(Action<u64>, Vec<Retired>)>,
    }

    impl Run {
        fn kinds(&self) -> Vec<&'static str> {
            self.actions.iter().map(kind).collect()
        }

        fn asking(&self) -> Vec<&'static str> {
            self.asked.iter().map(|(a, _)| kind(a)).collect()
        }

        fn notes(&self) -> Vec<Note> {
            self.actions.iter().filter_map(|a| if let Action::Note(n) = a { Some(*n) } else { None }).collect()
        }

        /// Where the first action of `what` is, which must be there.
        fn at(&self, what: &str) -> usize {
            self.kinds().iter().position(|k| *k == what).unwrap_or_else(|| panic!("no {what} in {:?}", self.kinds()))
        }

        fn has(&self, what: &str) -> bool {
            self.kinds().contains(&what)
        }

        /// The owed Deletes right after the step that asked `what`.
        fn owed_at(&self, what: &str) -> Vec<Retired> {
            self.asked.iter().find(|(a, _)| kind(a) == what).map(|(_, owed)| owed.clone()).unwrap_or_else(|| panic!("{what} not asked: {:?}", self.asking()))
        }
    }

    fn kind(a: &Action<u64>) -> &'static str {
        match a {
            Action::Note(_) => "Note",
            Action::ReadUse { .. } => "ReadUse",
            Action::Switch { .. } => "Switch",
            Action::Negotiate => "Negotiate",
            Action::KeepRedundant { .. } => "KeepRedundant",
            Action::Prepare { .. } => "Prepare",
            Action::Abandon { .. } => "Abandon",
            Action::Commit { .. } => "Commit",
            Action::SwitchAtOnce { .. } => "SwitchAtOnce",
            Action::DeleteChild { .. } => "DeleteChild",
            Action::CloseIkeSa => "CloseIkeSa",
            Action::AgeClockFailed => "AgeClockFailed",
            Action::AgeClockRestart => "AgeClockRestart",
            Action::BecameCurrent(_) => "BecameCurrent",
        }
    }

    /// `event`, then `answers` one per step, into `m` under `policy`; every step checked against the
    /// protocol: at most one asking action, the last, and then no outcome and the machine not idle;
    /// an outcome only with none, and the machine idle. The script must end exactly with the
    /// operation.
    fn drive(m: &mut FamilyMachine<u64>, policy: &Policy, event: Input<u64>, answers: &[Input<u64>]) -> Run {
        let mut inputs = std::iter::once(event).chain(answers.iter().copied());
        let mut run = Run { actions: Vec::new(), outcome: Outcome::Nothing, asked: Vec::new() };
        loop {
            let input = inputs.next().unwrap_or_else(|| panic!("the script ran out of answers after {:?}", run.kinds()));
            let step = m.step(input, policy).unwrap_or_else(|e| panic!("{input:?} refused: {e:?}, after {:?}", run.kinds()));
            let asking = step.actions.iter().filter(|a| a.asks()).count();
            run.actions.extend(step.actions.iter().copied());
            match step.outcome {
                None => {
                    assert_eq!(asking, 1, "one asking action: {:?}", step.actions);
                    let last = *step.actions.last().unwrap();
                    assert!(last.asks(), "the asking action last: {:?}", step.actions);
                    assert!(!m.idle());
                    run.asked.push((last, m.record().owed().to_vec()));
                }
                Some(outcome) => {
                    assert_eq!(asking, 0, "none asks at the end: {:?}", step.actions);
                    assert!(m.idle());
                    assert!(inputs.next().is_none(), "answers left over after {outcome:?}");
                    run.outcome = outcome;
                    return run;
                }
            }
        }
    }

    /// The renewal of `CURRENT` to `NEW` at `now`, committed as `committed`, switched to and its
    /// Delete answered as `rest` says: what `CURRENT` was renewed with in the tests below.
    fn renewal(m: &mut FamilyMachine<u64>, policy: &Policy, now: Instant, committed: Committed, rest: &[Input<u64>]) -> Run {
        let mut answers = up_to_commit(now);
        answers.push(Input::Committed(committed));
        answers.extend_from_slice(rest);
        drive(m, policy, renew(now, CURRENT), &answers)
    }

    fn retired(c: ChildId, by: Party, stand: DeleteStand) -> Retired {
        Retired { spis: c.spis(), generation: Some(c.generation), deleted_by: by, stand }
    }

    fn settled(m: &FamilyMachine<u64>) -> Vec<Retired> {
        m.record().settled().copied().collect()
    }

    /// The machine as it is after nothing happened to it but the operations that left it idle and
    /// recorded nothing.
    fn untouched(m: &FamilyMachine<u64>) {
        assert_eq!(*m, FamilyMachine::new());
    }

    #[test]
    fn a_renewal_is_not_due_without_a_current_sa_the_same_in_the_session_and_the_data_plane_on_it() {
        let t0 = t0();
        let mut m = FamilyMachine::<u64>::new();
        for (current, session_on) in [(None, Some(CURRENT.spis())), (Some(CURRENT), None), (Some(CURRENT), Some(NEW)), (Some(CURRENT), Some((0x11, 0x99)))] {
            let run = drive(&mut m, &POLICY, Input::RenewByVolume { now: t0, current, session_on }, &[]);
            assert_eq!((run.outcome, run.actions), (Outcome::NotDue, vec![]), "{current:?} {session_on:?}");
            untouched(&m);
        }
        // The data plane's current generation is not that SA, or it is not due: nothing noted.
        for answer in [Input::Use { used: None, signal: Some(SIGNAL), basis: BASIS, peer_rekey_held: false }, not_due()] {
            let run = drive(&mut m, &POLICY, renew(t0, CURRENT), &[answer]);
            assert_eq!(run.actions, [Action::ReadUse { spis: CURRENT.spis() }], "{answer:?}");
            assert_eq!(run.outcome, Outcome::NotDue);
            untouched(&m);
        }
    }

    #[test]
    fn a_renewal_held_back_by_the_spacing_is_noted_with_how_long_and_whether_the_last_failed() {
        let t0 = t0();
        let mut m = FamilyMachine::<u64>::new();
        // A failed attempt at t0: 5 s before the next, whatever I_min is.
        drive(&mut m, &POLICY, renew(t0, CURRENT), &[due(), Input::Negotiated(Err(Failure::Other))]);
        let run = drive(&mut m, &POLICY, renew(t0 + secs(1), CURRENT), &[due()]);
        assert_eq!(run.notes(), [Note::HeldBackBySpacing { ms: 4000, last_failed: true }]);
        assert_eq!((run.outcome, run.has("Negotiate")), (Outcome::NotDue, false));
        assert_eq!(m.record().last_attempt(), Some(LastAttempt { started: t0, failed: true }), "not counted as an attempt");
        let run = drive(&mut m, &POLICY, renew(t0 + secs(5) - Duration::from_nanos(1), CURRENT), &[due()]);
        assert_eq!(run.notes(), [Note::HeldBackBySpacing { ms: 0, last_failed: true }], "a nanosecond short: still held back");
        let run = drive(&mut m, &POLICY, renew(t0 + secs(5), CURRENT), &[due(), Input::Negotiated(Err(Failure::IkeSaOver))]);
        assert_eq!(run.asking(), ["ReadUse", "Negotiate"], "at the very instant");
        assert_eq!(m.record().last_attempt(), Some(LastAttempt { started: t0 + secs(5), failed: false }));
        // An attempt only started: I_min, 50 ms for this figure.
        let run = drive(&mut m, &POLICY, renew(t0 + secs(5) + ms(10), CURRENT), &[due()]);
        assert_eq!(run.notes(), [Note::HeldBackBySpacing { ms: 40, last_failed: false }]);
        let run = drive(&mut m, &POLICY, renew(t0 + secs(5) + ms(50), CURRENT), &[due(), Input::Negotiated(Err(Failure::IkeSaOver))]);
        assert!(run.has("Negotiate"));
    }

    #[test]
    fn a_renewal_with_a_rekey_of_the_peers_held_is_left_to_it_and_not_counted() {
        let t0 = t0();
        let mut m = FamilyMachine::<u64>::new();
        let held = Input::Use { used: Some(USED), signal: Some(SIGNAL), basis: BASIS, peer_rekey_held: true };
        let run = drive(&mut m, &POLICY, renew(t0, CURRENT), &[held]);
        assert_eq!(run.notes(), [Note::LeftToPeersHeldRekey]);
        assert_eq!(run.outcome, Outcome::NotDue);
        untouched(&m);
    }

    #[test]
    fn a_failed_negotiation_counts_and_notes_the_retry_and_an_ike_sa_over_counts_nothing() {
        let t0 = t0();
        let mut m = FamilyMachine::<u64>::new();
        let run = drive(&mut m, &POLICY, renew(t0, CURRENT), &[due(), Input::Negotiated(Err(Failure::Other))]);
        assert_eq!(run.asking(), ["ReadUse", "Negotiate"]);
        assert_eq!(run.actions[2..], [Action::AgeClockFailed, Action::Note(Note::RenewalFailed { retry_at: Some(t0 + secs(5)) })]);
        assert_eq!(run.outcome, Outcome::Failed);
        assert_eq!(m.record().last_attempt(), Some(LastAttempt { started: t0, failed: true }));
        assert_eq!((m.record().in_flight(), m.record().owed().len(), m.record().settled().len(), m.pending_switch()), (false, 0, 0, None));

        let mut m = FamilyMachine::<u64>::new();
        let run = drive(&mut m, &POLICY, renew(t0, CURRENT), &[due(), Input::Negotiated(Err(Failure::IkeSaOver))]);
        assert_eq!((run.outcome, run.kinds()), (Outcome::TornDown, vec!["ReadUse", "Negotiate"]), "nothing more: not counted failed");
        assert_eq!(m.record().last_attempt(), Some(LastAttempt { started: t0, failed: false }));
        assert!(!m.record().in_flight());
    }

    #[test]
    fn a_refused_install_owes_the_abandons_delete_of_the_new_sa_or_the_replaced_one_before_it_is_asked() {
        let t0 = t0();
        let new_sa = Retired { spis: NEW, generation: None, deleted_by: Ours, stand: NotSent };
        let replaced = retired(CURRENT, Ours, NotSent);
        for (session_on, owed) in [(Some(NEW), new_sa), (Some(CURRENT.spis()), replaced), (None, replaced), (Some((0x31, 0x32)), replaced)] {
            for (report, outcome) in [
                (ACKED, Outcome::Failed),
                (came(Ours, Failed), Outcome::Failed),
                (came(Ours, Unknown), Outcome::Failed),
                (DeleteCame { ike_sa_over: true, ..ACKED }, Outcome::TornDown),
                (DeleteCame { ike_sa_over: true, ..came(Ours, NotOwed("ike_sa_gone")) }, Outcome::TornDown),
            ] {
                let mut m = FamilyMachine::<u64>::new();
                let answers = [due(), negotiated(t0, NEW), Input::Prepared(Err(NotPrepared { session_on })), Input::Abandoned(report)];
                let run = drive(&mut m, &POLICY, renew(t0, CURRENT), &answers);
                let what = format!("{session_on:?} {report:?}");
                assert_eq!(run.asking(), ["ReadUse", "Negotiate", "Prepare", "Abandon"], "{what}");
                assert_eq!(run.asked[3].0, Action::Abandon { new_local_spi: NEW.0, delete: true }, "{what}");
                assert_eq!(run.owed_at("Abandon"), [owed], "{what}: owed at the step that asks the abandon");
                assert!(run.at("AgeClockFailed") < run.at("Abandon"), "{what}");
                assert_eq!(run.outcome, outcome, "{what}");
                let came_to = Retired { deleted_by: report.deleted_by, stand: report.stand, ..owed };
                let still_owed = matches!(report.stand, Failed | Unknown);
                assert_eq!(m.record().owed(), if still_owed { vec![came_to] } else { vec![] }, "{what}");
                assert_eq!(settled(&m), if still_owed { vec![] } else { vec![came_to] }, "{what}");
                let mut notes = vec![];
                if still_owed {
                    notes.push(Note::DeleteOwed { local_spi: owed.spis.0, generation: owed.generation, stand: report.stand, owed: 1 });
                }
                notes.push(Note::ReplacementGivenUp { new_local_spi: NEW.0, delete: report, replaced_local_spi: CURRENT.local_spi });
                assert_eq!(run.notes(), notes, "{what}");
                assert_eq!(m.record().last_attempt(), Some(LastAttempt { started: t0, failed: true }), "{what}");
                assert_eq!((m.record().in_flight(), m.pending_switch()), (false, None), "{what}");
                assert!(!run.has("BecameCurrent") && !run.has("AgeClockRestart") && !run.has("Commit"), "{what}");
            }
        }
    }

    #[test]
    fn a_commit_that_keeps_the_peers_sa_defers_its_switch_and_retires_the_replaced_sa_as_the_peers() {
        let t0 = t0();
        let mut m = FamilyMachine::<u64>::new();
        let run = renewal(&mut m, &POLICY, t0, Committed::PeersKept(PEERS), &[]);
        assert_eq!(run.asking(), ["ReadUse", "Negotiate", "Prepare", "Commit"]);
        assert!(!run.has("Switch") && !run.has("SwitchAtOnce") && !run.has("DeleteChild"), "no switch before a proof, no Delete of ours");
        let next = ChildId { generation: 8, local_spi: NEW.0, peer_spi: NEW.1 };
        assert_eq!(
            run.actions[run.at("Commit") + 1..],
            [
                Action::AgeClockRestart,
                Action::BecameCurrent(next),
                Action::Note(Note::Renewed { rx: USED.0, tx: USED.1, at_bytes: SIGNAL.at_bytes, new_local_spi: NEW.0, negotiated_ms: 10, replaced_local_spi: 0x11, deferred: true, delete: None }),
            ]
        );
        assert_eq!(run.outcome, Outcome::Renewed { new: NEW, deferred: true, ike_sa_over: false });
        assert_eq!(m.pending_switch(), Some(DeferredSwitch { id: ID, local_spi: NEW.0, replaced: CURRENT.spis(), answered: t0 + TOOK }));
        assert_eq!(m.switch_due_at(&POLICY), Some(t0 + TOOK + WAIT));
        assert_eq!((m.record().owed(), settled(&m)), (&[][..], vec![retired(CURRENT, Peers, NotOwed("peer_deletes"))]));
        assert_eq!(m.record().last_attempt(), Some(LastAttempt { started: t0, failed: false }));
        assert!(!m.record().in_flight());

        // A report the consumer mapped as ours to delete is kept owed all the same, and said.
        let mut m = FamilyMachine::<u64>::new();
        let run = renewal(&mut m, &POLICY, t0, Committed::PeersKept(came(Ours, NotSent)), &[]);
        assert_eq!(run.notes()[0], Note::PeersDeleteRecordedOwed { local_spi: 0x11, retirement: Retirement::Owed { room: 2 } });
        assert_eq!(m.record().owed(), [retired(CURRENT, Ours, NotSent)]);
        assert_eq!(run.outcome, Outcome::Renewed { new: NEW, deferred: true, ike_sa_over: false });
        // The IKE SA over in the commit's report is not looked at on this way, as the controller.
        let mut m = FamilyMachine::<u64>::new();
        let run = renewal(&mut m, &POLICY, t0, Committed::PeersKept(DeleteCame { ike_sa_over: true, ..PEERS }), &[]);
        assert_eq!(run.outcome, Outcome::Renewed { new: NEW, deferred: true, ike_sa_over: false });
    }

    #[test]
    fn a_switch_at_once_refused_counts_the_attempt_failed_and_closes_the_ike_sa_owing_nothing() {
        let t0 = t0();
        for committed in [Committed::OursDeleteNotAsked, Committed::Other(ACKED)] {
            let mut m = FamilyMachine::<u64>::new();
            let run = renewal(&mut m, &POLICY, t0, committed, &[Input::Switched(Err(()))]);
            assert_eq!(run.asking(), ["ReadUse", "Negotiate", "Prepare", "Commit", "SwitchAtOnce"], "{committed:?}");
            assert_eq!(run.asked[4].0, Action::SwitchAtOnce { id: ID, now: t0 + TOOK });
            assert_eq!(run.actions[run.at("SwitchAtOnce") + 1..], [Action::AgeClockFailed, Action::Note(Note::SwitchAtOnceRefused { new_local_spi: NEW.0 }), Action::CloseIkeSa]);
            assert_eq!(run.outcome, Outcome::TornDown);
            assert_eq!((m.record().owed().len(), m.record().settled().len(), m.record().in_flight(), m.pending_switch()), (0, 0, false, None), "{committed:?}");
            assert_eq!(m.record().last_attempt(), Some(LastAttempt { started: t0, failed: true }));
        }
    }

    #[test]
    fn ours_kept_the_replaced_sas_delete_is_owed_before_it_is_asked_and_takes_what_it_came_to() {
        let t0 = t0();
        let owed = retired(CURRENT, Ours, NotSent);
        for (stand, still_owed) in [(Sent { acknowledged: true }, false), (Sent { acknowledged: false }, true), (Unknown, true), (Failed, true), (NotOwed("ike_sa_gone"), false)] {
            for ike_sa_over in [false, true] {
                let report = DeleteCame { deleted_by: Ours, stand, ike_sa_over };
                let mut m = FamilyMachine::<u64>::new();
                let run = renewal(&mut m, &POLICY, t0, Committed::OursDeleteNotAsked, &[Input::Switched(Ok(())), Input::Deleted(report)]);
                assert_eq!(run.asking(), ["ReadUse", "Negotiate", "Prepare", "Commit", "SwitchAtOnce", "DeleteChild"], "{report:?}");
                assert_eq!(run.asked[5].0, Action::DeleteChild { spis: CURRENT.spis() });
                assert_eq!(run.owed_at("DeleteChild"), [owed], "{report:?}: owed at the step that asks the Delete");
                assert_eq!(run.owed_at("SwitchAtOnce"), [], "{report:?}: not before the switch");
                let came_to = retired(CURRENT, Ours, stand);
                assert_eq!(m.record().owed(), if still_owed { vec![came_to] } else { vec![] }, "{report:?}");
                assert_eq!(settled(&m), if still_owed { vec![] } else { vec![came_to] }, "{report:?}");
                let mut notes = vec![];
                if still_owed {
                    notes.push(Note::DeleteOwed { local_spi: 0x11, generation: Some(7), stand, owed: 1 });
                }
                notes.push(Note::Renewed { rx: USED.0, tx: USED.1, at_bytes: SIGNAL.at_bytes, new_local_spi: NEW.0, negotiated_ms: 10, replaced_local_spi: 0x11, deferred: false, delete: Some(report) });
                assert_eq!(run.notes(), notes, "{report:?}");
                assert_eq!(run.outcome, Outcome::Renewed { new: NEW, deferred: false, ike_sa_over }, "{report:?}");
                assert_eq!((m.record().in_flight(), m.pending_switch()), (false, None));
                assert_eq!(m.record().last_attempt(), Some(LastAttempt { started: t0, failed: false }));
            }
        }
        // What the commit itself reported, with no Delete to ask.
        for (report, still_owed) in [(ACKED, false), (came(Ours, Failed), true), (DeleteCame { ike_sa_over: true, ..came(Ours, Unknown) }, true)] {
            let mut m = FamilyMachine::<u64>::new();
            let run = renewal(&mut m, &POLICY, t0, Committed::Other(report), &[Input::Switched(Ok(()))]);
            assert_eq!(run.asking(), ["ReadUse", "Negotiate", "Prepare", "Commit", "SwitchAtOnce"], "{report:?}");
            assert_eq!(m.record().owed().len(), usize::from(still_owed), "{report:?}");
            assert_eq!(run.outcome, Outcome::Renewed { new: NEW, deferred: false, ike_sa_over: report.ike_sa_over });
        }
    }

    #[test]
    fn a_renewal_of_ours_goes_in_the_controllers_order() {
        let t0 = t0();
        let mut m = FamilyMachine::<u64>::new();
        let run = renewal(&mut m, &POLICY, t0, Committed::OursDeleteNotAsked, &[Input::Switched(Ok(())), Input::Deleted(ACKED)]);
        let next = ChildId { generation: 8, local_spi: NEW.0, peer_spi: NEW.1 };
        assert_eq!(
            run.actions,
            [
                Action::ReadUse { spis: CURRENT.spis() },
                Action::Negotiate,
                Action::KeepRedundant { now: t0 + TOOK },
                Action::Prepare { new: NEW, now: t0 + TOOK },
                Action::Commit { new_local_spi: NEW.0, delete: false },
                Action::SwitchAtOnce { id: ID, now: t0 + TOOK },
                Action::DeleteChild { spis: CURRENT.spis() },
                Action::AgeClockRestart,
                Action::BecameCurrent(next),
                Action::Note(Note::Renewed { rx: USED.0, tx: USED.1, at_bytes: SIGNAL.at_bytes, new_local_spi: NEW.0, negotiated_ms: 10, replaced_local_spi: 0x11, deferred: false, delete: Some(ACKED) }),
            ]
        );
        let order = ["Negotiate", "KeepRedundant", "Prepare", "Commit", "SwitchAtOnce", "DeleteChild", "AgeClockRestart", "BecameCurrent"];
        for pair in order.windows(2) {
            assert!(run.at(pair[0]) < run.at(pair[1]), "{} before {}", pair[0], pair[1]);
        }
        assert_eq!((m.record().owed(), settled(&m)), (&[][..], vec![retired(CURRENT, Ours, Sent { acknowledged: true })]));
    }

    /// A switch deferred for `NEW` (answered at `t0 + TOOK`), the family on generation 8 of it, from
    /// a renewal of ours at `t0` that kept the peer's SA.
    fn with_a_switch_pending(t0: Instant) -> FamilyMachine<u64> {
        let mut m = FamilyMachine::<u64>::new();
        renewal(&mut m, &POLICY, t0, Committed::PeersKept(PEERS), &[]);
        assert!(m.pending_switch().is_some());
        m
    }

    const NEXT: ChildId = ChildId { generation: 8, local_spi: NEW.0, peer_spi: NEW.1 };

    #[test]
    fn with_a_switch_pending_a_renewal_is_decided_on_the_replaced_sa_then_made_after_the_switch_on_the_new_one() {
        let t0 = t0();
        let at = t0 + secs(1);
        let mut m = with_a_switch_pending(t0);
        let pending = m.pending_switch().unwrap();
        let newer = (0x31, 0x32);
        let answers = [
            due(),
            Input::Switched(Ok(())),
            due(),
            negotiated(at, newer),
            Input::Prepared(Ok(ID + 1)),
            Input::Committed(Committed::OursDeleteNotAsked),
            Input::Switched(Ok(())),
            Input::Deleted(ACKED),
        ];
        let run = drive(&mut m, &POLICY, renew(at, NEXT), &answers);
        assert_eq!(run.asking(), ["ReadUse", "Switch", "ReadUse", "Negotiate", "Prepare", "Commit", "SwitchAtOnce", "DeleteChild"]);
        assert_eq!(run.asked[0].0, Action::ReadUse { spis: CURRENT.spis() }, "the replaced SA's use: outbound is on it");
        assert_eq!(run.asked[1].0, Action::Switch { switch: pending, proof: SwitchProof::SlotNeeded, now: at });
        assert_eq!(run.actions[2], Action::Note(Note::SwitchMade { local_spi: NEW.0, ms: 990, proof: SwitchProof::SlotNeeded, replaced_local_spi: 0x11 }));
        assert_eq!(run.asked[2].0, Action::ReadUse { spis: NEW }, "then the new current generation's own counts");
        assert_eq!(run.outcome, Outcome::Renewed { new: newer, deferred: false, ike_sa_over: false });
        assert!(run.actions.contains(&Action::BecameCurrent(ChildId { generation: 9, local_spi: 0x31, peer_spi: 0x32 })));
        assert_eq!(m.pending_switch(), None);
        assert_eq!(m.record().owed(), []);

        // Switched, then the new SA not due: nothing more, the switch made all the same.
        let mut m = with_a_switch_pending(t0);
        let run = drive(&mut m, &POLICY, renew(at, NEXT), &[due(), Input::Switched(Ok(())), not_due()]);
        assert_eq!((run.asking(), run.outcome), (vec!["ReadUse", "Switch", "ReadUse"], Outcome::NotDue));
        assert_eq!(m.pending_switch(), None);
        assert_eq!(m.record().last_attempt(), Some(LastAttempt { started: t0, failed: false }), "no attempt counted");
    }

    #[test]
    fn with_a_switch_pending_a_renewal_not_due_on_the_replaced_sa_makes_no_switch() {
        let t0 = t0();
        let at = t0 + secs(1);
        let not_on_it = Input::Use { used: None, signal: Some(SIGNAL), basis: BASIS, peer_rekey_held: false };
        let held = Input::Use { used: Some(USED), signal: Some(SIGNAL), basis: BASIS, peer_rekey_held: true };
        for (now, answer, notes) in [
            (at, not_on_it, vec![]),
            (at, not_due(), vec![]),
            (at, held, vec![Note::LeftToPeersHeldRekey]),
            (t0 + ms(20), due(), vec![Note::HeldBackBySpacing { ms: 30, last_failed: false }]),
        ] {
            let mut m = with_a_switch_pending(t0);
            let before = m.clone();
            let run = drive(&mut m, &POLICY, renew(now, NEXT), &[answer]);
            assert_eq!((run.asking(), run.outcome, run.notes()), (vec!["ReadUse"], Outcome::NotDue, notes), "{answer:?}");
            assert_eq!(m, before, "{answer:?}: the switch still pending, nothing recorded");
        }
    }

    #[test]
    fn a_pending_switch_refused_for_a_renewal_closes_the_ike_sa_and_starts_nothing() {
        let t0 = t0();
        let mut m = with_a_switch_pending(t0);
        let run = drive(&mut m, &POLICY, renew(t0 + secs(1), NEXT), &[due(), Input::Switched(Err(()))]);
        assert_eq!(run.asking(), ["ReadUse", "Switch"]);
        assert_eq!(run.actions[2..], [Action::Note(Note::SwitchRefused { local_spi: NEW.0 }), Action::CloseIkeSa]);
        assert_eq!(run.outcome, Outcome::TornDown);
        assert_eq!(m.pending_switch(), None);
        assert_eq!(m.record().last_attempt(), Some(LastAttempt { started: t0, failed: false }), "no attempt counted");
    }

    /// A renewal of `current` to `new` at `now`, its Delete answered `stand`; the generation it is on
    /// after.
    fn renewed_with(m: &mut FamilyMachine<u64>, policy: &Policy, now: Instant, current: ChildId, new: (u32, u32), stand: DeleteStand) -> ChildId {
        let answers = [
            due(),
            negotiated(now, new),
            Input::Prepared(Ok(u64::from(new.0))),
            Input::Committed(Committed::OursDeleteNotAsked),
            Input::Switched(Ok(())),
            Input::Deleted(came(Ours, stand)),
        ];
        let run = drive(m, policy, renew(now, current), &answers);
        assert_eq!(run.outcome, Outcome::Renewed { new, deferred: false, ike_sa_over: false });
        current.successor(new.0, new.1)
    }

    #[test]
    fn at_the_bound_of_owed_deletes_no_renewal_is_negotiated_suspension_is_noted_once_and_nothing_settles_by_age() {
        let t0 = t0();
        let mut m = FamilyMachine::<u64>::new();
        let mut current = CURRENT;
        for n in 0..3u32 {
            assert!(!m.suspended());
            current = renewed_with(&mut m, &POLICY, t0 + secs(n.into()), current, (0x100 + n, 0x200 + n), Failed);
        }
        let owed = m.record().owed().to_vec();
        assert_eq!(owed.len(), 3);
        // Due, at the bound: suspended, noted once, never negotiated, whatever the time.
        for (n, later) in [secs(3), secs(4), secs(3600), secs(86_400 * 30)].into_iter().enumerate() {
            let run = drive(&mut m, &POLICY, renew(t0 + later, current), &[due()]);
            assert_eq!(run.asking(), ["ReadUse"], "the gate is asked before the negotiation");
            assert_eq!(run.notes(), if n == 0 { vec![Note::Suspended { owed: 3 }] } else { vec![] }, "{later:?}");
            assert_eq!(run.outcome, Outcome::NotDue);
            assert!(m.suspended());
            assert_eq!(m.record().owed(), owed, "no debt settled by age: {later:?}");
        }
        // Nothing else settles one either: the deferred switch's events, for the owed SAs' own SPIs.
        for o in &owed {
            let run = drive(&mut m, &POLICY, Input::PeerDeletedReplaced { now: t0 + secs(86_400), local_spi: o.spis.0 }, &[]);
            assert_eq!(run.outcome, Outcome::Nothing);
            let run = drive(&mut m, &POLICY, Input::SwitchCheck { now: t0 + secs(86_400), peer_sent: true }, &[]);
            assert_eq!(run.outcome, Outcome::Nothing);
        }
        assert_eq!(m.record().owed(), owed);
        // Not due at all: the gate is not asked, nothing noted.
        let run = drive(&mut m, &POLICY, renew(t0 + secs(10), current), &[not_due()]);
        assert_eq!((run.notes(), m.suspended()), (vec![], true));
        // With room again (here, the consumer's bound raised): resumed, noted once, and renewed.
        let raised = owing(4);
        let run = drive(&mut m, &raised, renew(t0 + secs(11), current), &[due(), Input::Negotiated(Err(Failure::IkeSaOver))]);
        assert_eq!(run.notes(), [Note::Resumed { owed: 3 }]);
        assert_eq!(run.asking(), ["ReadUse", "Negotiate"]);
        assert!(!m.suspended());
        let run = drive(&mut m, &raised, renew(t0 + secs(12), current), &[due(), Input::Negotiated(Err(Failure::IkeSaOver))]);
        assert_eq!(run.notes(), [], "resumed once");
        current = renewed_with(&mut m, &raised, t0 + secs(13), current, (0x400, 0x401), Unknown);
        assert_eq!(m.record().owed().len(), 4);
        let run = drive(&mut m, &raised, renew(t0 + secs(14), current), &[due()]);
        assert_eq!(run.notes(), [Note::Suspended { owed: 4 }]);
    }

    #[test]
    fn suspended_with_a_switch_pending_no_switch_is_made() {
        let t0 = t0();
        // One Delete owed, then a switch deferred; at a bound of one, the renewal by volume that
        // comes due on the replaced SA makes no switch.
        let mut m = FamilyMachine::<u64>::new();
        let current = renewed_with(&mut m, &owing(2), t0, ChildId { generation: 6, local_spi: 0x01, peer_spi: 0x02 }, CURRENT.spis(), Failed);
        assert_eq!(current, CURRENT);
        renewal(&mut m, &owing(2), t0 + secs(1), Committed::PeersKept(PEERS), &[]);
        let pending = m.pending_switch();
        assert!(pending.is_some());
        for n in 0..3 {
            let run = drive(&mut m, &owing(1), renew(t0 + secs(2 + n), NEXT), &[due()]);
            assert_eq!(run.asking(), ["ReadUse"], "no Switch");
            assert_eq!(run.notes(), if n == 0 { vec![Note::Suspended { owed: 1 }] } else { vec![] });
            assert_eq!(run.outcome, Outcome::NotDue);
            assert_eq!(m.pending_switch(), pending, "still pending");
        }
        // The switch is still made by its own proof.
        let run = drive(&mut m, &owing(1), Input::SwitchCheck { now: t0 + secs(5), peer_sent: true }, &[Input::Switched(Ok(()))]);
        assert_eq!(run.outcome, Outcome::Switched);
    }

    #[test]
    fn a_deferred_switch_waits_for_a_proof_or_the_wait_and_is_made_unproven_at_the_very_instant() {
        let t0 = t0();
        let answered = t0 + TOOK;
        let due_at = answered + WAIT;
        let mut m = with_a_switch_pending(t0);
        let pending = m.pending_switch().unwrap();
        assert_eq!(m.switch_due_at(&POLICY), Some(due_at));
        for now in [answered, due_at - Duration::from_nanos(1)] {
            let run = drive(&mut m, &POLICY, Input::SwitchCheck { now, peer_sent: false }, &[]);
            assert_eq!((run.outcome, run.actions), (Outcome::Nothing, vec![]), "{:?} after the answer", now - answered);
        }
        let run = drive(&mut m, &POLICY, Input::SwitchCheck { now: due_at, peer_sent: false }, &[Input::Switched(Ok(()))]);
        assert_eq!(
            run.actions,
            [
                Action::Switch { switch: pending, proof: SwitchProof::Unproven, now: due_at },
                Action::Note(Note::SwitchMade { local_spi: NEW.0, ms: 5000, proof: SwitchProof::Unproven, replaced_local_spi: 0x11 }),
            ]
        );
        assert_eq!(run.outcome, Outcome::Switched);
        assert_eq!((m.pending_switch(), m.switch_due_at(&POLICY)), (None, None));
        let run = drive(&mut m, &POLICY, Input::SwitchCheck { now: due_at, peer_sent: true }, &[]);
        assert_eq!(run.outcome, Outcome::Nothing, "made once");

        // The peer seen on the new SA: at once.
        let mut m = with_a_switch_pending(t0);
        let run = drive(&mut m, &POLICY, Input::SwitchCheck { now: answered, peer_sent: true }, &[Input::Switched(Ok(()))]);
        assert_eq!(run.actions[0], Action::Switch { switch: pending, proof: SwitchProof::PeerSent, now: answered });
        assert_eq!(run.actions[1], Action::Note(Note::SwitchMade { local_spi: NEW.0, ms: 0, proof: SwitchProof::PeerSent, replaced_local_spi: 0x11 }));
    }

    #[test]
    fn only_the_peers_delete_of_the_replaced_sa_proves_a_deferred_switch() {
        let t0 = t0();
        let at = t0 + secs(1);
        let mut m = with_a_switch_pending(t0);
        let pending = m.pending_switch().unwrap();
        for local_spi in [NEW.0, NEW.1, CURRENT.peer_spi, 0x99] {
            let run = drive(&mut m, &POLICY, Input::PeerDeletedReplaced { now: at, local_spi }, &[]);
            assert_eq!((run.outcome, run.actions), (Outcome::Nothing, vec![]), "{local_spi:#x}");
            assert_eq!(m.pending_switch(), Some(pending));
        }
        let run = drive(&mut m, &POLICY, Input::PeerDeletedReplaced { now: at, local_spi: CURRENT.local_spi }, &[Input::Switched(Ok(()))]);
        assert_eq!(run.actions[0], Action::Switch { switch: pending, proof: SwitchProof::ReplacedDeleted, now: at });
        assert_eq!(run.outcome, Outcome::Switched);
        let run = drive(&mut m, &POLICY, Input::PeerDeletedReplaced { now: at, local_spi: CURRENT.local_spi }, &[]);
        assert_eq!(run.outcome, Outcome::Nothing, "none waits any more");
    }

    #[test]
    fn a_deferred_switch_refused_closes_the_ike_sa() {
        let t0 = t0();
        for event in [Input::SwitchCheck { now: t0 + secs(6), peer_sent: false }, Input::PeerDeletedReplaced { now: t0 + secs(1), local_spi: CURRENT.local_spi }] {
            let mut m = with_a_switch_pending(t0);
            let run = drive(&mut m, &POLICY, event, &[Input::Switched(Err(()))]);
            assert_eq!(run.kinds(), ["Switch", "Note", "CloseIkeSa"], "{event:?}");
            assert_eq!(run.actions[1], Action::Note(Note::SwitchRefused { local_spi: NEW.0 }));
            assert_eq!(run.outcome, Outcome::TornDown);
            assert_eq!(m.pending_switch(), None);
        }
    }

    #[test]
    fn with_no_switch_pending_the_switch_events_do_nothing() {
        let t0 = t0();
        let mut m = FamilyMachine::<u64>::new();
        assert_eq!(m.switch_due_at(&POLICY), None);
        for event in [Input::SwitchCheck { now: t0, peer_sent: true }, Input::SwitchCheck { now: t0 + secs(3600), peer_sent: false }, Input::PeerDeletedReplaced { now: t0, local_spi: 0x11 }] {
            let run = drive(&mut m, &POLICY, event, &[]);
            assert_eq!((run.outcome, run.actions), (Outcome::Nothing, vec![]));
            untouched(&m);
        }
    }

    /// One input of every kind.
    fn every_input(now: Instant) -> Vec<Input<u64>> {
        vec![
            renew(now, CURRENT),
            Input::SwitchCheck { now, peer_sent: true },
            Input::PeerDeletedReplaced { now, local_spi: 0x11 },
            due(),
            Input::Switched(Ok(())),
            negotiated(now, NEW),
            Input::Prepared(Ok(ID)),
            Input::Abandoned(ACKED),
            Input::Committed(Committed::OursDeleteNotAsked),
            Input::Deleted(ACKED),
        ]
    }

    /// Every input but those of `fits` is refused where `m` stands, naming `phase`, and changes
    /// nothing.
    fn refuses_all_but(m: &mut FamilyMachine<u64>, now: Instant, phase: &'static str, fits: &[&str]) {
        for input in every_input(now) {
            if fits.contains(&input.kind()) {
                continue;
            }
            let before = m.clone();
            assert_eq!(m.step(input, &POLICY), Err(Unexpected { phase, input: input.kind() }), "{input:?} in {phase}");
            assert_eq!(*m, before, "{input:?} in {phase}: nothing changes");
        }
    }

    const EVENTS: [&str; 3] = ["RenewByVolume", "SwitchCheck", "PeerDeletedReplaced"];

    #[test]
    fn an_input_that_does_not_fit_is_refused_and_changes_nothing() {
        let t0 = t0();
        let mut m = FamilyMachine::<u64>::new();
        refuses_all_but(&mut m, t0, "idle", &EVENTS);
        // Every phase of a renewal of ours, and the Delete owed on the way.
        let step = |m: &mut FamilyMachine<u64>, input: Input<u64>| assert_eq!(m.step(input, &POLICY).map(|s| s.outcome.is_none()), Ok(true), "{input:?}");
        step(&mut m, renew(t0, CURRENT));
        refuses_all_but(&mut m, t0, "use", &["Use"]);
        step(&mut m, due());
        refuses_all_but(&mut m, t0, "negotiating", &["Negotiated"]);
        step(&mut m, negotiated(t0, NEW));
        refuses_all_but(&mut m, t0, "preparing", &["Prepared"]);
        step(&mut m, Input::Prepared(Ok(ID)));
        refuses_all_but(&mut m, t0, "committing", &["Committed"]);
        step(&mut m, Input::Committed(Committed::OursDeleteNotAsked));
        refuses_all_but(&mut m, t0, "switching_at_once", &["Switched"]);
        step(&mut m, Input::Switched(Ok(())));
        refuses_all_but(&mut m, t0, "deleting", &["Deleted"]);
        assert_eq!(m.step(Input::Deleted(ACKED), &POLICY).map(|s| s.outcome.is_some()), Ok(true));
        refuses_all_but(&mut m, t0, "idle", &EVENTS);
        // The abandon.
        let mut m = FamilyMachine::<u64>::new();
        for input in [renew(t0, CURRENT), due(), negotiated(t0, NEW), Input::Prepared(Err(NotPrepared { session_on: Some(NEW) }))] {
            step(&mut m, input);
        }
        refuses_all_but(&mut m, t0, "abandoning", &["Abandoned"]);
        // A switch pending: the replaced SA's use, and the switch.
        let mut m = with_a_switch_pending(t0);
        step(&mut m, renew(t0 + secs(1), NEXT));
        refuses_all_but(&mut m, t0, "pending_use", &["Use"]);
        step(&mut m, due());
        refuses_all_but(&mut m, t0, "switching", &["Switched"]);
        let mut m = with_a_switch_pending(t0);
        step(&mut m, Input::SwitchCheck { now: t0, peer_sent: true });
        refuses_all_but(&mut m, t0, "switching", &["Switched"]);
    }

    #[test]
    fn a_thousand_renewals_whose_deletes_are_answered_owe_nothing_and_keep_the_settled_ones_bounded() {
        let t0 = t0();
        let mut m = FamilyMachine::<u64>::new();
        let mut current = ChildId::first(1, 2);
        for n in 0..1000u32 {
            let now = t0 + secs(n.into());
            let new = (0x1000 + 2 * n, 0x1001 + 2 * n);
            let mut answers = vec![];
            if m.pending_switch().is_some() {
                answers.extend([due(), Input::Switched(Ok(()))]);
            }
            answers.extend([due(), negotiated(now, new), Input::Prepared(Ok(n.into()))]);
            match n % 3 {
                0 => answers.push(Input::Committed(Committed::PeersKept(PEERS))),
                1 => answers.extend([Input::Committed(Committed::OursDeleteNotAsked), Input::Switched(Ok(())), Input::Deleted(ACKED)]),
                _ => answers.extend([Input::Committed(Committed::Other(ACKED)), Input::Switched(Ok(()))]),
            }
            let run = drive(&mut m, &POLICY, renew(now, current), &answers);
            assert_eq!(run.outcome, Outcome::Renewed { new, deferred: n % 3 == 0, ike_sa_over: false }, "{n}");
            current = current.successor(new.0, new.1);
            assert!(run.actions.contains(&Action::BecameCurrent(current)), "{n}");
            assert_eq!(m.record().owed(), [], "{n}");
            assert_eq!(m.record().settled().len(), (n as usize + 1).min(POLICY.retired.settled_kept), "{n}");
            assert!(!m.suspended() && !m.record().in_flight(), "{n}");
        }
        assert_eq!(current.generation, 1000);
    }
}
