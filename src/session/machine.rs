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
//! An [`Input`] is either an *event* ([`Input::is_event`]), which starts an operation, or the
//! *answer* to the action the last step asked for. The consumer gives an event with
//! [`FamilyMachine::step`], taken only while the machine is [`idle`](FamilyMachine::idle) --
//! [`Input::DataPlaneReset`] aside, taken anywhere --, and an answer with [`FamilyMachine::answer`],
//! with the [`Ask`] of the step that asked for it. Each [`Step`] carries the actions the consumer is
//! to carry out, in order, each completely before the next: at most one of them asks for an answer
//! ([`Action::asks`]), and it is the last; then the operation goes on, [`Step::outcome`] is `None`
//! and [`Step::ask`] names the action asked. Otherwise the operation is over, the outcome says how,
//! and the machine is idle again. An input that does not fit where the machine stands is refused
//! ([`Unexpected`], with its [`Refusal`]): handed back whole, nothing changes, and nothing panics.
//!
//! # The contract with the consumer's adapter
//!
//! What the machine asks is right only if the adapter that carries it out keeps to this:
//!
//! 1. One operation at a time per machine, from its event to its outcome, the adapter holding
//!    exclusive access to the machine and to the consumer state the operation reads for all of it
//!    (the controller's `LIVENESS` lock).
//! 2. Each asking action is carried out exactly once, and its answer is what carrying it out
//!    returned, given with the step's [`Ask`] before any other input (only
//!    [`Input::DataPlaneReset`] may come in between). Under that, a late or duplicated answer cannot
//!    exist; the `Ask` is what makes the machine refuse one if the adapter breaks the rule
//!    ([`Refusal::NotTheAsk`]), instead of taking it for the pending action's.
//! 3. Events only while idle; one refused ([`Refusal::Busy`]) comes back whole in
//!    [`Unexpected::input`] and is the adapter's to give again.
//! 4. Every data-plane action of an operation is for the data plane the operation began on. A reset
//!    given while an operation is under way is deferred to the operation's end
//!    ([`FamilyMachine::reset_pending`]): the operation's actions that touch the data plane, before
//!    and after the reset is given, are for the data plane the operation began on -- its names `T`
//!    mean nothing in another. The adapter keeps that data plane for the operation (as the
//!    controller's flows keep the handle they cloned) and never carries such an action out on a data
//!    plane that took its place; where it no longer has it, it answers what an action asks with the
//!    refusal or with "no data plane" ([`NotSwitched::NoDataPlane`], [`NoDataPlane`]) and drops the
//!    actions that ask nothing ([`Action::Withdraw`], [`Action::CloseRedundant`],
//!    [`Action::KeepRedundant`]). Wire obligations are untouched by a reset: an abandon, a commit, a
//!    Delete owed, a refusal or release of a held rekey go on as ever.
//! 5. A composite action is one obligation ([Composite actions](#composite-actions)).
//!
//! The machine enforces 2, by the `Ask`; 3, by refusing the event; and the reset's place, by
//! deferring it. 1, 4 and 5 only the adapter can keep: the machine does not see how its actions are
//! carried out.
//!
//! # Composite actions
//!
//! Some actions are more than one change of the data plane: [`Action::Switch`] and
//! [`Action::SwitchAtOnce`] (the switch, and on a refusal the new SA withdrawn),
//! [`Action::InstallAndSwitch`] (the install as the next generation, the switch, and on a refusal
//! the new SA withdrawn), [`Action::PrepareDeferred`] (the install as the next generation, and the
//! read of the current generation's SPIs), [`Action::MoveToRedundant`] (the pending switch, then the
//! promotion). Grouping them in one action states an obligation of the adapter: to carry all of it
//! out as one change of the data plane, with nothing else changing or using the family's SAs in
//! between -- no packet sealed between the parts. The machine cannot see how it is carried out and
//! guarantees none of it; how the adapter gets it (a lock, a single thread, a transaction) is its
//! own. The controller holds its data plane's lock across the parts. Split, each would show:
//!
//! - `Switch`, `SwitchAtOnce`, `InstallAndSwitch` refused: between the refusal and the withdrawal, a
//!   next generation left installed that nothing will switch to or withdraw, inbound accepted on it.
//! - `InstallAndSwitch`: between the install and the switch, the family's next generation there for
//!   anything else to switch to or replace.
//! - `PrepareDeferred`: the SPIs answered (`replaced`) not those of the generation the deferred
//!   switch will leave, if the current generation moved between the install and the read.
//! - `MoveToRedundant`: between the pending switch and the promotion, outbound on the SA the peer
//!   just deleted.
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
//! # The flows
//!
//! - A renewal of ours by volume ([`Input::RenewByVolume`]; the controller's `renew_family`):
//!   decided on what the SA in use moved, under the spacing of attempts and the bound of owed
//!   Deletes, negotiated with no Delete, installed as the next generation, committed, switched to
//!   at once -- or, the peer's SA of a crossed rekey kept, its switch deferred --, and only then the
//!   replaced SA's Delete asked, owed before it is.
//! - The deferred switch ([`Input::SwitchCheck`], [`Input::PeerDeletedReplaced`]; the
//!   controller's `switch_when_proven`, `replaced_closed`): made on the first proof that the peer
//!   has the new SA, or without one once the wait is over.
//! - A rekey of the peer's held unanswered, of the family's current SA ([`Input::PeerRekeyHeld`];
//!   `serve_held`) or of its redundant SA ([`Input::PeerRekeyHeldOfRedundant`];
//!   `serve_held_redundant`): the new SA in the data plane before the answer is released.
//! - A replacement already complete on the wire ([`Input::Replacement`]; `install_one`).
//! - The family moved to the peer's redundant SA ([`Input::MovedToRedundant`];
//!   `move_to_redundant`).
//! - The data plane gone or replaced ([`Input::DataPlaneReset`]; the controller's `attach`,
//!   `detach`): a switch deferred in it is dropped -- at once while idle, at the end of the
//!   operation under way otherwise.
//!
//! Wherever another operation needs the family's next generation, a switch still pending is made
//! first ([`SwitchProof::SlotNeeded`]).
//!
//! # What stays the consumer's
//!
//! Everything that holds keys or touches the wire or the data plane is done by the consumer, as an
//! action says. So are: which family an event is of, and which of the two held-rekey events a held
//! rekey is (`serve_held`'s look at the redundant SAs); whether a replacement handed over is already
//! installed (`install_one`'s first check); whether there is a data plane at all and
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

/// Why a switch asked for was not made ([`Input::Switched`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotSwitched {
    /// The data plane refused it; the new SA withdrawn.
    Refused,
    /// No data plane runs any more that the switch could be made in (the controller's
    /// `switch_pending` with no pump: dropped). Told apart only for the deferred switch
    /// ([`Action::Switch`]). For the switch at once ([`Action::SwitchAtOnce`]) the controller has no
    /// such branch -- it holds its data plane for the whole renewal --, and the machine takes it as
    /// [`Refused`](Self::Refused).
    NoDataPlane,
}

/// What came of a move to the peer's redundant SA in the data plane ([`Input::Moved`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Moved {
    /// The pending switch, if one was asked, was refused.
    pub pending_refused: bool,
    /// The promotion, if one was asked, was made; not read when none was.
    pub promoted: Result<(), ()>,
}

/// No data plane runs any more for the action asked (the controller's `move_to_redundant` with no
/// pump).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoDataPlane;

/// What an answer says came to exist outside the machine ([`Input::brought`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Brought<T> {
    /// A CHILD SA negotiated on the wire, of SPIs `new` `(local, peer)`.
    Child { new: (u32, u32) },
    /// An SA put in the data plane, of this name.
    InPlane(T),
}

/// What the consumer gives the machine: an event, taken only while it is idle (but
/// [`DataPlaneReset`](Self::DataPlaneReset), taken anywhere), or the answer to the action the last
/// step asked for.
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
    /// Event: a rekey of the peer's of the family's current SA is held unanswered (the controller's
    /// `serve_held`); its new SA's SPIs are `new` `(local, peer)`, `current` is the consumer's current
    /// generation of the family.
    PeerRekeyHeld { now: Instant, current: Option<ChildId>, new: (u32, u32) },
    /// Event: a rekey of the peer's of the family's redundant SA of SPIs `replaces`, held unanswered
    /// (the controller's `serve_held_redundant`); its new SA's SPIs are `new`, and `old` is the
    /// redundant SA's name in the data plane, if the data plane holds it.
    PeerRekeyHeldOfRedundant { now: Instant, new: (u32, u32), replaces: (u32, u32), old: Option<T> },
    /// Event: a replacement of the family's current SA, already complete on the wire, of SPIs `new`
    /// (the controller's `install_one`, for one not installed yet): a rekey of the peer's this side
    /// answered (`by_peer`), or one of ours or an SA created anew.
    Replacement { now: Instant, new: (u32, u32), by_peer: bool },
    /// Event: the peer deleted the family's current SA, `replaced`, and the family is on its
    /// redundant SA `to` now (the controller's `move_to_redundant`). `in_plane` is `to`'s name in
    /// the data plane, if the data plane holds it; `consumer_owes_install` whether the consumer's
    /// daemon owes an install the old way (the order rule), which keeps the data plane from moving.
    MovedToRedundant { now: Instant, current: Option<ChildId>, to: (u32, u32), replaced: (u32, u32), in_plane: Option<T>, consumer_owes_install: bool },
    /// Event: the data plane a deferred switch was in is gone, or another took its place: a switch
    /// deferred in it has nothing to switch, and is dropped (the controller's `attach` and `detach`,
    /// which take every record's switch and log nothing). Nothing else of the record changes.
    ///
    /// Taken in every phase. While an operation is under way it is deferred to the operation's end
    /// ([`FamilyMachine::reset_pending`]): the step asks nothing new, the pending action is still to
    /// be answered, and the switch is dropped once the operation is over -- one the operation itself
    /// deferred too, as it was put in the data plane that is gone. The controller never meets this:
    /// `attach`, `detach` and every flow run under the same lock, and a flow completes against the
    /// handle it cloned at its start. The operation's actions that touch the data plane, before and
    /// after the reset is given, are for the data plane the operation began on; the adapter never
    /// carries one out on a data plane that took its place, and where it no longer has that one it
    /// answers with the refusal or "no data plane" and drops the actions that ask nothing. The wire
    /// obligations go on as ever.
    DataPlaneReset,
    /// Answer to [`Action::ReadUse`]: `used` is what the SA asked about has moved, `(rx, tx)`, or
    /// `None` when the data plane's current generation of the family is not that SA, or there is no
    /// data plane. `signal` and `basis` are the consumer's volume policy over those bytes (the
    /// renewal signal, and the byte figure the spacing is sized by); `peer_rekey_held` whether a
    /// rekey of the peer's of the family is held unanswered.
    Use { used: Option<(u64, u64)>, signal: Option<RenewalSignal>, basis: Option<u64>, peer_rekey_held: bool },
    /// Answer to [`Action::Switch`] and [`Action::SwitchAtOnce`]: made, or not ([`NotSwitched`]).
    Switched(Result<(), NotSwitched>),
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
    /// Answer to [`Action::PrepareDeferred`]: the new SA's name in the data plane and the SPIs
    /// `(local, peer)` of the data plane's current generation of the family, or the refusal.
    PreparedDeferred(Result<(T, (u32, u32)), ()>),
    /// Answer to [`Action::RefuseHeld`].
    Refused(Result<(), Failure>),
    /// Answer to [`Action::ReleaseHeld`]: released, with how long the answer was held as the
    /// consumer reads it at the release (the controller's `since.elapsed()`), or the error.
    Released(Result<Duration, Failure>),
    /// Answer to [`Action::AddRedundant`]: the new SA's name in the data plane, or the refusal.
    Added(Result<T, ()>),
    /// Answer to [`Action::InstallAndSwitch`].
    InstalledAndSwitched(Result<(), ()>),
    /// Answer to [`Action::MoveToRedundant`]: what came of the pending switch and the promotion, or
    /// no data plane to make them in.
    Moved(Result<Moved, NoDataPlane>),
}

impl<T> Input<T> {
    /// Whether the input is an event, given with [`FamilyMachine::step`]; otherwise it is an answer,
    /// given with [`FamilyMachine::answer`].
    pub fn is_event(&self) -> bool {
        matches!(
            self,
            Input::RenewByVolume { .. }
                | Input::SwitchCheck { .. }
                | Input::PeerDeletedReplaced { .. }
                | Input::PeerRekeyHeld { .. }
                | Input::PeerRekeyHeldOfRedundant { .. }
                | Input::Replacement { .. }
                | Input::MovedToRedundant { .. }
                | Input::DataPlaneReset
        )
    }

    /// The input's name, as a consumer may print a refused one.
    pub fn kind(&self) -> &'static str {
        match self {
            Input::RenewByVolume { .. } => "RenewByVolume",
            Input::SwitchCheck { .. } => "SwitchCheck",
            Input::PeerDeletedReplaced { .. } => "PeerDeletedReplaced",
            Input::PeerRekeyHeld { .. } => "PeerRekeyHeld",
            Input::PeerRekeyHeldOfRedundant { .. } => "PeerRekeyHeldOfRedundant",
            Input::Replacement { .. } => "Replacement",
            Input::MovedToRedundant { .. } => "MovedToRedundant",
            Input::DataPlaneReset => "DataPlaneReset",
            Input::Use { .. } => "Use",
            Input::Switched(_) => "Switched",
            Input::Negotiated(_) => "Negotiated",
            Input::Prepared(_) => "Prepared",
            Input::Abandoned(_) => "Abandoned",
            Input::Committed(_) => "Committed",
            Input::Deleted(_) => "Deleted",
            Input::PreparedDeferred(_) => "PreparedDeferred",
            Input::Refused(_) => "Refused",
            Input::Released(_) => "Released",
            Input::Added(_) => "Added",
            Input::InstalledAndSwitched(_) => "InstalledAndSwitched",
            Input::Moved(_) => "Moved",
        }
    }
}

impl<T: Copy> Input<T> {
    /// What the answer says came to exist outside the machine: the CHILD SA a rekey negotiated
    /// ([`Input::Negotiated`]), or the SA a data plane took ([`Input::Prepared`],
    /// [`Input::PreparedDeferred`], [`Input::Added`]); `None` for any other input, and for a refusal.
    ///
    /// A consumer whose answer was refused ([`Unexpected`]) reconciles this against its own records:
    /// whether it is a duplicate of something it tracks or an orphan is not the machine's to decide,
    /// as the machine never took it. A refused report of a Delete loses nothing: the Delete was
    /// recorded as owed before it was asked (the controller's `owe_delete`), and stays owed.
    pub fn brought(&self) -> Option<Brought<T>> {
        match self {
            Input::Negotiated(Ok(n)) => Some(Brought::Child { new: n.new }),
            Input::Prepared(Ok(id)) | Input::PreparedDeferred(Ok((id, _))) | Input::Added(Ok(id)) => Some(Brought::InPlane(*id)),
            _ => None,
        }
    }
}

/// What the machine asks the consumer to do, in the order given, each completely before the next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action<T> {
    /// A line the controller logs, for the consumer to render. Asks nothing.
    Note(Note),
    /// Read what the data plane's current generation of the family has moved, if it is the SA of
    /// `spis` `(local, peer)`. Asks [`Input::Use`]; with no data plane, `used: None`.
    ReadUse { spis: (u32, u32) },
    /// Make the deferred `switch` at `now`, for `proof`: outbound moves to `switch.id`, the replaced
    /// SA still accepted inbound for the consumer's term; should the data plane refuse, `switch.id`
    /// is withdrawn from it. One operation under the data plane's lock, as the controller's
    /// `switch_in`: a [composite action](crate::session::machine#composite-actions). Asks
    /// [`Input::Switched`]; with no data plane, [`NotSwitched::NoDataPlane`]: the switch dropped,
    /// nothing closed (the controller's `switch_pending`).
    Switch { switch: DeferredSwitch<T>, proof: SwitchProof, now: Instant },
    /// Negotiate a rekey of the family's current SA, with no Delete of it. Asks
    /// [`Input::Negotiated`].
    Negotiate,
    /// Put in the data plane, at `now`, the peer's SAs of crossed rekeys the session kept meanwhile,
    /// as redundant generations (the controller's `keep_redundant_in_pump`). Asks nothing.
    KeepRedundant { now: Instant },
    /// Install the new SA of `new` `(local, peer)` as the family's next generation at `now`: inbound
    /// accepted on it from here on. On a refusal, read the family's SA in the session before anything
    /// else ([`NotPrepared`]). Asks [`Input::Prepared`]; no data plane is that refusal (the
    /// controller's `NoPump` takes the same way: the abandon, its Delete owed).
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
    /// the switch in the controller's `renew_family`: a
    /// [composite action](crate::session::machine#composite-actions). Not a deferred switch. Asks
    /// [`Input::Switched`]; [`NotSwitched::NoDataPlane`] is taken as [`NotSwitched::Refused`], the
    /// controller having no such branch (it holds its data plane for the whole renewal).
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
    /// Install the new SA of `new` `(local, peer)`, of a rekey this side answers as the responder,
    /// as the family's next generation at `now` -- inbound accepted on it from here on, outbound left
    /// on the current one -- and read the SPIs of the data plane's current generation of the family,
    /// under the same lock (the controller's `prepare_deferred`): a
    /// [composite action](crate::session::machine#composite-actions). Asks
    /// [`Input::PreparedDeferred`]; no data plane is its refusal (the controller's `NoPump` takes
    /// the same way: the rekey refused, or left to the consumer).
    PrepareDeferred { new: (u32, u32), now: Instant },
    /// Refuse the held rekey whose new SA receives on `new_local_spi` (`TEMPORARY_FAILURE`): the data
    /// plane cannot take it. Asks [`Input::Refused`].
    RefuseHeld { new_local_spi: u32 },
    /// Release the held answer to the rekey whose new SA receives on `new_local_spi`, its SA now in
    /// the data plane. Asks [`Input::Released`].
    ReleaseHeld { new_local_spi: u32 },
    /// Take `id`, a generation that will not be used, back out of the data plane at `now`. Asks
    /// nothing.
    Withdraw { id: T, now: Instant },
    /// Add the new SA of `new` `(local, peer)` to the data plane as a redundant generation of the
    /// family at `now`: inbound accepted on it, never sealed with. Asks [`Input::Added`]; no data
    /// plane is its refusal (the controller's `NoPump` takes the same way: the rekey refused).
    AddRedundant { new: (u32, u32), now: Instant },
    /// Close the redundant generation `id` in the data plane at `now`, still accepted inbound for
    /// the consumer's term. Asks nothing.
    CloseRedundant { id: T, now: Instant },
    /// Install the new SA of `new` `(local, peer)` as the family's next generation at `now` and
    /// switch outbound to it at once, the replaced SA still accepted inbound for the consumer's
    /// term; should the switch be refused, the new SA is withdrawn. One operation under the data
    /// plane's lock, as the controller's `install_replacement`: a
    /// [composite action](crate::session::machine#composite-actions). Asks
    /// [`Input::InstalledAndSwitched`]; no data plane is its refusal (the controller's `NoPump`
    /// takes the same way: left to the consumer).
    InstallAndSwitch { new: (u32, u32), now: Instant },
    /// Under one lock of the data plane, at `now` (the controller's `move_to_redundant`), a
    /// [composite action](crate::session::machine#composite-actions): first the `pending` switch, if
    /// any, made as [`Action::Switch`] does for [`SwitchProof::SlotNeeded`] (a refusal is only
    /// reported); then the redundant generation `promote`, if any, made the family's current one --
    /// outbound moves to it, the SA it replaces still accepted inbound for the consumer's term. Asks
    /// [`Input::Moved`]; with no data plane, [`NoDataPlane`]: the pending switch dropped, nothing
    /// withdrawn.
    MoveToRedundant { pending: Option<DeferredSwitch<T>>, promote: Option<T>, now: Instant },
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
            | Action::DeleteChild { .. }
            | Action::PrepareDeferred { .. }
            | Action::RefuseHeld { .. }
            | Action::ReleaseHeld { .. }
            | Action::AddRedundant { .. }
            | Action::InstallAndSwitch { .. }
            | Action::MoveToRedundant { .. } => true,
            Action::Note(_)
            | Action::KeepRedundant { .. }
            | Action::CloseIkeSa
            | Action::AgeClockFailed
            | Action::AgeClockRestart
            | Action::BecameCurrent(_)
            | Action::Withdraw { .. }
            | Action::CloseRedundant { .. } => false,
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
    /// No data plane runs any more for the deferred switch to the SA receiving on `local_spi`: it is
    /// dropped (`switch_pending`).
    SwitchDroppedNoDataPlane { local_spi: u32 },
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
    /// The peer's held rekey (its new SA receiving on `local_spi`) refused, `TEMPORARY_FAILURE`: the
    /// data plane cannot take the new SA; the SA in use stays (`serve_held`; the data plane's error
    /// is the consumer's).
    HeldRefused { local_spi: u32 },
    /// Refusing the peer's held rekey (its new SA receiving on `local_spi`) failed (`serve_held`; both
    /// errors are the consumer's).
    RefusingHeldFailed { local_spi: u32 },
    /// The IKE SA of the peer's held rekey is over: its new SA (receiving on `local_spi`) withdrawn
    /// from the data plane (`serve_held`).
    HeldOver { local_spi: u32 },
    /// The peer's held rekey was not released: its new SA (receiving on `local_spi`) withdrawn from
    /// the data plane; the SA in use stays (`serve_held`; the error is the consumer's).
    HeldNotReleased { local_spi: u32 },
    /// The peer's rekey served in the data plane (its new SA receiving on `local_spi`), its answer
    /// held `held_ms`: outbound stays on the replaced SA (receiving on `replaced_local_spi`) until the
    /// peer is known to have the new one (`serve_held`).
    HeldServed { local_spi: u32, held_ms: u128, replaced_local_spi: u32 },
    /// The peer's held rekey of its redundant SA (receiving on `replaced_local_spi`) refused,
    /// `TEMPORARY_FAILURE` (`serve_held_redundant`; the data plane's error is the consumer's).
    RedundantHeldRefused { replaced_local_spi: u32 },
    /// Refusing the peer's held rekey of its redundant SA failed (`serve_held_redundant`; both errors
    /// are the consumer's).
    RefusingRedundantHeldFailed,
    /// The peer's held rekey of its redundant SA was not released: its new SA (receiving on
    /// `local_spi`) withdrawn from the data plane (`serve_held_redundant`; the error is the
    /// consumer's).
    RedundantHeldNotReleased { local_spi: u32 },
    /// The peer's rekey of its redundant SA (receiving on `replaced_local_spi`) served: its new SA
    /// (receiving on `local_spi`) kept in its place, inbound only (`serve_held_redundant`).
    RedundantRekeyServed { replaced_local_spi: u32, local_spi: u32 },
    /// The peer's rekey answered without being held (its new SA receiving on `local_spi`) installed:
    /// outbound stays on the replaced SA (receiving on `replaced_local_spi`) until the peer is known
    /// to have the new one (`install_one`).
    PeerReplacementInstalled { local_spi: u32, replaced_local_spi: u32 },
    /// The replacement (receiving on `local_spi`) could not be put in the data plane: left to the
    /// consumer to install as before (`install_one`, both ways; the error is the consumer's).
    ReplacementNotInstalled { local_spi: u32 },
    /// The replacement (receiving on `local_spi`) installed: outbound moved to it, the replaced SA
    /// still accepted inbound (`install_one`).
    ReplacementInstalled { local_spi: u32 },
    /// The switch pending to the SA receiving on `local_spi` was refused by the data plane on the
    /// move to the redundant SA -- the peer deleted that SA anyway (`move_to_redundant`; the error is
    /// the consumer's).
    MoveSwitchRefused { local_spi: u32 },
    /// The peer deleted the SA in use (receiving on `replaced_local_spi`) and kept its redundant one
    /// (receiving on `to_local_spi`): outbound moved to it, nothing renegotiated
    /// (`move_to_redundant`).
    MovedToRedundant { replaced_local_spi: u32, to_local_spi: u32 },
    /// As [`MovedToRedundant`](Self::MovedToRedundant), but the data plane does not move to it, for
    /// `why`: left to the consumer to install as before (`move_to_redundant`).
    NotMovedToRedundant { replaced_local_spi: u32, to_local_spi: u32, why: NotPromoted },
}

/// Why the data plane did not move to the peer's redundant SA ([`Note::NotMovedToRedundant`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotPromoted {
    /// The consumer's daemon owes an install ("the daemon owes an install").
    ConsumerOwesInstall,
    /// The data plane does not hold the redundant SA ("the pump does not hold it").
    NotInPlane,
    /// The data plane refused the promotion; its error is the consumer's.
    Refused,
    /// No data plane runs ("no pump runs").
    NoDataPlane,
}

/// How an operation ended. `T` is the consumer's name for an SA in its data plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome<T> {
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
    /// Flow B: no switch is proven or due, or none waits on that Delete. Also the end of
    /// [`Input::DataPlaneReset`]: any switch deferred dropped, nothing else done.
    Nothing,
    /// Flow B: the deferred switch was made.
    Switched,
    /// Flows C and C': the peer's held rekey refused, or the refusal failed; the SA in use stays.
    Refused,
    /// Flows C and C': the held answer not released; its new SA withdrawn, the SA in use stays.
    NotReleased,
    /// Flow C: the peer's held rekey served, its new SA of SPIs `new` the family's current one, its
    /// switch deferred.
    Served { new: (u32, u32) },
    /// Flow C': the peer's held rekey of its redundant SA served: the new SA, `id` in the data plane,
    /// stands in the redundant one's place.
    RedundantReplaced { id: T },
    /// Flow D: installed in the data plane; `deferred`, a rekey of the peer's whose switch waits on a
    /// proof, else switched to.
    Installed { deferred: bool },
    /// Flow D: not installed in the data plane, left to the consumer to install as before;
    /// `ike_sa_over`, the IKE SA closed as a switch pending first was refused.
    LeftToConsumer { ike_sa_over: bool },
    /// Flow E: the family is on the redundant SA of SPIs `new`; `installed`, outbound moved to it in
    /// the data plane, else left to the consumer to install as before.
    MovedTo { new: (u32, u32), installed: bool },
}

/// One step of the machine: the actions to carry out, in order, and, once the operation is over,
/// how it ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step<T> {
    /// What the consumer is to do, in order. At most one asks for an answer, and it is the last.
    pub actions: Vec<Action<T>>,
    /// `None` while the operation goes on (the last action asks); how it ended once it is over.
    pub outcome: Option<Outcome<T>>,
    /// The ask the machine waits on, to be given with the answer ([`FamilyMachine::answer`]): `Some`
    /// exactly when `outcome` is `None`.
    pub ask: Option<Ask>,
}

/// One asking action of one machine: what its answer is given with ([`FamilyMachine::answer`]), so
/// that the machine takes it for that action only. Never the same for two asking actions of a
/// machine; never the same for two machines whose scopes differ ([`FamilyMachine::with_scope`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ask {
    scope: u64,
    serial: u64,
}

/// Why an input was refused ([`Unexpected`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// An event (not [`Input::DataPlaneReset`]) given while an operation is under way.
    Busy,
    /// An answer given with [`FamilyMachine::step`].
    NotAnEvent,
    /// An answer given while nothing is asked: the machine is idle.
    NothingAsked,
    /// An answer given with an [`Ask`] that is not the pending one: an earlier one, one already
    /// answered, another machine's.
    NotTheAsk,
    /// The pending [`Ask`], with an input that is not the answer its action asks for (an event
    /// included).
    NotItsAnswer,
}

/// An input that does not fit where the machine stands: refused, and nothing changed in the machine
/// -- the pending ask, if any, can still be answered. The input comes back whole, so that nothing it
/// carried is lost ([`Input::brought`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unexpected<T> {
    /// Where the machine stands.
    pub phase: &'static str,
    /// Why it was refused.
    pub why: Refusal,
    /// The input refused.
    pub input: Input<T>,
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
    /// Flow C: the held rekey's new SA installed as the next generation.
    Held { now: Instant, current: Option<ChildId>, new: (u32, u32) },
    /// Flow D: the replacement installed.
    Replacement { now: Instant, new: (u32, u32), by_peer: bool },
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
    /// Flow C: the held rekey's new SA asked to be installed as the next generation.
    HeldPreparing { now: Instant, current: Option<ChildId>, new: (u32, u32) },
    /// Flow C: the held rekey's refusal asked for.
    HeldRefusing { new: (u32, u32) },
    /// Flow C: the held answer's release asked for; the new SA is `id`, the data plane's current
    /// generation `replaced`.
    HeldReleasing { now: Instant, current: Option<ChildId>, new: (u32, u32), id: T, replaced: (u32, u32) },
    /// Flow C': the held rekey's new SA asked to be added as a redundant generation.
    RedundantAdding { now: Instant, new: (u32, u32), replaces: (u32, u32), old: Option<T> },
    /// Flow C': the held rekey's refusal asked for.
    RedundantRefusing { replaces: (u32, u32) },
    /// Flow C': the held answer's release asked for; the new SA is `id`.
    RedundantReleasing { now: Instant, new: (u32, u32), replaces: (u32, u32), old: Option<T>, id: T },
    /// Flow D: the peer's replacement asked to be installed as the next generation.
    ReplacementPreparing { now: Instant, new: (u32, u32) },
    /// Flow D: our replacement asked to be installed and switched to.
    ReplacementInstalling { new: (u32, u32) },
    /// Flow E: the move asked for.
    Moving { now: Instant, current: Option<ChildId>, to: (u32, u32), replaced: (u32, u32), in_plane: Option<T>, consumer_owes_install: bool, pending: Option<DeferredSwitch<T>> },
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
            Phase::HeldPreparing { .. } => "held_preparing",
            Phase::HeldRefusing { .. } => "held_refusing",
            Phase::HeldReleasing { .. } => "held_releasing",
            Phase::RedundantAdding { .. } => "redundant_adding",
            Phase::RedundantRefusing { .. } => "redundant_refusing",
            Phase::RedundantReleasing { .. } => "redundant_releasing",
            Phase::ReplacementPreparing { .. } => "replacement_preparing",
            Phase::ReplacementInstalling { .. } => "replacement_installing",
            Phase::Moving { .. } => "moving",
        }
    }
}

/// Where a step leaves the operation: an action asked for and the phase that waits on its answer, or
/// the operation over. Returned once per step and taken apart at once: not worth a box.
#[allow(clippy::large_enum_variant)]
enum Flow<T> {
    Ask(Action<T>, Phase<T>),
    Done(Outcome<T>),
}

/// The renewals of one family of CHILD SAs: its record ([`FamilyRenewal`]), where the operation
/// under way stands, and whether its renewals by volume are suspended. `T` is the consumer's name
/// for an SA in its data plane, as in [`DeferredSwitch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FamilyMachine<T> {
    record: FamilyRenewal<T>,
    phase: Phase<T>,
    suspended: bool,
    /// The consumer's number for this machine, in every [`Ask`] of it.
    scope: u64,
    /// The serial of the last [`Ask`] handed out; the pending one while the phase is not idle.
    serial: u64,
    /// A [`Input::DataPlaneReset`] came while an operation was under way: applied at its end.
    reset_pending: bool,
}

impl<T: Copy> Default for FamilyMachine<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Copy> FamilyMachine<T> {
    /// A family with nothing recorded, idle, its renewals by volume not suspended; its scope 0.
    pub fn new() -> Self {
        Self::with_scope(0)
    }

    /// As [`new`](Self::new), its asks in `scope`: a number the consumer chooses so that this
    /// machine's asks differ from any other machine's (its connection and family).
    pub fn with_scope(scope: u64) -> Self {
        Self { record: FamilyRenewal::new(), phase: Phase::Idle, suspended: false, scope, serial: 0, reset_pending: false }
    }

    /// The machine's scope ([`with_scope`](Self::with_scope)).
    pub fn scope(&self) -> u64 {
        self.scope
    }

    /// The ask the machine waits on, the same as the last step's [`Step::ask`]: `Some` exactly while
    /// an operation is under way.
    pub fn asked(&self) -> Option<Ask> {
        match self.phase {
            Phase::Idle => None,
            _ => Some(Ask { scope: self.scope, serial: self.serial }),
        }
    }

    /// Whether a [`Input::DataPlaneReset`] given during the operation under way waits for its end.
    pub fn reset_pending(&self) -> bool {
        self.reset_pending
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

    /// An event, taken under `policy`: it starts an operation, and the step says what to do for it.
    /// Taken only while the machine is idle, but [`Input::DataPlaneReset`], taken anywhere: under way,
    /// an operation goes on as it was and the reset waits for its end (no action, the same ask).
    ///
    /// Refused ([`Unexpected`]), nothing changed: an answer ([`Refusal::NotAnEvent`]), an event while
    /// an operation is under way ([`Refusal::Busy`]).
    pub fn step(&mut self, input: Input<T>, policy: &Policy) -> Result<Step<T>, Unexpected<T>> {
        if !input.is_event() {
            return Err(self.refused(Refusal::NotAnEvent, input));
        }
        let busy = !self.idle();
        if busy && !matches!(input, Input::DataPlaneReset) {
            return Err(self.refused(Refusal::Busy, input));
        }
        let flow = match input {
            Input::RenewByVolume { now, current, session_on } => self.renew_by_volume(now, current, session_on),
            Input::SwitchCheck { now, peer_sent } => match self.record.switch_proof(peer_sent, policy.unproven_after, now) {
                Some(proof) => self.switch_first(now, proof, AfterSwitch::Done),
                None => Flow::Done(Outcome::Nothing),
            },
            Input::PeerDeletedReplaced { now, local_spi } => {
                if self.record.waits_on_delete_of(local_spi) {
                    self.switch_first(now, SwitchProof::ReplacedDeleted, AfterSwitch::Done)
                } else {
                    Flow::Done(Outcome::Nothing)
                }
            }
            Input::DataPlaneReset if busy => {
                // The controller's flows complete against the data plane they began on, and
                // `attach` and `detach` come after them: the switch is dropped at the end.
                self.reset_pending = true;
                return Ok(Step { actions: Vec::new(), outcome: None, ask: self.asked() });
            }
            Input::DataPlaneReset => {
                // `attach` and `detach`: dropped, not made; nothing logged.
                let _ = self.record.take_switch();
                Flow::Done(Outcome::Nothing)
            }
            Input::PeerRekeyHeld { now, current, new } => self.switch_first(now, SwitchProof::SlotNeeded, AfterSwitch::Held { now, current, new }),
            Input::PeerRekeyHeldOfRedundant { now, new, replaces, old } => Flow::Ask(Action::AddRedundant { new, now }, Phase::RedundantAdding { now, new, replaces, old }),
            Input::Replacement { now, new, by_peer } => self.switch_first(now, SwitchProof::SlotNeeded, AfterSwitch::Replacement { now, new, by_peer }),
            Input::MovedToRedundant { now, current, to, replaced, in_plane, consumer_owes_install } => {
                let pending = self.record.take_switch();
                let promote = if consumer_owes_install { None } else { in_plane };
                Flow::Ask(Action::MoveToRedundant { pending, promote, now }, Phase::Moving { now, current, to, replaced, in_plane, consumer_owes_install, pending })
            }
            Input::Use { .. }
            | Input::Switched(_)
            | Input::Negotiated(_)
            | Input::Prepared(_)
            | Input::Abandoned(_)
            | Input::Committed(_)
            | Input::Deleted(_)
            | Input::PreparedDeferred(_)
            | Input::Refused(_)
            | Input::Released(_)
            | Input::Added(_)
            | Input::InstalledAndSwitched(_)
            | Input::Moved(_) => return Err(self.refused(Refusal::NotAnEvent, input)),
        };
        Ok(self.finish(flow, Vec::new()))
    }

    /// The answer to the action `ask` names, taken under `policy`: the operation goes on, or ends.
    ///
    /// Refused ([`Unexpected`]), nothing changed and the pending ask still to be answered, in this
    /// order: nothing asked, the machine idle ([`Refusal::NothingAsked`]); `ask` not the pending one
    /// ([`Refusal::NotTheAsk`]); `input` not the answer the pending action asks for
    /// ([`Refusal::NotItsAnswer`]).
    pub fn answer(&mut self, ask: Ask, input: Input<T>, policy: &Policy) -> Result<Step<T>, Unexpected<T>> {
        let Some(pending) = self.asked() else { return Err(self.refused(Refusal::NothingAsked, input)) };
        if ask != pending {
            return Err(self.refused(Refusal::NotTheAsk, input));
        }
        let mut actions = Vec::new();
        let out = &mut actions;
        let flow = match (self.phase, input) {
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
            (Phase::HeldPreparing { now, current, new }, Input::PreparedDeferred(prepared)) => match prepared {
                Ok((id, replaced)) => Flow::Ask(Action::ReleaseHeld { new_local_spi: new.0 }, Phase::HeldReleasing { now, current, new, id, replaced }),
                Err(()) => Flow::Ask(Action::RefuseHeld { new_local_spi: new.0 }, Phase::HeldRefusing { new }),
            },
            (Phase::HeldRefusing { new }, Input::Refused(refused)) => Self::held_refused(refused, Note::HeldRefused { local_spi: new.0 }, Note::RefusingHeldFailed { local_spi: new.0 }, out),
            (Phase::HeldReleasing { now, current, new, id, replaced }, Input::Released(released)) => self.held_released(now, current, new, id, replaced, released, out),
            (Phase::RedundantAdding { now, new, replaces, old }, Input::Added(added)) => match added {
                Ok(id) => Flow::Ask(Action::ReleaseHeld { new_local_spi: new.0 }, Phase::RedundantReleasing { now, new, replaces, old, id }),
                Err(()) => Flow::Ask(Action::RefuseHeld { new_local_spi: new.0 }, Phase::RedundantRefusing { replaces }),
            },
            (Phase::RedundantRefusing { replaces }, Input::Refused(refused)) => {
                Self::held_refused(refused, Note::RedundantHeldRefused { replaced_local_spi: replaces.0 }, Note::RefusingRedundantHeldFailed, out)
            }
            (Phase::RedundantReleasing { now, new, replaces, old, id }, Input::Released(released)) => Self::redundant_released(now, new, replaces, old, id, released, out),
            (Phase::ReplacementPreparing { now, new }, Input::PreparedDeferred(prepared)) => match prepared {
                Ok((id, replaced)) => {
                    self.defer_switch(DeferredSwitch { id, local_spi: new.0, replaced, answered: now }, out);
                    out.push(Action::Note(Note::PeerReplacementInstalled { local_spi: new.0, replaced_local_spi: replaced.0 }));
                    Flow::Done(Outcome::Installed { deferred: true })
                }
                Err(()) => {
                    out.push(Action::Note(Note::ReplacementNotInstalled { local_spi: new.0 }));
                    Flow::Done(Outcome::LeftToConsumer { ike_sa_over: false })
                }
            },
            (Phase::ReplacementInstalling { new }, Input::InstalledAndSwitched(installed)) => {
                out.push(Action::Note(match installed {
                    Ok(()) => Note::ReplacementInstalled { local_spi: new.0 },
                    Err(()) => Note::ReplacementNotInstalled { local_spi: new.0 },
                }));
                Flow::Done(match installed {
                    Ok(()) => Outcome::Installed { deferred: false },
                    Err(()) => Outcome::LeftToConsumer { ike_sa_over: false },
                })
            }
            (Phase::Moving { now, current, to, replaced, in_plane, consumer_owes_install, pending }, Input::Moved(moved)) => {
                Self::moved(now, current, to, replaced, in_plane, consumer_owes_install, pending, moved, out)
            }
            (_, input) => return Err(self.refused(Refusal::NotItsAnswer, input)),
        };
        Ok(self.finish(flow, actions))
    }

    /// `input` refused for `why` where the machine stands; nothing changed.
    fn refused(&self, why: Refusal, input: Input<T>) -> Unexpected<T> {
        Unexpected { phase: self.phase.name(), why, input }
    }

    /// The step `flow` leaves, after `actions`: the action asked for, under a new ask, and the phase
    /// that waits on its answer; or the operation over, the machine idle, and a reset given during
    /// it applied now -- the switch deferred dropped, one the operation deferred included.
    fn finish(&mut self, flow: Flow<T>, mut actions: Vec<Action<T>>) -> Step<T> {
        match flow {
            Flow::Ask(action, phase) => {
                actions.push(action);
                self.phase = phase;
                self.serial = self.serial.wrapping_add(1);
                Step { actions, outcome: None, ask: self.asked() }
            }
            Flow::Done(outcome) => {
                self.phase = Phase::Idle;
                if std::mem::take(&mut self.reset_pending) {
                    // As `attach` and `detach`, after the flow: dropped, nothing logged.
                    let _ = self.record.take_switch();
                }
                Step { actions, outcome: Some(outcome), ask: None }
            }
        }
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

    /// The switch at once's answer. Not made -- refused, or no data plane, which the controller does
    /// not tell apart here (it holds its data plane for the whole renewal) --: the attempt failed and
    /// the IKE SA is closed, the two ends disagreeing. Made: the replaced SA's Delete is owed before
    /// it is asked; asked now if the commit did not, else what the commit reported is what it came
    /// to.
    fn switched_at_once(&mut self, r: Renewing, n: NewChild, report: Option<DeleteCame>, made: Result<(), NotSwitched>, policy: &Policy, out: &mut Vec<Action<T>>) -> Flow<T> {
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
    fn renewed(&mut self, r: Renewing, n: NewChild, deferred: bool, delete: Option<DeleteCame>, out: &mut Vec<Action<T>>) -> Outcome<T> {
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

    /// The deferred switch's answer. Made: noted, then what follows. No data plane: dropped, noted,
    /// nothing closed, then what follows -- for its own sake, nothing switched. Refused -- the new SA
    /// withdrawn, the answer gone: the two ends disagree, the IKE SA is closed.
    fn switched(&mut self, now: Instant, switch: DeferredSwitch<T>, proof: SwitchProof, then: AfterSwitch, made: Result<(), NotSwitched>, out: &mut Vec<Action<T>>) -> Flow<T> {
        if made == Err(NotSwitched::NoDataPlane) {
            // `switch_pending` with no pump: dropped, and `true`, the caller going on.
            out.push(Action::Note(Note::SwitchDroppedNoDataPlane { local_spi: switch.local_spi }));
            return match then {
                AfterSwitch::Done => Flow::Done(Outcome::Nothing),
                then @ (AfterSwitch::Renew { .. } | AfterSwitch::Held { .. } | AfterSwitch::Replacement { .. }) => self.after_switch(then),
            };
        }
        if made.is_err() {
            out.push(Action::Note(Note::SwitchRefused { local_spi: switch.local_spi }));
            out.push(Action::CloseIkeSa);
            // `install_one` leaves the replacement as it was, for the consumer, the tunnel torn down.
            return Flow::Done(match then {
                AfterSwitch::Replacement { .. } => Outcome::LeftToConsumer { ike_sa_over: true },
                AfterSwitch::Renew { .. } | AfterSwitch::Done | AfterSwitch::Held { .. } => Outcome::TornDown,
            });
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
            AfterSwitch::Held { now, current, new } => Flow::Ask(Action::PrepareDeferred { new, now }, Phase::HeldPreparing { now, current, new }),
            AfterSwitch::Replacement { now, new, by_peer: true } => Flow::Ask(Action::PrepareDeferred { new, now }, Phase::ReplacementPreparing { now, new }),
            AfterSwitch::Replacement { now, new, by_peer: false } => Flow::Ask(Action::InstallAndSwitch { new, now }, Phase::ReplacementInstalling { new }),
        }
    }

    // Flows C and C': a rekey of the peer's held (`serve_held`, `serve_held_redundant`).

    /// The refusal's answer: refused, noted `refused`; the IKE SA over, torn down with no line;
    /// the refusal failed, noted `failed`. The SA in use stays.
    fn held_refused(refused: Result<(), Failure>, noted: Note, failed: Note, out: &mut Vec<Action<T>>) -> Flow<T> {
        match refused {
            Ok(()) => out.push(Action::Note(noted)),
            Err(Failure::IkeSaOver) => return Flow::Done(Outcome::TornDown),
            Err(Failure::Other) => out.push(Action::Note(failed)),
        }
        Flow::Done(Outcome::Refused)
    }

    /// The release's answer, flow C. Released: the switch deferred until the peer is known to have
    /// the new SA, the family's clock started again and its current generation the new SA. Not: the
    /// new SA withdrawn, the SA in use stays -- torn down if the IKE SA is over.
    #[allow(clippy::too_many_arguments)]
    fn held_released(&mut self, now: Instant, current: Option<ChildId>, new: (u32, u32), id: T, replaced: (u32, u32), released: Result<Duration, Failure>, out: &mut Vec<Action<T>>) -> Flow<T> {
        match released {
            Ok(held) => {
                self.defer_switch(DeferredSwitch { id, local_spi: new.0, replaced, answered: now }, out);
                out.push(Action::AgeClockRestart);
                out.push(Action::BecameCurrent(next(current, new)));
                out.push(Action::Note(Note::HeldServed { local_spi: new.0, held_ms: held.as_millis(), replaced_local_spi: replaced.0 }));
                Flow::Done(Outcome::Served { new })
            }
            Err(Failure::IkeSaOver) => {
                out.push(Action::Withdraw { id, now });
                out.push(Action::Note(Note::HeldOver { local_spi: new.0 }));
                Flow::Done(Outcome::TornDown)
            }
            Err(Failure::Other) => {
                out.push(Action::Withdraw { id, now });
                out.push(Action::Note(Note::HeldNotReleased { local_spi: new.0 }));
                Flow::Done(Outcome::NotReleased)
            }
        }
    }

    /// The release's answer, flow C'. Released: the redundant SA it replaces closed in the data plane
    /// if it held it, the new one in its place. Not: the new SA withdrawn -- torn down if the IKE SA
    /// is over. No switch, no clock, no generation: the family's current SA is not touched.
    fn redundant_released(now: Instant, new: (u32, u32), replaces: (u32, u32), old: Option<T>, id: T, released: Result<Duration, Failure>, out: &mut Vec<Action<T>>) -> Flow<T> {
        match released {
            Ok(_) => {
                if let Some(old) = old {
                    out.push(Action::CloseRedundant { id: old, now });
                }
                out.push(Action::Note(Note::RedundantRekeyServed { replaced_local_spi: replaces.0, local_spi: new.0 }));
                Flow::Done(Outcome::RedundantReplaced { id })
            }
            Err(failure) => {
                out.push(Action::Withdraw { id, now });
                out.push(Action::Note(Note::RedundantHeldNotReleased { local_spi: new.0 }));
                Flow::Done(match failure {
                    Failure::IkeSaOver => Outcome::TornDown,
                    Failure::Other => Outcome::NotReleased,
                })
            }
        }
    }

    // Flow E: the move to the peer's redundant SA (`move_to_redundant`).

    /// The move's answer: the pending switch noted as made or refused (the peer deleted its SA
    /// anyway: nothing closed); the move noted, or, the data plane not moving, the redundant SA
    /// withdrawn if it held it and the move left to the consumer. No data plane: the pending switch
    /// dropped with no line, nothing withdrawn, the move left to the consumer. Either way the
    /// family's clock starts again and its current generation is the redundant SA.
    #[allow(clippy::too_many_arguments)]
    fn moved(
        now: Instant,
        current: Option<ChildId>,
        to: (u32, u32),
        replaced: (u32, u32),
        in_plane: Option<T>,
        consumer_owes_install: bool,
        pending: Option<DeferredSwitch<T>>,
        moved: Result<Moved, NoDataPlane>,
        out: &mut Vec<Action<T>>,
    ) -> Flow<T> {
        let Ok(Moved { pending_refused, promoted }) = moved else {
            // `move_to_redundant` with no pump: the switch taken is dropped, no line; nothing to
            // withdraw from.
            out.push(Action::Note(Note::NotMovedToRedundant { replaced_local_spi: replaced.0, to_local_spi: to.0, why: NotPromoted::NoDataPlane }));
            out.push(Action::AgeClockRestart);
            out.push(Action::BecameCurrent(next(current, to)));
            return Flow::Done(Outcome::MovedTo { new: to, installed: false });
        };
        if let Some(pending) = pending {
            out.push(Action::Note(if pending_refused {
                Note::MoveSwitchRefused { local_spi: pending.local_spi }
            } else {
                let ms = now.saturating_duration_since(pending.answered).as_millis();
                Note::SwitchMade { local_spi: pending.local_spi, ms, proof: SwitchProof::SlotNeeded, replaced_local_spi: pending.replaced.0 }
            }));
        }
        let why = match (in_plane, consumer_owes_install, promoted) {
            (None, _, _) => Some(NotPromoted::NotInPlane),
            (Some(_), true, _) => Some(NotPromoted::ConsumerOwesInstall),
            (Some(_), false, Err(())) => Some(NotPromoted::Refused),
            (Some(_), false, Ok(())) => None,
        };
        match why {
            None => out.push(Action::Note(Note::MovedToRedundant { replaced_local_spi: replaced.0, to_local_spi: to.0 })),
            Some(why) => {
                if let Some(id) = in_plane {
                    out.push(Action::Withdraw { id, now });
                }
                out.push(Action::Note(Note::NotMovedToRedundant { replaced_local_spi: replaced.0, to_local_spi: to.0, why }));
            }
        }
        out.push(Action::AgeClockRestart);
        out.push(Action::BecameCurrent(next(current, to)));
        Flow::Done(Outcome::MovedTo { new: to, installed: why.is_none() })
    }

    /// The controller's `defer_switch`: `switch` deferred; one still pending is dropped, noted.
    fn defer_switch(&mut self, switch: DeferredSwitch<T>, out: &mut Vec<Action<T>>) {
        if let Some(earlier) = self.record.defer_switch(switch) {
            out.push(Action::Note(Note::SwitchDropped { local_spi: earlier.local_spi }));
        }
    }
}

/// The SA of SPIs `new` `(local, peer)` put in `current`'s place: its successor, or the first
/// generation of a family that had none (the controller's `CurrentChild::next`; at `u64::MAX` the
/// generation stays there rather than wrap).
fn next(current: Option<ChildId>, new: (u32, u32)) -> ChildId {
    current.map_or(ChildId::first(new.0, new.1), |current| current.successor(new.0, new.1))
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
        outcome: Outcome<u64>,
        /// The asking action of each step but the last, with the owed Deletes the record held right
        /// after that step.
        asked: Vec<(Action<u64>, Vec<Retired>)>,
        /// The ask of each step but the last, and the phase that waited on it.
        asks: Vec<(Ask, &'static str)>,
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
            Action::PrepareDeferred { .. } => "PrepareDeferred",
            Action::RefuseHeld { .. } => "RefuseHeld",
            Action::ReleaseHeld { .. } => "ReleaseHeld",
            Action::Withdraw { .. } => "Withdraw",
            Action::AddRedundant { .. } => "AddRedundant",
            Action::CloseRedundant { .. } => "CloseRedundant",
            Action::InstallAndSwitch { .. } => "InstallAndSwitch",
            Action::MoveToRedundant { .. } => "MoveToRedundant",
        }
    }

    /// `event`, then `answers` one per step, each with the ask of the step before, into `m` under
    /// `policy`; every step checked against the protocol: at most one asking action, the last, and
    /// then no outcome, an ask, the machine's, and the machine not idle; an outcome only with none,
    /// no ask, and the machine idle with no reset pending. At every asking step the answer is first
    /// given wrong ([`refuses_around`]). The script must end exactly with the operation.
    fn drive(m: &mut FamilyMachine<u64>, policy: &Policy, event: Input<u64>, answers: &[Input<u64>]) -> Run {
        drive_reset(m, policy, event, answers, None)
    }

    /// As [`drive`], with `reset` = `Some((at, times))`: a data plane reset given `times` times right
    /// after the step that asked the `at`-th answer (from 0) -- each taken with no action and the
    /// same ask, nothing else changed ([`resets`]).
    fn drive_reset(m: &mut FamilyMachine<u64>, policy: &Policy, event: Input<u64>, answers: &[Input<u64>], reset: Option<(usize, usize)>) -> Run {
        assert!(event.is_event(), "{event:?} is not an event");
        let mut answers = answers.iter().copied();
        let mut run = Run { actions: Vec::new(), outcome: Outcome::Nothing, asked: Vec::new(), asks: Vec::new() };
        let mut step = m.step(event, policy).unwrap_or_else(|e| panic!("{event:?} refused: {e:?}"));
        loop {
            let asking = step.actions.iter().filter(|a| a.asks()).count();
            run.actions.extend(step.actions.iter().copied());
            match step.outcome {
                None => {
                    assert_eq!(asking, 1, "one asking action: {:?}", step.actions);
                    let last = *step.actions.last().unwrap();
                    assert!(last.asks(), "the asking action last: {:?}", step.actions);
                    assert!(!m.idle());
                    let ask = step.ask.unwrap_or_else(|| panic!("no ask while the operation goes on: {:?}", step.actions));
                    assert_eq!(m.asked(), Some(ask));
                    run.asked.push((last, m.record().owed().to_vec()));
                    run.asks.push((ask, m.phase.name()));
                    if let Some((at, times)) = reset {
                        if at + 1 == run.asks.len() {
                            resets(m, policy, ask, times);
                        }
                    }
                    let answer = answers.next().unwrap_or_else(|| panic!("the script ran out of answers after {:?}", run.kinds()));
                    refuses_around(m, policy, ask, answer);
                    step = m.answer(ask, answer, policy).unwrap_or_else(|e| panic!("{answer:?} refused: {e:?}, after {:?}", run.kinds()));
                }
                Some(outcome) => {
                    assert_eq!(asking, 0, "none asks at the end: {:?}", step.actions);
                    assert_eq!(step.ask, None);
                    assert!(m.idle() && m.asked().is_none() && !m.reset_pending());
                    assert!(answers.next().is_none(), "answers left over after {outcome:?}");
                    run.outcome = outcome;
                    return run;
                }
            }
        }
    }

    /// Where `m` waits on `ask`, whose answer is to be `answer`: that answer given with an earlier
    /// ask, a later one or another machine's, or given as an event, and an event given, are each
    /// refused, handed back whole, and change nothing.
    fn refuses_around(m: &mut FamilyMachine<u64>, policy: &Policy, ask: Ask, answer: Input<u64>) {
        let before = m.clone();
        let phase = m.phase.name();
        let others = [Ask { serial: ask.serial.wrapping_sub(1), ..ask }, Ask { serial: ask.serial.wrapping_add(1), ..ask }, Ask { scope: ask.scope.wrapping_add(1), ..ask }];
        for wrong in others {
            assert_eq!(m.answer(wrong, answer, policy), Err(Unexpected { phase, why: Refusal::NotTheAsk, input: answer }), "{wrong:?} in {phase}");
            assert_eq!(*m, before, "{wrong:?} in {phase}: nothing changes");
        }
        assert_eq!(m.step(answer, policy), Err(Unexpected { phase, why: Refusal::NotAnEvent, input: answer }), "{answer:?} as an event in {phase}");
        assert_eq!(*m, before, "{answer:?} as an event in {phase}: nothing changes");
        let event = Input::SwitchCheck { now: Instant::now(), peer_sent: true };
        assert_eq!(m.step(event, policy), Err(Unexpected { phase, why: Refusal::Busy, input: event }), "an event in {phase}");
        assert_eq!(*m, before, "an event in {phase}: nothing changes");
    }

    /// A data plane reset given `times` times while `m` waits on `ask`: each taken with no action and
    /// the same ask, the reset pending, nothing else changed.
    fn resets(m: &mut FamilyMachine<u64>, policy: &Policy, ask: Ask, times: usize) {
        let before = m.clone();
        for _ in 0..times {
            assert_eq!(m.step(Input::DataPlaneReset, policy), Ok(Step { actions: vec![], outcome: None, ask: Some(ask) }));
            assert!(m.reset_pending());
            assert_eq!(FamilyMachine { reset_pending: false, ..m.clone() }, before, "nothing else changes");
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

    /// `m` with the serial of its asks at 0: what is left to compare of a machine whose operations
    /// asked, and changed nothing else.
    fn but_serial(m: &FamilyMachine<u64>) -> FamilyMachine<u64> {
        FamilyMachine { serial: 0, ..m.clone() }
    }

    /// The machine as it is after nothing happened to it but the operations that left it idle and
    /// recorded nothing (their asks aside).
    fn untouched(m: &FamilyMachine<u64>) {
        assert_eq!(but_serial(m), FamilyMachine::new());
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
            let run = renewal(&mut m, &POLICY, t0, committed, &[Input::Switched(Err(NotSwitched::Refused))]);
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
            assert_eq!(but_serial(&m), but_serial(&before), "{answer:?}: the switch still pending, nothing recorded");
        }
    }

    #[test]
    fn a_pending_switch_refused_for_a_renewal_closes_the_ike_sa_and_starts_nothing() {
        let t0 = t0();
        let mut m = with_a_switch_pending(t0);
        let run = drive(&mut m, &POLICY, renew(t0 + secs(1), NEXT), &[due(), Input::Switched(Err(NotSwitched::Refused))]);
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
            let run = drive(&mut m, &POLICY, event, &[Input::Switched(Err(NotSwitched::Refused))]);
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
            held(now),
            held_of_redundant(now, Some(5)),
            Input::Replacement { now, new: NEW, by_peer: true },
            moved_to(now, Some(5), false),
            Input::PreparedDeferred(Ok((ID, REPLACED))),
            Input::Refused(Ok(())),
            Input::Released(Ok(ms(1))),
            Input::Added(Ok(ID)),
            Input::InstalledAndSwitched(Ok(())),
            Input::Moved(Ok(Moved { pending_refused: false, promoted: Ok(()) })),
            Input::DataPlaneReset,
        ]
    }

    /// A machine and the ask its last step left pending: what a consumer carries from step to step.
    struct Driven {
        m: FamilyMachine<u64>,
        ask: Option<Ask>,
    }

    impl Driven {
        /// `m`, idle.
        fn new(m: FamilyMachine<u64>) -> Self {
            assert!(m.idle());
            Self { m, ask: None }
        }

        /// `input` given as an event, or as the answer to the pending ask; the operation must go on.
        fn go(&mut self, input: Input<u64>) {
            let step = match self.ask {
                Some(ask) if !input.is_event() => self.m.answer(ask, input, &POLICY),
                _ => self.m.step(input, &POLICY),
            };
            assert_eq!(step.as_ref().map(|s| s.outcome.is_none()), Ok(true), "{input:?}");
            self.ask = step.ok().and_then(|s| s.ask);
        }
    }

    /// Every input but those of `fits` is refused where `d` stands, naming `phase`, handed back
    /// whole, and changes nothing: given as an answer to the pending ask, it is not its answer, or
    /// with none pending nothing is asked; given as an event, an answer is not one, and an event
    /// while an operation is under way is refused -- but the data plane reset, taken with no action
    /// and the same ask (on a copy here; its own tests follow it to the end).
    fn refuses_all_but(d: &mut Driven, now: Instant, phase: &'static str, fits: &[&str]) {
        let m = &mut d.m;
        assert_eq!(m.asked(), d.ask, "{phase}");
        for input in every_input(now) {
            if fits.contains(&input.kind()) {
                continue;
            }
            let before = m.clone();
            let (ask, why) = match d.ask {
                Some(ask) => (ask, Refusal::NotItsAnswer),
                None => (Ask { scope: 0, serial: 0 }, Refusal::NothingAsked),
            };
            assert_eq!(m.answer(ask, input, &POLICY), Err(Unexpected { phase, why, input }), "{input:?} as an answer in {phase}");
            assert_eq!(*m, before, "{input:?} as an answer in {phase}: nothing changes");
            if let (Input::DataPlaneReset, Some(_)) = (input, d.ask) {
                let mut taken = m.clone();
                assert_eq!(taken.step(input, &POLICY), Ok(Step { actions: vec![], outcome: None, ask: d.ask }), "{phase}");
                assert!(taken.reset_pending(), "{phase}");
                continue;
            }
            let why = if input.is_event() { Refusal::Busy } else { Refusal::NotAnEvent };
            assert_eq!(m.step(input, &POLICY), Err(Unexpected { phase, why, input }), "{input:?} as an event in {phase}");
            assert_eq!(*m, before, "{input:?} as an event in {phase}: nothing changes");
        }
    }

    const EVENTS: [&str; 8] = ["RenewByVolume", "SwitchCheck", "PeerDeletedReplaced", "PeerRekeyHeld", "PeerRekeyHeldOfRedundant", "Replacement", "MovedToRedundant", "DataPlaneReset"];

    #[test]
    fn an_input_that_does_not_fit_is_refused_and_changes_nothing() {
        let t0 = t0();
        let mut d = Driven::new(FamilyMachine::new());
        refuses_all_but(&mut d, t0, "idle", &EVENTS);
        // Every phase of a renewal of ours, and the Delete owed on the way.
        d.go(renew(t0, CURRENT));
        refuses_all_but(&mut d, t0, "use", &["Use"]);
        d.go(due());
        refuses_all_but(&mut d, t0, "negotiating", &["Negotiated"]);
        d.go(negotiated(t0, NEW));
        refuses_all_but(&mut d, t0, "preparing", &["Prepared"]);
        d.go(Input::Prepared(Ok(ID)));
        refuses_all_but(&mut d, t0, "committing", &["Committed"]);
        d.go(Input::Committed(Committed::OursDeleteNotAsked));
        refuses_all_but(&mut d, t0, "switching_at_once", &["Switched"]);
        d.go(Input::Switched(Ok(())));
        refuses_all_but(&mut d, t0, "deleting", &["Deleted"]);
        let ask = d.ask.unwrap();
        assert_eq!(d.m.answer(ask, Input::Deleted(ACKED), &POLICY).map(|s| s.outcome.is_some()), Ok(true));
        d.ask = None;
        refuses_all_but(&mut d, t0, "idle", &EVENTS);
        // The abandon.
        let mut d = Driven::new(FamilyMachine::new());
        for input in [renew(t0, CURRENT), due(), negotiated(t0, NEW), Input::Prepared(Err(NotPrepared { session_on: Some(NEW) }))] {
            d.go(input);
        }
        refuses_all_but(&mut d, t0, "abandoning", &["Abandoned"]);
        // A switch pending: the replaced SA's use, and the switch.
        let mut d = Driven::new(with_a_switch_pending(t0));
        d.go(renew(t0 + secs(1), NEXT));
        refuses_all_but(&mut d, t0, "pending_use", &["Use"]);
        d.go(due());
        refuses_all_but(&mut d, t0, "switching", &["Switched"]);
        let mut d = Driven::new(with_a_switch_pending(t0));
        d.go(Input::SwitchCheck { now: t0, peer_sent: true });
        refuses_all_but(&mut d, t0, "switching", &["Switched"]);
        // Flows C, C', D and E.
        for (path, phase, fits) in [
            (vec![held(t0)], "held_preparing", "PreparedDeferred"),
            (vec![held(t0), Input::PreparedDeferred(Err(()))], "held_refusing", "Refused"),
            (vec![held(t0), Input::PreparedDeferred(Ok((ID, REPLACED)))], "held_releasing", "Released"),
            (vec![held_of_redundant(t0, None)], "redundant_adding", "Added"),
            (vec![held_of_redundant(t0, None), Input::Added(Err(()))], "redundant_refusing", "Refused"),
            (vec![held_of_redundant(t0, None), Input::Added(Ok(ID))], "redundant_releasing", "Released"),
            (vec![Input::Replacement { now: t0, new: NEW, by_peer: true }], "replacement_preparing", "PreparedDeferred"),
            (vec![Input::Replacement { now: t0, new: NEW, by_peer: false }], "replacement_installing", "InstalledAndSwitched"),
            (vec![moved_to(t0, Some(5), false)], "moving", "Moved"),
        ] {
            let mut d = Driven::new(FamilyMachine::new());
            for input in path {
                d.go(input);
            }
            refuses_all_but(&mut d, t0, phase, &[fits]);
        }
        for event in [held(t0 + secs(1)), Input::Replacement { now: t0 + secs(1), new: (0x31, 0x32), by_peer: false }] {
            let mut d = Driven::new(with_a_switch_pending(t0));
            d.go(event);
            refuses_all_but(&mut d, t0, "switching", &["Switched"]);
        }
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

    // Flows C, C', D and E.

    /// The data plane's current generation when a rekey of `CURRENT` is served: `CURRENT` itself.
    const REPLACED: (u32, u32) = (0x11, 0x12);

    /// A rekey of `CURRENT` to `NEW` by the peer, held.
    fn held(now: Instant) -> Input<u64> {
        Input::PeerRekeyHeld { now, current: Some(CURRENT), new: NEW }
    }

    /// The peer's redundant SA of a crossed rekey, its SPIs, and the peer's rekey of it.
    const REDUNDANT: (u32, u32) = (0x31, 0x32);
    const REDUNDANT_NEW: (u32, u32) = (0x41, 0x42);

    fn held_of_redundant(now: Instant, old: Option<u64>) -> Input<u64> {
        Input::PeerRekeyHeldOfRedundant { now, new: REDUNDANT_NEW, replaces: REDUNDANT, old }
    }

    /// The peer deleted `CURRENT` and the family moved to its redundant SA.
    const TO: (u32, u32) = (0x51, 0x52);

    fn moved_to(now: Instant, in_plane: Option<u64>, consumer_owes_install: bool) -> Input<u64> {
        Input::MovedToRedundant { now, current: Some(CURRENT), to: TO, replaced: REPLACED, in_plane, consumer_owes_install }
    }

    #[test]
    fn a_held_rekey_of_the_peers_is_installed_before_its_answer_goes_and_its_switch_waits_on_a_proof() {
        let t0 = t0();
        let mut m = FamilyMachine::<u64>::new();
        let run = drive(&mut m, &POLICY, held(t0), &[Input::PreparedDeferred(Ok((ID, REPLACED))), Input::Released(Ok(ms(7)))]);
        assert_eq!(
            run.actions,
            [
                Action::PrepareDeferred { new: NEW, now: t0 },
                Action::ReleaseHeld { new_local_spi: NEW.0 },
                Action::AgeClockRestart,
                Action::BecameCurrent(NEXT),
                Action::Note(Note::HeldServed { local_spi: NEW.0, held_ms: 7, replaced_local_spi: 0x11 }),
            ]
        );
        assert_eq!(run.outcome, Outcome::Served { new: NEW });
        assert_eq!(m.pending_switch(), Some(DeferredSwitch { id: ID, local_spi: NEW.0, replaced: REPLACED, answered: t0 }));
        assert_eq!((m.record().last_attempt(), m.record().owed().len(), m.record().settled().len()), (None, 0, 0), "no renewal of ours, nothing retired");
        // No switch before a proof.
        let run = drive(&mut m, &POLICY, Input::SwitchCheck { now: t0 + WAIT - Duration::from_nanos(1), peer_sent: false }, &[]);
        assert_eq!(run.outcome, Outcome::Nothing);
        let run = drive(&mut m, &POLICY, Input::PeerDeletedReplaced { now: t0, local_spi: REPLACED.0 }, &[Input::Switched(Ok(()))]);
        assert_eq!(run.actions[0], Action::Switch { switch: m_switch(ID, REPLACED, t0), proof: SwitchProof::ReplacedDeleted, now: t0 });
        // A family with no current generation: the new SA is its first.
        let mut m = FamilyMachine::<u64>::new();
        let event = Input::PeerRekeyHeld { now: t0, current: None, new: NEW };
        let run = drive(&mut m, &POLICY, event, &[Input::PreparedDeferred(Ok((ID, REPLACED))), Input::Released(Ok(ms(7)))]);
        assert!(run.actions.contains(&Action::BecameCurrent(ChildId::first(NEW.0, NEW.1))));
    }

    /// The switch deferred for `NEW` as `id` in the data plane, outbound left on `replaced`.
    fn m_switch(id: u64, replaced: (u32, u32), answered: Instant) -> DeferredSwitch<u64> {
        DeferredSwitch { id, local_spi: NEW.0, replaced, answered }
    }

    #[test]
    fn a_held_rekey_makes_a_switch_still_pending_first_and_one_refused_closes_the_ike_sa() {
        let t0 = t0();
        let at = t0 + secs(1);
        let newer = (0x61, 0x62);
        let mut m = with_a_switch_pending(t0);
        let pending = m.pending_switch().unwrap();
        let event = Input::PeerRekeyHeld { now: at, current: Some(NEXT), new: newer };
        let run = drive(&mut m, &POLICY, event, &[Input::Switched(Ok(())), Input::PreparedDeferred(Ok((ID + 1, NEW))), Input::Released(Ok(ms(1)))]);
        assert_eq!(run.asking(), ["Switch", "PrepareDeferred", "ReleaseHeld"]);
        assert_eq!(run.asked[0].0, Action::Switch { switch: pending, proof: SwitchProof::SlotNeeded, now: at });
        assert_eq!(run.notes(), [Note::SwitchMade { local_spi: NEW.0, ms: 990, proof: SwitchProof::SlotNeeded, replaced_local_spi: 0x11 }, Note::HeldServed { local_spi: 0x61, held_ms: 1, replaced_local_spi: NEW.0 }], "none dropped");
        assert_eq!(m.pending_switch(), Some(DeferredSwitch { id: ID + 1, local_spi: 0x61, replaced: NEW, answered: at }));
        assert!(run.actions.contains(&Action::BecameCurrent(NEXT.successor(0x61, 0x62))));

        let mut m = with_a_switch_pending(t0);
        let run = drive(&mut m, &POLICY, event, &[Input::Switched(Err(NotSwitched::Refused))]);
        assert_eq!(run.kinds(), ["Switch", "Note", "CloseIkeSa"]);
        assert_eq!(run.actions[1], Action::Note(Note::SwitchRefused { local_spi: NEW.0 }));
        assert_eq!((run.outcome, m.pending_switch()), (Outcome::TornDown, None));
    }

    #[test]
    fn a_held_rekey_the_data_plane_cannot_take_is_refused_and_one_not_released_is_withdrawn() {
        let t0 = t0();
        for (refused, outcome, notes) in [
            (Ok(()), Outcome::Refused, vec![Note::HeldRefused { local_spi: NEW.0 }]),
            (Err(Failure::IkeSaOver), Outcome::TornDown, vec![]),
            (Err(Failure::Other), Outcome::Refused, vec![Note::RefusingHeldFailed { local_spi: NEW.0 }]),
        ] {
            let mut m = FamilyMachine::<u64>::new();
            let run = drive(&mut m, &POLICY, held(t0), &[Input::PreparedDeferred(Err(())), Input::Refused(refused)]);
            assert_eq!(run.asked.iter().map(|(a, _)| *a).collect::<Vec<_>>(), [Action::PrepareDeferred { new: NEW, now: t0 }, Action::RefuseHeld { new_local_spi: NEW.0 }]);
            assert_eq!((run.outcome, run.notes(), run.has("ReleaseHeld")), (outcome, notes, false), "{refused:?}");
            untouched(&m);
        }
        for (failure, outcome, note) in [(Failure::IkeSaOver, Outcome::TornDown, Note::HeldOver { local_spi: NEW.0 }), (Failure::Other, Outcome::NotReleased, Note::HeldNotReleased { local_spi: NEW.0 })] {
            let mut m = FamilyMachine::<u64>::new();
            let run = drive(&mut m, &POLICY, held(t0), &[Input::PreparedDeferred(Ok((ID, REPLACED))), Input::Released(Err(failure))]);
            assert_eq!(run.actions[2..], [Action::Withdraw { id: ID, now: t0 }, Action::Note(note)], "{failure:?}");
            assert_eq!(run.outcome, outcome);
            untouched(&m);
        }
    }

    #[test]
    fn a_held_rekey_of_the_peers_redundant_sa_puts_the_new_one_in_its_place_and_touches_nothing_else() {
        let t0 = t0();
        for old in [Some(5), None] {
            let mut m = with_a_switch_pending(t0);
            let before = m.clone();
            let run = drive(&mut m, &POLICY, held_of_redundant(t0 + secs(1), old), &[Input::Added(Ok(ID)), Input::Released(Ok(ms(2)))]);
            let mut expected = vec![Action::AddRedundant { new: REDUNDANT_NEW, now: t0 + secs(1) }, Action::ReleaseHeld { new_local_spi: REDUNDANT_NEW.0 }];
            if let Some(old) = old {
                expected.push(Action::CloseRedundant { id: old, now: t0 + secs(1) });
            }
            expected.push(Action::Note(Note::RedundantRekeyServed { replaced_local_spi: REDUNDANT.0, local_spi: REDUNDANT_NEW.0 }));
            assert_eq!(run.actions, expected, "{old:?}");
            assert_eq!(run.outcome, Outcome::RedundantReplaced { id: ID });
            assert_eq!(but_serial(&m), but_serial(&before), "{old:?}: no switch, no record: the switch pending stays");
        }
        for (refused, outcome, notes) in [
            (Ok(()), Outcome::Refused, vec![Note::RedundantHeldRefused { replaced_local_spi: REDUNDANT.0 }]),
            (Err(Failure::IkeSaOver), Outcome::TornDown, vec![]),
            (Err(Failure::Other), Outcome::Refused, vec![Note::RefusingRedundantHeldFailed]),
        ] {
            let mut m = FamilyMachine::<u64>::new();
            let run = drive(&mut m, &POLICY, held_of_redundant(t0, Some(5)), &[Input::Added(Err(())), Input::Refused(refused)]);
            assert_eq!(run.asking(), ["AddRedundant", "RefuseHeld"]);
            assert_eq!(run.asked[1].0, Action::RefuseHeld { new_local_spi: REDUNDANT_NEW.0 });
            assert_eq!((run.outcome, run.notes()), (outcome, notes), "{refused:?}");
            untouched(&m);
        }
        for (failure, outcome) in [(Failure::IkeSaOver, Outcome::TornDown), (Failure::Other, Outcome::NotReleased)] {
            let mut m = FamilyMachine::<u64>::new();
            let run = drive(&mut m, &POLICY, held_of_redundant(t0, Some(5)), &[Input::Added(Ok(ID)), Input::Released(Err(failure))]);
            assert_eq!(run.actions[2..], [Action::Withdraw { id: ID, now: t0 }, Action::Note(Note::RedundantHeldNotReleased { local_spi: REDUNDANT_NEW.0 })], "{failure:?}");
            assert_eq!(run.outcome, outcome);
            assert!(!run.has("CloseRedundant"));
            untouched(&m);
        }
    }

    #[test]
    fn a_replacement_complete_on_the_wire_is_installed_its_switch_deferred_if_the_peers_and_at_once_if_ours() {
        let t0 = t0();
        let mut m = FamilyMachine::<u64>::new();
        let run = drive(&mut m, &POLICY, Input::Replacement { now: t0, new: NEW, by_peer: true }, &[Input::PreparedDeferred(Ok((ID, REPLACED)))]);
        assert_eq!(run.actions, [Action::PrepareDeferred { new: NEW, now: t0 }, Action::Note(Note::PeerReplacementInstalled { local_spi: NEW.0, replaced_local_spi: 0x11 })]);
        assert_eq!(run.outcome, Outcome::Installed { deferred: true });
        assert_eq!(m.pending_switch(), Some(m_switch(ID, REPLACED, t0)), "no switch before a proof");
        let mut m = FamilyMachine::<u64>::new();
        let run = drive(&mut m, &POLICY, Input::Replacement { now: t0, new: NEW, by_peer: true }, &[Input::PreparedDeferred(Err(()))]);
        assert_eq!(run.notes(), [Note::ReplacementNotInstalled { local_spi: NEW.0 }]);
        assert_eq!(run.outcome, Outcome::LeftToConsumer { ike_sa_over: false });
        untouched(&m);
        for (installed, outcome, note) in [
            (Ok(()), Outcome::Installed { deferred: false }, Note::ReplacementInstalled { local_spi: NEW.0 }),
            (Err(()), Outcome::LeftToConsumer { ike_sa_over: false }, Note::ReplacementNotInstalled { local_spi: NEW.0 }),
        ] {
            let mut m = FamilyMachine::<u64>::new();
            let run = drive(&mut m, &POLICY, Input::Replacement { now: t0, new: NEW, by_peer: false }, &[Input::InstalledAndSwitched(installed)]);
            assert_eq!(run.actions, [Action::InstallAndSwitch { new: NEW, now: t0 }, Action::Note(note)], "{installed:?}");
            assert_eq!(run.outcome, outcome);
            untouched(&m);
        }
    }

    #[test]
    fn a_replacement_makes_a_switch_still_pending_first_and_one_refused_leaves_it_to_the_consumer_the_ike_sa_closed() {
        let t0 = t0();
        let at = t0 + secs(1);
        let newer = (0x61, 0x62);
        for by_peer in [true, false] {
            let mut m = with_a_switch_pending(t0);
            let pending = m.pending_switch().unwrap();
            let event = Input::Replacement { now: at, new: newer, by_peer };
            let answer = if by_peer { Input::PreparedDeferred(Ok((ID + 1, NEW))) } else { Input::InstalledAndSwitched(Ok(())) };
            let run = drive(&mut m, &POLICY, event, &[Input::Switched(Ok(())), answer]);
            assert_eq!(run.asked[0].0, Action::Switch { switch: pending, proof: SwitchProof::SlotNeeded, now: at });
            assert_eq!(run.asking()[1], if by_peer { "PrepareDeferred" } else { "InstallAndSwitch" });
            assert_eq!(run.outcome, Outcome::Installed { deferred: by_peer });
            assert!(!run.has("AgeClockRestart") && !run.has("BecameCurrent") && !run.has("AgeClockFailed"), "the consumer's hand-over did that");

            let mut m = with_a_switch_pending(t0);
            let run = drive(&mut m, &POLICY, event, &[Input::Switched(Err(NotSwitched::Refused))]);
            assert_eq!(run.kinds(), ["Switch", "Note", "CloseIkeSa"]);
            assert_eq!(run.outcome, Outcome::LeftToConsumer { ike_sa_over: true });
            assert_eq!(m.pending_switch(), None);
        }
    }

    #[test]
    fn a_move_to_the_peers_redundant_sa_makes_the_pending_switch_and_the_promotion_as_one_action() {
        let t0 = t0();
        let to = ChildId { generation: 8, local_spi: TO.0, peer_spi: TO.1 };
        let tail = [Action::AgeClockRestart, Action::BecameCurrent(to)];
        let not_moved = |why| Action::Note(Note::NotMovedToRedundant { replaced_local_spi: 0x11, to_local_spi: TO.0, why });
        for (in_plane, owes, promoted, promote, middle, installed) in [
            (Some(5), false, Ok(()), Some(5), vec![Action::Note(Note::MovedToRedundant { replaced_local_spi: 0x11, to_local_spi: TO.0 })], true),
            (Some(5), false, Err(()), Some(5), vec![Action::Withdraw { id: 5, now: t0 }, not_moved(NotPromoted::Refused)], false),
            (Some(5), true, Err(()), None, vec![Action::Withdraw { id: 5, now: t0 }, not_moved(NotPromoted::ConsumerOwesInstall)], false),
            (None, false, Err(()), None, vec![not_moved(NotPromoted::NotInPlane)], false),
            (None, true, Err(()), None, vec![not_moved(NotPromoted::NotInPlane)], false),
        ] {
            let mut m = FamilyMachine::<u64>::new();
            let run = drive(&mut m, &POLICY, moved_to(t0, in_plane, owes), &[Input::Moved(Ok(Moved { pending_refused: false, promoted }))]);
            let mut expected = vec![Action::MoveToRedundant { pending: None, promote, now: t0 }];
            expected.extend(middle);
            expected.extend(tail);
            assert_eq!(run.actions, expected, "{in_plane:?} {owes}");
            assert_eq!(run.outcome, Outcome::MovedTo { new: TO, installed });
            untouched(&m);
        }
        // A switch pending is made first, in the same action; a refusal only noted.
        for pending_refused in [false, true] {
            let mut m = with_a_switch_pending(t0);
            let pending = m.pending_switch();
            let at = t0 + secs(1);
            let event = Input::MovedToRedundant { now: at, current: Some(NEXT), to: TO, replaced: NEW, in_plane: Some(5), consumer_owes_install: false };
            let run = drive(&mut m, &POLICY, event, &[Input::Moved(Ok(Moved { pending_refused, promoted: Ok(()) }))]);
            assert_eq!(run.actions[0], Action::MoveToRedundant { pending, promote: Some(5), now: at });
            let switch_note = if pending_refused {
                Note::MoveSwitchRefused { local_spi: NEW.0 }
            } else {
                Note::SwitchMade { local_spi: NEW.0, ms: 990, proof: SwitchProof::SlotNeeded, replaced_local_spi: 0x11 }
            };
            assert_eq!(run.notes(), [switch_note, Note::MovedToRedundant { replaced_local_spi: NEW.0, to_local_spi: TO.0 }]);
            assert!(!run.has("CloseIkeSa"), "the peer deleted that SA anyway");
            assert!(run.actions.contains(&Action::BecameCurrent(NEXT.successor(TO.0, TO.1))));
            assert_eq!((run.outcome, m.pending_switch()), (Outcome::MovedTo { new: TO, installed: true }, None));
        }
        // A family with no current generation: the redundant SA is its first.
        let mut m = FamilyMachine::<u64>::new();
        let event = Input::MovedToRedundant { now: t0, current: None, to: TO, replaced: REPLACED, in_plane: Some(5), consumer_owes_install: false };
        let run = drive(&mut m, &POLICY, event, &[Input::Moved(Ok(Moved { pending_refused: false, promoted: Ok(()) }))]);
        assert!(run.actions.contains(&Action::BecameCurrent(ChildId::first(TO.0, TO.1))));
    }

    #[test]
    fn suspended_with_a_switch_pending_from_a_held_rekey_no_switch_is_made_and_the_peers_rekeys_are_still_served() {
        let t0 = t0();
        let mut m = FamilyMachine::<u64>::new();
        let mut current = CURRENT;
        for n in 0..3u32 {
            current = renewed_with(&mut m, &POLICY, t0 + secs(n.into()), current, (0x100 + n, 0x200 + n), Unknown);
        }
        let held_new = (0x300, 0x301);
        let at = t0 + secs(3);
        let run = drive(&mut m, &POLICY, Input::PeerRekeyHeld { now: at, current: Some(current), new: held_new }, &[Input::PreparedDeferred(Ok((ID, current.spis()))), Input::Released(Ok(ms(1)))]);
        assert_eq!(run.outcome, Outcome::Served { new: held_new });
        let pending = m.pending_switch();
        assert!(pending.is_some());
        let served = current.successor(held_new.0, held_new.1);
        for n in 0..3 {
            let run = drive(&mut m, &POLICY, renew(at + secs(1 + n), served), &[due()]);
            assert_eq!(run.asked[0].0, Action::ReadUse { spis: current.spis() }, "the replaced SA's use");
            assert_eq!(run.asking(), ["ReadUse"], "no Switch for a renewal that will not start");
            assert_eq!(run.notes(), if n == 0 { vec![Note::Suspended { owed: 3 }] } else { vec![] });
            assert_eq!((run.outcome, m.pending_switch()), (Outcome::NotDue, pending));
        }
        // The peer's next rekey of the family is served all the same, and makes the switch.
        let run = drive(&mut m, &POLICY, Input::PeerRekeyHeld { now: at + secs(5), current: Some(served), new: (0x400, 0x401) }, &[Input::Switched(Ok(())), Input::PreparedDeferred(Ok((ID + 1, held_new))), Input::Released(Ok(ms(1)))]);
        assert_eq!(run.outcome, Outcome::Served { new: (0x400, 0x401) });
        assert_eq!(m.record().owed().len(), 3, "and owes nothing new");
    }

    #[test]
    fn a_data_plane_reset_drops_the_deferred_switch_and_nothing_else() {
        let t0 = t0();
        // A Delete owed, a settled SA, a failed last attempt, suspended, then a switch deferred.
        let mut m = FamilyMachine::<u64>::new();
        let current = renewed_with(&mut m, &owing(2), t0, ChildId { generation: 6, local_spi: 0x01, peer_spi: 0x02 }, CURRENT.spis(), Failed);
        renewal(&mut m, &owing(2), t0 + secs(1), Committed::PeersKept(PEERS), &[]);
        assert_eq!(current, CURRENT);
        drive(&mut m, &owing(1), renew(t0 + secs(2), NEXT), &[due()]);
        assert!(m.suspended() && m.pending_switch().is_some() && !m.record().owed().is_empty() && m.record().settled().len() > 0);
        let before = m.clone();
        let run = drive(&mut m, &POLICY, Input::DataPlaneReset, &[]);
        assert_eq!((run.outcome, run.actions), (Outcome::Nothing, vec![]), "no action, no note");
        assert_eq!((m.pending_switch(), m.switch_due_at(&POLICY)), (None, None));
        let mut expected = before.clone();
        let _ = expected.record.take_switch();
        assert_eq!(m, expected, "the rest of the record, the suspension and the phase as before");
        assert_eq!((m.record().owed(), m.record().last_attempt(), m.suspended()), (before.record().owed(), before.record().last_attempt(), true));
        let run = drive(&mut m, &POLICY, Input::SwitchCheck { now: t0 + secs(3600), peer_sent: false }, &[]);
        assert_eq!((run.outcome, run.actions), (Outcome::Nothing, vec![]), "nothing left to switch, past the wait");
        // None pending: nothing changes.
        let before = m.clone();
        let run = drive(&mut m, &POLICY, Input::DataPlaneReset, &[]);
        assert_eq!((run.outcome, run.actions, &m), (Outcome::Nothing, vec![], &before));
        // While an operation is under way: taken with no action and the same ask, nothing else
        // changed until the operation's end (followed there by the tests below).
        let mut m = with_a_switch_pending(t0);
        let step = m.step(held(t0 + secs(1)), &POLICY).unwrap();
        let before = m.clone();
        assert_eq!(m.step(Input::DataPlaneReset, &POLICY), Ok(Step { actions: vec![], outcome: None, ask: step.ask }));
        assert_eq!(FamilyMachine { reset_pending: false, ..m.clone() }, before);
        assert!(m.reset_pending());
        let mut m = FamilyMachine::<u64>::new();
        let step = m.step(renew(t0, CURRENT), &POLICY).unwrap();
        let before = m.clone();
        assert_eq!(m.step(Input::DataPlaneReset, &POLICY), Ok(Step { actions: vec![], outcome: None, ask: step.ask }));
        assert_eq!(FamilyMachine { reset_pending: false, ..m.clone() }, before);
        assert!(m.reset_pending());
    }

    // Answers correlated with the action that asked for them.

    #[test]
    fn an_old_answer_cannot_complete_a_new_operation() {
        let t0 = t0();
        let mut m = FamilyMachine::<u64>::new();
        let step = m.step(renew(t0, CURRENT), &POLICY).unwrap();
        let step = m.answer(step.ask.unwrap(), due(), &POLICY).unwrap();
        assert_eq!(step.actions, [Action::Negotiate]);
        let a1 = step.ask.unwrap();
        assert_eq!(m.answer(a1, Input::Negotiated(Err(Failure::Other)), &POLICY).map(|s| s.outcome), Ok(Some(Outcome::Failed)));
        // The next renewal, the spacing after a failure passed, waits on its own rekey.
        let later = t0 + secs(5);
        let step = m.step(renew(later, CURRENT), &POLICY).unwrap();
        let step = m.answer(step.ask.unwrap(), due(), &POLICY).unwrap();
        assert_eq!(step.actions, [Action::Negotiate]);
        let a2 = step.ask.unwrap();
        assert_ne!(a1, a2);
        let late = negotiated(t0, NEW);
        let before = m.clone();
        assert_eq!(m.answer(a1, late, &POLICY), Err(Unexpected { phase: "negotiating", why: Refusal::NotTheAsk, input: late }));
        assert_eq!(m, before, "nothing changes");
        let step = m.answer(a2, negotiated(later, NEW), &POLICY).unwrap();
        assert_eq!(step.actions, [Action::KeepRedundant { now: later + TOOK }, Action::Prepare { new: NEW, now: later + TOOK }]);
    }

    #[test]
    fn an_answer_given_twice_is_taken_once() {
        let t0 = t0();
        let mut m = FamilyMachine::<u64>::new();
        let mut ask = m.step(renew(t0, CURRENT), &POLICY).unwrap().ask.unwrap();
        let script = [due(), negotiated(t0, NEW), Input::Prepared(Ok(ID)), Input::Committed(Committed::OursDeleteNotAsked), Input::Switched(Ok(())), Input::Deleted(ACKED)];
        for (n, answer) in script.into_iter().enumerate() {
            let step = m.answer(ask, answer, &POLICY).unwrap();
            let last = n + 1 == script.len();
            assert_eq!(step.outcome.is_some(), last, "{answer:?}");
            let before = m.clone();
            let (phase, why) = if last { ("idle", Refusal::NothingAsked) } else { (m.phase.name(), Refusal::NotTheAsk) };
            assert_eq!(m.answer(ask, answer, &POLICY), Err(Unexpected { phase, why, input: answer }), "{answer:?} again");
            assert_eq!(m, before, "{answer:?} again: nothing changes");
            if let Some(next) = step.ask {
                ask = next;
            }
        }
        assert_eq!(settled(&m), [retired(CURRENT, Ours, Sent { acknowledged: true })], "the Delete recorded once");
    }

    #[test]
    fn the_late_refusal_of_the_deferred_switch_is_not_taken_for_the_switch_at_once_after_it() {
        let t0 = t0();
        let at = t0 + secs(1);
        let newer = (0x31, 0x32);
        let mut m = with_a_switch_pending(t0);
        let ask = m.step(renew(at, NEXT), &POLICY).unwrap().ask.unwrap();
        let switch_ask = m.answer(ask, due(), &POLICY).unwrap().ask.unwrap();
        assert_eq!(m.phase.name(), "switching");
        let mut ask = switch_ask;
        for answer in [Input::Switched(Ok(())), due(), negotiated(at, newer), Input::Prepared(Ok(ID + 1)), Input::Committed(Committed::OursDeleteNotAsked)] {
            ask = m.answer(ask, answer, &POLICY).unwrap().ask.unwrap();
        }
        assert_eq!(m.phase.name(), "switching_at_once");
        let late = Input::Switched(Err(NotSwitched::Refused));
        let before = m.clone();
        assert_eq!(m.answer(switch_ask, late, &POLICY), Err(Unexpected { phase: "switching_at_once", why: Refusal::NotTheAsk, input: late }), "no CloseIkeSa");
        assert_eq!(m, before, "nothing changes");
        let step = m.answer(ask, Input::Switched(Ok(())), &POLICY).unwrap();
        assert_eq!(step.actions, [Action::DeleteChild { spis: NEW }]);
        let step = m.answer(step.ask.unwrap(), Input::Deleted(ACKED), &POLICY).unwrap();
        assert_eq!(step.outcome, Some(Outcome::Renewed { new: newer, deferred: false, ike_sa_over: false }));
        assert!(!step.actions.contains(&Action::CloseIkeSa));
    }

    #[test]
    fn another_machines_ask_is_not_the_ask() {
        let t0 = t0();
        let (mut a, mut b) = (FamilyMachine::<u64>::with_scope(1), FamilyMachine::<u64>::with_scope(2));
        assert_eq!((a.scope(), b.scope(), FamilyMachine::<u64>::new().scope()), (1, 2, 0));
        let ask_a = a.step(renew(t0, CURRENT), &POLICY).unwrap().ask.unwrap();
        let ask_b = b.step(renew(t0, CURRENT), &POLICY).unwrap().ask.unwrap();
        assert_eq!(ask_a.serial, ask_b.serial, "the same serial");
        assert_ne!(ask_a, ask_b);
        let before = a.clone();
        assert_eq!(a.answer(ask_b, due(), &POLICY), Err(Unexpected { phase: "use", why: Refusal::NotTheAsk, input: due() }));
        assert_eq!(a, before);
        assert_eq!(a.answer(ask_a, due(), &POLICY).map(|s| s.actions), Ok(vec![Action::Negotiate]));
    }

    #[test]
    fn a_wrong_answer_an_answer_as_an_event_and_an_event_while_busy_are_refused_and_handed_back_whole() {
        let t0 = t0();
        let mut m = FamilyMachine::<u64>::new();
        assert_eq!(m.answer(Ask { scope: 0, serial: 0 }, due(), &POLICY), Err(Unexpected { phase: "idle", why: Refusal::NothingAsked, input: due() }));
        assert_eq!(m.step(due(), &POLICY), Err(Unexpected { phase: "idle", why: Refusal::NotAnEvent, input: due() }));
        untouched(&m);
        let ask = m.step(renew(t0, CURRENT), &POLICY).unwrap().ask.unwrap();
        let before = m.clone();
        let wrong = negotiated(t0, NEW);
        assert_eq!(m.answer(ask, wrong, &POLICY), Err(Unexpected { phase: "use", why: Refusal::NotItsAnswer, input: wrong }));
        assert_eq!(m, before);
        let event = held(t0);
        assert_eq!(m.answer(ask, event, &POLICY), Err(Unexpected { phase: "use", why: Refusal::NotItsAnswer, input: event }), "an event is no answer");
        assert_eq!(m, before);
        assert_eq!(m.step(due(), &POLICY), Err(Unexpected { phase: "use", why: Refusal::NotAnEvent, input: due() }));
        assert_eq!(m, before);
        let refused = m.step(event, &POLICY).unwrap_err();
        assert_eq!((refused.phase, refused.why, refused.input), ("use", Refusal::Busy, event), "the event handed back as it was");
        assert_eq!(m, before);
        assert_eq!(m.answer(ask, due(), &POLICY).map(|s| s.actions), Ok(vec![Action::Negotiate]), "the pending ask still answered");
    }

    #[test]
    fn what_an_answer_brought_is_handed_back_with_its_refusal() {
        let t0 = t0();
        let n = NewChild { new: NEW, now: t0, took: TOOK };
        for (input, brought) in [
            (Input::Negotiated(Ok(n)), Some(Brought::Child { new: NEW })),
            (Input::Prepared(Ok(ID)), Some(Brought::InPlane(ID))),
            (Input::PreparedDeferred(Ok((ID, REPLACED))), Some(Brought::InPlane(ID))),
            (Input::Added(Ok(ID)), Some(Brought::InPlane(ID))),
            (Input::Negotiated(Err(Failure::Other)), None),
            (Input::Prepared(Err(NotPrepared { session_on: Some(NEW) })), None),
            (Input::PreparedDeferred(Err(())), None),
            (Input::Added(Err(())), None),
        ] {
            assert_eq!(input.brought(), brought, "{input:?}");
        }
        for input in every_input(t0) {
            let brings = matches!(input, Input::Negotiated(Ok(_)) | Input::Prepared(Ok(_)) | Input::PreparedDeferred(Ok(_)) | Input::Added(Ok(_)));
            assert_eq!(input.brought().is_some(), brings, "{input:?}");
        }
        // A rekey's answer refused: the child's SPIs come back, for the consumer to reconcile.
        let mut m = FamilyMachine::<u64>::new();
        let ask = m.step(renew(t0, CURRENT), &POLICY).unwrap().ask.unwrap();
        let refused = m.answer(ask, negotiated(t0, NEW), &POLICY).unwrap_err();
        assert_eq!((refused.why, refused.input.brought()), (Refusal::NotItsAnswer, Some(Brought::Child { new: NEW })));
    }

    /// One operation of every flow, from a machine with a switch pending or not (`start`): together
    /// they reach every phase that asks, and three of them defer a switch (A with the peer's SA kept,
    /// C served, D by the peer).
    fn every_flow(t0: Instant) -> Vec<(bool, Input<u64>, Vec<Input<u64>>)> {
        let at = t0 + secs(1);
        let newer = (0x61, 0x62);
        let renewing = |rest: &[Input<u64>]| [&up_to_commit(t0)[..], rest].concat();
        vec![
            (false, renew(t0, CURRENT), renewing(&[Input::Committed(Committed::OursDeleteNotAsked), Input::Switched(Ok(())), Input::Deleted(came(Ours, Unknown))])),
            (false, renew(t0, CURRENT), renewing(&[Input::Committed(Committed::Other(ACKED)), Input::Switched(Ok(()))])),
            (false, renew(t0, CURRENT), renewing(&[Input::Committed(Committed::PeersKept(PEERS))])),
            (false, renew(t0, CURRENT), renewing(&[Input::Committed(Committed::OursDeleteNotAsked), Input::Switched(Err(NotSwitched::Refused))])),
            (false, renew(t0, CURRENT), vec![due(), negotiated(t0, NEW), Input::Prepared(Err(NotPrepared { session_on: Some(NEW) })), Input::Abandoned(came(Ours, Failed))]),
            (
                true,
                renew(at, NEXT),
                vec![due(), Input::Switched(Ok(())), due(), negotiated(at, newer), Input::Prepared(Ok(ID + 1)), Input::Committed(Committed::OursDeleteNotAsked), Input::Switched(Ok(())), Input::Deleted(ACKED)],
            ),
            (true, Input::SwitchCheck { now: at, peer_sent: true }, vec![Input::Switched(Ok(()))]),
            (true, Input::PeerRekeyHeld { now: at, current: Some(NEXT), new: newer }, vec![Input::Switched(Ok(())), Input::PreparedDeferred(Ok((ID + 1, NEW))), Input::Released(Ok(ms(1)))]),
            (false, held(t0), vec![Input::PreparedDeferred(Err(())), Input::Refused(Ok(()))]),
            (false, held(t0), vec![Input::PreparedDeferred(Ok((ID, REPLACED))), Input::Released(Err(Failure::Other))]),
            (false, held_of_redundant(t0, Some(5)), vec![Input::Added(Ok(ID)), Input::Released(Ok(ms(2)))]),
            (false, held_of_redundant(t0, Some(5)), vec![Input::Added(Err(())), Input::Refused(Ok(()))]),
            (false, Input::Replacement { now: t0, new: NEW, by_peer: true }, vec![Input::PreparedDeferred(Ok((ID, REPLACED)))]),
            (true, Input::Replacement { now: at, new: newer, by_peer: false }, vec![Input::Switched(Ok(())), Input::InstalledAndSwitched(Ok(()))]),
            (
                true,
                Input::MovedToRedundant { now: at, current: Some(NEXT), to: TO, replaced: NEW, in_plane: Some(5), consumer_owes_install: false },
                vec![Input::Moved(Ok(Moved { pending_refused: false, promoted: Ok(()) }))],
            ),
        ]
    }

    /// The machine a flow of `every_flow` starts from.
    fn start(t0: Instant, switch_pending: bool) -> FamilyMachine<u64> {
        if switch_pending {
            with_a_switch_pending(t0)
        } else {
            FamilyMachine::new()
        }
    }

    const ASKING_PHASES: [&str; 18] = [
        "pending_use",
        "switching",
        "use",
        "negotiating",
        "preparing",
        "abandoning",
        "committing",
        "switching_at_once",
        "deleting",
        "held_preparing",
        "held_refusing",
        "held_releasing",
        "redundant_adding",
        "redundant_refusing",
        "redundant_releasing",
        "replacement_preparing",
        "replacement_installing",
        "moving",
    ];

    #[test]
    fn at_every_asking_phase_of_every_flow_another_ask_an_answer_as_an_event_and_an_event_are_refused() {
        // `drive` gives them at every step that asks (`refuses_around`); here, every phase that asks
        // is reached.
        let t0 = t0();
        let mut reached = std::collections::BTreeSet::new();
        for (pending, event, answers) in every_flow(t0) {
            let run = drive(&mut start(t0, pending), &POLICY, event, &answers);
            reached.extend(run.asks.iter().map(|(_, phase)| *phase));
        }
        assert_eq!(reached, ASKING_PHASES.into_iter().collect());
    }

    // A data plane reset during an operation, and no data plane.

    #[test]
    fn a_data_plane_reset_during_an_operation_changes_nothing_of_it_and_drops_the_switch_deferred_at_its_end() {
        let t0 = t0();
        let mut deferring = 0;
        for (pending, event, answers) in every_flow(t0) {
            let mut plain = start(t0, pending);
            let without = drive(&mut plain, &POLICY, event, &answers);
            deferring += usize::from(plain.pending_switch().is_some());
            let mut expected = plain.clone();
            let _ = expected.record.take_switch();
            for (at, (_, phase)) in without.asks.iter().enumerate() {
                for times in [1, 2] {
                    let what = format!("{event:?}, reset {times} time(s) in {phase}");
                    let mut m = start(t0, pending);
                    let run = drive_reset(&mut m, &POLICY, event, &answers, Some((at, times)));
                    assert_eq!((&run.actions, run.outcome), (&without.actions, without.outcome), "{what}: the operation's own actions and outcome");
                    assert_eq!(m.pending_switch(), None, "{what}: no switch left");
                    assert_eq!(m, expected, "{what}: the rest as without the reset");
                }
            }
        }
        assert_eq!(deferring, 3, "the flows that defer a switch");
    }

    #[test]
    fn no_data_plane_for_the_deferred_switch_drops_it_closes_nothing_and_what_follows_goes_on() {
        let t0 = t0();
        let at = t0 + secs(1);
        let newer = (0x61, 0x62);
        let none = Input::Switched(Err(NotSwitched::NoDataPlane));
        let dropped = Action::Note(Note::SwitchDroppedNoDataPlane { local_spi: NEW.0 });
        // For its own sake: nothing switched.
        for (event, proof) in [
            (Input::SwitchCheck { now: at, peer_sent: true }, SwitchProof::PeerSent),
            (Input::PeerDeletedReplaced { now: at, local_spi: CURRENT.local_spi }, SwitchProof::ReplacedDeleted),
        ] {
            let mut m = with_a_switch_pending(t0);
            let switch = m.pending_switch().unwrap();
            let run = drive(&mut m, &POLICY, event, &[none]);
            assert_eq!(run.actions, [Action::Switch { switch, proof, now: at }, dropped], "{event:?}");
            assert_eq!((run.outcome, m.pending_switch()), (Outcome::Nothing, None), "{event:?}");
        }
        // Made first for another operation: it goes on as after a switch made, and what it asks of
        // the data plane is answered as with none (`used: None`, the refusals).
        let no_use = Input::Use { used: None, signal: Some(SIGNAL), basis: BASIS, peer_rekey_held: false };
        let not_installed = Action::Note(Note::ReplacementNotInstalled { local_spi: newer.0 });
        for (event, answers, then, outcome) in [
            (renew(at, NEXT), vec![due(), none, no_use], vec![Action::ReadUse { spis: NEW }], Outcome::NotDue),
            (
                Input::PeerRekeyHeld { now: at, current: Some(NEXT), new: newer },
                vec![none, Input::PreparedDeferred(Err(())), Input::Refused(Ok(()))],
                vec![Action::PrepareDeferred { new: newer, now: at }, Action::RefuseHeld { new_local_spi: newer.0 }, Action::Note(Note::HeldRefused { local_spi: newer.0 })],
                Outcome::Refused,
            ),
            (
                Input::Replacement { now: at, new: newer, by_peer: true },
                vec![none, Input::PreparedDeferred(Err(()))],
                vec![Action::PrepareDeferred { new: newer, now: at }, not_installed],
                Outcome::LeftToConsumer { ike_sa_over: false },
            ),
            (
                Input::Replacement { now: at, new: newer, by_peer: false },
                vec![none, Input::InstalledAndSwitched(Err(()))],
                vec![Action::InstallAndSwitch { new: newer, now: at }, not_installed],
                Outcome::LeftToConsumer { ike_sa_over: false },
            ),
        ] {
            let mut m = with_a_switch_pending(t0);
            let switch = m.pending_switch().unwrap();
            let run = drive(&mut m, &POLICY, event, &answers);
            let made = run.at("Switch");
            assert_eq!(run.actions[made], Action::Switch { switch, proof: SwitchProof::SlotNeeded, now: at }, "{event:?}");
            assert_eq!(run.actions[made + 1..], [vec![dropped], then].concat(), "{event:?}");
            assert_eq!((run.outcome, m.pending_switch()), (outcome, None), "{event:?}");
            assert!(!run.has("CloseIkeSa"), "{event:?}");
        }
    }

    #[test]
    fn no_data_plane_for_the_switch_at_once_is_its_refusal() {
        let t0 = t0();
        for committed in [Committed::OursDeleteNotAsked, Committed::Other(ACKED)] {
            let (mut refused, mut none) = (FamilyMachine::<u64>::new(), FamilyMachine::<u64>::new());
            let by_refusal = renewal(&mut refused, &POLICY, t0, committed, &[Input::Switched(Err(NotSwitched::Refused))]);
            let run = renewal(&mut none, &POLICY, t0, committed, &[Input::Switched(Err(NotSwitched::NoDataPlane))]);
            assert_eq!(run.actions[run.at("SwitchAtOnce") + 1..], [Action::AgeClockFailed, Action::Note(Note::SwitchAtOnceRefused { new_local_spi: NEW.0 }), Action::CloseIkeSa], "{committed:?}");
            assert_eq!((&run.actions, run.outcome), (&by_refusal.actions, by_refusal.outcome), "{committed:?}");
            assert_eq!(run.outcome, Outcome::TornDown);
            assert_eq!(none, refused, "{committed:?}");
        }
    }

    #[test]
    fn no_data_plane_for_the_move_drops_the_pending_switch_withdraws_nothing_and_leaves_the_move_to_the_consumer() {
        let t0 = t0();
        let at = t0 + secs(1);
        for in_plane in [Some(5), None] {
            let mut m = with_a_switch_pending(t0);
            let pending = m.pending_switch();
            let event = Input::MovedToRedundant { now: at, current: Some(NEXT), to: TO, replaced: NEW, in_plane, consumer_owes_install: false };
            let run = drive(&mut m, &POLICY, event, &[Input::Moved(Err(NoDataPlane))]);
            assert_eq!(
                run.actions,
                [
                    Action::MoveToRedundant { pending, promote: in_plane, now: at },
                    Action::Note(Note::NotMovedToRedundant { replaced_local_spi: NEW.0, to_local_spi: TO.0, why: NotPromoted::NoDataPlane }),
                    Action::AgeClockRestart,
                    Action::BecameCurrent(NEXT.successor(TO.0, TO.1)),
                ],
                "{in_plane:?}"
            );
            assert_eq!((run.outcome, m.pending_switch()), (Outcome::MovedTo { new: TO, installed: false }, None), "{in_plane:?}");
        }
    }

    #[test]
    fn a_renewal_whose_install_is_refused_after_a_reset_still_owes_and_asks_the_abandons_delete() {
        let t0 = t0();
        let new_sa = Retired { spis: NEW, generation: None, deleted_by: Ours, stand: NotSent };
        let mut m = FamilyMachine::<u64>::new();
        let answers = [due(), negotiated(t0, NEW), Input::Prepared(Err(NotPrepared { session_on: Some(NEW) })), Input::Abandoned(came(Ours, Unknown))];
        // The reset given while the install is asked: the data plane it was asked of is gone.
        let run = drive_reset(&mut m, &POLICY, renew(t0, CURRENT), &answers, Some((2, 1)));
        assert_eq!(run.asks[2].1, "preparing");
        assert_eq!(run.asking(), ["ReadUse", "Negotiate", "Prepare", "Abandon"]);
        assert_eq!(run.asked[3].0, Action::Abandon { new_local_spi: NEW.0, delete: true });
        assert_eq!(run.owed_at("Abandon"), [new_sa], "owed at the step that asks the abandon");
        assert_eq!(m.record().owed(), [Retired { stand: Unknown, ..new_sa }], "still owed");
        assert_eq!(run.outcome, Outcome::Failed);
    }

    // The composite actions, carried out on a model of a data plane.

    /// A model of a data plane, for these tests only: not any real data plane, and nothing of one
    /// but what the composite actions touch. One family: the generation outbound is sealed with, an
    /// optional next one, redundant ones (inbound only) and previous ones (inbound only, for a term),
    /// each a name and its SPIs. Switches can be made to refuse.
    #[derive(Debug, Default)]
    struct Model {
        last: u64,
        current: Option<(u64, (u32, u32))>,
        next: Option<(u64, (u32, u32))>,
        redundant: Vec<(u64, (u32, u32))>,
        previous: Vec<(u64, (u32, u32))>,
        refuse_switch: bool,
    }

    impl Model {
        /// Sealing with `spis`.
        fn on(spis: (u32, u32)) -> Self {
            Self { last: 1, current: Some((1, spis)), ..Self::default() }
        }

        fn named(&mut self, spis: (u32, u32)) -> (u64, (u32, u32)) {
            self.last += 1;
            (self.last, spis)
        }

        /// `spis` installed as the next generation, if there is none.
        fn prepare_next(&mut self, spis: (u32, u32)) -> Result<u64, ()> {
            if self.next.is_some() {
                return Err(());
            }
            let next = self.named(spis);
            self.next = Some(next);
            Ok(next.0)
        }

        /// Outbound moved to the next generation `id`, the current one kept as a previous one.
        fn switch(&mut self, id: u64) -> Result<(), ()> {
            match self.next {
                Some(next) if next.0 == id && !self.refuse_switch => {
                    self.next = None;
                    self.previous.extend(self.current.replace(next));
                    Ok(())
                }
                _ => Err(()),
            }
        }

        fn withdraw(&mut self, id: u64) {
            self.next = self.next.filter(|next| next.0 != id);
            self.redundant.retain(|r| r.0 != id);
        }

        fn add_redundant(&mut self, spis: (u32, u32)) -> u64 {
            let redundant = self.named(spis);
            self.redundant.push(redundant);
            redundant.0
        }

        /// Outbound moved to the redundant generation `id`, the current one kept as a previous one.
        fn promote_redundant(&mut self, id: u64) -> Result<(), ()> {
            let at = self.redundant.iter().position(|r| r.0 == id).ok_or(())?;
            let promoted = self.redundant.remove(at);
            self.previous.extend(self.current.replace(promoted));
            Ok(())
        }

        fn close_redundant(&mut self, id: u64) {
            if let Some(at) = self.redundant.iter().position(|r| r.0 == id) {
                let closed = self.redundant.remove(at);
                self.previous.push(closed);
            }
        }

        fn name_of(&self, spis: (u32, u32)) -> Option<u64> {
            self.redundant.iter().chain(&self.next).chain(&self.current).find(|g| g.1 == spis).map(|g| g.0)
        }
    }

    /// How an executor carries a composite action out: as one change of the model, or split into
    /// its parts, the model let go of between them.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Carry {
        Whole,
        Split,
    }

    /// An adapter over the model: it drives a machine, answers what touches the data plane from the
    /// model and what goes on the wire from a script, and looks at the model wherever it lets go of
    /// it -- after every action, and between the parts of a composite one when it splits them.
    #[derive(Debug)]
    struct Executor {
        model: Model,
        carry: Carry,
        /// The peer's SAs of crossed rekeys the session kept, for the next `KeepRedundant`.
        keep: Vec<(u32, u32)>,
        /// The SA a move to the redundant SA moves off, the peer having deleted it.
        deleted: Option<u64>,
        /// A composite's switch refused, its next generation not withdrawn yet.
        refused: bool,
        /// How many times the model was looked at, and what was found broken.
        observed: usize,
        broken: Vec<&'static str>,
    }

    impl Executor {
        fn new(carry: Carry) -> Self {
            Self { model: Model::on(CURRENT.spis()), carry, keep: vec![], deleted: None, refused: false, observed: 0, broken: vec![] }
        }

        /// The invariants, wherever the model is let go of.
        fn observe(&mut self) {
            self.observed += 1;
            let m = &self.model;
            let others = m.next.iter().chain(&m.redundant).chain(&m.previous).map(|g| g.0).collect::<Vec<_>>();
            if !m.current.is_some_and(|c| !others.contains(&c.0)) {
                self.broken.push("outbound not on exactly one generation");
            }
            if self.refused && m.next.is_some() {
                self.broken.push("a next generation left behind by a refused switch");
            }
            if self.deleted.is_some() && m.current.map(|c| c.0) == self.deleted {
                self.broken.push("outbound on the SA the peer deleted");
            }
        }

        /// Between the parts of a composite action.
        fn between(&mut self) {
            if self.carry == Carry::Split {
                self.observe();
            }
        }

        /// A composite's switch to the next generation `id`, withdrawn if refused.
        fn switch_or_withdraw(&mut self, id: u64) -> Result<(), ()> {
            let switched = self.model.switch(id);
            if switched.is_err() {
                self.refused = true;
                self.between();
                self.model.withdraw(id);
                self.refused = false;
            }
            switched
        }

        /// `action` carried out; the answer it asks for, from the model or from `wire`.
        fn carry_out(&mut self, action: Action<u64>, wire: &mut dyn Iterator<Item = Input<u64>>) -> Option<Input<u64>> {
            let switched = |made: Result<(), ()>| Input::Switched(made.map_err(|()| NotSwitched::Refused));
            match action {
                Action::Note(_) | Action::CloseIkeSa | Action::AgeClockFailed | Action::AgeClockRestart | Action::BecameCurrent(_) => None,
                Action::Negotiate | Action::Abandon { .. } | Action::Commit { .. } | Action::DeleteChild { .. } | Action::RefuseHeld { .. } | Action::ReleaseHeld { .. } => {
                    Some(wire.next().unwrap_or_else(|| panic!("no wire answer for {action:?}")))
                }
                Action::ReadUse { spis } => {
                    let used = self.model.current.is_some_and(|c| c.1 == spis).then_some(USED);
                    Some(Input::Use { used, signal: Some(SIGNAL), basis: BASIS, peer_rekey_held: false })
                }
                Action::Switch { switch, .. } => Some(switched(self.switch_or_withdraw(switch.id))),
                Action::SwitchAtOnce { id, .. } => Some(switched(self.switch_or_withdraw(id))),
                Action::KeepRedundant { .. } => {
                    for spis in std::mem::take(&mut self.keep) {
                        self.model.add_redundant(spis);
                    }
                    None
                }
                Action::Prepare { new, .. } => Some(Input::Prepared(self.model.prepare_next(new).map_err(|()| NotPrepared { session_on: Some(new) }))),
                Action::PrepareDeferred { new, .. } => {
                    let current = self.model.current.map(|c| c.1);
                    let prepared = self.model.prepare_next(new);
                    self.between();
                    let replaced = self.model.current.map_or((0, 0), |c| c.1);
                    if Some(replaced) != current {
                        self.broken.push("the SPIs answered not those of the generation current at the install");
                    }
                    Some(Input::PreparedDeferred(prepared.map(|id| (id, replaced))))
                }
                Action::Withdraw { id, .. } => {
                    self.model.withdraw(id);
                    None
                }
                Action::AddRedundant { new, .. } => Some(Input::Added(Ok(self.model.add_redundant(new)))),
                Action::CloseRedundant { id, .. } => {
                    self.model.close_redundant(id);
                    None
                }
                Action::InstallAndSwitch { new, .. } => {
                    let installed = self.model.prepare_next(new).and_then(|id| {
                        self.between();
                        self.switch_or_withdraw(id)
                    });
                    Some(Input::InstalledAndSwitched(installed))
                }
                Action::MoveToRedundant { pending, promote, .. } => {
                    let mut pending_refused = false;
                    if let Some(pending) = pending {
                        if promote.is_some() {
                            self.deleted = Some(pending.id);
                        }
                        pending_refused = self.switch_or_withdraw(pending.id).is_err();
                        self.between();
                    }
                    let promoted = promote.map_or(Err(()), |id| self.model.promote_redundant(id));
                    Some(Input::Moved(Ok(Moved { pending_refused, promoted })))
                }
            }
        }

        /// `event` and all that follows it carried out for `m`, the wire answering from `wire` in
        /// order; the model looked at after every action. How the operation ended.
        fn run(&mut self, m: &mut FamilyMachine<u64>, event: Input<u64>, wire: &[Input<u64>]) -> Outcome<u64> {
            let mut wire = wire.iter().copied();
            let mut step = m.step(event, &POLICY).unwrap_or_else(|e| panic!("{e:?}"));
            loop {
                let mut answer = None;
                for action in step.actions {
                    answer = self.carry_out(action, &mut wire);
                    self.observe();
                }
                match (step.outcome, step.ask, answer) {
                    (Some(outcome), None, None) => {
                        assert!(wire.next().is_none(), "wire answers left over after {outcome:?}");
                        return outcome;
                    }
                    (None, Some(ask), Some(answer)) => step = m.answer(ask, answer, &POLICY).unwrap_or_else(|e| panic!("{e:?}")),
                    other => panic!("{other:?}"),
                }
            }
        }
    }

    /// The flows with composite actions, each from a fresh machine and model, carried out as `carry`
    /// says, their outcomes checked: the executors after, by name.
    fn composite_flows(carry: Carry) -> Vec<(&'static str, Executor)> {
        let t0 = t0();
        let at = t0 + secs(1);
        let peers_kept = (vec![negotiated(t0, NEW), Input::Committed(Committed::PeersKept(PEERS))], Outcome::Renewed { new: NEW, deferred: true, ike_sa_over: false });
        let ours = [negotiated(t0, NEW), Input::Committed(Committed::OursDeleteNotAsked)];
        let replacement = |by_peer| Input::Replacement { now: t0, new: NEW, by_peer };
        let left = Outcome::LeftToConsumer { ike_sa_over: false };
        let script = [
            ("A ours kept", false, vec![(renew(t0, CURRENT), [&ours[..], &[Input::Deleted(ACKED)]].concat(), Outcome::Renewed { new: NEW, deferred: false, ike_sa_over: false })]),
            ("A peer's kept, then B", false, vec![(renew(t0, CURRENT), peers_kept.0.clone(), peers_kept.1), (Input::SwitchCheck { now: at, peer_sent: true }, vec![], Outcome::Switched)]),
            ("A switch at once refused", true, vec![(renew(t0, CURRENT), ours.to_vec(), Outcome::TornDown)]),
            ("C served", false, vec![(held(t0), vec![Input::Released(Ok(ms(1)))], Outcome::Served { new: NEW })]),
            ("D by the peer", false, vec![(replacement(true), vec![], Outcome::Installed { deferred: true })]),
            ("D ours", false, vec![(replacement(false), vec![], Outcome::Installed { deferred: false })]),
            ("D ours refused", true, vec![(replacement(false), vec![], left)]),
        ];
        let mut flows = vec![];
        for (name, refuse_switch, operations) in script {
            let (mut x, mut m) = (Executor::new(carry), FamilyMachine::new());
            x.model.refuse_switch = refuse_switch;
            for (event, wire, outcome) in operations {
                assert_eq!(x.run(&mut m, event, &wire), outcome, "{name}");
            }
            flows.push((name, x));
        }
        // B refused: the deferred switch refused by the data plane.
        let (mut x, mut m) = (Executor::new(carry), FamilyMachine::new());
        assert_eq!(x.run(&mut m, renew(t0, CURRENT), &peers_kept.0), peers_kept.1);
        x.model.refuse_switch = true;
        assert_eq!(x.run(&mut m, Input::SwitchCheck { now: at, peer_sent: true }, &[]), Outcome::TornDown);
        flows.push(("B refused", x));
        // E: the peer's redundant SA put in by a renewal that kept the peer's SA, whose switch is
        // pending; then the peer deletes that SA, and the family moves to the redundant one.
        let (mut x, mut m) = (Executor::new(carry), FamilyMachine::new());
        x.keep = vec![TO];
        assert_eq!(x.run(&mut m, renew(t0, CURRENT), &peers_kept.0), peers_kept.1);
        let in_plane = x.model.name_of(TO);
        assert!(in_plane.is_some() && m.pending_switch().is_some());
        let event = Input::MovedToRedundant { now: at, current: Some(NEXT), to: TO, replaced: NEW, in_plane, consumer_owes_install: false };
        assert_eq!(x.run(&mut m, event, &[]), Outcome::MovedTo { new: TO, installed: true });
        assert_eq!(x.model.current.map(|c| c.1), Some(TO));
        flows.push(("E", x));
        flows
    }

    #[test]
    fn carried_out_as_one_change_the_composite_actions_leave_the_data_plane_whole_at_every_point() {
        for (name, x) in composite_flows(Carry::Whole) {
            assert!(x.observed > 0, "{name}");
            assert_eq!(x.broken, Vec::<&str>::new(), "{name}");
        }
    }

    #[test]
    fn split_into_their_parts_the_composite_actions_are_seen_broken_in_between() {
        let flows = composite_flows(Carry::Split);
        let broken = |name: &str| flows.iter().find(|(n, _)| *n == name).map(|(_, x)| x.broken.clone()).unwrap_or_else(|| panic!("no flow {name}"));
        assert_eq!(broken("E"), ["outbound on the SA the peer deleted"]);
        for name in ["A switch at once refused", "B refused", "D ours refused"] {
            assert_eq!(broken(name), ["a next generation left behind by a refused switch"], "{name}");
        }
        for name in ["A ours kept", "A peer's kept, then B", "C served", "D by the peer", "D ours"] {
            assert_eq!(broken(name), Vec::<&str>::new(), "{name}: nothing seen between parts that all went through");
        }
    }
}
