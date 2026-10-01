//! The volume figures of one SA, each kept apart by where it comes from ([`Origin`]), and the
//! renewal a figure may ask for of the SA in use ([`VolumeLimits::renewal_signal`]).
//!
//! Where a figure comes from and what is done with it are kept apart. The origin is a fact: the
//! figure was negotiated with the peer, stated by the consumer's configuration, or learned (an
//! estimate the consumer made). What is done with it is the consumer's policy
//! ([`VolumePolicy`]): for each origin, whether a figure of it is a hard limit
//! ([`Enforcement::Hard`]) or only a place to start a renewal ([`Enforcement::Advisory`]), and at
//! which share of it a renewal starts. Which origins are hard is not a rule of this crate.
//!
//! What the policy cannot change:
//!
//! - The hard limit is the smallest figure among the origins the policy holds hard
//!   ([`VolumeLimits::hard_bytes`]); an advisory figure is never presented as one, whatever else is
//!   present.
//! - A renewal is measured against one figure, by precedence negotiated, else configured, else
//!   learned ([`VolumeLimits::renewal_basis`]): a figure of a lower precedence never replaces one of
//!   a higher one, even a larger one.
//! - A renewal point is reached by either direction of the SA on its own, never by their sum, and
//!   no reading says nothing ([`VolumeLimits::renewal_signal`]). A signal only ever asks for a
//!   renewal: nothing here retires or blocks an SA.
//! - Changing one figure changes that figure and nothing else ([`VolumeLimits::set`]): no count,
//!   age or generation is part of it, so the counts the SA already has are measured against the
//!   new figure as they are.
//!
//! Every figure is in bytes, and is kept as given: a zero is a figure of zero, not "none" (whether
//! a zero means none is for the caller to decide before it passes one in).

use super::Share;

/// Where a volume figure comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// Agreed with the peer in the exchange that made the SA (IKEv1's lifetime in kilobytes, RFC
    /// 2407 §4.5).
    Negotiated,
    /// Stated by the consumer's configuration.
    Configured,
    /// Inferred by the consumer, for instance from the peer's own rekeys: an estimate.
    Learned,
}

/// What a figure of one origin is held to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enforcement {
    /// A real limit: the SA ends at it ([`VolumeLimits::hard_bytes`]).
    Hard,
    /// Only a place to start a renewal: nothing ends an SA on it.
    Advisory,
}

/// What the policy does with a figure of one origin: whether it is a hard limit, and the share of
/// it at which the SA is to be renewed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Treatment {
    pub enforcement: Enforcement,
    pub renew_at: Share,
}

/// The consumer's policy for volume figures: a [`Treatment`] for each [`Origin`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VolumePolicy {
    pub negotiated: Treatment,
    pub configured: Treatment,
    pub learned: Treatment,
}

impl VolumePolicy {
    /// The treatment of a figure from `origin`.
    pub const fn treatment(&self, origin: Origin) -> Treatment {
        match origin {
            Origin::Negotiated => self.negotiated,
            Origin::Configured => self.configured,
            Origin::Learned => self.learned,
        }
    }
}

/// The volume figures of one SA, at most one per [`Origin`], each kept separately so none is ever
/// taken for another, under the [`VolumePolicy`] that says what each may do. There is no default:
/// the policy is always the consumer's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VolumeLimits {
    policy: VolumePolicy,
    /// The negotiated figure, in bytes.
    negotiated: Option<u64>,
    /// The configured figure, in bytes.
    configured: Option<u64>,
    /// The learned figure, in bytes.
    learned: Option<u64>,
}

/// What the volume asks of the SA in use: a renewal, because one direction has reached
/// [`at_bytes`](Self::at_bytes), the renewal point of the figure from [`origin`](Self::origin).
/// Never more than that: a signal is not an end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenewalSignal {
    /// Which figure the renewal point was taken from.
    pub origin: Origin,
    /// The renewal point reached, in bytes per direction.
    pub at_bytes: u64,
}

impl VolumeLimits {
    /// No figures yet, under `policy`.
    pub const fn new(policy: VolumePolicy) -> Self {
        Self { policy, negotiated: None, configured: None, learned: None }
    }

    /// These figures with `bytes` as the figure from `origin`, in place of any it had (`None`
    /// removes it).
    pub fn with(mut self, origin: Origin, bytes: Option<u64>) -> Self {
        self.set(origin, bytes);
        self
    }

    /// The figure from `origin` is now `bytes` (`None`: there is none), whether there was none, a
    /// higher one or a lower one. It changes that figure and nothing else.
    pub fn set(&mut self, origin: Origin, bytes: Option<u64>) {
        match origin {
            Origin::Negotiated => self.negotiated = bytes,
            Origin::Configured => self.configured = bytes,
            Origin::Learned => self.learned = bytes,
        }
    }

    /// The figure from `origin`, in bytes, if there is one.
    pub fn figure(&self, origin: Origin) -> Option<u64> {
        match origin {
            Origin::Negotiated => self.negotiated,
            Origin::Configured => self.configured,
            Origin::Learned => self.learned,
        }
    }

    /// The policy these figures are held to.
    pub fn policy(&self) -> VolumePolicy {
        self.policy
    }

    /// The hard volume limit, in bytes: the smallest figure present among the origins the policy
    /// enforces as [`Enforcement::Hard`]; `None` if there is none. An advisory figure is never one,
    /// whatever else is present, so an SA is never ended on a figure the policy does not hold hard.
    pub fn hard_bytes(&self) -> Option<u64> {
        [Origin::Negotiated, Origin::Configured, Origin::Learned]
            .into_iter()
            .filter(|&origin| self.policy.treatment(origin).enforcement == Enforcement::Hard)
            .filter_map(|origin| self.figure(origin))
            .min()
    }

    /// The figure a renewal is measured against, in bytes, and where it comes from: by precedence
    /// negotiated, else configured, else learned.
    pub fn renewal_basis(&self) -> Option<(u64, Origin)> {
        let negotiated = self.negotiated.map(|bytes| (bytes, Origin::Negotiated));
        let configured = self.configured.map(|bytes| (bytes, Origin::Configured));
        let learned = self.learned.map(|bytes| (bytes, Origin::Learned));
        negotiated.or(configured).or(learned)
    }

    /// The volume, in bytes per direction, at which the SA in use is to be renewed, and the origin
    /// of the figure it is taken from: the [`renew_at`](Treatment::renew_at) share the policy gives
    /// that origin, of the [`renewal_basis`](Self::renewal_basis).
    pub fn renewal_point(&self) -> Option<(u64, Origin)> {
        self.renewal_basis().map(|(bytes, origin)| (self.policy.treatment(origin).renew_at.of(bytes), origin))
    }

    /// Whether the SA in use, having moved `used` (`(rx, tx)`, its own counts), is to be renewed:
    /// either direction at the [`renewal_point`](Self::renewal_point) or past it, each direction on
    /// its own and never the sum (an IPsec SA is one direction). `used` of `None` (no reading)
    /// means the volume says nothing, not that it is zero.
    pub fn renewal_signal(&self, used: Option<(u64, u64)>) -> Option<RenewalSignal> {
        let (rx, tx) = used?;
        let (at_bytes, origin) = self.renewal_point()?;
        (rx >= at_bytes || tx >= at_bytes).then_some(RenewalSignal { origin, at_bytes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::Rounding;
    use Origin::{Configured, Learned, Negotiated};

    const HARD_AT_EIGHT_TENTHS: Treatment =
        Treatment { enforcement: Enforcement::Hard, renew_at: Share::new(8, 10, Rounding::Down) };
    const ADVISORY_AT_HALF: Treatment =
        Treatment { enforcement: Enforcement::Advisory, renew_at: Share::new(1, 2, Rounding::Up) };

    /// The policy of a consumer that holds only a negotiated figure hard, renewing at 8/10 of it,
    /// and renews at half of a configured or learned one.
    const POLICY: VolumePolicy =
        VolumePolicy { negotiated: HARD_AT_EIGHT_TENTHS, configured: ADVISORY_AT_HALF, learned: ADVISORY_AT_HALF };

    fn none() -> VolumeLimits {
        VolumeLimits::new(POLICY)
    }

    #[test]
    fn the_hard_limit_is_the_negotiated_figure_only_whatever_else_is_present() {
        let configured = none().with(Configured, Some(5_120_000)).with(Learned, Some(4_000_000));
        assert_eq!(configured.hard_bytes(), None, "a configured and a learned figure: no hard limit");
        assert_eq!(none().with(Learned, Some(4_000_000)).hard_bytes(), None, "a learned figure alone: no hard limit");
        let negotiated = none().with(Negotiated, Some(50_120_000)).with(Configured, Some(5_120_000)).with(Learned, Some(4_000_000));
        assert_eq!(negotiated.hard_bytes(), Some(50_120_000), "the grant, never the smaller advisory figures");
        assert_eq!(none().hard_bytes(), None);
    }

    #[test]
    fn the_renewal_basis_is_the_negotiated_figure_else_the_configured_one_else_the_learned_one() {
        let mut l = none();
        assert_eq!(l.renewal_basis(), None);
        l.set(Learned, Some(4_000_000));
        assert_eq!(l.renewal_basis(), Some((4_000_000, Learned)));
        let l = l.with(Configured, Some(5_120_000));
        assert_eq!(l.renewal_basis(), Some((5_120_000, Configured)), "a learned figure never replaces a configured one, even a lower one");
        let l = l.with(Negotiated, Some(9_000_000));
        assert_eq!(l.renewal_basis(), Some((9_000_000, Negotiated)), "a grant comes first, even a larger one");
        let l = l.with(Negotiated, None);
        assert_eq!(l.renewal_basis(), Some((5_120_000, Configured)), "a figure removed: the next one again");
    }

    #[test]
    fn the_renewal_point_is_the_share_the_policy_gives_the_origin_of_the_basis() {
        let configured = none().with(Configured, Some(5_120_000));
        assert_eq!(configured.renewal_point(), Some((2_560_000, Configured)), "configured: half");
        let learned = none().with(Learned, Some(5_120_000));
        assert_eq!(learned.renewal_point(), Some((2_560_000, Learned)), "learned: half");
        let negotiated = none().with(Negotiated, Some(5_120_000)).with(Configured, Some(5_120_000));
        assert_eq!(negotiated.renewal_point(), Some((4_096_000, Negotiated)), "negotiated: 8/10, whatever else is present");
        assert_eq!(none().with(Learned, Some(1001)).renewal_point(), Some((501, Learned)), "half rounded up");
        assert_eq!(none().with(Negotiated, Some(1001)).renewal_point(), Some((800, Negotiated)), "8/10 rounded down");
        assert_eq!(none().renewal_point(), None);
    }

    #[test]
    fn the_renewal_point_of_a_huge_basis_saturates_and_never_exceeds_the_basis() {
        let huge = none().with(Negotiated, Some(u64::MAX));
        assert_eq!(huge.renewal_point(), Some((u64::MAX / 10, Negotiated)), "saturated before dividing: early, never wrapped");
        let largest_kb = none().with(Learned, Some(4_294_967_295_000));
        assert_eq!(largest_kb.renewal_point(), Some((2_147_483_647_500, Learned)), "the largest KB figure: exact");
        let largest = none().with(Configured, Some(u64::MAX));
        assert_eq!(largest.renewal_point(), Some((u64::MAX / 2 + 1, Configured)), "half, rounded up, never past it");
    }

    #[test]
    fn a_zero_figure_is_kept_as_given() {
        let granted_zero = none().with(Negotiated, Some(0));
        assert_eq!(granted_zero.figure(Negotiated), Some(0));
        assert_eq!(granted_zero.hard_bytes(), Some(0), "what was negotiated, as it was");
        assert_eq!(granted_zero.renewal_signal(Some((0, 0))), Some(RenewalSignal { origin: Negotiated, at_bytes: 0 }));
        let configured_zero = none().with(Configured, Some(0));
        assert_eq!(configured_zero.renewal_basis(), Some((0, Configured)), "the caller decides whether zero is none");
        assert_eq!(configured_zero.renewal_signal(Some((0, 0))), Some(RenewalSignal { origin: Configured, at_bytes: 0 }));
    }

    #[test]
    fn a_signal_comes_when_either_direction_reaches_the_point_on_its_own_and_names_its_origin() {
        let l = none().with(Learned, Some(5_120_000));
        let at = 2_560_000;
        assert_eq!(l.renewal_signal(Some((at - 1, at - 1))), None, "each direction a byte short; their sum is no reading");
        let rx = l.renewal_signal(Some((at, 0))).unwrap();
        assert_eq!((rx.origin, rx.at_bytes), (Learned, at), "inbound at the point, to the byte");
        assert_eq!(l.renewal_signal(Some((0, at))), Some(rx), "outbound at the point");
        assert_eq!(l.renewal_signal(Some((0, at + 1))), Some(rx), "outbound past it");
        assert_eq!(l.renewal_signal(Some((at + 1, 0))), Some(rx), "inbound past it");
        let configured = none().with(Configured, Some(5_120_000));
        assert_eq!(configured.renewal_signal(Some((at - 1, at - 1))), None);
        assert_eq!(configured.renewal_signal(Some((at, 0))).map(|s| s.origin), Some(Configured));
        let negotiated = none().with(Negotiated, Some(5_120_000));
        assert_eq!(negotiated.renewal_signal(Some((at, 0))), None, "a grant's point is its 8/10, not half");
        assert_eq!(negotiated.renewal_signal(Some((4_095_999, 4_095_999))), None);
        assert_eq!(negotiated.renewal_signal(Some((0, 4_096_000))).map(|s| s.origin), Some(Negotiated));
    }

    #[test]
    fn no_reading_and_no_figure_are_no_signal() {
        let l = none().with(Learned, Some(5_120_000));
        assert_eq!(l.renewal_signal(None), None, "no reading says nothing, it is not zero");
        assert_eq!(none().renewal_signal(Some((u64::MAX, u64::MAX))), None, "no figure: nothing to measure against");
    }

    #[test]
    fn learning_changes_the_learned_figure_and_nothing_else() {
        // The shape is the guarantee: the figure alone goes in, so no count, age or generation can be reset by it.
        let _: fn(&mut VolumeLimits, Origin, Option<u64>) = VolumeLimits::set;
        let before = none().with(Negotiated, Some(7_000_000)).with(Configured, Some(5_120_000));
        let mut after = before;
        after.set(Learned, Some(4_000_000));
        assert_eq!(after, VolumeLimits { learned: Some(4_000_000), ..before });
        after.set(Learned, Some(3_000_000));
        assert_eq!(after, VolumeLimits { learned: Some(3_000_000), ..before }, "lowered: still only the learned field");
        assert_eq!((after.hard_bytes(), after.renewal_basis()), (before.hard_bytes(), before.renewal_basis()), "and what the others decide is the same");
        after.set(Learned, None);
        assert_eq!(after, before, "removed: as it was");
    }

    #[test]
    fn usage_already_past_a_new_point_is_signalled_at_once_on_the_counts_already_there() {
        let used = Some((4_500_000, 10_000));
        let mut l = none();
        assert_eq!(l.renewal_signal(used), None, "no figure yet: no signal");
        l.set(Learned, Some(5_120_000));
        assert_eq!(l.renewal_signal(used), Some(RenewalSignal { origin: Learned, at_bytes: 2_560_000 }));
    }

    #[test]
    fn every_treatment_of_the_policy_is_read() {
        let learned_hard = VolumePolicy { learned: HARD_AT_EIGHT_TENTHS, ..POLICY };
        let l = VolumeLimits::new(learned_hard).with(Configured, Some(5_120_000)).with(Learned, Some(4_000_000));
        assert_eq!(l.hard_bytes(), Some(4_000_000), "a learned figure the policy holds hard is the hard limit");
        assert_eq!(l.renewal_point(), Some((2_560_000, Configured)), "while the basis is still the configured one, at its share");
        let learned_alone = VolumeLimits::new(learned_hard).with(Learned, Some(4_000_000));
        assert_eq!(learned_alone.renewal_point(), Some((3_200_000, Learned)), "8/10 of it, the share the policy gives it");

        let all_hard = VolumePolicy { negotiated: HARD_AT_EIGHT_TENTHS, configured: HARD_AT_EIGHT_TENTHS, learned: HARD_AT_EIGHT_TENTHS };
        let two = VolumeLimits::new(all_hard).with(Negotiated, Some(9_000_000)).with(Configured, Some(5_120_000));
        assert_eq!(two.hard_bytes(), Some(5_120_000), "two hard figures: the smaller");
        assert_eq!(two.renewal_basis(), Some((9_000_000, Negotiated)), "the basis keeps its precedence");
        let three = two.with(Learned, Some(6_000_000));
        assert_eq!(three.hard_bytes(), Some(5_120_000));
        assert_eq!(three.with(Learned, Some(1)).hard_bytes(), Some(1));

        let none_hard = VolumePolicy { negotiated: ADVISORY_AT_HALF, ..POLICY };
        let advisory_grant = VolumeLimits::new(none_hard).with(Negotiated, Some(5_120_000));
        assert_eq!(advisory_grant.hard_bytes(), None, "a negotiated figure the policy does not hold hard is none");
        assert_eq!(advisory_grant.renewal_point(), Some((2_560_000, Negotiated)));

        let nine_tenths = VolumePolicy {
            configured: Treatment { enforcement: Enforcement::Advisory, renew_at: Share::new(9, 10, Rounding::Down) },
            ..POLICY
        };
        assert_eq!(VolumeLimits::new(nine_tenths).with(Configured, Some(5_120_000)).renewal_point(), Some((4_608_000, Configured)));
        assert_eq!(VolumeLimits::new(nine_tenths).policy(), nine_tenths);
        assert_eq!(nine_tenths.treatment(Configured).renew_at, Share::new(9, 10, Rounding::Down));
        assert_eq!(nine_tenths.treatment(Learned), ADVISORY_AT_HALF);
        assert_eq!(nine_tenths.treatment(Negotiated), HARD_AT_EIGHT_TENTHS);
    }

    #[test]
    fn each_figure_is_kept_apart_and_none_removes_it() {
        let l = none().with(Negotiated, Some(1)).with(Configured, Some(2)).with(Learned, Some(3));
        assert_eq!((l.figure(Negotiated), l.figure(Configured), l.figure(Learned)), (Some(1), Some(2), Some(3)));
        let l = l.with(Configured, None);
        assert_eq!((l.figure(Negotiated), l.figure(Configured), l.figure(Learned)), (Some(1), None, Some(3)));
        let l = l.with(Negotiated, Some(10));
        assert_eq!((l.figure(Negotiated), l.figure(Configured), l.figure(Learned)), (Some(10), None, Some(3)), "replaced, not added to");
        assert_eq!(VolumeLimits::new(POLICY), none());
    }
}
