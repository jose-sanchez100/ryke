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
//! - A renewal is measured against one figure ([`VolumeLimits::renewal_basis`]). The candidates are
//!   the figure chosen by precedence -- negotiated, else configured, else learned, whatever its
//!   enforcement -- and every figure present whose origin the policy holds hard; each one's renewal
//!   point is its own origin's share of it, and the one whose point is the lowest is measured
//!   against (on a tie, the one earlier in precedence). So a renewal point is never above the
//!   renewal point of any hard limit, hence never above the hard limit itself: an SA is not ended
//!   before its renewal is asked for. An advisory figure other than the one chosen by precedence is
//!   never a candidate: a learned figure never replaces a configured one, even a lower one.
//! - Under a policy whose only hard origin is [`Origin::Negotiated`], the figure measured against
//!   is always the one chosen by precedence: a negotiated figure, when present, is both that figure
//!   and the only hard one; when it is absent, no figure is hard.
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

    /// The figure a renewal is measured against, in bytes, and where it comes from. The candidates
    /// are the figure chosen by precedence (negotiated, else configured, else learned, whatever its
    /// enforcement) and every figure present whose origin the policy holds
    /// [`Enforcement::Hard`]; the one returned is the candidate whose renewal point -- the
    /// [`renew_at`](Treatment::renew_at) share its own origin is given -- is the lowest, and on a
    /// tie the one earlier in precedence.
    ///
    /// So a hard limit lower in precedence governs only when its renewal point comes first, and an
    /// advisory figure lower in precedence never does, even a smaller one. Under a policy that holds
    /// only [`Origin::Negotiated`] hard, this is the figure chosen by precedence, always.
    pub fn renewal_basis(&self) -> Option<(u64, Origin)> {
        self.governing().map(|(bytes, _, origin)| (bytes, origin))
    }

    /// The volume, in bytes per direction, at which the SA in use is to be renewed, and the origin
    /// of the figure it is taken from: the [`renew_at`](Treatment::renew_at) share the policy gives
    /// that origin, of the [`renewal_basis`](Self::renewal_basis) -- the lowest renewal point of the
    /// candidates it names. Never above the renewal point of any hard limit present, so (a share
    /// being never more than the whole) never above [`hard_bytes`](Self::hard_bytes).
    pub fn renewal_point(&self) -> Option<(u64, Origin)> {
        self.governing().map(|(_, at_bytes, origin)| (at_bytes, origin))
    }

    /// The governing figure, its renewal point and its origin (see
    /// [`renewal_basis`](Self::renewal_basis)): of the figures present in precedence order, the
    /// first one and every hard one, the lowest point; `min_by_key` keeps the first of equal ones,
    /// which is the one earlier in precedence.
    fn governing(&self) -> Option<(u64, u64, Origin)> {
        [Origin::Negotiated, Origin::Configured, Origin::Learned]
            .into_iter()
            .filter_map(|origin| self.figure(origin).map(|bytes| (bytes, origin)))
            .enumerate()
            .filter(|&(rank, (_, origin))| rank == 0 || self.policy.treatment(origin).enforcement == Enforcement::Hard)
            .map(|(_, (bytes, origin))| (bytes, self.policy.treatment(origin).renew_at.of(bytes), origin))
            .min_by_key(|&(_, at_bytes, _)| at_bytes)
    }

    /// Whether the SA in use, having moved `used` (`(rx, tx)`, its own counts), is to be renewed:
    /// either direction at the [`renewal_point`](Self::renewal_point) (the governing figure's, which
    /// the signal names) or past it, each direction on
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

    /// In the historical arithmetic the consumer's figures were pinned with: a test below pins it at
    /// an amount whose product overflows a `u64`.
    const HARD_AT_EIGHT_TENTHS: Treatment =
        Treatment { enforcement: Enforcement::Hard, renew_at: Share::saturating_u64(8, 10, Rounding::Down) };
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
        let exact = VolumePolicy {
            negotiated: Treatment { enforcement: Enforcement::Hard, renew_at: Share::new(8, 10, Rounding::Down) },
            ..POLICY
        };
        let huge_exact = VolumeLimits::new(exact).with(Negotiated, Some(u64::MAX));
        assert_eq!(huge_exact.renewal_point(), Some((14_757_395_258_967_641_292, Negotiated)), "the exact share, rounded down");
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
        assert_eq!(two.renewal_basis(), Some((5_120_000, Configured)), "the hard figure whose renewal point comes first");
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

    const ALL_HARD: VolumePolicy =
        VolumePolicy { negotiated: HARD_AT_EIGHT_TENTHS, configured: HARD_AT_EIGHT_TENTHS, learned: HARD_AT_EIGHT_TENTHS };
    const HARD_AT_HALF: Treatment = Treatment { enforcement: Enforcement::Hard, renew_at: Share::new(1, 2, Rounding::Up) };

    /// Every policy over `shares`: each origin hard or advisory, at each of the shares.
    fn policies(shares: &[Share]) -> Vec<VolumePolicy> {
        let mut treatments = Vec::new();
        for enforcement in [Enforcement::Hard, Enforcement::Advisory] {
            treatments.extend(shares.iter().map(|&renew_at| Treatment { enforcement, renew_at }));
        }
        let mut all = Vec::new();
        for &negotiated in &treatments {
            for &configured in &treatments {
                for &learned in &treatments {
                    all.push(VolumePolicy { negotiated, configured, learned });
                }
            }
        }
        all
    }

    /// Every combination of `values` (and of no figure) for the three origins, under `policy`.
    fn combinations(policy: VolumePolicy, values: &[u64]) -> Vec<VolumeLimits> {
        let figures: Vec<Option<u64>> = std::iter::once(None).chain(values.iter().copied().map(Some)).collect();
        let mut all = Vec::new();
        for &n in &figures {
            for &c in &figures {
                for &l in &figures {
                    all.push(VolumeLimits::new(policy).with(Negotiated, n).with(Configured, c).with(Learned, l));
                }
            }
        }
        all
    }

    #[test]
    fn a_hard_limit_lower_in_precedence_but_more_restrictive_governs_the_renewal() {
        // The case the precedence alone got wrong: a hard limit of 1 000 bytes, renewed at 8 000.
        let l = VolumeLimits::new(ALL_HARD).with(Negotiated, Some(10_000)).with(Configured, Some(1_000));
        assert_eq!(l.hard_bytes(), Some(1_000));
        assert_eq!(l.renewal_basis(), Some((1_000, Configured)));
        assert_eq!(l.renewal_point(), Some((800, Configured)), "renewed before the hard limit it would end at");
        let learned = VolumeLimits::new(ALL_HARD).with(Negotiated, Some(10_000)).with(Configured, Some(5_000)).with(Learned, Some(100));
        assert_eq!(learned.renewal_point(), Some((80, Learned)), "the lowest in precedence, when it is hard and comes first");
        assert_eq!(learned.renewal_basis(), Some((100, Learned)));
        // A larger hard figure whose own share puts its renewal point first governs too.
        let shares = VolumePolicy { configured: HARD_AT_HALF, ..ALL_HARD };
        let l = VolumeLimits::new(shares).with(Negotiated, Some(1_000)).with(Configured, Some(1_200));
        assert_eq!(l.hard_bytes(), Some(1_000));
        assert_eq!(l.renewal_point(), Some((600, Configured)), "half of 1 200 comes before 8/10 of 1 000");
        assert_eq!(l.renewal_basis(), Some((1_200, Configured)));
    }

    #[test]
    fn with_two_or_three_hard_limits_the_lowest_renewal_point_governs_in_every_order_of_size() {
        let origins = [Negotiated, Configured, Learned];
        // Two hard figures, every pair of origins, either one the smaller.
        for (i, &first) in origins.iter().enumerate() {
            for &second in &origins[i + 1..] {
                for (a, b) in [(1_000, 2_000), (2_000, 1_000)] {
                    let l = VolumeLimits::new(ALL_HARD).with(first, Some(a)).with(second, Some(b));
                    let (smaller, origin) = if a < b { (a, first) } else { (b, second) };
                    assert_eq!(l.hard_bytes(), Some(smaller), "{first:?} {a}, {second:?} {b}");
                    assert_eq!(l.renewal_basis(), Some((smaller, origin)), "{first:?} {a}, {second:?} {b}");
                    assert_eq!(l.renewal_point(), Some((smaller * 8 / 10, origin)), "{first:?} {a}, {second:?} {b}");
                }
            }
        }
        // Three hard figures, every order of size.
        for (n, c, l) in [(1, 2, 3), (1, 3, 2), (2, 1, 3), (2, 3, 1), (3, 1, 2), (3, 2, 1)] {
            let limits = VolumeLimits::new(ALL_HARD)
                .with(Negotiated, Some(n * 1_000))
                .with(Configured, Some(c * 1_000))
                .with(Learned, Some(l * 1_000));
            let origin = [(n, Negotiated), (c, Configured), (l, Learned)].into_iter().min_by_key(|&(size, _)| size).unwrap().1;
            assert_eq!(limits.hard_bytes(), Some(1_000), "{n} {c} {l}");
            assert_eq!(limits.renewal_basis(), Some((1_000, origin)), "{n} {c} {l}");
            assert_eq!(limits.renewal_point(), Some((800, origin)), "{n} {c} {l}");
        }
    }

    #[test]
    fn a_hard_limit_less_restrictive_than_the_figure_by_precedence_leaves_that_figure_governing() {
        let l = VolumeLimits::new(ALL_HARD).with(Negotiated, Some(1_000)).with(Configured, Some(10_000)).with(Learned, Some(5_000));
        assert_eq!(l.renewal_basis(), Some((1_000, Negotiated)));
        assert_eq!(l.renewal_point(), Some((800, Negotiated)));
        // The figure by precedence governs even when it is advisory, as long as its point comes first.
        let advisory_grant = VolumePolicy { negotiated: ADVISORY_AT_HALF, ..ALL_HARD };
        let l = VolumeLimits::new(advisory_grant).with(Negotiated, Some(1_000)).with(Configured, Some(10_000));
        assert_eq!(l.hard_bytes(), Some(10_000));
        assert_eq!(l.renewal_basis(), Some((1_000, Negotiated)));
        assert_eq!(l.renewal_point(), Some((500, Negotiated)));
    }

    #[test]
    fn on_a_tie_of_renewal_points_the_figure_earlier_in_precedence_governs() {
        let shares = VolumePolicy { configured: HARD_AT_HALF, ..ALL_HARD };
        let l = VolumeLimits::new(shares).with(Negotiated, Some(1_000)).with(Configured, Some(1_600));
        assert_eq!(l.renewal_point(), Some((800, Negotiated)), "8/10 of 1 000 and half of 1 600");
        assert_eq!(l.renewal_basis(), Some((1_000, Negotiated)));
        let lower = VolumePolicy { learned: HARD_AT_HALF, ..ALL_HARD };
        let l = VolumeLimits::new(lower).with(Configured, Some(1_000)).with(Learned, Some(1_600));
        assert_eq!(l.renewal_point(), Some((800, Configured)));
        assert_eq!(l.renewal_basis(), Some((1_000, Configured)));
        let same = VolumeLimits::new(ALL_HARD).with(Negotiated, Some(1_000)).with(Configured, Some(1_000)).with(Learned, Some(1_000));
        assert_eq!(same.renewal_basis(), Some((1_000, Negotiated)), "equal figures at equal shares");
    }

    #[test]
    fn an_advisory_figure_lower_in_precedence_is_never_a_candidate_even_the_smallest() {
        let l = none().with(Negotiated, Some(10_000)).with(Configured, Some(1)).with(Learned, Some(1));
        assert_eq!(l.renewal_point(), Some((8_000, Negotiated)));
        let learned_advisory = VolumePolicy { learned: ADVISORY_AT_HALF, ..ALL_HARD };
        let l = VolumeLimits::new(learned_advisory).with(Negotiated, Some(10_000)).with(Configured, Some(5_000)).with(Learned, Some(1));
        assert_eq!(l.renewal_point(), Some((4_000, Configured)), "the hard one that comes first, never the advisory one");
        assert_eq!(l.renewal_basis(), Some((5_000, Configured)));
        let configured = none().with(Configured, Some(5_120_000)).with(Learned, Some(1));
        assert_eq!(configured.renewal_point(), Some((2_560_000, Configured)), "a learned figure never replaces a configured one");
    }

    #[test]
    fn a_governing_hard_limit_is_signalled_by_either_direction_on_its_own_to_the_byte() {
        let l = VolumeLimits::new(ALL_HARD).with(Negotiated, Some(10_000)).with(Configured, Some(1_000));
        let signal = Some(RenewalSignal { origin: Configured, at_bytes: 800 });
        assert_eq!(l.renewal_signal(Some((799, 799))), None, "each direction a byte short");
        assert_eq!(l.renewal_signal(Some((400, 400))), None, "their sum at the point is no reading");
        assert_eq!(l.renewal_signal(Some((799, 0))), None, "inbound a byte short");
        assert_eq!(l.renewal_signal(Some((800, 0))), signal, "inbound at the point");
        assert_eq!(l.renewal_signal(Some((801, 0))), signal, "inbound past it");
        assert_eq!(l.renewal_signal(Some((0, 799))), None, "outbound a byte short");
        assert_eq!(l.renewal_signal(Some((0, 800))), signal, "outbound at the point");
        assert_eq!(l.renewal_signal(Some((0, 801))), signal, "outbound past it");
        assert_eq!(l.renewal_signal(None), None, "no reading: no signal");
    }

    #[test]
    fn the_renewal_point_never_exceeds_the_point_of_any_hard_limit_nor_the_hard_limit() {
        let shares = [
            Share::new(0, 1, Rounding::Down),
            Share::new(1, 2, Rounding::Up),
            Share::new(8, 10, Rounding::Down),
            Share::new(1, 1, Rounding::Down),
        ];
        let origins = [Negotiated, Configured, Learned];
        for policy in policies(&shares) {
            for l in combinations(policy, &[0, 1, 999, 1_000, 1_001]) {
                let first = origins.into_iter().find(|&origin| l.figure(origin).is_some());
                let Some((at, origin)) = l.renewal_point() else {
                    assert_eq!(first, None, "{l:?}");
                    assert_eq!(l.hard_bytes(), None, "{l:?}");
                    continue;
                };
                let (basis, basis_origin) = l.renewal_basis().unwrap();
                assert_eq!(basis_origin, origin, "{l:?}");
                assert_eq!(policy.treatment(origin).renew_at.of(basis), at, "{l:?}");
                let hard = policy.treatment(origin).enforcement == Enforcement::Hard;
                assert!(Some(origin) == first || hard, "{l:?}: an advisory figure other than the first governs");
                let first = first.unwrap();
                assert!(at <= policy.treatment(first).renew_at.of(l.figure(first).unwrap()), "{l:?}");
                for other in origins.into_iter().filter(|&o| policy.treatment(o).enforcement == Enforcement::Hard) {
                    if let Some(bytes) = l.figure(other) {
                        assert!(at <= policy.treatment(other).renew_at.of(bytes), "{l:?}: above {other:?}'s point");
                    }
                }
                if let Some(hard_bytes) = l.hard_bytes() {
                    assert!(at <= hard_bytes, "{l:?}: renewal point {at} above the hard limit {hard_bytes}");
                }
            }
        }
    }

    #[test]
    fn with_no_figure_or_only_a_hard_one_removed_the_rule_falls_back_as_figures_go() {
        let l = VolumeLimits::new(ALL_HARD);
        assert_eq!((l.hard_bytes(), l.renewal_basis(), l.renewal_point()), (None, None, None));
        assert_eq!(l.renewal_signal(Some((u64::MAX, u64::MAX))), None);
        let both = l.with(Negotiated, Some(10_000)).with(Configured, Some(1_000));
        assert_eq!(both.with(Configured, None).renewal_point(), Some((8_000, Negotiated)), "the hard figure removed: the precedence one again");
        assert_eq!(both.with(Negotiated, None).renewal_point(), Some((800, Configured)));
    }

    #[test]
    fn a_zero_hard_figure_governs_at_zero() {
        let l = VolumeLimits::new(ALL_HARD).with(Negotiated, Some(10_000)).with(Configured, Some(0));
        assert_eq!(l.hard_bytes(), Some(0));
        assert_eq!(l.renewal_point(), Some((0, Configured)));
        assert_eq!(l.renewal_signal(Some((0, 0))), Some(RenewalSignal { origin: Configured, at_bytes: 0 }));
        let learned = VolumeLimits::new(ALL_HARD).with(Configured, Some(1_000)).with(Learned, Some(0));
        assert_eq!(learned.renewal_basis(), Some((0, Learned)));
        let advisory = none().with(Negotiated, Some(10_000)).with(Configured, Some(0));
        assert_eq!(advisory.renewal_point(), Some((8_000, Negotiated)), "an advisory zero lower in precedence is not a candidate");
    }

    #[test]
    fn under_a_policy_holding_only_the_negotiated_figure_hard_nothing_differs_from_precedence_alone() {
        // The rule before hard limits were candidates, verbatim, kept here as the reference.
        fn old_renewal_basis(l: &VolumeLimits) -> Option<(u64, Origin)> {
            let negotiated = l.negotiated.map(|bytes| (bytes, Origin::Negotiated));
            let configured = l.configured.map(|bytes| (bytes, Origin::Configured));
            let learned = l.learned.map(|bytes| (bytes, Origin::Learned));
            negotiated.or(configured).or(learned)
        }
        fn old_renewal_point(l: &VolumeLimits) -> Option<(u64, Origin)> {
            old_renewal_basis(l).map(|(bytes, origin)| (l.policy.treatment(origin).renew_at.of(bytes), origin))
        }
        fn old_renewal_signal(l: &VolumeLimits, used: Option<(u64, u64)>) -> Option<RenewalSignal> {
            let (rx, tx) = used?;
            let (at_bytes, origin) = old_renewal_point(l)?;
            (rx >= at_bytes || tx >= at_bytes).then_some(RenewalSignal { origin, at_bytes })
        }
        let shares = [Share::new(8, 10, Rounding::Down), Share::new(1, 2, Rounding::Up), Share::new(1, 1, Rounding::Down)];
        let values = [0, 1, 999, 1_000, 1_001, 5_120_000, 4_294_967_295_000, u64::MAX / 8 + 1, u64::MAX];
        let readings = [None, Some((0, 0)), Some((799, 0)), Some((0, 800)), Some((2_560_000, 0)), Some((u64::MAX, u64::MAX))];
        let only_negotiated_hard = policies(&shares).into_iter().filter(|policy| {
            [Negotiated, Configured, Learned]
                .into_iter()
                .all(|origin| (policy.treatment(origin).enforcement == Enforcement::Hard) == (origin == Negotiated))
        });
        let mut compared = 0;
        for policy in only_negotiated_hard {
            for l in combinations(policy, &values) {
                assert_eq!(l.renewal_basis(), old_renewal_basis(&l), "{l:?}");
                assert_eq!(l.renewal_point(), old_renewal_point(&l), "{l:?}");
                for used in readings {
                    assert_eq!(l.renewal_signal(used), old_renewal_signal(&l, used), "{l:?} {used:?}");
                }
                compared += 1;
            }
        }
        assert_eq!(compared, 27 * 1000, "every policy of that shape, every presence and value of the three figures");
    }
}
