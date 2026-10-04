//! Lifecycle logic over the protocol sessions: when an SA is to be renewed, how far apart renewal
//! attempts are kept, and what a family of SAs has to remember between them.
//!
//! Everything here is pure and driven by the caller. It owns no socket, thread or clock, and sees no
//! key material: time comes in as an argument (an [`Instant`](std::time::Instant) or a
//! [`Duration`](std::time::Duration) the caller read), and so do the counts of what an SA has moved.
//! The protocol exchanges themselves stay in [`crate::ikev1`] and [`crate::ikev2`], with their
//! existing blocking APIs; what is here only says *when* the caller should start one of them, and
//! keeps the facts the caller reports of them.
//!
//! What it holds today:
//!
//! - [`limits`]: the volume figures of an SA by where each comes from, which of them is a hard
//!   limit under the consumer's policy, and the renewal one may ask for.
//! - [`machine`]: one family's renewals as a machine of events and actions -- a renewal of ours by
//!   volume, the switches deferred as the responder, the peer's rekeys served -- over its record,
//!   in the order a consumer carries them out, its data plane and its protocol session its own.
//! - [`renewal`]: the record of one family's renewals -- its last attempt, a rekey negotiated and
//!   not yet resolved, a switch of outbound deferred until the peer has the new SA, the SAs it
//!   retired and where their Deletes stand -- and an SA's clock by age. It records facts and
//!   answers queries; it decides nothing.
//! - [`spacing`]: how far apart renewal attempts of one SA are kept, and when the next one may
//!   start.
//! - [`timing`]: when an SA is to be renewed by its age and by its volume, where it stands against
//!   its limits, and how soon a failed attempt is tried again.
//!
//! Every figure a policy is made of -- a share of a lifetime, a spacing, a reference rate, which
//! origins of a volume figure are hard limits -- is the consumer's: it is passed in as a parameter,
//! and no type here has a default for one. What is here is the arithmetic those figures go through,
//! the same for every consumer.

pub mod limits;
pub mod machine;
pub mod renewal;
pub mod spacing;
pub mod timing;

/// Which way [`Share::of`] rounds when the share of an amount is not a whole number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rounding {
    /// Toward zero: the point is never later than the exact share.
    Down,
    /// Away from zero: the point is never earlier than the exact share.
    Up,
}

/// A fraction `num / den` of an amount, with its [`Rounding`]: where in a lifetime or a volume
/// something is to happen.
///
/// A share also says which arithmetic [`of`](Self::of) uses, fixed by the constructor it was made
/// with; two shares that differ only in that are not equal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Share {
    num: u64,
    den: u64,
    rounding: Rounding,
    arithmetic: Arithmetic,
}

/// Which arithmetic a [`Share`] is computed with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Arithmetic {
    /// [`Share::new`]'s: the product taken in `u128`, the exact share.
    Exact,
    /// [`Share::saturating_u64`]'s: the product taken in `u64`, saturating.
    SaturatingU64,
}

impl Share {
    /// The share `num / den` of an amount, rounded as `rounding` says, exactly: [`of`](Self::of)
    /// takes the product `amount * num` in a `u128`, where it always fits, and divides it by `den`,
    /// rounding down (the floor) or up (the ceiling). Equivalent fractions give equal results for
    /// every amount, and the result is always between `0` and `amount`.
    ///
    /// Panics if `den == 0` (a share of nothing) or `num > den` (more than the whole); in a `const`,
    /// either is a compile error.
    pub const fn new(num: u64, den: u64, rounding: Rounding) -> Self {
        Self::checked(num, den, rounding, Arithmetic::Exact)
    }

    /// The share `num / den` of an amount, rounded as `rounding` says, in the historical
    /// arithmetic: compatibility arithmetic, for a consumer whose figures were validated with it. New
    /// consumers use [`new`](Self::new).
    ///
    /// The product is taken in a `u64` and saturates:
    ///
    /// - [`Rounding::Down`]: `amount.saturating_mul(num) / den`. A product that would overflow
    ///   saturates, which gives an *earlier* point than the exact share -- never a wrapped, small one.
    /// - [`Rounding::Up`]: `amount - amount.saturating_mul(den - num) / den`. Here the product is the
    ///   part taken off `amount`: one that would overflow saturates, so less is taken off than
    ///   exactly would be, which gives a *later* point than the exact share -- still never past
    ///   `amount`, and never a wrapped one. (With `den - num == 1`, as for a half, the product
    ///   cannot overflow.)
    ///
    /// The result is between `0` and `amount`, and it is the exact share -- what [`new`](Self::new)
    /// gives -- whenever the product fits a `u64`: it differs only when `amount * num` (rounding
    /// down) or `amount * (den - num)` (rounding up) exceeds `u64::MAX`. There it is not the exact
    /// share, and equivalent fractions can disagree: `1/1` of 1000 is 1000, `u64::MAX/u64::MAX` of
    /// 1000 is 1.
    ///
    /// Panics as [`new`](Self::new) does.
    pub const fn saturating_u64(num: u64, den: u64, rounding: Rounding) -> Self {
        Self::checked(num, den, rounding, Arithmetic::SaturatingU64)
    }

    const fn checked(num: u64, den: u64, rounding: Rounding, arithmetic: Arithmetic) -> Self {
        assert!(den > 0, "a share needs a non-zero denominator");
        assert!(num <= den, "a share is never more than the whole");
        Self { num, den, rounding, arithmetic }
    }

    /// This share of `amount`, in integers, with no overflow and never more than `amount`, in the
    /// arithmetic of the constructor the share was made with: [`new`](Self::new)'s exact one,
    /// `amount * num / den` rounded down or up, or [`saturating_u64`](Self::saturating_u64)'s
    /// historical one.
    pub const fn of(self, amount: u64) -> u64 {
        match self.arithmetic {
            Arithmetic::Exact => self.exact_of(amount),
            Arithmetic::SaturatingU64 => self.saturating_of(amount),
        }
    }

    /// [`Share::new`]'s arithmetic. The product of two `u64`s always fits a `u128`, and with
    /// `num <= den` the quotient, either way rounded, is at most `amount`, so it fits a `u64` again.
    const fn exact_of(self, amount: u64) -> u64 {
        let product = amount as u128 * self.num as u128;
        let den = self.den as u128;
        (match self.rounding {
            Rounding::Down => product / den,
            Rounding::Up => product.div_ceil(den),
        }) as u64
    }

    /// [`Share::saturating_u64`]'s arithmetic.
    const fn saturating_of(self, amount: u64) -> u64 {
        match self.rounding {
            Rounding::Down => amount.saturating_mul(self.num) / self.den,
            Rounding::Up => amount - amount.saturating_mul(self.den - self.num) / self.den,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EIGHT_TENTHS: Share = Share::new(8, 10, Rounding::Down);
    const HALF_UP: Share = Share::new(1, 2, Rounding::Up);

    /// Amounts around the places a share's arithmetic could go wrong: small and odd ones, where the
    /// rounding shows, and the ones where a product starts to overflow.
    fn spread() -> Vec<u64> {
        let mut amounts: Vec<u64> = (0..=10_000).collect();
        amounts.extend([
            5_120_000,
            50_120_000,
            4_294_967_295_000,
            u64::MAX / 10 - 1,
            u64::MAX / 10,
            u64::MAX / 10 + 1,
            u64::MAX / 8 - 1,
            u64::MAX / 8,
            u64::MAX / 8 + 1,
            u64::MAX / 2,
            u64::MAX / 2 + 1,
            u64::MAX - 1,
            u64::MAX,
        ]);
        amounts
    }

    #[test]
    fn a_share_rounds_down_or_up_as_it_is_told() {
        let third_down = Share::new(1, 3, Rounding::Down);
        let third_up = Share::new(1, 3, Rounding::Up);
        assert_eq!((third_down.of(0), third_up.of(0)), (0, 0));
        assert_eq!((third_down.of(1), third_up.of(1)), (0, 1));
        assert_eq!((third_down.of(2), third_up.of(2)), (0, 1));
        assert_eq!((third_down.of(3), third_up.of(3)), (1, 1), "exact: no rounding either way");
        assert_eq!((third_down.of(4), third_up.of(4)), (1, 2));
        assert_eq!((EIGHT_TENTHS.of(9), EIGHT_TENTHS.of(10), EIGHT_TENTHS.of(11)), (7, 8, 8));
        assert_eq!((HALF_UP.of(1), HALF_UP.of(2), HALF_UP.of(3), HALF_UP.of(1001)), (1, 1, 2, 501));
        assert_eq!(Share::new(8, 10, Rounding::Up).of(11), 9);
    }

    #[test]
    fn the_whole_and_none_are_shares_too_at_any_amount() {
        for rounding in [Rounding::Down, Rounding::Up] {
            let whole = Share::new(7, 7, rounding);
            let none = Share::new(0, 7, rounding);
            for amount in [0, 1, 6, 7, 8, u64::MAX / 7, u64::MAX / 7 + 1, u64::MAX] {
                assert_eq!(whole.of(amount), amount, "{rounding:?} {amount}");
                assert_eq!(none.of(amount), 0, "{rounding:?} {amount}");
            }
        }
    }

    #[test]
    fn a_share_is_never_more_than_the_amount_and_never_wraps() {
        let shares = [
            EIGHT_TENTHS,
            HALF_UP,
            Share::new(1, 2, Rounding::Down),
            Share::new(1, 3, Rounding::Up),
            Share::new(2, 3, Rounding::Down),
            Share::new(9, 10, Rounding::Up),
            Share::new(1, u64::MAX, Rounding::Up),
            Share::new(u64::MAX - 1, u64::MAX, Rounding::Down),
        ];
        for share in shares {
            for amount in spread() {
                assert!(share.of(amount) <= amount, "{share:?} of {amount}");
            }
        }
    }

    #[test]
    fn a_product_past_a_u64_is_still_the_exact_share() {
        // Down: 8/10 of u64::MAX, where the historical arithmetic saturates to u64::MAX / 10.
        assert_eq!(EIGHT_TENTHS.of(u64::MAX), 14_757_395_258_967_641_292);
        assert_eq!(EIGHT_TENTHS.of(u64::MAX / 8), 1_844_674_407_370_955_160, "the last amount whose product fits");
        assert_eq!(EIGHT_TENTHS.of(u64::MAX / 8 + 1), 1_844_674_407_370_955_161, "the first past it: 8/10 of 2^61, rounded down");
        // Up: a third of u64::MAX is a whole number, so rounding up adds nothing.
        let third_up = Share::new(1, 3, Rounding::Up);
        assert_eq!(third_up.of(u64::MAX), u64::MAX / 3);
        assert_eq!(HALF_UP.of(u64::MAX), u64::MAX / 2 + 1);
    }

    #[test]
    fn eight_tenths_down_and_half_up_are_the_exact_integer_formulas() {
        for x in spread() {
            assert_eq!(u128::from(EIGHT_TENTHS.of(x)), u128::from(x) * 8 / 10, "{x}");
            assert_eq!(HALF_UP.of(x), x - x / 2, "{x}");
        }
    }

    #[test]
    fn equivalent_fractions_give_equal_shares_of_every_amount() {
        let half = u64::MAX / 2;
        let families: [&[(u64, u64)]; 3] = [&[(1, 1), (u64::MAX, u64::MAX)], &[(1, 2), (2, 4), (half, u64::MAX - 1)], &[(8, 10), (4, 5), (800, 1000)]];
        for rounding in [Rounding::Down, Rounding::Up] {
            for family in families {
                let (num, den) = family[0];
                let first = Share::new(num, den, rounding);
                for &(num, den) in &family[1..] {
                    let other = Share::new(num, den, rounding);
                    for amount in spread() {
                        assert_eq!(other.of(amount), first.of(amount), "{other:?} and {first:?} of {amount}");
                    }
                }
            }
        }
    }

    #[test]
    fn none_and_the_whole_of_zero_one_and_the_largest_amount() {
        for rounding in [Rounding::Down, Rounding::Up] {
            for amount in [0, 1, u64::MAX] {
                assert_eq!(Share::new(0, 1, rounding).of(amount), 0, "{rounding:?} {amount}");
                assert_eq!(Share::new(0, u64::MAX, rounding).of(amount), 0, "{rounding:?} {amount}");
                assert_eq!(Share::new(1, 1, rounding).of(amount), amount, "{rounding:?} {amount}");
                assert_eq!(Share::new(u64::MAX, u64::MAX, rounding).of(amount), amount, "{rounding:?} {amount}");
            }
        }
    }

    #[test]
    fn rounding_shows_only_where_the_share_is_not_a_whole_number_at_any_size() {
        let (third_down, third_up) = (Share::new(1, 3, Rounding::Down), Share::new(1, 3, Rounding::Up));
        // u64::MAX is a multiple of 3; u64::MAX - 1 is not.
        assert_eq!((third_down.of(u64::MAX), third_up.of(u64::MAX)), (u64::MAX / 3, u64::MAX / 3));
        assert_eq!((third_down.of(u64::MAX - 1), third_up.of(u64::MAX - 1)), (u64::MAX / 3 - 1, u64::MAX / 3));
        let (down, up) = (Share::new(u64::MAX - 1, u64::MAX, Rounding::Down), Share::new(u64::MAX - 1, u64::MAX, Rounding::Up));
        assert_eq!((down.of(u64::MAX), up.of(u64::MAX)), (u64::MAX - 1, u64::MAX - 1), "exact");
        assert_eq!((down.of(1), up.of(1)), (0, 1), "a hair under one");
        assert_eq!((down.of(2), up.of(2)), (1, 2));
    }

    #[test]
    fn extreme_fractions_and_amounts_match_a_u128_reference() {
        let near = [1, 2, 3, u64::MAX / 2, u64::MAX / 2 + 1, u64::MAX - 2, u64::MAX - 1, u64::MAX];
        for &den in &near {
            for &num in near.iter().chain(&[0]).filter(|&&num| num <= den) {
                for &amount in near.iter().chain(&[0]) {
                    let product = u128::from(amount) * u128::from(num);
                    let den_wide = u128::from(den);
                    let down = Share::new(num, den, Rounding::Down).of(amount);
                    let up = Share::new(num, den, Rounding::Up).of(amount);
                    assert_eq!(u128::from(down), product / den_wide, "{num}/{den} of {amount}, down");
                    assert_eq!(u128::from(up), product.div_ceil(den_wide), "{num}/{den} of {amount}, up");
                    assert!(down <= up && up <= amount, "{num}/{den} of {amount}");
                }
            }
        }
    }

    #[test]
    fn the_exact_and_the_historical_arithmetic_agree_wherever_the_product_fits_a_u64() {
        let fractions = [(0, 1), (1, 1), (1, 2), (1, 3), (2, 3), (8, 10), (9, 10), (1, 1000), (999, 1000), (7, 7), (0, 7), (1, u64::MAX), (u64::MAX - 1, u64::MAX)];
        let mut compared = 0;
        for (num, den) in fractions {
            for rounding in [Rounding::Down, Rounding::Up] {
                let factor = match rounding {
                    Rounding::Down => num,
                    Rounding::Up => den - num,
                };
                for amount in spread() {
                    if amount.checked_mul(factor).is_some() {
                        let historical = Share::saturating_u64(num, den, rounding).of(amount);
                        assert_eq!(Share::new(num, den, rounding).of(amount), historical, "{num}/{den} {rounding:?} of {amount}");
                        compared += 1;
                    }
                }
            }
        }
        assert!(compared > 26 * 9_000, "every fraction and rounding over the small amounts at least: {compared}");
    }

    #[test]
    #[should_panic(expected = "non-zero denominator")]
    fn a_share_of_nothing_is_refused() {
        let _ = Share::new(0, 0, Rounding::Down);
    }

    #[test]
    #[should_panic(expected = "more than the whole")]
    fn a_share_above_the_whole_is_refused() {
        let _ = Share::new(11, 10, Rounding::Up);
    }

    const EIGHT_TENTHS_U64: Share = Share::saturating_u64(8, 10, Rounding::Down);
    const HALF_UP_U64: Share = Share::saturating_u64(1, 2, Rounding::Up);

    #[test]
    fn the_historical_arithmetic_is_the_two_integer_formulas_it_was_validated_as() {
        for x in spread() {
            assert_eq!(EIGHT_TENTHS_U64.of(x), x.saturating_mul(8) / 10, "{x}");
            assert_eq!(HALF_UP_U64.of(x), x - x / 2, "{x}");
        }
    }

    #[test]
    fn the_historical_arithmetic_saturates_early_rounding_down_and_late_rounding_up() {
        assert_eq!(EIGHT_TENTHS_U64.of(u64::MAX), u64::MAX / 10);
        assert_eq!(EIGHT_TENTHS_U64.of(u64::MAX / 8), 1_844_674_407_370_955_160, "the last amount whose product fits");
        assert_eq!(EIGHT_TENTHS_U64.of(u64::MAX / 8 + 1), 1_844_674_407_370_955_161, "the first that saturates");
        let third_up = Share::saturating_u64(1, 3, Rounding::Up);
        assert_eq!(third_up.of(u64::MAX), u64::MAX - u64::MAX / 3);
        assert!(third_up.of(u64::MAX) > u64::MAX / 3 + 1);
        assert_eq!(HALF_UP_U64.of(u64::MAX), u64::MAX / 2 + 1, "half rounded up never saturates: den - num is 1");
        for amount in [u64::MAX / 7 + 1, u64::MAX] {
            assert_eq!(Share::saturating_u64(7, 7, Rounding::Down).of(amount), u64::MAX / 7, "{amount}");
            assert_eq!(Share::saturating_u64(7, 7, Rounding::Up).of(amount), amount, "{amount}");
            assert_eq!(Share::saturating_u64(0, 7, Rounding::Down).of(amount), 0, "{amount}");
            assert_eq!(Share::saturating_u64(0, 7, Rounding::Up).of(amount), amount - u64::MAX / 7, "{amount}");
        }
        for share in [EIGHT_TENTHS_U64, HALF_UP_U64, Share::saturating_u64(1, u64::MAX, Rounding::Up)] {
            for amount in spread() {
                assert!(share.of(amount) <= amount, "{share:?} of {amount}");
            }
        }
    }

    #[test]
    fn the_historical_arithmetic_can_disagree_on_equivalent_fractions_as_documented() {
        // 1000 * u64::MAX saturates to u64::MAX, and u64::MAX / u64::MAX is 1: not the whole.
        assert_eq!(Share::saturating_u64(1, 1, Rounding::Down).of(1000), 1000);
        assert_eq!(Share::saturating_u64(u64::MAX, u64::MAX, Rounding::Down).of(1000), 1);
    }

    #[test]
    fn shares_that_differ_only_in_their_arithmetic_are_not_equal() {
        assert_ne!(Share::new(8, 10, Rounding::Down), EIGHT_TENTHS_U64);
        assert_eq!(Share::saturating_u64(8, 10, Rounding::Down), EIGHT_TENTHS_U64);
        assert_ne!(Share::saturating_u64(4, 5, Rounding::Down), EIGHT_TENTHS_U64, "equal fractions, not equal shares");
    }

    #[test]
    #[should_panic(expected = "non-zero denominator")]
    fn a_historical_share_of_nothing_is_refused() {
        let _ = Share::saturating_u64(0, 0, Rounding::Down);
    }

    #[test]
    #[should_panic(expected = "more than the whole")]
    fn a_historical_share_above_the_whole_is_refused() {
        let _ = Share::saturating_u64(11, 10, Rounding::Up);
    }
}
