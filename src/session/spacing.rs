//! How far apart renewal attempts of one SA are kept, and when the next one may start.
//!
//! An attempt starts no sooner than [`Spacing::i_min`] after the previous attempt started, or
//! [`Spacing::retry_after_failure`] after it if that one failed -- whatever asks for it. Where two
//! parties can each ask for an attempt (say, one that watches the data plane and one that runs the
//! exchanges), holding every trigger to the same spacing means neither starts what the other would
//! not. The spacing never delays an SA's end: that is the caller's to act on at once.
//!
//! The minimum spacing scales with the byte limit `L` of the SA the attempt would replace: the
//! time `L / limit_divisor` bytes take at [`Spacing::reference_rate`], never under
//! [`Spacing::floor`] nor over [`Spacing::cap`]; no byte limit, the cap. A small window ends an SA
//! sooner than a fixed spacing sized for a large one would let the next attempt start, and a large
//! window needs no more than the cap. It is computed from `L` alone, so two parties that both know
//! the limit agree on the spacing with no message of their own. The wait after a failure is not
//! scaled: it is what stops a loop against a peer that refuses or does not answer.
//!
//! Nothing here reads a clock: every instant is the caller's.

use std::time::{Duration, Instant};

/// The figures the spacing of attempts is computed from. All of them are the consumer's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Spacing {
    /// The least [`i_min`](Self::i_min) can be, whatever the limit.
    pub floor: Duration,
    /// The most [`i_min`](Self::i_min) can be, and what it is with no byte limit. Where it is below
    /// [`floor`](Self::floor), the cap wins.
    pub cap: Duration,
    /// The rate the spacing is sized against, in bytes per second.
    pub reference_rate: u64,
    /// I_min is the time `limit / limit_divisor` bytes take at
    /// [`reference_rate`](Self::reference_rate).
    pub limit_divisor: u64,
    /// The least time after the start of an attempt that failed before the next one may start (or
    /// [`i_min`](Self::i_min), if that is longer).
    pub retry_after_failure: Duration,
}

/// The last renewal attempt of an SA: when it started, and whether it failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LastAttempt {
    pub started: Instant,
    pub failed: bool,
}

/// When a renewal that is due may start. There is deliberately no outcome that retires the SA in
/// use or stops it carrying traffic: a renewal point only ever asks for a renewal, and the SA serves
/// until its replacement is in place or one of its hard limits ends it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Schedule {
    /// Not due: nothing to start.
    NotDue,
    /// An attempt is already under way: no second one beside it.
    InFlight,
    /// Due, but the spacing between attempts holds it until this instant.
    At(Instant),
    /// Due, and nothing holds it back.
    Now,
}

impl Spacing {
    /// The minimum spacing of attempts for an SA held to `limit_bytes`: the time
    /// `limit_bytes / limit_divisor` bytes take at [`reference_rate`](Self::reference_rate), to the
    /// nanosecond (rounded down), never under [`floor`](Self::floor) nor over [`cap`](Self::cap).
    /// `None` (no byte limit): the cap.
    ///
    /// Never panics: where `limit_divisor * reference_rate` is zero there is no rate to size against,
    /// and the result is the cap; where `floor` is above `cap`, the cap wins.
    pub fn i_min(&self, limit_bytes: Option<u64>) -> Duration {
        let Some(l) = limit_bytes else {
            return self.cap;
        };
        let per_second = u128::from(self.limit_divisor) * u128::from(self.reference_rate);
        if per_second == 0 {
            return self.cap;
        }
        let nanos = u128::from(l) * 1_000_000_000 / per_second;
        // `max` then `min` rather than `clamp`, which panics when `floor > cap`; the two agree
        // whenever `floor <= cap`.
        Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX)).max(self.floor).min(self.cap)
    }

    /// The earliest instant the next attempt may start, given when the last one started, whether it
    /// failed, and the byte limit of the SA it would replace. `None`: no attempt yet, any time.
    ///
    /// Panics if that instant is past what an [`Instant`] can hold, as `Instant + Duration` does.
    pub fn ready_at(&self, last_start: Option<Instant>, last_failed: bool, limit_bytes: Option<u64>) -> Option<Instant> {
        let i_min = self.i_min(limit_bytes);
        let spacing = if last_failed { self.retry_after_failure.max(i_min) } else { i_min };
        last_start.map(|t| t + spacing)
    }

    /// Whether an attempt may start at `now` (at the very instant [`ready_at`](Self::ready_at)
    /// names, it may).
    pub fn ready(&self, last_start: Option<Instant>, last_failed: bool, limit_bytes: Option<u64>, now: Instant) -> bool {
        self.ready_at(last_start, last_failed, limit_bytes).is_none_or(|at| at <= now)
    }

    /// When a renewal may start, at `now`: not at all unless it is `due`; never while an attempt is
    /// in flight; and not before the spacing after the last attempt
    /// ([`ready_at`](Self::ready_at), sized by `limit_bytes`) -- at the very instant it names, it
    /// may.
    pub fn schedule(
        &self,
        due: bool,
        attempt_in_flight: bool,
        last_attempt: Option<LastAttempt>,
        limit_bytes: Option<u64>,
        now: Instant,
    ) -> Schedule {
        if !due {
            return Schedule::NotDue;
        }
        if attempt_in_flight {
            return Schedule::InFlight;
        }
        let failed = last_attempt.is_some_and(|last| last.failed);
        match self.ready_at(last_attempt.map(|last| last.started), failed, limit_bytes) {
            Some(at) if at > now => Schedule::At(at),
            _ => Schedule::Now,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FLOOR: Duration = Duration::from_millis(50);
    const CAP: Duration = Duration::from_millis(200);
    const RETRY: Duration = Duration::from_secs(5);

    /// The figures of a consumer that sizes I_min at a quarter of the limit, at 64 MB/s, between 50
    /// and 200 ms, and retries 5 s after a failure.
    const FIGURES: Spacing = Spacing {
        floor: FLOOR,
        cap: CAP,
        reference_rate: 64_000_000,
        limit_divisor: 4,
        retry_after_failure: RETRY,
    };

    #[test]
    fn attempts_are_spaced_from_the_previous_start_i_min_or_the_retry_after_a_failure_to_the_instant() {
        let s = FIGURES;
        let t0 = Instant::now();
        let ms = Duration::from_millis;
        let i = s.i_min(None);
        assert!(s.ready(None, false, None, t0), "no attempt yet: any time");
        assert!(!s.ready(Some(t0), false, None, t0 + i - ms(1)));
        assert!(s.ready(Some(t0), false, None, t0 + i), "exactly I_min after the start");
        assert!(!s.ready(Some(t0), true, None, t0 + i), "a failed attempt: I_min is not enough");
        assert!(!s.ready(Some(t0), true, None, t0 + RETRY - ms(1)));
        assert!(s.ready(Some(t0), true, None, t0 + RETRY));
        assert_eq!(s.ready_at(Some(t0), false, None), Some(t0 + i));
        assert_eq!(s.ready_at(None, true, Some(1)), None);
    }

    #[test]
    fn i_min_is_a_quarter_of_the_hard_byte_limit_at_the_reference_rate_between_the_floor_and_the_cap() {
        let s = FIGURES;
        assert_eq!(s.i_min(None), CAP, "no byte limit: the cap");
        assert_eq!(s.i_min(Some(5_120_000)), FLOOR, "20 ms by the rate: the floor");
        assert_eq!(s.i_min(Some(50_120_000)), Duration::from_nanos(195_781_250));
        assert_eq!(s.i_min(Some(51_200_000)), CAP, "exactly the cap by the rate");
        assert_eq!(s.i_min(Some(0)), FLOOR);
        assert_eq!(s.i_min(Some(u64::MAX)), CAP, "no overflow");
    }

    #[test]
    fn i_min_is_exact_to_the_nanosecond_around_the_floor_and_the_cap() {
        let s = FIGURES;
        let ns = Duration::from_nanos;
        // The floor is 12 800 000 bytes by the rate, the cap 51 200 000.
        assert_eq!(s.i_min(Some(12_799_999)), FLOOR);
        assert_eq!(s.i_min(Some(12_800_000)), FLOOR, "exactly the floor by the rate");
        assert_eq!(s.i_min(Some(12_800_001)), ns(50_000_003), "rounded down to the nanosecond");
        assert_eq!(s.i_min(Some(51_199_999)), ns(199_999_996));
        assert_eq!(s.i_min(Some(51_200_001)), CAP);
    }

    #[test]
    fn i_min_never_decreases_as_the_hard_byte_limit_grows() {
        let s = FIGURES;
        let ls = [0, 1, 5_120_000, 12_800_000, 25_000_000, 50_120_000, 51_200_000, 100_000_000, u64::MAX];
        for w in ls.windows(2) {
            assert!(s.i_min(Some(w[0])) <= s.i_min(Some(w[1])), "{} -> {}", w[0], w[1]);
        }
        assert!(s.i_min(Some(u64::MAX)) <= s.i_min(None));
    }

    #[test]
    fn after_a_failure_the_retry_spacing_holds_whatever_the_hard_byte_limit() {
        let s = FIGURES;
        let t0 = Instant::now();
        for l in [None, Some(0), Some(5_120_000), Some(50_120_000), Some(u64::MAX)] {
            assert_eq!(s.ready_at(Some(t0), true, l), Some(t0 + RETRY), "{l:?}");
        }
    }

    #[test]
    fn the_retry_after_a_failure_is_never_shorter_than_i_min() {
        let s = Spacing { retry_after_failure: Duration::from_millis(10), ..FIGURES };
        let t0 = Instant::now();
        assert_eq!(s.ready_at(Some(t0), true, None), Some(t0 + CAP), "I_min is longer: it holds");
        assert_eq!(s.ready_at(Some(t0), true, Some(5_120_000)), Some(t0 + FLOOR));
    }

    #[test]
    fn every_figure_of_the_spacing_is_read() {
        let t0 = Instant::now();
        let ms = Duration::from_millis;
        let base = FIGURES;
        // At 50 120 000 bytes I_min sits between the floor and the cap, so every figure moves it.
        let mid = Some(50_120_000);
        assert_eq!(base.i_min(mid), Duration::from_nanos(195_781_250));
        assert_eq!(Spacing { reference_rate: 128_000_000, ..base }.i_min(mid), Duration::from_nanos(97_890_625));
        assert_eq!(Spacing { limit_divisor: 2, ..base }.i_min(mid), CAP, "a half takes longer: capped");
        assert_eq!(Spacing { limit_divisor: 8, ..base }.i_min(mid), Duration::from_nanos(97_890_625));
        assert_eq!(Spacing { cap: ms(100), ..base }.i_min(mid), ms(100));
        assert_eq!(Spacing { cap: ms(100), ..base }.i_min(None), ms(100));
        assert_eq!(Spacing { floor: ms(196), ..base }.i_min(mid), ms(196));
        assert_eq!(Spacing { floor: ms(1), ..base }.i_min(Some(0)), ms(1));
        assert_eq!(Spacing { retry_after_failure: ms(700), ..base }.ready_at(Some(t0), true, mid), Some(t0 + ms(700)));
    }

    #[test]
    fn a_degenerate_spacing_does_not_panic() {
        let ms = Duration::from_millis;
        for limit in [None, Some(0), Some(1), Some(50_120_000), Some(u64::MAX)] {
            assert_eq!(Spacing { reference_rate: 0, ..FIGURES }.i_min(limit), CAP, "no rate: the cap ({limit:?})");
            assert_eq!(Spacing { limit_divisor: 0, ..FIGURES }.i_min(limit), CAP, "no divisor: the cap ({limit:?})");
            let inverted = Spacing { floor: ms(300), cap: ms(100), ..FIGURES };
            assert_eq!(inverted.i_min(limit), ms(100), "a floor above the cap: the cap wins ({limit:?})");
            let zero = Spacing { floor: Duration::ZERO, cap: Duration::ZERO, retry_after_failure: Duration::ZERO, ..FIGURES };
            assert_eq!(zero.i_min(limit), Duration::ZERO, "{limit:?}");
            let huge = Spacing { reference_rate: u64::MAX, limit_divisor: u64::MAX, cap: Duration::MAX, ..FIGURES };
            assert!(huge.i_min(limit) <= Duration::MAX);
        }
        let unbounded = Spacing { reference_rate: 1, limit_divisor: 1, cap: Duration::MAX, ..FIGURES };
        assert_eq!(unbounded.i_min(Some(u64::MAX)), Duration::from_nanos(u64::MAX), "a time past u64 nanoseconds saturates");
        let t0 = Instant::now();
        let zero = Spacing { floor: Duration::ZERO, cap: Duration::ZERO, retry_after_failure: Duration::ZERO, ..FIGURES };
        assert!(zero.ready(Some(t0), true, Some(5_120_000), t0), "no spacing at all: at once");
    }

    #[test]
    fn not_due_is_not_due_whatever_else_holds() {
        let s = FIGURES;
        let t0 = Instant::now();
        assert_eq!(s.schedule(false, false, None, None, t0), Schedule::NotDue);
        assert_eq!(
            s.schedule(false, true, Some(LastAttempt { started: t0, failed: true }), Some(5_120_000), t0),
            Schedule::NotDue
        );
    }

    #[test]
    fn due_with_no_earlier_attempt_is_now() {
        let s = FIGURES;
        let t0 = Instant::now();
        assert_eq!(s.schedule(true, false, None, Some(5_120_000), t0), Schedule::Now);
        assert_eq!(s.schedule(true, false, None, None, t0), Schedule::Now);
    }

    #[test]
    fn an_attempt_in_flight_excludes_another() {
        let s = FIGURES;
        let t0 = Instant::now();
        assert_eq!(s.schedule(true, true, None, Some(5_120_000), t0), Schedule::InFlight);
        let long_ago = Some(LastAttempt { started: t0, failed: false });
        assert_eq!(
            s.schedule(true, true, long_ago, Some(5_120_000), t0 + Duration::from_secs(3600)),
            Schedule::InFlight,
            "however long ago the last one started"
        );
    }

    #[test]
    fn after_a_started_attempt_a_renewal_waits_out_i_min_and_comes_at_the_very_instant() {
        let s = FIGURES;
        let t0 = Instant::now();
        let ns = Duration::from_nanos;
        let last = Some(LastAttempt { started: t0, failed: false });
        let limit = Some(5_120_000);
        assert_eq!(s.i_min(limit), FLOOR, "5 120 000 bytes: the floor");
        let at = t0 + FLOOR;
        assert_eq!(s.schedule(true, false, last, limit, t0), Schedule::At(at));
        assert_eq!(s.schedule(true, false, last, limit, at - ns(1)), Schedule::At(at));
        assert_eq!(s.schedule(true, false, last, limit, at), Schedule::Now, "at the instant itself");
        assert_eq!(s.schedule(true, false, last, None, t0), Schedule::At(t0 + CAP), "no limit: the cap");
        let mid = t0 + ns(195_781_250);
        assert_eq!(s.schedule(true, false, last, Some(50_120_000), mid - ns(1)), Schedule::At(mid));
        assert_eq!(s.schedule(true, false, last, Some(50_120_000), mid), Schedule::Now);
    }

    #[test]
    fn after_a_failed_attempt_a_renewal_waits_out_the_retry_spacing() {
        let s = FIGURES;
        let t0 = Instant::now();
        let failed = Some(LastAttempt { started: t0, failed: true });
        let at = t0 + RETRY;
        assert_eq!(s.schedule(true, false, failed, Some(5_120_000), t0 + FLOOR), Schedule::At(at), "I_min is not enough after a failure");
        assert_eq!(s.schedule(true, false, failed, Some(5_120_000), at - Duration::from_nanos(1)), Schedule::At(at));
        assert_eq!(s.schedule(true, false, failed, Some(5_120_000), at), Schedule::Now);
        assert_eq!(s.schedule(true, false, failed, None, at), Schedule::Now);
    }
}
