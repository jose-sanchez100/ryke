//! When an SA is to be renewed by its age and by its volume, where it stands against its limits,
//! and how soon a renewal attempt that failed is tried again.
//!
//! An SA has two independent limits (RFC 2407 §4.5: seconds and kilobytes; the first one reached
//! ends the SA). Each has a renewal point ahead of its end, where a replacement is to be negotiated
//! while the SA still carries traffic, and an end, after which the SA must not carry another
//! packet. [`RenewalTiming`] holds the figures those points are computed from, all of them the
//! consumer's; [`RenewalTiming::standing`] says where an SA stands, and
//! [`RenewalTiming::due_by_standing`] and [`RenewalTiming::due_by_age`] whether a renewal is to be
//! started.
//!
//! Every time and every count is an argument: the SA's age, how long ago an attempt failed, what
//! it has moved. Nothing here reads a clock or counts a byte.

use std::time::Duration;

use super::Share;

/// The figures an SA's renewal is timed by. All of them are the consumer's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenewalTiming {
    /// The share of a lifetime in seconds at which renewal starts. The room it leaves before the
    /// end is the room a first attempt that is lost has to be retried in.
    pub margin: Share,
    /// Never renewed before this share of its lifetime, whatever [`lead`](Self::lead) asks: an SA
    /// too short for the lead is still renewed, at this point, rather than at once.
    pub earliest: Share,
    /// Kept free before the end of a lifetime for one attempt that gets no answer to be over
    /// before the SA is.
    pub lead: Duration,
    /// No SA is renewed sooner than this into its life, whatever its lifetime: it bounds how often
    /// a lifetime of zero, or close to it, could ask for a renewal.
    pub min_interval: Duration,
    /// The least time after a failed attempt before the next one, however little is left.
    pub retry_min: Duration,
    /// The most time after a failed attempt before the next one, and the wait once an SA is past
    /// its lifetime in seconds.
    pub retry_max: Duration,
    /// The share of a volume limit at which renewal starts.
    pub volume_margin: Share,
}

/// One of an SA's limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    /// Its lifetime in seconds.
    Seconds,
    /// Its volume, in bytes per direction.
    Volume,
    /// Its end as its data plane reported it (the SA was removed there). A fact the caller brings:
    /// [`RenewalTiming::standing`] never computes it, but a [`Standing`] can carry it, so that
    /// [`RenewalTiming::due_by_standing`] can judge an SA the caller knows ended that way.
    DataPlane,
}

/// Where an SA stands against its limits at one moment. The distinction that matters is between
/// the two that ask something of the SA's user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// Neither a renewal point nor a limit reached.
    InTime,
    /// A renewal point is reached but the SA is still good: a replacement is negotiated ahead of
    /// time and the SA carries traffic until it is in place.
    RenewAhead(Limit),
    /// A limit itself is reached: the SA's life is over and it must not carry another packet.
    /// Definitive -- nothing about it is "due", it is finished.
    Expired(Limit),
}

impl RenewalTiming {
    /// The age at which an SA granted `lifetime_secs` is to be renewed -- the deadline to *start*
    /// renewing, not its end, in whole milliseconds:
    ///
    /// - the [`margin`](Self::margin) of the lifetime; but
    /// - at least [`lead`](Self::lead) before its end, so that an attempt that gets no answer is
    ///   over before the SA is; and
    /// - never before the [`earliest`](Self::earliest) share of it: an SA too short for the lead is
    ///   renewed there anyway, which leaves the rest of its life for the retries of
    ///   [`retry_after`](Self::retry_after). The lifetime is never lengthened to make room, and with
    ///   `earliest <= margin` a renewal is never scheduled after the SA's end;
    /// - and never sooner than [`min_interval`](Self::min_interval).
    ///
    /// What bounds the attempts of a very short lifetime is then the spacing between them: one per
    /// SA at its renewal point, and one that failed waits [`retry_min`](Self::retry_min) at least.
    pub fn renewal_age(&self, lifetime_secs: u32) -> Duration {
        let life_ms = u64::from(lifetime_secs) * 1000;
        let soft = self.margin.of(life_ms);
        // Exactly the lead in milliseconds for any lead a `u64` of them holds; a longer one leaves
        // nothing before the end, as it would anyway.
        let latest = life_ms.saturating_sub(u64::try_from(self.lead.as_millis()).unwrap_or(u64::MAX));
        Duration::from_millis(soft.min(latest).max(self.earliest.of(life_ms))).max(self.min_interval)
    }

    /// How long after a failed attempt (counted from when it failed) the next one is due, for an
    /// SA with `remaining` left of its lifetime in seconds: half of what is left, so several tries
    /// fit before it ends, but between [`retry_min`](Self::retry_min) and
    /// [`retry_max`](Self::retry_max); once the SA is past its lifetime (`remaining` zero),
    /// `retry_max` -- the peer may well keep using an SA past a lifetime that was not negotiated.
    ///
    /// Never panics: where `retry_min` is above `retry_max`, `retry_max` wins.
    pub fn retry_after(&self, remaining: Duration) -> Duration {
        if remaining.is_zero() {
            self.retry_max
        } else {
            // `max` then `min` rather than `clamp`, which panics when `retry_min > retry_max`; the
            // two agree whenever `retry_min <= retry_max`.
            (remaining / 2).max(self.retry_min).min(self.retry_max)
        }
    }

    /// Whether an SA `age` old that was granted `lifetime_secs` is due for renewal: it has reached
    /// [`renewal_age`](Self::renewal_age), and any earlier attempt that failed (`since_failure`
    /// ago) failed at least [`retry_after`](Self::retry_after) ago. A successful attempt needs no
    /// entry here: it makes a new SA, whose age starts again.
    pub fn due_by_age(&self, age: Duration, lifetime_secs: u32, since_failure: Option<Duration>) -> bool {
        let remaining = Duration::from_secs(lifetime_secs.into()).saturating_sub(age);
        age >= self.renewal_age(lifetime_secs) && since_failure.is_none_or(|since| since >= self.retry_after(remaining))
    }

    /// The volume, in bytes per direction, at which an SA held to `limit_bytes` is due for
    /// renewal: its [`volume_margin`](Self::volume_margin) share. Nothing says how fast a volume
    /// fills, so unlike the seconds' there is no lead for an attempt to fit in -- the margin is all
    /// the room there is.
    pub fn volume_renewal_point(&self, limit_bytes: u64) -> u64 {
        self.volume_margin.of(limit_bytes)
    }

    /// Where an SA `age` old that was granted `lifetime_secs` stands, given (when the data plane
    /// counted it and a volume limit applies) that it has moved `used_bytes` of `limit_bytes`.
    ///
    /// `used_bytes` is `(rx, tx)`, each direction checked against the *same* limit on its own and
    /// never their sum: an IPsec SA is one direction, and RFC 2407 §4.5's Life Duration applies to
    /// "the" SA, so the direction that gets there first is the one that ends or renews it. Each
    /// limit is judged on its own -- a seconds limit is not stretched by an idle SA, nor a volume
    /// limit by a young one -- and an end beats a renewal point, in this order: the end by seconds,
    /// the end by volume, the renewal point by seconds, the renewal point by volume.
    ///
    /// No minimum age gates the renewal point by volume: the counts are the SA's own, so a new SA's
    /// start at zero and only real traffic reaches the point; gating it on age would instead let a
    /// fast-filling SA reach its end with no renewal ever asked for -- exactly the case a margin is
    /// for. `used_bytes` of `None` (no reading) means the volume says nothing, not that it is zero;
    /// `limit_bytes` of `None` means there is no volume limit. A limit of zero ends the SA at once
    /// rather than reading as no limit.
    pub fn standing(
        &self,
        age: Duration,
        lifetime_secs: u32,
        used_bytes: Option<(u64, u64)>,
        limit_bytes: Option<u64>,
    ) -> Standing {
        let volume = used_bytes.zip(limit_bytes);
        let over = |at: u64| move |(rx, tx): (u64, u64)| rx >= at || tx >= at;
        if age >= Duration::from_secs(lifetime_secs.into()) {
            Standing::Expired(Limit::Seconds)
        } else if volume.is_some_and(|(used, limit)| over(limit)(used)) {
            Standing::Expired(Limit::Volume)
        } else if age >= self.renewal_age(lifetime_secs) {
            Standing::RenewAhead(Limit::Seconds)
        } else if volume.is_some_and(|(used, limit)| over(self.volume_renewal_point(limit))(used)) {
            Standing::RenewAhead(Limit::Volume)
        } else {
            Standing::InTime
        }
    }

    /// Whether an SA that stands as `standing` is to be renewed now, given how long ago a renewal
    /// attempt of it failed (`since_failure`) and how much of its lifetime in seconds is left
    /// (`remaining`): a failed attempt is retried in time, not on every look.
    ///
    /// - Ahead of its end by seconds, the spacing is [`retry_after`](Self::retry_after)'s: half of
    ///   what is left, so several tries fit before the end.
    /// - Ahead of its end by volume, or once it has ended by any limit,
    ///   [`retry_min`](Self::retry_min): no remaining time says how soon a volume runs out, and an
    ///   ended SA carries nothing until a replacement is up. ([`standing`](Self::standing) never
    ///   stands an SA ahead of a [`Limit::DataPlane`] end, which is only ever an end; should one be
    ///   brought, it is judged as a volume.)
    pub fn due_by_standing(&self, standing: Standing, since_failure: Option<Duration>, remaining: Duration) -> bool {
        let retry_after = match standing {
            Standing::InTime => return false,
            Standing::RenewAhead(Limit::Seconds) => self.retry_after(remaining),
            Standing::RenewAhead(Limit::Volume | Limit::DataPlane) | Standing::Expired(_) => self.retry_min,
        };
        since_failure.is_none_or(|since| since >= retry_after)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::Rounding;
    use Limit::{DataPlane, Seconds, Volume};
    use Standing::{Expired, InTime, RenewAhead};

    const LEAD: Duration = Duration::from_secs(20);
    const MIN_INTERVAL: Duration = Duration::from_secs(1);
    const RETRY_MIN: Duration = Duration::from_secs(5);
    const RETRY_MAX: Duration = Duration::from_secs(30);
    /// The longest one attempt that gets no answer takes, in the consumer these figures are from:
    /// what [`LEAD`] leaves room for.
    const ATTEMPT_WORST_CASE: Duration = Duration::from_secs(15);

    /// The figures of a consumer that renews at 8/10 of a lifetime or a volume, never before half
    /// of a lifetime, keeps 20 s free before the end and retries between 5 and 30 s.
    const TIMING: RenewalTiming = RenewalTiming {
        margin: Share::new(8, 10, Rounding::Down),
        earliest: Share::new(1, 2, Rounding::Down),
        lead: LEAD,
        min_interval: MIN_INTERVAL,
        retry_min: RETRY_MIN,
        retry_max: RETRY_MAX,
        volume_margin: Share::new(8, 10, Rounding::Down),
    };

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    fn ms(m: u64) -> Duration {
        Duration::from_millis(m)
    }

    #[test]
    fn a_renewal_is_scheduled_before_the_sa_ends_however_short_its_lifetime() {
        let t = TIMING;
        // The ordinary case: the margin of the lifetime (from 100 s up, where that leaves the lead).
        for (life, due_ms) in [(100u32, 80_000u64), (3600, 2_880_000), (28_800, 23_040_000), (86_400, 69_120_000), (u32::MAX, 3_435_973_836_000)] {
            assert_eq!(t.renewal_age(life), ms(due_ms), "{life} s");
        }
        // Short lifetimes: the end minus the lead, never before half of the life.
        for (life, due_ms) in [
            (1u32, 1_000u64),
            (2, 1_000),
            (3, 1_500),
            (5, 2_500),
            (10, 5_000),
            (20, 10_000),
            (29, 14_500),
            (30, 15_000),
            (31, 15_500),
            (39, 19_500),
            (40, 20_000),
            (41, 21_000),
            (45, 25_000),
            (59, 39_000),
            (60, 40_000),
            (61, 41_000),
            (74, 54_000),
            (75, 55_000),
            (99, 79_000),
            (101, 80_800),
        ] {
            assert_eq!(t.renewal_age(life), ms(due_ms), "{life} s");
        }
        // The properties behind the table, for every boundary.
        let mut previous = Duration::ZERO;
        for life in [1u32, 2, 5, 10, 20, 29, 30, 31, 39, 40, 45, 59, 60, 61, 75, 99, 100, 101, 3600, 28_800, 86_400, u32::MAX] {
            let due = t.renewal_age(life);
            let life_d = secs(life.into());
            assert!(due <= life_d, "{life} s: renewal scheduled after the SA ends ({due:?})");
            assert!(due * 2 >= life_d, "{life} s: renewed before half of its life ({due:?})");
            assert!(due >= MIN_INTERVAL, "{life} s: renewal sooner than the minimum ({due:?})");
            if life >= 30 {
                assert!(due + ATTEMPT_WORST_CASE <= life_d, "{life} s: an attempt started at {due:?} may run past the end");
            }
            assert!(due >= previous, "{life} s: a longer life must not be renewed earlier ({due:?} < {previous:?})");
            previous = due;
        }
        // A lifetime of zero is renewed at the minimum interval, not at once.
        assert_eq!(t.renewal_age(0), MIN_INTERVAL);
    }

    #[test]
    fn the_lead_is_kept_whole_from_exactly_forty_seconds_of_life() {
        let t = TIMING;
        for life in 0..=7200u32 {
            let keeps_the_lead = secs(life.into()).saturating_sub(t.renewal_age(life)) >= LEAD;
            assert_eq!(keeps_the_lead, life >= 40, "{life} s");
        }
    }

    #[test]
    fn a_failed_renewal_is_retried_in_time_for_what_is_left_of_the_sa() {
        let t = TIMING;
        // Past its lifetime, or with a long time left: the longest wait.
        assert_eq!(t.retry_after(Duration::ZERO), RETRY_MAX);
        assert_eq!(t.retry_after(secs(3600)), RETRY_MAX);
        assert_eq!(t.retry_after(secs(60)), secs(30));
        // Otherwise half of what is left, so several tries fit...
        assert_eq!(t.retry_after(secs(20)), secs(10));
        assert_eq!(t.retry_after(ms(10_001)), Duration::from_micros(5_000_500), "half, not rounded to the millisecond");
        // ...but never a tight loop.
        assert_eq!(t.retry_after(secs(4)), RETRY_MIN);
        assert_eq!(t.retry_after(ms(1)), RETRY_MIN);
        assert_eq!(t.retry_after(Duration::from_nanos(1)), RETRY_MIN);
        let mut previous = RETRY_MIN;
        for remaining_ms in (1..120_000u64).step_by(250) {
            let wait = t.retry_after(ms(remaining_ms));
            assert!((RETRY_MIN..=RETRY_MAX).contains(&wait), "{remaining_ms} ms left: {wait:?}");
            assert!(wait >= previous, "{remaining_ms} ms left: more time left must not shorten the wait");
            previous = wait;
        }
        assert!(t.due_by_age(secs(2910), 3600, Some(secs(31))));
        assert!(!t.due_by_age(secs(2910), 3600, Some(secs(10))));
    }

    #[test]
    fn an_sa_is_due_by_age_at_its_renewal_age_and_a_failed_attempt_waits_its_retry_to_the_millisecond() {
        let t = TIMING;
        // A 120 s SA is due at 96 s (8/10).
        assert!(!t.due_by_age(ms(95_999), 120, None));
        assert!(t.due_by_age(secs(96), 120, None));
        // Failed at 100 s, 20 s left: retried 10 s after the failure.
        assert!(!t.due_by_age(secs(100), 120, Some(ms(9_999))));
        assert!(t.due_by_age(secs(100), 120, Some(secs(10))));
        // Past its lifetime: every retry_max.
        assert!(!t.due_by_age(secs(140), 120, Some(ms(29_999))));
        assert!(t.due_by_age(secs(140), 120, Some(RETRY_MAX)));
        // A new SA's age starts again: not due.
        assert!(!t.due_by_age(secs(1), 120, Some(secs(50))));
        // Lifetimes of 0 and 1 s: at the minimum interval, to the millisecond.
        for life in [0, 1] {
            assert!(!t.due_by_age(ms(999), life, None), "{life} s");
            assert!(t.due_by_age(ms(1_000), life, None), "{life} s");
        }
    }

    /// The attempts a peer that never answers gets from a caller that looks once a second, each
    /// taking [`ATTEMPT_WORST_CASE`] -- as `(start, end)` in time since the SA was made.
    fn failing_attempts(life: u32, horizon: Duration) -> Vec<(Duration, Duration)> {
        let (mut now, mut last_failure, mut attempts) = (Duration::ZERO, None::<Duration>, Vec::new());
        while now <= horizon {
            if TIMING.due_by_age(now, life, last_failure.map(|failed| now - failed)) {
                let end = now + ATTEMPT_WORST_CASE;
                attempts.push((now, end));
                last_failure = Some(end);
                now = end;
            } else {
                now += secs(1);
            }
        }
        attempts
    }

    #[test]
    fn a_peer_that_never_answers_is_tried_before_the_sa_ends_and_never_in_a_tight_loop() {
        for life in [1u32, 2, 10, 29, 30, 45, 60, 61, 100, 3600] {
            let life_d = secs(life.into());
            let horizon = life_d + secs(600);
            let attempts = failing_attempts(life, horizon);
            let first = attempts.first().unwrap_or_else(|| panic!("{life} s: never attempted"));
            assert!(first.0 <= life_d, "{life} s: the first attempt starts at {:?}, after the SA ended", first.0);
            for pair in attempts.windows(2) {
                assert!(pair[1].0 - pair[0].1 >= RETRY_MIN, "{life} s: attempts {pair:?} follow each other too closely");
            }
            let bound = horizon.as_secs() / (RETRY_MIN + ATTEMPT_WORST_CASE).as_secs() + 1;
            assert!((attempts.len() as u64) <= bound, "{life} s: {} attempts in {horizon:?}", attempts.len());
        }
        let attempts = failing_attempts(3600, secs(3600));
        assert!(attempts.len() >= 10, "a 3600 s SA whose first attempt failed got {} more tries before it ended", attempts.len());
    }

    #[test]
    fn a_volume_is_renewed_at_its_margin_and_a_huge_one_saturates_early() {
        let t = TIMING;
        assert_eq!(t.volume_renewal_point(1_000_000), 800_000);
        assert_eq!(t.volume_renewal_point(0), 0);
        assert_eq!(t.volume_renewal_point(9), 7, "rounded down");
        assert_eq!(t.volume_renewal_point(u64::from(u32::MAX) * 1000), 3_435_973_836_000, "the largest KB grant: exact");
        assert_eq!(t.volume_renewal_point(u64::MAX / 8), 1_844_674_407_370_955_160);
        assert_eq!(t.volume_renewal_point(u64::MAX), u64::MAX / 10, "saturated: early, never wrapped to a small value");
    }

    #[test]
    fn an_sa_stands_against_its_seconds_and_its_volume_independently() {
        let t = TIMING;
        // 3600 s (renewal point 2880 s) and 1_000_000 bytes (renewal point 800_000).
        let both = |n: u64| Some((n, n));
        let stand = |age: u64, used: Option<(u64, u64)>| t.standing(secs(age), 3600, used, Some(1_000_000));
        // Seconds alone (no volume limit, or no reading of it).
        assert_eq!(t.standing(secs(0), 3600, None, None), InTime);
        assert_eq!(t.standing(secs(2879), 3600, both(u64::MAX), None), InTime, "no limit: whatever the count says");
        assert_eq!(t.standing(ms(2_879_999), 3600, None, None), InTime);
        assert_eq!(t.standing(secs(2880), 3600, None, None), RenewAhead(Seconds));
        assert_eq!(t.standing(ms(3_599_999), 3600, None, None), RenewAhead(Seconds));
        assert_eq!(t.standing(secs(3600), 3600, None, None), Expired(Seconds));
        assert_eq!(t.standing(secs(9999), 3600, None, None), Expired(Seconds));
        assert_eq!(stand(2880, None), RenewAhead(Seconds), "a limit with no reading says nothing about the volume");
        assert_eq!(stand(10, None), InTime);
        // Volume alone, both directions moving together: a byte short, at, past.
        assert_eq!(stand(10, both(0)), InTime);
        assert_eq!(stand(10, both(799_999)), InTime);
        assert_eq!(stand(10, both(800_000)), RenewAhead(Volume));
        assert_eq!(stand(10, both(800_001)), RenewAhead(Volume));
        assert_eq!(stand(10, both(999_999)), RenewAhead(Volume));
        assert_eq!(stand(10, both(1_000_000)), Expired(Volume));
        assert_eq!(stand(10, both(1_000_001)), Expired(Volume));
        // Each direction on its own against the same limit, never their sum.
        assert_eq!(stand(10, Some((0, 1_000_000))), Expired(Volume), "tx alone at the limit, rx idle");
        assert_eq!(stand(10, Some((1_000_000, 0))), Expired(Volume), "rx alone at the limit, tx idle");
        assert_eq!(stand(10, Some((999_999, 999_999))), RenewAhead(Volume), "their sum would be past a combined limit; neither direction is");
        assert_eq!(stand(10, Some((0, 800_000))), RenewAhead(Volume), "tx alone at the renewal point");
        assert_eq!(stand(10, Some((800_000, 0))), RenewAhead(Volume), "rx alone at the renewal point");
        assert_eq!(stand(10, Some((799_999, 0))), InTime);
        assert_eq!(stand(10, Some((0, 799_999))), InTime);
        // Independence: an idle old SA ends with its seconds, a young full one with its volume.
        assert_eq!(stand(3600, both(0)), Expired(Seconds));
        assert_eq!(stand(0, both(1_000_000)), Expired(Volume));
        assert_eq!(stand(0, both(900_000)), RenewAhead(Volume), "no minimum age gates the volume");
        // An end beats a renewal point, whichever limit either belongs to.
        assert_eq!(stand(2880, both(1_000_000)), Expired(Volume), "renewal point of the seconds, end of the volume");
        assert_eq!(stand(3600, both(800_000)), Expired(Seconds), "end of the seconds, renewal point of the volume");
        assert_eq!(stand(3600, both(1_000_000)), Expired(Seconds), "both ended: the seconds are named first");
        assert_eq!(stand(3000, both(900_000)), RenewAhead(Seconds), "two renewal points: the seconds are named first");
        // A limit of zero ends the SA at once instead of reading as no limit.
        assert_eq!(t.standing(secs(0), 3600, both(0), Some(0)), Expired(Volume));
        // Lifetimes of 0 and 1 s, and the largest.
        assert_eq!(t.standing(Duration::ZERO, 0, None, None), Expired(Seconds));
        assert_eq!(t.standing(ms(999), 1, None, None), InTime, "1 s: renewed at the minimum interval, which is its end");
        assert_eq!(t.standing(ms(1_000), 1, None, None), Expired(Seconds));
        assert_eq!(t.standing(ms(14_999), 30, None, None), InTime);
        assert_eq!(t.standing(secs(15), 30, None, None), RenewAhead(Seconds));
        assert_eq!(t.standing(secs(3_435_973_836), u32::MAX, None, None), RenewAhead(Seconds));
        assert_eq!(t.standing(ms(3_435_973_835_999), u32::MAX, None, None), InTime);
    }

    #[test]
    fn a_renewal_is_asked_for_by_the_standing_and_a_failed_one_is_retried_by_it() {
        let t = TIMING;
        // In time: nothing is due, whatever the history.
        assert!(!t.due_by_standing(InTime, None, secs(3000)));
        assert!(!t.due_by_standing(InTime, Some(secs(1000)), Duration::ZERO));
        // Nearing its seconds: never tried is due at once, a failed one after half of what is left.
        assert!(t.due_by_standing(RenewAhead(Seconds), None, secs(20)));
        assert!(!t.due_by_standing(RenewAhead(Seconds), Some(ms(9_999)), secs(20)));
        assert!(t.due_by_standing(RenewAhead(Seconds), Some(secs(10)), secs(20)));
        assert!(!t.due_by_standing(RenewAhead(Seconds), Some(ms(29_999)), secs(3000)));
        assert!(t.due_by_standing(RenewAhead(Seconds), Some(RETRY_MAX), secs(3000)));
        // Nearing its volume, or ended by any limit: the shortest spacing, whatever is left.
        for standing in [RenewAhead(Volume), RenewAhead(DataPlane), Expired(Seconds), Expired(Volume), Expired(DataPlane)] {
            for remaining in [Duration::ZERO, ms(1), secs(20), secs(3000)] {
                assert!(t.due_by_standing(standing, None, remaining), "{standing:?} {remaining:?}");
                assert!(!t.due_by_standing(standing, Some(RETRY_MIN - ms(1)), remaining), "{standing:?} {remaining:?}");
                assert!(t.due_by_standing(standing, Some(RETRY_MIN), remaining), "{standing:?} {remaining:?}");
            }
        }
    }

    #[test]
    fn every_figure_of_the_timing_is_read() {
        let base = TIMING;
        let nine_tenths = RenewalTiming { margin: Share::new(9, 10, Rounding::Down), ..base };
        assert_eq!(nine_tenths.renewal_age(3600), secs(3240));
        assert_eq!(base.renewal_age(3600), secs(2880));
        let later_earliest = RenewalTiming { earliest: Share::new(3, 4, Rounding::Down), ..base };
        assert_eq!(later_earliest.renewal_age(30), ms(22_500));
        assert_eq!(base.renewal_age(30), secs(15));
        let longer_lead = RenewalTiming { lead: secs(1000), ..base };
        assert_eq!(longer_lead.renewal_age(3600), secs(2600));
        let longer_min = RenewalTiming { min_interval: secs(10), ..base };
        assert_eq!(longer_min.renewal_age(2), secs(10));
        let retries = RenewalTiming { retry_min: secs(1), retry_max: secs(60), ..base };
        assert_eq!(retries.retry_after(secs(1)), secs(1));
        assert_eq!(retries.retry_after(secs(100)), secs(50));
        assert_eq!(retries.retry_after(Duration::ZERO), secs(60));
        assert!(retries.due_by_standing(Expired(Volume), Some(secs(1)), Duration::ZERO));
        assert!(!base.due_by_standing(Expired(Volume), Some(secs(1)), Duration::ZERO));
        let volume = RenewalTiming { volume_margin: Share::new(1, 2, Rounding::Up), ..base };
        assert_eq!(volume.volume_renewal_point(1001), 501);
        assert_eq!(volume.standing(secs(10), 3600, Some((501, 0)), Some(1001)), RenewAhead(Volume));
        assert_eq!(base.standing(secs(10), 3600, Some((501, 0)), Some(1001)), InTime);
        assert_eq!(volume.renewal_age(3600), base.renewal_age(3600), "the volume's margin is not the seconds'");
    }

    #[test]
    fn a_degenerate_timing_does_not_panic() {
        let inverted = RenewalTiming { retry_min: secs(60), retry_max: secs(10), ..TIMING };
        for remaining in [Duration::ZERO, ms(1), secs(20), secs(3600), Duration::MAX] {
            assert_eq!(inverted.retry_after(remaining), secs(10), "retry_max wins ({remaining:?})");
        }
        let extreme = RenewalTiming {
            margin: Share::new(1, 1, Rounding::Up),
            earliest: Share::new(0, 1, Rounding::Down),
            lead: Duration::MAX,
            min_interval: Duration::MAX,
            retry_min: Duration::MAX,
            retry_max: Duration::ZERO,
            volume_margin: Share::new(u64::MAX, u64::MAX, Rounding::Down),
        };
        for life in [0, 1, 39, 40, u32::MAX] {
            assert_eq!(extreme.renewal_age(life), Duration::MAX, "{life} s");
            let _ = extreme.standing(Duration::MAX, life, Some((u64::MAX, u64::MAX)), Some(u64::MAX));
            let _ = extreme.due_by_age(Duration::MAX, life, Some(Duration::MAX));
        }
        let none = RenewalTiming { lead: Duration::ZERO, min_interval: Duration::ZERO, ..TIMING };
        assert_eq!(none.renewal_age(0), Duration::ZERO);
        assert_eq!(none.renewal_age(100), secs(80));
        // An earliest share past the margin moves the renewal past the margin, and the lead.
        let late = RenewalTiming { earliest: Share::new(19, 20, Rounding::Down), ..TIMING };
        assert_eq!(late.renewal_age(100), secs(95));
    }
}
