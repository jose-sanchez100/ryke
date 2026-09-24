//! The estimator, the schedule and the exchange driver of [`super`], run without
//! a socket and without a sleep: the estimator on numbers, the driver on a virtual
//! clock that only moves when a wait says so.

use super::*;
use std::cell::{Cell, RefCell};

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

/// The estimator that has taken these samples, in order.
fn estimator(samples: &[Duration]) -> Estimator {
    let mut estimator = Estimator::default();
    for s in samples {
        estimator.sample(*s);
    }
    estimator
}

// ---- the estimator (RFC 6298 §2, §5) ----

#[test]
fn nothing_is_followed_before_the_first_sample_not_even_after_timeouts() {
    let mut estimator = Estimator::default();
    assert_eq!(estimator.rto(), None);
    estimator.timed_out(3);
    assert_eq!(estimator.rto(), None, "a backoff has no estimate to scale");
}

/// RFC 6298 §2.2: `SRTT = R`, `RTTVAR = R/2`, so `RTO = R + 4 * R/2 = 3R`.
#[test]
fn the_first_sample_sets_the_smoothed_time_and_half_of_it_as_variance() {
    let estimator = estimator(&[ms(100)]);
    assert_eq!(estimator.srtt, Some(ms(100).as_nanos()));
    assert_eq!(estimator.rttvar, ms(50).as_nanos());
    assert_eq!(estimator.rto(), Some(ms(300)));
}

/// RFC 6298 §2.3 with the weights 1/8 and 1/4: from (100 ms, 50 ms), a sample of
/// 200 ms gives `RTTVAR = (3 * 50 + |100 - 200|) / 4 = 62.5 ms` -- against the
/// *old* `SRTT` -- and `SRTT = (7 * 100 + 200) / 8 = 112.5 ms`.
#[test]
fn a_later_sample_moves_the_variance_by_a_quarter_and_the_smoothed_time_by_an_eighth() {
    let estimator = estimator(&[ms(100), ms(200)]);
    assert_eq!(estimator.rttvar, Duration::from_micros(62_500).as_nanos());
    assert_eq!(estimator.srtt, Some(Duration::from_micros(112_500).as_nanos()));
    assert_eq!(estimator.rto(), Some(Duration::from_micros(112_500 + 4 * 62_500)));
}

/// A sample below the smoothed time moves it down just the same (`abs_diff`):
/// from (200 ms, 100 ms), a sample of 100 ms gives `RTTVAR = (3 * 100 + 100) / 4 =
/// 100 ms` and `SRTT = (7 * 200 + 100) / 8 = 187.5 ms`.
#[test]
fn a_faster_sample_lowers_the_smoothed_time() {
    let estimator = estimator(&[ms(200), ms(100)]);
    assert_eq!(estimator.rttvar, ms(100).as_nanos());
    assert_eq!(estimator.srtt, Some(Duration::from_micros(187_500).as_nanos()));
}

/// A path that stops varying leaves only the clock granularity `G` above the
/// smoothed time (RFC 6298 §2.3: `max(G, 4 * RTTVAR)`).
#[test]
fn a_steady_path_settles_a_granularity_above_its_round_trip() {
    let steady = estimator(&[ms(100); 200]);
    assert_eq!(steady.rttvar, 0);
    assert_eq!(steady.rto(), Some(ms(101)));
    assert_eq!(estimator(&[Duration::ZERO]).rto(), Some(ms(1)), "a round trip of nothing still leaves G");
}

/// RFC 6298 §5.5 and §5.7: every timeout doubles the timer, and it stays doubled
/// until a sample is taken -- which puts it back to what the estimate says.
#[test]
fn timeouts_double_the_timer_until_a_sample_is_taken() {
    let mut estimator = estimator(&[ms(100)]);
    estimator.timed_out(1);
    assert_eq!(estimator.rto(), Some(ms(600)));
    estimator.timed_out(2);
    assert_eq!(estimator.rto(), Some(ms(2400)), "1 + 2 timeouts, three doublings");
    estimator.sample(ms(100));
    assert_eq!(estimator.backoff, 0);
    assert!(estimator.rto().unwrap() < ms(600), "the sample ended the backoff: {:?}", estimator.rto());
}

#[test]
fn the_extremes_of_duration_neither_overflow_nor_panic() {
    let mut huge = estimator(&[Duration::MAX]);
    assert_eq!(huge.rto(), Some(Duration::MAX), "the timer saturates");
    for _ in 0..100 {
        huge.sample(Duration::MAX);
        huge.sample(Duration::ZERO);
    }
    huge.timed_out(u32::MAX);
    assert_eq!(huge.backoff, 16, "the backoff is capped, not wrapped");
    assert!(huge.rto().is_some());

    // One nanosecond: SRTT 1 ns, RTTVAR 0, so 1 ns + G, doubled 16 times and no more.
    let mut tiny = estimator(&[Duration::from_nanos(1)]);
    assert_eq!(tiny.rto(), Some(Duration::from_nanos(1_000_001)));
    tiny.timed_out(u32::MAX);
    tiny.timed_out(u32::MAX);
    assert_eq!(tiny.rto(), Some(Duration::from_nanos(1_000_001 << 16)));
}

#[test]
fn nanoseconds_beyond_a_duration_are_the_largest_duration() {
    assert_eq!(duration(0), Duration::ZERO);
    assert_eq!(duration(1_500_000_001), Duration::new(1, 500_000_001));
    assert_eq!(duration(Duration::MAX.as_nanos()), Duration::MAX);
    assert_eq!(duration(Duration::MAX.as_nanos() + 1), Duration::MAX);
    assert_eq!(duration(u128::MAX), Duration::MAX);
}

// ---- the schedule ----

/// Without an estimate the schedule is the caller's own, untouched.
#[test]
fn no_estimate_no_change() {
    for (total, sends) in [(secs(30), 3), (secs(15), 3), (ms(300), 3), (secs(9), 1), (Duration::ZERO, 3), (Duration::MAX, 3)] {
        assert_eq!(retransmit_plan(total, sends, None, MIN_RTO), retransmit_waits(total, sends), "{total:?} in {sends}");
    }
}

/// The worker's Main Mode: 10 s per send, three sends, so 30 s in all. On a fast
/// path the first retransmission leaves after a second, not after 4.3 s, and the
/// deadline is still 30 s.
#[test]
fn a_fast_path_retransmits_after_the_floor_and_still_ends_at_the_deadline() {
    let plan = retransmit_plan(secs(30), 3, Some(ms(300)), MIN_RTO);
    assert_eq!(plan, [secs(1), secs(2), secs(4), secs(23)]);
    assert_eq!(plan.iter().sum::<Duration>(), secs(30));
}

/// Quick Mode's 5 s per send: an estimate of 1.5 s fits three sends.
#[test]
fn an_estimate_above_the_floor_sets_the_first_wait() {
    assert_eq!(retransmit_plan(secs(15), 3, Some(ms(1500)), MIN_RTO), [ms(1500), secs(3), ms(10_500)]);
}

/// An estimate slower than the unmeasured first wait (4.3 s here) gets no more
/// than that: the schedule is the unmeasured one, exactly.
#[test]
fn a_slow_estimate_is_held_to_the_unmeasured_schedule() {
    for rto in [secs(5), secs(20), secs(3600), Duration::MAX] {
        assert_eq!(retransmit_plan(secs(30), 3, Some(rto), MIN_RTO), retransmit_waits(secs(30), 3), "{rto:?}");
    }
}

/// No estimate is followed below the floor, and a floor above what the unmeasured
/// schedule waits first gives way to it.
#[test]
fn the_floor_bounds_the_timer_from_below_unless_the_unmeasured_wait_is_shorter() {
    assert_eq!(retransmit_plan(secs(30), 3, Some(ms(3)), MIN_RTO)[0], secs(1));
    assert_eq!(retransmit_plan(secs(30), 3, Some(Duration::ZERO), MIN_RTO)[0], secs(1));
    assert_eq!(retransmit_plan(secs(30), 3, Some(ms(3)), ms(10))[0], ms(10), "a floor a test lowers");
    assert_eq!(retransmit_plan(ms(300), 3, Some(ms(3)), MIN_RTO), retransmit_waits(ms(300), 3), "a 300 ms deadline cannot wait a second first");
}

/// A send is made when its whole wait fits: waits that add up to the deadline
/// exactly (1 + 2 + 4 + 8 = 15 s) all count, and one more second does not
/// make room for a fifth.
#[test]
fn a_send_whose_wait_fills_the_deadline_exactly_is_made() {
    assert_eq!(retransmit_plan(secs(15), 3, Some(secs(1)), MIN_RTO), [secs(1), secs(2), secs(4), secs(8)]);
    assert_eq!(retransmit_plan(secs(16), 3, Some(secs(1)), MIN_RTO), [secs(1), secs(2), secs(4), secs(9)], "the last wait takes what is left");
    assert_eq!(retransmit_plan(secs(14), 3, Some(secs(1)), MIN_RTO), [secs(1), secs(2), secs(11)], "8 s more would pass the deadline");
}

/// The retry counter: eight sends when the timer follows an estimate, or the
/// caller's own count when that is more -- however much time there is.
#[test]
fn the_sends_are_capped_at_the_retry_limit_or_the_callers_count() {
    let plan = retransmit_plan(secs(3600), 3, Some(secs(1)), MIN_RTO);
    assert_eq!(plan.len(), 8);
    assert_eq!(plan[..7], [secs(1), secs(2), secs(4), secs(8), secs(16), secs(32), secs(64)]);
    assert_eq!(plan.iter().sum::<Duration>(), secs(3600));
    assert_eq!(retransmit_plan(secs(3600), 10, Some(secs(1)), MIN_RTO).len(), 10, "a caller that asked for ten gets ten");
}

#[test]
fn a_total_of_nothing_has_no_timer_to_follow() {
    assert_eq!(retransmit_plan(Duration::ZERO, 3, Some(ms(300)), MIN_RTO), [Duration::ZERO; 3]);
}

/// Whatever the deadline, the count, the estimate and the floor: the waits add up
/// to the deadline, are never fewer than the caller's sends nor more than the
/// limit, never shrink, start where the estimate says within the bounds, and
/// every send leaves no later than it would unmeasured.
#[test]
fn every_plan_ends_at_the_deadline_and_no_send_is_later_than_unmeasured() {
    let totals = [Duration::ZERO, Duration::from_nanos(1), Duration::from_nanos(7), ms(30), secs(1), secs(15), secs(30), secs(3600), Duration::MAX];
    let rtos = [None, Some(Duration::ZERO), Some(Duration::from_nanos(1)), Some(ms(1)), Some(ms(100)), Some(secs(1)), Some(secs(3)), Some(secs(10)), Some(Duration::MAX)];
    let mut wrong = Vec::new();
    for total in totals {
        for sends in 1..=6u32 {
            let fixed = retransmit_waits(total, sends);
            for rto in rtos {
                for floor in [Duration::ZERO, ms(10), MIN_RTO] {
                    let plan = retransmit_plan(total, sends, rto, floor);
                    let tag = format!("total {total:?}, {sends} sends, rto {rto:?}, floor {floor:?}: {plan:?}");
                    if plan.iter().try_fold(Duration::ZERO, |sum, w| sum.checked_add(*w)) != Some(total) {
                        wrong.push(format!("does not add up to the deadline -- {tag}"));
                    }
                    if plan.len() < sends as usize || plan.len() > MAX_SENDS.max(sends) as usize {
                        wrong.push(format!("{} sends -- {tag}", plan.len()));
                    }
                    if plan.windows(2).any(|w| w[1] < w[0]) {
                        wrong.push(format!("a wait shorter than the one before -- {tag}"));
                    }
                    let (mut measured, mut unmeasured) = (Duration::ZERO, Duration::ZERO);
                    for k in 0..(sends as usize).min(plan.len()) {
                        if measured > unmeasured {
                            wrong.push(format!("send {k} later than unmeasured -- {tag}"));
                        }
                        measured = measured.saturating_add(plan[k]);
                        unmeasured = unmeasured.saturating_add(fixed[k]);
                    }
                    if let (Some(rto), Some(&ceiling)) = (rto, fixed.first()) {
                        let low = floor.min(ceiling).max(rto.min(ceiling));
                        if plan[0] < low || plan[0] > ceiling {
                            wrong.push(format!("first wait outside {low:?}..={ceiling:?} -- {tag}"));
                        }
                    }
                }
            }
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
}

// ---- an exchange on a virtual clock ----

/// A gateway and a clock that only moves when a wait says so: the reply to the
/// n-th send arrives `latency[n]` after that send (`None`: it is lost). No sleep
/// anywhere -- what the exchange did is read off the virtual times.
struct Sim {
    base: Instant,
    now: Cell<Duration>,
    latency: Vec<Option<Duration>>,
    sent_at: RefCell<Vec<Duration>>,
    answered: RefCell<Vec<bool>>,
}

impl Sim {
    fn new(latency: &[Option<Duration>]) -> Self {
        Self { base: Instant::now(), now: Cell::new(Duration::ZERO), latency: latency.to_vec(), sent_at: RefCell::default(), answered: RefCell::default() }
    }

    fn clock(&self) -> Instant {
        self.base + self.now.get()
    }

    /// Run one exchange; the reply is the number of the send it answers.
    fn run(&self, rtt: Option<&RoundTrips>, patience: Option<(Duration, u32)>) -> Option<usize> {
        let reply: Result<Option<usize>, ()> = exchange(
            rtt,
            patience,
            &|| self.clock(),
            |n| {
                assert_eq!(n as usize, self.sent_at.borrow().len(), "sends are counted from zero, one at a time");
                self.sent_at.borrow_mut().push(self.now.get());
                self.answered.borrow_mut().push(false);
                Ok(())
            },
            |wait| {
                let now = self.now.get();
                let next = (0..self.sent_at.borrow().len())
                    .filter(|&k| !self.answered.borrow()[k])
                    .filter_map(|k| self.latency.get(k).copied().flatten().map(|l| (self.sent_at.borrow()[k] + l, k)))
                    .min();
                let deadline = wait.map(|w| now.saturating_add(w));
                if let Some((arrives, k)) = next {
                    if deadline.is_none_or(|d| arrives <= d) {
                        self.now.set(now.max(arrives));
                        self.answered.borrow_mut()[k] = true;
                        return Ok(Some(k));
                    }
                }
                let deadline = deadline.expect("waiting for ever for a reply that is never coming");
                self.now.set(deadline);
                Ok(None)
            },
        );
        reply.unwrap()
    }

    fn sends(&self) -> Vec<Duration> {
        self.sent_at.borrow().clone()
    }
}

/// A `RoundTrips` that has taken one sample, with the given floor.
fn seeded(floor: Duration, round_trip: Duration) -> RoundTrips {
    let rtt = RoundTrips::with_floor(floor);
    rtt.sampled(round_trip);
    rtt
}

#[test]
fn a_reply_to_the_only_send_is_a_sample_of_exactly_its_round_trip() {
    let (sim, rtt) = (Sim::new(&[Some(ms(120))]), RoundTrips::default());
    assert_eq!(sim.run(Some(&rtt), Some((secs(10), 3))), Some(0));
    assert_eq!(rtt.samples(), 1);
    assert_eq!(rtt.smoothed(), Some(ms(120)));
    assert_eq!(rtt.backoff(), 0);
    assert_eq!(sim.sends(), [Duration::ZERO]);
}

/// Nothing measured yet: a lost request is sent again on the unmeasured schedule,
/// 10 s * 3 / 7 later, and the exchange takes no sample of it.
#[test]
fn without_an_estimate_a_lost_request_waits_the_unmeasured_time() {
    let (sim, rtt) = (Sim::new(&[None, Some(ms(50))]), RoundTrips::default());
    assert_eq!(sim.run(Some(&rtt), Some((secs(10), 3))), Some(1));
    assert_eq!(sim.sends(), [Duration::ZERO, retransmit_waits(secs(30), 3)[0]]);
    assert_eq!(rtt.samples(), 0, "the reply followed a retransmission");
    assert_eq!(rtt.backoff(), 1, "one timer ran out");
}

/// The point of measuring: with an estimate the same lost request is sent again
/// after a second instead of 4.3 s.
#[test]
fn with_an_estimate_a_lost_request_is_sent_again_sooner() {
    let (sim, rtt) = (Sim::new(&[None, Some(ms(30))]), seeded(MIN_RTO, ms(100)));
    assert_eq!(sim.run(Some(&rtt), Some((secs(10), 3))), Some(1));
    assert_eq!(sim.sends(), [Duration::ZERO, MIN_RTO]);
    assert_eq!(sim.now.get(), MIN_RTO + ms(30));
}

/// The sends after the first keep backing off, and there are more of them than the
/// unmeasured three when the deadline has room.
#[test]
fn a_silent_gateway_is_sent_to_at_growing_intervals_until_the_deadline() {
    let (sim, rtt) = (Sim::new(&[]), seeded(MIN_RTO, ms(100)));
    assert_eq!(sim.run(Some(&rtt), Some((secs(10), 3))), None);
    assert_eq!(sim.sends(), [Duration::ZERO, secs(1), secs(3), secs(7)]);
    assert_eq!(sim.now.get(), secs(30), "the last wait ends exactly at the caller's deadline");
    assert_eq!(rtt.backoff(), 4, "the seeded sample had none; the four timers that ran out back the timer off");
}

/// The same silent gateway without a measurement: exactly the unmeasured
/// schedule, three sends, and the same deadline.
#[test]
fn a_silent_gateway_without_an_estimate_gets_the_unmeasured_schedule() {
    let (sim, rtt) = (Sim::new(&[]), RoundTrips::default());
    assert_eq!(sim.run(Some(&rtt), Some((secs(10), 3))), None);
    let fixed = retransmit_waits(secs(30), 3);
    assert_eq!(sim.sends(), [Duration::ZERO, fixed[0], fixed[0] + fixed[1]]);
    assert_eq!(sim.now.get(), secs(30));
}

/// Karn (RFC 6298 §5): the reply that comes after a retransmission may answer
/// either send, so it is not a sample -- here the reply to send 0, arriving late.
#[test]
fn a_reply_after_a_retransmission_is_not_a_sample() {
    let rtt = seeded(ms(10), ms(100)); // timer 300 ms
    let sim = Sim::new(&[Some(ms(500)), Some(ms(500))]);
    assert_eq!(sim.run(Some(&rtt), Some((secs(10), 3))), Some(0), "the late reply to the first send is the one that came");
    assert_eq!(sim.sends(), [Duration::ZERO, ms(300)]);
    assert_eq!(rtt.samples(), 1, "only the seeded one");
    assert_eq!(rtt.smoothed(), Some(ms(100)), "the estimate did not move");
    assert_eq!(rtt.backoff(), 1);
}

/// Every timer that ran out before the reply backs the timer off, not just one of
/// them: two lost sends, then an answer to the third.
#[test]
fn each_timer_that_ran_out_before_the_reply_backs_the_timer_off() {
    let rtt = seeded(ms(10), ms(100)); // timer 300 ms
    let sim = Sim::new(&[None, None, Some(ms(30))]);
    assert_eq!(sim.run(Some(&rtt), Some((secs(10), 3))), Some(2));
    assert_eq!(sim.sends(), [Duration::ZERO, ms(300), ms(900)], "300 ms, then twice that");
    assert_eq!(rtt.samples(), 1, "the reply followed retransmissions");
    assert_eq!(rtt.backoff(), 2);
    assert_eq!(rtt.rto(), Some(ms(1200)));
}

/// The backoff outlives the exchange (RFC 6298 §5.7), so the next one starts with
/// a longer timer, is answered without a retransmission, and *that* sample
/// teaches the estimator the slower path.
#[test]
fn a_path_that_turned_slow_is_learned_from_the_backed_off_timer() {
    let rtt = seeded(ms(10), ms(100)); // timer 300 ms
    assert_eq!(Sim::new(&[Some(ms(500))]).run(Some(&rtt), Some((secs(10), 3))), Some(0));
    assert_eq!(rtt.rto(), Some(ms(600)), "one timeout, doubled");
    let next = Sim::new(&[Some(ms(500))]);
    assert_eq!(next.run(Some(&rtt), Some((secs(10), 3))), Some(0));
    assert_eq!(next.sends(), [Duration::ZERO], "600 ms was long enough for a 500 ms reply");
    assert_eq!(rtt.samples(), 2);
    assert_eq!(rtt.backoff(), 0);
    assert!(rtt.smoothed().unwrap() > ms(100), "the estimate moved toward 500 ms: {:?}", rtt.smoothed());
}

/// Latencies that vary, each within the timer the previous ones set, are all
/// samples, each of exactly the time it took. (One beyond the timer is answered
/// after a retransmission and is not: see
/// `a_reply_after_a_retransmission_is_not_a_sample`.)
#[test]
fn a_varying_latency_is_followed_sample_by_sample() {
    let rtt = RoundTrips::with_floor(ms(10));
    let mut reference = Estimator::default();
    for latency in [ms(80), ms(120), ms(60), ms(100), ms(90), ms(150)] {
        assert_eq!(Sim::new(&[Some(latency)]).run(Some(&rtt), Some((secs(10), 3))), Some(0));
        reference.sample(latency);
        assert_eq!(rtt.rto(), reference.rto());
    }
    assert_eq!(rtt.samples(), 6);
}

/// An exchange run without an estimator (XAUTH, Mode-Config) follows the
/// unmeasured schedule and leaves the estimator alone, answered or not.
#[test]
fn an_exchange_without_an_estimator_measures_nothing_and_backs_nothing_off() {
    let rtt = seeded(MIN_RTO, ms(100));
    let (before, backoff) = (rtt.rto(), rtt.backoff());
    let sim = Sim::new(&[None, Some(ms(50))]);
    assert_eq!(sim.run(None, Some((secs(10), 3))), Some(1));
    assert_eq!(sim.sends(), [Duration::ZERO, retransmit_waits(secs(30), 3)[0]], "the unmeasured schedule, though an estimate exists");
    assert_eq!(Sim::new(&[Some(ms(40))]).run(None, Some((secs(10), 3))), Some(0));
    assert_eq!(Sim::new(&[]).run(None, Some((secs(10), 3))), None);
    assert_eq!((rtt.rto(), rtt.backoff(), rtt.samples()), (before, backoff, 1));
}

/// No read timeout: one send and no retransmission, as before -- and an answer to
/// that one send is still a sample.
#[test]
fn without_a_read_timeout_the_request_is_sent_once_and_waited_for_ever() {
    let (sim, rtt) = (Sim::new(&[Some(secs(3600))]), RoundTrips::default());
    assert_eq!(sim.run(Some(&rtt), None), Some(0));
    assert_eq!(sim.sends(), [Duration::ZERO]);
    assert_eq!(rtt.smoothed(), Some(secs(3600)));
}

/// An I/O error ends the exchange at once, and what it was measuring is not
/// half-recorded.
#[test]
fn an_error_from_the_send_or_the_wait_ends_the_exchange_and_leaves_the_estimate_alone() {
    let rtt = seeded(MIN_RTO, ms(100));
    let (before, backoff) = (rtt.rto(), rtt.backoff());
    let mut sends = 0;
    let failed_send: Result<Option<()>, &str> = exchange(
        Some(&rtt),
        Some((secs(10), 3)),
        &Instant::now,
        |_| {
            sends += 1;
            if sends == 2 { Err("send failed") } else { Ok(()) }
        },
        |_| Ok(None),
    );
    assert_eq!((failed_send, sends), (Err("send failed"), 2));
    let failed_wait: Result<Option<()>, &str> = exchange(Some(&rtt), Some((secs(10), 3)), &Instant::now, |_| Ok(()), |_| Err("read failed"));
    assert_eq!(failed_wait, Err("read failed"));
    assert_eq!((rtt.rto(), rtt.backoff(), rtt.samples()), (before, backoff, 1));
}

/// The largest patience there is, and none at all: no overflow, no panic, and the
/// exchange still ends where the waits say.
#[test]
fn the_extremes_of_patience_are_handled() {
    let rtt = seeded(MIN_RTO, ms(100));
    let sim = Sim::new(&[Some(ms(10))]);
    assert_eq!(sim.run(Some(&rtt), Some((Duration::MAX, 3))), Some(0));

    let silent = Sim::new(&[]);
    assert_eq!(silent.run(Some(&rtt), Some((Duration::ZERO, 3))), None);
    assert_eq!(silent.sends(), [Duration::ZERO; 3], "no time to wait: every send goes out at once and the exchange gives up");
    assert_eq!(silent.now.get(), Duration::ZERO);
}
