//! Round-trip-time measurement and the retransmission schedule that follows it
//! (RFC 2408 §5.1).
//!
//! RFC 2408 §5.1, on transmitting an ISAKMP message: "Implementations MUST NOT use
//! a fixed timer. Instead, transmission timer values should be adjusted
//! dynamically based on measured round trip times. In addition, successive
//! retransmissions of the same packet should be separated by increasingly longer
//! time intervals (e.g., exponential backoff)." The second sentence is
//! [`crate::ikev1::retransmit_waits`]; this module is the first one.
//!
//! RFC 2408 names no algorithm, so the estimator is the one TCP uses for the same
//! job, RFC 6298 §2: `RTTVAR = 3/4 RTTVAR + 1/4 |SRTT - R|`, `SRTT = 7/8 SRTT + 1/8 R`,
//! `RTO = SRTT + max(G, 4 RTTVAR)`, with Karn's rule (§5) for the samples: a round
//! trip is measured only when the request was sent once, because the reply to a
//! request that went out twice may answer either send. An exchange that needed a
//! retransmission takes no sample and backs the timer off instead (§5.5, §5.7), and
//! the backoff stays until a sample is taken, so a path that turned slow is not
//! retransmitted into for ever at the old estimate.
//!
//! What the estimate may do is bounded by what the caller asked for. The caller's
//! patience for a silent gateway -- its read timeout once per send -- is the
//! exchange's *deadline*, and nothing here moves it: neither the waits nor the
//! datagrams that arrive while waiting (which are read against that deadline, not
//! against a timer of their own) can make an exchange last longer. Inside it the
//! first wait is the RTO, but never longer than the first wait of the schedule
//! without an estimate, and never shorter than [`MIN_RTO`] (RFC 6298 §2.4 asks for
//! a second) -- so an estimate can only make a retransmission come sooner than
//! the unmeasured schedule would, never later, and a path with no samples, or one
//! whose exchanges depend on a backend (XAUTH, Mode-Config), keeps exactly the
//! schedule it had. Each wait after the first is twice the one before, as many
//! sends as fit (at most [`MAX_SENDS`]), and the last wait runs to the deadline.
//!
//! The estimator is per ISAKMP SA: [`RoundTrips`] is shared by every clone of a
//! [`crate::ikev1::phase1::Phase1State`], so what `connect` measured serves the
//! rekeys that follow, and it starts empty after `Phase1State::resume`.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use crate::debug::ike_debug;
use crate::ikev1::retransmit_waits;

/// The shortest retransmission timer an estimate is allowed to set (RFC 6298 §2.4:
/// "if it is less than 1 second, then the RTO SHOULD be rounded up to 1 second"),
/// unless the unmeasured schedule's own first wait is shorter still.
pub(crate) const MIN_RTO: Duration = Duration::from_secs(1);

/// The most times one message is sent when the timer follows an estimate (the
/// retry counter of RFC 2408 §5.1 -- after it, RETRY LIMIT REACHED). Without an
/// estimate the caller's own count applies.
const MAX_SENDS: u32 = 8;

/// The RFC 6298 estimator, in nanoseconds so that its arithmetic cannot overflow
/// whatever `Duration` it is given (the largest `Duration` is under 2^94 ns).
#[derive(Default)]
struct Estimator {
    srtt: Option<u128>,
    rttvar: u128,
    /// How many times the timer has been doubled since the last sample.
    backoff: u32,
    #[cfg(test)]
    samples: u32,
}

impl Estimator {
    /// The clock granularity `G` of RFC 6298 §2, a floor under the variance term.
    const GRANULARITY: u128 = 1_000_000;
    /// Doublings beyond this change nothing: the timer is capped by the schedule.
    const MAX_BACKOFF: u32 = 16;

    /// RFC 6298 §2: the first sample sets `SRTT = R`, `RTTVAR = R/2`; every later
    /// one moves them by 1/8 and 1/4 (the variance first, against the old `SRTT`).
    /// A sample ends any backoff (§5.7).
    fn sample(&mut self, round_trip: Duration) {
        let r = round_trip.as_nanos();
        match self.srtt {
            None => {
                self.srtt = Some(r);
                self.rttvar = r / 2;
            }
            Some(srtt) => {
                self.rttvar = (3 * self.rttvar + srtt.abs_diff(r)) / 4;
                self.srtt = Some((7 * srtt + r) / 8);
            }
        }
        self.backoff = 0;
        #[cfg(test)]
        {
            self.samples += 1;
        }
    }

    /// `timeouts` retransmission timers ran out (RFC 6298 §5.5): the timer doubles
    /// each time, until a sample is taken.
    fn timed_out(&mut self, timeouts: u32) {
        self.backoff = self.backoff.saturating_add(timeouts).min(Self::MAX_BACKOFF);
    }

    /// `SRTT + max(G, 4 RTTVAR)`, doubled once per backoff -- `None` until there
    /// is a sample, as there is nothing to follow.
    fn rto(&self) -> Option<Duration> {
        let base = self.srtt? + (4 * self.rttvar).max(Self::GRANULARITY);
        Some(duration(base.saturating_mul(1u128 << self.backoff)))
    }
}

/// A `Duration` from nanoseconds, the largest one there is when they do not fit.
fn duration(nanos: u128) -> Duration {
    const NANOS_PER_SEC: u128 = 1_000_000_000;
    u64::try_from(nanos / NANOS_PER_SEC).map_or(Duration::MAX, |secs| Duration::new(secs, (nanos % NANOS_PER_SEC) as u32))
}

/// What has been measured of the round trip to a gateway, shared by every clone
/// (see the module doc).
#[derive(Clone)]
pub(crate) struct RoundTrips {
    estimator: Arc<Mutex<Estimator>>,
    /// [`MIN_RTO`], or a smaller one a test sets so that a schedule can be
    /// observed without waiting seconds for it.
    floor: Duration,
}

impl Default for RoundTrips {
    fn default() -> Self {
        Self { estimator: Arc::default(), floor: MIN_RTO }
    }
}

impl RoundTrips {
    fn estimator(&self) -> MutexGuard<'_, Estimator> {
        self.estimator.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A round trip measured from a request sent once and answered.
    pub(crate) fn sampled(&self, round_trip: Duration) {
        let mut estimator = self.estimator();
        estimator.sample(round_trip);
        ike_debug!("round trip {round_trip:?}: smoothed {:?}, timer {:?}", estimator.srtt.map(duration), estimator.rto());
    }

    /// `timeouts` waits ran out before the exchange ended.
    pub(crate) fn timed_out(&self, timeouts: u32) {
        self.estimator().timed_out(timeouts);
    }

    /// The waits after each send of a message the caller would wait `total` for
    /// in all, and would send at least `sends` times: [`retransmit_plan`] on what
    /// is known of the path.
    pub(crate) fn plan(&self, total: Duration, sends: u32) -> Vec<Duration> {
        retransmit_plan(total, sends, self.estimator().rto(), self.floor)
    }

    #[cfg(test)]
    pub(crate) fn with_floor(floor: Duration) -> Self {
        Self { floor, ..Self::default() }
    }

    #[cfg(test)]
    pub(crate) fn rto(&self) -> Option<Duration> {
        self.estimator().rto()
    }

    #[cfg(test)]
    pub(crate) fn smoothed(&self) -> Option<Duration> {
        self.estimator().srtt.map(duration)
    }

    #[cfg(test)]
    pub(crate) fn backoff(&self) -> u32 {
        self.estimator().backoff
    }

    #[cfg(test)]
    pub(crate) fn samples(&self) -> u32 {
        self.estimator().samples
    }
}

/// How long to wait after each send of one message, when the whole wait is `total`,
/// `sends` sends are the least there are, and the round trip is estimated at `rto`
/// (`None`: it is not -- the schedule is then [`retransmit_waits`]).
///
/// The first wait is `rto` within `floor..=`the first wait of [`retransmit_waits`]
/// (a `floor` above that ceiling gives way to it, so the ceiling is the last
/// word): never later than the unmeasured schedule would retransmit, never
/// sooner than `floor`. Each wait
/// after it is twice the one before, for as many as still fit in `total` (at
/// most [`MAX_SENDS`], and never fewer than `sends`), and the last one is
/// stretched to end exactly at `total`, so that the deadline is the caller's
/// however the waits were cut. Every send goes out no later than it would
/// unmeasured, and the waits never shrink.
pub(crate) fn retransmit_plan(total: Duration, sends: u32, rto: Option<Duration>, floor: Duration) -> Vec<Duration> {
    let fixed = retransmit_waits(total, sends);
    let (Some(rto), Some(&ceiling)) = (rto, fixed.first()) else { return fixed };
    let first = rto.max(floor).min(ceiling);
    if first.is_zero() {
        return fixed;
    }
    let mut waits = Vec::new();
    let (mut spent, mut next) = (Duration::ZERO, first);
    while (waits.len() as u32) < MAX_SENDS.max(sends) {
        match spent.checked_add(next) {
            Some(after) if after <= total => {
                waits.push(next);
                spent = after;
                next = next.saturating_mul(2);
            }
            _ => break,
        }
    }
    // `first` is at most `total / (2^sends - 1)`, so `sends` waits always fit.
    debug_assert!(waits.len() >= sends as usize, "{waits:?} for {sends} sends in {total:?}");
    if let Some(last) = waits.last_mut() {
        *last += total - spent;
    }
    waits
}

/// Send one request and wait for its answer, again and again as `patience` says,
/// measuring the round trip when `rtt` is given.
///
/// `patience` is what the caller will wait for a silent gateway: `Some((timeout,
/// sends))` is `timeout` once per send, `sends` sends at least, in all (`None`:
/// wait for ever, sending once). With `rtt` the waits follow the estimate
/// ([`RoundTrips::plan`]) and the outcome feeds it; without it they are
/// [`retransmit_waits`], and nothing is measured -- what an exchange whose reply
/// depends on more than the path (a backend, a person) is run with.
///
/// `send` puts the request on the wire (its argument counts the sends so far);
/// `wait` waits up to the given time for the reply -- `Ok(None)`: it did not come
/// -- and must be bound by it, whatever else arrives meanwhile. `clock` is the
/// monotonic clock the round trip is read from. Returns `Ok(None)` when every wait
/// ran out.
///
/// Karn's rule (RFC 6298 §5): a reply to the first send, and only that, is a
/// sample. A reply after a retransmission is used but not measured -- it may
/// answer any of the sends -- and the timeouts that came before it back the timer
/// off, as do those of an exchange nothing answered.
pub(crate) fn exchange<T, E>(
    rtt: Option<&RoundTrips>,
    patience: Option<(Duration, u32)>,
    clock: &dyn Fn() -> Instant,
    mut send: impl FnMut(u32) -> Result<(), E>,
    mut wait: impl FnMut(Option<Duration>) -> Result<Option<T>, E>,
) -> Result<Option<T>, E> {
    let waits: Vec<Option<Duration>> = match patience {
        Some((timeout, sends)) => {
            let total = timeout.saturating_mul(sends);
            let waits = match rtt {
                Some(rtt) => rtt.plan(total, sends),
                None => retransmit_waits(total, sends),
            };
            waits.into_iter().map(Some).collect()
        }
        None => vec![None],
    };
    let started = clock();
    for (sent, wait_for) in waits.iter().enumerate() {
        let sent = sent as u32;
        send(sent)?;
        if let Some(reply) = wait(*wait_for)? {
            if let Some(rtt) = rtt {
                if sent == 0 {
                    rtt.sampled(clock().saturating_duration_since(started));
                } else {
                    rtt.timed_out(sent);
                }
            }
            return Ok(Some(reply));
        }
    }
    if let Some(rtt) = rtt {
        rtt.timed_out(waits.len() as u32);
    }
    Ok(None)
}

#[cfg(test)]
mod tests;
