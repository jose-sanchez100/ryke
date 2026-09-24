//! IKEv1 (RFC 2409 / ISAKMP RFC 2408) — a self-contained implementation for the
//! Aggressive Mode + Xauth + Mode-Config + Quick Mode flow that Android's
//! built-in "IPSec Xauth PSK" client (Android ≤ 10) uses.
//!
//! This subtree deliberately shares nothing with the IKEv2 code except the
//! low-level crypto primitives (SHA/HMAC/AES/DES via RustCrypto and the MODP
//! [`crate::crypto::DhGroup`]). IKEv1's ISAKMP framing, its raw-keyed PRF (no
//! `prf+`), its CBC-with-IV-chaining encryption, and its Aggressive-Mode key
//! schedule are all structurally different from IKEv2.

pub mod cfg;
pub mod client;
pub mod crypto1;
pub mod informational;
pub mod isakmp;
pub mod modecfg;
pub mod payloads;
pub mod phase1;
pub mod phase2;
pub mod quick;
#[cfg(test)]
mod retransmit_tests;
// Not used until the client and Quick Mode run their exchanges through it.
#[allow(dead_code)]
mod rtt;
pub mod server;
pub mod xauth;

pub use client::{Client, Established};
pub use server::{Server, ServerEvent};

use std::time::Duration;

/// How long to wait for the answer after each of `sends` sends of one message
/// (the first, then each retransmission), when the whole wait is `total`.
///
/// RFC 2408 §5.1: "Implementations MUST NOT use a fixed timer", and successive
/// retransmissions "should be separated by increasingly longer time intervals
/// (e.g., exponential backoff)". Each wait here is twice the one before it
/// (1 : 2 : 4 for three sends), so the message is sent again soon when the
/// datagram was merely lost, and the gateway is left alone longer the longer
/// it stays silent. The waits add up to exactly `total`, the time the caller
/// already accepted for a gateway that is gone; only how it is split changes.
///
/// What §5.1 also asks -- an interval "adjusted dynamically based on measured
/// round trip times" -- is not done: the split is the same whatever the path.
/// `sends` is a small constant of the caller's (at most 16). A `total` below
/// `2^sends - 1` nanoseconds cannot be cut into unequal parts: the leading waits
/// are then zero and the last one holds all the time.
///
/// Callers pass `T * sends` for a per-send timeout `T` (the socket's read timeout
/// or Quick Mode's `timeout`), so the *whole* wait is unchanged from a fixed `T`
/// per send, but no single wait is `T`: for three sends they are 3T/7, 6T/7 and
/// 12T/7, and the first retransmission leaves at 3T/7, not at T.
pub(crate) fn retransmit_waits(total: Duration, sends: u32) -> Vec<Duration> {
    debug_assert!((1..=16).contains(&sends));
    let unit = total / ((1u32 << sends) - 1);
    let mut waits: Vec<Duration> = (0..sends).map(|i| unit * (1u32 << i)).collect();
    // The division truncates: what it leaves goes to the last wait, which is
    // the longest, so the waits still add up to `total`.
    let left_over = total - waits.iter().sum::<Duration>();
    if let Some(last) = waits.last_mut() {
        *last += left_over;
    }
    waits
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whatever the total and the number of sends: every wait is longer than the
    /// one before it (each twice as long, give or take the nanosecond the
    /// division leaves), none is zero, and together they are the total.
    #[test]
    fn the_waits_between_sends_grow_and_add_up_to_the_total() {
        let mut wrong = Vec::new();
        for sends in 1..=6 {
            for total in [Duration::from_millis(30), Duration::from_secs(5), Duration::from_secs(15), Duration::from_nanos(1_000_003), Duration::from_secs(3600)] {
                let waits = retransmit_waits(total, sends);
                if waits.len() != sends as usize {
                    wrong.push(format!("{sends} sends, {total:?}: {} waits", waits.len()));
                }
                if waits.iter().sum::<Duration>() != total {
                    wrong.push(format!("{sends} sends, {total:?}: the waits add up to {:?}", waits.iter().sum::<Duration>()));
                }
                if waits.iter().any(Duration::is_zero) {
                    wrong.push(format!("{sends} sends, {total:?}: a wait of zero, {waits:?}"));
                }
                if waits.windows(2).any(|w| w[1] <= w[0]) {
                    wrong.push(format!("{sends} sends, {total:?}: the waits do not grow, {waits:?}"));
                }
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }

    /// At the ends of the range of durations: no overflow, no time lost or made
    /// up, one wait per send, and no wait shorter than the one before it -- for a
    /// total of nothing, of a nanosecond, and of the largest `Duration` there is.
    #[test]
    fn the_waits_keep_their_count_their_order_and_their_sum_at_the_extremes_of_duration() {
        let mut wrong = Vec::new();
        let totals = [Duration::ZERO, Duration::from_nanos(1), Duration::from_nanos(6), Duration::from_nanos(7), Duration::MAX - Duration::from_nanos(1), Duration::MAX];
        for sends in 1..=16 {
            for total in totals {
                let waits = retransmit_waits(total, sends);
                if waits.len() != sends as usize {
                    wrong.push(format!("{sends} sends, {total:?}: {} waits", waits.len()));
                }
                if waits.iter().try_fold(Duration::ZERO, |sum, w| sum.checked_add(*w)) != Some(total) {
                    wrong.push(format!("{sends} sends, {total:?}: the waits do not add up to the total, {waits:?}"));
                }
                if waits.windows(2).any(|w| w[1] < w[0]) {
                    wrong.push(format!("{sends} sends, {total:?}: a wait shorter than the one before it, {waits:?}"));
                }
            }
        }
        assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    }

    /// The limit of the split, pinned so that nobody takes the growth for
    /// universal: a total below `2^sends - 1` nanoseconds cannot be cut into
    /// unequal parts, so the sends before the last go out back to back and the
    /// last wait holds all the time there is.
    #[test]
    fn a_total_too_short_to_split_sends_all_but_the_last_at_once() {
        assert_eq!(retransmit_waits(Duration::from_nanos(1), 3), [Duration::ZERO, Duration::ZERO, Duration::from_nanos(1)]);
        assert_eq!(retransmit_waits(Duration::ZERO, 3), [Duration::ZERO; 3]);
        assert_eq!(retransmit_waits(Duration::from_nanos(7), 3), [Duration::from_nanos(1), Duration::from_nanos(2), Duration::from_nanos(4)]);
    }

    /// The split this crate uses for a request: three sends, waits of 1 : 2 : 4
    /// sevenths of the total.
    #[test]
    fn three_sends_wait_a_seventh_two_sevenths_and_four_sevenths_of_the_total() {
        assert_eq!(
            retransmit_waits(Duration::from_secs(70), 3),
            [Duration::from_secs(10), Duration::from_secs(20), Duration::from_secs(40)]
        );
        assert_eq!(retransmit_waits(Duration::from_secs(9), 1), [Duration::from_secs(9)], "one send waits the whole time");
    }
}
