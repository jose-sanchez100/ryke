//! What an ISAKMP SA keeps of the exchanges that are not its own client's: the
//! table the readers of the IKEv1 socket share, so that what the peer says
//! outside the exchange being waited for is kept instead of dropped.
//!
//! The table is **passive** unless the caller turns it on
//! ([`Phase1State::enable_gateway_quick_mode`](super::phase1::Phase1State::enable_gateway_quick_mode)):
//! every method that records something is then a no-op returning the neutral
//! value (`Push::Passive`, no events, no overflow), so an ISAKMP SA that never
//! asks for it behaves exactly as it did before the table existed. Turning it on
//! is one way and shared: [`ExchangeTable`] is `Arc`-backed like
//! [`RetainedFinals`](super::phase1::RetainedFinals) and
//! [`RoundTrips`](super::rtt::RoundTrips), so every clone of the
//! [`Phase1State`](super::phase1::Phase1State) sees it, and it dies with the
//! last of them (the ISAKMP SA's end).
//!
//! What it holds so far is the **peer-event mailbox**: the Deletes an
//! authenticated Informational message names, as the raw facts they are
//! ([`PeerEvent`]), in the order they arrived. Nothing is classified when an
//! event is pushed: what a Delete means -- the SA in use, a pending one, a
//! retired one, none of ours -- depends on the caller's SPIs at the moment it
//! reads the event, not on those at the moment the datagram came in. The time of
//! an event is the `Instant` its caller puts in it, never a clock read here, so a
//! test needs no sleep.
//!
//! [`parse_deletes`] is the pure reader of the Delete payloads of one
//! authenticated message that feeds it, over every Delete payload and every SPI
//! of each (RFC 2408 §3.15, §5.15).

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use super::isakmp::{payload, Payload};
use super::payloads::{protocol, IPSEC_DOI};
use crate::debug::ike_debug;

/// The most distinct events the mailbox holds before it drops new ones and sets
/// its overflow flag. One message alone can name more distinct SPIs than this (about
/// two thousand ESP SPIs fit a datagram), so the facts beyond the cap between two
/// drains are dropped and the sticky flag is set: the reader is then told that the
/// mailbox is incomplete ([`ExchangeTable::take_overflow`]).
pub(crate) const MAILBOX_CAP: usize = 256;

/// The longest SPI a Delete is read for: an ISAKMP SA's SPI is the cookie pair, 16
/// octets (RFC 2408 §3.15); an ESP SPI is 4.
pub(crate) const MAX_SPI_LEN: usize = 16;

/// An ESP SPI's length (RFC 2408 §5.15: "ESP and AH have 4 octet SPIs").
const ESP_SPI_LEN: usize = 4;

/// RFC 2408 §3.15: "For ISAKMP this value is zero (0) and for the IPSEC DOI it is one (1)".
const DOI_ISAKMP: u32 = 0;

/// The fixed part of a Delete payload's body: `DOI(4) | Protocol-Id(1) | SPI-Size(1) | #SPIs(2)`.
const DELETE_FIXED_LEN: usize = 8;

/// The most SPIs a trace names (the rest are counted): a message can name thousands.
const TRACE_SPIS: usize = 16;

/// An SPI as a Delete names it: up to [`MAX_SPI_LEN`] octets, held inline so that an
/// event is a plain value whatever the peer claims.
///
/// Its `Debug` shows the length only: an SPI is public when it is an ESP one (it is
/// in every ESP packet), and [`PeerEvent`] and [`DeletedSpi`] show those; nothing else
/// of what a peer put in a Delete goes into a log line.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PeerSpi {
    len: u8,
    /// Zero past `len`, always, so that two equal SPIs are equal bytes.
    bytes: [u8; MAX_SPI_LEN],
}

impl PeerSpi {
    /// The SPI of no octets: what an ISAKMP Delete whose SPI size is zero is read as naming.
    const EMPTY: Self = Self { len: 0, bytes: [0; MAX_SPI_LEN] };

    /// The SPI `spi`; `None` when it is longer than [`MAX_SPI_LEN`].
    pub(crate) fn new(spi: &[u8]) -> Option<Self> {
        if spi.len() > MAX_SPI_LEN {
            return None;
        }
        let mut bytes = [0u8; MAX_SPI_LEN];
        bytes[..spi.len()].copy_from_slice(spi);
        Some(Self { len: spi.len() as u8, bytes })
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    /// The SPI as the 32-bit value of an ESP SPI; `None` for any other length.
    pub(crate) fn esp(&self) -> Option<u32> {
        <[u8; ESP_SPI_LEN]>::try_from(self.as_bytes()).ok().map(u32::from_be_bytes)
    }
}

impl fmt::Debug for PeerSpi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "<{} bytes>", self.len)
    }
}

/// An SPI of a Delete in the `Debug` shape: the value for an ESP one, the length for anything else.
struct Shown<'a>(u8, &'a PeerSpi);

impl fmt::Debug for Shown<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.0, self.1.esp()) {
            (protocol::ESP, Some(spi)) => write!(f, "esp:{spi:08x}"),
            (protocol::ISAKMP, _) => write!(f, "isakmp:{:?}", self.1),
            (other, _) => write!(f, "protocol {other}:{:?}", self.1),
        }
    }
}

/// One thing the peer's Delete payloads named: a Protocol-Id and one SPI of that protocol.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct DeletedSpi {
    pub protocol: u8,
    pub spi: PeerSpi,
}

impl DeletedSpi {
    /// The event this is, for a message that arrived at `arrived`.
    pub(crate) fn event(&self, arrived: Instant) -> PeerEvent {
        PeerEvent::Delete { protocol: self.protocol, spi: self.spi, arrived }
    }
}

impl fmt::Debug for DeletedSpi {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Shown(self.protocol, &self.spi).fmt(f)
    }
}

/// A fact the peer put on the wire outside the exchange being waited for, exactly as
/// it arrived and not yet read as anything: no SA is looked up and no verdict given
/// when it is recorded (see the module doc).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum PeerEvent {
    /// An authenticated Delete named `spi` of `protocol` (RFC 2408 §3.15), in a message
    /// that arrived at `arrived`.
    Delete { protocol: u8, spi: PeerSpi, arrived: Instant },
}

impl PeerEvent {
    /// Whether `self` and `other` say the same thing: two Deletes of the same SPI of
    /// the same protocol are one fact, whenever each arrived.
    fn same_fact(&self, other: &PeerEvent) -> bool {
        match (self, other) {
            (PeerEvent::Delete { protocol: p, spi: s, .. }, PeerEvent::Delete { protocol: q, spi: t, .. }) => p == q && s == t,
        }
    }
}

impl fmt::Debug for PeerEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeerEvent::Delete { protocol, spi, arrived } => {
                f.debug_struct("Delete").field("names", &Shown(*protocol, spi)).field("arrived", arrived).finish()
            }
        }
    }
}

/// What [`ExchangeTable::push_event`] did with an event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Push {
    /// New: the mailbox keeps it.
    Stored,
    /// The mailbox already holds the same fact; nothing changed, and that is not an error.
    Repeat,
    /// New, but the mailbox is full ([`MAILBOX_CAP`]): dropped, and the overflow flag is set.
    Overflow,
    /// The table is passive: nothing is recorded.
    Passive,
}

/// The raw events, oldest first, without repeats.
#[derive(Default)]
struct Mailbox {
    events: Vec<PeerEvent>,
    overflowed: bool,
}

impl Mailbox {
    fn push(&mut self, event: PeerEvent) -> Push {
        if self.events.iter().any(|kept| kept.same_fact(&event)) {
            return Push::Repeat;
        }
        if self.events.len() >= MAILBOX_CAP {
            self.overflowed = true;
            return Push::Overflow;
        }
        self.events.push(event);
        Push::Stored
    }
}

#[derive(Default)]
struct Books {
    mailbox: Mailbox,
}

struct Shared {
    enabled: AtomicBool,
    books: Mutex<Books>,
}

/// The exchange table of one ISAKMP SA, shared by every clone (see the module doc).
#[derive(Clone)]
pub(crate) struct ExchangeTable {
    shared: Arc<Shared>,
}

impl Default for ExchangeTable {
    fn default() -> Self {
        Self::passive()
    }
}

impl ExchangeTable {
    /// A table that records nothing, until [`Self::enable`] turns it on.
    pub(crate) fn passive() -> Self {
        Self { shared: Arc::new(Shared { enabled: AtomicBool::new(false), books: Mutex::default() }) }
    }

    /// A table that records from the start.
    pub(crate) fn enabled() -> Self {
        let table = Self::passive();
        table.enable();
        table
    }

    pub(crate) fn is_enabled(&self) -> bool {
        self.shared.enabled.load(Ordering::Acquire)
    }

    /// Turns the table on, for every clone of it. There is no way back: a reader that has
    /// seen the table on may rely on it staying on.
    pub(crate) fn enable(&self) {
        self.shared.enabled.store(true, Ordering::Release);
    }

    fn books(&self) -> MutexGuard<'_, Books> {
        self.shared.books.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Records `event` unless the mailbox already holds the same fact or is full.
    /// Passive: nothing is recorded.
    pub(crate) fn push_event(&self, event: PeerEvent) -> Push {
        if !self.is_enabled() {
            return Push::Passive;
        }
        self.books().mailbox.push(event)
    }

    /// Every event recorded since the last drain, in the order they arrived; the
    /// mailbox is empty after it, and a fact it held can be recorded again. Does not
    /// touch the overflow flag ([`Self::take_overflow`]). Passive: none.
    pub(crate) fn drain_events(&self) -> Vec<PeerEvent> {
        if !self.is_enabled() {
            return Vec::new();
        }
        std::mem::take(&mut self.books().mailbox.events)
    }

    /// Whether an event was dropped for want of room since the last call, and forgets
    /// it. Sticky until then, drains included: a reader that finds it set knows the
    /// mailbox is missing something and must ask the peer (a liveness probe) instead of
    /// taking what it holds for all there was. Passive: `false`.
    pub(crate) fn take_overflow(&self) -> bool {
        if !self.is_enabled() {
            return false;
        }
        std::mem::take(&mut self.books().mailbox.overflowed)
    }

    /// How many events the mailbox holds.
    #[cfg(test)]
    fn events_held(&self) -> usize {
        self.books().mailbox.events.len()
    }
}

/// Why a Delete payload was not read (it names nothing); every case is the peer's doing,
/// in a message that authenticated, so the payload is set aside and the rest of the message
/// is read all the same (RFC 2408 §5.15 steps 2 and 3: a payload with an unsupported DOI or
/// Protocol-Id "is discarded").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DeleteSkip {
    /// The body is shorter than the fixed part: it is `len` octets.
    Short { len: usize },
    /// The DOI is neither 0 nor 1.
    Doi { doi: u32 },
    /// The Protocol-Id is neither ISAKMP nor ESP.
    Protocol { protocol: u8 },
    /// The SPI size is not one this code reads for `protocol`.
    SpiSize { protocol: u8, size: u8 },
    /// `declared` SPIs of `size` octets do not fit the `room` octets after the fixed part.
    Count { declared: u16, size: u8, room: usize },
}

impl fmt::Display for DeleteSkip {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            DeleteSkip::Short { len } => write!(f, "{len} octets, shorter than the {DELETE_FIXED_LEN} of its fixed part"),
            DeleteSkip::Doi { doi } => write!(f, "DOI {doi} is neither 0 nor 1"),
            DeleteSkip::Protocol { protocol } => write!(f, "Protocol-Id {protocol} is neither ISAKMP ({}) nor ESP ({})", protocol::ISAKMP, protocol::ESP),
            DeleteSkip::SpiSize { protocol, size } => write!(f, "SPI size {size} for Protocol-Id {protocol}"),
            DeleteSkip::Count { declared, size, room } => write!(f, "{declared} SPIs of {size} octets do not fit the {room} octets it has for them"),
        }
    }
}

/// What the Delete payloads of one authenticated message named. See [`parse_deletes`].
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct DeleteScan {
    /// Every SPI named by every payload that was read, in the order the message names
    /// them: payload by payload, SPI by SPI within one. A message that lists the same
    /// SPI twice names it twice here, except SPIs of size zero, which are named once per
    /// payload (see [`parse_deletes`]).
    pub named: Vec<DeletedSpi>,
    /// The Delete payloads the message carried, read or not.
    pub payloads_seen: usize,
    /// The ones not read, which is `skips.len()`.
    pub skipped_malformed: usize,
    /// Why, payload by payload, in the order they were met.
    pub skips: Vec<DeleteSkip>,
    /// The payloads read that carry DOI 0, which RFC 2408 §3.15 gives to ISAKMP but not to a
    /// Delete of an ESP SA: accepted all the same, and traced.
    pub doi_zero: usize,
    /// The payloads read that have octets after their last SPI: tolerated, and traced.
    pub trailing_bytes: usize,
}

/// Reads every Delete payload of an authenticated message, and every SPI of each (RFC 2408
/// §3.15: a payload may carry several SPIs, "each SPI MUST be for the same protocol"; §5.15:
/// the SAs listed "cannot be used with the transmitting entity").
///
/// A payload is read when its DOI is 0 or 1, its Protocol-Id is ISAKMP or ESP, its SPI
/// size is 4 for ESP and 0 to 16 for ISAKMP (the size RFC 2408 §3.14 leaves open for an
/// ISAKMP SA's SPI in a Notify, taken the same way here: the content is the cookie pair
/// the header already names), and `# of SPIs` SPIs of that size fit the octets after the
/// fixed part. Octets after the last SPI are tolerated: refusing them would turn a
/// teardown into silence. A payload that fails any of this names nothing and the others
/// are still read. A count of zero names nothing and is not a failure. `# of SPIs` is
/// checked against the octets there are, not trusted, so nothing is allocated for a
/// claim the payload does not back; the one case it cannot bound is an SPI of size zero,
/// where every SPI is the same empty one and is named once.
///
/// Payloads that are not Delete payloads are not looked at.
pub(crate) fn parse_deletes(payloads: &[Payload]) -> DeleteScan {
    let mut scan = DeleteScan::default();
    for delete in payloads.iter().filter(|p| p.payload_type == payload::DELETE) {
        scan.payloads_seen += 1;
        if let Err(skip) = scan.read(&delete.data) {
            scan.skipped_malformed += 1;
            scan.skips.push(skip);
        }
    }
    scan
}

impl DeleteScan {
    /// Reads one Delete payload's body; nothing is added to `self` unless all of it is valid.
    fn read(&mut self, body: &[u8]) -> Result<(), DeleteSkip> {
        let (fixed, spis) = body.split_first_chunk::<DELETE_FIXED_LEN>().ok_or(DeleteSkip::Short { len: body.len() })?;
        let doi = u32::from_be_bytes([fixed[0], fixed[1], fixed[2], fixed[3]]);
        let (protocol, size) = (fixed[4], fixed[5]);
        let declared = u16::from_be_bytes([fixed[6], fixed[7]]);
        if doi != DOI_ISAKMP && doi != IPSEC_DOI {
            return Err(DeleteSkip::Doi { doi });
        }
        let size_ok = match protocol {
            protocol::ISAKMP => usize::from(size) <= MAX_SPI_LEN,
            protocol::ESP => usize::from(size) == ESP_SPI_LEN,
            _ => return Err(DeleteSkip::Protocol { protocol }),
        };
        if !size_ok {
            return Err(DeleteSkip::SpiSize { protocol, size });
        }
        let listed = usize::from(declared).checked_mul(usize::from(size)).and_then(|needed| spis.get(..needed));
        let Some(listed) = listed else {
            return Err(DeleteSkip::Count { declared, size, room: spis.len() });
        };
        let mut named = Vec::new();
        if size == 0 {
            // Every SPI is the empty one: naming it once says all there is to say.
            if declared > 0 {
                named.push(DeletedSpi { protocol, spi: PeerSpi::EMPTY });
            }
        } else {
            named.reserve_exact(usize::from(declared));
            for spi in listed.chunks_exact(usize::from(size)) {
                named.push(DeletedSpi { protocol, spi: PeerSpi::new(spi).ok_or(DeleteSkip::SpiSize { protocol, size })? });
            }
        }
        self.named.append(&mut named);
        if doi == DOI_ISAKMP {
            self.doi_zero += 1;
        }
        if spis.len() > listed.len() {
            self.trailing_bytes += 1;
        }
        Ok(())
    }

    /// The trace lines for what was read, one per thing worth saying: each payload not read
    /// and why, the DOI 0 and trailing-octets tolerances, and the SPIs named. The payloads
    /// not read and the SPIs named are each capped at [`TRACE_SPIS`] lines, the rest counted
    /// in one line. An ESP SPI is public (it is in every ESP packet) and is written; an
    /// ISAKMP SA is written by its SPI's length, never its content.
    pub(crate) fn trace_lines(&self) -> Vec<String> {
        let mut lines: Vec<String> = self.skips.iter().take(TRACE_SPIS).map(|skip| format!("INFORMATIONAL: ignoring a Delete payload: {skip}")).collect();
        if let Some(more) = self.skips.len().checked_sub(TRACE_SPIS).filter(|more| *more > 0) {
            lines.push(format!("INFORMATIONAL: {more} more Delete payload(s) set aside"));
        }
        if self.doi_zero > 0 {
            lines.push(format!("INFORMATIONAL: accepted {} Delete payload(s) with DOI 0", self.doi_zero));
        }
        if self.trailing_bytes > 0 {
            lines.push(format!("INFORMATIONAL: {} Delete payload(s) had octets after their last SPI -- ignored", self.trailing_bytes));
        }
        for named in self.named.iter().take(TRACE_SPIS) {
            lines.push(match (named.protocol, named.spi.esp()) {
                (protocol::ESP, Some(spi)) => format!("INFORMATIONAL: peer Delete names ESP spi={spi:08x}"),
                _ => format!("INFORMATIONAL: peer Delete names an ISAKMP SA (SPI of {} octets)", named.spi.as_bytes().len()),
            });
        }
        if let Some(more) = self.named.len().checked_sub(TRACE_SPIS).filter(|more| *more > 0) {
            lines.push(format!("INFORMATIONAL: peer Delete names {more} more SPI(s)"));
        }
        lines
    }

    /// Writes [`Self::trace_lines`] to the trace.
    pub(crate) fn trace(&self) {
        if !crate::debug::enabled(1) {
            return;
        }
        for line in self.trace_lines() {
            ike_debug!("{line}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ikev1::informational::parse_delete;
    use crate::ikev1::phase1::Phase1State;
    use crate::ikev1::crypto1::{Prf, AES_BLOCK};
    use crate::crypto::DhGroup;
    use std::time::Duration;

    // ---- Delete parser ----

    /// The body of a Delete payload with the fields as given, whatever they claim: `spis` is what follows the fixed part.
    fn body(doi: u32, protocol_id: u8, size: u8, declared: u16, spis: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(DELETE_FIXED_LEN + spis.len());
        out.extend_from_slice(&doi.to_be_bytes());
        out.push(protocol_id);
        out.push(size);
        out.extend_from_slice(&declared.to_be_bytes());
        out.extend_from_slice(spis);
        out
    }

    fn delete(body: Vec<u8>) -> Payload {
        Payload { payload_type: payload::DELETE, data: body }
    }

    /// A well-formed ESP Delete payload (DOI 1) naming `spis`.
    fn esp_delete(spis: &[u32]) -> Payload {
        let listed: Vec<u8> = spis.iter().flat_map(|spi| spi.to_be_bytes()).collect();
        delete(body(IPSEC_DOI, protocol::ESP, 4, spis.len() as u16, &listed))
    }

    /// A well-formed ISAKMP Delete payload (DOI 1) naming the cookie pair `cookies`.
    fn isakmp_delete(cookies: [u8; 16]) -> Payload {
        delete(body(IPSEC_DOI, protocol::ISAKMP, 16, 1, &cookies))
    }

    fn hash_payload() -> Payload {
        Payload { payload_type: payload::HASH, data: vec![0xEE; 32] }
    }

    fn notify_payload() -> Payload {
        Payload { payload_type: payload::NOTIFY, data: vec![0, 0, 0, 1, 3, 4, 0x8E, 0x28, 1, 2, 3, 4] }
    }

    fn esp(spi: u32) -> DeletedSpi {
        DeletedSpi { protocol: protocol::ESP, spi: PeerSpi::new(&spi.to_be_bytes()).unwrap() }
    }

    /// `parse_deletes`, with the two counters checked against the list they count.
    fn scan(payloads: &[Payload]) -> DeleteScan {
        let scan = parse_deletes(payloads);
        assert_eq!(scan.skipped_malformed, scan.skips.len(), "the counter and the list of reasons disagree");
        assert!(scan.skipped_malformed <= scan.payloads_seen);
        scan
    }

    #[test]
    fn one_spi_in_one_payload_is_named() {
        let scan = scan(&[hash_payload(), esp_delete(&[0xAABB_CCDD])]);
        assert_eq!(scan.named, [esp(0xAABB_CCDD)]);
        assert_eq!((scan.payloads_seen, scan.skipped_malformed, scan.doi_zero, scan.trailing_bytes), (1, 0, 0, 0));
    }

    #[test]
    fn every_spi_of_a_payload_is_named_in_the_order_it_lists_them() {
        let scan = scan(&[esp_delete(&[0x0000_0003, 0x0000_0001, 0xFFFF_FFFE, 0x0000_0002])]);
        assert_eq!(scan.named, [esp(3), esp(1), esp(0xFFFF_FFFE), esp(2)]);
        assert_eq!(scan.payloads_seen, 1);
    }

    #[test]
    fn every_delete_payload_of_a_message_is_read_whatever_stands_between_them() {
        let scan = scan(&[hash_payload(), esp_delete(&[10, 11]), notify_payload(), esp_delete(&[20]), esp_delete(&[30, 31, 32])]);
        assert_eq!(scan.named, [esp(10), esp(11), esp(20), esp(30), esp(31), esp(32)]);
        assert_eq!((scan.payloads_seen, scan.skipped_malformed), (3, 0));
    }

    /// Reversing the payloads, or the SPIs of one, reverses what comes out: the order of appearance is kept, never sorted.
    #[test]
    fn the_order_of_appearance_is_kept_whichever_way_it_runs() {
        let forward = scan(&[esp_delete(&[1, 2]), esp_delete(&[3])]);
        assert_eq!(forward.named, [esp(1), esp(2), esp(3)]);
        let payloads_reversed = scan(&[esp_delete(&[3]), esp_delete(&[1, 2])]);
        assert_eq!(payloads_reversed.named, [esp(3), esp(1), esp(2)]);
        let spis_reversed = scan(&[esp_delete(&[2, 1]), esp_delete(&[3])]);
        assert_eq!(spis_reversed.named, [esp(2), esp(1), esp(3)]);
        let all_reversed = scan(&[esp_delete(&[3]), esp_delete(&[2, 1])]);
        assert_eq!(all_reversed.named, [esp(3), esp(2), esp(1)]);
    }

    #[test]
    fn an_isakmp_delete_and_an_esp_delete_in_one_message_are_both_named_with_their_own_protocol() {
        let cookies: [u8; 16] = std::array::from_fn(|i| 0xA0 + i as u8);
        let scan = scan(&[esp_delete(&[7]), isakmp_delete(cookies), esp_delete(&[8])]);
        assert_eq!(scan.named.len(), 3);
        assert_eq!(scan.named[0], esp(7));
        assert_eq!(scan.named[1].protocol, protocol::ISAKMP);
        assert_eq!(scan.named[1].spi.as_bytes(), cookies, "the cookie pair is carried whole");
        assert_eq!(scan.named[2], esp(8));
        let reversed = super::parse_deletes(&[esp_delete(&[8]), isakmp_delete(cookies), esp_delete(&[7])]);
        assert_eq!(reversed.named.iter().map(|d| d.protocol).collect::<Vec<_>>(), [protocol::ESP, protocol::ISAKMP, protocol::ESP]);
        assert_eq!(reversed.named[0], esp(8));
    }

    #[test]
    fn a_message_without_a_delete_names_nothing() {
        let scan = scan(&[hash_payload(), notify_payload()]);
        assert_eq!(scan, DeleteScan::default());
        assert_eq!(super::parse_deletes(&[]), DeleteScan::default());
    }

    #[test]
    fn doi_zero_and_one_are_read_and_any_other_is_not() {
        let cases: [(u32, bool); 6] = [(0, true), (1, true), (2, false), (0x0100_0000, false), (0x0001_0000, false), (u32::MAX, false)];
        for (doi, read) in cases {
            for (proto, size, spi) in [(protocol::ESP, 4u8, vec![0, 0, 0, 9]), (protocol::ISAKMP, 16, vec![5; 16])] {
                let scan = scan(&[delete(body(doi, proto, size, 1, &spi))]);
                assert_eq!(scan.named.len(), usize::from(read), "DOI {doi:#x}, Protocol-Id {proto}");
                assert_eq!(scan.skips, if read { vec![] } else { vec![DeleteSkip::Doi { doi }] }, "DOI {doi:#x}, Protocol-Id {proto}");
                assert_eq!(scan.doi_zero, usize::from(doi == 0), "DOI {doi:#x}: only a DOI of 0 is flagged for a trace");
            }
        }
    }

    #[test]
    fn a_protocol_id_other_than_isakmp_and_esp_is_not_read() {
        for protocol_id in [0u8, 2, 4, 5, 255] {
            let scan = scan(&[delete(body(IPSEC_DOI, protocol_id, 4, 1, &[0, 0, 0, 1]))]);
            assert!(scan.named.is_empty(), "Protocol-Id {protocol_id}");
            assert_eq!(scan.skips, [DeleteSkip::Protocol { protocol: protocol_id }], "Protocol-Id {protocol_id}");
        }
    }

    #[test]
    fn an_esp_spi_is_four_octets_and_an_isakmp_one_is_zero_to_sixteen() {
        // (Protocol-Id, SPI size, read?) -- the payload always carries exactly one SPI of the size it claims.
        let cases: [(u8, u8, bool); 14] = [
            (protocol::ESP, 0, false),
            (protocol::ESP, 3, false),
            (protocol::ESP, 4, true),
            (protocol::ESP, 5, false),
            (protocol::ESP, 8, false),
            (protocol::ESP, 16, false),
            (protocol::ESP, 255, false),
            (protocol::ISAKMP, 0, true),
            (protocol::ISAKMP, 4, true),
            (protocol::ISAKMP, 15, true),
            (protocol::ISAKMP, 16, true),
            (protocol::ISAKMP, 17, false),
            (protocol::ISAKMP, 32, false),
            (protocol::ISAKMP, 255, false),
        ];
        for (proto, size, read) in cases {
            let scan = scan(&[delete(body(IPSEC_DOI, proto, size, 1, &vec![0x5A; usize::from(size)]))]);
            assert_eq!(scan.named.len(), usize::from(read), "Protocol-Id {proto}, SPI size {size}");
            let want = if read { vec![] } else { vec![DeleteSkip::SpiSize { protocol: proto, size }] };
            assert_eq!(scan.skips, want, "Protocol-Id {proto}, SPI size {size}");
        }
    }

    /// An ISAKMP SPI of size zero has no content to differ by: the count is no measure of how much there is to
    /// say, so it cannot be what a name list grows by. One empty SPI is named, however many are claimed.
    #[test]
    fn spis_of_size_zero_are_named_once_whatever_their_count() {
        for declared in [1u16, 2, 300, u16::MAX] {
            let scan = scan(&[delete(body(IPSEC_DOI, protocol::ISAKMP, 0, declared, &[]))]);
            assert_eq!(scan.named.len(), 1, "{declared} SPIs of size zero");
            assert!(scan.named[0].spi.as_bytes().is_empty());
            assert_eq!(scan.named[0].protocol, protocol::ISAKMP);
        }
        let flood: Vec<Payload> = (0..500).map(|_| delete(body(IPSEC_DOI, protocol::ISAKMP, 0, u16::MAX, &[]))).collect();
        let scan = scan(&flood);
        assert_eq!(scan.named.len(), 500, "one name per payload, not 65535");
    }

    #[test]
    fn a_count_that_the_payload_cannot_hold_skips_the_payload() {
        // Room for exactly two SPIs of four octets.
        let two = [0, 0, 0, 1, 0, 0, 0, 2];
        let cases: [(u16, bool); 5] = [(0, true), (1, true), (2, true), (3, false), (u16::MAX, false)];
        for (declared, read) in cases {
            let scan = scan(&[delete(body(IPSEC_DOI, protocol::ESP, 4, declared, &two))]);
            assert_eq!(scan.named.len(), if read { usize::from(declared) } else { 0 }, "{declared} SPIs claimed, 2 held");
            let want = if read { vec![] } else { vec![DeleteSkip::Count { declared, size: 4, room: 8 }] };
            assert_eq!(scan.skips, want, "{declared} SPIs claimed, 2 held");
        }
        // The edge, to the octet: three SPIs fit 12 octets and not 11.
        let edge = |room: usize| scan(&[delete(body(IPSEC_DOI, protocol::ESP, 4, 3, &vec![9; room]))]);
        assert_eq!(edge(12).named.len(), 3);
        assert!(edge(11).named.is_empty());
        assert_eq!(edge(11).skips, [DeleteSkip::Count { declared: 3, size: 4, room: 11 }]);
    }

    /// 0xFFFF claimed SPIs of every size, over a body of a few octets: refused without reading past the body or
    /// allocating for the claim, whatever product the claim makes with the size.
    #[test]
    fn a_huge_count_over_a_tiny_body_is_refused_without_a_panic() {
        for (proto, size) in [(protocol::ESP, 4u8), (protocol::ISAKMP, 1), (protocol::ISAKMP, 16)] {
            for tail in [0usize, 1, 3, 4, 15] {
                let scan = scan(&[delete(body(IPSEC_DOI, proto, size, 0xFFFF, &vec![1; tail]))]);
                assert!(scan.named.is_empty(), "Protocol-Id {proto}, size {size}, {tail} octets held");
                assert_eq!(scan.skips, [DeleteSkip::Count { declared: 0xFFFF, size, room: tail }]);
            }
        }
    }

    #[test]
    fn a_count_of_zero_names_nothing_and_is_not_a_failure() {
        let scan = scan(&[delete(body(IPSEC_DOI, protocol::ESP, 4, 0, &[])), delete(body(IPSEC_DOI, protocol::ISAKMP, 16, 0, &[]))]);
        assert!(scan.named.is_empty());
        assert_eq!((scan.payloads_seen, scan.skipped_malformed, scan.trailing_bytes), (2, 0, 0));
    }

    #[test]
    fn a_body_shorter_than_its_fixed_part_is_skipped_at_every_length_below_it() {
        let full = body(IPSEC_DOI, protocol::ESP, 4, 1, &[0, 0, 0, 1]);
        for len in 0..DELETE_FIXED_LEN {
            let scan = scan(&[delete(full[..len].to_vec())]);
            assert!(scan.named.is_empty(), "{len} octets");
            assert_eq!(scan.skips, [DeleteSkip::Short { len }], "{len} octets");
        }
        // At the fixed part exactly it is a Delete of one SPI that is not there.
        let scan = scan(&[delete(full[..DELETE_FIXED_LEN].to_vec())]);
        assert_eq!(scan.skips, [DeleteSkip::Count { declared: 1, size: 4, room: 0 }]);
    }

    #[test]
    fn octets_after_the_last_spi_are_tolerated_and_flagged() {
        let mut listed = vec![0, 0, 0, 1, 0, 0, 0, 2];
        listed.extend_from_slice(&[0xDE, 0xAD, 0xBE]);
        let scan = scan(&[delete(body(IPSEC_DOI, protocol::ESP, 4, 2, &listed))]);
        assert_eq!(scan.named, [esp(1), esp(2)], "the SPIs are read, the rest is not");
        assert_eq!((scan.skipped_malformed, scan.trailing_bytes), (0, 1));
        // A count of zero followed by octets is trailing too, and still names nothing.
        let none = scan_one(body(IPSEC_DOI, protocol::ESP, 4, 0, &[1, 2]));
        assert!(none.named.is_empty());
        assert_eq!((none.skipped_malformed, none.trailing_bytes), (0, 1));
        // And an exact fit is not.
        assert_eq!(scan_one(body(IPSEC_DOI, protocol::ESP, 4, 1, &[0, 0, 0, 1])).trailing_bytes, 0);
    }

    fn scan_one(body: Vec<u8>) -> DeleteScan {
        scan(&[delete(body)])
    }

    /// A payload the peer got wrong costs the message nothing else: the ones around it are read, and the
    /// scan says what it set aside.
    #[test]
    fn a_malformed_payload_is_skipped_and_the_others_of_the_message_are_still_read() {
        let bad_first = scan(&[
            hash_payload(),
            delete(body(0x7F, protocol::ESP, 4, 1, &[0, 0, 0, 1])),
            esp_delete(&[42]),
        ]);
        assert_eq!(bad_first.named, [esp(42)]);
        assert_eq!((bad_first.payloads_seen, bad_first.skipped_malformed), (2, 1));
        assert_eq!(bad_first.skips, [DeleteSkip::Doi { doi: 0x7F }]);

        let bad_middle = scan(&[esp_delete(&[1]), delete(vec![0, 0, 0]), esp_delete(&[2])]);
        assert_eq!(bad_middle.named, [esp(1), esp(2)]);
        assert_eq!(bad_middle.skips, [DeleteSkip::Short { len: 3 }]);

        let all_bad = scan(&[delete(vec![]), delete(body(IPSEC_DOI, 9, 4, 1, &[0; 4])), delete(body(IPSEC_DOI, protocol::ESP, 4, 9, &[0; 4]))]);
        assert!(all_bad.named.is_empty());
        assert_eq!((all_bad.payloads_seen, all_bad.skipped_malformed), (3, 3));
    }

    /// A payload names all of its SPIs or none: one that fails keeps back the SPIs it listed before the fault.
    #[test]
    fn a_skipped_payload_names_none_of_its_spis() {
        let mut one_short = vec![0, 0, 0, 1, 0, 0, 0, 2];
        one_short.push(0xFF); // a third SPI of one octet, not four
        let scan = scan(&[delete(body(IPSEC_DOI, protocol::ESP, 4, 3, &one_short))]);
        assert!(scan.named.is_empty());
        assert_eq!(scan.skips, [DeleteSkip::Count { declared: 3, size: 4, room: 9 }]);
    }

    /// No cap on how many payloads or SPIs a message may carry but its size: a datagram of 8192 octets holds
    /// over a thousand 4-octet SPIs, and all of them are named, in order.
    #[test]
    fn a_message_is_read_to_its_end_whatever_it_names() {
        let many: Vec<u32> = (0..1500u32).map(|i| 0x1000_0000 + i).collect();
        let scan_all = scan(&[esp_delete(&many)]);
        assert_eq!(scan_all.named.len(), 1500);
        assert_eq!(scan_all.named.first(), Some(&esp(0x1000_0000)));
        assert_eq!(scan_all.named.last(), Some(&esp(0x1000_0000 + 1499)));
        let payloads: Vec<Payload> = (0..700u32).map(|i| esp_delete(&[i])).collect();
        let scan_payloads = scan(&payloads);
        assert_eq!((scan_payloads.payloads_seen, scan_payloads.named.len()), (700, 700));
        assert!(scan_payloads.named.iter().enumerate().all(|(i, named)| *named == esp(i as u32)));
    }

    /// The legacy reader is what the passive path keeps using, and it reads the first SPI of the first
    /// payload only: this pins that, so that "a passive table changes nothing" is a claim a test can break.
    #[test]
    fn the_legacy_parse_delete_still_reads_only_the_first_spi() {
        let two = body(IPSEC_DOI, protocol::ESP, 4, 2, &[0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB]);
        assert_eq!(parse_delete(&two), Some((protocol::ESP, &[0xAA, 0xAA, 0xAA, 0xAA][..])), "the second SPI is not looked at");
        let new = scan_one(two);
        assert_eq!(new.named, [esp(0xAAAA_AAAA), esp(0xBBBB_BBBB)], "the new reader names both");
    }

    // ---- Trace lines ----

    #[test]
    fn the_trace_says_what_was_set_aside_and_names_esp_spis_but_never_an_isakmp_spi() {
        let cookies = [0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8];
        let mut trailing = vec![0, 0, 0, 1];
        trailing.push(0x99);
        let scan = scan(&[
            esp_delete(&[0x0BAD_F00D]),
            isakmp_delete(cookies),
            delete(body(0, protocol::ESP, 4, 1, &[0, 0, 0, 2])),
            delete(body(IPSEC_DOI, protocol::ESP, 4, 1, &trailing)),
            delete(body(IPSEC_DOI, 2, 4, 1, &[0xAC; 4])),
        ]);
        assert_eq!(
            scan.trace_lines(),
            [
                "INFORMATIONAL: ignoring a Delete payload: Protocol-Id 2 is neither ISAKMP (1) nor ESP (3)",
                "INFORMATIONAL: accepted 1 Delete payload(s) with DOI 0",
                "INFORMATIONAL: 1 Delete payload(s) had octets after their last SPI -- ignored",
                "INFORMATIONAL: peer Delete names ESP spi=0badf00d",
                "INFORMATIONAL: peer Delete names an ISAKMP SA (SPI of 16 octets)",
                "INFORMATIONAL: peer Delete names ESP spi=00000002",
                "INFORMATIONAL: peer Delete names ESP spi=00000001",
            ],
            "the whole trace, so that an SPI of the ISAKMP SA written in any format would fail"
        );
        scan.trace(); // writes nothing at the default level, and does not fail
    }

    #[test]
    fn the_trace_of_a_long_list_names_the_first_spis_and_counts_the_rest() {
        let many: Vec<u32> = (1..=(TRACE_SPIS as u32 + 5)).collect();
        let lines = scan(&[esp_delete(&many)]).trace_lines();
        assert_eq!(lines.len(), TRACE_SPIS + 1);
        assert!(lines.last().unwrap().contains("5 more"), "{lines:?}");
        assert!(scan(&[esp_delete(&[1, 2, 3])]).trace_lines().iter().all(|line| !line.contains("more")));
        assert!(DeleteScan::default().trace_lines().is_empty());
    }

    /// The payloads set aside are capped like the SPIs named: the first `TRACE_SPIS` are written and the rest counted.
    #[test]
    fn the_trace_of_many_skipped_payloads_writes_the_first_reasons_and_counts_the_rest() {
        let skipped: Vec<Payload> = (0..TRACE_SPIS + 5).map(|_| delete(Vec::new())).collect();
        let all = scan(&skipped);
        assert_eq!((all.payloads_seen, all.skipped_malformed), (TRACE_SPIS + 5, TRACE_SPIS + 5));
        let lines = all.trace_lines();
        assert_eq!(lines.len(), TRACE_SPIS + 1);
        let reason = "INFORMATIONAL: ignoring a Delete payload: 0 octets, shorter than the 8 of its fixed part";
        assert!(lines[..TRACE_SPIS].iter().all(|line| line == reason), "{lines:?}");
        assert_eq!(lines[TRACE_SPIS], "INFORMATIONAL: 5 more Delete payload(s) set aside");
        let at_the_cap: Vec<Payload> = (0..TRACE_SPIS).map(|_| delete(Vec::new())).collect();
        assert_eq!(scan(&at_the_cap).trace_lines().len(), TRACE_SPIS, "exactly the cap writes no counting line");
    }

    // ---- PeerSpi, PeerEvent ----

    #[test]
    fn an_spi_is_held_up_to_sixteen_octets_and_no_further() {
        assert!(PeerSpi::new(&[]).is_some_and(|spi| spi.as_bytes().is_empty()));
        assert_eq!(PeerSpi::new(&[1; 16]).unwrap().as_bytes(), [1; 16]);
        assert!(PeerSpi::new(&[1; 17]).is_none());
        assert!(PeerSpi::new(&[0; 255]).is_none());
        assert_eq!(PeerSpi::new(&[0, 0, 0, 1]).unwrap().esp(), Some(1));
        assert_eq!(PeerSpi::new(&[0, 0, 1]).unwrap().esp(), None);
        // Equal bytes are equal SPIs, and a longer SPI that starts with the same octets is another one.
        assert_eq!(PeerSpi::new(&[7, 7]), PeerSpi::new(&[7, 7]));
        assert_ne!(PeerSpi::new(&[7, 7]), PeerSpi::new(&[7, 7, 0]));
        assert_ne!(PeerSpi::new(&[]), PeerSpi::new(&[0]));
    }

    #[test]
    fn debug_shows_an_esp_spi_and_only_the_length_of_any_other() {
        let at = Instant::now();
        let esp_event = esp(0xCAFE_0001).event(at);
        let isakmp = DeletedSpi { protocol: protocol::ISAKMP, spi: PeerSpi::new(&[0xB7; 16]).unwrap() };
        let shown = format!("{esp_event:?} {:?} {:?}", isakmp.event(at), isakmp);
        assert!(shown.contains("esp:cafe0001"), "{shown}");
        assert!(shown.contains("isakmp:<16 bytes>"), "{shown}");
        assert!(!shown.to_lowercase().contains("b7b7"), "{shown}");
        // A 4-octet SPI of ISAKMP is no ESP SPI: it is not shown either.
        let short = DeletedSpi { protocol: protocol::ISAKMP, spi: PeerSpi::new(&[0xB7; 4]).unwrap() };
        assert!(!format!("{short:?}").to_lowercase().contains("b7"), "{short:?}");
    }

    // ---- Mailbox ----

    fn event(table_protocol: u8, spi: &[u8], at: Instant) -> PeerEvent {
        PeerEvent::Delete { protocol: table_protocol, spi: PeerSpi::new(spi).unwrap(), arrived: at }
    }

    fn esp_event(spi: u32, at: Instant) -> PeerEvent {
        esp(spi).event(at)
    }

    #[test]
    fn events_come_out_in_the_order_they_arrived_and_each_fact_once() {
        let table = ExchangeTable::enabled();
        let t0 = Instant::now();
        let at = |ms: u64| t0 + Duration::from_millis(ms);
        assert_eq!(table.push_event(esp_event(3, at(0))), Push::Stored);
        assert_eq!(table.push_event(esp_event(1, at(1))), Push::Stored);
        assert_eq!(table.push_event(esp_event(3, at(2))), Push::Repeat, "a repeat updates nothing and is not an error");
        assert_eq!(table.push_event(esp_event(2, at(3))), Push::Stored);
        assert_eq!(table.push_event(esp_event(1, at(4))), Push::Repeat);
        let events = table.drain_events();
        assert_eq!(events, [esp_event(3, at(0)), esp_event(1, at(1)), esp_event(2, at(3))], "arrival order, first arrival kept");
        let arrived: Vec<Instant> = events.iter().map(|PeerEvent::Delete { arrived, .. }| *arrived).collect();
        assert_eq!(arrived, [at(0), at(1), at(3)], "a repeat does not move the time of the fact it repeats");
        assert!(table.drain_events().is_empty(), "a drain empties the mailbox");
        assert!(!table.take_overflow());
    }

    /// Two Deletes are one fact only when protocol and SPI both agree.
    #[test]
    fn the_protocol_and_the_whole_spi_tell_facts_apart() {
        let table = ExchangeTable::enabled();
        let at = Instant::now();
        let spi4 = [0, 0, 0, 5];
        let facts = [
            event(protocol::ESP, &spi4, at),
            event(protocol::ISAKMP, &spi4, at),
            event(protocol::ISAKMP, &[0, 0, 0, 5, 0], at),
            event(protocol::ISAKMP, &[], at),
            event(protocol::ESP, &[0, 0, 0, 6], at),
        ];
        for fact in facts {
            assert_eq!(table.push_event(fact), Push::Stored, "{fact:?}");
        }
        assert_eq!(table.drain_events(), facts);
    }

    #[test]
    fn a_fact_drained_can_be_recorded_again() {
        let table = ExchangeTable::enabled();
        let at = Instant::now();
        assert_eq!(table.push_event(esp_event(1, at)), Push::Stored);
        assert_eq!(table.drain_events().len(), 1);
        assert_eq!(table.push_event(esp_event(1, at)), Push::Stored, "the reader has it; a new Delete of it is news");
    }

    /// The 256th distinct fact fits, the 257th does not: it is dropped and the flag says so. A repeat of
    /// a fact the full mailbox holds is a repeat, not an overflow.
    #[test]
    fn the_mailbox_holds_256_distinct_facts_and_the_257th_sets_the_overflow_flag() {
        let table = ExchangeTable::enabled();
        let at = Instant::now();
        for spi in 0..MAILBOX_CAP as u32 {
            assert_eq!(table.push_event(esp_event(spi, at)), Push::Stored, "fact {spi}");
        }
        assert_eq!(table.events_held(), MAILBOX_CAP);
        assert!(!table.take_overflow(), "256 facts fit");
        assert_eq!(table.push_event(esp_event(0, at)), Push::Repeat, "a repeat of a fact held, when full");
        assert!(!table.take_overflow(), "and says nothing of overflow");
        assert_eq!(table.push_event(esp_event(MAILBOX_CAP as u32, at)), Push::Overflow, "the 257th");
        assert_eq!(table.events_held(), MAILBOX_CAP, "it was not kept");
        let events = table.drain_events();
        assert_eq!(events.len(), MAILBOX_CAP);
        assert_eq!(events.first(), Some(&esp_event(0, at)));
        assert_eq!(events.last(), Some(&esp_event(MAILBOX_CAP as u32 - 1, at)), "the dropped one is the newest, the 256 kept are the first");
        assert!(table.take_overflow(), "sticky across the drain");
    }

    #[test]
    fn the_overflow_flag_is_sticky_until_taken_and_then_clear() {
        let table = ExchangeTable::enabled();
        let at = Instant::now();
        for spi in 0..=MAILBOX_CAP as u32 {
            table.push_event(esp_event(spi, at));
        }
        table.drain_events();
        table.drain_events();
        assert!(table.take_overflow(), "two drains did not clear it");
        assert!(!table.take_overflow(), "taking it clears it");
        // With room again, the table records and does not flag.
        assert_eq!(table.push_event(esp_event(1, at)), Push::Stored);
        assert!(!table.take_overflow());
    }

    #[test]
    fn a_passive_table_ignores_pushes_and_reports_nothing() {
        let table = ExchangeTable::passive();
        let at = Instant::now();
        for spi in 0..(MAILBOX_CAP as u32 * 3) {
            assert_eq!(table.push_event(esp_event(spi, at)), Push::Passive);
        }
        assert!(table.drain_events().is_empty());
        assert!(!table.take_overflow(), "a passive table never overflows");
        assert!(!table.is_enabled());
        assert_eq!(table.events_held(), 0);
    }

    #[test]
    fn what_was_pushed_before_the_table_was_enabled_was_not_kept() {
        let table = ExchangeTable::passive();
        let at = Instant::now();
        assert_eq!(table.push_event(esp_event(1, at)), Push::Passive);
        table.enable();
        assert!(table.drain_events().is_empty());
        assert_eq!(table.push_event(esp_event(1, at)), Push::Stored);
        assert_eq!(table.drain_events(), [esp_event(1, at)]);
    }

    // ---- The table ----

    #[test]
    fn a_table_is_passive_unless_made_enabled() {
        assert!(!ExchangeTable::passive().is_enabled());
        assert!(!ExchangeTable::default().is_enabled());
        assert!(ExchangeTable::enabled().is_enabled());
    }

    #[test]
    fn clones_share_the_switch_and_the_mailbox_and_separate_tables_share_nothing() {
        let table = ExchangeTable::passive();
        let clone = table.clone();
        let other = ExchangeTable::passive();
        clone.enable();
        assert!(table.is_enabled(), "enabled through a clone, seen through the original");
        assert!(!other.is_enabled(), "another table is not touched");
        let at = Instant::now();
        assert_eq!(clone.push_event(esp_event(9, at)), Push::Stored);
        assert_eq!(table.drain_events(), [esp_event(9, at)], "the mailbox is the clones' together");
        assert!(clone.drain_events().is_empty());
        table.enable();
        assert!(table.is_enabled() && clone.is_enabled(), "turning it on again changes nothing");
    }

    #[test]
    fn turning_a_state_on_is_seen_through_every_copy_of_it_and_by_no_other_state() {
        let resumed = || Phase1State::resume(Prf::Sha256, DhGroup::Modp2048, [1; 8], [2; 8], vec![], vec![], vec![], vec![], AES_BLOCK, vec![]);
        let st = resumed();
        let before = st.clone();
        let other = resumed();
        assert!(!st.exchanges.is_enabled(), "a state starts passive");
        st.enable_gateway_quick_mode();
        assert!(st.exchanges.is_enabled());
        assert!(before.exchanges.is_enabled(), "a copy made before the call sees it");
        assert!(st.clone().exchanges.is_enabled(), "and one made after");
        assert!(!other.exchanges.is_enabled(), "a state of another ISAKMP SA does not");
        let at = Instant::now();
        assert_eq!(before.exchanges.push_event(esp_event(4, at)), Push::Stored);
        assert_eq!(st.exchanges.drain_events(), [esp_event(4, at)]);
    }
}
