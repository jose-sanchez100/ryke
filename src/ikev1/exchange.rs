//! What an ISAKMP SA keeps of the exchanges that are not its own client's: the
//! table the readers of the IKEv1 socket share, so that what the peer says
//! outside the exchange being waited for is kept instead of dropped.
//!
//! The table is **passive** unless the caller turns it on
//! ([`Phase1State::enable_gateway_quick_mode`]):
//! every method that records something is then a no-op returning the neutral
//! value (`Push::Passive`, no events, no overflow), so an ISAKMP SA that never
//! asks for it behaves exactly as it did before the table existed. Turning it on
//! is one way and shared: [`ExchangeTable`] is `Arc`-backed like
//! [`RetainedFinals`](super::phase1::RetainedFinals) and
//! [`RoundTrips`](super::rtt::RoundTrips), so every clone of the
//! [`Phase1State`] sees it, and it dies with the
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
//!
//! It also holds the **Message-ID ledger** of the ISAKMP SA
//! ([`MessageIdLedger`], see [`super::msgid`]): the ids this side draws, the
//! peer's ids it has admitted, and what it remembers of the peer's Quick Modes.
//! Passive, the one thing the table still does is hand out our ids, and it hands
//! them out exactly as every caller drew them before the table existed
//! ([`ExchangeTable::fresh_message_id`]). The ledger is told the time by its
//! callers, except for the ids of ours, which the table stamps by its own clock
//! ([`ExchangeTable::now`]): the monotonic one, or the clock a test moves.
//!
//! **Reading** ([`classify`]): once the table is on, every reader of the socket between the
//! exchanges this side runs -- the liveness checks ([`peek`](super::informational::peek),
//! [`probe`](super::informational::probe)) and the serving turn
//! ([`serve_turn`](super::informational::serve_turn)) -- hands each datagram to this one function,
//! which tells what it is by the ISAKMP SA, the exchange type, the Message ID and what the table
//! holds of that id before anything of it is decrypted (RFC 2409 §5.5: the Message ID "identifies a
//! Quick Mode in progress for a particular ISAKMP SA which itself is identified by the cookies").
//! What it finds is kept, not acted on: an authenticated message 1 of a Quick Mode the peer starts
//! goes to the **inbox** ([`PeerQuick`], [`ExchangeTable::take_inbox`]), and what an authenticated
//! Informational names -- its Deletes and its error Notifies -- goes to the mailbox as raw
//! [`PeerEvent`]s, which the reader of the mailbox classifies against the SPIs it holds when it drains
//! them ([`classify_peer_deletes`]). The only answers sent on the way are the ones that move no
//! state: an R-U-THERE-ACK, and a final message of ours sent again for the peer message it answered,
//! repeated bit for bit. A passive table is never asked: those readers keep the code they had before
//! the table existed.
//!
//! The wait of a Quick Mode of ours for its message 2 is a reader like the others, and keeps
//! everything they keep while it waits: a message under its Message ID is handed to it
//! ([`Classified::RouteToOwn`]) and is its answer only once its HASH(2) verifies, and an error Notify
//! ends it only when [`ExchangeTable::attribute_error_notify`] tells that the Notify is about it.

use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use super::crypto1;
use super::informational::{error_notify_name, notify_type, ChildFamily, RefusalNotify};
use super::isakmp::{exchange, flags, payload, IsakmpHeader, Payload};
use super::msgid::{self, Admission, MessageIdLedger, MidCounters, MidEnd, MidKind, MidRecord, MidState, Origin};
use super::payloads::{id_type, protocol, IPSEC_DOI};
use super::phase1::Phase1State;
use super::phase2;
use crate::debug::ike_debug;
use crate::entropy::Entropy;
use crate::error::IkeError;
use crate::ikev2::natt::unwrap_ike_4500;

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

/// The most authenticated message-1 copies of the peer's Quick Modes the inbox holds (POLICY): a
/// gateway starts one Quick Mode per family at a time, so more than this between two takes of the
/// inbox is not a gateway rekeying; an entry gives way, counted, and its exchange is parked when
/// nothing else depends on its record ([`ExchangeTable::queue_peer_quick`]).
pub(crate) const INBOX_CAP: usize = 4;

/// How long a peer Quick Mode whose message 1 went to the inbox stays an exchange in progress in
/// the ledger, at the longest, unless whoever takes it up moves its deadline (POLICY): as long as a
/// message 1 held for the daemon may wait for its answer, 8 s. A message 1 dropped from a full inbox
/// and parked is parked for as long.
pub(crate) const PEER_QUICK_WAIT: Duration = Duration::from_secs(8);

/// How many cookie pairs of other ISAKMP SAs are remembered, so that a datagram of one is traced
/// once rather than every time (POLICY).
const FOREIGN_REMEMBERED: usize = 16;

/// The most R-U-THEREs of one Informational message answered (POLICY): RFC 3706 §5.2 puts one in a
/// message; a message that carries more gets an answer for its first few distinct sequence numbers.
pub(crate) const ACKS_PER_MESSAGE: usize = 4;

/// How many refusals of the peer's Quick Modes this side sends per [`REFUSAL_WINDOW`] on one ISAKMP SA, at
/// most (POLICY): beyond that a refusal is silence ([`ExchangeTable::charge_refusal`]). A gateway whose offers
/// this side cannot take keeps offering them, and an error Notify answers no question of its; this keeps the
/// answers to such a gateway few.
pub(crate) const REFUSALS_PER_WINDOW: usize = 4;

/// The window [`REFUSALS_PER_WINDOW`] counts over (POLICY).
pub(crate) const REFUSAL_WINDOW: Duration = Duration::from_secs(60);

/// How many refusals the table keeps -- the newest -- to send again unchanged for a copy of a message 1 it
/// refused (POLICY): as many as may be counted in one [`REFUSAL_WINDOW`].
pub(crate) const REFUSALS_KEPT: usize = REFUSALS_PER_WINDOW;

/// The shortest time between two sendings of one kept refusal (POLICY): a copy of a refused message 1 read
/// sooner after the last one is not answered ([`ExchangeTable::repeat_refusal`]). The same spacing as the
/// answers to copies of a message 1 answered, one per 200 ms per Message ID: a peer that replays one copy at
/// line rate gets at most five refusals a second, never one per datagram.
pub(crate) const REFUSAL_RESEND_SPACING: Duration = Duration::from_millis(200);

/// How many messages 1 of the peer's the table remembers a copy with the Commit bit of -- the newest -- by
/// Message ID and fingerprint (POLICY, [`ExchangeTable::note_commit`]): a gateway rekeys one family at a time,
/// so this outlasts every exchange that can still be answered, unless the peer sends this many other flagged
/// messages in between.
pub(crate) const COMMITS_REMEMBERED: usize = 16;

/// How many answers given to the peer's Quick Modes still in progress the table remembers
/// ([`ExchangeTable::note_accepted`]) (POLICY): the responder answers one exchange per family at a time, so
/// this is never reached but by a caller that answers this many exchanges at once.
pub(crate) const ACCEPTS_REMEMBERED: usize = 16;

/// An SPI as a Delete or a Notify names it: up to sixteen octets, held inline so that an
/// event is a plain value whatever the peer claims.
///
/// Its `Debug` shows the length only: an SPI is public when it is an ESP one (it is
/// in every ESP packet), and [`PeerEvent`] shows those; nothing else of what a peer
/// put in a Delete goes into a log line.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PeerSpi {
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

    /// The octets of the SPI.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    /// The SPI as the 32-bit value of an ESP SPI; `None` for any other length.
    pub fn esp(&self) -> Option<u32> {
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
/// when it is recorded. What a Delete means depends on the SPIs the reader holds when
/// it reads the event (`classify_peer_deletes`); what an error Notify is about, on the
/// exchanges the reader has in progress then.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PeerEvent {
    /// An authenticated Delete named `spi` of `protocol` (RFC 2408 §3.15), in a message
    /// that arrived at `arrived`.
    Delete { protocol: u8, spi: PeerSpi, arrived: Instant },
    /// An authenticated Informational under Message ID `msgid` carried an error Notify
    /// (RFC 2408 §3.14.1: types 1 to 16383) of `msg_type`, for `protocol` and the SPI it names
    /// ("the receiving entity's SPI", RFC 2408 §3.14), in a message that arrived at `arrived`.
    /// For Protocol-Id ISAKMP the SPI is the empty one: RFC 2408 §3.14 has its content ignored.
    ErrorNotify { msg_type: u16, protocol: u8, spi: PeerSpi, msgid: u32, arrived: Instant },
}

impl PeerEvent {
    /// When the message that carried the fact arrived.
    pub fn arrived(&self) -> Instant {
        match self {
            PeerEvent::Delete { arrived, .. } | PeerEvent::ErrorNotify { arrived, .. } => *arrived,
        }
    }

    /// Whether `self` and `other` say the same thing: two Deletes of the same SPI of
    /// the same protocol are one fact, whenever each arrived, and so are two error
    /// Notifies of the same type, protocol and SPI under the same Message ID.
    fn same_fact(&self, other: &PeerEvent) -> bool {
        match (self, other) {
            (PeerEvent::Delete { protocol: p, spi: s, .. }, PeerEvent::Delete { protocol: q, spi: t, .. }) => p == q && s == t,
            (
                PeerEvent::ErrorNotify { msg_type: a, protocol: p, spi: s, msgid: m, .. },
                PeerEvent::ErrorNotify { msg_type: b, protocol: q, spi: t, msgid: n, .. },
            ) => a == b && p == q && s == t && m == n,
            _ => false,
        }
    }
}

impl fmt::Debug for PeerEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeerEvent::Delete { protocol, spi, arrived } => {
                f.debug_struct("Delete").field("names", &Shown(*protocol, spi)).field("arrived", arrived).finish()
            }
            PeerEvent::ErrorNotify { msg_type, protocol, spi, msgid, arrived } => f
                .debug_struct("ErrorNotify")
                .field("msg_type", msg_type)
                .field("names", &Shown(*protocol, spi))
                .field("msgid", &format_args!("{msgid:08x}"))
                .field("arrived", arrived)
                .finish(),
        }
    }
}

/// One error Notify of an authenticated Informational as the message carried it -- what a
/// [`PeerEvent::ErrorNotify`] says, without the time -- for the reader that waits on an exchange and has
/// to tell which exchange it is about ([`ExchangeTable::attribute_error_notify`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ErrorNotice {
    /// The Notify Message Type (RFC 2408 §3.14.1: an error is 1 to 16383).
    pub msg_type: u16,
    /// The Protocol-Id it names.
    pub protocol: u8,
    /// The SPI it names; the empty one for Protocol-Id ISAKMP (see [`PeerEvent::ErrorNotify`]).
    pub spi: PeerSpi,
    /// The Message ID of the Informational that carried it.
    pub msgid: u32,
}

impl ErrorNotice {
    /// The event this is, for a message that arrived at `arrived`.
    fn event(&self, arrived: Instant) -> PeerEvent {
        PeerEvent::ErrorNotify { msg_type: self.msg_type, protocol: self.protocol, spi: self.spi, msgid: self.msgid, arrived }
    }
}

/// An authenticated message 1 of a Quick Mode the peer started (its HASH(1) verified, RFC 2409
/// §5.5), as the inbox keeps it for the responder: nothing of it has been validated beyond that,
/// and nothing has been answered.
#[derive(Clone, PartialEq, Eq)]
pub struct PeerQuick {
    /// The Message ID of the exchange.
    pub msgid: u32,
    /// The ISAKMP message exactly as it came, without the non-ESP marker of a datagram on UDP 4500:
    /// the IV of message 2 is its last cipher block (RFC 2409 Appendix B).
    pub datagram: Vec<u8>,
    /// What tells a copy of the message from another message under the same id: the SHA-256 of the
    /// Message ID and of the decrypted payload chain.
    pub fingerprint: [u8; 32],
    /// Whether this copy's header has the Commit bit set (RFC 2408 §3.1). No HASH covers the header,
    /// so it is a fact about this copy only, which nothing here acts on; a copy with it set is not
    /// recorded in the ledger, so a later copy without it is still a new message.
    pub commit_flag: bool,
    /// Whether a copy of this message -- same Message ID, same fingerprint -- with the Commit bit set
    /// was read while this entry was in the inbox, or was in it when this entry came: always so when
    /// `commit_flag` is. The bit is never acted on here, but it is not forgotten either: a flagged
    /// copy that comes after the copy the ledger recorded is noted on that copy's entry, so whoever
    /// answers the exchange knows that a copy of it bound this side to wait for the peer's CONNECTED
    /// Notify before it sends encrypted traffic (RFC 2408 §3.1: "the entity which did not set the
    /// Commit Bit MUST wait for an Informational Exchange containing a Notify payload (with the
    /// CONNECTED Notify Message) from the entity which set the Commit Bit").
    pub commit_seen: bool,
    /// When it was read, by the table's clock.
    pub arrived: Instant,
}

impl fmt::Debug for PeerQuick {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerQuick")
            .field("msgid", &format_args!("{:08x}", self.msgid))
            .field("datagram", &format_args!("<{} bytes>", self.datagram.len()))
            .field("commit_flag", &self.commit_flag)
            .field("commit_seen", &self.commit_seen)
            .field("arrived", &self.arrived)
            .finish()
    }
}

/// What [`ExchangeTable::queue_peer_quick`] did with a message 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Queued {
    /// The inbox holds it now.
    Added,
    /// A copy with the Commit bit of a message the inbox holds without it: that entry now says so
    /// ([`PeerQuick::commit_seen`]), and nothing was added.
    CommitNoted,
    /// The inbox already holds the same copy (same id, same content, same Commit bit), and what it
    /// says of the Commit bit already: nothing changed.
    Held,
    /// A copy with the Commit bit of a message the inbox does not hold, while the inbox is full of
    /// copies without it: dropped, counted. A flagged copy has no ledger record, so it never makes a
    /// recorded one give way.
    Full,
    /// The table is passive: nothing is kept.
    Passive,
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

/// The authenticated message-1 copies waiting for the responder, oldest first, and how many gave way.
#[derive(Default)]
struct Inbox {
    entries: VecDeque<PeerQuick>,
    dropped: u64,
}

#[derive(Default)]
struct Books {
    mailbox: Mailbox,
    ids: MessageIdLedger,
    inbox: Inbox,
    /// The cookie pairs of other ISAKMP SAs already traced, oldest first.
    foreign: VecDeque<[u8; 16]>,
    /// The responder exchanges registered, oldest first ([`ExchangeTable::register_responder`]).
    responders: VecDeque<ResponderEntry>,
    /// Quick Mode messages under the id of an exchange of ours being waited for that did not authenticate
    /// as its message 2 ([`ExchangeTable::count_unauthenticated_reply`]).
    unauthenticated_replies: u64,
    /// The refusals sent, for the rate limit and for the copies of what they refused.
    refusals: Refusals,
    /// The messages 1 of the peer's a copy with the Commit bit of was read, by Message ID and fingerprint,
    /// oldest first: at most [`COMMITS_REMEMBERED`] ([`ExchangeTable::note_commit`]).
    commits: VecDeque<(u32, [u8; 32])>,
    /// The answers given to the peer's Quick Modes still in progress, by Message ID, fingerprint and how many
    /// times the ledger had taken the exchange up again then ([`MidRecord::tries`]), oldest first: at most
    /// [`ACCEPTS_REMEMBERED`] ([`ExchangeTable::note_accepted`]).
    accepts: VecDeque<(u32, [u8; 32], u8)>,
}

/// The refusals of the peer's Quick Modes this side sent ([`ExchangeTable::charge_refusal`],
/// [`ExchangeTable::keep_refusal`]).
#[derive(Default)]
struct Refusals {
    /// When each refusal counted in the current window went, oldest first: at most [`REFUSALS_PER_WINDOW`].
    charged: VecDeque<Instant>,
    /// The refusals kept to be sent again, oldest first: at most [`REFUSALS_KEPT`].
    kept: VecDeque<KeptRefusal>,
}

/// A refusal sent, with the copy of a message 1 it answered.
#[derive(Clone)]
pub(crate) struct KeptRefusal {
    /// The Message ID of the refused message 1.
    pub refused_msgid: u32,
    /// Its fingerprint ([`msgid::fingerprint`]).
    pub fingerprint: [u8; 32],
    /// Whether the copy refused had the Commit bit set: a copy without it is not the same refusal's.
    pub commit_flag: bool,
    /// The Notify type it carried.
    pub notify: RefusalNotify,
    /// The Message ID of the Informational that carried it.
    pub msgid: u32,
    /// That Informational, exactly as built.
    pub datagram: Vec<u8>,
    /// When it was last handed out to be sent, by the table's clock: when it was built, then each time it was
    /// handed out again ([`ExchangeTable::repeat_refusal`]).
    pub last_sent: Instant,
}

/// What [`ExchangeTable::repeat_refusal`] makes of a copy of a refused message 1.
pub(crate) enum RepeatRefusal {
    /// The refusal kept, to be sent again as it was: [`REFUSAL_RESEND_SPACING`] or more since it was last.
    Send(KeptRefusal),
    /// The refusal was sent less than [`REFUSAL_RESEND_SPACING`] ago: nothing is sent now.
    TooSoon,
}

/// The most responder exchanges [`ExchangeTable::register_responder`] keeps (POLICY): the responder
/// answers one gateway Quick Mode per family at a time and keeps a concluded one a while for the copies
/// of its message 1 that may still come; beyond this many the oldest gives way.
const RESPONDERS_KEPT: usize = 4;

/// What the readers know of one responder exchange of this side: what an error Notify of the peer's can
/// name it by besides its Message ID, and whether one did.
struct ResponderEntry {
    msgid: u32,
    /// The SPI this side chose for its inbound SA in the exchange's message 2: the SPI a refusal of that
    /// message names (RFC 2408 §3.14: "The receiving entity's SPI").
    inbound_spi: u32,
    /// The type of the first error Notify the peer refused the exchange with
    /// ([`ExchangeTable::note_responder_rejected`]).
    peer_rejected: Option<u16>,
}

struct Shared {
    enabled: AtomicBool,
    books: Mutex<Books>,
    /// What "now" is for the ids this side draws ([`ExchangeTable::now`]): the monotonic clock,
    /// except in tests, which hold it still or move it, so that none of them sleeps. A passive
    /// table never reads it.
    clock: Box<dyn Fn() -> Instant + Send + Sync>,
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
        Self { shared: Arc::new(Shared { enabled: AtomicBool::new(false), books: Mutex::default(), clock: Box::new(Instant::now) }) }
    }

    /// A table that records nothing until [`Self::enable`], and tells the time by `clock`.
    #[cfg(test)]
    pub(crate) fn with_clock(clock: Box<dyn Fn() -> Instant + Send + Sync>) -> Self {
        Self { shared: Arc::new(Shared { enabled: AtomicBool::new(false), books: Mutex::default(), clock }) }
    }

    /// A table that records from the start.
    #[cfg(test)]
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

    /// Puts an authenticated message 1 of the peer's in the inbox, unless the inbox already holds
    /// the same copy (same Message ID, fingerprint and Commit bit). Passive: nothing is kept.
    ///
    /// The Commit bit of the copies of one message is kept on the copy without it
    /// ([`PeerQuick::commit_seen`]), whichever came first: a flagged copy of a message the inbox
    /// holds without the bit is noted on that entry and not added; one of a message it does not hold
    /// that way is added as an entry of its own, and the copy without the bit that comes after it
    /// carries the fact from the start.
    ///
    /// A full inbox ([`INBOX_CAP`]) makes room by dropping, counted and traced, its oldest copy with
    /// the Commit bit -- which has no ledger record, and whose fact the entry of its clean copy keeps --
    /// and only when it has none, its oldest entry. A flagged copy never makes an entry without the
    /// bit give way: it is dropped itself ([`Queued::Full`]). An entry without the bit that gives way
    /// has its exchange parked in the ledger until [`PEER_QUICK_WAIT`] after `quick` arrived --
    /// nothing answered it, so a copy the peer sends again may be taken up once more
    /// ([`MessageIdLedger::park`]) -- unless a copy of it had the Commit bit (a later clean copy taken
    /// up again would not carry that fact) or another entry the inbox keeps has its Message ID (the
    /// record is that entry's too).
    pub(crate) fn queue_peer_quick(&self, mut quick: PeerQuick) -> Queued {
        if !self.is_enabled() {
            return Queued::Passive;
        }
        let msgid = quick.msgid;
        let arrived = quick.arrived;
        let (gave_way, so_far) = {
            let mut books = self.books();
            let inbox = &mut books.inbox;
            let same_message = |held: &PeerQuick| held.msgid == quick.msgid && held.fingerprint == quick.fingerprint;
            if quick.commit_flag {
                if let Some(clean) = inbox.entries.iter_mut().find(|held| !held.commit_flag && same_message(held)) {
                    if clean.commit_seen {
                        return Queued::Held;
                    }
                    clean.commit_seen = true;
                    return Queued::CommitNoted;
                }
                quick.commit_seen = true;
            } else {
                quick.commit_seen = inbox.entries.iter().any(|held| held.commit_flag && same_message(held));
            }
            if inbox.entries.iter().any(|held| held.commit_flag == quick.commit_flag && same_message(held)) {
                return Queued::Held;
            }
            let mut gave_way = None;
            if inbox.entries.len() >= INBOX_CAP {
                let victim = match inbox.entries.iter().position(|held| held.commit_flag) {
                    Some(flagged) => Some(flagged),
                    None if quick.commit_flag => None,
                    None => Some(0),
                };
                inbox.dropped += 1;
                let Some(oldest) = victim.and_then(|at| inbox.entries.remove(at)) else {
                    ike_debug!(
                        "QUICK: the inbox of gateway Quick Modes is full -- dropped a copy with the Commit bit of msgid={msgid:08x}, which has no record ({} dropped so far)",
                        inbox.dropped
                    );
                    return Queued::Full;
                };
                let still_held = inbox.entries.iter().any(|held| held.msgid == oldest.msgid) || oldest.msgid == quick.msgid;
                gave_way = Some((oldest.msgid, oldest.commit_flag, !oldest.commit_seen && !still_held));
            }
            inbox.entries.push_back(quick);
            (gave_way, inbox.dropped)
        };
        if let Some((gone, flagged, may_park)) = gave_way {
            let parked = may_park && self.park(gone, arrived, arrived.checked_add(PEER_QUICK_WAIT).unwrap_or(arrived));
            ike_debug!(
                "QUICK: the inbox of gateway Quick Modes is full -- dropped {}, msgid={gone:08x}{} ({so_far} dropped so far)",
                if flagged { "its oldest copy with the Commit bit" } else { "its oldest entry" },
                if parked { ", which may be taken up again" } else { "" }
            );
        }
        Queued::Added
    }

    /// Every message 1 the inbox holds, oldest first; the inbox is empty after it. Passive: none.
    pub(crate) fn take_inbox(&self) -> Vec<PeerQuick> {
        if !self.is_enabled() {
            return Vec::new();
        }
        std::mem::take(&mut self.books().inbox.entries).into()
    }

    /// How many entries the inbox holds, whatever the switch says.
    #[cfg(test)]
    pub(crate) fn inbox_held(&self) -> usize {
        self.books().inbox.entries.len()
    }

    /// Whether `cookies` (the initiator's then the responder's) is a pair of another ISAKMP SA this
    /// table has not seen yet: `true` once per pair, while it is among the last [`FOREIGN_REMEMBERED`]
    /// seen, so that a reader traces a stray datagram once rather than every time. Passive: `false`.
    pub(crate) fn first_sight_of_foreign(&self, cookies: [u8; 16]) -> bool {
        if !self.is_enabled() {
            return false;
        }
        let foreign = &mut self.books().foreign;
        if foreign.contains(&cookies) {
            return false;
        }
        if foreign.len() >= FOREIGN_REMEMBERED {
            foreign.pop_front();
        }
        foreign.push_back(cookies);
        true
    }

    /// The exchange of the peer's under `msgid` that this side answers as the responder, when there
    /// is one: a Quick Mode message under its id is that exchange's (a copy of its message 1, or its
    /// message 3), and goes to it rather than through the checks of a new message 1. There is no
    /// responder yet, so every id is [`ResponderLookup::Unknown`] here, and a Quick Mode message under
    /// an id of the peer's is read as a message 1 whose fate the ledger decides.
    pub(crate) fn responder_exchange(&self, _msgid: u32) -> ResponderLookup {
        ResponderLookup::Unknown
    }

    /// `f` over the Message-ID ledger; `passive` without looking at it when the table is passive.
    fn ledger<T>(&self, passive: T, f: impl FnOnce(&mut MessageIdLedger) -> T) -> T {
        if !self.is_enabled() {
            return passive;
        }
        f(&mut self.books().ids)
    }

    /// The time by this table's clock: the monotonic clock's, but in a test that moves its own.
    /// What the ids of ours are stamped with ([`Self::fresh_message_id`]), and what a caller with
    /// no clock of its own passes as `now` to the other methods, so that one clock runs the ledger.
    pub(crate) fn now(&self) -> Instant {
        (self.shared.clock)()
    }

    /// A Message ID for an exchange of ours of `kind`. Passive: exactly the draw every caller
    /// made before the table existed -- four octets of `entropy`, `| 1` -- with the ledger and the
    /// clock left alone, so an ISAKMP SA that never enables its table sends the ids it always did.
    /// Enabled: [`MessageIdLedger::fresh`] at [`Self::now`] (never an id the ledger holds,
    /// recorded as ours).
    pub(crate) fn fresh_message_id(&self, kind: MidKind, entropy: &mut impl Entropy) -> Result<u32, IkeError> {
        if !self.is_enabled() {
            return Ok(msgid::draw(entropy));
        }
        let now = self.now();
        self.books().ids.fresh(kind, entropy, now)
    }

    /// [`Self::fresh_message_id`], never `avoid` either ([`MessageIdLedger::fresh_other_than`]): the Message ID
    /// of an Informational of ours about the exchange `avoid`. Passive: the draw of [`Self::fresh_message_id`],
    /// drawn again while it is `avoid` (at most [`msgid::MID_DRAWS`] draws, then the next odd id), the ledger
    /// and the clock left alone.
    pub(crate) fn fresh_message_id_other_than(&self, kind: MidKind, entropy: &mut impl Entropy, avoid: u32) -> Result<u32, IkeError> {
        if !self.is_enabled() {
            let mut id = msgid::draw(entropy);
            for _ in 1..msgid::MID_DRAWS {
                if id != avoid {
                    break;
                }
                id = msgid::draw(entropy);
            }
            // An odd id plus two is odd: never 0, and never `avoid` once it differed by two.
            return Ok(if id == avoid { id.wrapping_add(2) } else { id });
        }
        let now = self.now();
        self.books().ids.fresh_other_than(kind, entropy, now, Some(avoid))
    }

    /// [`MessageIdLedger::sweep`]. Passive: nothing.
    pub(crate) fn sweep(&self, now: Instant) {
        self.ledger((), |ids| ids.sweep(now))
    }

    /// [`MessageIdLedger::would_admit`]. Passive: [`Admission::Passive`].
    pub(crate) fn would_admit(&self, id: u32, kind: MidKind, fingerprint: &[u8; 32], now: Instant) -> Admission {
        self.ledger(Admission::Passive, |ids| ids.would_admit(id, kind, fingerprint, now))
    }

    /// [`MessageIdLedger::record_authenticated`]. Passive: [`Admission::Passive`], nothing recorded.
    pub(crate) fn record_authenticated(&self, id: u32, kind: MidKind, fingerprint: [u8; 32], now: Instant, deadline: Instant) -> Admission {
        self.ledger(Admission::Passive, |ids| ids.record_authenticated(id, kind, fingerprint, now, deadline))
    }

    /// [`MessageIdLedger::origin_of`]. Passive: `None`.
    pub(crate) fn origin_of(&self, id: u32) -> Option<Origin> {
        self.ledger(None, |ids| ids.origin_of(id))
    }

    /// [`MessageIdLedger::record`]. Passive: `None`.
    pub(crate) fn id_record(&self, id: u32) -> Option<MidRecord> {
        self.ledger(None, |ids| ids.record(id))
    }

    /// [`MessageIdLedger::finish`]. Passive: `false`.
    pub(crate) fn finish(&self, id: u32, now: Instant, end: MidEnd) -> bool {
        self.ledger(false, |ids| ids.finish(id, now, end))
    }

    /// [`MessageIdLedger::set_deadline`]. Passive: `false`.
    pub(crate) fn set_deadline(&self, id: u32, now: Instant, deadline: Instant) -> bool {
        self.ledger(false, |ids| ids.set_deadline(id, now, deadline))
    }

    /// [`MessageIdLedger::attach_fingerprint`]. Passive: `false`.
    #[cfg_attr(not(test), expect(dead_code, reason = "the gateway Quick Mode responder will use it; until then only the tests do"))]
    pub(crate) fn attach_fingerprint(&self, id: u32, fingerprint: [u8; 32]) -> bool {
        self.ledger(false, |ids| ids.attach_fingerprint(id, fingerprint))
    }

    /// [`MessageIdLedger::park`]. Passive: `false`.
    pub(crate) fn park(&self, id: u32, now: Instant, until: Instant) -> bool {
        self.ledger(false, |ids| ids.park(id, now, until))
    }

    /// [`MessageIdLedger::reconsider`]. Passive: `false`.
    pub(crate) fn reconsider(&self, id: u32, now: Instant, deadline: Instant) -> bool {
        self.ledger(false, |ids| ids.reconsider(id, now, deadline))
    }

    /// [`MessageIdLedger::seen_ni`]. Passive: `false`.
    pub(crate) fn seen_ni(&self, family: ChildFamily, ni: &[u8]) -> bool {
        self.ledger(false, |ids| ids.seen_ni(family, ni))
    }

    /// [`MessageIdLedger::remember_ni`]. Passive: nothing.
    pub(crate) fn remember_ni(&self, family: ChildFamily, ni: &[u8]) {
        self.ledger((), |ids| ids.remember_ni(family, ni))
    }

    /// [`MessageIdLedger::accept_allowed`]. Passive: `false` (a passive table admits no peer Quick Mode).
    #[cfg_attr(not(test), expect(dead_code, reason = "the gateway Quick Mode responder will use it; until then only the tests do"))]
    pub(crate) fn accept_allowed(&self, family: ChildFamily, now: Instant) -> bool {
        self.ledger(false, |ids| ids.accept_allowed(family, now))
    }

    /// [`MessageIdLedger::responder_concluded`]. Passive: nothing.
    #[cfg_attr(not(test), expect(dead_code, reason = "the gateway Quick Mode responder will use it; until then only the tests do"))]
    pub(crate) fn responder_concluded(&self, family: ChildFamily, now: Instant) {
        self.ledger((), |ids| ids.responder_concluded(family, now))
    }

    /// [`MessageIdLedger::counters`]. Passive: all zero.
    pub(crate) fn id_counters(&self) -> MidCounters {
        self.ledger(MidCounters::default(), |ids| ids.counters())
    }

    /// How many ids the ledger holds, whatever the switch says.
    #[cfg(test)]
    pub(crate) fn ids_held(&self) -> usize {
        self.books().ids.len()
    }

    /// Counts a Quick Mode message under the id of the exchange of ours being waited for that does not
    /// authenticate as its message 2 (its HASH(2), RFC 2409 §5.5): dropped by the waiting reader, which
    /// goes on waiting. Returns how many there were since the ISAKMP SA began. Passive: 0, nothing counted.
    pub(crate) fn count_unauthenticated_reply(&self) -> u64 {
        if !self.is_enabled() {
            return 0;
        }
        let mut books = self.books();
        books.unauthenticated_replies += 1;
        books.unauthenticated_replies
    }

    /// How many messages [`Self::count_unauthenticated_reply`] counted.
    #[cfg(test)]
    pub(crate) fn unauthenticated_replies(&self) -> u64 {
        self.books().unauthenticated_replies
    }

    /// Registers the responder exchange `msgid`, whose message 2 gives `inbound_spi` as this side's
    /// inbound SPI, so that an error Notify naming either is told to be about it
    /// ([`Self::attribute_error_notify`]). Registering an id again replaces its entry; beyond
    /// [`RESPONDERS_KEPT`] the oldest gives way. Passive: nothing.
    #[cfg_attr(not(test), expect(dead_code, reason = "the gateway Quick Mode responder will use it; until then only the tests do"))]
    pub(crate) fn register_responder(&self, msgid: u32, inbound_spi: u32) {
        if !self.is_enabled() {
            return;
        }
        let responders = &mut self.books().responders;
        responders.retain(|entry| entry.msgid != msgid);
        if responders.len() >= RESPONDERS_KEPT {
            responders.pop_front();
        }
        responders.push_back(ResponderEntry { msgid, inbound_spi, peer_rejected: None });
    }

    /// Records that the peer refused the responder exchange `msgid` with an error Notify of `msg_type`
    /// ([`Attribution::Responder`]); the first such Notify is the one kept. `false`, and nothing recorded,
    /// when no responder exchange of that id is registered: a peer Quick Mode the responder has not taken
    /// up, say, whose Notify only the mailbox keeps. Passive: `false`.
    pub(crate) fn note_responder_rejected(&self, msgid: u32, msg_type: u16) -> bool {
        if !self.is_enabled() {
            return false;
        }
        match self.books().responders.iter_mut().find(|entry| entry.msgid == msgid) {
            Some(entry) => {
                entry.peer_rejected.get_or_insert(msg_type);
                true
            }
            None => false,
        }
    }

    /// Whether one more refusal of a peer Quick Mode may be sent now, by the table's clock, and charges it when
    /// it may: at most [`REFUSALS_PER_WINDOW`] in any [`REFUSAL_WINDOW`] on this ISAKMP SA. A refusal sent again
    /// for a copy of what it refused ([`Self::repeat_refusal`]) is not charged. Passive: `false`.
    pub(crate) fn charge_refusal(&self) -> bool {
        if !self.is_enabled() {
            return false;
        }
        let now = self.now();
        let charged = &mut self.books().refusals.charged;
        while charged.front().is_some_and(|at| now.saturating_duration_since(*at) >= REFUSAL_WINDOW) {
            charged.pop_front();
        }
        if charged.len() >= REFUSALS_PER_WINDOW {
            return false;
        }
        charged.push_back(now);
        true
    }

    /// Keeps `refusal`, sent for a copy of a message 1, to be sent again for a copy of the same message
    /// ([`Self::repeat_refusal`]); beyond [`REFUSALS_KEPT`] the oldest gives way. Passive: nothing.
    pub(crate) fn keep_refusal(&self, refusal: KeptRefusal) {
        if !self.is_enabled() {
            return;
        }
        let kept = &mut self.books().refusals.kept;
        kept.retain(|held| (held.refused_msgid, held.fingerprint, held.commit_flag) != (refusal.refused_msgid, refusal.fingerprint, refusal.commit_flag));
        if kept.len() >= REFUSALS_KEPT {
            kept.pop_front();
        }
        kept.push_back(refusal);
    }

    /// The refusal kept for a copy of the message 1 `refused_msgid` whose fingerprint is `fingerprint` and whose
    /// Commit bit is `commit_flag` -- the same message, whatever its last cipher block -- if one is kept, and
    /// whether it is to be sent again now, by the table's clock: when it was last handed out
    /// [`REFUSAL_RESEND_SPACING`] or more ago ([`RepeatRefusal::Send`], and handed out now), not sooner
    /// ([`RepeatRefusal::TooSoon`]). Passive: `None`.
    pub(crate) fn repeat_refusal(&self, refused_msgid: u32, fingerprint: &[u8; 32], commit_flag: bool) -> Option<RepeatRefusal> {
        if !self.is_enabled() {
            return None;
        }
        let now = self.now();
        let mut books = self.books();
        let kept = books.refusals.kept.iter_mut().find(|held| held.refused_msgid == refused_msgid && held.fingerprint == *fingerprint && held.commit_flag == commit_flag)?;
        if now.saturating_duration_since(kept.last_sent) < REFUSAL_RESEND_SPACING {
            return Some(RepeatRefusal::TooSoon);
        }
        kept.last_sent = now;
        Some(RepeatRefusal::Send(kept.clone()))
    }

    /// The refusal kept for a copy of the message 1 `refused_msgid` whose fingerprint is `fingerprint` and whose
    /// Commit bit is `commit_flag`, if one is kept; nothing changes.
    #[cfg(test)]
    pub(crate) fn kept_refusal(&self, refused_msgid: u32, fingerprint: &[u8; 32], commit_flag: bool) -> Option<KeptRefusal> {
        self.books()
            .refusals
            .kept
            .iter()
            .find(|held| held.refused_msgid == refused_msgid && held.fingerprint == *fingerprint && held.commit_flag == commit_flag)
            .cloned()
    }

    /// Remembers that a copy of the peer's message 1 `msgid` whose fingerprint is `fingerprint` had the Commit
    /// bit set (RFC 2408 §3.1), whatever became of the copy -- refused, refused in silence for the budget,
    /// dropped from a full inbox, or noted on another entry: the fact outlives the copy, so that whatever
    /// answers a copy of the message without the bit, read before or after, knows it
    /// ([`Self::commit_seen_for`]). Sticky: a pair remembered is not forgotten but by [`COMMITS_REMEMBERED`]
    /// newer ones; one remembered again becomes the newest. No HASH covers the header, so the fact binds
    /// nothing and is never acted on but to keep the SA answered from use. Passive: nothing.
    pub(crate) fn note_commit(&self, msgid: u32, fingerprint: [u8; 32]) {
        if !self.is_enabled() {
            return;
        }
        let commits = &mut self.books().commits;
        commits.retain(|held| *held != (msgid, fingerprint));
        if commits.len() >= COMMITS_REMEMBERED {
            commits.pop_front();
        }
        commits.push_back((msgid, fingerprint));
    }

    /// Whether a copy with the Commit bit of the peer's message 1 `msgid` whose fingerprint is `fingerprint`
    /// was read ([`Self::note_commit`]). Passive: `false`.
    pub(crate) fn commit_seen_for(&self, msgid: u32, fingerprint: &[u8; 32]) -> bool {
        self.is_enabled() && self.books().commits.contains(&(msgid, *fingerprint))
    }

    /// Remembers that the responder answered the peer's Quick Mode `msgid`, whose message 1 has the fingerprint
    /// `fingerprint`, in the exchange the ledger holds in progress now ([`Self::accept_outstanding`]); `false`,
    /// and nothing remembered, when the ledger holds no such exchange. What is remembered is kept while that
    /// exchange is in progress and has not been taken up again ([`MessageIdLedger::reconsider`]): beyond
    /// [`ACCEPTS_REMEMBERED`] answers outstanding at once the oldest gives way. Passive: `false`.
    pub(crate) fn note_accepted(&self, msgid: u32, fingerprint: [u8; 32]) -> bool {
        if !self.is_enabled() {
            return false;
        }
        let mut books = self.books();
        let Books { ids, accepts, .. } = &mut *books;
        let Some(tries) = answerable_spell(ids, msgid, &fingerprint) else { return false };
        accepts.retain(|&(id, print, spell)| answerable_spell(ids, id, &print) == Some(spell) && id != msgid);
        if accepts.len() >= ACCEPTS_REMEMBERED {
            accepts.pop_front();
        }
        accepts.push_back((msgid, fingerprint, tries));
        true
    }

    /// Whether the responder already answered the peer's Quick Mode `msgid`, whose message 1 has the
    /// fingerprint `fingerprint`, in the exchange the ledger holds in progress now ([`Self::note_accepted`]): an
    /// answer outstanding, which a second one must not replace (no new SPI, nonce or keys for the same message).
    /// The ledger is read as the last call told the time left it. Passive: `false`.
    pub(crate) fn accept_outstanding(&self, msgid: u32, fingerprint: &[u8; 32]) -> bool {
        if !self.is_enabled() {
            return false;
        }
        let books = self.books();
        let Some(tries) = answerable_spell(&books.ids, msgid, fingerprint) else { return false };
        books.accepts.contains(&(msgid, *fingerprint, tries))
    }

    /// The error Notify type recorded for the responder exchange `msgid`, if it is registered and has one.
    #[cfg(test)]
    pub(crate) fn responder_rejected(&self, msgid: u32) -> Option<u16> {
        self.books().responders.iter().find(|entry| entry.msgid == msgid).and_then(|entry| entry.peer_rejected)
    }

    /// Which exchange of this ISAKMP SA the error Notify `notice` is about, for a reader of an enabled
    /// table; `read_before` is [`InformationalSeen::read_before`] of the message that carried it, and
    /// `awaited` the Quick Mode of ours that reader waits on, if it waits on one.
    ///
    /// RFC 2408 §3.14: "Notification which occurs during, or is concerned with, a Phase 2 negotiation
    /// is identified by the Initiator and Responder cookie pair in the ISAKMP Header and the Message ID
    /// and SPI associated with the current negotiation", the SPI being "The receiving entity's SPI"
    /// (and, for Protocol-Id ISAKMP, "If the SPI Size is non-zero, the content of the SPI field MUST be
    /// ignored"); and RFC 2409 §5.7 gives the Informational that carries it a Message ID that "MUST NOT
    /// be the same as the message ID of another phase 2 exchange which generated this informational
    /// exchange". A peer may therefore name the exchange by its Message ID, by an SPI, or by neither.
    /// The rules, in this order, the first that applies deciding (POLICY):
    /// 1. The Message ID is that of an exchange in progress: `awaited` ([`Attribution::OwnExchange`]); a
    ///    Quick Mode of the peer's in progress in the ledger ([`Attribution::Responder`]); or another
    ///    exchange of ours in progress, which nobody waits on here ([`Attribution::None`]).
    /// 2. It is about ESP and names, as a 4-octet SPI, the SPI this side offered in `awaited`'s message 1,
    ///    or the inbound SPI of a registered responder exchange ([`Self::register_responder`]).
    /// 3. Nothing in it names an exchange, and exactly one exchange is in progress -- `awaited` and the
    ///    Quick Modes the ledger holds in progress, of either side, each counted once: that one. Nothing
    ///    names an exchange when the ledger holds its Message ID as no exchange (as the peer's
    ///    Informational, or not at all), it names no SPI (its Protocol-Id is ISAKMP, or its SPI is
    ///    empty), and its message is no copy or replay of one read before. So this rule never gives an
    ///    exchange a Notify under the id of an exchange not in progress, of ours (our own message
    ///    reflected, or about that exchange) or of the peer's (a Quick Mode over or parked: about that
    ///    exchange, or reusing its id against RFC 2409 §5.7); one that names an SPI rules 1 and 2 do not
    ///    know (of an SA retired, say); or a copy or a replay, which is about what was in progress when
    ///    its first copy came.
    /// 4. None: traced, and ignored by a waiting reader (the event is in the mailbox all the same).
    ///
    /// Rule 3 takes only a Notify with no discriminator, never one whose discriminator the rules before did
    /// not know: a peer that puts an unrelated SPI or Message ID in a real refusal of our Quick Mode makes
    /// the waiting reader run to its timeout instead of failing at once, which is the safer way to fail --
    /// the other way, a Notify about something else ends an exchange it is not about. The ledger is read
    /// at the table's clock, swept first. Passive: [`Attribution::None`] -- the readers of a passive table
    /// keep their own rule, that any error Notify ends the wait.
    pub(crate) fn attribute_error_notify(&self, notice: &ErrorNotice, read_before: bool, awaited: Option<AwaitedQuick>) -> Attribution {
        if !self.is_enabled() {
            return Attribution::None;
        }
        let now = self.now();
        let mut guard = self.books();
        let books = &mut *guard;
        books.ids.sweep(now);
        let msgid = notice.msgid;
        let is_awaited = |id: u32| awaited.is_some_and(|own| own.msgid == id);
        let unattributed = |why: &str| {
            ike_debug!(
                "INFORMATIONAL: error Notify {} ({}) under msgid={msgid:08x} is about no exchange that can be told ({why}) -- ignored here, kept for the reader",
                error_notify_name(notice.msg_type),
                notice.msg_type
            );
            Attribution::None
        };
        // 1. The Message ID of an exchange in progress.
        if is_awaited(msgid) {
            return Attribution::OwnExchange;
        }
        let record = books.ids.record(msgid);
        if let Some(MidRecord { origin, kind, state: MidState::Active { .. }, .. }) = record {
            return match (origin, kind) {
                (Origin::Peer, MidKind::Quick) => Attribution::Responder(msgid),
                _ => unattributed("its Message ID is an exchange in progress that nothing waits on here"),
            };
        }
        // 2. The ESP SPI it names.
        if let (protocol::ESP, Some(spi)) = (notice.protocol, notice.spi.esp()) {
            if awaited.is_some_and(|own| own.offered_spi == spi) {
                return Attribution::OwnExchange;
            }
            if let Some(entry) = books.responders.iter().find(|entry| entry.inbound_spi == spi) {
                return Attribution::Responder(entry.msgid);
            }
        }
        // 3. The only exchange in progress -- only for a Notify that names none.
        match record {
            Some(MidRecord { origin: Origin::Local, .. }) => return unattributed("its Message ID is one of ours, of an exchange that is over"),
            Some(MidRecord { kind: MidKind::Quick | MidKind::ModeConfig, .. }) => {
                return unattributed("its Message ID is that of an exchange of the peer's that is not in progress")
            }
            Some(MidRecord { kind: MidKind::Informational, .. }) | None => {}
        }
        if notice.protocol != protocol::ISAKMP && !notice.spi.as_bytes().is_empty() {
            return unattributed("it names an SPI that no exchange in progress has");
        }
        if read_before {
            return unattributed("its message is a copy or a replay of one read before");
        }
        let mut outstanding: Vec<u32> = awaited.map(|own| own.msgid).into_iter().collect();
        for id in books.ids.in_progress(MidKind::Quick, now, 2) {
            if !outstanding.contains(&id) {
                outstanding.push(id);
            }
        }
        match outstanding.as_slice() {
            [only] if is_awaited(*only) => Attribution::OwnExchange,
            [only] if books.ids.origin_of(*only) == Some(Origin::Peer) => Attribution::Responder(*only),
            [] => unattributed("no exchange is in progress"),
            [_] => unattributed("the only exchange in progress is one of ours that nothing waits on here"),
            _ => unattributed("more than one exchange is in progress"),
        }
    }
}

/// How many times the ledger took up again the peer's Quick Mode `msgid` ([`MidRecord::tries`]) when it holds
/// it in progress with the fingerprint `fingerprint`: what tells one spell in progress of the exchange from
/// the next ([`ExchangeTable::note_accepted`]). `None` when it holds no such exchange.
fn answerable_spell(ids: &MessageIdLedger, msgid: u32, fingerprint: &[u8; 32]) -> Option<u8> {
    match ids.record(msgid)? {
        MidRecord { origin: Origin::Peer, kind: MidKind::Quick, state: MidState::Active { .. }, fingerprint: Some(print), tries, .. } if print == *fingerprint => Some(tries),
        _ => None,
    }
}

/// The Quick Mode of ours a reader waits on, as [`ExchangeTable::attribute_error_notify`] needs it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AwaitedQuick {
    /// Its Message ID.
    pub msgid: u32,
    /// The SPI this side offered in its message 1 -- its own inbound SPI for the SA -- which a refusal of
    /// the offer names (RFC 2408 §3.14: "The receiving entity's SPI").
    pub offered_spi: u32,
}

/// Which exchange an error Notify is about ([`ExchangeTable::attribute_error_notify`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Attribution {
    /// The Quick Mode of ours the reader waits on: the peer refused it.
    OwnExchange,
    /// The responder exchange of this side under this Message ID.
    Responder(u32),
    /// No exchange that can be told: the waiting reader ignores it.
    None,
}

/// What [`ExchangeTable::responder_exchange`] knows of an id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ResponderLookup {
    /// No responder exchange of this side has the id.
    Unknown,
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

// ---- Reading: one classification of a datagram, for every reader ----

/// Why [`classify`] set a datagram aside. Every case is silence: nothing of it is answered, recorded
/// or kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ignored {
    /// No ISAKMP message: on a floated tunnel a datagram without the non-ESP marker (ESP or a NAT
    /// keepalive there), anywhere one with no ISAKMP header that parses.
    NotIsakmp,
    /// A message of an exchange type that no reader between exchanges reads, and that no final
    /// message of ours answered.
    ExchangeType(u8),
    /// A Quick Mode message read as a message 1 under Message ID 0, which is Phase 1's.
    ZeroMessageId,
    /// A Quick Mode message read as a message 1 whose header says its payloads are not encrypted
    /// (RFC 2409 §5.5: in Quick Mode "all payloads except the ISAKMP header are encrypted").
    NotEncrypted,
    /// A message that does not decrypt, or whose HASH(1) does not verify (RFC 2409 §5.5, §5.7).
    Unauthenticated,
    /// A Quick Mode message read as a message 1 that authenticated, but whose first payload is not a
    /// HASH followed by an SA (RFC 2409 §5.5: "a HASH payload MUST immediately follow the ISAKMP
    /// header and a SA payload MUST immediately follow the HASH"). No HASH covers the exchange type,
    /// and HASH(1) has one form in a Quick Mode message 1 and in an Informational, `prf(SKEYID_a,
    /// M-ID | ...)` (§5.5, §5.7): such a message is an Informational, or another message of that form,
    /// sent with the Quick Mode exchange type, and takes no id.
    NotMessage1,
    /// A Quick Mode message under an id of ours that no exchange of ours in progress takes, and that
    /// is not a repeat a final message of ours answered.
    OurId,
    /// A message 1 under an id of the peer's that the ledger does not take as new: a copy, another
    /// message under the id, a replay, a parked exchange not to be taken up now, or no room.
    Admission(Admission),
    /// A new message 1 whose nonce the peer sent in one of the last Quick Modes it started: RFC 2409
    /// §5.5 calls Quick Mode "an exchange of nonces that provides replay protection".
    NonceReplay,
    /// A copy of a message 1 the inbox already holds.
    InboxHeld,
    /// A copy with the Commit bit of a message 1 the inbox does not hold, while the inbox is full of
    /// copies without it ([`Queued::Full`]).
    InboxFull,
}

/// What an authenticated Informational said, as [`classify`] read it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct InformationalSeen {
    /// The Message ID it came under.
    pub msgid: u32,
    /// The sequence numbers of the R-U-THEREs it carried, each to be answered with an R-U-THERE-ACK
    /// carrying it (RFC 3706 §6.1) -- every time one comes, a copy of one answered before included.
    pub r_u_there: Vec<u32>,
    /// Whether it carried the R-U-THERE-ACK the reader waits for.
    pub ack_matched: bool,
    /// How many events it added to the mailbox (a fact the mailbox holds already adds none).
    pub events_pushed: usize,
    /// The error Notifies it carried, in its order, whether or not the mailbox held the same facts
    /// already: what a reader waiting on an exchange attributes ([`ExchangeTable::attribute_error_notify`]).
    pub error_notifies: Vec<ErrorNotice>,
    /// Whether one of its Delete payloads is of Protocol-Id ISAKMP, whatever SPI it names: the meaning
    /// the passive wait gives a Delete ([`super::informational::is_isakmp_sa_delete`]), not a check of
    /// the cookie pair.
    pub isakmp_deleted: bool,
    /// Whether the ledger held its Message ID already as an exchange of the peer's that is over
    /// ([`Admission::FinishedSame`] or [`Admission::Replay`]): a copy or a replay of an Informational
    /// read before -- whose id "is unique to this exchange" (RFC 2409 §5.7) -- or a message under the
    /// id of a Quick Mode of the peer's that is over. `false` for a first read, and for a copy the
    /// ledger cannot tell: under Message ID 0 or not shaped as an Informational (neither is recorded),
    /// or under an id it had no room to record or has let go of since.
    pub read_before: bool,
}

impl InformationalSeen {
    fn keep(&mut self, st: &Phase1State, event: PeerEvent) {
        if st.exchanges.push_event(event) == Push::Stored {
            self.events_pushed += 1;
        }
    }

    /// Reads one Notify payload's body: see [`classify`].
    fn read_notify(&mut self, st: &Phase1State, body: &[u8], expect_ack_seq: Option<u32>, now: Instant) {
        let Some(notify) = NotifyFields::parse(body) else {
            ike_debug!("INFORMATIONAL: ignoring a Notify payload of {} octets, too short for the length of its SPI", body.len());
            return;
        };
        // RFC 3706 §5.3: the Notification Data of both is the 4-octet sequence number.
        let seq = <[u8; 4]>::try_from(notify.data).ok().map(u32::from_be_bytes);
        match (notify.msg_type, seq) {
            (notify_type::R_U_THERE, Some(seq)) => {
                if self.r_u_there.contains(&seq) {
                    ike_debug!("DPD: R-U-THERE seq={seq} twice in one message -- answered once");
                } else if self.r_u_there.len() >= ACKS_PER_MESSAGE {
                    ike_debug!("DPD: not answering R-U-THERE seq={seq}: {ACKS_PER_MESSAGE} of this message are answered already");
                } else {
                    self.r_u_there.push(seq);
                }
            }
            (notify_type::R_U_THERE_ACK, Some(seq)) if expect_ack_seq == Some(seq) => {
                ike_debug!("DPD: R-U-THERE-ACK seq={seq} received -- peer is alive");
                self.ack_matched = true;
            }
            (notify_type::R_U_THERE_ACK, Some(seq)) => ike_debug!("DPD: ignoring R-U-THERE-ACK seq={seq} (expecting {expect_ack_seq:?})"),
            (notify_type::R_U_THERE | notify_type::R_U_THERE_ACK, None) => {
                ike_debug!("DPD: ignoring a Notify of type {} whose data is {} octets, not a sequence number", notify.msg_type, notify.data.len());
            }
            (msg_type @ 1..=16383, _) => {
                // RFC 2408 §3.14: for ISAKMP the cookie pair is the SPI, and "If the SPI Size is non-zero,
                // the content of the SPI field MUST be ignored".
                let spi = if notify.protocol == protocol::ISAKMP { Some(PeerSpi::EMPTY) } else { PeerSpi::new(notify.spi) };
                let Some(spi) = spi else {
                    ike_debug!("INFORMATIONAL: ignoring error Notify {msg_type}: its SPI of {} octets is longer than any SPI read here", notify.spi.len());
                    return;
                };
                ike_debug!("INFORMATIONAL: peer sent error Notify {} ({msg_type}) under msgid={:08x} -- kept for the reader", error_notify_name(msg_type), self.msgid);
                let notice = ErrorNotice { msg_type, protocol: notify.protocol, spi, msgid: self.msgid };
                self.error_notifies.push(notice);
                self.keep(st, notice.event(now));
            }
            (msg_type, _) => ike_debug!("INFORMATIONAL: ignoring a status Notify of type {msg_type}"),
        }
    }
}

/// The fields of a Notify payload's body (RFC 2408 §3.14): `DOI(4) | Protocol-Id(1) | SPI Size(1) |
/// Notify Message Type(2) | SPI | Notification Data`.
struct NotifyFields<'a> {
    protocol: u8,
    msg_type: u16,
    spi: &'a [u8],
    data: &'a [u8],
}

impl<'a> NotifyFields<'a> {
    /// `None` when the body is shorter than its fixed part and the SPI it declares.
    fn parse(body: &'a [u8]) -> Option<Self> {
        let (fixed, rest) = body.split_first_chunk::<8>()?;
        let spi_size = usize::from(fixed[5]);
        Some(Self { protocol: fixed[4], msg_type: u16::from_be_bytes([fixed[6], fixed[7]]), spi: rest.get(..spi_size)?, data: rest.get(spi_size..)? })
    }
}

/// What one datagram read off the IKEv1 socket is, by [`classify`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Classified {
    /// An ISAKMP message for another ISAKMP SA (another cookie pair).
    Foreign,
    /// Set aside: see [`Ignored`].
    Ignored(Ignored),
    /// A bit-exact repeat of a peer message a final message of ours answered: that final message,
    /// for the reader to send again as it was.
    ResendFinal(Vec<u8>),
    /// A Quick Mode message under the id of an exchange of ours in progress, for whoever waits on
    /// that exchange, untouched (the ISAKMP message, without the non-ESP marker). Nothing of it was
    /// decrypted or checked: the reader that waits on the exchange takes it as its answer only once
    /// its HASH(2) verifies.
    RouteToOwn { msgid: u32, message: Vec<u8> },
    /// An authenticated message 1 of a Quick Mode the peer started, now in the inbox.
    PeerQuick { msgid: u32 },
    /// A copy with the Commit bit of an authenticated message 1 the inbox holds without it: noted on
    /// that entry ([`PeerQuick::commit_seen`]).
    CommitNoted { msgid: u32 },
    /// An authenticated Informational, read to its last payload.
    Informational(InformationalSeen),
}

/// What one datagram read off the IKEv1 socket of `st`'s ISAKMP SA is, and what is kept of it.
/// `datagram` is the datagram as read (the non-ESP marker first when `st` floated to UDP 4500);
/// `expect_ack_seq` the sequence number of the R-U-THERE the reader waits for the ACK of, if it waits
/// for one. Only for an enabled table: the readers ask it when the table is on, and never otherwise.
/// Every time it is told is the table's clock ([`ExchangeTable::now`]), read once per datagram.
///
/// In this order, every step before anything of the datagram is decrypted unless it says so:
/// 1. The framing and the ISAKMP SA: no marker on a floated tunnel, or no header that parses, is no
///    ISAKMP message; another cookie pair is [`Classified::Foreign`] (traced once per pair).
/// 2. A Quick Mode message:
///    - a bit-exact repeat of a peer message a final message of ours answered is
///      [`Classified::ResendFinal`], whatever the ledger holds of its id: the peer asking again for a
///      message 3 of ours that was lost (RFC 2408 §3.1, Commit Bit NOTE, proposes that recovery),
///      which is never a new message 1 and never what an exchange in progress waits for;
///    - under the id of a Quick Mode of ours in progress, [`Classified::RouteToOwn`];
///    - under any other id of ours, [`Ignored::OurId`];
///    - under the id of a responder exchange of this side (there is none yet, see
///      [`ExchangeTable::responder_exchange`]): that exchange's;
///    - otherwise a message 1 candidate: a Message ID that is not 0 and the ENCRYPTION flag set, then
///      decrypted with the IV of its Message ID and checked by HASH(1) (RFC 2409 §5.5, Appendix B),
///      then its HASH first and an SA right after it (§5.5): no HASH covers the exchange type, and an
///      Informational's HASH(1) has the same form (§5.7), so without that an Informational sent as
///      Quick Mode would take an id ([`Ignored::NotMessage1`]). The ledger decides by its id and
///      content; only a new message 1 whose nonce was not seen before, or a parked one the peer sent
///      again in time, goes to the inbox; the ledger records a new one as a peer Quick Mode in
///      progress until [`PEER_QUICK_WAIT`] and remembers its nonce -- except for a copy with the
///      Commit bit set, which is neither recorded nor remembered, so that it takes no id (no HASH
///      covers the header, RFC 2409 §5.5): it goes to the inbox with that fact when its message is
///      new, or in progress or parked for the ledger, and when the inbox holds that message without
///      the bit, the fact is noted on it instead ([`Classified::CommitNoted`]). Whatever becomes of
///      such a copy, the table remembers that its message had the bit ([`ExchangeTable::note_commit`]).
/// 3. An Informational: decrypted with the IV of its own Message ID and checked by HASH(1) (RFC 2409
///    §5.7, Appendix B); a failure sets it aside. Its id is recorded as the peer's, so that no id of
///    ours reuses it -- only when it carries nothing but Notify and Delete payloads (§5.7: "HDR*,
///    HASH(1), N/D"), so that a Quick Mode message 1 sent as an Informational, which authenticates as
///    one, does not take the id the message 1 needs -- but nothing of what follows depends on the
///    ledger: a copy of a message read before is read again. The SPIs of every Delete payload become [`PeerEvent::Delete`]s, in the
///    order the message names them ([`parse_deletes`]); then every Notify, in its order: an R-U-THERE
///    is to be answered ([`InformationalSeen::r_u_there`], at most [`ACKS_PER_MESSAGE`] distinct
///    sequence numbers), an R-U-THERE-ACK of `expect_ack_seq` matches, an error Notify becomes a
///    [`PeerEvent::ErrorNotify`], and any other Notify (CONNECTED, the other status types) is traced
///    and ignored. What the message said is also returned as read, mailbox or no mailbox: its error
///    Notifies and whether it deleted the ISAKMP SA, for a reader that waits on an exchange of ours.
/// 4. Any other exchange type: a bit-exact repeat a final message of ours answered (Aggressive Mode
///    message 2, an XAUTH request) is [`Classified::ResendFinal`]; anything else is set aside.
pub(crate) fn classify(st: &Phase1State, datagram: &[u8], expect_ack_seq: Option<u32>) -> Classified {
    let message = if st.floated {
        match unwrap_ike_4500(datagram) {
            Some(message) => message,
            None => return Classified::Ignored(Ignored::NotIsakmp),
        }
    } else {
        datagram
    };
    let Ok(header) = IsakmpHeader::parse(message) else { return Classified::Ignored(Ignored::NotIsakmp) };
    if header.init_cookie != st.cky_i || header.resp_cookie != st.cky_r {
        let mut cookies = [0u8; 16];
        let (initiator, responder) = cookies.split_at_mut(8);
        initiator.copy_from_slice(&header.init_cookie);
        responder.copy_from_slice(&header.resp_cookie);
        if st.exchanges.first_sight_of_foreign(cookies) {
            ike_debug!("a datagram for another ISAKMP SA -- ignored (written once per cookie pair)");
        }
        return Classified::Foreign;
    }
    let now = st.exchanges.now();
    match header.exchange_type {
        exchange::QUICK => classify_quick(st, &header, message, now),
        exchange::INFORMATIONAL => classify_informational(st, &header, message, expect_ack_seq, now),
        other => match st.finals.answer_to(message) {
            Some(final_message) => Classified::ResendFinal(final_message),
            None => Classified::Ignored(Ignored::ExchangeType(other)),
        },
    }
}

/// Step 2 of [`classify`].
fn classify_quick(st: &Phase1State, header: &IsakmpHeader, message: &[u8], now: Instant) -> Classified {
    let msgid = header.message_id;
    if let Some(final_message) = st.finals.answer_to(message) {
        return Classified::ResendFinal(final_message);
    }
    st.exchanges.sweep(now);
    if let Some(MidRecord { origin: Origin::Local, kind: MidKind::Quick, state: MidState::Active { .. }, .. }) = st.exchanges.id_record(msgid) {
        return Classified::RouteToOwn { msgid, message: message.to_vec() };
    }
    if st.exchanges.origin_of(msgid) == Some(Origin::Local) {
        ike_debug!("QUICK: a message under msgid={msgid:08x}, an exchange of ours no longer in progress -- ignored");
        return Classified::Ignored(Ignored::OurId);
    }
    match st.exchanges.responder_exchange(msgid) {
        ResponderLookup::Unknown => classify_message_1(st, header, message, now),
    }
}

/// The message 1 candidate of [`classify`]'s step 2.
fn classify_message_1(st: &Phase1State, header: &IsakmpHeader, message: &[u8], now: Instant) -> Classified {
    let msgid = header.message_id;
    if msgid == 0 {
        ike_debug!("QUICK: a gateway Quick Mode message under msgid=00000000 -- ignored");
        return Classified::Ignored(Ignored::ZeroMessageId);
    }
    if !header.encrypted() {
        ike_debug!("QUICK: a gateway Quick Mode message under msgid={msgid:08x} without the ENCRYPTION flag -- ignored");
        return Classified::Ignored(Ignored::NotEncrypted);
    }
    let iv0 = crypto1::phase2_iv(st.prf, &st.phase1_iv, msgid, st.enc_block);
    let Ok((_header, payloads, _next)) = phase2::parse_encrypted(message, st.prf, &st.skeyid_a, &st.enc_key, st.enc_block, &iv0) else {
        ike_debug!("QUICK: a gateway Quick Mode message under msgid={msgid:08x} does not authenticate as a message 1 -- ignored");
        return Classified::Ignored(Ignored::Unauthenticated);
    };
    if !matches!(payloads.as_slice(), [hash, sa, ..] if hash.payload_type == payload::HASH && sa.payload_type == payload::SA) {
        ike_debug!("QUICK: a gateway message under msgid={msgid:08x} authenticates, but its HASH is not followed by an SA -- no message 1, ignored");
        return Classified::Ignored(Ignored::NotMessage1);
    }
    let print = msgid::fingerprint(msgid, &payloads);
    let commit_flag = header.flags & flags::COMMIT != 0;
    if commit_flag {
        // Whatever becomes of this copy, the fact outlives it (`ExchangeTable::note_commit`).
        st.exchanges.note_commit(msgid, print);
    }
    let admission = st.exchanges.would_admit(msgid, MidKind::Quick, &print, now);
    let new = match admission {
        Admission::New => true,
        Admission::Parked { ready: true } if !commit_flag => false,
        // A flagged copy of a message the ledger holds in progress or parked: its Commit bit is kept,
        // nothing else.
        Admission::Duplicate | Admission::Parked { .. } if commit_flag => false,
        other => {
            ike_debug!(
                "QUICK: gateway message 1 under msgid={msgid:08x}: {other:?} for the Message-ID ledger -- not answered ({} dropped so far)",
                st.exchanges.id_counters().dropped()
            );
            return Classified::Ignored(Ignored::Admission(other));
        }
    };
    // A copy of a message the ledger holds is the same message as before, nonce included: only a new
    // one is checked.
    if new {
        let seen = |family| payloads.iter().filter(|p| p.payload_type == payload::NONCE).any(|ni| st.exchanges.seen_ni(family, &ni.data));
        if seen(ChildFamily::Primary) || seen(ChildFamily::Ipv6) {
            ike_debug!("QUICK: gateway message 1 under msgid={msgid:08x} repeats the nonce of an earlier one -- a replay, not answered");
            return Classified::Ignored(Ignored::NonceReplay);
        }
    }
    if !commit_flag {
        let deadline = now.checked_add(PEER_QUICK_WAIT).unwrap_or(now);
        if new {
            let recorded = st.exchanges.record_authenticated(msgid, MidKind::Quick, print, now, deadline);
            if recorded != Admission::New {
                return Classified::Ignored(Ignored::Admission(recorded));
            }
            let family = nonce_family(&payloads);
            for ni in payloads.iter().filter(|p| p.payload_type == payload::NONCE) {
                st.exchanges.remember_ni(family, &ni.data);
            }
        } else if !st.exchanges.reconsider(msgid, now, deadline) {
            return Classified::Ignored(Ignored::Admission(Admission::Parked { ready: false }));
        }
    }
    let quick = PeerQuick { msgid, datagram: message.to_vec(), fingerprint: print, commit_flag, commit_seen: commit_flag, arrived: now };
    match st.exchanges.queue_peer_quick(quick) {
        Queued::Added => {
            ike_debug!(
                "QUICK: gateway message 1 under msgid={msgid:08x} authenticated -- kept for the responder{}",
                if commit_flag { " (this copy has the Commit bit set)" } else { "" }
            );
            Classified::PeerQuick { msgid }
        }
        Queued::CommitNoted => {
            ike_debug!("QUICK: a copy of gateway message 1 under msgid={msgid:08x} has the Commit bit set -- noted on the copy kept for the responder");
            Classified::CommitNoted { msgid }
        }
        Queued::Held => Classified::Ignored(Ignored::InboxHeld),
        Queued::Full => Classified::Ignored(Ignored::InboxFull),
        Queued::Passive => Classified::Ignored(Ignored::Admission(Admission::Passive)),
    }
}

/// The family whose nonce memory a message 1's nonce goes to: IPv6 when its first ID payload (IDci)
/// is of an IPv6 type (RFC 2407 §4.6.2.1: ID_IPV6_ADDR 5, ID_IPV6_ADDR_SUBNET 6, ID_IPV6_ADDR_RANGE
/// 8), the primary family otherwise. Not a validation of the IDs, which is the responder's: a nonce is
/// looked for in both families' memories, so this only says which one keeps it.
fn nonce_family(payloads: &[Payload]) -> ChildFamily {
    let idci_type = payloads.iter().find(|p| p.payload_type == payload::ID).and_then(|id| id.data.first().copied());
    match idci_type {
        Some(id_type::IPV6_ADDR | id_type::IPV6_ADDR_SUBNET | ID_IPV6_ADDR_RANGE) => ChildFamily::Ipv6,
        _ => ChildFamily::Primary,
    }
}

/// RFC 2407 §4.6.2.1: ID_IPV6_ADDR_RANGE (not one this code sends or accepts as a selector).
const ID_IPV6_ADDR_RANGE: u8 = 8;

/// Step 3 of [`classify`].
fn classify_informational(st: &Phase1State, header: &IsakmpHeader, message: &[u8], expect_ack_seq: Option<u32>, now: Instant) -> Classified {
    let msgid = header.message_id;
    let iv0 = crypto1::phase2_iv(st.prf, &st.phase1_iv, msgid, st.enc_block);
    let Ok((_header, payloads, _next)) = phase2::parse_encrypted(message, st.prf, &st.skeyid_a, &st.enc_key, st.enc_block, &iv0) else {
        ike_debug!("INFORMATIONAL: a message under msgid={msgid:08x} does not authenticate -- ignored");
        return Classified::Ignored(Ignored::Unauthenticated);
    };
    // RFC 2409 §5.7: "HDR*, HASH(1), N/D". No HASH covers the exchange type, and a Quick Mode
    // message 1 has a HASH(1) of the same form (§5.5), so one sent with this exchange type
    // authenticates as an Informational: read, its id is not recorded, or the message 1 itself
    // would find its id taken.
    let shaped = payloads.iter().all(|p| matches!(p.payload_type, payload::HASH | payload::NOTIFY | payload::DELETE));
    let read_before = if !shaped {
        ike_debug!("INFORMATIONAL: msgid={msgid:08x} carries a payload other than a Notify or a Delete -- read, its id not recorded");
        false
    } else if msgid != 0 {
        // So that no id of ours repeats it (the id of an Informational "is unique to this exchange",
        // RFC 2409 §5.7); whatever the ledger answers, the message is read: a copy, a replay or no room
        // changes nothing below but `read_before`.
        let admission = st.exchanges.record_authenticated(msgid, MidKind::Informational, msgid::fingerprint(msgid, &payloads), now, now);
        matches!(admission, Admission::FinishedSame | Admission::Replay)
    } else {
        false
    };
    let mut seen = InformationalSeen { msgid, read_before, ..InformationalSeen::default() };
    let deletes = parse_deletes(&payloads);
    deletes.trace();
    for named in &deletes.named {
        seen.isakmp_deleted |= named.protocol == protocol::ISAKMP;
        seen.keep(st, named.event(now));
    }
    for notify in payloads.iter().filter(|p| p.payload_type == payload::NOTIFY) {
        seen.read_notify(st, &notify.data, expect_ack_seq, now);
    }
    Classified::Informational(seen)
}

// ---- Reading the mailbox ----

/// Which generation of a family's CHILD SA an SPI belongs to, for [`classify_peer_deletes`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Generation {
    /// The SA in use.
    Current,
    /// The SA negotiated to replace the one in use, not in use yet.
    Pending,
    /// An SA a newer one replaced.
    Retired,
}

/// The peer's SPIs of one family's CHILD SAs -- the SPIs the peer chose for its inbound side, which
/// ESP is sent to and which its Deletes name -- as the reader of the mailbox holds them at the moment
/// it reads it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FamilySpis<'a> {
    /// The SA in use, if the family has one.
    pub current_peer_spi: Option<u32>,
    /// The SA negotiated to replace it, if one is pending.
    pub pending_peer_spi: Option<u32>,
    /// The SAs newer ones replaced, that the reader still knows of.
    pub retired_peer_spis: &'a [u32],
}

impl FamilySpis<'_> {
    fn generation_of(&self, spi: u32) -> Option<Generation> {
        if self.current_peer_spi == Some(spi) {
            Some(Generation::Current)
        } else if self.pending_peer_spi == Some(spi) {
            Some(Generation::Pending)
        } else if self.retired_peer_spis.contains(&spi) {
            Some(Generation::Retired)
        } else {
            None
        }
    }
}

/// The peer's SPIs of both families of CHILD SAs (see [`FamilySpis`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SpiState<'a> {
    pub primary: FamilySpis<'a>,
    pub ipv6: FamilySpis<'a>,
}

/// What a Delete the peer sent names, against the SPIs the reader holds ([`classify_peer_deletes`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeleteVerdict {
    /// The ESP SA of `family` whose peer SPI is `spi`, of `generation`.
    Child { family: ChildFamily, generation: Generation, spi: u32 },
    /// The ISAKMP SA: a teardown of the whole tunnel, whatever the SPI it carries (the meaning a
    /// Delete of Protocol-Id ISAKMP has always had here).
    IsakmpTeardown,
}

/// What the Deletes among `events` (from the mailbox, see
/// [`Phase1State::drain_peer_events`]) name, against
/// the SPIs the reader holds now, `spis`: the events carry only what the peer said, so the meaning is
/// given at the moment they are read, never at the moment they arrived. Classification only: what to
/// do about each verdict is the reader's.
///
/// A Delete of the ISAKMP SA comes first: when there is one, the answer is
/// [`DeleteVerdict::IsakmpTeardown`] alone. Otherwise one verdict per ESP Delete that names an SPI of
/// either family (the primary family's SPIs are looked at first; in each family the current SA, then
/// the pending one, then the retired ones), in the order the events are given; one that names no SA
/// the reader holds is traced and left out. Error Notifies are not Deletes and are not looked at.
pub fn classify_peer_deletes(events: &[PeerEvent], spis: &SpiState<'_>) -> Vec<DeleteVerdict> {
    if events.iter().any(|event| matches!(event, PeerEvent::Delete { protocol: protocol::ISAKMP, .. })) {
        return vec![DeleteVerdict::IsakmpTeardown];
    }
    let mut verdicts = Vec::new();
    for event in events {
        let PeerEvent::Delete { protocol: protocol::ESP, spi, .. } = event else { continue };
        let Some(spi) = spi.esp() else { continue };
        let found = [(ChildFamily::Primary, &spis.primary), (ChildFamily::Ipv6, &spis.ipv6)]
            .into_iter()
            .find_map(|(family, held)| held.generation_of(spi).map(|generation| (family, generation)));
        match found {
            Some((family, generation)) => verdicts.push(DeleteVerdict::Child { family, generation, spi }),
            None => ike_debug!("INFORMATIONAL: the peer's Delete of spi={spi:08x} names no CHILD SA of this tunnel -- ignored"),
        }
    }
    verdicts
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
        let arrived: Vec<Instant> = events.iter().map(PeerEvent::arrived).collect();
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

    // ---- Message IDs through the table ----

    /// A passive table hands out every id of ours exactly as the callers drew it before the table
    /// existed -- one draw of four octets, `| 1`, nothing remembered, so the same draw twice is the
    /// same id twice, and no clock read -- and every other ledger method is a no-op giving its
    /// neutral answer; turning the table on afterwards finds nothing recorded.
    #[test]
    fn a_passive_table_draws_our_ids_as_before_and_leaves_the_ledger_alone() {
        use crate::entropy::{Entropy, SeedEntropy};
        use std::sync::atomic::AtomicUsize;
        let at = Instant::now();
        let reads = Arc::new(AtomicUsize::new(0));
        let counted = reads.clone();
        let table = ExchangeTable::with_clock(Box::new(move || {
            counted.fetch_add(1, Ordering::Relaxed);
            at
        }));
        for seed in [0u64, 1, 7, 0xDEAD_BEEF, u64::MAX] {
            for kind in [MidKind::Quick, MidKind::Informational, MidKind::ModeConfig] {
                for _ in 0..2 {
                    let mut entropy = SeedEntropy::new(seed);
                    let mut before = SeedEntropy::new(seed);
                    let mut mid_b = [0u8; 4];
                    before.fill(&mut mid_b);
                    assert_eq!(table.fresh_message_id(kind, &mut entropy), Ok(u32::from_be_bytes(mid_b) | 1), "seed {seed:#x}, {kind:?}");
                    assert_eq!(entropy.next_u64(), before.next_u64(), "seed {seed:#x}, {kind:?}: one draw of four octets, no more");
                }
            }
        }
        let print = [1u8; 32];
        let later = at + Duration::from_secs(60);
        table.sweep(later);
        assert_eq!(table.would_admit(3, MidKind::Quick, &print, at), Admission::Passive);
        assert_eq!(table.record_authenticated(3, MidKind::Quick, print, at, later), Admission::Passive);
        assert_eq!(table.origin_of(3), None);
        assert_eq!(table.id_record(3), None);
        assert!(!table.finish(3, at, MidEnd::Done));
        assert!(!table.set_deadline(3, at, later));
        assert!(!table.attach_fingerprint(3, print));
        assert!(!table.park(3, at, later));
        assert!(!table.reconsider(3, later, later));
        table.remember_ni(ChildFamily::Primary, &[9; 16]);
        assert!(!table.seen_ni(ChildFamily::Primary, &[9; 16]));
        table.responder_concluded(ChildFamily::Primary, at);
        assert!(!table.accept_allowed(ChildFamily::Primary, later), "a passive table admits no gateway Quick Mode");
        assert_eq!(table.id_counters(), MidCounters::default());
        assert_eq!(table.ids_held(), 0);
        assert_eq!(reads.load(Ordering::Relaxed), 0, "a passive table never reads its clock");
        table.enable();
        assert_eq!(table.ids_held(), 0, "nothing was recorded while passive");
        assert!(!table.seen_ni(ChildFamily::Primary, &[9; 16]), "nor remembered");
        assert!(table.accept_allowed(ChildFamily::Primary, at), "nor a conclusion noted");
        // On, the same draw twice is two ids: the second one is not the first.
        let first = table.fresh_message_id(MidKind::Quick, &mut SeedEntropy::new(1)).unwrap();
        let second = table.fresh_message_id(MidKind::Quick, &mut SeedEntropy::new(1)).unwrap();
        assert_ne!(first, second);
        assert_eq!((table.origin_of(first), table.origin_of(second)), (Some(Origin::Local), Some(Origin::Local)));
        assert_eq!(table.ids_held(), 2);
        assert_eq!(reads.load(Ordering::Relaxed), 2, "on, each id of ours is stamped by the table's clock");
    }

    /// Our ids are stamped by the table's clock, not by one the caller cannot see: with the clock a
    /// test moves, our exchange starts when that clock says and stays in progress for its whole
    /// time, however far the clock was moved before (the real clock would have it end at once).
    #[test]
    fn our_ids_are_stamped_by_the_table_clock() {
        use crate::entropy::SeedEntropy;
        use crate::ikev1::msgid::{MidState, LOCAL_QUICK_DEADLINE};
        use crate::ikev1::phase1::TestClock;
        let clock = TestClock::new();
        let table = clock.exchanges();
        table.enable();
        clock.advance(Duration::from_secs(30));
        let now = clock.now();
        assert_eq!(table.now(), now);
        assert_eq!(table.record_authenticated(2, MidKind::Quick, [1; 32], now, now + Duration::from_secs(15)), Admission::New);
        let ours = table.fresh_message_id(MidKind::Quick, &mut SeedEntropy::new(9)).unwrap();
        let record = table.id_record(ours).expect("recorded");
        assert_eq!((record.first_seen, record.state), (now, MidState::Active { deadline: now + LOCAL_QUICK_DEADLINE }));
        clock.advance(Duration::from_secs(1));
        table.sweep(clock.now());
        assert_eq!(table.id_record(ours).map(|r| r.state), Some(MidState::Active { deadline: now + LOCAL_QUICK_DEADLINE }), "a simulated second later");
        clock.advance(LOCAL_QUICK_DEADLINE);
        table.sweep(clock.now());
        assert_eq!(table.id_record(ours).map(|r| r.state), Some(MidState::Done), "past its deadline by the same clock");
    }

    /// The ledger is the clones' together, like the mailbox: an id drawn through one is known through another.
    #[test]
    fn clones_share_the_ledger() {
        use crate::entropy::SeedEntropy;
        let table = ExchangeTable::enabled();
        let clone = table.clone();
        let at = Instant::now();
        let ours = clone.fresh_message_id(MidKind::Quick, &mut SeedEntropy::new(5)).unwrap();
        assert_eq!(table.origin_of(ours), Some(Origin::Local));
        assert_eq!(table.record_authenticated(2, MidKind::Quick, [1; 32], at, at + Duration::from_secs(15)), Admission::New);
        assert_eq!(clone.would_admit(2, MidKind::Quick, &[1; 32], at), Admission::Duplicate);
        assert_eq!(table.id_counters().duplicates, 1);
        assert_eq!(ExchangeTable::enabled().origin_of(ours), None, "another table holds nothing of it");
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

    // ---- classify: the fixture ----

    use crate::entropy::SeedEntropy;
    use crate::ikev1::informational::tests::phase1_pair;
    use crate::ikev1::msgid::{LOCAL_QUICK_DEADLINE, MID_CAP, RECONSIDER_GAP};
    use crate::ikev1::phase1::TestClock;
    use crate::ikev1::quick;
    use crate::ikev2::natt::wrap_ike_4500;
    use crate::ikev2::sk::SkCipher;

    /// A client and a gateway of one ISAKMP SA, the client's exchange table on and telling the time
    /// (its retained final messages too) by the clock the test moves.
    fn enabled_pair() -> (Phase1State, Phase1State, TestClock) {
        let (mut client, gateway) = phase1_pair();
        let clock = TestClock::new();
        client.exchanges = clock.exchanges();
        client.finals = clock.finals();
        client.enable_gateway_quick_mode();
        (client, gateway, clock)
    }

    /// A Quick Mode message 1 the gateway starts for an IPv4 CHILD SA, built by the public initiator code.
    fn gateway_qm1(gateway: &Phase1State, seed: u64, pfs: Option<DhGroup>) -> Vec<u8> {
        let ts = ([10, 9, 0, 0], [255, 255, 0, 0]);
        quick::initiate_quick_with_pfs(gateway, &mut SeedEntropy::new(seed), SkCipher::Aes256Gcm, ts, ([0; 4], [0; 4]), pfs, 3600).unwrap().0
    }

    /// The same for an IPv6 CHILD SA.
    fn gateway_qm1_v6(gateway: &Phase1State, seed: u64) -> Vec<u8> {
        let ts = ("fd00:9::".parse().unwrap(), 64);
        quick::initiate_quick_ipv6(gateway, &mut SeedEntropy::new(seed), SkCipher::Aes256Gcm, ts, ("::".parse().unwrap(), 0), None, 3600).unwrap().0
    }

    /// An encrypted message of the gateway's under `msgid`, with HASH(1) over `payloads` (RFC 2409 §5.5, §5.7)
    /// and the header flags `flags` besides ENCRYPTION.
    fn gateway_message(gateway: &Phase1State, exchange_type: u8, msgid: u32, flags: u8, payloads: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let header = IsakmpHeader {
            init_cookie: gateway.cky_i,
            resp_cookie: gateway.cky_r,
            next_payload: payload::NONE,
            version: IsakmpHeader::VERSION_1_0,
            exchange_type,
            flags,
            message_id: msgid,
            length: 0,
        };
        let iv0 = crypto1::phase2_iv(gateway.prf, &gateway.phase1_iv, msgid, gateway.enc_block);
        phase2::build_encrypted(header, gateway.prf, &gateway.skeyid_a, &gateway.enc_key, gateway.enc_block, &iv0, payloads).unwrap().0
    }

    /// The payloads of a Quick Mode message 1 as far as `classify` cares: an SA body it does not read, a nonce.
    fn qm1_payloads(nonce: u8) -> Vec<(u8, Vec<u8>)> {
        vec![(payload::SA, vec![0, 0, 0, 1, 0, 0, 0, 1]), (payload::NONCE, vec![nonce; 16])]
    }

    fn informational(gateway: &Phase1State, msgid: u32, payloads: &[(u8, Vec<u8>)]) -> Vec<u8> {
        gateway_message(gateway, exchange::INFORMATIONAL, msgid, 0, payloads)
    }

    fn as_pair(p: Payload) -> (u8, Vec<u8>) {
        (p.payload_type, p.data)
    }

    /// A Notify payload: `DOI(4) | Protocol-Id | SPI Size | type(2) | SPI | data` (RFC 2408 §3.14).
    fn notify(protocol_id: u8, spi: &[u8], msg_type: u16, data: &[u8]) -> (u8, Vec<u8>) {
        let mut body = IPSEC_DOI.to_be_bytes().to_vec();
        body.extend_from_slice(&[protocol_id, spi.len() as u8]);
        body.extend_from_slice(&msg_type.to_be_bytes());
        body.extend_from_slice(spi);
        body.extend_from_slice(data);
        (payload::NOTIFY, body)
    }

    fn msgid_of(message: &[u8]) -> u32 {
        IsakmpHeader::parse(message).unwrap().message_id
    }

    /// `message` with the Commit bit set in its header, which nothing authenticates.
    fn with_commit(message: &[u8]) -> Vec<u8> {
        let mut flagged = message.to_vec();
        flagged[19] |= flags::COMMIT;
        flagged
    }

    /// What the gateway put in `message`, decrypted with its own state: what the fingerprint is computed over.
    fn fingerprint_of(gateway: &Phase1State, message: &[u8]) -> [u8; 32] {
        let msgid = msgid_of(message);
        let iv0 = crypto1::phase2_iv(gateway.prf, &gateway.phase1_iv, msgid, gateway.enc_block);
        let (_h, payloads, _next) = phase2::parse_encrypted(message, gateway.prf, &gateway.skeyid_a, &gateway.enc_key, gateway.enc_block, &iv0).unwrap();
        msgid::fingerprint(msgid, &payloads)
    }

    /// Records `MID_CAP` peer Quick Modes in progress in the client's ledger, under even ids (ours are odd):
    /// whatever it held that was over gives way, and every record is then an exchange in progress.
    fn fill_with_peer_quick_modes(client: &Phase1State, clock: &TestClock) {
        let now = clock.now();
        for n in 1..=MID_CAP as u32 {
            assert_eq!(client.exchanges.record_authenticated(2 * n, MidKind::Quick, [7; 32], now, now + Duration::from_secs(3600)), Admission::New);
        }
    }

    // ---- classify: Quick Mode message 1 ----

    /// An authenticated message 1 of a gateway Quick Mode -- IPv4 with PFS, IPv6 without -- is kept in the
    /// inbox once, as it came, recorded as the peer's exchange in progress for `PEER_QUICK_WAIT`; a
    /// bit-identical copy is a duplicate for the ledger and is not queued again.
    #[test]
    fn an_authenticated_gateway_message_1_goes_to_the_inbox_once() {
        type Build = fn(&Phase1State) -> Vec<u8>;
        let cases: [(&str, Build); 2] = [("IPv4, PFS", |gw| gateway_qm1(gw, 0x11, Some(DhGroup::Modp1024))), ("IPv6, no PFS", |gw| gateway_qm1_v6(gw, 0x12))];
        for (what, build) in cases {
            let (client, gateway, clock) = enabled_pair();
            clock.advance(Duration::from_secs(5));
            let msg1 = build(&gateway);
            let msgid = msgid_of(&msg1);
            assert_eq!(classify(&client, &msg1, None), Classified::PeerQuick { msgid }, "{what}");
            assert_eq!(classify(&client, &msg1, None), Classified::Ignored(Ignored::Admission(Admission::Duplicate)), "{what}: a bit-identical copy");
            let record = client.exchanges.id_record(msgid).expect("recorded");
            assert_eq!(
                (record.origin, record.kind, record.state, record.fingerprint),
                (Origin::Peer, MidKind::Quick, MidState::Active { deadline: clock.now() + PEER_QUICK_WAIT }, Some(fingerprint_of(&gateway, &msg1))),
                "{what}"
            );
            let kept = client.take_peer_quick_modes();
            let expected = PeerQuick { msgid, datagram: msg1.clone(), fingerprint: fingerprint_of(&gateway, &msg1), commit_flag: false, commit_seen: false, arrived: clock.now() };
            assert_eq!(kept, [expected], "{what}");
            assert!(client.take_peer_quick_modes().is_empty(), "{what}: taken");
            assert!(client.drain_peer_events().is_empty(), "{what}: a message 1 is no event");
        }
    }

    /// What does not authenticate as a message 1 of this ISAKMP SA -- or is no ISAKMP message -- takes no
    /// place in the ledger or the inbox.
    #[test]
    fn what_is_not_an_authenticated_message_1_of_this_sa_is_recorded_nowhere() {
        let (client, gateway, _clock) = enabled_pair();
        let msg1 = gateway_qm1(&gateway, 0x21, None);
        let mut wrong_key = gateway.clone();
        wrong_key.skeyid_a = vec![0x99; gateway.skeyid_a.len()];
        let mut cipher_byte = msg1.clone();
        cipher_byte[IsakmpHeader::LEN + 2] ^= 0x01;
        let mut no_encryption = msg1.clone();
        no_encryption[19] &= !flags::ENCRYPTION;
        let mut zero_id = msg1.clone();
        zero_id[20..24].copy_from_slice(&[0; 4]);
        let mut foreign = msg1.clone();
        foreign[0] ^= 0xFF;
        let mut cut = msg1[..msg1.len() - 3].to_vec();
        let cut_len = cut.len() as u32;
        cut[24..28].copy_from_slice(&cut_len.to_be_bytes());
        let mut long = msg1.clone();
        long.push(0);
        let mut version_2 = msg1.clone();
        version_2[17] = 0x20;
        let cases: [(&str, Vec<u8>, Classified); 10] = [
            ("HASH(1) by another key", gateway_qm1(&wrong_key, 0x22, None), Classified::Ignored(Ignored::Unauthenticated)),
            ("a cipher byte changed", cipher_byte, Classified::Ignored(Ignored::Unauthenticated)),
            ("no ENCRYPTION flag", no_encryption, Classified::Ignored(Ignored::NotEncrypted)),
            ("Message ID 0", zero_id, Classified::Ignored(Ignored::ZeroMessageId)),
            ("another ISAKMP SA's cookies", foreign, Classified::Foreign),
            ("ciphertext not a whole number of blocks", cut, Classified::Ignored(Ignored::Unauthenticated)),
            ("one octet more than the header says", long, Classified::Ignored(Ignored::NotIsakmp)),
            ("major version 2", version_2, Classified::Ignored(Ignored::NotIsakmp)),
            ("shorter than a header", vec![0x5A; 27], Classified::Ignored(Ignored::NotIsakmp)),
            ("empty", Vec::new(), Classified::Ignored(Ignored::NotIsakmp)),
        ];
        for (what, datagram, expected) in cases {
            assert_eq!(classify(&client, &datagram, None), expected, "{what}");
            assert_eq!((client.exchanges.ids_held(), client.exchanges.inbox_held()), (0, 0), "{what}: nothing recorded");
        }
        assert_eq!(classify(&client, &msg1, None), Classified::PeerQuick { msgid: msgid_of(&msg1) }, "control: the original is a message 1");
    }

    /// A Quick Mode message under an id of ours is never read as a message 1: under the id of a Quick Mode of
    /// ours in progress it is that exchange's, untouched; under any other id of ours it is set aside. Under the
    /// id of a peer exchange the ledger holds, the ledger decides: another message, or one past its time.
    #[test]
    fn a_quick_mode_message_under_an_id_the_ledger_knows_is_not_a_new_message_1() {
        let (client, gateway, clock) = enabled_pair();
        let mut e = SeedEntropy::new(0x31);
        let our_quick = client.fresh_message_id(MidKind::Quick, &mut e).unwrap();
        let our_config = client.fresh_message_id(MidKind::ModeConfig, &mut e).unwrap();
        let our_informational = client.fresh_message_id(MidKind::Informational, &mut e).unwrap();
        let under = |msgid: u32, nonce: u8| gateway_message(&gateway, exchange::QUICK, msgid, 0, &qm1_payloads(nonce));
        let peer = gateway_qm1(&gateway, 0x32, None);
        let peer_id = msgid_of(&peer);
        assert_eq!(classify(&client, &peer, None), Classified::PeerQuick { msgid: peer_id });
        let held = client.exchanges.ids_held();
        let in_progress: [(&str, Vec<u8>, Classified); 4] = [
            ("our Quick Mode in progress", under(our_quick, 1), Classified::RouteToOwn { msgid: our_quick, message: under(our_quick, 1) }),
            ("our Mode-Config request", under(our_config, 1), Classified::Ignored(Ignored::OurId)),
            ("our Informational", under(our_informational, 1), Classified::Ignored(Ignored::OurId)),
            ("another message under the peer's id in progress", under(peer_id, 1), Classified::Ignored(Ignored::Admission(Admission::Different))),
        ];
        for (what, datagram, expected) in in_progress {
            assert_eq!(classify(&client, &datagram, None), expected, "{what}");
        }
        clock.advance(LOCAL_QUICK_DEADLINE);
        let over: [(&str, Vec<u8>, Classified); 3] = [
            ("our Quick Mode past its deadline", under(our_quick, 1), Classified::Ignored(Ignored::OurId)),
            ("a copy of the peer's message 1 past its time", peer.clone(), Classified::Ignored(Ignored::Admission(Admission::FinishedSame))),
            ("another message under the peer's finished id", under(peer_id, 2), Classified::Ignored(Ignored::Admission(Admission::Replay))),
        ];
        for (what, datagram, expected) in over {
            assert_eq!(classify(&client, &datagram, None), expected, "{what}");
        }
        assert_eq!(client.exchanges.ids_held(), held, "nothing more was recorded");
        assert_eq!(client.take_peer_quick_modes().len(), 1, "only the first message 1");
    }

    /// The gateway repeating, bit for bit, the message 2 our message 3 answered gets that message 3 again --
    /// while our Quick Mode is still in progress for the ledger, and after its record is over and forgotten
    /// under a ledger full of the peer's exchanges in progress -- and is never recorded as the peer's.
    #[test]
    fn a_repeat_of_the_message_our_final_answered_gets_it_again_whatever_the_ledger_holds() {
        let (client, gateway, clock) = enabled_pair();
        let ours = client.fresh_message_id(MidKind::Quick, &mut SeedEntropy::new(0x41)).unwrap();
        let message_2 = gateway_message(&gateway, exchange::QUICK, ours, 0, &qm1_payloads(4));
        let message_3 = b"our Quick Mode message 3".to_vec();
        client.finals.retain(&message_2, &message_3);
        assert_eq!(classify(&client, &message_2, None), Classified::ResendFinal(message_3.clone()), "our exchange still in progress");
        clock.advance(LOCAL_QUICK_DEADLINE);
        fill_with_peer_quick_modes(&client, &clock);
        assert_eq!(client.exchanges.id_record(ours), None, "our record was forgotten to make room");
        assert_eq!(client.exchanges.would_admit(0xFFFF_FFF0, MidKind::Quick, &[0; 32], clock.now()), Admission::Saturated);
        assert_eq!(classify(&client, &message_2, None), Classified::ResendFinal(message_3), "the recovery does not depend on the ledger");
        assert_eq!(client.exchanges.id_record(ours), None, "and the repeat is not recorded as the peer's");
        assert_eq!(client.exchanges.inbox_held(), 0);
    }

    /// The non-ESP marker of a datagram on UDP 4500 is framing, not content: a plain copy and a marked copy of
    /// one message 1, read through two views of the same ISAKMP SA, are the same message for the ledger
    /// whichever comes first, and the inbox keeps the message without the marker.
    #[test]
    fn a_plain_copy_and_a_floated_copy_of_a_message_1_are_one_message() {
        for floated_first in [false, true] {
            let (client, gateway, _clock) = enabled_pair();
            let mut floated = client.clone();
            floated.floated = true;
            let msg1 = gateway_qm1(&gateway, 0x51, None);
            let msgid = msgid_of(&msg1);
            let marked = wrap_ike_4500(&msg1);
            let (first, second) = if floated_first { ((&floated, &marked), (&client, &msg1)) } else { ((&client, &msg1), (&floated, &marked)) };
            assert_eq!(classify(first.0, first.1, None), Classified::PeerQuick { msgid }, "floated first: {floated_first}");
            assert_eq!(classify(second.0, second.1, None), Classified::Ignored(Ignored::Admission(Admission::Duplicate)), "floated first: {floated_first}");
            assert_eq!(classify(&floated, &msg1, None), Classified::Ignored(Ignored::NotIsakmp), "unmarked on 4500 is not IKE");
            let kept = client.take_peer_quick_modes();
            assert_eq!(kept.iter().map(|q| &q.datagram).collect::<Vec<_>>(), [&msg1], "floated first: {floated_first}");
        }
    }

    /// The Commit bit is a fact of one copy, which no HASH covers: a copy with it set is kept with that fact
    /// and takes no id, so the copy without it is still a new message 1, and carries the fact of the flagged
    /// copy the inbox holds; a flagged copy after it changes nothing more.
    #[test]
    fn a_copy_with_the_commit_bit_is_kept_as_such_and_takes_no_id() {
        let (client, gateway, _clock) = enabled_pair();
        let msg1 = gateway_qm1(&gateway, 0x61, None);
        let msgid = msgid_of(&msg1);
        let flagged = with_commit(&msg1);
        assert_eq!(classify(&client, &flagged, None), Classified::PeerQuick { msgid });
        assert_eq!(client.exchanges.id_record(msgid), None, "no id taken");
        assert_eq!(classify(&client, &flagged, None), Classified::Ignored(Ignored::InboxHeld), "the same flagged copy again");
        assert_eq!(classify(&client, &msg1, None), Classified::PeerQuick { msgid }, "the clean copy is new");
        assert_eq!(client.exchanges.id_record(msgid).map(|r| r.origin), Some(Origin::Peer));
        assert_eq!(classify(&client, &flagged, None), Classified::Ignored(Ignored::InboxHeld), "the fact is held already");
        let kept = client.take_peer_quick_modes();
        assert_eq!(kept.iter().map(|q| (q.msgid, q.commit_flag, q.commit_seen)).collect::<Vec<_>>(), [(msgid, true, true), (msgid, false, true)]);
        assert_eq!(kept[0].fingerprint, kept[1].fingerprint, "one message, two copies");
    }

    /// A Commit bit that comes on a later copy of a message 1 the ledger recorded is not dropped with the
    /// copy: while the recorded copy waits in the inbox the fact is noted on it; once it was taken, the flagged
    /// copy is an entry of its own; for a parked exchange it is kept too, and the copy taken up again carries
    /// it. The record is never touched by a flagged copy.
    #[test]
    fn a_commit_bit_on_a_later_copy_is_kept_with_its_message() {
        let (client, gateway, _clock) = enabled_pair();
        let msg1 = gateway_qm1(&gateway, 0x65, None);
        let msgid = msgid_of(&msg1);
        let flagged = with_commit(&msg1);
        assert_eq!(classify(&client, &msg1, None), Classified::PeerQuick { msgid });
        let record = client.exchanges.id_record(msgid);
        assert_eq!(classify(&client, &flagged, None), Classified::CommitNoted { msgid }, "noted on the waiting copy");
        assert_eq!(classify(&client, &flagged, None), Classified::Ignored(Ignored::InboxHeld), "noted once");
        let kept = client.take_peer_quick_modes();
        assert_eq!(kept.iter().map(|q| (q.msgid, q.commit_flag, q.commit_seen, &q.datagram)).collect::<Vec<_>>(), [(msgid, false, true, &msg1)]);
        assert_eq!(classify(&client, &flagged, None), Classified::PeerQuick { msgid }, "the waiting copy was taken");
        let kept = client.take_peer_quick_modes();
        assert_eq!(kept.iter().map(|q| (q.msgid, q.commit_flag, q.commit_seen)).collect::<Vec<_>>(), [(msgid, true, true)]);
        assert_eq!(client.exchanges.id_record(msgid), record, "the record is the clean copy's, untouched");

        let (client, gateway, clock) = enabled_pair();
        let messages: Vec<Vec<u8>> = (0..=INBOX_CAP as u64).map(|n| gateway_qm1(&gateway, 0x66 + n, None)).collect();
        for message in &messages {
            assert_eq!(classify(&client, message, None), Classified::PeerQuick { msgid: msgid_of(message) });
        }
        let parked = msgid_of(&messages[0]);
        let record = client.exchanges.id_record(parked);
        assert!(matches!(record.map(|r| r.state), Some(MidState::Parked { .. })), "{record:?}");
        assert_eq!(classify(&client, &with_commit(&messages[0]), None), Classified::Ignored(Ignored::InboxFull), "never instead of a recorded copy");
        assert_eq!(client.take_peer_quick_modes().len(), INBOX_CAP);
        assert_eq!(classify(&client, &with_commit(&messages[0]), None), Classified::PeerQuick { msgid: parked }, "kept once there is room");
        assert_eq!(client.exchanges.id_record(parked), record, "still parked, untouched");
        clock.advance(RECONSIDER_GAP);
        assert_eq!(classify(&client, &messages[0], None), Classified::PeerQuick { msgid: parked }, "taken up again");
        let kept = client.take_peer_quick_modes();
        assert_eq!(kept.iter().map(|q| (q.msgid, q.commit_flag, q.commit_seen)).collect::<Vec<_>>(), [(parked, true, true), (parked, false, true)]);
    }

    /// The exchange type is in the header, which no HASH covers, and HASH(1) has one form in a Quick Mode
    /// message 1 and in an Informational (RFC 2409 §5.5, §5.7): a message sent with the other's exchange type
    /// authenticates, but takes no id and is not kept as a message 1, whether it comes before or after the
    /// genuine message, which is read as it would be without it.
    #[test]
    fn a_message_sent_with_the_other_exchange_type_takes_nothing_from_the_genuine_one() {
        for retyped_first in [true, false] {
            let (client, gateway, clock) = enabled_pair();
            let msg1 = gateway_qm1(&gateway, 0xB1, None);
            let msgid = msgid_of(&msg1);
            let delete_id = 0x2001;
            let delete = informational(&gateway, delete_id, &[as_pair(esp_delete(&[0x66]))]);
            let retype = |message: &[u8], exchange_type: u8| {
                let mut retyped = message.to_vec();
                retyped[18] = exchange_type;
                retyped
            };
            let (msg1_as_informational, delete_as_quick) = (retype(&msg1, exchange::INFORMATIONAL), retype(&delete, exchange::QUICK));
            let read_nothing = Classified::Informational(InformationalSeen { msgid, ..InformationalSeen::default() });
            let read_retyped = |when: &str| {
                assert_eq!(classify(&client, &msg1_as_informational, None), read_nothing, "{when}");
                assert_eq!(classify(&client, &delete_as_quick, None), Classified::Ignored(Ignored::NotMessage1), "{when}");
                assert!(client.drain_peer_events().is_empty(), "{when}");
            };
            if retyped_first {
                read_retyped("first");
                assert_eq!((client.exchanges.ids_held(), client.exchanges.inbox_held()), (0, 0), "nothing recorded or kept");
            }
            assert_eq!(classify(&client, &msg1, None), Classified::PeerQuick { msgid }, "retyped first: {retyped_first}");
            let Classified::Informational(seen) = classify(&client, &delete, None) else { panic!("retyped first: {retyped_first}") };
            assert_eq!(seen.events_pushed, 1, "retyped first: {retyped_first}");
            assert_eq!(client.drain_peer_events(), [esp(0x66).event(clock.now())], "retyped first: {retyped_first}");
            if !retyped_first {
                read_retyped("after");
            }
            let kinds = |id| client.exchanges.id_record(id).map(|r| (r.origin, r.kind, r.state));
            assert_eq!(kinds(msgid), Some((Origin::Peer, MidKind::Quick, MidState::Active { deadline: clock.now() + PEER_QUICK_WAIT })), "retyped first: {retyped_first}");
            assert_eq!(kinds(delete_id), Some((Origin::Peer, MidKind::Informational, MidState::Done)), "retyped first: {retyped_first}");
            assert_eq!(client.take_peer_quick_modes().iter().map(|q| &q.datagram).collect::<Vec<_>>(), [&msg1], "retyped first: {retyped_first}");
        }
    }

    /// A message 1 replayed after the ledger forgot its id is caught by its nonce, in the memory of the family
    /// its IDci names; a message 1 with a nonce of its own is not.
    #[test]
    fn a_replayed_message_1_is_caught_by_its_nonce_once_the_ledger_forgot_its_id() {
        type Build = fn(&Phase1State, u64) -> Vec<u8>;
        let cases: [(&str, Build, ChildFamily); 2] = [("IPv4", |gw, seed| gateway_qm1(gw, seed, None), ChildFamily::Primary), ("IPv6", gateway_qm1_v6, ChildFamily::Ipv6)];
        for (what, build, family) in cases {
            let (client, gateway, clock) = enabled_pair();
            let msg1 = build(&gateway, 0x71);
            let msgid = msgid_of(&msg1);
            assert_eq!(classify(&client, &msg1, None), Classified::PeerQuick { msgid }, "{what}");
            clock.advance(PEER_QUICK_WAIT);
            let now = clock.now();
            let mut id = 2u32;
            while client.exchanges.id_record(msgid).is_some() {
                client.exchanges.record_authenticated(id, MidKind::Informational, [7; 32], now, now);
                id += 2;
            }
            assert_eq!(classify(&client, &msg1, None), Classified::Ignored(Ignored::NonceReplay), "{what}");
            assert_eq!(client.exchanges.id_counters().ni_replays, 1, "{what}");
            let fresh = build(&gateway, 0x72);
            assert_eq!(classify(&client, &fresh, None), Classified::PeerQuick { msgid: msgid_of(&fresh) }, "{what}: a new nonce");
            let other = if family == ChildFamily::Primary { ChildFamily::Ipv6 } else { ChildFamily::Primary };
            let nonce = |message: &[u8]| {
                let iv0 = crypto1::phase2_iv(gateway.prf, &gateway.phase1_iv, msgid_of(message), gateway.enc_block);
                let (_h, ps, _n) = phase2::parse_encrypted(message, gateway.prf, &gateway.skeyid_a, &gateway.enc_key, gateway.enc_block, &iv0).unwrap();
                ps.into_iter().find(|p| p.payload_type == payload::NONCE).unwrap().data
            };
            assert!(client.exchanges.seen_ni(family, &nonce(&fresh)), "{what}: kept by its family");
            assert!(!client.exchanges.seen_ni(other, &nonce(&fresh)), "{what}: and not by the other");
        }
    }

    /// The family a nonce is remembered for is read from the IDci type only (RFC 2407 §4.6.2.1).
    #[test]
    fn the_nonce_family_follows_the_idci_type() {
        let id = |id_type: u8| Payload { payload_type: payload::ID, data: vec![id_type, 0, 0, 0, 1, 2, 3, 4] };
        let nonce = Payload { payload_type: payload::NONCE, data: vec![1; 16] };
        let cases: [(&str, Vec<Payload>, ChildFamily); 8] = [
            ("ID_IPV4_ADDR", vec![nonce.clone(), id(1), id(5)], ChildFamily::Primary),
            ("ID_IPV4_ADDR_SUBNET", vec![id(4)], ChildFamily::Primary),
            ("ID_IPV4_ADDR_RANGE", vec![id(7)], ChildFamily::Primary),
            ("ID_IPV6_ADDR", vec![id(5), id(1)], ChildFamily::Ipv6),
            ("ID_IPV6_ADDR_SUBNET", vec![nonce.clone(), id(6)], ChildFamily::Ipv6),
            ("ID_IPV6_ADDR_RANGE", vec![id(8)], ChildFamily::Ipv6),
            ("no ID", vec![nonce], ChildFamily::Primary),
            ("an empty ID body", vec![Payload { payload_type: payload::ID, data: Vec::new() }], ChildFamily::Primary),
        ];
        for (what, payloads, family) in cases {
            assert_eq!(nonce_family(&payloads), family, "{what}");
        }
    }

    /// The inbox holds four: the fifth message 1 drops the oldest, which is parked -- silence for a copy of it
    /// before `RECONSIDER_GAP`, taken up again for a copy after.
    #[test]
    fn a_full_inbox_drops_its_oldest_and_parks_it_for_the_peers_next_copy() {
        let (client, gateway, clock) = enabled_pair();
        let messages: Vec<Vec<u8>> = (0..=INBOX_CAP as u64).map(|n| gateway_qm1(&gateway, 0x81 + n, None)).collect();
        for message in &messages {
            assert_eq!(classify(&client, message, None), Classified::PeerQuick { msgid: msgid_of(message) });
        }
        let kept: Vec<u32> = client.take_peer_quick_modes().iter().map(|q| q.msgid).collect();
        assert_eq!(kept, messages[1..].iter().map(|m| msgid_of(m)).collect::<Vec<_>>(), "the oldest gave way");
        let oldest = msgid_of(&messages[0]);
        let now = clock.now();
        assert_eq!(
            client.exchanges.id_record(oldest).map(|r| r.state),
            Some(MidState::Parked { not_before: now + RECONSIDER_GAP, until: now + PEER_QUICK_WAIT })
        );
        assert_eq!(classify(&client, &messages[0], None), Classified::Ignored(Ignored::Admission(Admission::Parked { ready: false })), "too soon");
        clock.advance(RECONSIDER_GAP);
        assert_eq!(classify(&client, &messages[0], None), Classified::PeerQuick { msgid: oldest }, "taken up again");
        let record = client.exchanges.id_record(oldest).unwrap();
        assert_eq!((record.state, record.tries), (MidState::Active { deadline: clock.now() + PEER_QUICK_WAIT }, 1));
    }

    /// Messages of other ISAKMP SAs are traced once per cookie pair, among the last sixteen pairs seen.
    #[test]
    fn a_foreign_cookie_pair_is_traced_once_while_it_is_remembered() {
        let (client, gateway, _clock) = enabled_pair();
        let pair = |n: u8| [n; 16];
        for n in 1..=FOREIGN_REMEMBERED as u8 {
            assert!(client.exchanges.first_sight_of_foreign(pair(n)), "pair {n}");
        }
        assert!(!client.exchanges.first_sight_of_foreign(pair(1)), "seen");
        assert!(client.exchanges.first_sight_of_foreign(pair(0xEE)), "a seventeenth");
        assert!(client.exchanges.first_sight_of_foreign(pair(1)), "made the first be forgotten");
        assert!(!ExchangeTable::passive().first_sight_of_foreign(pair(2)), "passive: nothing");
        let mut other = gateway_qm1(&gateway, 0x91, None);
        other[8] ^= 0x01;
        assert_eq!(classify(&client, &other, None), Classified::Foreign);
        assert_eq!(classify(&client, &other, None), Classified::Foreign, "every time, traced or not");
    }

    /// An exchange type no reader reads gets the final message of ours that answered it when it repeats that
    /// message bit for bit -- Aggressive Mode message 2 -- and nothing otherwise.
    #[test]
    fn another_exchange_type_is_answered_only_with_a_retained_final() {
        let (client, gateway, _clock) = enabled_pair();
        let header = |exchange_type| IsakmpHeader {
            init_cookie: gateway.cky_i,
            resp_cookie: gateway.cky_r,
            next_payload: payload::NONE,
            version: IsakmpHeader::VERSION_1_0,
            exchange_type,
            flags: 0,
            message_id: 0,
            length: 0,
        };
        let aggressive_2 = crate::ikev1::isakmp::build_message(header(exchange::AGGRESSIVE), &[(payload::HASH, vec![0xAB; 20])]);
        let message_3 = b"our Aggressive Mode message 3".to_vec();
        client.finals.retain(&aggressive_2, &message_3);
        assert_eq!(classify(&client, &aggressive_2, None), Classified::ResendFinal(message_3));
        let transaction = crate::ikev1::isakmp::build_message(header(exchange::TRANSACTION), &[(payload::HASH, vec![0xCD; 20])]);
        assert_eq!(classify(&client, &transaction, None), Classified::Ignored(Ignored::ExchangeType(exchange::TRANSACTION)));
        assert_eq!((client.exchanges.ids_held(), client.exchanges.inbox_held()), (0, 0));
    }

    // ---- classify: Informational ----

    /// Every Delete payload of an authenticated Informational and every SPI of each becomes a raw event, in the
    /// order the message names them, whatever stands between them; then every error Notify, in its order.
    /// Malformed payloads name nothing and the rest is still read. Status Notifies are no event.
    #[test]
    fn an_informational_puts_every_delete_and_error_notify_it_names_in_the_mailbox_in_order() {
        let (client, gateway, clock) = enabled_pair();
        let cookies: Vec<u8> = [gateway.cky_i, gateway.cky_r].concat();
        let d = |spis: &[u32]| as_pair(esp_delete(spis));
        let short = as_pair(delete(vec![0, 0, 0, 1, protocol::ESP]));
        let isakmp_spi = PeerSpi::EMPTY;
        let err = |msg_type: u16, protocol_id: u8, spi: PeerSpi, msgid: u32| PeerEvent::ErrorNotify { msg_type, protocol: protocol_id, spi, msgid, arrived: clock.now() };
        let ev = |spi: u32| esp(spi).event(clock.now());
        let spi4 = |v: u32| PeerSpi::new(&v.to_be_bytes()).unwrap();
        let connected = notify(protocol::ISAKMP, &[], 16384, &[]);
        type Row = (&'static str, u32, Vec<(u8, Vec<u8>)>, Vec<PeerEvent>);
        let rows: Vec<Row> = vec![
            ("many SPIs in one payload", 0x101, vec![d(&[1, 2, 3])], vec![ev(1), ev(2), ev(3)]),
            ("many payloads, a Notify between", 0x103, vec![d(&[1]), connected.clone(), d(&[2, 3])], vec![ev(1), ev(2), ev(3)]),
            ("reversed", 0x105, vec![d(&[3, 2]), d(&[1])], vec![ev(3), ev(2), ev(1)]),
            (
                "mixed with error Notifies",
                0x107,
                vec![notify(protocol::ESP, &0xABu32.to_be_bytes(), 14, &[]), d(&[1]), notify(protocol::ISAKMP, &cookies, 18, &[]), d(&[2])],
                vec![ev(1), ev(2), err(14, protocol::ESP, spi4(0xAB), 0x107), err(18, protocol::ISAKMP, isakmp_spi, 0x107)],
            ),
            ("malformed first payload", 0x109, vec![short, d(&[4])], vec![ev(4)]),
            (
                "the ISAKMP SA",
                0x10B,
                vec![as_pair(isakmp_delete(cookies.clone().try_into().unwrap()))],
                vec![PeerEvent::Delete { protocol: protocol::ISAKMP, spi: PeerSpi::new(&cookies).unwrap(), arrived: clock.now() }],
            ),
            ("an error Notify whose SPI is too long to hold", 0x10D, vec![notify(protocol::ESP, &[1; 17], 14, &[]), d(&[5])], vec![ev(5)]),
            ("a Notify too short for its SPI", 0x10F, vec![(payload::NOTIFY, vec![0, 0, 0, 1, protocol::ESP, 4, 0, 14, 1]), d(&[6])], vec![ev(6)]),
            ("status Notifies only", 0x111, vec![connected, notify(protocol::ESP, &[0; 4], 24576, &[])], vec![]),
        ];
        for (what, msgid, payloads, events) in rows {
            let message = informational(&gateway, msgid, &payloads);
            let Classified::Informational(seen) = classify(&client, &message, None) else { panic!("{what}: not read") };
            assert_eq!((seen.msgid, seen.events_pushed, seen.r_u_there.as_slice(), seen.ack_matched), (msgid, events.len(), &[][..], false), "{what}");
            assert_eq!(client.drain_peer_events(), events, "{what}");
            assert_eq!(client.exchanges.id_record(msgid).map(|r| (r.origin, r.kind, r.state)), Some((Origin::Peer, MidKind::Informational, MidState::Done)), "{what}");
        }
    }

    /// DPD through `classify`: every R-U-THERE is to be answered, the same message twice included (nothing of it
    /// depends on the ledger), at most `ACKS_PER_MESSAGE` distinct sequence numbers of one message; only the
    /// R-U-THERE-ACK the reader waits for matches; a sequence number that is not four octets is no sequence number.
    #[test]
    fn dpd_notifies_are_answered_every_time_and_matched_only_by_their_sequence_number() {
        let (client, gateway, _clock) = enabled_pair();
        let r_u_there = |seq: u32| notify(protocol::ISAKMP, &[], notify_type::R_U_THERE, &seq.to_be_bytes());
        let ack = |seq: u32| notify(protocol::ISAKMP, &[], notify_type::R_U_THERE_ACK, &seq.to_be_bytes());
        let probe_7 = informational(&gateway, 0x201, &[r_u_there(7)]);
        for round in 1..=2 {
            let Classified::Informational(seen) = classify(&client, &probe_7, None) else { panic!("round {round}") };
            assert_eq!(seen.r_u_there, [7], "round {round}: answered again");
        }
        type Row = (&'static str, Vec<(u8, Vec<u8>)>, Option<u32>, Vec<u32>, bool);
        let rows: [Row; 6] = [
            ("six distinct, one twice", [1, 2, 2, 3, 4, 5, 6].map(r_u_there).to_vec(), None, vec![1, 2, 3, 4], false),
            ("the ACK waited for", vec![ack(9)], Some(9), vec![], true),
            ("another ACK", vec![ack(9)], Some(8), vec![], false),
            ("an ACK nobody waits for", vec![ack(9)], None, vec![], false),
            ("a three-octet sequence number", vec![notify(protocol::ISAKMP, &[], notify_type::R_U_THERE, &[0, 0, 7])], None, vec![], false),
            ("a probe and the ACK in one", vec![ack(3), r_u_there(4)], Some(3), vec![4], true),
        ];
        for (n, (what, payloads, expect, answered, matched)) in rows.into_iter().enumerate() {
            let message = informational(&gateway, 0x301 + 2 * n as u32, &payloads);
            let Classified::Informational(seen) = classify(&client, &message, expect) else { panic!("{what}") };
            assert_eq!((seen.r_u_there, seen.ack_matched, seen.events_pushed), (answered, matched, 0), "{what}");
        }
    }

    /// An Informational is read whatever the ledger says: with every id held by an exchange in progress, one
    /// under an unseen id is still read to its end, and is not recorded. One that does not authenticate is not
    /// read at all.
    #[test]
    fn an_informational_is_read_even_when_the_ledger_has_no_room() {
        let (client, gateway, clock) = enabled_pair();
        fill_with_peer_quick_modes(&client, &clock);
        assert_eq!(client.exchanges.would_admit(0x7001, MidKind::Quick, &[0; 32], clock.now()), Admission::Saturated);
        let message = informational(&gateway, 0x7001, &[as_pair(esp_delete(&[0x44])), notify(protocol::ISAKMP, &[], notify_type::R_U_THERE, &3u32.to_be_bytes())]);
        let Classified::Informational(seen) = classify(&client, &message, None) else { panic!("not read") };
        assert_eq!((seen.r_u_there.as_slice(), seen.events_pushed), (&[3][..], 1));
        assert_eq!(client.drain_peer_events(), [esp(0x44).event(clock.now())]);
        assert_eq!(client.exchanges.id_record(0x7001), None, "no room to record it, read all the same");
        let mut wrong_key = gateway.clone();
        wrong_key.skeyid_a = vec![0x99; gateway.skeyid_a.len()];
        assert_eq!(classify(&client, &informational(&wrong_key, 0x7003, &[as_pair(esp_delete(&[0x45]))]), None), Classified::Ignored(Ignored::Unauthenticated));
        assert!(client.drain_peer_events().is_empty());
    }

    /// On a floated tunnel an Informational is read from a marked datagram, and an unmarked one is not IKE.
    #[test]
    fn a_floated_informational_is_read_only_with_its_marker() {
        let (mut client, gateway, clock) = enabled_pair();
        client.floated = true;
        let message = informational(&gateway, 0x401, &[as_pair(esp_delete(&[0x55]))]);
        assert_eq!(classify(&client, &message, None), Classified::Ignored(Ignored::NotIsakmp));
        assert!(client.drain_peer_events().is_empty());
        assert!(matches!(classify(&client, &wrap_ike_4500(&message), None), Classified::Informational(_)));
        assert_eq!(client.drain_peer_events(), [esp(0x55).event(clock.now())]);
    }

    // ---- classify_peer_deletes ----

    /// Each Delete is read against the SPIs held now: current, pending or retired, of either family, in the
    /// order the events came; one that names nothing held is left out, error Notifies are not Deletes, and a
    /// Delete of the ISAKMP SA anywhere among them is the one answer.
    #[test]
    fn deletes_are_classified_against_the_spis_held_when_they_are_read() {
        let at = Instant::now();
        let retired_primary = [0x102, 0x103];
        let retired_v6 = [0x202];
        let spis = SpiState {
            primary: FamilySpis { current_peer_spi: Some(0x100), pending_peer_spi: Some(0x101), retired_peer_spis: &retired_primary },
            ipv6: FamilySpis { current_peer_spi: Some(0x200), pending_peer_spi: None, retired_peer_spis: &retired_v6 },
        };
        let ev = |spi: u32| esp_event(spi, at);
        let notify_event = PeerEvent::ErrorNotify { msg_type: 14, protocol: protocol::ESP, spi: PeerSpi::new(&0x100u32.to_be_bytes()).unwrap(), msgid: 3, arrived: at };
        let isakmp = event(protocol::ISAKMP, &[], at);
        let child = |family, generation, spi| DeleteVerdict::Child { family, generation, spi };
        use ChildFamily::{Ipv6, Primary};
        use Generation::{Current, Pending, Retired};
        let rows: [(&str, Vec<PeerEvent>, Vec<DeleteVerdict>); 8] = [
            (
                "every generation of both families, and strangers",
                vec![ev(0x103), ev(0x999), ev(0x200), notify_event, ev(0x101), ev(0x100), ev(0x202), ev(0x102)],
                vec![child(Primary, Retired, 0x103), child(Ipv6, Current, 0x200), child(Primary, Pending, 0x101), child(Primary, Current, 0x100), child(Ipv6, Retired, 0x202), child(Primary, Retired, 0x102)],
            ),
            ("the ISAKMP SA first", vec![isakmp, ev(0x100)], vec![DeleteVerdict::IsakmpTeardown]),
            ("the ISAKMP SA last", vec![ev(0x100), ev(0x200), isakmp], vec![DeleteVerdict::IsakmpTeardown]),
            ("an ISAKMP SA named by its cookies", vec![ev(0x101), event(protocol::ISAKMP, &[0xC1; 16], at)], vec![DeleteVerdict::IsakmpTeardown]),
            ("nothing held", vec![ev(0x999), ev(0x300)], vec![]),
            ("no events", vec![], vec![]),
            ("an ESP SPI not of four octets", vec![event(protocol::ESP, &[0, 1, 0], at)], vec![]),
            ("an error Notify alone", vec![notify_event], vec![]),
        ];
        for (what, events, verdicts) in rows {
            assert_eq!(classify_peer_deletes(&events, &spis), verdicts, "{what}");
        }
        let nothing_held = SpiState::default();
        assert!(classify_peer_deletes(&[ev(0x100), ev(0x200)], &nothing_held).is_empty());
        let shared = [0x100];
        let both = SpiState { primary: FamilySpis { current_peer_spi: Some(0x100), ..FamilySpis::default() }, ipv6: FamilySpis { retired_peer_spis: &shared, ..FamilySpis::default() } };
        assert_eq!(classify_peer_deletes(&[ev(0x100)], &both), [child(Primary, Current, 0x100)], "the primary family is looked at first");
        let pending_only = SpiState { ipv6: FamilySpis { pending_peer_spi: Some(0x210), ..FamilySpis::default() }, ..SpiState::default() };
        assert_eq!(classify_peer_deletes(&[ev(0x210)], &pending_only), [child(Ipv6, Pending, 0x210)], "a Delete of the pending SA is told apart");
    }

    // ---- the inbox and the new events ----

    /// A passive table keeps no message 1, and the inbox does not keep the same copy twice.
    #[test]
    fn the_inbox_keeps_each_copy_once_and_nothing_while_passive() {
        let at = Instant::now();
        let quick = |msgid: u32, commit_flag: bool| PeerQuick { msgid, datagram: vec![1, 2, 3], fingerprint: [msgid as u8; 32], commit_flag, commit_seen: false, arrived: at };
        let seen = |msgid: u32, commit_flag: bool| PeerQuick { commit_seen: true, ..quick(msgid, commit_flag) };
        let passive = ExchangeTable::passive();
        assert_eq!(passive.queue_peer_quick(quick(1, false)), Queued::Passive);
        assert_eq!(passive.inbox_held(), 0);
        assert!(passive.take_inbox().is_empty());
        let table = ExchangeTable::enabled();
        assert_eq!(table.queue_peer_quick(quick(1, false)), Queued::Added);
        assert_eq!(table.queue_peer_quick(quick(1, false)), Queued::Held);
        assert_eq!(table.queue_peer_quick(quick(1, true)), Queued::CommitNoted, "a flagged copy of a message held clean");
        assert_eq!(table.queue_peer_quick(quick(1, true)), Queued::Held, "noted already");
        assert_eq!(table.queue_peer_quick(quick(2, true)), Queued::Added, "a flagged copy of a message not held");
        assert_eq!(table.queue_peer_quick(quick(2, true)), Queued::Held);
        assert_eq!(table.queue_peer_quick(quick(2, false)), Queued::Added, "its clean copy, which carries the fact");
        assert_eq!(table.take_inbox(), [seen(1, false), seen(2, true), seen(2, false)]);
        assert_eq!(table.queue_peer_quick(quick(1, false)), Queued::Added, "taken, so news again");
        assert_eq!(table.take_inbox(), [quick(1, false)], "and nothing of the Commit bit is left over");
    }

    /// What gives way in a full inbox: a flagged copy first (it has no record, and its clean copy keeps its
    /// fact), never a recorded copy for a flagged one; a recorded copy that gives way has its exchange parked,
    /// unless a flagged copy of it was seen or the inbox still keeps an entry under its id.
    #[test]
    fn a_full_inbox_gives_up_flagged_copies_first_and_parks_only_what_nothing_else_needs() {
        let at = Instant::now();
        let entry = |msgid: u32, print: u8, commit_flag: bool| PeerQuick { msgid, datagram: vec![msgid as u8], fingerprint: [print; 32], commit_flag, commit_seen: false, arrived: at };
        let clean = |msgid: u32| entry(msgid, msgid as u8, false);
        let flagged = |msgid: u32| entry(msgid, msgid as u8, true);
        type Row = (&'static str, Vec<PeerQuick>, PeerQuick, Queued, Vec<(u32, bool, bool)>, Vec<u32>);
        let rows: [Row; 6] = [
            (
                "a flagged copy and its clean copy, then a new message",
                vec![flagged(1), clean(1), clean(2), clean(3)],
                clean(4),
                Queued::Added,
                vec![(1, false, true), (2, false, false), (3, false, false), (4, false, false)],
                vec![],
            ),
            ("full of recorded copies, a flagged copy of a new message", vec![clean(1), clean(2), clean(3), clean(4)], flagged(5), Queued::Full, vec![(1, false, false), (2, false, false), (3, false, false), (4, false, false)], vec![]),
            ("full of recorded copies, a new message", vec![clean(1), clean(2), clean(3), clean(4)], clean(5), Queued::Added, vec![(2, false, false), (3, false, false), (4, false, false), (5, false, false)], vec![1]),
            (
                "the oldest recorded copy had a flagged copy",
                vec![clean(1), flagged(1), clean(2), clean(3), clean(4)],
                clean(5),
                Queued::Added,
                vec![(2, false, false), (3, false, false), (4, false, false), (5, false, false)],
                vec![],
            ),
            ("a flagged copy makes way for another", vec![flagged(1), clean(2), clean(3), clean(4)], flagged(5), Queued::Added, vec![(2, false, false), (3, false, false), (4, false, false), (5, true, true)], vec![]),
            (
                "another message under the id of the oldest",
                vec![clean(1), entry(1, 0xEE, false), clean(2), clean(3)],
                clean(4),
                Queued::Added,
                vec![(1, false, false), (2, false, false), (3, false, false), (4, false, false)],
                vec![],
            ),
        ];
        for (what, before, new, queued, after, parked) in rows {
            let table = ExchangeTable::enabled();
            let mut recorded: Vec<u32> = before.iter().chain([&new]).filter(|q| !q.commit_flag).map(|q| q.msgid).collect();
            recorded.dedup();
            for &msgid in &recorded {
                assert_eq!(table.record_authenticated(msgid, MidKind::Quick, [msgid as u8; 32], at, at + PEER_QUICK_WAIT), Admission::New, "{what}");
            }
            for held in before {
                assert_ne!(table.queue_peer_quick(held), Queued::Full, "{what}: setting up");
            }
            assert_eq!(table.queue_peer_quick(new), queued, "{what}");
            let kept: Vec<(u32, bool, bool)> = table.take_inbox().iter().map(|q| (q.msgid, q.commit_flag, q.commit_seen)).collect();
            assert_eq!(kept, after, "{what}");
            for msgid in recorded {
                let state = table.id_record(msgid).map(|r| r.state);
                let expected = if parked.contains(&msgid) {
                    MidState::Parked { not_before: at + RECONSIDER_GAP, until: at + PEER_QUICK_WAIT }
                } else {
                    MidState::Active { deadline: at + PEER_QUICK_WAIT }
                };
                assert_eq!(state, Some(expected), "{what}: msgid {msgid}");
            }
        }
    }

    /// Two error Notifies are one fact only when type, protocol, SPI and Message ID all agree; a Delete and a
    /// Notify are never one fact. `Debug` shows an ESP SPI and nothing of another.
    #[test]
    fn error_notifies_are_facts_of_their_own() {
        let at = Instant::now();
        let spi = |v: &[u8]| PeerSpi::new(v).unwrap();
        let notify_event = |msg_type, protocol_id, s: &[u8], msgid| PeerEvent::ErrorNotify { msg_type, protocol: protocol_id, spi: spi(s), msgid, arrived: at };
        let table = ExchangeTable::enabled();
        let facts = [
            notify_event(14, protocol::ESP, &[0, 0, 0, 5], 9),
            notify_event(18, protocol::ESP, &[0, 0, 0, 5], 9),
            notify_event(14, protocol::ISAKMP, &[0, 0, 0, 5], 9),
            notify_event(14, protocol::ESP, &[0, 0, 0, 6], 9),
            notify_event(14, protocol::ESP, &[0, 0, 0, 5], 11),
            event(protocol::ESP, &[0, 0, 0, 5], at),
        ];
        for fact in facts {
            assert_eq!(table.push_event(fact), Push::Stored, "{fact:?}");
        }
        assert_eq!(table.push_event(notify_event(14, protocol::ESP, &[0, 0, 0, 5], 9)), Push::Repeat);
        assert_eq!(table.drain_events(), facts);
        let shown = format!("{:?} {:?}", notify_event(14, protocol::ESP, &[0xCA, 0xFE, 0, 1], 0x10), notify_event(18, protocol::ISAKMP, &[0xB7; 16], 0x10));
        assert!(shown.contains("esp:cafe0001") && shown.contains("isakmp:<16 bytes>") && shown.contains("00000010"), "{shown}");
        assert!(!shown.to_lowercase().contains("b7b7"), "{shown}");
        let quick = format!("{:?}", PeerQuick { msgid: 0x10, datagram: vec![0xB7; 40], fingerprint: [0xB7; 32], commit_flag: false, commit_seen: false, arrived: at });
        assert!(quick.contains("<40 bytes>") && !quick.to_lowercase().contains("b7"), "{quick}");
    }

    // ---- Which exchange an error Notify is about ----

    /// An error Notify of type 14 under `msgid`, about `protocol_id`, naming `spi`.
    fn notice(msgid: u32, protocol_id: u8, spi: &[u8]) -> ErrorNotice {
        ErrorNotice { msg_type: 14, protocol: protocol_id, spi: PeerSpi::new(spi).unwrap(), msgid }
    }

    /// Which exchange an error Notify is about: by its Message ID first (our Quick Mode waited on, a
    /// gateway Quick Mode in progress, another exchange of ours nobody waits on), then by the ESP SPI it
    /// names (the one we offered, a registered responder exchange's), then the only exchange in progress
    /// when nothing in the Notify names one -- never under the id of an exchange that is over, of either
    /// side, never when it names an SPI nobody has, never for a copy or a replay -- and otherwise none
    /// (RFC 2408 §3.14, RFC 2409 §5.7). Each row is decided by the rule its name gives; asking changes
    /// nothing in the ledger.
    #[test]
    fn an_error_notify_is_given_to_the_exchange_it_names_and_otherwise_to_the_only_one_in_progress() {
        const OFFERED: u32 = 0x5150_0001;
        const RESPONDER_SPI: u32 = 0x7E57_0001;
        const FRESH: u32 = 0x7000_0000;
        const PEER: u32 = 0x4000_0000;
        const RESPONDER: u32 = 0x4000_0002;
        const PEER_INFORMATIONAL: u32 = 0x6000_0000;
        const PEER_MODE_CONFIG: u32 = 0x6000_0002;
        /// RFC 2407 §4.4.1: PROTO_IPSEC_AH, a protocol no SA of this side is negotiated for.
        const AH: u8 = 2;
        /// Whether the Informational that carried the Notify is a copy or a replay of one read before.
        const FIRST: bool = false;
        const COPY: bool = true;
        /// What the table holds besides the exchanges that are over (of ours: an Informational and a
        /// Quick Mode; of the peer's: an Informational and a Mode-Config exchange).
        #[derive(Clone, Copy, Default)]
        struct Held {
            ours: bool,
            peer: bool,
            /// The gateway Quick Mode `peer` adds is parked.
            parked: bool,
            other_own: bool,
            responder: bool,
        }
        struct World {
            table: ExchangeTable,
            ours: u32,
            other_own: u32,
            informational: u32,
            finished: u32,
        }
        let world = |held: Held| {
            let clock = TestClock::new();
            let table = clock.exchanges();
            table.enable();
            let now = clock.now();
            let mut e = SeedEntropy::new(0xA77);
            let informational = table.fresh_message_id(MidKind::Informational, &mut e).unwrap();
            let finished = table.fresh_message_id(MidKind::Quick, &mut e).unwrap();
            assert!(table.finish(finished, now, MidEnd::Done));
            assert_eq!(table.record_authenticated(PEER_INFORMATIONAL, MidKind::Informational, [4; 32], now, now), Admission::New);
            assert_eq!(table.record_authenticated(PEER_MODE_CONFIG, MidKind::ModeConfig, [5; 32], now, now), Admission::New);
            let ours = if held.ours { table.fresh_message_id(MidKind::Quick, &mut e).unwrap() } else { 0x0101_0101 };
            let other_own = if held.other_own { table.fresh_message_id(MidKind::Quick, &mut e).unwrap() } else { 0x0303_0303 };
            if held.peer {
                assert_eq!(table.record_authenticated(PEER, MidKind::Quick, [1; 32], now, now + PEER_QUICK_WAIT), Admission::New);
            }
            if held.parked {
                assert!(table.park(PEER, now, now + PEER_QUICK_WAIT));
            }
            if held.responder {
                assert_eq!(table.record_authenticated(RESPONDER, MidKind::Quick, [2; 32], now, now + PEER_QUICK_WAIT), Admission::New);
                table.register_responder(RESPONDER, RESPONDER_SPI);
            }
            (World { table, ours, other_own, informational, finished }, clock)
        };
        let ours = Held { ours: true, ..Held::default() };
        let ours_and_peer = Held { peer: true, ..ours };
        let esp = |spi: u32| (protocol::ESP, spi.to_be_bytes().to_vec());
        let isakmp = (protocol::ISAKMP, Vec::new());
        let at_once = Duration::ZERO;
        type Pick = fn(&World) -> u32;
        type Want = fn(&World) -> Attribution;
        let (fresh, our_id): (Pick, Pick) = (|_| FRESH, |w| w.ours);
        let (own, none): (Want, Want) = (|_| Attribution::OwnExchange, |_| Attribution::None);
        // (rule and case, what is held, the Message ID, (Protocol-Id, SPI), whether its message was read
        // before, whether ours is waited on, how far the clock moves first, the answer)
        type Case = (&'static str, Held, Pick, (u8, Vec<u8>), bool, bool, Duration, Want);
        let cases: Vec<Case> = vec![
            ("1: our Message ID, a gateway Quick Mode in progress too", ours_and_peer, our_id, esp(0x0BAD_0001), FIRST, true, at_once, own),
            ("1: our Message ID past the ledger's deadline for it", ours_and_peer, our_id, isakmp.clone(), FIRST, true, Duration::from_secs(21), own),
            ("1: a gateway Quick Mode's Message ID", ours_and_peer, |_| PEER, isakmp.clone(), FIRST, true, at_once, |_| Attribution::Responder(PEER)),
            ("1: another Quick Mode of ours in progress, though the SPI is ours", Held { other_own: true, ..ours }, |w| w.other_own, esp(OFFERED), FIRST, true, at_once, none),
            ("1 holds for a copy: our Message ID", ours, our_id, isakmp.clone(), COPY, true, at_once, own),
            ("1 holds for a copy: a gateway Quick Mode's Message ID", ours_and_peer, |_| PEER, isakmp.clone(), COPY, true, at_once, |_| Attribution::Responder(PEER)),
            ("2: the SPI we offered", ours_and_peer, fresh, esp(OFFERED), FIRST, true, at_once, own),
            ("2: a registered responder exchange's inbound SPI", Held { responder: true, ..ours }, fresh, esp(RESPONDER_SPI), FIRST, true, at_once, |_| Attribution::Responder(RESPONDER)),
            ("2: the SPI we offered, under one of our Informational ids", ours_and_peer, |w| w.informational, esp(OFFERED), FIRST, true, at_once, own),
            ("2 holds for a copy: the SPI we offered", ours, fresh, esp(OFFERED), COPY, true, at_once, own),
            ("2 is for ESP only", ours_and_peer, fresh, (protocol::ISAKMP, OFFERED.to_be_bytes().to_vec()), FIRST, true, at_once, none),
            ("2 reads a 4-octet SPI only", ours_and_peer, fresh, (protocol::ESP, [OFFERED.to_be_bytes(), [0; 4]].concat()), FIRST, true, at_once, none),
            ("3: the only exchange in progress", ours, fresh, isakmp.clone(), FIRST, true, at_once, own),
            ("3: the only one, an ESP Notify that names no SPI", ours, fresh, (protocol::ESP, Vec::new()), FIRST, true, at_once, own),
            ("3: the only one, the SPI of an ISAKMP Notify is ignored", ours, fresh, (protocol::ISAKMP, vec![0xC0; 16]), FIRST, true, at_once, own),
            ("3: under the id the gateway's Informational took", ours, |_| PEER_INFORMATIONAL, isakmp.clone(), FIRST, true, at_once, own),
            ("3: a gateway Quick Mode, nobody waiting", Held { peer: true, ..Held::default() }, fresh, isakmp.clone(), FIRST, false, at_once, |_| Attribution::Responder(PEER)),
            ("3: one of ours that nobody waits on", ours, fresh, isakmp.clone(), FIRST, false, at_once, none),
            ("3: a gateway Quick Mode past its deadline is not in progress", ours_and_peer, fresh, isakmp.clone(), FIRST, true, Duration::from_secs(9), own),
            ("3 never when it names an ESP SPI of nobody's", ours, fresh, esp(0x0DEA_D001), FIRST, true, at_once, none),
            ("3 never when it names an SPI of another length under ESP", ours, fresh, (protocol::ESP, [OFFERED.to_be_bytes(), [0; 4]].concat()), FIRST, true, at_once, none),
            ("3 never when it names an SPI of another protocol", ours, fresh, (AH, OFFERED.to_be_bytes().to_vec()), FIRST, true, at_once, none),
            ("3 never under one of our Informational ids", ours, |w| w.informational, isakmp.clone(), FIRST, true, at_once, none),
            ("3 never under the id of a Quick Mode of ours that is over", ours, |w| w.finished, isakmp.clone(), FIRST, true, at_once, none),
            ("3 never under the id of a gateway Quick Mode past its deadline", ours_and_peer, |_| PEER, isakmp.clone(), FIRST, true, Duration::from_secs(9), none),
            ("3 never under the id of a parked gateway Quick Mode", Held { parked: true, ..ours_and_peer }, |_| PEER, isakmp.clone(), FIRST, true, at_once, none),
            ("3 never under the id of a gateway Mode-Config exchange", ours, |_| PEER_MODE_CONFIG, isakmp.clone(), FIRST, true, at_once, none),
            ("3 never for a copy", ours, fresh, isakmp.clone(), COPY, true, at_once, none),
            ("3 never for a copy under the id the gateway's Informational took", ours, |_| PEER_INFORMATIONAL, isakmp.clone(), COPY, true, at_once, none),
            ("3 never for a copy, nobody waiting", Held { peer: true, ..Held::default() }, fresh, isakmp.clone(), COPY, false, at_once, none),
            ("4: two exchanges in progress", ours_and_peer, fresh, isakmp.clone(), FIRST, true, at_once, none),
            ("4: two of ours in progress", Held { other_own: true, ..ours }, fresh, isakmp.clone(), FIRST, true, at_once, none),
            ("4: nothing in progress, nothing waited on", Held::default(), fresh, isakmp.clone(), FIRST, false, at_once, none),
        ];
        let mut wrong = Vec::new();
        for (name, held, pick, (protocol_id, spi), read_before, waits, advance, want) in cases {
            let (w, clock) = world(held);
            clock.advance(advance);
            let awaited = waits.then_some(AwaitedQuick { msgid: w.ours, offered_spi: OFFERED });
            let held_before = w.table.ids_held();
            let got = w.table.attribute_error_notify(&notice(pick(&w), protocol_id, &spi), read_before, awaited);
            if got != want(&w) {
                wrong.push(format!("{name}: {got:?}, wanted {:?}", want(&w)));
            }
            assert_eq!(w.table.ids_held(), held_before, "{name}: asking records nothing");
        }
        assert!(wrong.is_empty(), "error Notifies attributed wrongly:\n{}", wrong.join("\n"));
        let passive = ExchangeTable::passive();
        let mine = AwaitedQuick { msgid: 0x11, offered_spi: OFFERED };
        assert_eq!(passive.attribute_error_notify(&notice(0x11, protocol::ESP, &OFFERED.to_be_bytes()), FIRST, Some(mine)), Attribution::None, "passive: never asked");
    }

    /// A responder exchange is known by its Message ID and its inbound SPI; registered again under its id it
    /// replaces its entry, and beyond four the oldest gives way. The first refusal recorded on it is the one
    /// kept; nothing is recorded for an id not registered, and a passive table registers nothing.
    #[test]
    fn responder_exchanges_are_known_by_id_and_spi_and_keep_the_first_refusal() {
        let table = ExchangeTable::enabled();
        let naming = |spi: u32| notice(0x7000_0000, protocol::ESP, &spi.to_be_bytes());
        for n in 0..5u32 {
            table.register_responder(0x100 + 2 * n, 0xA000 + n);
        }
        assert_eq!(table.attribute_error_notify(&naming(0xA000), false, None), Attribution::None, "the oldest gave way");
        assert_eq!(table.attribute_error_notify(&naming(0xA004), false, None), Attribution::Responder(0x108));
        table.register_responder(0x108, 0xB000);
        assert_eq!(table.attribute_error_notify(&naming(0xA004), false, None), Attribution::None, "registered again under another SPI");
        assert_eq!(table.attribute_error_notify(&naming(0xB000), false, None), Attribution::Responder(0x108));
        assert!(table.note_responder_rejected(0x108, 14));
        assert!(table.note_responder_rejected(0x108, 18));
        assert_eq!(table.responder_rejected(0x108), Some(14), "the first refusal stays");
        assert_eq!(table.responder_rejected(0x102), None);
        assert!(!table.note_responder_rejected(0x100, 14), "the oldest is gone");
        let passive = ExchangeTable::passive();
        passive.register_responder(0x108, 0xB000);
        assert!(!passive.note_responder_rejected(0x108, 14));
        assert_eq!(passive.responder_rejected(0x108), None);
        assert_eq!(passive.attribute_error_notify(&naming(0xB000), false, None), Attribution::None);
    }

    /// The messages under our waited-on id that fail HASH(2) are counted by an enabled table only, by every
    /// clone together.
    #[test]
    fn replies_that_fail_hash_2_are_counted_only_by_an_enabled_table() {
        let table = ExchangeTable::passive();
        assert_eq!(table.count_unauthenticated_reply(), 0);
        assert_eq!(table.unauthenticated_replies(), 0);
        table.enable();
        assert_eq!((table.count_unauthenticated_reply(), table.clone().count_unauthenticated_reply()), (1, 2));
        assert_eq!(table.unauthenticated_replies(), 2);
    }

    /// What an Informational said comes back as read, whatever the mailbox held already: its error Notifies
    /// in their order (the ISAKMP one with the empty SPI), and whether any of its Delete payloads named the
    /// ISAKMP SA.
    #[test]
    fn an_informational_tells_its_error_notifies_and_an_isakmp_delete_as_read_every_time() {
        let (client, gateway, _clock) = enabled_pair();
        let mut cookies = [0u8; 16];
        cookies[..8].copy_from_slice(&gateway.cky_i);
        cookies[8..].copy_from_slice(&gateway.cky_r);
        let message = informational(
            &gateway,
            0x3001,
            &[
                notify(protocol::ESP, &[0, 0, 0x0E, 0x01], 14, &[]),
                as_pair(esp_delete(&[0x0E01])),
                as_pair(isakmp_delete(cookies)),
                notify(protocol::ISAKMP, &[0xAB; 16], 18, &[]),
            ],
        );
        let read = [
            ErrorNotice { msg_type: 14, protocol: protocol::ESP, spi: PeerSpi::new(&[0, 0, 0x0E, 0x01]).unwrap(), msgid: 0x3001 },
            ErrorNotice { msg_type: 18, protocol: protocol::ISAKMP, spi: PeerSpi::EMPTY, msgid: 0x3001 },
        ];
        for (round, pushed, read_before) in [(1, 4, false), (2, 0, true)] {
            let Classified::Informational(seen) = classify(&client, &message, None) else { panic!("round {round}: not read") };
            assert_eq!((seen.error_notifies, seen.isakmp_deleted, seen.events_pushed), (read.to_vec(), true, pushed), "round {round}");
            assert_eq!(seen.read_before, read_before, "round {round}");
        }
        let esp_only = informational(&gateway, 0x3003, &[as_pair(esp_delete(&[0x0E02])), as_pair(esp_delete(&[0x0E03]))]);
        let Classified::Informational(seen) = classify(&client, &esp_only, None) else { panic!("not read") };
        assert!(!seen.isakmp_deleted && seen.error_notifies.is_empty(), "{seen:?}");
    }

    /// An Informational is read before when the ledger held its Message ID already as an exchange of the
    /// peer's that is over: a copy of one read before, another message under its id (a replay), or one
    /// under the id of a gateway Quick Mode that is over. Never for a first read, under the id of a gateway
    /// Quick Mode in progress or of one of ours (rule 1 and the Message ID decide those), nor for what the
    /// ledger does not record: Message ID 0, or a message with a payload an Informational does not carry.
    #[test]
    fn an_informational_is_read_before_when_the_ledger_held_its_id_as_a_peer_exchange_that_is_over() {
        #[derive(Clone, Copy)]
        enum Held {
            Nothing,
            GatewayQuickOver,
            GatewayQuickInProgress,
            OurInformational,
        }
        let refusal = |msg_type: u16| notify(protocol::ISAKMP, &[], msg_type, &[]);
        let nonce = (payload::NONCE, vec![0x5E; 16]);
        // (case, what the ledger holds under the id first, the payloads of each message in turn, whether
        // each was read before)
        type Case = (&'static str, Held, Vec<Vec<(u8, Vec<u8>)>>, Vec<bool>);
        let cases: Vec<Case> = vec![
            ("a first read, then a copy of it", Held::Nothing, vec![vec![refusal(14)], vec![refusal(14)]], vec![false, true]),
            ("another message under the id of one read before", Held::Nothing, vec![vec![refusal(14)], vec![refusal(18)]], vec![false, true]),
            ("under the id of a gateway Quick Mode that is over", Held::GatewayQuickOver, vec![vec![refusal(14)]], vec![true]),
            ("under the id of a gateway Quick Mode in progress", Held::GatewayQuickInProgress, vec![vec![refusal(14)], vec![refusal(14)]], vec![false, false]),
            ("under one of our Informational ids", Held::OurInformational, vec![vec![refusal(14)], vec![refusal(14)]], vec![false, false]),
            ("a payload no Informational carries: not recorded", Held::Nothing, vec![vec![refusal(14), nonce.clone()], vec![refusal(14), nonce.clone()]], vec![false, false]),
        ];
        for (name, held, messages, want) in cases {
            let (client, gateway, clock) = enabled_pair();
            let now = clock.now();
            let msgid = match held {
                Held::Nothing => 0x3101,
                Held::GatewayQuickOver | Held::GatewayQuickInProgress => {
                    assert_eq!(client.exchanges.record_authenticated(0x3103, MidKind::Quick, [3; 32], now, now + PEER_QUICK_WAIT), Admission::New);
                    if matches!(held, Held::GatewayQuickOver) {
                        assert!(client.exchanges.finish(0x3103, now, MidEnd::Done));
                    }
                    0x3103
                }
                Held::OurInformational => client.fresh_message_id(MidKind::Informational, &mut SeedEntropy::new(0x3105)).unwrap(),
            };
            let got: Vec<bool> = messages
                .iter()
                .map(|payloads| match classify(&client, &informational(&gateway, msgid, payloads), None) {
                    Classified::Informational(seen) => seen.read_before,
                    other => panic!("{name}: not read as an Informational: {other:?}"),
                })
                .collect();
            assert_eq!(got, want, "{name}");
        }
        // Message ID 0 is never recorded, so a copy under it is not told from a first read.
        let (client, gateway, _clock) = enabled_pair();
        let under_zero = informational(&gateway, 0, &[refusal(14)]);
        for round in 1..=2 {
            let Classified::Informational(seen) = classify(&client, &under_zero, None) else { panic!("round {round}: not read") };
            assert!(!seen.read_before, "round {round}");
        }
    }
}
