//! The responder after its answer, as the readers of an enabled exchange table and its caller drive it: a gateway
//! Quick Mode held, released, proven, abandoned, cancelled, parked, deferred; copies of its message 1 and its message
//! 3 read by a serving turn; the resends of message 2. The gateway is the real gateway-side code
//! ([`QuickInitiator`] on the gateway's [`Phase1State`]); no socket, no thread, no sleep: a scripted socket and the
//! table's [`TestClock`].

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use super::cache::{
    DeferReason, EndReason, IllegalTransition, Outcome, PendingResponder, Proof, ResponderEvents, ResponderId, ResponderState, Transition, ANSWERED_FOR, ANSWER_SPACING,
    DEFER_MAX, PARKED_FOR, PEER_QM_HOLD_MAX, RESP_RETAIN,
};
use super::tests::{accepted, gateways_v6, kept, msgid_of, on_the_wire, ours_v6, pair, plain, refused, v6, Counting, Qm1, Tunnel, GATEWAYS_V4, GCM, OURS_V4};
use super::*;
use crate::entropy::SeedEntropy;
use crate::ikev1::exchange::{self as table, Attribution, Classified, ErrorNotice, ExchangeTable, Ignored, Message3, PeerSpi, ResponderDrop, REFUSAL_RESEND_SPACING};
use crate::ikev1::informational::{self, TurnReport};
use crate::ikev1::msgid::{AtDeadline, MidKind, MidState, ACCEPT_SPACING, MID_CAP, NI_KEPT, RECONSIDER_GAP};
use crate::ikev1::phase1::TestClock;
use crate::ikev1::quick::QuickInitiator;
use crate::ikev1::rtt::RoundTrips;
use crate::ikev2::natt::unwrap_ike_4500;

use ChildFamily::{Ipv6, Primary};
use ResponderState::{Answered, Held, Parked};

const GATEWAY: &str = "192.0.2.1:500";

fn gateway() -> SocketAddr {
    GATEWAY.parse().unwrap()
}

/// An `IkeSocket` that hands out the datagrams it was given, then times out, and keeps what was sent to it -- or
/// refuses every send.
#[derive(Default)]
struct Wire {
    incoming: RefCell<VecDeque<Vec<u8>>>,
    sent: RefCell<Vec<(Vec<u8>, SocketAddr)>>,
    refuses: Cell<bool>,
}

impl Wire {
    fn carrying(datagrams: &[Vec<u8>]) -> Self {
        Self { incoming: RefCell::new(datagrams.iter().cloned().collect()), ..Self::default() }
    }

    fn refusing() -> Self {
        Self { refuses: Cell::new(true), ..Self::default() }
    }

    /// What was sent, as ISAKMP messages: on a floated tunnel each must carry the non-ESP marker and go to port
    /// 4500, and the marker is taken off.
    fn messages(&self, floated: bool) -> Vec<Vec<u8>> {
        self.sent
            .borrow()
            .iter()
            .map(|(datagram, dest)| {
                if floated {
                    assert_eq!(dest.port(), crate::natt_port(), "a floated tunnel sends on 4500");
                    unwrap_ike_4500(datagram).expect("the non-ESP marker").to_vec()
                } else {
                    datagram.clone()
                }
            })
            .collect()
    }
}

impl IkeSocket for Wire {
    fn send_to(&self, buf: &[u8], dest: SocketAddr) -> io::Result<usize> {
        if self.refuses.get() {
            return Err(io::ErrorKind::ConnectionRefused.into());
        }
        self.sent.borrow_mut().push((buf.to_vec(), dest));
        Ok(buf.len())
    }
    fn set_read_timeout(&self, _dur: Option<Duration>) -> io::Result<()> {
        Ok(())
    }
    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let Some(datagram) = self.incoming.borrow_mut().pop_front() else { return Err(io::ErrorKind::WouldBlock.into()) };
        buf[..datagram.len()].copy_from_slice(&datagram);
        Ok((datagram.len(), gateway()))
    }
}

/// An `IkeSocket` whose every send first runs `before` -- the clock moving on, a reader at work meanwhile -- and then
/// goes, kept in `sent`, or fails.
struct Stalled<'a> {
    before: Box<dyn Fn() + 'a>,
    fails: bool,
    sent: RefCell<Vec<Vec<u8>>>,
}

impl<'a> Stalled<'a> {
    fn new(fails: bool, before: impl Fn() + 'a) -> Self {
        Self { before: Box::new(before), fails, sent: RefCell::default() }
    }
}

impl IkeSocket for Stalled<'_> {
    fn send_to(&self, buf: &[u8], _dest: SocketAddr) -> io::Result<usize> {
        (self.before)();
        if self.fails {
            return Err(io::ErrorKind::ConnectionRefused.into());
        }
        self.sent.borrow_mut().push(buf.to_vec());
        Ok(buf.len())
    }
    fn set_read_timeout(&self, _dur: Option<Duration>) -> io::Result<()> {
        Ok(())
    }
    fn recv_from(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        Err(io::ErrorKind::WouldBlock.into())
    }
}

/// Entropy that no reader may draw from: what reads a copy of a message 1 or a message 3 derives nothing anew.
struct NoDraws;

impl Entropy for NoDraws {
    fn fill(&mut self, _out: &mut [u8]) {
        panic!("a reader drew from the entropy: something was derived anew");
    }
}

/// A client with its exchange table on, configured for both families (both answerable), its gateway, and the clock.
struct World {
    client: Phase1State,
    gw: Phase1State,
    clock: TestClock,
    tunnel: Tunnel,
    seed: Cell<u64>,
}

impl World {
    fn new(floated: bool) -> Self {
        let (client, gw, clock) = pair(floated);
        Self { client, gw, clock, tunnel: Tunnel::of(vec![plain(), v6(GCM, None)]), seed: Cell::new(0xC5B0) }
    }

    fn advance(&self, by: Duration) {
        self.clock.advance(by);
    }

    /// The gateway's rekey of the family's SA, built by the gateway-side initiator (AES-GCM, no PFS, 3600 s).
    fn rekey(&self, family: ChildFamily, seed: u64) -> (Vec<u8>, QuickInitiator) {
        let mut e = SeedEntropy::new(seed);
        match family {
            Primary => quick::initiate_quick_with_pfs(&self.gw, &mut e, GCM, GATEWAYS_V4, OURS_V4, None, 3600),
            Ipv6 => quick::initiate_quick_ipv6(&self.gw, &mut e, GCM, gateways_v6(), ours_v6(), None, 3600),
        }
        .unwrap()
    }

    /// The gateway-side initiator of `qm1` as the gateway sent it (no PFS): a fresh one for each message 2 tried.
    fn initiator(&self, qm1: &[u8]) -> QuickInitiator {
        QuickInitiator::of_message_1(&self.gw, qm1, GCM, None)
    }

    fn read(&self, message: &[u8]) -> Classified {
        table::classify(&self.client, &on_the_wire(&self.client, message), None)
    }

    fn answer(&self, quick: &PeerQuick) -> QuickVerdict {
        let seed = self.seed.get();
        self.seed.set(seed + 1);
        answer_quick(&self.client, &mut SeedEntropy::new(seed), &self.tunnel.expect(self.clock.now()), quick)
    }

    /// `message` read as the readers read it, its entry taken from the inbox (the only one), and answered.
    fn offer(&self, message: &[u8]) -> QuickVerdict {
        let msgid = msgid_of(message);
        assert_eq!(self.read(message), Classified::PeerQuick { msgid }, "the readers keep it");
        let [quick] = <[PeerQuick; 1]>::try_from(self.client.take_peer_quick_modes()).expect("one entry");
        self.answer(&quick)
    }

    fn hold(&self, message: &[u8]) -> Box<HeldQuick> {
        accepted(self.offer(message))
    }

    fn release(&self, held: Box<HeldQuick>) -> (AnsweredQuick, Vec<u8>) {
        let wire = Wire::default();
        let answered = (*held).release(&wire, &self.client, gateway(), self.clock.now()).expect("released");
        let [sent] = <[Vec<u8>; 1]>::try_from(wire.messages(self.client.floated)).expect("one message 2");
        (answered, sent)
    }

    /// One serving turn over `messages` (as datagrams of this tunnel): what it reported and sent. Nothing a turn reads
    /// here may draw from the entropy.
    fn serve(&self, messages: &[&[u8]]) -> (TurnReport, Vec<Vec<u8>>) {
        let wire = Wire::carrying(&messages.iter().map(|m| on_the_wire(&self.client, m)).collect::<Vec<_>>());
        let report = informational::serve_turn(&wire, &self.client, &mut NoDraws, gateway(), 8, Duration::from_millis(20)).unwrap();
        (report, wire.messages(self.client.floated))
    }

    /// The ledger's state of `msgid` now (swept first: a record reads as the last call told the time left it).
    fn state(&self, msgid: u32) -> Option<MidState> {
        self.client.exchanges.sweep(self.clock.now());
        self.client.exchanges.id_record(msgid).map(|record| record.state)
    }
}

/// `message` with one more cipher block of `fill` after its last: the same authenticated content (the payload chain
/// ends before it), another last cipher block.
fn appended(message: &[u8], fill: u8) -> Vec<u8> {
    let mut longer = message.to_vec();
    longer.extend_from_slice(&[fill; 16]);
    let length = longer.len() as u32;
    longer[24..28].copy_from_slice(&length.to_be_bytes());
    longer
}

/// The payload chain of `qm2` decrypted under `iv`.
fn decrypted(st: &Phase1State, qm2: &[u8], iv: &[u8]) -> Vec<Payload> {
    phase2::decrypt_payloads(qm2, &st.enc_key, st.enc_block, iv).unwrap().1
}

/// The last cipher block of `message`.
fn last_block(message: &[u8]) -> Vec<u8> {
    crypto1::next_iv(&message[IsakmpHeader::LEN..], crypto1::AES_BLOCK)
}

/// A message 3 of the gateway's under `msgid` with the HASH `hash`, encrypted under `iv`, the header flags `flags`
/// besides ENCRYPTION.
fn message_3(gw: &Phase1State, msgid: u32, hash: Vec<u8>, iv: &[u8], flags: u8) -> Vec<u8> {
    let mut header = quick::qm_header(gw.cky_i, gw.cky_r, msgid);
    header.flags = flags;
    phase2::encrypt_payloads(header, &gw.enc_key, gw.enc_block, iv, &[(payload::HASH, hash)]).unwrap().0
}

/// An authenticated Informational of the gateway's under `msgid` carrying `payloads` (RFC 2409 §5.7).
fn gateway_informational(gw: &Phase1State, msgid: u32, payloads: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let header = IsakmpHeader {
        init_cookie: gw.cky_i,
        resp_cookie: gw.cky_r,
        next_payload: payload::NONE,
        version: IsakmpHeader::VERSION_1_0,
        exchange_type: exchange::INFORMATIONAL,
        flags: 0,
        message_id: msgid,
        length: 0,
    };
    let iv0 = crypto1::phase2_iv(gw.prf, &gw.phase1_iv, msgid, gw.enc_block);
    phase2::build_encrypted(header, gw.prf, &gw.skeyid_a, &gw.enc_key, gw.enc_block, &iv0, payloads).unwrap().0
}

fn no_events(msgid: u32) -> ResponderEvents {
    ResponderEvents { msgid, ..ResponderEvents::default() }
}

// ---- Held, released, proven ----

/// Held, released, proven by its message 3, on a plain and on a floated tunnel: the exchange is held -- in progress in
/// the ledger until the hold bound, parked at it --, message 2 leaves exactly as held, answered -- in progress until
/// [`ANSWERED_FOR`] --, the gateway's initiator takes it, and its message 3, read by a serving turn, is recorded once
/// for the caller without a change of state; a copy of it is nothing new; the caller proves the exchange, and a
/// message 3 read after that is ignored.
#[test]
fn a_held_answer_released_and_its_message_3_read_are_recorded_for_the_caller_to_prove() {
    for floated in [false, true] {
        let w = World::new(floated);
        let (qm1, qi) = w.rekey(Primary, 0xB100);
        let held = w.hold(&qm1);
        let (id, msgid, qm2, inbound_spi) = (held.id(), held.msgid(), held.qm2().to_vec(), held.local_spi());
        let t_hold = w.clock.now();
        assert_eq!(w.client.responder_pending(Primary), Some(PendingResponder { id, msgid, state: Held, inbound_spi }), "floated {floated}");
        let record = w.client.exchanges.id_record(msgid).unwrap();
        assert_eq!(
            (record.state, record.at_deadline),
            (MidState::Active { deadline: t_hold + PEER_QM_HOLD_MAX }, AtDeadline::Park { until: t_hold + PEER_QM_HOLD_MAX + PARKED_FOR })
        );
        let (report, sent) = w.serve(&[&qm1]);
        assert_eq!((report.datagrams_read, sent.len()), (1, 0), "floated {floated}: a copy while held gets nothing");
        assert_eq!(w.read(&qm1), Classified::Ignored(Ignored::Responder(ResponderDrop::CopyWhileHeld)));
        w.advance(Duration::from_millis(90));
        let (_answered, sent) = w.release(held);
        assert_eq!(sent, qm2, "floated {floated}: message 2 exactly as held");
        let t_answer = w.clock.now();
        assert_eq!(w.client.responder_state(msgid), Some(Answered));
        let record = w.client.exchanges.id_record(msgid).unwrap();
        assert_eq!((record.state, record.at_deadline), (MidState::Active { deadline: t_answer + ANSWERED_FOR }, AtDeadline::Done));
        let (qm3, ..) = qi.complete_with_lifetime(&sent).expect("the gateway takes message 2");
        let (report, sent) = w.serve(&[&qm3]);
        assert_eq!((report.datagrams_read, report.answered_again, sent.len()), (1, 0, 0), "floated {floated}");
        assert_eq!(w.client.take_responder_events(Primary), Some(ResponderEvents { qm3_seen: true, ..no_events(msgid) }));
        assert_eq!(w.client.responder_state(msgid), Some(Answered), "a fact, not a change of state");
        assert_eq!(w.read(&qm3), Classified::Message3 { msgid, read: Message3::Again });
        assert_eq!(w.client.take_responder_events(Primary), Some(no_events(msgid)), "nothing new");
        assert_eq!(w.client.conclude_responder(id, Outcome::Proven(Proof::Qm3)), Ok(ResponderState::Proven(Proof::Qm3)));
        assert_eq!(w.state(msgid), Some(MidState::Done));
        assert_eq!(w.client.responder_pending(Primary), None);
        assert_eq!(w.client.take_responder_events(Primary), None);
        assert_eq!(w.read(&qm3), Classified::Message3 { msgid, read: Message3::AfterProof });
        assert_eq!(w.client.exchanges.responder_counters().qm3, 3);
    }
}

/// Message 2 lost: the gateway sends its message 1 again, bit for bit, and gets the message 2 held, byte for byte --
/// the same SPI, nonce and keys, nothing drawn -- at most once per 200 ms, whatever sent message 2 last; the
/// gateway's initiator takes it.
#[test]
fn a_copy_of_message_1_after_message_2_was_lost_gets_the_message_2_held_byte_for_byte() {
    for floated in [false, true] {
        let w = World::new(floated);
        let (qm1, qi) = w.rekey(Primary, 0xB200);
        let held = w.hold(&qm1);
        let (msgid, qm2) = (held.msgid(), held.qm2().to_vec());
        let (_answered, _lost) = w.release(held);
        w.advance(ANSWER_SPACING - Duration::from_millis(1));
        let (report, sent) = w.serve(&[&qm1]);
        assert_eq!((report.answered_again, sent.len()), (0, 0), "floated {floated}: within 200 ms of the release");
        w.advance(Duration::from_millis(1));
        let (report, sent) = w.serve(&[&qm1, &qm1]);
        assert_eq!((report.datagrams_read, report.answered_again), (2, 1), "floated {floated}: one answer for two copies");
        assert_eq!(sent, [qm2.as_slice()], "floated {floated}: the message 2 held, byte for byte");
        w.advance(ANSWER_SPACING);
        assert_eq!(w.serve(&[&qm1]).1, [qm2.as_slice()], "floated {floated}: and again 200 ms later");
        w.advance(ANSWER_SPACING);
        // The liveness checks are readers too.
        let wire = Wire::carrying(&[on_the_wire(&w.client, &qm1)]);
        let liveness = informational::peek(&wire, &w.client, &mut NoDraws, gateway(), Duration::from_millis(5), 0x1111_0001, None).unwrap();
        assert_eq!(liveness, informational::Liveness::Alive);
        assert_eq!(wire.messages(floated), [qm2.as_slice()], "floated {floated}: peek answers it too");
        let counters = w.client.exchanges.responder_counters();
        assert_eq!((counters.answered_again, counters.copies_unanswered), (3, 2));
        qi.complete_with_lifetime(&qm2).expect("the gateway takes it");
        assert_eq!(w.client.responder_state(msgid), Some(Answered));
    }
}

/// A copy of message 1 under another last cipher block (the same content: a block appended on the path, read first):
/// message 2 answers it under that copy's block, which the gateway cannot read; the gateway's own copy, read next,
/// gets the same plaintext encrypted under its own last block -- the same SPI, nonce and identities --, the gateway's
/// initiator takes that, and its message 3, encrypted under the second encryption's last block, is recorded. A copy
/// under a third last block is not answered; the gateway's copy again gets the second encryption byte for byte.
#[test]
fn a_copy_under_another_last_block_is_answered_under_its_own_and_message_3_is_checked_against_both() {
    let w = World::new(false);
    let (genuine, _) = w.rekey(Primary, 0xB300);
    let raced = appended(&genuine, 0xA5);
    let held = w.hold(&raced);
    let msgid = held.msgid();
    assert_eq!(held.qm1_last_block(), last_block(&raced).as_slice());
    let (_answered, first) = w.release(held);
    assert!(w.initiator(&genuine).complete_with_lifetime(&first).is_err(), "encrypted under the raced copy's block");
    w.advance(ANSWER_SPACING);
    let (_, sent) = w.serve(&[&genuine]);
    let [second] = <[Vec<u8>; 1]>::try_from(sent).expect("answered");
    assert_ne!(second, first);
    assert_eq!(decrypted(&w.gw, &second, &last_block(&genuine)), decrypted(&w.gw, &first, &last_block(&raced)), "the same message 2 under another IV");
    let (qm3, ..) = w.initiator(&genuine).complete_with_lifetime(&second).expect("the gateway takes the second encryption");
    assert_eq!(w.read(&qm3), Classified::Message3 { msgid, read: Message3::First }, "checked against the second encryption");
    w.advance(ANSWER_SPACING);
    assert_eq!(w.read(&appended(&genuine, 0x5A)), Classified::Ignored(Ignored::Responder(ResponderDrop::CopyNoRoom)), "a third last block");
    w.advance(ANSWER_SPACING);
    assert_eq!(w.serve(&[&genuine]).1, [second.as_slice()]);
    assert_eq!(w.serve(&[&raced]).1, Vec::<Vec<u8>>::new(), "within 200 ms");
    w.advance(ANSWER_SPACING);
    assert_eq!(w.serve(&[&raced]).1, [first], "the raced copy's encryption, kept too");
}

// ---- Message 3 ----

/// Every datagram under the id of a responder exchange that is no copy of its message 1: its message 3 is recorded
/// only when it authenticates (HASH(3) under the last block of a message 2 sent) and only as a fact -- with the
/// Commit bit as that fact alone, never as a message 3 --; anything else is dropped and counted, and none changes the
/// state; while message 2 is held nothing is its message 3, not even the one that would be once it left; after an
/// abandon a late message 3 activates nothing. Nothing is ever sent.
#[test]
fn a_message_3_is_recorded_only_when_it_authenticates_and_never_changes_the_state() {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum At {
        Held,
        Answered,
        Proven,
    }
    type Make = fn(&World, &HeldView) -> Vec<u8>;
    struct HeldView {
        msgid: u32,
        ni: Vec<u8>,
        nr: Vec<u8>,
        qm2_last_block: Vec<u8>,
    }
    fn hash3(w: &World, h: &HeldView) -> Vec<u8> {
        quick::hash3(w.gw.prf, &w.gw.skeyid_a, h.msgid, &h.ni, &h.nr)
    }
    type Want = (Classified, ResponderEvents, ResponderState);
    type Row = (&'static str, At, Make, fn(u32) -> Want);
    let rows: Vec<Row> = vec![
        ("its message 3, answered", At::Answered, |w, h| message_3(&w.gw, h.msgid, hash3(w, h), &h.qm2_last_block, 0), |id| {
            (Classified::Message3 { msgid: id, read: Message3::First }, ResponderEvents { qm3_seen: true, ..no_events(id) }, Answered)
        }),
        ("its message 3 with the Commit bit", At::Answered, |w, h| message_3(&w.gw, h.msgid, hash3(w, h), &h.qm2_last_block, flags::COMMIT), |id| {
            (Classified::Message3 { msgid: id, read: Message3::WithCommit }, ResponderEvents { commit_seen: true, ..no_events(id) }, Answered)
        }),
        ("a HASH(3) over another nonce", At::Answered, |w, h| {
            let other = quick::hash3(w.gw.prf, &w.gw.skeyid_a, h.msgid, &h.ni, &[0x42; 16]);
            message_3(&w.gw, h.msgid, other, &h.qm2_last_block, 0)
        }, |id| (Classified::Ignored(Ignored::Responder(ResponderDrop::NotMessage3)), no_events(id), Answered)),
        ("its HASH(3) under the IV of a first message", At::Answered, |w, h| {
            let iv0 = crypto1::phase2_iv(w.gw.prf, &w.gw.phase1_iv, h.msgid, w.gw.enc_block);
            message_3(&w.gw, h.msgid, hash3(w, h), &iv0, 0)
        }, |id| (Classified::Ignored(Ignored::Responder(ResponderDrop::NotMessage3)), no_events(id), Answered)),
        ("its message 3 without the ENCRYPTION flag", At::Answered, |w, h| {
            let mut m = message_3(&w.gw, h.msgid, hash3(w, h), &h.qm2_last_block, 0);
            m[19] &= !flags::ENCRYPTION;
            m
        }, |id| (Classified::Ignored(Ignored::Responder(ResponderDrop::NotMessage3)), no_events(id), Answered)),
        ("a bare header", At::Answered, |w, h| {
            let mut m = message_3(&w.gw, h.msgid, hash3(w, h), &h.qm2_last_block, 0);
            m.truncate(IsakmpHeader::LEN);
            m[24..28].copy_from_slice(&(IsakmpHeader::LEN as u32).to_be_bytes());
            m
        }, |id| {
            (Classified::Ignored(Ignored::Responder(ResponderDrop::NotMessage3)), no_events(id), Answered)
        }),
        ("held: what would be its message 3 once message 2 left", At::Held, |w, h| message_3(&w.gw, h.msgid, hash3(w, h), &h.qm2_last_block, 0), |id| {
            (Classified::Ignored(Ignored::Responder(ResponderDrop::WhileHeld)), no_events(id), Held)
        }),
        ("proven: its message 3", At::Proven, |w, h| message_3(&w.gw, h.msgid, hash3(w, h), &h.qm2_last_block, 0), |id| {
            (Classified::Message3 { msgid: id, read: Message3::AfterProof }, no_events(id), ResponderState::Proven(Proof::Esp))
        }),
    ];
    let mut wrong = Vec::new();
    for (what, at, make, want) in rows {
        let w = World::new(false);
        let held = w.hold(&w.rekey(Primary, 0xB400).0);
        let view = HeldView { msgid: held.msgid(), ni: held.ni().to_vec(), nr: held.nr().to_vec(), qm2_last_block: held.qm2_last_block().to_vec() };
        let (msgid, id) = (view.msgid, held.id());
        let _keep = match at {
            At::Held => Some(held),
            _ => {
                w.release(held);
                if at == At::Proven {
                    w.client.conclude_responder(id, Outcome::Proven(Proof::Esp)).unwrap();
                }
                None
            }
        };
        let before = w.client.exchanges.responder_counters();
        let datagram = make(&w, &view);
        let (want_read, want_events, want_state) = want(msgid);
        let (_, sent) = w.serve(&[&datagram]);
        let got = w.read(&datagram);
        let events = w.client.take_responder_events(Primary).unwrap_or(no_events(msgid));
        // The serving turn read it once already: the second read is a copy of it.
        let want_read = match want_read {
            Classified::Message3 { msgid, read: Message3::First } => Classified::Message3 { msgid, read: Message3::Again },
            other => other,
        };
        if got != want_read || events != want_events || w.client.responder_state(msgid) != Some(want_state) || !sent.is_empty() {
            wrong.push(format!("{what}: {got:?} / {events:?} / {:?} / {} sent", w.client.responder_state(msgid), sent.len()));
        }
        let after = w.client.exchanges.responder_counters();
        let dropped = (after.qm3_invalid - before.qm3_invalid, after.qm3_while_held - before.qm3_while_held);
        let want_dropped = match want_read {
            Classified::Ignored(Ignored::Responder(ResponderDrop::NotMessage3)) => (2, 0),
            Classified::Ignored(Ignored::Responder(ResponderDrop::WhileHeld)) => (0, 2),
            _ => (0, 0),
        };
        if dropped != want_dropped {
            wrong.push(format!("{what}: counted {dropped:?}, not {want_dropped:?}"));
        }
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));

    // Abandoned: the late message 3, valid as it is, activates nothing and is not even read as a message 3.
    let w = World::new(false);
    let (qm1, qi) = w.rekey(Primary, 0xB410);
    let held = w.hold(&qm1);
    let (msgid, id) = (held.msgid(), held.id());
    let (_answered, qm2) = w.release(held);
    assert_eq!(w.client.conclude_responder(id, Outcome::Abandoned(EndReason::NoProof)), Ok(ResponderState::Abandoned(EndReason::NoProof)));
    let (qm3, ..) = qi.complete_with_lifetime(&qm2).unwrap();
    let (report, sent) = w.serve(&[&qm3]);
    assert_eq!((report.datagrams_read, sent.len()), (1, 0));
    assert_eq!(w.read(&qm3), Classified::Ignored(Ignored::Unauthenticated), "no exchange of that id any more");
    assert_eq!(w.client.responder_state(msgid), Some(ResponderState::Abandoned(EndReason::NoProof)));
    assert_eq!((w.client.responder_pending(Primary), w.client.take_responder_events(Primary)), (None, None));
}

// ---- Copies of message 1 after the exchange ended, and other messages under its id ----

/// After the exchange ended, a copy of its message 1 is answered only while it is proven, with its message 2, for
/// [`RESP_RETAIN`]; once abandoned or cancelled -- message 2 dropped at once -- and once the retention ran out, it
/// gets silence, and no new answer: the entry handed to the responder again is not in progress.
#[test]
fn a_copy_of_message_1_after_the_end_gets_message_2_only_while_proven() {
    type End = (&'static str, Option<Outcome>, Duration, bool);
    let ends: [End; 6] = [
        ("proven", Some(Outcome::Proven(Proof::Esp)), ANSWER_SPACING, true),
        ("proven, a nanosecond before the retention ends", Some(Outcome::Proven(Proof::Qm3)), RESP_RETAIN - Duration::from_nanos(1), true),
        ("proven, the retention over", Some(Outcome::Proven(Proof::Qm3)), RESP_RETAIN, false),
        ("abandoned", Some(Outcome::Abandoned(EndReason::NoProof)), ANSWER_SPACING, false),
        ("cancelled", Some(Outcome::Cancelled(EndReason::NewDeleted)), ANSWER_SPACING, false),
        ("answered, nobody ending it: abandoned at its deadline", None, ANSWERED_FOR, false),
    ];
    for (what, outcome, after, answered) in ends {
        let w = World::new(false);
        let (qm1, _) = w.rekey(Primary, 0xB500);
        let entry = kept(&w.client, &qm1);
        let held = accepted(w.answer(&entry));
        let (msgid, id) = (held.msgid(), held.id());
        let (_answered, qm2) = w.release(held);
        if let Some(outcome) = outcome {
            w.client.conclude_responder(id, outcome).unwrap();
        }
        w.advance(after);
        let (_, sent) = w.serve(&[&qm1]);
        assert_eq!(sent, if answered { vec![qm2] } else { vec![] }, "{what}");
        let verdict = w.answer(&entry);
        assert!(matches!(verdict, QuickVerdict::Silent(Silence::NotInProgress)), "{what}: {verdict:?}");
        if outcome.is_none() {
            assert_eq!(w.client.responder_state(msgid), Some(ResponderState::Abandoned(EndReason::Deadline)), "{what}");
        }
    }
}

/// Another message 1 under the id of a responder exchange -- another nonce -- is dropped and counted, while it is held
/// and once answered: nothing is sent, the exchange does not change.
#[test]
fn another_message_1_under_the_id_of_a_responder_exchange_is_dropped() {
    for released in [false, true] {
        let w = World::new(false);
        let genuine = Qm1::rekeying(&plain(), 0xB600);
        let held = w.hold(&genuine.message(&w.gw));
        let msgid = held.msgid();
        let _kept = if released {
            w.release(held);
            w.advance(ANSWER_SPACING);
            None
        } else {
            Some(held)
        };
        let mut other = genuine.clone();
        other.ni = vec![0x77; 16];
        let (_, sent) = w.serve(&[&other.message(&w.gw)]);
        assert!(sent.is_empty(), "released {released}");
        assert_eq!(w.read(&other.message(&w.gw)), Classified::Ignored(Ignored::Responder(ResponderDrop::OtherMessage)));
        assert_eq!(w.client.exchanges.responder_counters().other_messages, 2);
        assert_eq!(w.client.responder_state(msgid), Some(if released { Answered } else { Held }));
        assert!(w.client.take_responder_events(Primary).unwrap().is_empty());
    }
}

// ---- Held past its bound, reconsidered, burned ----

/// A held exchange whose daemon never speaks is parked at its bound (nothing was sent): a copy of its message 1 read
/// less than a second after that gets silence, one read a second after is taken up again and answered anew (a new
/// SPI and nonce: no message 2 ever left), twice; parked a third time it is over, and its copies get silence. A
/// release of a parked answer sends nothing.
#[test]
fn a_held_exchange_past_its_bound_is_parked_reconsidered_twice_then_over() {
    let w = World::new(false);
    let (qm1, _) = w.rekey(Primary, 0xB700);
    let msgid = msgid_of(&qm1);
    let mut spis = Vec::new();
    let mut held = w.hold(&qm1);
    for spell in 0..=2u8 {
        spis.push(held.local_spi());
        assert_eq!(w.client.exchanges.id_record(msgid).map(|record| record.tries), Some(spell));
        w.advance(PEER_QM_HOLD_MAX);
        assert_eq!(w.client.responder_state(msgid), Some(Parked), "spell {spell}");
        assert_eq!(w.client.responder_pending(Primary), None);
        let wire = Wire::default();
        assert_eq!((*held).release(&wire, &w.client, gateway(), w.clock.now()).err(), Some(ReleaseError::NotHeld(Some(Parked))));
        assert!(wire.sent.borrow().is_empty());
        if spell == 2 {
            break;
        }
        assert!(matches!(w.state(msgid), Some(MidState::Parked { .. })), "spell {spell}: {:?}", w.state(msgid));
        w.advance(RECONSIDER_GAP - Duration::from_millis(1));
        assert!(matches!(w.read(&qm1), Classified::Ignored(Ignored::Admission(_))), "spell {spell}: too soon");
        w.advance(Duration::from_millis(1));
        held = w.hold(&qm1);
    }
    assert_eq!(w.state(msgid), Some(MidState::Done), "taken up twice: over");
    w.advance(RECONSIDER_GAP);
    assert!(matches!(w.read(&qm1), Classified::Ignored(Ignored::Admission(_))));
    assert!(w.client.take_peer_quick_modes().is_empty());
    assert!(spis[0] != spis[1] && spis[1] != spis[2], "answered anew each time: {spis:x?}");
}

/// A message parked at its hold bound and answered anew is another answer: a late release of the first one -- the
/// daemon's, after the hold ran out -- sends nothing and leaves the second one held, and a park or an end named by
/// the first one is refused and leaves the second as it was; the second one's own release sends its own message 2.
#[test]
fn an_answer_parked_and_given_anew_is_never_touched_through_the_first_one() {
    let w = World::new(false);
    let (qm1, _) = w.rekey(Primary, 0xC300);
    let msgid = msgid_of(&qm1);
    let first = w.hold(&qm1);
    let stale = first.id();
    w.advance(PEER_QM_HOLD_MAX);
    assert_eq!(w.client.responder_state(msgid), Some(Parked), "the hold ran out");
    w.advance(RECONSIDER_GAP);
    let second = w.hold(&qm1);
    let t_second = w.clock.now();
    let (current, spi, qm2) = (second.id(), second.local_spi(), second.qm2().to_vec());
    assert!(stale != current && first.local_spi() != spi && first.nr() != second.nr(), "answered anew: another hold, SPI and nonce");
    let pending = Some(PendingResponder { id: current, msgid, state: Held, inbound_spi: spi });
    assert_eq!(w.client.responder_pending(Primary), pending);

    let wire = Wire::default();
    assert_eq!((*first).release(&wire, &w.client, gateway(), w.clock.now()).err(), Some(ReleaseError::NotHeld(Some(Parked))));
    assert!(wire.sent.borrow().is_empty(), "nothing sent for the first answer");
    assert_eq!(w.client.park_responder(stale), Err(IllegalTransition { msgid, from: Some(Parked), to: Transition::Park }));
    let ends = [
        (Outcome::Cancelled(EndReason::Disconnect), Transition::Cancel),
        (Outcome::Abandoned(EndReason::NoProof), Transition::Abandon),
        (Outcome::Proven(Proof::Qm3), Transition::Prove),
    ];
    for (outcome, to) in ends {
        assert_eq!(w.client.conclude_responder(stale, outcome), Err(IllegalTransition { msgid, from: Some(Parked), to }), "{outcome:?}");
    }
    assert_eq!(w.client.responder_pending(Primary), pending, "the second answer as it was");
    assert_eq!(w.client.exchanges.id_record(msgid).map(|record| record.state), Some(MidState::Active { deadline: t_second + PEER_QM_HOLD_MAX }));

    let (answered, sent) = w.release(second);
    assert_eq!((answered.id(), sent), (current, qm2), "its own message 2");
    assert_eq!(w.client.conclude_responder(current, Outcome::Proven(Proof::Qm3)), Ok(ResponderState::Proven(Proof::Qm3)));
}

/// An exchange the responder saw end for good is never answered anew, even once the ledger and the nonce memory
/// forgot it and a copy of its message 1 is read as a new message: nothing is drawn, no other SPI, nonce or keys.
#[test]
fn a_message_whose_exchange_ended_is_not_answered_anew_once_the_ledger_forgot_it() {
    let w = World::new(false);
    let (qm1, _) = w.rekey(Primary, 0xC400);
    let held = w.hold(&qm1);
    let (msgid, id) = (held.msgid(), held.id());
    w.release(held);
    w.client.conclude_responder(id, Outcome::Abandoned(EndReason::NoProof)).unwrap();
    let now = w.clock.now();
    for n in 1..=MID_CAP as u32 {
        w.client.exchanges.record_authenticated(2 * n, MidKind::Informational, [7; 32], now, now);
    }
    for n in 0..NI_KEPT {
        w.client.exchanges.remember_ni(Primary, &[n as u8; 16]);
    }
    assert_eq!(w.client.exchanges.id_record(msgid), None, "the ledger forgot it");
    w.advance(ACCEPT_SPACING);
    assert_eq!(w.read(&qm1), Classified::PeerQuick { msgid }, "read as a new message 1");
    let [entry] = <[PeerQuick; 1]>::try_from(w.client.take_peer_quick_modes()).expect("one entry");
    let mut entropy = Counting::new(0xC401);
    let verdict = answer_quick(&w.client, &mut entropy, &w.tunnel.expect(w.clock.now()), &entry);
    assert!(matches!(verdict, QuickVerdict::Silent(Silence::AlreadyAnswered)), "{verdict:?}");
    assert_eq!(entropy.fills, 0, "nothing drawn");
    assert_eq!((w.client.responder_state(msgid), w.client.responder_pending(Primary)), (Some(ResponderState::Abandoned(EndReason::NoProof)), None));
}

/// A message 2 that left is never answered anew: once released, the entry handed to the responder again is the
/// answer given ([`Silence::AlreadyAnswered`]) while the exchange is in progress, and not in progress once it ended --
/// whatever ended it; a held one handed in again is already answered too. Parking is refused once message 2 left.
#[test]
fn a_message_2_that_left_is_never_replaced_by_another() {
    let w = World::new(false);
    let (qm1, _) = w.rekey(Primary, 0xB800);
    let entry = kept(&w.client, &qm1);
    let held = accepted(w.answer(&entry));
    let (msgid, id) = (held.msgid(), held.id());
    assert!(matches!(w.answer(&entry), QuickVerdict::Silent(Silence::AlreadyAnswered)));
    w.release(held);
    assert!(matches!(w.answer(&entry), QuickVerdict::Silent(Silence::AlreadyAnswered)));
    assert_eq!(w.client.park_responder(id), Err(IllegalTransition { msgid, from: Some(Answered), to: Transition::Park }));
    w.client.conclude_responder(id, Outcome::Cancelled(EndReason::Disconnect)).unwrap();
    assert!(matches!(w.answer(&entry), QuickVerdict::Silent(Silence::NotInProgress)));
}

// ---- Admission: spacing, nonce replay, the deferred slot, the cache ----

/// [`ACCEPT_SPACING`] after a family's gateway Quick Mode ended, a message 1 of the family waits: it is not answered,
/// not offered again before the spacing passed, and answered once it did; the other family is not held back.
#[test]
fn a_message_1_right_after_its_familys_last_exchange_ended_waits_for_the_spacing() {
    let w = World::new(false);
    let first = w.hold(&w.rekey(Primary, 0xB900).0);
    let first_id = first.id();
    w.release(first);
    w.client.conclude_responder(first_id, Outcome::Proven(Proof::Esp)).unwrap();
    w.advance(ACCEPT_SPACING / 2);
    let (next, _) = w.rekey(Primary, 0xB901);
    let verdict = w.offer(&next);
    assert!(matches!(verdict, QuickVerdict::Silent(Silence::Deferred(DeferReason::Spacing))), "{verdict:?}");
    accepted(w.offer(&w.rekey(Ipv6, 0xB902).0));
    w.advance(ACCEPT_SPACING / 2 - Duration::from_nanos(1));
    assert!(w.client.take_peer_quick_modes().is_empty(), "not yet");
    w.advance(Duration::from_nanos(1));
    let [again] = <[PeerQuick; 1]>::try_from(w.client.take_peer_quick_modes()).expect("offered again");
    assert_eq!(again.msgid, msgid_of(&next));
    accepted(w.answer(&again));
}

/// A message 1 whose nonce the gateway sent in a Quick Mode before is a replay, after the ledger forgot that exchange
/// too: under its own Message ID and under another, it never reaches the responder.
#[test]
fn a_replayed_message_1_is_refused_by_its_nonce_after_the_ledger_forgot_its_id() {
    let w = World::new(false);
    let genuine = Qm1::rekeying(&plain(), 0xBA00);
    let message = genuine.message(&w.gw);
    let held = w.hold(&message);
    let (msgid, id) = (held.msgid(), held.id());
    w.release(held);
    w.client.conclude_responder(id, Outcome::Abandoned(EndReason::NoProof)).unwrap();
    let now = w.clock.now();
    for n in 1..=MID_CAP as u32 {
        w.client.exchanges.record_authenticated(2 * n, MidKind::Informational, [7; 32], now, now);
    }
    assert_eq!(w.client.exchanges.id_record(msgid), None, "the ledger forgot it");
    let mut other_id = genuine.clone();
    other_id.msgid = 0x6A6A_6A6B;
    for replay in [message, other_id.message(&w.gw)] {
        assert_eq!(w.read(&replay), Classified::Ignored(Ignored::NonceReplay));
    }
    assert!(w.client.take_peer_quick_modes().is_empty());
}

/// One message 1 per family waits while the family is busy: the latest read wins and the one it displaces is parked
/// (it may be taken up again); it is not offered while the family is busy, and is offered and answered once the family
/// is free -- not counted as a reconsideration; the other family is independent; one that waited [`DEFER_MAX`] is
/// dropped, its exchange parked at that instant.
#[test]
fn a_message_1_for_a_busy_family_waits_in_its_one_slot_the_latest_winning() {
    let w = World::new(false);
    let busy = w.hold(&w.rekey(Primary, 0xBB00).0);
    let busy_id = busy.id();
    let (displaced, _) = w.rekey(Primary, 0xBB01);
    assert!(matches!(w.offer(&displaced), QuickVerdict::Silent(Silence::Deferred(DeferReason::Busy))));
    w.advance(Duration::from_millis(10));
    let (latest, _) = w.rekey(Primary, 0xBB02);
    assert!(matches!(w.offer(&latest), QuickVerdict::Silent(Silence::Deferred(DeferReason::Busy))));
    assert_eq!(w.client.exchanges.deferred_held(), [msgid_of(&latest)], "the latest wins");
    assert!(matches!(w.state(msgid_of(&displaced)), Some(MidState::Parked { .. })), "the displaced one may be taken up again");
    assert!(w.client.take_peer_quick_modes().is_empty(), "not offered while the family is busy");
    let other = w.hold(&w.rekey(Ipv6, 0xBB03).0);
    assert_eq!(w.client.responder_pending(Ipv6).map(|p| p.msgid), Some(other.msgid()), "the other family is independent");
    assert_eq!(w.client.exchanges.deferred_held(), [msgid_of(&latest)]);
    w.client.conclude_responder(busy_id, Outcome::Cancelled(EndReason::NotInstalled)).unwrap();
    w.advance(ACCEPT_SPACING);
    let [offered] = <[PeerQuick; 1]>::try_from(w.client.take_peer_quick_modes()).expect("offered once the family is free");
    assert_eq!(offered.msgid, msgid_of(&latest));
    let held = accepted(w.answer(&offered));
    assert_eq!(w.client.exchanges.id_record(held.msgid()).map(|record| record.tries), Some(0), "the wait was not a reconsideration");

    let (waits, _) = w.rekey(Primary, 0xBB04);
    let read_at = w.clock.now();
    assert!(matches!(w.offer(&waits), QuickVerdict::Silent(Silence::Deferred(DeferReason::Busy))));
    let record = w.client.exchanges.id_record(msgid_of(&waits)).unwrap();
    assert_eq!((record.state, record.at_deadline), (MidState::Active { deadline: read_at + DEFER_MAX }, AtDeadline::Park { until: read_at + DEFER_MAX + PARKED_FOR }));
    w.advance(DEFER_MAX);
    assert!(w.client.take_peer_quick_modes().is_empty());
    assert!(w.client.exchanges.deferred_held().is_empty(), "dropped once it waited its time");
    assert!(matches!(w.state(msgid_of(&waits)), Some(MidState::Parked { .. })));
}

/// A family with no current SA to renew: its message 1 waits (never refused), and is answered once the caller lists
/// the family answerable again.
#[test]
fn a_message_1_for_a_family_not_ready_waits_until_it_is() {
    let mut w = World::new(false);
    w.tunnel = Tunnel::of(vec![plain(), v6(GCM, None).answerable(false)]);
    let (qm1, _) = w.rekey(Ipv6, 0xBB10);
    assert!(matches!(w.offer(&qm1), QuickVerdict::Silent(Silence::Deferred(DeferReason::NotReady))));
    let [again] = <[PeerQuick; 1]>::try_from(w.client.take_peer_quick_modes()).expect("offered: the table does not know the family's state");
    assert!(matches!(w.answer(&again), QuickVerdict::Silent(Silence::Deferred(DeferReason::NotReady))), "still not ready");
    w.tunnel = Tunnel::of(vec![plain(), v6(GCM, None)]);
    let [ready] = <[PeerQuick; 1]>::try_from(w.client.take_peer_quick_modes()).unwrap();
    accepted(w.answer(&ready));
}

/// A message 1 handed out of its family's slot again and still not answerable waits as it did: the same wait, its
/// time counting from its first read, its ledger deadline unchanged, never traced as a new one -- turn after turn,
/// through the responder too; a copy read later, and another message, are waits of their own.
#[test]
fn a_message_1_offered_again_and_still_not_answerable_still_waits_as_it_was() {
    let mut w = World::new(false);
    w.tunnel = Tunnel::of(vec![plain(), v6(GCM, None).answerable(false)]);
    let (qm1, _) = w.rekey(Ipv6, 0xC600);
    let msgid = msgid_of(&qm1);
    let read_at = w.clock.now();
    assert!(matches!(w.offer(&qm1), QuickVerdict::Silent(Silence::Deferred(DeferReason::NotReady))));
    let waits = |turn: &str| {
        assert_eq!(w.client.exchanges.deferred_held(), [msgid], "{turn}");
        assert_eq!(w.client.exchanges.id_record(msgid).map(|record| record.state), Some(MidState::Active { deadline: read_at + DEFER_MAX }), "{turn}");
    };
    for turn in 0..3 {
        w.advance(Duration::from_millis(160));
        let [again] = <[PeerQuick; 1]>::try_from(w.client.take_peer_quick_modes()).expect("offered every turn");
        assert_eq!(again.arrived, read_at);
        assert_eq!(w.client.exchanges.defer_peer_quick(Ipv6, &again), table::Deferral::StillWaits, "turn {turn}");
        waits(&format!("turn {turn}"));
    }
    let [again] = <[PeerQuick; 1]>::try_from(w.client.take_peer_quick_modes()).unwrap();
    assert!(matches!(w.answer(&again), QuickVerdict::Silent(Silence::Deferred(DeferReason::NotReady))));
    waits("through the responder");
    let [again] = <[PeerQuick; 1]>::try_from(w.client.take_peer_quick_modes()).unwrap();
    let later = PeerQuick { arrived: w.clock.now(), ..again.clone() };
    assert_eq!(w.client.exchanges.defer_peer_quick(Ipv6, &later), table::Deferral::Waits, "a copy read later");
    let [again] = <[PeerQuick; 1]>::try_from(w.client.take_peer_quick_modes()).unwrap();
    let (other, _) = w.rekey(Ipv6, 0xC601);
    let other = super::tests::unread_entry(&w.gw, &other, w.clock.now());
    assert_eq!(w.client.exchanges.defer_peer_quick(Ipv6, &other), table::Deferral::Waits, "another message");
    assert_eq!(w.client.exchanges.defer_peer_quick(Ipv6, &again), table::Deferral::Waits, "the slot was another message's since");
}

/// A cache that holds as many exchanges in progress as it may: the next message 1 waits, never displacing one in
/// progress, and is answered once one ended.
#[test]
fn a_message_1_waits_while_the_cache_is_full_of_exchanges_in_progress() {
    let w = World::new(false);
    w.client.exchanges.set_responder_cache_limits(1, cache::CACHE_BYTES);
    let first = w.hold(&w.rekey(Primary, 0xBC00).0);
    let (first_msgid, first_id) = (first.msgid(), first.id());
    let (qm1, _) = w.rekey(Ipv6, 0xBC01);
    assert!(matches!(w.offer(&qm1), QuickVerdict::Silent(Silence::Deferred(DeferReason::CacheFull))));
    assert!(w.client.take_peer_quick_modes().is_empty(), "not offered while the cache is full");
    assert_eq!(w.client.responder_state(first_msgid), Some(Held), "the one in progress stays");
    w.client.park_responder(first_id).unwrap();
    let [offered] = <[PeerQuick; 1]>::try_from(w.client.take_peer_quick_modes()).unwrap();
    accepted(w.answer(&offered));
    assert_eq!(w.client.exchanges.responder_cache_held().0, 1);
}

// ---- Resends of message 2 ----

/// The resends of message 2 follow the round trip of the path: the first after the estimate -- or the floor without
/// one, never below it --, the next twice as long after, at most two, every one before [`PEER_QM_PROOF_WAIT`] ends.
#[test]
fn the_resends_of_message_2_follow_the_round_trip_and_fit_the_proof_window() {
    let ms = Duration::from_millis;
    type Case = (&'static str, Option<Duration>, Vec<Duration>, Vec<Duration>);
    let cases: Vec<Case> = vec![
        ("the floor of a second, nothing measured: the second resend would end the window", None, vec![], vec![ms(1000)]),
        ("a floor of 100 ms, nothing measured", Some(ms(100)), vec![], vec![ms(100), ms(300)]),
        ("a fast path under the floor of a second", None, vec![ms(200)], vec![ms(1000)]),
        ("a measured 300 ms: a timer of 900 ms", Some(ms(100)), vec![ms(300)], vec![ms(900), ms(2700)]),
        ("a measured second: a timer of 3 s, past the window", Some(ms(100)), vec![ms(1000)], vec![]),
    ];
    for (what, floor, samples, want) in cases {
        let rtt = floor.map_or_else(RoundTrips::default, RoundTrips::with_floor);
        for sample in samples {
            rtt.sampled(sample);
        }
        assert_eq!(rtt.responder_resends(PEER_QM_PROOF_WAIT, cache::QM2_RESENDS), want, "{what}");
    }
}

/// An answered exchange resends its message 2, byte for byte, when each resend is due and not before; none after the
/// last, none once the exchange ended, and none within 200 ms of a message 2 a reader sent for a copy of message 1.
#[test]
fn message_2_is_resent_when_due_and_never_after_the_end() {
    let ms = Duration::from_millis;
    let mut w = World::new(false);
    w.client.rtt = RoundTrips::with_floor(ms(250));
    let (qm1, _) = w.rekey(Primary, 0xBD00);
    let held = w.hold(&qm1);
    let (mut answered, qm2) = w.release(held);
    let sent_at = w.clock.now();
    assert_eq!(answered.next_resend(sent_at), Some(sent_at + ms(250)));
    let wire = Wire::default();
    w.advance(ms(249));
    assert!(!answered.resend_due(w.clock.now(), &wire, gateway()).unwrap());
    w.advance(ms(1));
    assert!(answered.resend_due(w.clock.now(), &wire, gateway()).unwrap());
    assert_eq!(wire.messages(false), [qm2.as_slice()]);
    assert!(!answered.resend_due(w.clock.now(), &wire, gateway()).unwrap(), "once");
    assert_eq!(answered.next_resend(w.clock.now()), Some(sent_at + ms(750)));
    w.advance(ms(400));
    assert_eq!(w.serve(&[&qm1]).1, [qm2.as_slice()], "a copy of message 1 at 650 ms");
    w.advance(ms(100));
    assert!(!answered.resend_due(w.clock.now(), &wire, gateway()).unwrap(), "100 ms after that answer: skipped");
    assert_eq!(answered.next_resend(w.clock.now()), None, "no resend left");
    assert_eq!(wire.messages(false).len(), 1);

    // Ended before its resends were due: none goes.
    let (qm1, _) = w.rekey(Ipv6, 0xBD01);
    let (mut answered, _) = w.release(w.hold(&qm1));
    w.client.conclude_responder(answered.id(), Outcome::Proven(Proof::Esp)).unwrap();
    w.advance(ms(100));
    assert_eq!(answered.next_resend(w.clock.now()), None);
    let wire = Wire::default();
    assert!(!answered.resend_due(w.clock.now(), &wire, gateway()).unwrap());
    assert!(wire.sent.borrow().is_empty());
}

/// A resend sends the encryption of message 2 handed out last: once the gateway's own copy of message 1 got message 2
/// under its last cipher block, the resend is that encryption -- which the gateway reads --, not the one under the
/// raced copy's block, which it cannot; once the raced copy is answered again, the next resend follows it (POLICY).
#[test]
fn a_resend_sends_the_encryption_of_message_2_handed_out_last() {
    let ms = Duration::from_millis;
    let mut w = World::new(false);
    w.client.rtt = RoundTrips::with_floor(ms(500));
    let (genuine, _) = w.rekey(Primary, 0xC700);
    let raced = appended(&genuine, 0xA5);
    let (mut answered, first) = w.release(w.hold(&raced));
    w.advance(ANSWER_SPACING);
    let [second] = <[Vec<u8>; 1]>::try_from(w.serve(&[&genuine]).1).expect("the gateway's own copy answered");
    assert_ne!(second, first);
    let wire = Wire::default();
    w.advance(ms(300));
    assert!(answered.resend_due(w.clock.now(), &wire, gateway()).unwrap(), "the first resend, at 500 ms");
    assert_eq!(wire.messages(false), [second.as_slice()], "under the gateway's own last block");
    w.initiator(&genuine).complete_with_lifetime(&second).expect("which the gateway reads");
    w.advance(ANSWER_SPACING);
    assert_eq!(w.serve(&[&raced]).1, [first.as_slice()]);
    w.advance(ms(800));
    assert!(answered.resend_due(w.clock.now(), &wire, gateway()).unwrap(), "the second resend, at 1500 ms");
    assert_eq!(wire.messages(false), [second, first]);
}

// ---- Release ----

/// A release sends nothing once the exchange is not held -- parked by the caller or cancelled --, and one whose send
/// fails leaves the exchange parked: nothing left, so a copy of its message 1 may be answered anew.
#[test]
fn a_release_sends_message_2_only_for_an_exchange_held_and_parks_it_when_the_send_fails() {
    type Before = fn(&World, ResponderId);
    let rows: [(&str, Before, Option<ResponderState>); 2] = [
        ("parked by the caller", |w, id| assert_eq!(w.client.park_responder(id), Ok(Parked)), Some(Parked)),
        ("cancelled", |w, id| {
            w.client.conclude_responder(id, Outcome::Cancelled(EndReason::TornDown)).unwrap();
        }, Some(ResponderState::Cancelled(EndReason::TornDown))),
    ];
    for (what, before, state) in rows {
        let w = World::new(false);
        let held = w.hold(&w.rekey(Primary, 0xBE00).0);
        before(&w, held.id());
        let wire = Wire::default();
        assert_eq!((*held).release(&wire, &w.client, gateway(), w.clock.now()).err(), Some(ReleaseError::NotHeld(state)), "{what}");
        assert!(wire.sent.borrow().is_empty(), "{what}");
    }
    let w = World::new(false);
    let (qm1, _) = w.rekey(Primary, 0xBE01);
    let held = w.hold(&qm1);
    let msgid = held.msgid();
    let refusing = Wire::refusing();
    assert_eq!((*held).release(&refusing, &w.client, gateway(), w.clock.now()).err(), Some(ReleaseError::NotSent(io::ErrorKind::ConnectionRefused)));
    assert_eq!(w.client.responder_state(msgid), Some(Parked));
    assert!(matches!(w.state(msgid), Some(MidState::Parked { .. })));
    w.advance(RECONSIDER_GAP);
    accepted(w.offer(&qm1));
}

/// The hold bound falling while message 2 is being sent changes nothing of the release: the exchange is answered
/// before the send, so a message 2 that went is answered -- never "not held" --, a copy of message 1 gets it again and
/// nothing is answered anew; one whose send failed is parked with nothing sent, and may be answered anew; one whose
/// send failed after a reader answered a copy of message 1 with it meanwhile is answered, and released.
#[test]
fn the_hold_bound_falling_during_the_send_never_leaves_a_message_2_sent_and_not_held() {
    let just_before_the_bound = PEER_QM_HOLD_MAX - Duration::from_nanos(1);
    let w = World::new(false);
    let (qm1, qi) = w.rekey(Primary, 0xC900);
    let held = w.hold(&qm1);
    let (msgid, qm2) = (held.msgid(), held.qm2().to_vec());
    w.advance(just_before_the_bound);
    let released_at = w.clock.now();
    let wire = Stalled::new(false, || w.advance(Duration::from_millis(2)));
    let answered = (*held).release(&wire, &w.client, gateway(), released_at).expect("answered before the send");
    assert_eq!(wire.sent.borrow().as_slice(), [qm2.as_slice()]);
    assert_eq!(w.client.exchanges.responder_state_of(answered.id()), Some(Answered));
    assert_eq!(w.client.exchanges.id_record(msgid).map(|record| record.state), Some(MidState::Active { deadline: released_at + ANSWERED_FOR }));
    w.advance(ANSWER_SPACING);
    assert_eq!(w.serve(&[&qm1]).1, [qm2.as_slice()], "a copy gets the message 2 that went");
    assert!(w.client.take_peer_quick_modes().is_empty(), "nothing to answer anew");
    qi.complete_with_lifetime(&qm2).expect("the gateway takes it");

    let w = World::new(false);
    let (qm1, _) = w.rekey(Primary, 0xC901);
    let held = w.hold(&qm1);
    let msgid = held.msgid();
    w.advance(just_before_the_bound);
    let wire = Stalled::new(true, || w.advance(Duration::from_millis(2)));
    assert_eq!((*held).release(&wire, &w.client, gateway(), w.clock.now()).err(), Some(ReleaseError::NotSent(io::ErrorKind::ConnectionRefused)));
    assert!(wire.sent.borrow().is_empty());
    assert_eq!(w.client.responder_state(msgid), Some(Parked));
    assert!(matches!(w.state(msgid), Some(MidState::Parked { .. })), "{:?}", w.state(msgid));
    w.advance(RECONSIDER_GAP);
    accepted(w.offer(&qm1));

    let w = World::new(false);
    let (qm1, qi) = w.rekey(Primary, 0xC902);
    let held = w.hold(&qm1);
    let (msgid, qm2) = (held.msgid(), held.qm2().to_vec());
    let by_reader = RefCell::new(Vec::new());
    let wire = Stalled::new(true, || {
        w.advance(ANSWER_SPACING);
        by_reader.replace(w.serve(&[&qm1]).1);
    });
    let answered = (*held).release(&wire, &w.client, gateway(), w.clock.now()).expect("message 2 went for the copy");
    assert_eq!(by_reader.borrow().as_slice(), [qm2.as_slice()], "the copy got the message 2 held");
    assert_eq!((answered.msgid(), w.client.responder_state(msgid)), (msgid, Some(Answered)));
    qi.complete_with_lifetime(&qm2).expect("the gateway takes it");
}

// ---- Facts for the caller ----

/// Both families at once are independent: each is held, answered and ended on its own, and what is said of one is
/// recorded on that one only -- an error Notify naming the inbound SPI of one, or under its Message ID, is about it
/// alone, and the caller's cancel of it leaves the other in progress; an ISAKMP Delete is a fact of both.
#[test]
fn two_families_are_independent_and_an_error_notify_is_recorded_on_the_exchange_it_names() {
    let w = World::new(false);
    let primary = w.hold(&w.rekey(Primary, 0xBF00).0);
    let ipv6 = w.hold(&w.rekey(Ipv6, 0xBF01).0);
    let (p_msgid, v_msgid, v_id, v_spi) = (primary.msgid(), ipv6.msgid(), ipv6.id(), ipv6.local_spi());
    w.release(ipv6);
    assert_eq!(w.client.responder_pending(Primary).map(|p| p.state), Some(Held));
    assert_eq!(w.client.responder_pending(Ipv6).map(|p| p.state), Some(Answered));
    let naming_spi = gateway_informational(&w.gw, 0x5E5E_0001, &[(payload::NOTIFY, informational::notify_body(protocol::ESP, &v_spi.to_be_bytes(), 14, &[]))]);
    let under_id = gateway_informational(&w.gw, p_msgid, &[(payload::NOTIFY, informational::notify_body(protocol::ISAKMP, &[], 16, &[]))]);
    let (_, sent) = w.serve(&[&naming_spi, &under_id]);
    assert!(sent.is_empty());
    assert_eq!(w.client.take_responder_events(Ipv6), Some(ResponderEvents { peer_rejected: Some(14), ..no_events(v_msgid) }));
    assert_eq!(w.client.take_responder_events(Primary), Some(ResponderEvents { peer_rejected: Some(16), ..no_events(p_msgid) }));
    assert_eq!(w.client.conclude_responder(v_id, Outcome::Cancelled(EndReason::PeerRejected)), Ok(ResponderState::Cancelled(EndReason::PeerRejected)));
    assert_eq!(w.client.responder_pending(Primary).map(|p| (p.msgid, p.state)), Some((p_msgid, Held)), "the other one stays");
    assert_eq!(w.client.responder_pending(Ipv6), None);
    w.advance(ACCEPT_SPACING);
    let ipv6 = w.hold(&w.rekey(Ipv6, 0xBF02).0);
    let isakmp_delete = gateway_informational(&w.gw, 0x5E5E_0003, &[(payload::DELETE, {
        let mut body = 1u32.to_be_bytes().to_vec();
        body.extend_from_slice(&[protocol::ISAKMP, 16, 0, 1]);
        body.extend_from_slice(&[w.gw.cky_i, w.gw.cky_r].concat());
        body
    })]);
    w.serve(&[&isakmp_delete]);
    assert_eq!(w.client.take_responder_events(Primary), Some(ResponderEvents { torn_down: true, ..no_events(p_msgid) }));
    assert_eq!(w.client.take_responder_events(Ipv6), Some(ResponderEvents { torn_down: true, ..no_events(ipv6.msgid()) }));
    assert_eq!(w.client.responder_state(p_msgid), Some(Held), "a fact: nothing changes here");
}

/// An answered exchange whose time ran out ([`ANSWERED_FOR`]) is over the moment it did, whether or not anything read
/// the cache since: an error Notify naming its inbound SPI is about no exchange, and nothing is recorded on it.
#[test]
fn an_exchange_whose_time_ran_out_is_given_no_fact() {
    type Probe = fn(&World, u32, u32) -> bool;
    let probes: [(&str, Probe); 2] = [
        ("an error Notify naming its SPI is attributed to it", |w, _, spi| {
            let notice = ErrorNotice { msg_type: 14, protocol: protocol::ESP, spi: PeerSpi::new(&spi.to_be_bytes()).unwrap(), msgid: 0x5E5E_0101 };
            w.client.exchanges.attribute_error_notify(&notice, false, None) != Attribution::None
        }),
        ("a refusal is recorded on it", |w, msgid, _| w.client.exchanges.note_responder_rejected(msgid, 14)),
    ];
    for (what, probe) in probes {
        let w = World::new(false);
        let held = w.hold(&w.rekey(Primary, 0xC500).0);
        let (msgid, spi) = (held.msgid(), held.local_spi());
        w.release(held);
        w.advance(ANSWERED_FOR);
        w.client.exchanges.sweep(w.clock.now());
        assert!(!probe(&w, msgid, spi), "{what}");
        assert_eq!(w.client.responder_state(msgid), Some(ResponderState::Abandoned(EndReason::Deadline)), "{what}");
    }
}

/// A Commit bit is a fact of the exchange, whichever copy carried it: on a copy of message 1 refused in silence for
/// the budget before the clean copy was answered (the table's memory), and on a copy read while the exchange is
/// answered -- which gets no message 2 and changes nothing else.
#[test]
fn a_commit_bit_on_any_copy_of_message_1_reaches_the_caller() {
    let w = World::new(false);
    for n in 0..crate::ikev1::exchange::REFUSALS_PER_WINDOW as u64 {
        let mut other = Qm1::rekeying(&plain(), 0xC000 + n);
        other.set_attribute(esp_attr::ENCAP_MODE, 2);
        refused(w.offer(&other.message(&w.gw)));
    }
    let qm1 = Qm1::rekeying(&plain(), 0xC010);
    let (clean, flagged) = super::tests::clean_and_flagged(&w.gw, &qm1);
    let entry = super::tests::unread_entry(&w.gw, &flagged, w.clock.now());
    assert!(matches!(w.answer(&entry), QuickVerdict::Silent(Silence::RateLimited(RefusalNotify::InvalidFlags))));
    let held = w.hold(&clean);
    assert_eq!(w.client.take_responder_events(Primary), Some(ResponderEvents { commit_seen: true, ..no_events(held.msgid()) }));

    let w = World::new(false);
    let qm1 = Qm1::rekeying(&plain(), 0xC020);
    let (clean, flagged) = super::tests::clean_and_flagged(&w.gw, &qm1);
    let held = w.hold(&clean);
    let msgid = held.msgid();
    w.release(held);
    w.advance(ANSWER_SPACING);
    let (_, sent) = w.serve(&[&flagged]);
    assert!(sent.is_empty(), "no message 2 for a copy with the Commit bit");
    assert_eq!(w.read(&flagged), Classified::Ignored(Ignored::Responder(ResponderDrop::CopyWithCommit)));
    assert_eq!(w.client.take_responder_events(Primary), Some(ResponderEvents { commit_seen: true, ..no_events(msgid) }));
    assert_eq!(w.client.responder_state(msgid), Some(Answered));
    assert_eq!(w.serve(&[&clean]).1.len(), 1, "the copy without the bit is answered");
}

// ---- Refusals kept ----

/// A copy of a refused message 1 read by a serving turn gets the refusal kept, byte for byte, at most once per 200 ms
/// and not counted against the budget: the refusals of three other messages still go after two such resends. A copy
/// with the Commit bit refused with INVALID-FLAGS is answered the same way; the copy without the bit is a message 1
/// of its own.
#[test]
fn a_copy_of_a_refused_message_1_gets_the_refusal_kept_from_the_readers() {
    let w = World::new(false);
    let mut bad = Qm1::rekeying(&plain(), 0xC100);
    bad.set_attribute(esp_attr::ENCAP_MODE, 2);
    let message = bad.message(&w.gw);
    let refusal = refused(w.offer(&message));
    let (report, sent) = w.serve(&[&message]);
    assert_eq!((report.answered_again, sent.len()), (0, 0), "within 200 ms of the refusal");
    assert_eq!(w.read(&message), Classified::Ignored(Ignored::Responder(ResponderDrop::RefusalTooSoon)));
    for _ in 0..2 {
        w.advance(Duration::from_millis(200));
        let (report, sent) = w.serve(&[&message, &message]);
        assert_eq!((report.answered_again, sent), (1, vec![refusal.datagram.clone()]));
    }
    for n in 0..3 {
        let mut other = Qm1::rekeying(&plain(), 0xC110 + n);
        other.set_attribute(esp_attr::ENCAP_MODE, 2);
        assert!(!refused(w.offer(&other.message(&w.gw))).repeat, "the budget was not spent by the resends");
    }

    let w = World::new(false);
    let qm1 = Qm1::rekeying(&plain(), 0xC120);
    let (clean, flagged) = super::tests::clean_and_flagged(&w.gw, &qm1);
    let refusal = refused(w.offer(&flagged));
    assert_eq!(refusal.notify, RefusalNotify::InvalidFlags);
    w.advance(Duration::from_millis(200));
    assert_eq!(w.serve(&[&flagged]).1, [refusal.datagram]);
    assert_eq!(w.read(&clean), Classified::PeerQuick { msgid: qm1.msgid });
}

/// A copy with the Commit bit refused with INVALID-FLAGS, then the message answered without it: the refusal is dropped
/// at the hold -- a flagged copy gets silence while the exchange is in progress (its bit noted) and once it ended for
/// good (abandoned, cancelled, proven and forgotten), never that refusal again, however often it comes.
#[test]
fn the_refusal_of_a_flagged_copy_is_not_sent_again_once_the_message_is_answered() {
    let ends: [(&str, Outcome, Duration); 3] = [
        ("abandoned", Outcome::Abandoned(EndReason::CommitSeen), ANSWER_SPACING),
        ("cancelled", Outcome::Cancelled(EndReason::CommitSeen), ANSWER_SPACING),
        ("proven, its retention over", Outcome::Proven(Proof::Esp), RESP_RETAIN),
    ];
    for (what, outcome, after) in ends {
        let w = World::new(false);
        let qm1 = Qm1::rekeying(&plain(), 0xC800);
        let (clean, flagged) = super::tests::clean_and_flagged(&w.gw, &qm1);
        assert_eq!(refused(w.offer(&flagged)).notify, RefusalNotify::InvalidFlags);
        let held = w.hold(&clean);
        assert!(held.commit_seen());
        assert!(w.client.exchanges.kept_refusal(qm1.msgid, &held.fingerprint(), true).is_none(), "{what}: dropped at the hold");
        w.advance(REFUSAL_RESEND_SPACING);
        assert!(w.serve(&[&flagged]).1.is_empty(), "{what}: held");
        let (answered, _) = w.release(held);
        w.client.conclude_responder(answered.id(), outcome).unwrap();
        w.advance(after);
        for n in 0..3 {
            w.advance(REFUSAL_RESEND_SPACING);
            let (report, sent) = w.serve(&[&flagged]);
            assert_eq!((report.datagrams_read, report.answered_again, sent.len()), (1, 0, 0), "{what}: copy {n}");
        }
    }
}

// ---- A passive table ----

/// A passive table keeps no responder exchange and never reads its clock for one: nothing can be held, pending,
/// deferred, concluded or parked, no facts, no state.
#[test]
fn a_passive_table_holds_no_responder_exchange() {
    let (mut client, gw) = super::super::informational::tests::phase1_pair();
    let reads = Arc::new(AtomicUsize::new(0));
    let counted = reads.clone();
    let at = Instant::now();
    client.exchanges = ExchangeTable::with_clock(Box::new(move || {
        counted.fetch_add(1, Ordering::Relaxed);
        at
    }));
    let message = Qm1::rekeying(&plain(), 0xC200).message(&gw);
    let entry = super::tests::unread_entry(&gw, &message, at);
    let retained = Retained { plaintext: vec![1], first_payload: payload::HASH, ni: vec![2; 16], nr: vec![3; 16], variants: Vec::new() };
    assert!(client.exchanges.hold_responder(entry.msgid, Primary, entry.fingerprint, 0x1234, retained, false).is_err());
    assert_eq!(client.exchanges.defer_peer_quick(Primary, &entry), table::Deferral::Parked);
    assert!(client.exchanges.deferred_held().is_empty());
    for family in [Primary, Ipv6] {
        assert_eq!((client.responder_pending(family), client.take_responder_events(family)), (None, None));
    }
    assert_eq!(client.responder_state(entry.msgid), None);
    let unheld = ResponderId::unheld(entry.msgid);
    assert!(client.conclude_responder(unheld, Outcome::Proven(Proof::Qm3)).is_err());
    assert!(client.park_responder(unheld).is_err());
    assert!(client.exchanges.begin_release(unheld).is_err() && client.exchanges.release_failed(unheld).is_err());
    assert!(matches!(client.exchanges.responder_exchange(entry.msgid), table::ResponderLookup::Unknown));
    assert!(client.take_peer_quick_modes().is_empty());
    let mut entropy = Counting::new(0xC201);
    assert!(matches!(answer_quick(&client, &mut entropy, &Tunnel::of(vec![plain()]).expect(at), &entry), QuickVerdict::Silent(Silence::Passive)));
    assert_eq!((entropy.fills, reads.load(Ordering::Relaxed), client.exchanges.ids_held()), (0, 0, 0));
}
