//! The wait of a Quick Mode of ours for its message 2 once the exchange table is on
//! ([`quick_exchange_enabled`], [`await_quick_reply_enabled`]), and the passive wait it leaves as it
//! was, against a gateway played in the reader's own thread: every datagram the client sends goes to
//! the gateway, whose answers are queued and read in order, and a read with nothing queued times out
//! at once. No network, no thread, no time waited: the table's clock is the only clock that moves.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::*;
use crate::entropy::SeedEntropy;
use crate::ikev1::exchange::{ExchangeTable, PeerEvent};
use crate::ikev1::informational::tests::phase1_pair;
use crate::ikev1::informational::{notify_type, parse_notify, ChildFamily, Liveness};
use crate::ikev1::isakmp::flags;
use crate::ikev1::msgid::Admission;
use crate::ikev1::phase1::TestClock;
use crate::ikev1::{classify_peer_deletes, DeleteVerdict, FamilySpis, Generation, SpiState};

/// The timeout the worker gives a Quick Mode of ours.
const TIMEOUT: Duration = Duration::from_secs(5);

/// The gateway's address as these tests give it (TEST-NET-1, RFC 5737): nothing is sent anywhere.
fn gateway_addr() -> SocketAddr {
    "192.0.2.1:500".parse().unwrap()
}

/// What the gateway read of our message 1, and its genuine answer.
struct Offer {
    msgid: u32,
    /// The SPI we offered: our inbound SPI of the new SA, the SPI a refusal of the offer names.
    spi: u32,
    /// Our message 1, as sent.
    qm1: Vec<u8>,
    /// The gateway's genuine message 2, which it sends after what it sends first.
    qm2: Vec<u8>,
}

/// What the gateway sends before its genuine message 2, for our message 1: `Some(datagrams)`, and then
/// its message 2; `None`, nothing at all.
type Before<'a> = Box<dyn FnMut(&Phase1State, &mut SeedEntropy, &Offer) -> Option<Vec<Vec<u8>>> + 'a>;

/// The gateway's half of one ISAKMP SA, behind an `IkeSocket` the client sends to and reads from.
struct Gateway<'a> {
    st: Phase1State,
    entropy: RefCell<SeedEntropy>,
    before: RefCell<Before<'a>>,
    /// The Quick Modes of ours it answered: their Message ID, its responder and its message 2.
    answered: RefCell<Vec<(u32, QuickResponder, Vec<u8>)>>,
    /// How many of our messages 3 it verified.
    completed: Cell<usize>,
    queued: RefCell<VecDeque<Vec<u8>>>,
    received: RefCell<Vec<Vec<u8>>>,
    /// Every send of the client fails (after it is recorded).
    sends_fail: bool,
}

impl<'a> Gateway<'a> {
    fn new(st: Phase1State, before: impl FnMut(&Phase1State, &mut SeedEntropy, &Offer) -> Option<Vec<Vec<u8>>> + 'a) -> Self {
        Self {
            st,
            entropy: RefCell::new(SeedEntropy::new(0x6A7E)),
            before: RefCell::new(Box::new(before)),
            answered: RefCell::default(),
            completed: Cell::new(0),
            queued: RefCell::default(),
            received: RefCell::default(),
            sends_fail: false,
        }
    }


    fn received(&self) -> Vec<Vec<u8>> {
        self.received.borrow().clone()
    }

    /// The exchange type of every datagram it received, in order.
    fn received_types(&self) -> Vec<u8> {
        self.received.borrow().iter().map(|datagram| IsakmpHeader::parse(datagram).unwrap().exchange_type).collect()
    }

    /// The messages 2 it sent, in order.
    fn messages_2(&self) -> Vec<Vec<u8>> {
        self.answered.borrow().iter().map(|(_, _, qm2)| qm2.clone()).collect()
    }

    fn queue(&self, datagram: Vec<u8>) {
        self.queued.borrow_mut().push_back(datagram);
    }

    /// What the gateway does with a datagram of ours: a Quick Mode message under an id it answered is
    /// our message 3 (verified and counted) or a copy of our message 1 (nothing); one under a new id is
    /// our message 1, answered as `before` says.
    fn hear(&self, datagram: &[u8]) {
        let Ok(header) = IsakmpHeader::parse(datagram) else { return };
        if header.exchange_type != exchange::QUICK {
            return;
        }
        let msgid = header.message_id;
        if let Some((_, responder, _)) = self.answered.borrow().iter().find(|(id, ..)| *id == msgid) {
            if responder.clone().complete(datagram).is_ok() {
                self.completed.set(self.completed.get() + 1);
            }
            return;
        }
        let mut entropy = self.entropy.borrow_mut();
        let (qm2, responder) = respond_quick(&self.st, datagram, &mut *entropy).expect("the gateway takes our message 1");
        let offer = Offer { msgid, spi: responder.peer_spi, qm1: datagram.to_vec(), qm2: qm2.clone() };
        let Some(first) = (self.before.borrow_mut())(&self.st, &mut entropy, &offer) else { return };
        let mut queued = self.queued.borrow_mut();
        queued.extend(first);
        queued.push_back(qm2.clone());
        self.answered.borrow_mut().push((msgid, responder, qm2));
    }
}

impl IkeSocket for Gateway<'_> {
    fn send_to(&self, buf: &[u8], dest: SocketAddr) -> io::Result<usize> {
        assert_eq!(dest, gateway_addr());
        self.received.borrow_mut().push(buf.to_vec());
        if self.sends_fail {
            return Err(io::ErrorKind::ConnectionRefused.into());
        }
        self.hear(buf);
        Ok(buf.len())
    }
    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        assert!(dur.is_some_and(|dur| !dur.is_zero()), "a read is always bounded, never by nothing: {dur:?}");
        Ok(())
    }
    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let Some(datagram) = self.queued.borrow_mut().pop_front() else { return Err(io::ErrorKind::WouldBlock.into()) };
        buf[..datagram.len()].copy_from_slice(&datagram);
        Ok((datagram.len(), gateway_addr()))
    }
}

/// A client and a gateway of one ISAKMP SA, the client's exchange table telling the time by the clock
/// returned, and on when `enabled`.
fn pair(enabled: bool) -> (Phase1State, Phase1State, TestClock) {
    let (mut client, gateway) = phase1_pair();
    let clock = TestClock::new();
    client.exchanges = clock.exchanges();
    if enabled {
        client.enable_gateway_quick_mode();
    }
    (client, gateway, clock)
}

/// Our Quick Mode for a new IPv4 CHILD SA (no trailing Delete), drawing from `seed`.
fn create(client: &Phase1State, gateway: &Gateway<'_>, seed: u64, timeout: Duration) -> Result<(RekeyedChild, SaLifetime), DriverError> {
    let ts = ([10, 212, 134, 202], [255, 255, 255, 255]);
    create_child_with_lifetime(gateway, client, &mut SeedEntropy::new(seed), gateway_addr(), SkCipher::Aes256Gcm, None, ts, ([0; 4], [0; 4]), 1800, timeout)
}

/// How a Quick Mode of ours ended.
#[derive(Debug, PartialEq, Eq)]
enum Ended {
    Completed,
    Refused(u16),
    TornDown,
    TimedOut,
    Other(String),
}

fn ended<T>(result: &Result<T, DriverError>) -> Ended {
    match result {
        Ok(_) => Ended::Completed,
        Err(DriverError::Ike(IkeError::PeerRejected { notify_type, .. })) => Ended::Refused(*notify_type),
        Err(DriverError::Ike(IkeError::PeerTornDown)) => Ended::TornDown,
        Err(DriverError::Ike(IkeError::Crypto(m))) if m.contains("timed out") => Ended::TimedOut,
        Err(e) => Ended::Other(format!("{e:?}")),
    }
}

/// An Informational of the gateway's under `msgid`: HASH(1) over `payloads` (RFC 2409 §5.7).
fn informational_under(gw: &Phase1State, msgid: u32, payloads: &[(u8, Vec<u8>)]) -> Vec<u8> {
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

/// An Informational of the gateway's under an id of its own.
fn informational(gw: &Phase1State, entropy: &mut SeedEntropy, payloads: &[(u8, Vec<u8>)]) -> Vec<u8> {
    informational_under(gw, gw.fresh_message_id(MidKind::Informational, entropy).unwrap(), payloads)
}

/// A Delete payload naming the ESP SPIs `spis` (RFC 2408 §3.15).
fn esp_delete(spis: &[u32]) -> (u8, Vec<u8>) {
    let mut body = IPSEC_DOI.to_be_bytes().to_vec();
    body.extend_from_slice(&[protocol::ESP, 4]);
    body.extend_from_slice(&(spis.len() as u16).to_be_bytes());
    for spi in spis {
        body.extend_from_slice(&spi.to_be_bytes());
    }
    (payload::DELETE, body)
}

/// A Delete payload naming the ISAKMP SA, by its cookie pair.
fn isakmp_delete(gw: &Phase1State) -> (u8, Vec<u8>) {
    let mut body = IPSEC_DOI.to_be_bytes().to_vec();
    body.extend_from_slice(&[protocol::ISAKMP, 16, 0, 1]);
    body.extend_from_slice(&gw.cky_i);
    body.extend_from_slice(&gw.cky_r);
    (payload::DELETE, body)
}

/// A Notify payload of `msg_type` for `protocol_id`, naming `spi` (RFC 2408 §3.14).
fn error_notify(protocol_id: u8, spi: &[u8], msg_type: u16) -> (u8, Vec<u8>) {
    let mut body = IPSEC_DOI.to_be_bytes().to_vec();
    body.extend_from_slice(&[protocol_id, spi.len() as u8]);
    body.extend_from_slice(&msg_type.to_be_bytes());
    body.extend_from_slice(spi);
    (payload::NOTIFY, body)
}

/// A Quick Mode message 1 the gateway starts for an IPv4 CHILD SA, and its Message ID.
fn gateway_qm1(gw: &Phase1State, entropy: &mut SeedEntropy) -> (Vec<u8>, u32) {
    let ts = ([10, 9, 0, 0], [255, 255, 0, 0]);
    let qm1 = initiate_quick(gw, entropy, SkCipher::Aes256Gcm, ts, ([0; 4], [0; 4]), 3600).unwrap().0;
    let msgid = IsakmpHeader::parse(&qm1).unwrap().message_id;
    (qm1, msgid)
}

/// A bare header under our cookies and `msgid`, ENCRYPTION set and a HASH announced: what anyone who
/// read the cleartext of our message 1 can send.
fn bare_header(gw: &Phase1State, msgid: u32) -> Vec<u8> {
    IsakmpHeader {
        init_cookie: gw.cky_i,
        resp_cookie: gw.cky_r,
        next_payload: payload::HASH,
        version: IsakmpHeader::VERSION_1_0,
        exchange_type: exchange::QUICK,
        flags: flags::ENCRYPTION,
        message_id: msgid,
        length: IsakmpHeader::LEN as u32,
    }
    .to_bytes()
}

/// The ESP SPIs the Deletes among `events` name, in order.
fn esp_named(events: &[PeerEvent]) -> Vec<u32> {
    events
        .iter()
        .filter_map(|event| match event {
            PeerEvent::Delete { protocol: protocol::ESP, spi, .. } => spi.esp(),
            _ => None,
        })
        .collect()
}

/// What an event says, without its time: `("Delete" or "Notify", Notify type, Protocol-Id, ESP SPI)`.
type Fact = (&'static str, u16, u8, Option<u32>);

fn facts(events: &[PeerEvent]) -> Vec<Fact> {
    events
        .iter()
        .map(|event| match event {
            PeerEvent::Delete { protocol, spi, .. } => ("Delete", 0, *protocol, spi.esp()),
            PeerEvent::ErrorNotify { msg_type, protocol, spi, .. } => ("Notify", *msg_type, *protocol, spi.esp()),
        })
        .collect()
}

/// The state of the client's record of our Quick Mode `msgid`.
fn state_of(client: &Phase1State, msgid: u32) -> Option<MidState> {
    client.exchanges.id_record(msgid).map(|record| record.state)
}

/// The Message ID of a datagram.
fn msgid_of(datagram: &[u8]) -> u32 {
    IsakmpHeader::parse(datagram).unwrap().message_id
}

const Q: u8 = exchange::QUICK;
const I: u8 = exchange::INFORMATIONAL;

// ---- Nothing is lost while we wait ----

/// Every Delete the gateway sends while our Quick Mode waits for its message 2 -- one SPI, several in
/// one payload, several payloads, in whatever order, in several messages -- is in the mailbox
/// afterwards, in the order it was named, and the wait still takes the real message 2 and completes.
#[test]
fn every_delete_read_while_our_quick_mode_waits_is_kept_in_order_and_the_answer_still_completes_it() {
    let (a, b, c) = (0x0A0A_0001, 0x0B0B_0002, 0x0C0C_0003);
    type Case = (&'static str, Vec<Vec<Vec<u32>>>, Vec<u32>);
    let cases: Vec<Case> = vec![
        ("one SPI", vec![vec![vec![a]]], vec![a]),
        ("several SPIs in one payload", vec![vec![vec![a, b, c]]], vec![a, b, c]),
        ("two payloads in one message", vec![vec![vec![a], vec![b]]], vec![a, b]),
        ("two payloads the other way round", vec![vec![vec![b], vec![a]]], vec![b, a]),
        ("two messages", vec![vec![vec![c]], vec![vec![a, b]]], vec![c, a, b]),
    ];
    for (name, messages, kept) in cases {
        let (client, gw_st, _clock) = pair(true);
        let gateway = Gateway::new(gw_st, move |gw, e, _| {
            Some(messages.iter().map(|payloads| informational(gw, e, &payloads.iter().map(|spis| esp_delete(spis)).collect::<Vec<_>>())).collect())
        });
        let got = create(&client, &gateway, 0xC4B1, TIMEOUT);
        assert_eq!(ended(&got), Ended::Completed, "{name}");
        assert_eq!(esp_named(&client.drain_peer_events()), kept, "{name}");
        assert_eq!(gateway.completed.get(), 1, "{name}: our message 3 reached the gateway and verified");
        assert_eq!(gateway.received_types(), [Q, Q], "{name}: message 1 once and message 3, nothing else");
    }
}

/// A Delete of the ISAKMP SA read while our Quick Mode waits ends it as torn down, as it always did --
/// also when it is the second Delete payload of its message -- and is in the mailbox with whatever its
/// message named before it.
#[test]
fn an_isakmp_delete_read_while_our_quick_mode_waits_ends_it_as_torn_down_and_is_kept() {
    let esp = 0x0E0E_0001;
    let cases: [(&str, bool, Vec<Fact>); 2] = [
        ("alone", false, vec![("Delete", 0, protocol::ISAKMP, None)]),
        ("after an ESP Delete in its message", true, vec![("Delete", 0, protocol::ESP, Some(esp)), ("Delete", 0, protocol::ISAKMP, None)]),
    ];
    for (name, esp_first, kept) in cases {
        let (client, gw_st, _clock) = pair(true);
        let gateway = Gateway::new(gw_st, move |gw, e, _| {
            let mut payloads = if esp_first { vec![esp_delete(&[esp])] } else { vec![] };
            payloads.push(isakmp_delete(gw));
            Some(vec![informational(gw, e, &payloads)])
        });
        let got = create(&client, &gateway, 0xC4B2, TIMEOUT);
        assert_eq!(ended(&got), Ended::TornDown, "{name}");
        assert_eq!(facts(&client.drain_peer_events()), kept, "{name}");
        assert_eq!(gateway.received_types(), [Q], "{name}: no message 3");
    }
}

/// A Quick Mode the gateway starts while ours waits goes to the inbox: it is not answered from inside
/// our exchange (nothing we send carries its Message ID), and ours completes.
#[test]
fn a_gateway_quick_mode_started_while_ours_waits_is_kept_for_later_and_not_answered() {
    let (client, gw_st, _clock) = pair(true);
    let theirs = Rc::new(Cell::new(0));
    let seen = theirs.clone();
    let gateway = Gateway::new(gw_st, move |gw, e, _| {
        let (qm1, msgid) = gateway_qm1(gw, e);
        seen.set(msgid);
        Some(vec![qm1])
    });
    assert_eq!(ended(&create(&client, &gateway, 0xC4B3, TIMEOUT)), Ended::Completed);
    let kept = client.take_peer_quick_modes();
    assert_eq!(kept.iter().map(|quick| quick.msgid).collect::<Vec<_>>(), [theirs.get()]);
    assert_eq!(gateway.received_types(), [Q, Q]);
    assert!(gateway.received().iter().all(|datagram| msgid_of(datagram) != theirs.get()), "nothing we sent answers it");
    assert!(matches!(state_of(&client, theirs.get()), Some(MidState::Active { .. })), "its exchange is in progress for whoever takes it up");
}

/// A Delete read while our rekey waits is kept raw and read against the SPIs held when the mailbox is
/// drained: a Delete of the SA being replaced, drained after the rekey, names a retired SA (no
/// teardown); the same Delete drained when the rekey failed names the SA still in use.
#[test]
fn a_delete_read_while_our_rekey_waits_is_read_against_the_spis_held_when_it_is_drained() {
    let in_use = 0x0D0D_0001;
    // The rekey completes: the SA it replaces is retired when the mailbox is drained.
    let (client, gw_st, _clock) = pair(true);
    let gateway = Gateway::new(gw_st, move |gw, e, _| Some(vec![informational(gw, e, &[esp_delete(&[in_use])])]));
    let ts = ([10, 212, 134, 202], [255, 255, 255, 255]);
    let rekeyed = rekey_child_with_lifetime(
        &gateway, &client, &mut SeedEntropy::new(0xC4B4), gateway_addr(), SkCipher::Aes256Gcm, None, ts, ([0; 4], [0; 4]), 1800, TIMEOUT, 0x5150_0001,
    );
    let (child, _lifetime) = rekeyed.expect("the rekey completes");
    assert_eq!(gateway.received_types(), [Q, Q, I], "message 1, message 3 and our Delete of the SA replaced");
    let events = client.drain_peer_events();
    let retired = [in_use];
    let after = SpiState { primary: FamilySpis { current_peer_spi: Some(child.peer_spi), pending_peer_spi: None, retired_peer_spis: &retired }, ..SpiState::default() };
    assert_eq!(classify_peer_deletes(&events, &after), [DeleteVerdict::Child { family: ChildFamily::Primary, generation: Generation::Retired, spi: in_use }]);
    let before = SpiState { primary: FamilySpis { current_peer_spi: Some(in_use), ..FamilySpis::default() }, ..SpiState::default() };
    assert_eq!(
        classify_peer_deletes(&events, &before),
        [DeleteVerdict::Child { family: ChildFamily::Primary, generation: Generation::Current, spi: in_use }],
        "the same event read against the SPIs before the rekey: the event itself carries no verdict"
    );

    // The rekey is refused: the SA in use stays the one in use, and its Delete names it.
    let (client, gw_st, _clock) = pair(true);
    let gateway = Gateway::new(gw_st, move |gw, e, offer| {
        Some(vec![informational(gw, e, &[esp_delete(&[in_use])]), informational(gw, e, &[error_notify(protocol::ESP, &offer.spi.to_be_bytes(), 14)])])
    });
    let refused = rekey_child_with_lifetime(
        &gateway, &client, &mut SeedEntropy::new(0xC4B5), gateway_addr(), SkCipher::Aes256Gcm, None, ts, ([0; 4], [0; 4]), 1800, TIMEOUT, 0x5150_0001,
    );
    assert_eq!(ended(&refused), Ended::Refused(14));
    let events = client.drain_peer_events();
    assert_eq!(classify_peer_deletes(&events, &before), [DeleteVerdict::Child { family: ChildFamily::Primary, generation: Generation::Current, spi: in_use }]);
}

/// An R-U-THERE read while our Quick Mode waits is answered at once with its R-U-THERE-ACK (RFC 3706
/// §6.1), each of them, and the wait goes on to its answer.
#[test]
fn an_r_u_there_read_while_our_quick_mode_waits_is_answered_and_the_wait_goes_on() {
    let (client, gw_st, _clock) = pair(true);
    let gateway = Gateway::new(gw_st, |gw, e, _| {
        Some(vec![informational::build_r_u_there(gw, e, 0x0D9D_0001).unwrap(), informational::build_r_u_there(gw, e, 0x0D9D_0002).unwrap()])
    });
    assert_eq!(ended(&create(&client, &gateway, 0xC4B6, TIMEOUT)), Ended::Completed);
    assert_eq!(gateway.received_types(), [Q, I, I, Q], "message 1, two ACKs, message 3");
    let acked: Vec<(u16, Vec<u8>)> = gateway.received()[1..3]
        .iter()
        .map(|ack| {
            let msgid = msgid_of(ack);
            let iv0 = crypto1::phase2_iv(gateway.st.prf, &gateway.st.phase1_iv, msgid, gateway.st.enc_block);
            let (_h, payloads, _next) =
                phase2::parse_encrypted(ack, gateway.st.prf, &gateway.st.skeyid_a, &gateway.st.enc_key, gateway.st.enc_block, &iv0).unwrap();
            let notify = payloads.iter().find(|p| p.payload_type == payload::NOTIFY).unwrap();
            let (msg_type, data) = parse_notify(&notify.data).unwrap();
            (msg_type, data.to_vec())
        })
        .collect();
    assert_eq!(
        acked,
        [(notify_type::R_U_THERE_ACK, 0x0D9D_0001u32.to_be_bytes().to_vec()), (notify_type::R_U_THERE_ACK, 0x0D9D_0002u32.to_be_bytes().to_vec())]
    );
}

// ---- HASH(2) before the verdict ----

/// The real message 2 of `offer`, decrypted and encrypted again under the same IV with one octet of its
/// HASH payload changed: it decrypts as message 2 does, and only its HASH(2) is wrong.
fn with_hash_2_changed(gw: &Phase1State, offer: &Offer) -> Vec<u8> {
    let iv1 = crypto1::next_iv(&offer.qm1[IsakmpHeader::LEN..], gw.enc_block);
    let (_header, payloads, _next) = phase2::decrypt_payloads(&offer.qm2, &gw.enc_key, gw.enc_block, &iv1).unwrap();
    let mut pairs: Vec<(u8, Vec<u8>)> = payloads.into_iter().map(|p| (p.payload_type, p.data)).collect();
    assert_eq!(pairs[0].0, payload::HASH);
    pairs[0].1[0] ^= 0x01;
    phase2::encrypt_payloads(qm_header(gw.cky_i, gw.cky_r, offer.msgid), &gw.enc_key, gw.enc_block, &iv1, &pairs).unwrap().0
}

/// A Quick Mode message under our Message ID that does not authenticate as its message 2 -- a bare
/// header, the real message 2 with one octet changed, a message 2 that decrypts but whose HASH(2) is
/// wrong -- is dropped and counted, and the wait goes on to the real message 2, which completes the
/// exchange (no retransmission was needed: the forgery ended nothing).
#[test]
fn a_message_under_our_id_that_fails_hash_2_is_dropped_and_the_real_answer_completes_the_exchange() {
    type Forge = fn(&Phase1State, &Offer) -> Vec<u8>;
    let cases: [(&str, Forge); 3] = [
        ("a bare header", |gw, offer| bare_header(gw, offer.msgid)),
        ("message 2 with an octet of its last block changed", |_, offer| {
            let mut changed = offer.qm2.clone();
            let last = changed.len() - 1;
            changed[last] ^= 0x01;
            changed
        }),
        ("message 2 with its HASH(2) changed", with_hash_2_changed),
    ];
    for (name, forge) in cases {
        let (client, gw_st, _clock) = pair(true);
        let gateway = Gateway::new(gw_st, move |gw, _, offer| Some(vec![forge(gw, offer), forge(gw, offer)]));
        assert_eq!(ended(&create(&client, &gateway, 0xC4B7, TIMEOUT)), Ended::Completed, "{name}");
        assert_eq!(client.exchanges.unauthenticated_replies(), 2, "{name}: both copies counted");
        assert_eq!(gateway.received_types(), [Q, Q], "{name}: message 1 once, message 3");
        assert_eq!(gateway.completed.get(), 1, "{name}");
    }
}

// ---- Error Notifies: attributed ----

/// An error Notify about our Quick Mode ends its wait as refused, as it always did, however the gateway
/// names it: by the exchange's Message ID or by the SPI we offered while a gateway Quick Mode is in
/// progress too, or with nothing when ours is the only exchange in progress. No message 3, the
/// exchange is over in the ledger, and the Notify is in the mailbox.
#[test]
fn an_error_notify_about_our_quick_mode_ends_its_wait_as_refused() {
    type Refusal = fn(&Phase1State, &mut SeedEntropy, &Offer) -> Vec<Vec<u8>>;
    let cases: [(&str, Refusal, u16); 3] = [
        ("under its Message ID", |gw, e, offer| vec![gateway_qm1(gw, e).0, informational_under(gw, offer.msgid, &[error_notify(protocol::ESP, &[0x0B, 0xAD, 0, 1], 14)])], 14),
        ("naming the SPI we offered", |gw, e, offer| vec![gateway_qm1(gw, e).0, informational(gw, e, &[error_notify(protocol::ESP, &offer.spi.to_be_bytes(), 18)])], 18),
        ("the only exchange in progress", |gw, e, _| vec![informational(gw, e, &[error_notify(protocol::ISAKMP, &[], 16)])], 16),
    ];
    for (name, refusal, notify) in cases {
        let (client, gw_st, _clock) = pair(true);
        let gateway = Gateway::new(gw_st, move |gw, e, offer| Some(refusal(gw, e, offer)));
        let got = create(&client, &gateway, 0xC4B8, TIMEOUT);
        assert_eq!(ended(&got), Ended::Refused(notify), "{name}");
        if let Err(DriverError::Ike(IkeError::PeerRejected { name: label, .. })) = &got {
            assert_eq!(*label, informational::error_notify_name(notify), "{name}: the name the passive wait gives it");
        }
        assert_eq!(gateway.received_types(), [Q], "{name}: no message 3");
        assert_eq!(state_of(&client, msgid_of(&gateway.received()[0])), Some(MidState::Done), "{name}");
        assert!(facts(&client.drain_peer_events()).iter().any(|fact| fact.0 == "Notify" && fact.1 == notify), "{name}: kept in the mailbox");
    }
}

/// Ids the client's ledger holds before our Quick Mode starts, for an error Notify to come under.
#[derive(Clone, Copy)]
struct Held {
    /// One of our Informationals.
    our_informational: u32,
    /// A gateway Quick Mode that is over.
    gateway_over: u32,
}

/// An error Notify about another exchange, or about none that can be told, does not end our wait: one
/// naming a responder exchange's inbound SPI is recorded on it; one under the Message ID of a gateway
/// Quick Mode in progress is that exchange's; one with no discriminator while two exchanges are in
/// progress, or under one of our own Informational ids, is ignored; and so is one that names something
/// no exchange in progress is, though ours is the only one: an SPI of nobody's -- INVALID-SPI for an SA
/// retired, say --, or the Message ID of a gateway Quick Mode that is over. Every one is in the mailbox,
/// and our Quick Mode completes.
#[test]
fn an_error_notify_about_another_exchange_or_none_leaves_our_wait_to_its_answer() {
    let (responder, responder_spi) = (0x4000_0002, 0x7E57_0001);
    type Notice = fn(&Phase1State, &mut SeedEntropy, &Offer, Held) -> Vec<Vec<u8>>;
    let cases: [(&str, Notice, u16); 6] = [
        ("a responder exchange's inbound SPI", |gw, e, _, _| vec![informational(gw, e, &[error_notify(protocol::ESP, &0x7E57_0001u32.to_be_bytes(), 14)])], 14),
        (
            "under a gateway Quick Mode's Message ID",
            |gw, e, _, _| {
                let (qm1, theirs) = gateway_qm1(gw, e);
                vec![qm1, informational_under(gw, theirs, &[error_notify(protocol::ISAKMP, &[], 14)])]
            },
            14,
        ),
        ("nothing to tell it by, two exchanges in progress", |gw, e, _, _| vec![gateway_qm1(gw, e).0, informational(gw, e, &[error_notify(protocol::ISAKMP, &[], 14)])], 14),
        ("under one of our Informational ids", |gw, _, _, held| vec![informational_under(gw, held.our_informational, &[error_notify(protocol::ISAKMP, &[], 14)])], 14),
        (
            "INVALID-SPI naming an SA retired, ours the only exchange in progress",
            |gw, e, _, _| vec![informational(gw, e, &[error_notify(protocol::ESP, &0x0DEA_D001u32.to_be_bytes(), 11)])],
            11,
        ),
        (
            "under the Message ID of a gateway Quick Mode that is over, ours the only exchange in progress",
            |gw, _, _, held| vec![informational_under(gw, held.gateway_over, &[error_notify(protocol::ISAKMP, &[], 14)])],
            14,
        ),
    ];
    for (name, notice, notify) in cases {
        let (client, gw_st, clock) = pair(true);
        let now = clock.now();
        client.exchanges.register_responder(responder, responder_spi);
        if name.starts_with("a responder") {
            client.exchanges.record_authenticated(responder, MidKind::Quick, [3; 32], now, now + Duration::from_secs(8));
        }
        let gateway_over = 0x4000_0004;
        assert_eq!(client.exchanges.record_authenticated(gateway_over, MidKind::Quick, [4; 32], now, now + Duration::from_secs(8)), Admission::New);
        assert!(client.exchanges.finish(gateway_over, now, MidEnd::Done));
        let held = Held { our_informational: client.fresh_message_id(MidKind::Informational, &mut SeedEntropy::new(0x1D)).unwrap(), gateway_over };
        let gateway = Gateway::new(gw_st, move |gw, e, offer| Some(notice(gw, e, offer, held)));
        assert_eq!(ended(&create(&client, &gateway, 0xC4B9, TIMEOUT)), Ended::Completed, "{name}");
        assert_eq!(gateway.received_types(), [Q, Q], "{name}");
        assert!(facts(&client.drain_peer_events()).iter().any(|fact| fact.0 == "Notify" && fact.1 == notify), "{name}: kept in the mailbox");
        let recorded = client.exchanges.responder_rejected(responder);
        assert_eq!(recorded, name.starts_with("a responder").then_some(14), "{name}: recorded on the responder exchange it names, and only there");
    }
}

/// A refusal of a Quick Mode of ours that names nothing -- Protocol-Id ISAKMP, under a Message ID of the
/// gateway's own -- ends it, since it was the only exchange in progress. Read again while our next Quick
/// Mode waits, alone too -- the same datagram (a copy, or a replay of it on the path), or another message
/// under its Message ID -- it ends nothing: it is about what was in progress when it first came, and the
/// next Quick Mode completes.
#[test]
fn a_refusal_read_again_while_our_next_quick_mode_waits_does_not_refuse_it() {
    type Again = fn(&Phase1State, &[u8]) -> Vec<u8>;
    let cases: [(&str, Again); 2] = [
        ("the same datagram", |_, refusal| refusal.to_vec()),
        ("another message under its Message ID", |gw, refusal| informational_under(gw, msgid_of(refusal), &[error_notify(protocol::ISAKMP, &[], 16)])),
    ];
    for (name, again) in cases {
        let (client, gw_st, _clock) = pair(true);
        let mut refusal: Option<Vec<u8>> = None;
        let gateway = Gateway::new(gw_st, move |gw, e, _| {
            let sent = match refusal.as_deref() {
                Some(first) => again(gw, first),
                None => {
                    let first = informational(gw, e, &[error_notify(protocol::ISAKMP, &[], 14)]);
                    refusal = Some(first.clone());
                    first
                }
            };
            Some(vec![sent])
        });
        assert_eq!(ended(&create(&client, &gateway, 0xC4C1, TIMEOUT)), Ended::Refused(14), "{name}: the first");
        // The gateway's message 2 for the refused one never comes.
        gateway.queued.borrow_mut().clear();
        assert_eq!(ended(&create(&client, &gateway, 0xC4C2, TIMEOUT)), Ended::Completed, "{name}: the next");
        assert_eq!(gateway.received_types(), [Q, Q, Q], "{name}: message 1 of each, message 3 of the next");
        assert_eq!(gateway.completed.get(), 1, "{name}");
    }
}

// ---- The ledger record of our Quick Mode ----

/// Our Quick Mode's Message ID is in progress in the ledger while the exchange waits, and over (`Done`)
/// once it ends, however it ends.
#[test]
fn our_quick_mode_is_in_progress_while_it_waits_and_over_however_it_ends() {
    #[derive(Clone, Copy)]
    enum Gw {
        Answers,
        Refuses,
        TearsDown,
        Silent,
        Unreachable,
    }
    let cases = [
        ("answered", Gw::Answers, Ended::Completed),
        ("refused", Gw::Refuses, Ended::Refused(14)),
        ("torn down", Gw::TearsDown, Ended::TornDown),
        ("timed out", Gw::Silent, Ended::TimedOut),
        ("unable to send", Gw::Unreachable, Ended::Other("Io(Kind(ConnectionRefused))".into())),
    ];
    for (name, kind, want) in cases {
        let (client, gw_st, _clock) = pair(true);
        let table = client.exchanges.clone();
        let waits = Rc::new(Cell::new(0));
        let counted = waits.clone();
        let mut gateway = Gateway::new(gw_st, move |gw, e, offer| {
            assert!(matches!(table.id_record(offer.msgid).map(|r| r.state), Some(MidState::Active { .. })), "{name}: in progress while it waits");
            counted.set(counted.get() + 1);
            match kind {
                Gw::Answers => Some(vec![]),
                Gw::Refuses => Some(vec![informational(gw, e, &[error_notify(protocol::ISAKMP, &[], 14)])]),
                Gw::TearsDown => Some(vec![informational(gw, e, &[isakmp_delete(gw)])]),
                Gw::Silent | Gw::Unreachable => None,
            }
        });
        gateway.sends_fail = matches!(kind, Gw::Unreachable);
        let got = create(&client, &gateway, 0xC4BA, TIMEOUT);
        assert_eq!(ended(&got), want, "{name}");
        let msgid = msgid_of(&gateway.received()[0]);
        assert_eq!(state_of(&client, msgid), Some(MidState::Done), "{name}");
        assert_eq!(waits.get() > 0, !matches!(kind, Gw::Unreachable), "{name}: the gateway saw our message 1");
    }
}

/// A caller whose patience is longer than the ledger's own deadline for our Quick Mode keeps it in
/// progress for as long as it waits -- three timeouts and `LEDGER_MARGIN` -- and a shorter patience
/// leaves the ledger's deadline as it was (never shortened). A message 2 read after the ledger's own
/// deadline (the table's clock moved 26 s while the gateway answered) still completes the exchange of
/// the longer patience; with the worker's patience (three 5 s timeouts) the same clock leaves the
/// exchange's id over, and its message 2 is dropped: the wait reads by the ledger, which a longer
/// patience has to move.
#[test]
fn a_patience_longer_than_the_ledgers_deadline_keeps_our_quick_mode_in_progress_as_long_as_it_waits() {
    use crate::ikev1::msgid::LOCAL_QUICK_DEADLINE;
    let secs = Duration::from_secs;
    let cases = [
        (secs(1), secs(0), Ended::Completed, LOCAL_QUICK_DEADLINE),
        (secs(10), secs(26), Ended::Completed, secs(30) + LEDGER_MARGIN),
        (TIMEOUT, secs(26), Ended::TimedOut, LOCAL_QUICK_DEADLINE),
    ];
    for (timeout, moved_by, want, in_progress_for) in cases {
        let (client, gw_st, clock) = pair(true);
        let (moved, table) = (clock.clone(), client.exchanges.clone());
        let started = clock.now();
        let seen = Rc::new(Cell::new(None));
        let deadline = seen.clone();
        let gateway = Gateway::new(gw_st, move |_, _, offer| {
            deadline.set(table.id_record(offer.msgid).map(|record| record.state));
            moved.advance(moved_by);
            Some(vec![])
        });
        assert_eq!(ended(&create(&client, &gateway, 0xC4BB, timeout)), want, "timeout {timeout:?}");
        assert_eq!(seen.get(), Some(MidState::Active { deadline: started + in_progress_for }), "timeout {timeout:?}: while it waits");
        assert_eq!(state_of(&client, msgid_of(&gateway.received()[0])), Some(MidState::Done), "timeout {timeout:?}");
    }
}

/// The recovery of a lost message 3 still works with the table on (RFC 2408 §3.1, Commit Bit NOTE): after
/// our Quick Mode completed, the gateway's repeat of its message 2 gets the same message 3 again, from a
/// liveness check and from the wait of our next Quick Mode, which then completes.
#[test]
fn a_lost_message_3_is_sent_again_after_the_exchange_and_while_the_next_one_waits() {
    let (client, gw_st, _clock) = pair(true);
    let first_qm2: Rc<RefCell<Vec<u8>>> = Rc::default();
    let repeat = first_qm2.clone();
    let gateway = Gateway::new(gw_st, move |_, _, _| Some(if repeat.borrow().is_empty() { vec![] } else { vec![repeat.borrow().clone()] }));
    assert_eq!(ended(&create(&client, &gateway, 0xC4BC, TIMEOUT)), Ended::Completed);
    let qm3 = gateway.received()[1].clone();
    *first_qm2.borrow_mut() = gateway.messages_2()[0].clone();

    gateway.queue(first_qm2.borrow().clone());
    let alive = informational::peek(&gateway, &client, &mut SeedEntropy::new(0x9E), gateway_addr(), Duration::from_millis(5), 0x5150_0001, None);
    assert_eq!(alive.unwrap(), Liveness::Alive);
    assert_eq!(gateway.received().last(), Some(&qm3), "a liveness check sends message 3 again");

    assert_eq!(ended(&create(&client, &gateway, 0xC4BD, TIMEOUT)), Ended::Completed);
    let received = gateway.received();
    assert_eq!(received.len(), 6, "message 1, 3; 3 again; message 1 of the next, 3 of the first again, 3 of the next");
    assert_eq!(received[4], qm3, "the next wait sends the first exchange's message 3 again");
    assert_eq!(gateway.completed.get(), 4, "every message 3 verified at the gateway");
}

// ---- The passive wait is the one there always was ----

/// While the table is passive -- every mode but the one that answers the gateway's Quick Modes -- the
/// wait is the one there always was, beside what the enabled one does with the same gateway:
/// - a bare header under our Message ID ends the passive wait as its answer, and the exchange fails;
///   the enabled wait drops it and completes;
/// - an ESP Delete read while waiting is dropped (nothing reaches the table); the enabled wait keeps it;
/// - an error Notify about nothing that can be told ends the passive wait as refused; the enabled wait
///   ignores it while a gateway Quick Mode is in progress too;
/// - a Delete of the ISAKMP SA in the second Delete payload of its message is not seen by the passive
///   wait, which only reads the first; the enabled wait ends as torn down.
///
/// The passive wait never reads the table's clock.
#[test]
fn a_passive_table_waits_as_it_always_did() {
    type Script = fn(&Phase1State, &mut SeedEntropy, &Offer) -> Vec<Vec<u8>>;
    let cases: [(&str, Script, Ended, Ended, usize); 4] = [
        (
            "a bare header under our id",
            |gw, _, offer| vec![bare_header(gw, offer.msgid)],
            Ended::Other("Ike(Crypto(\"CBC ciphertext not block-aligned\"))".into()),
            Ended::Completed,
            0,
        ),
        ("an ESP Delete", |gw, e, _| vec![informational(gw, e, &[esp_delete(&[0x0E5D_0001])])], Ended::Completed, Ended::Completed, 1),
        (
            "an error Notify about nothing that can be told",
            |gw, e, _| vec![gateway_qm1(gw, e).0, informational(gw, e, &[error_notify(protocol::ISAKMP, &[], 14)])],
            Ended::Refused(14),
            Ended::Completed,
            1,
        ),
        (
            "an ISAKMP Delete in the second Delete payload",
            |gw, e, _| vec![informational(gw, e, &[esp_delete(&[0x0E5D_0002]), isakmp_delete(gw)])],
            Ended::Completed,
            Ended::TornDown,
            2,
        ),
    ];
    for (name, script, passive, enabled, events) in cases {
        let clock_reads = Arc::new(AtomicUsize::new(0));
        for on in [false, true] {
            let (mut client, gw_st, _clock) = pair(false);
            let reads = clock_reads.clone();
            client.exchanges = ExchangeTable::with_clock(Box::new(move || {
                reads.fetch_add(1, Ordering::Relaxed);
                Instant::now()
            }));
            if on {
                client.enable_gateway_quick_mode();
            }
            let gateway = Gateway::new(gw_st, move |gw, e, offer| Some(script(gw, e, offer)));
            let got = create(&client, &gateway, 0xC4BE, TIMEOUT);
            if on {
                assert_eq!(ended(&got), enabled, "{name}: enabled");
                assert_eq!(client.drain_peer_events().len(), events, "{name}: enabled, the mailbox");
                assert!(clock_reads.load(Ordering::Relaxed) > 0, "{name}: an enabled table reads its clock");
            } else {
                assert_eq!(ended(&got), passive, "{name}: passive");
                assert_eq!(clock_reads.load(Ordering::Relaxed), 0, "{name}: a passive wait never reads the table's clock");
                client.enable_gateway_quick_mode();
                assert!(client.drain_peer_events().is_empty(), "{name}: nothing reached the table while it was passive");
                let sent_qm3 = gateway.received_types() == [Q, Q];
                assert_eq!(sent_qm3, passive == Ended::Completed, "{name}: passive, message 3 sent only when completed");
            }
        }
    }
}
