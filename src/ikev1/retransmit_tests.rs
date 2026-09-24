//! The initiator's handling of lost final messages and of duplicates (RFC 2408
//! §3.1 Commit-Bit NOTE, RFC 2409 §5) against a scripted gateway: the real
//! responder steps over one UDP socket, with a script deciding which datagrams
//! the gateway never sees, repeats, or sends twice.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::Duration;

use super::cfg;
use super::client::{Client, Established};
use super::informational::{self, Liveness};
use super::isakmp::{exchange, IsakmpHeader};
use super::payloads::Id;
use super::phase1::{respond_aggressive, respond_main, Ikev1ExchangeMode, Ikev1LocalAuth, InitiatorConfig, Phase1Config, Phase1State};
use super::quick::{self, respond_quick};
use super::xauth::test_gateway;
use crate::crypto::DhGroup;
use crate::entropy::SeedEntropy;
use crate::esp::ChildSa;
use crate::ikev2::natt::{unwrap_ike_4500, wrap_ike_4500};
use crate::ikev2::sk::SkCipher;
use crate::transport::DriverError;

const PSK: &[u8] = b"correct horse battery staple";
const XAUTH_MSGID: u32 = 0x1000_0001;

#[derive(Clone, Copy, Default)]
struct Script {
    main_mode: bool,
    xauth: bool,
    /// Every datagram the gateway sends goes out twice.
    duplicate_replies: bool,
    /// The gateway never sees the first Aggressive Mode message 3; its own
    /// timer fires and it repeats message 2 instead.
    lose_am_msg3: bool,
    /// The same for the XAUTH ACK, answered by repeating the SET.
    lose_xauth_ack: bool,
    /// The same for Quick Mode message 3, answered by repeating message 2.
    lose_qm_msg3: bool,
    /// After the handshake the gateway serves one more Quick Mode exchange (the
    /// client's rekey), and never sees its message 3 either.
    lose_rekey_msg3: bool,
    /// The gateway never sees the client's first Phase 1 message: the client
    /// answers its own timer with the same bytes, and only that reaches the gateway.
    lose_msg1: bool,
    /// Ahead of Quick Mode message 2 the gateway sends a datagram of the same
    /// ISAKMP SA and exchange type under another Message ID: not its reply, and
    /// not a message that would pass for it (its last byte differs).
    stray_quick_message_first: bool,
    /// After the SET the network delivers the gateway's XAUTH REQUEST once
    /// more, late: what the client meets while it waits for the Mode-Config reply.
    late_request_repeat: bool,
    /// The gateway also serves a Mode-Config round (after XAUTH, before Quick Mode).
    mode_cfg: bool,
    /// The client forces NAT traversal, so both sides float to port 4500 with
    /// Aggressive Mode's message 3 (RFC 3947 §5.3): the gateway has a socket on
    /// port 4500 of its own address, and everything from message 3 on goes
    /// there, with the non-ESP marker. A gateway that never saw message 3 has not
    /// floated yet, so what it repeats -- message 2 -- still goes to port 500.
    floated: bool,
}

struct Report {
    /// Each message the gateway never saw, as the client sent it again. The
    /// gateway takes nothing else for it: had the client rebuilt the message
    /// instead of sending the same bytes, the gateway would still be waiting.
    resent: Vec<Vec<u8>>,
    child: ChildSa,
    /// The CHILD SA of the rekey, when the script asked for one.
    rekeyed: Option<ChildSa>,
}

struct Gateway {
    sock: UdpSocket,
    /// Port 4500 of the gateway's address, for a `floated` script.
    natt: Option<UdpSocket>,
    /// Everything the gateway sends and reads now goes through `natt`.
    on_4500: bool,
    peer4500: Option<SocketAddr>,
    script: Script,
    entropy: SeedEntropy,
    peer: Option<SocketAddr>,
    resent: Vec<Vec<u8>>,
    /// Datagrams that came in while the gateway waited for something else (the
    /// first message of the next exchange, ahead of a retransmission), for the
    /// step that reads them.
    pending: Vec<Vec<u8>>,
    /// Set while the gateway waits for the message 3 it has not seen (see
    /// [`Self::send_repeat`]).
    repeats_on_500: bool,
}

impl Gateway {
    fn send(&self, msg: &[u8]) {
        self.send_once(msg);
        if self.script.duplicate_replies {
            self.send_once(msg);
        }
    }

    fn send_once(&self, msg: &[u8]) {
        match &self.natt {
            Some(natt) if self.on_4500 => {
                natt.send_to(&wrap_ike_4500(msg), self.peer4500.expect("the client has written to port 4500 by now")).unwrap();
            }
            _ => {
                self.sock.send_to(msg, self.peer.expect("the client has written by now")).unwrap();
            }
        }
    }

    /// The next datagram of `exchange_type`. Anything else is not for the
    /// state the gateway is in (a Quick Mode message before Phase 1 is
    /// complete, say) and is dropped, as a real gateway drops it.
    fn recv(&mut self, exchange_type: u8) -> Result<Vec<u8>, String> {
        if let Some(i) = self.pending.iter().position(|d| IsakmpHeader::parse(d).is_ok_and(|h| h.exchange_type == exchange_type)) {
            return Ok(self.pending.remove(i));
        }
        self.recv_socket(exchange_type)
    }

    /// [`Self::recv`] from the socket only, whatever is pending.
    fn recv_socket(&mut self, exchange_type: u8) -> Result<Vec<u8>, String> {
        let mut buf = [0u8; 8192];
        loop {
            let datagram = match &self.natt {
                Some(natt) if self.on_4500 => {
                    let (n, from) = natt.recv_from(&mut buf).map_err(|e| format!("gateway: waiting on port 4500 for exchange type {exchange_type}: {e}"))?;
                    self.peer4500.get_or_insert(from);
                    match unwrap_ike_4500(&buf[..n]) {
                        Some(message) => message.to_vec(),
                        None => continue,
                    }
                }
                _ => {
                    let (n, from) = self.sock.recv_from(&mut buf).map_err(|e| format!("gateway: waiting for exchange type {exchange_type}: {e}"))?;
                    self.peer.get_or_insert(from);
                    buf[..n].to_vec()
                }
            };
            if IsakmpHeader::parse(&datagram).is_ok_and(|h| h.exchange_type == exchange_type) {
                return Ok(datagram);
            }
        }
    }

    /// Like [`Self::recv`], but a repeat of `request` (the client's own
    /// retransmission) is answered again with `answer` instead of returned.
    fn recv_answering(&mut self, exchange_type: u8, request: &[u8], answer: &[u8]) -> Result<Vec<u8>, String> {
        loop {
            let datagram = self.recv(exchange_type)?;
            if datagram == request {
                self.send(answer);
                continue;
            }
            return Ok(datagram);
        }
    }

    /// The client's `lost` message never reaches the gateway; when the
    /// gateway's own timer fires it repeats `own`, and it waits for the client
    /// to send `lost` again, the same bytes. A repeat of `request` (the client's
    /// own retransmission) is answered with `own` again; anything else of that
    /// exchange type meanwhile (the first message of what follows) is kept for
    /// the next step.
    fn lose_then_repeat(&mut self, lost: Vec<u8>, own: &[u8], exchange_type: u8, request: &[u8]) -> Result<(), String> {
        self.send_repeat(own);
        loop {
            let datagram = self.recv_socket(exchange_type)?;
            if datagram == lost {
                self.resent.push(datagram);
                return Ok(());
            }
            if datagram == request {
                self.send_repeat(own);
            } else {
                self.pending.push(datagram);
            }
        }
    }

    /// The gateway repeating `own` because the client's answer never came. On
    /// the well-known port while the gateway has not floated: it has not seen
    /// the message that would have told it the client did (RFC 3947 §5.3).
    fn send_repeat(&self, own: &[u8]) {
        if self.natt.is_some() && self.on_4500 && self.repeats_on_500 {
            self.sock.send_to(own, self.peer.expect("the client has written by now")).unwrap();
        } else {
            self.send(own);
        }
    }

    fn serve(mut self) -> Result<Report, String> {
        let cfg = Phase1Config {
            local_auth: Ikev1LocalAuth::Psk(PSK.to_vec()),
            trusted_cas: Vec::new(),
            now_unix: 0,
            our_id: Id::ipv4([192, 168, 0, 1]),
        };
        let our_addr = self.sock.local_addr().unwrap();
        let st = if self.script.main_mode { self.main_mode(&cfg, our_addr)? } else { self.aggressive_mode(&cfg, our_addr)? };
        if self.script.xauth {
            self.xauth(&st)?;
        }
        if self.script.mode_cfg {
            self.mode_cfg(&st)?;
        }
        let child = self.quick_mode(&st, self.script.lose_qm_msg3)?;
        let rekeyed = if self.script.lose_rekey_msg3 { Some(self.quick_mode(&st, true)?) } else { None };
        Ok(Report { resent: self.resent, child, rekeyed })
    }

    /// The client's first message of `exchange_type`; with `lose_msg1`, the first
    /// delivery is dropped and the message is the client's retransmission of it.
    fn msg1(&mut self, exchange_type: u8) -> Result<Vec<u8>, String> {
        let msg1 = self.recv(exchange_type)?;
        if !self.script.lose_msg1 {
            return Ok(msg1);
        }
        let again = self.recv(exchange_type)?;
        if again != msg1 {
            return Err("gateway: the client's retransmission of message 1 is not the same bytes".into());
        }
        Ok(again)
    }

    fn aggressive_mode(&mut self, cfg: &Phase1Config, our_addr: SocketAddr) -> Result<Phase1State, String> {
        let msg1 = self.msg1(exchange::AGGRESSIVE)?;
        let (msg2, st) = respond_aggressive(cfg, &msg1, &mut self.entropy, our_addr, self.peer.unwrap()).map_err(|e| format!("gateway: msg1: {e:?}"))?;
        self.send(&msg2);
        self.on_4500 = self.natt.is_some();
        let msg3 = self.recv_answering(exchange::AGGRESSIVE, &msg1, &msg2)?;
        if self.script.lose_am_msg3 {
            self.repeats_on_500 = true;
            self.lose_then_repeat(msg3.clone(), &msg2, exchange::AGGRESSIVE, &msg1)?;
            self.repeats_on_500 = false;
        }
        st.verify_hash_i(&msg3).map_err(|e| format!("gateway: msg3: {e:?}"))?;
        Ok(st)
    }

    fn main_mode(&mut self, cfg: &Phase1Config, our_addr: SocketAddr) -> Result<Phase1State, String> {
        let msg1 = self.msg1(exchange::MAIN)?;
        let (msg2, sa) = respond_main(cfg, &msg1, &mut self.entropy, our_addr, self.peer.unwrap()).map_err(|e| format!("gateway: msg1: {e:?}"))?;
        self.send(&msg2);
        let msg3 = self.recv_answering(exchange::MAIN, &msg1, &msg2)?;
        let (msg4, ke) = sa.complete_ke(&msg3, &mut self.entropy).map_err(|e| format!("gateway: msg3: {e:?}"))?;
        self.send(&msg4);
        let msg5 = self.recv_answering(exchange::MAIN, &msg3, &msg4)?;
        let (msg6, st) = ke.complete_id(&msg5).map_err(|e| format!("gateway: msg5: {e:?}"))?;
        self.send(&msg6);
        Ok(st)
    }

    fn xauth(&mut self, st: &Phase1State) -> Result<(), String> {
        let (request, next_iv) = test_gateway::build_request(st, XAUTH_MSGID);
        self.send(&request);
        let reply = self.recv_answering(exchange::TRANSACTION, &[], &[])?;
        let (_credentials, set) = test_gateway::handle_reply(st, &reply, &next_iv, XAUTH_MSGID, true);
        self.send(&set);
        if self.script.late_request_repeat {
            self.send(&request);
        }
        let ack = self.recv_answering(exchange::TRANSACTION, &reply, &set)?;
        if self.script.lose_xauth_ack {
            self.lose_then_repeat(ack, &set, exchange::TRANSACTION, &reply)?;
        }
        Ok(())
    }

    fn mode_cfg(&mut self, st: &Phase1State) -> Result<(), String> {
        let request = self.recv(exchange::TRANSACTION)?;
        let msgid = IsakmpHeader::parse(&request).map_err(|e| format!("gateway: mode-config request: {e:?}"))?.message_id;
        self.send(&cfg::test_gateway::handle_request(st, &request, msgid, Ipv4Addr::new(10, 9, 9, 9)));
        Ok(())
    }

    fn quick_mode(&mut self, st: &Phase1State, lose_msg3: bool) -> Result<ChildSa, String> {
        let msg1 = self.recv(exchange::QUICK)?;
        let (msg2, responder) = respond_quick(st, &msg1, &mut self.entropy).map_err(|e| format!("gateway: quick msg1: {e:?}"))?;
        if self.script.stray_quick_message_first {
            let mut stray = msg2.clone();
            stray[20..24].copy_from_slice(&0x0bad_c0deu32.to_be_bytes());
            *stray.last_mut().unwrap() ^= 0xff;
            self.send(&stray);
        }
        self.send(&msg2);
        let msg3 = self.recv_answering(exchange::QUICK, &msg1, &msg2)?;
        if lose_msg3 {
            self.lose_then_repeat(msg3.clone(), &msg2, exchange::QUICK, &msg1)?;
        }
        responder.complete(&msg3).map_err(|e| format!("gateway: quick msg3: {e:?}"))
    }
}

fn initiator_config(script: Script) -> InitiatorConfig {
    InitiatorConfig {
        local_auth: Ikev1LocalAuth::Psk(PSK.to_vec()),
        trusted_cas: Vec::new(),
        now_unix: 0,
        key_len: 32,
        our_id: Id::ipv4([10, 1, 1, 1]),
        group: DhGroup::Modp1024,
        xauth: script.xauth,
        xauth_creds: script.xauth.then(|| (b"user".to_vec(), b"pass".to_vec())),
        ts_local: ([10, 0, 99, 0], [255, 255, 255, 0]),
        ts_remote: ([10, 0, 99, 0], [255, 255, 255, 0]),
        esp_cipher: SkCipher::Aes256Gcm,
        pfs_group: None,
        mode_cfg: script.mode_cfg,
        ipv6: false,
        mode: if script.main_mode { Ikev1ExchangeMode::Main } else { Ikev1ExchangeMode::Aggressive },
        p1_lifetime_secs: 28800,
        p2_lifetime_secs: 3600,
        force_natt: script.floated,
    }
}

struct Run {
    established: Result<Established, DriverError>,
    /// The client's socket, still open, for what the caller does after `connect`.
    client_sock: UdpSocket,
    gateway_addr: SocketAddr,
    gateway: std::thread::JoinHandle<Result<Report, String>>,
}

/// `connect` against a gateway following `script`, with a short read timeout so
/// that a failure shows quickly.
fn connect(script: Script) -> Run {
    connect_with_timeout(script, Duration::from_millis(400))
}

/// [`connect`] with the client's read timeout `timeout`: the patience for each
/// message, which the retransmission schedule spreads over its sends.
fn connect_with_timeout(script: Script, timeout: Duration) -> Run {
    // A floating client sends to port 4500 of the gateway's address, whatever
    // port the gateway's first socket has: each such run takes an address of its
    // own, so that runs in parallel never share the port.
    static NEXT_GATEWAY_HOST: AtomicU8 = AtomicU8::new(1);
    let host = if script.floated { Ipv4Addr::new(127, 77, NEXT_GATEWAY_HOST.fetch_add(1, Ordering::Relaxed), 1) } else { Ipv4Addr::LOCALHOST };
    let gw_sock = UdpSocket::bind((host, 0)).unwrap();
    gw_sock.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
    let natt = script.floated.then(|| {
        let natt = UdpSocket::bind((host, crate::natt_port())).unwrap();
        natt.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
        natt
    });
    let gateway_addr = gw_sock.local_addr().unwrap();
    let gateway = Gateway {
        sock: gw_sock,
        natt,
        on_4500: false,
        peer4500: None,
        script,
        entropy: SeedEntropy::new(0x2222),
        peer: None,
        resent: Vec::new(),
        pending: Vec::new(),
        repeats_on_500: false,
    };
    let gateway = std::thread::spawn(move || gateway.serve());

    let client_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut client = if script.floated {
        Client::from_sockets(client_sock.try_clone().unwrap(), UdpSocket::bind("127.0.0.1:0").unwrap(), SeedEntropy::new(0x1111))
    } else {
        Client::from_socket(client_sock.try_clone().unwrap(), SeedEntropy::new(0x1111))
    };
    client.set_read_timeout(Some(timeout)).unwrap();
    let established = client.connect(gateway_addr, &initiator_config(script));
    Run { established, client_sock, gateway_addr, gateway }
}

/// How many messages the gateway saw sent again. Each one was identical to the
/// message it never received: [`Gateway::lose_then_repeat`] takes nothing else.
fn assert_resent_identically(report: &Report, expected: usize) {
    assert_eq!(report.resent.len(), expected);
}

/// A network that delivers every gateway datagram twice: a repeat of a message
/// the client already handled must never be read as the next one (Main Mode
/// message 2 taken for message 4, an XAUTH REQUEST taken for the SET).
#[test]
fn main_mode_survives_every_gateway_reply_arriving_twice() {
    let run = connect(Script { main_mode: true, xauth: true, duplicate_replies: true, ..Script::default() });
    let est = run.established.expect("the handshake must complete");
    let report = run.gateway.join().unwrap().expect("gateway");
    assert_eq!(est.child.inbound.spi(), report.child.outbound.spi());
}

#[test]
fn aggressive_mode_survives_every_gateway_reply_arriving_twice() {
    let run = connect(Script { xauth: true, duplicate_replies: true, ..Script::default() });
    let est = run.established.expect("the handshake must complete");
    let report = run.gateway.join().unwrap().expect("gateway");
    assert_eq!(est.child.inbound.spi(), report.child.outbound.spi());
}

/// RFC 2408 §3.1: the gateway that never received message 3 repeats message
/// 2, and the initiator answers it with the same message 3 -- RFC 2409 §5: no
/// IV or state advance for a retransmission.
#[test]
fn aggressive_mode_message_3_is_sent_again_when_the_gateway_repeats_message_2() {
    let run = connect(Script { lose_am_msg3: true, ..Script::default() });
    let est = run.established.expect("the handshake must complete");
    let report = run.gateway.join().unwrap().expect("gateway");
    assert_resent_identically(&report, 1);
    assert_eq!(est.child.inbound.spi(), report.child.outbound.spi());
}

/// Control for the floated harness: with forced NAT traversal both sides move
/// to port 4500 with message 3, and nothing lost, the handshake completes there.
#[test]
fn control_a_floated_aggressive_mode_handshake_completes_on_port_4500() {
    let run = connect(Script { floated: true, ..Script::default() });
    let est = run.established.expect("the handshake must complete");
    let report = run.gateway.join().unwrap().expect("gateway");
    assert!(est.phase1.floated, "the handshake was to float");
    assert_resent_identically(&report, 0);
    assert_eq!(est.child.inbound.spi(), report.child.outbound.spi());
}

/// RFC 2408 §3.1 with RFC 3947 §5.3: message 3 goes out on port 4500, the
/// gateway never sees it, and it has not floated yet, so it repeats message 2
/// to port 500 -- where the initiator, now listening on 4500, must still hear
/// it and send the same message 3 again.
#[test]
fn a_floated_aggressive_mode_message_3_is_sent_again_when_the_gateway_repeats_message_2_on_port_500() {
    let run = connect(Script { floated: true, lose_am_msg3: true, ..Script::default() });
    let est = run.established.expect("the handshake must complete");
    let report = run.gateway.join().unwrap().expect("gateway");
    assert_resent_identically(&report, 1);
    assert_eq!(est.child.inbound.spi(), report.child.outbound.spi());
}

/// The same while the initiator waits for the gateway's XAUTH REQUEST, the
/// message that would have told it message 3 arrived.
#[test]
fn aggressive_mode_message_3_is_sent_again_while_waiting_for_the_xauth_request() {
    let run = connect(Script { xauth: true, lose_am_msg3: true, ..Script::default() });
    let est = run.established.expect("the handshake must complete");
    let report = run.gateway.join().unwrap().expect("gateway");
    assert_resent_identically(&report, 1);
    assert_eq!(est.child.inbound.spi(), report.child.outbound.spi());
}

#[test]
fn the_xauth_ack_is_sent_again_when_the_gateway_repeats_the_set() {
    let run = connect(Script { xauth: true, lose_xauth_ack: true, ..Script::default() });
    let est = run.established.expect("the handshake must complete");
    let report = run.gateway.join().unwrap().expect("gateway");
    assert_resent_identically(&report, 1);
    assert_eq!(est.child.inbound.spi(), report.child.outbound.spi());
}

/// With Mode-Config after XAUTH (what a FortiGate does): the ACK lost, the
/// client has already sent its Mode-Config request and is waiting for the
/// reply when the gateway's repeated SET arrives -- that wait answers it.
#[test]
fn the_xauth_ack_is_sent_again_while_waiting_for_the_mode_config_reply() {
    let run = connect(Script { xauth: true, mode_cfg: true, lose_xauth_ack: true, ..Script::default() });
    let est = run.established.expect("the handshake must complete");
    let report = run.gateway.join().unwrap().expect("gateway");
    assert_resent_identically(&report, 1);
    assert_eq!(est.assigned_ip4, Some(Ipv4Addr::new(10, 9, 9, 9)));
    assert_eq!(est.child.inbound.spi(), report.child.outbound.spi());
}

/// Every gateway datagram twice, through XAUTH, Mode-Config and Quick Mode: a
/// repeated XAUTH REQUEST or SET must not be read as the Mode-Config reply.
#[test]
fn mode_config_survives_every_gateway_reply_arriving_twice() {
    let run = connect(Script { xauth: true, mode_cfg: true, duplicate_replies: true, ..Script::default() });
    let est = run.established.expect("the handshake must complete");
    let report = run.gateway.join().unwrap().expect("gateway");
    assert_eq!(est.assigned_ip4, Some(Ipv4Addr::new(10, 9, 9, 9)));
    assert_eq!(est.child.inbound.spi(), report.child.outbound.spi());
}

/// A repeat of the XAUTH REQUEST that reaches the client after the SET, while
/// it waits for the Mode-Config reply (which names no Message ID to check),
/// is a message it already handled -- not that reply.
#[test]
fn a_late_repeat_of_the_xauth_request_is_not_the_mode_config_reply() {
    let run = connect(Script { xauth: true, mode_cfg: true, late_request_repeat: true, ..Script::default() });
    let est = run.established.expect("the handshake must complete");
    let report = run.gateway.join().unwrap().expect("gateway");
    assert_eq!(est.assigned_ip4, Some(Ipv4Addr::new(10, 9, 9, 9)));
    assert_eq!(est.child.inbound.spi(), report.child.outbound.spi());
}

/// Quick Mode message 3 is the last message of the exchange, so `connect` has
/// returned long before the gateway repeats its message 2; the initiator's
/// next look at the socket must answer it.
#[test]
fn quick_mode_message_3_is_sent_again_when_the_gateway_repeats_message_2_after_connect() {
    let run = connect(Script { lose_qm_msg3: true, ..Script::default() });
    let est = run.established.expect("the handshake must complete");
    let mut entropy = SeedEntropy::new(0x3333);
    let seen = informational::peek(&run.client_sock, &est.phase1, &mut entropy, run.gateway_addr, Duration::from_millis(1000), est.child.outbound.spi(), None)
        .expect("peek");
    assert_eq!(seen, Liveness::Alive);
    let report = run.gateway.join().unwrap().expect("gateway");
    assert_resent_identically(&report, 1);
    assert_eq!(est.child.inbound.spi(), report.child.outbound.spi());
}

/// A Quick Mode reply carries its request's Message ID: another exchange's
/// message under the same ISAKMP SA, arriving first, is not message 2.
#[test]
fn quick_mode_message_2_is_the_one_carrying_the_requests_message_id() {
    let run = connect(Script { stray_quick_message_first: true, ..Script::default() });
    let est = run.established.expect("the handshake must complete");
    let report = run.gateway.join().unwrap().expect("gateway");
    assert_resent_identically(&report, 0);
    assert_eq!(est.child.inbound.spi(), report.child.outbound.spi());
}

/// The same for a rekey (`quick::rekey_child`, which returns once it has sent
/// message 3): what is kept is kept for every Quick Mode exchange, not only
/// the one `connect` runs.
#[test]
fn a_rekeys_quick_mode_message_3_is_sent_again_when_the_gateway_repeats_message_2() {
    let run = connect(Script { lose_rekey_msg3: true, ..Script::default() });
    let est = run.established.expect("the handshake must complete");
    let mut entropy = SeedEntropy::new(0x3333);
    let ts = ([10, 0, 99, 0], [255, 255, 255, 0]);
    let (rekeyed, _lifetime) = quick::rekey_child(
        &run.client_sock,
        &est.phase1,
        &mut entropy,
        run.gateway_addr,
        SkCipher::Aes256Gcm,
        None,
        ts,
        ts,
        3600,
        Duration::from_millis(1000),
        est.child.inbound.spi(),
    )
    .expect("rekey");
    let seen = informational::peek(&run.client_sock, &est.phase1, &mut entropy, run.gateway_addr, Duration::from_millis(1000), rekeyed.peer_spi, None)
        .expect("peek");
    assert_eq!(seen, Liveness::Alive);
    let report = run.gateway.join().unwrap().expect("gateway");
    assert_resent_identically(&report, 1);
    assert_eq!(rekeyed.local_spi, report.rekeyed.expect("the gateway completed the rekey").outbound.spi());
}

/// Control: the harness, with no fault scripted, completes every shape of
/// handshake, so the failures above are the faults' and not the harness's.
#[test]
fn control_without_faults_every_handshake_shape_completes() {
    for (main_mode, xauth, mode_cfg) in
        [(false, false, false), (false, true, false), (true, false, false), (true, true, false), (false, true, true), (true, true, true)]
    {
        let run = connect(Script { main_mode, xauth, mode_cfg, ..Script::default() });
        let est = run.established.unwrap_or_else(|e| panic!("main_mode={main_mode} xauth={xauth} mode_cfg={mode_cfg}: {e:?}"));
        let report = run.gateway.join().unwrap().expect("gateway");
        assert_resent_identically(&report, 0);
        assert_eq!(est.child.inbound.spi(), report.child.outbound.spi());
    }
}

/// RFC 2408 §5.1: what the handshake measures of the path. Each exchange whose reply
/// depends on nothing but the path -- Phase 1's messages (Main Mode's three, Aggressive
/// Mode's one) and Quick Mode's -- is a sample of the estimate the ISAKMP SA keeps, and
/// XAUTH's and Mode-Config's, which wait on a backend, are not. The read timeout is long
/// enough that no exchange of a loopback handshake is ever sent twice, which would take
/// no sample (Karn's rule).
#[test]
fn the_handshake_measures_the_path_in_phase_1_and_quick_mode_but_not_in_xauth_or_mode_config() {
    for (main_mode, xauth, mode_cfg, samples) in [
        (false, false, false, 2), // Aggressive Mode message 2, Quick Mode message 2
        (true, false, false, 4),  // Main Mode messages 2, 4 and 6, Quick Mode message 2
        (false, true, true, 2),   // the same: XAUTH and Mode-Config add none
        (true, true, true, 4),
    ] {
        let run = connect_with_timeout(Script { main_mode, xauth, mode_cfg, ..Script::default() }, Duration::from_secs(3));
        let est = run.established.unwrap_or_else(|e| panic!("main_mode={main_mode} xauth={xauth} mode_cfg={mode_cfg}: {e:?}"));
        run.gateway.join().unwrap().expect("gateway");
        assert_eq!(est.phase1.rtt.samples(), samples, "main_mode={main_mode} xauth={xauth} mode_cfg={mode_cfg}");
        let smoothed = est.phase1.rtt.smoothed().expect("measured");
        assert!(smoothed < Duration::from_secs(2), "a loopback gateway measured as {smoothed:?}");
        assert_eq!(est.phase1.rtt.backoff(), 0);
    }
}

/// Karn's rule end to end: the reply that follows a retransmission is not a sample. The
/// gateway never sees the client's first message; the client sends it again after its
/// timer (0.64 s for this 1.5 s read timeout, which nothing measured yet can shorten) and
/// the gateway's answer to that is used but not measured, so the handshake ends with one
/// sample fewer than `the_handshake_measures_the_path_...` counts, whichever mode it ran.
#[test]
fn a_reply_that_followed_a_retransmission_is_used_but_not_measured() {
    for (main_mode, samples) in [(false, 1), (true, 3)] {
        let run = connect_with_timeout(Script { main_mode, lose_msg1: true, ..Script::default() }, Duration::from_millis(1500));
        let est = run.established.unwrap_or_else(|e| panic!("main_mode={main_mode}: {e:?}"));
        run.gateway.join().unwrap().expect("gateway");
        assert_eq!(est.phase1.rtt.samples(), samples, "main_mode={main_mode}: message 1 went out twice, so its answer is no sample");
        assert_eq!(est.phase1.rtt.backoff(), 0, "the samples that came after ended the backoff");
    }
}
