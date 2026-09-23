//! The initiator's handling of lost final messages and of duplicates (RFC 2408
//! §3.1 Commit-Bit NOTE, RFC 2409 §5) against a scripted gateway: the real
//! responder steps over one UDP socket, with a script deciding which datagrams
//! the gateway never sees, repeats, or sends twice.

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
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
    /// Ahead of Quick Mode message 2 the gateway sends a datagram of the same
    /// ISAKMP SA and exchange type under another Message ID: not its reply, and
    /// not a message that would pass for it (its last byte differs).
    stray_quick_message_first: bool,
    /// After the SET the network delivers the gateway's XAUTH REQUEST once
    /// more, late: what the client meets while it waits for the Mode-Config reply.
    late_request_repeat: bool,
    /// The gateway also serves a Mode-Config round (after XAUTH, before Quick Mode).
    mode_cfg: bool,
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
    script: Script,
    entropy: SeedEntropy,
    peer: Option<SocketAddr>,
    resent: Vec<Vec<u8>>,
    /// Datagrams that came in while the gateway waited for something else (the
    /// first message of the next exchange, ahead of a retransmission), for the
    /// step that reads them.
    pending: Vec<Vec<u8>>,
}

impl Gateway {
    fn send(&self, msg: &[u8]) {
        let peer = self.peer.expect("the client has written by now");
        self.sock.send_to(msg, peer).unwrap();
        if self.script.duplicate_replies {
            self.sock.send_to(msg, peer).unwrap();
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
            let (n, from) = self.sock.recv_from(&mut buf).map_err(|e| format!("gateway: waiting for exchange type {exchange_type}: {e}"))?;
            self.peer.get_or_insert(from);
            let datagram = buf[..n].to_vec();
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
        self.send(own);
        loop {
            let datagram = self.recv_socket(exchange_type)?;
            if datagram == lost {
                self.resent.push(datagram);
                return Ok(());
            }
            if datagram == request {
                self.send(own);
            } else {
                self.pending.push(datagram);
            }
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

    fn aggressive_mode(&mut self, cfg: &Phase1Config, our_addr: SocketAddr) -> Result<Phase1State, String> {
        let msg1 = self.recv(exchange::AGGRESSIVE)?;
        let (msg2, st) = respond_aggressive(cfg, &msg1, &mut self.entropy, our_addr, self.peer.unwrap()).map_err(|e| format!("gateway: msg1: {e:?}"))?;
        self.send(&msg2);
        let msg3 = self.recv_answering(exchange::AGGRESSIVE, &msg1, &msg2)?;
        if self.script.lose_am_msg3 {
            self.lose_then_repeat(msg3.clone(), &msg2, exchange::AGGRESSIVE, &msg1)?;
        }
        st.verify_hash_i(&msg3).map_err(|e| format!("gateway: msg3: {e:?}"))?;
        Ok(st)
    }

    fn main_mode(&mut self, cfg: &Phase1Config, our_addr: SocketAddr) -> Result<Phase1State, String> {
        let msg1 = self.recv(exchange::MAIN)?;
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
        force_natt: false,
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
    let gw_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    gw_sock.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
    let gateway_addr = gw_sock.local_addr().unwrap();
    let gateway = Gateway { sock: gw_sock, script, entropy: SeedEntropy::new(0x2222), peer: None, resent: Vec::new(), pending: Vec::new() };
    let gateway = std::thread::spawn(move || gateway.serve());

    let client_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut client = Client::from_socket(client_sock.try_clone().unwrap(), SeedEntropy::new(0x1111));
    client.set_read_timeout(Some(Duration::from_millis(400))).unwrap();
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
