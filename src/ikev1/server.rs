//! A blocking IKEv1 **responder** (server) over UDP: Aggressive Mode or Main
//! Mode (Phase 1) + Quick Mode (Phase 2), authenticated by a PSK or, in Main
//! Mode, an RSA signature (see [`Phase1Config`]). Per-client handshake state
//! is keyed by the cookie pair so the multi-message exchanges correlate. On
//! completion the established ESP CHILD SA is available via
//! [`Server::take_child`].
//!
//! This is a test double for [`super::Client`], not a gateway, and what holds
//! for it says nothing about the client or the library's other building
//! blocks. What it does:
//!
//! - Phase 1 in Main or Aggressive Mode, then Quick Mode for an ESP CHILD SA
//!   (a later Quick Mode replaces it), and nothing else: no XAUTH, no
//!   Mode-Config, no NAT traversal, no commit bit. Phase 1 accepts an
//!   XAUTH-PSK proposal, but no XAUTH exchange follows it;
//! - a message repeated bitwise identical gets the answer already sent, and a
//!   repeated last message of an exchange is dropped. Nothing is taken twice
//!   (RFC 2409 §5: no state moves on for a retransmission), and a late
//!   repeat of a message 1 opens no second ISAKMP SA;
//! - a message that fails its checks leaves the exchange where it was;
//! - Quick Mode is taken only once Phase 1 has authenticated the peer, each
//!   exchange under a Message ID of its own that is never reused;
//! - having advertised DPD, it answers every R-U-THERE (RFC 3706 §5.2) whose
//!   sequence number has not gone backwards (§6.2). A Delete closes what it
//!   names; like every IKEv1 Delete it gets no answer;
//! - it never starts an exchange (no DPD, rekey or Delete of its own). The
//!   SAs last until the peer deletes them -- it enforces no lifetime, seconds
//!   or volume. What it grants is stated in its Quick Mode answer and exposed
//!   ([`Server::child_lifetime`]) for whoever runs the CHILD SA it hands out
//!   ([`Server::take_child`]) to hold it to; [`Server::set_child_volume_limit`]
//!   makes it play a gateway that limits the volume of an SA, which is what a
//!   client's handling of one is tested against.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

use crate::entropy::Entropy;
use crate::esp::ChildSa;
use crate::ikev1::crypto1;
use crate::ikev1::informational::{build_r_u_there_ack, notify_type, parse_delete, parse_notify};
use crate::ikev1::isakmp::{exchange, payload, IsakmpHeader};
use crate::ikev1::payloads::protocol;
use crate::ikev1::phase1::{respond_aggressive, respond_main, MainRespKeSent, MainRespSaSent, Phase1Config, Phase1State};
use crate::ikev1::phase2;
use crate::ikev1::quick::{respond_quick_capped, QuickResponder, SaLifetime};
use crate::transport::{DriverError, UdpTransport};

/// What [`Server::handle_one`] did with one datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerEvent {
    /// Answered Phase-1 message 1 (either mode) or Main-Mode message 3;
    /// Phase 1 is half-open.
    Phase1SaInit,
    /// Verified the initiator's HASH_I — Phase 1 is established.
    Phase1Established,
    /// Answered Quick-Mode message 1; the CHILD SA is being negotiated.
    QuickSaInit,
    /// Quick Mode completed — the ESP CHILD SA is ready (see [`Server::take_child`]).
    ChildSaEstablished { cky_i: [u8; 8] },
    /// Resent the answer to a message the peer repeated.
    Retransmitted,
    /// Answered an R-U-THERE with its R-U-THERE-ACK.
    DpdAnswered { cky_i: [u8; 8] },
    /// The peer deleted the CHILD SA; the ISAKMP SA stays up. A caller that
    /// took the CHILD SA ([`Server::take_child`]) drops it.
    ChildDeleted { cky_i: [u8; 8] },
    /// The peer deleted the ISAKMP SA, and with it its CHILD SA.
    Deleted { cky_i: [u8; 8] },
    /// A datagram we don't act on: an unknown cookie pair, a message out of
    /// turn or repeated with nothing to answer, or an unexpected exchange.
    Ignored,
}

/// Where an ISAKMP SA's Phase 1 stands.
enum Phase1 {
    /// Main Mode, message 2 sent.
    MainSaSent(MainRespSaSent),
    /// Main Mode, message 4 sent.
    MainKeSent(MainRespKeSent),
    /// Aggressive Mode, message 2 sent: HASH_I is still to come.
    AggressiveSent(Phase1State),
    /// Both ends authenticated.
    Established(Phase1State),
}

/// The latest Quick Mode exchange of an ISAKMP SA.
struct Quick {
    message_id: u32,
    /// Its message 1 and our message 2.
    msg1: Vec<u8>,
    msg2: Vec<u8>,
    /// Waiting for message 3; `None` once it came in.
    responder: Option<QuickResponder>,
}

/// One ISAKMP SA, from the message 1 that opened it.
struct Session {
    phase1: Phase1,
    /// The message 1 that opened it.
    first: Vec<u8>,
    /// The last Phase-1 message we took, and our answer when it has one.
    last: (Vec<u8>, Option<Vec<u8>>),
    quick: Option<Quick>,
    /// Every Quick Mode Message ID used so far.
    quick_ids: HashSet<u32>,
    /// The ESP SPIs of the CHILD SA, ours then the peer's, while it lasts --
    /// kept apart from [`Server::children`] since the caller may have taken it.
    child_spis: Option<(u32, u32)>,
    /// The lifetime that CHILD SA was granted, likewise.
    child_lifetime: Option<SaLifetime>,
    /// The highest R-U-THERE sequence number answered.
    dpd_seq: Option<u32>,
}

/// A UDP IKEv1 responder driven by an [`Entropy`] source, authenticating peers
/// as its [`Phase1Config`] says.
pub struct Server<E> {
    transport: UdpTransport,
    entropy: E,
    cfg: Phase1Config,
    sessions: HashMap<([u8; 8], [u8; 8]), Session>,
    children: HashMap<[u8; 8], ChildSa>,
    /// The volume, in kilobytes, this side limits a CHILD SA to, if it does.
    child_volume_limit: Option<u32>,
}

impl<E: Entropy> Server<E> {
    pub fn bind(addr: impl ToSocketAddrs, entropy: E, cfg: Phase1Config) -> io::Result<Self> {
        Ok(Self {
            transport: UdpTransport::bind(addr)?,
            entropy,
            cfg,
            sessions: HashMap::new(),
            children: HashMap::new(),
            child_volume_limit: None,
        })
    }

    /// Limit the volume of the CHILD SAs negotiated from now on to `kilobytes`
    /// of this side's own (`None`: no limit, the default): what a Quick Mode
    /// answer states is the offer's own volume limit if it has one, shortened to
    /// this, and this alone when the offer has none (RFC 2407 §4.5.4). Stating
    /// the limit is all this does -- see the module's note on lifetimes.
    pub fn set_child_volume_limit(&mut self, kilobytes: Option<u32>) {
        self.child_volume_limit = kilobytes;
    }

    /// The lifetime the CHILD SA of the ISAKMP SA opened with initiator cookie
    /// `cky_i` was granted -- its seconds and its volume limit, if it has one --
    /// for as long as the CHILD SA lasts, whether or not [`Self::take_child`]
    /// took it.
    pub fn child_lifetime(&self, cky_i: [u8; 8]) -> Option<SaLifetime> {
        self.sessions.iter().find(|((i, _), _)| *i == cky_i).and_then(|(_, s)| s.child_lifetime)
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.transport.local_addr()
    }

    pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.transport.set_read_timeout(dur)
    }

    /// Borrow the established ESP CHILD SA for a given initiator cookie.
    pub fn child(&self, cky_i: [u8; 8]) -> Option<&ChildSa> {
        self.children.get(&cky_i)
    }

    /// Take ownership of the established ESP CHILD SA (to run the data plane,
    /// which mutates the sequence counters).
    pub fn take_child(&mut self, cky_i: [u8; 8]) -> Option<ChildSa> {
        self.children.remove(&cky_i)
    }

    /// Receive one datagram and advance the handshake it belongs to.
    pub fn handle_one(&mut self) -> Result<ServerEvent, DriverError> {
        let (data, from) = self.transport.recv_from()?;
        let hdr = IsakmpHeader::parse(&data)?;
        match hdr.exchange_type {
            exchange::MAIN | exchange::AGGRESSIVE if hdr.resp_cookie == [0; 8] => self.open_phase1(&hdr, data, from),
            exchange::MAIN | exchange::AGGRESSIVE => self.continue_phase1(&hdr, data, from),
            exchange::QUICK => self.quick_mode(&hdr, data, from),
            exchange::INFORMATIONAL => self.informational(&hdr, &data, from),
            _ => Ok(ServerEvent::Ignored),
        }
    }

    /// Message 1 of either mode: the repeat of one we answered, a late repeat
    /// of one whose exchange moved on, or a new ISAKMP SA -- told apart by the
    /// whole message, since the initiator cookie alone is anyone's to send.
    fn open_phase1(&mut self, hdr: &IsakmpHeader, data: Vec<u8>, from: SocketAddr) -> Result<ServerEvent, DriverError> {
        if let Some(s) = self.sessions.values().find(|s| s.first == data) {
            return answer_repeat(&self.transport, &s.last, &data, from);
        }
        let our_addr = self.transport.local_addr_for(from)?;
        let (msg2, phase1) = if hdr.exchange_type == exchange::AGGRESSIVE {
            let (msg2, st) = respond_aggressive(&self.cfg, &data, &mut self.entropy, our_addr, from)?;
            (msg2, Phase1::AggressiveSent(st))
        } else {
            let (msg2, st) = respond_main(&self.cfg, &data, &mut self.entropy, our_addr, from)?;
            (msg2, Phase1::MainSaSent(st))
        };
        let cky_r = IsakmpHeader::parse(&msg2)?.resp_cookie;
        self.transport.send_to(&msg2, from)?;
        let session = Session {
            phase1,
            first: data.clone(),
            last: (data, Some(msg2)),
            quick: None,
            quick_ids: HashSet::new(),
            child_spis: None,
            child_lifetime: None,
            dpd_seq: None,
        };
        self.sessions.insert((hdr.init_cookie, cky_r), session);
        Ok(ServerEvent::Phase1SaInit)
    }

    /// Main-Mode messages 3 and 5, Aggressive-Mode message 3.
    fn continue_phase1(&mut self, hdr: &IsakmpHeader, data: Vec<u8>, from: SocketAddr) -> Result<ServerEvent, DriverError> {
        let Some(s) = self.sessions.get_mut(&(hdr.init_cookie, hdr.resp_cookie)) else {
            return Ok(ServerEvent::Ignored);
        };
        if s.last.0 == data {
            return answer_repeat(&self.transport, &s.last, &data, from);
        }
        // Each step works on a copy, so a message that fails leaves the
        // exchange where it was for the real one.
        let (answer, phase1, event) = match (&s.phase1, hdr.exchange_type) {
            (Phase1::MainSaSent(st), exchange::MAIN) => {
                let (msg4, st) = st.clone().complete_ke(&data, &mut self.entropy)?;
                (Some(msg4), Phase1::MainKeSent(st), ServerEvent::Phase1SaInit)
            }
            (Phase1::MainKeSent(st), exchange::MAIN) => {
                let (msg6, st) = st.clone().complete_id(&data)?;
                (Some(msg6), Phase1::Established(st), ServerEvent::Phase1Established)
            }
            (Phase1::AggressiveSent(st), exchange::AGGRESSIVE) => {
                st.verify_hash_i(&data)?;
                (None, Phase1::Established(st.clone()), ServerEvent::Phase1Established)
            }
            _ => return Ok(ServerEvent::Ignored),
        };
        if let Some(answer) = &answer {
            self.transport.send_to(answer, from)?;
        }
        s.phase1 = phase1;
        s.last = (data, answer);
        Ok(event)
    }

    /// Quick Mode (RFC 2409 §5.5), under an authenticated ISAKMP SA only.
    fn quick_mode(&mut self, hdr: &IsakmpHeader, data: Vec<u8>, from: SocketAddr) -> Result<ServerEvent, DriverError> {
        let cky_i = hdr.init_cookie;
        let Some(s) = self.sessions.get_mut(&(cky_i, hdr.resp_cookie)) else {
            return Ok(ServerEvent::Ignored);
        };
        let Phase1::Established(st) = &s.phase1 else {
            return Ok(ServerEvent::Ignored);
        };
        if !hdr.encrypted() || hdr.message_id == 0 {
            return Ok(ServerEvent::Ignored);
        }
        if let Some(q) = s.quick.as_mut().filter(|q| q.message_id == hdr.message_id) {
            if q.msg1 == data {
                self.transport.send_to(&q.msg2, from)?;
                return Ok(ServerEvent::Retransmitted);
            }
            let Some(responder) = &q.responder else {
                return Ok(ServerEvent::Ignored);
            };
            let child = responder.clone().complete(&data)?;
            let lifetime = responder.negotiated_lifetime();
            q.responder = None;
            s.child_spis = Some((child.inbound.spi(), child.outbound.spi()));
            s.child_lifetime = Some(lifetime);
            self.children.insert(cky_i, child);
            return Ok(ServerEvent::ChildSaEstablished { cky_i });
        }
        if s.quick_ids.contains(&hdr.message_id) {
            // An exchange already over: never taken again.
            return Ok(ServerEvent::Ignored);
        }
        let (msg2, responder) = respond_quick_capped(st, &data, &mut self.entropy, self.child_volume_limit)?;
        self.transport.send_to(&msg2, from)?;
        s.quick_ids.insert(hdr.message_id);
        s.quick = Some(Quick { message_id: hdr.message_id, msg1: data, msg2, responder: Some(responder) });
        Ok(ServerEvent::QuickSaInit)
    }

    /// An Informational under an authenticated ISAKMP SA: an R-U-THERE is
    /// answered, a Delete closes what it names (RFC 2408 §3.15).
    fn informational(&mut self, hdr: &IsakmpHeader, data: &[u8], from: SocketAddr) -> Result<ServerEvent, DriverError> {
        let cky_i = hdr.init_cookie;
        let key = (cky_i, hdr.resp_cookie);
        let Some(s) = self.sessions.get_mut(&key) else {
            return Ok(ServerEvent::Ignored);
        };
        let Phase1::Established(st) = &s.phase1 else {
            return Ok(ServerEvent::Ignored);
        };
        if !hdr.encrypted() {
            // RFC 3706 §5.2, and RFC 2408 §4.8 for the rest.
            return Ok(ServerEvent::Ignored);
        }
        let iv = crypto1::phase2_iv(st.prf, &st.phase1_iv, hdr.message_id, st.enc_block);
        let (_, payloads, _) = phase2::parse_encrypted(data, st.prf, &st.skeyid_a, &st.enc_key, st.enc_block, &iv)?;
        let cookies = [key.0, key.1].concat();
        for p in &payloads {
            match p.payload_type {
                payload::DELETE => match parse_delete(&p.data) {
                    Some((protocol::ISAKMP, spi)) if spi == cookies => {
                        self.sessions.remove(&key);
                        self.children.remove(&cky_i);
                        return Ok(ServerEvent::Deleted { cky_i });
                    }
                    Some((protocol::ESP, spi)) if s.child_spis.is_some_and(|(_, theirs)| spi == theirs.to_be_bytes()) => {
                        s.child_spis = None;
                        s.child_lifetime = None;
                        self.children.remove(&cky_i);
                        return Ok(ServerEvent::ChildDeleted { cky_i });
                    }
                    _ => {}
                },
                payload::NOTIFY => match parse_notify(&p.data) {
                    Some((notify_type::R_U_THERE, seq)) if p.data.get(8..24) == Some(&cookies[..]) => {
                        let Ok(seq) = <[u8; 4]>::try_from(seq).map(u32::from_be_bytes) else { continue };
                        if s.dpd_seq.is_some_and(|last| seq < last) {
                            continue;
                        }
                        let ack = build_r_u_there_ack(st, &mut self.entropy, seq)?;
                        self.transport.send_to(&ack, from)?;
                        s.dpd_seq = Some(seq);
                        return Ok(ServerEvent::DpdAnswered { cky_i });
                    }
                    _ => {}
                },
                _ => {}
            }
        }
        Ok(ServerEvent::Ignored)
    }
}

/// Resend our answer to `data` when it repeats the `last` message we took,
/// and drop it otherwise.
fn answer_repeat(transport: &UdpTransport, last: &(Vec<u8>, Option<Vec<u8>>), data: &[u8], from: SocketAddr) -> Result<ServerEvent, DriverError> {
    match last {
        (taken, Some(answer)) if taken == data => {
            transport.send_to(answer, from)?;
            Ok(ServerEvent::Retransmitted)
        }
        _ => Ok(ServerEvent::Ignored),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::DhGroup;
    use crate::entropy::SeedEntropy;
    use crate::ikev1::informational::{build_esp_delete, build_isakmp_delete, build_r_u_there};
    use crate::ikev1::isakmp::{self, flags};
    use crate::ikev1::payloads::Id;
    use crate::ikev1::phase1::{initiate_aggressive, initiate_main, Ikev1ExchangeMode, Ikev1LocalAuth, InitiatorConfig};
    use crate::ikev1::quick::initiate_quick;
    use crate::ikev2::sk::SkCipher;
    use std::net::UdpSocket;

    const PSK: &[u8] = b"correct horse battery staple";
    const TS: ([u8; 4], [u8; 4]) = ([10, 0, 99, 0], [255, 255, 255, 0]);

    fn server() -> (Server<SeedEntropy>, SocketAddr) {
        let cfg = Phase1Config { local_auth: Ikev1LocalAuth::Psk(PSK.to_vec()), trusted_cas: Vec::new(), now_unix: 0, our_id: Id::ipv4([192, 168, 0, 1]) };
        let server = Server::bind("127.0.0.1:0", SeedEntropy::new(0x2222), cfg).unwrap();
        server.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let addr = server.local_addr().unwrap();
        (server, addr)
    }

    fn initiator_config(mode: Ikev1ExchangeMode) -> InitiatorConfig {
        InitiatorConfig {
            local_auth: Ikev1LocalAuth::Psk(PSK.to_vec()),
            trusted_cas: Vec::new(),
            now_unix: 0,
            key_len: 32,
            our_id: Id::ipv4([10, 1, 1, 1]),
            group: DhGroup::Modp1024,
            xauth: false,
            xauth_creds: None,
            ts_local: TS,
            ts_remote: TS,
            esp_cipher: SkCipher::Aes256Gcm,
            pfs_group: None,
            mode_cfg: false,
            ipv6: false,
            mode,
            p1_lifetime_secs: 28800,
            p2_lifetime_secs: 3600,
            force_natt: false,
        }
    }

    /// A peer that builds its messages by hand, so it can send any of them
    /// again bitwise identical, as a retransmission.
    struct Peer {
        sock: UdpSocket,
        me: SocketAddr,
        server: SocketAddr,
        entropy: SeedEntropy,
    }

    impl Peer {
        fn new(server: SocketAddr) -> Peer {
            let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
            sock.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
            Peer { me: sock.local_addr().unwrap(), sock, server, entropy: SeedEntropy::new(0x1111) }
        }

        /// Send `msg`, have the server take it, and collect what it sent
        /// back, if anything.
        fn send(&self, server: &mut Server<SeedEntropy>, msg: &[u8]) -> (Result<ServerEvent, DriverError>, Option<Vec<u8>>) {
            self.sock.send_to(msg, self.server).unwrap();
            let event = server.handle_one();
            let mut buf = vec![0u8; 65535];
            let reply = self.sock.recv(&mut buf).ok().map(|n| buf[..n].to_vec());
            (event, reply)
        }

        /// Aggressive Mode up to and including message 2; returns message 3
        /// (unsent) and the Phase-1 state it leads to.
        fn aggressive_until_message_3(&mut self, server: &mut Server<SeedEntropy>) -> (Vec<u8>, Phase1State, Vec<u8>) {
            let (msg1, init) = initiate_aggressive(&initiator_config(Ikev1ExchangeMode::Aggressive), &mut self.entropy, self.me, self.server);
            let (event, msg2) = self.send(server, &msg1);
            assert_eq!(event.unwrap(), ServerEvent::Phase1SaInit);
            let (msg3, st) = init.complete(&msg2.unwrap(), self.me, self.server).unwrap();
            (msg3, st, msg1)
        }

        fn aggressive(&mut self, server: &mut Server<SeedEntropy>) -> Phase1State {
            let (msg3, st, _) = self.aggressive_until_message_3(server);
            let (event, reply) = self.send(server, &msg3);
            assert_eq!(event.unwrap(), ServerEvent::Phase1Established);
            assert_eq!(reply, None);
            st
        }

        /// Quick Mode's message 1 and the initiator waiting on message 2.
        fn quick_message_1(&mut self, st: &Phase1State) -> (Vec<u8>, crate::ikev1::quick::QuickInitiator) {
            initiate_quick(st, &mut self.entropy, SkCipher::Aes256Gcm, TS, TS, 3600).unwrap()
        }

        /// A whole Quick Mode; returns the peer's CHILD SA.
        fn quick(&mut self, server: &mut Server<SeedEntropy>, st: &Phase1State) -> ChildSa {
            self.quick_with_lifetime(server, st).0
        }

        /// [`Self::quick`], with the lifetime the peer was left holding.
        fn quick_with_lifetime(&mut self, server: &mut Server<SeedEntropy>, st: &Phase1State) -> (ChildSa, SaLifetime) {
            let (msg1, init) = self.quick_message_1(st);
            let (event, msg2) = self.send(server, &msg1);
            assert_eq!(event.unwrap(), ServerEvent::QuickSaInit);
            let (msg3, child, lifetime) = init.complete_with_lifetime(&msg2.unwrap()).unwrap();
            let (event, _) = self.send(server, &msg3);
            assert!(matches!(event.unwrap(), ServerEvent::ChildSaEstablished { .. }));
            (child, lifetime)
        }

        /// The R-U-THERE-ACK sequence number in a reply of the server's.
        fn ack_seq(&self, st: &Phase1State, reply: &[u8]) -> u32 {
            let hdr = IsakmpHeader::parse(reply).unwrap();
            let iv = crypto1::phase2_iv(st.prf, &st.phase1_iv, hdr.message_id, st.enc_block);
            let (_, payloads, _) = phase2::parse_encrypted(reply, st.prf, &st.skeyid_a, &st.enc_key, st.enc_block, &iv).unwrap();
            let notify = payloads.iter().find(|p| p.payload_type == payload::NOTIFY).unwrap();
            let (msg_type, data) = parse_notify(&notify.data).unwrap();
            assert_eq!(msg_type, notify_type::R_U_THERE_ACK);
            u32::from_be_bytes(data.try_into().unwrap())
        }
    }

    /// What the server seals, the peer opens, and back.
    fn assert_interoperate(peer: &mut ChildSa, server: &mut ChildSa) {
        let pkt: Vec<u8> = (0..40u8).collect();
        let sealed = peer.outbound.seal(&pkt, 4).unwrap();
        assert_eq!(server.inbound.open(&sealed).unwrap().0, pkt);
        let sealed = server.outbound.seal(&pkt, 4).unwrap();
        assert_eq!(peer.inbound.open(&sealed).unwrap().0, pkt);
    }

    /// A repeated message 1 gets the same message 2 back, not a second
    /// ISAKMP SA; once the exchange moved on, a late one gets nothing.
    #[test]
    fn a_repeated_message_1_gets_the_same_message_2_and_no_second_sa() {
        let (mut server, addr) = server();
        let mut peer = Peer::new(addr);
        let (msg1, init) = initiate_aggressive(&initiator_config(Ikev1ExchangeMode::Aggressive), &mut peer.entropy, peer.me, addr);
        let (_, msg2) = peer.send(&mut server, &msg1);
        let (event, again) = peer.send(&mut server, &msg1);
        assert_eq!(event.unwrap(), ServerEvent::Retransmitted);
        assert_eq!(again, msg2);
        assert_eq!(server.sessions.len(), 1);

        let (msg3, _) = init.complete(&msg2.unwrap(), peer.me, addr).unwrap();
        assert_eq!(peer.send(&mut server, &msg3).0.unwrap(), ServerEvent::Phase1Established);
        let (event, late) = peer.send(&mut server, &msg1);
        assert_eq!(event.unwrap(), ServerEvent::Ignored);
        assert_eq!(late, None);
        assert_eq!(server.sessions.len(), 1);
    }

    /// Main Mode: a repeated message 3 or 5 gets the same message 4 or 6
    /// back, and the handshake completes on it as if nothing happened; a
    /// late message 1 gets nothing.
    #[test]
    fn main_mode_repeats_get_the_same_answer() {
        let (mut server, addr) = server();
        let mut peer = Peer::new(addr);
        let (msg1, init) = initiate_main(&initiator_config(Ikev1ExchangeMode::Main), &mut peer.entropy);
        let (_, msg2) = peer.send(&mut server, &msg1);
        let (msg3, init) = init.complete_sa(&msg2.unwrap(), &mut peer.entropy, peer.me, addr).unwrap();
        let (_, msg4) = peer.send(&mut server, &msg3);
        let (event, again) = peer.send(&mut server, &msg3);
        assert_eq!(event.unwrap(), ServerEvent::Retransmitted);
        assert_eq!(again, msg4);
        let (event, late) = peer.send(&mut server, &msg1);
        assert_eq!(event.unwrap(), ServerEvent::Ignored);
        assert_eq!(late, None);

        let (msg5, init) = init.complete_ke(&msg4.unwrap()).unwrap();
        let (event, msg6) = peer.send(&mut server, &msg5);
        assert_eq!(event.unwrap(), ServerEvent::Phase1Established);
        let (event, again) = peer.send(&mut server, &msg5);
        assert_eq!(event.unwrap(), ServerEvent::Retransmitted);
        assert_eq!(again, msg6);

        let st = init.complete_id(&msg6.unwrap(), &mut peer.entropy).unwrap_or_else(|_| panic!("Main Mode must complete"));
        let mut child = peer.quick(&mut server, &st);
        assert_interoperate(&mut child, &mut server.take_child(st.cky_i).unwrap());
    }

    /// Main Mode: a message 5 that fails its checks is refused and leaves the
    /// handshake waiting for the real one.
    #[test]
    fn a_bad_main_mode_message_5_does_not_lose_the_handshake() {
        let (mut server, addr) = server();
        let mut peer = Peer::new(addr);
        let (msg1, init) = initiate_main(&initiator_config(Ikev1ExchangeMode::Main), &mut peer.entropy);
        let (_, msg2) = peer.send(&mut server, &msg1);
        let (msg3, init) = init.complete_sa(&msg2.unwrap(), &mut peer.entropy, peer.me, addr).unwrap();
        let (_, msg4) = peer.send(&mut server, &msg3);
        let (msg5, init) = init.complete_ke(&msg4.unwrap()).unwrap();
        let mut bad = msg5.clone();
        bad[IsakmpHeader::LEN] ^= 1;
        let (event, reply) = peer.send(&mut server, &bad);
        assert!(event.is_err());
        assert_eq!(reply, None);
        let (event, msg6) = peer.send(&mut server, &msg5);
        assert_eq!(event.unwrap(), ServerEvent::Phase1Established);
        assert!(init.complete_id(&msg6.unwrap(), &mut peer.entropy).is_ok());
    }

    /// RFC 2409 §5.5: Phase 2 runs under an established ISAKMP SA. Before
    /// HASH_I has authenticated the peer, Quick Mode gets nothing, and
    /// neither does an Informational.
    #[test]
    fn quick_mode_waits_for_phase_1_to_authenticate_the_peer() {
        let (mut server, addr) = server();
        let mut peer = Peer::new(addr);
        let (msg3, st, _) = peer.aggressive_until_message_3(&mut server);
        let (quick1, _) = peer.quick_message_1(&st);
        let (event, reply) = peer.send(&mut server, &quick1);
        assert_eq!(event.unwrap(), ServerEvent::Ignored);
        assert_eq!(reply, None);
        let probe = build_r_u_there(&st, &mut peer.entropy, 1).unwrap();
        let (event, reply) = peer.send(&mut server, &probe);
        assert_eq!(event.unwrap(), ServerEvent::Ignored);
        assert_eq!(reply, None);

        assert_eq!(peer.send(&mut server, &msg3).0.unwrap(), ServerEvent::Phase1Established);
        let (event, reply) = peer.send(&mut server, &quick1);
        assert_eq!(event.unwrap(), ServerEvent::QuickSaInit);
        assert!(reply.is_some());
    }

    /// A repeated Quick-Mode message 1 gets the same message 2, not a fresh
    /// exchange mistaken for message 3; a repeated message 3 is dropped.
    #[test]
    fn a_repeated_quick_mode_message_1_gets_the_same_message_2() {
        let (mut server, addr) = server();
        let mut peer = Peer::new(addr);
        let st = peer.aggressive(&mut server);
        let (msg1, init) = peer.quick_message_1(&st);
        let (_, msg2) = peer.send(&mut server, &msg1);
        let (event, again) = peer.send(&mut server, &msg1);
        assert_eq!(event.unwrap(), ServerEvent::Retransmitted);
        assert_eq!(again, msg2);

        let (msg3, mut child, _) = init.complete(&msg2.unwrap()).unwrap();
        assert_eq!(peer.send(&mut server, &msg3).0.unwrap(), ServerEvent::ChildSaEstablished { cky_i: st.cky_i });
        let (event, reply) = peer.send(&mut server, &msg3);
        assert_eq!(event.unwrap(), ServerEvent::Ignored);
        assert_eq!(reply, None);
        assert_interoperate(&mut child, &mut server.take_child(st.cky_i).unwrap());
    }

    /// A Quick-Mode message 3 that fails its checks is refused and leaves the
    /// exchange waiting for the real one.
    #[test]
    fn a_bad_quick_mode_message_3_does_not_lose_the_exchange() {
        let (mut server, addr) = server();
        let mut peer = Peer::new(addr);
        let st = peer.aggressive(&mut server);
        let (msg1, init) = peer.quick_message_1(&st);
        let (_, msg2) = peer.send(&mut server, &msg1);
        let (msg3, mut child, _) = init.complete(&msg2.unwrap()).unwrap();
        let mut bad = msg3.clone();
        bad[IsakmpHeader::LEN] ^= 1;
        assert!(peer.send(&mut server, &bad).0.is_err());
        assert_eq!(peer.send(&mut server, &msg3).0.unwrap(), ServerEvent::ChildSaEstablished { cky_i: st.cky_i });
        assert_interoperate(&mut child, &mut server.take_child(st.cky_i).unwrap());
    }

    /// A Quick Mode whose exchange is over is never taken again, even
    /// replayed with its own Message ID and valid protection.
    #[test]
    fn a_replayed_quick_mode_of_an_exchange_already_over_is_ignored() {
        let (mut server, addr) = server();
        let mut peer = Peer::new(addr);
        let st = peer.aggressive(&mut server);
        let (old, init) = peer.quick_message_1(&st);
        let (_, msg2) = peer.send(&mut server, &old);
        let (msg3, _, _) = init.complete(&msg2.unwrap()).unwrap();
        peer.send(&mut server, &msg3).0.unwrap();
        let mut child = peer.quick(&mut server, &st);

        let (event, reply) = peer.send(&mut server, &old);
        assert_eq!(event.unwrap(), ServerEvent::Ignored);
        assert_eq!(reply, None);
        assert_interoperate(&mut child, &mut server.take_child(st.cky_i).unwrap());
    }

    /// A message naming an ISAKMP SA by the wrong responder cookie is not
    /// that SA's.
    #[test]
    fn a_message_under_the_wrong_responder_cookie_is_ignored() {
        let (mut server, addr) = server();
        let mut peer = Peer::new(addr);
        let st = peer.aggressive(&mut server);
        let mut probe = build_r_u_there(&st, &mut peer.entropy, 7).unwrap();
        probe[8] ^= 1;
        let (event, reply) = peer.send(&mut server, &probe);
        assert_eq!(event.unwrap(), ServerEvent::Ignored);
        assert_eq!(reply, None);
    }

    /// An R-U-THERE or a Delete sent under this ISAKMP SA but naming another
    /// SA is not about this one (RFC 3706 §6.1, RFC 2408 §3.15).
    #[test]
    fn a_notify_or_delete_naming_another_sa_is_ignored() {
        let (mut server, addr) = server();
        let mut peer = Peer::new(addr);
        let st = peer.aggressive(&mut server);
        let cky_i = st.cky_i;
        let child = peer.quick(&mut server, &st);
        // Same keys, other cookies in the payload, this SA's in the header.
        let mut other = st.clone();
        other.cky_r[0] ^= 1;
        for build in [build_r_u_there(&other, &mut peer.entropy, 1), build_isakmp_delete(&other, &mut peer.entropy)] {
            let mut msg = build.unwrap();
            msg[8..16].copy_from_slice(&st.cky_r);
            let (event, reply) = peer.send(&mut server, &msg);
            assert_eq!(event.unwrap(), ServerEvent::Ignored);
            assert_eq!(reply, None);
        }
        // The server's own inbound SPI, not the peer's.
        let delete = build_esp_delete(&st, &mut peer.entropy, child.outbound.spi()).unwrap();
        assert_eq!(peer.send(&mut server, &delete).0.unwrap(), ServerEvent::Ignored);
        assert!(server.child(cky_i).is_some());
        let probe = build_r_u_there(&st, &mut peer.entropy, 1).unwrap();
        assert_eq!(peer.send(&mut server, &probe).0.unwrap(), ServerEvent::DpdAnswered { cky_i });
    }

    /// RFC 3706 §5.2 / §6.1: having advertised DPD, the server answers every
    /// R-U-THERE with the same sequence number -- a repeat included -- but
    /// not one whose number went backwards (§6.2), nor one sent in the clear.
    #[test]
    fn r_u_there_is_answered_with_its_sequence_number() {
        let (mut server, addr) = server();
        let mut peer = Peer::new(addr);
        let st = peer.aggressive(&mut server);
        let cky_i = st.cky_i;
        for seq in [100, 100, 101] {
            let probe = build_r_u_there(&st, &mut peer.entropy, seq).unwrap();
            let (event, reply) = peer.send(&mut server, &probe);
            assert_eq!(event.unwrap(), ServerEvent::DpdAnswered { cky_i }, "seq {seq}");
            assert_eq!(peer.ack_seq(&st, &reply.expect("an R-U-THERE must be answered")), seq);
        }
        let stale = build_r_u_there(&st, &mut peer.entropy, 99).unwrap();
        let (event, reply) = peer.send(&mut server, &stale);
        assert_eq!(event.unwrap(), ServerEvent::Ignored);
        assert_eq!(reply, None);

        // The same Notify, unencrypted.
        let mut spi_and_seq = [st.cky_i, st.cky_r].concat();
        spi_and_seq.extend_from_slice(&102u32.to_be_bytes());
        let mut body = vec![0, 0, 0, 1, protocol::ISAKMP, 16];
        body.extend_from_slice(&notify_type::R_U_THERE.to_be_bytes());
        body.extend_from_slice(&spi_and_seq);
        let hdr = IsakmpHeader { init_cookie: st.cky_i, resp_cookie: st.cky_r, next_payload: 0, version: IsakmpHeader::VERSION_1_0, exchange_type: exchange::INFORMATIONAL, flags: 0, message_id: 0x0102_0304, length: 0 };
        let clear = isakmp::build_message(hdr, &[(payload::NOTIFY, body)]);
        let (event, reply) = peer.send(&mut server, &clear);
        assert_eq!(event.unwrap(), ServerEvent::Ignored);
        assert_eq!(reply, None);
        assert_eq!(flags::ENCRYPTION & clear[19], 0);
    }

    /// An ESP Delete naming the SPI the peer receives on drops the CHILD SA,
    /// whether or not the caller took it, and only once; the ISAKMP SA stays
    /// up.
    #[test]
    fn an_esp_delete_drops_the_child_sa() {
        let (mut server, addr) = server();
        let mut peer = Peer::new(addr);
        let st = peer.aggressive(&mut server);
        let cky_i = st.cky_i;
        let child = peer.quick(&mut server, &st);
        let delete = build_esp_delete(&st, &mut peer.entropy, child.inbound.spi()).unwrap();
        assert_eq!(peer.send(&mut server, &delete).0.unwrap(), ServerEvent::ChildDeleted { cky_i });
        assert!(server.child(cky_i).is_none());

        let child = peer.quick(&mut server, &st);
        server.take_child(cky_i).unwrap();
        let delete = build_esp_delete(&st, &mut peer.entropy, child.inbound.spi()).unwrap();
        let (event, reply) = peer.send(&mut server, &delete);
        assert_eq!(event.unwrap(), ServerEvent::ChildDeleted { cky_i });
        assert_eq!(reply, None);
        assert_eq!(peer.send(&mut server, &delete).0.unwrap(), ServerEvent::Ignored);
        let probe = build_r_u_there(&st, &mut peer.entropy, 1).unwrap();
        assert_eq!(peer.send(&mut server, &probe).0.unwrap(), ServerEvent::DpdAnswered { cky_i });
    }

    /// The lifetime the server grants a CHILD SA is what it says: the peer is
    /// left holding the same, [`Server::child_lifetime`] reports it for as long as
    /// the CHILD SA lasts -- taken by the caller or not -- and not once an ESP
    /// Delete has closed it. A limit set with [`Server::set_child_volume_limit`]
    /// applies to the exchanges after it, not to one already over.
    #[test]
    fn the_server_says_what_it_granted_and_forgets_it_with_the_child_sa() {
        let (mut server, addr) = server();
        let mut peer = Peer::new(addr);
        let st = peer.aggressive(&mut server);
        let cky_i = st.cky_i;
        assert_eq!(server.child_lifetime(cky_i), None, "no CHILD SA yet");

        server.set_child_volume_limit(Some(100_000));
        let (child, held) = peer.quick_with_lifetime(&mut server, &st);
        let limited = SaLifetime { seconds: 3600, kilobytes: Some(100_000) };
        assert_eq!((held, server.child_lifetime(cky_i)), (limited, Some(limited)));
        server.take_child(cky_i).unwrap();
        assert_eq!(server.child_lifetime(cky_i), Some(limited), "taking the CHILD SA does not end its lifetime");

        server.set_child_volume_limit(None);
        assert_eq!(server.child_lifetime(cky_i), Some(limited), "a new limit is not applied to an SA already granted");
        let delete = build_esp_delete(&st, &mut peer.entropy, child.inbound.spi()).unwrap();
        assert_eq!(peer.send(&mut server, &delete).0.unwrap(), ServerEvent::ChildDeleted { cky_i });
        assert_eq!(server.child_lifetime(cky_i), None);

        let (_child, held) = peer.quick_with_lifetime(&mut server, &st);
        let unlimited = SaLifetime { seconds: 3600, kilobytes: None };
        assert_eq!((held, server.child_lifetime(cky_i)), (unlimited, Some(unlimited)));
        assert_eq!(server.child_lifetime([0xEE; 8]), None, "another ISAKMP SA's");
    }

    /// An ISAKMP Delete closes the ISAKMP SA with its CHILD SA; nothing is
    /// answered under it afterwards.
    #[test]
    fn an_isakmp_delete_closes_the_sa() {
        let (mut server, addr) = server();
        let mut peer = Peer::new(addr);
        let st = peer.aggressive(&mut server);
        let cky_i = st.cky_i;
        peer.quick(&mut server, &st);
        let delete = build_isakmp_delete(&st, &mut peer.entropy).unwrap();
        let (event, reply) = peer.send(&mut server, &delete);
        assert_eq!(event.unwrap(), ServerEvent::Deleted { cky_i });
        assert_eq!(reply, None);
        assert!(server.sessions.is_empty());
        assert!(server.child(cky_i).is_none());
        let probe = build_r_u_there(&st, &mut peer.entropy, 1).unwrap();
        let (event, reply) = peer.send(&mut server, &probe);
        assert_eq!(event.unwrap(), ServerEvent::Ignored);
        assert_eq!(reply, None);
    }
}
