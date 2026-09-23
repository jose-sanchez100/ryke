//! A blocking IKEv2 **responder** (server) over UDP.
//!
//! Handles the two-message handshake — `IKE_SA_INIT` then `IKE_AUTH` — keeping
//! per-SA state keyed by the SPI pair so the second message can be correlated
//! with the first. Authenticates as its [`AuthConfig`] says: a pre-shared key,
//! or certificates (RFC 7427 signatures).
//!
//! This is a *minimal* responder in the sense of RFC 7296 Appendix A, not a
//! gateway, and what holds for it says nothing about [`crate::Ikev2Session`]
//! (the client) or the library's other building blocks. What it does:
//!
//! - one IKE SA and one ESP CHILD SA per `IKE_SA_INIT` + `IKE_AUTH`, and
//!   nothing else: no EAP, no NAT traversal, no configuration payload, no
//!   cookies;
//! - window size 1 (§2.3): a request is taken only with the next Message ID
//!   (§2.2); a retransmission of the last one gets the response already sent,
//!   unchanged, never a new one (§2.1); any other request is dropped
//!   unanswered. An `IKE_SA_INIT` retransmission is recognised by the whole
//!   request, not the initiator's SPI, which two peers behind one NAT may
//!   share;
//! - every INFORMATIONAL request is answered: a Delete closes what it names
//!   (§1.4.1), anything else gets an empty response (Appendix A);
//! - every `CREATE_CHILD_SA` request -- another CHILD SA, or a rekey of the
//!   CHILD SA or of the IKE SA -- is refused with `NO_ADDITIONAL_SAS`
//!   (Appendix A), so a peer replaces an expiring SA by deleting it and
//!   connecting again;
//! - IKE fragmentation (RFC 7383), which `IKE_SA_INIT` always advertises:
//!   a fragmented request is reassembled, each fragment authenticated
//!   before it is kept ([`crate::ikev2::fragment::Reassembly`]), and one
//!   left incomplete for [`FRAGMENT_REASSEMBLY_TIMEOUT`] is dropped. Its
//!   response goes out in fragments no larger than the largest fragment
//!   of the request, unless it fits in one of those whole (§2.4); a
//!   retransmitted fragment 1 of the request gets them again, any other
//!   fragment of it nothing (§2.6.1). A request that came whole is
//!   answered whole. There is no path MTU discovery;
//! - it never starts an exchange (no liveness checks, rekeys or Deletes of
//!   its own). The SAs last until the peer deletes them or reconnects with
//!   `INITIAL_CONTACT`; the ESP data plane is the caller's
//!   ([`Server::take_child`]).

use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

use crate::entropy::Entropy;
use crate::esp::ChildSa;
use crate::ikev2::exchange::{responder_respond, CompletedSaInit, LocalSecret};
use crate::ikev2::fragment::{self, Accepted, MessageKey, Reassembly};
use crate::ikev2::ike_auth::{self, AuthConfig};
use crate::ikev2::informational::{build_informational, open_informational};
use crate::ikev2::message::{ExchangeType, IkeHeader, PayloadType};
use crate::ikev2::payload::{protocol_id, Delete, Identification};
use crate::ikev2::rekey::build_child_refusal;
use crate::ikev2::sk::{self, open_encrypted};
use crate::role::Role;
use crate::transport::{DriverError, UdpTransport};

/// Nonce length we generate (RFC 7296 §2.10: ≥16 and ≥ half the PRF key).
const NONCE_LEN: usize = 32;

/// How long the fragments of a request are kept waiting for the rest
/// (RFC 7383 §2.6).
pub const FRAGMENT_REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(30);

/// What [`Server::handle_one`] did with one datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerEvent {
    /// Answered an `IKE_SA_INIT`; the IKE SA is half-open awaiting `IKE_AUTH`.
    SaInit { spi_i: u64, spi_r: u64 },
    /// Completed `IKE_AUTH`; the IKE SA is established with a verified peer.
    Established { spi_i: u64, spi_r: u64, peer_id: Identification },
    /// Resent the response to a request the peer retransmitted.
    Retransmitted { spi_i: u64, spi_r: u64 },
    /// Kept an authentic fragment (RFC 7383) of the peer's next request;
    /// the rest is still to come.
    FragmentStored { spi_i: u64, spi_r: u64 },
    /// Answered an INFORMATIONAL request that deleted nothing (a liveness
    /// check, or notifies).
    Informational { spi_i: u64, spi_r: u64 },
    /// The peer deleted the IKE SA's CHILD SA; the IKE SA stays up. A caller
    /// that took the CHILD SA ([`Server::take_child`]) drops it.
    ChildDeleted { spi_i: u64, spi_r: u64 },
    /// The peer deleted the IKE SA, and with it its CHILD SA.
    Deleted { spi_i: u64, spi_r: u64 },
    /// Refused a `CREATE_CHILD_SA` request with `NO_ADDITIONAL_SAS`.
    Refused { spi_i: u64, spi_r: u64 },
    /// A datagram we don't act on: an unknown SPI pair, a request out of
    /// order or of an exchange we don't take at that point, or a response.
    Ignored,
}

/// One IKE SA, from the `IKE_SA_INIT` that opened it.
struct IkeSa {
    sa: CompletedSaInit,
    /// The `IKE_SA_INIT` request that opened it and our response.
    init: (Vec<u8>, Vec<u8>),
    /// The Message ID the peer's next request must carry.
    next_request_id: u32,
    /// The peer's last request and our response to it: one datagram, or its
    /// fragments.
    last: Option<(Vec<u8>, Vec<Vec<u8>>)>,
    /// The fragments in hand of the peer's next request, since when, and
    /// the size of the largest.
    fragments: Option<(Reassembly, Instant, usize)>,
    /// The peer's verified identity, once `IKE_AUTH` is through.
    peer_id: Option<Identification>,
    /// The ESP SPIs of the CHILD SA, ours then the peer's, while it lasts --
    /// kept apart from [`Server::children`] since the caller may have taken it.
    child_spis: Option<(u32, u32)>,
}

/// A UDP IKEv2 responder driven by an [`Entropy`] source, authenticating peers
/// as its [`AuthConfig`] says.
pub struct Server<E> {
    transport: UdpTransport,
    entropy: E,
    auth: AuthConfig,
    sessions: HashMap<(u64, u64), IkeSa>,
    children: HashMap<(u64, u64), ChildSa>,
}

impl<E: Entropy> Server<E> {
    pub fn bind(addr: impl ToSocketAddrs, entropy: E, auth: AuthConfig) -> io::Result<Self> {
        Ok(Self {
            transport: UdpTransport::bind(addr)?,
            entropy,
            auth,
            sessions: HashMap::new(),
            children: HashMap::new(),
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.transport.local_addr()
    }

    pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.transport.set_read_timeout(dur)
    }

    /// The keys for an established IKE SA (for the eventual ESP data path).
    pub fn session(&self, spi_i: u64, spi_r: u64) -> Option<&CompletedSaInit> {
        self.sessions.get(&(spi_i, spi_r)).map(|ike| &ike.sa)
    }

    /// Borrow the established ESP CHILD SA for an IKE SA (the data-plane keys).
    pub fn child(&self, spi_i: u64, spi_r: u64) -> Option<&ChildSa> {
        self.children.get(&(spi_i, spi_r))
    }

    /// Take ownership of the established ESP CHILD SA (to run the data plane,
    /// which mutates the sequence counters).
    pub fn take_child(&mut self, spi_i: u64, spi_r: u64) -> Option<ChildSa> {
        self.children.remove(&(spi_i, spi_r))
    }

    /// Receive one datagram and advance the handshake it belongs to.
    pub fn handle_one(&mut self) -> Result<ServerEvent, DriverError> {
        let (data, from) = self.transport.recv_from()?;
        let header = IkeHeader::parse(&data)?;
        if header.flags.response {
            // We never send a request, so no response is ours to take.
            return Ok(ServerEvent::Ignored);
        }
        if header.exchange_type == ExchangeType::IkeSaInit {
            return self.answer_sa_init(data, from);
        }

        let key = (header.initiator_spi, header.responder_spi);
        let Some(ike) = self.sessions.get(&key) else {
            return Ok(ServerEvent::Ignored);
        };
        if header.next_payload == PayloadType::EncryptedFragment {
            return self.take_fragment(key, &header, data, from);
        }
        if let Some((_, response)) = ike.last.as_ref().filter(|(request, _)| *request == data) {
            for datagram in response {
                self.transport.send_to(datagram, from)?;
            }
            return Ok(ServerEvent::Retransmitted { spi_i: key.0, spi_r: key.1 });
        }
        if header.message_id != ike.next_request_id {
            // RFC 7296 §2.3: outside the window, and never acknowledged.
            return Ok(ServerEvent::Ignored);
        }
        self.answer(key, &header, data, from, None)
    }

    /// Answer the request `data` with the next Message ID -- in fragments no
    /// larger than `fragment_size` when it came in fragments that large.
    fn answer(
        &mut self,
        key: (u64, u64),
        header: &IkeHeader,
        data: Vec<u8>,
        from: SocketAddr,
        fragment_size: Option<usize>,
    ) -> Result<ServerEvent, DriverError> {
        let ike = &self.sessions[&key];
        // The keys to fragment the response with, before a Delete takes them.
        let sa = fragment_size.map(|_| ike.sa.clone());
        let (response, event) = match (header.exchange_type, ike.peer_id.is_some()) {
            (ExchangeType::IkeAuth, false) => self.answer_ike_auth(key, &data)?,
            (ExchangeType::Informational, true) => self.answer_informational(key, header.message_id, &data)?,
            (ExchangeType::CreateChildSa, true) => self.refuse_create_child_sa(key, header.message_id, &data)?,
            _ => return Ok(ServerEvent::Ignored),
        };
        let response = match (sa, fragment_size) {
            // RFC 7383 §2.4: in the form of the request, unless it fits whole.
            (Some(sa), Some(size)) if response.len() > size => {
                let keys = &sa.keys;
                let iv_base = self.entropy.next_u64();
                fragment::fragment_message(sa.suite.sk_cipher(), &response, &keys.sk_er, &keys.sk_ar, iv_base, size)?
            }
            _ => vec![response],
        };
        for datagram in &response {
            self.transport.send_to(datagram, from)?;
        }
        if let Some(ike) = self.sessions.get_mut(&key) {
            ike.next_request_id += 1;
            ike.last = Some((data, response));
        }
        Ok(event)
    }

    /// One fragment (RFC 7383) of a request on the IKE SA `key`.
    ///
    /// Fragment 1 of the request last answered, once it authenticates, gets
    /// the answer again; any other fragment of it is ignored (§2.6.1). A
    /// fragment of the next request goes through [`Reassembly::accept`] --
    /// checked, authenticated, and only then kept -- and one of another
    /// request is ignored. The request it completes is sealed again as one
    /// `SK` message under the peer's keys and answered as if it had come
    /// whole, but in fragments.
    fn take_fragment(&mut self, key: (u64, u64), header: &IkeHeader, data: Vec<u8>, from: SocketAddr) -> Result<ServerEvent, DriverError> {
        let (spi_i, spi_r) = key;
        let ike = self.sessions.get_mut(&key).expect("looked up by the caller");
        let (cipher, sk_e, sk_a) = (ike.sa.suite.sk_cipher(), &ike.sa.keys.sk_ei, &ike.sa.keys.sk_ai);
        if let Some((_, response)) = ike.last.as_ref().filter(|_| header.message_id.wrapping_add(1) == ike.next_request_id) {
            if !fragment::verify_fragment(cipher, &data, sk_e, sk_a).is_ok_and(|(number, _)| number == 1) {
                return Ok(ServerEvent::Ignored);
            }
            for datagram in response {
                self.transport.send_to(datagram, from)?;
            }
            return Ok(ServerEvent::Retransmitted { spi_i, spi_r });
        }
        if header.message_id != ike.next_request_id {
            return Ok(ServerEvent::Ignored);
        }
        let message = MessageKey::of(header);
        let kept = ike.fragments.take().filter(|(_, since, _)| since.elapsed() <= FRAGMENT_REASSEMBLY_TIMEOUT);
        let (mut request, since, largest, other) = match kept {
            Some((request, since, largest)) if request.key() == message => (request, since, largest, None),
            other => (Reassembly::new(message), Instant::now(), 0, other),
        };
        match request.accept(&data, cipher, sk_e, sk_a) {
            Accepted::Stored => {
                ike.fragments = Some((request, since, largest.max(data.len())));
                Ok(ServerEvent::FragmentStored { spi_i, spi_r })
            }
            Accepted::Discarded(_) => {
                ike.fragments = if request.is_empty() { other } else { Some((request, since, largest)) };
                Ok(ServerEvent::Ignored)
            }
            Accepted::Complete(first, inner) => {
                let mut iv = [0u8; 8];
                self.entropy.fill(&mut iv);
                let whole = sk::build_encrypted(cipher, *header, first, &inner, sk_e, sk_a, &iv)?;
                let header = IkeHeader::parse(&whole)?;
                self.answer(key, &header, whole, from, Some(largest.max(data.len())))
            }
        }
    }

    /// RFC 7296 §2.1: an `IKE_SA_INIT` is a retransmission for a half-open IKE
    /// SA (resent the same response), one whose `IKE_AUTH` already came in
    /// (ignored), or a new IKE SA.
    fn answer_sa_init(&mut self, data: Vec<u8>, from: SocketAddr) -> Result<ServerEvent, DriverError> {
        if let Some((&(spi_i, spi_r), ike)) = self.sessions.iter().find(|(_, ike)| ike.init.0 == data) {
            if ike.last.is_some() {
                return Ok(ServerEvent::Ignored);
            }
            self.transport.send_to(&ike.init.1, from)?;
            return Ok(ServerEvent::Retransmitted { spi_i, spi_r });
        }
        let local = LocalSecret::generate(&mut self.entropy, NONCE_LEN);
        let (response, sa) = responder_respond(&data, &local)?;
        self.transport.send_to(&response, from)?;
        let (spi_i, spi_r) = (sa.spi_i, sa.spi_r);
        let ike = IkeSa { sa, init: (data, response), next_request_id: 1, last: None, fragments: None, peer_id: None, child_spis: None };
        self.sessions.insert((spi_i, spi_r), ike);
        Ok(ServerEvent::SaInit { spi_i, spi_r })
    }

    fn answer_ike_auth(&mut self, key: (u64, u64), data: &[u8]) -> Result<(Vec<u8>, ServerEvent), DriverError> {
        let sa = self.sessions[&key].sa.clone();
        let child_spi = self.entropy.next_u64() as u32;
        let mut iv = [0u8; 8];
        self.entropy.fill(&mut iv);
        let (response, peer_id, peer_child_spi, initial_contact) =
            ike_auth::responder_process_auth(&sa, data, &self.auth, child_spi, &iv, None)?;
        if initial_contact {
            // RFC 7296 §2.4: the peer has no state from before, so any IKE/CHILD
            // SA we still hold for the same identity is stale -- drop it, but not
            // the one we're establishing right now.
            let stale: Vec<(u64, u64)> = self
                .sessions
                .iter()
                .filter(|entry| *entry.0 != key && entry.1.peer_id.as_ref() == Some(&peer_id))
                .map(|entry| *entry.0)
                .collect();
            for k in stale {
                self.sessions.remove(&k);
                self.children.remove(&k);
            }
        }
        let child =
            ChildSa::derive(sa.suite.prf_algorithm(), &sa.keys.sk_d, &sa.ni, &sa.nr, Role::Responder, child_spi, peer_child_spi);
        self.children.insert(key, child);
        let ike = self.sessions.get_mut(&key).expect("looked up by the caller");
        ike.peer_id = Some(peer_id.clone());
        ike.child_spis = Some((child_spi, peer_child_spi));
        Ok((response, ServerEvent::Established { spi_i: key.0, spi_r: key.1, peer_id }))
    }

    /// RFC 7296 §1.4.1: a Delete of the IKE SA is answered empty and closes it
    /// with its CHILD SA; a Delete of the CHILD SA is answered with a Delete of
    /// its other half. Nothing else needs more than an empty response.
    fn answer_informational(&mut self, key: (u64, u64), message_id: u32, data: &[u8]) -> Result<(Vec<u8>, ServerEvent), DriverError> {
        let ike = self.sessions.get_mut(&key).expect("looked up by the caller");
        let mut ike_deleted = false;
        let mut child_deleted = None;
        for (payload_type, body) in open_informational(&ike.sa, data)? {
            if payload_type != PayloadType::Delete {
                continue;
            }
            let delete = Delete::parse(&body)?;
            match (delete.protocol_id, ike.child_spis) {
                (protocol_id::IKE, _) => ike_deleted = true,
                (protocol_id::ESP, Some((ours, theirs))) if delete.spis.contains(&theirs) => child_deleted = Some(ours),
                _ => {}
            }
        }
        let mut iv = [0u8; 8];
        self.entropy.fill(&mut iv);
        let (spi_i, spi_r) = key;
        if ike_deleted {
            let response = build_informational(&ike.sa, message_id, true, &[], &iv)?;
            self.sessions.remove(&key);
            self.children.remove(&key);
            return Ok((response, ServerEvent::Deleted { spi_i, spi_r }));
        }
        let Some(ours) = child_deleted else {
            let response = build_informational(&ike.sa, message_id, true, &[], &iv)?;
            return Ok((response, ServerEvent::Informational { spi_i, spi_r }));
        };
        let answer = [(PayloadType::Delete, Delete::esp(vec![ours]).to_bytes())];
        let response = build_informational(&ike.sa, message_id, true, &answer, &iv)?;
        ike.child_spis = None;
        self.children.remove(&key);
        Ok((response, ServerEvent::ChildDeleted { spi_i, spi_r }))
    }

    /// RFC 7296 Appendix A: a minimal responder recognises `CREATE_CHILD_SA`
    /// requests and refuses every one with `NO_ADDITIONAL_SAS` -- but only a
    /// request the peer really sent, which it must have protected.
    fn refuse_create_child_sa(&mut self, key: (u64, u64), message_id: u32, data: &[u8]) -> Result<(Vec<u8>, ServerEvent), DriverError> {
        let sa = &self.sessions[&key].sa;
        open_encrypted(sa.suite.sk_cipher(), data, &sa.keys.sk_ei, &sa.keys.sk_ai)?;
        let mut iv = [0u8; 8];
        self.entropy.fill(&mut iv);
        let response = build_child_refusal(sa, message_id, &iv)?;
        Ok((response, ServerEvent::Refused { spi_i: key.0, spi_r: key.1 }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::{OsEntropy, SeedEntropy};
    use crate::ikev2::client::Client;
    use crate::ikev2::exchange::{default_offer, initiator_complete, initiator_request};
    use crate::ikev2::ike_auth::{esp_offer, initiator_auth_request, initiator_verify_auth, AuthConfig};
    use crate::ikev2::ike_rekey::build_ike_rekey_request;
    use crate::ikev2::informational::dpd_request;
    use crate::ikev2::payload::{notify_type, Identification, Notify, TrafficSelectors};
    use crate::ikev2::rekey::build_child_request;
    use crate::ikev2::sk::SkCipher;
    use std::net::UdpSocket;
    use std::thread;

    /// RFC 7296 §2.4: a client that reconnects (same identity, fresh IKE SA --
    /// e.g. after a restart or a network flap it didn't cleanly tear down
    /// after) sends `N(INITIAL_CONTACT)` on its first `IKE_AUTH`. The server
    /// must drop its *old* SA for that identity once the new one
    /// authenticates, not accumulate stale entries forever.
    #[test]
    fn initial_contact_evicts_the_peers_stale_prior_sa() {
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut server = Server::bind(bind, OsEntropy::new().unwrap(), AuthConfig::psk(Identification::fqdn("gw.test"), b"pw".to_vec())).unwrap();
        let server_addr = server.local_addr().unwrap();
        server.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

        let handle_two = |server: &mut Server<OsEntropy>| {
            server.handle_one().unwrap(); // IKE_SA_INIT
            server.handle_one().unwrap() // IKE_AUTH
        };

        let connect = move |server_addr: SocketAddr| {
            let cfg = AuthConfig::psk(Identification::fqdn("client.test"), b"pw".to_vec());
            let mut client = Client::bind("127.0.0.1:0", OsEntropy::new().unwrap()).unwrap();
            client.connect(server_addr, &cfg, 0x1234).unwrap()
        };

        // First connection: client establishes, server records it.
        let t1 = thread::spawn(move || connect(server_addr));
        let ev1 = handle_two(&mut server);
        t1.join().unwrap();
        let key1 = match ev1 {
            ServerEvent::Established { spi_i, spi_r, .. } => (spi_i, spi_r),
            other => panic!("expected Established, got {other:?}"),
        };
        assert_eq!(server.sessions.len(), 1);
        assert!(server.sessions.contains_key(&key1));

        // Second connection, same identity, fresh IKE SA (as if the client
        // restarted): its IKE_AUTH carries INITIAL_CONTACT, so the server
        // must evict the first SA once the second authenticates.
        let t2 = thread::spawn(move || connect(server_addr));
        let ev2 = handle_two(&mut server);
        t2.join().unwrap();
        let key2 = match ev2 {
            ServerEvent::Established { spi_i, spi_r, .. } => (spi_i, spi_r),
            other => panic!("expected Established, got {other:?}"),
        };
        assert_ne!(key1, key2, "the two connects must produce distinct IKE SAs");
        assert_eq!(server.sessions.len(), 1, "the stale first SA must have been evicted");
        assert!(server.sessions.contains_key(&key2));
        assert!(!server.sessions.contains_key(&key1));
        assert!(server.children.contains_key(&key2));
        assert!(!server.children.contains_key(&key1));
    }

    const PSK: &[u8] = b"pw";
    /// The ESP SPI the test peer picks for its CHILD SA.
    const PEER_CHILD_SPI: u32 = 0x0C0F_FEE0;

    fn server() -> (Server<SeedEntropy>, SocketAddr) {
        let server = Server::bind("127.0.0.1:0", SeedEntropy::new(0x5EED), AuthConfig::psk(Identification::fqdn("gw.test"), PSK.to_vec())).unwrap();
        server.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let addr = server.local_addr().unwrap();
        (server, addr)
    }

    /// A peer that builds its requests by hand, so it can send any of them
    /// again bitwise identical, as a retransmission.
    struct Peer {
        sock: UdpSocket,
        server: SocketAddr,
        sa: CompletedSaInit,
        init_request: Vec<u8>,
        auth_request: Vec<u8>,
        auth_response: Vec<u8>,
        /// The SPI the server picked for its end of the CHILD SA.
        server_child_spi: u32,
    }

    impl Peer {
        fn key(&self) -> (u64, u64) {
            (self.sa.spi_i, self.sa.spi_r)
        }

        /// Send `request`, have the server take it, and collect what it sent
        /// back, if anything.
        fn send(&self, server: &mut Server<SeedEntropy>, request: &[u8]) -> (Result<ServerEvent, DriverError>, Option<Vec<u8>>) {
            self.sock.send_to(request, self.server).unwrap();
            let event = server.handle_one();
            let mut buf = vec![0u8; 65535];
            let reply = self.sock.recv(&mut buf).ok().map(|n| buf[..n].to_vec());
            (event, reply)
        }

        /// Open a response of the server's, returning its header and inner payloads.
        fn open(&self, response: &[u8]) -> (IkeHeader, Vec<(PayloadType, Vec<u8>)>) {
            let header = IkeHeader::parse(response).unwrap();
            let (first, inner) = open_encrypted(self.sa.suite.sk_cipher(), response, &self.sa.keys.sk_er, &self.sa.keys.sk_ar).unwrap();
            let payloads = crate::ikev2::message::payloads(first, &inner).map(|p| p.unwrap()).map(|p| (p.payload_type, p.data.to_vec())).collect();
            (header, payloads)
        }
    }

    /// Run `IKE_SA_INIT` and `IKE_AUTH` against `server` from a fresh socket.
    fn establish(server: &mut Server<SeedEntropy>, addr: SocketAddr) -> Peer {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        let local = LocalSecret::generate(&mut SeedEntropy::new(0xC11E), NONCE_LEN);
        let init_request = initiator_request(&local, &default_offer());
        sock.send_to(&init_request, addr).unwrap();
        assert!(matches!(server.handle_one().unwrap(), ServerEvent::SaInit { .. }));
        let mut buf = vec![0u8; 65535];
        let n = sock.recv(&mut buf).unwrap();
        let sa = initiator_complete(&local, &init_request, &buf[..n]).unwrap();

        let cfg = AuthConfig::psk(Identification::fqdn("client.test"), PSK.to_vec());
        let auth_request = initiator_auth_request(&sa, &cfg, PEER_CHILD_SPI, &esp_offer(0), &[1u8; 8]).unwrap();
        sock.send_to(&auth_request, addr).unwrap();
        assert!(matches!(server.handle_one().unwrap(), ServerEvent::Established { .. }));
        let n = sock.recv(&mut buf).unwrap();
        let auth_response = buf[..n].to_vec();
        let (_, server_child_spi, ..) = initiator_verify_auth(&sa, &auth_response, &cfg, &esp_offer(0)).unwrap();
        Peer { sock, server: addr, sa, init_request, auth_request, auth_response, server_child_spi }
    }

    /// RFC 7296 §2.1: the peer resends `IKE_SA_INIT` when our response got
    /// lost; it must get that same response back, not a second IKE SA with
    /// other SPIs, nonces and keys that it would never use.
    #[test]
    fn a_retransmitted_ike_sa_init_gets_the_same_response_and_no_second_ike_sa() {
        let (mut server, addr) = server();
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        let local = LocalSecret::generate(&mut SeedEntropy::new(0xC11E), NONCE_LEN);
        let request = initiator_request(&local, &default_offer());
        let mut buf = vec![0u8; 65535];

        sock.send_to(&request, addr).unwrap();
        let ServerEvent::SaInit { spi_i, spi_r } = server.handle_one().unwrap() else { panic!("expected SaInit") };
        let n = sock.recv(&mut buf).unwrap();
        let first = buf[..n].to_vec();

        sock.send_to(&request, addr).unwrap();
        assert_eq!(server.handle_one().unwrap(), ServerEvent::Retransmitted { spi_i, spi_r });
        let n = sock.recv(&mut buf).unwrap();
        assert_eq!(buf[..n], first[..], "the retransmission must get the same response");
        assert_eq!(server.sessions.len(), 1, "no second IKE SA");

        // A new request with the same initiator SPI -- another peer behind
        // the same NAT, say -- is a new IKE SA all the same.
        let other = LocalSecret { nonce: vec![0x77; NONCE_LEN], ..local };
        sock.send_to(&initiator_request(&other, &default_offer()), addr).unwrap();
        assert!(matches!(server.handle_one().unwrap(), ServerEvent::SaInit { .. }));
        assert_eq!(server.sessions.len(), 2);
    }

    /// RFC 7296 §1.4: INFORMATIONAL exchanges come only after the initial
    /// ones, so on a half-open IKE SA nothing but `IKE_AUTH` is taken.
    #[test]
    fn nothing_but_ike_auth_is_taken_before_ike_auth() {
        let (mut server, addr) = server();
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        let local = LocalSecret::generate(&mut SeedEntropy::new(0xC11E), NONCE_LEN);
        let request = initiator_request(&local, &default_offer());
        let mut buf = vec![0u8; 65535];
        sock.send_to(&request, addr).unwrap();
        server.handle_one().unwrap();
        let n = sock.recv(&mut buf).unwrap();
        let sa = initiator_complete(&local, &request, &buf[..n]).unwrap();

        sock.send_to(&dpd_request(&sa, 1, &[15u8; 8]).unwrap(), addr).unwrap();
        assert_eq!(server.handle_one().unwrap(), ServerEvent::Ignored);
        assert!(sock.recv(&mut buf).is_err(), "no answer before IKE_AUTH");

        let cfg = AuthConfig::psk(Identification::fqdn("client.test"), PSK.to_vec());
        sock.send_to(&initiator_auth_request(&sa, &cfg, PEER_CHILD_SPI, &esp_offer(0), &[16u8; 8]).unwrap(), addr).unwrap();
        assert!(matches!(server.handle_one().unwrap(), ServerEvent::Established { .. }));
    }

    /// RFC 7296 §2.1: once `IKE_AUTH` came in, a late `IKE_SA_INIT`
    /// retransmission is ignored.
    #[test]
    fn an_ike_sa_init_retransmitted_after_ike_auth_is_ignored() {
        let (mut server, addr) = server();
        let peer = establish(&mut server, addr);
        let (event, reply) = peer.send(&mut server, &peer.init_request);
        assert_eq!(event.unwrap(), ServerEvent::Ignored);
        assert_eq!(reply, None);
        assert_eq!(server.sessions.len(), 1);
    }

    /// RFC 7296 §2.1: a retransmitted `IKE_AUTH` gets the same response. Taking
    /// it anew would put a CHILD SA with an SPI the peer never learnt in place
    /// of the one it is using.
    #[test]
    fn a_retransmitted_ike_auth_gets_the_same_response_and_keeps_the_child_sa() {
        let (mut server, addr) = server();
        let peer = establish(&mut server, addr);
        let (spi_i, spi_r) = peer.key();
        let (event, reply) = peer.send(&mut server, &peer.auth_request);
        assert_eq!(event.unwrap(), ServerEvent::Retransmitted { spi_i, spi_r });
        assert_eq!(reply.as_deref(), Some(&peer.auth_response[..]));
        assert_eq!(server.child(spi_i, spi_r).unwrap().inbound.spi(), peer.server_child_spi);
    }

    /// RFC 7296 §1.4 / Appendix A: every INFORMATIONAL request gets a
    /// response -- an empty one for a liveness check -- and (§2.1) its
    /// retransmission gets that same response again.
    #[test]
    fn a_liveness_check_is_answered_and_its_retransmission_resent_as_is() {
        let (mut server, addr) = server();
        let peer = establish(&mut server, addr);
        let (spi_i, spi_r) = peer.key();
        let check = dpd_request(&peer.sa, 2, &[2u8; 8]).unwrap();
        let (event, reply) = peer.send(&mut server, &check);
        assert_eq!(event.unwrap(), ServerEvent::Informational { spi_i, spi_r });
        let reply = reply.expect("a liveness check must be answered");
        let (header, payloads) = peer.open(&reply);
        assert_eq!((header.exchange_type, header.message_id, header.flags.response), (ExchangeType::Informational, 2, true));
        assert!(payloads.is_empty());

        let (event, again) = peer.send(&mut server, &check);
        assert_eq!(event.unwrap(), ServerEvent::Retransmitted { spi_i, spi_r });
        assert_eq!(again, Some(reply));

        let (event, reply) = peer.send(&mut server, &dpd_request(&peer.sa, 3, &[3u8; 8]).unwrap());
        assert_eq!(event.unwrap(), ServerEvent::Informational { spi_i, spi_r });
        assert_eq!(peer.open(&reply.unwrap()).0.message_id, 3);
    }

    /// RFC 7296 §2.1-§2.3: with a window of one, a request is taken only with
    /// the next Message ID; an old one we hold no response for, or one ahead
    /// of it, is dropped unanswered and uses nothing up.
    #[test]
    fn a_request_outside_the_window_is_dropped_unanswered() {
        let (mut server, addr) = server();
        let peer = establish(&mut server, addr);
        let (spi_i, spi_r) = peer.key();
        for message_id in [1, 3, 5] {
            let (event, reply) = peer.send(&mut server, &dpd_request(&peer.sa, message_id, &[4u8; 8]).unwrap());
            assert_eq!(event.unwrap(), ServerEvent::Ignored, "message id {message_id}");
            assert_eq!(reply, None, "message id {message_id}");
        }
        let (event, reply) = peer.send(&mut server, &dpd_request(&peer.sa, 2, &[5u8; 8]).unwrap());
        assert_eq!(event.unwrap(), ServerEvent::Informational { spi_i, spi_r });
        assert!(reply.is_some());
    }

    /// A request that fails its integrity check is not the peer's: it gets no
    /// response and does not use up its Message ID.
    #[test]
    fn a_tampered_request_is_rejected_without_using_up_its_message_id() {
        let (mut server, addr) = server();
        let peer = establish(&mut server, addr);
        let (spi_i, spi_r) = peer.key();
        let check = dpd_request(&peer.sa, 2, &[6u8; 8]).unwrap();
        let mut tampered = check.clone();
        *tampered.last_mut().unwrap() ^= 1;
        let (event, reply) = peer.send(&mut server, &tampered);
        assert!(event.is_err());
        assert_eq!(reply, None);
        let (event, reply) = peer.send(&mut server, &check);
        assert_eq!(event.unwrap(), ServerEvent::Informational { spi_i, spi_r });
        assert!(reply.is_some());
    }

    /// We never send a request, so a response to our SPIs is never answered,
    /// whatever its Message ID.
    #[test]
    fn a_response_is_never_answered() {
        let (mut server, addr) = server();
        let peer = establish(&mut server, addr);
        let (spi_i, spi_r) = peer.key();
        let response = build_informational(&peer.sa, 2, true, &[], &[7u8; 8]).unwrap();
        let (event, reply) = peer.send(&mut server, &response);
        assert_eq!(event.unwrap(), ServerEvent::Ignored);
        assert_eq!(reply, None);
        let (event, _) = peer.send(&mut server, &dpd_request(&peer.sa, 2, &[8u8; 8]).unwrap());
        assert_eq!(event.unwrap(), ServerEvent::Informational { spi_i, spi_r });
    }

    /// RFC 7296 §1.4.1: a Delete of the IKE SA is answered (empty) and closes
    /// it together with its CHILD SA.
    #[test]
    fn a_delete_of_the_ike_sa_is_answered_and_closes_it() {
        let (mut server, addr) = server();
        let peer = establish(&mut server, addr);
        let (spi_i, spi_r) = peer.key();
        let delete = build_informational(&peer.sa, 2, false, &[(PayloadType::Delete, Delete::ike_sa().to_bytes())], &[9u8; 8]).unwrap();
        let (event, reply) = peer.send(&mut server, &delete);
        assert_eq!(event.unwrap(), ServerEvent::Deleted { spi_i, spi_r });
        let (header, payloads) = peer.open(&reply.expect("a Delete must be answered"));
        assert_eq!((header.message_id, header.flags.response), (2, true));
        assert!(payloads.is_empty());
        assert!(server.session(spi_i, spi_r).is_none());
        assert!(server.child(spi_i, spi_r).is_none());

        let (event, reply) = peer.send(&mut server, &dpd_request(&peer.sa, 3, &[10u8; 8]).unwrap());
        assert_eq!(event.unwrap(), ServerEvent::Ignored);
        assert_eq!(reply, None);
    }

    /// RFC 7296 §1.4.1: a Delete of the CHILD SA -- naming the SPI the peer
    /// receives on -- is answered with a Delete of our half, even after the
    /// caller took the CHILD SA, and leaves the IKE SA up.
    #[test]
    fn a_delete_of_the_child_sa_is_answered_with_its_other_half() {
        let (mut server, addr) = server();
        let peer = establish(&mut server, addr);
        let (spi_i, spi_r) = peer.key();
        assert!(server.take_child(spi_i, spi_r).is_some());
        let delete = build_informational(&peer.sa, 2, false, &[(PayloadType::Delete, Delete::esp(vec![PEER_CHILD_SPI]).to_bytes())], &[11u8; 8]).unwrap();
        let (event, reply) = peer.send(&mut server, &delete);
        assert_eq!(event.unwrap(), ServerEvent::ChildDeleted { spi_i, spi_r });
        let (_, payloads) = peer.open(&reply.expect("a Delete must be answered"));
        let deleted: Vec<Delete> = payloads.iter().filter(|p| p.0 == PayloadType::Delete).map(|p| Delete::parse(&p.1).unwrap()).collect();
        assert_eq!(deleted, vec![Delete::esp(vec![peer.server_child_spi])]);
        assert!(server.session(spi_i, spi_r).is_some(), "the IKE SA stays up");

        // Deleting it again names nothing we still have: an empty answer.
        let again = build_informational(&peer.sa, 3, false, &[(PayloadType::Delete, Delete::esp(vec![PEER_CHILD_SPI]).to_bytes())], &[12u8; 8]).unwrap();
        let (event, reply) = peer.send(&mut server, &again);
        assert_eq!(event.unwrap(), ServerEvent::Informational { spi_i, spi_r });
        assert!(peer.open(&reply.unwrap()).1.is_empty());
    }

    /// RFC 7296 Appendix A: a minimal responder refuses every `CREATE_CHILD_SA`
    /// request -- another CHILD SA, or a rekey of the IKE SA -- with
    /// `NO_ADDITIONAL_SAS`, answered as a `CREATE_CHILD_SA` response.
    #[test]
    fn a_create_child_sa_request_is_refused_no_additional_sas() {
        let (mut server, addr) = server();
        let peer = establish(&mut server, addr);
        let (spi_i, spi_r) = peer.key();
        let ts = TrafficSelectors::ipv6_full_tunnel();
        let child = build_child_request(&peer.sa, 2, None, 0x7777, &[0x33; 32], SkCipher::Aes256Gcm, None, &ts, &[13u8; 8]).unwrap();
        let ike_rekey = build_ike_rekey_request(&peer.sa, 3, 0x1111_2222_3333_4444, &[0x44; 32], &[5u8; 32], &[14u8; 8]).unwrap();

        // One the peer did not send -- it fails the integrity check -- is not
        // answered at all.
        let mut tampered = child.clone();
        *tampered.last_mut().unwrap() ^= 1;
        let (event, reply) = peer.send(&mut server, &tampered);
        assert!(event.is_err());
        assert_eq!(reply, None);

        for (message_id, request) in [(2, child), (3, ike_rekey)] {
            let (event, reply) = peer.send(&mut server, &request);
            assert_eq!(event.unwrap(), ServerEvent::Refused { spi_i, spi_r });
            let (header, payloads) = peer.open(&reply.expect("a CREATE_CHILD_SA request must be answered"));
            assert_eq!((header.exchange_type, header.message_id, header.flags.response), (ExchangeType::CreateChildSa, message_id, true));
            let notifies: Vec<u16> = payloads.iter().filter(|p| p.0 == PayloadType::Notify).map(|p| Notify::parse(&p.1).unwrap().notify_type).collect();
            assert_eq!(notifies, vec![notify_type::NO_ADDITIONAL_SAS]);
        }
    }

    /// `msg`, a request the peer (the IKE SA's initiator) built on `sa`, as
    /// `pieces` RFC 7383 fragments with IVs from `iv_base`.
    fn peer_fragments(sa: &CompletedSaInit, msg: &[u8], pieces: usize, iv_base: u64) -> Vec<Vec<u8>> {
        let cipher = sa.suite.sk_cipher();
        let (first, inner) = open_encrypted(cipher, msg, &sa.keys.sk_ei, &sa.keys.sk_ai).unwrap();
        let header = IkeHeader::parse(msg).unwrap();
        let per = inner.len().div_ceil(pieces);
        let fragments = fragment::build_fragments(cipher, &header, first, &inner, &sa.keys.sk_ei, &sa.keys.sk_ai, iv_base, per).unwrap();
        assert_eq!(fragments.len(), pieces, "test setup: the request must split {pieces} ways");
        fragments
    }

    fn forged(mut msg: Vec<u8>) -> Vec<u8> {
        *msg.last_mut().unwrap() ^= 1;
        msg
    }

    /// Everything the server sent `sock` until it went quiet.
    fn recv_all(sock: &UdpSocket) -> Vec<Vec<u8>> {
        let mut buf = vec![0u8; 65535];
        std::iter::from_fn(|| sock.recv(&mut buf).ok().map(|n| buf[..n].to_vec())).collect()
    }

    /// The server's fragmented response, reassembled and sealed again whole,
    /// for the functions that open whole messages.
    fn reassembled(sa: &CompletedSaInit, fragments: &[Vec<u8>]) -> Vec<u8> {
        let header = IkeHeader::parse(&fragments[0]).unwrap();
        let mut response = Reassembly::new(MessageKey::of(&header));
        let (cipher, sk_e, sk_a) = (sa.suite.sk_cipher(), &sa.keys.sk_er, &sa.keys.sk_ar);
        for (i, f) in fragments.iter().enumerate() {
            match response.accept(f, cipher, sk_e, sk_a) {
                Accepted::Stored if i + 1 < fragments.len() => {}
                Accepted::Complete(first, inner) if i + 1 == fragments.len() => {
                    return sk::build_encrypted(cipher, header, first, &inner, sk_e, sk_a, &[6u8; 8]).unwrap();
                }
                other => panic!("fragment {i} of {}: {other:?}", fragments.len()),
            }
        }
        unreachable!()
    }

    /// RFC 7383 §2.6 and §2.4: the server advertises IKE fragmentation in
    /// `IKE_SA_INIT`, so an `IKE_AUTH` request in fragments is reassembled
    /// -- a forged fragment ahead of the real ones changes nothing -- and
    /// answered in fragments no larger than the request's. Of a
    /// retransmission of the request, fragment 1 gets those fragments
    /// again, and any other fragment, or a forged fragment 1, nothing
    /// (§2.6.1). Such a request used to fail to parse.
    #[test]
    fn a_fragmented_ike_auth_is_reassembled_and_answered_in_fragments() {
        let (mut server, addr) = server();
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        let local = LocalSecret::generate(&mut SeedEntropy::new(0xC11E), NONCE_LEN);
        let init_request = initiator_request(&local, &default_offer());
        sock.send_to(&init_request, addr).unwrap();
        let ServerEvent::SaInit { spi_i, spi_r } = server.handle_one().unwrap() else { panic!("expected SaInit") };
        let init_response = recv_all(&sock).remove(0);
        let sa = initiator_complete(&local, &init_request, &init_response).unwrap();

        let cfg = AuthConfig::psk(Identification::fqdn("client.test"), PSK.to_vec());
        let auth_request = initiator_auth_request(&sa, &cfg, PEER_CHILD_SPI, &esp_offer(0), &[1u8; 8]).unwrap();
        let fragments = peer_fragments(&sa, &auth_request, 4, 10);
        let largest = fragments.iter().map(Vec::len).max().unwrap();

        sock.send_to(&forged(fragments[0].clone()), addr).unwrap();
        assert_eq!(server.handle_one().unwrap(), ServerEvent::Ignored);
        for f in &fragments[..3] {
            sock.send_to(f, addr).unwrap();
            assert_eq!(server.handle_one().unwrap(), ServerEvent::FragmentStored { spi_i, spi_r });
        }
        sock.send_to(&fragments[3], addr).unwrap();
        assert!(matches!(server.handle_one().unwrap(), ServerEvent::Established { .. }));
        let answer = recv_all(&sock);
        assert!(answer.len() > 1, "the response comes in fragments too");
        for f in &answer {
            assert!(f.len() <= largest, "no fragment of the response is larger than those of the request");
            assert_eq!(IkeHeader::parse(f).unwrap().next_payload, PayloadType::EncryptedFragment);
        }
        let (_, server_child_spi, ..) = initiator_verify_auth(&sa, &reassembled(&sa, &answer), &cfg, &esp_offer(0)).unwrap();
        assert_eq!(server.child(spi_i, spi_r).unwrap().inbound.spi(), server_child_spi);

        for other in [fragments[2].clone(), forged(fragments[0].clone())] {
            sock.send_to(&other, addr).unwrap();
            assert_eq!(server.handle_one().unwrap(), ServerEvent::Ignored);
        }
        assert!(recv_all(&sock).is_empty(), "only fragment 1 of a request answered gets the answer again");
        sock.send_to(&fragments[0], addr).unwrap();
        assert_eq!(server.handle_one().unwrap(), ServerEvent::Retransmitted { spi_i, spi_r });
        assert_eq!(recv_all(&sock), answer);
        assert_eq!(server.child(spi_i, spi_r).unwrap().inbound.spi(), server_child_spi, "and nothing is negotiated again");
    }

    /// RFC 7383 §2.4: a response to a fragmented request that fits in one of
    /// the request's fragments goes out whole.
    #[test]
    fn a_fragmented_request_whose_answer_fits_whole_is_answered_whole() {
        let (mut server, addr) = server();
        let peer = establish(&mut server, addr);
        let (spi_i, spi_r) = peer.key();
        let note = Notify::status(40_000, vec![0x5a; 300]);
        let request = build_informational(&peer.sa, 2, false, &[(PayloadType::Notify, note.to_bytes())], &[2u8; 8]).unwrap();
        let fragments = peer_fragments(&peer.sa, &request, 3, 20);
        for f in &fragments[..2] {
            peer.sock.send_to(f, addr).unwrap();
            assert_eq!(server.handle_one().unwrap(), ServerEvent::FragmentStored { spi_i, spi_r });
        }
        let (event, reply) = peer.send(&mut server, &fragments[2]);
        assert_eq!(event.unwrap(), ServerEvent::Informational { spi_i, spi_r });
        let (header, payloads) = peer.open(&reply.expect("the request is answered"));
        assert_eq!((header.exchange_type, header.message_id, header.next_payload), (ExchangeType::Informational, 2, PayloadType::Encrypted));
        assert!(payloads.is_empty());
    }

    /// RFC 7296 §2.3 with RFC 7383 §2.6: a fragment of a request ahead of
    /// the window is dropped and keeps nothing, and fragments of the next
    /// request are kept only while they authenticate.
    #[test]
    fn a_fragment_outside_the_window_is_dropped() {
        let (mut server, addr) = server();
        let peer = establish(&mut server, addr);
        let note = Notify::status(40_000, vec![0x5a; 100]);
        let ahead = build_informational(&peer.sa, 3, false, &[(PayloadType::Notify, note.to_bytes())], &[2u8; 8]).unwrap();
        let (event, reply) = peer.send(&mut server, &peer_fragments(&peer.sa, &ahead, 2, 30)[0]);
        assert_eq!((event.unwrap(), reply), (ServerEvent::Ignored, None));
        assert!(server.sessions[&peer.key()].fragments.is_none());
    }
}
