//! A minimal blocking IKEv2 **initiator** (client) over UDP.
//!
//! RFC 7296 §2.23 NAT-T: [`Client::from_sockets`] hands in both the
//! well-known port-500 socket and a port-4500 one up front (mirroring
//! [`crate::ikev1::client::Client::from_sockets`]'s own pre-bind-both
//! approach), and [`Client::connect`] switches to the latter -- wrapping
//! every message with the non-ESP marker
//! (`crate::ikev2::natt::wrap_ike_4500`) -- the moment `IKE_SA_INIT`'s
//! `NAT_DETECTION_*` notifies say NAT was detected on the path. Without
//! this, a NAT'd peer floats to UDP 4500 for everything after `IKE_SA_INIT`
//! while this client's own socket never moves -- so its `IKE_AUTH` request
//! (and later the ESP-in-UDP data plane) lands nowhere and is silently
//! dropped by the OS. See [`crate::ikev2::exchange::NatStatus`]'s own doc
//! for the detection details; this module only owns the transport-switching
//! side of it.
//!
//! RFC 7383 IKE fragmentation, which `IKE_SA_INIT` always advertises: an
//! `IKE_AUTH` response in fragments is reassembled, each fragment
//! authenticated before it is kept ([`crate::ikev2::fragment::Reassembly`]).
//! The request itself always goes out whole, and it is sent once: this
//! client does not retransmit, so a lost request or fragment of the
//! response fails the handshake with the socket's read timeout.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

use crate::entropy::Entropy;
use crate::error::IkeError;
use crate::esp::ChildSa;
use crate::ikev2::exchange::{
    default_offer, initiator_complete_natt, initiator_request_natt, CompletedSaInit, LocalSecret, NatStatus,
};
use crate::ikev2::fragment::{Accepted, MessageKey, Reassembly, MAX_FRAGMENTS};
use crate::ikev2::ike_auth::{self, AuthConfig};
use crate::ikev2::message::{IkeHeader, PayloadType};
use crate::ikev2::natt::{unwrap_ike_4500, wrap_ike_4500};
use crate::ikev2::payload::Identification;
use crate::role::Role;
use crate::transport::{DriverError, UdpTransport};

const NONCE_LEN: usize = 32;

/// A UDP IKEv2 initiator driven by an [`Entropy`] source.
pub struct Client<E> {
    transport: UdpTransport,
    /// Present only via [`Self::from_sockets`] -- a caller that never hands
    /// one in (`bind`/`from_socket`, both pre-dating NAT-T) simply can't
    /// float; [`Self::send_step`]/[`Self::recv_step`] error out rather than
    /// silently staying on port 500 if `IKE_SA_INIT` ever decides floating
    /// is needed without one configured.
    natt_transport: Option<UdpTransport>,
    entropy: E,
}

impl<E: Entropy> Client<E> {
    /// Bind a local socket (use `"0.0.0.0:0"` for an ephemeral source port).
    /// No NAT-T -- see [`Self::from_sockets`] for that.
    pub fn bind(addr: impl ToSocketAddrs, entropy: E) -> io::Result<Self> {
        Ok(Self { transport: UdpTransport::bind(addr)?, natt_transport: None, entropy })
    }

    /// Like [`Self::bind`], but wrapping an already-bound socket instead of
    /// binding a fresh one -- for a caller holding a persistent well-known-
    /// port socket across multiple connects (e.g. a worker process that
    /// binds port 500 once at startup, the way a real IKE daemon does) hands
    /// in a `try_clone`'d handle here per attempt rather than this crate
    /// binding its own. No NAT-T -- see [`Self::from_sockets`] for that.
    pub fn from_socket(socket: UdpSocket, entropy: E) -> Self {
        Self { transport: UdpTransport::from_socket(socket), natt_transport: None, entropy }
    }

    /// Like [`Self::from_socket`], but also wrapping a persistent port-4500
    /// socket for RFC 3947/7296 NAT-T floating -- the entry point a caller
    /// that already binds both well-known ports once at startup should use
    /// instead of `from_socket`, so a connection that turns out to need
    /// floating actually can.
    pub fn from_sockets(socket500: UdpSocket, socket4500: UdpSocket, entropy: E) -> Self {
        Self {
            transport: UdpTransport::from_socket(socket500),
            natt_transport: Some(UdpTransport::from_socket(socket4500)),
            entropy,
        }
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.transport.local_addr()
    }

    pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.transport.set_read_timeout(dur)?;
        if let Some(natt) = &self.natt_transport {
            natt.set_read_timeout(dur)?;
        }
        Ok(())
    }

    /// Marks the port-4500 socket for kernel ESP-in-UDP decapsulation
    /// (`crate::transport::enable_udp_encap`) the moment floating is first
    /// confirmed -- a no-op when `floated` is `false`. Without this, the
    /// ESP-in-UDP data plane that follows a floated handshake never gets
    /// delivered to XFRM: incoming ESP-in-UDP packets have no non-ESP
    /// marker (RFC 3948 §2.2) to distinguish them from IKE control traffic,
    /// so without this sockopt the kernel has no way to tell they're meant
    /// for XFRM instead of this socket's own `recv()`.
    fn enable_natt_encap(&self, floated: bool) -> Result<(), DriverError> {
        if floated {
            let natt = self.natt_transport.as_ref().ok_or(IkeError::Crypto(
                "NAT-T floating required but this Client has no port-4500 socket (use Client::from_sockets)",
            ))?;
            natt.enable_udp_encap()?;
        }
        Ok(())
    }

    /// Send `msg` to `server`, floated (wrapped with the non-ESP marker, to
    /// `server`'s IP on UDP 4500 instead of its own port) whenever `floated`
    /// is `true`. Errors if `floated` is requested but this `Client` was
    /// never given a port-4500 socket (see [`Self::from_sockets`]).
    fn send_step(&self, msg: &[u8], server: SocketAddr, floated: bool) -> Result<(), DriverError> {
        if floated {
            let natt = self.natt_transport.as_ref().ok_or(IkeError::Crypto(
                "NAT-T floating required but this Client has no port-4500 socket (use Client::from_sockets)",
            ))?;
            natt.send_to(&wrap_ike_4500(msg), SocketAddr::new(server.ip(), crate::natt_port()))?;
        } else {
            self.transport.send_to(msg, server)?;
        }
        Ok(())
    }

    /// Read one reply from the transport matching `floated`, unwrapping the
    /// non-ESP marker when floated (dropping any datagram missing it and
    /// reading again -- bounded by the same socket read timeout `recv_from`
    /// itself already enforces).
    fn recv_step(&self, floated: bool) -> Result<Vec<u8>, DriverError> {
        let transport = if floated {
            self.natt_transport.as_ref().ok_or(IkeError::Crypto(
                "NAT-T floating required but this Client has no port-4500 socket (use Client::from_sockets)",
            ))?
        } else {
            &self.transport
        };
        loop {
            let (raw, _from) = transport.recv_from()?;
            if floated {
                match unwrap_ike_4500(&raw) {
                    Some(m) => return Ok(m.to_vec()),
                    None => continue,
                }
            } else {
                return Ok(raw);
            }
        }
    }

    /// The response to our `request` on `sa`: the first whole message that
    /// comes, or the fragments of one (RFC 7383 §2.6) reassembled and sealed
    /// again as one `SK` message under the responder's keys. A fragment of
    /// another message, or one that does not authenticate, is dropped;
    /// after `4 * MAX_FRAGMENTS` datagrams without a complete response, it
    /// gives up.
    fn recv_response(&mut self, sa: &CompletedSaInit, request: &[u8], floated: bool) -> Result<Vec<u8>, DriverError> {
        let asked = IkeHeader::parse(request)?;
        let mut answer = Reassembly::new(MessageKey { initiator: false, response: true, ..MessageKey::of(&asked) });
        let cipher = sa.suite.sk_cipher();
        for _ in 0..4 * usize::from(MAX_FRAGMENTS) {
            let msg = self.recv_step(floated)?;
            let Ok(header) = IkeHeader::parse(&msg) else { continue };
            if header.next_payload != PayloadType::EncryptedFragment {
                return Ok(msg);
            }
            if let Accepted::Complete(first, inner) = answer.accept(&msg, cipher, &sa.keys.sk_er, &sa.keys.sk_ar) {
                let mut iv = [0u8; 8];
                self.entropy.fill(&mut iv);
                return Ok(crate::ikev2::sk::build_encrypted(cipher, header, first, &inner, &sa.keys.sk_er, &sa.keys.sk_ar, &iv)?);
            }
        }
        Err(IkeError::Crypto("no complete IKE_AUTH response among the fragments received").into())
    }

    /// Run `IKE_SA_INIT` against `server` and return our completed state
    /// plus what it found out about NAT on the path (RFC 7296 §2.23):
    /// sends our default offer carrying `NAT_DETECTION_*` notifies, waits
    /// for the response, and derives the keys.
    pub fn sa_init(&mut self, server: SocketAddr) -> Result<(CompletedSaInit, NatStatus), DriverError> {
        let our_addr = self.transport.local_addr_for(server)?;
        let local = LocalSecret::generate(&mut self.entropy, NONCE_LEN);
        let request = initiator_request_natt(&local, &default_offer(), our_addr, server);
        self.transport.send_to(&request, server)?;
        let (response, _from) = self.transport.recv_from()?;
        Ok(initiator_complete_natt(&local, &request, &response, our_addr, server)?)
    }

    /// After a completed SA_INIT, run `IKE_AUTH` (PSK) against `server`.
    /// `floated` must be whatever [`Self::sa_init`]'s [`NatStatus::float_to_4500`]
    /// returned for this same exchange. Returns the peer's verified identity,
    /// the responder's chosen CHILD SA SPI, and the inner IPv4 the responder
    /// assigned via its Configuration Payload (if any).
    pub fn authenticate(
        &mut self,
        server: SocketAddr,
        sa: &CompletedSaInit,
        floated: bool,
        cfg: &AuthConfig,
        child_spi: u32,
    ) -> Result<(Identification, u32, Option<Ipv4Addr>), DriverError> {
        self.enable_natt_encap(floated)?;
        let mut iv = [0u8; 8];
        self.entropy.fill(&mut iv);
        let esp_offer = ike_auth::esp_offer(0);
        let request = ike_auth::initiator_auth_request(sa, cfg, child_spi, &esp_offer, &iv)?;
        self.send_step(&request, server, floated)?;
        let response = self.recv_response(sa, &request, floated)?;
        let (id, spi, _esp_suite, ip4, _tsr) = ike_auth::initiator_verify_auth(sa, &response, cfg, &esp_offer, ike_auth::ChildTsOffer::Ipv4)?;
        Ok((id, spi, ip4))
    }

    /// Full handshake: `IKE_SA_INIT` then `IKE_AUTH`, floating to UDP 4500
    /// (see this module's own doc) the moment `IKE_SA_INIT` detects NAT on
    /// the path. Returns the established IKE SA, the peer's verified
    /// identity, the ESP CHILD SA (data-plane keys) derived for the given
    /// `child_spi`, and the responder-assigned inner IPv4 (from its
    /// Configuration Payload) if one was provided.
    pub fn connect(
        &mut self,
        server: SocketAddr,
        cfg: &AuthConfig,
        child_spi: u32,
    ) -> Result<(CompletedSaInit, Identification, ChildSa, Option<Ipv4Addr>), DriverError> {
        let (sa, status) = self.sa_init(server)?;
        let floated = status.float_to_4500();
        let (peer, peer_child_spi, assigned_ip) = self.authenticate(server, &sa, floated, cfg, child_spi)?;
        let child =
            ChildSa::derive(sa.suite.prf_algorithm(), &sa.keys.sk_d, &sa.ni, &sa.nr, Role::Initiator, child_spi, peer_child_spi);
        Ok((sa, peer, child, assigned_ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::SeedEntropy;
    use crate::ikev2::exchange::{initiator_complete, initiator_request, responder_respond};

    fn init_secret() -> LocalSecret {
        LocalSecret { dh_private: [7u8; 32], nonce: vec![0x11; 32], spi: 0xAAAA_AAAA_1111_2222 }
    }
    fn resp_secret() -> LocalSecret {
        LocalSecret { dh_private: [9u8; 32], nonce: vec![0x22; 32], spi: 0xBBBB_BBBB_3333_4444 }
    }

    /// A completed SA_INIT built entirely in-process (no sockets) -- enough
    /// to exercise `authenticate`'s floated-but-unconfigured error path
    /// without needing a real peer.
    fn completed_sa() -> CompletedSaInit {
        let request = initiator_request(&init_secret(), &default_offer());
        let (response, _) = responder_respond(&request, &resp_secret()).unwrap();
        initiator_complete(&init_secret(), &request, &response).unwrap()
    }

    /// `authenticate(.., floated: true, ..)` must refuse to silently send
    /// over the unfloated transport when this `Client` was never given a
    /// port-4500 socket (`bind`/`from_socket`, not `from_sockets`) -- the
    /// exact class of bug this module's own doc describes: a NAT'd peer
    /// expects everything after `IKE_SA_INIT` on port 4500, so sending
    /// unfloated there would just vanish.
    #[test]
    fn authenticate_errors_when_floated_but_client_has_no_natt_socket() {
        let mut client = Client { transport: UdpTransport::bind("127.0.0.1:0").unwrap(), natt_transport: None, entropy: SeedEntropy::new(1) };
        let sa = completed_sa();
        let cfg = AuthConfig::psk(Identification::fqdn("client.example"), b"psk".to_vec());
        let server: SocketAddr = "127.0.0.1:1".parse().unwrap(); // unreachable, but never actually sent to
        let err = client.authenticate(server, &sa, true, &cfg, 0x1234).unwrap_err();
        assert!(matches!(err, DriverError::Ike(IkeError::Crypto(_))), "expected a Crypto error naming the missing NAT-T socket, got {err:?}");
    }

    /// The non-floated path is unaffected by the same `Client` having no
    /// port-4500 socket -- most connections never need one.
    #[test]
    fn from_sockets_holds_both_ports_and_enables_natt_encap_only_when_floated() {
        let socket500 = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let socket4500 = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let expected_addr = socket500.local_addr().unwrap();
        let client = Client::from_sockets(socket500, socket4500, SeedEntropy::new(1));
        assert_eq!(client.local_addr().unwrap(), expected_addr);
        assert!(client.natt_transport.is_some());
        client.enable_natt_encap(true).expect("a from_sockets Client can enable NAT-T encap once floated");
        client.enable_natt_encap(false).expect("enabling encap is a no-op when not floated");
    }

    /// `bind`/`from_socket` (no NAT-T pair) must refuse floating outright --
    /// the safety net `authenticate`'s own error path relies on.
    #[test]
    fn enable_natt_encap_errors_without_a_natt_socket() {
        let client = Client { transport: UdpTransport::bind("127.0.0.1:0").unwrap(), natt_transport: None, entropy: SeedEntropy::new(1) };
        assert!(client.enable_natt_encap(false).is_ok(), "not floated -- nothing to enable");
        assert!(client.enable_natt_encap(true).is_err(), "floated with no port-4500 socket must error, not silently no-op");
    }

    /// RFC 7383 §2.6: the client advertises IKE fragmentation in
    /// `IKE_SA_INIT`, so an `IKE_AUTH` response in fragments must be
    /// reassembled -- a forged fragment ahead of the real ones changing
    /// nothing. It used to be handed whole to `initiator_verify_auth`,
    /// which found no `SK` payload in it.
    #[test]
    fn connect_reassembles_a_fragmented_ike_auth_response() {
        use crate::ikev2::exchange::{responder_respond_natt, SaInitResult};
        use crate::ikev2::fragment::build_fragments;
        use crate::ikev2::sk::open_encrypted;

        let gateway = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        gateway.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let bind = gateway.local_addr().unwrap();
        let responder = std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let (n, from) = gateway.recv_from(&mut buf).unwrap();
            let (response, sa) = match responder_respond_natt(&buf[..n], &resp_secret(), bind, from, None).unwrap() {
                SaInitResult::Established { response, sa } => (response, sa),
                _ => panic!("expected Established"),
            };
            gateway.send_to(&response, from).unwrap();
            let (n, from) = gateway.recv_from(&mut buf).unwrap();
            let rcfg = AuthConfig::psk(Identification::fqdn("gw.test"), b"psk".to_vec());
            let (resp, ..) = ike_auth::responder_process_auth(&sa, &buf[..n], &rcfg, 0xC0FFEE, &[9u8; 8], None).unwrap();
            let (cipher, sk_e, sk_a) = (sa.suite.sk_cipher(), &sa.keys.sk_er, &sa.keys.sk_ar);
            let (first, inner) = open_encrypted(cipher, &resp, sk_e, sk_a).unwrap();
            let header = IkeHeader::parse(&resp).unwrap();
            let fragments = build_fragments(cipher, &header, first, &inner, sk_e, sk_a, 42, inner.len().div_ceil(3)).unwrap();
            let mut forged = fragments[0].clone();
            *forged.last_mut().unwrap() ^= 1;
            for f in std::iter::once(&forged).chain(&fragments) {
                gateway.send_to(f, from).unwrap();
            }
        });
        let mut client = Client::bind("127.0.0.1:0", SeedEntropy::new(1)).unwrap();
        client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let cfg = AuthConfig::psk(Identification::fqdn("client.test"), b"psk".to_vec());
        let (_sa, peer, child, _) = client.connect(bind, &cfg, 0x1234).unwrap();
        responder.join().unwrap();
        assert_eq!(peer, Identification::fqdn("gw.test"));
        assert_eq!(child.outbound.spi(), 0xC0FFEE);
    }
}
