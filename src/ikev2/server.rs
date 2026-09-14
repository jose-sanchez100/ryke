//! A blocking IKEv2 **responder** (server) over UDP.
//!
//! Handles the two-message handshake — `IKE_SA_INIT` then `IKE_AUTH` — keeping
//! per-SA state keyed by the SPI pair so the second message can be correlated
//! with the first. Uses pre-shared-key authentication.

use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;

use crate::entropy::Entropy;
use crate::esp::ChildSa;
use crate::ikev2::exchange::{responder_respond, CompletedSaInit, LocalSecret};
use crate::ikev2::ike_auth::{self, AuthConfig};
use crate::ikev2::message::{ExchangeType, IkeHeader};
use crate::ikev2::payload::Identification;
use crate::role::Role;
use crate::transport::{DriverError, UdpTransport};

/// Nonce length we generate (RFC 7296 §2.10: ≥16 and ≥ half the PRF key).
const NONCE_LEN: usize = 32;

/// What [`Server::handle_one`] did with one datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerEvent {
    /// Answered an `IKE_SA_INIT`; the IKE SA is half-open awaiting `IKE_AUTH`.
    SaInit { spi_i: u64, spi_r: u64 },
    /// Completed `IKE_AUTH`; the IKE SA is established with a verified peer.
    Established { spi_i: u64, spi_r: u64, peer_id: Identification },
    /// A datagram we don't act on (unhandled exchange, or unknown SPI pair).
    Ignored,
}

/// A UDP IKEv2 responder driven by an [`Entropy`] source, authenticating peers
/// with a pre-shared key.
pub struct Server<E> {
    transport: UdpTransport,
    entropy: E,
    auth: AuthConfig,
    sessions: HashMap<(u64, u64), CompletedSaInit>,
    children: HashMap<(u64, u64), ChildSa>,
    /// The verified peer identity of each `Established` IKE SA -- used to find
    /// and tear down a peer's stale prior SA on `N(INITIAL_CONTACT)`.
    established_peers: HashMap<(u64, u64), Identification>,
}

impl<E: Entropy> Server<E> {
    pub fn bind(addr: impl ToSocketAddrs, entropy: E, auth: AuthConfig) -> io::Result<Self> {
        Ok(Self {
            transport: UdpTransport::bind(addr)?,
            entropy,
            auth,
            sessions: HashMap::new(),
            children: HashMap::new(),
            established_peers: HashMap::new(),
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
        self.sessions.get(&(spi_i, spi_r))
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

        match header.exchange_type {
            ExchangeType::IkeSaInit => {
                let local = LocalSecret::generate(&mut self.entropy, NONCE_LEN);
                let (response, sa) = responder_respond(&data, &local)?;
                self.transport.send_to(&response, from)?;
                let (spi_i, spi_r) = (sa.spi_i, sa.spi_r);
                self.sessions.insert((spi_i, spi_r), sa);
                Ok(ServerEvent::SaInit { spi_i, spi_r })
            }
            ExchangeType::IkeAuth => {
                let key = (header.initiator_spi, header.responder_spi);
                let Some(sa) = self.sessions.get(&key).cloned() else {
                    return Ok(ServerEvent::Ignored);
                };
                let child_spi = self.entropy.next_u64() as u32;
                let mut iv = [0u8; 8];
                self.entropy.fill(&mut iv);
                let (response, peer_id, peer_child_spi, initial_contact) =
                    ike_auth::responder_process_auth(&sa, &data, &self.auth, child_spi, &iv, None)?;
                self.transport.send_to(&response, from)?;
                if initial_contact {
                    // RFC 7296 §2.4: the peer has no state from before, so any IKE/CHILD
                    // SA we still hold for the same identity is stale -- drop it, but not
                    // the one we're establishing right now.
                    let stale: Vec<(u64, u64)> = self
                        .established_peers
                        .iter()
                        .filter(|entry| *entry.0 != key && *entry.1 == peer_id)
                        .map(|entry| *entry.0)
                        .collect();
                    for k in stale {
                        self.sessions.remove(&k);
                        self.children.remove(&k);
                        self.established_peers.remove(&k);
                    }
                }
                let child =
                    ChildSa::derive(sa.suite.prf_algorithm(), &sa.keys.sk_d, &sa.ni, &sa.nr, Role::Responder, child_spi, peer_child_spi);
                self.children.insert(key, child);
                self.established_peers.insert(key, peer_id.clone());
                Ok(ServerEvent::Established { spi_i: key.0, spi_r: key.1, peer_id })
            }
            _ => Ok(ServerEvent::Ignored),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::OsEntropy;
    use crate::ikev2::client::Client;
    use crate::ikev2::ike_auth::AuthConfig;
    use crate::ikev2::payload::Identification;
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
}
