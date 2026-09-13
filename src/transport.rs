//! UDP transport for IKE messages.
//!
//! Blocking `std::net::UdpSocket` — no async runtime, matching the crate's
//! dependency-light design. Port 500 today; NAT-T on 4500 (with the non-ESP
//! marker) and IKE fragmentation arrive at M3.

use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::Duration;

use thiserror::Error;

use crate::error::IkeError;

/// Largest datagram we read. IKE messages can be large (certificates), but at
/// M1 (`IKE_SA_INIT`) a few KB suffices; fragmentation reassembly lands at M3.
pub const MAX_DATAGRAM: usize = 65535;

/// Errors from the UDP driver layer: transport I/O plus protocol errors.
#[derive(Debug, Error)]
pub enum DriverError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Ike(#[from] IkeError),
}

/// The local IP our packets actually carry as their source when reaching
/// `peer`, resolved via the OS routing table: a throwaway UDP `connect`
/// picks the route without sending anything. Needed because the real IKE
/// socket always binds the literal wildcard address (`0.0.0.0`, so it can
/// answer on whichever local interface a peer happens to reach it through)
/// and `getsockname()` on a socket that was never itself `connect()`-ed
/// reports that same `0.0.0.0` back, not the concrete interface address the
/// OS actually picks per-destination at send time -- confirmed the hard way
/// on the IKEv1 side: a caller that used the wildcard-bound socket's own
/// `local_addr()` directly ended up installing a kernel XFRM SA with `src
/// 0.0.0.0` as the outer tunnel address, which the kernel dutifully
/// "encapsulated" packets under (SA usage counters moved) but which can never
/// actually leave the box as a valid IP packet -- traffic vanished silently
/// with no error anywhere. IKEv2's `Ikev2Session` already solved this with an
/// identical probe (`ikev2::session::local_ip_for`); this is the shared,
/// public home for the same trick so [`UdpTransport::local_addr_for`] (and
/// therefore [`crate::ikev1::client::Client`]) gets it too.
pub fn local_ip_for(peer: SocketAddr) -> io::Result<IpAddr> {
    let probe = UdpSocket::bind(("0.0.0.0", 0))?;
    probe.connect(peer)?;
    probe.local_addr().map(|a| a.ip())
}

/// A blocking UDP transport for IKE messages.
pub struct UdpTransport {
    socket: UdpSocket,
}

impl UdpTransport {
    pub fn bind(addr: impl ToSocketAddrs) -> io::Result<Self> {
        Ok(Self { socket: UdpSocket::bind(addr)? })
    }

    /// This socket's own bound local address -- **not** meaningful as "the
    /// address our packets actually leave from" when bound to the wildcard
    /// address (the common case for a long-lived IKE socket); use
    /// [`Self::local_addr_for`] for that.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// The concrete local `(IP, port)` our packets actually carry when
    /// reaching `peer`: this socket's own bound port (a real IKE socket
    /// always binds a literal well-known port, so that part is already
    /// meaningful) combined with [`local_ip_for`]'s routing-table-resolved IP
    /// (which isn't, when the socket is wildcard-bound).
    pub fn local_addr_for(&self, peer: SocketAddr) -> io::Result<SocketAddr> {
        let port = self.socket.local_addr()?.port();
        Ok(SocketAddr::new(local_ip_for(peer)?, port))
    }

    pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.socket.set_read_timeout(dur)
    }

    /// Receive one datagram, returning exactly the bytes read and the sender.
    pub fn recv_from(&self) -> io::Result<(Vec<u8>, SocketAddr)> {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        let (n, from) = self.socket.recv_from(&mut buf)?;
        buf.truncate(n);
        crate::debug::dump("<<<", from, &buf);
        Ok((buf, from))
    }

    pub fn send_to(&self, data: &[u8], to: SocketAddr) -> io::Result<usize> {
        crate::debug::dump(">>>", to, data);
        self.socket.send_to(data, to)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A wildcard-bound transport's own `local_addr()` reports `0.0.0.0` (the
    /// bug this module exists to work around); `local_addr_for(peer)` must
    /// instead resolve the concrete loopback IP the OS would actually use
    /// reaching `peer`, keeping the transport's own bound port.
    #[test]
    fn local_addr_for_resolves_the_concrete_ip_not_the_wildcard() {
        let peer_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer = peer_sock.local_addr().unwrap();

        let transport = UdpTransport::bind("0.0.0.0:0").unwrap();
        let wildcard = transport.local_addr().unwrap();
        assert_eq!(wildcard.ip(), std::net::Ipv4Addr::UNSPECIFIED);

        let resolved = transport.local_addr_for(peer).unwrap();
        assert_eq!(resolved.ip(), std::net::Ipv4Addr::LOCALHOST);
        assert_eq!(resolved.port(), wildcard.port());
    }
}
