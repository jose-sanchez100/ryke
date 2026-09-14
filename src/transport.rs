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

/// `UDP_ENCAP` (Linux `<linux/udp.h>`) -- not exposed as a named constant by
/// the `libc` crate for every target this builds on, so it's a raw literal
/// here (a stable, long-standing kernel UAPI value, not something that
/// varies by libc/target the way most sockopt names do).
#[cfg(target_os = "linux")]
const UDP_ENCAP: libc::c_int = 100;
/// `UDP_ENCAP_ESPINUDP` (`draft-ietf-ipsec-udp-encaps-06`, the value every
/// real-world NAT-T implementation including this app's own kernel XFRM SAs
/// (`daemon::xfrm::install_child_sa`) uses) -- also `<linux/udp.h>`.
#[cfg(target_os = "linux")]
const UDP_ENCAP_ESPINUDP: libc::c_int = 2;

/// Marks a UDP socket for kernel ESP-in-UDP decapsulation (RFC 3948): once
/// set, an inbound datagram that looks like ESP (no 4-byte zero non-ESP
/// marker) is redirected by the kernel into XFRM/ESP processing instead of
/// being delivered to this socket's own `recv()`.
///
/// **Must only be called once NAT-T floating is actually confirmed**, never
/// unconditionally at bind time -- confirmed the hard way: enabling it
/// eagerly broke every loopback test, including ones that never float at
/// all. Before NAT is detected, IKE messages carry no marker either, since
/// there's nothing to distinguish them from yet. With this sockopt set that
/// early, the kernel would misidentify that unmarked *IKE* traffic as ESP
/// and swallow it before userspace ever sees it -- breaking every
/// connection, not just NAT'd ones. Once floating is confirmed, every
/// further message on this socket genuinely does carry the marker when it's
/// IKE, so the ambiguity is gone and enabling this becomes safe -- and
/// necessary, since without it a kernel XFRM data plane's `encap` template
/// on the SA is useless: the ESP-in-UDP packets it's meant to unwrap would
/// never reach the kernel in the first place, sitting as ordinary payload on
/// *this* socket instead. A no-op outside Linux.
#[cfg(target_os = "linux")]
pub fn enable_udp_encap(socket: &UdpSocket) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let value: libc::c_int = UDP_ENCAP_ESPINUDP;
    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_UDP,
            UDP_ENCAP,
            &value as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret != 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}
#[cfg(not(target_os = "linux"))]
pub fn enable_udp_encap(_socket: &UdpSocket) -> io::Result<()> {
    Ok(())
}

/// A blocking UDP transport for IKE messages.
pub struct UdpTransport {
    socket: UdpSocket,
}

impl UdpTransport {
    pub fn bind(addr: impl ToSocketAddrs) -> io::Result<Self> {
        Ok(Self::from_socket(UdpSocket::bind(addr)?))
    }

    /// Wrap an already-bound socket instead of binding a fresh one -- for a
    /// caller that holds a persistent socket across multiple connects (e.g.
    /// a long-running worker process that binds the well-known IKE port once
    /// at startup and reuses it, `UdpSocket::try_clone`'d per attempt, the
    /// same way a real IKE daemon like strongSwan/OpenIKED never rebinds).
    pub fn from_socket(socket: UdpSocket) -> Self {
        Self { socket }
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

    /// See [`enable_udp_encap`]'s doc -- same "only once floating is
    /// confirmed" caveat applies here, this is just the `UdpTransport`-typed
    /// entry point for callers that only ever see the wrapped socket.
    pub(crate) fn enable_udp_encap(&self) -> io::Result<()> {
        enable_udp_encap(&self.socket)
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
