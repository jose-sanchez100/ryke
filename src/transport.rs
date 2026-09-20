//! UDP transport for IKE messages.
//!
//! Blocking `std::net::UdpSocket` — no async runtime, matching the crate's
//! dependency-light design. Port 500 today; NAT-T on 4500 (with the non-ESP
//! marker) and IKE fragmentation arrive at M3.

use std::cell::Cell;
use std::io;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::mpsc;
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

/// What an IKEv1 exchange after Phase 1 ([`crate::ikev1::quick`]'s Quick Mode,
/// [`crate::ikev1::informational`]'s DPD and Delete watching) needs from its
/// socket: send a datagram, bound the wait, receive one. A plain
/// [`UdpSocket`] is one, and is what every caller has always passed.
///
/// It is a trait because some hosts cannot let these exchanges read the socket
/// themselves: a host that runs its own `recv_from` loop on the IKE port
/// (to demultiplex IKE from ESP-in-UDP, say) would race the exchange for every
/// datagram, and each side would swallow the other's. Such a host hands the
/// IKE datagrams it has already classified to a [`ChannelIo`] instead -- the
/// IKEv1 counterpart of [`crate::ikev2::session::LivenessSession::
/// install_external_receiver`].
pub trait IkeSocket {
    /// Same contract as [`UdpSocket::send_to`].
    fn send_to(&self, buf: &[u8], dest: SocketAddr) -> io::Result<usize>;
    /// Same contract as [`UdpSocket::set_read_timeout`]: bounds each following
    /// [`Self::recv_from`], `None` blocks, a zero duration is an error.
    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()>;
    /// Same contract as [`UdpSocket::recv_from`], including that running out
    /// of time is an error of kind `WouldBlock` or `TimedOut` (callers accept
    /// either, as they differ by OS).
    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
}

impl IkeSocket for UdpSocket {
    fn send_to(&self, buf: &[u8], dest: SocketAddr) -> io::Result<usize> {
        UdpSocket::send_to(self, buf, dest)
    }
    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        UdpSocket::set_read_timeout(self, dur)
    }
    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        UdpSocket::recv_from(self, buf)
    }
}

/// An [`IkeSocket`] that sends through a real socket but receives from a
/// channel of datagrams somebody else read off that socket.
///
/// Datagrams come out exactly as they were put in (a floated tunnel's still
/// carry their non-ESP marker, which the exchanges strip themselves), reported
/// as sent from `peer`: the channel carries bytes only, and `peer` is the one
/// address those datagrams are about. The read timeout is this object's own --
/// it is never applied to the shared socket, so it cannot disturb whoever is
/// reading that.
pub struct ChannelIo {
    sock: UdpSocket,
    rx: mpsc::Receiver<Vec<u8>>,
    peer: SocketAddr,
    read_timeout: Cell<Option<Duration>>,
}

impl ChannelIo {
    /// `sock` is used for sending only (a `try_clone` of the socket the
    /// datagrams in `rx` were read from); `peer` is reported as every
    /// datagram's sender.
    pub fn new(sock: UdpSocket, rx: mpsc::Receiver<Vec<u8>>, peer: SocketAddr) -> Self {
        Self { sock, rx, peer, read_timeout: Cell::new(None) }
    }
}

impl IkeSocket for ChannelIo {
    fn send_to(&self, buf: &[u8], dest: SocketAddr) -> io::Result<usize> {
        self.sock.send_to(buf, dest)
    }

    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        if dur == Some(Duration::ZERO) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "cannot set a 0 duration timeout"));
        }
        self.read_timeout.set(dur);
        Ok(())
    }

    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let datagram = match self.read_timeout.get() {
            Some(wait) => self.rx.recv_timeout(wait).map_err(|e| match e {
                mpsc::RecvTimeoutError::Timeout => io::Error::from(io::ErrorKind::TimedOut),
                mpsc::RecvTimeoutError::Disconnected => io::Error::from(io::ErrorKind::BrokenPipe),
            })?,
            None => self.rx.recv().map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?,
        };
        // A datagram longer than `buf` is cut off, as `recv_from` does.
        let n = datagram.len().min(buf.len());
        buf[..n].copy_from_slice(&datagram[..n]);
        Ok((n, self.peer))
    }
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

/// Stands in, in tests, for a host's ESP pump: the *only* reader of `sock`,
/// forwarding what looks like IKE on a floated port (see
/// [`crate::ikev2::natt::is_ike_on_4500`]) to the returned channel and
/// swallowing everything else, exactly the role a real pump has. Dropping the
/// returned guard stops the thread.
///
/// The reader blocks with no receive timeout, and the guard wakes it with a
/// datagram to stop it: on Windows a datagram that arrives just as a timed
/// receive expires can be lost (measured: about 1 in 16 with a 20 ms timeout),
/// which would make tests that depend on a specific datagram flaky there.
#[cfg(test)]
pub(crate) fn spawn_pump_reader(sock: &UdpSocket, marked_only: bool) -> (mpsc::Receiver<Vec<u8>>, PumpReaderGuard) {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let (tx, rx) = mpsc::channel();
    let reader = sock.try_clone().unwrap();
    reader.set_read_timeout(None).unwrap();
    let wake = reader.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let flag = stop.clone();
    let thread = std::thread::spawn(move || {
        let mut buf = [0u8; 65535];
        loop {
            let Ok((n, _)) = reader.recv_from(&mut buf) else { continue };
            if flag.load(Ordering::Relaxed) {
                return;
            }
            if !marked_only || crate::ikev2::natt::is_ike_on_4500(&buf[..n]) {
                let _ = tx.send(buf[..n].to_vec());
            }
        }
    });
    (rx, PumpReaderGuard { stop, wake, thread: Some(thread) })
}

#[cfg(test)]
pub(crate) struct PumpReaderGuard {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    wake: SocketAddr,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(test)]
impl Drop for PumpReaderGuard {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            if let Ok(nudge) = UdpSocket::bind((self.wake.ip(), 0)) {
                let _ = nudge.send_to(&[0], self.wake);
            }
            let _ = t.join();
        }
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

    fn channel_io() -> (ChannelIo, mpsc::Sender<Vec<u8>>, UdpSocket) {
        let (tx, rx) = mpsc::channel();
        let far_end = UdpSocket::bind("127.0.0.1:0").unwrap();
        let io = ChannelIo::new(UdpSocket::bind("127.0.0.1:0").unwrap(), rx, far_end.local_addr().unwrap());
        (io, tx, far_end)
    }

    #[test]
    fn channel_io_hands_over_queued_datagrams_in_order_as_from_the_peer() {
        let (io, tx, far_end) = channel_io();
        tx.send(vec![1, 2, 3]).unwrap();
        tx.send(vec![4]).unwrap();
        let mut buf = [0u8; 16];
        assert_eq!(io.recv_from(&mut buf).unwrap(), (3, far_end.local_addr().unwrap()));
        assert_eq!(&buf[..3], &[1, 2, 3]);
        assert_eq!(io.recv_from(&mut buf).unwrap().0, 1);
        assert_eq!(buf[0], 4);
    }

    #[test]
    fn channel_io_cuts_an_oversized_datagram_off_like_a_socket_does() {
        let (io, tx, _far_end) = channel_io();
        tx.send(vec![7; 10]).unwrap();
        let mut buf = [0u8; 4];
        assert_eq!(io.recv_from(&mut buf).unwrap().0, 4);
    }

    #[test]
    fn channel_io_times_out_and_reports_a_closed_channel() {
        let (io, tx, _far_end) = channel_io();
        io.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        let mut buf = [0u8; 4];
        let started = std::time::Instant::now();
        let err = io.recv_from(&mut buf).unwrap_err();
        assert!(matches!(err.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut), "got {err:?}");
        assert!(started.elapsed() >= Duration::from_millis(50));

        drop(tx);
        assert_eq!(io.recv_from(&mut buf).unwrap_err().kind(), io::ErrorKind::BrokenPipe);
    }

    #[test]
    fn channel_io_refuses_a_zero_timeout_like_a_socket_does() {
        let (io, _tx, _far_end) = channel_io();
        assert_eq!(io.set_read_timeout(Some(Duration::ZERO)).unwrap_err().kind(), io::ErrorKind::InvalidInput);
        assert_eq!(UdpSocket::bind("127.0.0.1:0").unwrap().set_read_timeout(Some(Duration::ZERO)).unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn channel_io_sends_through_its_socket() {
        let (io, _tx, far_end) = channel_io();
        far_end.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        io.send_to(b"hello", far_end.local_addr().unwrap()).unwrap();
        let mut buf = [0u8; 16];
        let (n, _) = far_end.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello");
    }
}
