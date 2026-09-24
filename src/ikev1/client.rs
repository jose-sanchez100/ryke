//! A minimal blocking IKEv1 **initiator** (client) over UDP: Aggressive Mode
//! or Main Mode (see [`InitiatorConfig::mode`]) for Phase 1 (PSK or RSA
//! signature — see [`crate::ikev1::phase1::Ikev1LocalAuth`]), an optional
//! XAUTH round (see [`crate::ikev1::xauth`]) when the gateway requires one,
//! an optional Mode-Config round (see [`crate::ikev1::cfg`],
//! `InitiatorConfig::mode_cfg`) for an assigned inner IPv4 (and, with
//! `InitiatorConfig::ipv6`, IPv6), then Quick Mode
//! (optionally with PFS, see `InitiatorConfig::pfs_group`), establishing an
//! ESP CHILD SA.
//!
//! RFC 3947 NAT-T: [`Client::from_sockets`] hands in both the well-known
//! port-500 socket and a port-4500 one up front (mirroring
//! `ikev2::session::Ikev2Session::sa_init_with_sockets`'s own pre-bind-both
//! approach), and `connect()` switches to the latter -- wrapping every
//! message with the non-ESP marker (`ikev2::natt::wrap_ike_4500`, reused
//! as-is: the marker and the underlying NAT-D hash shape are IKE-version-
//! agnostic) -- the moment [`crate::ikev1::phase1::Phase1State::floated`] (or
//! its precursors on the intermediate per-message states) says NAT was
//! detected. See `phase1.rs`'s own NAT-T doc comments for the detection
//! details; this module only owns the transport-switching side of it.
//!
//! Retransmissions and duplicates (RFC 2408 §3.1, §5.1, RFC 2409 §5): every
//! request is sent again, the same bytes, when its answer does not come
//! (`Client::send_and_await`), at longer and longer intervals
//! ([`crate::ikev1::retransmit_waits`]; the read timeout, once per send, is the
//! whole time a caller waits for a silent gateway) and never more than
//! `MAX_RETRANSMITS` times. The messages nothing answers -- Aggressive Mode's
//! third, the XAUTH ACK, Quick Mode's third -- are kept with the message they
//! answered ([`crate::ikev1::phase1::Phase1State`]'s retained finals) and sent
//! again, untouched, when the gateway repeats that message -- on the port the
//! exchange floated to, and also on port 500 while it waits after a floated
//! Aggressive Mode third message, which is where a gateway that never saw it
//! (and so has not floated) repeats its second (RFC 3947 §5.3); a bit-for-bit
//! repeat of a message the handshake already took is dropped, never read as
//! the next one, and the whole wait for a message ends at its deadline, however
//! many other datagrams come in meanwhile.
//!
//! What this does not do: recognise a repeat that the gateway re-encrypted
//! (only identical bytes count); measure the round-trip time the retransmission
//! interval should follow (RFC 2408 §5.1 asks for it); answer a Quick Mode or a
//! Phase 1 that the gateway starts (this is an initiator only); rekey the
//! ISAKMP SA; or hold a Phase-2 lifetime in kilobytes (a volume limit is
//! accepted and left to the gateway, see `quick`'s "SA lifetimes"; a Phase-1 one
//! is refused). The look at port 500
//! after a floated Aggressive Mode third message is `connect`'s own, made only
//! while it waits: once `connect` has returned nothing looks there. Quick
//! Mode's third message, sent by `connect` or by a rekey, is
//! sent again only when the caller next reads the socket
//! (`informational::peek`, `probe`, the next rekey), since nothing runs in the
//! background: a gateway whose Quick Mode message 2 is answered by nothing waits
//! until then.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

use crate::debug::ike_debug;
use crate::entropy::Entropy;
use crate::error::IkeError;
use crate::esp::ChildSa;
use crate::ikev1::cfg as modecfg;
use crate::ikev1::informational;
use crate::ikev1::isakmp::{exchange, IsakmpHeader};
use crate::ikev1::phase1::{
    initiate_aggressive, initiate_main, Ikev1ExchangeMode, Ikev1LocalAuth, InitiatorConfig, Phase1State,
};
use crate::ikev1::quick::initiate_quick_with_pfs;
use crate::ikev1::retransmit_waits;
use crate::ikev1::xauth;
use crate::ikev2::natt::{unwrap_ike_4500, wrap_ike_4500};
use crate::transport::{DriverError, UdpTransport};

/// What a completed IKEv1 handshake yields: the Phase-1 state (for rekey /
/// info exchanges), the established ESP CHILD SA (the data-plane keys), and
/// — when `InitiatorConfig::mode_cfg` was set — the address info the gateway
/// assigned. `assigned_ip4`/`netmask`/`dns`/`subnets` are all empty/`None`
/// when Mode-Config wasn't run.
pub struct Established {
    pub phase1: Phase1State,
    pub child: ChildSa,
    pub assigned_ip4: Option<Ipv4Addr>,
    pub netmask: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    pub subnets: Vec<(Ipv4Addr, u8)>,
    /// The IPv6 counterparts of `assigned_ip4`/`dns`/`subnets`, from the same
    /// Mode-Config reply -- only ever populated when
    /// `InitiatorConfig::ipv6` asked for them *and* the gateway actually had
    /// IPv6 to give (an all-zero placeholder reads as `None`/empty, see
    /// [`crate::ikev1::modecfg::ConfigPayload::assigned_ipv6`]). Nothing here
    /// creates an IPv6 CHILD SA by itself: with `assigned_ip6` set, the caller
    /// runs [`crate::ikev1::quick::create_child_ipv6`].
    pub assigned_ip6: Option<(Ipv6Addr, u8)>,
    pub dns6: Vec<Ipv6Addr>,
    pub subnets6: Vec<(Ipv6Addr, u8)>,
    /// The CHILD SA's negotiated ESP lifetime, in seconds (RFC 2407 §4.5): the
    /// responder's own seconds limit when its answer states one (the DOI default,
    /// 28800 s, when it states none), never beyond what we offered -- see
    /// `quick::negotiated_p2_lifetime`. A caller scheduling a
    /// [`crate::ikev1::quick::rekey_child`] call ahead of expiry reads this
    /// rather than assuming `InitiatorConfig::p2_lifetime_secs` was actually
    /// honored. It is a time limit only: a volume (kilobytes) limit the gateway
    /// stated is neither held here nor anywhere else in this crate (see
    /// `quick`'s "SA lifetimes" section), so nothing tells the caller when the
    /// gateway's volume limit is near.
    pub p2_lifetime_secs: u32,
    /// The traffic selectors this CHILD SA was actually established with --
    /// `ts_local` may differ from `InitiatorConfig::ts_local` when
    /// Mode-Config narrowed it to the assigned address (see `connect`'s own
    /// doc on that). A future `rekey_child` call must re-offer these same
    /// selectors, not `cfg.ts_local`/`cfg.ts_remote` verbatim.
    pub ts_local: ([u8; 4], [u8; 4]),
    pub ts_remote: ([u8; 4], [u8; 4]),
    /// Our real local `(IP, port)` as seen reaching the peer -- resolved via
    /// [`crate::transport::UdpTransport::local_addr_for`], **not**
    /// [`Client::local_addr`] (which reports the wildcard-bound socket's own
    /// address, `0.0.0.0`, when the socket was never itself `connect()`-ed).
    /// A caller installing a kernel XFRM SA needs this concrete address as
    /// the outer tunnel endpoint -- confirmed live: using `Client::
    /// local_addr()` instead installed an SA with `src 0.0.0.0`, which the
    /// kernel "encapsulated" packets under (usage counters moved) but which
    /// could never actually leave the box as a valid IP packet.
    pub local_addr: SocketAddr,
}

impl Established {
    /// Build the pair of graceful-disconnect Informational messages (one
    /// Delete for the CHILD SA, one for the whole ISAKMP SA, sent as two
    /// separate exchanges — see [`crate::ikev1::informational::build_delete`]'s
    /// doc for why they're not combined into one message). Just builds the
    /// bytes; the caller sends both, in order (typically well after
    /// `connect()` returned and this `Established`'s own `Client`/socket is
    /// long gone — a fresh caller-supplied socket is all that's needed,
    /// since these are fire-and-forget datagrams with no reply to correlate
    /// back to a session). Without ever sending these, the gateway has no
    /// way to learn this side disconnected short of DPD or the SA's own
    /// lifetime expiry — confirmed live against a real FortiGate: it kept
    /// the dialup session (and its `0.0.0.0/0` reverse-route) up
    /// indefinitely after this app exited.
    pub fn close_message(&self, entropy: &mut impl Entropy) -> Result<(Vec<u8>, Vec<u8>), IkeError> {
        informational::build_delete(&self.phase1, entropy, self.child.inbound.spi())
    }
}

/// What [`Client::recv_matching`] waits for, and what it must not mistake for it.
struct Awaiting<'a> {
    cky_i: [u8; 8],
    /// `None` while the responder's cookie isn't known yet (awaiting message 2).
    cky_r: Option<[u8; 8]>,
    exchange_type: u8,
    /// The Message ID the awaited message must carry, when it is known ahead
    /// of time (a Quick Mode reply carries its request's).
    msg_id: Option<u32>,
    floated: bool,
    /// Peer messages this handshake already took: a bit-for-bit repeat of one
    /// is dropped, never read as the next message (RFC 2409 §5).
    handled: &'a [Vec<u8>],
    /// Once Phase 1 exists: the state retaining our final messages, and the
    /// gateway to send them to. A repeat of the peer message one of them
    /// answered gets it sent again (RFC 2408 §3.1, Commit Bit NOTE).
    resend: Option<(&'a Phase1State, SocketAddr)>,
}

impl<'a> Awaiting<'a> {
    /// A Phase 1 message, before there is a [`Phase1State`].
    fn new(cky_i: [u8; 8], cky_r: Option<[u8; 8]>, exchange_type: u8) -> Self {
        Self { cky_i, cky_r, exchange_type, msg_id: None, floated: false, handled: &[], resend: None }
    }

    /// A message of `exchange_type` under the established ISAKMP SA `st`, whose
    /// gateway is `server`.
    fn in_sa(st: &'a Phase1State, exchange_type: u8, server: SocketAddr) -> Self {
        Self { floated: st.floated, resend: Some((st, server)), ..Self::new(st.cky_i, Some(st.cky_r), exchange_type) }
    }

    fn floated(mut self, floated: bool) -> Self {
        self.floated = floated;
        self
    }

    fn msg_id(mut self, msg_id: u32) -> Self {
        self.msg_id = Some(msg_id);
        self
    }

    fn handled(mut self, handled: &'a [Vec<u8>]) -> Self {
        self.handled = handled;
        self
    }
}

/// A UDP IKEv1 initiator driven by an [`Entropy`] source.
pub struct Client<E> {
    transport: UdpTransport,
    /// Present only via [`Self::from_sockets`] -- a caller that never hands
    /// one in (`bind`/`from_socket`, both pre-dating NAT-T) simply can't
    /// float; [`Self::send_step`]/[`Self::recv_matching`] error out rather
    /// than silently staying on port 500 if `phase1.rs`'s NAT-D logic ever
    /// decides floating is needed without one configured.
    natt_transport: Option<UdpTransport>,
    entropy: E,
}

impl<E: Entropy> Client<E> {
    /// Bind a local socket (`"0.0.0.0:0"` for an ephemeral source port). No
    /// NAT-T -- see [`Self::from_sockets`] for that.
    pub fn bind(addr: impl ToSocketAddrs, entropy: E) -> io::Result<Self> {
        Ok(Self { transport: UdpTransport::bind(addr)?, natt_transport: None, entropy })
    }

    /// Like [`Self::bind`], but wrapping an already-bound socket instead of
    /// binding a fresh one (see [`crate::transport::UdpTransport::from_socket`]) --
    /// for a caller holding a persistent well-known-port socket across multiple
    /// connects (e.g. a worker process that binds port 500 once at startup,
    /// the way a real IKE daemon does) hands in a `try_clone`'d handle here
    /// per attempt rather than this crate binding its own. No NAT-T -- see
    /// [`Self::from_sockets`] for that.
    pub fn from_socket(socket: UdpSocket, entropy: E) -> Self {
        Self { transport: UdpTransport::from_socket(socket), natt_transport: None, entropy }
    }

    /// Like [`Self::from_socket`], but also wrapping a persistent port-4500
    /// socket for RFC 3947 NAT-T floating -- the entry point a caller that
    /// already binds both well-known ports once at startup (e.g. alongside
    /// an IKEv2 path) should use instead of `from_socket`, so a connection
    /// that turns out to need floating actually can.
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
    /// handshake itself completes fine over port 4500 (it's all marked IKE
    /// traffic, which this socket receives as plain datagrams either way),
    /// but the ESP-in-UDP data plane that follows never does: incoming
    /// ESP-in-UDP packets have no non-ESP marker (RFC 3948 §2.2) to
    /// distinguish them from IKE control traffic, so without this sockopt
    /// the kernel has no way to tell they're meant for XFRM instead of this
    /// socket's own `recv()` -- they'd just sit there unread while `ping`
    /// through the tunnel gets no reply, exactly as confirmed live: a
    /// fully-succeeding NAT-T handshake with a dead data plane. Mirrors
    /// `ikev2::session::Ikev2Session::sa_init_with_sockets`'s own call site,
    /// just on the `Established` (`Client::connect`) end instead of `IKE_SA_INIT`.
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
    /// never given a port-4500 socket (see [`Self::from_sockets`]) -- rather
    /// than silently sending unfloated, which the peer (now itself expecting
    /// port 4500) would never see.
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

    /// Read datagrams until one carries this session's own ISAKMP cookies
    /// (`cky_r: None` while it isn't known yet, i.e. while awaiting message
    /// 2) *and* the expected `exchange_type` (and Message ID, when `msg_id`
    /// names one) -- everything else is dropped and read again.
    ///
    /// The socket's read timeout bounds the **whole** wait, not each datagram:
    /// a stream of datagrams that never match, arriving faster than the
    /// timeout, would otherwise restart it every time and keep this (and the
    /// retransmission timer of [`Self::send_and_await`], which runs on it)
    /// waiting for ever. Running out of time is a `TimedOut` error, and the
    /// socket's timeout is left as it was found.
    ///
    /// Two kinds of datagram are recognised before that filter, both repeats
    /// of what this handshake already dealt with:
    ///
    /// - a peer message that one of our final messages answered (the gateway
    ///   repeating its Aggressive Mode message 2 or its XAUTH SET because our
    ///   message 3, or our ACK, never arrived: RFC 2408 §3.1, Commit Bit NOTE)
    ///   gets that final message sent again, byte for byte -- no IV or state
    ///   advances for a retransmission (RFC 2409 §5);
    /// - a bit-for-bit repeat of a message in `handled` is dropped: taken for
    ///   the awaited one, a repeated Main Mode message 2 (while awaiting message
    ///   4) or XAUTH REQUEST (while awaiting the SET) fails the handshake.
    ///
    /// This socket is held persistently across
    /// connect attempts (`Client::from_socket`'s doc), so a stray datagram
    /// left over from an earlier, abandoned attempt (e.g. a gateway's
    /// retransmission of an unanswered XAUTH request, still arriving
    /// seconds after this app gave up on it) can otherwise be waiting in
    /// the queue, or arrive mid-exchange, right when this attempt's own
    /// `recv_from` is called -- confirmed live against a real FortiGate:
    /// an unrelated leftover datagram (a different SA's own cookies) got
    /// misread as this exchange's next expected message, its
    /// still-encrypted or otherwise foreign bytes parsed as if they were
    /// this message's real (plaintext or correctly-keyed) content.
    ///
    /// The `exchange_type` check exists for a second, related but distinct
    /// failure confirmed live on the very next attempt after cookie
    /// filtering alone: this same peer, same SA, can legitimately have more
    /// than one message in flight for it -- e.g. a large cert-heavy Main
    /// Mode message 6 lost to IP-level fragmentation (this crate has no IKE
    /// fragmentation support, a separate, still-open gap from NAT-T) while
    /// the gateway's very next message,
    /// its XAUTH request (a real, correctly-cookied datagram for the same
    /// SA, just for a *different* sub-exchange -- `exchange::TRANSACTION`,
    /// message-id nonzero, not `exchange::MAIN`'s message-id 0), arrives
    /// right behind it. Without this check that XAUTH request was
    /// misidentified as message 6 and decrypted under message 6's IV
    /// instead of its own `phase2_iv`, producing the same class of
    /// "declared length exceeds available bytes" garbage cookie-filtering
    /// alone was meant to fix -- a different bogus value each retry, since
    /// each retransmission's ciphertext differs.
    ///
    /// `floated`: once NAT-T (`phase1.rs`'s NAT-D detection) decides this
    /// exchange must float, every message after that point -- both directions
    /// -- moves to the port-4500 transport and carries the non-ESP marker
    /// (RFC 3948 §2.2); a datagram received here without that marker while
    /// `floated` is `true` is dropped as unparseable-for-this-step, same as
    /// any other stray/foreign datagram.
    fn recv_matching(&self, want: &Awaiting) -> Result<Vec<u8>, DriverError> {
        let transport = self.transport_for(want)?;
        self.recv_matching_for(transport, want, transport.read_timeout()?)
    }

    /// The socket `want`'s messages arrive on: the port-4500 one once floated.
    fn transport_for(&self, want: &Awaiting) -> Result<&UdpTransport, DriverError> {
        if want.floated {
            Ok(self.natt_transport.as_ref().ok_or(IkeError::Crypto(
                "NAT-T floating required but this Client has no port-4500 socket (use Client::from_sockets)",
            ))?)
        } else {
            Ok(&self.transport)
        }
    }

    /// [`Self::recv_matching`] for a wait of `wait` in all (`None`: never gives
    /// up), on `transport`, whose read timeout is left as it was found.
    fn recv_matching_for(&self, transport: &UdpTransport, want: &Awaiting, wait: Option<Duration>) -> Result<Vec<u8>, DriverError> {
        let bound = transport.read_timeout()?;
        let result = self.recv_matching_until(transport, want, wait.map(|w| Instant::now() + w));
        transport.set_read_timeout(bound)?;
        result
    }

    /// How long a wait on the floated socket lasts before the well-known port is
    /// looked at ([`Self::answer_repeats_on_port_500`]).
    const PORT_500_SLICE: Duration = Duration::from_millis(100);

    /// How many datagrams one look at the well-known port takes, so that a flood
    /// there cannot keep a wait from ending.
    const PORT_500_LOOK_MAX: usize = 8;

    /// One look at the well-known port while the exchange has floated to 4500 and
    /// a final message of ours is waiting to be asked for: the gateway that never
    /// saw our Aggressive Mode message 3 has not floated (it learns of NAT from
    /// that very message, RFC 3947 §5.3), so it repeats its message 2 *there*
    /// (RFC 2408 §3.1, Commit Bit NOTE), and nothing else would read it. What it
    /// repeats, bit for bit, is answered with the retained final message, sent as
    /// the exchange is now sent (floated); anything else on that port is dropped.
    /// The socket is read without blocking beyond a poll (at most
    /// [`Self::PORT_500_LOOK_MAX`] datagrams), and its read timeout is left as found.
    fn answer_repeats_on_port_500(&self, want: &Awaiting) -> Result<(), DriverError> {
        #[cfg(test)]
        tests::port_500_look_starts();
        let Some((st, server)) = want.resend else { return Ok(()) };
        let bound = self.transport.read_timeout()?;
        self.transport.set_read_timeout(Some(Duration::from_millis(1)))?;
        for _ in 0..Self::PORT_500_LOOK_MAX {
            let Ok((raw, from)) = self.transport.recv_from() else { break };
            match st.finals.answer_to(&raw) {
                Some(final_message) => {
                    ike_debug!("the gateway repeated a message our final message answered, on port 500 -- sending that final message again");
                    if let Err(e) = self.send_step(&final_message, server, want.floated) {
                        ike_debug!("failed to send the final message again: {e:?}");
                    }
                }
                None => ike_debug!("dropping a datagram from {from} on port 500 ({} bytes): the exchange has floated to 4500", raw.len()),
            }
        }
        self.transport.set_read_timeout(bound)?;
        Ok(())
    }

    /// [`Self::recv_matching`]'s loop, giving up at `deadline` (`None`: never).
    /// While the exchange is floated and final messages of ours are retained
    /// (`want.resend`), port 500 is looked at ([`Self::answer_repeats_on_port_500`])
    /// every [`Self::PORT_500_SLICE`] by the clock -- the wait is cut into reads no
    /// longer than what is left of that interval, so neither silence nor a
    /// stream of unrelated datagrams on this socket puts the look off: one
    /// thread, one socket read at a time, and the deadline is still absolute.
    fn recv_matching_until(&self, transport: &UdpTransport, want: &Awaiting, deadline: Option<Instant>) -> Result<Vec<u8>, DriverError> {
        let Awaiting { cky_i, cky_r, exchange_type, floated, .. } = *want;
        let also_port_500 = floated && want.resend.is_some();
        let mut next_look = Instant::now() + Self::PORT_500_SLICE;
        loop {
            // The look is due by the clock, not by the port going quiet: datagrams
            // for someone else arriving on this socket without a pause must not keep
            // a repeat on port 500 from being answered.
            let now = Instant::now();
            if also_port_500 && now >= next_look {
                self.answer_repeats_on_port_500(want)?;
                next_look = Instant::now() + Self::PORT_500_SLICE;
            }
            let mut slice = None;
            if let Some(deadline) = deadline {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(io::Error::from(io::ErrorKind::TimedOut).into());
                }
                slice = Some(remaining);
            }
            if also_port_500 {
                // Never zero, which a socket refuses as a timeout: `next_look` is
                // either after `now` or was just set a slice past it.
                let until_look = next_look.saturating_duration_since(now);
                slice = Some(slice.map_or(until_look, |s| s.min(until_look)));
            }
            if slice.is_some() {
                transport.set_read_timeout(slice)?;
            }
            let (raw, from) = match transport.recv_from() {
                Ok(read) => read,
                Err(e) if also_port_500 && matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => continue,
                Err(e) => return Err(e.into()),
            };
            let msg = if floated {
                match unwrap_ike_4500(&raw) {
                    Some(m) => m.to_vec(),
                    None => {
                        ike_debug!("dropping datagram from {from} on the floated transport with no non-ESP marker ({} bytes)", raw.len());
                        continue;
                    }
                }
            } else {
                raw
            };
            let hdr = match IsakmpHeader::parse(&msg) {
                Ok(h) => h,
                Err(_) => {
                    ike_debug!("dropping unparseable stray datagram from {from} ({} bytes)", msg.len());
                    continue;
                }
            };
            let cookies_ok = hdr.init_cookie == cky_i && cky_r.is_none_or(|r| hdr.resp_cookie == r);
            if cookies_ok {
                if let Some((st, server)) = want.resend {
                    if let Some(final_message) = st.finals.answer_to(&msg) {
                        ike_debug!("the gateway repeated a message our final message answered -- sending that final message again");
                        if let Err(e) = self.send_step(&final_message, server, floated) {
                            ike_debug!("failed to send the final message again: {e:?}");
                        }
                        continue;
                    }
                }
                if want.handled.contains(&msg) {
                    ike_debug!("dropping a repeat of a message already handled (exchange={}, msg-id={:08x})", hdr.exchange_type, hdr.message_id);
                    continue;
                }
            }
            if !cookies_ok || hdr.exchange_type != exchange_type || want.msg_id.is_some_and(|id| id != hdr.message_id) {
                ike_debug!(
                    "dropping out-of-turn datagram from {from}: cookies {:02x?}/{:02x?}, exchange={}, msg-id={:08x} (awaiting {:02x?}/{cky_r:02x?}, exchange={exchange_type}, msg-id={:x?})",
                    hdr.init_cookie,
                    hdr.resp_cookie,
                    hdr.exchange_type,
                    hdr.message_id,
                    cky_i,
                    want.msg_id,
                );
                continue;
            }
            return Ok(msg);
        }
    }

    /// How many times to resend a request (unchanged: same message-id and
    /// cookies, exactly what a retransmission must be) after its answer
    /// times out, before [`Self::send_and_await`] gives up and surfaces the
    /// timeout as a real error: enough resends to ride out a lost UDP datagram
    /// without failing the whole handshake over it, and no more (RFC 2408 §5.1:
    /// a retry counter, then RETRY LIMIT REACHED).
    ///
    /// The waits between the sends are not equal (RFC 2408 §5.1: "MUST NOT use a
    /// fixed timer"): they grow as 1 : 2 : 4 ([`retransmit_waits`]) and add up
    /// to the read timeout once for the first send and once for each
    /// retransmission -- exactly what the caller's read timeout already asked a
    /// dead gateway to be waited for, so that policy is unchanged. They do not
    /// follow a measured round-trip time, which §5.1 also asks for.
    const MAX_RETRANSMITS: u32 = 2;

    /// Send `msg` and wait for its matching reply via [`Self::recv_matching_for`],
    /// resending `msg` up to [`Self::MAX_RETRANSMITS`] more times if a wait
    /// times out before a match arrives, each wait longer than the one before it
    /// (see [`Self::MAX_RETRANSMITS`]). Every request/response round trip in
    /// [`Self::connect`] used to be a bare `send_step` + `recv_matching`: a
    /// single, unacknowledged UDP send with no recovery if that one datagram
    /// (or its reply) is dropped -- the whole handshake just times out. This
    /// covers exactly that case. Each resend is the same bytes (nothing is
    /// rebuilt, no IV advances: RFC 2409 §5), and each wait is absolute (see
    /// [`Self::recv_matching`]), so stray datagrams cannot hold the
    /// retransmission off. A socket with no read timeout waits for ever, as
    /// before, and so never retransmits.
    fn send_and_await(&self, msg: &[u8], server: SocketAddr, want: &Awaiting) -> Result<Vec<u8>, DriverError> {
        self.send_step(msg, server, want.floated)?;
        let transport = self.transport_for(want)?;
        let sends = Self::MAX_RETRANSMITS + 1;
        let waits: Vec<Option<Duration>> = match transport.read_timeout()? {
            Some(timeout) => retransmit_waits(timeout.saturating_mul(sends), sends).into_iter().map(Some).collect(),
            None => vec![None],
        };
        let mut waits = waits.into_iter();
        let mut wait = waits.next().flatten();
        let mut retransmits_left = Self::MAX_RETRANSMITS;
        loop {
            match self.recv_matching_for(transport, want, wait) {
                Ok(reply) => return Ok(reply),
                Err(DriverError::Io(e)) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                    let Some(next) = waits.next() else { return Err(DriverError::Io(e)) };
                    wait = next;
                    retransmits_left -= 1;
                    ike_debug!(
                        "retransmitting exchange={}, now waiting {wait:?} for the answer ({retransmits_left} retransmit(s) left)",
                        want.exchange_type
                    );
                    self.send_step(msg, server, want.floated)?;
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Run the full handshake — Phase 1 (Aggressive or Main Mode, see
    /// [`InitiatorConfig::mode`]) then Quick Mode (msg1/msg2/msg3) — against
    /// `server`, returning the established SA.
    pub fn connect(&mut self, server: SocketAddr, cfg: &InitiatorConfig) -> Result<Established, DriverError> {
        if cfg.mode == Ikev1ExchangeMode::Aggressive && matches!(cfg.local_auth, Ikev1LocalAuth::Sig { .. }) {
            return Err(IkeError::Crypto("Aggressive Mode requires PSK auth (RSA-sig needs Main Mode)").into());
        }
        // Resolved once, up front -- every NAT-D hash computed for this
        // exchange (Main or Aggressive) uses this same fixed pair, exactly
        // like `ikev2::session`'s own NAT-T does (it hashes against the
        // *configured* peer address, not each reply's observed source --
        // confirmed by reading `sa_init_with_sockets`).
        let our_addr = self.transport.local_addr_for(server)?;
        // The gateway's messages this handshake has already taken, so a bit-for-bit
        // repeat of one is not read as the next (see `Awaiting::handled`).
        let mut handled: Vec<Vec<u8>> = Vec::new();
        let phase1 = match cfg.mode {
            Ikev1ExchangeMode::Aggressive => {
                ike_debug!("Aggressive Mode: sending msg1 to {server}");
                let (msg1, ai) = initiate_aggressive(cfg, &mut self.entropy, our_addr, server);
                let cky_i: [u8; 8] = msg1[..8].try_into().unwrap();
                let msg2 = self.send_and_await(&msg1, server, &Awaiting::new(cky_i, None, exchange::AGGRESSIVE))?;
                let (msg3, phase1) = ai.complete(&msg2, our_addr, server)?;
                ike_debug!("Aggressive Mode: complete, sending msg3 (floated={})", phase1.floated);
                self.enable_natt_encap(phase1.floated)?;
                // Nothing answers message 3, so a gateway that never got it can only
                // say so by repeating message 2: keep the pair to answer that.
                phase1.finals.retain(&msg2, &msg3);
                self.send_step(&msg3, server, phase1.floated)?;

                // Aggressive Mode has no acknowledgement for msg3, so pause briefly
                // before the next round — otherwise a fast responder can receive it
                // before it has marked Phase 1 complete and drop it as "phase 1
                // incomplete".
                std::thread::sleep(std::time::Duration::from_millis(200));
                phase1
            }
            Ikev1ExchangeMode::Main => {
                ike_debug!("Main Mode: sending msg1 to {server}");
                let (msg1, sa_sent) = initiate_main(cfg, &mut self.entropy);
                let cky_i: [u8; 8] = msg1[..8].try_into().unwrap();
                let msg2 = self.send_and_await(&msg1, server, &Awaiting::new(cky_i, None, exchange::MAIN))?;
                let cky_r: [u8; 8] = msg2[8..16].try_into().unwrap();
                let (msg3, ke_sent) = sa_sent.complete_sa(&msg2, &mut self.entropy, our_addr, server)?;
                handled.push(msg2);
                // Still unfloated: NAT-D isn't verified until message 4
                // arrives (below), so whether to float is still unknown.
                let msg4 = self.send_and_await(&msg3, server, &Awaiting::new(cky_i, Some(cky_r), exchange::MAIN).handled(&handled))?;
                let (msg5, id_sent) = ke_sent.complete_ke(&msg4)?;
                handled.push(msg4);
                ike_debug!("Main Mode: NAT-T floated={}", id_sent.floated);
                self.enable_natt_encap(id_sent.floated)?;
                let msg6 = self.send_and_await(
                    &msg5,
                    server,
                    &Awaiting::new(cky_i, Some(cky_r), exchange::MAIN).floated(id_sent.floated).handled(&handled),
                )?;
                let msg6_len = msg6.len();
                let floated = id_sent.floated;
                let phase1 = match id_sent.complete_id(&msg6, &mut self.entropy) {
                    Ok(p) => p,
                    Err(failure) => {
                        // See `phase1::AuthFailure`'s doc: SKEYID_a/e are
                        // valid regardless of the failed AUTH check, so this
                        // Delete is a real one the gateway will accept --
                        // best-effort, same as every other Informational this
                        // crate sends (no ack defined, ignore send errors).
                        if let Some(teardown) = failure.teardown {
                            ike_debug!("Main Mode: gateway AUTH did not verify -- sending an ISAKMP Delete so it doesn't spin DPD probes against a peer that already gave up");
                            let _ = self.send_step(&teardown, server, floated);
                        }
                        return Err(failure.error.into());
                    }
                };
                // Unlike Aggressive Mode, message 6 is a real reply the
                // initiator already waited for above, so Phase 1 is known
                // complete on both sides here -- no artificial pause needed
                // before Quick Mode.
                ike_debug!(
                    "Main Mode: complete, msg6_len={msg6_len}, phase1_iv={}",
                    phase1.phase1_iv.iter().map(|b| format!("{b:02x}")).collect::<String>()
                );
                phase1
            }
        };

        ike_debug!(
            "Phase 1: established -- prf={:?} group={:?} lifetime={}s floated={} peer DPD support={}",
            phase1.prf, phase1.group, phase1.negotiated_lifetime_secs, phase1.floated, phase1.peer_supports_dpd
        );

        // XAUTH: the gateway (not us) sends the first message here — see
        // crate::ikev1::xauth's doc comment. Only run when the caller actually
        // has credentials to answer with; `xauth: true, xauth_creds: None`
        // (SA negotiation only, no real gateway) skips this. Everything from
        // here on (XAUTH, Mode-Config, Quick Mode) uses `phase1.floated`,
        // decided above -- once floated, every later exchange on this same
        // SA stays floated (the peer only ever listens on the port it also
        // decided to float to).
        if let Some((user, password)) = &cfg.xauth_creds {
            ike_debug!("XAUTH: waiting for the gateway's request");
            let request = self.recv_matching(&Awaiting::in_sa(&phase1, exchange::TRANSACTION, server).handled(&handled))?;
            let reply = xauth::build_xauth_reply(&phase1, &request, user, password)?;
            handled.push(request);
            let set_msg = self.send_and_await(&reply, server, &Awaiting::in_sa(&phase1, exchange::TRANSACTION, server).handled(&handled))?;
            let (ack, ok) = xauth::build_xauth_ack(&phase1, &set_msg)?;
            // Nothing answers the ACK either: a gateway that never got it repeats
            // its SET, and that is answered with this same ACK.
            phase1.finals.retain(&set_msg, &ack);
            self.send_step(&ack, server, phase1.floated)?;
            ike_debug!("XAUTH: {}", if ok { "succeeded" } else { "failed" });
            if !ok {
                return Err(IkeError::AuthFailed.into());
            }
        }

        // Mode-Config: request an assigned inner IPv4 (+ netmask/DNS/subnet)
        // -- see `crate::ikev1::cfg`'s doc. Some gateways reject the following
        // Quick Mode proposal outright ("peer has not completed Configuration
        // Method") if this round is skipped.
        let (mut assigned_ip4, mut netmask, mut dns, mut subnets) = (None, None, Vec::new(), Vec::new());
        let (mut assigned_ip6, mut dns6, mut subnets6) = (None, Vec::new(), Vec::new());
        if cfg.mode_cfg {
            ike_debug!("Mode-Config: requesting an assigned IPv4{}", if cfg.ipv6 { " and IPv6" } else { "" });
            let mut mid_b = [0u8; 4];
            self.entropy.fill(&mut mid_b);
            let msgid = u32::from_be_bytes(mid_b) | 1; // non-zero
            let (request, next_iv) = modecfg::build_cfg_request_with(&phase1, msgid, cfg.ipv6)?;
            // No message id filter: a Mode-Config reply is taken under whichever id
            // the gateway chose (`parse_cfg_reply` decrypts under the request's IV).
            let reply = self.send_and_await(&request, server, &Awaiting::in_sa(&phase1, exchange::TRANSACTION, server).handled(&handled))?;
            let got = modecfg::parse_cfg_reply(&phase1, &reply, &next_iv)?;
            assigned_ip4 = got.assigned_ipv4();
            netmask = got.assigned_netmask();
            dns = got.assigned_dns();
            subnets = got.assigned_subnets();
            if cfg.ipv6 {
                assigned_ip6 = got.assigned_ipv6();
                dns6 = got.assigned_ipv6_dns();
                subnets6 = got.assigned_ipv6_subnets();
            }
            ike_debug!(
                "Mode-Config: assigned {assigned_ip4:?}/{netmask:?}, IPv6 {assigned_ip6:?}; dns={dns:?} dns6={dns6:?}; subnets={subnets:?} subnets6={subnets6:?}"
            );
        }

        // Phase 2: Quick Mode, optionally with PFS (see `InitiatorConfig::pfs_group`'s doc).
        //
        // When Mode-Config assigned us an address, narrow our own selector
        // (IDci/TSi) to that single host instead of `cfg.ts_local` -- the
        // gateway is the Quick Mode *responder* here, and a responder's
        // reverse-route injection installs a route for whatever the
        // initiator's selector actually was. Offering `0.0.0.0/0` as TSi (the
        // `cfg.ts_local` default, still used when Mode-Config wasn't run)
        // gets that reflected back verbatim: a `0.0.0.0/0` catch-all route
        // via this tunnel's own interface, not a host route to our assigned
        // address. `ts_remote` stays whatever the caller configured
        // (`0.0.0.0/0` for full tunnel) -- narrowing is only meaningful for
        // our own address, not the network reachable through the gateway.
        let ts_local = match assigned_ip4 {
            Some(ip) => (ip.octets(), [255, 255, 255, 255]),
            None => cfg.ts_local,
        };
        ike_debug!(
            "Quick Mode: starting{}",
            if cfg.pfs_group.is_some() { " with PFS" } else { "" }
        );
        let (qm1, qi) =
            initiate_quick_with_pfs(&phase1, &mut self.entropy, cfg.esp_cipher, ts_local, cfg.ts_remote, cfg.pfs_group, cfg.p2_lifetime_secs)?;
        let qm1_msgid = IsakmpHeader::parse(&qm1)?.message_id;
        let qm2 = self.send_and_await(&qm1, server, &Awaiting::in_sa(&phase1, exchange::QUICK, server).msg_id(qm1_msgid).handled(&handled))?;
        let (qm3, child, p2_lifetime_secs) = qi.complete(&qm2)?;
        // Quick Mode message 3 is the last of the exchange and nothing answers it:
        // keep the pair, so the gateway repeating message 2 gets it sent again --
        // also once this returns, whenever the caller next reads this socket.
        phase1.finals.retain(&qm2, &qm3);
        self.send_step(&qm3, server, phase1.floated)?;
        ike_debug!(
            "Quick Mode (IPv4 CHILD SA): complete -- spi_in={:08x} spi_out={:08x}, lifetime {p2_lifetime_secs}s",
            child.inbound.spi(), child.outbound.spi()
        );

        // Post-float, our own reported address's port must be 4500 too, not
        // just the peer's -- a caller deciding whether to install a
        // UDP-encap kernel XFRM SA reads `phase1.floated` directly (see
        // `Phase1State::floated`'s doc) and pairs it with this `local_addr`
        // and its own already-known `server` address (bumped to port 4500
        // the same way) -- the same IKE-version-agnostic, port-based signal
        // an IKEv2 NAT-T path would use too.
        let local_addr =
            if phase1.floated { SocketAddr::new(our_addr.ip(), crate::natt_port()) } else { self.transport.local_addr_for(server)? };
        Ok(Established { phase1, child, assigned_ip4, netmask, dns, subnets, assigned_ip6, dns6, subnets6, local_addr, p2_lifetime_secs, ts_local, ts_remote: cfg.ts_remote })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::SeedEntropy;
    use std::net::UdpSocket;

    thread_local! {
        static ON_PORT_500_LOOK: std::cell::RefCell<Option<Box<dyn FnMut()>>> = const { std::cell::RefCell::new(None) };
    }

    /// Called as [`Client::answer_repeats_on_port_500`] is entered, before it
    /// decides whether there is anything to do: what a test hooked in with
    /// [`OnPort500Look`] sees, on the thread that is waiting.
    pub(super) fn port_500_look_starts() {
        ON_PORT_500_LOOK.with(|hook| {
            if let Some(hook) = hook.borrow_mut().as_mut() {
                hook();
            }
        });
    }

    /// Runs a hook each time this thread starts a look at port 500, until dropped.
    struct OnPort500Look;

    impl OnPort500Look {
        fn install(hook: impl FnMut() + 'static) -> Self {
            ON_PORT_500_LOOK.with(|h| *h.borrow_mut() = Some(Box::new(hook)));
            Self
        }
    }

    impl Drop for OnPort500Look {
        fn drop(&mut self) {
            ON_PORT_500_LOOK.with(|h| *h.borrow_mut() = None);
        }
    }

    /// A minimal (no payloads) but wire-valid ISAKMP header buffer --
    /// version and length set correctly, since `IsakmpHeader::parse` now
    /// validates both -- with the exchange type set and cookies left zeroed
    /// for the caller to patch via slicing.
    fn blank_header(exchange_type: u8) -> Vec<u8> {
        let mut buf = vec![0u8; IsakmpHeader::LEN];
        buf[17] = IsakmpHeader::VERSION_1_0;
        buf[18] = exchange_type;
        buf[24..28].copy_from_slice(&(IsakmpHeader::LEN as u32).to_be_bytes());
        buf
    }

    /// A stray datagram carrying a *different* session's cookies (e.g. a
    /// gateway's retransmission of an earlier, abandoned connection attempt,
    /// still arriving on this long-held socket) must be silently dropped by
    /// `recv_matching`, not mistaken for the real reply -- the exact bug
    /// this method exists to fix (see its own doc comment), confirmed live
    /// against a real FortiGate before this fix landed.
    #[test]
    fn recv_matching_skips_a_stray_datagram_with_the_wrong_cookies() {
        let client = Client { transport: UdpTransport::bind("127.0.0.1:0").unwrap(), natt_transport: None, entropy: SeedEntropy::new(1) };
        let client_addr = client.local_addr().unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();

        let cky_i = [0xAA; 8];
        let cky_r = [0xBB; 8];

        // A stray message: correct wire shape, but cookies from an unrelated
        // session -- must not satisfy `recv_matching`.
        let mut stray = blank_header(exchange::MAIN);
        stray[..8].copy_from_slice(&[0x11; 8]);
        stray[8..16].copy_from_slice(&[0x22; 8]);
        sender.send_to(&stray, client_addr).unwrap();

        // The real message, sent right after -- must be the one returned.
        let mut real = blank_header(exchange::MAIN);
        real[..8].copy_from_slice(&cky_i);
        real[8..16].copy_from_slice(&cky_r);
        sender.send_to(&real, client_addr).unwrap();

        client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let got = client.recv_matching(&Awaiting::new(cky_i, Some(cky_r), exchange::MAIN)).unwrap();
        assert_eq!(got, real, "must skip the stray datagram and return the one with matching cookies");
    }

    /// While `cky_r` isn't known yet (awaiting message 2), any resp_cookie is
    /// accepted -- only `cky_i` (which we chose ourselves and put in our own
    /// message 1) can be checked at that point.
    #[test]
    fn recv_matching_accepts_any_resp_cookie_when_not_yet_known() {
        let client = Client { transport: UdpTransport::bind("127.0.0.1:0").unwrap(), natt_transport: None, entropy: SeedEntropy::new(1) };
        let client_addr = client.local_addr().unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();

        let cky_i = [0xAA; 8];
        let mut real = blank_header(exchange::MAIN);
        real[..8].copy_from_slice(&cky_i);
        real[8..16].copy_from_slice(&[0xCC; 8]); // responder's freshly-chosen cookie
        sender.send_to(&real, client_addr).unwrap();

        client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let got = client.recv_matching(&Awaiting::new(cky_i, None, exchange::MAIN)).unwrap();
        assert_eq!(got, real);
    }

    /// The exact bug found live: a correctly-cookied datagram for the same
    /// SA but a *different* sub-exchange (e.g. the gateway's XAUTH request
    /// arriving while `connect()` is still waiting for Main Mode's message
    /// 6, because message 6 itself was lost) must be skipped, not accepted
    /// as if it were the awaited message -- accepting it fed the wrong IV
    /// formula to the next decrypt, producing an unrelated "declared length
    /// exceeds available bytes" a few bytes into the resulting garbage.
    #[test]
    fn recv_matching_skips_a_same_session_datagram_from_the_wrong_sub_exchange() {
        let client = Client { transport: UdpTransport::bind("127.0.0.1:0").unwrap(), natt_transport: None, entropy: SeedEntropy::new(1) };
        let client_addr = client.local_addr().unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();

        let cky_i = [0xAA; 8];
        let cky_r = [0xBB; 8];

        // A same-SA, same-cookies datagram, but for the Transaction (XAUTH)
        // exchange, not the Main Mode message 6 this call awaits.
        let mut wrong_exchange = blank_header(exchange::TRANSACTION);
        wrong_exchange[..8].copy_from_slice(&cky_i);
        wrong_exchange[8..16].copy_from_slice(&cky_r);
        sender.send_to(&wrong_exchange, client_addr).unwrap();

        let mut real = blank_header(exchange::MAIN);
        real[..8].copy_from_slice(&cky_i);
        real[8..16].copy_from_slice(&cky_r);
        sender.send_to(&real, client_addr).unwrap();

        client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let got = client.recv_matching(&Awaiting::new(cky_i, Some(cky_r), exchange::MAIN)).unwrap();
        assert_eq!(got, real, "must skip the Transaction-exchange datagram and return the Main-Mode one");
    }

    /// A header for `exchange_type` under the session `cky_i`/`cky_r` with
    /// `message_id`.
    fn message(cky_i: [u8; 8], cky_r: [u8; 8], exchange_type: u8, message_id: u32) -> Vec<u8> {
        let mut m = blank_header(exchange_type);
        m[..8].copy_from_slice(&cky_i);
        m[8..16].copy_from_slice(&cky_r);
        m[20..24].copy_from_slice(&message_id.to_be_bytes());
        m
    }

    /// A message this handshake already took must not be taken again when the
    /// gateway repeats it (RFC 2409 §5: a retransmission does not advance the
    /// exchange). Here it is the first thing to arrive, ahead of the real next
    /// message, carrying the same cookies and exchange type: without `handled`
    /// it would be returned as if it were that next message.
    #[test]
    fn recv_matching_drops_a_bit_for_bit_repeat_of_a_message_already_handled() {
        let client = Client { transport: UdpTransport::bind("127.0.0.1:0").unwrap(), natt_transport: None, entropy: SeedEntropy::new(1) };
        client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let (cky_i, cky_r) = ([0xAA; 8], [0xBB; 8]);
        let taken = message(cky_i, cky_r, exchange::MAIN, 0);
        let next = message(cky_i, cky_r, exchange::MAIN, 7);
        let handled = vec![taken.clone()];

        sender.send_to(&taken, client.local_addr().unwrap()).unwrap();
        sender.send_to(&next, client.local_addr().unwrap()).unwrap();
        let got = client.recv_matching(&Awaiting::new(cky_i, Some(cky_r), exchange::MAIN).handled(&handled)).unwrap();
        assert_eq!(got, next, "the repeat of a handled message must be dropped");

        // Control: the same two datagrams without the list -- the first one wins.
        sender.send_to(&taken, client.local_addr().unwrap()).unwrap();
        sender.send_to(&next, client.local_addr().unwrap()).unwrap();
        let got = client.recv_matching(&Awaiting::new(cky_i, Some(cky_r), exchange::MAIN)).unwrap();
        assert_eq!(got, taken, "without the handled list the first matching datagram is returned");
        client.recv_matching(&Awaiting::new(cky_i, Some(cky_r), exchange::MAIN)).unwrap();
    }

    /// A datagram that is not identical to a handled message is not one of
    /// them, however similar: one flipped bit and it is a different message.
    #[test]
    fn recv_matching_only_drops_exact_repeats() {
        let client = Client { transport: UdpTransport::bind("127.0.0.1:0").unwrap(), natt_transport: None, entropy: SeedEntropy::new(1) };
        client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let (cky_i, cky_r) = ([0xAA; 8], [0xBB; 8]);
        let taken = message(cky_i, cky_r, exchange::MAIN, 0);
        let similar = message(cky_i, cky_r, exchange::MAIN, 1);
        let handled = vec![taken];

        sender.send_to(&similar, client.local_addr().unwrap()).unwrap();
        let got = client.recv_matching(&Awaiting::new(cky_i, Some(cky_r), exchange::MAIN).handled(&handled)).unwrap();
        assert_eq!(got, similar);
    }

    /// A Quick Mode reply carries its request's Message ID: another exchange's
    /// message (a leftover of an earlier Quick Mode, a gateway-initiated one)
    /// is not the reply, and `msg_id` says so.
    #[test]
    fn recv_matching_skips_a_message_with_another_message_id_when_one_is_named() {
        let client = Client { transport: UdpTransport::bind("127.0.0.1:0").unwrap(), natt_transport: None, entropy: SeedEntropy::new(1) };
        client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let (cky_i, cky_r) = ([0xAA; 8], [0xBB; 8]);
        let other = message(cky_i, cky_r, exchange::QUICK, 0x0102_0304);
        let reply = message(cky_i, cky_r, exchange::QUICK, 0x0a0b_0c0d);

        sender.send_to(&other, client.local_addr().unwrap()).unwrap();
        sender.send_to(&reply, client.local_addr().unwrap()).unwrap();
        let got = client.recv_matching(&Awaiting::new(cky_i, Some(cky_r), exchange::QUICK).msg_id(0x0a0b_0c0d)).unwrap();
        assert_eq!(got, reply);

        // Control: with no id named, the first Quick Mode message is taken.
        sender.send_to(&other, client.local_addr().unwrap()).unwrap();
        let got = client.recv_matching(&Awaiting::new(cky_i, Some(cky_r), exchange::QUICK)).unwrap();
        assert_eq!(got, other);
    }

    /// A Phase 1 state with the given cookies and no key material worth
    /// speaking of, for the tests that only need its cookies and retained finals.
    fn phase1_with_cookies(cky_i: [u8; 8], cky_r: [u8; 8]) -> Phase1State {
        Phase1State::resume(
            crate::ikev1::crypto1::Prf::Sha256,
            crate::crypto::DhGroup::Modp2048,
            cky_i,
            cky_r,
            vec![],
            vec![],
            vec![],
            vec![],
            crate::ikev1::crypto1::AES_BLOCK,
            vec![],
        )
    }

    /// The gateway repeating the message one of our final messages answered gets
    /// that final message again, untouched, from inside `recv_matching` -- and
    /// the wait goes on for what it is really waiting for. The repeated message
    /// is tried with the awaited exchange type and with another one: neither may
    /// be returned or ignored.
    #[test]
    fn recv_matching_sends_the_retained_final_message_again_when_the_gateway_repeats_what_it_answered() {
        for repeated_type in [exchange::TRANSACTION, exchange::AGGRESSIVE] {
            let client = Client { transport: UdpTransport::bind("127.0.0.1:0").unwrap(), natt_transport: None, entropy: SeedEntropy::new(1) };
            client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let gateway = UdpSocket::bind("127.0.0.1:0").unwrap();
            gateway.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            let (cky_i, cky_r) = ([0xAA; 8], [0xBB; 8]);
            let st = phase1_with_cookies(cky_i, cky_r);
            let repeated = message(cky_i, cky_r, repeated_type, 9);
            let mut our_final = message(cky_i, cky_r, repeated_type, 9);
            our_final.extend_from_slice(b"our final message");
            st.finals.retain(&repeated, &our_final);
            let next = message(cky_i, cky_r, exchange::TRANSACTION, 12);

            gateway.send_to(&repeated, client.local_addr().unwrap()).unwrap();
            gateway.send_to(&next, client.local_addr().unwrap()).unwrap();
            let got = client.recv_matching(&Awaiting::in_sa(&st, exchange::TRANSACTION, gateway.local_addr().unwrap())).unwrap();
            assert_eq!(got, next, "repeated exchange type {repeated_type}");

            let mut buf = [0u8; 256];
            let (n, _) = gateway.recv_from(&mut buf).expect("the retained final message must have been sent again");
            assert_eq!(&buf[..n], &our_final[..], "repeated exchange type {repeated_type}");
        }
    }

    /// Without the state to send from (`resend: None`, before Phase 1 exists) or
    /// for a datagram that is not, bit for bit, one of the answered messages,
    /// nothing is sent.
    #[test]
    fn recv_matching_sends_nothing_for_a_message_no_final_message_answered() {
        let client = Client { transport: UdpTransport::bind("127.0.0.1:0").unwrap(), natt_transport: None, entropy: SeedEntropy::new(1) };
        client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let gateway = UdpSocket::bind("127.0.0.1:0").unwrap();
        gateway.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        let (cky_i, cky_r) = ([0xAA; 8], [0xBB; 8]);
        let st = phase1_with_cookies(cky_i, cky_r);
        st.finals.retain(&message(cky_i, cky_r, exchange::TRANSACTION, 9), b"our final message");
        let similar = message(cky_i, cky_r, exchange::TRANSACTION, 10);

        gateway.send_to(&similar, client.local_addr().unwrap()).unwrap();
        let got = client.recv_matching(&Awaiting::in_sa(&st, exchange::TRANSACTION, gateway.local_addr().unwrap())).unwrap();
        assert_eq!(got, similar);
        let mut buf = [0u8; 256];
        assert!(gateway.recv_from(&mut buf).is_err(), "nothing answered that message, so nothing may be sent");
    }

    /// A request whose reply is lost must be resent, not just give up on the
    /// first read timeout -- every real round trip in [`Client::connect`]
    /// goes through [`Client::send_and_await`]. The fake responder here
    /// discards the first delivery entirely and only answers the
    /// retransmission, mirroring
    /// `ikev2::session::tests::send_and_retry_recovers_from_one_dropped_request`.
    #[test]
    fn send_and_await_retransmits_after_one_dropped_reply() {
        let client = Client { transport: UdpTransport::bind("127.0.0.1:0").unwrap(), natt_transport: None, entropy: SeedEntropy::new(1) };
        client.set_read_timeout(Some(Duration::from_millis(100))).unwrap();

        let responder_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let responder_addr = responder_sock.local_addr().unwrap();

        let cky_i = [0xAA; 8];
        let cky_r = [0xBB; 8];
        let mut req = blank_header(exchange::MAIN);
        req[..8].copy_from_slice(&cky_i);
        let mut reply = blank_header(exchange::MAIN);
        reply[..8].copy_from_slice(&cky_i);
        reply[8..16].copy_from_slice(&cky_r);

        let (req_check, reply_send) = (req.clone(), reply.clone());
        let responder = std::thread::spawn(move || {
            let mut buf = [0u8; 128];
            // First delivery: simulate a dropped datagram -- read and discard it.
            let (n, _from) = responder_sock.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..n], req_check);
            // The retransmission (identical bytes): answer this one.
            let (n, from) = responder_sock.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..n], req_check);
            responder_sock.send_to(&reply_send, from).unwrap();
        });

        let got = client.send_and_await(&req, responder_addr, &Awaiting::new(cky_i, Some(cky_r), exchange::MAIN)).unwrap();
        assert_eq!(got, reply);
        responder.join().unwrap();
    }

    /// The read timeout bounds the whole wait, not each datagram: a stream of
    /// stray datagrams (a chatty gateway, a leftover from an abandoned attempt,
    /// anything else that reaches the port) arriving faster than the timeout
    /// must not keep `recv_matching` waiting for ever.
    #[test]
    fn recv_matching_gives_up_within_its_timeout_however_many_stray_datagrams_arrive() {
        let client = Client { transport: UdpTransport::bind("127.0.0.1:0").unwrap(), natt_transport: None, entropy: SeedEntropy::new(1) };
        client.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        let strays = StrayStream::start(client.local_addr().unwrap(), Duration::from_secs(2));

        let started = std::time::Instant::now();
        let err = client.recv_matching(&Awaiting::new([0xAA; 8], Some([0xBB; 8]), exchange::MAIN)).unwrap_err();
        let waited = started.elapsed();
        strays.stop();
        assert!(matches!(&err, DriverError::Io(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)), "{err:?}");
        assert!(waited < Duration::from_millis(900), "waited {waited:?} for a 300 ms timeout");
    }

    /// One stray datagram late in the wait, then silence: the wait must still
    /// end when the timeout counted from its start says so, not a whole timeout
    /// after that stray. And the socket's timeout is the caller's again afterwards.
    #[test]
    fn recv_matching_does_not_start_its_timeout_over_after_a_stray_datagram() {
        let client = Client { transport: UdpTransport::bind("127.0.0.1:0").unwrap(), natt_transport: None, entropy: SeedEntropy::new(1) };
        client.set_read_timeout(Some(Duration::from_millis(400))).unwrap();
        let to = client.local_addr().unwrap();
        let late_stray = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            let mut stray = blank_header(exchange::MAIN);
            stray[..16].copy_from_slice(&[0x11; 16]);
            UdpSocket::bind("127.0.0.1:0").unwrap().send_to(&stray, to).unwrap();
        });

        let started = std::time::Instant::now();
        let err = client.recv_matching(&Awaiting::new([0xAA; 8], Some([0xBB; 8]), exchange::MAIN)).unwrap_err();
        let waited = started.elapsed();
        late_stray.join().unwrap();
        assert!(matches!(&err, DriverError::Io(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)), "{err:?}");
        assert!(waited < Duration::from_millis(550), "waited {waited:?} for a 400 ms timeout");
        assert_eq!(client.transport.read_timeout().unwrap(), Some(Duration::from_millis(400)), "the caller's timeout must be left as it was");
    }

    /// A deadline that has passed is a timeout -- the kind `send_and_await`
    /// retransmits on -- and reads nothing more, whatever waits on the socket.
    /// Reaching it with a zero timeout instead would be refused by the socket
    /// as `InvalidInput`, an error that ends the handshake.
    #[test]
    fn recv_matching_until_reports_a_passed_deadline_as_a_timeout_and_reads_nothing() {
        let client = Client { transport: UdpTransport::bind("127.0.0.1:0").unwrap(), natt_transport: None, entropy: SeedEntropy::new(1) };
        client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let (cky_i, cky_r) = ([0xAA; 8], [0xBB; 8]);
        let waiting = message(cky_i, cky_r, exchange::MAIN, 0);
        sender.send_to(&waiting, client.local_addr().unwrap()).unwrap();

        let passed = std::time::Instant::now().checked_sub(Duration::from_millis(1)).unwrap();
        let want = Awaiting::new(cky_i, Some(cky_r), exchange::MAIN);
        let err = client.recv_matching_until(&client.transport, &want, Some(passed)).unwrap_err();
        assert!(matches!(&err, DriverError::Io(e) if e.kind() == io::ErrorKind::TimedOut), "{err:?}");

        let got = client.recv_matching(&want).unwrap();
        assert_eq!(got, waiting, "an expired deadline must leave the datagram on the socket");
    }

    /// The retransmission timer runs on that same bound: strays must not
    /// starve the resends of the request.
    #[test]
    fn send_and_await_keeps_retransmitting_while_stray_datagrams_arrive() {
        let client = Client { transport: UdpTransport::bind("127.0.0.1:0").unwrap(), natt_transport: None, entropy: SeedEntropy::new(1) };
        client.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        let listener = UdpSocket::bind("127.0.0.1:0").unwrap();
        let listener_addr = listener.local_addr().unwrap();
        listener.set_read_timeout(Some(Duration::from_millis(1800))).unwrap();
        let counter = std::thread::spawn(move || {
            let mut buf = [0u8; 128];
            let (mut sends, deadline) = (0u32, std::time::Instant::now() + Duration::from_millis(1800));
            while std::time::Instant::now() < deadline && listener.recv_from(&mut buf).is_ok() {
                sends += 1;
            }
            sends
        });
        let strays = StrayStream::start(client.local_addr().unwrap(), Duration::from_secs(2));

        let started = std::time::Instant::now();
        let err = client.send_and_await(&blank_header(exchange::MAIN), listener_addr, &Awaiting::new([0xAA; 8], None, exchange::AGGRESSIVE)).unwrap_err();
        let waited = started.elapsed();
        strays.stop();
        assert!(matches!(&err, DriverError::Io(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)), "{err:?}");
        assert!(waited < Duration::from_millis(1500), "gave up after {waited:?}");
        assert_eq!(counter.join().unwrap(), Client::<SeedEntropy>::MAX_RETRANSMITS + 1);
    }

    /// Datagrams with someone else's cookies, one every 40 ms until stopped
    /// or `for_at_most` has passed.
    struct StrayStream {
        stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
        thread: std::thread::JoinHandle<()>,
    }

    impl StrayStream {
        fn start(to: SocketAddr, for_at_most: Duration) -> Self {
            let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let flag = stop.clone();
            let thread = std::thread::spawn(move || {
                let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
                let mut stray = blank_header(exchange::MAIN);
                stray[..16].copy_from_slice(&[0x11; 16]);
                let end = std::time::Instant::now() + for_at_most;
                while !flag.load(std::sync::atomic::Ordering::Relaxed) && std::time::Instant::now() < end {
                    sender.send_to(&stray, to).unwrap();
                    std::thread::sleep(Duration::from_millis(40));
                }
            });
            Self { stop, thread }
        }

        fn stop(self) {
            self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
            self.thread.join().unwrap();
        }
    }

    /// A client that has floated to port 4500 (both sockets on loopback), and a
    /// gateway at an address of its own -- port 4500 of it is where a floated
    /// client sends -- with the socket it uses for port 500.
    struct Floated {
        client: Client<SeedEntropy>,
        gateway_500: UdpSocket,
        gateway_4500: UdpSocket,
        server: SocketAddr,
    }

    fn floated_client(gateway_host: [u8; 4]) -> Floated {
        let client = Client {
            transport: UdpTransport::bind("127.0.0.1:0").unwrap(),
            natt_transport: Some(UdpTransport::bind("127.0.0.1:0").unwrap()),
            entropy: SeedEntropy::new(1),
        };
        let host = Ipv4Addr::from(gateway_host);
        let gateway_4500 = UdpSocket::bind((host, crate::natt_port())).unwrap();
        let gateway_500 = UdpSocket::bind((host, 0)).unwrap();
        let server = gateway_500.local_addr().unwrap();
        Floated { client, gateway_500, gateway_4500, server }
    }

    impl Floated {
        fn port_500(&self) -> SocketAddr {
            self.client.transport.local_addr().unwrap()
        }

        fn port_4500(&self) -> SocketAddr {
            self.client.natt_transport.as_ref().unwrap().local_addr().unwrap()
        }

        /// What the gateway's port 4500 has received, without the non-ESP marker.
        fn received_on_4500(&self, wait: Duration) -> Option<Vec<u8>> {
            self.gateway_4500.set_read_timeout(Some(wait)).unwrap();
            let mut buf = [0u8; 512];
            let (n, _) = self.gateway_4500.recv_from(&mut buf).ok()?;
            Some(unwrap_ike_4500(&buf[..n]).expect("a floated message carries the non-ESP marker").to_vec())
        }
    }

    /// RFC 2408 §3.1 with RFC 3947 §5.3: the gateway that never saw our Aggressive
    /// Mode message 3 has not floated, and repeats its message 2 to port 500. A
    /// wait on port 4500 hears it there and sends the retained final message
    /// again -- floated, untouched, while the wait goes on for what it really
    /// awaits -- and leaves the sockets' timeouts as it found them.
    #[test]
    fn a_floated_wait_answers_a_repeat_on_port_500_with_the_retained_final_message() {
        let f = floated_client([127, 78, 1, 1]);
        f.client.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let (cky_i, cky_r) = ([0xAA; 8], [0xBB; 8]);
        let st = phase1_with_cookies(cky_i, cky_r);
        let repeated = message(cky_i, cky_r, exchange::AGGRESSIVE, 0);
        let mut our_final = message(cky_i, cky_r, exchange::AGGRESSIVE, 0);
        our_final.extend_from_slice(b"our final message");
        st.finals.retain(&repeated, &our_final);
        let next = message(cky_i, cky_r, exchange::TRANSACTION, 12);

        f.gateway_500.send_to(&repeated, f.port_500()).unwrap();
        let (gateway_4500, to) = (f.gateway_4500.try_clone().unwrap(), f.port_4500());
        let late = next.clone();
        let sender = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(400));
            gateway_4500.send_to(&wrap_ike_4500(&late), to).unwrap();
        });
        let got = f.client.recv_matching(&Awaiting::in_sa(&st, exchange::TRANSACTION, f.server).floated(true)).unwrap();
        sender.join().unwrap();
        assert_eq!(got, next, "the wait goes on for the message it awaits");
        assert_eq!(f.received_on_4500(Duration::from_secs(2)), Some(our_final), "the retained final message, floated");
        assert_eq!(f.client.transport.read_timeout().unwrap(), Some(Duration::from_secs(3)), "the port-500 socket's timeout must be left as it was");
        assert_eq!(f.client.natt_transport.as_ref().unwrap().read_timeout().unwrap(), Some(Duration::from_secs(3)));
    }

    /// Datagrams on port 500 that no final message answered get nothing sent, and
    /// however fast they come the wait still ends at its deadline: a look at the
    /// port takes a few datagrams, not all that arrive.
    #[test]
    fn a_floated_wait_ends_at_its_deadline_however_fast_datagrams_reach_port_500() {
        let f = floated_client([127, 78, 1, 2]);
        f.client.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        let (cky_i, cky_r) = ([0xAA; 8], [0xBB; 8]);
        let st = phase1_with_cookies(cky_i, cky_r);
        st.finals.retain(&message(cky_i, cky_r, exchange::AGGRESSIVE, 0), b"our final message");
        let (stop, to) = (std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)), f.port_500());
        let flag = stop.clone();
        let flood = std::thread::spawn(move || {
            let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
            let similar = message(cky_i, cky_r, exchange::AGGRESSIVE, 1);
            let end = std::time::Instant::now() + Duration::from_millis(1500);
            while !flag.load(std::sync::atomic::Ordering::Relaxed) && std::time::Instant::now() < end {
                let _ = sender.send_to(&similar, to);
            }
        });

        let started = std::time::Instant::now();
        let err = f.client.recv_matching(&Awaiting::in_sa(&st, exchange::TRANSACTION, f.server).floated(true)).unwrap_err();
        let waited = started.elapsed();
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        flood.join().unwrap();
        assert!(matches!(&err, DriverError::Io(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)), "{err:?}");
        assert!(waited < Duration::from_millis(800), "waited {waited:?} for a 300 ms timeout");
        assert_eq!(f.received_on_4500(Duration::from_millis(200)), None, "no final message answered any of them");
    }

    /// Without a final message of ours retained (`resend: None`) there is nothing a
    /// repeat on port 500 could ask for, so that port is left alone: what waits
    /// there is still there afterwards.
    #[test]
    fn a_floated_wait_with_nothing_to_resend_leaves_port_500_unread() {
        let f = floated_client([127, 78, 1, 3]);
        f.client.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        let (cky_i, cky_r) = ([0xAA; 8], [0xBB; 8]);
        let waiting = message(cky_i, cky_r, exchange::AGGRESSIVE, 0);
        f.gateway_500.send_to(&waiting, f.port_500()).unwrap();

        let want = Awaiting::new(cky_i, Some(cky_r), exchange::TRANSACTION).floated(true);
        let err = f.client.recv_matching(&want).unwrap_err();
        assert!(matches!(&err, DriverError::Io(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)), "{err:?}");
        let still_there = f.client.recv_matching(&Awaiting::new(cky_i, Some(cky_r), exchange::AGGRESSIVE)).unwrap();
        assert_eq!(still_there, waiting);
    }

    /// Which waits look at port 500: one on the floated socket that has a final
    /// message of ours retained to answer with -- not one on port 500 itself (it
    /// is reading that port for its own answer), and not one with nothing to send.
    /// Every wait is longer than a slice, so a look that is meant cannot be missed;
    /// where none is meant, none may even start.
    #[test]
    fn only_a_floated_wait_with_a_final_message_retained_looks_at_port_500() {
        for (floated, retained) in [(false, false), (false, true), (true, false), (true, true)] {
            let f = floated_client([127, 78, 1, 4]);
            f.client.set_read_timeout(Some(Duration::from_millis(350))).unwrap();
            let (cky_i, cky_r) = ([0xAA; 8], [0xBB; 8]);
            let st = phase1_with_cookies(cky_i, cky_r);
            st.finals.retain(&message(cky_i, cky_r, exchange::AGGRESSIVE, 0), b"our final message");
            let looks = std::rc::Rc::new(std::cell::Cell::new(0u32));
            let counted = looks.clone();
            let _hook = OnPort500Look::install(move || counted.set(counted.get() + 1));

            let want = if retained { Awaiting::in_sa(&st, exchange::TRANSACTION, f.server) } else { Awaiting::new(cky_i, Some(cky_r), exchange::TRANSACTION) };
            let err = f.client.recv_matching(&want.floated(floated)).unwrap_err();
            assert!(matches!(&err, DriverError::Io(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)), "{err:?}");
            assert_eq!(looks.get() > 0, floated && retained, "floated={floated}, retained={retained}: {} looks", looks.get());
            // One look a slice, not one at every turn of the loop: 350 ms hold no
            // more than three slices of 100 ms.
            assert!(looks.get() <= 3, "floated={floated}, retained={retained}: {} looks in 350 ms", looks.get());
        }
    }

    /// A stream of datagrams for someone else on the floated socket keeps it from
    /// ever going quiet for a slice, so the look at port 500 cannot wait for
    /// quiet: a repeat of message 2 there is answered while the stream goes on,
    /// and the wait still ends at its deadline.
    #[test]
    fn a_floated_wait_still_looks_at_port_500_while_datagrams_keep_arriving_on_port_4500() {
        let f = floated_client([127, 78, 1, 5]);
        f.client.set_read_timeout(Some(Duration::from_millis(700))).unwrap();
        let (cky_i, cky_r) = ([0xAA; 8], [0xBB; 8]);
        let st = phase1_with_cookies(cky_i, cky_r);
        let repeated = message(cky_i, cky_r, exchange::AGGRESSIVE, 0);
        let mut our_final = message(cky_i, cky_r, exchange::AGGRESSIVE, 0);
        our_final.extend_from_slice(b"our final message");
        st.finals.retain(&repeated, &our_final);
        f.gateway_500.send_to(&repeated, f.port_500()).unwrap();

        let (stop, gateway_4500, to) = (std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)), f.gateway_4500.try_clone().unwrap(), f.port_4500());
        let flag = stop.clone();
        let flood = std::thread::spawn(move || {
            let mut stray = blank_header(exchange::MAIN);
            stray[..16].copy_from_slice(&[0x11; 16]);
            let stray = wrap_ike_4500(&stray);
            let end = std::time::Instant::now() + Duration::from_millis(2500);
            while !flag.load(std::sync::atomic::Ordering::Relaxed) && std::time::Instant::now() < end {
                let _ = gateway_4500.send_to(&stray, to);
            }
        });

        let started = std::time::Instant::now();
        let err = f.client.recv_matching(&Awaiting::in_sa(&st, exchange::TRANSACTION, f.server).floated(true)).unwrap_err();
        let waited = started.elapsed();
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        flood.join().unwrap();
        assert!(matches!(&err, DriverError::Io(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)), "{err:?}");
        assert!(waited < Duration::from_millis(1200), "waited {waited:?} for a 700 ms timeout");
        assert_eq!(f.received_on_4500(Duration::from_millis(200)), Some(our_final), "the retained final message, sent while the stream went on");
    }

    /// A wait on port 500 itself reads that port for the answer it is waiting
    /// for, so a look at it would take that answer and drop it as no repeat of
    /// anything. Here the answer is put on the port the moment a look starts
    /// (were one to start) and, if none does, by the gateway some time into the
    /// wait: the wait must return it either way.
    #[test]
    fn an_unfloated_wait_does_not_lose_its_answer_to_a_look_at_port_500() {
        let client = Client { transport: UdpTransport::bind("127.0.0.1:0").unwrap(), natt_transport: None, entropy: SeedEntropy::new(1) };
        client.set_read_timeout(Some(Duration::from_millis(1500))).unwrap();
        let gateway = UdpSocket::bind("127.0.0.1:0").unwrap();
        let (cky_i, cky_r) = ([0xAA; 8], [0xBB; 8]);
        let st = phase1_with_cookies(cky_i, cky_r);
        st.finals.retain(&message(cky_i, cky_r, exchange::AGGRESSIVE, 0), b"our final message");
        let answer = message(cky_i, cky_r, exchange::TRANSACTION, 12);

        let sent = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (to, from_hook, answer_hook, sent_hook) = (client.local_addr().unwrap(), gateway.try_clone().unwrap(), answer.clone(), sent.clone());
        let _hook = OnPort500Look::install(move || {
            if !sent_hook.swap(true, std::sync::atomic::Ordering::SeqCst) {
                from_hook.send_to(&answer_hook, to).unwrap();
            }
        });
        let (from_late, answer_late, sent_late) = (gateway.try_clone().unwrap(), answer.clone(), sent.clone());
        let late = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(400));
            if !sent_late.swap(true, std::sync::atomic::Ordering::SeqCst) {
                from_late.send_to(&answer_late, to).unwrap();
            }
        });

        let got = client.recv_matching(&Awaiting::in_sa(&st, exchange::TRANSACTION, gateway.local_addr().unwrap()));
        late.join().unwrap();
        assert!(matches!(&got, Ok(m) if *m == answer), "{got:?}");
    }

    /// The times at which each of the sends of one request reaches a listener that
    /// never answers, and when `send_and_await` gave up.
    fn send_times_of_an_unanswered_request(read_timeout: Duration) -> (Vec<std::time::Instant>, Duration) {
        let client = Client { transport: UdpTransport::bind("127.0.0.1:0").unwrap(), natt_transport: None, entropy: SeedEntropy::new(1) };
        client.set_read_timeout(Some(read_timeout)).unwrap();
        let listener = UdpSocket::bind("127.0.0.1:0").unwrap();
        let listener_addr = listener.local_addr().unwrap();
        listener.set_read_timeout(Some(read_timeout * 5)).unwrap();
        let recorder = std::thread::spawn(move || {
            let mut buf = [0u8; 128];
            let mut times = Vec::new();
            while listener.recv_from(&mut buf).is_ok() {
                times.push(std::time::Instant::now());
            }
            times
        });
        let started = std::time::Instant::now();
        let err = client.send_and_await(&blank_header(exchange::MAIN), listener_addr, &Awaiting::new([0xAA; 8], None, exchange::AGGRESSIVE)).unwrap_err();
        let gave_up_after = started.elapsed();
        assert!(matches!(&err, DriverError::Io(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)), "{err:?}");
        (recorder.join().unwrap(), gave_up_after)
    }

    /// RFC 2408 §5.1: "Implementations MUST NOT use a fixed timer" and successive
    /// retransmissions are "separated by increasingly longer time intervals".
    /// Every wait is longer than the one before it, and the request is given up on
    /// when the read timeout, once for the send and once for each retransmission,
    /// says so -- the time a caller was already told to wait for a dead gateway.
    #[test]
    fn send_and_await_separates_its_retransmissions_by_longer_and_longer_intervals() {
        let read_timeout = Duration::from_millis(500);
        let (times, gave_up_after) = send_times_of_an_unanswered_request(read_timeout);
        assert_eq!(times.len() as u32, Client::<SeedEntropy>::MAX_RETRANSMITS + 1);
        let gaps: Vec<Duration> = times.windows(2).map(|w| w[1] - w[0]).collect();
        assert!(gaps.windows(2).all(|g| g[1] >= g[0] + Duration::from_millis(100)), "the waits between the sends were {gaps:?}");
        let budget = read_timeout * (Client::<SeedEntropy>::MAX_RETRANSMITS + 1);
        assert!(gave_up_after >= budget - Duration::from_millis(50) && gave_up_after < budget + Duration::from_millis(600), "gave up after {gave_up_after:?}, budget {budget:?}");
    }

    /// With no reply at all, `send_and_await` must give up after
    /// `MAX_RETRANSMITS` resends (exactly `MAX_RETRANSMITS + 1` total sends)
    /// rather than retry forever, surfacing the same read-timeout error
    /// `recv_matching` alone would have.
    #[test]
    fn send_and_await_gives_up_after_max_retransmits() {
        let client = Client { transport: UdpTransport::bind("127.0.0.1:0").unwrap(), natt_transport: None, entropy: SeedEntropy::new(1) };
        client.set_read_timeout(Some(Duration::from_millis(30))).unwrap();

        let listener = UdpSocket::bind("127.0.0.1:0").unwrap();
        let listener_addr = listener.local_addr().unwrap();
        let sends_seen = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let sends_seen2 = sends_seen.clone();
        let counter = std::thread::spawn(move || {
            let mut buf = [0u8; 128];
            listener.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
            while listener.recv_from(&mut buf).is_ok() {
                sends_seen2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        });

        let cky_i = [0xAA; 8];
        let req = blank_header(exchange::MAIN);
        let err = client.send_and_await(&req, listener_addr, &Awaiting::new(cky_i, None, exchange::MAIN)).unwrap_err();
        assert!(matches!(err, DriverError::Io(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)));

        std::thread::sleep(Duration::from_millis(600));
        assert_eq!(sends_seen.load(std::sync::atomic::Ordering::SeqCst), Client::<SeedEntropy>::MAX_RETRANSMITS + 1);
        counter.join().unwrap();
    }
}
