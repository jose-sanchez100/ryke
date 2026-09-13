//! A minimal blocking IKEv1 **initiator** (client) over UDP: Aggressive Mode
//! or Main Mode (see [`InitiatorConfig::mode`]) for Phase 1 (PSK or RSA
//! signature — see [`crate::ikev1::phase1::Ikev1LocalAuth`]), an optional
//! XAUTH round (see [`crate::ikev1::xauth`]) when the gateway requires one,
//! an optional Mode-Config round (see [`crate::ikev1::cfg`],
//! `InitiatorConfig::mode_cfg`) for an assigned inner IPv4, then Quick Mode
//! (optionally with PFS, see `InitiatorConfig::pfs_group`), establishing an
//! ESP CHILD SA.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

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
use crate::ikev1::xauth;
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

/// A UDP IKEv1 initiator driven by an [`Entropy`] source.
pub struct Client<E> {
    transport: UdpTransport,
    entropy: E,
}

impl<E: Entropy> Client<E> {
    /// Bind a local socket (`"0.0.0.0:0"` for an ephemeral source port).
    pub fn bind(addr: impl ToSocketAddrs, entropy: E) -> io::Result<Self> {
        Ok(Self { transport: UdpTransport::bind(addr)?, entropy })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.transport.local_addr()
    }

    pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.transport.set_read_timeout(dur)
    }

    /// Read datagrams until one carries this session's own ISAKMP cookies
    /// (`cky_r: None` while it isn't known yet, i.e. while awaiting message
    /// 2) *and* the expected `exchange_type` -- everything else is dropped
    /// and read again, bounded by the same socket read timeout `recv_from`
    /// itself already enforces. This socket is held persistently across
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
    /// Mode message 6 lost to fragmentation (no NAT-T here, see
    /// [`crate::ikev1`]'s known gap) while the gateway's very next message,
    /// its XAUTH request (a real, correctly-cookied datagram for the same
    /// SA, just for a *different* sub-exchange -- `exchange::TRANSACTION`,
    /// message-id nonzero, not `exchange::MAIN`'s message-id 0), arrives
    /// right behind it. Without this check that XAUTH request was
    /// misidentified as message 6 and decrypted under message 6's IV
    /// instead of its own `phase2_iv`, producing the same class of
    /// "declared length exceeds available bytes" garbage cookie-filtering
    /// alone was meant to fix -- a different bogus value each retry, since
    /// each retransmission's ciphertext differs.
    fn recv_matching(&self, cky_i: [u8; 8], cky_r: Option<[u8; 8]>, exchange_type: u8) -> Result<Vec<u8>, DriverError> {
        loop {
            let (msg, from) = self.transport.recv_from()?;
            let hdr = match IsakmpHeader::parse(&msg) {
                Ok(h) => h,
                Err(_) => {
                    ike_debug!("dropping unparseable stray datagram from {from} ({} bytes)", msg.len());
                    continue;
                }
            };
            let cookies_ok = hdr.init_cookie == cky_i && cky_r.is_none_or(|r| hdr.resp_cookie == r);
            if !cookies_ok || hdr.exchange_type != exchange_type {
                ike_debug!(
                    "dropping out-of-turn datagram from {from}: cookies {:02x?}/{:02x?}, exchange={}, msg-id={:08x} (awaiting {:02x?}/{cky_r:02x?}, exchange={exchange_type})",
                    hdr.init_cookie,
                    hdr.resp_cookie,
                    hdr.exchange_type,
                    hdr.message_id,
                    cky_i,
                );
                continue;
            }
            return Ok(msg);
        }
    }

    /// Run the full handshake — Phase 1 (Aggressive or Main Mode, see
    /// [`InitiatorConfig::mode`]) then Quick Mode (msg1/msg2/msg3) — against
    /// `server`, returning the established SA.
    pub fn connect(&mut self, server: SocketAddr, cfg: &InitiatorConfig) -> Result<Established, DriverError> {
        if cfg.mode == Ikev1ExchangeMode::Aggressive && matches!(cfg.local_auth, Ikev1LocalAuth::Sig { .. }) {
            return Err(IkeError::Crypto("Aggressive Mode requires PSK auth (RSA-sig needs Main Mode)").into());
        }
        let phase1 = match cfg.mode {
            Ikev1ExchangeMode::Aggressive => {
                ike_debug!("Aggressive Mode: sending msg1 to {server}");
                let (msg1, ai) = initiate_aggressive(cfg, &mut self.entropy);
                let cky_i: [u8; 8] = msg1[..8].try_into().unwrap();
                self.transport.send_to(&msg1, server)?;
                let msg2 = self.recv_matching(cky_i, None, exchange::AGGRESSIVE)?;
                let (msg3, phase1) = ai.complete(&msg2)?;
                ike_debug!("Aggressive Mode: complete, sending msg3");
                self.transport.send_to(&msg3, server)?;

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
                self.transport.send_to(&msg1, server)?;
                let msg2 = self.recv_matching(cky_i, None, exchange::MAIN)?;
                let cky_r: [u8; 8] = msg2[8..16].try_into().unwrap();
                let (msg3, ke_sent) = sa_sent.complete_sa(&msg2, &mut self.entropy)?;
                self.transport.send_to(&msg3, server)?;
                let msg4 = self.recv_matching(cky_i, Some(cky_r), exchange::MAIN)?;
                let (msg5, id_sent) = ke_sent.complete_ke(&msg4)?;
                self.transport.send_to(&msg5, server)?;
                let msg6 = self.recv_matching(cky_i, Some(cky_r), exchange::MAIN)?;
                let msg6_len = msg6.len();
                let phase1 = id_sent.complete_id(&msg6)?;
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

        // XAUTH: the gateway (not us) sends the first message here — see
        // crate::ikev1::xauth's doc comment. Only run when the caller actually
        // has credentials to answer with; `xauth: true, xauth_creds: None`
        // (SA negotiation only, no real gateway) skips this.
        if let Some((user, password)) = &cfg.xauth_creds {
            ike_debug!("XAUTH: waiting for the gateway's request");
            let request = self.recv_matching(phase1.cky_i, Some(phase1.cky_r), exchange::TRANSACTION)?;
            let reply = xauth::build_xauth_reply(&phase1, &request, user, password)?;
            self.transport.send_to(&reply, server)?;
            let set_msg = self.recv_matching(phase1.cky_i, Some(phase1.cky_r), exchange::TRANSACTION)?;
            let (ack, ok) = xauth::build_xauth_ack(&phase1, &set_msg)?;
            self.transport.send_to(&ack, server)?;
            if !ok {
                return Err(IkeError::AuthFailed.into());
            }
        }

        // Mode-Config: request an assigned inner IPv4 (+ netmask/DNS/subnet)
        // -- see `crate::ikev1::cfg`'s doc. Some gateways reject the following
        // Quick Mode proposal outright ("peer has not completed Configuration
        // Method") if this round is skipped.
        let (mut assigned_ip4, mut netmask, mut dns, mut subnets) = (None, None, Vec::new(), Vec::new());
        if cfg.mode_cfg {
            ike_debug!("Mode-Config: requesting an assigned IPv4");
            let mut mid_b = [0u8; 4];
            self.entropy.fill(&mut mid_b);
            let msgid = u32::from_be_bytes(mid_b) | 1; // non-zero
            let (request, next_iv) = modecfg::build_cfg_request(&phase1, msgid)?;
            self.transport.send_to(&request, server)?;
            let reply = self.recv_matching(phase1.cky_i, Some(phase1.cky_r), exchange::TRANSACTION)?;
            let got = modecfg::parse_cfg_reply(&phase1, &reply, &next_iv)?;
            assigned_ip4 = got.assigned_ipv4();
            netmask = got.assigned_netmask();
            dns = got.assigned_dns();
            subnets = got.assigned_subnets();
            ike_debug!("Mode-Config: assigned {assigned_ip4:?}");
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
        let (qm1, qi) = initiate_quick_with_pfs(&phase1, &mut self.entropy, cfg.esp_cipher, ts_local, cfg.ts_remote, cfg.pfs_group)?;
        self.transport.send_to(&qm1, server)?;
        let qm2 = self.recv_matching(phase1.cky_i, Some(phase1.cky_r), exchange::QUICK)?;
        let (qm3, child) = qi.complete(&qm2)?;
        self.transport.send_to(&qm3, server)?;
        ike_debug!("Quick Mode: complete -- CHILD SA established");

        let local_addr = self.transport.local_addr_for(server)?;
        Ok(Established { phase1, child, assigned_ip4, netmask, dns, subnets, local_addr })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::SeedEntropy;
    use std::net::UdpSocket;

    /// A stray datagram carrying a *different* session's cookies (e.g. a
    /// gateway's retransmission of an earlier, abandoned connection attempt,
    /// still arriving on this long-held socket) must be silently dropped by
    /// `recv_matching`, not mistaken for the real reply -- the exact bug
    /// this method exists to fix (see its own doc comment), confirmed live
    /// against a real FortiGate before this fix landed.
    #[test]
    fn recv_matching_skips_a_stray_datagram_with_the_wrong_cookies() {
        let client = Client { transport: UdpTransport::bind("127.0.0.1:0").unwrap(), entropy: SeedEntropy::new(1) };
        let client_addr = client.local_addr().unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();

        let cky_i = [0xAA; 8];
        let cky_r = [0xBB; 8];

        // A stray message: correct wire shape, but cookies from an unrelated
        // session -- must not satisfy `recv_matching`.
        let mut stray = vec![0u8; IsakmpHeader::LEN];
        stray[..8].copy_from_slice(&[0x11; 8]);
        stray[8..16].copy_from_slice(&[0x22; 8]);
        sender.send_to(&stray, client_addr).unwrap();

        // The real message, sent right after -- must be the one returned.
        let mut real = vec![0u8; IsakmpHeader::LEN];
        real[..8].copy_from_slice(&cky_i);
        real[8..16].copy_from_slice(&cky_r);
        real[18] = exchange::MAIN;
        sender.send_to(&real, client_addr).unwrap();

        client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let got = client.recv_matching(cky_i, Some(cky_r), exchange::MAIN).unwrap();
        assert_eq!(got, real, "must skip the stray datagram and return the one with matching cookies");
    }

    /// While `cky_r` isn't known yet (awaiting message 2), any resp_cookie is
    /// accepted -- only `cky_i` (which we chose ourselves and put in our own
    /// message 1) can be checked at that point.
    #[test]
    fn recv_matching_accepts_any_resp_cookie_when_not_yet_known() {
        let client = Client { transport: UdpTransport::bind("127.0.0.1:0").unwrap(), entropy: SeedEntropy::new(1) };
        let client_addr = client.local_addr().unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();

        let cky_i = [0xAA; 8];
        let mut real = vec![0u8; IsakmpHeader::LEN];
        real[..8].copy_from_slice(&cky_i);
        real[8..16].copy_from_slice(&[0xCC; 8]); // responder's freshly-chosen cookie
        real[18] = exchange::MAIN;
        sender.send_to(&real, client_addr).unwrap();

        client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let got = client.recv_matching(cky_i, None, exchange::MAIN).unwrap();
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
        let client = Client { transport: UdpTransport::bind("127.0.0.1:0").unwrap(), entropy: SeedEntropy::new(1) };
        let client_addr = client.local_addr().unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();

        let cky_i = [0xAA; 8];
        let cky_r = [0xBB; 8];

        // A same-SA, same-cookies datagram, but for the Transaction (XAUTH)
        // exchange, not the Main Mode message 6 this call awaits.
        let mut wrong_exchange = vec![0u8; IsakmpHeader::LEN];
        wrong_exchange[..8].copy_from_slice(&cky_i);
        wrong_exchange[8..16].copy_from_slice(&cky_r);
        wrong_exchange[18] = exchange::TRANSACTION;
        sender.send_to(&wrong_exchange, client_addr).unwrap();

        let mut real = vec![0u8; IsakmpHeader::LEN];
        real[..8].copy_from_slice(&cky_i);
        real[8..16].copy_from_slice(&cky_r);
        real[18] = exchange::MAIN;
        sender.send_to(&real, client_addr).unwrap();

        client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let got = client.recv_matching(cky_i, Some(cky_r), exchange::MAIN).unwrap();
        assert_eq!(got, real, "must skip the Transaction-exchange datagram and return the Main-Mode one");
    }
}
