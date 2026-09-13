//! A minimal blocking IKEv1 **initiator** (client) over UDP: Aggressive Mode
//! or Main Mode (see [`InitiatorConfig::mode`]) for Phase 1 (PSK), an
//! optional Mode-Config round (see [`crate::ikev1::cfg`],
//! `InitiatorConfig::mode_cfg`) for an assigned inner IPv4, then Quick Mode
//! (optionally with PFS, see `InitiatorConfig::pfs_group`), establishing an
//! ESP CHILD SA. No XAUTH yet — suitable for gateways configured for plain
//! PSK (including ryke's own responder).

use std::io;
use std::net::{Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

use crate::debug::ike_debug;
use crate::entropy::Entropy;
use crate::esp::ChildSa;
use crate::ikev1::cfg as modecfg;
use crate::ikev1::phase1::{initiate_aggressive, initiate_main, Ikev1ExchangeMode, InitiatorConfig, Phase1State};
use crate::ikev1::quick::initiate_quick_with_pfs;
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

    /// Run the full handshake — Phase 1 (Aggressive or Main Mode, see
    /// [`InitiatorConfig::mode`]) then Quick Mode (msg1/msg2/msg3) — against
    /// `server`, returning the established SA.
    pub fn connect(&mut self, server: SocketAddr, cfg: &InitiatorConfig) -> Result<Established, DriverError> {
        let phase1 = match cfg.mode {
            Ikev1ExchangeMode::Aggressive => {
                ike_debug!("Aggressive Mode: sending msg1 to {server}");
                let (msg1, ai) = initiate_aggressive(cfg, &mut self.entropy);
                self.transport.send_to(&msg1, server)?;
                let (msg2, _from) = self.transport.recv_from()?;
                let (msg3, phase1) = ai.complete(&msg2)?;
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
                self.transport.send_to(&msg1, server)?;
                let (msg2, _from) = self.transport.recv_from()?;
                let (msg3, ke_sent) = sa_sent.complete_sa(&msg2, &mut self.entropy)?;
                self.transport.send_to(&msg3, server)?;
                let (msg4, _from) = self.transport.recv_from()?;
                let (msg5, id_sent) = ke_sent.complete_ke(&msg4)?;
                self.transport.send_to(&msg5, server)?;
                let (msg6, _from) = self.transport.recv_from()?;
                let phase1 = id_sent.complete_id(&msg6)?;
                // Unlike Aggressive Mode, message 6 is a real reply the
                // initiator already waited for above, so Phase 1 is known
                // complete on both sides here -- no artificial pause needed
                // before Quick Mode.
                ike_debug!("Main Mode: complete");
                phase1
            }
        };

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
            let (reply, _from) = self.transport.recv_from()?;
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
        let (qm2, _from) = self.transport.recv_from()?;
        let (qm3, child) = qi.complete(&qm2)?;
        self.transport.send_to(&qm3, server)?;
        ike_debug!("Quick Mode: complete -- CHILD SA established");

        let local_addr = self.transport.local_addr_for(server)?;
        Ok(Established { phase1, child, assigned_ip4, netmask, dns, subnets, local_addr })
    }
}
