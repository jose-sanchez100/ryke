//! A high-level IKEv2 **initiator** session: `IKE_SA_INIT` (NAT-T aware) +
//! `IKE_AUTH` (direct PSK/cert, or EAP-MSCHAPv2) + CHILD SA key derivation,
//! producing everything a kernel XFRM data plane needs to install the SA/policy
//! itself. Pure orchestration over the existing exchange/ike_auth/eap_auth
//! building blocks — no new protocol or crypto code — lifted from (and
//! replacing the hand-rolled loop in) `examples/ike_client_eap_fortigate.rs`,
//! which proved this exact sequence end-to-end against a real FortiGate.
//!
//! Deliberately does **not** use [`crate::esp::ChildSa`]/[`crate::esp::EspSa`]
//! for the derived keys — those exist for the userspace-ESP test/interop path.
//! A consumer handing packets to the kernel via XFRM needs the raw key
//! material directly, which is what [`ConnectedTunnel`] carries.
//!
//! Both the IKE control channel (`SK{}` payload) and the CHILD SA / ESP data
//! plane are now cipher-agile: [`ConnectedTunnel`]'s `key_out`/`key_in` are
//! tagged [`ChildKeyMaterial`] bundles instead of a fixed 36-byte AES-256-GCM
//! array, resolved from whatever the peer actually named in its `SAr2`/final
//! EAP message (via [`crate::ikev2::negotiate::ChosenEspSuite`]). What cipher
//! the peer *can* choose is still up to the caller-supplied `esp_offer`
//! (a proposal template, e.g. [`crate::ikev2::ike_auth::esp_offer`] for the
//! default AES-GCM-256 one).

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::mpsc;
use std::time::Duration;

use crate::crypto::{derive_child_keys, DhGroup, IntegAlgorithm};
use crate::debug::ike_debug;
use crate::entropy::{Entropy, OsEntropy};
use crate::error::IkeError;
use crate::ikev2::eap_auth::{EapEvent, EapInitiator, ServerVerify};
use crate::ikev2::exchange::{
    default_offer, initiator_complete_natt, initiator_request_natt, CompletedSaInit, LocalSecret,
    NatStatus,
};
use crate::ikev2::fragment;
use crate::ikev2::ike_auth::{self, AuthConfig};
use crate::ikev2::informational::{build_informational, dpd_request, open_informational};
use crate::ikev2::message::{payloads, IkeHeader, PayloadType};
use crate::ikev1::quick::{ChildKeyMaterial, RekeyedChild};
use crate::ikev2::natt::{unwrap_ike_4500, wrap_ike_4500};
use crate::ikev2::negotiate::ChosenEspSuite;
use crate::ikev2::payload::{
    notify_type, notify_type_name, protocol_id, Configuration, Delete, Identification, SecurityAssociation, TrafficSelector,
    TrafficSelectors,
};
use crate::ikev2::rekey::{self, dh_transform_id, PfsKeyExchange};
use crate::ikev2::sk::{self, open_encrypted, SkCipher};
use crate::role::Role;
use crate::transport::{DriverError, MAX_DATAGRAM};

const IKE_PORT: u16 = 500;
const NONCE_LEN: usize = 32;

/// EAP-MSCHAPv2 credentials for [`Ikev2Session::connect_eap`].
pub struct EapCreds {
    pub user: Vec<u8>,
    pub password: String,
}

/// Everything a kernel XFRM data plane needs, derived from a completed IKEv2
/// handshake — install two states under `key_out`/`key_in`'s cipher (`key_out`
/// on the state keyed by `peer_spi`, `key_in` on the one keyed by
/// `local_spi`) plus matching tunnel-mode policies.
pub struct ConnectedTunnel {
    /// The SPI we chose for our own inbound CHILD SA.
    pub local_spi: u32,
    /// The peer's CHILD SA SPI — what it expects stamped on packets we send it.
    pub peer_spi: u32,
    /// Egress SA key material, keyed by `peer_spi` on the wire.
    pub key_out: ChildKeyMaterial,
    /// Ingress SA key material, keyed by `local_spi` on the wire.
    pub key_in: ChildKeyMaterial,
    pub assigned_ip4: Option<Ipv4Addr>,
    pub dns: Vec<Ipv4Addr>,
    /// Every `INTERNAL_IP6_DNS` attribute CFG_REPLY carried, if any --
    /// requested alongside the IPv4 attributes ([`Configuration::request_ipv4`]).
    /// Still not actually reachable over the tunnel on Windows (which
    /// unconditionally blackholes all IPv6 -- see
    /// `platform::windows::xfrm::set_ipv6_blackhole_table_220`); on Linux,
    /// only reachable if the resolver address itself falls inside
    /// the granted IPv6 ranges of [`LivenessSession::create_child_ipv6`]. Kept here regardless so a caller can at
    /// least log/surface what the gateway offered, not silently drop it.
    pub dns6: Vec<Ipv6Addr>,
    /// The `INTERNAL_IP6_ADDRESS` CFG_REPLY attribute, if the responder
    /// sent one -- (address, prefix length), the prefix length travelling
    /// with the attribute itself (see [`Configuration::assigned_ipv6`]'s
    /// doc). `None` on a v4-only gateway, or when CFG wasn't requested.
    pub assigned_ip6: Option<(Ipv6Addr, u8)>,
    /// Every non-`/0` `INTERNAL_IP6_SUBNET` CFG_REPLY carried -- the gateway's
    /// explicit split-tunnel instruction for IPv6. Empty when it sent none
    /// (which also covers an IPv6-unconfigured FortiGate's junk `::/0`
    /// entry, dropped by [`Configuration::assigned_ipv6_subnets`]). This is
    /// only what CFG said: the `IKE_AUTH` CHILD SA is IPv4-only, and whether
    /// IPv6 is carried at all is decided by the separate IPv6 CHILD SA
    /// [`LivenessSession::create_child_ipv6`] negotiates afterwards, whose
    /// result carries the final ranges to route.
    pub cfg_subnets6: Vec<(Ipv6Addr, u8)>,
    /// The *first* `INTERNAL_IP4_SUBNET` attribute from CFG_REPLY, if the
    /// responder sent at least one -- kept for backward compat / diagnostics
    /// only. A responder that hands back several (one per split-tunnel
    /// range, e.g. FortiGate) has the rest silently dropped here -- always
    /// prefer [`Self::granted_subnets`], which carries all of them.
    pub subnet: Option<(Ipv4Addr, u8)>,
    /// What to actually route through the tunnel: every `INTERNAL_IP4_SUBNET`
    /// attribute CFG_REPLY carried, when the responder sent at least one --
    /// that's an explicit routing instruction from the gateway and takes
    /// precedence over TSr outright -- else every CIDR-representable range
    /// from the responder's granted `TSr`, used as a fallback for gateways
    /// that never send CFG_REPLY subnet info at all. `0.0.0.0/0` here means a
    /// genuine full-tunnel grant. Empty only if neither source yielded
    /// anything -- a caller should treat that as "route nothing beyond the
    /// VIP itself", not synthesize a full-tunnel guess.
    pub granted_subnets: Vec<(Ipv4Addr, u8)>,
    /// Our address (as the peer reaches us), post-NAT-T-float.
    pub local_addr: SocketAddr,
    /// The peer's address, post-NAT-T-float (UDP 4500 if either end is NAT'd).
    pub peer_addr: SocketAddr,
    pub nat: NatStatus,
    /// Handle for checking the tunnel is still up after the handshake --
    /// see [`LivenessSession::probe`]. Holds the same IKE control socket
    /// used during the handshake (kept open rather than dropped) precisely
    /// so this works: a kernel XFRM data plane gives no signal at all when
    /// the peer tears its side down, so this is the only way to find out
    /// without waiting for a hard SA lifetime expiry.
    pub liveness: LivenessSession,
}

/// The SPI pair of one CHILD SA, tracked per SA so a rekey's `REKEY_SA`
/// notify and the post-rekey Delete reference the right values.
#[derive(Clone, Copy)]
struct ChildSpis {
    local: u32,
    peer: u32,
}

/// What [`LivenessSession::create_child_ipv6`] negotiated: the new SA's SPIs
/// and keys (same shape a rekey returns), plus what the gateway granted for it.
pub struct Ipv6Child {
    pub child: RekeyedChild,
    /// The IPv6 ranges to route into this CHILD SA: the connect-time
    /// `INTERNAL_IP6_SUBNET` split ranges if the gateway sent any (an explicit
    /// routing instruction, same precedence as IPv4's `granted_subnets`), else
    /// every CIDR-representable range of the `TSr` it granted -- `::/0` being
    /// a full IPv6 tunnel. Never empty: a reply granting no IPv6 selector at
    /// all is an error, not an `Ipv6Child`.
    pub granted_subnets6: Vec<(Ipv6Addr, u8)>,
}

/// Post-handshake handle for RFC 7296 §2.4 Dead Peer Detection, and (see
/// [`Self::rekey_child`]) for the only point an IKEv2 tunnel's CHILD SA can
/// ever apply PFS: the initial CHILD SA created at `IKE_AUTH` structurally
/// has no KE payload slot at all (RFC 7296), so PFS can only take effect at a
/// later `CREATE_CHILD_SA` rekey. Reuses the already-open IKE control socket
/// and completed SA rather than opening a new one, since both DPD and rekey
/// must come from the same (address, port, SPI pair) the peer already
/// associates with this IKE SA.
pub struct LivenessSession {
    sock: UdpSocket,
    sa: CompletedSaInit,
    dest: SocketAddr,
    float: bool,
    next_message_id: u32,
    /// The ESP cipher already running on this tunnel's CHILD SA -- a rekey
    /// must preserve it rather than silently falling back to a fixed
    /// default (see `ike_auth::esp_offer_for_cipher`'s own doc).
    cipher: SkCipher,
    /// PFS DH group to use at CHILD SA rekey time, read off the DH transform
    /// (if any) on the `esp_offer` this tunnel was connected with. `None`
    /// when the profile configured no PFS group -- [`Self::rekey_child`]
    /// then rekeys without PFS (still useful for key freshness, just not
    /// this project's ask).
    pfs_group: Option<DhGroup>,
    /// The CHILD SA's current SPIs, updated after every successful rekey so
    /// the next one's `REKEY_SA` notify references the right value.
    child_local_spi: u32,
    child_peer_spi: u32,
    /// Windows only, unused (`None`) everywhere else -- see
    /// `platform::windows::xfrm`'s module doc. On Linux the kernel's
    /// `UDP_ENCAP` sockopt steals ESP-shaped datagrams away from this
    /// session's own socket before `recv_and_classify` ever sees them, so it
    /// can safely call `self.sock.recv` directly: only IKE ever arrives
    /// there. Windows has no such trick, so a single background thread owns
    /// the real `recv_from` loop instead (demuxing IKE from raw
    /// ESP-in-UDP itself) and hands this session its already-classified IKE
    /// datagrams through a channel via [`Self::install_external_receiver`]
    /// -- two independent readers on `try_clone()`'d handles of the same
    /// socket would otherwise race for each other's traffic. `None` (the
    /// default produced by every existing constructor) preserves today's
    /// direct-socket-read behavior unchanged.
    external_rx: Option<mpsc::Receiver<Vec<u8>>>,
    /// The separate IPv6 CHILD SA, once [`Self::create_child_ipv6`] has
    /// negotiated one -- `None` until then (and forever on a gateway that
    /// doesn't do IPv6). It has its own SPIs and keys, distinct from
    /// `child_local_spi`/`child_peer_spi` above, and is rekeyed on its own
    /// ([`Self::rekey_child_ipv6`]).
    child6: Option<ChildSpis>,
    /// The connect-time `INTERNAL_IP6_SUBNET` split ranges
    /// ([`ConnectedTunnel::cfg_subnets6`]), kept to combine with the IPv6
    /// CHILD SA's granted `TSr` when it is created.
    cfg_subnets6: Vec<(Ipv6Addr, u8)>,
}

/// Result of one [`LivenessSession::probe`] call.
#[derive(Debug, PartialEq, Eq)]
pub enum Liveness {
    /// The peer answered our DPD probe -- still up.
    Alive,
    /// An unsolicited INFORMATIONAL carrying a Delete payload for the whole
    /// IKE SA -- or for the CHILD SA this session currently relies on --
    /// arrived from the peer: it tore the tunnel down on its own initiative
    /// (e.g. an admin disconnected it on the gateway). Already ack'd on the
    /// peer's behalf before returning. A CHILD SA Delete naming some *other*
    /// SPI is not this -- see [`LivenessSession::recv_and_classify`]'s doc:
    /// that's routine post-rekey cleanup of the SA [`LivenessSession::rekey_child`]
    /// just superseded, and does not end the tunnel.
    PeerTornDown,
    /// No reply within the timeout. Could be transient packet loss rather
    /// than a dead peer -- callers should require a few consecutive misses
    /// before concluding the tunnel is actually down, same as any DPD
    /// implementation.
    NoReply,
}

impl LivenessSession {
    /// Allocate the next request Message ID -- factored out of `probe` and
    /// `delete_child_sa` (both used to inline `let mid = self.next_message_id;
    /// self.next_message_id += 1;`) since [`Self::send_and_await`] now needs
    /// the id fixed once, before entering its own retry loop, rather than
    /// re-derived per attempt.
    fn alloc_message_id(&mut self) -> u32 {
        let mid = self.next_message_id;
        self.next_message_id += 1;
        mid
    }

    /// Send `wire` (already built for Message ID `expected_mid`) and wait up
    /// to `timeout` for its response via [`Self::recv_and_classify`],
    /// retransmitting the identical bytes up to a few times on
    /// [`Liveness::NoReply`] (RFC 7296 §2.1) before giving up -- a single
    /// dropped datagram in either direction shouldn't read as a dead peer or
    /// a torn-down tunnel. Each retry gets its own full `timeout` window, not
    /// a shrinking remainder.
    fn send_and_await(&mut self, wire: &[u8], expected_mid: u32, timeout: Duration) -> Result<Liveness, DriverError> {
        const ATTEMPTS: u32 = 3;
        let mut last = Liveness::NoReply;
        for attempt in 0..ATTEMPTS {
            if attempt > 0 {
                ike_debug!("INFORMATIONAL: retransmitting to {} (attempt {}/{ATTEMPTS})", self.dest, attempt + 1);
            }
            crate::debug::dump(">>>", self.dest, wire);
            self.sock.send_to(wire, self.dest)?;
            last = self.recv_and_classify(timeout, Some(expected_mid))?;
            if last != Liveness::NoReply {
                return Ok(last);
            }
        }
        Ok(last)
    }

    /// Send an empty INFORMATIONAL request (RFC 7296 §2.4: a live peer must
    /// answer one, also empty) and wait up to `timeout` for the reply,
    /// retransmitting a few times (see [`Self::send_and_await`]) before
    /// concluding [`Liveness::NoReply`].
    pub fn probe(&mut self, timeout: Duration) -> Result<Liveness, DriverError> {
        let mid = self.alloc_message_id();

        let mut iv = [0u8; 8];
        OsEntropy::new()?.fill(&mut iv);
        let req = dpd_request(&self.sa, mid, &iv)?;
        let wire = wrap(&req, self.float);
        self.send_and_await(&wire, mid, timeout)
    }

    /// Cheap, side-effect-free (no outgoing packet) check for whether the
    /// peer has said anything unprompted since the last check -- typically a
    /// Delete. Safe to call on every routine status poll instead of
    /// `probe`'s full round trip (reserved for a periodic active DPD check,
    /// e.g. every ~15s): a UDP datagram the peer already sent sits in the
    /// kernel's receive buffer until read regardless of how long ago it
    /// arrived, so even a short `timeout` here reliably catches anything
    /// already pending -- unlike `probe`, it does not need to "wait long
    /// enough" for a reply that was never asked for. A plain timeout here
    /// (nothing pending) is [`Liveness::Alive`], not [`Liveness::NoReply`]:
    /// silence is completely normal when nothing was just sent.
    pub fn peek(&mut self, timeout: Duration) -> Result<Liveness, DriverError> {
        self.recv_and_classify(timeout, None)
    }

    /// Shared receive loop for `probe`/`peek`: reads until `timeout`
    /// elapses, classifying whatever arrives. A request arriving from the
    /// peer instead of our own ack (typically carrying a Delete payload,
    /// since a peer tearing the SA down sends one unprompted) is itself
    /// ack'd -- a reply is owed per RFC 7296 regardless of what it turns out
    /// to mean; a benign unsolicited message (e.g. the peer running its own
    /// DPD probe against us) is otherwise ignored, continuing to wait out
    /// the remaining timeout. `expected_mid`, when set (from `probe`), is
    /// the request id whose response counts as our own [`Liveness::Alive`]
    /// confirmation -- a response with any other id is a stale/unrelated ack
    /// and is ignored; `peek` passes `None` since it never sent anything, so
    /// any response it happens to see is necessarily stale.
    ///
    /// A Delete payload is only [`Liveness::PeerTornDown`] when it actually
    /// ends this tunnel: `protocol_id::IKE` (the whole IKE SA, and thereby
    /// every CHILD SA under it, RFC 7296 §1.4.1) always qualifies; a
    /// `protocol_id::ESP` Delete only qualifies when it names `child_peer_spi`
    /// -- the CHILD SA this session is currently relying on. Confirmed live
    /// against a real FortiGate: after [`Self::rekey_child`] installs a fresh
    /// CHILD SA, the gateway deletes the *old*, now-superseded one and
    /// notifies this side of it via exactly this kind of unsolicited Delete
    /// -- treating every Delete as a teardown (the previous behavior) tore
    /// this whole tunnel down on its own successful rekey, leaving the new
    /// CHILD SA the gateway had just finished installing orphaned. A Delete
    /// naming any other SPI (or an unparseable one) is likewise not a
    /// teardown -- same reasoning, just for whichever earlier generation it
    /// happens to reference -- and is silently ignored, continuing to wait
    /// out the timeout, same as any other benign unsolicited message.
    /// Gracefully tear down the IKE SA before dropping the socket: sends a
    /// Delete payload for the whole IKE SA (RFC 7296 §1.4.1 — this implicitly
    /// deletes every CHILD SA under it too, no separate ESP Delete needed).
    /// Without this, disconnecting only removed the local kernel XFRM state;
    /// the gateway never heard about it and kept its side of the IKE/CHILD
    /// SAs around until their own lifetime/DPD eventually expired them.
    /// Best-effort: the local teardown that follows a call to this doesn't
    /// depend on the peer ever seeing this message, so a missing ack (or any
    /// I/O error past the initial send) is not surfaced as a hard failure.
    pub fn close(&mut self) -> Result<(), DriverError> {
        let mid = self.alloc_message_id();
        let mut iv = [0u8; 8];
        OsEntropy::new()?.fill(&mut iv);
        let del = Delete::ike_sa();
        let req = build_informational(&self.sa, mid, false, &[(PayloadType::Delete, del.to_bytes())], &iv)?;
        ike_debug!("INFORMATIONAL: sending IKE_SA Delete to {} (graceful disconnect)", self.dest);
        let wire = wrap(&req, self.float);
        // Best-effort ack wait -- RFC 7296 says the requester may consider
        // the SA closed immediately, it doesn't need to wait for this.
        let _ = self.send_and_await(&wire, mid, Duration::from_millis(500));
        Ok(())
    }

    /// Whether this tunnel was connected with a PFS group configured (a DH
    /// transform present on the `esp_offer` passed to `connect_direct`/
    /// `connect_eap`) -- a caller deciding whether an automatic periodic
    /// rekey is worth running at all can check this first, since without a
    /// configured group [`Self::rekey_child`] still works but never actually
    /// achieves PFS (RFC 7296 §2.8: a rekey with no KE payload just refreshes
    /// keys from fresh nonces, no forward secrecy beyond `SK_d` itself).
    pub fn pfs_configured(&self) -> bool {
        self.pfs_group.is_some()
    }

    /// Windows only -- see [`Self`]'s `external_rx` doc. Redirects every
    /// future [`Self::probe`]/[`Self::peek`] read from this session's own
    /// socket to `rx` instead: the caller is expected to already own a
    /// background thread that is the socket's sole reader, demuxing IKE
    /// datagrams (which it forwards here, whole and still wrapped, exactly
    /// as `recv_and_classify` would have read them itself) from raw
    /// ESP-in-UDP (which it handles on its own). Sending (DPD requests,
    /// acks) still goes straight out `self.sock` unaffected -- only the read
    /// side needs arbitration.
    pub fn install_external_receiver(&mut self, rx: mpsc::Receiver<Vec<u8>>) {
        self.external_rx = Some(rx);
    }

    /// Initiate a `CREATE_CHILD_SA` rekey (RFC 7296 §2.8) of this tunnel's
    /// CHILD SA, applying PFS when this session was configured with a group
    /// (see [`Self::pfs_configured`]). This is the *only* point in an IKEv2
    /// tunnel's life PFS can ever actually take effect: the initial CHILD SA
    /// created at `IKE_AUTH` structurally has no KE payload slot at all (RFC
    /// 7296), unlike IKEv1 Quick Mode which negotiates it on the very first
    /// exchange. Preserves the tunnel's already-negotiated ESP cipher (see
    /// `ike_auth::esp_offer_for_cipher`'s own doc) -- a rekey only ever adds
    /// PFS on top of what's running, never silently changes algorithm.
    pub fn rekey_child(&mut self, timeout: Duration) -> Result<RekeyedChild, DriverError> {
        let old = ChildSpis { local: self.child_local_spi, peer: self.child_peer_spi };
        let ts = TrafficSelectors { selectors: vec![TrafficSelector::ipv4_any()] };
        let (rekeyed, _tsr) = self.child_exchange(Some(old), &ts, "rekey", timeout)?;
        self.child_local_spi = rekeyed.local_spi;
        self.child_peer_spi = rekeyed.peer_spi;
        Ok(rekeyed)
    }

    /// Negotiate the tunnel's IPv6 CHILD SA (`CREATE_CHILD_SA`, RFC 7296
    /// §1.3.1) next to the IPv4 one `IKE_AUTH` created, proposing `::/0` as
    /// both traffic selectors. IPv6 needs its own CHILD SA rather than a
    /// second selector in the `IKE_AUTH` offer because gateways like FortiGate
    /// keep IPv4 and IPv6 as separate Phase 2 selectors and grant one address
    /// family per CHILD SA. PFS is applied exactly as [`Self::rekey_child`]
    /// applies it (a Phase 2 with PFS enabled rejects a CHILD SA without a KE
    /// payload).
    ///
    /// A gateway with no IPv6 selector answers with an error notify
    /// (`NO_PROPOSAL_CHOSEN`/`TS_UNACCEPTABLE`, surfaced as
    /// [`IkeError::PeerRejected`]) and the tunnel carries on IPv4-only, so a
    /// caller should treat an `Err` here as "no IPv6", not as a failed
    /// connection. Errors if a reply grants no IPv6 selector at all (after
    /// deleting the CHILD SA it just created), and if one already exists.
    pub fn create_child_ipv6(&mut self, timeout: Duration) -> Result<Ipv6Child, DriverError> {
        if self.child6.is_some() {
            return Err(IkeError::Crypto("an IPv6 CHILD SA already exists on this tunnel").into());
        }
        let (child, tsr) = self.child_exchange(None, &TrafficSelectors::ipv6_full_tunnel(), "new IPv6 CHILD SA", timeout)?;
        let granted_subnets6 = granted_subnets_v6(tsr.as_ref(), &self.cfg_subnets6);
        // The CFG ranges alone don't prove the gateway granted this SA any
        // IPv6: it has to have granted an IPv6 selector too.
        let granted_ipv6_ts = tsr.as_ref().is_some_and(|ts| ts.selectors.iter().any(|s| s.to_ipv6_cidr().is_some()));
        if granted_subnets6.is_empty() || !granted_ipv6_ts {
            ike_debug!("CREATE_CHILD_SA (new IPv6 CHILD SA): reply granted no IPv6 traffic selector (TSr={tsr:?}) -- deleting it");
            if let Err(e) = self.delete_child_sa(child.local_spi) {
                ike_debug!("CREATE_CHILD_SA (new IPv6 CHILD SA): failed to delete the unwanted CHILD SA: {e}");
            }
            return Err(IkeError::PeerRejected {
                notify_type: notify_type::TS_UNACCEPTABLE,
                name: notify_type_name(notify_type::TS_UNACCEPTABLE),
            }
            .into());
        }
        ike_debug!("CREATE_CHILD_SA (new IPv6 CHILD SA): granted TSr={tsr:?} -> routing {granted_subnets6:?}");
        self.child6 = Some(ChildSpis { local: child.local_spi, peer: child.peer_spi });
        Ok(Ipv6Child { child, granted_subnets6 })
    }

    /// Whether [`Self::create_child_ipv6`] has negotiated an IPv6 CHILD SA
    /// that [`Self::rekey_child_ipv6`] can rekey.
    pub fn has_ipv6_child(&self) -> bool {
        self.child6.is_some()
    }

    /// Rekey the IPv6 CHILD SA -- [`Self::rekey_child`]'s counterpart for the
    /// SA [`Self::create_child_ipv6`] made, with its own SPIs, keys and `REKEY_SA`.
    /// Errors if there is no IPv6 CHILD SA.
    pub fn rekey_child_ipv6(&mut self, timeout: Duration) -> Result<RekeyedChild, DriverError> {
        let old = self.child6.ok_or(IkeError::Crypto("no IPv6 CHILD SA to rekey"))?;
        let (rekeyed, _tsr) = self.child_exchange(Some(old), &TrafficSelectors::ipv6_full_tunnel(), "rekey IPv6", timeout)?;
        self.child6 = Some(ChildSpis { local: rekeyed.local_spi, peer: rekeyed.peer_spi });
        Ok(rekeyed)
    }

    /// One `CREATE_CHILD_SA` exchange creating a CHILD SA proposing `ts` as
    /// both TSi and TSr: a rekey of `replaces` when given (which also
    /// deletes the SA it superseded), a brand-new CHILD SA otherwise. Returns
    /// the new SA and the `TSr` the gateway granted. `what` only labels the
    /// debug output. Doesn't update any of `self`'s recorded SPIs -- the
    /// public callers own which SA that is.
    fn child_exchange(
        &mut self,
        replaces: Option<ChildSpis>,
        ts: &TrafficSelectors,
        what: &str,
        timeout: Duration,
    ) -> Result<(RekeyedChild, Option<TrafficSelectors>), DriverError> {
        let mut entropy = OsEntropy::new()?;
        let mut ni = vec![0u8; NONCE_LEN];
        entropy.fill(&mut ni);
        let new_local_spi = loop {
            let s = entropy.next_u64() as u32;
            if s != 0 {
                break s;
            }
        };
        let dh_private = self.pfs_group.map(|_| {
            let mut p = [0u8; 32];
            entropy.fill(&mut p);
            p
        });
        let pfs: Option<PfsKeyExchange> =
            self.pfs_group.zip(dh_private.as_ref()).map(|(group, private)| (group, private.as_slice()));

        let mid = self.next_message_id;
        self.next_message_id += 1;
        let mut iv = [0u8; 8];
        entropy.fill(&mut iv);
        ike_debug!(
            "CREATE_CHILD_SA ({what}): initiating{} -- old_spi_out={:?}, new_local_spi={new_local_spi:08x}",
            if pfs.is_some() { " with PFS" } else { "" }, replaces.map(|c| format!("{:08x}", c.peer))
        );
        let req = rekey::build_child_request(
            &self.sa,
            mid,
            replaces.map(|c| c.peer),
            new_local_spi,
            &ni,
            self.cipher,
            pfs,
            ts,
            &iv,
        )?;
        self.sock.set_read_timeout(Some(timeout))?;
        let wire = wrap(&req, self.float);
        crate::debug::dump(">>>", self.dest, &wire);
        self.sock.send_to(&wire, self.dest)?;
        let mut buf = [0u8; 4096];
        let n = self.recv_datagram(&mut buf, timeout)?;
        crate::debug::dump("<<<", self.dest, &buf[..n]);
        let response = unwrap(&buf[..n], self.float)?;
        let (child, tsr) = rekey::initiator_complete_child(
            &self.sa,
            &ni,
            new_local_spi,
            self.cipher,
            dh_private.as_ref().map(|p| p.as_slice()),
            &response,
        )?;
        ike_debug!(
            "CREATE_CHILD_SA ({what}): complete -- new spi_in={:08x} spi_out={:08x}",
            child.inbound.spi(), child.outbound.spi()
        );
        // RFC 7296 §2.8's own worked example ends a rekey with the initiator
        // explicitly deleting the SA it just replaced -- without this, a real
        // gateway (confirmed live against a FortiGate) has no way to know the
        // old CHILD SA is no longer wanted and keeps it (and its kernel
        // state) around until its own lifetime eventually expires it, which
        // with a short-lived P2 profile means old, unused SAs pile up.
        // Best-effort: the new CHILD SA above is already valid and in use
        // regardless of whether the peer sees or acks this.
        if let Some(old) = replaces {
            if let Err(e) = self.delete_child_sa(old.local) {
                ike_debug!(
                    "CREATE_CHILD_SA ({what}): failed to send Delete for superseded CHILD SA spi_in={:08x} (new CHILD SA unaffected): {e}",
                    old.local
                );
            }
        }
        let key_out = ChildKeyMaterial {
            cipher: child.outbound.cipher(),
            enc: child.outbound.enc_material(),
            integ: child.outbound.integ_key().to_vec(),
        };
        let key_in = ChildKeyMaterial {
            cipher: child.inbound.cipher(),
            enc: child.inbound.enc_material(),
            integ: child.inbound.integ_key().to_vec(),
        };
        Ok((RekeyedChild { local_spi: child.inbound.spi(), peer_spi: child.outbound.spi(), key_out, key_in }, tsr))
    }

    /// The next IKE datagram, waiting at most `timeout`: from `external_rx`
    /// when one is installed (see its doc -- the socket then has another
    /// reader and would never show it to us), straight off the socket
    /// otherwise. Timeouts surface as [`io::ErrorKind::TimedOut`] in both
    /// cases. The socket's own read timeout is the caller's to set beforehand.
    fn recv_datagram(&self, buf: &mut [u8], timeout: Duration) -> io::Result<usize> {
        match &self.external_rx {
            Some(rx) => match rx.recv_timeout(timeout) {
                Ok(datagram) => {
                    let n = datagram.len().min(buf.len());
                    buf[..n].copy_from_slice(&datagram[..n]);
                    Ok(n)
                }
                Err(mpsc::RecvTimeoutError::Timeout) => Err(io::ErrorKind::TimedOut.into()),
                Err(mpsc::RecvTimeoutError::Disconnected) => Err(io::ErrorKind::BrokenPipe.into()),
            },
            None => self.sock.recv(buf),
        }
    }

    /// Send an INFORMATIONAL Delete (RFC 7296 §1.4.1/§3.10) for a single ESP
    /// CHILD SA, and best-effort wait for the ack. `local_spi` is *our own*
    /// inbound SPI for that SA -- per RFC 7296 §3.10, a Delete names the
    /// SPI the sender itself expects in inbound packets, i.e. the value the
    /// peer would use as the destination sending ESP *to* us, not the SPI
    /// we use sending to them (that's the peer's own value to report, on
    /// their own Delete, not ours). Used by [`Self::rekey_child`] to
    /// explicitly retire the CHILD SA a rekey just replaced -- see that
    /// call site's doc for why this exists.
    fn delete_child_sa(&mut self, local_spi: u32) -> Result<(), DriverError> {
        let mid = self.alloc_message_id();
        let mut iv = [0u8; 8];
        OsEntropy::new()?.fill(&mut iv);
        let del = Delete::esp(vec![local_spi]);
        let req = build_informational(&self.sa, mid, false, &[(PayloadType::Delete, del.to_bytes())], &iv)?;
        ike_debug!("INFORMATIONAL: sending ESP Delete for superseded CHILD SA spi_in={local_spi:08x} to {}", self.dest);
        let wire = wrap(&req, self.float);
        // Best-effort ack wait, same reasoning as `close()`: the peer may
        // consider the SA gone immediately either way.
        let _ = self.send_and_await(&wire, mid, Duration::from_millis(500));
        Ok(())
    }

    fn recv_and_classify(&mut self, timeout: Duration, expected_mid: Option<u32>) -> Result<Liveness, DriverError> {
        self.sock.set_read_timeout(Some(timeout))?;
        let mut buf = [0u8; 8192];
        loop {
            // See `external_rx`'s own doc: on Windows a background thread is
            // this socket's sole reader and forwards already-demuxed IKE
            // datagrams here instead.
            let raw: &[u8] = if let Some(rx) = &self.external_rx {
                match rx.recv_timeout(timeout) {
                    Ok(datagram) => {
                        buf[..datagram.len()].copy_from_slice(&datagram);
                        &buf[..datagram.len()]
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        return Ok(if expected_mid.is_some() { Liveness::NoReply } else { Liveness::Alive });
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        return Ok(if expected_mid.is_some() { Liveness::NoReply } else { Liveness::Alive });
                    }
                }
            } else {
                match self.sock.recv(&mut buf) {
                    Ok(n) => &buf[..n],
                    Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                        return Ok(if expected_mid.is_some() { Liveness::NoReply } else { Liveness::Alive });
                    }
                    Err(e) => return Err(e.into()),
                }
            };
            let n = raw.len();
            crate::debug::dump("<<<", self.dest, &buf[..n]);
            let msg = unwrap(&buf[..n], self.float)?;
            let header = IkeHeader::parse(&msg)?;

            if header.flags.response {
                if expected_mid == Some(header.message_id) {
                    return Ok(Liveness::Alive);
                }
                continue; // a stale/unrelated response -- keep waiting
            }

            // An unsolicited request from the peer -- ack it regardless of
            // content, then decide what it means.
            let delete = open_informational(&self.sa, &msg)
                .ok()
                .and_then(|ps| ps.into_iter().find(|(t, _)| *t == PayloadType::Delete))
                .and_then(|(_, body)| Delete::parse(&body).ok());
            let mut ack_iv = [0u8; 8];
            OsEntropy::new()?.fill(&mut ack_iv);
            if let Ok(ack) = build_informational(&self.sa, header.message_id, true, &[], &ack_iv) {
                let _ = self.sock.send_to(&wrap(&ack, self.float), self.dest);
            }
            // See this function's own doc for why only these two cases end
            // the tunnel -- an ESP Delete for any other SPI is routine
            // post-rekey cleanup of a superseded CHILD SA, not a teardown.
            let tears_down = match delete {
                Some(Delete { protocol_id: p, .. }) if p == protocol_id::IKE => true,
                Some(Delete { protocol_id: p, spis }) if p == protocol_id::ESP => spis.contains(&self.child_peer_spi),
                _ => false,
            };
            if tears_down {
                ike_debug!("INFORMATIONAL: peer sent Delete -- tunnel torn down by the gateway");
                return Ok(Liveness::PeerTornDown);
            }
        }
    }
}

/// A blocking IKEv2 initiator session, driven by an [`Entropy`] source.
pub struct Ikev2Session<E> {
    entropy: E,
}

/// The local IP our packets actually carry as their source when reaching
/// `peer`, resolved via the OS routing table (see
/// `examples/ike_client_eap_fortigate.rs`'s `local_addr_for` — same trick:
/// a throwaway UDP `connect` picks the route without sending anything). Only
/// the IP is used -- the actual IKE socket always binds a literal well-known
/// port (see [`Ikev2Session::sa_init_on_port`]), not whatever ephemeral port
/// this probe happens to get.
fn local_ip_for(peer: SocketAddr) -> io::Result<std::net::IpAddr> {
    let probe = UdpSocket::bind(("0.0.0.0", 0))?;
    probe.connect(peer)?;
    Ok(probe.local_addr()?.ip())
}

/// The local port everything **after** `IKE_SA_INIT` moves to once NAT-T
/// floating is confirmed (RFC 7296 §2.23) -- a fixed `natt_port() - IKE_PORT`
/// offset from `local_port` so a production caller's literal 500 maps to the
/// literal [`crate::natt_port`] (4500) every other real IKE peer expects, while this
/// crate's own tests (which bind an arbitrary high `local_port` to stay
/// unprivileged) get an equally arbitrary, still-unique high port instead of
/// colliding with each other or a real 4500 already in use on the box.
fn natt_local_port(local_port: u16) -> u16 {
    local_port + (crate::natt_port() - IKE_PORT)
}

/// Per-attempt read timeouts for [`send_and_retry`] (RFC 7296 §2.1: "It is
/// the responsibility of the requester to retransmit if it has not received
/// a response within its retransmission timeout"). The RFC leaves the exact
/// schedule to the implementation; this follows the common IKE convention of
/// a short initial wait that backs off, capped, for a handful of attempts
/// total -- long enough to ride out a lost datagram or a slow gateway
/// without leaving a caller hanging for minutes.
const RETRY_BACKOFFS: &[Duration] =
    &[Duration::from_secs(2), Duration::from_secs(4), Duration::from_secs(8), Duration::from_secs(8), Duration::from_secs(8)];

/// Send `wire` to `dest` and wait for any datagram in reply, retransmitting
/// the same `wire` bytes (same Message ID -- RFC 7296 §2.1 requires a
/// retransmission to be bit-for-bit identical, never a freshly built
/// request) once per entry in [`RETRY_BACKOFFS`] until one arrives. Returns
/// the last attempt's timeout error if every attempt goes unanswered.
fn send_and_retry(sock: &UdpSocket, dest: SocketAddr, wire: &[u8]) -> Result<Vec<u8>, DriverError> {
    let mut buf = [0u8; 8192];
    let mut last_err = None;
    for (attempt, timeout) in RETRY_BACKOFFS.iter().enumerate() {
        if attempt > 0 {
            ike_debug!("retransmitting request to {dest} (attempt {}/{})", attempt + 1, RETRY_BACKOFFS.len());
        }
        crate::debug::dump(">>>", dest, wire);
        sock.send_to(wire, dest)?;
        sock.set_read_timeout(Some(*timeout))?;
        match sock.recv(&mut buf) {
            Ok(n) => {
                crate::debug::dump("<<<", dest, &buf[..n]);
                return Ok(buf[..n].to_vec());
            }
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                last_err = Some(e);
            }
            Err(e) => return Err(e.into()),
        }
    }
    Err(last_err.expect("RETRY_BACKOFFS is non-empty").into())
}

/// Timeout for each individual fragment read once the first fragment of a
/// response has arrived (RFC 7383 doesn't specify one -- this mirrors
/// [`RETRY_BACKOFFS`]'s steady-state 8s entries: a real gateway sends every
/// fragment of one message back-to-back, so this only needs to be long
/// enough to ride out ordinary jitter, not a full retransmit cycle).
const FRAGMENT_READ_TIMEOUT: Duration = Duration::from_secs(8);

/// Like [`send_and_retry`], but transparently reassembles the reply if the
/// peer fragmented it (RFC 7383): when the first datagram back carries an
/// `SKF` payload instead of `SK`, this keeps reading further datagrams for
/// the same Message ID until every fragment `1..=total` is in, verifies and
/// decrypts them via [`fragment::reassemble`], then re-encrypts the result
/// as a single ordinary `SK` message under the same peer key material. That
/// keeps every existing `open_encrypted` call site (which only ever expects
/// a plain `SK` payload) unchanged -- this is the one place that needs to
/// know fragments exist at all.
///
/// `cipher`/`sk_e`/`sk_a` are the *peer's* send keys (the same ones the
/// caller is about to pass to `open_encrypted`/`initiator_verify_auth`/etc.
/// on the returned bytes).
fn send_and_retry_reassembling(
    sock: &UdpSocket,
    dest: SocketAddr,
    wire: &[u8],
    float: bool,
    cipher: SkCipher,
    sk_e: &[u8],
    sk_a: &[u8],
) -> Result<Vec<u8>, DriverError> {
    let raw = send_and_retry(sock, dest, wire)?;
    let first = unwrap(&raw, float)?;
    let header = IkeHeader::parse(&first)?;
    if header.next_payload != PayloadType::EncryptedFragment {
        return Ok(first);
    }
    ike_debug!("IKE_AUTH: response is fragmented (RFC 7383) -- reassembling");

    let mid = header.message_id;
    let mut fragments = vec![first];
    let mut buf = [0u8; MAX_DATAGRAM];
    loop {
        if let Ok((first_inner, inner)) = fragment::reassemble(cipher, &fragments, sk_e, sk_a) {
            ike_debug!("IKE_AUTH: reassembled {} fragment(s)", fragments.len());
            let mut iv = [0u8; 8];
            OsEntropy::new()?.fill(&mut iv);
            let synthetic = sk::build_encrypted(cipher, header, first_inner, &inner, sk_e, sk_a, &iv)?;
            return Ok(synthetic);
        }
        sock.set_read_timeout(Some(FRAGMENT_READ_TIMEOUT))?;
        let n = sock.recv(&mut buf)?;
        crate::debug::dump("<<<", dest, &buf[..n]);
        let msg = unwrap(&buf[..n], float)?;
        let h = IkeHeader::parse(&msg)?;
        if h.message_id == mid && h.next_payload == PayloadType::EncryptedFragment {
            fragments.push(msg);
        }
        // Anything else (a stray retransmit of an earlier message, a
        // duplicate fragment, ...) is just ignored -- keep waiting for the
        // rest of this message's fragments.
    }
}

fn wrap(msg: &[u8], float: bool) -> Vec<u8> {
    if float { wrap_ike_4500(msg) } else { msg.to_vec() }
}

fn unwrap(dgram: &[u8], float: bool) -> Result<Vec<u8>, IkeError> {
    if float {
        unwrap_ike_4500(dgram).map(|m| m.to_vec()).ok_or(IkeError::MissingPayload("non-ESP marker"))
    } else {
        Ok(dgram.to_vec())
    }
}

/// Best-effort: tell the peer to drop this IKE_SA before a caller in
/// `connect_eap_after_sa_init`/`connect_direct_after_sa_init` gives up on it
/// (a rejected EAP credential, a bad server AUTH, etc) and returns an error.
/// `SK_e`/`SK_a` are already derived at `IKE_SA_INIT`, before `IKE_AUTH` even
/// starts, so an INFORMATIONAL Delete can always be built and sent for this
/// SA even though it never finished authenticating -- mirrors
/// [`LivenessSession::close`]'s graceful-disconnect Delete, just for a
/// connection attempt that never reached [`ConnectedTunnel`] at all.
///
/// Without this, simply dropping the socket on a failed attempt (the
/// previous behavior) leaves a half-open IKE_SA on the peer that only clears
/// on its own idle timeout -- several minutes on a FortiGate, during which
/// it still counts toward that gateway's concurrent-negotiation limit, so a
/// few failed attempts in a row (e.g. retrying a wrong password) can start
/// starving or throttling further ones from the same client.
///
/// `last_received` is the last message actually read from the peer in this
/// exchange -- its Message ID plus one is this SA's next free id (own
/// requests and the peer's share one strictly-increasing sequence, same
/// reasoning as `connect_eap_after_sa_init`'s own `next_message_id`
/// computation). Every failure mode here (entropy, encoding, I/O) is
/// swallowed: this call is purely a courtesy to the peer, never something
/// the caller's own error should wait on or be replaced by.
fn notify_ike_sa_delete_on_failed_auth(sock: &UdpSocket, sa: &CompletedSaInit, dest: SocketAddr, float: bool, last_received: &[u8]) {
    let Ok(mid) = IkeHeader::parse(last_received).map(|h| h.message_id + 1) else { return };
    let mut iv = [0u8; 8];
    let Ok(mut entropy) = OsEntropy::new() else { return };
    entropy.fill(&mut iv);
    let Ok(del) = build_informational(sa, mid, false, &[(PayloadType::Delete, Delete::ike_sa().to_bytes())], &iv) else { return };
    ike_debug!("INFORMATIONAL: sending IKE_SA Delete to {dest} (authentication failed)");
    let wire = wrap(&del, float);
    crate::debug::dump(">>>", dest, &wire);
    if sock.send_to(&wire, dest).is_err() {
        return;
    }
    // Best-effort ack wait, same reasoning as `LivenessSession::close`: RFC
    // 7296 lets the sender consider the SA closed immediately, without
    // needing to wait for one.
    let _ = sock.set_read_timeout(Some(Duration::from_millis(500)));
    let mut buf = [0u8; 512];
    let _ = sock.recv(&mut buf);
}

/// The cipher a peer's ESP answer implies, or [`IkeError::NoProposalChosen`]
/// if it named no ESP proposal at all, or one this crate doesn't implement
/// (see [`crate::ikev2::sk::SkCipher::from_encr_integ`]).
fn resolve_esp_cipher(suite: Option<ChosenEspSuite>) -> Result<SkCipher, IkeError> {
    suite.and_then(|s| s.sk_cipher()).ok_or(IkeError::NoProposalChosen)
}

/// Independently re-opens an already-decrypted-once response to pull out its
/// Configuration payload (DNS/subnet) — deliberately not threaded through
/// [`ike_auth::initiator_verify_auth`]/[`EapInitiator`]'s existing return
/// shapes, which callers/tests already depend on; this is cheap (one more GCM
/// open) and keeps this module's needs from touching those public signatures.
fn scan_cfg_reply(message: &[u8], sa: &CompletedSaInit) -> Option<Configuration> {
    let (first, inner) = open_encrypted(sa.suite.sk_cipher(), message, &sa.keys.sk_er, &sa.keys.sk_ar).ok()?;
    payloads(first, &inner)
        .flatten()
        .find(|p| p.payload_type == PayloadType::Configuration)
        .and_then(|p| Configuration::parse(p.data).ok())
}

/// See [`ConnectedTunnel::granted_subnets`] -- `cfg_subnet` when the
/// responder sent one (an explicit routing instruction, takes precedence),
/// else every CIDR-representable range from the responder's `TSr`.
fn granted_subnets(tsr: Option<&TrafficSelectors>, cfg_subnets: &[(Ipv4Addr, u8)]) -> Vec<(Ipv4Addr, u8)> {
    if !cfg_subnets.is_empty() {
        return cfg_subnets.to_vec();
    }
    tsr.map(|ts| ts.selectors.iter().filter_map(|s| s.to_ipv4_cidr()).collect()).unwrap_or_default()
}

/// IPv6 counterpart of [`granted_subnets`], with the same precedence: an
/// explicit `INTERNAL_IP6_SUBNET` from CFG_REPLY wins, else every
/// CIDR-representable IPv6 range the responder granted in `TSr` -- `::/0`
/// being a full IPv6 tunnel. Only ever non-empty for a responder that
/// accepted the IPv6 selector we proposed (`ike_auth::initiator_ts`), so it
/// is what actually says the CHILD SA can carry IPv6, not merely that the
/// gateway has an IPv6 address to hand out.
fn granted_subnets_v6(tsr: Option<&TrafficSelectors>, cfg_subnets6: &[(Ipv6Addr, u8)]) -> Vec<(Ipv6Addr, u8)> {
    if !cfg_subnets6.is_empty() {
        return cfg_subnets6.to_vec();
    }
    tsr.map(|ts| ts.selectors.iter().filter_map(|s| s.to_ipv6_cidr()).collect()).unwrap_or_default()
}

impl<E: Entropy> Ikev2Session<E> {
    pub fn new(entropy: E) -> Self {
        Self { entropy }
    }

    /// Bind a socket on `local_port` (like every other real-world IKE
    /// client, always the same well-known port rather than an arbitrary
    /// ephemeral one: some networks' own egress filtering specifically
    /// recognizes and permits UDP 500/4500 as IKE and is stricter about
    /// anything else) on whichever local IP an OS route lookup to `peer`
    /// picks, plus [`natt_local_port`], and run `IKE_SA_INIT` -- see
    /// [`Self::sa_init_with_sockets`] for the rest (this just binds the pair
    /// it needs). Exists so a caller with no persistent-socket needs of its
    /// own (this crate's `connect_*_on_port` entry points, its own tests)
    /// doesn't have to bind anything itself.
    fn sa_init_on_port(
        &mut self,
        peer: SocketAddr,
        offer: &SecurityAssociation,
        local_port: u16,
    ) -> Result<(UdpSocket, SocketAddr, CompletedSaInit, NatStatus), DriverError> {
        let sock = UdpSocket::bind(("0.0.0.0", local_port))?;
        let natt_sock = UdpSocket::bind(("0.0.0.0", natt_local_port(local_port)))?;
        self.sa_init_with_sockets(peer, offer, sock, natt_sock)
    }

    /// Run `IKE_SA_INIT` (NAT-detecting) over an already-bound `sock`/
    /// `natt_sock` pair -- the socket-owning counterpart to
    /// [`Self::sa_init_on_port`], for a caller that holds its own persistent
    /// sockets across multiple connects (e.g. a worker process binding the
    /// well-known IKE port once at startup, the way a real IKE daemon does,
    /// and handing in a fresh `UdpSocket::try_clone()` per attempt so the
    /// original stays open and bound for the next one). `sock` must already
    /// be bound to whatever local port this exchange's `IKE_SA_INIT` should
    /// claim as its source (ordinarily [`ike_port()`]); `natt_sock` to the
    /// port everything floats to if NAT is detected (ordinarily
    /// [`natt_port()`]) -- both consumed by value since exactly one of them
    /// ends up owned by the returned [`ConnectedTunnel::liveness`] and the
    /// other is simply dropped here.
    ///
    /// Pre-binding *both* up front, before knowing whether floating will be
    /// needed, is exactly what every other real IKE peer does (strongSwan's
    /// `socket-default` plugin opens both its `port` and `port_nat_t`
    /// sockets at startup and never rebinds either; OpenIKED's
    /// `ikev2_enable_natt` just switches `sa_fd` to an already-open,
    /// already-listening NAT-T socket -- see `iked.c`'s
    /// `sc_sock4[0]`/`sc_sock4[1]` and `ikev2.c`'s `ikev2_msg_getsocket`)
    /// rather than only ever changing the *destination* port on a socket
    /// that never moves. That half-measure is what this crate did before:
    /// once RFC 7296 §2.23 NAT detection floats the exchange, *both* ends
    /// move to symmetric UDP 4500 for everything after -- keeping the local
    /// socket pinned to port 500 means nothing is ever listening on 4500 to
    /// receive what the peer now sends there (its own retransmits, and
    /// critically the ESP-in-UDP data plane once a kernel XFRM SA is
    /// installed from [`ConnectedTunnel::local_addr`]/`peer_addr`) -- those
    /// packets are just silently dropped by the OS. This is exactly why a
    /// real gateway's own debug log can show a fully successful handshake
    /// (it floated correctly on *its* side) while nothing floated actually
    /// reaches the client.
    ///
    /// Returns the socket that ended up handling `IKE_SA_INIT`'s response --
    /// still `sock` if no NAT was detected, or the already-switched-to,
    /// already-[`crate::transport::enable_udp_encap`]'d `natt_sock` if it
    /// was -- plus the address that socket's traffic actually carries as its
    /// source from now on.
    fn sa_init_with_sockets(
        &mut self,
        peer: SocketAddr,
        offer: &SecurityAssociation,
        sock: UdpSocket,
        natt_sock: UdpSocket,
    ) -> Result<(UdpSocket, SocketAddr, CompletedSaInit, NatStatus), DriverError> {
        let ip = local_ip_for(peer)?;
        let local_port = sock.local_addr()?.port();
        let natt_port = natt_sock.local_addr()?.port();
        let our_addr = SocketAddr::new(ip, local_port);
        natt_sock.set_read_timeout(Some(Duration::from_secs(10)))?;

        let local = LocalSecret::generate(&mut self.entropy, NONCE_LEN);
        let req = initiator_request_natt(&local, offer, our_addr, peer);
        ike_debug!("IKE_SA_INIT: sending to {peer} (spi_i={:016x})", local.spi);
        let resp = send_and_retry(&sock, peer, &req)?;
        let (sa, nat) = initiator_complete_natt(&local, &req, &resp, our_addr, peer)?;
        ike_debug!(
            "IKE_SA_INIT: matched proposal #{} encr={} prf={} integ={:?} dh={}",
            sa.suite.proposal_num, sa.suite.encr_id, sa.suite.prf_id, sa.suite.integ_id, sa.suite.dh_id
        );
        ike_debug!(
            "IKE_SA_INIT: NAT detection -- we_are_natted={} peer_is_natted={} ({})",
            nat.we_are_natted, nat.peer_is_natted,
            if nat.float_to_4500() { "floating to port 4500" } else { "no float needed" }
        );

        if nat.float_to_4500() {
            crate::transport::enable_udp_encap(&natt_sock)?;
            Ok((natt_sock, SocketAddr::new(ip, natt_port), sa, nat))
        } else {
            Ok((sock, our_addr, sa, nat))
        }
    }

    /// Draw a non-zero SPI for our own inbound CHILD SA.
    fn child_spi(&mut self) -> u32 {
        loop {
            let s = self.entropy.next_u64() as u32;
            if s != 0 {
                return s;
            }
        }
    }

    fn derive_keys(sa: &CompletedSaInit, cipher: SkCipher) -> (ChildKeyMaterial, ChildKeyMaterial) {
        let integ_len = cipher.integ_algorithm().map(IntegAlgorithm::key_len).unwrap_or(0);
        let keys = derive_child_keys(sa.suite.prf_algorithm(), &sa.keys.sk_d, &sa.ni, &sa.nr, cipher.key_len() + cipher.salt_len(), integ_len);
        // RFC 7296 §2.17: `encr_i` is the initiator's outbound key, `encr_r`
        // the responder's — a packet carries the SPI of the SA that
        // *receives* it, so our egress key (peer_spi-keyed) is encr_i and our
        // ingress key (local_spi-keyed) is encr_r. Matches
        // `esp::ChildSa::derive`'s Initiator arm exactly.
        debug_assert_eq!(sa.role, Role::Initiator);
        let key_out = ChildKeyMaterial { cipher, enc: keys.encr_i, integ: keys.integ_i };
        let key_in = ChildKeyMaterial { cipher, enc: keys.encr_r, integ: keys.integ_r };
        (key_out, key_in)
    }

    /// Direct (non-EAP) `IKE_AUTH` — PSK or certificate, per `cfg` (reused
    /// as-is from [`ike_auth::AuthConfig`]). Set `want_cfg` to also send a
    /// CFG_REQUEST (e.g. a certificate profile with mode-config enabled).
    /// `esp_offer` is the CHILD SA proposal template — see
    /// [`ike_auth::initiator_auth_request_with_cfg`]'s doc for its contract;
    /// [`ike_auth::esp_offer`] gives the default AES-GCM-256 one.
    pub fn connect_direct(
        &mut self,
        peer: SocketAddr,
        offer: &SecurityAssociation,
        cfg: &AuthConfig,
        want_cfg: bool,
        esp_offer: &SecurityAssociation,
    ) -> Result<ConnectedTunnel, DriverError> {
        self.connect_direct_on_port(peer, offer, cfg, want_cfg, esp_offer, IKE_PORT)
    }

    /// Like [`Self::connect_direct`], but binding `local_port` instead of
    /// the real IKE port 500 -- see [`Self::sa_init_on_port`]'s doc. Exists
    /// only so this module's own loopback tests can use an unprivileged
    /// port; every real caller wants [`Self::connect_direct`].
    #[allow(clippy::too_many_arguments)]
    pub fn connect_direct_on_port(
        &mut self,
        peer: SocketAddr,
        offer: &SecurityAssociation,
        cfg: &AuthConfig,
        want_cfg: bool,
        esp_offer: &SecurityAssociation,
        local_port: u16,
    ) -> Result<ConnectedTunnel, DriverError> {
        let (sock, our_addr, sa, nat) = self.sa_init_on_port(peer, offer, local_port)?;
        self.connect_direct_after_sa_init(peer, cfg, want_cfg, esp_offer, sock, our_addr, sa, nat)
    }

    /// Like [`Self::connect_direct`], but over an already-bound `sock`/
    /// `natt_sock` pair instead of binding fresh ones -- see
    /// [`Self::sa_init_with_sockets`]'s doc. For a caller (the worker
    /// process in `free-vpn-v2`) holding persistent sockets across multiple
    /// connects, so the well-known ports stay held (like a real IKE daemon)
    /// even between tunnels, not just while one happens to be up.
    #[allow(clippy::too_many_arguments)]
    pub fn connect_direct_with_sockets(
        &mut self,
        peer: SocketAddr,
        offer: &SecurityAssociation,
        cfg: &AuthConfig,
        want_cfg: bool,
        esp_offer: &SecurityAssociation,
        sock: UdpSocket,
        natt_sock: UdpSocket,
    ) -> Result<ConnectedTunnel, DriverError> {
        let (sock, our_addr, sa, nat) = self.sa_init_with_sockets(peer, offer, sock, natt_sock)?;
        self.connect_direct_after_sa_init(peer, cfg, want_cfg, esp_offer, sock, our_addr, sa, nat)
    }

    /// The rest of `connect_direct` once `IKE_SA_INIT` (and the resulting
    /// float/no-float decision) is already done -- shared by
    /// [`Self::connect_direct_on_port`] and
    /// [`Self::connect_direct_with_sockets`] so binding-fresh-sockets vs.
    /// reusing-caller-supplied-ones is the only thing that differs between
    /// them.
    #[allow(clippy::too_many_arguments)]
    fn connect_direct_after_sa_init(
        &mut self,
        peer: SocketAddr,
        cfg: &AuthConfig,
        want_cfg: bool,
        esp_offer: &SecurityAssociation,
        sock: UdpSocket,
        our_addr: SocketAddr,
        sa: CompletedSaInit,
        nat: NatStatus,
    ) -> Result<ConnectedTunnel, DriverError> {
        let float = nat.float_to_4500();
        let dest = if float { SocketAddr::new(peer.ip(), crate::natt_port()) } else { peer };
        let local_spi = self.child_spi();

        let mut iv = [0u8; 8];
        self.entropy.fill(&mut iv);
        let req = ike_auth::initiator_auth_request_with_cfg(&sa, cfg, local_spi, want_cfg, esp_offer, &iv)?;
        ike_debug!("IKE_AUTH: sending to {dest} (local_spi={local_spi:08x}, floated={float})");
        let wire = wrap(&req, float);
        let response =
            send_and_retry_reassembling(&sock, dest, &wire, float, sa.suite.sk_cipher(), &sa.keys.sk_er, &sa.keys.sk_ar)?;

        let (_peer_id, peer_spi, esp_suite, assigned_ip4, tsr) = match ike_auth::initiator_verify_auth(&sa, &response, cfg) {
            Ok(v) => v,
            Err(e) => {
                ike_debug!("IKE_AUTH: peer authentication failed: {e}");
                notify_ike_sa_delete_on_failed_auth(&sock, &sa, dest, float, &response);
                return Err(e.into());
            }
        };
        ike_debug!("IKE_AUTH: authenticated -- peer_spi={peer_spi:08x} assigned_ip={assigned_ip4:?}");
        let cfg_reply = want_cfg.then(|| scan_cfg_reply(&response, &sa)).flatten();
        let dns = cfg_reply.as_ref().map(Configuration::assigned_dns).unwrap_or_default();
        let dns6 = cfg_reply.as_ref().map(Configuration::assigned_ipv6_dns).unwrap_or_default();
        let cfg_subnets = cfg_reply.as_ref().map(Configuration::assigned_subnets).unwrap_or_default();
        let subnet = cfg_subnets.first().copied();
        let assigned_ip6 = cfg_reply.as_ref().and_then(Configuration::assigned_ipv6);
        let cfg_subnets6 = cfg_reply.as_ref().map(Configuration::assigned_ipv6_subnets).unwrap_or_default();
        ike_debug!("IKE_AUTH: CFG_REPLY IPv6 -- assigned_ipv6={assigned_ip6:?} assigned_ipv6_subnets={cfg_subnets6:?}");

        let cipher = resolve_esp_cipher(esp_suite)?;
        let (key_out, key_in) = Self::derive_keys(&sa, cipher);
        let pfs_group = dh_transform_id(esp_offer).and_then(DhGroup::from_transform_id);
        let liveness = LivenessSession {
            sock,
            sa,
            dest,
            float,
            next_message_id: 2, // IKE_AUTH was message 1
            cipher,
            pfs_group,
            child_local_spi: local_spi,
            child_peer_spi: peer_spi,
            external_rx: None,
            child6: None,
            cfg_subnets6: cfg_subnets6.clone(),
        };
        Ok(ConnectedTunnel {
            local_spi,
            peer_spi,
            key_out,
            key_in,
            assigned_ip4,
            dns,
            dns6,
            assigned_ip6,
            cfg_subnets6,
            subnet,
            granted_subnets: granted_subnets(tsr.as_ref(), &cfg_subnets),
            local_addr: our_addr,
            peer_addr: dest,
            nat,
            liveness,
        })
    }

    /// `IKE_AUTH` via EAP-MSCHAPv2 (RFC 7296 §2.16) — the FortiGate-proven
    /// path. `verify` reused as-is from [`eap_auth::ServerVerify`]
    /// (`ServerVerify::Psk` for a PSK-authenticated gateway, `TrustedCas` for
    /// a certificate one; `Insecure` only for an already-trusted setting).
    /// Set `want_cfg` when the peer is configured for mode-config -- e.g. a
    /// real FortiGate dialup policy, which otherwise answers "mode-cfg not
    /// completed" and tears the IKE SA down right after EAP succeeds; a
    /// responder not using mode-config at all just ignores an unused
    /// CFG_REQUEST, but leave it off when the profile genuinely isn't
    /// mode-config so the wire behavior matches what was actually
    /// negotiated. `esp_offer` is the CHILD SA proposal template — see
    /// [`ike_auth::initiator_auth_request_with_cfg`]'s doc for its contract;
    /// [`ike_auth::esp_offer`] gives the default AES-GCM-256 one.
    #[allow(clippy::too_many_arguments)]
    pub fn connect_eap(
        &mut self,
        peer: SocketAddr,
        offer: &SecurityAssociation,
        local_id: Identification,
        creds: EapCreds,
        verify: ServerVerify,
        want_cfg: bool,
        esp_offer: &SecurityAssociation,
    ) -> Result<ConnectedTunnel, DriverError> {
        self.connect_eap_on_port(peer, offer, local_id, creds, verify, want_cfg, esp_offer, IKE_PORT)
    }

    /// Like [`Self::connect_eap_with_sockets`], but also attaches the
    /// client's own X.509 chain (`client_certs[0]` = leaf, as bare identity —
    /// no AUTH exists in the EAP-triggering message, see
    /// [`ike_auth::initiator_eap_request_with_certs`]'s doc). No `CERTREQ` is
    /// sent -- `verify`'s trusted-CA list is for validating the *gateway's*
    /// certificate on our side, not a hint of which cert the gateway should
    /// present back to us; a real FortiGate presents its one configured
    /// server certificate unconditionally regardless. For a gateway (e.g. a
    /// FortiGate dialup policy) configured for "Certificate + EAP": it wants
    /// the client's certificate for identity/policy matching on top of EAP
    /// deciding the actual authentication outcome — a non-standard hybrid
    /// (not RFC 4739) that real FortiClient uses, confirmed against the
    /// patched strongSwan reference this project has used throughout
    /// (`~/strongswan-dev/strongswan-6.0.7-mod`'s `forticlient_mode()`).
    /// A plain empty `client_certs` reproduces [`Self::connect_eap_with_sockets`]
    /// exactly, which is why that method doesn't need its own separate
    /// implementation of this same logic. `want_cfg` behaves exactly as it
    /// does on [`Self::connect_eap`] -- whether the peer is configured for
    /// mode-config is a property of the connection profile, independent of
    /// whether it also happens to require this certificate hybrid.
    #[allow(clippy::too_many_arguments)]
    pub fn connect_eap_with_client_cert_and_sockets(
        &mut self,
        peer: SocketAddr,
        offer: &SecurityAssociation,
        local_id: Identification,
        creds: EapCreds,
        verify: ServerVerify,
        client_certs: &[Vec<u8>],
        want_cfg: bool,
        esp_offer: &SecurityAssociation,
        sock: UdpSocket,
        natt_sock: UdpSocket,
    ) -> Result<ConnectedTunnel, DriverError> {
        let (sock, our_addr, sa, nat) = self.sa_init_with_sockets(peer, offer, sock, natt_sock)?;
        self.connect_eap_after_sa_init_ext(peer, local_id, creds, verify, client_certs, want_cfg, esp_offer, sock, our_addr, sa, nat)
    }

    /// Like [`Self::connect_eap`], but binding `local_port` instead of the
    /// real IKE port 500 -- see [`Self::sa_init_on_port`]'s doc. Exists only
    /// so this module's own loopback tests can use an unprivileged port;
    /// every real caller wants [`Self::connect_eap`].
    #[allow(clippy::too_many_arguments)]
    pub fn connect_eap_on_port(
        &mut self,
        peer: SocketAddr,
        offer: &SecurityAssociation,
        local_id: Identification,
        creds: EapCreds,
        verify: ServerVerify,
        want_cfg: bool,
        esp_offer: &SecurityAssociation,
        local_port: u16,
    ) -> Result<ConnectedTunnel, DriverError> {
        let (sock, our_addr, sa, nat) = self.sa_init_on_port(peer, offer, local_port)?;
        self.connect_eap_after_sa_init(peer, local_id, creds, verify, want_cfg, esp_offer, sock, our_addr, sa, nat)
    }

    /// Like [`Self::connect_eap`], but over an already-bound `sock`/
    /// `natt_sock` pair instead of binding fresh ones -- see
    /// [`Self::connect_direct_with_sockets`]'s doc (same rationale: a
    /// persistent-socket-holding worker process).
    #[allow(clippy::too_many_arguments)]
    pub fn connect_eap_with_sockets(
        &mut self,
        peer: SocketAddr,
        offer: &SecurityAssociation,
        local_id: Identification,
        creds: EapCreds,
        verify: ServerVerify,
        want_cfg: bool,
        esp_offer: &SecurityAssociation,
        sock: UdpSocket,
        natt_sock: UdpSocket,
    ) -> Result<ConnectedTunnel, DriverError> {
        let (sock, our_addr, sa, nat) = self.sa_init_with_sockets(peer, offer, sock, natt_sock)?;
        self.connect_eap_after_sa_init(peer, local_id, creds, verify, want_cfg, esp_offer, sock, our_addr, sa, nat)
    }

    /// The rest of `connect_eap` once `IKE_SA_INIT` (and the resulting
    /// float/no-float decision) is already done -- shared by
    /// [`Self::connect_eap_on_port`] and [`Self::connect_eap_with_sockets`],
    /// same split as [`Self::connect_direct_after_sa_init`].
    #[allow(clippy::too_many_arguments)]
    fn connect_eap_after_sa_init(
        &mut self,
        peer: SocketAddr,
        local_id: Identification,
        creds: EapCreds,
        verify: ServerVerify,
        want_cfg: bool,
        esp_offer: &SecurityAssociation,
        sock: UdpSocket,
        our_addr: SocketAddr,
        sa: CompletedSaInit,
        nat: NatStatus,
    ) -> Result<ConnectedTunnel, DriverError> {
        self.connect_eap_after_sa_init_ext(peer, local_id, creds, verify, &[], want_cfg, esp_offer, sock, our_addr, sa, nat)
    }

    /// The rest of [`Self::connect_eap_with_client_cert_and_sockets`] once
    /// `IKE_SA_INIT` is done -- also what [`Self::connect_eap_after_sa_init`]
    /// delegates to with an empty `client_certs`, so there is exactly one
    /// implementation of the EAP-round-driving loop.
    #[allow(clippy::too_many_arguments)]
    fn connect_eap_after_sa_init_ext(
        &mut self,
        peer: SocketAddr,
        local_id: Identification,
        creds: EapCreds,
        verify: ServerVerify,
        client_certs: &[Vec<u8>],
        want_cfg: bool,
        esp_offer: &SecurityAssociation,
        sock: UdpSocket,
        our_addr: SocketAddr,
        sa: CompletedSaInit,
        nat: NatStatus,
    ) -> Result<ConnectedTunnel, DriverError> {
        let float = nat.float_to_4500();
        let dest = if float { SocketAddr::new(peer.ip(), crate::natt_port()) } else { peer };
        let local_spi = self.child_spi();

        ike_debug!("IKE_AUTH (EAP-MSCHAPv2): starting as user '{}' against {dest}", String::from_utf8_lossy(&creds.user));
        let mut initiator =
            EapInitiator::new_with_esp_offer(sa, local_id, creds.user, creds.password, local_spi, esp_offer.clone(), verify);
        // want_cfg: whether this peer is configured for mode-config -- a real
        // FortiGate dialup policy otherwise answers "mode-cfg not completed"
        // and tears the IKE SA down right after EAP succeeds; a responder not
        // using mode-config at all just ignores an unused CFG_REQUEST, but
        // the flag stays caller-driven rather than always-on so the wire
        // behavior matches what the profile actually negotiated.
        initiator.set_want_cfg(want_cfg);
        if !client_certs.is_empty() {
            initiator.set_client_certs(client_certs.to_vec());
            // Deliberately no set_send_certreq() here: `verify`'s trusted-CA
            // list exists to validate the *gateway's* certificate on our
            // side, not to be broadcast back as a hint of which cert the
            // gateway should present -- confirmed live against a real
            // FortiGate that it presents its one configured server
            // certificate unconditionally regardless of our CERTREQ, so
            // deriving CERTREQ hashes from a whole system CA bundle (100+
            // entries) only bloated the message for no behavioral effect.
        }
        let mut msg = initiator.start(&mut self.entropy)?;
        let mut last_message;
        let mut round = 0u32;
        let cipher = initiator.ike_sa().suite.sk_cipher();
        loop {
            round += 1;
            let wire = wrap(&msg, float);
            let sa = initiator.ike_sa();
            let ike_msg =
                send_and_retry_reassembling(&sock, dest, &wire, float, cipher, &sa.keys.sk_er, &sa.keys.sk_ar)?;
            last_message = ike_msg.clone();
            match initiator.handle(&ike_msg, &mut self.entropy)? {
                EapEvent::Reply(next) => {
                    ike_debug!("IKE_AUTH (EAP-MSCHAPv2): round {round} -- continuing");
                    msg = next
                }
                EapEvent::Established(final_msg) => {
                    ike_debug!("IKE_AUTH (EAP-MSCHAPv2): authentication succeeded after {round} round(s)");
                    if let Some(fm) = final_msg {
                        let wire = wrap(&fm, float);
                        crate::debug::dump(">>>", dest, &wire);
                        sock.send_to(&wire, dest)?;
                    }
                    break;
                }
                EapEvent::Failed(reason) => {
                    ike_debug!("IKE_AUTH (EAP-MSCHAPv2): authentication failed after {round} round(s)");
                    notify_ike_sa_delete_on_failed_auth(&sock, initiator.ike_sa(), dest, float, &last_message);
                    let err = match reason {
                        Some(r) if r.credentials_rejected => IkeError::EapCredentialsRejected(r.raw),
                        _ => IkeError::AuthFailed,
                    };
                    return Err(err.into());
                }
            }
        }

        let peer_spi = initiator.peer_child_spi().ok_or(IkeError::MissingPayload("SA"))?;
        let cipher = resolve_esp_cipher(initiator.peer_esp_suite())?;
        let assigned_ip4 = initiator.assigned_ip4();
        let tsr = initiator.granted_ts().cloned();
        let sa = initiator.ike_sa();
        let cfg_reply = scan_cfg_reply(&last_message, sa);
        let dns = cfg_reply.as_ref().map(Configuration::assigned_dns).unwrap_or_default();
        let dns6 = cfg_reply.as_ref().map(Configuration::assigned_ipv6_dns).unwrap_or_default();
        let cfg_subnets = cfg_reply.as_ref().map(Configuration::assigned_subnets).unwrap_or_default();
        let subnet = cfg_subnets.first().copied();
        // See the identical block in the non-EAP IKE_AUTH path above.
        let assigned_ip6 = cfg_reply.as_ref().and_then(Configuration::assigned_ipv6);
        let cfg_subnets6 = cfg_reply.as_ref().map(Configuration::assigned_ipv6_subnets).unwrap_or_default();
        ike_debug!("IKE_AUTH (EAP): CFG_REPLY IPv6 -- assigned_ipv6={assigned_ip6:?} assigned_ipv6_subnets={cfg_subnets6:?}");
        let (key_out, key_in) = Self::derive_keys(sa, cipher);
        // The next message ID we may originate is one past the last request
        // the peer sent us (its own EAP-round message IDs) -- our own
        // requests and the peer's share one strictly-increasing sequence.
        let next_message_id = IkeHeader::parse(&last_message)?.message_id + 1;
        let pfs_group = dh_transform_id(esp_offer).and_then(DhGroup::from_transform_id);
        let liveness = LivenessSession {
            sock,
            sa: sa.clone(),
            dest,
            float,
            next_message_id,
            cipher,
            pfs_group,
            child_local_spi: local_spi,
            child_peer_spi: peer_spi,
            external_rx: None,
            child6: None,
            cfg_subnets6: cfg_subnets6.clone(),
        };

        Ok(ConnectedTunnel {
            local_spi,
            peer_spi,
            key_out,
            key_in,
            assigned_ip4,
            dns,
            dns6,
            assigned_ip6,
            cfg_subnets6,
            subnet,
            granted_subnets: granted_subnets(tsr.as_ref(), &cfg_subnets),
            local_addr: our_addr,
            peer_addr: dest,
            nat,
            liveness,
        })
    }
}

/// The default IKE port (500) — the caller supplies the gateway's address at
/// this port for `peer` in [`Ikev2Session::connect_direct`]/`connect_eap`.
pub const fn ike_port() -> u16 {
    IKE_PORT
}

/// Our default offered proposal — see [`default_offer`]; re-exported here so a
/// caller that doesn't need a custom offer (e.g. this FortiGate's ECP256-only
/// phase1-proposal) has one obvious default to reach for.
pub fn default_ike_offer() -> SecurityAssociation {
    default_offer()
}

/// Our default CHILD SA proposal template (AES-GCM-256) — see
/// [`ike_auth::esp_offer`]; re-exported here for [`Ikev2Session::connect_direct`]/
/// `connect_eap`'s `esp_offer` parameter, for a caller that doesn't need a
/// custom one. The SPI argument doesn't matter — it's always overwritten
/// with the real per-connection SPI, see `esp_offer`'s own doc.
pub fn default_esp_offer() -> SecurityAssociation {
    ike_auth::esp_offer(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::OsEntropy;
    use crate::ikev2::eap_auth::{EapResponder, ServerAuth};
    use crate::ikev2::exchange::{
        initiator_complete, initiator_request, responder_respond, responder_respond_natt,
    };
    use crate::ikev2::ike_auth::responder_process_auth;
    use crate::ikev2::payload::Delete;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::thread;

    /// A completed SA pair, established over loopback plain `IKE_SA_INIT`
    /// (no NAT-T float) -- same shape as [`informational`]'s own test
    /// helper, needed here to exercise [`LivenessSession::probe`] without
    /// running a full `IKE_AUTH`/EAP handshake.
    fn liveness_sa_pair() -> (CompletedSaInit, CompletedSaInit) {
        let init = LocalSecret::generate(&mut OsEntropy::new().unwrap(), NONCE_LEN);
        let resp = LocalSecret::generate(&mut OsEntropy::new().unwrap(), NONCE_LEN);
        let request = initiator_request(&init, &default_offer());
        let (response, resp_done) = responder_respond(&request, &resp).unwrap();
        let init_done = initiator_complete(&init, &request, &response).unwrap();
        (init_done, resp_done)
    }

    #[test]
    fn send_and_retry_recovers_from_one_dropped_request() {
        let server_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server_addr = server_sock.local_addr().unwrap();
        let client_sock = UdpSocket::bind("127.0.0.1:0").unwrap();

        let responder = thread::spawn(move || {
            let mut buf = [0u8; 64];
            // First datagram: simulate packet loss by just reading and
            // discarding it -- no reply.
            let (n, _from) = server_sock.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"ping");
            // The retransmission (same bytes, RFC 7296 §2.1): reply this time.
            let (n, from) = server_sock.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"ping");
            server_sock.send_to(b"pong", from).unwrap();
        });

        let resp = send_and_retry(&client_sock, server_addr, b"ping").unwrap();
        assert_eq!(resp, b"pong");
        responder.join().unwrap();
    }

    #[test]
    fn liveness_probe_returns_alive_when_the_peer_answers() {
        let bind = next_addr();
        let (init_sa, resp_sa) = liveness_sa_pair();
        let responder = thread::spawn(move || {
            let sock = UdpSocket::bind(bind).unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut buf = [0u8; 2048];
            let (n, from) = sock.recv_from(&mut buf).unwrap();
            let req_id = IkeHeader::parse(&buf[..n]).unwrap().message_id;
            assert!(open_informational(&resp_sa, &buf[..n]).unwrap().is_empty());
            let ack = build_informational(&resp_sa, req_id, true, &[], &[9u8; 8]).unwrap();
            sock.send_to(&ack, from).unwrap();
        });
        thread::sleep(Duration::from_millis(50));

        let probe_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut liveness =
            LivenessSession { sock: probe_sock, sa: init_sa, dest: bind, float: false, next_message_id: 2, cipher: SkCipher::Aes256Gcm, pfs_group: None, child_local_spi: 0, child_peer_spi: 0, external_rx: None, child6: None, cfg_subnets6: Vec::new() };
        assert_eq!(liveness.probe(Duration::from_secs(5)).unwrap(), Liveness::Alive);
        responder.join().unwrap();
    }

    #[test]
    fn liveness_probe_retransmits_and_still_succeeds_after_one_dropped_request() {
        let bind = next_addr();
        let (init_sa, resp_sa) = liveness_sa_pair();
        let responder = thread::spawn(move || {
            let sock = UdpSocket::bind(bind).unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut buf = [0u8; 2048];
            // Drop the first DPD request -- simulate one lost datagram.
            let (n1, _from) = sock.recv_from(&mut buf).unwrap();
            let first_id = IkeHeader::parse(&buf[..n1]).unwrap().message_id;
            // The retransmission carries the identical Message ID (RFC 7296
            // §2.1 -- a retransmit is never a freshly built request).
            let (n2, from) = sock.recv_from(&mut buf).unwrap();
            let req_id = IkeHeader::parse(&buf[..n2]).unwrap().message_id;
            assert_eq!(req_id, first_id);
            assert_eq!(&buf[..n1], &buf[..n2], "retransmission must resend the exact same bytes");
            let ack = build_informational(&resp_sa, req_id, true, &[], &[9u8; 8]).unwrap();
            sock.send_to(&ack, from).unwrap();
        });
        thread::sleep(Duration::from_millis(50));

        let probe_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut liveness =
            LivenessSession { sock: probe_sock, sa: init_sa, dest: bind, float: false, next_message_id: 2, cipher: SkCipher::Aes256Gcm, pfs_group: None, child_local_spi: 0, child_peer_spi: 0, external_rx: None, child6: None, cfg_subnets6: Vec::new() };
        assert_eq!(liveness.probe(Duration::from_millis(300)).unwrap(), Liveness::Alive);
        responder.join().unwrap();
    }

    #[test]
    fn liveness_probe_detects_a_peer_initiated_delete_and_acks_it() {
        let bind = next_addr();
        let (init_sa, resp_sa) = liveness_sa_pair();
        let responder = thread::spawn(move || {
            let sock = UdpSocket::bind(bind).unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut buf = [0u8; 2048];
            // Ignore our DPD request entirely -- simulate the gateway
            // instead proactively tearing the CHILD_SA/IKE_SA down first.
            let (_n, from) = sock.recv_from(&mut buf).unwrap();
            let del = Delete::ike_sa();
            let msg = build_informational(&resp_sa, 100, false, &[(PayloadType::Delete, del.to_bytes())], &[7u8; 8]).unwrap();
            sock.send_to(&msg, from).unwrap();
            // Our probe owes this an ack per RFC 7296 even though it's
            // reporting the tunnel as gone -- confirm it actually arrives.
            let (n, _) = sock.recv_from(&mut buf).unwrap();
            let ack_header = IkeHeader::parse(&buf[..n]).unwrap();
            assert_eq!(ack_header.message_id, 100);
            assert!(ack_header.flags.response);
        });
        thread::sleep(Duration::from_millis(50));

        let probe_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut liveness =
            LivenessSession { sock: probe_sock, sa: init_sa, dest: bind, float: false, next_message_id: 2, cipher: SkCipher::Aes256Gcm, pfs_group: None, child_local_spi: 0, child_peer_spi: 0, external_rx: None, child6: None, cfg_subnets6: Vec::new() };
        assert_eq!(liveness.probe(Duration::from_secs(5)).unwrap(), Liveness::PeerTornDown);
        responder.join().unwrap();
    }

    #[test]
    fn close_sends_an_ike_sa_delete_and_consumes_the_ack() {
        let bind = next_addr();
        let (init_sa, resp_sa) = liveness_sa_pair();
        let responder = thread::spawn(move || {
            let sock = UdpSocket::bind(bind).unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut buf = [0u8; 2048];
            let (n, from) = sock.recv_from(&mut buf).unwrap();
            let header = IkeHeader::parse(&buf[..n]).unwrap();
            assert!(!header.flags.response);
            let payloads = open_informational(&resp_sa, &buf[..n]).unwrap();
            assert_eq!(payloads.len(), 1);
            assert_eq!(payloads[0].0, PayloadType::Delete);
            assert_eq!(Delete::parse(&payloads[0].1).unwrap(), Delete::ike_sa());
            let ack = build_informational(&resp_sa, header.message_id, true, &[], &[9u8; 8]).unwrap();
            sock.send_to(&ack, from).unwrap();
        });
        thread::sleep(Duration::from_millis(50));

        let probe_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut liveness =
            LivenessSession { sock: probe_sock, sa: init_sa, dest: bind, float: false, next_message_id: 2, cipher: SkCipher::Aes256Gcm, pfs_group: None, child_local_spi: 0, child_peer_spi: 0, external_rx: None, child6: None, cfg_subnets6: Vec::new() };
        liveness.close().unwrap();
        responder.join().unwrap();
    }

    #[test]
    fn close_does_not_fail_when_the_peer_never_acks() {
        // Unreachable dest: send() itself still succeeds (UDP is fire and
        // forget), only the best-effort ack wait times out -- close() must
        // not surface that as an error.
        let unreachable: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let (init_sa, _resp_sa) = liveness_sa_pair();
        let probe_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut liveness =
            LivenessSession { sock: probe_sock, sa: init_sa, dest: unreachable, float: false, next_message_id: 2, cipher: SkCipher::Aes256Gcm, pfs_group: None, child_local_spi: 0, child_peer_spi: 0, external_rx: None, child6: None, cfg_subnets6: Vec::new() };
        liveness.close().unwrap();
    }

    #[test]
    fn liveness_probe_times_out_when_the_peer_never_answers() {
        let (init_sa, _resp_sa) = liveness_sa_pair();
        // A bound socket that never reads or answers, so the probe reliably
        // exercises the timeout path on every OS. (A *closed* port would
        // make Windows answer with ICMP Port Unreachable and surface it as
        // WSAECONNRESET on the next recv, which isn't what's under test.)
        let silent_peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        let unreachable: SocketAddr = silent_peer.local_addr().unwrap();
        let probe_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut liveness =
            LivenessSession { sock: probe_sock, sa: init_sa, dest: unreachable, float: false, next_message_id: 2, cipher: SkCipher::Aes256Gcm, pfs_group: None, child_local_spi: 0, child_peer_spi: 0, external_rx: None, child6: None, cfg_subnets6: Vec::new() };
        assert_eq!(liveness.probe(Duration::from_millis(300)).unwrap(), Liveness::NoReply);
    }

    #[test]
    fn peek_reports_alive_when_nothing_is_pending() {
        let (init_sa, _resp_sa) = liveness_sa_pair();
        let unreachable: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let probe_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut liveness =
            LivenessSession { sock: probe_sock, sa: init_sa, dest: unreachable, float: false, next_message_id: 2, cipher: SkCipher::Aes256Gcm, pfs_group: None, child_local_spi: 0, child_peer_spi: 0, external_rx: None, child6: None, cfg_subnets6: Vec::new() };
        // Unlike probe(), silence on a peek is Alive (nothing new to
        // report), not NoReply -- peek never asked anything.
        assert_eq!(liveness.peek(Duration::from_millis(50)).unwrap(), Liveness::Alive);
    }

    #[test]
    fn peek_catches_a_delete_that_already_arrived_without_sending_anything() {
        let (init_sa, resp_sa) = liveness_sa_pair();
        // Bound here (not inside the spawned thread) so the send below can
        // never race a not-yet-bound socket the way a post-spawn sleep would.
        let responder_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let bind = responder_sock.local_addr().unwrap();
        let responder = thread::spawn(move || {
            responder_sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut buf = [0u8; 2048];
            // Learn the probe socket's ephemeral port from the throwaway
            // datagram it sends below, then push the Delete to it entirely
            // unprompted -- peek() must find it already waiting, having
            // asked for nothing itself.
            let (_n, from) = responder_sock.recv_from(&mut buf).unwrap();
            let del = Delete::ike_sa();
            let msg = build_informational(&resp_sa, 100, false, &[(PayloadType::Delete, del.to_bytes())], &[7u8; 8]).unwrap();
            responder_sock.send_to(&msg, from).unwrap();
        });

        // A throwaway datagram so the responder above learns our ephemeral
        // port (peek() itself never sends anything) -- an unrelated garbage
        // packet the responder just uses for its return address, discarded
        // on our side by peek() itself once the real Delete follows.
        let probe_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        probe_sock.send_to(b"hello", bind).unwrap();

        let mut liveness =
            LivenessSession { sock: probe_sock, sa: init_sa, dest: bind, float: false, next_message_id: 2, cipher: SkCipher::Aes256Gcm, pfs_group: None, child_local_spi: 0, child_peer_spi: 0, external_rx: None, child6: None, cfg_subnets6: Vec::new() };
        assert_eq!(liveness.peek(Duration::from_secs(5)).unwrap(), Liveness::PeerTornDown);
        responder.join().unwrap();
    }

    /// The regression test for the bug this fixes: after `rekey_child`
    /// installs a fresh CHILD SA, a real FortiGate deletes the old,
    /// now-superseded one and notifies this side via an unsolicited ESP
    /// Delete naming that old SPI. `child_peer_spi` here (0xAAAA) is the
    /// *current* CHILD SA -- the Delete names a different, older SPI
    /// (0x1111) -- so this must not be mistaken for the tunnel going down.
    #[test]
    fn peek_ignores_an_esp_delete_for_a_superseded_child_sa() {
        let (init_sa, resp_sa) = liveness_sa_pair();
        let responder_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let bind = responder_sock.local_addr().unwrap();
        let responder = thread::spawn(move || {
            responder_sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut buf = [0u8; 2048];
            let (_n, from) = responder_sock.recv_from(&mut buf).unwrap();
            let del = Delete::esp(vec![0x1111]);
            let msg = build_informational(&resp_sa, 100, false, &[(PayloadType::Delete, del.to_bytes())], &[7u8; 8]).unwrap();
            responder_sock.send_to(&msg, from).unwrap();
            // Still owed an ack even though it's being ignored as a teardown.
            let (n, _) = responder_sock.recv_from(&mut buf).unwrap();
            let ack_header = IkeHeader::parse(&buf[..n]).unwrap();
            assert_eq!(ack_header.message_id, 100);
            assert!(ack_header.flags.response);
        });

        let probe_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        probe_sock.send_to(b"hello", bind).unwrap();

        let mut liveness = LivenessSession {
            sock: probe_sock,
            sa: init_sa,
            dest: bind,
            float: false,
            next_message_id: 2,
            cipher: SkCipher::Aes256Gcm,
            pfs_group: None,
            child_local_spi: 0,
            child_peer_spi: 0xAAAA,
            external_rx: None,
            child6: None,
            cfg_subnets6: Vec::new(),
        };
        // The stale Delete is ignored and the wait times out -- silence
        // (nothing new to report) is Alive, exactly as if nothing had
        // arrived at all.
        assert_eq!(liveness.peek(Duration::from_millis(300)).unwrap(), Liveness::Alive);
        responder.join().unwrap();
    }

    /// The other half of the same fix: an ESP Delete naming the CHILD SA
    /// this session is *actually* relying on right now still ends the
    /// tunnel -- only a Delete for some other (superseded) SPI is ignored.
    #[test]
    fn peek_still_tears_down_on_an_esp_delete_for_the_current_child_sa() {
        let (init_sa, resp_sa) = liveness_sa_pair();
        let responder_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let bind = responder_sock.local_addr().unwrap();
        let responder = thread::spawn(move || {
            responder_sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut buf = [0u8; 2048];
            let (_n, from) = responder_sock.recv_from(&mut buf).unwrap();
            let del = Delete::esp(vec![0xAAAA]);
            let msg = build_informational(&resp_sa, 100, false, &[(PayloadType::Delete, del.to_bytes())], &[7u8; 8]).unwrap();
            responder_sock.send_to(&msg, from).unwrap();
        });

        let probe_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        probe_sock.send_to(b"hello", bind).unwrap();

        let mut liveness = LivenessSession {
            sock: probe_sock,
            sa: init_sa,
            dest: bind,
            float: false,
            next_message_id: 2,
            cipher: SkCipher::Aes256Gcm,
            pfs_group: None,
            child_local_spi: 0,
            child_peer_spi: 0xAAAA,
            external_rx: None,
            child6: None,
            cfg_subnets6: Vec::new(),
        };
        assert_eq!(liveness.peek(Duration::from_secs(5)).unwrap(), Liveness::PeerTornDown);
        responder.join().unwrap();
    }

    // A free-ish loopback port per test, avoiding cross-test collisions
    // without needing a real ephemeral-port allocator here.
    static NEXT_PORT: AtomicU32 = AtomicU32::new(29500);
    fn next_addr() -> SocketAddr {
        let port = NEXT_PORT.fetch_add(1, Ordering::SeqCst) as u16;
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    /// The regression test for the real-world bug this fixes: a client
    /// behind NAT (confirmed live against a FortiGate) kept sending from its
    /// original port-500-equivalent socket after `IKE_SA_INIT` reported
    /// floating was required -- it only ever changed the *destination* port,
    /// never actually switched its own local socket the way every other real
    /// IKE peer does (see `sa_init_on_port`'s doc: strongSwan pre-opens both
    /// `port`/`port_nat_t` sockets, OpenIKED's `ikev2_enable_natt` switches
    /// to an already-listening NAT-T socket). Exercises `sa_init_on_port`
    /// directly rather than the full `connect_direct` -- that's the one
    /// place the switch happens, and completing a full handshake wouldn't
    /// actually catch this bug: a reply always finds its way back to
    /// whatever source port a request went out from regardless of whether
    /// that port is "correct", so only checking what the client *itself*
    /// ends up bound to (not just whether the exchange completed) proves
    /// anything.
    ///
    /// A real NAT can't be reproduced on loopback, so the test responder
    /// below fakes one the same way a live NAT would present itself to us:
    /// it tells `responder_respond_natt` the request arrived from a
    /// different port than it actually did, which is exactly what
    /// `NAT_DETECTION_DESTINATION_IP` failing to match looks like from the
    /// client's side (RFC 7296 §2.23) -- the client's `our_addr` (what it
    /// truthfully bound) disagreeing with what the peer reports having
    /// observed is the whole detection mechanism, regardless of whether a
    /// real NAT box or a lying test double produced the mismatch.
    #[test]
    fn sa_init_switches_the_local_socket_to_the_natt_port_when_nat_is_detected() {
        let bind = next_addr();
        let responder = thread::spawn(move || {
            let sock = UdpSocket::bind(bind).unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut buf = [0u8; 2048];
            let (n, from) = sock.recv_from(&mut buf).unwrap();
            let resp_secret = LocalSecret::generate(&mut OsEntropy::new().unwrap(), 32);
            let faked_source = SocketAddr::new(from.ip(), from.port().wrapping_add(1));
            let result = responder_respond_natt(&buf[..n], &resp_secret, bind, faked_source, None).unwrap();
            let response = match result {
                crate::ikev2::exchange::SaInitResult::Established { response, .. } => response,
                _ => panic!("expected Established"),
            };
            sock.send_to(&response, from).unwrap();
        });
        thread::sleep(Duration::from_millis(50));

        let mut session = Ikev2Session::new(OsEntropy::new().unwrap());
        let local_port = next_addr().port();
        let (sock, our_addr, _sa, nat) = session.sa_init_on_port(bind, &default_ike_offer(), local_port).unwrap();
        responder.join().unwrap();

        assert!(nat.float_to_4500(), "the responder's faked source address must trigger floating");
        let expected_natt_port = natt_local_port(local_port);
        assert_eq!(
            sock.local_addr().unwrap().port(),
            expected_natt_port,
            "the returned socket must actually be bound to the floated port, not just report it"
        );
        assert_eq!(our_addr.port(), expected_natt_port);

        // The client must genuinely hold the floated port -- not just claim
        // it in `our_addr` -- otherwise anything the peer sends there once
        // floated (its own retransmits, or real ESP-in-UDP data-plane
        // traffic once a kernel XFRM SA is installed) has nowhere to land
        // and is silently dropped by the OS. This is the exact bug: the old
        // code never bound this port at all.
        match UdpSocket::bind(("0.0.0.0", expected_natt_port)) {
            Err(e) if e.kind() == io::ErrorKind::AddrInUse => {}
            other => panic!("expected AddrInUse (port genuinely held by `sock`), got {other:?}"),
        }

        // ...and it must release the pre-float port rather than holding both
        // indefinitely, matching `sa_init_on_port`'s doc (the unused half of
        // the pair is dropped, not kept open).
        UdpSocket::bind(("0.0.0.0", local_port)).expect("the pre-float port must be released once floated");
    }

    /// A minimal in-process IKEv2 responder over loopback UDP, PSK-only,
    /// no EAP, no CFG — just enough to exercise `connect_direct` end-to-end
    /// without a real gateway.
    fn run_psk_responder(bind: SocketAddr, psk: Vec<u8>) {
        let sock = UdpSocket::bind(bind).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut buf = [0u8; 4096];
        let (n, from) = sock.recv_from(&mut buf).unwrap();
        let resp_secret = LocalSecret::generate(&mut OsEntropy::new().unwrap(), 32);
        let result = responder_respond_natt(&buf[..n], &resp_secret, bind, from, None).unwrap();
        let (response, sa) = match result {
            crate::ikev2::exchange::SaInitResult::Established { response, sa } => (response, sa),
            _ => panic!("expected Established"),
        };
        sock.send_to(&response, from).unwrap();

        let (n, from) = sock.recv_from(&mut buf).unwrap();
        let rcfg = AuthConfig::psk(Identification::fqdn("responder.test"), psk);
        let (resp, _peer_id, _spi, _ic) =
            responder_process_auth(&sa, &buf[..n], &rcfg, 0xC0FFEE, &[9u8; 8], None).unwrap();
        sock.send_to(&resp, from).unwrap();
    }

    /// Same as [`run_psk_responder`], but sends its `IKE_AUTH` response as
    /// several RFC 7383 `SKF` fragments instead of one `SK` message -- e.g.
    /// what a real gateway does when a Cert+EAP `IKE_AUTH` reply (large
    /// certificate chain) exceeds its fragmentation threshold. Reproduces
    /// the bug report: the client received the header
    /// `...DE1073520232000000001000004642400...` with Next Payload `0x35`
    /// (`SKF`) and failed with `MissingPayload("SK")` because nothing ever
    /// reassembled it.
    fn run_psk_responder_fragmented(bind: SocketAddr, psk: Vec<u8>) {
        let sock = UdpSocket::bind(bind).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut buf = [0u8; 4096];
        let (n, from) = sock.recv_from(&mut buf).unwrap();
        let resp_secret = LocalSecret::generate(&mut OsEntropy::new().unwrap(), 32);
        let result = responder_respond_natt(&buf[..n], &resp_secret, bind, from, None).unwrap();
        let (response, sa) = match result {
            crate::ikev2::exchange::SaInitResult::Established { response, sa } => (response, sa),
            _ => panic!("expected Established"),
        };
        sock.send_to(&response, from).unwrap();

        let (n, from) = sock.recv_from(&mut buf).unwrap();
        let rcfg = AuthConfig::psk(Identification::fqdn("responder.test"), psk);
        let (resp, _peer_id, _spi, _ic) =
            responder_process_auth(&sa, &buf[..n], &rcfg, 0xC0FFEE, &[9u8; 8], None).unwrap();

        // Split the already-built single-SK response back into its inner
        // payloads, then reseal them as three small SKF fragments -- same
        // cipher/keys, just RFC-7383-shaped on the wire.
        let cipher = sa.suite.sk_cipher();
        let (first_inner, inner) = open_encrypted(cipher, &resp, &sa.keys.sk_er, &sa.keys.sk_ar).unwrap();
        let header = IkeHeader::parse(&resp).unwrap();
        let content_per_fragment = (inner.len() / 3).max(1);
        let fragments =
            fragment::build_fragments(cipher, &header, first_inner, &inner, &sa.keys.sk_er, &sa.keys.sk_ar, 42, content_per_fragment)
                .unwrap();
        assert!(fragments.len() > 1, "test setup: expected the response to actually need multiple fragments");
        for frag in &fragments {
            sock.send_to(frag, from).unwrap();
        }
    }

    #[test]
    fn connect_direct_reassembles_a_fragmented_ike_auth_response() {
        let bind = next_addr();
        let psk = b"shared-secret".to_vec();
        let responder = thread::spawn({
            let psk = psk.clone();
            move || run_psk_responder_fragmented(bind, psk)
        });
        thread::sleep(Duration::from_millis(50));

        let mut session = Ikev2Session::new(OsEntropy::new().unwrap());
        let cfg = AuthConfig::psk(Identification::fqdn("client.test"), psk);
        let tunnel = session
            .connect_direct_on_port(bind, &default_ike_offer(), &cfg, false, &default_esp_offer(), next_addr().port())
            .unwrap();
        assert_eq!(tunnel.peer_spi, 0xC0FFEE);
        responder.join().unwrap();
    }

    #[test]
    fn granted_subnets_prefers_cfg_over_ts_when_both_are_present() {
        use crate::ikev2::payload::TrafficSelector;

        let ts = TrafficSelectors { selectors: vec![TrafficSelector::ipv4_any()] };
        let cfg = (Ipv4Addr::new(10, 0, 99, 0), 24);

        // Gateway granted full-tunnel TS but also sent a narrower CFG
        // subnet -- CFG wins outright, TS is not merged in alongside it.
        assert_eq!(granted_subnets(Some(&ts), &[cfg]), vec![cfg]);

        // No CFG subnet at all -- fall back to what TS granted.
        assert_eq!(
            granted_subnets(Some(&ts), &[]),
            vec![(Ipv4Addr::new(0, 0, 0, 0), 0)]
        );

        // Neither source yielded anything.
        assert_eq!(granted_subnets(None, &[]), Vec::<(Ipv4Addr, u8)>::new());
    }

    #[test]
    fn granted_subnets_v6_prefers_cfg_subnets_then_falls_back_to_tsr() {
        use crate::ikev2::payload::TrafficSelector;
        let full = TrafficSelectors { selectors: vec![TrafficSelector::ipv4_any(), TrafficSelector::ipv6_any()] };
        let cfg = (Ipv6Addr::new(0x2001, 0x470, 0xda14, 1, 0, 0, 0, 0), 64);

        // An explicit INTERNAL_IP6_SUBNET is a routing instruction and wins.
        assert_eq!(granted_subnets_v6(Some(&full), &[cfg]), vec![cfg]);
        // No CFG subnet: the granted TSr says what the CHILD SA carries -- `::/0` is a full tunnel.
        assert_eq!(granted_subnets_v6(Some(&full), &[]), vec![(Ipv6Addr::UNSPECIFIED, 0)]);
        // The responder narrowed the IPv6 selector away (v4-only or
        // IPv6-unconfigured gateway): the CHILD SA carries no IPv6.
        let v4_only = TrafficSelectors { selectors: vec![TrafficSelector::ipv4_any()] };
        assert_eq!(granted_subnets_v6(Some(&v4_only), &[]), Vec::<(Ipv6Addr, u8)>::new());
        assert_eq!(granted_subnets_v6(None, &[]), Vec::<(Ipv6Addr, u8)>::new());
    }

    #[test]
    fn granted_subnets_keeps_every_cfg_subnet_the_responder_sent() {
        // A responder (e.g. FortiGate) can send more than one
        // INTERNAL_IP4_SUBNET attribute -- one per split-tunnel range. All
        // of them must survive, not just the first.
        let cfgs = [
            (Ipv4Addr::new(10, 0, 1, 0), 24),
            (Ipv4Addr::new(10, 0, 2, 0), 24),
            (Ipv4Addr::new(192, 168, 50, 0), 24),
        ];
        assert_eq!(granted_subnets(None, &cfgs), cfgs.to_vec());
    }

    #[test]
    fn connect_direct_psk_against_a_loopback_responder() {
        let bind = next_addr();
        let psk = b"shared-secret".to_vec();
        let responder = thread::spawn({
            let psk = psk.clone();
            move || run_psk_responder(bind, psk)
        });
        // Give the responder a moment to bind before the client sends.
        thread::sleep(Duration::from_millis(50));

        let mut session = Ikev2Session::new(OsEntropy::new().unwrap());
        let cfg = AuthConfig::psk(Identification::fqdn("client.test"), psk);
        let tunnel = session
            .connect_direct_on_port(bind, &default_ike_offer(), &cfg, false, &default_esp_offer(), next_addr().port())
            .unwrap();
        assert_eq!(tunnel.peer_spi, 0xC0FFEE);
        assert_eq!(tunnel.key_out.cipher, SkCipher::Aes256Gcm);
        assert_ne!(tunnel.key_out.enc, vec![0u8; tunnel.key_out.enc.len()]);
        assert_ne!(tunnel.key_in.enc, vec![0u8; tunnel.key_in.enc.len()]);
        assert_ne!(tunnel.key_out, tunnel.key_in);
        responder.join().unwrap();
    }

    /// The point of `connect_direct_with_sockets`: a worker process that
    /// binds the well-known ports once and reuses them across every connect
    /// (like charon/strongSwan/OpenIKED all do -- see `sa_init_with_sockets`'s
    /// doc) must still hold them after a tunnel disconnects, not just while
    /// one happens to be up. Proven here by handing the session
    /// `UdpSocket::try_clone()`'d handles (exactly what a real worker would
    /// do per connect attempt) and confirming the *caller's own originals*
    /// are still alive and bound to the same ports after the returned
    /// `ConnectedTunnel` (and the clone it consumed) is dropped -- a real
    /// disconnect's exact shape.
    #[test]
    fn connect_direct_with_sockets_leaves_the_callers_original_handles_bound_after_the_tunnel_drops() {
        let bind = next_addr();
        let psk = b"shared-secret".to_vec();
        let responder = thread::spawn({
            let psk = psk.clone();
            move || run_psk_responder(bind, psk)
        });
        thread::sleep(Duration::from_millis(50));

        let local_port = next_addr().port();
        let natt_port = natt_local_port(local_port);
        let held_sock = UdpSocket::bind(("0.0.0.0", local_port)).unwrap();
        let held_natt_sock = UdpSocket::bind(("0.0.0.0", natt_port)).unwrap();

        let mut session = Ikev2Session::new(OsEntropy::new().unwrap());
        let cfg = AuthConfig::psk(Identification::fqdn("client.test"), psk);
        let tunnel = session
            .connect_direct_with_sockets(
                bind,
                &default_ike_offer(),
                &cfg,
                false,
                &default_esp_offer(),
                held_sock.try_clone().unwrap(),
                held_natt_sock.try_clone().unwrap(),
            )
            .unwrap();
        assert_eq!(tunnel.peer_spi, 0xC0FFEE);
        responder.join().unwrap();

        drop(tunnel);

        // The caller's own handles must still work -- both a local re-query
        // and, more convincingly, that nothing else can steal the port out
        // from under them.
        assert_eq!(held_sock.local_addr().unwrap().port(), local_port);
        assert_eq!(held_natt_sock.local_addr().unwrap().port(), natt_port);
        match UdpSocket::bind(("0.0.0.0", local_port)) {
            Err(e) if e.kind() == io::ErrorKind::AddrInUse => {}
            other => panic!("expected AddrInUse (held_sock must still own this port), got {other:?}"),
        }
    }

    /// Extends [`run_psk_responder`]'s handshake with one `CREATE_CHILD_SA`
    /// rekey round, returning the responder's resulting `ChildSa`, plus
    /// whatever SPI (if any) the client's own follow-up ESP Delete named --
    /// [`LivenessSession::rekey_child`] is expected to explicitly retire the
    /// CHILD SA it just replaced (see that function's own doc), so a caller
    /// can check the SPI named is the *old* one, not the freshly-rekeyed one.
    fn run_psk_responder_then_rekey(bind: SocketAddr, psk: Vec<u8>, pfs_group: Option<DhGroup>) -> (crate::esp::ChildSa, Option<u32>) {
        let sock = UdpSocket::bind(bind).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut buf = [0u8; 4096];
        let (n, from) = sock.recv_from(&mut buf).unwrap();
        let resp_secret = LocalSecret::generate(&mut OsEntropy::new().unwrap(), 32);
        let result = responder_respond_natt(&buf[..n], &resp_secret, bind, from, None).unwrap();
        let (response, sa) = match result {
            crate::ikev2::exchange::SaInitResult::Established { response, sa } => (response, sa),
            _ => panic!("expected Established"),
        };
        sock.send_to(&response, from).unwrap();

        let (n, from) = sock.recv_from(&mut buf).unwrap();
        let rcfg = AuthConfig::psk(Identification::fqdn("responder.test"), psk);
        let (resp, _peer_id, _spi, _ic) =
            responder_process_auth(&sa, &buf[..n], &rcfg, 0xC0FFEE, &[9u8; 8], None).unwrap();
        sock.send_to(&resp, from).unwrap();

        let (n, from) = sock.recv_from(&mut buf).unwrap();
        let dh_private = pfs_group.map(|_| [6u8; 32]);
        let (resp2, child) = rekey::responder_process_rekey_with_pfs(
            &sa,
            &buf[..n],
            0xFEED_FACE,
            &[0x77u8; 32],
            SkCipher::Aes256Gcm,
            dh_private.as_ref().map(|p| p.as_slice()),
            &[8u8; 8],
            None,
        )
        .unwrap();
        sock.send_to(&resp2, from).unwrap();

        // The client-side rekey should follow up with an unprompted ESP
        // Delete for the CHILD SA it just replaced -- read and decode it
        // (best-effort: a short timeout, so a caller not exercising this
        // still gets a well-defined `None` rather than hanging).
        sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let deleted_spi = match sock.recv_from(&mut buf) {
            Ok((n, _from)) => open_informational(&sa, &buf[..n])
                .ok()
                .and_then(|ps| ps.into_iter().find(|(t, _)| *t == PayloadType::Delete))
                .and_then(|(_, body)| Delete::parse(&body).ok())
                .filter(|d| d.protocol_id == protocol_id::ESP)
                .and_then(|d| d.spis.first().copied()),
            Err(_) => None,
        };
        (child, deleted_spi)
    }

    /// The end-to-end point of this whole feature: an IKEv2 tunnel connected
    /// with a PFS group configured (a DH transform on `esp_offer`) can never
    /// apply it at `IKE_AUTH` (RFC 7296 has no KE payload slot there) -- only
    /// [`LivenessSession::rekey_child`], driven here exactly as the worker's
    /// automatic-rekey trigger would, actually exercises it: fresh SPIs, a
    /// fresh PFS-derived key distinct from the original tunnel's, and real
    /// interop against an independent responder-side `ChildSa`.
    #[test]
    fn rekey_child_with_pfs_actually_rekeys_and_interoperates() {
        use crate::esp::{next_header, EspSa};
        use crate::ikev2::payload::{transform_type, Transform};

        let bind = next_addr();
        let psk = b"shared-secret".to_vec();
        let pfs_group = DhGroup::Modp2048;
        let responder = thread::spawn({
            let psk = psk.clone();
            move || run_psk_responder_then_rekey(bind, psk, Some(pfs_group))
        });
        thread::sleep(Duration::from_millis(50));

        let mut esp_offer = default_esp_offer();
        esp_offer.proposals[0].transforms.push(Transform {
            transform_type: transform_type::DH,
            transform_id: pfs_group.transform_id(),
            key_length: None,
        });

        let mut session = Ikev2Session::new(OsEntropy::new().unwrap());
        let cfg = AuthConfig::psk(Identification::fqdn("client.test"), psk);
        let mut tunnel = session
            .connect_direct_on_port(bind, &default_ike_offer(), &cfg, false, &esp_offer, next_addr().port())
            .unwrap();
        assert!(tunnel.liveness.pfs_configured(), "esp_offer carried a DH transform");

        let old_local_spi = tunnel.local_spi;
        let rekeyed = tunnel.liveness.rekey_child(Duration::from_secs(5)).unwrap();
        assert_ne!(rekeyed.local_spi, old_local_spi, "a rekey must allocate a fresh SPI, never reuse the old one");
        assert_ne!(rekeyed.key_out, tunnel.key_out, "PFS must yield a fresh key, not the original tunnel's");

        let (mut resp_child, deleted_spi) = responder.join().unwrap();
        // The regression check for the "old SA never gets deleted" bug:
        // the rekey must have explicitly retired the SA it just replaced,
        // naming *our own* old inbound SPI (RFC 7296 §3.10 -- a Delete
        // names the sender's own SPI, not the peer's), not the fresh one.
        assert_eq!(deleted_spi, Some(old_local_spi), "rekey_child must send an ESP Delete for the SA it just replaced");
        let mut client_out =
            EspSa::new_with_cipher(rekeyed.peer_spi, rekeyed.key_out.cipher, &rekeyed.key_out.enc, &rekeyed.key_out.integ).unwrap();
        let pkt = client_out.seal(b"after ikev2 pfs rekey", next_header::IPV4).unwrap();
        assert_eq!(resp_child.inbound.open(&pkt).unwrap().0, b"after ikev2 pfs rekey");
    }

    /// Windows' arrangement: a background thread (the ESP pump's reader) is
    /// the session socket's *only* reader and hands IKE datagrams to the
    /// session through `external_rx`, so the gateway's replies never show up
    /// on the session's own socket. Every `CREATE_CHILD_SA` -- a rekey, and
    /// the separate IPv6 CHILD SA too -- must still take its response from
    /// that channel. Modelled deterministically: a proxy sits between the
    /// session and the responder and delivers the responder's replies to the
    /// channel only, never to the socket.
    #[test]
    fn child_exchange_takes_its_response_from_external_rx_when_the_socket_never_sees_it() {
        use crate::esp::{next_header, EspSa};
        use std::sync::atomic::AtomicBool;
        use std::sync::Arc;

        let bind = next_addr();
        let psk = b"shared-secret".to_vec();
        let responder = thread::spawn({
            let psk = psk.clone();
            move || run_psk_responder_then_rekey(bind, psk, None)
        });
        thread::sleep(Duration::from_millis(50));

        let mut session = Ikev2Session::new(OsEntropy::new().unwrap());
        let cfg = AuthConfig::psk(Identification::fqdn("client.test"), psk);
        let mut tunnel = session
            .connect_direct_on_port(bind, &default_ike_offer(), &cfg, false, &default_esp_offer(), next_addr().port())
            .unwrap();

        let proxy = UdpSocket::bind("127.0.0.1:0").unwrap();
        proxy.set_read_timeout(Some(Duration::from_millis(100))).unwrap();
        let proxy_addr = proxy.local_addr().unwrap();
        let (tx, rx) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let proxy_thread = thread::spawn({
            let stop = stop.clone();
            move || {
                let mut buf = [0u8; 8192];
                while !stop.load(Ordering::Relaxed) {
                    match proxy.recv_from(&mut buf) {
                        Ok((n, from)) if from == bind => {
                            let _ = tx.send(buf[..n].to_vec());
                        }
                        Ok((n, _client)) => {
                            let _ = proxy.send_to(&buf[..n], bind);
                        }
                        Err(_) => {}
                    }
                }
            }
        });
        tunnel.liveness.dest = proxy_addr;
        tunnel.liveness.install_external_receiver(rx);

        let old_local_spi = tunnel.local_spi;
        let rekeyed = tunnel.liveness.rekey_child(Duration::from_secs(3));
        stop.store(true, Ordering::Relaxed);
        proxy_thread.join().unwrap();
        let rekeyed = rekeyed.expect("the CREATE_CHILD_SA response never reached the session");
        assert_ne!(rekeyed.local_spi, old_local_spi);

        let (mut resp_child, deleted_spi) = responder.join().unwrap();
        assert_eq!(deleted_spi, Some(old_local_spi));
        let mut client_out =
            EspSa::new_with_cipher(rekeyed.peer_spi, rekeyed.key_out.cipher, &rekeyed.key_out.enc, &rekeyed.key_out.integ).unwrap();
        let pkt = client_out.seal(b"after a rekey answered through external_rx", next_header::IPV4).unwrap();
        assert_eq!(resp_child.inbound.open(&pkt).unwrap().0, b"after a rekey answered through external_rx");
    }

    /// A session over a throwaway loopback socket, for exercising
    /// [`LivenessSession::recv_datagram`] on its own.
    fn recv_test_session(external_rx: Option<mpsc::Receiver<Vec<u8>>>) -> LivenessSession {
        let (init_sa, _resp_sa) = liveness_sa_pair();
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let dest = sock.local_addr().unwrap();
        LivenessSession { sock, sa: init_sa, dest, float: false, next_message_id: 2, cipher: SkCipher::Aes256Gcm, pfs_group: None, child_local_spi: 0, child_peer_spi: 0, external_rx, child6: None, cfg_subnets6: Vec::new() }
    }

    #[test]
    fn recv_datagram_reads_the_socket_when_no_external_receiver_is_installed() {
        let session = recv_test_session(None);
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        session.sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        sender.send_to(b"from the socket", session.sock.local_addr().unwrap()).unwrap();
        let mut buf = [0u8; 64];
        let n = session.recv_datagram(&mut buf, Duration::from_secs(2)).unwrap();
        assert_eq!(&buf[..n], b"from the socket");

        session.sock.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        let e = session.recv_datagram(&mut buf, Duration::from_millis(50)).unwrap_err();
        assert!(matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut), "got {e:?}");
    }

    #[test]
    fn recv_datagram_reads_the_external_receiver_and_never_the_socket_when_one_is_installed() {
        let (tx, rx) = mpsc::channel();
        let session = recv_test_session(Some(rx));
        // A datagram on the socket itself must stay invisible: another
        // thread owns that socket in this arrangement.
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender.send_to(b"on the socket", session.sock.local_addr().unwrap()).unwrap();
        tx.send(b"through the channel".to_vec()).unwrap();
        let mut buf = [0u8; 64];
        let n = session.recv_datagram(&mut buf, Duration::from_secs(2)).unwrap();
        assert_eq!(&buf[..n], b"through the channel");

        let e = session.recv_datagram(&mut buf, Duration::from_millis(50)).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        drop(tx);
        let e = session.recv_datagram(&mut buf, Duration::from_millis(50)).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::BrokenPipe);
    }

    /// Responder for the IPv6 CHILD SA flow: the same handshake, then a
    /// `CREATE_CHILD_SA` creating the IPv6 CHILD SA, then one rekeying it
    /// (each answered by echoing the initiator's selectors, as a gateway with
    /// a `::/0` Phase 2 would), then the client's ESP Delete for the SA the
    /// rekey replaced.
    fn run_psk_responder_then_ipv6_child(bind: SocketAddr, psk: Vec<u8>) -> (crate::esp::ChildSa, crate::esp::ChildSa, Option<u32>) {
        let sock = UdpSocket::bind(bind).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut buf = [0u8; 4096];
        let (n, from) = sock.recv_from(&mut buf).unwrap();
        let resp_secret = LocalSecret::generate(&mut OsEntropy::new().unwrap(), 32);
        let result = responder_respond_natt(&buf[..n], &resp_secret, bind, from, None).unwrap();
        let (response, sa) = match result {
            crate::ikev2::exchange::SaInitResult::Established { response, sa } => (response, sa),
            _ => panic!("expected Established"),
        };
        sock.send_to(&response, from).unwrap();

        let (n, from) = sock.recv_from(&mut buf).unwrap();
        let rcfg = AuthConfig::psk(Identification::fqdn("responder.test"), psk);
        let (resp, _peer_id, _spi, _ic) =
            responder_process_auth(&sa, &buf[..n], &rcfg, 0xC0FFEE, &[9u8; 8], None).unwrap();
        sock.send_to(&resp, from).unwrap();

        let mut children = Vec::new();
        for (spi, iv) in [(0xFEED_FACEu32, [8u8; 8]), (0xFEED_F00D, [7u8; 8])] {
            let (n, from) = sock.recv_from(&mut buf).unwrap();
            let (resp, child) = rekey::responder_process_rekey_with_pfs(
                &sa, &buf[..n], spi, &[0x77u8; 32], SkCipher::Aes256Gcm, None, &iv, None,
            )
            .unwrap();
            sock.send_to(&resp, from).unwrap();
            children.push(child);
        }
        sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let deleted_spi = match sock.recv_from(&mut buf) {
            Ok((n, _from)) => open_informational(&sa, &buf[..n])
                .ok()
                .and_then(|ps| ps.into_iter().find(|(t, _)| *t == PayloadType::Delete))
                .and_then(|(_, body)| Delete::parse(&body).ok())
                .filter(|d| d.protocol_id == protocol_id::ESP)
                .and_then(|d| d.spis.first().copied()),
            Err(_) => None,
        };
        let second = children.pop().unwrap();
        let first = children.pop().unwrap();
        (first, second, deleted_spi)
    }

    /// IPv6 gets a CHILD SA of its own, next to the IPv4 one IKE_AUTH made
    /// (a gateway like FortiGate keeps them as separate Phase 2 selectors):
    /// `create_child_ipv6` negotiates it with fresh SPIs/keys and reports the
    /// `::/0` the gateway granted, and `rekey_child_ipv6` rekeys *that* SA --
    /// naming its SPI, not the IPv4 one's -- leaving the IPv4 CHILD SA alone.
    #[test]
    fn ipv6_child_sa_is_created_and_rekeyed_separately_from_the_ipv4_one() {
        use crate::esp::{next_header, EspSa};

        let bind = next_addr();
        let psk = b"shared-secret".to_vec();
        let responder = thread::spawn({
            let psk = psk.clone();
            move || run_psk_responder_then_ipv6_child(bind, psk)
        });
        thread::sleep(Duration::from_millis(50));

        let mut session = Ikev2Session::new(OsEntropy::new().unwrap());
        let cfg = AuthConfig::psk(Identification::fqdn("client.test"), psk);
        let mut tunnel = session
            .connect_direct_on_port(bind, &default_ike_offer(), &cfg, false, &default_esp_offer(), next_addr().port())
            .unwrap();
        assert!(!tunnel.liveness.has_ipv6_child());
        let v4_local_spi = tunnel.local_spi;

        let v6 = tunnel.liveness.create_child_ipv6(Duration::from_secs(5)).unwrap();
        assert!(tunnel.liveness.has_ipv6_child());
        assert_eq!(v6.granted_subnets6, vec![(Ipv6Addr::UNSPECIFIED, 0)], "the echoed ::/0 is a full IPv6 tunnel");
        assert_ne!(v6.child.local_spi, v4_local_spi);
        assert_ne!(v6.child.key_out, tunnel.key_out, "the IPv6 CHILD SA has keys of its own");
        assert!(tunnel.liveness.create_child_ipv6(Duration::from_secs(5)).is_err(), "only one IPv6 CHILD SA per tunnel");

        let rekeyed = tunnel.liveness.rekey_child_ipv6(Duration::from_secs(5)).unwrap();
        assert_ne!(rekeyed.local_spi, v6.child.local_spi);
        assert_eq!(tunnel.liveness.child_local_spi, v4_local_spi, "rekeying IPv6 leaves the IPv4 CHILD SA's SPIs alone");

        let (first, mut second, deleted_spi) = responder.join().unwrap();
        drop(first);
        assert_eq!(deleted_spi, Some(v6.child.local_spi), "the IPv6 rekey must retire the IPv6 CHILD SA, not the IPv4 one");
        let mut client_out =
            EspSa::new_with_cipher(rekeyed.peer_spi, rekeyed.key_out.cipher, &rekeyed.key_out.enc, &rekeyed.key_out.integ).unwrap();
        let pkt = client_out.seal(b"after ipv6 rekey", next_header::IPV6).unwrap();
        assert_eq!(second.inbound.open(&pkt).unwrap().0, b"after ipv6 rekey");
    }

    /// A minimal in-process EAP-MSCHAPv2 responder (PSK server auth) over
    /// loopback UDP, driving `EapResponder` directly.
    fn run_eap_responder(bind: SocketAddr, group_psk: Vec<u8>, user: Vec<u8>, password: String) {
        let sock = UdpSocket::bind(bind).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut entropy = OsEntropy::new().unwrap();
        let mut buf = [0u8; 4096];

        let (n, from) = sock.recv_from(&mut buf).unwrap();
        let resp_secret = LocalSecret::generate(&mut OsEntropy::new().unwrap(), 32);
        let result = responder_respond_natt(&buf[..n], &resp_secret, bind, from, None).unwrap();
        let (response, sa) = match result {
            crate::ikev2::exchange::SaInitResult::Established { response, sa } => (response, sa),
            _ => panic!("expected Established"),
        };
        sock.send_to(&response, from).unwrap();

        let mut responder = EapResponder::new(
            sa,
            Identification::fqdn("gw.test"),
            ServerAuth::Psk(group_psk),
            user,
            password,
            0xBEEF,
        );
        loop {
            let (n, from) = sock.recv_from(&mut buf).unwrap();
            match responder.handle(&buf[..n], &mut entropy).unwrap() {
                EapEvent::Reply(m) => sock.send_to(&m, from).unwrap(),
                EapEvent::Established(Some(m)) => {
                    sock.send_to(&m, from).unwrap();
                    return;
                }
                EapEvent::Established(None) => return,
                EapEvent::Failed(_) => panic!("responder failed the exchange"),
            };
        }
    }

    #[test]
    fn connect_eap_against_a_loopback_responder() {
        let bind = next_addr();
        let group_psk = b"group-psk".to_vec();
        let user = b"alice".to_vec();
        let password = "s3cret".to_string();
        let responder = thread::spawn({
            let group_psk = group_psk.clone();
            let user = user.clone();
            let password = password.clone();
            move || run_eap_responder(bind, group_psk, user, password)
        });
        thread::sleep(Duration::from_millis(50));

        let mut session = Ikev2Session::new(OsEntropy::new().unwrap());
        let creds = EapCreds { user, password };
        let tunnel = session
            .connect_eap_on_port(
                bind,
                &default_ike_offer(),
                Identification::fqdn("client.test"),
                creds,
                ServerVerify::Psk(group_psk),
                true,
                &default_esp_offer(),
                next_addr().port(),
            )
            .unwrap();
        assert_eq!(tunnel.peer_spi, 0xBEEF);
        assert_ne!(tunnel.key_out, tunnel.key_in);
        responder.join().unwrap();
    }

    /// `connect_eap_with_client_cert_and_sockets` (the "Certificate + EAP"
    /// hybrid a FortiGate dialup policy can require) against the *same*
    /// plain `run_eap_responder` the test above uses, completely unmodified
    /// -- proving the extra CERT payload it attaches to the
    /// EAP-triggering first message don't break a real, spec-conformant
    /// EAP-MSCHAPv2 responder that simply doesn't look for them. `ryke`
    /// only implements the initiator side of this hybrid (this project's
    /// own EAP responder isn't Fortinet-specific), so this is the strongest
    /// test coverage available without a real FortiGate.
    #[test]
    fn connect_eap_with_client_cert_completes_against_a_plain_loopback_responder() {
        use crate::test_certs::LEAF_CERT_DER;
        let bind = next_addr();
        let group_psk = b"group-psk".to_vec();
        let user = b"alice".to_vec();
        let password = "s3cret".to_string();
        let responder = thread::spawn({
            let group_psk = group_psk.clone();
            let user = user.clone();
            let password = password.clone();
            move || run_eap_responder(bind, group_psk, user, password)
        });
        thread::sleep(Duration::from_millis(50));

        let sock = UdpSocket::bind(next_addr()).unwrap();
        let natt_sock = UdpSocket::bind(next_addr()).unwrap();
        let mut session = Ikev2Session::new(OsEntropy::new().unwrap());
        let creds = EapCreds { user, password };
        let tunnel = session
            .connect_eap_with_client_cert_and_sockets(
                bind,
                &default_ike_offer(),
                Identification::fqdn("client.example"),
                creds,
                ServerVerify::Psk(group_psk),
                &[LEAF_CERT_DER.to_vec()],
                true,
                &default_esp_offer(),
                sock,
                natt_sock,
            )
            .unwrap();
        assert_eq!(tunnel.peer_spi, 0xBEEF);
        assert_ne!(tunnel.key_out, tunnel.key_in);
        responder.join().unwrap();
    }

    #[test]
    fn eap_server_verify_failure_notifies_the_gateway_with_an_informational_delete() {
        // Without `notify_ike_sa_delete_on_failed_auth`, a rejected
        // authentication just dropped the socket -- the gateway (e.g. a
        // FortiGate) was left holding a half-open IKE_SA until its own idle
        // timeout. The client must tell it instead.
        //
        // Easiest failure to trigger without a real gateway: the client's
        // own `ServerVerify::Psk` doesn't match what the responder actually
        // used to authenticate itself. This fails purely in the client's
        // application-level check (`EapInitiator::verify_server`) -- the
        // responder's genuine first EAP message still decrypts and parses
        // fine (`SK_e`/`SK_a` come from `IKE_SA_INIT`'s DH exchange, not
        // this PSK), so the responder here behaves exactly like a real one
        // that has no idea anything is wrong, right up until it gets our
        // Delete instead of the EAP response it was expecting.
        let bind = next_addr();
        let group_psk = b"group-psk".to_vec();
        let responder = thread::spawn(move || {
            let sock = UdpSocket::bind(bind).unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut buf = [0u8; 4096];

            let (n, from) = sock.recv_from(&mut buf).unwrap();
            let resp_secret = LocalSecret::generate(&mut OsEntropy::new().unwrap(), 32);
            let result = responder_respond_natt(&buf[..n], &resp_secret, bind, from, None).unwrap();
            let (response, sa) = match result {
                crate::ikev2::exchange::SaInitResult::Established { response, sa } => (response, sa),
                _ => panic!("expected Established"),
            };
            sock.send_to(&response, from).unwrap();

            let mut eap_responder =
                EapResponder::new(sa.clone(), Identification::fqdn("gw.test"), ServerAuth::Psk(group_psk), b"alice".to_vec(), "s3cret".to_string(), 0xBEEF);
            let (n, from) = sock.recv_from(&mut buf).unwrap();
            match eap_responder.handle(&buf[..n], &mut OsEntropy::new().unwrap()).unwrap() {
                EapEvent::Reply(m) => sock.send_to(&m, from).unwrap(),
                other => panic!("expected the responder's IDr/AUTH/EAP-Identity reply, got {other:?}"),
            };

            // The client's `verify_server` rejects this genuine reply (its
            // own `ServerVerify::Psk` is different from `group_psk` above)
            // and must notify us instead of just going silent.
            let (n, _from) = sock.recv_from(&mut buf).unwrap();
            let ps = open_informational(&sa, &buf[..n]).unwrap();
            assert!(ps.iter().any(|(t, _)| *t == PayloadType::Delete));
        });
        thread::sleep(Duration::from_millis(50));

        let mut session = Ikev2Session::new(OsEntropy::new().unwrap());
        let creds = EapCreds { user: b"alice".to_vec(), password: "s3cret".to_string() };
        let result = session.connect_eap_on_port(
            bind,
            &default_ike_offer(),
            Identification::fqdn("client.test"),
            creds,
            ServerVerify::Psk(b"not-the-real-group-psk".to_vec()),
            true,
            &default_esp_offer(),
            next_addr().port(),
        );
        match result {
            Err(DriverError::Ike(IkeError::AuthFailed)) => {}
            other => panic!("expected Err(DriverError::Ike(IkeError::AuthFailed)), got {}", other.is_ok()),
        }
        responder.join().unwrap();
    }
}
