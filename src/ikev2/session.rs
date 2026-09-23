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
use std::time::{Duration, Instant};

use crate::crypto::{derive_child_keys, DhGroup, IntegAlgorithm};
use crate::debug::ike_debug;
use crate::entropy::{Entropy, OsEntropy};
use crate::error::IkeError;
use crate::esp::ChildSa;
use crate::ikev2::eap_auth::{EapEvent, EapInitiator, ServerVerify};
use crate::ikev2::exchange::{
    default_offer, initiator_complete_natt, initiator_request_natt_retry, CompletedSaInit, LocalSecret,
    NatStatus,
};
use crate::ikev2::fragment::{self, Accepted, MessageKey, Reassembly};
use crate::ikev2::ike_auth::{self, AuthConfig, ChildTsOffer};
use crate::ikev2::ike_rekey;
use crate::ikev2::informational::{
    build_error_response, build_informational, deletes_in, dpd_request, open_from_peer, payload_list, peer_sk_a, peer_sk_e, request_error_notify,
};
use crate::ikev2::message::{payloads, ExchangeType, IkeHeader, PayloadType};
use crate::ikev1::quick::{ChildKeyMaterial, RekeyedChild};
use crate::ikev2::natt::{unwrap_ike_4500, wrap_ike_4500};
use crate::ikev2::negotiate::{self, ChosenEspSuite};
use crate::ikev2::payload::{
    notify_type, notify_type_name, protocol_id, Configuration, Delete, Identification, SecurityAssociation, TrafficSelectors,
};
use crate::ikev2::rekey::{self, PfsKeyExchange, PfsPolicy};
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
    /// The IPv6 ranges the primary CHILD SA itself carries -- non-empty only
    /// when a unified IPv4+IPv6 offer ([`Ikev2Session::with_unified_ts`]) was
    /// granted with both families (same precedence as
    /// [`Ipv6Child::granted_subnets6`]: CFG's split ranges, else the granted
    /// `TSr`). Empty on every other connect, where IPv6 (if the gateway does
    /// it at all) comes from a CHILD SA of its own,
    /// [`LivenessSession::create_child_ipv6`].
    pub child_subnets6: Vec<(Ipv6Addr, u8)>,
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

/// One CHILD SA's inbound SPI (the one *we* expect on ESP packets), tracked
/// per SA: both a rekey's `REKEY_SA` notify (RFC 7296 §1.3.3) and the
/// post-rekey Delete name that value, not the peer's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ChildSpis {
    local: u32,
    /// What the peer expects on the ESP we send it: the `REKEY_SA` a *peer*-started rekey names.
    peer: u32,
}

impl ChildSpis {
    fn of(child: &RekeyedChild) -> Self {
        ChildSpis { local: child.local_spi, peer: child.peer_spi }
    }
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

/// How long the IKE SA a peer-started rekey replaced stays recognisable: the
/// peer deletes it moments after the exchange, and may retransmit the rekey
/// request if our answer never reached it.
const RETIRED_IKE_SA_TTL: Duration = Duration::from_secs(60);

/// How many of an IKE SA's last Message IDs only a rekey or Delete of the IKE
/// SA may use, so that one can still be sent once the others have run out
/// (RFC 7296 §2.2) -- enough for a rekey retried many times over, the Delete
/// of the IKE SA it replaces, and a close.
const MESSAGE_IDS_KEPT_FOR_ENDING: u32 = 64;

/// An IKE SA this session has moved on from that the *peer* deletes: the one
/// its rekey replaced (RFC 7296 §2.18), or the redundant one its rekey made
/// when both ends rekeyed at once (§2.8.2). The peer still talks under its
/// keys for a moment: it deletes it with an INFORMATIONAL on it, which is
/// routine cleanup and not the tunnel going down.
struct RetiredIkeSa {
    sa: CompletedSaInit,
    /// Its receive window, which goes on as it was (RFC 7296 §2.2).
    requests: PeerRequests,
    since: Instant,
}

impl RetiredIkeSa {
    fn new(sa: CompletedSaInit, requests: PeerRequests) -> Self {
        RetiredIkeSa { sa, requests, since: Instant::now() }
    }
}

/// Which of this session's IKE SAs a message from the peer is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OnIkeSa {
    Current,
    Retired,
}

/// A request from the peer this session answered, and the answer as sent.
struct AnsweredRequest {
    message_id: u32,
    request: Vec<u8>,
    response: Vec<u8>,
    /// Whether it ended the tunnel.
    tears_down: bool,
}

/// The receiving side of an IKE SA's Message IDs (RFC 7296 §2.1-§2.3): the
/// ID the peer's next request carries, and the answer to its last one. The
/// window is one request wide -- this side never sends `SET_WINDOW_SIZE` --
/// so the only request answered is the next one; the last one, sent again
/// byte for byte, is a retransmission and gets the same answer without being
/// acted on again (§2.1), and anything else is dropped unanswered: an older
/// request is a replay, a later one is outside the window, and a different
/// request under the last one's ID is neither (INVALID_MESSAGE_ID, which may
/// be sent, is not, §2.3). Kept apart from the IDs of our own requests
/// (`LivenessSession::next_message_id`): the two ends number their requests
/// independently (§2.2).
#[derive(Default)]
struct PeerRequests {
    /// The Message ID of the peer's next request: 0 on a new IKE SA (RFC
    /// 7296 §2.2), both after the handshake -- the peer, its original
    /// responder, sent no request in it -- and after a rekey by either side
    /// (§2.18: the new IKE SA starts its counters over).
    next: u64,
    last: Option<AnsweredRequest>,
    /// The fragments in hand of the next request, if it comes fragmented
    /// (RFC 7383), and since when.
    fragments: Option<(Reassembly, Instant)>,
    /// The IKE SA is gone -- the peer deleted it (§1.4.1), or a request of
    /// its was answered `INVALID_SYNTAX` (§2.21.3): nothing but a
    /// retransmission of that last request is answered on it any more.
    gone: bool,
}

/// How long the fragments of a request from the peer are kept waiting for
/// the rest (RFC 7383 §2.6 recommends a responder wait as long as it would
/// for an answer as an initiator: [`RETRY_BACKOFFS`], all of it).
const FRAGMENT_REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(30);

/// What [`LivenessSession::take_fragment`] made of one fragment.
enum Fragmented {
    /// Nothing to act on yet (stored, or dropped).
    Pending,
    /// The last fragment of a message: the whole message, as one `SK`
    /// message.
    Whole(IkeHeader, Vec<u8>),
    /// Fragment 1 of the last request answered: the answer went out again.
    /// Whether that request ended the tunnel.
    AnsweredAgain { tears_down: bool },
}

/// Where this session's IKE SA is in its life -- see [`LivenessSession::rekey_ike`].
struct IkeSaState {
    /// When the current IKE SA came to be: the handshake, or the last rekey
    /// (started by either side).
    since: Instant,
    retired: Option<RetiredIkeSa>,
    /// The peer's last IKE SA rekey request this session answered and the
    /// answer (as sent), to resend if the peer retransmits the request because
    /// that answer was lost -- by then the IKE SA it went out on may be gone.
    answered_rekey: Option<(Vec<u8>, Vec<u8>)>,
    /// Our own rekey of the IKE SA, while its request is unanswered.
    rekeying: Option<OwnIkeRekey>,
    /// We are deleting the current IKE SA and wait for the answer: a rekey of
    /// it from the peer now collides with that (RFC 7296 §2.25.2).
    closing: bool,
}

impl IkeSaState {
    fn new() -> Self {
        IkeSaState { since: Instant::now(), retired: None, answered_rekey: None, rekeying: None, closing: false }
    }
}

/// What the peer did to the IKE SA while a rekey of ours was in flight.
#[derive(Default)]
struct OwnIkeRekey {
    /// The peer rekeyed it too (RFC 7296 §2.8.2).
    crossed: Option<CrossedIkeRekey>,
    /// Then deleted it: its rekey is done, it never saw ours, and no answer to
    /// ours is coming.
    old_deleted: bool,
}

/// The peer's own rekey of the IKE SA we are rekeying, answered as usual
/// (RFC 7296 §2.8.2): the IKE SA it made, and the lower of that exchange's
/// two nonces -- which of the two new IKE SAs is redundant is only known once
/// our own exchange's nonces are in too.
struct CrossedIkeRekey {
    sa: CompletedSaInit,
    lowest_nonce: Vec<u8>,
}

/// Which of the tunnel's CHILD SAs a rekey concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildKind {
    /// The one `IKE_AUTH` created (IPv4, or IPv4+IPv6 when the offer was unified).
    Primary,
    /// The separate IPv6 CHILD SA ([`LivenessSession::create_child_ipv6`]).
    Ipv6,
}

/// A CHILD SA rekey the *peer* started and this session answered: the new SA's
/// SPIs and keys, for the caller to put in place of the one it replaced (the
/// same shape [`LivenessSession::rekey_child`] returns for a rekey of our own).
pub struct PeerRekeyedChild {
    pub kind: ChildKind,
    pub child: RekeyedChild,
}

/// How long a CHILD SA the peer rekeyed away stays recognisable: the peer
/// deletes it right after the exchange, and that Delete is answered with ours.
const SUPERSEDED_CHILD_TTL: Duration = Duration::from_secs(60);

/// A CHILD SA the peer's rekey replaced, until its Delete has been answered.
struct SupersededChild {
    local_spi: u32,
    peer_spi: u32,
    since: Instant,
}

/// Where the peer-started CHILD SA rekeys this session took on are.
#[derive(Default)]
struct PeerChildState {
    /// Rekeys answered but not yet collected ([`LivenessSession::take_peer_rekeys`]).
    pending: Vec<PeerRekeyedChild>,
    superseded: Vec<SupersededChild>,
    /// A CHILD SA the peer deleted outright (not superseding it with a rekey)
    /// while the other family was still up -- not yet collected
    /// ([`LivenessSession::take_peer_deleted_children`]). The caller
    /// renegotiates a brand-new CHILD SA for it (RFC 7296 has nothing to say
    /// about this beyond "it's gone"; auto-recovering is this project's own
    /// policy, not a spec requirement -- see that method's doc).
    deleted: Vec<ChildKind>,
    /// The CHILD SA exchange of our own still waiting for its answer, which
    /// a request of the peer's can collide with (RFC 7296 §2.25.1).
    in_flight: Option<OwnChildOp>,
}

/// A CHILD SA exchange this session started and the peer has not answered yet.
#[derive(Clone, Copy)]
enum ChildOp {
    /// Creating a CHILD SA from scratch.
    Create,
    /// Rekeying this CHILD SA.
    Rekey(ChildSpis),
    /// Deleting this CHILD SA.
    Close(ChildSpis),
}

/// [`ChildOp`], and what the peer did meanwhile to the CHILD SA it is about.
struct OwnChildOp {
    op: ChildOp,
    /// The peer rekeyed the same CHILD SA at the same time.
    crossed: Option<CrossedRekey>,
    /// The peer deleted the CHILD SA this rekey replaces.
    old_deleted: bool,
}

/// The peer's own rekey of the CHILD SA we are rekeying, answered as usual
/// (RFC 7296 §2.8.1): the SA it made, and the lower of that exchange's two
/// nonces -- which of the two new SAs is redundant is only known once our own
/// exchange's nonces are in too.
struct CrossedRekey {
    child: RekeyedChild,
    lowest_nonce: Vec<u8>,
}

/// The key material of `child`'s two directions, as a caller installs it.
fn rekeyed_child(child: &ChildSa) -> RekeyedChild {
    RekeyedChild {
        local_spi: child.inbound.spi(),
        peer_spi: child.outbound.spi(),
        key_out: ChildKeyMaterial {
            cipher: child.outbound.cipher(),
            enc: child.outbound.enc_material(),
            integ: child.outbound.integ_key().to_vec(),
        },
        key_in: ChildKeyMaterial {
            cipher: child.inbound.cipher(),
            enc: child.inbound.enc_material(),
            integ: child.inbound.integ_key().to_vec(),
        },
    }
}

/// What came of waiting for the response to one request -- see
/// [`LivenessSession::request_response`].
enum Reply {
    Response(Vec<u8>),
    Unanswered,
    PeerTornDown,
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
    /// The PFS policy of the `esp_offer` this tunnel was connected with
    /// ([`PfsPolicy::from_offer`]): the group our `CREATE_CHILD_SA` requests
    /// offer, if any -- none, and [`Self::rekey_child`] rekeys without PFS
    /// (still useful for key freshness, just not this project's ask) -- and
    /// what a rekey the peer starts has to keep.
    pfs: PfsPolicy,
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
    /// Whether the (primary) CHILD SA carries IPv6 as well as IPv4 -- true
    /// only when a unified `0.0.0.0/0` + `::/0` offer
    /// ([`Ikev2Session::with_unified_ts`]) was granted with both families.
    /// [`Self::rekey_child`] then keeps proposing both, and
    /// [`Self::create_child_ipv6`] has nothing to add.
    child_carries_ipv6: bool,
    /// The IKE SA's age and, after a peer-started rekey, the SA it replaced.
    ike: IkeSaState,
    /// CHILD SA rekeys the peer started -- see [`Self::take_peer_rekeys`].
    peer_child: PeerChildState,
    /// Whether `child_local_spi`/`child_peer_spi` still name a CHILD SA the
    /// peer actually has. Set to `false` the moment an unsolicited ESP
    /// Delete names `child_peer_spi` while `child6` is still up (RFC 7296
    /// §1.4.1: deleting one CHILD SA never implies deleting the IKE SA or any
    /// other CHILD SA under it, so there is an IKE SA worth keeping alive)
    /// -- see [`Self::take_peer_deleted_children`]. `child_local_spi`/
    /// `child_peer_spi` are stale while this is `false`; nothing reads them
    /// until [`Self::create_child_primary`] replaces both and sets this back
    /// to `true`. Always `true` when there is no separate `child6` at all,
    /// since then losing the primary CHILD SA leaves nothing to salvage and
    /// [`Self::answer_peer_request`] tears the whole tunnel down instead of
    /// clearing this.
    primary_child_alive: bool,
    /// The current IKE SA's receive window: which request of the peer's is
    /// answered next, and the answer to resend verbatim when the peer
    /// retransmits the last one because our answer was lost (RFC 7296 §2.1)
    /// -- acting on it again could answer differently, state having moved on
    /// (a `peer_child.superseded` entry gone, say), and leave the peer
    /// without the Delete it waits for.
    peer_requests: PeerRequests,
}

/// Result of one [`LivenessSession::probe`] call.
#[derive(Debug, PartialEq, Eq)]
pub enum Liveness {
    /// The peer answered our DPD probe -- still up.
    Alive,
    /// An unsolicited INFORMATIONAL carrying a Delete payload for the whole
    /// IKE SA -- or for the CHILD SAs this session currently relies on --
    /// arrived from the peer: it tore the tunnel down on its own initiative
    /// (e.g. an admin disconnected it on the gateway). Already ack'd on the
    /// peer's behalf before returning. A CHILD SA Delete naming some *other*
    /// SPI is not this -- see [`LivenessSession::answer_peer_informational`]'s
    /// doc: that's routine post-rekey cleanup of the SA a rekey just
    /// superseded, and does not end the tunnel. Also a request of the peer's
    /// on the IKE SA that authenticated but was badly formatted: answered
    /// `INVALID_SYNTAX`, which RFC 7296 §2.21.3 makes fatal to the IKE SA in
    /// both peers (see [`LivenessSession::answer_malformed_request`]).
    PeerTornDown,
    /// No reply within the timeout. Could be transient packet loss rather
    /// than a dead peer -- callers should require a few consecutive misses
    /// before concluding the tunnel is actually down, same as any DPD
    /// implementation.
    NoReply,
}

impl LivenessSession {
    /// The Message ID for a request other than a rekey or Delete of the IKE
    /// SA itself, fixed once before any retransmission. None is handed out
    /// from the last [`MESSAGE_IDS_KEPT_FOR_ENDING`]: those are
    /// [`Self::alloc_ending_message_id`]'s.
    fn alloc_message_id(&mut self) -> Result<u32, IkeError> {
        if self.message_ids_exhausted() {
            return Err(IkeError::MessageIdsExhausted);
        }
        self.alloc_ending_message_id()
    }

    /// The Message ID for a request that rekeys or deletes the IKE SA: any
    /// left. Message IDs never wrap (RFC 7296 §2.2), so the very last one,
    /// `u32::MAX`, is never used -- it would leave nothing to go on to.
    fn alloc_ending_message_id(&mut self) -> Result<u32, IkeError> {
        let mid = self.next_message_id;
        self.next_message_id = mid.checked_add(1).ok_or(IkeError::MessageIdsExhausted)?;
        Ok(mid)
    }

    /// Whether this IKE SA has run through the Message IDs its requests may
    /// use (RFC 7296 §2.2: they never wrap, and the IKE SA is then rekeyed or
    /// closed). From here on, every request but [`Self::rekey_ike`] and
    /// [`Self::close`] fails with [`IkeError::MessageIdsExhausted`] without
    /// being sent; a rekey of the IKE SA, by either side, starts them over.
    pub fn message_ids_exhausted(&self) -> bool {
        self.next_message_id >= u32::MAX - MESSAGE_IDS_KEPT_FOR_ENDING
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
        let mut answer = Reassembly::new(self.answer_key(expected_mid, ExchangeType::Informational));
        for attempt in 0..ATTEMPTS {
            if attempt > 0 {
                ike_debug!("INFORMATIONAL: retransmitting to {} (attempt {}/{ATTEMPTS})", self.dest, attempt + 1);
            }
            crate::debug::dump(">>>", self.dest, wire);
            self.sock.send_to(wire, self.dest)?;
            last = self.recv_and_classify(timeout, Some(&mut answer))?;
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
        let mid = self.alloc_message_id()?;

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

    /// Gracefully tear down the IKE SA before dropping the socket: sends a
    /// Delete payload for the whole IKE SA (RFC 7296 §1.4.1 — this implicitly
    /// deletes every CHILD SA under it too, no separate ESP Delete needed).
    /// Without this, disconnecting only removed the local kernel XFRM state;
    /// the gateway never heard about it and kept its side of the IKE/CHILD
    /// SAs around until their own lifetime/DPD eventually expired them.
    /// Best-effort: the local teardown that follows a call to this doesn't
    /// depend on the peer ever seeing this message, so a missing ack (or any
    /// I/O error past the initial send) is not surfaced as a hard failure.
    /// It may use the Message IDs kept back for ending the IKE SA (see
    /// [`Self::message_ids_exhausted`]); with none left at all it fails with
    /// [`IkeError::MessageIdsExhausted`], having sent nothing.
    pub fn close(&mut self) -> Result<(), DriverError> {
        self.delete_ike_sa("graceful disconnect")
    }

    /// Send a Delete for the current IKE SA, on that SA, and best-effort wait
    /// for the ack. `why` only labels the debug output.
    fn delete_ike_sa(&mut self, why: &str) -> Result<(), DriverError> {
        let mid = self.alloc_ending_message_id()?;
        let mut iv = [0u8; 8];
        OsEntropy::new()?.fill(&mut iv);
        let del = Delete::ike_sa();
        let req = build_informational(&self.sa, mid, false, &[(PayloadType::Delete, del.to_bytes())], &iv)?;
        ike_debug!("INFORMATIONAL: sending IKE_SA Delete to {} ({why})", self.dest);
        let wire = wrap(&req, self.float);
        // Best-effort ack wait -- RFC 7296 says the requester may consider
        // the SA closed immediately, it doesn't need to wait for this.
        self.ike.closing = true;
        let _ = self.send_and_await(&wire, mid, Duration::from_millis(500));
        self.ike.closing = false;
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
        self.pfs.proposed().is_some()
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
    ///
    /// When the peer rekeys the same SA at the same time, the SA returned is
    /// whichever of the two new ones survives (RFC 7296 §2.8.1) -- possibly
    /// the peer's -- and is what the caller installs; see
    /// [`Self::settle_rekey`].
    ///
    /// `timeout` is per attempt, here and in every other `CREATE_CHILD_SA`
    /// this session starts: a request left unanswered that long is sent again
    /// (RFC 7296 §2.1), three attempts in all, before the exchange fails with
    /// [`io::ErrorKind::TimedOut`] and leaves the CHILD SA as it was.
    pub fn rekey_child(&mut self, timeout: Duration) -> Result<RekeyedChild, DriverError> {
        let old = ChildSpis { local: self.child_local_spi, peer: self.child_peer_spi };
        // A unified SA keeps being proposed as one: rekeying it IPv4-only would
        // silently drop IPv6 at the first rekey.
        let ts = if self.child_carries_ipv6 { TrafficSelectors::unified_full_tunnel() } else { TrafficSelectors::ipv4_full_tunnel() };
        let (rekeyed, tsr) = self.child_exchange(Some((ChildKind::Primary, old)), &ts, "rekey", timeout)?;
        if self.child_carries_ipv6 && !tsr.as_ref().is_some_and(|t| t.has_ipv6()) {
            ike_debug!("CREATE_CHILD_SA (rekey): the unified CHILD SA's rekey came back without IPv6 (TSr={tsr:?})");
        }
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
        if self.child_carries_ipv6 {
            return Err(IkeError::Crypto("the tunnel's CHILD SA already carries IPv6").into());
        }
        let (child, tsr) = self.child_exchange(None, &TrafficSelectors::ipv6_full_tunnel(), "new IPv6 CHILD SA", timeout)?;
        let granted_subnets6 = granted_subnets_v6(tsr.as_ref(), &self.cfg_subnets6);
        // The CFG ranges alone don't prove the gateway granted this SA any
        // IPv6: it has to have granted an IPv6 selector too.
        let granted_ipv6_ts = tsr.as_ref().is_some_and(|ts| ts.selectors.iter().any(|s| s.to_ipv6_cidr().is_some()));
        if granted_subnets6.is_empty() || !granted_ipv6_ts {
            ike_debug!("CREATE_CHILD_SA (new IPv6 CHILD SA): reply granted no IPv6 traffic selector (TSr={tsr:?}) -- deleting it");
            if let Err(e) = self.delete_child_sa(ChildSpis::of(&child)) {
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

    /// Negotiate a brand-new primary (IPv4) CHILD SA from scratch, replacing
    /// one the peer deleted outright while the separate IPv6 CHILD SA was
    /// still up (see [`Self::take_peer_deleted_children`]) -- [`Self::rekey_child`]'s
    /// counterpart for when there is no existing SPI left to reference with
    /// `REKEY_SA` (the peer already forgot it), same shape as
    /// [`Self::create_child_ipv6`] just for the IPv4 side. Only ever called
    /// while `child6.is_some()`: if there were no separate IPv6 CHILD SA to
    /// preserve, losing the primary left nothing to salvage and
    /// [`Self::answer_peer_request`] tore the whole tunnel down instead of
    /// queuing this. An error leaves the primary CHILD SA absent for the
    /// caller to retry on the next liveness tick, same interop stance
    /// [`Self::create_child_ipv6`] already takes towards a gateway that
    /// momentarily refuses.
    pub fn create_child_primary(&mut self, timeout: Duration) -> Result<RekeyedChild, DriverError> {
        let (child, _tsr) = self.child_exchange(None, &TrafficSelectors::ipv4_full_tunnel(), "new primary CHILD SA", timeout)?;
        self.child_local_spi = child.local_spi;
        self.child_peer_spi = child.peer_spi;
        self.primary_child_alive = true;
        Ok(child)
    }

    /// Whether the tunnel's primary CHILD SA carries IPv6 too (a unified
    /// IPv4+IPv6 offer that the gateway granted in full) -- if so no separate
    /// IPv6 CHILD SA is needed, or possible.
    pub fn child_carries_ipv6(&self) -> bool {
        self.child_carries_ipv6
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
        let (rekeyed, _tsr) = self.child_exchange(Some((ChildKind::Ipv6, old)), &TrafficSelectors::ipv6_full_tunnel(), "rekey IPv6", timeout)?;
        Ok(rekeyed)
    }

    /// One `CREATE_CHILD_SA` exchange creating a CHILD SA proposing `ts` as
    /// both TSi and TSr: a rekey of `kind`'s CHILD SA `old` when `replaces` is
    /// `Some((kind, old))`, a brand-new CHILD SA otherwise. Returns the new SA
    /// and the `TSr` the gateway granted. `what` only labels the debug output.
    /// A rekey is settled by [`Self::settle_rekey`], which records the SA that
    /// ends up replacing `old` as `kind`'s; a brand-new CHILD SA isn't recorded
    /// anywhere -- the callers own which SA that is.
    fn child_exchange(
        &mut self,
        replaces: Option<(ChildKind, ChildSpis)>,
        ts: &TrafficSelectors,
        what: &str,
        timeout: Duration,
    ) -> Result<(RekeyedChild, Option<TrafficSelectors>), DriverError> {
        let op = replaces.map_or(ChildOp::Create, |(_, old)| ChildOp::Rekey(old));
        self.peer_child.in_flight = Some(OwnChildOp { op, crossed: None, old_deleted: false });
        let exchanged = self.child_request(replaces.map(|(_, old)| old), ts, what, timeout);
        let own = self.peer_child.in_flight.take();
        match (replaces, own) {
            (Some((kind, old)), Some(own)) => self.settle_rekey(kind, old, own, exchanged, what),
            _ => exchanged.map(|(child, tsr, _)| (rekeyed_child(&child), tsr)),
        }
    }

    /// Where a rekey of `kind`'s CHILD SA `old` leaves things, once our own
    /// `CREATE_CHILD_SA` exchange for it (`exchanged`: the new SA, the `TSr`
    /// granted and the lower of the exchange's two nonces) is over. Records the
    /// SA replacing `old` as `kind`'s, deletes what is left over, and returns
    /// the SA the caller installs.
    ///
    /// The peer may have rekeyed `old` too while ours was in flight
    /// (RFC 7296 §2.8.1): both exchanges were answered, so three SAs now
    /// exist. The one created with the lowest of the four nonces is redundant
    /// and is deleted by whoever created it, and whoever created the survivor
    /// deletes `old`. If ours is the redundant one the peer's is returned
    /// instead; if theirs is, the peer deletes it, and that Delete is
    /// answered with ours. If our exchange failed instead -- our request went
    /// unanswered, retransmissions included, or the peer answered
    /// `CHILD_SA_NOT_FOUND` because its own rekey had already replaced `old`
    /// -- the peer's SA stands and the error means
    /// nothing. Only the survivor is ever handed to the caller, which holds
    /// one CHILD SA per family: the redundant SA's inbound traffic is not
    /// accepted in the moment before its Delete, although RFC 7296 §2.8.1
    /// asks for both.
    ///
    /// The peer may also have deleted `old` meanwhile (§2.25.1: answered as
    /// usual, with our Delete for it). Then a rekey that stood has nothing
    /// left to delete, and one that failed leaves `kind` without a CHILD SA,
    /// exactly as if the Delete had arrived outside the exchange.
    fn settle_rekey(
        &mut self,
        kind: ChildKind,
        old: ChildSpis,
        own: OwnChildOp,
        exchanged: Result<(ChildSa, Option<TrafficSelectors>, Vec<u8>), DriverError>,
        what: &str,
    ) -> Result<(RekeyedChild, Option<TrafficSelectors>), DriverError> {
        let (child, tsr) = match (exchanged, own.crossed) {
            (Ok((child, tsr, _)), None) => (child, tsr),
            (Ok((child, tsr, our_lowest)), Some(crossed)) => {
                let ours = rekeyed_child(&child);
                if our_lowest < crossed.lowest_nonce {
                    ike_debug!(
                        "CREATE_CHILD_SA ({what}): the peer rekeyed the same CHILD SA -- ours (spi_in={:08x}) holds the lowest nonce, deleting it and keeping the peer's (spi_in={:08x})",
                        ours.local_spi, crossed.child.local_spi
                    );
                    if let Err(e) = self.delete_child_sa(ChildSpis::of(&ours)) {
                        ike_debug!("CREATE_CHILD_SA ({what}): failed to send Delete for the redundant CHILD SA spi_in={:08x}: {e}", ours.local_spi);
                    }
                    return Ok((crossed.child, tsr));
                }
                ike_debug!(
                    "CREATE_CHILD_SA ({what}): the peer rekeyed the same CHILD SA -- its SA (spi_in={:08x}) holds the lowest nonce, the peer deletes it; keeping ours (spi_in={:08x})",
                    crossed.child.local_spi, ours.local_spi
                );
                let theirs = ChildSpis::of(&crossed.child);
                self.peer_child.superseded.push(SupersededChild { local_spi: theirs.local, peer_spi: theirs.peer, since: Instant::now() });
                // `old` went into `superseded` when the peer's rekey was answered,
                // for the peer to delete; now it's ours to delete.
                self.peer_child.superseded.retain(|s| s.peer_spi != old.peer);
                (child, tsr)
            }
            (Err(DriverError::Ike(IkeError::PeerTornDown)), _) => return Err(IkeError::PeerTornDown.into()),
            (Err(e), Some(crossed)) => {
                ike_debug!(
                    "CREATE_CHILD_SA ({what}): failed ({e}), but the peer rekeyed the same CHILD SA meanwhile -- keeping its SA (spi_in={:08x})",
                    crossed.child.local_spi
                );
                return Ok((crossed.child, None));
            }
            (Err(e), None) if own.old_deleted => return Err(self.lost_child(kind, e)),
            (Err(e), None) => return Err(e),
        };
        let rekeyed = rekeyed_child(&child);
        self.set_child_spis(kind, &rekeyed);
        // RFC 7296 §2.8's own worked example ends a rekey with the initiator
        // explicitly deleting the SA it just replaced -- without this, a real
        // gateway (confirmed live against a FortiGate) has no way to know the
        // old CHILD SA is no longer wanted and keeps it (and its kernel
        // state) around until its own lifetime eventually expires it, which
        // with a short-lived P2 profile means old, unused SAs pile up.
        // Best-effort: the new CHILD SA above is already valid and in use
        // regardless of whether the peer sees or acks this.
        if !own.old_deleted {
            if let Err(e) = self.delete_child_sa(old) {
                ike_debug!(
                    "CREATE_CHILD_SA ({what}): failed to send Delete for superseded CHILD SA spi_in={:08x} (new CHILD SA unaffected): {e}",
                    old.local
                );
            }
        }
        Ok((rekeyed, tsr))
    }

    /// Record `child` as `kind`'s CHILD SA.
    fn set_child_spis(&mut self, kind: ChildKind, child: &RekeyedChild) {
        match kind {
            ChildKind::Primary => {
                self.child_local_spi = child.local_spi;
                self.child_peer_spi = child.peer_spi;
            }
            ChildKind::Ipv6 => self.child6 = Some(ChildSpis::of(child)),
        }
    }

    /// `kind`'s CHILD SA is gone -- the peer deleted it while our rekey of it
    /// was in flight, and that rekey came to nothing (`e`). Handled as
    /// [`Self::answer_peer_request`] handles that Delete outside an exchange:
    /// queued for renegotiation while the other family keeps the tunnel up,
    /// the tunnel's end otherwise. Returns the error to surface.
    fn lost_child(&mut self, kind: ChildKind, e: DriverError) -> DriverError {
        match kind {
            ChildKind::Primary if self.child6.is_some() => {
                ike_debug!("CREATE_CHILD_SA: the peer deleted the primary CHILD SA while we rekeyed it -- IPv6 CHILD SA and IKE SA are still up, renegotiating it");
                self.primary_child_alive = false;
                self.peer_child.deleted.push(ChildKind::Primary);
                e
            }
            ChildKind::Primary => {
                ike_debug!("CREATE_CHILD_SA: the peer deleted the tunnel's only CHILD SA while we rekeyed it -- tunnel torn down by the gateway");
                IkeError::PeerTornDown.into()
            }
            ChildKind::Ipv6 => {
                ike_debug!("CREATE_CHILD_SA: the peer deleted the IPv6 CHILD SA while we rekeyed it -- primary CHILD SA and IKE SA are still up, renegotiating it");
                self.child6 = None;
                self.peer_child.deleted.push(ChildKind::Ipv6);
                e
            }
        }
    }

    /// The `CREATE_CHILD_SA` exchange itself, for [`Self::child_exchange`]:
    /// the new SA, the `TSr` granted, and the lower of the exchange's two
    /// nonces (for [`Self::settle_rekey`]).
    fn child_request(
        &mut self,
        replaces: Option<ChildSpis>,
        ts: &TrafficSelectors,
        what: &str,
        timeout: Duration,
    ) -> Result<(ChildSa, Option<TrafficSelectors>, Vec<u8>), DriverError> {
        let mut entropy = OsEntropy::new()?;
        let mut ni = vec![0u8; NONCE_LEN];
        entropy.fill(&mut ni);
        let new_local_spi = loop {
            let s = entropy.next_u64() as u32;
            if s != 0 {
                break s;
            }
        };
        let pfs_group = self.pfs.proposed();
        let dh_private = pfs_group.map(|_| {
            let mut p = [0u8; 32];
            entropy.fill(&mut p);
            p
        });
        let pfs: Option<PfsKeyExchange> = pfs_group.zip(dh_private.as_ref()).map(|(group, private)| (group, private.as_slice()));

        let mid = self.alloc_message_id()?;
        let mut iv = [0u8; 8];
        entropy.fill(&mut iv);
        ike_debug!(
            "CREATE_CHILD_SA ({what}): initiating{} -- rekeyed_spi_in={:?}, new_local_spi={new_local_spi:08x}",
            if pfs.is_some() { " with PFS" } else { "" }, replaces.map(|c| format!("{:08x}", c.local))
        );
        let req = rekey::build_child_request(
            &self.sa,
            mid,
            // RFC 7296 §1.3.3: REKEY_SA names the SA by the SPI *we* expect on
            // inbound ESP, not the one the peer chose (our outbound SPI).
            replaces.map(|c| c.local),
            new_local_spi,
            &ni,
            self.cipher,
            pfs,
            ts,
            &iv,
        )?;
        // Whatever the peer sends while this waits is answered, and a Delete of
        // the whole IKE SA ends the wait: the peer tearing the tunnel down
        // deletes the CHILD SA first (which is what starts a from-scratch
        // recreate through here, see `create_child_primary`/`create_child_ipv6`)
        // and the IKE SA a moment later -- confirmed live against a real
        // FortiGate (see `IkeError::PeerTornDown`'s doc). A peer-started IKE SA
        // rekey colliding with this exchange is refused with TEMPORARY_FAILURE
        // (RFC 7296 §2.25.1), for the peer to retry once this is over. A lost
        // request or response is retransmitted, the same bytes every time
        // (§2.1): the peer answers a retransmission with the answer it already
        // gave, so no second SA is made.
        let response = match self.request_response(&wrap(&req, self.float), mid, timeout)? {
            Reply::Response(response) => response,
            Reply::PeerTornDown => return Err(IkeError::PeerTornDown.into()),
            Reply::Unanswered => {
                ike_debug!("CREATE_CHILD_SA ({what}): no answer to message id {mid}, retransmissions included");
                return Err(io::Error::from(io::ErrorKind::TimedOut).into());
            }
        };
        let (child, tsr) = rekey::initiator_complete_child(&self.sa, &ni, new_local_spi, self.cipher, pfs, &response)?;
        ike_debug!(
            "CREATE_CHILD_SA ({what}): complete -- new spi_in={:08x} spi_out={:08x}",
            child.inbound.spi(), child.outbound.spi()
        );
        let nr = rekey::peer_child_nonce(&self.sa, &response).unwrap_or_default();
        Ok((child, tsr, ni.min(nr)))
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
    /// CHILD SA, and best-effort wait for the ack. The Delete names
    /// `child.local`, *our own* inbound SPI for that SA -- per RFC 7296
    /// §3.10, a Delete names the SPI the sender itself expects in inbound
    /// packets, i.e. the value the peer would use as the destination sending
    /// ESP *to* us, not the SPI we use sending to them (that's the peer's own
    /// value to report, on their own Delete, not ours). Used by
    /// [`Self::settle_rekey`] to explicitly retire the CHILD SA a rekey just
    /// replaced -- see that call site's doc for why this exists.
    fn delete_child_sa(&mut self, child: ChildSpis) -> Result<(), DriverError> {
        let mid = self.alloc_message_id()?;
        let mut iv = [0u8; 8];
        OsEntropy::new()?.fill(&mut iv);
        let del = Delete::esp(vec![child.local]);
        let req = build_informational(&self.sa, mid, false, &[(PayloadType::Delete, del.to_bytes())], &iv)?;
        ike_debug!("INFORMATIONAL: sending ESP Delete for CHILD SA spi_in={:08x} to {}", child.local, self.dest);
        let wire = wrap(&req, self.float);
        // Until it's answered, the peer's requests about this SA collide
        // with it (RFC 7296 §2.25.1).
        let outer = self.peer_child.in_flight.replace(OwnChildOp { op: ChildOp::Close(child), crossed: None, old_deleted: false });
        // Best-effort ack wait, same reasoning as `close()`: the peer may
        // consider the SA gone immediately either way.
        let _ = self.send_and_await(&wire, mid, Duration::from_millis(500));
        self.peer_child.in_flight = outer;
        Ok(())
    }

    /// Shared receive loop for `probe`/`peek`: reads until `timeout`
    /// elapses, classifying whatever arrives. `expected_mid`, when set (from
    /// `probe`), is the Message ID of our INFORMATIONAL request whose answer
    /// is [`Liveness::Alive`] -- only the genuine answer counts (see
    /// [`Self::is_answer`]), and any other response is stale or forged and
    /// passed over; `peek` passes `None` since it never sent anything. A
    /// request from the peer is answered, or not, by
    /// [`Self::answer_peer_request`], and the wait goes on unless it ended
    /// the tunnel ([`Liveness::PeerTornDown`]). A datagram that isn't an
    /// IKEv2 message at all is dropped: anyone can send one.
    fn recv_and_classify(&mut self, timeout: Duration, mut awaited: Option<&mut Reassembly>) -> Result<Liveness, DriverError> {
        let quiet = if awaited.is_some() { Liveness::NoReply } else { Liveness::Alive };
        let deadline = Instant::now() + timeout;
        let mut buf = [0u8; 8192];
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(quiet);
            }
            self.sock.set_read_timeout(Some(remaining))?;
            let n = match self.recv_datagram(&mut buf, remaining) {
                Ok(n) => n,
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => return Ok(quiet),
                // The Windows receive thread is gone: nothing more comes this way.
                Err(e) if e.kind() == io::ErrorKind::BrokenPipe && self.external_rx.is_some() => return Ok(quiet),
                Err(e) => return Err(e.into()),
            };
            crate::debug::dump("<<<", self.dest, &buf[..n]);
            let Ok(msg) = unwrap(&buf[..n], self.float) else { continue };
            let Ok(header) = IkeHeader::parse(&msg) else { continue };
            let (header, msg) = if header.next_payload == PayloadType::EncryptedFragment {
                match self.take_fragment(&header, &msg, awaited.as_deref_mut())? {
                    Fragmented::Whole(header, msg) => (header, msg),
                    Fragmented::Pending => continue,
                    Fragmented::AnsweredAgain { tears_down: true } => return Ok(Liveness::PeerTornDown),
                    Fragmented::AnsweredAgain { tears_down: false } => continue,
                }
            } else {
                (header, msg)
            };
            if header.flags.response {
                let answer = awaited.as_deref().map(Reassembly::key);
                if answer.is_some_and(|key| self.is_answer(&header, &msg, key.message_id, key.exchange_type)) {
                    return Ok(Liveness::Alive);
                }
                continue;
            }
            if self.answer_peer_request(&header, &msg)? {
                return Ok(Liveness::PeerTornDown);
            }
        }
    }

    /// The [`MessageKey`] of the peer's answer to our request `mid` of
    /// `exchange` on the current IKE SA.
    fn answer_key(&self, mid: u32, exchange: ExchangeType) -> MessageKey {
        MessageKey {
            initiator_spi: self.sa.spi_i,
            responder_spi: self.sa.spi_r,
            exchange_type: exchange,
            initiator: self.sa.role == Role::Responder,
            response: true,
            message_id: mid,
        }
    }

    /// One fragment (RFC 7383) from the peer, `header` its IKE header.
    ///
    /// - A response counts only toward `awaited`, the answer to the request
    ///   we wait on, and only if it belongs to it; otherwise it is dropped.
    /// - A request is taken only where [`Self::answer_peer_request`] would
    ///   take the whole of it: on one of this session's IKE SAs, and in its
    ///   receive window. Fragment 1 of the last request answered, once it
    ///   authenticates, gets the answer again; any other fragment of it is
    ///   ignored (RFC 7383 §2.6.1). The fragments of the next request are
    ///   kept for [`FRAGMENT_REASSEMBLY_TIMEOUT`], and a fragment of another
    ///   request replaces them only if it is authentic.
    ///
    /// Each fragment goes through [`Reassembly::accept`]. A message it
    /// completes is sealed again as one `SK` message under the peer's keys,
    /// and then goes where an unfragmented one would, checks included.
    fn take_fragment(&mut self, header: &IkeHeader, msg: &[u8], awaited: Option<&mut Reassembly>) -> Result<Fragmented, DriverError> {
        let mid = header.message_id;
        if header.flags.response {
            let Some(answer) = awaited.filter(|answer| answer.key() == MessageKey::of(header)) else {
                return Ok(Fragmented::Pending);
            };
            let sa = &self.sa;
            return match answer.accept(msg, sa.suite.sk_cipher(), peer_sk_e(sa), peer_sk_a(sa)) {
                Accepted::Complete(first, inner) => whole_from_peer(sa, *header, first, &inner),
                Accepted::Stored => Ok(Fragmented::Pending),
                Accepted::Discarded(why) => {
                    ike_debug!("response {mid}: fragment dropped: {why}");
                    Ok(Fragmented::Pending)
                }
            };
        }
        let Some(on) = self.ike_sa_of(header) else {
            return Ok(Fragmented::Pending);
        };
        let sa = self.ike_sa(on).clone();
        let (cipher, sk_e, sk_a) = (sa.suite.sk_cipher(), peer_sk_e(&sa), peer_sk_a(&sa));
        if let Some(last) = self.peer_requests(on).last.as_ref().filter(|last| last.message_id == mid) {
            if !fragment::verify_fragment(cipher, msg, sk_e, sk_a).is_ok_and(|(number, _)| number == 1) {
                return Ok(Fragmented::Pending);
            }
            ike_debug!("request {mid} from the peer: retransmitted (fragment 1) -- resending our answer");
            let _ = self.sock.send_to(&last.response, self.dest);
            return Ok(Fragmented::AnsweredAgain { tears_down: last.tears_down });
        }
        if self.peer_requests(on).next != u64::from(mid) || self.peer_requests(on).gone {
            return Ok(Fragmented::Pending);
        }
        let key = MessageKey::of(header);
        let requests = self.peer_requests_on(on);
        let kept = requests.fragments.take().filter(|(_, since)| since.elapsed() <= FRAGMENT_REASSEMBLY_TIMEOUT);
        let (mut request, since, other) = match kept {
            Some((request, since)) if request.key() == key => (request, since, None),
            other => (Reassembly::new(key), Instant::now(), other),
        };
        match request.accept(msg, cipher, sk_e, sk_a) {
            Accepted::Complete(first, inner) => whole_from_peer(&sa, *header, first, &inner),
            Accepted::Stored => {
                requests.fragments = Some((request, since));
                Ok(Fragmented::Pending)
            }
            Accepted::Discarded(why) => {
                ike_debug!("request {mid} from the peer: fragment dropped: {why}");
                requests.fragments = if request.is_empty() { other } else { Some((request, since)) };
                Ok(Fragmented::Pending)
            }
        }
    }

    /// Whether `msg` is the peer's answer to our request `mid` of `exchange`
    /// on the current IKE SA (RFC 7296 §2.2, §3.1): a response with that
    /// Message ID and exchange type, on this IKE SA's SPIs, from the peer's
    /// side of it -- and authentic. The integrity check covers the header,
    /// but the keys don't depend on it, so it doesn't make the rest of these
    /// checks redundant. A Message ID alone proves nothing: it is sequential,
    /// and a forged datagram carrying it would otherwise fake liveness for a
    /// dead peer.
    fn is_answer(&self, header: &IkeHeader, msg: &[u8], mid: u32, exchange: ExchangeType) -> bool {
        header.flags.response
            && header.message_id == mid
            && header.exchange_type == exchange
            && from_peer_on(&self.sa, header)
            && open_from_peer(&self.sa, msg).is_ok()
    }

    /// The IKE SA a message from the peer is on, by its header: the current
    /// one, or the one retired after a rekey, if either.
    fn ike_sa_of(&self, header: &IkeHeader) -> Option<OnIkeSa> {
        if from_peer_on(&self.sa, header) {
            Some(OnIkeSa::Current)
        } else if self.ike.retired.as_ref().is_some_and(|r| from_peer_on(&r.sa, header)) {
            Some(OnIkeSa::Retired)
        } else {
            None
        }
    }

    fn ike_sa(&self, on: OnIkeSa) -> &CompletedSaInit {
        match (on, &self.ike.retired) {
            (OnIkeSa::Retired, Some(retired)) => &retired.sa,
            _ => &self.sa,
        }
    }

    fn peer_requests(&self, on: OnIkeSa) -> &PeerRequests {
        match (on, &self.ike.retired) {
            (OnIkeSa::Retired, Some(retired)) => &retired.requests,
            _ => &self.peer_requests,
        }
    }

    fn peer_requests_on(&mut self, on: OnIkeSa) -> &mut PeerRequests {
        match (on, &mut self.ike.retired) {
            (OnIkeSa::Retired, Some(retired)) => &mut retired.requests,
            _ => &mut self.peer_requests,
        }
    }

    /// Send `wire`, our answer to the peer's request `request` (with
    /// `header`) on the IKE SA `on`, and keep it as that IKE SA's answer to
    /// resend should the peer retransmit the request (RFC 7296 §2.1). The
    /// peer's next request is then the one after it. `tears_down` is whether
    /// the request ended the tunnel, for the retransmission to say so again.
    fn respond(&mut self, on: OnIkeSa, header: &IkeHeader, request: &[u8], wire: Vec<u8>, tears_down: bool) {
        crate::debug::dump(">>>", self.dest, &wire);
        let _ = self.sock.send_to(&wire, self.dest);
        let requests = self.peer_requests_on(on);
        requests.next = u64::from(header.message_id) + 1;
        requests.last = Some(AnsweredRequest { message_id: header.message_id, request: request.to_vec(), response: wire, tears_down });
    }

    /// Answer one request the peer sent on its own initiative -- `true` when
    /// it ended the tunnel. What is not a request this session should answer
    /// is dropped without an answer or any change of state, in this order:
    /// one on neither of this session's IKE SAs (by the SPIs and the
    /// Initiator flag of the header, RFC 7296 §3.1), one outside that IKE
    /// SA's receive window ([`PeerRequests`]: a retransmission of the last
    /// one answered gets its answer again instead), and one that does not
    /// authenticate (§2.21.3: nothing is acted on before that). Only then is
    /// the request acted on: an INFORMATIONAL by
    /// [`Self::answer_peer_informational`], a `CREATE_CHILD_SA` by
    /// [`Self::answer_peer_create_child_sa`] -- on the retired IKE SA it is
    /// refused with `NO_ADDITIONAL_SAS`, the CHILD SAs having moved to the
    /// new one -- and nothing else.
    fn answer_peer_request(&mut self, header: &IkeHeader, msg: &[u8]) -> Result<bool, DriverError> {
        if self.ike.retired.as_ref().is_some_and(|r| r.since.elapsed() > RETIRED_IKE_SA_TTL) {
            self.ike.retired = None;
        }
        self.peer_child.superseded.retain(|s| s.since.elapsed() <= SUPERSEDED_CHILD_TTL);
        let mid = header.message_id;
        // A retransmission of the IKE rekey we already took on means our
        // answer was lost: send it again. The IKE SA it came on may be gone.
        if let Some((_, response)) = self.ike.answered_rekey.as_ref().filter(|(request, _)| request == msg) {
            ike_debug!("CREATE_CHILD_SA: the peer retransmitted its IKE SA rekey -- resending our answer");
            let _ = self.sock.send_to(response, self.dest);
            return Ok(false);
        }
        let Some(on) = self.ike_sa_of(header) else {
            ike_debug!("request {mid} from the peer: not on this session's IKE SA -- dropped");
            return Ok(false);
        };
        let requests = self.peer_requests(on);
        if let Some(last) = requests.last.as_ref().filter(|last| last.message_id == mid) {
            if last.request != msg {
                ike_debug!("request {mid} from the peer: not the request answered under that message id -- dropped");
                return Ok(false);
            }
            ike_debug!("request {mid} from the peer: retransmitted -- resending our answer");
            let _ = self.sock.send_to(&last.response, self.dest);
            return Ok(last.tears_down);
        }
        if requests.next != u64::from(mid) {
            ike_debug!("request {mid} from the peer: outside the receive window (expecting {}) -- dropped", requests.next);
            return Ok(false);
        }
        if requests.gone {
            ike_debug!("request {mid} from the peer: on an IKE SA that is gone -- dropped");
            return Ok(false);
        }
        let Ok((first, body)) = open_from_peer(self.ike_sa(on), msg) else {
            ike_debug!("request {mid} from the peer: does not authenticate -- dropped");
            return Ok(false);
        };
        if !matches!(header.exchange_type, ExchangeType::Informational | ExchangeType::CreateChildSa) {
            return Ok(false);
        }
        let mut iv = [0u8; 8];
        OsEntropy::new()?.fill(&mut iv);
        let (inner, deletes) = match payload_list(first, &body).and_then(|inner| deletes_in(&inner).map(|deletes| (inner, deletes))) {
            Ok(parsed) => parsed,
            Err(e) => return self.answer_malformed_request(on, header, msg, &e, &iv),
        };
        match (header.exchange_type, on) {
            (ExchangeType::Informational, _) => self.answer_peer_informational(on, header, msg, deletes, &iv),
            (_, OnIkeSa::Current) => {
                self.answer_peer_create_child_sa(header, msg, &inner, &iv)?;
                Ok(false)
            }
            (_, OnIkeSa::Retired) => {
                self.refuse_peer_child_request(on, header, msg, &iv, notify_type::NO_ADDITIONAL_SAS, "on the IKE SA a rekey replaced")?;
                Ok(false)
            }
        }
    }

    /// Answer the peer's request on the IKE SA `on` that authenticated and
    /// is in the window, but whose payloads can't be taken -- `error` says
    /// why -- with the error notify alone, in the request's exchange (RFC
    /// 7296 §2.21.3: after authentication, a request with errors gets a
    /// response). Nothing in the request is acted on (§2.21.2: it is
    /// rejected in its entirety). `true` when that ended the tunnel.
    ///
    /// A payload of a type we don't know with the critical flag set (§2.5)
    /// earns `UNSUPPORTED_CRITICAL_PAYLOAD`, and the IKE SA goes on: the RFC
    /// doesn't make that one fatal. Any other error -- a malformed payload
    /// chain, a Delete whose fields don't hold together (§3.11) -- earns
    /// `INVALID_SYNTAX`, which §2.21.3 makes "fatal in both peers": the IKE
    /// SA is deleted without an INFORMATIONAL exchange of its own. On the
    /// current IKE SA that ends the tunnel ([`Liveness::PeerTornDown`]); on
    /// the one retired after a rekey, that one alone is gone. Either way,
    /// nothing but a retransmission of this request is answered on it again.
    fn answer_malformed_request(&mut self, on: OnIkeSa, header: &IkeHeader, msg: &[u8], error: &IkeError, iv: &[u8; 8]) -> Result<bool, DriverError> {
        let notify = request_error_notify(error);
        let answer = build_error_response(self.ike_sa(on), header, &notify, iv)?;
        let fatal = notify.notify_type == notify_type::INVALID_SYNTAX;
        let tears_down = fatal && on == OnIkeSa::Current;
        ike_debug!(
            "{:?} request {} from the peer: {error} -- answered {}{}",
            header.exchange_type,
            header.message_id,
            notify_type_name(notify.notify_type),
            if fatal { ", which deletes the IKE SA" } else { "" }
        );
        if fatal {
            self.peer_requests_on(on).gone = true;
        }
        self.respond(on, header, msg, wrap(&answer, self.float), tears_down);
        Ok(tears_down)
    }

    /// Answer an INFORMATIONAL request from the peer on the IKE SA `on`,
    /// its payloads already read without error, and act on its Delete
    /// payloads, `deletes` -- every one of them, and every SPI each names
    /// (RFC 7296 §3.11). `true` when that ended the tunnel.
    ///
    /// A Delete of the IKE SA (§1.4.1) takes every CHILD SA under it with it
    /// and is answered empty; it ends the tunnel, except while a rekey of ours
    /// of that IKE SA crossed the peer's own, which the Delete completes
    /// (§2.8.2, see [`Self::rekey_ike`]). On the IKE SA retired after a
    /// rekey, a Delete is routine: the CHILD SAs moved on.
    ///
    /// A Delete of CHILD SAs is answered with our Delete for each pair
    /// (§1.4.1), naming our inbound SPI of it, but for one we are deleting
    /// ourselves, whose Delete is on its way (§2.25.1). It ends the tunnel
    /// only when it leaves it no CHILD SA: the primary with no IPv6 one, or
    /// both. One family's CHILD SA going on its own, the other still up, is
    /// queued in `peer_child.deleted` for the caller to renegotiate (see
    /// [`Self::take_peer_deleted_children`]); nothing in §1.4.1 makes
    /// deleting a CHILD SA delete the IKE SA or any other. The CHILD SA a
    /// rekey of the peer's replaced is the peer's routine cleanup -- confirmed
    /// live against a FortiGate, which deletes the old SA right after every
    /// rekey -- and one a CHILD SA exchange of ours is about is settled by
    /// that exchange ([`Self::settle_rekey`]). SPIs this side doesn't know
    /// are passed over.
    fn answer_peer_informational(
        &mut self,
        on: OnIkeSa,
        header: &IkeHeader,
        msg: &[u8],
        deletes: Vec<Delete>,
        iv: &[u8; 8],
    ) -> Result<bool, DriverError> {
        let ike_deleted = deletes.iter().any(|d| d.protocol_id == protocol_id::IKE);
        let named: Vec<u32> = deletes.iter().filter(|d| d.protocol_id == protocol_id::ESP).flat_map(|d| d.spis.iter().copied()).collect();

        if on == OnIkeSa::Retired || ike_deleted {
            let ack = build_informational(self.ike_sa(on), header.message_id, true, &[], iv)?;
            let tears_down = on == OnIkeSa::Current && self.peer_deleted_ike_sa();
            if on == OnIkeSa::Retired && ike_deleted {
                ike_debug!("INFORMATIONAL: peer deleted the IKE SA we moved on from");
            }
            if (on == OnIkeSa::Retired && ike_deleted) || tears_down {
                self.peer_requests_on(on).gone = true;
            }
            self.respond(on, header, msg, wrap(&ack, self.float), tears_down);
            if tears_down {
                ike_debug!("INFORMATIONAL: peer deleted the IKE SA -- tunnel torn down by the gateway");
            }
            return Ok(tears_down);
        }

        // What the Delete payloads name, before anything changes: the answer
        // is built first, so that failing to leaves everything as it was.
        let superseded: Vec<u32> = self.peer_child.superseded.iter().filter(|c| named.contains(&c.peer_spi)).map(|c| c.local_spi).collect();
        // The CHILD SA a CHILD SA exchange of our own is about, if named.
        let collided = self.peer_child.in_flight.as_ref().and_then(|own| match own.op {
            ChildOp::Rekey(old) | ChildOp::Close(old) if named.contains(&old.peer) => Some(own.op),
            _ => None,
        });
        let (collided_peer, rekeying) = match collided {
            Some(ChildOp::Rekey(old)) => (Some(old.peer), Some(old.local)),
            Some(ChildOp::Close(closing)) => (Some(closing.peer), None),
            _ => (None, None),
        };
        let names = |spi: u32| named.contains(&spi) && Some(spi) != collided_peer;
        let primary = self.primary_child_alive && names(self.child_peer_spi);
        let child6 = self.child6.filter(|c| names(c.peer));
        // Ours for each pair, but for an SA we are deleting (RFC 7296 §2.25.1).
        let mut ours = superseded.clone();
        for spi in rekeying.into_iter().chain(primary.then_some(self.child_local_spi)).chain(child6.map(|c| c.local)) {
            if !ours.contains(&spi) {
                ours.push(spi);
            }
        }
        let payloads: Vec<_> = if ours.is_empty() { Vec::new() } else { vec![(PayloadType::Delete, Delete::esp(ours).to_bytes())] };
        let ack = build_informational(&self.sa, header.message_id, true, &payloads, iv)?;

        if !superseded.is_empty() {
            ike_debug!("INFORMATIONAL: peer deleted the CHILD SA its rekey replaced (spi_in={superseded:08x?})");
            self.peer_child.superseded.retain(|c| !named.contains(&c.peer_spi));
        }
        match collided {
            Some(ChildOp::Rekey(old)) => {
                ike_debug!("INFORMATIONAL: peer deleted the CHILD SA we are rekeying (spi_in={:08x})", old.local);
                if let Some(own) = self.peer_child.in_flight.as_mut() {
                    own.old_deleted = true;
                }
            }
            Some(ChildOp::Close(closing)) => {
                ike_debug!("INFORMATIONAL: peer deleted the CHILD SA we are deleting (spi_in={:08x}) -- ours is on its way", closing.local);
            }
            _ => {}
        }
        let tears_down = primary && (self.child6.is_none() || child6.is_some());
        if !tears_down {
            if primary {
                ike_debug!(
                    "INFORMATIONAL: peer deleted the primary CHILD SA (spi_out={:08x}) -- IPv6 CHILD SA and IKE SA are still up, renegotiating it",
                    self.child_peer_spi
                );
                self.primary_child_alive = false;
                self.peer_child.deleted.push(ChildKind::Primary);
            }
            if let Some(c6) = child6 {
                ike_debug!(
                    "INFORMATIONAL: peer deleted the IPv6 CHILD SA (spi_out={:08x}) -- primary CHILD SA and IKE SA are still up, renegotiating it",
                    c6.peer
                );
                self.child6 = None;
                self.peer_child.deleted.push(ChildKind::Ipv6);
            }
        }
        self.respond(on, header, msg, wrap(&ack, self.float), tears_down);
        if tears_down {
            ike_debug!("INFORMATIONAL: peer deleted the tunnel's CHILD SAs -- tunnel torn down by the gateway");
        }
        Ok(tears_down)
    }

    /// The peer deleted the current IKE SA: whether that ends the tunnel. It
    /// doesn't while a rekey of ours crossed the peer's own (RFC 7296
    /// §2.8.2): the peer's rekey, which we answered, is done, and it deletes
    /// the IKE SA that rekey replaced, never having seen ours -- which is
    /// dropped (see [`Self::rekey_ike`]).
    fn peer_deleted_ike_sa(&mut self) -> bool {
        match self.ike.rekeying.as_mut() {
            Some(own) if own.crossed.is_some() => {
                ike_debug!("INFORMATIONAL: peer deleted the IKE SA we are rekeying, having rekeyed it itself -- dropping our rekey");
                own.old_deleted = true;
                false
            }
            _ => true,
        }
    }

    /// Answer a `CREATE_CHILD_SA` the peer started on the current IKE SA,
    /// carrying the payloads `inner`: an IKE SA rekey -- see
    /// [`Self::answer_peer_ike_rekey`] -- otherwise one of a CHILD SA -- see
    /// [`Self::answer_peer_child_request`]. What can't be taken on is refused,
    /// still as a `CREATE_CHILD_SA` response.
    fn answer_peer_create_child_sa(
        &mut self,
        header: &IkeHeader,
        msg: &[u8],
        inner: &[(PayloadType, Vec<u8>)],
        iv: &[u8; 8],
    ) -> Result<(), DriverError> {
        if ike_rekey::is_ike_sa_rekey(inner) {
            return self.answer_peer_ike_rekey(header, msg, iv);
        }
        self.answer_peer_child_request(header, msg, iv)
    }

    /// The peer rekeying the IKE SA (RFC 7296 §2.18): taken on, and the session
    /// moves to the new IKE SA -- unless it collides with an exchange of ours.
    /// Following RFC 7296 §2.25.1/§2.25.2, one colliding with a CHILD SA being
    /// created, rekeyed or deleted, or with our Delete of this IKE SA, is
    /// refused with `TEMPORARY_FAILURE`, for the peer to retry later. One
    /// colliding with our own rekey of the IKE SA is answered as usual, but
    /// the session stays put: which of the two new IKE SAs survives is
    /// settled by [`Self::rekey_ike`] once ours is answered (§2.8.2).
    fn answer_peer_ike_rekey(&mut self, header: &IkeHeader, msg: &[u8], iv: &[u8; 8]) -> Result<(), DriverError> {
        let collision = if self.ike.closing {
            Some("we are deleting this IKE SA")
        } else if self.peer_child.in_flight.is_some() {
            Some("a CHILD SA exchange of ours is in flight")
        } else if self.ike.rekeying.as_ref().is_some_and(|own| own.crossed.is_some()) {
            Some("our rekey of the IKE SA already crossed one of the peer's")
        } else {
            None
        };
        if let Some(why) = collision {
            return self.refuse_peer_child_request(OnIkeSa::Current, header, msg, iv, notify_type::TEMPORARY_FAILURE, why);
        }
        let mut entropy = OsEntropy::new()?;
        let mut dh_private = [0u8; 32];
        entropy.fill(&mut dh_private);
        let mut nr = vec![0u8; NONCE_LEN];
        entropy.fill(&mut nr);
        let new_spi_r = loop {
            let spi = entropy.next_u64();
            if spi != 0 {
                break spi;
            }
        };
        let (response, new_sa) = match ike_rekey::responder_process_ike_rekey(&self.sa, msg, new_spi_r, &dh_private, &nr, iv) {
            Ok(answered) => answered,
            Err(e) => {
                let why = format!("the IKE SA rekey cannot be taken on: {e}");
                return self.refuse_peer_child_request(OnIkeSa::Current, header, msg, iv, notify_type::NO_ADDITIONAL_SAS, &why);
            }
        };
        // Recorded in the window of the IKE SA it came on before this session
        // leaves that IKE SA.
        let wire = wrap(&response, self.float);
        self.respond(OnIkeSa::Current, header, msg, wire.clone(), false);
        self.ike.answered_rekey = Some((msg.to_vec(), wire));
        match self.ike.rekeying.as_mut() {
            Some(own) => {
                ike_debug!(
                    "CREATE_CHILD_SA: the peer rekeyed the IKE SA (message id {}) while we rekey it too -- settled once ours is answered",
                    header.message_id
                );
                let ni = rekey::peer_child_nonce(&self.sa, msg).unwrap_or_default();
                own.crossed = Some(CrossedIkeRekey { sa: new_sa, lowest_nonce: ni.min(nr) });
            }
            None => {
                ike_debug!(
                    "CREATE_CHILD_SA: the peer rekeyed the IKE SA (message id {}) -- now on SPIs {:016x}/{:016x}",
                    header.message_id, new_sa.spi_i, new_sa.spi_r
                );
                self.move_to_peers_ike_sa(new_sa);
            }
        }
        Ok(())
    }

    /// Move to `new_sa`, an IKE SA the peer's rekey made: the one it replaced
    /// is the peer's to delete, and that Delete is routine ([`RetiredIkeSa`]).
    fn move_to_peers_ike_sa(&mut self, new_sa: CompletedSaInit) {
        self.ike.retired = Some(self.switch_ike_sa(new_sa));
    }

    /// The `CREATE_CHILD_SA` requests that aren't an IKE SA rekey: the peer
    /// rekeying one of our CHILD SAs on its own timer (RFC 7296 §1.3.3) is
    /// taken on -- the new SA is derived, answered, and handed to the caller
    /// through [`Self::take_peer_rekeys`] -- and an extra CHILD SA is refused
    /// with `NO_ADDITIONAL_SAS`. Every refusal is still a `CREATE_CHILD_SA`
    /// response, the reply the exchange calls for: an answer of another
    /// exchange type (an empty INFORMATIONAL, say) is a protocol error a
    /// gateway such as strongSwan answers by destroying the whole IKE SA,
    /// where a plain refusal leaves it standing.
    ///
    /// A rekey colliding with an exchange of our own about the same CHILD SA
    /// follows RFC 7296 §2.25.1: one of an SA we are deleting is refused with
    /// `TEMPORARY_FAILURE`; one of an SA we are rekeying ourselves is answered
    /// as usual, but the new SA is only noted for [`Self::settle_rekey`] to
    /// weigh against ours, not handed to the caller. While we rekey or delete
    /// the IKE SA, any of these is refused with `TEMPORARY_FAILURE` (§2.25.2).
    fn answer_peer_child_request(&mut self, header: &IkeHeader, msg: &[u8], iv: &[u8; 8]) -> Result<(), DriverError> {
        let current = OnIkeSa::Current;
        if self.ike.rekeying.is_some() || self.ike.closing {
            let why = "we are rekeying or deleting the IKE SA";
            return self.refuse_peer_child_request(current, header, msg, iv, notify_type::TEMPORARY_FAILURE, why);
        }
        let Some(rekeyed_spi) = rekey::rekey_sa_spi(&self.sa, msg) else {
            return self.refuse_peer_child_request(current, header, msg, iv, notify_type::NO_ADDITIONAL_SAS, "a new CHILD SA is not taken on");
        };
        let crossed = match self.peer_child.in_flight.as_ref() {
            Some(OwnChildOp { op: ChildOp::Close(c), .. }) if c.peer == rekeyed_spi => {
                return self.refuse_peer_child_request(
                    current,
                    header,
                    msg,
                    iv,
                    notify_type::TEMPORARY_FAILURE,
                    &format!("we are deleting the CHILD SA with spi {rekeyed_spi:08x}"),
                );
            }
            Some(OwnChildOp { op: ChildOp::Rekey(old), crossed: None, .. }) => old.peer == rekeyed_spi,
            _ => false,
        };
        let (kind, old) = if self.primary_child_alive && rekeyed_spi == self.child_peer_spi {
            (ChildKind::Primary, ChildSpis { local: self.child_local_spi, peer: self.child_peer_spi })
        } else if let Some(child6) = self.child6.filter(|c| c.peer == rekeyed_spi) {
            (ChildKind::Ipv6, child6)
        } else {
            return self.refuse_peer_child_request(
                current,
                header,
                msg,
                iv,
                notify_type::CHILD_SA_NOT_FOUND,
                &format!("no CHILD SA with spi {rekeyed_spi:08x}"),
            );
        };
        let mut entropy = OsEntropy::new()?;
        let mut nr = vec![0u8; NONCE_LEN];
        entropy.fill(&mut nr);
        let mut dh_private = [0u8; 32];
        entropy.fill(&mut dh_private);
        let new_spi = loop {
            let spi = entropy.next_u64() as u32;
            if spi != 0 {
                break spi;
            }
        };
        match rekey::responder_answer_child_rekey(&self.sa, msg, new_spi, &nr, self.cipher, &self.pfs, &dh_private, iv) {
            Ok((response, child)) => {
                self.respond(current, header, msg, wrap(&response, self.float), false);
                let rekeyed = rekeyed_child(&child);
                ike_debug!(
                    "CREATE_CHILD_SA: the peer rekeyed the {kind:?} CHILD SA (message id {}) -- new spi_in={:08x} spi_out={:08x}",
                    header.message_id, rekeyed.local_spi, rekeyed.peer_spi
                );
                self.set_child_spis(kind, &rekeyed);
                self.peer_child.superseded.push(SupersededChild { local_spi: old.local, peer_spi: old.peer, since: Instant::now() });
                match self.peer_child.in_flight.as_mut().filter(|_| crossed) {
                    Some(own) => {
                        ike_debug!("CREATE_CHILD_SA: we are rekeying that CHILD SA too -- settled once our own rekey is answered");
                        let ni = rekey::peer_child_nonce(&self.sa, msg).unwrap_or_default();
                        own.crossed = Some(CrossedRekey { child: rekeyed, lowest_nonce: ni.min(nr) });
                    }
                    None => self.peer_child.pending.push(PeerRekeyedChild { kind, child: rekeyed }),
                }
                Ok(())
            }
            Err(e) => {
                // RFC 7296 §1.3: INVALID_KE_PAYLOAD names the group we'd take, for
                // the peer to retry its rekey with a KE of it.
                let (reason, data) = match e {
                    IkeError::NoProposalChosen => (notify_type::NO_PROPOSAL_CHOSEN, Vec::new()),
                    IkeError::InvalidKeGroup(group) => (notify_type::INVALID_KE_PAYLOAD, group.to_be_bytes().to_vec()),
                    _ => (notify_type::INVALID_SYNTAX, Vec::new()),
                };
                self.refuse_peer_child_request_with(current, header, msg, iv, reason, data, &format!("cannot take it on: {e}"))
            }
        }
    }

    fn refuse_peer_child_request(
        &mut self,
        on: OnIkeSa,
        header: &IkeHeader,
        msg: &[u8],
        iv: &[u8; 8],
        reason: u16,
        why: &str,
    ) -> Result<(), DriverError> {
        self.refuse_peer_child_request_with(on, header, msg, iv, reason, Vec::new(), why)
    }

    /// Refuse the peer's `CREATE_CHILD_SA` request `msg` on the IKE SA `on`
    /// with the error notify `reason` carrying `data` -- an answer like any
    /// other, resent as it is if the request is retransmitted (RFC 7296 §2.1).
    #[allow(clippy::too_many_arguments)]
    fn refuse_peer_child_request_with(
        &mut self,
        on: OnIkeSa,
        header: &IkeHeader,
        msg: &[u8],
        iv: &[u8; 8],
        reason: u16,
        data: Vec<u8>,
        why: &str,
    ) -> Result<(), DriverError> {
        let refusal = rekey::build_child_error_with_data(self.ike_sa(on), header.message_id, reason, data, iv)?;
        ike_debug!("CREATE_CHILD_SA request from the peer (message id {}) -- refusing with {}: {why}", header.message_id, notify_type_name(reason));
        self.respond(on, header, msg, wrap(&refusal, self.float), false);
        Ok(())
    }

    /// The CHILD SA rekeys the peer started and this session answered since the
    /// last call, oldest first. The answer is on the wire already: the caller
    /// installs each new SA (and drops the one it replaced) promptly, since the
    /// peer moves its own traffic to the new SA as soon as it has the answer.
    /// The session's SPIs and the peer's deletion of the replaced SA are
    /// tracked here; only the data plane is the caller's.
    pub fn take_peer_rekeys(&mut self) -> Vec<PeerRekeyedChild> {
        std::mem::take(&mut self.peer_child.pending)
    }

    /// Which families the peer deleted outright (an unsolicited ESP Delete,
    /// not a rekey) since the last call, while the IKE SA and the other
    /// family were still up -- queued by [`Self::answer_peer_request`],
    /// mirroring [`Self::take_peer_rekeys`]'s shape. Unlike a rekey there is
    /// no new SA already on the wire to install: the caller renegotiates one
    /// from scratch, [`Self::create_child_primary`] or
    /// [`Self::create_child_ipv6`] depending on `kind`. RFC 7296 says nothing
    /// about doing this at all (a Delete just means the SA is gone); trying
    /// to bring the family back automatically instead of leaving it down
    /// until the user reconnects is this project's own policy choice.
    pub fn take_peer_deleted_children(&mut self) -> Vec<ChildKind> {
        std::mem::take(&mut self.peer_child.deleted)
    }

    /// Move to `new_sa` as the IKE SA (Message IDs start again at 0 both ways,
    /// RFC 7296 §2.18), returning the one it replaced with its receive
    /// window, which goes on as it was. The CHILD SAs come along untouched:
    /// only their parent changed.
    fn switch_ike_sa(&mut self, new_sa: CompletedSaInit) -> RetiredIkeSa {
        self.next_message_id = 0;
        self.ike.since = Instant::now();
        let old = std::mem::replace(&mut self.sa, new_sa);
        RetiredIkeSa::new(old, std::mem::take(&mut self.peer_requests))
    }

    /// How long the current IKE SA has been up -- since the handshake, or since
    /// the last rekey of it by either side. A caller keeping ahead of the IKE
    /// SA's lifetime rekeys ([`Self::rekey_ike`]) once this reaches the
    /// fraction of it it wants.
    pub fn ike_sa_age(&self) -> Duration {
        self.ike.since.elapsed()
    }

    /// Rekey the IKE SA itself (RFC 7296 §1.3.2, §2.18): a `CREATE_CHILD_SA`
    /// with a fresh DH exchange yields new IKE keys and SPIs, the CHILD SAs
    /// (and so the tunnel's data plane) carry on untouched, and the old IKE SA
    /// is deleted. Without this the IKE SA runs into its lifetime -- a gateway
    /// such as strongSwan starts its own rekey well before that, which this
    /// side could only refuse, and then destroys the SA at its hard limit,
    /// taking the tunnel with it.
    ///
    /// [`Liveness::Alive`]: rekeyed. [`Liveness::NoReply`]: the peer never
    /// answered; the old IKE SA is left as it was. [`Liveness::PeerTornDown`]:
    /// the peer deleted the tunnel meanwhile. A refusal is an `Err`
    /// ([`IkeError::PeerRejected`]) and leaves the old IKE SA as it was.
    ///
    /// This is how an IKE SA whose Message IDs have run out
    /// ([`Self::message_ids_exhausted`]) goes on, and it may use the last few
    /// kept for it. Once even those are gone it fails with
    /// [`IkeError::MessageIdsExhausted`] without sending anything, and the
    /// IKE SA can only be dropped.
    ///
    /// The peer may rekey the IKE SA too while ours is in flight (RFC 7296
    /// §2.8.2). Its rekey is answered as usual, so three IKE SAs exist once
    /// ours is answered too: the new one made with the lowest of the four
    /// nonces is redundant and is deleted by whoever made it, the other one
    /// takes over the CHILD SAs, and whoever made that one deletes the old IKE
    /// SA. If ours came to nothing instead -- the peer refused it with
    /// `TEMPORARY_FAILURE`, having finished its own first, or deleted the old
    /// IKE SA without ever answering it -- the peer's IKE SA stands. Either
    /// way the tunnel carries on under the survivor, and this is
    /// [`Liveness::Alive`].
    pub fn rekey_ike(&mut self, timeout: Duration) -> Result<Liveness, DriverError> {
        let mut entropy = OsEntropy::new()?;
        let mut ni = vec![0u8; NONCE_LEN];
        entropy.fill(&mut ni);
        let mut dh_private = [0u8; 32];
        entropy.fill(&mut dh_private);
        let new_spi_i = loop {
            let spi = entropy.next_u64();
            if spi != 0 {
                break spi;
            }
        };
        let mut iv = [0u8; 8];
        entropy.fill(&mut iv);
        let mid = self.alloc_ending_message_id()?;
        ike_debug!("CREATE_CHILD_SA (IKE SA rekey): initiating -- new_spi_i={new_spi_i:016x}");
        let req = ike_rekey::build_ike_rekey_request(&self.sa, mid, new_spi_i, &ni, &dh_private, &iv)?;
        self.ike.rekeying = Some(OwnIkeRekey::default());
        let reply = self.request_response(&wrap(&req, self.float), mid, timeout);
        let own = self.ike.rekeying.take().unwrap_or_default();
        let ours = match reply {
            Ok(Reply::PeerTornDown) => return Ok(Liveness::PeerTornDown),
            Ok(Reply::Response(response)) => Some(
                ike_rekey::initiator_complete_ike_rekey(&self.sa, &ni, new_spi_i, &dh_private, &response)
                    .map(|new_sa| (new_sa, ni.min(rekey::peer_child_nonce(&self.sa, &response).unwrap_or_default())))
                    .map_err(DriverError::from),
            ),
            Ok(Reply::Unanswered) => None,
            Err(e) => Some(Err(e)),
        };
        let Some(crossed) = own.crossed else {
            return match ours {
                Some(Ok((new_sa, _))) => {
                    self.finish_ike_rekey(new_sa);
                    Ok(Liveness::Alive)
                }
                Some(Err(e)) => Err(e),
                None => Ok(Liveness::NoReply),
            };
        };
        match ours {
            Some(Ok((new_sa, our_lowest))) if our_lowest < crossed.lowest_nonce => {
                ike_debug!("CREATE_CHILD_SA (IKE SA rekey): the peer rekeyed the IKE SA too -- ours holds the lowest nonce, deleting it and keeping the peer's");
                // Ours is deleted like any IKE SA, on it (RFC 7296 §1.4.1),
                // and meanwhile the peer deletes the old one, which is routine.
                self.ike.retired = Some(self.switch_ike_sa(new_sa));
                if let Err(e) = self.delete_ike_sa("the redundant IKE SA of a simultaneous rekey") {
                    ike_debug!("CREATE_CHILD_SA (IKE SA rekey): failed to delete the redundant IKE SA: {e}");
                }
                self.switch_ike_sa(crossed.sa);
            }
            Some(Ok((new_sa, _))) => {
                ike_debug!("CREATE_CHILD_SA (IKE SA rekey): the peer rekeyed the IKE SA too -- its new SA holds the lowest nonce, the peer deletes it; keeping ours");
                // Its Delete comes on it, and is routine.
                self.ike.retired = Some(RetiredIkeSa::new(crossed.sa, PeerRequests::default()));
                self.finish_ike_rekey(new_sa);
            }
            ours => {
                let why = match ours {
                    Some(Err(e)) => e.to_string(),
                    _ if own.old_deleted => "the peer deleted the IKE SA it replaced".to_string(),
                    _ => "no answer".to_string(),
                };
                ike_debug!("CREATE_CHILD_SA (IKE SA rekey): ours came to nothing ({why}), but the peer rekeyed the IKE SA meanwhile -- moving to its SA");
                self.move_to_peers_ike_sa(crossed.sa);
            }
        }
        Ok(Liveness::Alive)
    }

    /// Move to `new_sa`, the IKE SA our own rekey made, deleting the one it
    /// replaced first.
    fn finish_ike_rekey(&mut self, new_sa: CompletedSaInit) {
        ike_debug!("CREATE_CHILD_SA (IKE SA rekey): complete -- new spi_i={:016x} spi_r={:016x}", new_sa.spi_i, new_sa.spi_r);
        // RFC 7296 §2.18: the rekey's initiator deletes the old IKE SA, with an
        // INFORMATIONAL on that SA. Best-effort like `close`: the new SA is
        // already valid whether or not the peer sees or acks this.
        if let Err(e) = self.delete_ike_sa("the IKE SA our rekey replaced") {
            ike_debug!("CREATE_CHILD_SA (IKE SA rekey): failed to delete the old IKE SA (new IKE SA unaffected): {e}");
        }
        self.switch_ike_sa(new_sa);
    }

    /// Send `wire`, a request already built for Message ID `mid`, and wait for
    /// its response, retransmitting the identical bytes (RFC 7296 §2.1) a few
    /// times when `timeout` passes without one. Only the genuine answer counts
    /// (see [`Self::is_answer`]); anything else with its Message ID is passed
    /// over. Requests the peer sends meanwhile are answered as usual.
    /// [`Reply::Unanswered`] too when the peer deleted the IKE SA after
    /// rekeying it itself (see [`OwnIkeRekey::old_deleted`]): no answer is
    /// coming.
    fn request_response(&mut self, wire: &[u8], mid: u32, timeout: Duration) -> Result<Reply, DriverError> {
        const ATTEMPTS: u32 = 3;
        let exchange = IkeHeader::parse(&unwrap(wire, self.float)?)?.exchange_type;
        let mut answer = Reassembly::new(self.answer_key(mid, exchange));
        for attempt in 0..ATTEMPTS {
            if attempt > 0 {
                ike_debug!("request {mid}: retransmitting to {} (attempt {}/{ATTEMPTS})", self.dest, attempt + 1);
            }
            crate::debug::dump(">>>", self.dest, wire);
            self.sock.send_to(wire, self.dest)?;
            let deadline = Instant::now() + timeout;
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                self.sock.set_read_timeout(Some(remaining))?;
                let mut buf = [0u8; 8192];
                let n = match self.recv_datagram(&mut buf, remaining) {
                    Ok(n) => n,
                    Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => break,
                    Err(e) => return Err(e.into()),
                };
                crate::debug::dump("<<<", self.dest, &buf[..n]);
                let Ok(msg) = unwrap(&buf[..n], self.float) else { continue };
                let Ok(header) = IkeHeader::parse(&msg) else { continue };
                let (header, msg) = if header.next_payload == PayloadType::EncryptedFragment {
                    match self.take_fragment(&header, &msg, Some(&mut answer))? {
                        Fragmented::Whole(header, msg) => (header, msg),
                        Fragmented::Pending => continue,
                        Fragmented::AnsweredAgain { tears_down: true } => return Ok(Reply::PeerTornDown),
                        Fragmented::AnsweredAgain { tears_down: false } => continue,
                    }
                } else {
                    (header, msg)
                };
                if header.flags.response {
                    if self.is_answer(&header, &msg, mid, exchange) {
                        return Ok(Reply::Response(msg));
                    }
                    continue; // stale, unrelated or forged -- keep waiting
                }
                if self.answer_peer_request(&header, &msg)? {
                    return Ok(Reply::PeerTornDown);
                }
                if self.ike.rekeying.as_ref().is_some_and(|own| own.old_deleted) {
                    return Ok(Reply::Unanswered);
                }
            }
        }
        Ok(Reply::Unanswered)
    }
}

/// A blocking IKEv2 initiator session, driven by an [`Entropy`] source.
pub struct Ikev2Session<E> {
    entropy: E,
    /// Force NAT-T whatever NAT detection says -- see [`Self::with_forced_natt`].
    force_natt: bool,
    /// Offer IPv4 and IPv6 together in IKE_AUTH -- see [`Self::with_unified_ts`].
    unified_ts: bool,
}

/// The local IP our packets actually carry as their source when reaching
/// `peer`, resolved via the OS routing table (see
/// `examples/ike_client_eap_fortigate.rs`'s `local_addr_for` — same trick:
/// a throwaway UDP `connect` picks the route without sending anything). Only
/// the IP is used -- the actual IKE socket always binds a literal well-known
/// port (see [`Ikev2Session::sa_init_on_port`]), not whatever ephemeral port
/// this probe happens to get.
fn local_ip_for(peer: SocketAddr) -> io::Result<std::net::IpAddr> {
    crate::transport::local_ip_for(peer)
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

/// Like [`send_and_retry`], for the `IKE_AUTH` request `wire` (sealed under
/// `cipher`; `sk_e`/`sk_a` are the *peer's* send keys, the ones the caller
/// then opens the answer with): returns the peer's response to it, whole or
/// reassembled from RFC 7383 fragments.
///
/// - Only a datagram answering this request is looked at: the response on
///   the request's IKE SA, exchange and Message ID, from the other side
///   ([`MessageKey`]). Anything else, IKE or not, is passed over.
/// - A whole response must authenticate (RFC 7296 §2.21.3); one that does
///   not is passed over, and the wait goes on.
/// - A fragment goes to a [`Reassembly`], which authenticates it before it
///   counts, drops replays and follows the Total Fragments rules of RFC 7383
///   §2.6. Once complete, the message is sealed again as one ordinary `SK`
///   message under the same peer keys, so the callers, which open `SK`
///   messages, need not know fragments exist.
/// - The request is retransmitted on the [`RETRY_BACKOFFS`] schedule until
///   the whole response is in (RFC 7296 §2.1, RFC 7383 §2.6: a responder
///   answers a retransmission with its whole response again). Fragments in
///   hand are kept across retransmissions, since the peer resends the same
///   ones, and dropped when the last attempt times out.
fn send_and_retry_reassembling(
    sock: &UdpSocket,
    dest: SocketAddr,
    wire: &[u8],
    float: bool,
    cipher: SkCipher,
    sk_e: &[u8],
    sk_a: &[u8],
) -> Result<Vec<u8>, DriverError> {
    let request = IkeHeader::parse(&unwrap(wire, float)?)?;
    let key = MessageKey { initiator: !request.flags.initiator, response: true, ..MessageKey::of(&request) };
    let mut reassembly = Reassembly::new(key);
    let mut buf = [0u8; MAX_DATAGRAM];
    for (attempt, timeout) in RETRY_BACKOFFS.iter().enumerate() {
        if attempt > 0 {
            ike_debug!("retransmitting request to {dest} (attempt {}/{})", attempt + 1, RETRY_BACKOFFS.len());
        }
        crate::debug::dump(">>>", dest, wire);
        sock.send_to(wire, dest)?;
        let deadline = Instant::now() + *timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            sock.set_read_timeout(Some(remaining))?;
            let n = match sock.recv(&mut buf) {
                Ok(n) => n,
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => break,
                Err(e) => return Err(e.into()),
            };
            crate::debug::dump("<<<", dest, &buf[..n]);
            let Ok(msg) = unwrap(&buf[..n], float) else { continue };
            let Ok(header) = IkeHeader::parse(&msg) else { continue };
            if MessageKey::of(&header) != key {
                continue;
            }
            if header.next_payload != PayloadType::EncryptedFragment {
                if sk::open_encrypted(cipher, &msg, sk_e, sk_a).is_ok() {
                    return Ok(msg);
                }
                ike_debug!("response {}: does not authenticate -- dropped", key.message_id);
                continue;
            }
            match reassembly.accept(&msg, cipher, sk_e, sk_a) {
                Accepted::Complete(first_inner, inner) => {
                    ike_debug!("response {}: reassembled from fragments (RFC 7383)", key.message_id);
                    let mut iv = [0u8; 8];
                    OsEntropy::new()?.fill(&mut iv);
                    return Ok(sk::build_encrypted(cipher, header, first_inner, &inner, sk_e, sk_a, &iv)?);
                }
                Accepted::Stored => {}
                Accepted::Discarded(why) => ike_debug!("response {}: fragment dropped: {why}", key.message_id),
            }
        }
    }
    let what = if reassembly.is_empty() { "no response" } else { "the response came in part" };
    Err(io::Error::new(io::ErrorKind::TimedOut, format!("{what} after {} attempts", RETRY_BACKOFFS.len())).into())
}

/// Whether `header` is that of a message from the peer on the IKE SA `sa`
/// (RFC 7296 §3.1): its SPIs, and the Initiator flag of the peer's role in it
/// -- set when the peer is the IKE SA's original initiator, which after a
/// rekey is whoever started the rekey (§2.18).
fn from_peer_on(sa: &CompletedSaInit, header: &IkeHeader) -> bool {
    header.initiator_spi == sa.spi_i && header.responder_spi == sa.spi_r && header.flags.initiator == (sa.role == Role::Responder)
}

/// A message from the peer on `sa`, reassembled from fragments: `header`
/// (that of its fragments), `first` and `inner` sealed as one `SK` message
/// under the peer's keys, for the code that opens those.
fn whole_from_peer(sa: &CompletedSaInit, header: IkeHeader, first: PayloadType, inner: &[u8]) -> Result<Fragmented, DriverError> {
    let mut iv = [0u8; 8];
    OsEntropy::new()?.fill(&mut iv);
    let msg = sk::build_encrypted(sa.suite.sk_cipher(), header, first, inner, peer_sk_e(sa), peer_sk_a(sa), &iv)?;
    Ok(Fragmented::Whole(IkeHeader::parse(&msg)?, msg))
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
fn notify_ike_sa_delete_on_failed_auth(sock: &UdpSocket, sa: &CompletedSaInit, dest: SocketAddr, float: bool, last_received: &[u8], reason: &str) {
    let Ok(mid) = IkeHeader::parse(last_received).map(|h| h.message_id + 1) else { return };
    let mut iv = [0u8; 8];
    let Ok(mut entropy) = OsEntropy::new() else { return };
    entropy.fill(&mut iv);
    let Ok(del) = build_informational(sa, mid, false, &[(PayloadType::Delete, Delete::ike_sa().to_bytes())], &iv) else { return };
    ike_debug!("INFORMATIONAL: sending IKE_SA Delete to {dest} ({reason})");
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

/// What a CFG_REPLY tells [`ConnectedTunnel`], read the same way after every
/// flavour of `IKE_AUTH`.
#[derive(Default)]
struct CfgInfo {
    dns: Vec<Ipv4Addr>,
    dns6: Vec<Ipv6Addr>,
    subnets: Vec<(Ipv4Addr, u8)>,
    assigned_ip6: Option<(Ipv6Addr, u8)>,
    subnets6: Vec<(Ipv6Addr, u8)>,
}

impl CfgInfo {
    fn from_reply(reply: Option<&Configuration>) -> Self {
        let Some(cp) = reply else { return Self::default() };
        CfgInfo {
            dns: cp.assigned_dns(),
            dns6: cp.assigned_ipv6_dns(),
            subnets: cp.assigned_subnets(),
            assigned_ip6: cp.assigned_ipv6(),
            subnets6: cp.assigned_ipv6_subnets(),
        }
    }
}

/// How the responder answered the CHILD SA offer of `IKE_AUTH`, family-wise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChildGrant {
    /// An IPv4 CHILD SA -- what was offered, or what a unified offer was
    /// narrowed to (RFC 7296 §2.9), or all a missing/unreadable `TSr` allows
    /// us to assume.
    Ipv4Only,
    /// A unified offer granted with both families.
    Both,
    /// A unified offer answered with IPv6 alone -- nothing carries IPv4.
    Ipv6Only,
}

impl ChildGrant {
    fn classify(offered: ChildTsOffer, tsr: Option<&TrafficSelectors>) -> Self {
        let Some(tsr) = tsr.filter(|_| offered == ChildTsOffer::Unified) else { return ChildGrant::Ipv4Only };
        match (tsr.has_ipv4(), tsr.has_ipv6()) {
            (true, true) => ChildGrant::Both,
            (false, true) => ChildGrant::Ipv6Only,
            _ => ChildGrant::Ipv4Only,
        }
    }
}

/// The IKE SA an `IKE_AUTH` exchange left standing, before any CHILD SA of
/// its own exists -- everything [`Ikev2Session::recover_child_after_rejection`]
/// needs to carry on with it.
struct EstablishedIke {
    sock: UdpSocket,
    sa: CompletedSaInit,
    dest: SocketAddr,
    float: bool,
    /// The next Message ID we may originate.
    next_message_id: u32,
    our_addr: SocketAddr,
    nat: NatStatus,
}

/// Best-effort close of an IKE SA whose `IKE_AUTH` gave a CHILD SA we can't
/// use (an IPv6-only grant of a unified offer): the error to hand the caller,
/// which reads as the gateway having refused our TS.
fn reject_unusable_grant(sock: &UdpSocket, sa: &CompletedSaInit, dest: SocketAddr, float: bool, last_received: &[u8]) -> DriverError {
    ike_debug!("IKE_AUTH: the unified offer was granted IPv6 only -- nothing would carry IPv4");
    notify_ike_sa_delete_on_failed_auth(sock, sa, dest, float, last_received, "CHILD SA grants no IPv4");
    IkeError::PeerRejected {
        notify_type: notify_type::TS_UNACCEPTABLE,
        name: notify_type_name(notify_type::TS_UNACCEPTABLE),
    }
    .into()
}

impl<E: Entropy> Ikev2Session<E> {
    pub fn new(entropy: E) -> Self {
        Self { entropy, force_natt: false, unified_ts: false }
    }

    /// Makes every `IKE_SA_INIT` this session runs **force** NAT-T (what strongSwan
    /// calls `forceencaps=yes`): the request's `NAT_DETECTION_SOURCE_IP` lies about
    /// our address ([`crate::initiator_request_natt_with`]), so the gateway floats
    /// to UDP 4500 and sends ESP as ESP-in-UDP, and this side floats with it
    /// ([`NatStatus::forced`]). For a data plane that can only receive ESP inside
    /// UDP -- an IPv6 gateway has no NAT in between to make that happen by itself.
    /// The gateway must accept NAT-T on the transport in use.
    pub fn with_forced_natt(mut self) -> Self {
        self.force_natt = true;
        self
    }

    /// Offer `0.0.0.0/0` and `::/0` together in the `IKE_AUTH` CHILD SA
    /// (RFC 7296 §2.9), so one CHILD SA can carry both families -- what a
    /// conforming responder (strongSwan) grants outright. Off by default: the
    /// IPv4-only offer is the one every gateway this has met accepts, and how
    /// FortiGate reacts to a mixed one is not known. What follows is decided
    /// by the answer:
    ///
    /// * both families granted -> one CHILD SA carries both
    ///   ([`ConnectedTunnel::child_subnets6`], [`LivenessSession::child_carries_ipv6`]);
    /// * narrowed to IPv4 (or no `TSr` to read) -> the usual IPv4 tunnel;
    ///   IPv6, if wanted, is added as a CHILD SA of its own afterwards
    ///   ([`LivenessSession::create_child_ipv6`]);
    /// * the CHILD SA refused (RFC 7296 §1.2: an authenticated peer keeps the
    ///   IKE SA) -> the IPv4 CHILD SA is created on that same IKE SA with
    ///   `CREATE_CHILD_SA`, provided any requested CFG came with the refusal;
    ///   otherwise the IKE SA is closed and the refusal is returned
    ///   ([`IkeError::PeerRejected`]) for the caller to retry without this flag;
    /// * granted IPv6 only -> treated as a refusal, the IKE SA is closed.
    ///
    /// IKEv2 only: IKEv1 negotiates each family in its own Quick Mode.
    pub fn with_unified_ts(mut self) -> Self {
        self.unified_ts = true;
        self
    }

    fn ts_offer(&self) -> ChildTsOffer {
        if self.unified_ts { ChildTsOffer::Unified } else { ChildTsOffer::Ipv4 }
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
        let wildcard = crate::transport::wildcard_for(peer);
        let sock = UdpSocket::bind((wildcard, local_port))?;
        let natt_sock = UdpSocket::bind((wildcard, natt_local_port(local_port)))?;
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
    /// Run `IKE_SA_INIT` to completion over `sock`, transparently retrying
    /// through a `COOKIE` challenge and/or an `INVALID_KE_PAYLOAD` correction
    /// (RFC 7296 §2.6, §1.2/§2.7): a responder under load, or one that just
    /// doesn't support our guessed DH group, answers with a bare Notify and
    /// keeps no state at all -- the previous behavior surfaced that as a
    /// generic parse failure (`MissingPayload("SA")` or `PeerRejected`),
    /// which is indistinguishable from an outright refusal, so this crate
    /// gave up against a perfectly healthy gateway. Bounded to
    /// `MAX_SA_INIT_CHALLENGES` extra round trips -- enough for either
    /// challenge alone or a COOKIE-then-INVALID_KE chain -- so a responder
    /// that keeps challenging forever (buggy or hostile) can't hang this.
    fn sa_init_round_trip(
        &mut self,
        local: &LocalSecret,
        offer: &SecurityAssociation,
        our_addr: SocketAddr,
        peer: SocketAddr,
        sock: &UdpSocket,
    ) -> Result<(CompletedSaInit, NatStatus), DriverError> {
        const MAX_SA_INIT_CHALLENGES: u32 = 2;
        let mut cookie: Option<Vec<u8>> = None;
        let mut ke_group: Option<DhGroup> = None;
        let mut challenges = 0u32;
        loop {
            let req = initiator_request_natt_retry(local, offer, our_addr, peer, self.force_natt, cookie.as_deref(), ke_group);
            ike_debug!("IKE_SA_INIT: sending to {peer} (spi_i={:016x})", local.spi);
            let resp = send_and_retry(sock, peer, &req)?;
            match initiator_complete_natt(local, &req, &resp, our_addr, peer) {
                Ok(outcome) => return Ok(outcome),
                Err(IkeError::CookieRequired { cookie: c }) if challenges < MAX_SA_INIT_CHALLENGES => {
                    ike_debug!("IKE_SA_INIT: responder requires a return-routability cookie (RFC 7296 §2.6) -- retrying with it echoed back");
                    cookie = Some(c);
                    challenges += 1;
                }
                Err(IkeError::InvalidKeGroup(group)) if challenges < MAX_SA_INIT_CHALLENGES => {
                    let Some(group) = DhGroup::from_transform_id(group) else {
                        return Err(IkeError::InvalidKeGroup(group).into());
                    };
                    ike_debug!("IKE_SA_INIT: responder wants a different DH group (RFC 7296 §2.7, INVALID_KE_PAYLOAD) -- retrying");
                    ke_group = Some(group);
                    challenges += 1;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

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
        let (sa, mut nat) = self.sa_init_round_trip(&local, offer, our_addr, peer, &sock)?;
        nat.forced = self.force_natt;
        ike_debug!(
            "IKE_SA_INIT: matched proposal #{} encr={} prf={} integ={:?} dh={}",
            sa.suite.proposal_num, sa.suite.encr_id, sa.suite.prf_id, sa.suite.integ_id, sa.suite.dh_id
        );
        ike_debug!(
            "IKE_SA_INIT: NAT detection -- we_are_natted={} peer_is_natted={} forced={} ({})",
            nat.we_are_natted, nat.peer_is_natted, nat.forced,
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

    /// RFC 7296 §1.2 recovery for a unified offer ([`Self::with_unified_ts`])
    /// the gateway refused at `IKE_AUTH`: the IKE SA is standing (its AUTH
    /// verified), only the CHILD SA failed -- typically because the peer keeps
    /// one selector family per policy (FortiGate). So the IPv4 CHILD SA is
    /// created on that same IKE SA with `CREATE_CHILD_SA`, and IPv6 is left to
    /// the usual CHILD SA of its own ([`LivenessSession::create_child_ipv6`]).
    ///
    /// Needs the inner address to have arrived with the refusal when CFG was
    /// requested (`cfg_reply`): mode-config only travels in `IKE_AUTH`, so
    /// without it nothing could configure the tunnel. Whenever the recovery
    /// can't be completed the IKE SA is closed and an error returned -- the
    /// original `rejection` where the recovery never got going, so a caller
    /// can retry the whole connect without the unified offer.
    fn recover_child_after_rejection(
        &mut self,
        ike: EstablishedIke,
        want_cfg: bool,
        cfg_reply: Option<Configuration>,
        esp_offer: &SecurityAssociation,
        rejection: IkeError,
    ) -> Result<ConnectedTunnel, DriverError> {
        const CHILD_TIMEOUT: Duration = Duration::from_secs(10);
        let EstablishedIke { sock, sa, dest, float, next_message_id, our_addr, nat } = ike;
        let info = CfgInfo::from_reply(cfg_reply.as_ref());
        let assigned_ip4 = cfg_reply.as_ref().and_then(Configuration::assigned_ipv4);
        let cipher = negotiate::select_esp(esp_offer).and_then(|s| s.sk_cipher());
        let mut liveness = LivenessSession {
            sock,
            sa,
            dest,
            float,
            next_message_id,
            cipher: cipher.unwrap_or(SkCipher::Aes256Gcm),
            pfs: PfsPolicy::from_offer(esp_offer)?,
            child_local_spi: 0,
            child_peer_spi: 0,
            external_rx: None,
            child6: None,
            cfg_subnets6: info.subnets6.clone(),
            child_carries_ipv6: false,
            ike: IkeSaState::new(),
            peer_child: PeerChildState::default(), primary_child_alive: true, peer_requests: PeerRequests::default(),
        };
        if want_cfg && assigned_ip4.is_none() {
            ike_debug!("IKE_AUTH: CHILD SA refused ({rejection}) and no CFG_REPLY came with it -- no inner address to build on, closing");
            let _ = liveness.close();
            return Err(rejection.into());
        }
        if cipher.is_none() {
            ike_debug!("IKE_AUTH: CHILD SA refused ({rejection}), and the ESP offer names no cipher this crate implements -- closing");
            let _ = liveness.close();
            return Err(rejection.into());
        }
        ike_debug!("IKE_AUTH: CHILD SA refused ({rejection}) -- keeping the IKE SA, creating the IPv4 CHILD SA with CREATE_CHILD_SA");
        let (child, tsr) = match liveness.child_exchange(
            None,
            &TrafficSelectors::ipv4_full_tunnel(),
            "IPv4 CHILD SA after a refused IKE_AUTH offer",
            CHILD_TIMEOUT,
        ) {
            Ok(v) => v,
            Err(e) => {
                ike_debug!("IKE_AUTH: creating the IPv4 CHILD SA on the surviving IKE SA failed: {e}");
                let _ = liveness.close();
                return Err(e);
            }
        };
        if !tsr.as_ref().is_some_and(|t| t.has_ipv4()) {
            ike_debug!("CREATE_CHILD_SA (IPv4 after a refused IKE_AUTH offer): reply granted no IPv4 traffic selector (TSr={tsr:?}) -- closing");
            let _ = liveness.delete_child_sa(ChildSpis::of(&child));
            let _ = liveness.close();
            return Err(IkeError::PeerRejected {
                notify_type: notify_type::TS_UNACCEPTABLE,
                name: notify_type_name(notify_type::TS_UNACCEPTABLE),
            }
            .into());
        }
        liveness.child_local_spi = child.local_spi;
        liveness.child_peer_spi = child.peer_spi;
        Ok(ConnectedTunnel {
            local_spi: child.local_spi,
            peer_spi: child.peer_spi,
            key_out: child.key_out,
            key_in: child.key_in,
            assigned_ip4,
            dns: info.dns,
            dns6: info.dns6,
            assigned_ip6: info.assigned_ip6,
            cfg_subnets6: info.subnets6,
            child_subnets6: Vec::new(),
            subnet: info.subnets.first().copied(),
            granted_subnets: granted_subnets(tsr.as_ref(), &info.subnets),
            local_addr: our_addr,
            peer_addr: dest,
            nat,
            liveness,
        })
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
        // A PFS group the ESP offer asks for and IKEv2 can't run fails here,
        // before the gateway sees anything, not as a tunnel without PFS.
        PfsPolicy::from_offer(esp_offer)?;
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
        // A PFS group the ESP offer asks for and IKEv2 can't run fails here,
        // before the gateway sees anything, not as a tunnel without PFS.
        PfsPolicy::from_offer(esp_offer)?;
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
        let ts_offer = self.ts_offer();

        let mut iv = [0u8; 8];
        self.entropy.fill(&mut iv);
        let req = ike_auth::initiator_auth_request_with_cfg(&sa, cfg, local_spi, want_cfg, esp_offer, ts_offer, &iv)?;
        ike_debug!("IKE_AUTH: sending to {dest} (local_spi={local_spi:08x}, floated={float}, ts={ts_offer:?})");
        let wire = wrap(&req, float);
        let response =
            send_and_retry_reassembling(&sock, dest, &wire, float, sa.suite.sk_cipher(), &sa.keys.sk_er, &sa.keys.sk_ar)?;

        let (_peer_id, peer_spi, esp_suite, assigned_ip4, tsr) = match ike_auth::initiator_verify_auth(&sa, &response, cfg, esp_offer) {
            Ok(v) => v,
            Err(e) => {
                // RFC 7296 §1.2: an authenticated peer that refused only the
                // CHILD SA keeps the IKE SA standing. When the refused offer
                // was a unified one that IKE SA is put to use (see
                // `recover_child_after_rejection`); otherwise there is nothing
                // to carry traffic on it, so it is closed (rather than left
                // for the gateway to time out) either way.
                let reason = if matches!(e, IkeError::PeerRejected { .. }) {
                    ike_debug!("IKE_AUTH: authenticated, but the peer rejected the CHILD SA: {e}");
                    if ts_offer == ChildTsOffer::Unified {
                        let cfg_reply = want_cfg.then(|| scan_cfg_reply(&response, &sa)).flatten();
                        let next_message_id = IkeHeader::parse(&response)?.message_id + 1;
                        let ike = EstablishedIke { sock, sa, dest, float, next_message_id, our_addr, nat };
                        return self.recover_child_after_rejection(ike, want_cfg, cfg_reply, esp_offer, e);
                    }
                    "CHILD SA rejected"
                } else {
                    ike_debug!("IKE_AUTH: peer authentication failed: {e}");
                    "authentication failed"
                };
                notify_ike_sa_delete_on_failed_auth(&sock, &sa, dest, float, &response, reason);
                return Err(e.into());
            }
        };
        ike_debug!("IKE_AUTH: authenticated -- peer_spi={peer_spi:08x} assigned_ip={assigned_ip4:?}");
        let grant = ChildGrant::classify(ts_offer, tsr.as_ref());
        if grant == ChildGrant::Ipv6Only {
            return Err(reject_unusable_grant(&sock, &sa, dest, float, &response));
        }
        let cfg_reply = want_cfg.then(|| scan_cfg_reply(&response, &sa)).flatten();
        let info = CfgInfo::from_reply(cfg_reply.as_ref());
        ike_debug!("IKE_AUTH: CFG_REPLY IPv6 -- assigned_ipv6={:?} assigned_ipv6_subnets={:?}", info.assigned_ip6, info.subnets6);
        let child_subnets6 = if grant == ChildGrant::Both { granted_subnets_v6(tsr.as_ref(), &info.subnets6) } else { Vec::new() };
        ike_debug!("IKE_AUTH: offered {ts_offer:?}, granted {grant:?} (TSr={tsr:?})");

        let cipher = resolve_esp_cipher(esp_suite)?;
        let (key_out, key_in) = Self::derive_keys(&sa, cipher);
        let pfs = PfsPolicy::from_offer(esp_offer)?;
        let liveness = LivenessSession {
            sock,
            sa,
            dest,
            float,
            next_message_id: 2, // IKE_AUTH was message 1
            cipher,
            pfs,
            child_local_spi: local_spi,
            child_peer_spi: peer_spi,
            external_rx: None,
            child6: None,
            cfg_subnets6: info.subnets6.clone(),
            child_carries_ipv6: !child_subnets6.is_empty(),
            ike: IkeSaState::new(),
            peer_child: PeerChildState::default(), primary_child_alive: true, peer_requests: PeerRequests::default(),
        };
        Ok(ConnectedTunnel {
            local_spi,
            peer_spi,
            key_out,
            key_in,
            assigned_ip4,
            dns: info.dns,
            dns6: info.dns6,
            assigned_ip6: info.assigned_ip6,
            cfg_subnets6: info.subnets6,
            child_subnets6,
            subnet: info.subnets.first().copied(),
            granted_subnets: granted_subnets(tsr.as_ref(), &info.subnets),
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
        // A PFS group the ESP offer asks for and IKEv2 can't run fails here,
        // before the gateway sees anything, not as a tunnel without PFS.
        PfsPolicy::from_offer(esp_offer)?;
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
        // A PFS group the ESP offer asks for and IKEv2 can't run fails here,
        // before the gateway sees anything, not as a tunnel without PFS.
        PfsPolicy::from_offer(esp_offer)?;
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
        // A PFS group the ESP offer asks for and IKEv2 can't run fails here,
        // before the gateway sees anything, not as a tunnel without PFS.
        PfsPolicy::from_offer(esp_offer)?;
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
        let ts_offer = self.ts_offer();

        ike_debug!("IKE_AUTH (EAP-MSCHAPv2): starting as user '{}' against {dest} (ts={ts_offer:?})", String::from_utf8_lossy(&creds.user));
        let mut initiator =
            EapInitiator::new_with_esp_offer(sa, local_id, creds.user, creds.password, local_spi, esp_offer.clone(), verify);
        // want_cfg: whether this peer is configured for mode-config -- a real
        // FortiGate dialup policy otherwise answers "mode-cfg not completed"
        // and tears the IKE SA down right after EAP succeeds; a responder not
        // using mode-config at all just ignores an unused CFG_REQUEST, but
        // the flag stays caller-driven rather than always-on so the wire
        // behavior matches what the profile actually negotiated.
        initiator.set_want_cfg(want_cfg);
        initiator.set_ts_offer(ts_offer);
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
            let event = match initiator.handle(&ike_msg, &mut self.entropy) {
                Ok(event) => event,
                // EAP finished and the AUTH verified, but the gateway refused
                // the CHILD SA (RFC 7296 §1.2) -- see `EapInitiator::handle`.
                Err(e @ IkeError::PeerRejected { .. }) => {
                    ike_debug!("IKE_AUTH (EAP-MSCHAPv2): authenticated, but the peer rejected the CHILD SA: {e}");
                    // A refused unified offer keeps the IKE SA in use -- see
                    // `recover_child_after_rejection`.
                    if ts_offer == ChildTsOffer::Unified {
                        let sa = initiator.ike_sa().clone();
                        let cfg_reply = want_cfg.then(|| scan_cfg_reply(&ike_msg, &sa)).flatten();
                        let next_message_id = IkeHeader::parse(&ike_msg)?.message_id + 1;
                        let ike = EstablishedIke { sock, sa, dest, float, next_message_id, our_addr, nat };
                        return self.recover_child_after_rejection(ike, want_cfg, cfg_reply, esp_offer, e);
                    }
                    notify_ike_sa_delete_on_failed_auth(&sock, initiator.ike_sa(), dest, float, &ike_msg, "CHILD SA rejected");
                    return Err(e.into());
                }
                Err(e) => return Err(e.into()),
            };
            match event {
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
                    notify_ike_sa_delete_on_failed_auth(&sock, initiator.ike_sa(), dest, float, &last_message, "authentication failed");
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
        let grant = ChildGrant::classify(ts_offer, tsr.as_ref());
        if grant == ChildGrant::Ipv6Only {
            return Err(reject_unusable_grant(&sock, sa, dest, float, &last_message));
        }
        let cfg_reply = scan_cfg_reply(&last_message, sa);
        let info = CfgInfo::from_reply(cfg_reply.as_ref());
        ike_debug!("IKE_AUTH (EAP): CFG_REPLY IPv6 -- assigned_ipv6={:?} assigned_ipv6_subnets={:?}", info.assigned_ip6, info.subnets6);
        let child_subnets6 = if grant == ChildGrant::Both { granted_subnets_v6(tsr.as_ref(), &info.subnets6) } else { Vec::new() };
        ike_debug!("IKE_AUTH (EAP): offered {ts_offer:?}, granted {grant:?} (TSr={tsr:?})");
        let (key_out, key_in) = Self::derive_keys(sa, cipher);
        // The next message ID we may originate is one past the last request
        // the peer sent us (its own EAP-round message IDs) -- our own
        // requests and the peer's share one strictly-increasing sequence.
        let next_message_id = IkeHeader::parse(&last_message)?.message_id + 1;
        let pfs = PfsPolicy::from_offer(esp_offer)?;
        let liveness = LivenessSession {
            sock,
            sa: sa.clone(),
            dest,
            float,
            next_message_id,
            cipher,
            pfs,
            child_local_spi: local_spi,
            child_peer_spi: peer_spi,
            external_rx: None,
            child6: None,
            cfg_subnets6: info.subnets6.clone(),
            child_carries_ipv6: !child_subnets6.is_empty(),
            ike: IkeSaState::new(),
            peer_child: PeerChildState::default(), primary_child_alive: true, peer_requests: PeerRequests::default(),
        };

        Ok(ConnectedTunnel {
            local_spi,
            peer_spi,
            key_out,
            key_in,
            assigned_ip4,
            dns: info.dns,
            dns6: info.dns6,
            assigned_ip6: info.assigned_ip6,
            cfg_subnets6: info.subnets6,
            child_subnets6,
            subnet: info.subnets.first().copied(),
            granted_subnets: granted_subnets(tsr.as_ref(), &info.subnets),
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
        initiator_complete, initiator_request, responder_respond, responder_respond_natt, SaInitResult,
    };
    use crate::ikev2::ike_auth::{responder_process_auth, AssignedConfig};
    use crate::ikev2::informational::open_informational;
    use crate::ikev2::message::Flags;
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
            LivenessSession { sock: probe_sock, sa: init_sa, dest: bind, float: false, next_message_id: 2, cipher: SkCipher::Aes256Gcm, pfs: PfsPolicy::none(), child_local_spi: 0, child_peer_spi: 0, external_rx: None, child6: None, cfg_subnets6: Vec::new(), child_carries_ipv6: false, ike: IkeSaState::new(), peer_child: PeerChildState::default(), primary_child_alive: true, peer_requests: PeerRequests::default() };
        assert_eq!(liveness.probe(Duration::from_secs(5)).unwrap(), Liveness::Alive);
        responder.join().unwrap();
    }

    #[test]
    fn liveness_probe_ignores_a_spoofed_response_with_the_right_message_id_but_no_real_key() {
        // An off-path attacker who observes/guesses the (sequential, not
        // secret) Message ID can trivially forge a response header with the
        // right id and the Response flag set -- but can't produce a payload
        // that decrypts under the real peer's keys. That must not count as
        // proof of liveness (RFC 7296 §2.4): a real DPD probe demands the
        // reply be crypto-authenticated, not just correlated by id.
        let bind = next_addr();
        let (init_sa, _resp_sa) = liveness_sa_pair();
        // A second, unrelated SA pair stands in for "an attacker with no
        // access to the real keys" -- its ciphertext is well-formed but
        // fails to authenticate under `init_sa`'s peer keys.
        let (_other_init, other_resp) = liveness_sa_pair();
        let responder = thread::spawn(move || {
            let sock = UdpSocket::bind(bind).unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut buf = [0u8; 2048];
            let (n, from) = sock.recv_from(&mut buf).unwrap();
            let req_id = IkeHeader::parse(&buf[..n]).unwrap().message_id;
            // Forged ack: right Message ID and Response flag, wrong keys.
            let forged = build_informational(&other_resp, req_id, true, &[], &[9u8; 8]).unwrap();
            sock.send_to(&forged, from).unwrap();
            // No genuine reply ever follows -- the peer is actually silent.
            // It stays bound, though, until the probe is done: the probe
            // retransmits after each timeout, and on Windows a retransmission
            // to a closed port comes back as WSAECONNRESET on its next recv.
            sock
        });
        thread::sleep(Duration::from_millis(50));

        let probe_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut liveness =
            LivenessSession { sock: probe_sock, sa: init_sa, dest: bind, float: false, next_message_id: 2, cipher: SkCipher::Aes256Gcm, pfs: PfsPolicy::none(), child_local_spi: 0, child_peer_spi: 0, external_rx: None, child6: None, cfg_subnets6: Vec::new(), child_carries_ipv6: false, ike: IkeSaState::new(), peer_child: PeerChildState::default(), primary_child_alive: true, peer_requests: PeerRequests::default() };
        // Must NOT report Alive on the forged datagram -- with no genuine
        // reply arriving, the probe times out instead.
        assert_eq!(liveness.probe(Duration::from_millis(300)).unwrap(), Liveness::NoReply);
        let _silent_peer = responder.join().unwrap();
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
            LivenessSession { sock: probe_sock, sa: init_sa, dest: bind, float: false, next_message_id: 2, cipher: SkCipher::Aes256Gcm, pfs: PfsPolicy::none(), child_local_spi: 0, child_peer_spi: 0, external_rx: None, child6: None, cfg_subnets6: Vec::new(), child_carries_ipv6: false, ike: IkeSaState::new(), peer_child: PeerChildState::default(), primary_child_alive: true, peer_requests: PeerRequests::default() };
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
            let msg = build_informational(&resp_sa, 0, false, &[(PayloadType::Delete, del.to_bytes())], &[7u8; 8]).unwrap();
            sock.send_to(&msg, from).unwrap();
            // Our probe owes this an ack per RFC 7296 even though it's
            // reporting the tunnel as gone -- confirm it actually arrives.
            let (n, _) = sock.recv_from(&mut buf).unwrap();
            let ack_header = IkeHeader::parse(&buf[..n]).unwrap();
            assert_eq!(ack_header.message_id, 0);
            assert!(ack_header.flags.response);
        });
        thread::sleep(Duration::from_millis(50));

        let probe_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut liveness =
            LivenessSession { sock: probe_sock, sa: init_sa, dest: bind, float: false, next_message_id: 2, cipher: SkCipher::Aes256Gcm, pfs: PfsPolicy::none(), child_local_spi: 0, child_peer_spi: 0, external_rx: None, child6: None, cfg_subnets6: Vec::new(), child_carries_ipv6: false, ike: IkeSaState::new(), peer_child: PeerChildState::default(), primary_child_alive: true, peer_requests: PeerRequests::default() };
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
            LivenessSession { sock: probe_sock, sa: init_sa, dest: bind, float: false, next_message_id: 2, cipher: SkCipher::Aes256Gcm, pfs: PfsPolicy::none(), child_local_spi: 0, child_peer_spi: 0, external_rx: None, child6: None, cfg_subnets6: Vec::new(), child_carries_ipv6: false, ike: IkeSaState::new(), peer_child: PeerChildState::default(), primary_child_alive: true, peer_requests: PeerRequests::default() };
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
            LivenessSession { sock: probe_sock, sa: init_sa, dest: unreachable, float: false, next_message_id: 2, cipher: SkCipher::Aes256Gcm, pfs: PfsPolicy::none(), child_local_spi: 0, child_peer_spi: 0, external_rx: None, child6: None, cfg_subnets6: Vec::new(), child_carries_ipv6: false, ike: IkeSaState::new(), peer_child: PeerChildState::default(), primary_child_alive: true, peer_requests: PeerRequests::default() };
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
            LivenessSession { sock: probe_sock, sa: init_sa, dest: unreachable, float: false, next_message_id: 2, cipher: SkCipher::Aes256Gcm, pfs: PfsPolicy::none(), child_local_spi: 0, child_peer_spi: 0, external_rx: None, child6: None, cfg_subnets6: Vec::new(), child_carries_ipv6: false, ike: IkeSaState::new(), peer_child: PeerChildState::default(), primary_child_alive: true, peer_requests: PeerRequests::default() };
        assert_eq!(liveness.probe(Duration::from_millis(300)).unwrap(), Liveness::NoReply);
    }

    #[test]
    fn peek_reports_alive_when_nothing_is_pending() {
        let (init_sa, _resp_sa) = liveness_sa_pair();
        let unreachable: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let probe_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut liveness =
            LivenessSession { sock: probe_sock, sa: init_sa, dest: unreachable, float: false, next_message_id: 2, cipher: SkCipher::Aes256Gcm, pfs: PfsPolicy::none(), child_local_spi: 0, child_peer_spi: 0, external_rx: None, child6: None, cfg_subnets6: Vec::new(), child_carries_ipv6: false, ike: IkeSaState::new(), peer_child: PeerChildState::default(), primary_child_alive: true, peer_requests: PeerRequests::default() };
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
            let msg = build_informational(&resp_sa, 0, false, &[(PayloadType::Delete, del.to_bytes())], &[7u8; 8]).unwrap();
            responder_sock.send_to(&msg, from).unwrap();
        });

        // A throwaway datagram so the responder above learns our ephemeral
        // port (peek() itself never sends anything) -- an unrelated garbage
        // packet the responder just uses for its return address, discarded
        // on our side by peek() itself once the real Delete follows.
        let probe_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        probe_sock.send_to(b"hello", bind).unwrap();

        let mut liveness =
            LivenessSession { sock: probe_sock, sa: init_sa, dest: bind, float: false, next_message_id: 2, cipher: SkCipher::Aes256Gcm, pfs: PfsPolicy::none(), child_local_spi: 0, child_peer_spi: 0, external_rx: None, child6: None, cfg_subnets6: Vec::new(), child_carries_ipv6: false, ike: IkeSaState::new(), peer_child: PeerChildState::default(), primary_child_alive: true, peer_requests: PeerRequests::default() };
        assert_eq!(liveness.peek(Duration::from_secs(5)).unwrap(), Liveness::PeerTornDown);
        responder.join().unwrap();
    }

    /// A peer's CREATE_CHILD_SA (naming `rekeyed` in its `REKEY_SA`, or none for
    /// a brand-new CHILD SA) delivered to a session whose primary CHILD SA is
    /// `0xBBBB` inbound / `0xAAAA` outbound and whose IPv6 one is `child6`.
    /// Returns the answer as the peer receives it, the peer's IKE SA (to open
    /// it with) and the session afterwards.
    fn peer_child_request_answered(rekeyed: Option<u32>, child6: Option<ChildSpis>) -> (Vec<u8>, CompletedSaInit, LivenessSession) {
        let request = move |resp_sa: &CompletedSaInit| {
            rekey::build_child_request(
                resp_sa,
                0,
                rekeyed,
                PEER_NEW_SPI,
                &PEER_NI,
                SkCipher::Aes256Gcm,
                None,
                &TrafficSelectors::ipv4_full_tunnel(),
                &[7u8; 8],
            )
            .unwrap()
        };
        peer_child_request_answered_with(PfsPolicy::none(), child6, request)
    }

    /// [`peer_child_request_answered`] for a session running the PFS policy
    /// `pfs`, the peer sending the request `request` builds with its IKE SA
    /// (message id 0, its first request on the IKE SA).
    fn peer_child_request_answered_with(
        pfs: PfsPolicy,
        child6: Option<ChildSpis>,
        request: impl FnOnce(&CompletedSaInit) -> Vec<u8> + Send + 'static,
    ) -> (Vec<u8>, CompletedSaInit, LivenessSession) {
        let (init_sa, resp_sa) = liveness_sa_pair();
        let responder_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let bind = responder_sock.local_addr().unwrap();
        let responder = thread::spawn(move || {
            responder_sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut buf = [0u8; 2048];
            let (_n, from) = responder_sock.recv_from(&mut buf).unwrap();
            let request = request(&resp_sa);
            responder_sock.send_to(&request, from).unwrap();
            let (n, _) = responder_sock.recv_from(&mut buf).unwrap();
            (buf[..n].to_vec(), resp_sa)
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
            pfs,
            child_local_spi: 0xBBBB,
            child_peer_spi: 0xAAAA,
            external_rx: None,
            child6,
            cfg_subnets6: Vec::new(),
            child_carries_ipv6: false,
            ike: IkeSaState::new(),
            peer_child: PeerChildState::default(), primary_child_alive: true, peer_requests: PeerRequests::default(),
        };
        // Whatever the answer, the request is not a teardown: the IKE SA stands.
        assert_eq!(liveness.peek(Duration::from_millis(1500)).unwrap(), Liveness::Alive);
        let (response, resp_sa) = responder.join().unwrap();
        (response, resp_sa, liveness)
    }

    const PEER_NEW_SPI: u32 = 0x2222_2222;
    const PEER_NI: [u8; 32] = [0x33; 32];

    /// The error a refusal carries, after checking it is a CREATE_CHILD_SA
    /// response echoing the request's message id.
    fn refusal_reason(resp_sa: &CompletedSaInit, response: &[u8]) -> u16 {
        refusal_notify(resp_sa, response).0
    }

    /// [`refusal_reason`], with the notification's data.
    fn refusal_notify(resp_sa: &CompletedSaInit, response: &[u8]) -> (u16, Vec<u8>) {
        let header = IkeHeader::parse(response).unwrap();
        assert_eq!(header.exchange_type, ExchangeType::CreateChildSa, "the answer must be a CREATE_CHILD_SA response");
        assert!(header.flags.response);
        assert_eq!(header.message_id, 0, "the response echoes the request's message id");
        let inner = open_informational(resp_sa, response).unwrap();
        inner
            .iter()
            .find(|(t, _)| *t == PayloadType::Notify)
            .map(|(_, body)| crate::ikev2::payload::Notify::parse(body).unwrap())
            .map(|n| (n.notify_type, n.data.to_vec()))
            .expect("the refusal carries a Notify")
    }

    /// The peer's private DH key in these tests.
    const PEER_DH: [u8; 32] = [5; 32];

    /// A CREATE_CHILD_SA request from the peer (`sa`, message id 0)
    /// rekeying its CHILD SA `0xAAAA`, built by hand: `proposals` offered,
    /// and `ke` as the KE payload, if any.
    fn hand_built_peer_rekey(
        sa: &CompletedSaInit,
        proposals: Vec<crate::ikev2::payload::Proposal>,
        ke: Option<crate::ikev2::payload::KeyExchange>,
    ) -> Vec<u8> {
        use crate::ikev2::message::{encode_payload_chain, first_payload_type};
        use crate::ikev2::payload::Notify;

        let ts = TrafficSelectors::ipv4_full_tunnel();
        let rekey_sa =
            Notify { protocol_id: protocol_id::ESP, spi: 0xAAAAu32.to_be_bytes().to_vec(), notify_type: notify_type::REKEY_SA, data: Vec::new() };
        let mut inner = vec![
            (PayloadType::Notify, rekey_sa.to_bytes()),
            (PayloadType::SecurityAssociation, SecurityAssociation { proposals }.to_bytes()),
            (PayloadType::Nonce, PEER_NI.to_vec()),
        ];
        inner.extend(ke.map(|ke| (PayloadType::KeyExchange, ke.to_bytes())));
        inner.push((PayloadType::TrafficSelectorInitiator, ts.to_bytes()));
        inner.push((PayloadType::TrafficSelectorResponder, ts.to_bytes()));
        let header = IkeHeader {
            initiator_spi: sa.spi_i,
            responder_spi: sa.spi_r,
            next_payload: PayloadType::NoNext,
            major_version: 2,
            minor_version: 0,
            exchange_type: ExchangeType::CreateChildSa,
            flags: Flags { initiator: false, version: false, response: false },
            message_id: 0,
            length: 0,
        };
        let first = first_payload_type(&inner);
        sk::build_encrypted(sa.suite.sk_cipher(), header, first, &encode_payload_chain(&inner), &sa.keys.sk_er, &sa.keys.sk_ar, &[7u8; 8]).unwrap()
    }

    /// An ESP offer running AES-GCM-256 with the DH transforms `dh`.
    fn gcm_esp_offer_with_dh(spi: u32, dh: &[u16]) -> SecurityAssociation {
        use crate::ikev2::payload::{transform_type, Transform};

        let mut offer = ike_auth::esp_offer_for_cipher(spi, SkCipher::Aes256Gcm);
        offer.proposals[0].transforms.extend(dh.iter().map(|&id| Transform {
            transform_type: transform_type::DH,
            transform_id: id,
            key_length: None,
        }));
        offer
    }

    /// RFC 7296 §1.3, §3.3.6: with a PFS group configured, a gateway's rekey
    /// that would drop PFS is refused NO_PROPOSAL_CHOSEN, and one on another
    /// group while ours is offered too is refused INVALID_KE_PAYLOAD naming
    /// ours -- both leave the CHILD SA as it was. The same rekey with PFS on
    /// our group is answered and handed over.
    #[test]
    fn a_peer_rekey_must_keep_the_pfs_our_session_runs() {
        use crate::ikev2::payload::transform_id::{ECP256, MODP_2048};

        let required = || PfsPolicy::from_offer(&gcm_esp_offer_with_dh(0, &[MODP_2048])).unwrap();
        let unchanged = |liveness: &mut LivenessSession| {
            assert!(liveness.take_peer_rekeys().is_empty());
            assert_eq!((liveness.child_local_spi, liveness.child_peer_spi), (0xBBBB, 0xAAAA), "nothing changed");
        };

        let no_pfs = |sa: &CompletedSaInit| hand_built_peer_rekey(sa, gcm_esp_offer_with_dh(PEER_NEW_SPI, &[]).proposals, None);
        let (response, resp_sa, mut liveness) = peer_child_request_answered_with(required(), None, no_pfs);
        assert_eq!(refusal_notify(&resp_sa, &response), (notify_type::NO_PROPOSAL_CHOSEN, Vec::new()));
        unchanged(&mut liveness);

        let other_group = |sa: &CompletedSaInit| {
            let ke = crate::ikev2::payload::KeyExchange { dh_group: ECP256, data: DhGroup::EcpP256.public(&PEER_DH) };
            hand_built_peer_rekey(sa, gcm_esp_offer_with_dh(PEER_NEW_SPI, &[ECP256, MODP_2048]).proposals, Some(ke))
        };
        let (response, resp_sa, mut liveness) = peer_child_request_answered_with(required(), None, other_group);
        assert_eq!(refusal_notify(&resp_sa, &response), (notify_type::INVALID_KE_PAYLOAD, MODP_2048.to_be_bytes().to_vec()));
        unchanged(&mut liveness);

        // Control: PFS on our group.
        let ours = |sa: &CompletedSaInit| {
            let ke = crate::ikev2::payload::KeyExchange { dh_group: MODP_2048, data: DhGroup::Modp2048.public(&PEER_DH) };
            hand_built_peer_rekey(sa, gcm_esp_offer_with_dh(PEER_NEW_SPI, &[MODP_2048]).proposals, Some(ke))
        };
        let (response, resp_sa, mut liveness) = peer_child_request_answered_with(required(), None, ours);
        let (peer_child, _) =
            rekey::initiator_complete_child(&resp_sa, &PEER_NI, PEER_NEW_SPI, SkCipher::Aes256Gcm, Some((DhGroup::Modp2048, &PEER_DH)), &response)
                .expect("a PFS rekey answer, not a refusal");
        let taken = liveness.take_peer_rekeys();
        assert_eq!(taken.len(), 1);
        assert_eq!(taken[0].child.key_in.enc, peer_child.outbound.enc_material(), "the PFS keys match");

        // And a session whose offer leaves PFS optional ([MODP-2048, NONE]) takes the rekey without.
        let optional = PfsPolicy::from_offer(&gcm_esp_offer_with_dh(0, &[MODP_2048, 0])).unwrap();
        let (response, resp_sa, mut liveness) = peer_child_request_answered_with(optional, None, no_pfs);
        rekey::initiator_complete_child(&resp_sa, &PEER_NI, PEER_NEW_SPI, SkCipher::Aes256Gcm, None, &response).expect("answered without PFS");
        assert_eq!(liveness.take_peer_rekeys().len(), 1);
    }

    /// RFC 7296 §3.3.6: our CHILD SA rekey asked for PFS and the gateway's
    /// answer leaves it out -- the right cipher, but no DH transform and no
    /// KE. `rekey_child` refuses it rather than run the new SA without PFS,
    /// and the session keeps the SA it had.
    #[test]
    fn rekey_child_refuses_an_answer_that_drops_our_pfs() {
        use crate::ikev2::message::{encode_payload_chain, first_payload_type};
        use crate::ikev2::payload::transform_id::MODP_2048;

        let (init_sa, resp_sa) = liveness_sa_pair();
        let responder_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let bind = responder_sock.local_addr().unwrap();
        let responder = thread::spawn(move || {
            responder_sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut buf = [0u8; 4096];
            let (n, from) = responder_sock.recv_from(&mut buf).unwrap();
            let request = open_informational(&resp_sa, &buf[..n]).unwrap();
            assert!(request.iter().any(|(t, _)| *t == PayloadType::KeyExchange), "the rekey asks for PFS");
            let ts = TrafficSelectors::ipv4_full_tunnel();
            let inner = vec![
                (PayloadType::SecurityAssociation, gcm_esp_offer_with_dh(0xFEED_FACE, &[]).to_bytes()),
                (PayloadType::Nonce, vec![0x77; 32]),
                (PayloadType::TrafficSelectorInitiator, ts.to_bytes()),
                (PayloadType::TrafficSelectorResponder, ts.to_bytes()),
            ];
            let mut header = IkeHeader::parse(&buf[..n]).unwrap();
            header.flags = Flags { initiator: false, version: false, response: true };
            header.next_payload = PayloadType::NoNext;
            header.length = 0;
            let answer = sk::build_encrypted(
                resp_sa.suite.sk_cipher(),
                header,
                first_payload_type(&inner),
                &encode_payload_chain(&inner),
                &resp_sa.keys.sk_er,
                &resp_sa.keys.sk_ar,
                &[8u8; 8],
            )
            .unwrap();
            responder_sock.send_to(&answer, from).unwrap();
        });

        let mut liveness = LivenessSession {
            sock: UdpSocket::bind("127.0.0.1:0").unwrap(),
            sa: init_sa,
            dest: bind,
            float: false,
            next_message_id: 2,
            cipher: SkCipher::Aes256Gcm,
            pfs: PfsPolicy::from_offer(&gcm_esp_offer_with_dh(0, &[MODP_2048])).unwrap(),
            child_local_spi: 0xBBBB,
            child_peer_spi: 0xAAAA,
            external_rx: None,
            child6: None,
            cfg_subnets6: Vec::new(),
            child_carries_ipv6: false,
            ike: IkeSaState::new(),
            peer_child: PeerChildState::default(),
            primary_child_alive: true,
            peer_requests: PeerRequests::default(),
        };
        let err = liveness.rekey_child(Duration::from_secs(2)).err().expect("the answer without PFS is refused");
        assert!(matches!(err, DriverError::Ike(IkeError::NoProposalChosen)), "got {err:?}");
        assert_eq!((liveness.child_local_spi, liveness.child_peer_spi), (0xBBBB, 0xAAAA), "the SA in place is kept");
        responder.join().unwrap();
    }

    /// An ESP offer whose PFS group IKEv2 can't run -- one this crate doesn't
    /// know, or MODP-768 (RFC 8247 §2.4) -- fails every connect entry point
    /// before anything reaches the gateway, rather than turning into a
    /// tunnel without PFS.
    #[test]
    fn a_connect_with_a_pfs_group_ikev2_cannot_run_fails_before_sending_anything() {
        use crate::ikev2::payload::transform_id::MODP_768;

        let gateway = UdpSocket::bind("127.0.0.1:0").unwrap();
        gateway.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
        let peer = gateway.local_addr().unwrap();
        for group in [0x7777, MODP_768] {
            let esp_offer = gcm_esp_offer_with_dh(0, &[group]);
            let cfg = AuthConfig::psk(Identification::fqdn("client.test"), b"shared-secret".to_vec());
            let mut session = Ikev2Session::new(OsEntropy::new().unwrap());
            let direct = session.connect_direct_on_port(peer, &default_ike_offer(), &cfg, false, &esp_offer, next_addr().port());
            let creds = EapCreds { user: b"alice".to_vec(), password: "s3cret".to_string() };
            let eap = session.connect_eap_on_port(
                peer,
                &default_ike_offer(),
                Identification::fqdn("client.test"),
                creds,
                ServerVerify::Psk(b"group-psk".to_vec()),
                false,
                &esp_offer,
                next_addr().port(),
            );
            for (path, result) in [("direct", direct.err()), ("EAP", eap.err())] {
                assert!(matches!(result, Some(DriverError::Ike(IkeError::Crypto(_)))), "{path}, group {group}: {result:?}");
            }
            assert!(gateway.recv_from(&mut [0u8; 64]).is_err(), "group {group}: nothing reaches the gateway");
        }
    }

    /// A gateway's own rekey timer fires: its CREATE_CHILD_SA request must be
    /// answered as a CREATE_CHILD_SA, not with the empty INFORMATIONAL ack --
    /// strongSwan destroys the whole IKE SA on the latter ("received
    /// INFORMATIONAL response, but expected CREATE_CHILD_SA"). A brand-new
    /// CHILD SA (no REKEY_SA) is refused with NO_ADDITIONAL_SAS...
    #[test]
    fn a_peer_initiated_new_child_sa_is_refused_as_a_create_child_sa() {
        let (response, resp_sa, mut liveness) = peer_child_request_answered(None, None);
        assert_eq!(refusal_reason(&resp_sa, &response), notify_type::NO_ADDITIONAL_SAS);
        assert!(liveness.take_peer_rekeys().is_empty());
    }

    /// ...and a rekey of an SA this side has no record of with CHILD_SA_NOT_FOUND.
    #[test]
    fn a_peer_rekey_of_an_unknown_child_sa_is_refused_child_sa_not_found() {
        let (response, resp_sa, mut liveness) = peer_child_request_answered(Some(0x1111_1111), None);
        assert_eq!(refusal_reason(&resp_sa, &response), notify_type::CHILD_SA_NOT_FOUND);
        assert!(liveness.take_peer_rekeys().is_empty());
        assert_eq!((liveness.child_local_spi, liveness.child_peer_spi), (0xBBBB, 0xAAAA), "nothing changed");
    }

    /// The peer's rekey of the primary CHILD SA -- named by the SPI it expects
    /// inbound, our outbound one -- is answered with a new SA both sides derive
    /// alike, and handed to the caller.
    #[test]
    fn a_peer_rekey_of_the_primary_child_sa_is_answered_and_handed_over() {
        let (response, resp_sa, mut liveness) = peer_child_request_answered(Some(0xAAAA), Some(ChildSpis { local: 0x6666, peer: 0x7777 }));
        let (peer_child, _) =
            rekey::initiator_complete_child(&resp_sa, &PEER_NI, PEER_NEW_SPI, SkCipher::Aes256Gcm, None, &response).expect("a rekey answer, not a refusal");

        let mut taken = liveness.take_peer_rekeys();
        assert_eq!(taken.len(), 1);
        let taken = taken.remove(0);
        assert_eq!(taken.kind, ChildKind::Primary);
        assert_eq!(taken.child.peer_spi, PEER_NEW_SPI);
        assert_eq!(taken.child.local_spi, peer_child.outbound.spi());
        assert_eq!(taken.child.key_in.enc, peer_child.outbound.enc_material(), "what the peer sends, we open");
        assert_eq!(taken.child.key_out.enc, peer_child.inbound.enc_material(), "what we send, the peer opens");
        assert!(liveness.take_peer_rekeys().is_empty(), "handed over once");
        // The session follows the new SA; the IPv6 one is untouched.
        assert_eq!((liveness.child_local_spi, liveness.child_peer_spi), (taken.child.local_spi, PEER_NEW_SPI));
        assert_eq!(liveness.child6.map(|c| (c.local, c.peer)), Some((0x6666, 0x7777)));
    }

    /// Likewise the IPv6 CHILD SA, told apart from the primary by its SPI.
    #[test]
    fn a_peer_rekey_of_the_ipv6_child_sa_replaces_only_that_one() {
        let (response, resp_sa, mut liveness) = peer_child_request_answered(Some(0x7777), Some(ChildSpis { local: 0x6666, peer: 0x7777 }));
        rekey::initiator_complete_child(&resp_sa, &PEER_NI, PEER_NEW_SPI, SkCipher::Aes256Gcm, None, &response).expect("a rekey answer, not a refusal");

        let taken = liveness.take_peer_rekeys();
        assert_eq!(taken.iter().map(|t| t.kind).collect::<Vec<_>>(), [ChildKind::Ipv6]);
        assert_eq!((liveness.child_local_spi, liveness.child_peer_spi), (0xBBBB, 0xAAAA), "the primary SA is untouched");
        assert_eq!(liveness.child6.map(|c| c.peer), Some(PEER_NEW_SPI));
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
            let msg = build_informational(&resp_sa, 0, false, &[(PayloadType::Delete, del.to_bytes())], &[7u8; 8]).unwrap();
            responder_sock.send_to(&msg, from).unwrap();
            // Still owed an ack even though it's being ignored as a teardown.
            let (n, _) = responder_sock.recv_from(&mut buf).unwrap();
            let ack_header = IkeHeader::parse(&buf[..n]).unwrap();
            assert_eq!(ack_header.message_id, 0);
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
            pfs: PfsPolicy::none(),
            child_local_spi: 0,
            child_peer_spi: 0xAAAA,
            external_rx: None,
            child6: None,
            cfg_subnets6: Vec::new(),
            child_carries_ipv6: false,
            ike: IkeSaState::new(),
            peer_child: PeerChildState::default(), primary_child_alive: true, peer_requests: PeerRequests::default(),
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
            let msg = build_informational(&resp_sa, 0, false, &[(PayloadType::Delete, del.to_bytes())], &[7u8; 8]).unwrap();
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
            pfs: PfsPolicy::none(),
            child_local_spi: 0,
            child_peer_spi: 0xAAAA,
            external_rx: None,
            child6: None,
            cfg_subnets6: Vec::new(),
            child_carries_ipv6: false,
            ike: IkeSaState::new(),
            peer_child: PeerChildState::default(), primary_child_alive: true, peer_requests: PeerRequests::default(),
        };
        assert_eq!(liveness.peek(Duration::from_secs(5)).unwrap(), Liveness::PeerTornDown);
        responder.join().unwrap();
    }

    /// RFC 7296 §1.4.1: deleting one CHILD SA never implies deleting the IKE
    /// SA or any other CHILD SA under it -- only the reverse holds. So an ESP
    /// Delete naming the primary CHILD SA while a separate IPv6 CHILD SA is
    /// still up must not tear anything down: it queues `ChildKind::Primary`
    /// for the caller to renegotiate ([`LivenessSession::create_child_primary`]),
    /// same as this project already does for a peer-started rekey.
    #[test]
    fn peek_does_not_tear_down_on_a_primary_delete_while_ipv6_is_still_up() {
        let (init_sa, resp_sa) = liveness_sa_pair();
        let responder_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let bind = responder_sock.local_addr().unwrap();
        let responder = thread::spawn(move || {
            responder_sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut buf = [0u8; 2048];
            let (_n, from) = responder_sock.recv_from(&mut buf).unwrap();
            let del = Delete::esp(vec![0xAAAA]);
            let msg = build_informational(&resp_sa, 0, false, &[(PayloadType::Delete, del.to_bytes())], &[7u8; 8]).unwrap();
            responder_sock.send_to(&msg, from).unwrap();
            // Still owed an ack, exactly as any other Delete.
            let (n, _) = responder_sock.recv_from(&mut buf).unwrap();
            let ack_header = IkeHeader::parse(&buf[..n]).unwrap();
            assert_eq!(ack_header.message_id, 0);
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
            pfs: PfsPolicy::none(),
            child_local_spi: 0,
            child_peer_spi: 0xAAAA,
            external_rx: None,
            child6: Some(ChildSpis { local: 0x6666, peer: 0x7777 }),
            cfg_subnets6: Vec::new(),
            child_carries_ipv6: false,
            ike: IkeSaState::new(),
            peer_child: PeerChildState::default(),
            primary_child_alive: true, peer_requests: PeerRequests::default(),
        };
        assert_eq!(liveness.peek(Duration::from_secs(5)).unwrap(), Liveness::Alive, "the IKE SA and the IPv6 CHILD SA are still good");
        assert_eq!(liveness.take_peer_deleted_children(), vec![ChildKind::Primary]);
        assert!(liveness.take_peer_deleted_children().is_empty(), "handed over once");
        assert!(!liveness.primary_child_alive, "the stale SPIs must not be mistaken for a live SA until recreated");
        assert_eq!(liveness.child6.map(|c| (c.local, c.peer)), Some((0x6666, 0x7777)), "untouched");
        responder.join().unwrap();
    }

    /// The mirror image: an ESP Delete naming the separate IPv6 CHILD SA
    /// while the primary is still up doesn't tear anything down either, and
    /// queues `ChildKind::Ipv6` instead.
    #[test]
    fn peek_does_not_tear_down_on_an_ipv6_delete_while_the_primary_is_still_up() {
        let (init_sa, resp_sa) = liveness_sa_pair();
        let responder_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let bind = responder_sock.local_addr().unwrap();
        let responder = thread::spawn(move || {
            responder_sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let mut buf = [0u8; 2048];
            let (_n, from) = responder_sock.recv_from(&mut buf).unwrap();
            let del = Delete::esp(vec![0x7777]);
            let msg = build_informational(&resp_sa, 0, false, &[(PayloadType::Delete, del.to_bytes())], &[7u8; 8]).unwrap();
            responder_sock.send_to(&msg, from).unwrap();
            let (n, _) = responder_sock.recv_from(&mut buf).unwrap();
            let ack_header = IkeHeader::parse(&buf[..n]).unwrap();
            assert_eq!(ack_header.message_id, 0);
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
            pfs: PfsPolicy::none(),
            child_local_spi: 0xBBBB,
            child_peer_spi: 0xAAAA,
            external_rx: None,
            child6: Some(ChildSpis { local: 0x6666, peer: 0x7777 }),
            cfg_subnets6: Vec::new(),
            child_carries_ipv6: false,
            ike: IkeSaState::new(),
            peer_child: PeerChildState::default(),
            primary_child_alive: true, peer_requests: PeerRequests::default(),
        };
        assert_eq!(liveness.peek(Duration::from_secs(5)).unwrap(), Liveness::Alive, "the IKE SA and the primary CHILD SA are still good");
        assert_eq!(liveness.take_peer_deleted_children(), vec![ChildKind::Ipv6]);
        assert!(liveness.child6.is_none(), "gone until create_child_ipv6 recreates it");
        assert_eq!((liveness.child_local_spi, liveness.child_peer_spi), (0xBBBB, 0xAAAA), "untouched");
        assert!(liveness.primary_child_alive);
        responder.join().unwrap();
    }

    /// RFC 7296 §2.1: a retransmitted request must get the identical
    /// response, not a freshly reprocessed one. Without a cache, this
    /// specific case regresses: the first Delete for a superseded CHILD SA's
    /// peer SPI drains the matching entry from `peer_child.superseded` and
    /// echoes our own SPI for it; a retransmission of that exact same
    /// request (peer never saw our first ack) would find nothing left to
    /// echo on a second pass and answer empty instead -- leaving the peer
    /// without the SPI it's still waiting to hear deleted on its side.
    #[test]
    fn a_retransmitted_informational_gets_the_identical_ack() {
        let (init_sa, resp_sa) = liveness_sa_pair();
        let responder_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let bind = responder_sock.local_addr().unwrap();
        let responder = thread::spawn(move || {
            responder_sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let del = Delete::esp(vec![0x7777]);
            let msg = build_informational(&resp_sa, 0, false, &[(PayloadType::Delete, del.to_bytes())], &[7u8; 8]).unwrap();
            let mut buf = [0u8; 2048];
            let (_n, from) = responder_sock.recv_from(&mut buf).unwrap();
            // The identical bytes, twice -- a genuine retransmission (our
            // first ack was "lost"), not a freshly rebuilt request.
            responder_sock.send_to(&msg, from).unwrap();
            responder_sock.send_to(&msg, from).unwrap();
            let (n1, _) = responder_sock.recv_from(&mut buf).unwrap();
            let ack1 = buf[..n1].to_vec();
            let (n2, _) = responder_sock.recv_from(&mut buf).unwrap();
            let ack2 = buf[..n2].to_vec();
            assert_eq!(ack1, ack2, "a retransmitted request must get the byte-identical response");
            let opened = open_informational(&resp_sa, &ack1).unwrap();
            let echoed = opened
                .into_iter()
                .find(|(t, _)| *t == PayloadType::Delete)
                .and_then(|(_, body)| Delete::parse(&body).ok())
                .expect("the real ack echoes our SPI for the superseded CHILD SA, not a blank one");
            assert_eq!(echoed.spis, vec![0x9999]);
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
            pfs: PfsPolicy::none(),
            child_local_spi: 0,
            child_peer_spi: 0xAAAA,
            external_rx: None,
            child6: None,
            cfg_subnets6: Vec::new(),
            child_carries_ipv6: false,
            ike: IkeSaState::new(),
            peer_child: PeerChildState {
                superseded: vec![SupersededChild { local_spi: 0x9999, peer_spi: 0x7777, since: Instant::now() }],
                ..Default::default()
            },
            primary_child_alive: true,
            peer_requests: PeerRequests::default(),
        };
        assert_eq!(liveness.peek(Duration::from_millis(600)).unwrap(), Liveness::Alive);
        assert!(liveness.peer_child.superseded.is_empty(), "drained exactly once, not once per retransmission");
        responder.join().unwrap();
    }

    /// A session on the IKE SA `sa` whose gateway is `gateway`, a plain socket
    /// the test drives by hand: primary CHILD SA `0xBBBB` inbound / `0xAAAA`
    /// outbound, and `child6` as the IPv6 one.
    fn session_facing(gateway: &UdpSocket, sa: CompletedSaInit, child6: Option<ChildSpis>) -> LivenessSession {
        gateway.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        LivenessSession {
            sock: UdpSocket::bind("127.0.0.1:0").unwrap(),
            sa,
            dest: gateway.local_addr().unwrap(),
            float: false,
            next_message_id: 2,
            cipher: SkCipher::Aes256Gcm,
            pfs: PfsPolicy::none(),
            child_local_spi: 0xBBBB,
            child_peer_spi: 0xAAAA,
            external_rx: None,
            child6,
            cfg_subnets6: Vec::new(),
            child_carries_ipv6: false,
            ike: IkeSaState::new(),
            peer_child: PeerChildState::default(),
            primary_child_alive: true,
            peer_requests: PeerRequests::default(),
        }
    }

    /// The gateway sends `msg`, and the session takes in what is waiting.
    fn deliver(liveness: &mut LivenessSession, gateway: &UdpSocket, msg: &[u8]) -> Liveness {
        gateway.send_to(msg, liveness.sock.local_addr().unwrap()).unwrap();
        liveness.peek(Duration::from_millis(100)).expect("nothing the gateway's end sends makes peek fail")
    }

    /// What the session sent the gateway next, if anything.
    fn sent_to(gateway: &UdpSocket) -> Option<Vec<u8>> {
        let mut buf = [0u8; 4096];
        gateway.recv_from(&mut buf).ok().map(|(n, _)| buf[..n].to_vec())
    }

    fn delete_payload(delete: Delete) -> (PayloadType, Vec<u8>) {
        (PayloadType::Delete, delete.to_bytes())
    }

    /// The header of a message from the gateway on `sa` (its end of an IKE SA
    /// [`liveness_sa_pair`] made), as RFC 7296 §3.1 has it: the gateway is
    /// the original responder, so its Initiator flag is clear.
    fn gateway_header(sa: &CompletedSaInit, mid: u32, exchange_type: ExchangeType, response: bool) -> IkeHeader {
        IkeHeader {
            initiator_spi: sa.spi_i,
            responder_spi: sa.spi_r,
            next_payload: PayloadType::NoNext,
            major_version: 2,
            minor_version: 0,
            exchange_type,
            flags: Flags { initiator: false, version: false, response },
            message_id: mid,
            length: 0,
        }
    }

    /// A message under `header` as it stands, carrying `payloads` in its SK
    /// payload under the gateway's keys of `sa` -- authentic whatever the
    /// header says, since the keys don't depend on it.
    fn from_gateway(sa: &CompletedSaInit, header: IkeHeader, payloads: &[(PayloadType, Vec<u8>)]) -> Vec<u8> {
        use crate::ikev2::message::{encode_payload_chain, first_payload_type};

        let inner = encode_payload_chain(payloads);
        sk::build_encrypted(sa.suite.sk_cipher(), header, first_payload_type(payloads), &inner, &sa.keys.sk_er, &sa.keys.sk_ar, &[6u8; 8]).unwrap()
    }

    /// The payloads of `msg`, a message the gateway built on `sa` -- the
    /// inverse of [`from_gateway`].
    fn gateway_payloads(sa: &CompletedSaInit, msg: &[u8]) -> Vec<(PayloadType, Vec<u8>)> {
        let (first, inner) = open_encrypted(sa.suite.sk_cipher(), msg, &sa.keys.sk_er, &sa.keys.sk_ar).unwrap();
        payloads(first, &inner).map(|p| p.map(|p| (p.payload_type, p.data.to_vec()))).collect::<Result<_, _>>().unwrap()
    }

    /// `msg` with its integrity check value broken.
    fn tampered(mut msg: Vec<u8>) -> Vec<u8> {
        let last = msg.len() - 1;
        msg[last] ^= 1;
        msg
    }

    /// Every ESP SPI the Delete payloads of the session's answer `msg` name, sorted.
    fn esp_spis_deleted(sa: &CompletedSaInit, msg: &[u8]) -> Vec<u32> {
        let mut spis: Vec<u32> = open_informational(sa, msg)
            .unwrap()
            .into_iter()
            .filter(|(t, _)| *t == PayloadType::Delete)
            .map(|(_, body)| Delete::parse(&body).unwrap())
            .filter(|d| d.protocol_id == protocol_id::ESP)
            .flat_map(|d| d.spis)
            .collect();
        spis.sort_unstable();
        spis
    }

    /// RFC 7296 §2.21.3, §2.2: a request is answered, and acted on, only once
    /// it authenticates. A Delete of the IKE SA whose integrity check fails,
    /// or one under our own direction's keys (a reflection of our traffic),
    /// gets no answer and changes nothing -- and does not use up the Message
    /// ID the gateway's next genuine request carries.
    #[test]
    fn a_request_that_does_not_authenticate_is_neither_answered_nor_acted_on() {
        let (init_sa, resp_sa) = liveness_sa_pair();
        let gateway = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut liveness = session_facing(&gateway, init_sa, None);

        let forged = tampered(build_informational(&resp_sa, 0, false, &[delete_payload(Delete::ike_sa())], &[7u8; 8]).unwrap());
        assert_eq!(deliver(&mut liveness, &gateway, &forged), Liveness::Alive, "an unauthenticated Delete ends nothing");
        assert_eq!(sent_to(&gateway), None, "nor is it answered");
        let reflected = build_informational(&liveness.sa, 0, false, &[delete_payload(Delete::esp(vec![0xAAAA]))], &[7u8; 8]).unwrap();
        assert_eq!(deliver(&mut liveness, &gateway, &reflected), Liveness::Alive);
        assert_eq!(sent_to(&gateway), None);
        assert!(liveness.primary_child_alive);

        let genuine = build_informational(&resp_sa, 0, false, &[], &[8u8; 8]).unwrap();
        assert_eq!(deliver(&mut liveness, &gateway, &genuine), Liveness::Alive);
        let answer = sent_to(&gateway).expect("the genuine request with that Message ID is answered");
        assert_eq!(IkeHeader::parse(&answer).unwrap().message_id, 0);
        assert!(open_informational(&resp_sa, &answer).unwrap().is_empty());
    }

    /// RFC 7296 §2.1-§2.3: each IKE SA keeps a receive window of one request.
    /// The last request answered, sent again byte for byte, is a
    /// retransmission and gets the very same answer. An older one -- 0 once 1
    /// is answered -- is a replay, one past the next expected ID is outside
    /// the window, and a different request under an ID already answered is
    /// neither: none is answered, and the next expected ID still is.
    #[test]
    fn the_receive_window_resends_the_last_answer_and_drops_everything_else_but_the_next_request() {
        let (init_sa, resp_sa) = liveness_sa_pair();
        let gateway = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut liveness = session_facing(&gateway, init_sa, None);
        let request = |mid: u32, iv: u8| build_informational(&resp_sa, mid, false, &[], &[iv; 8]).unwrap();

        let (r0, r1) = (request(0, 1), request(1, 2));
        deliver(&mut liveness, &gateway, &r0);
        assert!(sent_to(&gateway).is_some(), "0 is answered");
        deliver(&mut liveness, &gateway, &r1);
        let a1 = sent_to(&gateway).expect("1 is answered");

        deliver(&mut liveness, &gateway, &r1);
        assert_eq!(sent_to(&gateway), Some(a1), "a retransmission gets the identical answer");
        deliver(&mut liveness, &gateway, &r0);
        assert_eq!(sent_to(&gateway), None, "an older request is a replay: not answered again");
        deliver(&mut liveness, &gateway, &request(3, 3));
        assert_eq!(sent_to(&gateway), None, "past the window");
        deliver(&mut liveness, &gateway, &request(1, 4));
        assert_eq!(sent_to(&gateway), None, "another request under an ID already answered");
        deliver(&mut liveness, &gateway, &request(2, 5));
        let a2 = sent_to(&gateway).expect("the next expected request is answered");
        assert_eq!(IkeHeader::parse(&a2).unwrap().message_id, 2);
    }

    /// RFC 7296 §2.2: the gateway, the original responder, sent no request
    /// during the handshake, so its first request on the IKE SA carries
    /// Message ID 0. The window used to take whatever ID came first -- 100,
    /// say -- as the start of the gateway's requests, and act on it; and 0
    /// was then a replay, never answered.
    #[test]
    fn the_gateways_first_request_must_carry_message_id_0() {
        let (init_sa, resp_sa) = liveness_sa_pair();
        let gateway = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut liveness = session_facing(&gateway, init_sa, None);
        let dpd = |mid: u32| build_informational(&resp_sa, mid, false, &[], &[mid as u8; 8]).unwrap();

        assert_eq!(deliver(&mut liveness, &gateway, &ike_delete_request(&resp_sa, 100)), Liveness::Alive, "not acted on");
        assert_eq!(sent_to(&gateway), None, "a first request other than 0 is outside the window");
        for mid in [100, 1] {
            assert_eq!(deliver(&mut liveness, &gateway, &dpd(mid)), Liveness::Alive);
            assert_eq!(sent_to(&gateway), None, "{mid} is outside the window");
        }
        for mid in [0, 1] {
            assert_eq!(deliver(&mut liveness, &gateway, &dpd(mid)), Liveness::Alive);
            let answer = sent_to(&gateway).unwrap_or_else(|| panic!("{mid} is answered"));
            assert_eq!(IkeHeader::parse(&answer).unwrap().message_id, mid);
        }
    }

    /// RFC 7296 §1.4.1: once the gateway has deleted the IKE SA, nothing
    /// new is answered on it -- only a retransmission of the Delete gets its
    /// answer again. A request after it used to be answered as if the IKE SA
    /// were still there.
    #[test]
    fn after_the_gateway_deletes_the_ike_sa_only_the_deletes_retransmission_is_answered() {
        let (init_sa, resp_sa) = liveness_sa_pair();
        let gateway = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut liveness = session_facing(&gateway, init_sa, None);
        let delete = ike_delete_request(&resp_sa, 0);
        assert_eq!(deliver(&mut liveness, &gateway, &delete), Liveness::PeerTornDown);
        let answer = sent_to(&gateway).expect("the Delete is answered");
        assert_eq!(deliver(&mut liveness, &gateway, &delete), Liveness::PeerTornDown);
        assert_eq!(sent_to(&gateway), Some(answer), "its retransmission gets the same answer");
        deliver(&mut liveness, &gateway, &build_informational(&resp_sa, 1, false, &[], &[1u8; 8]).unwrap());
        assert_eq!(sent_to(&gateway), None, "the IKE SA is gone");
    }

    /// RFC 7296 §2.18: "The new IKE SA MUST reset its message counters to
    /// 0" -- whichever side rekeyed. On the IKE SA our own rekey made, the
    /// gateway's first request is 0 again, though the old IKE SA had taken 0
    /// and 1 from it: 1 and 2 are outside the new window.
    #[test]
    fn the_ike_sa_our_rekey_makes_starts_the_gateways_requests_over_at_0() {
        let (init_sa, resp_sa) = liveness_sa_pair();
        let gateway = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut liveness = session_facing(&gateway, init_sa, None);
        for mid in [0, 1] {
            deliver(&mut liveness, &gateway, &build_informational(&resp_sa, mid, false, &[], &[1u8; 8]).unwrap());
            assert!(sent_to(&gateway).is_some(), "{mid} is answered on the old IKE SA");
        }

        let script = thread::spawn({
            let (gw, client, resp_sa) = (gateway.try_clone().unwrap(), liveness.sock.local_addr().unwrap(), resp_sa.clone());
            move || {
                gw.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let ours = recv_from_client(&gw);
                let (answer, new_sa) = gateway_answers_ike_rekey(&resp_sa, &ours, &[0x80u8; 32]);
                gw.send_to(&answer, client).unwrap();
                let delete = recv_from_client(&gw);
                gw.send_to(&informational_answer(&resp_sa, &delete, &[]), client).unwrap();
                new_sa
            }
        });
        assert_eq!(liveness.rekey_ike(Duration::from_secs(5)).unwrap(), Liveness::Alive);
        let new_sa = script.join().unwrap();
        gateway.set_read_timeout(Some(Duration::from_millis(300))).unwrap();

        let dpd = |mid: u32| build_informational(&new_sa, mid, false, &[], &[mid as u8; 8]).unwrap();
        for mid in [2, 1] {
            assert_eq!(deliver(&mut liveness, &gateway, &dpd(mid)), Liveness::Alive);
            assert_eq!(sent_to(&gateway), None, "{mid} is outside the new IKE SA's window");
        }
        for mid in [0, 1] {
            assert_eq!(deliver(&mut liveness, &gateway, &dpd(mid)), Liveness::Alive);
            let answer = sent_to(&gateway).unwrap_or_else(|| panic!("{mid} is answered on the new IKE SA"));
            assert!(open_informational(&new_sa, &answer).is_ok());
            assert_eq!(IkeHeader::parse(&answer).unwrap().message_id, mid);
        }
    }

    /// ...and on the IKE SA the gateway's own rekey made, likewise, while the
    /// old IKE SA keeps its window where it was: the gateway's next request
    /// there is 1, whatever the new one has taken.
    #[test]
    fn the_ike_sa_the_gateways_rekey_makes_starts_over_at_0_apart_from_the_old_one() {
        let (init_sa, resp_sa) = liveness_sa_pair();
        let gateway = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut liveness = session_facing(&gateway, init_sa, None);
        let ni = [0x55u8; 32];
        assert_eq!(deliver(&mut liveness, &gateway, &gateway_ike_rekey(&resp_sa, 0, &ni)), Liveness::Alive);
        let new_sa = gateway_ike_rekey_done(&resp_sa, &ni, &sent_to(&gateway).expect("the IKE SA rekey is answered"));

        let dpd = |sa: &CompletedSaInit, mid: u32| build_informational(sa, mid, false, &[], &[mid as u8; 8]).unwrap();
        for mid in [2, 1] {
            assert_eq!(deliver(&mut liveness, &gateway, &dpd(&new_sa, mid)), Liveness::Alive);
            assert_eq!(sent_to(&gateway), None, "{mid} is outside the new IKE SA's window");
        }
        for mid in [0, 1] {
            assert_eq!(deliver(&mut liveness, &gateway, &dpd(&new_sa, mid)), Liveness::Alive);
            assert!(open_informational(&new_sa, &sent_to(&gateway).expect("answered on the new IKE SA")).is_ok());
        }
        assert_eq!(deliver(&mut liveness, &gateway, &dpd(&resp_sa, 1)), Liveness::Alive);
        let answer = sent_to(&gateway).expect("the old IKE SA's own next request, 1, is answered on it");
        assert!(open_informational(&resp_sa, &answer).is_ok());
    }

    /// A message from the gateway on `sa`, under `header`, whose SK payload
    /// holds `inner` as it stands -- a payload chain of any shape, authentic
    /// under the gateway's keys.
    fn from_gateway_raw(sa: &CompletedSaInit, header: IkeHeader, first: PayloadType, inner: &[u8]) -> Vec<u8> {
        sk::build_encrypted(sa.suite.sk_cipher(), header, first, inner, &sa.keys.sk_er, &sa.keys.sk_ar, &[6u8; 8]).unwrap()
    }

    /// The session's answer `msg` on `sa` to the gateway's request `mid` of
    /// `exchange`, which must carry a single Notify and nothing else: its
    /// type and data.
    fn error_answer(sa: &CompletedSaInit, msg: &[u8], exchange: ExchangeType, mid: u32) -> (u16, Vec<u8>) {
        let header = IkeHeader::parse(msg).unwrap();
        assert_eq!((header.exchange_type, header.flags.response, header.message_id), (exchange, true, mid), "a response to the request");
        let inner = open_informational(sa, msg).unwrap();
        assert_eq!(inner.len(), 1, "the error notify alone: {inner:?}");
        assert_eq!(inner[0].0, PayloadType::Notify);
        let notify = crate::ikev2::payload::Notify::parse(&inner[0].1).unwrap();
        (notify.notify_type, notify.data)
    }

    /// A payload chain whose first payload -- a Delete -- declares a length
    /// shorter than its own generic header.
    const MALFORMED_CHAIN: [u8; 4] = [0, 0, 0, 3];

    /// RFC 7296 §2.21.3: a request that authenticates and is in the window
    /// but is badly formatted is answered `INVALID_SYNTAX`, which is "fatal
    /// in both peers": the IKE SA is gone. §2.21.2: nothing in it is acted
    /// on. A malformed payload chain used to be taken for no payloads at
    /// all -- in an INFORMATIONAL, an empty answer as to a DPD probe, and the
    /// IKE SA went on; in a CREATE_CHILD_SA, no answer at all. The answer is
    /// kept for a retransmission of the request, like any other.
    #[test]
    fn a_request_with_a_malformed_payload_chain_is_answered_invalid_syntax_and_ends_the_ike_sa() {
        for exchange in [ExchangeType::Informational, ExchangeType::CreateChildSa] {
            let (init_sa, resp_sa) = liveness_sa_pair();
            let gateway = UdpSocket::bind("127.0.0.1:0").unwrap();
            let mut liveness = session_facing(&gateway, init_sa, None);
            let request = from_gateway_raw(&resp_sa, gateway_header(&resp_sa, 0, exchange, false), PayloadType::Delete, &MALFORMED_CHAIN);

            assert_eq!(deliver(&mut liveness, &gateway, &request), Liveness::PeerTornDown, "{exchange:?}");
            let answer = sent_to(&gateway).expect("answered");
            assert_eq!(error_answer(&resp_sa, &answer, exchange, 0), (notify_type::INVALID_SYNTAX, Vec::new()), "{exchange:?}");
            assert_eq!(deliver(&mut liveness, &gateway, &request), Liveness::PeerTornDown, "{exchange:?}");
            assert_eq!(sent_to(&gateway), Some(answer), "{exchange:?}: a retransmission gets the same answer");
            deliver(&mut liveness, &gateway, &build_informational(&resp_sa, 1, false, &[], &[1u8; 8]).unwrap());
            assert_eq!(sent_to(&gateway), None, "{exchange:?}: the IKE SA is gone, nothing new is answered on it");
        }
    }

    /// ...and an unauthenticated one is still dropped, answered with nothing
    /// (§2.21.2), the IKE SA going on.
    #[test]
    fn a_malformed_request_that_does_not_authenticate_is_still_dropped() {
        let (init_sa, resp_sa) = liveness_sa_pair();
        let gateway = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut liveness = session_facing(&gateway, init_sa, None);
        let header = gateway_header(&resp_sa, 0, ExchangeType::Informational, false);
        let forged = tampered(from_gateway_raw(&resp_sa, header, PayloadType::Delete, &MALFORMED_CHAIN));
        assert_eq!(deliver(&mut liveness, &gateway, &forged), Liveness::Alive);
        assert_eq!(sent_to(&gateway), None);
        assert_eq!(deliver(&mut liveness, &gateway, &build_informational(&resp_sa, 0, false, &[], &[1u8; 8]).unwrap()), Liveness::Alive);
        assert!(sent_to(&gateway).is_some(), "Message ID 0 was not taken by the forgery");
    }

    /// RFC 7296 §2.5: a payload of a type we don't know with the critical
    /// flag set makes us reject the whole message, and the answer MUST carry
    /// `UNSUPPORTED_CRITICAL_PAYLOAD` with the payload's type. Nothing else
    /// in it is acted on -- here, a Delete of the IKE SA that follows it.
    /// It used to get an empty answer. The RFC does not make this error
    /// fatal, so the IKE SA goes on: the next request is answered.
    #[test]
    fn an_unknown_critical_payload_is_answered_unsupported_critical_payload_and_nothing_else_is_acted_on() {
        let (init_sa, resp_sa) = liveness_sa_pair();
        let gateway = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut liveness = session_facing(&gateway, init_sa, None);
        // Type 250 (unknown), critical, empty; then a Delete of the IKE SA.
        let chain = [PayloadType::Delete.to_u8(), 0x80, 0, 4, 0, 0, 0, 8, protocol_id::IKE, 0, 0, 0];
        let header = gateway_header(&resp_sa, 0, ExchangeType::Informational, false);
        let request = from_gateway_raw(&resp_sa, header, PayloadType::from_u8(250), &chain);

        assert_eq!(deliver(&mut liveness, &gateway, &request), Liveness::Alive, "the Delete is not acted on");
        let answer = sent_to(&gateway).expect("answered");
        assert_eq!(error_answer(&resp_sa, &answer, ExchangeType::Informational, 0), (notify_type::UNSUPPORTED_CRITICAL_PAYLOAD, vec![250]));
        assert_eq!(deliver(&mut liveness, &gateway, &build_informational(&resp_sa, 1, false, &[], &[1u8; 8]).unwrap()), Liveness::Alive);
        assert!(sent_to(&gateway).is_some(), "the IKE SA goes on: 1 is answered");

        // Control: not critical, the unknown payload is ignored (§2.5) and
        // the Delete after it is acted on.
        let (init_sa, resp_sa) = liveness_sa_pair();
        let mut liveness = session_facing(&gateway, init_sa, None);
        let mut chain = chain;
        chain[1] = 0;
        let header = gateway_header(&resp_sa, 0, ExchangeType::Informational, false);
        let request = from_gateway_raw(&resp_sa, header, PayloadType::from_u8(250), &chain);
        assert_eq!(deliver(&mut liveness, &gateway, &request), Liveness::PeerTornDown);
        assert!(open_informational(&resp_sa, &sent_to(&gateway).expect("answered")).unwrap().is_empty());
    }

    /// RFC 7296 §3.11: a Delete's Protocol ID is IKE, AH or ESP; its SPI Size
    /// is 0 for the IKE SA and 4 for AH or ESP; the IKE SA's carries no SPI;
    /// and its SPIs fill it exactly. One that breaks any of this is badly
    /// formatted -- INVALID_SYNTAX, fatal to the IKE SA (§2.21.3) -- and
    /// deletes nothing. A Delete of the IKE SA with an SPI Size of 4 used to
    /// be taken as that and answered empty; one announcing two ESP SPIs but
    /// carrying the primary's alone deleted it.
    #[test]
    fn a_malformed_delete_is_answered_invalid_syntax_and_deletes_nothing() {
        let primary = 0xAAAAu32.to_be_bytes();
        let cases: [(&str, Vec<u8>); 5] = [
            ("IKE, SPI Size 4, one SPI", [&[protocol_id::IKE, 4, 0, 1][..], &primary].concat()),
            ("IKE, one SPI announced", vec![protocol_id::IKE, 0, 0, 1]),
            ("ESP, SPI Size 8", [&[protocol_id::ESP, 8, 0, 1][..], &[0; 4], &primary].concat()),
            ("ESP, two SPIs announced, one there", [&[protocol_id::ESP, 4, 0, 2][..], &primary].concat()),
            ("Protocol ID 0", [&[0, 4, 0, 1][..], &primary].concat()),
        ];
        for (what, body) in cases {
            let (init_sa, resp_sa) = liveness_sa_pair();
            let gateway = UdpSocket::bind("127.0.0.1:0").unwrap();
            let mut liveness = session_facing(&gateway, init_sa, Some(ChildSpis { local: 0x6666, peer: 0x7777 }));
            let request = build_informational(&resp_sa, 0, false, &[(PayloadType::Delete, body)], &[7u8; 8]).unwrap();
            assert_eq!(deliver(&mut liveness, &gateway, &request), Liveness::PeerTornDown, "{what}");
            let answer = sent_to(&gateway).expect("answered");
            assert_eq!(error_answer(&resp_sa, &answer, ExchangeType::Informational, 0), (notify_type::INVALID_SYNTAX, Vec::new()), "{what}");
            assert!(liveness.take_peer_deleted_children().is_empty(), "{what}: nothing deleted");
            assert!(liveness.primary_child_alive && liveness.child6.is_some(), "{what}: nothing deleted");
        }

        // Control: a well-formed Delete of an AH SA this side doesn't have is
        // passed over, answered empty.
        let (init_sa, resp_sa) = liveness_sa_pair();
        let gateway = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut liveness = session_facing(&gateway, init_sa, Some(ChildSpis { local: 0x6666, peer: 0x7777 }));
        let ah = [&[protocol_id::AH, 4, 0, 1][..], &0x1234u32.to_be_bytes()].concat();
        let request = build_informational(&resp_sa, 0, false, &[(PayloadType::Delete, ah)], &[7u8; 8]).unwrap();
        assert_eq!(deliver(&mut liveness, &gateway, &request), Liveness::Alive);
        assert!(open_informational(&resp_sa, &sent_to(&gateway).expect("answered")).unwrap().is_empty());
    }

    /// §2.21.3 on the IKE SA retired after a rekey: `INVALID_SYNTAX` ends
    /// that IKE SA alone, which answers nothing new after it; the new one,
    /// holding the CHILD SAs, goes on.
    #[test]
    fn a_malformed_request_on_the_retired_ike_sa_ends_that_one_alone() {
        let (init_sa, resp_sa) = liveness_sa_pair();
        let gateway = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut liveness = session_facing(&gateway, init_sa, None);
        let ni = [0x55u8; 32];
        assert_eq!(deliver(&mut liveness, &gateway, &gateway_ike_rekey(&resp_sa, 0, &ni)), Liveness::Alive);
        let new_sa = gateway_ike_rekey_done(&resp_sa, &ni, &sent_to(&gateway).expect("the IKE SA rekey is answered"));

        let header = gateway_header(&resp_sa, 1, ExchangeType::Informational, false);
        assert_eq!(deliver(&mut liveness, &gateway, &from_gateway_raw(&resp_sa, header, PayloadType::Delete, &MALFORMED_CHAIN)), Liveness::Alive);
        let answer = sent_to(&gateway).expect("answered on the old IKE SA");
        assert_eq!(error_answer(&resp_sa, &answer, ExchangeType::Informational, 1), (notify_type::INVALID_SYNTAX, Vec::new()));
        assert_eq!(deliver(&mut liveness, &gateway, &build_informational(&resp_sa, 2, false, &[], &[3u8; 8]).unwrap()), Liveness::Alive);
        assert_eq!(sent_to(&gateway), None, "the old IKE SA is gone");
        assert_eq!(deliver(&mut liveness, &gateway, &build_informational(&new_sa, 0, false, &[], &[4u8; 8]).unwrap()), Liveness::Alive);
        assert!(open_informational(&new_sa, &sent_to(&gateway).expect("the new IKE SA goes on")).is_ok());
    }

    /// RFC 7296 §3.1, §2.2: a request is one on this IKE SA only when its
    /// header says so -- the IKE SA's SPIs, and the Initiator flag of the
    /// gateway's role in it. The integrity check covers the header, but the
    /// keys don't depend on it, so a body authentic under a header naming
    /// other SPIs, or claiming the other role, must be dropped unanswered.
    #[test]
    fn a_request_whose_header_is_not_this_ike_sas_is_dropped() {
        let (init_sa, resp_sa) = liveness_sa_pair();
        let gateway = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut liveness = session_facing(&gateway, init_sa, None);
        let delete = [delete_payload(Delete::ike_sa())];

        let mut other_spis = gateway_header(&resp_sa, 0, ExchangeType::Informational, false);
        other_spis.responder_spi ^= 1;
        let mut other_role = gateway_header(&resp_sa, 0, ExchangeType::Informational, false);
        other_role.flags.initiator = true;
        for header in [other_spis, other_role] {
            assert_eq!(deliver(&mut liveness, &gateway, &from_gateway(&resp_sa, header, &delete)), Liveness::Alive);
            assert_eq!(sent_to(&gateway), None);
        }
        // Control: under this IKE SA's own header, the same Delete ends the tunnel.
        let genuine = from_gateway(&resp_sa, gateway_header(&resp_sa, 0, ExchangeType::Informational, false), &delete);
        assert_eq!(deliver(&mut liveness, &gateway, &genuine), Liveness::PeerTornDown);
        assert!(sent_to(&gateway).is_some());
    }

    /// Anyone can send the IKE socket a datagram that is no IKEv2 message --
    /// too short to be one, or of another major version. It is dropped, and
    /// `peek` and `probe` carry on as if it had never come rather than fail.
    #[test]
    fn a_datagram_that_is_no_ikev2_message_is_dropped_without_failing_the_session() {
        let (init_sa, resp_sa) = liveness_sa_pair();
        let gateway = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut liveness = session_facing(&gateway, init_sa, None);
        let mut version_1 = build_informational(&resp_sa, 0, false, &[], &[1u8; 8]).unwrap();
        version_1[17] = 0x10;
        for junk in [b"garbage".to_vec(), version_1] {
            assert_eq!(deliver(&mut liveness, &gateway, &junk), Liveness::Alive);
            assert_eq!(sent_to(&gateway), None);
        }

        // Nor does junk ahead of a probe's answer (Message ID 2) hide it.
        let to = liveness.sock.local_addr().unwrap();
        gateway.send_to(b"garbage", to).unwrap();
        gateway.send_to(&build_informational(&resp_sa, 2, true, &[], &[2u8; 8]).unwrap(), to).unwrap();
        assert_eq!(liveness.probe(Duration::from_millis(300)).unwrap(), Liveness::Alive);
    }

    /// Nor does a stream of datagrams keep `peek` waiting past its timeout:
    /// each one read doesn't start the wait over.
    #[test]
    fn peek_keeps_to_its_timeout_while_datagrams_keep_coming() {
        let (init_sa, resp_sa) = liveness_sa_pair();
        let gateway = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut liveness = session_facing(&gateway, init_sa, None);
        let to = liveness.sock.local_addr().unwrap();
        let foreign = build_informational(&resp_sa, 7, true, &[], &[1u8; 8]).unwrap(); // an answer to nothing
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let sender = thread::spawn({
            let stop = stop.clone();
            move || {
                let until = Instant::now() + Duration::from_secs(3);
                while !stop.load(Ordering::Relaxed) && Instant::now() < until {
                    let _ = gateway.send_to(&foreign, to);
                    thread::sleep(Duration::from_millis(20));
                }
            }
        });
        let started = Instant::now();
        let live = liveness.peek(Duration::from_millis(200));
        let took = started.elapsed();
        stop.store(true, Ordering::Relaxed);
        sender.join().unwrap();
        assert_eq!(live.unwrap(), Liveness::Alive);
        assert!(took < Duration::from_millis(1000), "peek(200ms) took {took:?}");
    }

    /// RFC 7296 §2.2, §3.1: the answer to our request is the response with its
    /// Message ID on this IKE SA, of the request's exchange, from the peer's
    /// role, and authentic. A response short of any of that is not it: a
    /// probe answered only with such decoys got no answer.
    #[test]
    fn only_the_genuine_answer_to_a_probe_counts() {
        let (init_sa, resp_sa) = liveness_sa_pair();
        let gateway = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut liveness = session_facing(&gateway, init_sa, None);
        let to = liveness.sock.local_addr().unwrap();
        let answer = |mid: u32, change: &dyn Fn(&mut IkeHeader)| {
            let mut header = gateway_header(&resp_sa, mid, ExchangeType::Informational, true);
            change(&mut header);
            from_gateway(&resp_sa, header, &[])
        };

        let decoys = [
            answer(2, &|h| h.exchange_type = ExchangeType::CreateChildSa),
            answer(2, &|h| h.initiator_spi ^= 1),
            answer(2, &|h| h.flags.initiator = true),
            tampered(answer(2, &|_| ())),
        ];
        for decoy in &decoys {
            gateway.send_to(decoy, to).unwrap();
        }
        assert_eq!(liveness.probe(Duration::from_millis(200)).unwrap(), Liveness::NoReply);

        // Control: the genuine answer to the next probe (Message ID 3).
        gateway.send_to(&answer(3, &|_| ()), to).unwrap();
        assert_eq!(liveness.probe(Duration::from_millis(300)).unwrap(), Liveness::Alive);
    }

    /// The same for our CREATE_CHILD_SA: responses with the rekey's Message ID
    /// that are not the gateway's answer -- one that does not authenticate,
    /// one on other SPIs, one claiming the other role, one of another
    /// exchange -- arriving ahead of the real answer are passed over, and the
    /// rekey completes on the real one.
    #[test]
    fn a_rekey_takes_the_genuine_answer_past_decoys_with_its_message_id() {
        let (init_sa, resp_sa) = liveness_sa_pair();
        let gateway = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut liveness = session_facing(&gateway, init_sa, None);
        gateway.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let from = liveness.sock.local_addr().unwrap();
        let peer = thread::spawn(move || {
            let request = recv_from_client(&gateway);
            let mid = IkeHeader::parse(&request).unwrap().message_id;
            let (answer, child) = gateway_answers_rekey(&resp_sa, &request, &[0x80u8; 32]);
            let inner = gateway_payloads(&resp_sa, &answer);
            let decoy = |change: &dyn Fn(&mut IkeHeader)| {
                let mut header = gateway_header(&resp_sa, mid, ExchangeType::CreateChildSa, true);
                change(&mut header);
                from_gateway(&resp_sa, header, &inner)
            };
            let decoys = [
                tampered(answer.clone()),
                decoy(&|h| h.responder_spi ^= 1),
                decoy(&|h| h.flags.initiator = true),
                build_informational(&resp_sa, mid, true, &[], &[3u8; 8]).unwrap(),
            ];
            for decoy in decoys.iter().chain([&answer]) {
                gateway.send_to(decoy, from).unwrap();
            }
            let delete = recv_from_client(&gateway);
            gateway.send_to(&informational_answer(&resp_sa, &delete, &[0xAAAA]), from).unwrap();
            (child.outbound.spi(), delete_in(&resp_sa, &delete))
        });

        let rekeyed = liveness.rekey_child(Duration::from_secs(2)).expect("the rekey completes on the gateway's real answer");
        let (gateway_made, deleted) = peer.join().unwrap();
        assert_eq!((rekeyed.local_spi, rekeyed.peer_spi), (gateway_made, PEER_L_SPI));
        assert_eq!(deleted, Some(Delete::esp(vec![0xBBBB])), "and the SA it replaced is deleted as usual");
    }

    /// RFC 7296 §3.11, §1.4.1: an INFORMATIONAL may carry several Delete
    /// payloads, and each counts. A Delete of the IKE SA after one naming an
    /// SA this side doesn't know still ends the tunnel, and is answered with
    /// an empty INFORMATIONAL, as a Delete of the IKE SA is.
    #[test]
    fn every_delete_payload_of_a_request_counts() {
        let (init_sa, resp_sa) = liveness_sa_pair();
        let gateway = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut liveness = session_facing(&gateway, init_sa, None);
        let payloads = [delete_payload(Delete::esp(vec![0x1234])), delete_payload(Delete::ike_sa())];
        let request = build_informational(&resp_sa, 0, false, &payloads, &[7u8; 8]).unwrap();
        assert_eq!(deliver(&mut liveness, &gateway, &request), Liveness::PeerTornDown);
        let answer = sent_to(&gateway).expect("answered");
        assert!(open_informational(&resp_sa, &answer).unwrap().is_empty(), "the answer to a Delete of the IKE SA is empty");
    }

    /// ...and so does every SPI they name: a Delete of both CHILD SAs, in one
    /// payload or two, leaves the tunnel with none, which ends it as the
    /// primary's alone does when there is no IPv6 one. The answer carries our
    /// Delete for each pair (RFC 7296 §1.4.1).
    #[test]
    fn a_delete_naming_both_child_sas_takes_both() {
        for deletes in [vec![Delete::esp(vec![0x7777, 0xAAAA])], vec![Delete::esp(vec![0x7777]), Delete::esp(vec![0xAAAA])]] {
            let (init_sa, resp_sa) = liveness_sa_pair();
            let gateway = UdpSocket::bind("127.0.0.1:0").unwrap();
            let mut liveness = session_facing(&gateway, init_sa, Some(ChildSpis { local: 0x6666, peer: 0x7777 }));
            let payloads: Vec<_> = deletes.into_iter().map(delete_payload).collect();
            let request = build_informational(&resp_sa, 0, false, &payloads, &[7u8; 8]).unwrap();
            assert_eq!(deliver(&mut liveness, &gateway, &request), Liveness::PeerTornDown, "{} payload(s)", payloads.len());
            assert_eq!(esp_spis_deleted(&resp_sa, &sent_to(&gateway).expect("answered")), vec![0x6666, 0xBBBB]);
        }
    }

    /// RFC 7296 §1.4.1: "the response in the INFORMATIONAL exchange will
    /// contain Delete payloads for the paired SAs going in the other
    /// direction" -- the gateway deleting one of the tunnel's CHILD SAs gets
    /// ours for it back, naming our inbound SPI of the pair.
    #[test]
    fn a_child_sa_delete_is_answered_with_ours_for_the_pair() {
        for (named, ours, left) in [(0xAAAA, 0xBBBB, ChildKind::Primary), (0x7777, 0x6666, ChildKind::Ipv6)] {
            let (init_sa, resp_sa) = liveness_sa_pair();
            let gateway = UdpSocket::bind("127.0.0.1:0").unwrap();
            let mut liveness = session_facing(&gateway, init_sa, Some(ChildSpis { local: 0x6666, peer: 0x7777 }));
            let request = build_informational(&resp_sa, 0, false, &[delete_payload(Delete::esp(vec![named]))], &[7u8; 8]).unwrap();
            assert_eq!(deliver(&mut liveness, &gateway, &request), Liveness::Alive);
            assert_eq!(esp_spis_deleted(&resp_sa, &sent_to(&gateway).expect("answered")), vec![ours]);
            assert_eq!(liveness.take_peer_deleted_children(), vec![left]);
        }
    }

    /// RFC 7296 §2.2, §2.18: the window belongs to the IKE SA. After the
    /// gateway rekeyed it, the old IKE SA keeps its own until it is gone:
    /// another request under the ID its rekey took (0) is not answered, its
    /// Delete (1) is answered on it and a retransmission of that Delete gets
    /// the same answer, but nothing after it is (§1.4.1: the IKE SA is gone),
    /// while the new IKE SA starts over at 0.
    #[test]
    fn a_retired_ike_sa_keeps_its_own_receive_window() {
        let (init_sa, resp_sa) = liveness_sa_pair();
        let gateway = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut liveness = session_facing(&gateway, init_sa, None);
        let ni = [0x55u8; 32];
        assert_eq!(deliver(&mut liveness, &gateway, &gateway_ike_rekey(&resp_sa, 0, &ni)), Liveness::Alive);
        let new_sa = gateway_ike_rekey_done(&resp_sa, &ni, &sent_to(&gateway).expect("the IKE SA rekey is answered"));

        let reusing_0 = build_informational(&resp_sa, 0, false, &[], &[2u8; 8]).unwrap();
        assert_eq!(deliver(&mut liveness, &gateway, &reusing_0), Liveness::Alive);
        assert_eq!(sent_to(&gateway), None, "Message ID 0 of the old IKE SA was its rekey's");

        let delete = ike_delete_request(&resp_sa, 1);
        assert_eq!(deliver(&mut liveness, &gateway, &delete), Liveness::Alive, "the old IKE SA's Delete is routine");
        let answer = sent_to(&gateway).expect("answered on the old IKE SA");
        assert!(open_informational(&resp_sa, &answer).unwrap().is_empty());
        assert_eq!(deliver(&mut liveness, &gateway, &delete), Liveness::Alive);
        assert_eq!(sent_to(&gateway), Some(answer), "a retransmitted Delete gets the same answer");
        assert_eq!(deliver(&mut liveness, &gateway, &build_informational(&resp_sa, 2, false, &[], &[3u8; 8]).unwrap()), Liveness::Alive);
        assert_eq!(sent_to(&gateway), None, "the deleted IKE SA answers nothing new");

        assert_eq!(deliver(&mut liveness, &gateway, &build_informational(&new_sa, 0, false, &[], &[4u8; 8]).unwrap()), Liveness::Alive);
        assert!(open_informational(&new_sa, &sent_to(&gateway).expect("the new IKE SA's 0 is answered")).is_ok());
    }

    /// RFC 7296 §2.1: a refusal is an answer like any other. The gateway
    /// retransmitting a CREATE_CHILD_SA this side refused gets the same bytes
    /// back, not a refusal built anew.
    #[test]
    fn a_refused_create_child_sa_retransmitted_gets_the_same_refusal() {
        let (init_sa, resp_sa) = liveness_sa_pair();
        let gateway = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut liveness = session_facing(&gateway, init_sa, None);
        let ts = TrafficSelectors::ipv4_full_tunnel();
        let request = rekey::build_child_request(&resp_sa, 0, None, PEER_NEW_SPI, &PEER_NI, SkCipher::Aes256Gcm, None, &ts, &[7u8; 8]).unwrap();
        deliver(&mut liveness, &gateway, &request);
        let refusal = sent_to(&gateway).expect("refused");
        assert_eq!(refusal_reason(&resp_sa, &refusal), notify_type::NO_ADDITIONAL_SAS);
        deliver(&mut liveness, &gateway, &request);
        assert_eq!(sent_to(&gateway), Some(refusal), "the same refusal, byte for byte");
    }

    /// RFC 7296 §2.2: two counters, one for our requests and one for the
    /// gateway's. Ours going up (probes 2 and 3) leaves the ID the gateway's
    /// next request carries alone (0, then 1), and the other way round.
    #[test]
    fn our_message_ids_and_the_gateways_are_counted_apart() {
        let (init_sa, resp_sa) = liveness_sa_pair();
        let gateway = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut liveness = session_facing(&gateway, init_sa, None);
        let to = liveness.sock.local_addr().unwrap();
        for mid in [2, 3] {
            gateway.send_to(&build_informational(&resp_sa, mid, true, &[], &[1u8; 8]).unwrap(), to).unwrap();
            assert_eq!(liveness.probe(Duration::from_millis(300)).unwrap(), Liveness::Alive);
        }
        while sent_to(&gateway).is_some() {} // the probes themselves
        for mid in [0, 1] {
            deliver(&mut liveness, &gateway, &build_informational(&resp_sa, mid, false, &[], &[2u8; 8]).unwrap());
            assert_eq!(IkeHeader::parse(&sent_to(&gateway).expect("answered")).unwrap().message_id, mid);
        }
        assert_eq!(liveness.next_message_id, 4, "answering the gateway uses none of ours");
    }

    // A free-ish loopback port per test, avoiding cross-test collisions
    // without needing a real ephemeral-port allocator here.
    static NEXT_PORT: AtomicU32 = AtomicU32::new(29500);
    fn next_addr() -> SocketAddr {
        let port = NEXT_PORT.fetch_add(1, Ordering::SeqCst) as u16;
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    /// [`next_addr`]'s IPv6-loopback twin, `None` on a host with no IPv6
    /// loopback (the IPv6 tests then skip rather than fail).
    fn next_addr_v6() -> Option<SocketAddr> {
        UdpSocket::bind("[::1]:0").ok()?;
        let port = NEXT_PORT.fetch_add(1, Ordering::SeqCst) as u16;
        Some(format!("[::1]:{port}").parse().unwrap())
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

    /// A DH proposal deliberately built so the client's own first guess (RFC
    /// 7296 §1.2: it sends a `KE` payload for the group it expects to be
    /// picked before knowing the responder's actual choice) disagrees with
    /// what `negotiate::select` will actually pick on the other end --
    /// listing the DH transform this crate ranks *lower* first in the
    /// `Transform` list (what [`offer_dh_group`] naively reads) while also
    /// offering the one it ranks highest (what `negotiate::select_from_proposal`
    /// actually picks, regardless of list order): X25519 always outranks
    /// MODP_2048 in `DH_CANDIDATES`. A real client with several DH groups it's
    /// willing to accept genuinely hits this whenever the responder's
    /// preference isn't the client's first list entry.
    fn offer_with_a_dh_guess_the_responder_wont_pick() -> SecurityAssociation {
        SecurityAssociation {
            proposals: vec![crate::ikev2::payload::Proposal {
                num: 1,
                protocol_id: protocol_id::IKE,
                spi: Vec::new(),
                transforms: vec![
                    crate::ikev2::payload::Transform {
                        transform_type: crate::ikev2::payload::transform_type::DH,
                        transform_id: crate::ikev2::payload::transform_id::MODP_2048,
                        key_length: None,
                    },
                    crate::ikev2::payload::Transform {
                        transform_type: crate::ikev2::payload::transform_type::ENCR,
                        transform_id: crate::ikev2::payload::transform_id::AES_GCM_16,
                        key_length: Some(256),
                    },
                    crate::ikev2::payload::Transform {
                        transform_type: crate::ikev2::payload::transform_type::PRF,
                        transform_id: crate::ikev2::payload::transform_id::PRF_HMAC_SHA2_256,
                        key_length: None,
                    },
                    crate::ikev2::payload::Transform {
                        transform_type: crate::ikev2::payload::transform_type::DH,
                        transform_id: crate::ikev2::payload::transform_id::X25519,
                        key_length: None,
                    },
                ],
            }],
        }
    }

    /// Finding #5 of the ChatGPT6 Astra ryke audit: `sa_init_with_sockets` used
    /// to send one `IKE_SA_INIT` and hand back whatever `initiator_complete_natt`
    /// made of the reply -- a responder that named a different DH group via a
    /// bare `INVALID_KE_PAYLOAD` notify (RFC 7296 §1.2/§2.7, no state kept)
    /// surfaced as a plain parse failure, not something the client retried.
    /// This drives a real two-sided exchange: the responder genuinely prefers
    /// X25519 over the client's guessed MODP_2048 (see
    /// `offer_with_a_dh_guess_the_responder_wont_pick`) and answers the first
    /// request with `InvalidKe`; if the fix didn't retry with the corrected
    /// group, this would time out waiting for a second request that never
    /// comes, rather than complete.
    #[test]
    fn sa_init_retries_after_the_responder_names_a_different_dh_group() {
        let bind = next_addr();
        let responder = thread::spawn(move || {
            let sock = UdpSocket::bind(bind).unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let resp_secret = LocalSecret::generate(&mut OsEntropy::new().unwrap(), 32);
            let mut buf = [0u8; 2048];
            loop {
                let (n, from) = sock.recv_from(&mut buf).unwrap();
                let result = responder_respond_natt(&buf[..n], &resp_secret, bind, from, None).unwrap();
                match result {
                    SaInitResult::Established { response, .. } => {
                        sock.send_to(&response, from).unwrap();
                        break;
                    }
                    SaInitResult::InvalidKe { response, group } => {
                        assert_eq!(group, crate::ikev2::payload::transform_id::X25519, "the responder must name the group it actually prefers");
                        sock.send_to(&response, from).unwrap();
                    }
                    SaInitResult::CookieRequired { .. } => panic!("no cookie policy is in effect"),
                }
            }
        });
        thread::sleep(Duration::from_millis(50));

        let mut session = Ikev2Session::new(OsEntropy::new().unwrap());
        let local_port = next_addr().port();
        let (_sock, _our_addr, sa, _nat) =
            session.sa_init_on_port(bind, &offer_with_a_dh_guess_the_responder_wont_pick(), local_port).unwrap();
        responder.join().unwrap();

        assert_eq!(sa.suite.dh_id, crate::ikev2::payload::transform_id::X25519, "must have completed with the corrected group");
    }

    /// Finding #5, the other half: a responder demanding a return-routability
    /// cookie (RFC 7296 §2.6, anti-DoS) also keeps no state and answers with a
    /// bare `COOKIE` notify -- previously surfaced the same way as a malformed
    /// message instead of driving a retry that echoes the cookie back. Runs a
    /// real cookie-requiring responder end to end; without the fix this hangs
    /// waiting for a retry that never comes.
    #[test]
    fn sa_init_retries_after_the_responder_requires_a_cookie() {
        let bind = next_addr();
        let responder = thread::spawn(move || {
            let sock = UdpSocket::bind(bind).unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let resp_secret = LocalSecret::generate(&mut OsEntropy::new().unwrap(), 32);
            let secret = [0x5Au8; 32];
            let mut buf = [0u8; 2048];
            loop {
                let (n, from) = sock.recv_from(&mut buf).unwrap();
                let peer_bytes = from.ip().to_string().into_bytes();
                let policy = crate::ikev2::exchange::CookiePolicy { secret: &secret, peer: &peer_bytes, required: true };
                let result = responder_respond_natt(&buf[..n], &resp_secret, bind, from, Some(policy)).unwrap();
                match result {
                    SaInitResult::Established { response, .. } => {
                        sock.send_to(&response, from).unwrap();
                        break;
                    }
                    SaInitResult::CookieRequired { response } => {
                        sock.send_to(&response, from).unwrap();
                    }
                    SaInitResult::InvalidKe { .. } => panic!("the offer's own group must be acceptable"),
                }
            }
        });
        thread::sleep(Duration::from_millis(50));

        let mut session = Ikev2Session::new(OsEntropy::new().unwrap());
        let local_port = next_addr().port();
        let (_sock, _our_addr, _sa, _nat) = session.sa_init_on_port(bind, &default_ike_offer(), local_port).unwrap();
        responder.join().unwrap();
    }

    /// `with_forced_natt` over a path with **no** NAT: the responder tells
    /// `responder_respond_natt` the true source address (unlike the test above,
    /// which fakes a translation), so only the lie in our own
    /// `NAT_DETECTION_SOURCE_IP` can make anything float. The request that
    /// reached the responder must carry a source hash that doesn't match, and this
    /// side must float on its own -- its detection sees nothing.
    #[test]
    fn a_forced_session_floats_over_a_path_with_no_nat() {
        for force in [false, true] {
            let bind = next_addr();
            let responder = thread::spawn(move || {
                let sock = UdpSocket::bind(bind).unwrap();
                sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut buf = [0u8; 2048];
                let (n, from) = sock.recv_from(&mut buf).unwrap();
                // What the responder itself would conclude about the initiator.
                let (spi_i, source) = crate::ikev2::exchange::request_nat_source_hash(&buf[..n]).expect("NAT_DETECTION_SOURCE_IP");
                let sees_nat = crate::ikev2::natt::peer_is_behind_nat(&source, spi_i, 0, from.ip(), from.port());
                let resp_secret = LocalSecret::generate(&mut OsEntropy::new().unwrap(), 32);
                let response = match responder_respond_natt(&buf[..n], &resp_secret, bind, from, None).unwrap() {
                    crate::ikev2::exchange::SaInitResult::Established { response, .. } => response,
                    _ => panic!("expected Established"),
                };
                sock.send_to(&response, from).unwrap();
                sees_nat
            });
            thread::sleep(Duration::from_millis(50));

            let mut session = Ikev2Session::new(OsEntropy::new().unwrap());
            if force {
                session = session.with_forced_natt();
            }
            let local_port = next_addr().port();
            let (sock, our_addr, _sa, nat) = session.sa_init_on_port(bind, &default_ike_offer(), local_port).unwrap();
            let responder_sees_nat = responder.join().unwrap();

            assert!(!nat.we_are_natted && !nat.peer_is_natted, "there is no NAT on loopback (force={force})");
            assert_eq!(nat.forced, force);
            assert_eq!(responder_sees_nat, force, "the responder must conclude NAT exactly when we forced it");
            assert_eq!(nat.float_to_4500(), force);
            let expected_port = if force { natt_local_port(local_port) } else { local_port };
            assert_eq!(sock.local_addr().unwrap().port(), expected_port, "force={force}: the returned socket is the one to keep using");
            assert_eq!(our_addr.port(), expected_port);
        }
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

    /// Same as [`run_psk_responder`], but the CHILD SA of `IKE_AUTH` fails the
    /// way RFC 7296 §1.2 allows: the response keeps its valid IDr + AUTH and
    /// carries the `error` notify instead of SA/TS. Returns whether the client
    /// then closed the IKE SA with a Delete.
    fn run_psk_responder_rejecting_child(bind: SocketAddr, psk: Vec<u8>, error: u16) -> bool {
        use crate::ikev2::message::{encode_payload_chain, first_payload_type};
        use crate::ikev2::payload::Notify;

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
        let (resp, _peer_id, _spi, _ic) = responder_process_auth(&sa, &buf[..n], &rcfg, 0xC0FFEE, &[9u8; 8], None).unwrap();

        // Reseal the honest response without its SA/TS/... payloads, plus the error.
        let cipher = sa.suite.sk_cipher();
        let (first, inner) = open_encrypted(cipher, &resp, &sa.keys.sk_er, &sa.keys.sk_ar).unwrap();
        let mut kept: Vec<(PayloadType, Vec<u8>)> = payloads(first, &inner)
            .map(|p| p.unwrap())
            .filter(|p| matches!(p.payload_type, PayloadType::IdResponder | PayloadType::Authentication))
            .map(|p| (p.payload_type, p.data.to_vec()))
            .collect();
        kept.push((PayloadType::Notify, Notify::status(error, Vec::new()).to_bytes()));
        let header = IkeHeader::parse(&resp).unwrap();
        let rejected = sk::build_encrypted(
            cipher,
            header,
            first_payload_type(&kept),
            &encode_payload_chain(&kept),
            &sa.keys.sk_er,
            &sa.keys.sk_ar,
            &[8u8; 8],
        )
        .unwrap();
        sock.send_to(&rejected, from).unwrap();

        sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => open_informational(&sa, &buf[..n])
                .map(|ps| ps.iter().any(|(t, _)| *t == PayloadType::Delete))
                .unwrap_or(false),
            Err(_) => false,
        }
    }

    #[test]
    fn connect_direct_reports_a_child_sa_rejection_and_closes_the_ike_sa() {
        // A responder that authenticates us but refuses the CHILD SA (RFC 7296
        // §1.2) used to surface as `MissingPayload("SA")`, with the IKE SA left
        // for the gateway to time out.
        for error in [notify_type::TS_UNACCEPTABLE, notify_type::SINGLE_PAIR_REQUIRED, notify_type::NO_PROPOSAL_CHOSEN] {
            let bind = next_addr();
            let psk = b"shared-secret".to_vec();
            let responder = thread::spawn({
                let psk = psk.clone();
                move || run_psk_responder_rejecting_child(bind, psk, error)
            });
            thread::sleep(Duration::from_millis(50));

            let mut session = Ikev2Session::new(OsEntropy::new().unwrap());
            let cfg = AuthConfig::psk(Identification::fqdn("client.test"), psk);
            let err = session
                .connect_direct_on_port(bind, &default_ike_offer(), &cfg, false, &default_esp_offer(), next_addr().port())
                .err()
                .expect("a rejected CHILD SA must fail the connect");
            match err {
                DriverError::Ike(IkeError::PeerRejected { notify_type: got, name }) => {
                    assert_eq!(got, error);
                    assert_eq!(name, notify_type_name(error));
                }
                other => panic!("expected PeerRejected({}), got {other:?}", notify_type_name(error)),
            }
            assert!(responder.join().unwrap(), "the client must close the IKE SA with a Delete ({})", notify_type_name(error));
        }
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

    /// Same as [`run_psk_responder_fragmented`], but re-sends the first
    /// fragment a second time before the rest -- a real duplicate delivery
    /// (a UDP datagram duplicated in flight, or a peer retransmitting a
    /// fragment it wasn't sure had arrived), not a forged one. Reproduces
    /// Finding #6: before the fix, `send_and_retry_reassembling` appended
    /// every arrival straight into a `Vec`, so this one duplicate left the
    /// set permanently 4-long against a Total of 3 and reassembly never
    /// succeeded, even once all 3 legitimate fragments were in hand.
    fn run_psk_responder_fragmented_with_a_duplicate(bind: SocketAddr, psk: Vec<u8>) {
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

        let cipher = sa.suite.sk_cipher();
        let (first_inner, inner) = open_encrypted(cipher, &resp, &sa.keys.sk_er, &sa.keys.sk_ar).unwrap();
        let header = IkeHeader::parse(&resp).unwrap();
        let content_per_fragment = (inner.len() / 3).max(1);
        let fragments =
            fragment::build_fragments(cipher, &header, first_inner, &inner, &sa.keys.sk_er, &sa.keys.sk_ar, 42, content_per_fragment)
                .unwrap();
        assert!(fragments.len() > 1, "test setup: expected the response to actually need multiple fragments");

        sock.send_to(&fragments[0], from).unwrap(); // duplicate delivery of fragment #1, ahead of the real set
        for frag in &fragments {
            sock.send_to(frag, from).unwrap();
        }
    }

    #[test]
    fn connect_direct_reassembles_a_fragmented_response_despite_a_duplicate_fragment() {
        let bind = next_addr();
        let psk = b"shared-secret".to_vec();
        let responder = thread::spawn({
            let psk = psk.clone();
            move || run_psk_responder_fragmented_with_a_duplicate(bind, psk)
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

    /// A responder that has run `IKE_SA_INIT` and built its `IKE_AUTH`
    /// response, with that response in hand as three RFC 7383 fragments --
    /// for the tests below to deliver as they choose.
    struct FragmentingResponder {
        sock: UdpSocket,
        from: SocketAddr,
        sa: CompletedSaInit,
        /// The client's `IKE_AUTH` request, as it came in.
        request: Vec<u8>,
        header: IkeHeader,
        first_inner: PayloadType,
        inner: Vec<u8>,
        fragments: Vec<Vec<u8>>,
    }

    impl FragmentingResponder {
        fn start(bind: SocketAddr, psk: Vec<u8>) -> Self {
            let sock = UdpSocket::bind(bind).unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            let mut buf = [0u8; 4096];
            let (n, from) = sock.recv_from(&mut buf).unwrap();
            let resp_secret = LocalSecret::generate(&mut OsEntropy::new().unwrap(), 32);
            let (response, sa) = match responder_respond_natt(&buf[..n], &resp_secret, bind, from, None).unwrap() {
                SaInitResult::Established { response, sa } => (response, sa),
                _ => panic!("expected Established"),
            };
            sock.send_to(&response, from).unwrap();

            let (n, from) = sock.recv_from(&mut buf).unwrap();
            let request = buf[..n].to_vec();
            let rcfg = AuthConfig::psk(Identification::fqdn("responder.test"), psk);
            let (resp, _peer_id, _spi, _ic) = responder_process_auth(&sa, &request, &rcfg, 0xC0FFEE, &[9u8; 8], None).unwrap();
            let (first_inner, inner) = open_encrypted(sa.suite.sk_cipher(), &resp, &sa.keys.sk_er, &sa.keys.sk_ar).unwrap();
            let header = IkeHeader::parse(&resp).unwrap();
            let mut responder = Self { sock, from, sa, request, header, first_inner, inner, fragments: Vec::new() };
            responder.fragments = responder.split(3, 42);
            assert_eq!(responder.fragments.len(), 3, "test setup: the response must split three ways");
            responder
        }

        /// The response split into `pieces` fragments, with IVs from `iv_base`.
        fn split(&self, pieces: usize, iv_base: u64) -> Vec<Vec<u8>> {
            self.seal(self.header, &self.inner.clone(), pieces, iv_base)
        }

        /// `inner` under `header`, split into `pieces` fragments sealed with
        /// the responder's real keys.
        fn seal(&self, header: IkeHeader, inner: &[u8], pieces: usize, iv_base: u64) -> Vec<Vec<u8>> {
            let per = inner.len().div_ceil(pieces).max(1);
            let keys = &self.sa.keys;
            fragment::build_fragments(self.sa.suite.sk_cipher(), &header, self.first_inner, inner, &keys.sk_er, &keys.sk_ar, iv_base, per).unwrap()
        }

        fn send(&self, msg: &[u8]) {
            self.sock.send_to(msg, self.from).unwrap();
        }

        fn send_all(&self) {
            for f in &self.fragments {
                self.send(f);
            }
        }

        fn recv(&self) -> Vec<u8> {
            let mut buf = [0u8; 4096];
            let (n, _) = self.sock.recv_from(&mut buf).unwrap();
            buf[..n].to_vec()
        }
    }

    /// Runs `script` as the responder and connects to it: `Ok` with the
    /// CHILD SA's peer SPI, or the error the connect ended with.
    fn connect_through_fragments(script: impl FnOnce(FragmentingResponder) + Send + 'static) -> Result<u32, DriverError> {
        let bind = next_addr();
        let psk = b"shared-secret".to_vec();
        let responder = thread::spawn({
            let psk = psk.clone();
            move || script(FragmentingResponder::start(bind, psk))
        });
        thread::sleep(Duration::from_millis(50));
        let mut session = Ikev2Session::new(OsEntropy::new().unwrap());
        let cfg = AuthConfig::psk(Identification::fqdn("client.test"), psk);
        let result = session
            .connect_direct_on_port(bind, &default_ike_offer(), &cfg, false, &default_esp_offer(), next_addr().port())
            .map(|tunnel| tunnel.peer_spi);
        responder.join().unwrap();
        result
    }

    fn flip_last_byte(mut msg: Vec<u8>) -> Vec<u8> {
        *msg.last_mut().unwrap() ^= 1;
        msg
    }

    /// RFC 7383 §2.6: a fragment whose ICV does not verify is discarded.
    /// It used to be stored first and checked only once the set was
    /// complete, so a forged copy of fragment 1 sent ahead of the real set
    /// held its place, the genuine fragment 1 was dropped as its duplicate,
    /// and the connection failed.
    #[test]
    fn a_forged_fragment_ahead_of_the_real_set_does_not_take_its_place() {
        let got = connect_through_fragments(|r| {
            r.send(&flip_last_byte(r.fragments[0].clone()));
            r.send_all();
        });
        assert_eq!(got.unwrap(), 0xC0FFEE);
    }

    /// RFC 7383 §2.6: only an authentic fragment with a larger Total
    /// restarts the reassembly. A forged one used to throw away the
    /// genuine fragments already in hand.
    #[test]
    fn a_forged_fragment_with_a_larger_total_does_not_restart_the_reassembly() {
        let got = connect_through_fragments(|r| {
            r.send(&r.fragments[0]);
            r.send(&r.fragments[1]);
            r.send(&flip_last_byte(r.split(4, 900)[0].clone()));
            r.send(&r.fragments[2]);
        });
        assert_eq!(got.unwrap(), 0xC0FFEE);
    }

    /// RFC 7383 §2.6 (and §2.5.2: Total only grows as a sender retries with
    /// smaller fragments): a fragment with a smaller Total than the ones in
    /// hand is discarded, even an authentic one -- a late fragment of an
    /// older split. It used to restart the reassembly, and the next genuine
    /// fragment restarted it again.
    #[test]
    fn a_fragment_of_an_older_split_with_a_smaller_total_is_discarded() {
        let got = connect_through_fragments(|r| {
            r.send(&r.fragments[0]);
            r.send(&r.fragments[1]);
            r.send(&r.split(2, 500)[0]);
            r.send(&r.fragments[2]);
        });
        assert_eq!(got.unwrap(), 0xC0FFEE);
    }

    /// ...while an authentic fragment with a larger Total does restart it:
    /// the older, coarser split is dropped and the new one completes.
    #[test]
    fn a_split_with_a_larger_total_restarts_the_reassembly() {
        let got = connect_through_fragments(|r| {
            r.send(&r.split(2, 500)[0]);
            r.send_all();
        });
        assert_eq!(got.unwrap(), 0xC0FFEE);
    }

    /// RFC 7383 §2.6.1 and RFC 7296 §2.2: fragments belong together by
    /// their IKE SA, exchange, direction and Message ID. An authentic
    /// fragment from the same peer with the right Message ID but another
    /// exchange type, or sent as a request, used to be taken into the
    /// `IKE_AUTH` response.
    #[test]
    fn an_authentic_fragment_of_another_message_is_not_mixed_in() {
        let variants: [fn(&mut IkeHeader); 2] = [|h| h.exchange_type = ExchangeType::Informational, |h| h.flags.response = false];
        for (i, variant) in variants.into_iter().enumerate() {
            let got = connect_through_fragments(move |r| {
                let mut other = r.header;
                variant(&mut other);
                r.send(&r.seal(other, &[0x5a; 90], 3, 700)[0]);
                r.send_all();
            });
            assert_eq!(got.unwrap(), 0xC0FFEE, "variant {i}");
        }
    }

    /// RFC 7383 §2.6 and RFC 7296 §2.1: when fragments of the response go
    /// missing, the initiator retransmits its request and the responder
    /// resends the response. The request used to go out no more once the
    /// first fragment was in, so one lost fragment failed the connect.
    #[test]
    fn a_lost_fragment_is_recovered_by_retransmitting_the_request() {
        let got = connect_through_fragments(|r| {
            r.send(&r.fragments[0]);
            r.send(&r.fragments[2]);
            assert_eq!(r.recv(), r.request, "the retransmission is the same request");
            r.send_all();
        });
        assert_eq!(got.unwrap(), 0xC0FFEE);
    }

    /// A datagram that is not an IKE message at all, arriving between
    /// fragments, is passed over. It used to end the connect with a parse
    /// error.
    #[test]
    fn a_datagram_that_is_not_ike_does_not_end_the_reassembly() {
        let got = connect_through_fragments(|r| {
            r.send(&r.fragments[0]);
            r.send(b"xyz");
            r.send(&r.fragments[1]);
            r.send(&r.fragments[2]);
        });
        assert_eq!(got.unwrap(), 0xC0FFEE);
    }

    /// RFC 7296 §2.21.3 (and §3.14): a response that does not authenticate is
    /// discarded. An unfragmented forgery with the right header, sent ahead
    /// of the real fragments, used to be taken as the response.
    #[test]
    fn a_forged_whole_response_ahead_of_the_fragments_is_passed_over() {
        let got = connect_through_fragments(|r| {
            let cipher = r.sa.suite.sk_cipher();
            let wrong_e = vec![0u8; r.sa.keys.sk_er.len()];
            let wrong_a = vec![0u8; r.sa.keys.sk_ar.len()];
            r.send(&sk::build_encrypted(cipher, r.header, r.first_inner, &r.inner, &wrong_e, &wrong_a, &[3u8; 8]).unwrap());
            r.send_all();
        });
        assert_eq!(got.unwrap(), 0xC0FFEE);
    }

    /// `msg`, a message the gateway (the IKE SA's responder) built on `sa`,
    /// as `pieces` RFC 7383 fragments with IVs from `iv_base`.
    fn gateway_fragments(sa: &CompletedSaInit, msg: &[u8], pieces: usize, iv_base: u64) -> Vec<Vec<u8>> {
        let cipher = sa.suite.sk_cipher();
        let (first, inner) = open_encrypted(cipher, msg, &sa.keys.sk_er, &sa.keys.sk_ar).unwrap();
        let header = IkeHeader::parse(msg).unwrap();
        let per = inner.len().div_ceil(pieces).max(1);
        let fragments = fragment::build_fragments(cipher, &header, first, &inner, &sa.keys.sk_er, &sa.keys.sk_ar, iv_base, per).unwrap();
        assert_eq!(fragments.len(), pieces, "test setup: the message must split {pieces} ways");
        fragments
    }

    /// The gateway's `fragments`, a forged copy of the first one ahead.
    fn send_fragments_after_a_forgery(sock: &UdpSocket, to: SocketAddr, fragments: &[Vec<u8>]) {
        sock.send_to(&flip_last_byte(fragments[0].clone()), to).unwrap();
        for f in fragments {
            sock.send_to(f, to).unwrap();
        }
    }

    /// RFC 7383 §2.6: once IKE fragmentation is negotiated -- ryke always
    /// advertises it -- any later exchange of the IKE SA may come
    /// fragmented, not only `IKE_AUTH`. A DPD probe answered in fragments
    /// used to go unrecognised, three times over, and read as a dead peer.
    #[test]
    fn a_dpd_probe_answered_in_fragments_finds_the_peer_alive() {
        let bind = next_addr();
        let psk = b"shared-secret".to_vec();
        let gateway = thread::spawn({
            let psk = psk.clone();
            move || {
                let (sock, sa, from, _) = responder_through_auth_spis(bind, psk);
                let probe = recv_from_client(&sock);
                let mid = IkeHeader::parse(&probe).unwrap().message_id;
                let note = crate::ikev2::payload::Notify::status(40_000, vec![0x5a; 60]);
                let answer = build_informational(&sa, mid, true, &[(PayloadType::Notify, note.to_bytes())], &[4u8; 8]).unwrap();
                send_fragments_after_a_forgery(&sock, from, &gateway_fragments(&sa, &answer, 3, 100));
            }
        });
        thread::sleep(Duration::from_millis(50));
        let mut tunnel = connect_for_collision_test(bind, psk);
        let live = tunnel.liveness.probe(Duration::from_secs(1)).unwrap();
        gateway.join().unwrap();
        assert_eq!(live, Liveness::Alive);
    }

    /// RFC 7383 §2.6, for `CREATE_CHILD_SA`: a CHILD SA rekey answered in
    /// fragments used to fail as unanswered.
    #[test]
    fn a_child_rekey_answered_in_fragments_completes() {
        let bind = next_addr();
        let psk = b"shared-secret".to_vec();
        let gateway = thread::spawn({
            let psk = psk.clone();
            move || {
                let (sock, sa, from, _) = responder_through_auth_spis(bind, psk);
                let request = recv_from_client(&sock);
                let (answer, _) = gateway_answers_rekey(&sa, &request, &[0x77; 32]);
                send_fragments_after_a_forgery(&sock, from, &gateway_fragments(&sa, &answer, 4, 200));
                // The Delete of the replaced SA that follows.
                let delete = recv_from_client(&sock);
                sock.send_to(&informational_answer(&sa, &delete, &[RESPONDER_CHILD_SPI]), from).unwrap();
            }
        });
        thread::sleep(Duration::from_millis(50));
        let mut tunnel = connect_for_collision_test(bind, psk);
        let rekeyed = tunnel.liveness.rekey_child(Duration::from_secs(1)).unwrap();
        gateway.join().unwrap();
        assert_eq!(rekeyed.peer_spi, PEER_L_SPI);
    }

    /// RFC 7383 §2.6 and §2.6.1, a request from the gateway in fragments:
    /// it is answered once complete. Of a retransmission of it, fragment 1
    /// gets the same answer again and any other fragment is ignored. It
    /// used to be dropped unanswered.
    #[test]
    fn a_request_from_the_peer_in_fragments_is_answered_and_only_its_first_fragment_repeats_the_answer() {
        let bind = next_addr();
        let psk = b"shared-secret".to_vec();
        let gateway = thread::spawn({
            let psk = psk.clone();
            move || {
                let (sock, sa, from, _) = responder_through_auth_spis(bind, psk);
                let note = crate::ikev2::payload::Notify::status(40_000, vec![0x5a; 60]);
                let request = build_informational(&sa, 0, false, &[(PayloadType::Notify, note.to_bytes())], &[3u8; 8]).unwrap();
                let fragments = gateway_fragments(&sa, &request, 3, 300);
                send_fragments_after_a_forgery(&sock, from, &fragments);
                sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                let answer = recv_from_client(&sock);
                let answered =
                    open_informational(&sa, &answer).is_ok_and(|payloads| payloads.is_empty()) && IkeHeader::parse(&answer).unwrap().message_id == 0;
                sock.send_to(&fragments[1], from).unwrap();
                sock.send_to(&flip_last_byte(fragments[0].clone()), from).unwrap();
                let quiet_on_others = client_stays_quiet(&sock);
                sock.send_to(&fragments[0], from).unwrap();
                sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                let again = recv_from_client(&sock);
                (answered, quiet_on_others, again == answer)
            }
        });
        thread::sleep(Duration::from_millis(50));
        let mut tunnel = connect_for_collision_test(bind, psk);
        let live = tunnel.liveness.peek(Duration::from_secs(4)).unwrap();
        let (answered, quiet_on_others, answered_again) = gateway.join().unwrap();
        assert_eq!(live, Liveness::Alive);
        assert!(answered, "the reassembled request is answered, under its Message ID");
        assert!(quiet_on_others, "a fragment other than 1 of a request answered, or a forged fragment 1, is ignored");
        assert!(answered_again, "fragment 1 of a request answered gets the same answer again");
    }

    /// A Delete of the IKE SA that comes in fragments ends the tunnel, and
    /// fragment 1 of its retransmission still reads as that teardown.
    #[test]
    fn a_delete_of_the_ike_sa_in_fragments_tears_the_tunnel_down() {
        let bind = next_addr();
        let psk = b"shared-secret".to_vec();
        let gateway = thread::spawn({
            let psk = psk.clone();
            move || {
                let (sock, sa, from, _) = responder_through_auth_spis(bind, psk);
                let request = build_informational(&sa, 0, false, &[(PayloadType::Delete, Delete::ike_sa().to_bytes())], &[3u8; 8]).unwrap();
                let fragments = gateway_fragments(&sa, &request, 3, 400);
                send_fragments_after_a_forgery(&sock, from, &fragments);
                sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
                let answer = recv_from_client(&sock);
                let answered = IkeHeader::parse(&answer).unwrap().message_id == 0;
                sock.send_to(&fragments[0], from).unwrap();
                answered
            }
        });
        thread::sleep(Duration::from_millis(50));
        let mut tunnel = connect_for_collision_test(bind, psk);
        let first = tunnel.liveness.peek(Duration::from_secs(4)).unwrap();
        let again = tunnel.liveness.peek(Duration::from_secs(4)).unwrap();
        assert!(gateway.join().unwrap(), "the Delete is answered");
        assert_eq!((first, again), (Liveness::PeerTornDown, Liveness::PeerTornDown));
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

    /// The same handshake against an IPv6 responder: `sa_init_on_port` must bind
    /// its sockets on the IPv6 wildcard and resolve the local address from an
    /// IPv6 route, or every IPv6 gateway fails before sending a single packet
    /// (`EAFNOSUPPORT`).
    #[test]
    fn connect_direct_psk_against_an_ipv6_loopback_responder() {
        let Some(bind) = next_addr_v6() else { return };
        let psk = b"shared-secret".to_vec();
        let responder = thread::spawn({
            let psk = psk.clone();
            move || run_psk_responder(bind, psk)
        });
        thread::sleep(Duration::from_millis(50));

        let mut session = Ikev2Session::new(OsEntropy::new().unwrap());
        let cfg = AuthConfig::psk(Identification::fqdn("client.test"), psk);
        let tunnel = session
            .connect_direct_on_port(bind, &default_ike_offer(), &cfg, false, &default_esp_offer(), next_addr().port())
            .unwrap();
        assert_eq!(tunnel.peer_spi, 0xC0FFEE);
        assert!(tunnel.local_addr.is_ipv6() && tunnel.peer_addr.is_ipv6(), "outer addresses must be IPv6: {} -> {}", tunnel.local_addr, tunnel.peer_addr);
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
        let (resp, _peer_id, client_spi, _ic) =
            responder_process_auth(&sa, &buf[..n], &rcfg, 0xC0FFEE, &[9u8; 8], None).unwrap();
        sock.send_to(&resp, from).unwrap();

        let (n, from) = sock.recv_from(&mut buf).unwrap();
        // RFC 7296 §1.3.3: the REKEY_SA notify carries the SPI the initiator
        // expects on inbound ESP -- the one it put in its own SA payload at
        // IKE_AUTH -- which a responder such as strongSwan looks the old CHILD
        // SA up by (it answers CHILD_SA_NOT_FOUND for the other one).
        assert_eq!(rekey::rekey_sa_spi(&sa, &buf[..n]), Some(client_spi), "REKEY_SA must name the initiator's inbound SPI");
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

    /// A real full-tunnel teardown racing the client's own `rekey_child`: the
    /// gateway deletes the CHILD SA first (which is what starts a
    /// `rekey_child`/`create_child_primary` recreate through `child_exchange`
    /// in the worker's liveness check) and the IKE SA a moment later, which
    /// can arrive while `child_exchange` is still waiting for its own
    /// CREATE_CHILD_SA response. Confirmed live against a real FortiGate that
    /// this used to fail to parse as that response and error out generically,
    /// leaving the caller to retry the recreate forever against a peer with
    /// no IKE SA left to answer under -- this must surface as
    /// `IkeError::PeerTornDown` instead, immediately.
    #[test]
    fn rekey_child_reports_peer_torn_down_when_the_ike_sa_is_deleted_mid_exchange() {
        let bind = next_addr();
        let psk = b"shared-secret".to_vec();
        let responder = thread::spawn({
            let psk = psk.clone();
            move || {
                let (sock, sa, from) = responder_through_auth(bind, psk);
                let mut buf = [0u8; 4096];
                sock.recv_from(&mut buf).unwrap(); // the client's CREATE_CHILD_SA rekey request
                let delete = build_informational(&sa, 0, false, &[(PayloadType::Delete, Delete::ike_sa().to_bytes())], &[9u8; 8]).unwrap();
                sock.send_to(&delete, from).unwrap();
            }
        });
        thread::sleep(Duration::from_millis(50));

        let mut session = Ikev2Session::new(OsEntropy::new().unwrap());
        let cfg = AuthConfig::psk(Identification::fqdn("client.test"), psk);
        let mut tunnel = session
            .connect_direct_on_port(bind, &default_ike_offer(), &cfg, false, &default_esp_offer(), next_addr().port())
            .unwrap();
        let err = match tunnel.liveness.rekey_child(Duration::from_secs(5)) {
            Err(DriverError::Ike(e)) => e,
            other => panic!("expected an IKE error, got {:?}", other.map(|_| ())),
        };
        responder.join().unwrap();
        assert_eq!(err, IkeError::PeerTornDown);
    }

    /// The responder half of a handshake, shared by the IKE SA rekey tests:
    /// `IKE_SA_INIT` and `IKE_AUTH` answered, handing back the socket, the
    /// responder's IKE SA and the client's address.
    fn responder_through_auth(bind: SocketAddr, psk: Vec<u8>) -> (UdpSocket, CompletedSaInit, SocketAddr) {
        let (sock, sa, from, _client_spi) = responder_through_auth_spis(bind, psk);
        (sock, sa, from)
    }

    /// The responder's CHILD SA SPI in [`responder_through_auth_spis`]: what the client sends ESP to.
    const RESPONDER_CHILD_SPI: u32 = 0xC0FFEE;

    /// [`responder_through_auth`], also returning the client's own CHILD SA SPI
    /// (its inbound one) from `IKE_AUTH`.
    fn responder_through_auth_spis(bind: SocketAddr, psk: Vec<u8>) -> (UdpSocket, CompletedSaInit, SocketAddr, u32) {
        let sock = UdpSocket::bind(bind).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut buf = [0u8; 4096];
        let (n, from) = sock.recv_from(&mut buf).unwrap();
        let resp_secret = LocalSecret::generate(&mut OsEntropy::new().unwrap(), 32);
        let (response, sa) = match responder_respond_natt(&buf[..n], &resp_secret, bind, from, None).unwrap() {
            crate::ikev2::exchange::SaInitResult::Established { response, sa } => (response, sa),
            _ => panic!("expected Established"),
        };
        sock.send_to(&response, from).unwrap();
        let (n, from) = sock.recv_from(&mut buf).unwrap();
        let rcfg = AuthConfig::psk(Identification::fqdn("responder.test"), psk);
        let (resp, _peer_id, client_spi, _ic) = responder_process_auth(&sa, &buf[..n], &rcfg, RESPONDER_CHILD_SPI, &[9u8; 8], None).unwrap();
        sock.send_to(&resp, from).unwrap();
        (sock, sa, from, client_spi)
    }

    fn deletes_ike_sa(sa: &CompletedSaInit, msg: &[u8]) -> bool {
        open_informational(sa, msg)
            .ok()
            .and_then(|ps| ps.into_iter().find(|(t, _)| *t == PayloadType::Delete))
            .and_then(|(_, body)| Delete::parse(&body).ok())
            .is_some_and(|d| d.protocol_id == protocol_id::IKE)
    }

    /// What the IKE SA rekey the *client* starts looks like from the gateway:
    /// the rekey answered, the old IKE SA deleted under its own keys, and from
    /// then on everything -- a DPD probe, a CHILD SA rekey (keyed from the NEW
    /// `SK_d`) -- on the new SA, with Message IDs starting again at 0.
    #[test]
    fn rekey_ike_replaces_the_ike_sa_and_the_tunnel_carries_on_under_the_new_one() {
        use crate::esp::{next_header, EspSa};

        let bind = next_addr();
        let psk = b"shared-secret".to_vec();
        let responder = thread::spawn({
            let psk = psk.clone();
            move || {
                let (sock, sa, _from) = responder_through_auth(bind, psk);
                let mut buf = [0u8; 4096];
                let (n, from) = sock.recv_from(&mut buf).unwrap();
                let (resp, new_sa) =
                    ike_rekey::responder_process_ike_rekey(&sa, &buf[..n], 0xABCD_EF01_2345_6789, &[6u8; 32], &[0x77u8; 32], &[8u8; 8]).unwrap();
                sock.send_to(&resp, from).unwrap();

                // The old IKE SA is deleted with an INFORMATIONAL under its own keys.
                let (n, from) = sock.recv_from(&mut buf).unwrap();
                let deleted_old = deletes_ike_sa(&sa, &buf[..n]);
                let mid = IkeHeader::parse(&buf[..n]).unwrap().message_id;
                sock.send_to(&build_informational(&sa, mid, true, &[], &[1u8; 8]).unwrap(), from).unwrap();

                // Then a DPD probe under the new keys, Message ID 0.
                let (n, from) = sock.recv_from(&mut buf).unwrap();
                let probe_mid = IkeHeader::parse(&buf[..n]).unwrap().message_id;
                let probe_ok = open_informational(&new_sa, &buf[..n]).is_ok();
                sock.send_to(&build_informational(&new_sa, probe_mid, true, &[], &[2u8; 8]).unwrap(), from).unwrap();

                // And a CHILD SA rekey that only the new SK_d can derive.
                let (n, from) = sock.recv_from(&mut buf).unwrap();
                let (resp2, child) =
                    rekey::responder_process_rekey_with_pfs(&new_sa, &buf[..n], 0xFEED_FACE, &[0x78u8; 32], SkCipher::Aes256Gcm, None, &[7u8; 8], None)
                        .unwrap();
                sock.send_to(&resp2, from).unwrap();
                (deleted_old, probe_ok, probe_mid, child)
            }
        });
        thread::sleep(Duration::from_millis(50));

        let mut session = Ikev2Session::new(OsEntropy::new().unwrap());
        let cfg = AuthConfig::psk(Identification::fqdn("client.test"), psk);
        let mut tunnel = session
            .connect_direct_on_port(bind, &default_ike_offer(), &cfg, false, &default_esp_offer(), next_addr().port())
            .unwrap();
        assert_eq!(tunnel.liveness.rekey_ike(Duration::from_secs(5)).unwrap(), Liveness::Alive);
        assert_eq!(tunnel.liveness.probe(Duration::from_secs(2)).unwrap(), Liveness::Alive);
        let rekeyed = tunnel.liveness.rekey_child(Duration::from_secs(5)).unwrap();

        let (deleted_old, probe_ok, probe_mid, mut resp_child) = responder.join().unwrap();
        assert!(deleted_old, "the old IKE SA must be deleted under its own keys");
        assert!(probe_ok, "after the rekey the session must speak the new IKE SA's keys");
        assert_eq!(probe_mid, 0, "a rekeyed IKE SA starts its Message IDs again at 0");
        let mut client_out = EspSa::new_with_cipher(rekeyed.peer_spi, rekeyed.key_out.cipher, &rekeyed.key_out.enc, &rekeyed.key_out.integ).unwrap();
        let pkt = client_out.seal(b"after an ike sa rekey", next_header::IPV4).unwrap();
        assert_eq!(resp_child.inbound.open(&pkt).unwrap().0, b"after an ike sa rekey");
    }

    #[test]
    fn rekey_ike_refused_by_the_peer_is_an_error_and_leaves_the_ike_sa_alone() {
        let bind = next_addr();
        let psk = b"shared-secret".to_vec();
        let responder = thread::spawn({
            let psk = psk.clone();
            move || {
                let (sock, sa, _from) = responder_through_auth(bind, psk);
                let mut buf = [0u8; 4096];
                let (n, from) = sock.recv_from(&mut buf).unwrap();
                let mid = IkeHeader::parse(&buf[..n]).unwrap().message_id;
                sock.send_to(&rekey::build_child_refusal(&sa, mid, &[5u8; 8]).unwrap(), from).unwrap();
                // The IKE SA is still the old one: a probe under its keys is answered.
                let (n, from) = sock.recv_from(&mut buf).unwrap();
                let probe_mid = IkeHeader::parse(&buf[..n]).unwrap().message_id;
                let probe_ok = open_informational(&sa, &buf[..n]).is_ok();
                sock.send_to(&build_informational(&sa, probe_mid, true, &[], &[2u8; 8]).unwrap(), from).unwrap();
                probe_ok
            }
        });
        thread::sleep(Duration::from_millis(50));

        let mut session = Ikev2Session::new(OsEntropy::new().unwrap());
        let cfg = AuthConfig::psk(Identification::fqdn("client.test"), psk);
        let mut tunnel = session
            .connect_direct_on_port(bind, &default_ike_offer(), &cfg, false, &default_esp_offer(), next_addr().port())
            .unwrap();
        match tunnel.liveness.rekey_ike(Duration::from_secs(5)) {
            Err(DriverError::Ike(IkeError::PeerRejected { notify_type: t, .. })) => assert_eq!(t, notify_type::NO_ADDITIONAL_SAS),
            other => panic!("expected the refusal as PeerRejected, got {other:?}"),
        }
        assert_eq!(tunnel.liveness.probe(Duration::from_secs(2)).unwrap(), Liveness::Alive);
        assert!(responder.join().unwrap(), "a refused rekey must leave the session on the old IKE SA");
    }

    /// The mirror case, and the one a gateway's own timer produces: the *gateway*
    /// rekeys the IKE SA. It must be taken on (refusing it -- the old behaviour --
    /// ends with the gateway destroying the IKE SA at its hard limit), a
    /// retransmission of the request must get the same answer again (the first
    /// may have been lost), and the gateway's Delete of the old IKE SA, which
    /// arrives under the old keys, must not read as the tunnel being torn down.
    #[test]
    fn a_peer_started_ike_sa_rekey_is_taken_on_and_the_old_sas_delete_is_not_a_teardown() {
        let bind = next_addr();
        let psk = b"shared-secret".to_vec();
        let responder = thread::spawn({
            let psk = psk.clone();
            move || {
                let (sock, sa, from) = responder_through_auth(bind, psk);
                let mut buf = [0u8; 4096];
                let (ni, dh, new_spi_i) = (vec![0x55u8; 32], [3u8; 32], 0x1122_3344_5566_7788u64);
                let request = ike_rekey::build_ike_rekey_request(&sa, 0, new_spi_i, &ni, &dh, &[1u8; 8]).unwrap();
                sock.send_to(&request, from).unwrap();
                let (n, _) = sock.recv_from(&mut buf).unwrap();
                let first_answer = buf[..n].to_vec();
                let new_sa = ike_rekey::initiator_complete_ike_rekey(&sa, &ni, new_spi_i, &dh, &first_answer).unwrap();

                // The same request again -- as if the answer had been lost.
                sock.send_to(&request, from).unwrap();
                let (n, _) = sock.recv_from(&mut buf).unwrap();
                let resent_identically = buf[..n] == first_answer[..];

                // The gateway deletes the old IKE SA under the old keys...
                let delete = build_informational(&sa, 1, false, &[(PayloadType::Delete, Delete::ike_sa().to_bytes())], &[3u8; 8]).unwrap();
                sock.send_to(&delete, from).unwrap();
                let (n, _) = sock.recv_from(&mut buf).unwrap();
                let delete_acked = open_informational(&sa, &buf[..n]).is_ok() && IkeHeader::parse(&buf[..n]).unwrap().flags.response;

                // ...and keeps going on the new one.
                let dpd = build_informational(&new_sa, 0, false, &[], &[4u8; 8]).unwrap();
                sock.send_to(&dpd, from).unwrap();
                let (n, _) = sock.recv_from(&mut buf).unwrap();
                let dpd_acked = open_informational(&new_sa, &buf[..n]).is_ok();
                (resent_identically, delete_acked, dpd_acked)
            }
        });
        thread::sleep(Duration::from_millis(50));

        let mut session = Ikev2Session::new(OsEntropy::new().unwrap());
        let cfg = AuthConfig::psk(Identification::fqdn("client.test"), psk);
        let mut tunnel = session
            .connect_direct_on_port(bind, &default_ike_offer(), &cfg, false, &default_esp_offer(), next_addr().port())
            .unwrap();
        let live = tunnel.liveness.peek(Duration::from_millis(1500)).unwrap();
        let (resent_identically, delete_acked, dpd_acked) = responder.join().unwrap();
        assert_eq!(live, Liveness::Alive, "the old IKE SA's Delete after a rekey is routine, not a teardown");
        assert!(resent_identically, "a retransmitted rekey request must be answered with the same response");
        assert!(delete_acked, "the Delete of the old IKE SA must be acked under the old keys");
        assert!(dpd_acked, "the session must have moved to the new IKE SA's keys");
    }

    /// The whole of a gateway-started CHILD SA rekey, from a real handshake: the
    /// request is answered (and answered again, identically, if it is
    /// retransmitted -- the first answer may have been lost), the gateway then
    /// deletes the SA it replaced and that Delete is answered with ours -- the
    /// other direction's SPI of the pair, RFC 7296 §1.4.1 -- without reading as
    /// the tunnel going down; and the new SA is what a later Delete would hit.
    #[test]
    fn a_peer_started_child_rekey_runs_to_completion_including_the_old_sas_delete() {
        let bind = next_addr();
        let psk = b"shared-secret".to_vec();
        let responder = thread::spawn({
            let psk = psk.clone();
            move || {
                let (sock, sa, from, client_spi) = responder_through_auth_spis(bind, psk);
                let mut buf = [0u8; 4096];
                let (ni, dh, new_spi) = (vec![0x55u8; 32], [3u8; 32], 0xD00D_0001u32);
                // strongSwan's shape: PFS with a DH group, on the SA the handshake made.
                let request = rekey::build_child_request(
                    &sa,
                    0,
                    Some(RESPONDER_CHILD_SPI),
                    new_spi,
                    &ni,
                    SkCipher::Aes256Gcm,
                    Some((DhGroup::Modp2048, &dh)),
                    &TrafficSelectors::ipv4_full_tunnel(),
                    &[1u8; 8],
                )
                .unwrap();
                sock.send_to(&request, from).unwrap();
                let (n, _) = sock.recv_from(&mut buf).unwrap();
                let first_answer = buf[..n].to_vec();
                let (new_child, _) =
                    rekey::initiator_complete_child(&sa, &ni, new_spi, SkCipher::Aes256Gcm, Some((DhGroup::Modp2048, &dh)), &first_answer)
                        .expect("a rekey answer");

                // The same request again -- as if the answer had been lost.
                sock.send_to(&request, from).unwrap();
                let (n, _) = sock.recv_from(&mut buf).unwrap();
                let resent_identically = buf[..n] == first_answer[..];

                // The gateway deletes the SA it replaced: it names *its* inbound SPI of it.
                let delete = build_informational(&sa, 1, false, &[(PayloadType::Delete, Delete::esp(vec![RESPONDER_CHILD_SPI]).to_bytes())], &[3u8; 8]).unwrap();
                sock.send_to(&delete, from).unwrap();
                let (n, _) = sock.recv_from(&mut buf).unwrap();
                let answered_delete = open_informational(&sa, &buf[..n])
                    .unwrap()
                    .into_iter()
                    .find(|(t, _)| *t == PayloadType::Delete)
                    .map(|(_, body)| Delete::parse(&body).unwrap());
                (resent_identically, answered_delete, client_spi, new_child.outbound.spi())
            }
        });
        thread::sleep(Duration::from_millis(50));

        let mut session = Ikev2Session::new(OsEntropy::new().unwrap());
        let cfg = AuthConfig::psk(Identification::fqdn("client.test"), psk);
        let mut tunnel = session
            .connect_direct_on_port(bind, &default_ike_offer(), &cfg, false, &default_esp_offer(), next_addr().port())
            .unwrap();
        let live = tunnel.liveness.peek(Duration::from_millis(2000)).unwrap();
        let (resent_identically, answered_delete, old_local_spi, new_local_spi) = responder.join().unwrap();
        assert_eq!(live, Liveness::Alive, "the old SA's Delete after a rekey is routine, not a teardown");
        assert!(resent_identically, "a retransmitted rekey request must be answered with the same response");
        assert_eq!(
            answered_delete,
            Some(Delete::esp(vec![old_local_spi])),
            "the Delete of the replaced SA is answered with ours, naming our inbound SPI of it"
        );
        let taken = tunnel.liveness.take_peer_rekeys();
        assert_eq!(taken.len(), 1, "the retransmission is not a second rekey");
        assert_eq!((taken[0].kind, taken[0].child.local_spi, taken[0].child.peer_spi), (ChildKind::Primary, new_local_spi, 0xD00D_0001));
        // From now on the SA a Delete must name to end the tunnel is the new one.
        assert_eq!(tunnel.liveness.child_peer_spi, 0xD00D_0001);
    }

    /// The SPIs the scripted gateway of the collision tests below picks: for the
    /// SA its own rekey creates, and for the one it creates answering ours.
    const PEER_P_SPI: u32 = 0xD00D_0002;
    const PEER_L_SPI: u32 = 0xD00D_0003;

    /// The next datagram the client sends the scripted gateway.
    fn recv_from_client(sock: &UdpSocket) -> Vec<u8> {
        let mut buf = [0u8; 4096];
        let (n, _) = sock.recv_from(&mut buf).unwrap();
        buf[..n].to_vec()
    }

    /// The next *response* from the client, skipping retransmissions of a
    /// request of its own the gateway is holding back an answer to.
    fn recv_response_from_client(sock: &UdpSocket) -> Vec<u8> {
        loop {
            let msg = recv_from_client(sock);
            if IkeHeader::parse(&msg).unwrap().flags.response {
                return msg;
            }
        }
    }

    /// The gateway's own rekey of the CHILD SA it knows by `rekeyed` (its inbound SPI).
    fn gateway_child_rekey(sa: &CompletedSaInit, mid: u32, rekeyed: u32, new_spi: u32, ni: &[u8]) -> Vec<u8> {
        rekey::build_child_request(sa, mid, Some(rekeyed), new_spi, ni, SkCipher::Aes256Gcm, None, &TrafficSelectors::ipv4_full_tunnel(), &[1u8; 8])
            .unwrap()
    }

    /// The gateway's answer to the client's rekey `request`, with nonce `nr`.
    fn gateway_answers_rekey(sa: &CompletedSaInit, request: &[u8], nr: &[u8]) -> (Vec<u8>, crate::esp::ChildSa) {
        rekey::responder_process_rekey_with_pfs(sa, request, PEER_L_SPI, nr, SkCipher::Aes256Gcm, None, &[8u8; 8], None).unwrap()
    }

    fn esp_delete_request(sa: &CompletedSaInit, mid: u32, spi: u32) -> Vec<u8> {
        build_informational(sa, mid, false, &[(PayloadType::Delete, Delete::esp(vec![spi]).to_bytes())], &[3u8; 8]).unwrap()
    }

    /// The gateway's answer to the INFORMATIONAL `request`, carrying `deletes`.
    fn informational_answer(sa: &CompletedSaInit, request: &[u8], deletes: &[u32]) -> Vec<u8> {
        let mid = IkeHeader::parse(request).unwrap().message_id;
        let payloads: Vec<_> =
            if deletes.is_empty() { Vec::new() } else { vec![(PayloadType::Delete, Delete::esp(deletes.to_vec()).to_bytes())] };
        build_informational(sa, mid, true, &payloads, &[4u8; 8]).unwrap()
    }

    /// The Delete payload in a message from the client, if any.
    fn delete_in(sa: &CompletedSaInit, msg: &[u8]) -> Option<Delete> {
        open_informational(sa, msg)
            .unwrap()
            .into_iter()
            .find(|(t, _)| *t == PayloadType::Delete)
            .map(|(_, body)| Delete::parse(&body).unwrap())
    }

    /// The Notify a client's `CREATE_CHILD_SA` answer carries, if any.
    fn create_child_notify(sa: &CompletedSaInit, msg: &[u8]) -> Option<u16> {
        assert_eq!(IkeHeader::parse(msg).unwrap().exchange_type, ExchangeType::CreateChildSa, "a CREATE_CHILD_SA is answered as one");
        open_informational(sa, msg)
            .unwrap()
            .into_iter()
            .find(|(t, _)| *t == PayloadType::Notify)
            .map(|(_, body)| crate::ikev2::payload::Notify::parse(&body).unwrap().notify_type)
    }

    /// Nothing more from the client within a second.
    fn client_stays_quiet(sock: &UdpSocket) -> bool {
        sock.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        sock.recv_from(&mut [0u8; 4096]).is_err()
    }

    fn connect_for_collision_test(bind: SocketAddr, psk: Vec<u8>) -> ConnectedTunnel {
        let mut session = Ikev2Session::new(OsEntropy::new().unwrap());
        let cfg = AuthConfig::psk(Identification::fqdn("client.test"), psk);
        session.connect_direct_on_port(bind, &default_ike_offer(), &cfg, false, &default_esp_offer(), next_addr().port()).unwrap()
    }

    /// Both ends rekey the CHILD SA at once (RFC 7296 §2.8.1) and the lowest of
    /// the four nonces is in the gateway's exchange: its new SA is the
    /// redundant one, which the gateway deletes. Ours survives, and having
    /// initiated the survivor we delete the SA it replaced. The gateway's SA
    /// never reaches the caller, and its Delete is answered with ours. A
    /// gateway that deletes the replaced SA too, meanwhile, is answered
    /// without a Delete payload -- ours is on its way (§2.25.1).
    #[test]
    fn simultaneous_child_rekeys_keep_ours_when_the_gateways_holds_the_lowest_nonce() {
        let bind = next_addr();
        let psk = b"shared-secret".to_vec();
        let gateway = thread::spawn({
            let psk = psk.clone();
            move || {
                let (sock, sa, from, client_spi) = responder_through_auth_spis(bind, psk);
                let ours = recv_from_client(&sock);
                let ni = [0x00u8; 32]; // the lowest a nonce can be
                sock.send_to(&gateway_child_rekey(&sa, 0, RESPONDER_CHILD_SPI, PEER_P_SPI, &ni), from).unwrap();
                let answer = recv_from_client(&sock);
                let (theirs, _) =
                    rekey::initiator_complete_child(&sa, &ni, PEER_P_SPI, SkCipher::Aes256Gcm, None, &answer).expect("answered as usual");
                let (response, ours_sa) = gateway_answers_rekey(&sa, &ours, &[0x80u8; 32]);
                sock.send_to(&response, from).unwrap();

                let client_delete = recv_from_client(&sock); // answered once ours is
                sock.send_to(&esp_delete_request(&sa, 1, RESPONDER_CHILD_SPI), from).unwrap();
                let both_deleting = recv_response_from_client(&sock);
                sock.send_to(&informational_answer(&sa, &client_delete, &[]), from).unwrap();
                sock.send_to(&esp_delete_request(&sa, 2, PEER_P_SPI), from).unwrap();
                let answer = recv_from_client(&sock);
                (
                    client_spi,
                    delete_in(&sa, &client_delete),
                    delete_in(&sa, &both_deleting),
                    delete_in(&sa, &answer),
                    theirs.outbound.spi(),
                    ours_sa.outbound.spi(),
                )
            }
        });
        thread::sleep(Duration::from_millis(50));

        let mut tunnel = connect_for_collision_test(bind, psk);
        let rekeyed = tunnel.liveness.rekey_child(Duration::from_secs(5)).unwrap();
        let live = tunnel.liveness.peek(Duration::from_millis(1500)).unwrap();
        let (old_local_spi, client_deleted, both_deleting, answered, theirs_local_spi, ours_local_spi) = gateway.join().unwrap();
        assert_eq!((rekeyed.local_spi, rekeyed.peer_spi), (ours_local_spi, PEER_L_SPI), "ours survives");
        assert_eq!(client_deleted, Some(Delete::esp(vec![old_local_spi])), "the survivor's initiator deletes the SA it replaced");
        assert_eq!(both_deleting, None, "an SA both sides are deleting is answered without a Delete payload");
        assert_eq!(answered, Some(Delete::esp(vec![theirs_local_spi])), "the redundant SA's Delete is answered with ours");
        assert_eq!(live, Liveness::Alive);
        assert!(tunnel.liveness.take_peer_rekeys().is_empty(), "the redundant SA never reaches the caller");
        assert_eq!(tunnel.liveness.child_peer_spi, PEER_L_SPI);
    }

    /// The same collision with the lowest nonce in our own exchange: ours is
    /// the redundant SA and we delete it, the gateway's survives and is what
    /// `rekey_child` returns, and the gateway -- its initiator -- deletes the SA
    /// it replaced, a Delete answered with ours.
    #[test]
    fn simultaneous_child_rekeys_keep_the_gateways_when_ours_holds_the_lowest_nonce() {
        let bind = next_addr();
        let psk = b"shared-secret".to_vec();
        let gateway = thread::spawn({
            let psk = psk.clone();
            move || {
                let (sock, sa, from, client_spi) = responder_through_auth_spis(bind, psk);
                let ours = recv_from_client(&sock);
                let ni = [0xFFu8; 32];
                sock.send_to(&gateway_child_rekey(&sa, 0, RESPONDER_CHILD_SPI, PEER_P_SPI, &ni), from).unwrap();
                let answer = recv_from_client(&sock);
                let (theirs, _) =
                    rekey::initiator_complete_child(&sa, &ni, PEER_P_SPI, SkCipher::Aes256Gcm, None, &answer).expect("answered as usual");
                let (response, ours_sa) = gateway_answers_rekey(&sa, &ours, &[0x00u8; 32]);
                sock.send_to(&response, from).unwrap();

                let client_delete = recv_from_client(&sock);
                sock.send_to(&informational_answer(&sa, &client_delete, &[PEER_L_SPI]), from).unwrap();
                sock.send_to(&esp_delete_request(&sa, 1, RESPONDER_CHILD_SPI), from).unwrap();
                let answer = recv_from_client(&sock);
                (client_spi, delete_in(&sa, &client_delete), delete_in(&sa, &answer), theirs.outbound.spi(), ours_sa.outbound.spi())
            }
        });
        thread::sleep(Duration::from_millis(50));

        let mut tunnel = connect_for_collision_test(bind, psk);
        let rekeyed = tunnel.liveness.rekey_child(Duration::from_secs(5)).unwrap();
        let live = tunnel.liveness.peek(Duration::from_millis(1500)).unwrap();
        let (old_local_spi, client_deleted, answered, theirs_local_spi, ours_local_spi) = gateway.join().unwrap();
        assert_eq!((rekeyed.local_spi, rekeyed.peer_spi), (theirs_local_spi, PEER_P_SPI), "the gateway's SA survives");
        assert_eq!(client_deleted, Some(Delete::esp(vec![ours_local_spi])), "we delete our redundant SA, not the one it replaced");
        assert_eq!(answered, Some(Delete::esp(vec![old_local_spi])), "the gateway's Delete of the replaced SA is answered with ours");
        assert_eq!(live, Liveness::Alive);
        assert!(tunnel.liveness.take_peer_rekeys().is_empty(), "the survivor reaches the caller once, from rekey_child");
        assert_eq!(tunnel.liveness.child_peer_spi, PEER_P_SPI);
    }

    /// RFC 7296 §2.8.1's second sequence: our rekey request only reaches the
    /// gateway after its own rekey of the same SA is complete -- the replaced
    /// SA deleted and all -- so it answers `CHILD_SA_NOT_FOUND`. Having
    /// answered the gateway's rekey, we already know it collided: the error is
    /// ignored and the gateway's SA is the rekey's result.
    #[test]
    fn a_crossed_rekey_answered_child_sa_not_found_keeps_the_gateways_sa() {
        let bind = next_addr();
        let psk = b"shared-secret".to_vec();
        let gateway = thread::spawn({
            let psk = psk.clone();
            move || {
                let (sock, sa, from, client_spi) = responder_through_auth_spis(bind, psk);
                let ours = recv_from_client(&sock); // held back, as if delayed
                let ni = [0x55u8; 32];
                sock.send_to(&gateway_child_rekey(&sa, 0, RESPONDER_CHILD_SPI, PEER_P_SPI, &ni), from).unwrap();
                let answer = recv_from_client(&sock);
                let (theirs, _) =
                    rekey::initiator_complete_child(&sa, &ni, PEER_P_SPI, SkCipher::Aes256Gcm, None, &answer).expect("answered as usual");
                sock.send_to(&esp_delete_request(&sa, 1, RESPONDER_CHILD_SPI), from).unwrap();
                let answer = recv_from_client(&sock);
                let mid = IkeHeader::parse(&ours).unwrap().message_id;
                sock.send_to(&rekey::build_child_error(&sa, mid, notify_type::CHILD_SA_NOT_FOUND, &[5u8; 8]).unwrap(), from).unwrap();
                (client_spi, delete_in(&sa, &answer), theirs.outbound.spi(), client_stays_quiet(&sock))
            }
        });
        thread::sleep(Duration::from_millis(50));

        let mut tunnel = connect_for_collision_test(bind, psk);
        let rekeyed = tunnel.liveness.rekey_child(Duration::from_secs(5)).expect("the collision makes the error meaningless");
        let (old_local_spi, answered, theirs_local_spi, quiet) = gateway.join().unwrap();
        assert_eq!((rekeyed.local_spi, rekeyed.peer_spi), (theirs_local_spi, PEER_P_SPI));
        assert_eq!(answered, Some(Delete::esp(vec![old_local_spi])));
        assert!(quiet, "nothing is left for us to delete");
        assert!(tunnel.liveness.take_peer_rekeys().is_empty(), "the gateway's SA reaches the caller once, from rekey_child");
        assert_eq!(tunnel.liveness.child_peer_spi, PEER_P_SPI);
    }

    /// RFC 7296 §2.25.1: the gateway deleting the CHILD SA we are rekeying is
    /// answered as usual, with our Delete for it. It is not the tunnel going
    /// down while the rekey is in flight: the rekey stands, and the replaced SA
    /// being gone already, we send no Delete of our own for it.
    #[test]
    fn the_gateway_deleting_the_child_sa_we_are_rekeying_is_answered_and_the_rekey_stands() {
        let bind = next_addr();
        let psk = b"shared-secret".to_vec();
        let gateway = thread::spawn({
            let psk = psk.clone();
            move || {
                let (sock, sa, from, client_spi) = responder_through_auth_spis(bind, psk);
                let ours = recv_from_client(&sock);
                sock.send_to(&esp_delete_request(&sa, 0, RESPONDER_CHILD_SPI), from).unwrap();
                let answer = recv_from_client(&sock);
                let (response, ours_sa) = gateway_answers_rekey(&sa, &ours, &[0x80u8; 32]);
                sock.send_to(&response, from).unwrap();
                (client_spi, delete_in(&sa, &answer), ours_sa.outbound.spi(), client_stays_quiet(&sock))
            }
        });
        thread::sleep(Duration::from_millis(50));

        let mut tunnel = connect_for_collision_test(bind, psk);
        let rekeyed = tunnel.liveness.rekey_child(Duration::from_secs(5)).expect("the rekey stands");
        let (old_local_spi, answered, ours_local_spi, quiet) = gateway.join().unwrap();
        assert_eq!((rekeyed.local_spi, rekeyed.peer_spi), (ours_local_spi, PEER_L_SPI));
        assert_eq!(answered, Some(Delete::esp(vec![old_local_spi])), "answered as usual, with our Delete for it");
        assert!(quiet, "the replaced SA is gone already");
        assert!(tunnel.liveness.take_peer_deleted_children().is_empty(), "nothing to renegotiate");
        assert_eq!(tunnel.liveness.child_peer_spi, PEER_L_SPI);
    }

    /// ...and when the gateway then refuses the rekey, the tunnel's only CHILD
    /// SA is gone: the tunnel is down, as that Delete would have made it outside
    /// the exchange.
    #[test]
    fn the_gateway_deleting_the_only_child_sa_we_are_rekeying_then_refusing_the_rekey_is_a_teardown() {
        let bind = next_addr();
        let psk = b"shared-secret".to_vec();
        let gateway = thread::spawn({
            let psk = psk.clone();
            move || {
                let (sock, sa, from, client_spi) = responder_through_auth_spis(bind, psk);
                let ours = recv_from_client(&sock);
                sock.send_to(&esp_delete_request(&sa, 0, RESPONDER_CHILD_SPI), from).unwrap();
                let answer = recv_from_client(&sock);
                let mid = IkeHeader::parse(&ours).unwrap().message_id;
                sock.send_to(&rekey::build_child_error(&sa, mid, notify_type::CHILD_SA_NOT_FOUND, &[5u8; 8]).unwrap(), from).unwrap();
                (client_spi, delete_in(&sa, &answer))
            }
        });
        thread::sleep(Duration::from_millis(50));

        let mut tunnel = connect_for_collision_test(bind, psk);
        let err = match tunnel.liveness.rekey_child(Duration::from_secs(5)) {
            Err(DriverError::Ike(e)) => e,
            other => panic!("expected an IKE error, got {:?}", other.map(|_| ())),
        };
        let (old_local_spi, answered) = gateway.join().unwrap();
        assert_eq!(answered, Some(Delete::esp(vec![old_local_spi])));
        assert_eq!(err, IkeError::PeerTornDown);
    }

    /// RFC 7296 §2.25.1, the SA we are deleting after a rekey: the gateway's
    /// rekey of it is refused with `TEMPORARY_FAILURE`, and its own Delete of
    /// it is answered without a Delete payload (ours is on its way) -- neither
    /// touching the SA that replaced it.
    #[test]
    fn the_gateway_rekeying_or_deleting_the_child_sa_we_are_deleting_collides_cleanly() {
        let bind = next_addr();
        let psk = b"shared-secret".to_vec();
        let gateway = thread::spawn({
            let psk = psk.clone();
            move || {
                let (sock, sa, from, client_spi) = responder_through_auth_spis(bind, psk);
                let ours = recv_from_client(&sock);
                let (response, _) = gateway_answers_rekey(&sa, &ours, &[0x80u8; 32]);
                sock.send_to(&response, from).unwrap();
                let client_delete = recv_from_client(&sock); // answered only at the end
                sock.send_to(&gateway_child_rekey(&sa, 0, RESPONDER_CHILD_SPI, PEER_P_SPI, &[0x55u8; 32]), from).unwrap();
                let refusal = recv_response_from_client(&sock);
                sock.send_to(&esp_delete_request(&sa, 1, RESPONDER_CHILD_SPI), from).unwrap();
                let answer = recv_response_from_client(&sock);
                sock.send_to(&informational_answer(&sa, &client_delete, &[]), from).unwrap();
                (client_spi, delete_in(&sa, &client_delete), create_child_notify(&sa, &refusal), delete_in(&sa, &answer))
            }
        });
        thread::sleep(Duration::from_millis(50));

        let mut tunnel = connect_for_collision_test(bind, psk);
        let rekeyed = tunnel.liveness.rekey_child(Duration::from_secs(5)).unwrap();
        let (old_local_spi, client_deleted, refused_with, answered) = gateway.join().unwrap();
        assert_eq!(client_deleted, Some(Delete::esp(vec![old_local_spi])));
        assert_eq!(refused_with, Some(notify_type::TEMPORARY_FAILURE), "a rekey of an SA being deleted waits");
        assert_eq!(answered, None, "a Delete of an SA both sides are deleting is answered without one");
        assert!(tunnel.liveness.take_peer_rekeys().is_empty());
        assert!(tunnel.liveness.take_peer_deleted_children().is_empty());
        assert_eq!((tunnel.liveness.child_local_spi, tunnel.liveness.child_peer_spi), (rekeyed.local_spi, PEER_L_SPI));
    }

    /// RFC 7296 §2.25.1: a gateway's IKE SA rekey arriving while we rekey a
    /// CHILD SA, or while we delete the one it replaced, is refused with
    /// `TEMPORARY_FAILURE` -- the gateway retries it later -- and the session
    /// stays on the IKE SA it had.
    #[test]
    fn an_ike_sa_rekey_colliding_with_a_child_sa_exchange_of_ours_is_refused_temporary_failure() {
        let bind = next_addr();
        let psk = b"shared-secret".to_vec();
        let gateway = thread::spawn({
            let psk = psk.clone();
            move || {
                let (sock, sa, from, _client_spi) = responder_through_auth_spis(bind, psk);
                let ours = recv_from_client(&sock);
                sock.send_to(&gateway_ike_rekey(&sa, 0, &[0x55u8; 32]), from).unwrap();
                let while_rekeying = recv_response_from_client(&sock);
                let (response, _) = gateway_answers_rekey(&sa, &ours, &[0x80u8; 32]);
                sock.send_to(&response, from).unwrap();
                let client_delete = recv_from_client(&sock);
                sock.send_to(&gateway_ike_rekey(&sa, 1, &[0x55u8; 32]), from).unwrap();
                let while_deleting = recv_response_from_client(&sock);
                sock.send_to(&informational_answer(&sa, &client_delete, &[RESPONDER_CHILD_SPI]), from).unwrap();

                // Still the same IKE SA: a DPD probe under its keys is answered.
                let probe = recv_from_client(&sock);
                let probe_ok = open_informational(&sa, &probe).is_ok();
                sock.send_to(&informational_answer(&sa, &probe, &[]), from).unwrap();
                (create_child_notify(&sa, &while_rekeying), create_child_notify(&sa, &while_deleting), probe_ok)
            }
        });
        thread::sleep(Duration::from_millis(50));

        let mut tunnel = connect_for_collision_test(bind, psk);
        tunnel.liveness.rekey_child(Duration::from_secs(5)).unwrap();
        assert_eq!(tunnel.liveness.probe(Duration::from_secs(2)).unwrap(), Liveness::Alive);
        let (while_rekeying, while_deleting, probe_ok) = gateway.join().unwrap();
        assert_eq!(while_rekeying, Some(notify_type::TEMPORARY_FAILURE));
        assert_eq!(while_deleting, Some(notify_type::TEMPORARY_FAILURE));
        assert!(probe_ok, "the refused IKE SA rekey left the IKE SA as it was");
    }

    /// RFC 7296 §2.1: a CHILD SA rekey whose request is lost, and then whose
    /// response is, is sent again, the same bytes each time. The gateway
    /// answers the retransmission with the answer it already gave, and that
    /// completes the rekey: one new SA, the one the gateway made.
    #[test]
    fn a_child_sa_rekey_whose_request_then_response_is_lost_is_retransmitted_until_answered() {
        let bind = next_addr();
        let psk = b"shared-secret".to_vec();
        let gateway = thread::spawn({
            let psk = psk.clone();
            move || {
                let (sock, sa, from, client_spi) = responder_through_auth_spis(bind, psk);
                let lost = recv_from_client(&sock); // never reaches the gateway
                let answered = recv_from_client(&sock);
                let (response, child) = gateway_answers_rekey(&sa, &answered, &[0x80u8; 32]); // never reaches the client
                let again = recv_from_client(&sock);
                sock.send_to(&response, from).unwrap(); // the same answer, resent
                let client_delete = recv_from_client(&sock);
                sock.send_to(&informational_answer(&sa, &client_delete, &[RESPONDER_CHILD_SPI]), from).unwrap();
                (lost, answered, again, client_spi, delete_in(&sa, &client_delete), child.outbound.spi())
            }
        });
        thread::sleep(Duration::from_millis(50));

        let mut tunnel = connect_for_collision_test(bind, psk);
        let rekeyed = tunnel.liveness.rekey_child(Duration::from_millis(300)).expect("answered at the third attempt");
        let (lost, answered, again, old_local_spi, client_deleted, gateway_made) = gateway.join().unwrap();
        assert_eq!(lost, answered, "a retransmission is the same bytes");
        assert_eq!(answered, again, "a retransmission is the same bytes");
        assert_eq!((rekeyed.local_spi, rekeyed.peer_spi), (gateway_made, PEER_L_SPI), "the SA the gateway made");
        assert_eq!(client_deleted, Some(Delete::esp(vec![old_local_spi])), "the rekey is done as usual");
        assert_eq!(tunnel.liveness.child_peer_spi, PEER_L_SPI);
    }

    /// ...and one never answered fails after three attempts, all the same
    /// bytes, with a timeout: the CHILD SA stays the one it was, and nothing
    /// is sent to delete it.
    #[test]
    fn a_child_sa_rekey_never_answered_fails_after_three_attempts_and_keeps_the_child_sa() {
        let bind = next_addr();
        let psk = b"shared-secret".to_vec();
        let gateway = thread::spawn({
            let psk = psk.clone();
            move || {
                let (sock, _sa, _from, client_spi) = responder_through_auth_spis(bind, psk);
                let sent: Vec<Vec<u8>> = (0..3).map(|_| recv_from_client(&sock)).collect();
                (sent, client_spi, client_stays_quiet(&sock))
            }
        });
        thread::sleep(Duration::from_millis(50));

        let mut tunnel = connect_for_collision_test(bind, psk);
        let err = tunnel.liveness.rekey_child(Duration::from_millis(300)).map(|_| ()).expect_err("never answered");
        let (sent, old_local_spi, quiet) = gateway.join().unwrap();
        assert!(matches!(&err, DriverError::Io(e) if e.kind() == io::ErrorKind::TimedOut), "{err}");
        assert!(sent.iter().all(|m| *m == sent[0]), "a retransmission is the same bytes");
        assert!(quiet, "three attempts, and no Delete");
        assert_eq!((tunnel.liveness.child_local_spi, tunnel.liveness.child_peer_spi), (old_local_spi, RESPONDER_CHILD_SPI));
    }

    /// RFC 7296 §2.2: Message IDs never wrap. Once an IKE SA's have run out, a
    /// probe or a CHILD SA exchange fails without being sent, and the IDs
    /// kept back carry the rekey of the IKE SA and the Delete of the one it
    /// replaced. The new IKE SA starts again at 0.
    #[test]
    fn an_ike_sa_out_of_message_ids_sends_only_its_rekey_and_starts_over() {
        let last = u32::MAX - MESSAGE_IDS_KEPT_FOR_ENDING - 1;
        let bind = next_addr();
        let psk = b"shared-secret".to_vec();
        let gateway = thread::spawn({
            let psk = psk.clone();
            move || {
                let (sock, sa, from) = responder_through_auth(bind, psk);
                let probe = recv_from_client(&sock);
                sock.send_to(&informational_answer(&sa, &probe, &[]), from).unwrap();
                let rekey = recv_from_client(&sock);
                let (answer, new_sa) = gateway_answers_ike_rekey(&sa, &rekey, &[0x77u8; 32]);
                sock.send_to(&answer, from).unwrap();
                let delete = recv_from_client(&sock);
                sock.send_to(&informational_answer(&sa, &delete, &[]), from).unwrap();
                let probe_after = recv_from_client(&sock);
                let on_new_sa = open_informational(&new_sa, &probe_after).is_ok();
                sock.send_to(&informational_answer(&new_sa, &probe_after, &[]), from).unwrap();
                let mids: Vec<u32> = [&probe, &rekey, &delete, &probe_after].iter().map(|m| IkeHeader::parse(m).unwrap().message_id).collect();
                (mids, deletes_ike_sa(&sa, &delete), on_new_sa)
            }
        });
        thread::sleep(Duration::from_millis(50));

        let mut tunnel = connect_for_collision_test(bind, psk);
        tunnel.liveness.next_message_id = last;
        assert!(!tunnel.liveness.message_ids_exhausted());
        assert_eq!(tunnel.liveness.probe(Duration::from_secs(2)).unwrap(), Liveness::Alive, "the last ordinary Message ID");
        assert!(tunnel.liveness.message_ids_exhausted());
        let exhausted = |r: Result<(), DriverError>| matches!(r, Err(DriverError::Ike(IkeError::MessageIdsExhausted)));
        assert!(exhausted(tunnel.liveness.probe(Duration::from_secs(2)).map(|_| ())));
        assert!(exhausted(tunnel.liveness.rekey_child(Duration::from_secs(2)).map(|_| ())));
        assert!(exhausted(tunnel.liveness.create_child_ipv6(Duration::from_secs(2)).map(|_| ())));
        assert_eq!(tunnel.liveness.rekey_ike(Duration::from_secs(2)).unwrap(), Liveness::Alive);
        assert!(!tunnel.liveness.message_ids_exhausted());
        assert_eq!(tunnel.liveness.probe(Duration::from_secs(2)).unwrap(), Liveness::Alive);
        let (mids, deleted_old, on_new_sa) = gateway.join().unwrap();
        assert_eq!(mids, vec![last, last + 1, last + 2, 0], "nothing sent while out of them; the rekey and the Delete on the ones kept back");
        assert!(deleted_old, "the IKE SA the rekey replaced is deleted");
        assert!(on_new_sa);
    }

    /// ...and with none left at all, even a close or rekey of the IKE SA fails
    /// without sending anything: the counter never goes back to 0.
    #[test]
    fn message_ids_never_wrap() {
        let mut session = recv_test_session(None);
        let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
        peer.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        session.dest = peer.local_addr().unwrap();
        session.next_message_id = u32::MAX - 1;

        session.close().unwrap(); // on the last one there is, unanswered
        let mut buf = [0u8; 4096];
        let (n, _) = peer.recv_from(&mut buf).unwrap();
        assert_eq!(IkeHeader::parse(&buf[..n]).unwrap().message_id, u32::MAX - 1);
        while peer.recv_from(&mut buf).is_ok() {} // its retransmissions

        assert!(matches!(session.close(), Err(DriverError::Ike(IkeError::MessageIdsExhausted))));
        assert!(matches!(session.rekey_ike(Duration::from_millis(100)), Err(DriverError::Ike(IkeError::MessageIdsExhausted))));
        assert!(peer.recv_from(&mut buf).is_err(), "nothing sent");
        assert_eq!(session.next_message_id, u32::MAX);
    }

    /// The IKE SPI and DH secret of the scripted gateway's own IKE SA rekeys.
    const GATEWAY_IKE_SPI: u64 = 0x1122_3344_5566_7788;
    const GATEWAY_DH: [u8; 32] = [3u8; 32];

    /// The gateway's own rekey of the IKE SA `sa`, with nonce `ni`.
    fn gateway_ike_rekey(sa: &CompletedSaInit, mid: u32, ni: &[u8]) -> Vec<u8> {
        ike_rekey::build_ike_rekey_request(sa, mid, GATEWAY_IKE_SPI, ni, &GATEWAY_DH, &[1u8; 8]).unwrap()
    }

    /// The IKE SA the gateway's own rekey (nonce `ni`) made, from the client's `answer`.
    fn gateway_ike_rekey_done(sa: &CompletedSaInit, ni: &[u8], answer: &[u8]) -> CompletedSaInit {
        ike_rekey::initiator_complete_ike_rekey(sa, ni, GATEWAY_IKE_SPI, &GATEWAY_DH, answer).expect("answered as usual")
    }

    /// The gateway's answer to the client's IKE SA rekey `request`, with nonce
    /// `nr`, and the IKE SA it makes.
    fn gateway_answers_ike_rekey(sa: &CompletedSaInit, request: &[u8], nr: &[u8]) -> (Vec<u8>, CompletedSaInit) {
        ike_rekey::responder_process_ike_rekey(sa, request, 0xABCD_EF01_2345_6789, &[6u8; 32], nr, &[8u8; 8]).unwrap()
    }

    fn ike_delete_request(sa: &CompletedSaInit, mid: u32) -> Vec<u8> {
        build_informational(sa, mid, false, &[(PayloadType::Delete, Delete::ike_sa().to_bytes())], &[3u8; 8]).unwrap()
    }

    /// The next message from the client on the IKE SA `sa`, skipping
    /// retransmissions of its requests on another one.
    fn recv_on(sock: &UdpSocket, sa: &CompletedSaInit) -> Vec<u8> {
        loop {
            let msg = recv_from_client(sock);
            if open_informational(sa, &msg).is_ok() {
                return msg;
            }
        }
    }

    /// Both ends rekey the IKE SA at once (RFC 7296 §2.8.2) and the lowest of
    /// the four nonces is in the gateway's exchange: its new IKE SA is the
    /// redundant one, which the gateway deletes, on it. Ours survives, and
    /// having made it we delete the old IKE SA. A retransmission of the
    /// gateway's rekey still gets the same answer, although the session has
    /// not moved to its SA.
    #[test]
    fn simultaneous_ike_rekeys_keep_ours_when_the_gateways_holds_the_lowest_nonce() {
        let bind = next_addr();
        let psk = b"shared-secret".to_vec();
        let gateway = thread::spawn({
            let psk = psk.clone();
            move || {
                let (sock, sa, from) = responder_through_auth(bind, psk);
                let ours = recv_from_client(&sock);
                let ni = [0x00u8; 32]; // the lowest a nonce can be
                let request = gateway_ike_rekey(&sa, 0, &ni);
                sock.send_to(&request, from).unwrap();
                let answer = recv_from_client(&sock);
                let theirs = gateway_ike_rekey_done(&sa, &ni, &answer);
                sock.send_to(&request, from).unwrap();
                let resent_identically = recv_from_client(&sock) == answer;
                let (response, ours_sa) = gateway_answers_ike_rekey(&sa, &ours, &[0x80u8; 32]);
                sock.send_to(&response, from).unwrap();

                let client_delete = recv_from_client(&sock);
                let old_deleted = deletes_ike_sa(&sa, &client_delete);
                sock.send_to(&ike_delete_request(&theirs, 0), from).unwrap();
                let theirs_delete_answer = recv_response_from_client(&sock);
                let theirs_delete_acked = open_informational(&theirs, &theirs_delete_answer).is_ok();
                sock.send_to(&informational_answer(&sa, &client_delete, &[]), from).unwrap();

                let probe = recv_on(&sock, &ours_sa);
                sock.send_to(&informational_answer(&ours_sa, &probe, &[]), from).unwrap();
                (resent_identically, old_deleted, theirs_delete_acked, IkeHeader::parse(&probe).unwrap().message_id)
            }
        });
        thread::sleep(Duration::from_millis(50));

        let mut tunnel = connect_for_collision_test(bind, psk);
        assert_eq!(tunnel.liveness.rekey_ike(Duration::from_secs(5)).unwrap(), Liveness::Alive);
        assert_eq!(tunnel.liveness.probe(Duration::from_secs(2)).unwrap(), Liveness::Alive);
        let (resent_identically, old_deleted, theirs_delete_acked, probe_mid) = gateway.join().unwrap();
        assert!(resent_identically, "a retransmitted IKE SA rekey must be answered with the same response");
        assert!(old_deleted, "the survivor's maker deletes the old IKE SA, on it");
        assert!(theirs_delete_acked, "the gateway's Delete of its redundant IKE SA is answered on that SA");
        assert_eq!(probe_mid, 0, "the session is on our new IKE SA, Message IDs from 0");
    }

    /// Both ends rekey the IKE SA at once and the lowest nonce is in our
    /// exchange: our new IKE SA is the redundant one, and we delete it, on
    /// it. The gateway's survives, and the gateway deletes the old IKE SA --
    /// routine, answered on that SA.
    #[test]
    fn simultaneous_ike_rekeys_keep_the_gateways_when_ours_holds_the_lowest_nonce() {
        let bind = next_addr();
        let psk = b"shared-secret".to_vec();
        let gateway = thread::spawn({
            let psk = psk.clone();
            move || {
                let (sock, sa, from) = responder_through_auth(bind, psk);
                let ours = recv_from_client(&sock);
                let ni = [0xFFu8; 32];
                sock.send_to(&gateway_ike_rekey(&sa, 0, &ni), from).unwrap();
                let answer = recv_from_client(&sock);
                let theirs = gateway_ike_rekey_done(&sa, &ni, &answer);
                let (response, ours_sa) = gateway_answers_ike_rekey(&sa, &ours, &[0x00u8; 32]);
                sock.send_to(&response, from).unwrap();

                let client_delete = recv_from_client(&sock);
                let redundant_deleted = deletes_ike_sa(&ours_sa, &client_delete);
                sock.send_to(&ike_delete_request(&sa, 1), from).unwrap();
                let old_delete_answer = recv_on(&sock, &sa);
                let old_delete_acked = IkeHeader::parse(&old_delete_answer).unwrap().flags.response;
                sock.send_to(&informational_answer(&ours_sa, &client_delete, &[]), from).unwrap();

                let probe = recv_on(&sock, &theirs);
                sock.send_to(&informational_answer(&theirs, &probe, &[]), from).unwrap();
                (redundant_deleted, old_delete_acked, IkeHeader::parse(&probe).unwrap().message_id)
            }
        });
        thread::sleep(Duration::from_millis(50));

        let mut tunnel = connect_for_collision_test(bind, psk);
        assert_eq!(tunnel.liveness.rekey_ike(Duration::from_secs(5)).unwrap(), Liveness::Alive);
        assert_eq!(tunnel.liveness.probe(Duration::from_secs(2)).unwrap(), Liveness::Alive);
        let (redundant_deleted, old_delete_acked, probe_mid) = gateway.join().unwrap();
        assert!(redundant_deleted, "our redundant IKE SA is deleted by us, on it");
        assert!(old_delete_acked, "the gateway's Delete of the old IKE SA is answered on it");
        assert_eq!(probe_mid, 0, "the session is on the gateway's new IKE SA, Message IDs from 0");
    }

    /// RFC 7296 §2.8.2's special case: the gateway finishes its own rekey
    /// (which we answered) without ever seeing ours, and deletes the old IKE
    /// SA. That Delete is answered as usual and is no teardown: we drop our
    /// rekey -- no more retransmissions of it -- and carry on under the
    /// gateway's new IKE SA.
    #[test]
    fn the_gateway_deleting_the_ike_sa_after_its_own_crossed_rekey_drops_ours() {
        let bind = next_addr();
        let psk = b"shared-secret".to_vec();
        let gateway = thread::spawn({
            let psk = psk.clone();
            move || {
                let (sock, sa, from) = responder_through_auth(bind, psk);
                let _ours = recv_from_client(&sock); // never answered
                let ni = [0x55u8; 32];
                sock.send_to(&gateway_ike_rekey(&sa, 0, &ni), from).unwrap();
                let answer = recv_from_client(&sock);
                let theirs = gateway_ike_rekey_done(&sa, &ni, &answer);
                sock.send_to(&ike_delete_request(&sa, 1), from).unwrap();
                let delete_answer = recv_response_from_client(&sock);
                let delete_acked = open_informational(&sa, &delete_answer).is_ok();

                let next = recv_from_client(&sock);
                let next_on_theirs = open_informational(&theirs, &next).is_ok();
                if next_on_theirs {
                    sock.send_to(&informational_answer(&theirs, &next, &[]), from).unwrap();
                }
                (delete_acked, next_on_theirs)
            }
        });
        thread::sleep(Duration::from_millis(50));

        let mut tunnel = connect_for_collision_test(bind, psk);
        assert_eq!(tunnel.liveness.rekey_ike(Duration::from_secs(5)).unwrap(), Liveness::Alive);
        assert_eq!(tunnel.liveness.probe(Duration::from_secs(2)).unwrap(), Liveness::Alive);
        let (delete_acked, next_on_theirs) = gateway.join().unwrap();
        assert!(delete_acked, "the Delete of the old IKE SA is answered on it");
        assert!(next_on_theirs, "our rekey is dropped, not retransmitted, and the session is on the gateway's IKE SA");
    }

    /// The same collision from the other side: the gateway finished its rekey
    /// first and refuses ours with `TEMPORARY_FAILURE` -- the IKE SA it is
    /// about is on its way out (RFC 7296 §2.8.2). The gateway's IKE SA
    /// stands. A second rekey from the gateway before ours is settled is
    /// refused with `TEMPORARY_FAILURE` too.
    #[test]
    fn a_crossed_ike_rekey_refused_temporary_failure_moves_to_the_gateways_ike_sa() {
        let bind = next_addr();
        let psk = b"shared-secret".to_vec();
        let gateway = thread::spawn({
            let psk = psk.clone();
            move || {
                let (sock, sa, from) = responder_through_auth(bind, psk);
                let ours = recv_from_client(&sock);
                let ni = [0x55u8; 32];
                sock.send_to(&gateway_ike_rekey(&sa, 0, &ni), from).unwrap();
                let answer = recv_from_client(&sock);
                let theirs = gateway_ike_rekey_done(&sa, &ni, &answer);
                sock.send_to(&gateway_ike_rekey(&sa, 1, &[0x66u8; 32]), from).unwrap();
                let second = create_child_notify(&sa, &recv_response_from_client(&sock));
                let mid = IkeHeader::parse(&ours).unwrap().message_id;
                sock.send_to(&rekey::build_child_error(&sa, mid, notify_type::TEMPORARY_FAILURE, &[5u8; 8]).unwrap(), from).unwrap();

                let probe = recv_from_client(&sock);
                let probe_on_theirs = open_informational(&theirs, &probe).is_ok();
                if probe_on_theirs {
                    sock.send_to(&informational_answer(&theirs, &probe, &[]), from).unwrap();
                }
                (second, probe_on_theirs)
            }
        });
        thread::sleep(Duration::from_millis(50));

        let mut tunnel = connect_for_collision_test(bind, psk);
        assert_eq!(tunnel.liveness.rekey_ike(Duration::from_secs(5)).unwrap(), Liveness::Alive);
        assert_eq!(tunnel.liveness.probe(Duration::from_secs(2)).unwrap(), Liveness::Alive);
        let (second, probe_on_theirs) = gateway.join().unwrap();
        assert_eq!(second, Some(notify_type::TEMPORARY_FAILURE));
        assert!(probe_on_theirs, "the session is on the gateway's IKE SA");
    }

    /// RFC 7296 §2.8.2/§2.25.2: a gateway rekeying the IKE SA we are deleting
    /// after our own rekey of it -- it never saw ours -- is refused with
    /// `TEMPORARY_FAILURE`, and the session moves to our new IKE SA.
    #[test]
    fn an_ike_sa_rekey_of_the_ike_sa_we_are_deleting_is_refused_temporary_failure() {
        let bind = next_addr();
        let psk = b"shared-secret".to_vec();
        let gateway = thread::spawn({
            let psk = psk.clone();
            move || {
                let (sock, sa, from) = responder_through_auth(bind, psk);
                let ours = recv_from_client(&sock);
                let (response, new_sa) = gateway_answers_ike_rekey(&sa, &ours, &[0x80u8; 32]);
                sock.send_to(&response, from).unwrap();
                let client_delete = recv_from_client(&sock);
                sock.send_to(&gateway_ike_rekey(&sa, 0, &[0x55u8; 32]), from).unwrap();
                let refusal = create_child_notify(&sa, &recv_response_from_client(&sock));
                sock.send_to(&informational_answer(&sa, &client_delete, &[]), from).unwrap();

                let probe = recv_on(&sock, &new_sa);
                sock.send_to(&informational_answer(&new_sa, &probe, &[]), from).unwrap();
                (deletes_ike_sa(&sa, &client_delete), refusal)
            }
        });
        thread::sleep(Duration::from_millis(50));

        let mut tunnel = connect_for_collision_test(bind, psk);
        assert_eq!(tunnel.liveness.rekey_ike(Duration::from_secs(5)).unwrap(), Liveness::Alive);
        assert_eq!(tunnel.liveness.probe(Duration::from_secs(2)).unwrap(), Liveness::Alive);
        let (old_deleted, refusal) = gateway.join().unwrap();
        assert!(old_deleted);
        assert_eq!(refusal, Some(notify_type::TEMPORARY_FAILURE));
    }

    /// RFC 7296 §2.25.2: a CHILD SA rekey arriving while we rekey the IKE SA
    /// is refused with `TEMPORARY_FAILURE`, and our rekey goes on.
    #[test]
    fn a_child_sa_rekey_arriving_while_we_rekey_the_ike_sa_is_refused_temporary_failure() {
        let bind = next_addr();
        let psk = b"shared-secret".to_vec();
        let gateway = thread::spawn({
            let psk = psk.clone();
            move || {
                let (sock, sa, from, _client_spi) = responder_through_auth_spis(bind, psk);
                let ours = recv_from_client(&sock);
                sock.send_to(&gateway_child_rekey(&sa, 0, RESPONDER_CHILD_SPI, PEER_P_SPI, &[0x55u8; 32]), from).unwrap();
                let refusal = create_child_notify(&sa, &recv_response_from_client(&sock));
                let (response, new_sa) = gateway_answers_ike_rekey(&sa, &ours, &[0x80u8; 32]);
                sock.send_to(&response, from).unwrap();
                let client_delete = recv_from_client(&sock);
                sock.send_to(&informational_answer(&sa, &client_delete, &[]), from).unwrap();

                let probe = recv_on(&sock, &new_sa);
                sock.send_to(&informational_answer(&new_sa, &probe, &[]), from).unwrap();
                refusal
            }
        });
        thread::sleep(Duration::from_millis(50));

        let mut tunnel = connect_for_collision_test(bind, psk);
        assert_eq!(tunnel.liveness.rekey_ike(Duration::from_secs(5)).unwrap(), Liveness::Alive);
        assert_eq!(tunnel.liveness.probe(Duration::from_secs(2)).unwrap(), Liveness::Alive);
        assert_eq!(gateway.join().unwrap(), Some(notify_type::TEMPORARY_FAILURE));
        assert!(tunnel.liveness.take_peer_rekeys().is_empty(), "the refused CHILD SA rekey is nothing to install");
    }

    /// RFC 7296 §2.25.2: a gateway deleting the IKE SA we are rekeying, with no
    /// rekey of its own, is answered as usual and our rekey is dropped -- the
    /// tunnel is gone.
    #[test]
    fn the_gateway_deleting_the_ike_sa_we_are_rekeying_is_a_teardown() {
        let bind = next_addr();
        let psk = b"shared-secret".to_vec();
        let gateway = thread::spawn({
            let psk = psk.clone();
            move || {
                let (sock, sa, from) = responder_through_auth(bind, psk);
                let _ours = recv_from_client(&sock);
                sock.send_to(&ike_delete_request(&sa, 0), from).unwrap();
                open_informational(&sa, &recv_response_from_client(&sock)).is_ok()
            }
        });
        thread::sleep(Duration::from_millis(50));

        let mut tunnel = connect_for_collision_test(bind, psk);
        assert_eq!(tunnel.liveness.rekey_ike(Duration::from_secs(5)).unwrap(), Liveness::PeerTornDown);
        assert!(gateway.join().unwrap(), "the Delete is answered as usual");
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
        LivenessSession { sock, sa: init_sa, dest, float: false, next_message_id: 2, cipher: SkCipher::Aes256Gcm, pfs: PfsPolicy::none(), child_local_spi: 0, child_peer_spi: 0, external_rx, child6: None, cfg_subnets6: Vec::new(), child_carries_ipv6: false, ike: IkeSaState::new(), peer_child: PeerChildState::default(), primary_child_alive: true, peer_requests: PeerRequests::default() }
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

    /// Responder for the "gateway deletes the primary CHILD SA outright"
    /// flow: the usual handshake (its own inbound SPI for the primary fixed
    /// at `PRIMARY_SPI` so the test can build a real Delete for it), a
    /// `CREATE_CHILD_SA` for the IPv6 CHILD SA, an unsolicited Delete for the
    /// primary (no rekey involved -- this is what a real gateway revoking
    /// just that SA looks like), and finally the client's from-scratch
    /// `CREATE_CHILD_SA` renegotiating a replacement.
    const PRIMARY_SPI: u32 = 0xC0FFEE;
    fn run_psk_responder_then_primary_deleted(bind: SocketAddr, psk: Vec<u8>) -> crate::esp::ChildSa {
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
        let (resp, _peer_id, _spi, _ic) = responder_process_auth(&sa, &buf[..n], &rcfg, PRIMARY_SPI, &[9u8; 8], None).unwrap();
        sock.send_to(&resp, from).unwrap();

        // The IPv6 CHILD SA, same as `run_psk_responder_then_ipv6_child`.
        let (n, from) = sock.recv_from(&mut buf).unwrap();
        let (resp, _v6_child) =
            rekey::responder_process_rekey_with_pfs(&sa, &buf[..n], 0xFEED_FACE, &[0x77u8; 32], SkCipher::Aes256Gcm, None, &[6u8; 8], None).unwrap();
        sock.send_to(&resp, from).unwrap();

        // The gateway revokes the primary on its own initiative -- naming
        // the SPI it originally assigned itself (`PRIMARY_SPI`), which is
        // what the client tracks as `child_peer_spi`.
        let del = Delete::esp(vec![PRIMARY_SPI]);
        let msg = build_informational(&sa, 0, false, &[(PayloadType::Delete, del.to_bytes())], &[5u8; 8]).unwrap();
        sock.send_to(&msg, from).unwrap();
        let (n, _) = sock.recv_from(&mut buf).unwrap();
        let ack_header = IkeHeader::parse(&buf[..n]).unwrap();
        assert_eq!(ack_header.message_id, 0, "the client must still ack the Delete");

        // The client renegotiates a brand-new primary CHILD SA from scratch
        // (no REKEY_SA -- the old SPI is already gone on this side too).
        let (n, from) = sock.recv_from(&mut buf).unwrap();
        let (resp, new_primary) =
            rekey::responder_process_rekey_with_pfs(&sa, &buf[..n], 0xF00D_0001, &[0x99u8; 32], SkCipher::Aes256Gcm, None, &[4u8; 8], None).unwrap();
        sock.send_to(&resp, from).unwrap();
        new_primary
    }

    /// The regression test for the bug this fixes: a real gateway can delete
    /// just the primary CHILD SA (not the whole IKE SA) while a separate
    /// IPv6 CHILD SA is still up. Before this fix that either tore the whole
    /// tunnel down (losing the still-good IPv6 CHILD SA and the IKE SA for
    /// no reason -- RFC 7296 §1.4.1 doesn't ask for that) or, depending on
    /// which SPI comparison happened to fire, silently dropped the request
    /// and left the primary black-holed forever. Now: `peek` stays `Alive`,
    /// the deletion is queued, and `create_child_primary` brings a working
    /// replacement up while the IPv6 CHILD SA never moves.
    #[test]
    fn peer_deleting_the_primary_child_sa_is_survived_and_renegotiated() {
        use crate::esp::{next_header, EspSa};

        let bind = next_addr();
        let psk = b"shared-secret".to_vec();
        let responder = thread::spawn({
            let psk = psk.clone();
            move || run_psk_responder_then_primary_deleted(bind, psk)
        });
        thread::sleep(Duration::from_millis(50));

        let mut session = Ikev2Session::new(OsEntropy::new().unwrap());
        let cfg = AuthConfig::psk(Identification::fqdn("client.test"), psk);
        let mut tunnel = session
            .connect_direct_on_port(bind, &default_ike_offer(), &cfg, false, &default_esp_offer(), next_addr().port())
            .unwrap();
        assert_eq!(tunnel.liveness.child_peer_spi, PRIMARY_SPI);
        let old_local_spi = tunnel.liveness.child_local_spi;

        tunnel.liveness.create_child_ipv6(Duration::from_secs(5)).unwrap();
        assert!(tunnel.liveness.has_ipv6_child());

        // A short timeout: the Delete already arrived (see `peek`'s own doc
        // on why this reliably catches it), and `recv_and_classify` keeps
        // waiting out its full timeout after handling a non-teardown event
        // looking for anything else -- a long one here would just race the
        // responder thread's own wait for the renegotiation request below.
        assert_eq!(tunnel.liveness.peek(Duration::from_millis(300)).unwrap(), Liveness::Alive, "the IKE SA and the IPv6 CHILD SA are still good");
        assert_eq!(tunnel.liveness.take_peer_deleted_children(), vec![ChildKind::Primary]);

        let new_primary = tunnel.liveness.create_child_primary(Duration::from_secs(5)).unwrap();
        assert_ne!(new_primary.local_spi, old_local_spi, "a fresh SA, not the deleted one somehow reused");
        assert_eq!((tunnel.liveness.child_local_spi, tunnel.liveness.child_peer_spi), (new_primary.local_spi, new_primary.peer_spi));
        assert!(tunnel.liveness.has_ipv6_child(), "the IPv6 CHILD SA never moved");

        let mut new_primary_responder = responder.join().unwrap();
        let mut client_out = EspSa::new_with_cipher(
            new_primary.peer_spi, new_primary.key_out.cipher, &new_primary.key_out.enc, &new_primary.key_out.integ,
        )
        .unwrap();
        let pkt = client_out.seal(b"through the renegotiated primary", next_header::IPV4).unwrap();
        assert_eq!(new_primary_responder.inbound.open(&pkt).unwrap().0, b"through the renegotiated primary");
    }

    /// How [`run_psk_responder_unified`] answers the CHILD SA of `IKE_AUTH`.
    #[derive(Clone, Copy)]
    enum UnifiedReply {
        /// Grants exactly the selectors offered (what strongSwan does).
        GrantBoth,
        /// [`Self::GrantBoth`], then answers one rekey of that CHILD SA.
        GrantBothThenRekey,
        /// Narrows the reply to IPv4 (RFC 7296 §2.9), as a per-family peer might.
        NarrowToIpv4,
        /// Grants IPv6 alone.
        Ipv6Only,
        /// Refuses the CHILD SA with `error` but keeps the IKE SA (RFC 7296
        /// §1.2), the CFG_REPLY still attached; then answers the one
        /// `CREATE_CHILD_SA` that follows -- granting what it asks for (as a
        /// per-family gateway would for the family it keeps) if `serve_child`,
        /// refusing it with `NO_PROPOSAL_CHOSEN` otherwise.
        Refuse { error: u16, serve_child: bool },
    }

    /// What [`run_psk_responder_unified`] saw the client do.
    struct UnifiedObserved {
        /// TSi of the client's `IKE_AUTH` request.
        offered_tsi: TrafficSelectors,
        /// TSi of the `CREATE_CHILD_SA` the client sent after a refusal, if any.
        created_child_tsi: Option<TrafficSelectors>,
        /// Whether the client then sent an IKE SA Delete.
        client_deleted_ike_sa: bool,
    }

    /// Rewrites an honest `IKE_AUTH` response (`resp`, from `responder_process_auth`
    /// or an `EapResponder`'s final message) into what `reply` says the gateway
    /// answers -- see [`UnifiedReply`].
    fn reseal_for_unified(sa: &CompletedSaInit, resp: &[u8], reply: UnifiedReply, offered_tsi: &TrafficSelectors) -> Vec<u8> {
        use crate::ikev2::message::{encode_payload_chain, first_payload_type};
        use crate::ikev2::payload::Notify;

        let cipher = sa.suite.sk_cipher();
        let (first, inner) = open_encrypted(cipher, resp, &sa.keys.sk_er, &sa.keys.sk_ar).unwrap();
        let honest: Vec<(PayloadType, Vec<u8>)> =
            payloads(first, &inner).map(|p| p.unwrap()).map(|p| (p.payload_type, p.data.to_vec())).collect();
        let is_ts = |t: PayloadType| matches!(t, PayloadType::TrafficSelectorInitiator | PayloadType::TrafficSelectorResponder);
        let answer: Vec<(PayloadType, Vec<u8>)> = match reply {
            UnifiedReply::NarrowToIpv4 => honest,
            UnifiedReply::GrantBoth | UnifiedReply::GrantBothThenRekey | UnifiedReply::Ipv6Only => {
                let ts = if !matches!(reply, UnifiedReply::Ipv6Only) {
                    offered_tsi.clone()
                } else {
                    TrafficSelectors::ipv6_full_tunnel()
                };
                honest.into_iter().map(|(t, d)| if is_ts(t) { (t, ts.to_bytes()) } else { (t, d) }).collect()
            }
            UnifiedReply::Refuse { error, .. } => {
                let mut kept: Vec<_> = honest
                    .into_iter()
                    .filter(|(t, _)| {
                        matches!(t, PayloadType::IdResponder | PayloadType::Authentication | PayloadType::Configuration)
                    })
                    .collect();
                kept.push((PayloadType::Notify, Notify::status(error, Vec::new()).to_bytes()));
                kept
            }
        };
        sk::build_encrypted(
            cipher,
            IkeHeader::parse(resp).unwrap(),
            first_payload_type(&answer),
            &encode_payload_chain(&answer),
            &sa.keys.sk_er,
            &sa.keys.sk_ar,
            &[8u8; 8],
        )
        .unwrap()
    }

    /// The `CREATE_CHILD_SA` step of a [`UnifiedReply::Refuse`] responder:
    /// reads the client's request, answers it per `serve_child`, and returns
    /// the TSi it asked for.
    fn answer_recovery_child(sock: &UdpSocket, sa: &CompletedSaInit, serve_child: bool) -> Option<TrafficSelectors> {
        use crate::ikev2::message::{encode_payload_chain, first_payload_type};
        use crate::ikev2::payload::Notify;

        let cipher = sa.suite.sk_cipher();
        let mut buf = [0u8; 4096];
        let (n, from) = sock.recv_from(&mut buf).unwrap();
        let (first, inner) = open_encrypted(cipher, &buf[..n], &sa.keys.sk_ei, &sa.keys.sk_ai).unwrap();
        let asked = payloads(first, &inner)
            .map(|p| p.unwrap())
            .find(|p| p.payload_type == PayloadType::TrafficSelectorInitiator)
            .map(|p| TrafficSelectors::parse(p.data).unwrap());
        let resp = if serve_child {
            rekey::responder_process_rekey_with_pfs(sa, &buf[..n], 0xFEED_FACE, &[0x77u8; 32], SkCipher::Aes256Gcm, None, &[8u8; 8], None)
                .unwrap()
                .0
        } else {
            let mut header = IkeHeader::parse(&buf[..n]).unwrap();
            header.flags = Flags { initiator: false, version: false, response: true };
            let error = vec![(PayloadType::Notify, Notify::status(notify_type::NO_PROPOSAL_CHOSEN, Vec::new()).to_bytes())];
            sk::build_encrypted(
                cipher,
                header,
                first_payload_type(&error),
                &encode_payload_chain(&error),
                &sa.keys.sk_er,
                &sa.keys.sk_ar,
                &[8u8; 8],
            )
            .unwrap()
        };
        sock.send_to(&resp, from).unwrap();
        asked
    }

    /// Whether the next datagram on `sock` is an IKE SA Delete from the client.
    fn client_closes_ike_sa(sock: &UdpSocket, sa: &CompletedSaInit) -> bool {
        let mut buf = [0u8; 4096];
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => open_informational(sa, &buf[..n])
                .map(|ps| ps.iter().any(|(t, _)| *t == PayloadType::Delete))
                .unwrap_or(false),
            Err(_) => false,
        }
    }

    /// A PSK loopback responder for the unified-TS flows: assigns an inner
    /// address (CFG_REPLY) and answers `IKE_AUTH` per `reply`.
    fn run_psk_responder_unified(bind: SocketAddr, psk: Vec<u8>, reply: UnifiedReply) -> UnifiedObserved {
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
        let cipher = sa.suite.sk_cipher();
        let request = buf[..n].to_vec();
        let (first, inner) = open_encrypted(cipher, &request, &sa.keys.sk_ei, &sa.keys.sk_ai).unwrap();
        let offered_tsi = payloads(first, &inner)
            .map(|p| p.unwrap())
            .find(|p| p.payload_type == PayloadType::TrafficSelectorInitiator)
            .map(|p| TrafficSelectors::parse(p.data).unwrap())
            .expect("IKE_AUTH carries TSi");

        let rcfg = AuthConfig::psk(Identification::fqdn("responder.test"), psk);
        let assigned = AssignedConfig { ip: Ipv4Addr::new(10, 9, 8, 7), dns: vec![Ipv4Addr::new(10, 9, 8, 1)] };
        let (resp, _peer_id, _spi, _ic) =
            responder_process_auth(&sa, &request, &rcfg, 0xC0FFEE, &[9u8; 8], Some(&assigned)).unwrap();

        let rebuilt = reseal_for_unified(&sa, &resp, reply, &offered_tsi);
        sock.send_to(&rebuilt, from).unwrap();

        sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let created_child_tsi = match reply {
            UnifiedReply::Refuse { serve_child, .. } => answer_recovery_child(&sock, &sa, serve_child),
            UnifiedReply::GrantBothThenRekey => answer_recovery_child(&sock, &sa, true),
            _ => None,
        };
        // Whatever comes next is either the client closing the IKE SA or nothing.
        let client_deleted_ike_sa = client_closes_ike_sa(&sock, &sa);
        UnifiedObserved { offered_tsi, created_child_tsi, client_deleted_ike_sa }
    }

    fn connect_unified_direct(bind: SocketAddr, psk: &[u8]) -> Result<ConnectedTunnel, DriverError> {
        let mut session = Ikev2Session::new(OsEntropy::new().unwrap()).with_unified_ts();
        let cfg = AuthConfig::psk(Identification::fqdn("client.test"), psk.to_vec());
        session.connect_direct_on_port(bind, &default_ike_offer(), &cfg, true, &default_esp_offer(), next_addr().port())
    }

    fn spawn_unified_responder(reply: UnifiedReply, psk: &[u8]) -> (SocketAddr, thread::JoinHandle<UnifiedObserved>) {
        let bind = next_addr();
        let psk = psk.to_vec();
        let responder = thread::spawn(move || run_psk_responder_unified(bind, psk, reply));
        thread::sleep(Duration::from_millis(50));
        (bind, responder)
    }

    #[test]
    fn unified_offer_granted_in_full_makes_one_child_sa_carry_both_families() {
        let (bind, responder) = spawn_unified_responder(UnifiedReply::GrantBoth, b"shared-secret");
        let mut tunnel = connect_unified_direct(bind, b"shared-secret").unwrap();
        assert!(tunnel.liveness.child_carries_ipv6());
        assert_eq!(tunnel.child_subnets6, vec![(Ipv6Addr::UNSPECIFIED, 0)]);
        assert_eq!(tunnel.granted_subnets, vec![(Ipv4Addr::UNSPECIFIED, 0)]);
        assert_eq!(tunnel.peer_spi, 0xC0FFEE);
        assert!(
            tunnel.liveness.create_child_ipv6(Duration::from_millis(200)).is_err(),
            "no separate IPv6 CHILD SA next to one that already carries it"
        );
        let observed = responder.join().unwrap();
        assert_eq!(observed.offered_tsi, TrafficSelectors::unified_full_tunnel());
    }

    #[test]
    fn rekeying_a_unified_child_sa_proposes_both_families_again() {
        let (bind, responder) = spawn_unified_responder(UnifiedReply::GrantBothThenRekey, b"shared-secret");
        let mut tunnel = connect_unified_direct(bind, b"shared-secret").unwrap();
        let rekeyed = tunnel.liveness.rekey_child(Duration::from_secs(5)).unwrap();
        assert_ne!(rekeyed.local_spi, tunnel.local_spi);
        assert!(tunnel.liveness.child_carries_ipv6(), "still one SA for both families");
        assert_eq!(
            responder.join().unwrap().created_child_tsi,
            Some(TrafficSelectors::unified_full_tunnel()),
            "an IPv4-only rekey would silently drop IPv6"
        );
    }

    #[test]
    fn unified_offer_narrowed_to_ipv4_leaves_ipv6_to_a_child_sa_of_its_own() {
        let (bind, responder) = spawn_unified_responder(UnifiedReply::NarrowToIpv4, b"shared-secret");
        let tunnel = connect_unified_direct(bind, b"shared-secret").unwrap();
        assert!(!tunnel.liveness.child_carries_ipv6());
        assert!(tunnel.child_subnets6.is_empty());
        assert_eq!(tunnel.assigned_ip4, Some(Ipv4Addr::new(10, 9, 8, 7)));
        assert_eq!(tunnel.granted_subnets, vec![(Ipv4Addr::UNSPECIFIED, 0)]);
        assert_eq!(responder.join().unwrap().offered_tsi, TrafficSelectors::unified_full_tunnel());
    }

    #[test]
    fn unified_offer_is_off_unless_asked_for() {
        let bind = next_addr();
        let responder = thread::spawn(move || run_psk_responder_unified(bind, b"shared-secret".to_vec(), UnifiedReply::NarrowToIpv4));
        thread::sleep(Duration::from_millis(50));
        let mut session = Ikev2Session::new(OsEntropy::new().unwrap());
        let cfg = AuthConfig::psk(Identification::fqdn("client.test"), b"shared-secret".to_vec());
        session.connect_direct_on_port(bind, &default_ike_offer(), &cfg, true, &default_esp_offer(), next_addr().port()).unwrap();
        assert_eq!(responder.join().unwrap().offered_tsi, TrafficSelectors::ipv4_full_tunnel());
    }

    #[test]
    fn unified_offer_granted_ipv6_only_is_a_refusal_and_closes_the_ike_sa() {
        let (bind, responder) = spawn_unified_responder(UnifiedReply::Ipv6Only, b"shared-secret");
        let err = connect_unified_direct(bind, b"shared-secret").err().expect("an IPv6-only grant cannot carry the tunnel");
        assert!(matches!(err, DriverError::Ike(IkeError::PeerRejected { .. })), "{err:?}");
        assert!(responder.join().unwrap().client_deleted_ike_sa);
    }

    #[test]
    fn refused_unified_offer_keeps_the_ike_sa_and_creates_the_ipv4_child_sa_on_it() {
        for error in [notify_type::TS_UNACCEPTABLE, notify_type::SINGLE_PAIR_REQUIRED, notify_type::NO_PROPOSAL_CHOSEN] {
            let (bind, responder) = spawn_unified_responder(UnifiedReply::Refuse { error, serve_child: true }, b"shared-secret");
            let tunnel = connect_unified_direct(bind, b"shared-secret").unwrap();
            // Tunnel data comes from the CREATE_CHILD_SA, the inner address from the refusal's CFG_REPLY.
            assert_eq!(tunnel.local_spi, tunnel.liveness.child_local_spi);
            assert_eq!(tunnel.peer_spi, tunnel.liveness.child_peer_spi);
            assert_ne!(tunnel.peer_spi, 0xC0FFEE, "the IKE_AUTH SPI belongs to a CHILD SA that never existed");
            assert_eq!(tunnel.assigned_ip4, Some(Ipv4Addr::new(10, 9, 8, 7)));
            assert_eq!(tunnel.dns, vec![Ipv4Addr::new(10, 9, 8, 1)]);
            assert_eq!(tunnel.granted_subnets, vec![(Ipv4Addr::UNSPECIFIED, 0)]);
            assert!(!tunnel.liveness.child_carries_ipv6() && tunnel.child_subnets6.is_empty());
            let observed = responder.join().unwrap();
            assert_eq!(observed.offered_tsi, TrafficSelectors::unified_full_tunnel());
            assert_eq!(
                observed.created_child_tsi,
                Some(TrafficSelectors::ipv4_full_tunnel()),
                "the recovery must ask for the family the gateway keeps, alone"
            );
        }
    }

    #[test]
    fn refused_unified_offer_with_no_child_sa_to_fall_back_on_closes_the_ike_sa_and_reports_the_refusal() {
        let refuse = UnifiedReply::Refuse { error: notify_type::TS_UNACCEPTABLE, serve_child: false };
        let (bind, responder) = spawn_unified_responder(refuse, b"shared-secret");
        let err = connect_unified_direct(bind, b"shared-secret").err().expect("no CHILD SA, no tunnel");
        assert!(matches!(err, DriverError::Ike(IkeError::PeerRejected { .. })), "{err:?}");
        let observed = responder.join().unwrap();
        assert!(observed.created_child_tsi.is_some(), "the recovery was attempted");
        assert!(observed.client_deleted_ike_sa, "the IKE SA is closed, not left for the gateway to time out");
    }

    /// The `mode-config` half of the recovery: when CFG was requested but the
    /// refusal carried no CFG_REPLY, no inner address exists to build the
    /// tunnel on, so the IKE SA is closed and the original refusal returned.
    #[test]
    fn refused_unified_offer_without_a_cfg_reply_is_reported_as_the_refusal() {
        use crate::ikev2::message::{encode_payload_chain, first_payload_type};
        use crate::ikev2::payload::Notify;

        let bind = next_addr();
        let psk = b"shared-secret".to_vec();
        let responder = thread::spawn({
            let psk = psk.clone();
            move || {
                let sock = UdpSocket::bind(bind).unwrap();
                sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                let mut buf = [0u8; 4096];
                let (n, from) = sock.recv_from(&mut buf).unwrap();
                let resp_secret = LocalSecret::generate(&mut OsEntropy::new().unwrap(), 32);
                let (response, sa) = match responder_respond_natt(&buf[..n], &resp_secret, bind, from, None).unwrap() {
                    crate::ikev2::exchange::SaInitResult::Established { response, sa } => (response, sa),
                    _ => panic!("expected Established"),
                };
                sock.send_to(&response, from).unwrap();
                let (n, from) = sock.recv_from(&mut buf).unwrap();
                let rcfg = AuthConfig::psk(Identification::fqdn("responder.test"), psk);
                let (resp, ..) = responder_process_auth(&sa, &buf[..n], &rcfg, 0xC0FFEE, &[9u8; 8], None).unwrap();
                let cipher = sa.suite.sk_cipher();
                let (first, inner) = open_encrypted(cipher, &resp, &sa.keys.sk_er, &sa.keys.sk_ar).unwrap();
                let mut kept: Vec<_> = payloads(first, &inner)
                    .map(|p| p.unwrap())
                    .filter(|p| matches!(p.payload_type, PayloadType::IdResponder | PayloadType::Authentication))
                    .map(|p| (p.payload_type, p.data.to_vec()))
                    .collect();
                kept.push((PayloadType::Notify, Notify::status(notify_type::TS_UNACCEPTABLE, Vec::new()).to_bytes()));
                let rejected = sk::build_encrypted(
                    cipher,
                    IkeHeader::parse(&resp).unwrap(),
                    first_payload_type(&kept),
                    &encode_payload_chain(&kept),
                    &sa.keys.sk_er,
                    &sa.keys.sk_ar,
                    &[8u8; 8],
                )
                .unwrap();
                sock.send_to(&rejected, from).unwrap();
                sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                match sock.recv_from(&mut buf) {
                    Ok((n, _)) => open_informational(&sa, &buf[..n])
                        .map(|ps| ps.iter().any(|(t, _)| *t == PayloadType::Delete))
                        .unwrap_or(false),
                    Err(_) => false,
                }
            }
        });
        thread::sleep(Duration::from_millis(50));
        let err = connect_unified_direct(bind, &psk).err().expect("nothing to configure the tunnel with");
        assert!(
            matches!(err, DriverError::Ike(IkeError::PeerRejected { notify_type: notify_type::TS_UNACCEPTABLE, .. })),
            "{err:?}"
        );
        assert!(responder.join().unwrap(), "the IKE SA must be closed, not left for the gateway to time out");
    }

    /// [`run_psk_responder_unified`]'s EAP-MSCHAPv2 twin: the gateway answers the
    /// final EAP message per `reply`.
    fn run_eap_responder_unified(bind: SocketAddr, group_psk: Vec<u8>, user: Vec<u8>, password: String, reply: UnifiedReply) -> UnifiedObserved {
        let sock = UdpSocket::bind(bind).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut entropy = OsEntropy::new().unwrap();
        let mut buf = [0u8; 4096];

        let (n, from) = sock.recv_from(&mut buf).unwrap();
        let resp_secret = LocalSecret::generate(&mut OsEntropy::new().unwrap(), 32);
        let (response, sa) = match responder_respond_natt(&buf[..n], &resp_secret, bind, from, None).unwrap() {
            crate::ikev2::exchange::SaInitResult::Established { response, sa } => (response, sa),
            _ => panic!("expected Established"),
        };
        sock.send_to(&response, from).unwrap();

        let mut responder =
            EapResponder::new(sa.clone(), Identification::fqdn("gw.test"), ServerAuth::Psk(group_psk), user, password, 0xBEEF);
        responder.set_assigned(Some(AssignedConfig { ip: Ipv4Addr::new(10, 9, 8, 7), dns: vec![Ipv4Addr::new(10, 9, 8, 1)] }));
        let mut offered_tsi = None;
        loop {
            let (n, from) = sock.recv_from(&mut buf).unwrap();
            if offered_tsi.is_none() {
                let (first, inner) = open_encrypted(sa.suite.sk_cipher(), &buf[..n], &sa.keys.sk_ei, &sa.keys.sk_ai).unwrap();
                offered_tsi = payloads(first, &inner)
                    .map(|p| p.unwrap())
                    .find(|p| p.payload_type == PayloadType::TrafficSelectorInitiator)
                    .map(|p| TrafficSelectors::parse(p.data).unwrap());
            }
            match responder.handle(&buf[..n], &mut entropy).unwrap() {
                EapEvent::Reply(m) => {
                    sock.send_to(&m, from).unwrap();
                }
                EapEvent::Established(Some(m)) => {
                    let offered = offered_tsi.clone().expect("the first EAP message carries TSi");
                    sock.send_to(&reseal_for_unified(&sa, &m, reply, &offered), from).unwrap();
                    break;
                }
                EapEvent::Established(None) => panic!("the final EAP message is expected"),
                EapEvent::Failed(_) => panic!("responder failed the exchange"),
            }
        }
        sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let created_child_tsi = match reply {
            UnifiedReply::Refuse { serve_child, .. } => answer_recovery_child(&sock, &sa, serve_child),
            _ => None,
        };
        let client_deleted_ike_sa = client_closes_ike_sa(&sock, &sa);
        UnifiedObserved { offered_tsi: offered_tsi.expect("TSi"), created_child_tsi, client_deleted_ike_sa }
    }

    fn connect_unified_eap(reply: UnifiedReply) -> (Result<ConnectedTunnel, DriverError>, UnifiedObserved) {
        let bind = next_addr();
        let (group_psk, user, password) = (b"group-psk".to_vec(), b"alice".to_vec(), "s3cret".to_string());
        let responder = thread::spawn({
            let (group_psk, user, password) = (group_psk.clone(), user.clone(), password.clone());
            move || run_eap_responder_unified(bind, group_psk, user, password, reply)
        });
        thread::sleep(Duration::from_millis(50));
        let mut session = Ikev2Session::new(OsEntropy::new().unwrap()).with_unified_ts();
        let result = session.connect_eap_on_port(
            bind,
            &default_ike_offer(),
            Identification::fqdn("client.test"),
            EapCreds { user, password },
            ServerVerify::Psk(group_psk),
            true,
            &default_esp_offer(),
            next_addr().port(),
        );
        (result, responder.join().unwrap())
    }

    #[test]
    fn eap_unified_offer_granted_in_full_makes_one_child_sa_carry_both_families() {
        let (tunnel, observed) = connect_unified_eap(UnifiedReply::GrantBoth);
        let tunnel = tunnel.unwrap();
        assert!(tunnel.liveness.child_carries_ipv6());
        assert_eq!(tunnel.child_subnets6, vec![(Ipv6Addr::UNSPECIFIED, 0)]);
        assert_eq!(tunnel.peer_spi, 0xBEEF);
        assert_eq!(observed.offered_tsi, TrafficSelectors::unified_full_tunnel());
    }

    #[test]
    fn eap_unified_offer_narrowed_to_ipv4_stays_an_ipv4_tunnel() {
        let (tunnel, _observed) = connect_unified_eap(UnifiedReply::NarrowToIpv4);
        let tunnel = tunnel.unwrap();
        assert!(!tunnel.liveness.child_carries_ipv6() && tunnel.child_subnets6.is_empty());
        assert_eq!(tunnel.assigned_ip4, Some(Ipv4Addr::new(10, 9, 8, 7)));
    }

    #[test]
    fn eap_refused_unified_offer_keeps_the_ike_sa_and_creates_the_ipv4_child_sa_on_it() {
        let (tunnel, observed) =
            connect_unified_eap(UnifiedReply::Refuse { error: notify_type::TS_UNACCEPTABLE, serve_child: true });
        let tunnel = tunnel.unwrap();
        assert_ne!(tunnel.peer_spi, 0xBEEF, "the IKE_AUTH SPI belongs to a CHILD SA that never existed");
        assert_eq!(tunnel.assigned_ip4, Some(Ipv4Addr::new(10, 9, 8, 7)));
        assert_eq!(tunnel.dns, vec![Ipv4Addr::new(10, 9, 8, 1)]);
        assert_eq!(observed.created_child_tsi, Some(TrafficSelectors::ipv4_full_tunnel()));
    }

    #[test]
    fn eap_refused_unified_offer_that_the_child_sa_recovery_cannot_fix_closes_the_ike_sa() {
        let (tunnel, observed) =
            connect_unified_eap(UnifiedReply::Refuse { error: notify_type::NO_PROPOSAL_CHOSEN, serve_child: false });
        let err = tunnel.err().expect("no CHILD SA, no tunnel");
        assert!(matches!(err, DriverError::Ike(IkeError::PeerRejected { .. })), "{err:?}");
        assert!(observed.client_deleted_ike_sa);
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
