//! Integration test: a full IKEv1 handshake — Aggressive Mode + Quick Mode with
//! pre-shared-key auth — between ryke's own `ikev1::Client` and `ikev1::Server`
//! over real UDP sockets on loopback. Confirms both roles interoperate and that
//! the resulting ESP CHILD SAs share keys (what one seals, the other opens).

use std::time::Duration;

use ryke::crypto::DhGroup;
use ryke::ikev1::payloads::Id;
use ryke::ikev1::phase1::{Ikev1ExchangeMode, Ikev1LocalAuth, InitiatorConfig, Phase1Config};
use ryke::ikev1::{Client, Server, ServerEvent};
use ryke::ikev2::sk::SkCipher;
use ryke::SeedEntropy;

#[test]
fn ikev1_full_handshake_over_udp_loopback() {
    ikev1_full_handshake("127.0.0.1:0");
}

/// The same Aggressive Mode + Quick Mode handshake over IPv6 loopback -- a v6
/// gateway address through the transport and the NAT-D hashes. Skipped where
/// the host has no IPv6 loopback.
#[test]
fn ikev1_full_handshake_over_udp_ipv6_loopback() {
    if std::net::UdpSocket::bind("[::1]:0").is_err() {
        return;
    }
    ikev1_full_handshake("[::1]:0");
}

fn ikev1_full_handshake(bind: &str) {
    let psk = b"correct horse battery staple".to_vec();

    let rcfg = Phase1Config {
        local_auth: Ikev1LocalAuth::Psk(psk.clone()),
        trusted_cas: Vec::new(),
        now_unix: 0,
        our_id: Id::ipv4([192, 168, 0, 1]),
    };
    let mut server = Server::bind(bind, SeedEntropy::new(0x2222), rcfg).unwrap();
    server.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let server_addr = server.local_addr().unwrap();

    // Responder handles the four messages (Aggressive 1/3, Quick 1/3), then hands
    // the server back so we can pull out the CHILD SA.
    let handle = std::thread::spawn(move || {
        let e1 = server.handle_one().unwrap();
        let e2 = server.handle_one().unwrap();
        let e3 = server.handle_one().unwrap();
        let e4 = server.handle_one().unwrap();
        (e1, e2, e3, e4, server)
    });

    let icfg = InitiatorConfig {
        local_auth: Ikev1LocalAuth::Psk(psk),
        trusted_cas: Vec::new(),
        now_unix: 0,
        key_len: 32,
        our_id: Id::ipv4([10, 1, 1, 1]),
        group: DhGroup::Modp1024,
        xauth: false,
        xauth_creds: None,
        ts_local: ([10, 0, 99, 0], [255, 255, 255, 0]),
        ts_remote: ([10, 0, 99, 0], [255, 255, 255, 0]),
        esp_cipher: SkCipher::Aes256Gcm,
        pfs_group: None,
        mode_cfg: false,
        ipv6: false,
        mode: Ikev1ExchangeMode::Aggressive,
        p1_lifetime_secs: 28800,
        p2_lifetime_secs: 3600,
        force_natt: false,
    };
    let mut client = Client::bind(bind, SeedEntropy::new(0x1111)).unwrap();
    client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut est = client.connect(server_addr, &icfg).unwrap();

    let (e1, e2, e3, e4, mut server) = handle.join().unwrap();
    assert_eq!(e1, ServerEvent::Phase1SaInit);
    assert_eq!(e2, ServerEvent::Phase1Established);
    assert_eq!(e3, ServerEvent::QuickSaInit);
    assert!(matches!(e4, ServerEvent::ChildSaEstablished { .. }));

    // The two CHILD SAs must interoperate over the wire format.
    let mut rchild = server.take_child(est.phase1.cky_i).expect("server CHILD SA");
    let pkt: Vec<u8> = (0..40u8).collect();
    let sealed = est.child.outbound.seal(&pkt, 4).unwrap();
    let (got, nh) = rchild.inbound.open(&sealed).unwrap();
    assert_eq!(got, pkt);
    assert_eq!(nh, 4);

    let sealed_r = rchild.outbound.seal(&pkt, 4).unwrap();
    let (got_r, _) = est.child.inbound.open(&sealed_r).unwrap();
    assert_eq!(got_r, pkt);
}

/// Same handshake, but the initiator requests PFS on Quick Mode
/// (`InitiatorConfig::pfs_group`) -- `ikev1::Server`'s `respond_quick` needs
/// no configuration of its own for this: it auto-detects PFS purely from the
/// initiator's ESP proposal (see `quick.rs`'s own doc on why there's no
/// separate "does the responder want PFS" question in RFC 2409's design).
/// Confirms the full transport-level wiring (`Client::connect` now calling
/// `initiate_quick_with_pfs`), not just the in-process unit tests in
/// `quick.rs` itself.
#[test]
fn ikev1_full_handshake_over_udp_loopback_with_pfs() {
    let psk = b"correct horse battery staple".to_vec();

    let rcfg = Phase1Config {
        local_auth: Ikev1LocalAuth::Psk(psk.clone()),
        trusted_cas: Vec::new(),
        now_unix: 0,
        our_id: Id::ipv4([192, 168, 0, 1]),
    };
    let mut server = Server::bind("127.0.0.1:0", SeedEntropy::new(0x4444), rcfg).unwrap();
    server.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let server_addr = server.local_addr().unwrap();

    let handle = std::thread::spawn(move || {
        let e1 = server.handle_one().unwrap();
        let e2 = server.handle_one().unwrap();
        let e3 = server.handle_one().unwrap();
        let e4 = server.handle_one().unwrap();
        (e1, e2, e3, e4, server)
    });

    let icfg = InitiatorConfig {
        local_auth: Ikev1LocalAuth::Psk(psk),
        trusted_cas: Vec::new(),
        now_unix: 0,
        key_len: 32,
        our_id: Id::ipv4([10, 1, 1, 1]),
        group: DhGroup::Modp1024,
        xauth: false,
        xauth_creds: None,
        ts_local: ([10, 0, 99, 0], [255, 255, 255, 0]),
        ts_remote: ([10, 0, 99, 0], [255, 255, 255, 0]),
        esp_cipher: SkCipher::Aes256Gcm,
        pfs_group: Some(DhGroup::Modp2048),
        mode_cfg: false,
        ipv6: false,
        mode: Ikev1ExchangeMode::Aggressive,
        p1_lifetime_secs: 28800,
        p2_lifetime_secs: 3600,
        force_natt: false,
    };
    let mut client = Client::bind("127.0.0.1:0", SeedEntropy::new(0x3333)).unwrap();
    client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut est = client.connect(server_addr, &icfg).unwrap();

    let (e1, e2, e3, e4, mut server) = handle.join().unwrap();
    assert_eq!(e1, ServerEvent::Phase1SaInit);
    assert_eq!(e2, ServerEvent::Phase1Established);
    assert_eq!(e3, ServerEvent::QuickSaInit);
    assert!(matches!(e4, ServerEvent::ChildSaEstablished { .. }));

    let mut rchild = server.take_child(est.phase1.cky_i).expect("server CHILD SA");
    let pkt: Vec<u8> = (0..40u8).collect();
    let sealed = est.child.outbound.seal(&pkt, 4).unwrap();
    let (got, nh) = rchild.inbound.open(&sealed).unwrap();
    assert_eq!(got, pkt);
    assert_eq!(nh, 4);

    let sealed_r = rchild.outbound.seal(&pkt, 4).unwrap();
    let (got_r, _) = est.child.inbound.open(&sealed_r).unwrap();
    assert_eq!(got_r, pkt);
}

/// Same handshake, but Phase 1 runs as Main Mode (`InitiatorConfig::mode`)
/// instead of Aggressive Mode -- confirms `Client::connect`'s Main-Mode branch
/// and `Server`'s `exchange::MAIN` dispatch interoperate end-to-end over real
/// UDP sockets, not just the in-process unit tests in `phase1.rs`. Six Phase-1
/// messages instead of Aggressive's three, so the responder handles six
/// `handle_one` calls total before Quick Mode's usual two.
#[test]
fn ikev1_full_handshake_over_udp_loopback_main_mode() {
    let psk = b"correct horse battery staple".to_vec();

    let rcfg = Phase1Config {
        local_auth: Ikev1LocalAuth::Psk(psk.clone()),
        trusted_cas: Vec::new(),
        now_unix: 0,
        our_id: Id::ipv4([192, 168, 0, 1]),
    };
    let mut server = Server::bind("127.0.0.1:0", SeedEntropy::new(0x5555), rcfg).unwrap();
    server.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let server_addr = server.local_addr().unwrap();

    let handle = std::thread::spawn(move || {
        let e1 = server.handle_one().unwrap(); // msg1 -> msg2
        let e2 = server.handle_one().unwrap(); // msg3 -> msg4
        let e3 = server.handle_one().unwrap(); // msg5 -> msg6
        let e4 = server.handle_one().unwrap(); // Quick msg1 -> msg2
        let e5 = server.handle_one().unwrap(); // Quick msg3
        (e1, e2, e3, e4, e5, server)
    });

    let icfg = InitiatorConfig {
        local_auth: Ikev1LocalAuth::Psk(psk),
        trusted_cas: Vec::new(),
        now_unix: 0,
        key_len: 32,
        our_id: Id::ipv4([10, 1, 1, 1]),
        group: DhGroup::Modp1024,
        xauth: false,
        xauth_creds: None,
        ts_local: ([10, 0, 99, 0], [255, 255, 255, 0]),
        ts_remote: ([10, 0, 99, 0], [255, 255, 255, 0]),
        esp_cipher: SkCipher::Aes256Gcm,
        pfs_group: None,
        mode_cfg: false,
        ipv6: false,
        mode: Ikev1ExchangeMode::Main,
        p1_lifetime_secs: 28800,
        p2_lifetime_secs: 3600,
        force_natt: false,
    };
    let mut client = Client::bind("127.0.0.1:0", SeedEntropy::new(0x6666)).unwrap();
    client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut est = client.connect(server_addr, &icfg).unwrap();

    let (e1, e2, e3, e4, e5, mut server) = handle.join().unwrap();
    assert_eq!(e1, ServerEvent::Phase1SaInit);
    assert_eq!(e2, ServerEvent::Phase1SaInit);
    assert_eq!(e3, ServerEvent::Phase1Established);
    assert_eq!(e4, ServerEvent::QuickSaInit);
    assert!(matches!(e5, ServerEvent::ChildSaEstablished { .. }));

    let mut rchild = server.take_child(est.phase1.cky_i).expect("server CHILD SA");
    let pkt: Vec<u8> = (0..40u8).collect();
    let sealed = est.child.outbound.seal(&pkt, 4).unwrap();
    let (got, nh) = rchild.inbound.open(&sealed).unwrap();
    assert_eq!(got, pkt);
    assert_eq!(nh, 4);

    let sealed_r = rchild.outbound.seal(&pkt, 4).unwrap();
    let (got_r, _) = est.child.inbound.open(&sealed_r).unwrap();
    assert_eq!(got_r, pkt);
}

/// A full Aggressive Mode + Quick Mode handshake against a `Server` that limits
/// the volume of an SA to `volume_limit_kilobytes` of its own (`None`: it states
/// none). Returns what the client was left with, the lifetime the server says it
/// granted, and the server's CHILD SA.
fn handshake_against_a_gateway_with_volume_limit(
    volume_limit_kilobytes: Option<u32>,
    seed: u64,
) -> (ryke::ikev1::Established, Option<ryke::SaLifetime>, ryke::esp::ChildSa) {
    let psk = b"correct horse battery staple".to_vec();
    let rcfg = Phase1Config {
        local_auth: Ikev1LocalAuth::Psk(psk.clone()),
        trusted_cas: Vec::new(),
        now_unix: 0,
        our_id: Id::ipv4([192, 168, 0, 1]),
    };
    let mut server = Server::bind("127.0.0.1:0", SeedEntropy::new(seed), rcfg).unwrap();
    server.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    server.set_child_volume_limit(volume_limit_kilobytes);
    let server_addr = server.local_addr().unwrap();

    let handle = std::thread::spawn(move || {
        let events = [server.handle_one().unwrap(), server.handle_one().unwrap(), server.handle_one().unwrap(), server.handle_one().unwrap()];
        (events, server)
    });

    let icfg = InitiatorConfig {
        local_auth: Ikev1LocalAuth::Psk(psk),
        trusted_cas: Vec::new(),
        now_unix: 0,
        key_len: 32,
        our_id: Id::ipv4([10, 1, 1, 1]),
        group: DhGroup::Modp1024,
        xauth: false,
        xauth_creds: None,
        ts_local: ([10, 0, 99, 0], [255, 255, 255, 0]),
        ts_remote: ([10, 0, 99, 0], [255, 255, 255, 0]),
        esp_cipher: SkCipher::Aes256Gcm,
        pfs_group: None,
        mode_cfg: false,
        ipv6: false,
        mode: Ikev1ExchangeMode::Aggressive,
        p1_lifetime_secs: 28800,
        p2_lifetime_secs: 3600,
        force_natt: false,
    };
    let mut client = Client::bind("127.0.0.1:0", SeedEntropy::new(seed + 1)).unwrap();
    client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let est = client.connect(server_addr, &icfg).unwrap();

    let (events, mut server) = handle.join().unwrap();
    assert_eq!(events[..3], [ServerEvent::Phase1SaInit, ServerEvent::Phase1Established, ServerEvent::QuickSaInit]);
    assert!(matches!(events[3], ServerEvent::ChildSaEstablished { .. }));
    let granted = server.child_lifetime(est.phase1.cky_i);
    let rchild = server.take_child(est.phase1.cky_i).expect("server CHILD SA");
    (est, granted, rchild)
}

/// A gateway that states no volume limit leaves the client with seconds alone --
/// the lifetime is the one offered -- and the server says it granted the same.
#[test]
fn ikev1_quick_mode_without_a_volume_limit_holds_the_seconds_alone() {
    let (est, granted, _rchild) = handshake_against_a_gateway_with_volume_limit(None, 0x7000);
    assert_eq!((est.p2_lifetime_secs, est.p2_lifetime_kilobytes), (3600, None));
    assert_eq!(granted, Some(ryke::SaLifetime { seconds: 3600, kilobytes: None }));
}

/// A gateway whose SAs are limited in volume (a Cisco IOS default, 4608000 KB):
/// what it states in message 2 reaches the caller through `Established`, beside
/// the seconds, and is the very limit the server says it granted -- and the
/// limit changes nothing about the two CHILD SAs interoperating.
#[test]
fn ikev1_quick_mode_hands_the_gateways_volume_limit_to_the_caller() {
    let (mut est, granted, mut rchild) = handshake_against_a_gateway_with_volume_limit(Some(4_608_000), 0x7100);
    assert_eq!((est.p2_lifetime_secs, est.p2_lifetime_kilobytes), (3600, Some(4_608_000)));
    assert_eq!(granted, Some(ryke::SaLifetime { seconds: 3600, kilobytes: Some(4_608_000) }));

    let pkt: Vec<u8> = (0..40u8).collect();
    let sealed = est.child.outbound.seal(&pkt, 4).unwrap();
    assert_eq!(rchild.inbound.open(&sealed).unwrap().0, pkt);
    let sealed_r = rchild.outbound.seal(&pkt, 4).unwrap();
    assert_eq!(est.child.inbound.open(&sealed_r).unwrap().0, pkt);
}
