# ryke

A **clean-room IKEv2 / IKEv1 implementation in Rust**, with code for both the
initiator and the responder side of the exchanges.

`ryke` = **R**ust + **IKE**. Built from the RFCs; it does not wrap OpenSSL or any
existing IKE/IPsec daemon, and copies no third-party code.

## What each part guarantees

ryke comes in layers, and what holds for one says nothing about another. The
crate docs (`src/lib.rs`) give the full contract; in short:

| Part | Does | Does not |
|---|---|---|
| **Building blocks** (`ikev2::exchange`, `ike_auth`, `eap_auth`, `rekey`, `ike_rekey`, `informational`, …; `ikev1::phase1`, `quick`, `xauth`, `cfg`, `informational`) | Parse, check and build the messages of one exchange, for either role | Keep any state between messages: Message IDs, retransmissions and repeated requests, timers, lifetimes, simultaneous exchanges are up to whoever puts them together |
| **Initiator sessions** (`Ikev2Session` → `LivenessSession`; `ikev1::Client` + `ikev1::informational::{peek, probe}` + `ikev1::quick::rekey_child`) | Connect, then run the SA: liveness checks, rekeys, Deletes, answering the peer's requests | Decide *when* to check liveness, rekey or reconnect, or run in the background: the calls block. A few exchanges are missing (listed in the crate docs) |
| **Bundled servers** (`ikev2::server::Server`, `ikev1::Server`) | Minimal responders for tests and examples: a PSK or certificates (in IKEv1, Main Mode only), one CHILD SA at a time | The rest of a gateway: EAP or XAUTH, NAT-T, address assignment (CP / Mode-Config), exchanges of their own |

Whatever the part, the consumer supplies:

- **the data plane**: installing each CHILD SA's keys (kernel XFRM, or
  ryke's userspace ESP via `Tunnel` / `EspSa` / `ChildSa`) and capturing the
  traffic to carry (a TUN device, a SOCKS proxy, …);
- **the host's configuration**: applying the addresses, DNS servers and
  routes the gateway assigns;
- **credentials and trust**: keys, certificates, EAP credentials, trusted
  CAs, the name the gateway's certificate must carry, and the current time
  for certificate validity;
- **sockets and randomness**, where asked for.

[`docs/implementation-plan.md`](docs/implementation-plan.md) is the original
roadmap, older than most of this.

## Build

```bash
cargo build
cargo test
```

## License

MIT — see [LICENSE.md](LICENSE.md). © Vladimir Chebotarev
