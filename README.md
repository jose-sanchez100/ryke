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
| **Initiator sessions** (`Ikev2Session` → `LivenessSession`; `ikev1::Client` + `ikev1::informational::{peek, probe}` + `ikev1::quick::rekey_child`) | Connect, then run the SA: liveness checks, rekeys, Deletes, answering the peer's requests. IKEv2: reassemble any message the peer sends in fragments (RFC 7383), and send any of theirs beyond a datagram limit (576 bytes for IPv4, 1280 for IPv6 by default) in fragments when the peer negotiated them, resending the same ones on a retransmission | Decide *when* to check liveness, rekey or reconnect, or run in the background: the calls block. Fragment `IKE_SA_INIT`, or a message to a peer that did not negotiate fragmentation (it goes whole, and may be fragmented at the IP layer or dropped), or discover the path MTU. A few exchanges are missing (listed in the crate docs) |
| **Bundled servers** (`ikev2::server::Server`, `ikev1::Server`) | Minimal responders for tests and examples: a PSK or certificates (in IKEv1, Main Mode only), one CHILD SA at a time. The IKEv2 one reassembles fragmented requests, and answers beyond the datagram limit in fragments when the peer negotiated them | The rest of a gateway: EAP or XAUTH, NAT-T, address assignment (CP / Mode-Config), exchanges of their own |

Whatever the part, the consumer supplies:

- **the data plane**: installing each CHILD SA's keys (kernel XFRM, or
  ryke's userspace ESP via `Tunnel` / `EspSa` / `ChildSa`) and capturing the
  traffic to carry (a TUN device, a SOCKS proxy, …);
- **the host's configuration**: applying the addresses, DNS servers and
  routes the gateway assigns;
- **credentials and trust**: keys, certificates, EAP credentials, trusted
  CAs, the name the gateway's certificate must carry, and the current time
  for certificate validity. ryke builds the path to a trusted CA (unless
  the certificate is pinned), checks each certificate's extensions (RFC 5280
  §4.2) and the leaf's KeyUsage (RFC 4945 §5.1.3.2), and rejects a critical
  extension it does not process. Revocation (CRL, OCSP), ExtendedKeyUsage,
  certificate policies and any binding of the peer's ID to the certificate
  beyond that name are left to the consumer;
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
