//! Lightweight, dependency-free protocol tracing -- this crate's equivalent
//! of strongSwan/charon's `debug <n>` levels, for a caller (e.g.
//! `free-vpn-v2`'s worker process) that wants visibility into what's
//! happening on the wire without this crate taking on a logging-framework
//! dependency (it deliberately has none).
//!
//! One global level (like charon's own `debug` setting, not per-subsystem):
//! - **0** (default): silent.
//! - **1**: one line per protocol milestone -- exchange started/completed,
//!   proposal negotiated, NAT detection result, AUTH/EAP outcome (including
//!   the server's stated reason for an EAP-MSCHAPv2 failure, e.g.
//!   `E=691 R=1 ...`), CREATE_CHILD_SA rekey, DPD/peer-initiated teardown.
//! - **2**: level 1, plus a hex dump of every UDP datagram sent/received.
//!   Deliberately **wire bytes only** -- this crate never dumps a decrypted
//!   payload (an AUTH/EAP message's cleartext could contain credential
//!   material), so raising the level can never leak more than what already
//!   crosses the network in the open (headers, lengths, ciphertext).
//!
//! Output goes to stderr, one line per event, prefixed `[ryke]` -- plain
//! `eprintln!`, matching this crate's and `free-vpn-v2`'s existing
//! no-framework logging style.

use std::fmt::Write;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8, Ordering};

static LEVEL: AtomicU8 = AtomicU8::new(0);

/// Set the global trace level (0 = silent, 1 = milestones, 2 = + raw hex
/// dumps). One process-wide knob, set once before connecting -- not
/// per-session, since a caller normally wants this decided at startup (e.g.
/// forwarded from a `--debug`/`--debug-all` CLI flag), not toggled mid-call.
pub fn set_level(level: u8) {
    LEVEL.store(level, Ordering::Relaxed);
}

/// The current trace level.
pub fn level() -> u8 {
    LEVEL.load(Ordering::Relaxed)
}

pub(crate) fn enabled(wanted: u8) -> bool {
    level() >= wanted
}

pub(crate) fn emit(args: std::fmt::Arguments) {
    eprintln!("[ryke] {args}");
}

/// Level-1 milestone line.
macro_rules! ike_debug {
    ($($arg:tt)*) => {
        if $crate::debug::enabled(1) {
            $crate::debug::emit(format_args!($($arg)*));
        }
    };
}
pub(crate) use ike_debug;

fn hex(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len() * 2);
    for b in data {
        let _ = write!(s, "{b:02X}");
    }
    s
}

/// Level-2 raw datagram dump -- wire bytes as sent/received, still
/// SK{}-encrypted past `IKE_SA_INIT`. `direction` is `">>>"` (sent) or
/// `"<<<"` (received).
pub(crate) fn dump(direction: &str, addr: SocketAddr, data: &[u8]) {
    if enabled(2) {
        emit(format_args!("{direction} {addr} ({} bytes): {}", data.len(), hex(data)));
    }
}
