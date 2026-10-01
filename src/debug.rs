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
//! no-framework logging style. A host that wants to decide how a line is
//! printed (e.g. to put a time stamp in front of it, as `free-vpn-v2`'s
//! worker does) installs a [`set_sink`]; it is handed the finished line --
//! the `[ryke] ` prefix is always ryke's own and is already on it, and no
//! line break is -- and prints it however it likes. With none installed
//! (the default) the line goes to stderr exactly as described above.

use std::fmt::Write;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::OnceLock;

static LEVEL: AtomicU8 = AtomicU8::new(0);

/// What a host installs with [`set_sink`]: prints one finished trace line (`[ryke] ...`, no line break).
pub type Sink = fn(std::fmt::Arguments<'_>);

static SINK: OnceLock<Sink> = OnceLock::new();

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

pub fn enabled(wanted: u8) -> bool {
    level() >= wanted
}

/// Takes over the printing of every trace line in this process: `sink` gets each one finished (the `[ryke] `
/// prefix on it, no line break) instead of it going to stderr. Meant to be set once at startup, next to
/// [`set_level`]; the first call wins and a later one is ignored (the `bool` says whether this one took effect).
/// No dependency and no change for a host that never calls it.
pub fn set_sink(sink: Sink) -> bool {
    SINK.set(sink).is_ok()
}

pub fn emit(args: std::fmt::Arguments) {
    emit_to(SINK.get().copied(), format_args!("[ryke] {args}"));
}

/// Like [`emit`], for a line that carries a tag of its own instead of `[ryke] ` (it goes where trace lines go).
pub(crate) fn emit_tagged(args: std::fmt::Arguments) {
    emit_to(SINK.get().copied(), args);
}

/// Prints a finished `line` through `sink`, or to stderr when there is none.
fn emit_to(sink: Option<Sink>, line: std::fmt::Arguments<'_>) {
    match sink {
        Some(sink) => sink(line),
        None => eprintln!("{line}"),
    }
}

/// Level-1 milestone line.
#[macro_export]
macro_rules! ike_debug {
    ($($arg:tt)*) => {
        if $crate::debug::enabled(1) {
            $crate::debug::emit(format_args!($($arg)*));
        }
    };
}
pub use ike_debug;

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
pub fn dump(direction: &str, addr: SocketAddr, data: &[u8]) {
    if enabled(2) {
        emit(format_args!("{direction} {addr} ({} bytes): {}", data.len(), hex(data)));
    }
}

#[cfg(test)]
mod tests {
    use super::emit_to;
    use std::sync::Mutex;

    // A sink is a plain `fn`, so what it received goes to a static. This one is only ever used by the test below
    // (the process-wide `SINK` is never set by any test, so none of ryke's other tests is affected).
    static SEEN: Mutex<Vec<String>> = Mutex::new(Vec::new());

    fn record(line: std::fmt::Arguments<'_>) {
        SEEN.lock().unwrap().push(line.to_string());
    }

    #[test]
    fn a_sink_is_handed_the_finished_line_and_prints_nothing_itself() {
        emit_to(Some(record), format_args!("[ryke] {} {}", "exchange", 3));
        emit_to(Some(record), format_args!("[ryke/rekeyresp] tagged"));
        assert_eq!(*SEEN.lock().unwrap(), vec!["[ryke] exchange 3".to_string(), "[ryke/rekeyresp] tagged".to_string()]);
    }

    #[test]
    fn without_a_sink_the_line_goes_to_stderr_as_before() {
        // Captured by the test harness; this only checks that the default path is there and does not panic.
        emit_to(None, format_args!("[ryke] default path"));
    }
}
