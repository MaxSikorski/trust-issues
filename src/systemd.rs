//! Telling systemd how we're doing (the `sd_notify` protocol), without any
//! extra dependency: it's one text datagram to the socket in `NOTIFY_SOCKET`.
//!
//! Everything here does nothing unless systemd started us as a `Type=notify`
//! unit, so running by hand or in Docker is unchanged.
//!
//! - `READY=1` once the RPC server is listening, so units ordered after us
//!   (LND, Core Lightning) don't start talking to us too early.
//! - `STATUS=...` after every poll round, shown by `systemctl status`.
//! - `WATCHDOG=1` only while the node is making progress
//!   ([`Node::seconds_since_progress`](crate::node::Node::seconds_since_progress)).
//!   If it hangs, the pings stop and systemd restarts it, instead of it
//!   quietly serving an old tip to Lightning.
//! - `STOPPING=1` when we shut down.
//!
//! Only filesystem sockets are supported (systemd's usual
//! `/run/systemd/notify`), not Linux's abstract `@` sockets.

use std::path::Path;
use std::time::Duration;

/// Seconds of no progress, beyond one poll interval, before we stop pinging
/// the watchdog. Covers the slowest request (90 s timeout) with room to spare.
pub const STALL_GRACE_SECS: u64 = 180;

/// How long the node may go without progress before we call it hung.
pub fn stall_limit(poll_interval_secs: u64) -> u64 {
    poll_interval_secs + STALL_GRACE_SECS
}

/// Send one message to the systemd notify socket, if there is one.
/// Returns whether a message was sent.
pub fn notify(msg: &str) -> bool {
    match std::env::var_os("NOTIFY_SOCKET") {
        Some(sock) => notify_to(Path::new(&sock), msg).is_ok(),
        None => false,
    }
}

/// Send `msg` to the notify socket at `socket`.
pub fn notify_to(socket: &Path, msg: &str) -> std::io::Result<()> {
    if socket.as_os_str().to_string_lossy().starts_with('@') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "abstract notify sockets aren't supported",
        ));
    }
    #[cfg(unix)]
    {
        let s = std::os::unix::net::UnixDatagram::unbound()?;
        s.send_to(msg.as_bytes(), socket)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = msg;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "systemd needs unix",
        ))
    }
}

/// `READY=1` with a status line.
pub fn ready(status: &str) -> bool {
    notify(&format!("READY=1\nSTATUS={}", one_line(status)))
}

/// A status line for `systemctl status`.
pub fn status(status: &str) -> bool {
    notify(&format!("STATUS={}", one_line(status)))
}

/// `STOPPING=1`.
pub fn stopping() -> bool {
    notify("STOPPING=1")
}

/// How often to ping the watchdog (half its timeout), if the unit has
/// `WatchdogSec=` set and the watchdog is meant for us.
pub fn watchdog_interval() -> Option<Duration> {
    watchdog_interval_from(
        std::env::var("WATCHDOG_USEC").ok().as_deref(),
        std::env::var("WATCHDOG_PID").ok().as_deref(),
        std::process::id(),
    )
}

/// [`watchdog_interval`] from explicit values, so it can be tested.
pub fn watchdog_interval_from(
    usec: Option<&str>,
    pid: Option<&str>,
    our_pid: u32,
) -> Option<Duration> {
    let usec: u64 = usec?.trim().parse().ok().filter(|&u| u > 0)?;
    if let Some(p) = pid
        && p.trim().parse::<u32>().ok() != Some(our_pid)
    {
        return None;
    }
    Some(Duration::from_micros(usec / 2))
}

/// The watchdog's decision: ping only while the node is making progress.
pub fn should_ping(seconds_since_progress: u64, poll_interval_secs: u64) -> bool {
    seconds_since_progress <= stall_limit(poll_interval_secs)
}

fn one_line(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(200).collect()
}
