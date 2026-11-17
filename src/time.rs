//! The monotonic clock behind the per-source rate limits.
//!
//! In the real program (`server` feature) this is tokio's clock, so tests can
//! pause and advance it. Without `server` (the browser demo) there is no
//! network to be polite to and no system clock to read, so the clock is
//! frozen: every request happens at the same instant and `sleep` returns at
//! once. Chain time (tip age, alarms) never comes from here; it comes from
//! the node's own [`Clock`](crate::node::Clock), which the demo sets by hand.

#[cfg(feature = "server")]
pub use tokio::time::{Instant, sleep};

/// True when `sleep` really waits: inside a tokio runtime. The demo drives
/// the node with a plain executor and no timer, so it must not start one.
#[cfg(feature = "server")]
pub fn has_timer() -> bool {
    tokio::runtime::Handle::try_current().is_ok()
}

/// The frozen clock never waits, so there is nothing to bound a wait by.
#[cfg(not(feature = "server"))]
pub fn has_timer() -> bool {
    false
}

#[cfg(not(feature = "server"))]
pub use frozen::{Instant, sleep};

#[cfg(not(feature = "server"))]
mod frozen {
    use std::ops::Add;
    use std::time::Duration;

    /// A point on a clock that never moves on its own.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub struct Instant(Duration);

    impl Instant {
        pub fn now() -> Self {
            Instant(Duration::ZERO)
        }

        pub fn saturating_duration_since(&self, earlier: Instant) -> Duration {
            self.0.saturating_sub(earlier.0)
        }
    }

    impl Add<Duration> for Instant {
        type Output = Instant;

        fn add(self, d: Duration) -> Instant {
            Instant(self.0 + d)
        }
    }

    /// Returns at once: there is nothing to wait for without a network.
    pub async fn sleep(_d: Duration) {}
}
