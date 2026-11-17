//! Politeness: a per-source request budget and backoff after failures.

use std::time::Duration;

use tokio::time::Instant;

/// The most requests per second any source may get, whatever the config says.
pub const HARD_MAX_REQUESTS_PER_SEC: f64 = 2.0;
pub const DEFAULT_REQUESTS_PER_SEC: f64 = 1.0;
pub const DEFAULT_BURST: f64 = 5.0;

/// A classic token bucket: `burst` requests at once, then `rate` per second.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    capacity: f64,
    tokens: f64,
    rate: f64,
    last: Instant,
}

impl TokenBucket {
    pub fn new(rate_per_sec: f64, burst: f64, now: Instant) -> Self {
        let rate = rate_per_sec.clamp(0.01, HARD_MAX_REQUESTS_PER_SEC);
        let capacity = burst.max(1.0);
        Self {
            capacity,
            tokens: capacity,
            rate,
            last: now,
        }
    }

    /// Take one token. Returns how long the caller must wait before sending
    /// (zero if a token was available).
    pub fn take(&mut self, now: Instant) -> Duration {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.rate).min(self.capacity);
        self.tokens -= 1.0;
        if self.tokens >= 0.0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64(-self.tokens / self.rate)
        }
    }
}

pub const BACKOFF_START: Duration = Duration::from_secs(5);
pub const BACKOFF_CAP: Duration = Duration::from_secs(600);

/// Exponential backoff: 5 s, 10 s, 20 s … capped at 10 minutes, plus up to
/// 20% jitter. `jitter` is a number in [0, 1); pass a random one in production
/// and a fixed one in tests.
pub fn backoff(failures: u32, jitter: f64) -> Duration {
    let exp = failures.saturating_sub(1).min(16);
    let base = BACKOFF_START.saturating_mul(1u32 << exp).min(BACKOFF_CAP);
    let extra = base.mul_f64(0.2 * jitter.clamp(0.0, 0.999));
    (base + extra).min(BACKOFF_CAP + BACKOFF_CAP / 5)
}

/// A random number in [0, 1) for jitter, from the operating system.
pub fn os_jitter() -> f64 {
    let mut b = [0u8; 4];
    if getrandom::fill(&mut b).is_err() {
        return 0.5;
    }
    f64::from(u32::from_le_bytes(b)) / (f64::from(u32::MAX) + 1.0)
}
