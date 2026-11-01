//! Concurrency utilities, bounded channel helpers, and network formatters.

use std::net::Ipv4Addr;

/// Formats a raw network byte order (big-endian) IPv4 integer into a human-readable string.
#[inline]
pub fn format_ipv4(net_order_ip: u32) -> String {
    Ipv4Addr::from(u32::from_be(net_order_ip)).to_string()
}

/// Returns the current system Unix timestamp in nanoseconds.
#[inline]
#[must_use]
pub fn current_timestamp_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

/// Token bucket rate limiter for user-space event throttling.
#[derive(Debug)]
pub struct RateLimiter {
    capacity: u32,
    available_tokens: u32,
    refill_rate_per_sec: u32,
    last_refill_instant: std::time::Instant,
}

impl RateLimiter {
    pub fn new(capacity: u32, refill_rate_per_sec: u32) -> Self {
        Self {
            capacity,
            available_tokens: capacity,
            refill_rate_per_sec,
            last_refill_instant: std::time::Instant::now(),
        }
    }

    /// Tries to acquire a single token. Returns true if allowed, false if rate limited.
    pub fn try_acquire(&mut self) -> bool {
        self.refill();
        if self.available_tokens > 0 {
            self.available_tokens -= 1;
            true
        } else {
            false
        }
    }

    fn refill(&mut self) {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_refill_instant).as_secs_f64();
        let tokens_to_add = (elapsed * self.refill_rate_per_sec as f64) as u32;

        if tokens_to_add > 0 {
            self.available_tokens = (self.available_tokens + tokens_to_add).min(self.capacity);
            self.last_refill_instant = now;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_ipv4() {
        let net_order_ip = u32::from_ne_bytes([127, 0, 0, 1]);
        assert_eq!(format_ipv4(net_order_ip), "127.0.0.1");
    }

    #[test]
    fn test_rate_limiter() {
        let mut limiter = RateLimiter::new(2, 10);
        assert!(limiter.try_acquire());
        assert!(limiter.try_acquire());
        // Exhausted
        assert!(!limiter.try_acquire());
    }
}
