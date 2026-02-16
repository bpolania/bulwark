//! Token bucket rate limiting primitive.

use std::time::Instant;

/// A token bucket for rate limiting.
///
/// Tokens are consumed by requests and refilled at a constant rate.
/// When no tokens are available, the request is denied.
#[derive(Debug)]
pub struct TokenBucket {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64, // tokens per second
    last_refill: Instant,
}

impl TokenBucket {
    /// Create a new token bucket, initially full.
    pub fn new(max_tokens: f64, refill_rate: f64) -> Self {
        Self {
            tokens: max_tokens,
            max_tokens,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    /// Create a token bucket from RPM (requests per minute) and burst size.
    pub fn from_rpm(rpm: u32, burst: u32) -> Self {
        let max_tokens = burst as f64;
        let refill_rate = rpm as f64 / 60.0;
        Self::new(max_tokens, refill_rate)
    }

    /// Try to consume `cost` tokens. Returns `true` if successful.
    pub fn try_consume(&mut self, cost: f64) -> bool {
        self.refill();
        if self.tokens >= cost {
            self.tokens -= cost;
            true
        } else {
            false
        }
    }

    /// Return the number of tokens currently available (after refilling).
    pub fn available(&mut self) -> f64 {
        self.refill();
        self.tokens
    }

    /// Refill tokens based on elapsed time.
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_refill = now;
    }

    /// Seconds until `cost` tokens are available (0.0 if already available).
    pub fn seconds_until_available(&mut self, cost: f64) -> f64 {
        self.refill();
        if self.tokens >= cost {
            return 0.0;
        }
        let deficit = cost - self.tokens;
        if self.refill_rate > 0.0 {
            deficit / self.refill_rate
        } else {
            f64::INFINITY
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_full() {
        let mut bucket = TokenBucket::new(10.0, 1.0);
        assert!((bucket.available() - 10.0).abs() < 0.1);
    }

    #[test]
    fn consume_reduces_tokens() {
        let mut bucket = TokenBucket::new(10.0, 1.0);
        assert!(bucket.try_consume(3.0));
        assert!(bucket.available() < 8.0);
    }

    #[test]
    fn overdraft_rejected() {
        let mut bucket = TokenBucket::new(5.0, 1.0);
        assert!(bucket.try_consume(3.0));
        assert!(!bucket.try_consume(3.0));
    }

    #[test]
    fn exact_consume() {
        let mut bucket = TokenBucket::new(5.0, 0.0);
        assert!(bucket.try_consume(5.0));
        assert!(!bucket.try_consume(0.1));
    }

    #[test]
    fn from_rpm_constructor() {
        let bucket = TokenBucket::from_rpm(60, 10);
        assert!((bucket.max_tokens - 10.0).abs() < f64::EPSILON);
        assert!((bucket.refill_rate - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn refill_caps_at_max() {
        let mut bucket = TokenBucket::new(10.0, 1000.0);
        // Even with a high refill rate, shouldn't exceed max.
        std::thread::sleep(std::time::Duration::from_millis(10));
        assert!(bucket.available() <= 10.0 + 0.1);
    }

    #[test]
    fn seconds_until_available_zero_when_enough() {
        let mut bucket = TokenBucket::new(10.0, 1.0);
        assert!((bucket.seconds_until_available(5.0)).abs() < 0.01);
    }

    #[test]
    fn seconds_until_available_positive_when_deficit() {
        let mut bucket = TokenBucket::new(5.0, 0.0); // no refill
        assert!(bucket.try_consume(5.0));
        let wait = bucket.seconds_until_available(1.0);
        assert!(wait.is_infinite());
    }
}
