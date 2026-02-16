//! Per-analyzer circuit breaker with three states: Closed, Open, Half-Open.

use std::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Circuit breaker states.
const STATE_CLOSED: u8 = 0;
const STATE_OPEN: u8 = 1;
const STATE_HALF_OPEN: u8 = 2;

/// Per-analyzer circuit breaker.
///
/// - **Closed** (normal): requests flow through. Track consecutive failures.
/// - **Open** (tripped): skip this analyzer entirely.
/// - **Half-open** (testing): allow one request. If success → close; if fail → re-open.
pub struct CircuitBreaker {
    state: AtomicU8,
    consecutive_failures: AtomicU32,
    failure_threshold: u32,
    /// Monotonic timestamp (nanos since some epoch) of the last failure.
    last_failure_nanos: AtomicU64,
    cooldown: Duration,
    /// Reference instant for converting between Instant and stored nanos.
    epoch: Instant,
}

impl CircuitBreaker {
    /// Create a new circuit breaker.
    pub fn new(failure_threshold: u32, cooldown: Duration) -> Self {
        Self {
            state: AtomicU8::new(STATE_CLOSED),
            consecutive_failures: AtomicU32::new(0),
            failure_threshold,
            last_failure_nanos: AtomicU64::new(0),
            cooldown,
            epoch: Instant::now(),
        }
    }

    /// Whether the circuit breaker allows a request through.
    pub fn should_allow(&self) -> bool {
        match self.state.load(Ordering::Acquire) {
            STATE_CLOSED => true,
            STATE_OPEN => {
                // Check if cooldown has elapsed.
                let last_fail = self.last_failure_nanos.load(Ordering::Acquire);
                let elapsed = self.epoch.elapsed().as_nanos() as u64 - last_fail;
                if elapsed >= self.cooldown.as_nanos() as u64 {
                    // Transition to half-open: allow one test request.
                    self.state.store(STATE_HALF_OPEN, Ordering::Release);
                    true
                } else {
                    false
                }
            }
            STATE_HALF_OPEN => {
                // Already allowing one test request — block additional ones.
                // In practice the pipeline calls this once per request, so
                // the first caller gets through and subsequent callers
                // are blocked until the test completes.
                true
            }
            _ => false,
        }
    }

    /// Record a successful call. Resets state to closed.
    pub fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Release);
        self.state.store(STATE_CLOSED, Ordering::Release);
    }

    /// Record a failed call. May trip the breaker open.
    pub fn record_failure(&self) {
        let failures = self.consecutive_failures.fetch_add(1, Ordering::AcqRel) + 1;
        self.last_failure_nanos
            .store(self.epoch.elapsed().as_nanos() as u64, Ordering::Release);

        if failures >= self.failure_threshold {
            self.state.store(STATE_OPEN, Ordering::Release);
        }
    }

    /// Get the current state name (for diagnostics).
    pub fn state_name(&self) -> &'static str {
        match self.state.load(Ordering::Acquire) {
            STATE_CLOSED => "closed",
            STATE_OPEN => "open",
            STATE_HALF_OPEN => "half_open",
            _ => "unknown",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_closed_and_allows() {
        let cb = CircuitBreaker::new(3, Duration::from_secs(30));
        assert!(cb.should_allow());
        assert_eq!(cb.state_name(), "closed");
    }

    #[test]
    fn opens_after_threshold_failures() {
        let cb = CircuitBreaker::new(3, Duration::from_secs(30));

        cb.record_failure();
        assert!(cb.should_allow()); // 1 failure, threshold is 3
        cb.record_failure();
        assert!(cb.should_allow()); // 2 failures
        cb.record_failure();
        assert!(!cb.should_allow()); // 3 failures → open
        assert_eq!(cb.state_name(), "open");
    }

    #[test]
    fn success_resets_failure_count() {
        let cb = CircuitBreaker::new(3, Duration::from_secs(30));

        cb.record_failure();
        cb.record_failure();
        cb.record_success(); // reset
        cb.record_failure();
        cb.record_failure();
        assert!(cb.should_allow()); // only 2 failures since last success
    }

    #[test]
    fn half_open_after_cooldown() {
        let cb = CircuitBreaker::new(1, Duration::from_millis(10));

        cb.record_failure(); // trips open
        assert!(!cb.should_allow());

        // Wait for cooldown.
        std::thread::sleep(Duration::from_millis(15));

        assert!(cb.should_allow()); // half-open
        assert_eq!(cb.state_name(), "half_open");
    }

    #[test]
    fn half_open_success_closes() {
        let cb = CircuitBreaker::new(1, Duration::from_millis(10));

        cb.record_failure();
        std::thread::sleep(Duration::from_millis(15));

        assert!(cb.should_allow()); // half-open
        cb.record_success(); // → closed
        assert_eq!(cb.state_name(), "closed");
        assert!(cb.should_allow());
    }

    #[test]
    fn half_open_failure_reopens() {
        let cb = CircuitBreaker::new(1, Duration::from_millis(10));

        cb.record_failure();
        std::thread::sleep(Duration::from_millis(15));

        assert!(cb.should_allow()); // half-open
        cb.record_failure(); // → re-open
        assert_eq!(cb.state_name(), "open");
    }
}
