use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Sliding window rate limiter keyed by domain.
///
/// Each domain maintains a list of request timestamps. When a check is
/// performed, expired timestamps outside the window are pruned first.
pub struct RateLimiter {
    /// domain → list of request timestamps
    windows: Mutex<HashMap<String, Vec<Instant>>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            windows: Mutex::new(HashMap::new()),
        }
    }

    /// Check if a request is allowed under the rate limit.
    /// Returns `true` if allowed (and records the request), `false` if rate limited.
    pub fn check_and_record(&self, domain: &str, max_requests: u64, window_secs: u64) -> bool {
        let now = Instant::now();
        let window = Duration::from_secs(window_secs);
        let mut map = self.windows.lock().unwrap();
        let timestamps = map.entry(domain.to_string()).or_default();

        // Remove expired timestamps
        timestamps.retain(|t| now.duration_since(*t) < window);

        if timestamps.len() as u64 >= max_requests {
            return false;
        }

        timestamps.push(now);
        true
    }

    /// Get current request count for a domain within the given window.
    pub fn current_count(&self, domain: &str, window_secs: u64) -> u64 {
        let now = Instant::now();
        let window = Duration::from_secs(window_secs);
        let map = self.windows.lock().unwrap();
        map.get(domain)
            .map(|ts| {
                ts.iter()
                    .filter(|t| now.duration_since(**t) < window)
                    .count() as u64
            })
            .unwrap_or(0)
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn allows_requests_within_limit() {
        let limiter = RateLimiter::new();
        assert!(limiter.check_and_record("example.com", 3, 60));
        assert!(limiter.check_and_record("example.com", 3, 60));
        assert!(limiter.check_and_record("example.com", 3, 60));
    }

    #[test]
    fn denies_request_exceeding_limit() {
        let limiter = RateLimiter::new();
        assert!(limiter.check_and_record("example.com", 2, 60));
        assert!(limiter.check_and_record("example.com", 2, 60));
        assert!(!limiter.check_and_record("example.com", 2, 60));
    }

    #[test]
    fn window_expiration_allows_again() {
        let limiter = RateLimiter::new();
        // Fill up the limit with window_secs=1
        assert!(limiter.check_and_record("example.com", 2, 1));
        assert!(limiter.check_and_record("example.com", 2, 1));
        assert!(!limiter.check_and_record("example.com", 2, 1));

        // Wait for window to expire
        thread::sleep(Duration::from_millis(1100));

        // Should be allowed again
        assert!(limiter.check_and_record("example.com", 2, 1));
    }

    #[test]
    fn independent_counters_per_domain() {
        let limiter = RateLimiter::new();
        assert!(limiter.check_and_record("a.com", 1, 60));
        assert!(!limiter.check_and_record("a.com", 1, 60));

        // Different domain should still be allowed
        assert!(limiter.check_and_record("b.com", 1, 60));
    }

    #[test]
    fn current_count_reflects_recorded_requests() {
        let limiter = RateLimiter::new();
        assert_eq!(limiter.current_count("example.com", 60), 0);

        limiter.check_and_record("example.com", 10, 60);
        assert_eq!(limiter.current_count("example.com", 60), 1);

        limiter.check_and_record("example.com", 10, 60);
        assert_eq!(limiter.current_count("example.com", 60), 2);
    }

    #[test]
    fn current_count_excludes_expired() {
        let limiter = RateLimiter::new();
        limiter.check_and_record("example.com", 10, 1);
        assert_eq!(limiter.current_count("example.com", 1), 1);

        thread::sleep(Duration::from_millis(1100));
        assert_eq!(limiter.current_count("example.com", 1), 0);
    }

    #[test]
    fn zero_max_requests_always_denies() {
        let limiter = RateLimiter::new();
        assert!(!limiter.check_and_record("example.com", 0, 60));
    }

    #[test]
    fn no_rate_limit_means_unlimited() {
        // When rate_limit is None in config, check_and_record is never called.
        // This test verifies high limits work fine.
        let limiter = RateLimiter::new();
        for _ in 0..1000 {
            assert!(limiter.check_and_record("example.com", 10000, 60));
        }
    }

    #[test]
    fn concurrent_access_is_safe() {
        use std::sync::Arc;

        let limiter = Arc::new(RateLimiter::new());
        let mut handles = vec![];

        for _ in 0..10 {
            let l = Arc::clone(&limiter);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    l.check_and_record("example.com", 5000, 60);
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        // All 1000 requests should have been recorded
        assert_eq!(limiter.current_count("example.com", 60), 1000);
    }

    #[test]
    fn denied_requests_are_not_recorded() {
        let limiter = RateLimiter::new();
        assert!(limiter.check_and_record("example.com", 2, 60));
        assert!(limiter.check_and_record("example.com", 2, 60));
        // This one is denied
        assert!(!limiter.check_and_record("example.com", 2, 60));
        // Count should still be 2, not 3
        assert_eq!(limiter.current_count("example.com", 60), 2);
    }
}
