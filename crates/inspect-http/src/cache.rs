//! Response caching — LRU cache with TTL for analyzer responses.

use std::time::{Duration, Instant};

use lru::LruCache;
use parking_lot::Mutex;

use crate::protocol::AnalyzerResponse;

/// Cache key: blake3 hash of (analyzer_name + body).
pub type CacheKey = [u8; 32];

/// Cached analyzer response with expiration.
struct CachedEntry {
    response: AnalyzerResponse,
    cached_at: Instant,
}

/// LRU cache for analyzer responses, keyed by content hash.
pub struct AnalyzerCache {
    cache: Mutex<LruCache<CacheKey, CachedEntry>>,
    ttl: Duration,
}

impl AnalyzerCache {
    /// Create a new cache with the given capacity and TTL.
    pub fn new(max_entries: usize, ttl: Duration) -> Self {
        let cap = std::num::NonZeroUsize::new(max_entries.max(1)).unwrap();
        Self {
            cache: Mutex::new(LruCache::new(cap)),
            ttl,
        }
    }

    /// Compute a cache key from analyzer name and body content.
    pub fn compute_key(analyzer_name: &str, body: &[u8]) -> CacheKey {
        let mut hasher = blake3::Hasher::new();
        hasher.update(analyzer_name.as_bytes());
        hasher.update(b"|");
        hasher.update(body);
        *hasher.finalize().as_bytes()
    }

    /// Get a cached response, or `None` if not found or expired.
    pub fn get(&self, key: &CacheKey) -> Option<AnalyzerResponse> {
        let mut cache = self.cache.lock();
        if let Some(entry) = cache.get(key) {
            if entry.cached_at.elapsed() < self.ttl {
                return Some(entry.response.clone());
            }
            // Expired — remove it.
            cache.pop(key);
        }
        None
    }

    /// Store a response in the cache.
    pub fn put(&self, key: CacheKey, response: AnalyzerResponse) {
        let entry = CachedEntry {
            response,
            cached_at: Instant::now(),
        };
        self.cache.lock().put(key, entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::AnalyzerFinding;

    fn sample_response() -> AnalyzerResponse {
        AnalyzerResponse {
            findings: vec![AnalyzerFinding {
                finding_type: "test".into(),
                severity: "low".into(),
                detail: Some("detail".into()),
                action: None,
            }],
            verdict: Some("allow".into()),
        }
    }

    #[test]
    fn cache_hit() {
        let cache = AnalyzerCache::new(100, Duration::from_secs(60));
        let key = AnalyzerCache::compute_key("test-analyzer", b"hello world");

        cache.put(key, sample_response());

        let result = cache.get(&key);
        assert!(result.is_some());
        assert_eq!(result.unwrap().findings.len(), 1);
    }

    #[test]
    fn cache_miss() {
        let cache = AnalyzerCache::new(100, Duration::from_secs(60));
        let key = AnalyzerCache::compute_key("test-analyzer", b"hello world");

        let result = cache.get(&key);
        assert!(result.is_none());
    }

    #[test]
    fn cache_different_body_misses() {
        let cache = AnalyzerCache::new(100, Duration::from_secs(60));
        let key1 = AnalyzerCache::compute_key("analyzer", b"body1");
        let key2 = AnalyzerCache::compute_key("analyzer", b"body2");

        cache.put(key1, sample_response());

        assert!(cache.get(&key1).is_some());
        assert!(cache.get(&key2).is_none());
    }

    #[test]
    fn cache_ttl_expiry() {
        let cache = AnalyzerCache::new(100, Duration::from_millis(10));
        let key = AnalyzerCache::compute_key("test", b"body");

        cache.put(key, sample_response());
        assert!(cache.get(&key).is_some());

        std::thread::sleep(Duration::from_millis(15));
        assert!(cache.get(&key).is_none());
    }

    #[test]
    fn cache_lru_eviction() {
        let cache = AnalyzerCache::new(2, Duration::from_secs(60));

        let key1 = AnalyzerCache::compute_key("a", b"1");
        let key2 = AnalyzerCache::compute_key("a", b"2");
        let key3 = AnalyzerCache::compute_key("a", b"3");

        cache.put(key1, sample_response());
        cache.put(key2, sample_response());
        cache.put(key3, sample_response()); // evicts key1

        assert!(cache.get(&key1).is_none());
        assert!(cache.get(&key2).is_some());
        assert!(cache.get(&key3).is_some());
    }
}
