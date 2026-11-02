//! The pluggable cache for signing keys, client credentials tokens and logout token replay.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use async_trait::async_trait;

/// A string key-value store with expiry. Values are JSON documents the crate writes and reads
/// back itself, so any store works (Redis, a database table, a process-local map).
///
/// Implementations swallow their own failures: a miss is `None` and a failed write is a no-op,
/// because the cache only saves requests and never holds the only copy of anything.
#[async_trait]
pub trait Cache: Send + Sync + 'static {
    /// The live value for `key`.
    async fn get(&self, key: &str) -> Option<String>;

    /// Stores `value` for `ttl`.
    async fn set(&self, key: &str, value: String, ttl: Duration);

    /// Removes `key`.
    async fn delete(&self, key: &str);

    /// Stores `value` only when `key` has no live value; returns whether it was stored.
    ///
    /// Back-channel logout replay protection relies on this. The default implementation is
    /// `get` followed by `set` and therefore not atomic: two concurrent calls can both succeed.
    /// Override it with an atomic operation (Redis `SET NX`) when that matters.
    async fn add(&self, key: &str, value: String, ttl: Duration) -> bool {
        if self.get(key).await.is_some() {
            return false;
        }
        self.set(key, value, ttl).await;
        true
    }
}

/// The default cache: a process-local map with expiry.
#[derive(Debug, Default)]
pub struct MemoryCache {
    entries: Mutex<HashMap<String, (String, Instant)>>,
}

impl MemoryCache {
    /// An empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, (String, Instant)>> {
        // A poisoned lock only means another thread panicked mid-write; the map stays usable.
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[async_trait]
impl Cache for MemoryCache {
    async fn get(&self, key: &str) -> Option<String> {
        let mut entries = self.lock();
        match entries.get(key) {
            Some((value, expires)) if *expires > Instant::now() => Some(value.clone()),
            Some(_) => {
                entries.remove(key);
                None
            }
            None => None,
        }
    }

    async fn set(&self, key: &str, value: String, ttl: Duration) {
        let now = Instant::now();
        let mut entries = self.lock();
        entries.retain(|_, (_, expires)| *expires > now);
        entries.insert(key.to_owned(), (value, now + ttl));
    }

    async fn delete(&self, key: &str) {
        self.lock().remove(key);
    }

    async fn add(&self, key: &str, value: String, ttl: Duration) -> bool {
        let now = Instant::now();
        let mut entries = self.lock();
        if entries.get(key).is_some_and(|(_, expires)| *expires > now) {
            return false;
        }
        entries.insert(key.to_owned(), (value, now + ttl));
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn entries_expire_and_add_does_not_overwrite() {
        let cache = MemoryCache::new();
        cache.set("a", "1".into(), Duration::from_millis(30)).await;
        assert_eq!(cache.get("a").await.as_deref(), Some("1"));
        assert!(!cache.add("a", "2".into(), Duration::from_secs(60)).await);

        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(cache.get("a").await, None);
        assert!(cache.add("a", "3".into(), Duration::from_secs(60)).await);
        assert_eq!(cache.get("a").await.as_deref(), Some("3"));

        cache.delete("a").await;
        assert_eq!(cache.get("a").await, None);
    }
}
