//! DNS Cache

use crate::{
    *,
    entry::*,
};

/// in-memory DNS Cache that focus to cache hit ratio.
/// 1. if query miss it just waiting.
/// 2. if response exists but TTL expired, it start update task in background.
/// 3. if response exists and TTL does not expired, cache hit.
#[derive(Debug, Clone)]
pub struct DNSCache {
    map: Arc<moka::future::Cache<DNSQuery, DNSEntry>>,
}

impl DNSCache {
    pub fn new() -> Self {
        Self {
            map: moka::future::Cache::default(),
        }
    }
}
