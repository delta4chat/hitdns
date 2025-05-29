//! DNS Cache

use crate::{
    *,
    query::*,
    entry::*,
};

/// notify to update DNS Entry by resolving.
/// * this should queues to some task channel.
/// * this must not blocking.
pub trait ResolveNotify: Fn(&dyn DNSQuery) + Send + Sync + fmt::Debug {}

#[derive(Debug)]
pub struct DNSCacheEntryInner {
    updating: Arc<AtomicBool>,
    update_notify: Arc<Event>,
}

#[derive(Debug, Clone)]
pub struct DNSCacheEntry {
    entry: sdd::AtomicShared<DNSEntry>,
    inner: Arc<DNSCacheEntryInner>,
}

impl Deref for DNSCacheEntry {
    type Target = DNSCacheEntryInner;

    fn deref(&self) -> &DNSCacheEntryInner {
        self.inner.as_ref()
    }
}

impl DNSCacheEntry {
    pub fn new(entry: Option<DNSEntry>) -> Self {
        let update_notify = Arc::new(Event::new());
        Self {
            entry: entry.map(sdd::AtomicShared::new).unwrap_or_else(sdd::AtomicShared::null),
            update_notify,
        }
    }

    pub fn wait_timeout(&self, timeout: Duration) -> bool {
        match Instant::now().checked_add(timeout) {
            Some(deadline) => self.wait_deadline(deadline),
            _ => false,
        }
    }

    pub fn wait_deadline(&self, deadline: Instant) -> bool {
        while self.updating.load(Relaxed) {
            if Instant::now() >= deadline {
                return false;
            }

            // start listening
            {
                listener!(self.update_notify => update_notify_listener);
                update_notify_listener.wait_deadline(deadline);
            }
        }
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DNSCacheStatus {
    Hit(Arc<DNSEntry>),
    Expired(Arc<DNSEntry>),
    Miss,
}

/// in-memory DNS Cache that focus to cache hit ratio.
/// 1. if query miss it just waiting.
/// 2. if response exists but TTL expired, it start update task in background.
/// 3. if response exists and TTL does not expired, cache hit.
#[derive(Debug, Clone)]
pub struct DNSCache {
    memory: moka::future::Cache<Arc<dyn DNSQuery>, Arc<DNSEntry>, ahash::RandomState>,
    //disk: DNSDatabase,

    resolve_notify: Arc<dyn ResolveNotify>,
}

impl DNSCache {
    pub fn new(resolve_notify: Arc<dyn ResolveNotify>) -> Self {
        Self {
            memory: {
                moka::future::Cache::builder()
                .name("hitdns in-memory cache")
                .max_capacity(10485760)
                .time_to_idle(Duration::from_secs(60*60)) // one hour for time-to-idle
                .time_to_live(Duration::from_secs(60*60*24*365*100)) // 100 years for time-to-live
                //.async_eviction_listener(|_query, _entry, cause| {})
                .build_with_hasher(ahash::RandomState::default())
            },
            resolve_notify,
        }
    }

    pub async fn get(&self, query: &Arc<dyn DNSQuery>) -> DNSCacheStatus {
        if let Some(entry) = self.memory.get(query).await {
            let now = SystemTime::now();
            if now < entry.expire_time {
                DNSCacheStatus::Hit(entry)
            } else {
                if entry.update_count.fetch_add(1, Relaxed) % 1000 == 0 {
                    (self.resolve_notify)(&**query);
                }
                DNSCacheStatus::Expired(entry)
            }
        } else {
            //let entry = self.disk.get(query);
            DNSCacheStatus::Miss
        }
    }

    /// update the DNSEntry.
    /// return false if the DNSEntry is exists, and provided DNSEntry is older.
    pub async fn put(&self, query: &Arc<dyn DNSQuery>, entry: &Arc<DNSEntry>) -> bool {
        if self.memory.contains_key(query) {
            if let Some(old_entry) = self.memory.get(query).await {
                if old_entry.expire_time > entry.expire_time {
                    return false;
                }
            }
        }

        self.memory.insert(query.clone(), entry.clone()).await;

        true
    }
}
