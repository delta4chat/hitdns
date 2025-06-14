//! DNS Cache

use crate::{
    *,
    query::*,
    entry::*,
    database::*,
    resolver::*,
};

#[derive(Debug)]
pub struct DNSCacheEntryInner {
    updating: AtomicBool,
    update_notify: Event,
}

#[derive(Debug, Clone)]
pub struct DNSCacheEntry {
    query: Arc<dyn DNSQuery>,
    entry: sdd::AtomicShared<DNSEntry>,

    inner: Arc<DNSCacheEntryInner>,
}

impl Deref for DNSCacheEntry {
    type Target = DNSCacheEntryInner;

    fn deref<'a>(&'a self) -> &'a DNSCacheEntryInner {
        self.inner.as_ref()
    }
}

impl DNSCacheEntry {
    pub const UPDATE_TIMEOUT: Duration = Duration::from_secs(10);

    pub fn new(query: Arc<dyn DNSQuery>, entry: Option<DNSEntry>) -> Self {
        Self {
            query,
            entry: entry.map(sdd::AtomicShared::new).unwrap_or_else(sdd::AtomicShared::null),
            inner: Arc::new(DNSCacheEntryInner {
                updating: AtomicBool::new(false),
                update_notify: Event::new(),
            }),
        }
    }

    pub fn get_query<'a>(&'a self) -> &'a Arc<dyn DNSQuery> {
        &self.query
    }

    pub fn get_entry(&self) -> Option<sdd::Shared<DNSEntry>> {
        let g = sdd::Guard::new();
        self.entry.get_shared(Relaxed, &g)
    }

    pub fn set_entry(&self, entry: DNSEntry) {
        let entry = sdd::Shared::new(entry);
        self.entry.swap(
            (Some(entry), sdd::Tag::None),
            Relaxed
        );
    }

    pub fn is_updating(&self) -> bool {
        self.updating.load(Relaxed)
    }

    pub fn update(
        &self,
        resolver: DNSResolver,
        selector: DNSUpstreamSelector,
    ) -> Option<impl Fut<std::io::Result<()>>> {
        if self.updating.compare_exchange(false, true, Relaxed, Relaxed).is_err() {
            // another update task is running
            return None;
        }

        let this = self.clone();

        let mut defer = {
            let this = self.clone();
            asyncute::Defer::new(move || {
                this.updating.store(false, Relaxed);
            })
        };

        Some(async move {
            match resolver.resolve(&this.query, selector).timeout(Self::UPDATE_TIMEOUT).await {
                Some(ret) => {
                    match ret {
                        Ok(entry) => {
                            this.set_entry(entry);
                            this.update_notify.notify_relaxed(usize::MAX);
                            defer.run();
                            Ok(())
                        },
                        Err(e) => {
                            defer.run();
                            Err(e)
                        }
                    }
                },
                _ => {
                    Err(
                        std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "DNSCacheEntry::update() timed out"
                        )
                    )
                }
            }
        })
    }

    pub async fn wait_timeout(&self, timeout: Duration) -> bool {
        match Instant::now().checked_add(timeout) {
            Some(deadline) => self.wait_deadline(deadline).await,
            _ => false,
        }
    }

    pub async fn wait_deadline(&self, deadline: Instant) -> bool {
        while self.is_updating() {
            if Instant::now() >= deadline {
                return false;
            }

            // start listening
            {
                listener!(self.update_notify => update_notify_listener);
                update_notify_listener.deadline(deadline).await;
            }
        }
        true
    }
}

#[derive(Debug, Clone)]
#[repr(u8)]
pub enum DNSCacheStatus {
    Hit(sdd::Shared<DNSEntry>),
    Expired(sdd::Shared<DNSEntry>),
    Miss,
}

impl DNSCacheStatus {
    pub fn tuple<'g>(&self, g: &'g sdd::Guard) -> (u8, Option<&'g DNSEntry>) {
        use DNSCacheStatus::*;
        match self {
            Hit(e) => {
                (b'H', Some(e.get_guarded_ref(g)))
            },
            Expired(e) => {
                (b'E', Some(e.get_guarded_ref(g)))
            },
            Miss => {
                (b'M', None)
            }
        }
    }
}

impl PartialEq for DNSCacheStatus {
    fn eq(&self, other: &Self) -> bool {
        let g = sdd::Guard::new();
        self.tuple(&g) == other.tuple(&g)
    }
}
impl Eq for DNSCacheStatus {}

/// in-memory DNS Cache that focus to cache hit ratio.
/// 1. if query miss, start update task and waiting.
/// 2. if response exists but TTL expired, it start update task in background.
/// 3. if response exists and TTL does not expired, cache hit.
#[derive(Debug, Clone)]
pub struct DNSCache {
    memory: MokaCache<Arc<dyn DNSQuery>, DNSCacheEntry>,
    disk: DNSDatabase,

    resolver: DNSResolver,
}

impl DNSCache {
    pub fn new(disk: DNSDatabase, resolver: DNSResolver) -> Self {
        Self {
            memory: {
                MokaCacheBuilder::default()
                .name("hitdns in-memory cache")
                .max_capacity(10485760)
                //.async_eviction_listener(|_query, _entry, cause| {})
                .time_to_idle(Duration::from_secs(60*60)) // one hour for time-to-idle

                /* !!! NOTE do not set this, because moka by default is not doing calculate of time to live, so set this causes useless calculation.
                            .time_to_live(Duration::from_secs(60*60*24*365*100))
                */

                .build_with_hasher(ahash::RandomState::default())
            },
            disk,
            resolver,
        }
    }

    pub async fn get(&self, query: &Arc<dyn DNSQuery>, selector: DNSUpstreamSelector) -> DNSCacheStatus {
        let dce =
            self.memory
                .entry_by_ref(query)
                .or_insert_with(async {
                    DNSCacheEntry::new(
                        query.clone(),
                        None
                    )
                }).await.into_value();

        let update = || {
            let dce = dce.clone();
            let resolver = self.resolver.clone();
            if let Some(fut) = dce.update(resolver, selector) {
                asyncute::spawn(async move {
                    fut.await.expect("DNSCacheEntry update failed");
                }).detach();
            }
        };

        let update_wait = Duration::from_millis(100);
        let mut i = 50; // max wait time = 5 seconds
        let entry =
            loop {
                if i == 0 {
                    return DNSCacheStatus::Miss;
                }
                i -= 1;

                match dce.get_entry() {
                    Some(entry) => {
                        break entry;
                    },
                    _ => {
                        update();
                        dce.wait_timeout(update_wait).await;
                    }
                }
            };

        let now = SystemTime::now();
        if now < entry.expire_time {
            DNSCacheStatus::Hit(entry)
        } else {
            update();
            DNSCacheStatus::Expired(entry)
        }
    }

    /// update the DNSEntry.
    /// return false if the DNSEntry is exists, and provided DNSEntry is older.
    ///
    /// the parameters is passed by reference for "copy-on-write", so the `&DNSEntry` will only be cloned if needed to update it to DNSCacheEntry.
    pub async fn put(&self, query: &Arc<dyn DNSQuery>, entry: &DNSEntry) -> bool {
        let moka_entry =
            self.memory
                .entry_by_ref(query)
                .or_insert_with(async move {
                    DNSCacheEntry::new(
                        query.clone(),
                        Some(entry.clone()),
                    )
                }).await;

        // if called DNSCacheEntry::new
        if moka_entry.is_fresh() {
            return true;
        }

        // if this DNSCacheEntry is already exists.
        // so compare two value...

        let dce = moka_entry.into_value();

        if let Some(old_entry) = dce.get_entry() {
            if old_entry.expire_time > entry.expire_time {
                return false;
            }
        }

        dce.set_entry(entry.clone());
        true
    }
}
