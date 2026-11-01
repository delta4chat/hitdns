//! DNS Cache

use crate::{
    *,
    query::*,
    entry::*,
    database::*,
    resolver::*,
};

use asyncute::sdd;

#[derive(Debug)]
pub struct DNSCacheEntryInner {
    query: Arc<dyn DNSQuery>,
    entry: Atom<DNSEntry>,
    updating: AtomicBool,
    update_notify: Event,
}

#[derive(Debug, Clone)]
pub struct DNSCacheEntry {
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
            inner: Arc::new(DNSCacheEntryInner {
                query,
                entry: entry.into(),
                updating: AtomicBool::new(false),
                update_notify: Event::new(),
            }),
        }
    }

    pub fn get_query<'a>(&'a self) -> &'a Arc<dyn DNSQuery> {
        &self.query
    }

    pub fn get_entry(&self) -> Option<sdd::Shared<DNSEntry>> {
        self.entry.get()
    }

    pub fn set_entry(&self, entry: DNSEntry) {
        log::warn!("cache set entry {:?}", entry);
        self.entry.set(entry);
    }

    pub fn is_updating(&self) -> bool {
        self.updating.load(ATOM_LOAD)
    }

    pub async fn update(
        &self,
        resolver: DNSResolver,
        selector: DNSUpstreamSelector,
    ) -> std::io::Result<DNSEntry> {
        if self.updating.compare_exchange(false, true, ATOM_RMW, ATOM_LOAD).is_err() {
            // another update task is running
            return Err(std::io::Error::new(std::io::ErrorKind::ResourceBusy, "this DNSCacheEntry is already update progress."));
        }

        let mut defer =
            asyncute::Defer::new(|| {
                self.updating.store(false, ATOM_STORE);
            });

        match resolver.resolve(self.query.deref(), selector).timeout(Self::UPDATE_TIMEOUT).await {
            Some(ret) => {
                match ret {
                    Ok(entry) => {
                        self.set_entry(entry.clone());
                        defer.run();
                        self.update_notify.notify_relaxed(usize::MAX);
                        Ok(entry)
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
                event_listen!(self.update_notify => update_notify_listener);
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

                .build_with_hasher(ahash::RandomState::new())
            },
            disk,
            resolver,
        }
    }

    pub async fn load_all<Q: DNSQueryExt+'static>(&self) -> std::io::Result<usize> {

        let loads = Arc::new(AtomicUsize::new(0));
        {
            let this = self.clone();
            let loads = loads.clone();
            self.disk.cache_scan::<Q>(move |query, entry| {
                let query: Arc<dyn DNSQuery> = Arc::new(query);
                async_io::block_on(async {
                    this.put(&query, &entry).await;
                });
                loads.fetch_add(1, ATOM_RMW);
                Ok(())
            }).await?;
        }
        let loads = loads.load(ATOM_LOAD);
        log::info!("loaded {} cache items from in-disk database.", loads);
        Ok(loads)
    }
    pub async fn load_one(&self, query: &Arc<dyn DNSQuery>) -> std::io::Result<()> {
        let entry = self.disk.cache_get(&**query).await?;
        self.put(query, &entry).await;
        Ok(())
    }

    /// try to get a DNSEntry from DNSCache:
    /// 1. first lookup in-memory cache, and return if any.
    /// 2. if in-memory cache miss, then try to load from in-disk database, and return if any.
    /// 3. if in-disk database miss, finally try to resolve.
    pub async fn get(
        &self,
        query: &Arc<dyn DNSQuery>,
        selector: DNSUpstreamSelector,
    ) -> DNSCacheStatus {
        let dce =
            self.memory
                .entry_by_ref(query)
                .or_insert_with(async {
                    DNSCacheEntry::new(
                        query.clone(),
                        None
                    )
                }).await.into_value();

        log::debug!("entering dce: {:?}", &dce);

        let update = || {
            if dce.is_updating() {
                log::debug!("already updating: not spawning update task");
            } else {
                log::debug!("spawning update task");
                let query = query.clone();
                let dce = dce.clone();
                let this = self.clone();
                let resolver = this.resolver.clone();

                asyncute::spawn(async move {
                    let entry = dce.update(resolver, selector).await.expect("DNSCacheEntry update failed");
                    this.disk.cache_put(query.deref(), &entry).await.expect("write to disk db failed");
                }).detach();
            }
        };

        let update_wait = Duration::from_millis(100);
        let mut i = 50u8; // max wait time = 5 seconds
        let entry =
            loop {
                log::debug!("loop {}", i);
                if i == 0 {
                    return DNSCacheStatus::Miss;
                }
                i -= 1;

                match dce.get_entry() {
                    Some(entry) => {
                        log::debug!("dce geted de: {:?}", &entry);
                        break entry;
                    },
                    _ => {
                        log::debug!("dce geted nothing");
                        if dbg!(self.load_one(query).await).is_ok() {
                            log::debug!("load_one ok");
                            i += 1;
                            continue;
                        }
                        log::debug!("load_one err");

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
    /// * return false if the DNSEntry is exists, and provided DNSEntry is older.
    /// * the parameters is passed by reference for "copy-on-write", so the `&DNSEntry` will only be cloned if needed to update it to DNSCacheEntry.
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

        // spawn background task to update in-disk database due to operation may causes a lot of time.
        let dbput = || {
            let query = query.clone();
            let entry = entry.clone();
            let disk = self.disk.clone();
            asyncute::spawn(async move {
                dbg!(disk.cache_put(query.deref(), &entry).await).expect("unable to store DNSEntry to disk!");
            }).detach();
        };

        // if called DNSCacheEntry::new
        if moka_entry.is_fresh() {
            dbput();
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

        dbput();
        true
    }
}
