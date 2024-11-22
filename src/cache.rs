//! In-memory DNS Cache

use crate::*;

use event_listener::Event;

pub use portable_atomic::{AtomicU32, AtomicBool};
pub use portable_atomic::Ordering::{Relaxed, SeqCst};

pub static MIN_TTL: AtomicU32 = AtomicU32::new(0);
pub static MAX_TTL: AtomicU32 = AtomicU32::new(u32::MAX);

/* ========== DNS Cache Status ========== */

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DNSCacheStatus {
    Hit(Arc<DNSEntry>),
    Expired(Arc<DNSEntry>),
    Miss,
}
impl DNSCacheStatus {
    pub fn is_hit(&self) -> bool {
        match self {
            Self::Hit(_) => true,
            _ => false
        }
    }
    pub fn is_expired(&self) -> bool {
        match self {
            Self::Expired(_) => true,
            _ => false
        }
    }
    pub fn is_miss(&self) -> bool {
        match self {
            Self::Miss => true,
            _ => false
        }
    }
}
impl From<Arc<DNSEntry>> for DNSCacheStatus {
    fn from(entry: Arc<DNSEntry>) -> DNSCacheStatus {
        if SystemTime::now() < entry.expire {
            DNSCacheStatus::Hit(entry)
        } else {
            DNSCacheStatus::Expired(entry)
        }
    }
}

impl TryInto<Arc<DNSEntry>> for DNSCacheStatus {
    type Error = anyhow::Error;
    fn try_into(self) -> anyhow::Result<Arc<DNSEntry>> {
        match self {
            Self::Hit(entry) => Ok(entry),
            Self::Expired(entry) => Ok(entry),
            Self::Miss => {
                anyhow::bail!("no valid DNSEntry due to never success!")
            },
        }
    }
}

pub struct Defer {
    called: bool,
    f: Box<dyn FnMut()->()>,
}
impl Defer {
    pub fn new(f: impl FnMut()->() + 'static) -> Self {
        Self {
            called: false,
            f: Box::new(f),
        }
    }
    pub fn cancel(&mut self) {
        self.called = true;
    }
}
impl Drop for Defer {
    fn drop(&mut self) {
        if self.called {
            return;
        }

        self.called = true;

        (self.f)();
    }
}

unsafe impl Send for Defer {}

/* ========== DNS Cache Entry ========== */
#[derive(Debug, Clone)]
pub struct DNSCacheEntry {
    query: Arc<DNSQuery>,

    pub(crate) entry: Arc<RwLock<
                        Option<Arc<DNSEntry>>
                      >>,

    update_task: Arc<RwLock<
                   Option<Arc<
                     smol::Task<anyhow::Result<()>>
                   >>
                 >>,

    updating: Arc<AtomicBool>,
    update_event: Arc<Event>,
}
impl From<Arc<DNSQuery>> for DNSCacheEntry {
    fn from(query: Arc<DNSQuery>) -> DNSCacheEntry {
        DNSCacheEntry {
            query,
            entry: Arc::new(RwLock::new(None)),
            update_task: Arc::new(RwLock::new(None)),

            updating: Arc::new(AtomicBool::new(false)),
            update_event: Arc::new(Event::new()),
        }
    }
}
impl From<Arc<DNSEntry>> for DNSCacheEntry {
    fn from(entry: Arc<DNSEntry>) -> DNSCacheEntry {
        let query = entry.query.clone();

        let mut this: DNSCacheEntry = Arc::new(query).into();

        this.entry = Arc::new(RwLock::new(Some(entry)));

        this
    }
}

impl DNSCacheEntry {
    pub async fn status(&self) -> DNSCacheStatus {
        if let Some(entry) = self.entry.read().await.deref().clone() {
            entry.into()
        } else {
            DNSCacheStatus::Miss
        }
    }

    // wait until finish.
    pub async fn wait(&self) {
        let mut zzz = false;
        while self.is_updating().await {
            log::debug!(
                "{:?} still in updating...",
                self.query
            );

            if zzz {
                smol::Timer::after(Duration::from_millis(50)).await;
            } else {
                zzz = true;
            }

            if let None =
                self.update_event.listen()
                .timeout(Duration::from_millis(100))
                .await
            {
                log::trace!("timed out for waiting event from update_event");
                continue;
            } else {
                log::debug!("geted notify from event!");
                break;
            }
        }
    }

    pub async fn is_updating(&self) -> bool {
        if self.updating.load(SeqCst) {
            return true;
        }

        // smol-timeout Option
        if let Some(maybe_task) =
            self.update_task.read()
            .timeout(Duration::from_millis(100))
            .await
        {
            // Option<smol::Task>
            if let Some(task) = maybe_task.deref().clone() {
                ! task.is_finished()
            } else {
                false
            }
        } else {
            log::warn!("get read lock timeout!!!");
            true
        }
    }

    pub async fn expire(&self) -> bool {
        let maybe_ade = &mut *self.entry.write().await;
        if let Some(ade) = maybe_ade {
            let de = Arc::get_mut(ade).expect("should only one mutable writer due to it behind a RwLock");
            de.expire = SystemTime::UNIX_EPOCH;
            true
        } else {
            false
        }
    }

    /// (if caller does not provide a resolver, this method just query cached DNSEntry and any Cache Miss will cause Error.)
    ///
    /// if DNSEntry does not exipre, return immediately.
    /// if DNSEntry exists and expired, starting a background task for updating that, then return expired result.
    /// if DNSEntry does not exists, start a foreground task, waiting until it successfully or timed out.
    ///
    /// NOTE: this method promises that a new update task is never started repeatedly while another task is running, so only one task will be running at same time.
    pub async fn update(
        &self,
        maybe_resolver: Option<Arc<dyn DNSResolver>>,
        timeout: Duration,
    ) -> anyhow::Result<Arc<DNSEntry>> {
        let status = self.status().await;

        // no need update a un-expired DNSRecord.
        // cache hit.
        if let DNSCacheStatus::Hit(entry) = status {
            return Ok(entry);
        }

        if self.is_updating().await {
            log::debug!(
                "{:?} another update processing.",
                self.query
            );

            if let DNSCacheStatus::Miss = status {
                log::debug!("{:?} no last success result. force waiting until first result producted.", self.query);

                self.wait().await;
                return self.status().await.try_into();
            }

            // return last success result (but expired)
            return status.try_into();
        }

        // starting update task for updating expired result
        if let Some(ref resolver) = maybe_resolver {
            let resolver = resolver.clone();

            let entry_lock = self.entry.clone();
            let query = self.query.clone();

            let updating = self.updating.clone();
            let update_event = self.update_event.clone();

            let task = smolscale2::spawn(async move {
                let _guard = {
                    let u = updating.clone();
                    Defer::new(move || {
                        u.store(false, SeqCst);
                    })
                };
                updating.store(true, SeqCst);

                let upstream = resolver.dns_upstream();

                let start = Instant::now();
                let mut response = match timeout_helper(resolver.dns_resolve(&query), timeout).await {
                    Some(v) => { v? },
                    None => {
                        anyhow::bail!("resolving query {:?} from upstream {upstream:?} timed out: timeout={timeout:?}", &query);
                    }
                };
                let elapsed = start.elapsed();

                let expire_ttl: u32 = {
                    let min_ttl = MIN_TTL.load(Relaxed);
                    let max_ttl = MAX_TTL.load(Relaxed);

                    let mut ttl = response
                        .all_sections()
                        .map(|x| x.ttl())
                        .min()
                        .unwrap_or(min_ttl);

                    if ttl < min_ttl {
                        ttl = min_ttl;
                    }
                    if ttl > max_ttl {
                        ttl = max_ttl;
                    }

                    ttl
                };
                let expire = SystemTime::now() + Duration::from_secs(expire_ttl as u64);

                response.set_id(0);
                *response.extensions_mut() = None;

                let entry = Arc::new(DNSEntry {
                    query: query.deref().clone(),
                    response: response.to_vec()?,
                    elapsed,
                    upstream,
                    expire,
                });

                *entry_lock.write().await = Some(entry.clone());
                updating.store(false, Relaxed);
                log::debug!("send notify to {} listeners", update_event.notify_relaxed(usize::MAX));

                let query: Vec<u8> = bincode::serialize(&query).log_error()?;
                let entry: Vec<u8> = bincode::serialize(&entry).log_error()?;

                let _ =
                    sqlx::query("INSERT OR IGNORE INTO hitdns_cache_v1 VALUES (?1, ?2); UPDATE hitdns_cache_v1 SET entry = ?2 WHERE query = ?1")
                    .bind(query).bind(entry)
                    .execute(&*HITDNS_SQLITE_POOL)
                    .await.log_warn();

                Ok(())
            });

            *self.update_task.write().await = Some(Arc::new(task));
        }

        if let DNSCacheStatus::Miss = status {
            if maybe_resolver.is_none() {
                anyhow::bail!("DNSCacheEntry: Cache Miss but no resolver provided!");
            }

            // this is first query (or previous queries never success).
            // so must wait until finished.

            log::debug!("DNSCacheEntry: {:?} there no any previous success result, must wait...", self.query);
            self.wait().await;

            // return newset hit result.
            return self.status().await.try_into();
        }

        // return last success result (but expired)
        status.try_into()
    }
}

/* ========== DNS Cache ========== */
#[derive(Debug, Clone)]
pub struct DNSCache {
    pub(crate) memory: Arc<moka2::future::Cache<DNSQuery, DNSCacheEntry>>,
    load_negatives: Arc<scc::HashSet<DNSQuery>>,
    pub(crate) resolvers: Arc<DNSResolverArray>,
    pub(crate) debug: bool,
}
/// SAFETY: backend by scc::HashSet / moka2::future::Cache
unsafe impl Sync for DNSCache {}
unsafe impl Send for DNSCache {}

impl DNSCache {
    pub(crate) fn init() -> Self {
        let memory =
            Arc::new(
                moka2::future::Cache::builder()
                .max_capacity(10485760)
                .time_to_idle(Duration::from_secs(60*60)) // one hour for time-to-idle
                .time_to_live(Duration::from_secs(60*60*24*365*100)) // 100 years for time-to-live
                .async_eviction_listener(|_query, _entry, cause| {
                    Box::pin(async move {
                        use moka2::notification::RemovalCause::*;

                        if cause != Expired {
                            return;
                        }

                        /*
                        match bincode::serialize(&query) {
                            Ok(query) => {
                                let _ =
                                    sqlx::query("DELETE FROM hitdns_cache_v1 WHERE query = ?")
                                        .bind(query)
                                        .execute(&*HITDNS_SQLITE_POOL)
                                        .await;
                            }
                            _ => {}
                        }
                        */
                    })
                })
                .build()
            );

        let load_negatives = Arc::new(scc::HashSet::new());

        let debug = false;

        let resolvers = Arc::new(DNSResolverArray::from([]));

        Self {
            memory,
            load_negatives,
            resolvers,
            debug,
        }
    }

    pub async fn new(resolvers: DNSResolverArray, debug: bool) -> anyhow::Result<Self> {
        let mut this = Self::init();

        this.resolvers = Arc::new(resolvers);
        this.debug = debug;

        Ok(this)
    }

    pub(crate) async fn load_all(&self) -> anyhow::Result<()> {
        let mut ret = sqlx::query("SELECT * FROM hitdns_cache_v1").fetch(&*HITDNS_SQLITE_POOL);
        while let Ok(Some(line)) = ret.try_next().await {
            assert_eq!(line.columns().len(), 2);
            let query: Vec<u8> =
                line.try_get_raw(0)?
                .to_owned()
                .decode();
            let entry: Vec<u8> =
                line.try_get_raw(1)?
                .to_owned()
                .decode();

            let delete_fut = async {
                let _ =
                    sqlx::query("DELETE FROM hitdns_cache_v1 WHERE query = ?")
                    .bind(&query)
                    .execute(&*HITDNS_SQLITE_POOL)
                    .await;
            };

            let query: DNSQuery =
                match bincode::deserialize(&query).context("cannot deserialize 'query' from sqlite").log_error() {
                    Ok(v) => v,
                    _ => {
                        delete_fut.await;
                        continue;
                    }
                };
            let entry: DNSEntry =
                match bincode::deserialize(&entry).context("cannot deserialize 'entry' from sqlite").log_error() {
                    Ok(v) => v,
                    _ => {
                        delete_fut.await;
                        continue;
                    }
                };

            let cache_entry: DNSCacheEntry = Arc::new(entry).into();
            let _ = self.memory.insert(query, cache_entry).await;
        }
        Ok(())
    } // pub(crate) async fn load()

    /// NOTE: if one of rdclass or rdtype is not specified, this operation spends O(n) time.
    pub async fn expire(
        &self,
        name: impl ToString,
        maybe_rdclass: Option<u16>,
        maybe_rdtype: Option<u16>
    ) -> u128 {
        let name = {
            let mut n = name.to_string();
            if ! n.ends_with(".") {
                n.push('.');
            }
            n
        };

        let mut count = 0;

        if maybe_rdclass.is_some() && maybe_rdtype.is_some() {
            let query = DNSQuery {
                name: name,
                rdclass: maybe_rdclass.unwrap(),
                rdtype: maybe_rdtype.unwrap()
            };
            if let Some(dce) = self.memory.get(&query).await {
                if dce.expire().await {
                    count += 1;
                }
            }
            return count;
        }

        for (_, cur) in self.memory.iter() {
            if cur.query.name != name {
                continue;
            }
            if let Some(rdclass) = maybe_rdclass {
                if cur.query.rdclass != rdclass {
                    continue;
                }
            }
            if let Some(rdtype) = maybe_rdtype {
                if cur.query.rdtype != rdtype {
                    continue;
                }
            }

            if cur.expire().await {
                count += 1;
            }
        }
        count
    }

    // cached query (oldapi)
    pub async fn query(&self, req: dns::Message) -> anyhow::Result<dns::Message> {
        Ok(self.query_with_status(req).await?.0)
    }

    pub async fn load_one(&self, query: &DNSQuery) -> anyhow::Result<Arc<DNSEntry>> {
        if self.load_negatives.contains_async(query).await {
            anyhow::bail!("not to load {query} from disk! due it listed in negatives");
        }

        match self._load_one(query).await {
            Ok(val) => {
                Ok(val)
            },
            Err(err) => {
                log::debug!("unable to load {query} from disk: {err:?}...... maybe no entry found in disk? add it to negatives list to avoid high-freq disk read");
                let _ = self.load_negatives.insert_async(query.clone()).await;
                Err(err)
            }
        }
    }
    async fn _load_one(&self, query: &DNSQuery) -> anyhow::Result<Arc<DNSEntry>> {
        let line = {
            let query: Vec<u8> = bincode::serialize(query)?;

            sqlx::query("SELECT * FROM hitdns_cache_v1 WHERE query = ?")
                .bind(query)
                .fetch_one(&*HITDNS_SQLITE_POOL)
                .await?
        };

        let entry: Vec<u8> =
            line.try_get_raw(1)?
            .to_owned()
            .decode();

        let entry: DNSEntry = bincode::deserialize(&entry)?;
        let entry = Arc::new(entry);

        let cache_entry = entry.clone().into();
        let _ = self.memory.insert(query.clone(), cache_entry).await;

        Ok(entry)
    }

    // cached query with DNSCacheStatus
    pub async fn query_with_status(&self, req: dns::Message) -> anyhow::Result<(dns::Message, DNSCacheStatus)> {
        let started = Instant::now();

        let req_id: u16 = req.id();
        let query: DNSQuery = req.try_into().log_debug()?;
        log::debug!("DNSCache: received new query: id={req_id} query={:?}", &query);

        let mut cache_entry =
            self.memory
                .entry(query.clone())
                .or_insert_with(async { Arc::new(query.clone()).into() })
                .await
                .value().clone();

        let mut status = cache_entry.status().await;

        if status.is_miss() {
            if let Ok(entry) = self.load_one(&query).await {
                cache_entry = entry.into();
                status = cache_entry.status().await;
            }
        }

        let resolver =
            self.resolvers
            .best_or_random().await
            .log_warn()
            .ok();
        let entry =
            cache_entry.update(resolver, Duration::from_secs(10))
            .await
            .log_warn()?;

        let now_unix =
            SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .log_error()?;
        let expire_unix =
            entry.expire
            .duration_since(SystemTime::UNIX_EPOCH)
            .log_error()?;

        let mut res: dns::Message = entry.as_ref().try_into().log_warn()?;
        res.set_id(req_id);

        let ttl: u32 = if now_unix > expire_unix {
            0
        } else {
            (expire_unix - now_unix).as_secs() as u32
        };

        for record in res.answers_mut() {
            record.set_ttl(ttl);
        }
        for record in res.name_servers_mut() {
            record.set_ttl(ttl);
        }
        for record in res.additionals_mut() {
            record.set_ttl(ttl);
        }

        log::debug!("DNSCache: got response! id={req_id} query={:?} elapsed={:?} response={res:?}", cache_entry.query, started.elapsed());
        Ok((res, status))
    }
}
