use std::time::{Duration, Instant, SystemTime};

use std::sync::Arc;
use std::pin::Pin;
use std::ops::Deref;

mod dns {
    pub use hickory_proto::op::*;
    pub use hickory_proto::rr::IntoName;

    pub use hickory_proto::rr::LowerName;
    pub use LowerName as Name;

    pub use hickory_proto::rr::dns_class::DNSClass;
    pub use DNSClass as Class;
    pub use DNSClass as RdClass;

    pub use hickory_proto::rr::record_type::RecordType;
    pub use RecordType as Type;
    pub use RecordType as RdType;
}

use serde::{Serialize, Deserialize};
use bytes::Bytes;

use std::net::{SocketAddr, IpAddr};
use smol::net::AsyncToSocketAddrs;

use smol::net::UdpSocket;
use smol::net::{TcpListener, TcpStream};

use smol::io::{AsyncReadExt, AsyncWriteExt};
use smol::stream::{StreamExt};

use smol::future::Future;

use smol::channel::{Sender, Receiver};

#[cfg(feature="sqlite")]
use sqlx::{
    sqlite::{SqlitePool, SqlitePoolOptions, SqliteConnectOptions, SqliteJournalMode, SqliteLockingMode, SqliteSynchronous},
    {Row, Value, ValueRef},
};

use async_lock::RwLock;

use smol_timeout::TimeoutExt;

// a helper for wrapping non-Sized
async fn timeout_helper<T>(
    fut: impl Future<Output=T>,
    time: Duration
) -> Option<T> {
    let fut = async move { fut.await };
    fut.timeout(time).await
}

use once_cell::sync::Lazy;
use std::path::PathBuf;

use anyhow::Context;

// command line argument parser
use clap::Parser;

use core::fmt::Debug;
use core::iter::Sum;
use core::ops::{Add, Div};

/*
trait Average<T>: Sum<T> {
    fn average(&self) -> T;
}

impl Average<Duration> for dyn Iterator<Item=Duration> {
    fn average(&self) -> Duration {
        /*
        let mut secs: Vec<f64> = vec![];
        for dur in self.iter() {
            secs.push(dur.as_secs_f64());
        }*/
        let len = self.count();
        let avg = self.sum().as_secs_f64() / len as f64;
        Duration::from_secs_f64(avg)
    }
}*/

fn average<T>(set: &[T]) -> T
where
    T: Default + Copy + From<u64> +
    Add<Output=T> + Div<Output=T>
{
    let len = set.len();
    if len > 0 {
        let len: T = T::from(len as u64);
        let mut sum: T = Default::default();
        for n in set.iter() {
            sum = sum + *n;
        }
        sum / len
    } else {
        Default::default()
    }
}

trait LogResult: Debug + Sized {
    fn log_generic(self, level: log::Level) -> Self;

    fn log_error(self) -> Self {
        self.log_generic(log::Level::Error)
    }

    fn log_warn(self) -> Self {
        self.log_generic(log::Level::Warn)
    }

    fn log_info(self) -> Self {
        self.log_generic(log::Level::Info)
    }

    fn log_debug(self) -> Self {
        self.log_generic(log::Level::Debug)
    }
    fn log_trace(self) -> Self {
        self.log_generic(log::Level::Trace)
    }
}

impl<T: Debug, E: Debug> LogResult for Result<T, E> {
    fn log_generic(self, level: log::Level) -> Self {
        if let Err(_) = self {
            log::log!(level, "{:?}", self);
        }
        self
    }
}

static HITDNS_DIR: Lazy<PathBuf> = Lazy::new(||{
    let dir = directories::ProjectDirs::from("org", "delta4chat", "hitdns").expect("Cannot get platform-specified dir (via `directories::ProjectDirs`)").data_dir().to_owned();
    std::fs::create_dir_all(&dir).expect("cannot create project dir {dir:?}");
    dir

});

#[cfg(feature="sqlite")]
static HITDNS_SQLITE_FILENAME: Lazy<PathBuf> = Lazy::new(||{
    let mut buf = (*HITDNS_DIR).clone();
    buf.push("cache.sqlx.sqlite.db");
    buf
});

#[cfg(feature="sqlite")]
static HITDNS_SQLITE_POOL: Lazy<SqlitePool> = Lazy::new(||{
    let file = &*HITDNS_SQLITE_FILENAME;
    smol::block_on(async move {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .min_connections(1)
            .acquire_timeout(Duration::from_secs(10))

            .max_lifetime(None)
            .idle_timeout(None)

            .connect_with(
                SqliteConnectOptions::new()
                .filename(file)
                .create_if_missing(true)
                .read_only(false)
                .journal_mode(SqliteJournalMode::Wal)
                .locking_mode(SqliteLockingMode::Normal)
                .synchronous(SqliteSynchronous::Normal)
            ).await
            .expect("sqlx cannot connect to sqlite db");

        sqlx::query("CREATE TABLE IF NOT EXISTS hitdns_cache_v1 (query BLOB NOT NULL UNIQUE, entry BLOB NOT NULL) STRICT").execute(&pool).await.expect("sqlx cannot create table in opened sqlite db");
        pool
    })
});

#[cfg(feature="sled")]
static HITDNS_SLED_FILENAME: Lazy<PathBuf> = Lazy::new(||{
    let mut buf = (*HITDNS_DIR).clone();
    buf.push("hitdns.cache.sled.db");
    buf
});

#[cfg(feature="sled")]
static HITDNS_SLED_DB: Lazy<sled::Db> = Lazy::new(||{
    sled::Config::new()
        .path(&*HITDNS_SLED_FILENAME)
        .mode(sled::Mode::HighThroughput)
        .cache_capacity(1048576 * 8) // 8.0 MB
        .flush_every_ms(Some(1000))
        .temporary(false)
        .print_profile_on_drop(true)
        .use_compression(true)
        .compression_factor(22)
        .open().expect("cannot open sled db")
});

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
struct DNSQuery {
    name: String,
    rdclass: u16,
    rdtype: u16,
}

impl TryFrom<dns::Message> for DNSQuery {
    type Error = anyhow::Error;
    fn try_from(msg: dns::Message) -> anyhow::Result<Self> {
        if msg.message_type() != dns::MessageType::Query {
            anyhow::bail!("unexpected receive a non-query DNS message: {msg:?}");
        }

        let queries = msg.queries();
        let queries_len = queries.len();

        if queries_len == 0 {
            anyhow::bail!("unexpected DNS query message without any query section: {msg:?}");
        }

        // the best way to prevent the attacks of "try to fill large junk in DNS Server disk", that is, just keep first one query, and complete ignore "answers section" and "authority section" such as these field can store data that useless for query.
        if queries_len > 1 {
            log::debug!("unexpected DNS query message with multi queries, just keep the first query.");
        }
        if msg.name_servers().len() > 0 || msg.answers().len() > 0 {
            log::debug!("unexpected DNS query message with authority/answer section, ignore these sections.");
        }

        let query: dns::Query = queries[0].clone();
        Ok(query.into())
    }
}

impl From<dns::Query> for DNSQuery {
    fn from(val: dns::Query) -> DNSQuery {
        let mut name =
            val.name().to_string().to_ascii_lowercase();

        // de-duplicate by convert all domain to "ends with dot"
        if ! name.ends_with(".") {
            name.push('.');
        }

        DNSQuery {
            name,
            rdclass: val.query_class().into(),
            rdtype: val.query_type().into(),
        }
    }
}
impl TryFrom<&DNSQuery> for dns::Query {
    type Error = anyhow::Error;
    fn try_from(val: &DNSQuery)
        -> anyhow::Result<dns::Query>
    {
        use dns::IntoName;

        let mut name = val.name.to_string().to_ascii_lowercase();
        if ! name.ends_with(".") {
            name.push('.');
        }

        Ok(dns::Query::new()
            .set_name(name.into_name()?)
            .set_query_class(val.rdclass.into())
            .set_query_type(val.rdtype.into())
            .to_owned()
        )
    }
}

impl TryFrom<&DNSQuery> for dns::Message {
    type Error = anyhow::Error;
    fn try_from(val: &DNSQuery) -> anyhow::Result<dns::Message> {
        Ok(dns::Message::new()
            .set_id(0)
            .set_message_type(dns::MessageType::Query)
            .set_op_code(dns::OpCode::Query)
            .set_recursion_desired(true)
            .set_recursion_available(false)
            .set_authentic_data(false)
            .set_checking_disabled(false)
            .add_query(val.try_into()?)
            .to_owned()
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct DNSEntry {
    query: DNSQuery,
    response: Vec<u8>,
    expire: SystemTime,
    upstream: String,
    elapsed: Duration,
}

impl TryFrom<&DNSEntry> for dns::Message {
    type Error = anyhow::Error;
    fn try_from(entry: &DNSEntry) -> anyhow::Result<dns::Message> {
        Ok(dns::Message::from_vec(&entry.response)?)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DNSCacheStatus {
    Hit(Arc<DNSEntry>),
    Expired(Arc<DNSEntry>),
    Miss,
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
            }
        }
    }
}

#[derive(Debug, Clone)]
struct DNSCacheEntry {
    query: Arc<DNSQuery>,
    entry: Arc<RwLock<
               Option<Arc<DNSEntry>>
           >>,
    update_task: Arc<RwLock<
                Option<Arc< smol::Task<anyhow::Result<()>> >>
                  >>,
    update_notify: Arc<RwLock<
                Option< Receiver<()> >
                >>,
}
impl From<Arc<DNSQuery>> for DNSCacheEntry {
    fn from(query: Arc<DNSQuery>) -> DNSCacheEntry {
        DNSCacheEntry {
            query,
            entry: Arc::new(RwLock::new(None)),
            update_task: Arc::new(RwLock::new(None)),
            update_notify: Arc::new(RwLock::new(None)),
        }
    }
}
impl From<Arc<DNSEntry>> for DNSCacheEntry {
    fn from(entry: Arc<DNSEntry>) -> DNSCacheEntry {
        let query = entry.query.clone();
        let mut this: DNSCacheEntry =Arc::new(query).into();
        this.entry = Arc::new(RwLock::new(Some(entry)));
        this
    }
}

impl DNSCacheEntry {
    async fn status(&self) -> DNSCacheStatus {
        if let Some(entry) = self.entry.read().await.deref().clone() {
            entry.into()
        } else {
            DNSCacheStatus::Miss
        }
    }

    // wait until finish.
    async fn wait(&self) {
        while self.is_updating().await {
            log::debug!("{:?} still in updating...", self.query);
            smol::Timer::after(Duration::from_millis(50)).await;
            if let Some(maybe_rx) = self.update_notify.read().timeout(Duration::from_millis(20)).await {
                if let Some(rx) = maybe_rx.as_ref() {
                    let _ = rx.recv().await;
                } else {
                    break;
                }
            } else {
                log::warn!("timed out get read lock for update_notify!");
            }
        }

    }

    async fn is_updating(&self) -> bool {
        // smol-timeout Option
        if let Some(maybe_task) = self.update_task.read().timeout(Duration::from_millis(20)).await {
            // Option<smol::Task>
            if let Some(task) = maybe_task.deref().clone() {
                task.is_finished() == false
            } else {
                false
            }
        } else {
            log::warn!("get read lock timeout!!!");
            true
        }
    }

    /// if DNSEntry does not exipre, return immediately.
    /// if DNSEntry exists and expired, starting a background task for updating that, then return expired result.
    /// if DNSEntry does not exists, start a foreground task, waiting until it successfully or timed out.
    /// this method promises never starting multi task for cache miss.
    async fn update(&self, resolver: Arc<dyn DNSResolver>, timeout: Duration) -> anyhow::Result<Arc<DNSEntry>> {
        let status = self.status().await;
        // no need update a un-expired DNSRecord.
        // cache hit.
        if let DNSCacheStatus::Hit(entry) = status {
            return Ok(entry);
        }

        if self.is_updating().await {
            log::debug!("{:?} another update processing.", self.query);

            if let DNSCacheStatus::Miss = status {
                log::debug!("{:?} no last success result. force waiting until first result producted.", self.query);

                self.wait().await;
                return self.status().await.try_into();
            }

            // return last success result (but expired)
            return status.try_into();
        }

        // starting update task for updating expired result

        //let resolver = get_resolver.await?;

        let entry_lock = self.entry.clone();
        let query = self.query.clone();
        let (update_tx, update_rx) =smol::channel::bounded(1);
        *self.update_notify.write().await = Some(update_rx);
        *self.update_task.write().await = Some(Arc::new(
            smolscale2::spawn(async move {
                let upstream = resolver.dns_upstream();
                let start = Instant::now();
                let mut response = match timeout_helper(resolver.dns_resolve(&query), timeout).await {
                        Some(v) => v?,
                        None => {
                            anyhow::bail!("resolving query {:?} from upstream {upstream:?} timed out: timeout={timeout:?}", &query);
                        }
                    };
                let elapsed = start.elapsed();

                let expire_ttl: u32 = {
                    const MIN_TTL: u32 = 180;
                    let ttl: u32 = response.all_sections().map(|x| { x.ttl() }).min().unwrap_or(MIN_TTL);

                    if ttl < MIN_TTL {
                        MIN_TTL
                    } else {
                        ttl
                    }
                };
                let expire = SystemTime::now() + Duration::from_secs(expire_ttl.into());

                *response.extensions_mut() = None;

                let entry = Arc::new(DNSEntry {
                    query: query.deref().clone(),
                    response: response.to_vec()?,
                    elapsed,
                    upstream,
                    expire,
                });
                *entry_lock.write().await = Some(entry.clone());
                update_tx.send(()).await.log_error()?;

                #[cfg(feature="sqlite")]
                {
                    let query: Vec<u8> =
                        bincode::serialize(&query)
                        .log_error()?;
                    let entry: Vec<u8> =
                        bincode::serialize(&entry)
                        .log_error()?;

                    sqlx::query("INSERT OR IGNORE INTO hitdns_cache_v1 VALUES (?1, ?2); UPDATE hitdns_cache_v1 SET entry = ?2 WHERE query = ?1")
                        .bind(query).bind(entry)
                        .execute(&*HITDNS_SQLITE_POOL)
                        .await.log_warn()?;
                }

                #[cfg(feature="sled")]
                {
                    let query: Vec<u8> =
                        bincode::serialize(&query)
                        .log_error()?;
                    let entry: Vec<u8> =
                        bincode::serialize(&entry)
                        .log_error()?;

                    let tree =
                        HITDNS_SLED_DB
                        .open_tree(b"hitdns_cache_v2")
                        .log_warn()?;

                    tree.insert(query, entry).log_warn()?;
                    tree.flush_async().await.log_error()?;
                }

                Ok(())
            })
        ));

        if let DNSCacheStatus::Miss = status {
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


#[derive(Debug, Clone)]
struct DNSCache {
    memory: Arc<scc::HashMap<DNSQuery, DNSCacheEntry>>,
    //disk: SqlitePool,
    resolvers: Arc<DNSResolverArray>,
    //resolver: DNSOverHTTPS,
}
/// SAFETY: Async access
unsafe impl Sync for DNSCache {}
unsafe impl Send for DNSCache {}

impl DNSCache {
    async fn new(resolvers: DNSResolverArray) -> anyhow::Result<Self> {
        let memory = Arc::new(scc::HashMap::new());

        #[cfg(feature="sqlite")]
        {
            let mut ret = sqlx::query("SELECT * FROM hitdns_cache_v1").fetch(&*HITDNS_SQLITE_POOL);
            while let Ok(Some(line)) = ret.try_next().await {
                assert_eq!(line.columns().len(), 2);
                let query: Vec<u8> =
                    line.try_get_raw(0)?.to_owned()
                    .decode();
                let entry: Vec<u8> =
                    line.try_get_raw(1)?.to_owned()
                    .decode();

                let query: DNSQuery =
                    match
                        bincode::deserialize(&query)
                        .context("cannot deserialize 'query' from sqlite")
                        .log_error()
                    {
                        Ok(v) => v,
                        _ => { continue; },
                    };
                let entry: DNSEntry =
                    match
                        bincode::deserialize(&entry)
                        .context("cannot deserialize 'entry' from sqlite")
                        .log_error()
                    {
                        Ok(v) => v,
                        _ => { continue; },
                    };

                let cache_entry: DNSCacheEntry =
                    Arc::new(entry).into();

                let _ = memory.insert(query, cache_entry);
            }
        }

        #[cfg(feature="sled")]
        {
            let tree =
                HITDNS_SLED_DB
                .open_tree(b"hitdns_cache_v2").context("cannot open sled tree").log_warn()?;

            for ret in tree.iter() {
                log::trace!("from sled tree: {ret:?}");

                let (query, entry) = match ret {
                    Ok(v) => v,
                    Err(e) => {
                        log::warn!("cannot fetch one from sled tree (error={e:?}). end of sled tree?");
                        continue;
                    }
                };

                let query: DNSQuery =
                    match
                        bincode::deserialize(&query)
                        .context("cannot deserialize 'query' from sled")
                        .log_error()
                    {
                        Ok(v) => v,
                        _ => { continue; },
                    };
                let entry: DNSEntry =
                    match
                        bincode::deserialize(&entry)
                        .context("cannot deserialize 'entry' from sled")
                        .log_error()
                    {
                        Ok(v) => v,
                        _ => { continue; },
                    };

                let cache_entry: DNSCacheEntry =
                    Arc::new(entry).into();

                let _ = memory.insert(query, cache_entry);
            }

            // if enabled both 'sqlite' and 'sled' feature,
            // this will doing a migration that copying original DNS entry from sqlite to sled.
            #[cfg(all(feature="sqlite", feature="sled"))]
            {
                let mut x = vec![];
                memory.scan(|k, v| {
                    log::trace!("migrate {k:?}");
                    x.push((k.clone(), v.clone()));
                });
                for (query, cache_entry) in x.iter() {
                    let query: Vec<u8> =
                        bincode::serialize(&query)
                        .log_error()?;
                    let entry: Vec<u8> =
                        bincode::serialize(&{
                            let entry: Arc<DNSEntry> =
                                cache_entry.status()
                                .await.try_into()?;
                            entry.deref().clone()
                        })?;

                    tree.insert(query, entry).context("cannot insert to sled tree").log_warn()?;
                    tree.flush_async().await.log_error()?;
                }
            }
        }

        Ok(Self {
            memory,
            //disk,
            resolvers: Arc::new(resolvers),
        })
    }

    // cached query
    async fn query(&self, req: dns::Message) -> anyhow::Result<dns::Message> {
        let started = Instant::now();

        let req_id: u16 = req.id();
        let query: DNSQuery = req.try_into().log_debug()?;
        log::debug!("DNSCache: received new query: id={req_id} query={:?}", &query);

        let cache_entry =
            self.memory.entry_async(query.clone()).await
            .or_insert_with(||{
                Arc::new(query).into()
            })
            .get().clone();

        let entry = cache_entry.update(
            self.resolvers.best().await?,
            //self.resolver.clone(),
            Duration::from_secs(10)
        ).await.log_warn()?;

        let now_unix = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).log_error()?;
        let expire_unix = entry.expire.duration_since(SystemTime::UNIX_EPOCH).log_error()?;

        let mut res: dns::Message = entry.as_ref().try_into().log_warn()?;
        res.set_id(req_id);
        let ttl: u32 =
            if now_unix > expire_unix {
                0
            } else {
                (expire_unix - now_unix)
                    .as_secs() as u32
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
        Ok(res)
    }
}

#[derive(Debug, Clone)]
struct Hosts {
    map: Arc<
        std::collections::HashMap<  String, Vec<IpAddr>  >
        >,
    filename: Arc<PathBuf>,
}
impl TryFrom<&PathBuf> for Hosts {
    type Error = anyhow::Error;
    fn try_from(filename: &PathBuf) -> anyhow::Result<Hosts> {
        const HOSTS_EXAMPLE: &'static str = "   two examples of hosts.txt that is: 142.250.189.206 ipv4.google.com | 2607:f8b0:4005:814::200e ipv6.google.com   ";
        use std::collections::HashMap;
        let mut map: HashMap<String, Vec<IpAddr>> = HashMap::new();
        let mut file: String = std::fs::read_to_string(filename).context("cannot read from hosts.txt file").log_warn()?;

        // compatible Unix/Linux LF, Windows CR LF, and Mac CR
        // LF    = \n
        // CR LF = \r\n
        // CR    = \r
        while file.contains("\r") {
            file = file.replace("\r", "\n");
        }
        while file.contains("\n\n") {
            file = file.replace("\n\n", "\n");
        }

        // debug checks
        assert_eq!(file.contains("\r\n"), false);
        assert_eq!(file.contains("\r"), false);
        assert_eq!(file.contains("\n\n"), false);

        let mut lines = 0;
        for line in file.split("\n") {
            lines += 1;

            let mut line = line.to_string();
            // convert all Tab character to space
            while line.contains("\t") {
                line = line.replace("\t", " ");
            }

            // ignore comments.
            if ! line.contains(" ") { continue; }
            if line.replace(" ", "").starts_with("#") { continue; }

            while line.contains("  ") {
                line = line.replace("  ", " ");
            }
            let words = Vec::from_iter(line.split(" "));
            let words_len = words.len();
            if words_len <= 1 {
                log::warn!("Hosts: {filename:?}: ignore invalid line: no space character found at line {lines}. / {HOSTS_EXAMPLE}");
                continue;
            }
            let ip: IpAddr = match words[0].parse() {
                Ok(ip) => ip,
                Err(error) => {
                    log::warn!("Hosts: {filename:?}: ignore corrupted line: cannot parse the first word of line {lines} as a IPv4 or IPv6 address: {error:?} / {HOSTS_EXAMPLE}");
                    continue;
                }
            };
            let mut domain = words[1].to_string();
            if ! domain.ends_with(".") {
                domain.push('.');
            }
            let domain = domain.to_ascii_lowercase();

            // any words following the first and last word, expect these is comments.
            if words.len() > 2 {
                log::debug!("Hosts: {filename:?}: ignore tailing words of line {lines}.");
            }

            let ip_list = map.entry(domain).or_insert_with(|| { Vec::new() });
            ip_list.push(ip);
        }

        log::info!("Hosts: total {lines} lines loaded, {} domain names loaded. mapping: {map:#?}", map.len());

        Ok(Self {
            map: Arc::new(map),
            filename: Arc::new(filename.clone()),
        })
    }
}

impl Hosts {
    fn lookup(&self, domain: &str)
        -> Option<Vec<IpAddr>>
    {
        let mut domain: String = domain.to_string();
        if ! domain.ends_with(".") {
            domain.push('.');
        }
        let domain = domain.to_ascii_lowercase();

        match self.map.get(&domain) {
            Some(v) => { Some(v.clone()) },
            None => { None },
        }
    }
}
impl reqwest::dns::Resolve for Hosts {
    fn resolve(&self, domain: hyper::client::connect::dns::Name) -> reqwest::dns::Resolving {
        let maybe_ips = self.lookup(domain.as_str());
        let filename = self.filename.clone();
        Box::pin(async move {
            if let Some(ips) = maybe_ips {
                let addrs: Vec<SocketAddr> = {
                    // this is a stupid design by reqwest developers
                    // they said "Since the DNS protocol has no notion of ports, ... any port in the overridden addr will be ignored and traffic sent to the conventional port for the given scheme (e.g. 80 for http)."
                    // so why this API does not accept Vec<IpAddr> as argument type instead of Vec<SocketAddr> ?!
                    // alao the same problem exists at reqwest::ClientBuilder::resolve method
                    // 
                    // https://docs.rs/reqwest/0.11.23/reqwest/struct.ClientBuilder.html#method.resolve_to_addrs
                    // https://docs.rs/reqwest/0.11.23/reqwest/struct.ClientBuilder.html#method.resolve

                    let mut x = vec![];
                    for ip in ips.iter() {
                        x.push(SocketAddr::new(*ip, 0));
                    }
                    x
                };
                let ok: Box<dyn Iterator<Item=SocketAddr>+Send> = Box::new(addrs.into_iter());
                Ok(ok)
            } else {
                let msg = format!("DNS static resolve failed: unable to find a mapping from {domain:?} to IPv4/IPv6 addresses. provided hosts.txt = {:?}", filename);
                log::warn!("{}", &msg);
                let err: Box<dyn std::error::Error + Send + Sync> = Box::new(std::io::Error::new(std::io::ErrorKind::Unsupported, msg));
                Err(err)
            }
        })
    }

}

#[derive(Debug, Clone)]
struct DNSOverHTTPS {
    client: reqwest::Client,
    url: reqwest::Url,
    metrics: Arc<RwLock<DNSMetrics>>,
}

impl<'a> DNSOverHTTPS {
    const CONTENT_TYPE: &'static str = "application/dns-message";

    fn new(url: impl ToString, maybe_hosts: &Option<Hosts>, mut tls_sni: bool) -> anyhow::Result<Self> {
        let url: String = url.to_string();
        let url = reqwest::Url::parse(&url).log_warn()?;

        if url.scheme() != "https" {
            anyhow::bail!("DoH server URL scheme invalid.");
        }
        
        struct NoDNS(Option<Hosts>);
        impl reqwest::dns::Resolve for NoDNS {
            // pub type Resolving = Pin<Box<dyn Future<Output = Result<Addrs, Box<dyn StdError + Send + Sync>>> + Send>>;
            fn resolve(&self, domain: hyper::client::connect::dns::Name) -> reqwest::dns::Resolving {
                if let Some(hosts) = &self.0 {
                    return hosts.resolve(domain);
                }
                let msg = format!("unexpected DNS resolve request ({domain:?}) from reqwest::Client in DoH client. this avoids infinity-recursive DNS resolving if hitdns itself as a system resolver. because TLS certificate Common Name or Alt Subject Name can be IP addresses, so you can use IP address instead of a domain name (need DoH server supports). or instead you can give a hosts.txt file by --hosts or --use-system-hosts");
                log::warn!("{}", &msg);
                Box::pin(async move {
                    let err: Box<dyn std::error::Error + Send + Sync> = Box::new(std::io::Error::new(std::io::ErrorKind::Unsupported, msg));
                    Err(err)
                })
           }
        }

        if let Some(ref hosts) = maybe_hosts {
            if ! hosts.map.is_empty() {
                tls_sni = true;
            }
        }

        // client builder
        let mut cb =
            reqwest::Client::builder()

            // log::trace
            .connection_verbose(true)

            // use HTTPS(rustls) only
            .use_rustls_tls()
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            .https_only(true)
            .tls_sni(tls_sni)

            // HTTP/2 setting
            .http2_prior_knowledge() // use HTTP/2 only
            .http2_adaptive_window(false)
            .http2_max_frame_size(Some(65535))
            .http2_keep_alive_interval(Some(Duration::from_secs(10)))
            .http2_keep_alive_timeout(Duration::from_secs(10))
            .http2_keep_alive_while_idle(true)
            .referer(false)
            .redirect(reqwest::redirect::Policy::none())

            // connection settings
            .tcp_nodelay(true)
            .pool_idle_timeout(None)
            .pool_max_idle_per_host(5)

            // for all DNS resove from reqwest, should redirecting to static name mapping (hosts.txt), or just disable it if no hosts specified
            .dns_resolver(Arc::new(NoDNS(maybe_hosts.clone())));
            

        if let Some(hosts) = maybe_hosts {
            for (domain, ips) in hosts.map.iter() {
                let ips: Vec<SocketAddr> = {
                    let mut x = vec![];
                    for ip in ips.iter() {
                        x.push(SocketAddr::new(*ip, 0));
                    }
                    x
                };
                cb = cb.resolve_to_addrs(domain, &ips);
            }
        }
            // build client
        let client = cb.build().log_warn()?;

        Ok(Self {
            client,
            url: url.clone(),
            metrics:
                Arc::new(RwLock::new(DNSMetrics {
                    latency: Vec::new(),
                    upstream: url.to_string(),
                    reliability: 50,
                    online: false,
                    last_respond: SystemTime::UNIX_EPOCH,
                }))
        })
    }

    // un-cached DNS Query
    async fn _dns_resolve(&self, query: &DNSQuery)
        -> anyhow::Result<dns::Message>
    {
        let start = Instant::now();
        let result = self._orig_dns_resolve(query).await;
        let latency = start.elapsed();

        let ok = result.is_ok();
        let metrics_lock = self.metrics.clone();
        smolscale2::spawn(async move {
            let mut metrics = metrics_lock.write().await;

            if ok {
                metrics.online = true;
                metrics.latency.push(latency);
                metrics.last_respond = SystemTime::now();

                if metrics.reliability < 100 {
                    metrics.reliability += 1;
                }
            } else {
                metrics.online = false;
                metrics.latency.push(Duration::from_secs(999));

                if metrics.reliability > 0 {
                    metrics.reliability -= 1;
                }
            }
        }).detach();

        result
    }
    async fn _orig_dns_resolve(&self, query: &DNSQuery)
        -> anyhow::Result<dns::Message>
    {
        log::info!("DoH un-cached Query: {query:?}");

        let req: dns::Message = query.try_into().log_warn()?;

        let client = self.client.clone();
        let url = self.url.clone();

        let http_res = client.post(url)
            .header("Content-Type", Self::CONTENT_TYPE)
            .header("Accept", Self::CONTENT_TYPE)
            .body(req.to_vec()?)
            .send().await.log_info()?;

        if http_res.status().as_u16() != 200 {
            anyhow::bail!("DoH server returns non-200 HTTP status code: {http_res:?}");
        }

        if let Some(ct) = http_res.headers().get("Content-Type") {
            if ct.as_bytes().to_ascii_lowercase() != Self::CONTENT_TYPE.as_bytes() {
                anyhow::bail!("DoH server returns invalid Content-Type header: {http_res:?}");
            }
        } else {
            anyhow::bail!("DoH server does not specify Content-Type header: {http_res:?}");
        }

        let res: Bytes = http_res.bytes().await.log_warn()?;
        let mut response =
            dns::Message::from_vec(&res).log_warn()?;
        response.set_id(0);

        log::info!("DoH un-cached response {response:?}");
        Ok(response)
    }
}
impl DNSResolver for DNSOverHTTPS {
    fn dns_resolve(&self, query: &DNSQuery)
        -> PinFut<anyhow::Result<dns::Message>>
    {
        let query = query.clone();
        Box::pin(async move {
            self._dns_resolve(&query).await
        })
    }

    fn dns_upstream(&self) -> String {
        self.url.to_string()
    }

    fn dns_protocol(&self) -> &'static str {
        "DNS over HTTP/2 over TLS over TCP"
    }

    fn dns_metrics(&self) -> PinFut<DNSMetrics> {
        Box::pin(async move {
            self.metrics.read().await.clone()
        })
    }
}

type TlsStream =async_tls::client::TlsStream<TcpStream>;
struct DNSOverTLS {
    connector: async_tls::TlsConnector,
    sessions: Arc<scc::HashMap<
                SocketAddr, Vec<(u128, TlsStream)>
            >>,
    upstream: String,
    _task: smol::Task<()>,
}
impl DNSOverTLS {
    async fn new(
        upstream: impl ToString,
        maybe_hosts: &Option<Hosts>,
    ) -> anyhow::Result<Self> {
        let connector = async_tls::TlsConnector::new();
        let sessions = Arc::new(scc::HashMap::new());

        let upstream: String = upstream.to_string();
        let addrs: Vec<SocketAddr> = {
            let mut x = vec![];
            if ! upstream.contains(":") {
                anyhow::bail!("wrong DoT addr format");
            }
            if let Ok(addr) = upstream.parse() {
                x.push(addr);
            } else {
                if let Some(hosts) = maybe_hosts {
                    let mut y: Vec<&str> =
                        upstream.split(":").collect();

                    let port: u16 =
                        if let Some(p) = y.pop() {
                            p.parse()?
                        } else {
                            anyhow::bail!("cannot parse DoT upstream: no port number found");
                        };
                    let host: String = y.join(":");

                    if let Some(ips) = hosts.lookup(&host){
                        for ip in ips.iter() {
                            x.push(
                                SocketAddr::new(*ip, port)
                            );
                        }
                    } else {
                        anyhow::bail!("cannot parse DoT upstream: a domain name provided, but not found in hosts.txt")
                    }
                } else {
                    anyhow::bail!("cannot parse DoT upstream: a domain name provided but without hosts.txt");
                }
            }
            x
        };

        for addr in addrs.iter() {
            sessions.insert(*addr, vec![]).unwrap();
        }

        let _task = {
            let connector = connector.clone();
            let sessions = sessions.clone();
            smolscale2::spawn(async move {
                let mut reconnecting: Vec<SocketAddr> = vec![];
                let mut ret = vec![];
                loop {
                    while let Some(addr) = reconnecting.pop() {
                        // connecting...
                        let tcp_conn =
                            match
                            TcpStream::connect(addr).await
                            {
                                Ok(v) => v,
                                Err(err) => {
                                    log::warn!("unable connect to DoT upstream({addr:?}): cannot establish TCP connection: {err:?}");
                                    continue;
                                }
                            };

                        match
                            connector.connect(
                                addr.ip().to_string(),
                                tcp_conn
                            ).await
                        {
                            Ok(tls_conn) => {
                                let id =
                                    fastrand::u128(..);
                                log::info!("connected DoT {id}={tls_conn:?}");
                                if let Some(mut entry) =
                                    sessions
                                        .get_async(&addr)
                                        .await
                                {
                                    entry.get_mut()
                                        .push(
                                            (id, tls_conn)
                                        );
                                }
                            },

                            Err(err) => {
                                log::warn!("unable connect to DoT upstream({addr:?}): TLS handshake failed: {err:?}");
                            }
                        }
                    }

                    ret.clear();
                    sessions.scan_async(|addr, conns| {
                        let mut x = vec![];
                        for conn in conns.iter() {
                            let id = conn.0;
                            let io =
                                conn.1.get_ref().clone();
                            x.push((id, io));
                        }
                        ret.push( (*addr, x) );
                    }).await;

                    for (addr, io) in ret.iter_mut() {
                        if io.is_empty() {
                            reconnecting.push(*addr);
                        } else {
                            for i in 0 .. io.len() {
                                let (id, io) = &io[i];
                                if let Err(err) =
                                    io.peek(&mut [0]).await
                                {
                                    log::warn!("session died: addr={addr:?} | io={io:?} | error={err:?}");
                                    reconnecting.push(*addr);
                                    // remove dead conn
                                    sessions.update_async(
                                        addr,
                                        |_, conns| {
                                            conns.retain(|conn| { conn.0 != *id });
                                        }
                                    ).await;
                                }
                            }
                        }
                    }
                    ret.clear();

                    smol::Timer::after(
                        Duration::from_secs(1)
                    ).await;
                }
            })
        };
        Ok(Self {
            connector,
            sessions,
            upstream,
            _task,
        })
    }

    async fn _dns_resolve(&self, query: &DNSQuery)
        -> anyhow::Result<dns::Message>
    {
        let msg = {
            let msg: dns::Message = query.try_into()?;
            let msg: Vec<u8> = msg.to_vec()?;
            let mut buf = msg.len().to_be_bytes().to_vec();
            buf.extend(msg);
            buf
        };

        let mut all_conns = vec![];
        self.sessions.scan_async(|_, conns| {
            for conn in conns.iter() {
                all_conns.push( conn.1.get_ref().clone() );
            }
        }).await;

        let mut res_len = [0u8; 2];
        let mut res;
        while ! all_conns.is_empty() {
            let i = fastrand::usize(0 .. all_conns.len() );
            let mut conn = all_conns.swap_remove(i);
            if let Some(Ok(_)) =
                conn.write_all(&msg)
                .timeout(Duration::from_secs(2))
                .await
            {
                if let Some(tmp) =
                    conn.read_exact(&mut res_len)
                    .timeout(Duration::from_secs(3))
                    .await
                {
                    if tmp.is_err() {
                        log::warn!("DoT upstream error: reading response length: {tmp:?}");
                        continue;
                    }
                } else {
                    continue;
                }

                let res_len: usize =
                    u16::from_be_bytes(res_len).into();
                res = vec![0u8; res_len];

                if let Some(tmp) =
                    conn.read_exact(&mut res)
                    .timeout(Duration::from_secs(5))
                    .await
                {
                    if tmp.is_err() {
                        log::warn!("DoT upstream error: reading response body: {tmp:?}");
                        continue;
                    }
                } else {
                    continue;
                }

                return Ok(dns::Message::from_vec(&res)?);
            }
        }

        anyhow::bail!("all DoT upstream timed out!")
    }
}
impl DNSResolver for DNSOverTLS {
    fn dns_resolve(&self, query: &DNSQuery)
        -> PinFut<anyhow::Result<dns::Message>>
    {
        let query = query.clone();
        Box::pin(async move {
            self._dns_resolve(&query).await
        })
    }

    fn dns_upstream(&self) -> String {
        self.upstream.clone()
    }

    fn dns_protocol(&self) -> &str {
        "DNS over TLS over TCP"
    }

    fn dns_metrics(&self) -> PinFut<DNSMetrics> {
        // TODO
        todo!()
    }
}

struct DNSOverQUIC {
    addr: SocketAddr,
}

type PinFut<'a, T> = Pin<Box<
    dyn Future<Output=T> + Send + 'a
>>;

trait DNSResolver: Send + Sync + 'static {
    /// un-cached DNS query
    fn dns_resolve(&self, query: &DNSQuery) ->
        PinFut<anyhow::Result<dns::Message>>;

    /// a description for upstream, usually URL or any other.
    fn dns_upstream(&self) -> String;

    /// a protocol type of upstream
    fn dns_protocol(&self) -> &str;

    /// get analysis for this Upstream
    fn dns_metrics(&self) -> PinFut<DNSMetrics>;
}

#[derive(Debug, Clone)]
struct DNSMetrics {
    latency: Vec<Duration>,
    reliability: u8, // 0% - 100%
    online: bool,
    last_respond: SystemTime,
    upstream: String,
}

/*
impl<T: AsRef<DNSResolver> DNSResolver for &T
{
}
*/

impl core::fmt::Debug for dyn DNSResolver {
    fn fmt(&self, f: &mut core::fmt::Formatter)
        -> Result<(), core::fmt::Error>
    {
        f.debug_struct("dyn DNSResolver")
            .field("dns_upstream", &self.dns_upstream())
            .field("dns_protocol", &self.dns_protocol())
            .finish()
    }
}

#[derive(Debug, Clone)]
struct DNSResolverArray {
    list: Arc<Vec<Arc<dyn DNSResolver>>>,
}

impl DNSResolverArray {
    // constroctor
    fn from(
        val: impl IntoIterator<Item=Arc<dyn DNSResolver>>
    ) -> DNSResolverArray {
        let mut list = Vec::new();
        for resolver in val {
            list.push(resolver);
        }

        DNSResolverArray {
            list: Arc::new(list)
        }
    }

    /// select best resolver by minimum latency
    async fn best(&self)
        -> anyhow::Result<Arc<dyn DNSResolver>>
    {
        let mut best = None;
        let mut best_metrics = None;
        for resolver in self.list.as_ref().iter() {
            let my_metrics = resolver.dns_metrics().await;

            // ignore any offline resolvers
            if my_metrics.reliability <= 40 {
                continue;
            }

            let resolver = resolver.clone();
            if best.is_none() {
                best = Some(resolver);
                best_metrics = Some(my_metrics);
                continue;
            }

            let bm = best_metrics.clone().unwrap();

            let mut tmp: Vec<u128>;
            let metrics_avg = {
                tmp = my_metrics.latency.iter().map(
                    |x| { x.as_millis() }
                ).collect();

                average(&tmp)
            };   
            let best_avg = {
                tmp = bm.latency.iter().map(
                    |x| { x.as_millis() }
                ).collect();

                average(&tmp)
            };

            if metrics_avg < best_avg {
                best = Some( resolver.clone() );
                best_metrics = Some( my_metrics.clone() );
            }
            // Reliability seems to be more important than Latency
            if my_metrics.reliability > bm.reliability {
                best = Some(resolver);
                best_metrics = Some(my_metrics);
            }
        }

        if let Some(resolver) = best {
            log::info!("selected best resolver {:?} with metrics {best_metrics:?}", &resolver);
            Ok(resolver)
        } else {
            anyhow::bail!("cannot select best resolver! maybe Internet offline, or empty list of resolvers")
        }
    }

    fn random(&self)
        -> anyhow::Result<Arc<dyn DNSResolver>>
    {
        if self.list.is_empty() {
            anyhow::bail!("unexpected empty list of DNS Resolvers!");
        }

        for _ in 0..10 {
            // get newest length
            let len = self.list.len();

            let n = fastrand::usize(0..len);

            if let Some(resolver) = self.list.get(n) {
                return Ok( resolver.clone() );
            } else {
                log::debug!("unexpected cannot get({n}) from resolver list: maybe self.list.len()=={len} changed before get?");
            }
        }

        anyhow::bail!("cannot get resolver randomly")
    }

    fn fixed(&self) -> anyhow::Result<Arc<dyn DNSResolver>>
    {
        if let Some(resolver) = self.list.get(0) {
            Ok( resolver.clone() )
        } else {
            anyhow::bail!("cannot select best resolver: empty list of resolvers!")
        }
    }
}

/*
impl DNSResolver for DNSResolverArray {
    fn dns_resolve(&self, query: &DNSQuery) ->DNSResolving{
        self.select_best().dns_resolve(query)
    }

    fn dns_upstream(&self) -> String {
    }

    fn dns_protocol(&self) -> &str {
    }
}
*/

#[derive(Debug)]
struct DNSDaemon {
    udp: UdpSocket, udp_task: smol::Task<anyhow::Result<()>>,
    tcp: TcpListener, tcp_task: smol::Task<anyhow::Result<()>>,
    cache: Arc<DNSCache>,
}

impl DNSDaemon {
    async fn new(opt: HitdnsOpt) -> anyhow::Result<Self> {
        let udp_ = UdpSocket::bind(&opt.listen).await.log_error()?;
        let tcp_ = TcpListener::bind(&opt.listen).await.log_error()?;

        let hosts =
            if let Some(ref hosts_filename) = opt.hosts {
                hosts_filename.try_into().log_warn().ok()
            } else {
                None
            };
        let resolvers = {
            let mut x: Vec<Arc<dyn DNSResolver>> = vec![];
            for doh_url in opt.doh_upstream.iter() {
                x.push(
                    Arc::new(
                        DNSOverHTTPS::new(
                            doh_url,
                            &hosts,
                            opt.tls_sni
                        )?
                    )
                );
            }
            for dot_addr in opt.dot_upstream.iter() {
                x.push(
                    Arc::new(
                        DNSOverTLS::new(
                            dot_addr,
                            &hosts
                        ).await?
                    )
                );
            }
            DNSResolverArray::from(x)
        };
        let cache_ = Arc::new(
            DNSCache::new(resolvers).await?
        );

        let cache = cache_.clone();
        let udp = udp_.clone();
        let udp_task = smolscale2::spawn(async move {
            let mut buf = vec![0u8; 65535];
            let mut msg;
            loop {
                let (len, peer) = udp.recv_from(&mut buf).await.context("cannot recvfrom udp socket").log_error()?;
                msg = buf[..len].to_vec();
                let udp = udp.clone();
                let cache = cache.clone();
                smolscale2::spawn(async move {
                    let req = dns::Message::from_vec(&msg).log_debug()?;
                    let res: dns::Message = cache.query(req).await.log_warn()?;
                    udp.send_to(res.to_vec().expect("bug: DNSCache.query returns invalid data").as_ref(), peer).await.log_error()?;
                    Ok::<_, anyhow::Error>(())
                }).detach();
            }

            #[allow(unreachable_code)]
            Ok(())
        });

        let cache = cache_.clone();
        let tcp = tcp_.clone();
        let tcp_task = smolscale2::spawn(async move {
            loop {
                let (mut conn, peer) = tcp.accept().await.log_error()?;
                log::info!("DNS Daemon accepted new TCP connection from {peer:?}");
                let cache = cache.clone();
                smolscale2::spawn(async move {
                    let mut buf = vec![0u8; 65535];
                    let mut buf2: Vec<u8> = vec![];
                    let mut len = [0u8; 2];
                    let mut len2: usize;

                    let mut req: dns::Message;
                    let mut res: dns::Message;
                    loop {
                        conn.read_exact(&mut len).await.log_debug()?;
                        len2 = u16::from_be_bytes(len) as usize;
                        conn.read_exact(&mut buf[..len2]).await.log_debug()?;

                        req = dns::Message::from_vec(&buf[..len2]).log_debug()?;
                        res = cache.query(req).await?;

                        {
                            let buf = res.to_vec().log_warn()?;
                            len2 = buf.len();
                            if len2 > 65535 {
                                anyhow::bail!("response too long, it must less than 65536.");
                            }
                            len = (len2 as u16).to_be_bytes();
                            buf2.clear();
                            buf2.extend(&len);
                            buf2.extend(&buf);
                        }
                        conn.write(&buf2).await.log_debug()?;
                    }

                    #[allow(unreachable_code)]
                    Ok::<_, anyhow::Error>(())
                }).detach();
            }

            #[allow(unreachable_code)]
            Ok::<_, anyhow::Error>(())
        });

        Ok(Self {
            udp: udp_,
            udp_task,
            tcp: tcp_,
            tcp_task,
            cache: cache_
        })
    }

    async fn run(self) {
        loop {
            log::debug!("cache status: {:?}", self.cache.memory.len());
            log::debug!("smolscale2 worker threads: {:?}", smolscale2::running_threads());
            log::debug!("tcp listener: {:?}\ntcp task: {:?}", &self.tcp, &self.tcp_task);
            log::debug!("udp socket: {:?}\nudp task: {:?}", &self.udp, &self.udp_task);

            if self.tcp_task.is_finished() || self.udp_task.is_finished() {
                log::error!("listener task died");
                return;
            }

            smol::Timer::after(Duration::from_secs(10)).await;
        }
    }
}

#[derive(Debug, Clone, clap::Parser)]
#[command(author, version, about, long_about)]
struct HitdnsOpt {
    /// location of a hosts.txt file.
    /// examples of this file format, that can be found at /etc/hosts (Unix-like systems), or
    /// C:\Windows\System32\drivers\etc\hosts (Windows)
    #[arg(long)]
    hosts: Option<PathBuf>,

    #[arg(long)]
    /// Whether try to find system-side hosts.txt
    use_system_hosts: bool,

    /// Whether enable TLS SNI extension.
    /// if this is unspecified, default disable SNI (for bypass internet censorship in few totalitarian countries)
    /// if you specified --tls-sni or --hosts or --use-system-hosts, then TLS SNI will enabled by default.
    #[arg(long)]
    tls_sni: bool,

    /// Listen address of local plaintext DNS server.
    #[arg(long, default_value="127.0.0.1:10053")]
    listen: SocketAddr,

    /// upstream URL of DoH servers.
    /// DNS over HTTPS
    #[arg(long, default_value="https://1.0.0.1/dns-query")]
    doh_upstream: Vec<String>,

    /// *Experimental*
    /// upstream address of DoT servers.
    /// DNS over TLS
    #[arg(long)]
    dot_upstream: Vec<String>,
}

async fn main_async() -> anyhow::Result<()> {
    let mut opt = HitdnsOpt::parse();
    if opt.use_system_hosts {
        let filename =
            if cfg!(target_vendor="apple") {
                "/private/etc/hosts"
            } else if cfg!(target_os="android") {
                "/system/etc/hosts"
            } else if cfg!(target_family="unix") {
                "/etc/hosts"
            } else if cfg!(target_family="windows") {
                r"C:\Windows\System32\drivers\etc\hosts"
            } else {
                ""
            };

        if filename.is_empty() {
            log::warn!("cannot find your system-side hosts.txt, please provaide a path by --hosts");
        } else {
            let filename = PathBuf::from(filename);
            opt.hosts = Some(filename);
        }
    }

    DNSDaemon::new(opt).await.log_error()?.run().await;
    Ok(())
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    smolscale2::set_max_threads(4);
    smolscale2::block_on(main_async())
}

