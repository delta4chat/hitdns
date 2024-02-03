use std::time::{Duration, Instant, SystemTime};

use std::sync::Arc;
use std::ops::Deref;

mod dns {
    pub use hickory_proto::op::*;
    pub use hickory_proto::rr::{/*Name, */IntoName};
    //pub use hickory_proto::rr::record_type::RecordType;
}

use serde::{Serialize, Deserialize};
use bytes::Bytes;

use std::net::{SocketAddr, IpAddr};

use smol::net::UdpSocket;
use smol::net::{TcpListener, TcpStream};

use smol::io::{AsyncReadExt, AsyncWriteExt};
use smol::stream::{StreamExt};

use smol::future::Future;

use smol::channel::{Sender, Receiver};

use sqlx::sqlite::{SqlitePool, SqlitePoolOptions, SqliteConnectOptions, SqliteJournalMode, SqliteLockingMode, SqliteSynchronous};
use sqlx::{Row, Value, ValueRef};
use async_lock::RwLock;

use smol_timeout::TimeoutExt;

use once_cell::sync::Lazy;
use std::path::PathBuf;

use anyhow::Context;

// command line argument parser
use clap::Parser;

use core::fmt::Debug;

trait LogResult: Debug + Sized {
    fn log_error(self) -> Self {
        log::error!("{:?}", self);
        self
    }

    fn log_warn(self) -> Self {
        log::warn!("{:?}", self);
        self
    }

    fn log_info(self) -> Self {
        log::info!("{:?}", self);
        self
    }

    fn log_debug(self) -> Self {
        log::debug!("{:?}", self);
        self
    }
    fn log_trace(self) -> Self {
        log::trace!("{:?}", self);
        self
    }
}

impl<T: Debug, E: Debug> LogResult for Result<T, E> {
    fn log_error(self) -> Self {
        if let Err(_) = self {
            log::error!("{:?}", self);
        }
        self
    }
    fn log_warn(self) -> Self {
        if let Err(_) = self {
            log::error!("{:?}", self);
        }
        self
    }
    fn log_info(self) -> Self {
        if let Err(_) = self {
            log::info!("{:?}", self);
        }
        self
    }
    fn log_debug(self) -> Self {
        if let Err(_) = self {
            log::error!("{:?}", self);
        }
        self
    }
    fn log_trace(self) -> Self {
        if let Err(_) = self {
            log::trace!("{:?}", self);
        }
        self
    }

}

static HITDNS_DIR: Lazy<PathBuf> = Lazy::new(||{
    let dir = directories::ProjectDirs::from("org", "delta4chat", "hitdns").expect("Cannot get platform-specified dir (via `directories::ProjectDirs`)").data_dir().to_owned();
    std::fs::create_dir_all(&dir).expect("cannot create project dir {dir:?}");
    dir

});

static HITDNS_SQLITE_FILENAME: Lazy<PathBuf> = Lazy::new(||{
    let mut buf = (*HITDNS_DIR).clone();
    buf.push("cache.sqlx.sqlite.db");
    buf
});

static HITDNS_SQLITE_POOL: Lazy<SqlitePool> = Lazy::new(||{
    let file = &*HITDNS_SQLITE_FILENAME;
    println!("{file:?}");
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
            ).await.unwrap();

        sqlx::query("CREATE TABLE IF NOT EXISTS hitdns_cache_v1 (query BLOB NOT NULL UNIQUE, entry BLOB NOT NULL) STRICT").execute(&pool).await.unwrap();
        pool
    })
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
            name: val.name().to_string().to_ascii_lowercase(),
            rdclass: val.query_class().into(),
            rdtype: val.query_type().into(),
        }
    }
}
impl TryFrom<&DNSQuery> for dns::Query {
    type Error = anyhow::Error;
    fn try_from(val: &DNSQuery) -> anyhow::Result<dns::Query> {
        use dns::IntoName;

        let mut name = val.name.to_string().to_ascii_lowercase();
        if ! name.ends_with(".") {
            name.push('.');
        }

        Ok(dns::Query::new()
            .set_name(val.name.to_ascii_lowercase().into_name()?)
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
    async fn update(&self, resolver: DNSOverHTTPS, timeout: Duration) -> anyhow::Result<Arc<DNSEntry>> {
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
            smolscale::spawn(async move {
                let upstream = resolver.dns_upstream();
                let start = Instant::now();
                let mut response = match resolver.dns_resolve(&query).timeout(timeout).await {
                        Some(v) => v?,
                        None => {
                            anyhow::bail!("resolving query {:?} from upstream {upstream:?} timed out: timeout={timeout:?}", query);
                        }
                    };
                let elapsed = start.elapsed();

                let expire_ttl: u32 = {
                    const MIN_TTL: u32 = 60;
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

                {
                    let query: Vec<u8> = bincode::serialize(&query).log_error()?;
                    let entry: Vec<u8> = bincode::serialize(&entry).log_error()?;
                    sqlx::query("INSERT OR IGNORE INTO hitdns_cache_v1 VALUES (?1, ?2); UPDATE hitdns_cache_v1 SET entry = ?2 WHERE query = ?1").bind(query).bind(entry).execute(&*HITDNS_SQLITE_POOL).await.log_warn()?;
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
    memory: scc::HashMap<DNSQuery, DNSCacheEntry>,
    //disk: SqlitePool,
    //resolvers: Arc<DNSResolvers>,
    resolver: DNSOverHTTPS,
}
/// SAFETY: Async access
unsafe impl Sync for DNSCache {}
unsafe impl Send for DNSCache {}

impl DNSCache {
    async fn new(resolver: DNSOverHTTPS) -> anyhow::Result<Self> {
        let memory = scc::HashMap::new();

        let mut ret = sqlx::query("SELECT * FROM hitdns_cache_v1").fetch(&*HITDNS_SQLITE_POOL);
        while let Ok(Some(line)) = ret.try_next().await {
            assert_eq!(line.columns().len(), 2);
            let query: Vec<u8> = line.try_get_raw(0)?.to_owned().decode();
            let entry: Vec<u8> = line.try_get_raw(1)?.to_owned().decode();

            let query: DNSQuery = bincode::deserialize(&query).log_error()?;
            let entry: DNSEntry = bincode::deserialize(&entry).log_error()?;
            let cache_entry: DNSCacheEntry = Arc::new(entry).into();
            memory.insert_async(query, cache_entry).await.unwrap();
        }
        Ok(Self {
            memory,
            //disk,
            resolver,
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
            //self.resolvers.select_best(),
            self.resolver.clone(),
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
    map: Arc<std::collections::HashMap<String, Vec<IpAddr>>>,
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

impl reqwest::dns::Resolve for Hosts {
    fn resolve(&self, domain: hyper::client::connect::dns::Name) -> reqwest::dns::Resolving {
        let mut domain: String = domain.as_str().to_string();
        if ! domain.ends_with(".") {
            domain.push('.');
        }
        let domain = domain.to_ascii_lowercase();

        let maybe_ips:Option<Vec<IpAddr>> = match self.map.get(&domain) {
            Some(v) => { Some(v.clone()) },
            None => { None },
        };
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
}

impl<'a> DNSOverHTTPS {
    const CONTENT_TYPE: &'static str = "application/dns-message";

    fn new(url: impl ToString, maybe_hosts: Option<Hosts>) -> anyhow::Result<Self> {
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

        // client builder
        let mut cb =
            reqwest::Client::builder()

            // log::trace
            .connection_verbose(true)

            // use HTTPS(rustls) only
            .use_rustls_tls()
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            .https_only(true)
            .tls_sni(false)

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
                    let mut x = Vec::new();
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
            url,
        })
    }
}

impl DNSResolver for DNSOverHTTPS {
    // un-cached DNS Query
    async fn dns_resolve(&self, query: &DNSQuery) -> anyhow::Result<dns::Message> {
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

    fn dns_upstream(&self) -> String {
        self.url.to_string()
    }

    fn dns_protocol(&self) -> &'static str {
        "DNS over HTTP/2 over TLS over TCP"
    }
}

type TlsStream =async_tls::client::TlsStream<TcpStream>;
struct DNSOverTLS {
    connector: async_tls::TlsConnector,
    sessions: Vec<TlsStream>,
    addr: SocketAddr,
}
struct DNSOverQUIC {
    addr: SocketAddr,
}

enum DNSUpstream {
    DoH(DNSOverHTTPS),
    DoT(DNSOverTLS),
    DoQ(DNSOverQUIC),
}

//#[async_trait]
trait DNSResolver {
    /// un-cached DNS query
    fn dns_resolve(&self, query: &DNSQuery) -> impl Future<Output=anyhow::Result<dns::Message>>;

    /// a description for upstream, usually URL or any other.
    fn dns_upstream(&self) -> String;

    /// a protocol type of upstream
    fn dns_protocol(&self) -> &str;
}

/*
impl DNSResolver for T
where T: 
{
}

impl core::fmt::Debug for dyn DNSResolver {
    fn fmt(&self, f: 
}*/

struct DNSResolvers {
    //list: Vec<Arc<dyn DNSResolver>>,
}
/*
impl DNSResolvers {
    fn select_best(&self) -> anyhow::Result<impl DNSResolver> {
        let resolver = self.list[0].clone();
        Ok(resolver)
    }
}*/

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

        let cache_ = Arc::new(DNSCache::new(
            DNSOverHTTPS::new(
                opt.doh_upstream,
                if let Some(ref hosts_filename) = opt.hosts {
                    hosts_filename.try_into().log_warn().ok()
                } else {
                    None
                }
            )?
        ).await?);

        let cache = cache_.clone();
        let udp = udp_.clone();
        let udp_task = smolscale::spawn(async move {
            let mut buf = vec![0u8; 65535];
            let mut msg;
            loop {
                let (len, peer) = udp.recv_from(&mut buf).await.log_error()?;
                msg = buf[..len].to_vec();
                let udp = udp.clone();
                let cache = cache.clone();
                smolscale::spawn(async move {
                    let req = dns::Message::from_vec(&msg).log_debug()?;
                    let res: dns::Message = cache.query(req).await.log_warn()?;
                    udp.send_to(res.to_vec().unwrap().as_ref(), peer).await.log_error()?;
                    Ok::<_, anyhow::Error>(())
                }).detach();
            }

            #[allow(unreachable_code)]
            Ok(())
        });

        let cache = cache_.clone();
        let tcp = tcp_.clone();
        let tcp_task = smolscale::spawn(async move {
            loop {
                let (mut conn, peer) = tcp.accept().await.log_error()?;
                log::info!("DNS Daemon accepted new TCP connection from {peer:?}");
                let cache = cache.clone();
                smolscale::spawn(async move {
                    let mut buf = vec![0u8; 65535];
                    let mut buf2: Vec<u8> = Vec::new();
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
            log::trace!("cache status: {:?}", self.cache.memory.len());
            log::trace!("smolscale worker threads: {:?}", smolscale::running_threads());
            log::trace!("tcp listener: {:?}\ntcp task: {:?}", &self.tcp, &self.tcp_task);
            log::trace!("udp socket: {:?}\nudp task: {:?}", &self.udp, &self.udp_task);

            if self.tcp_task.is_finished() || self.udp_task.is_finished() {
                log::error!("listener died");
                return;
            }

            smol::Timer::after(Duration::from_secs(10)).await;
        }
    }
}

#[derive(Debug, Clone, clap::Parser)]
struct HitdnsOpt {
    /// location of a hosts.txt file.
    /// examples of this file format, that can be found at /etc/hosts (Unix-like systems), or
    /// C:\Windows\System32\drivers\etc\hosts (Windows)
    #[arg(long)]
    hosts: Option<PathBuf>,

    #[arg(long)]
    use_system_hosts: bool,

    #[arg(long, default_value="127.0.0.1:10053")]
    listen: SocketAddr,

    #[arg(long, default_value="https://1.0.0.1/dns-query")]
    doh_upstream: String,
}

async fn main_async() -> anyhow::Result<()> {
    env_logger::init();
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
    /*
    std::panic::set_hook(Box::new(|info| {
        log::error!("panic! {info:?}");
        //std::panic::default_hook(info);
    }));*/
    smolscale::permanently_single_threaded();
    //smolscale::set_max_threads(2);
    smolscale::block_on(main_async())
}
