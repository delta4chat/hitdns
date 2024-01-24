use std::time::{Duration, Instant, SystemTime};

use std::sync::Arc;
use std::pin::Pin;

mod dns {
    pub use hickory_proto::op::*;
    pub use hickory_proto::rr::{/*Name, */IntoName};
    //pub use hickory_proto::rr::record_type::RecordType;
}

use serde::{Serialize, Deserialize};
use bytes::Bytes;

use std::net::{SocketAddr/*, IpAddr*/};
use smol::net::AsyncToSocketAddrs;
use smol::net::UdpSocket;
use smol::net::{TcpListener, TcpStream};
use smol::io::{AsyncReadExt, AsyncWriteExt};
use smol::stream::{StreamExt};

use smol::channel::{Sender, Receiver};

use sqlx::sqlite::{SqlitePool, SqlitePoolOptions, SqliteConnectOptions, SqliteJournalMode, SqliteLockingMode, SqliteSynchronous};
use sqlx::{Row, Value, ValueRef};
use async_lock::RwLock;

use smol_timeout::TimeoutExt;
use async_trait::async_trait;

use once_cell::sync::Lazy;
use std::path::PathBuf;

// command line argument parser
use clap::Parser;

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
impl TryInto<DNSQuery> for dns::Message {
    type Error = anyhow::Error;
    fn try_into(self: dns::Message) -> anyhow::Result<DNSQuery> {
        if self.message_type() != dns::MessageType::Query {
            anyhow::bail!("unexpected received non-query DNS message: {self:?}");
        }
        let queries = self.queries();
        let queries_len = queries.len();
        if queries_len == 0 {
            anyhow::bail!("unexpected DNS query message without any query section: {self:?}");
        }
        if queries_len > 1 {
            anyhow::bail!("unexpected DNS query message with multi queries: {self:?}");
        }

        /*
        if self.name_servers().len() > 0 || self.answers().len() > 0 {
            anyhow::bail!("unexpected DNS query message with authority/answer section: {self:?}");
        }
        */

        assert!(queries_len == 1);
        let query: dns::Query = queries[0].clone();
        Ok(query.into())
    }
}

impl From<dns::Query> for DNSQuery {
    fn from(val: dns::Query) -> DNSQuery {
        DNSQuery {
            name: val.name().to_string(),
            rdclass: val.query_class().into(),
            rdtype: val.query_type().into(),
        }
    }
}
impl From<DNSQuery> for dns::Query {
    fn from(val: DNSQuery) -> dns::Query {
        use dns::IntoName;
        dns::Query::new()
            .set_name(val.name.into_name().unwrap())
            .set_query_class(val.rdclass.into())
            .set_query_type(val.rdtype.into())
            .to_owned()
    }
}

impl From<DNSQuery> for dns::Message {
    fn from(val: DNSQuery) -> dns::Message {
        dns::Message::new()
            .set_id(0)
            .set_message_type(dns::MessageType::Query)
            .set_op_code(dns::OpCode::Query)
            .set_recursion_desired(true)
            .set_recursion_available(false)
            .set_authentic_data(false)
            .set_checking_disabled(false)
            .add_query(val.into())
            .to_owned()
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

impl TryInto<dns::Message> for &DNSEntry {
    type Error = anyhow::Error;
    fn try_into(self) -> anyhow::Result<dns::Message> {
        Ok(dns::Message::from_vec(&self.response)?)
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
    query: DNSQuery,
    entry: Arc<RwLock<
               Option<Arc<DNSEntry>>
           >>,
    update_task: Arc<RwLock<
                Arc< smol::Task<anyhow::Result<()>> >
                  >>,
    update_notify: Arc<RwLock<Receiver<()>>>,
}
impl From<DNSQuery> for DNSCacheEntry {
    fn from(query: DNSQuery) -> DNSCacheEntry {
        let (_, update_notify) = smol::channel::bounded(1);
        DNSCacheEntry {
            query,
            entry: Arc::new(RwLock::new(None)),
            update_task: Arc::new(
                RwLock::new(
                    Arc::new(
                        smol::spawn(smol::future::ready(Ok(())))
                    )
                )
            ),
            update_notify: Arc::new(RwLock::new(update_notify)),
        }
    }
}
impl From<DNSEntry> for DNSCacheEntry {
    fn from(entry: DNSEntry) -> DNSCacheEntry {
        let (_, update_notify) = smol::channel::bounded(1);
        DNSCacheEntry {
            query: entry.query.clone(),
            entry: Arc::new(RwLock::new(Some(Arc::new(entry)))),
            update_task: Arc::new(
                RwLock::new(
                    Arc::new(
                        smol::spawn(smol::future::ready(Ok(())))
                    )
                )
            ),
            update_notify: Arc::new(RwLock::new(update_notify)),
        }
    }
}

impl DNSCacheEntry {
    async fn status(&self) -> DNSCacheStatus {
        let maybe_entry = self.entry.read().await;
        if maybe_entry.is_some() {
            maybe_entry.clone().unwrap().into()
        } else {
            DNSCacheStatus::Miss
        }
    }

    // wait until finish.
    async fn wait(&self) {
        while self.is_updating().await {
            log::trace!("still in updating...");
            //smol::Timer::after(Duration::from_millis(50)).await;
            let _ = self.update_notify.read().await.recv().await;
        }

    }
    async fn is_updating(&self) -> bool {
        if let Some(t) = self.update_task.read().timeout(Duration::from_millis(20)).await {
            t.is_finished() == false
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
            log::debug!("another update processing.");

            if let DNSCacheStatus::Miss = status {
                log::debug!("no last success result. force waiting until first result producted.");

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
        *self.update_notify.write().await = update_rx;
        *self.update_task.write().await = Arc::new(
            smolscale::spawn(async move {
                let upstream = resolver.dns_upstream();
                let start = Instant::now();
                let mut response = match resolver.dns_resolve(query.clone()).timeout(timeout).await {
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
                    query: query.clone(),
                    response: response.to_vec()?,
                    elapsed,
                    upstream,
                    expire,
                });
                *entry_lock.write().await = Some(entry.clone());
                update_tx.send(()).await?;

                {
                    let query: Vec<u8> = bincode::serialize(&query)?;
                    let entry: Vec<u8> = bincode::serialize(&entry)?;
                    sqlx::query("INSERT OR IGNORE INTO hitdns_cache_v1 VALUES (?1, ?2); UPDATE hitdns_cache_v1 SET entry = ?2 WHERE query = ?1").bind(query).bind(entry).execute(&*HITDNS_SQLITE_POOL).await?;
                }

                Ok(())
            })
        );

        if let DNSCacheStatus::Miss = status {
            // this is first query (or previous queries never success).
            // so must wait until finished.

            log::debug!("there no any previous success result, must wait...");
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
    //resolvers: DNSResolvers,
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

            let query: DNSQuery = bincode::deserialize(&query)?;
            let entry: DNSEntry = bincode::deserialize(&entry)?;
            let cache_entry: DNSCacheEntry = entry.into();
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
        log::debug!("received new query: {:?}", &req);
        let req_id: u16 = req.id();
        let query: DNSQuery = req.try_into()?;

        let cache_entry =
            self.memory.entry_async(query.clone()).await
            .or_insert_with(||{
                query.clone().into()
            })
            .get().clone();

        let entry = cache_entry.update(
            //self.resolvers.select_best(),
            self.resolver.clone(),
            Duration::from_secs(10)
        ).await?;

        let now_unix = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)?;
        let expire_unix = entry.expire.duration_since(SystemTime::UNIX_EPOCH)?;

        let mut res: dns::Message = entry.as_ref().try_into()?;
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

        Ok(res)
    }
}

#[derive(Debug, Clone)]
struct DNSOverHTTPS {
    client: reqwest::Client,
    url: reqwest::Url,
}

impl DNSOverHTTPS {
    const CONTENT_TYPE: &'static str = "application/dns-message";
    fn new(url: impl ToString) -> anyhow::Result<Self> {
        let url: String = url.to_string();
        let url = reqwest::Url::parse(&url)?;

        if url.scheme() != "https" {
            anyhow::bail!("DoH server URL scheme invalid.");
        }
        
        struct NoDNS;
        impl reqwest::dns::Resolve for NoDNS {
            fn resolve(&self, _: hyper::client::connect::dns::Name) -> reqwest::dns::Resolving {
                panic!("un");
                /*
                Pin::new(Box::new(async move {
                    Err(anyhow::Error::msg("unexpected DNS resolve request from reqwest::Client in DoH client."))
                }))*/
            }
        }

        let client =
            reqwest::Client::builder()

            // disable all DNS resove
            .dns_resolver(Arc::new(NoDNS{}))

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

            // build client
            .build()?;

        Ok(Self {
            client,
            url,
        })
    }
}
/*
/// SAFETY: Async
unsafe impl Sync for DNSOverHTTPS {}
unsafe impl Send for DNSOverHTTPS {}
*/

//impl DNSResolver for DNSOverHTTPS {
impl DNSOverHTTPS {
    // un-cached DNS Query
    async fn dns_resolve(&self, query: DNSQuery) -> anyhow::Result<dns::Message> {
        log::info!("DoH un-cached Query: {query:?}");

        let req: dns::Message = query.into();

        let client = self.client.clone();
        let url = self.url.clone();

        let http_res = client.post(url)
            .header("Content-Type", Self::CONTENT_TYPE)
            .header("Accept", Self::CONTENT_TYPE)
            .body(req.to_vec()?)
            .send().await?;

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

        let res: Bytes = http_res.bytes().await?;
        let mut response =
            dns::Message::from_vec(&res)?;
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

#[async_trait]
trait DNSResolver: Send + Sync + 'static {
    /// un-cached DNS query
    async fn dns_resolve(&self, query: DNSQuery) -> anyhow::Result<dns::Message>;

    /// a description for upstream, usually URL or any other.
    fn dns_upstream(&self) -> String;

    /// a protocol type of upstream
    fn dns_protocol(&self) -> &str;
}

/*
#[derive(Clone)]
struct DNSResolvers(Vec<Arc<Box<dyn DNSResolver>>>);

impl DNSResolvers {
    async fn select_best(&'a self) -> anyhow::Result<Arc<Box<dyn DNSResolver>>> {
        let resolver = self.0 [0].clone();
        Ok(resolver)
    }
}*/

struct DNSDaemon {
    udp: UdpSocket, udp_task: smol::Task<anyhow::Result<()>>,
    tcp: TcpListener, tcp_task: smol::Task<anyhow::Result<()>>,
    cache: Arc<DNSCache>,
}

impl DNSDaemon {
    async fn new(listen: impl AsyncToSocketAddrs, doh_url: impl ToString) -> anyhow::Result<Self> {
        let udp_ = UdpSocket::bind(&listen).await?;
        let tcp_ = TcpListener::bind(&listen).await?;

        let cache_ = Arc::new(DNSCache::new(
            DNSOverHTTPS::new(doh_url.to_string())?
        ).await?);

        let cache = cache_.clone();
        let udp = udp_.clone();
        let udp_task = smolscale::spawn(async move {
            let mut buf = vec![0u8; 65535];
            let mut msg;
            loop {
                let (len, peer) = udp.recv_from(&mut buf).await?;
                msg = buf[..len].to_vec();
                let udp = udp.clone();
                let cache = cache.clone();
                smolscale::spawn(async move {
                    let req = dns::Message::from_vec(&msg)?;
                    let res: dns::Message = cache.query(req).await?;
                    udp.send_to(res.to_vec().unwrap().as_ref(), peer).await?;
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
                let (mut conn, peer) = tcp.accept().await?;
                log::debug!("accepted new incoming TCP DNS request from {peer:?}");
                let cache = cache.clone();
                smolscale::spawn(async move {
                    let mut buf = vec![0u8; 65535];
                    let mut buf2;
                    let mut len = [0u8; 2];
                    let mut len2: usize;

                    let mut req: dns::Message;
                    let mut res: dns::Message;
                    loop {
                        conn.read_exact(&mut len).await?;
                        len2 = u16::from_be_bytes(len) as usize;
                        conn.read_exact(&mut buf[..len2]).await?;

                        req = dns::Message::from_vec(&buf[..len2])?;
                        res = cache.query(req).await?;
                        buf2 = res.to_vec()?;
                        len2 = buf2.len();
                        assert!(len2 <= 65535);
                        len = (len2 as u16).to_be_bytes();

                        conn.write(&len).await?;
                        conn.write_all(&buf2).await?;
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
        self.udp_task.detach();
        self.tcp_task.detach();

        loop {
            log::trace!("cache status: {:?}", self.cache.memory.len());
            log::trace!("smolscale worker threads: {:?}", smolscale::running_threads());
            log::trace!("tcp: {:?}", self.tcp);
            log::trace!("udp: {:?}", self.udp);
            smol::Timer::after(Duration::from_secs(10)).await;
        }
    }
}

#[derive(Debug, Clone, clap::Parser)]
struct HitdnsOpt {
    #[arg(long, default_value="127.0.0.1:10053")]
    listen: SocketAddr,

    #[arg(long, default_value="https://1.0.0.1/dns-query")]
    doh_upstream: String,
}

async fn main_async() -> anyhow::Result<()> {
    env_logger::init();
    let opt = HitdnsOpt::parse();
    DNSDaemon::new(opt.listen, opt.doh_upstream).await?.run().await;
    Ok(())
}

fn main() -> anyhow::Result<()> {
    smolscale::block_on(main_async())
}
