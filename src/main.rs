// cache.rs
pub mod cache;
pub use cache::*;

// db.rs
pub mod db;
pub use db::*;

// types.rs
pub mod types;
pub use types::*;

// traits.rs
pub mod traits;
pub use traits::*;

// hosts.rs
pub mod hosts;
pub use hosts::*;

// protocol/*.rs
pub mod protocol;
pub use protocol::*;

// dohp.rs
pub mod dohp;
pub use dohp::*;

// api.rs
pub mod api;
pub use api::*;

// stats.rs
pub mod stats;
pub use stats::*;

// test.rs
mod test;

/* ==================== */

pub use core::ops::{Deref, DerefMut, Add, Div};
pub use core::pin::Pin;
pub use core::time::Duration;

pub use core::fmt::Debug;
pub use core::iter::Sum;

extern crate alloc;
pub use alloc::collections::VecDeque;
pub use alloc::sync::Arc;

pub use std::net::{IpAddr, SocketAddr};
pub use std::path::{Path, PathBuf};
pub use std::time::{Instant, SystemTime};

pub mod dns {
    pub use hickory_proto::op::*;
    pub use hickory_proto::rr::{
        IntoName,
        domain::Name,
        LowerName,
        RecordData,
        dns_class::DNSClass,
        record_type::RecordType,
        record_data::RData,
        dnssec::rdata::key::{KeyTrust, KeyUsage},
        rdata,
        Record,
    };

    pub use hickory_proto::serialize::binary::BinEncodable;

    pub use DNSClass as Class;
    pub use DNSClass as RdClass;
    pub use RecordType as Type;
    pub use RecordType as RdType;
}

#[cfg(not(feature="doh3"))]
pub use reqwest as reqwest_h3;

pub use portable_atomic::{AtomicUsize, AtomicU64, AtomicU8, AtomicBool};

pub use bytes::Bytes;
pub use serde::{Serialize, Deserialize};

pub use smol::net::AsyncToSocketAddrs;

pub use smol::net::UdpSocket;
pub use smol::net::{TcpListener, TcpStream};

pub use smol::io::{
    AsyncReadExt, AsyncWriteExt,
    AsyncRead, AsyncWrite,
};
pub use smol::stream::StreamExt;

pub use smol::channel::{Receiver, Sender};
pub use smol::future::Future;

#[cfg(feature = "sqlite")]
pub use sqlx::{
    sqlite::{
        SqliteConnectOptions, SqliteJournalMode,
        SqliteLockingMode, SqlitePool, SqlitePoolOptions,
        SqliteSynchronous,
    },
    {Row, Value, ValueRef},
};

pub use once_cell::sync::Lazy;

pub use anyhow::Context;

// command line argument parser
pub use clap::Parser;

pub use smoltimeout::TimeoutExt;

// hitdns nonce randomly for each run
pub static HITDNS_NONCE: Lazy<String> = Lazy::new(|| {
    let unix = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs_f64();

    let rand = fastrand::u128(..);

    format!("{unix}_{rand}")
});

pub fn unique<T: PartialEq+Clone>(set: &mut Vec<T>) {
    let mut new = Vec::new();
    for it in set.iter() {
        if new.contains(it) {
            continue;
        }
        new.push(it.clone());
    }

    set.clear();
    set.extend(new);
}

// hitdns opt parsed from clap or toml-env
pub static HITDNS_OPT: Lazy<HitdnsOpt> = Lazy::new(|| {
    smol::block_on(async move {
        let mut opt = HitdnsOpt::parse();

        if let Some(ref config) = opt.config {
            let mut args: toml_env::Args = Default::default();

            args.config_path = Some(config);
            args.logging = toml_env::Logging::Log; // use `log` crate for logging

            // use empty name to disable these config source
            args.dotenv_path = Path::new("");
            args.config_variable_name = "";

            match toml_env::initialize(args) {
                Ok(val) => {
                    if let Some(opt_toml) = val {
                        log::info!("loaded config from TOML config file: {config:?}");
                        opt = opt_toml;
                    }
                },
                Err(err) => {
                    log::error!("cannot parse TOML config file ({config:?}): {err:?}");
                }
            }

        }
        
        /* ===== handle Test mode ===== */
        if opt.test {
            opt.listen = vec![ "127.8.9.6:0".parse().unwrap() ];
        }

        /* ===== handle optional args ===== */

        if opt.min_ttl.is_none() {
            opt.min_ttl = Some(180); // 3 minutes
        }

        if opt.max_ttl.is_none() {
            opt.max_ttl = Some(604800); // 7 days
        }

        /* ============= */

        if opt.use_system_hosts && opt.hosts.is_none() {
            let filename =
                if cfg!(target_vendor = "apple") {
                    "/private/etc/hosts".to_string()
                } else if cfg!(target_os = "android") {
                    "/system/etc/hosts".to_string()
                } else if cfg!(target_family = "unix") {
                    "/etc/hosts".to_string()
                } else if cfg!(target_family = "windows") {
                    let mut out = std::env::var("SystemDrive").unwrap_or(String::from("C:"));
                    out.push_str(r"\Windows\System32\drivers\etc\hosts");
                    out
                } else {
                    "".to_string()
                };

            if filename.is_empty() {
                log::warn!("cannot find your system-side hosts.txt, please provaide a path by --hosts");
            } else {
                let filename = PathBuf::from(filename);
                opt.hosts = Some(filename);
            }
        }

        unique(&mut opt.listen);
        for idx in 0 .. opt.listen.len() {
            let listen = opt.listen[idx];

            if listen.port() == 0 { // handle port 0 (automatic allocated by OS)
                let adr = smol::net::UdpSocket::bind(listen).await.unwrap();
                opt.listen[idx] = adr.local_addr().unwrap();
            }
        }
        unique(&mut opt.listen);

        let maybe_listen = opt.listen.first();
        let mut ports: Vec<u16> = opt.listen.iter().map(|adr| { adr.port() }).collect();

        unique(&mut opt.dohp_listen);
        if ! opt.no_dohp {
            if opt.dohp_listen.is_empty() && maybe_listen.is_some() {
                let mut dyna: SocketAddr = "127.0.0.1:0".parse().unwrap();
                dyna.set_port(maybe_listen.unwrap().port());

                loop {
                    dyna.set_port(dyna.port().checked_sub(1).unwrap_or(dyna.port()));

                    // skip the port used by others
                    if ports.contains(&dyna.port()) {
                        continue;
                    }

                    if let Ok(sock) = TcpListener::bind(dyna).await {
                        if let Ok(addr) = sock.local_addr() {
                            dyna = addr;
                            ports.push(addr.port());
                            break;
                        }
                    }
                }

                opt.dohp_listen.push(dyna);
            }
        }
        unique(&mut opt.dohp_listen);

        if ! opt.no_api {
            if opt.api_listen.is_none() && maybe_listen.is_some() {
                let mut dyna: SocketAddr = "127.0.0.1:0".parse().unwrap();
                dyna.set_port(maybe_listen.unwrap().port());

                loop {
                    dyna.set_port(dyna.port().checked_sub(1).unwrap_or(dyna.port()));

                    // skip the port used by others
                    if ports.contains(&dyna.port()) {
                        continue;
                    }

                    if let Ok(sock) = TcpListener::bind(dyna).await {
                        if let Ok(addr) = sock.local_addr() {
                            dyna = addr;
                            ports.push(addr.port());
                            break;
                        }
                    }
                }

                opt.api_listen = Some(dyna);
            }
        }

        /* ===== handle --disable-ipv6 ===== */
        if opt.disable_ipv6 {
            for addr in opt.listen.iter() {
                if addr.is_ipv6() {
                    panic!("IPv6 is disabled by config, please do not use IPv6 address for --listen");
                }
            }
            if let Some(addr) = opt.api_listen {
                if addr.is_ipv6() {
                    panic!("IPv6 is disabled by config, please do not use IPv6 address for --api-listen");
                }
            }
            for addr in opt.dohp_listen.iter() {
                if addr.is_ipv6() {
                    panic!("IPv6 is disabled by config, please do not use IPv6 address for --dohp-listen");
                }
            }
        }

        opt
    }) // smol::block_on
});

pub static HITDNS_DIR: Lazy<PathBuf> = Lazy::new(|| {
    let dir =
        if HITDNS_OPT.test {
            directories::ProjectDirs::from("org", "delta4chat", "hitdns-test")
            .expect("Cannot get platform-specified dir (via `directories::ProjectDirs`)")
            .data_dir()
            .to_owned()
        } else {
            if let Some(ref val) = (&*HITDNS_OPT).data_dir {
                val.to_owned()
            } else {
                directories::ProjectDirs::from("org", "delta4chat", "hitdns")
                .expect("Cannot get platform-specified dir (via `directories::ProjectDirs`)")
                .data_dir()
                .to_owned()
            }
        };

    std::fs::create_dir_all(&dir).expect("cannot create project dir {dir:?}");

    dir
});

#[cfg(feature = "ftlog")]
pub static TIME_FMT_JS: Lazy<time::format_description::OwnedFormatItem> = Lazy::new(|| {
    time::format_description::parse_owned::<1>(
        // RFC-3339 format with 3 digits of sub-seconds
        // (aka. JavaScript 'Date' Format)
        "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"
    ).unwrap()
});

/*
pub trait Average<  T: Default + Copy + From<u64>  > {
    fn average(&self: &[T]) -> T {
        average(self)
    }
}
*/

pub fn randchr() -> char {
    const TEMPLATE: &[char] = &[
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'
    ];
    const TEMPLATE_LEN: usize = TEMPLATE.len();

    return TEMPLATE[fastrand::usize(0..TEMPLATE_LEN)];
}
pub fn randstr(len: usize) -> String {
    let mut out = String::new();
    for _ in 0..len {
        out.push(randchr());
    }
    out
}

/// u128 nanoseconds version of [core::time::Duration::from_nanos](https://doc.rust-lang.org/1.84.1/src/core/time.rs.html#318-326)
pub const fn duration_from_nanos(nanos: u128) -> Duration {
    const NANOS_PER_SEC: u128 = 1_000_000_000;

    let secs = (nanos / NANOS_PER_SEC) as u64;
    let subsec_nanos = (nanos % NANOS_PER_SEC) as u32;

    Duration::new(secs, subsec_nanos)
}

pub fn average<T>(mut iter: impl Iterator<Item=T>, one: T) -> T
where
    T: Default + Copy + Ord + Add<Output=T> + Div<Output=T>
{
    let mut len: T = Default::default();
    let mut sum: T = Default::default();

    while let Some(val) = iter.next() {
        sum = sum + val;
        len = len + one;
    }

    if len > Default::default() {
        sum / len
    } else {
        Default::default()
    }
}

// a helper for wrapping non-Sized
pub async fn timeout_helper<T>(
    fut: impl Future<Output = T>,
    time: Duration,
) -> Option<T> {
    let fut = async move { fut.await };
    fut.timeout(time).await
}

#[derive(Debug, Clone)]
pub struct DNSQueryInfo {
    peer: String,
    query_msg: dns::Message,
    query: DNSQuery,
    time: SystemTime,
    delta: Duration,

    cache_status: Option<DNSCacheStatus>,
    used_time: Option<Duration>,
}
impl From<dns::Message> for DNSQueryInfo {
    fn from(val: dns::Message) -> Self {
        Self {
            peer: String::new(),
            query_msg: val.clone(),
            query: val.try_into().expect("dns message is not a valid query"),
            time: SystemTime::now(),
            delta: Default::default(),

            cache_status: None,
            used_time: None,
        }
    }
}

fn dns_hosts_hook(
    info: &DNSQueryInfo,
    opt: HitdnsOpt,
) -> PinFut<Option<dns::Message>> {
    Box::pin(async move {
        let mut resp = None;

        if info.query.rdclass != 1 {
            return resp;
        }

        match info.query.rdtype {
            1 | 28 => {
                let mut ips = Vec::new();
                if let Some(ip46) = HOSTS.lookup(info.query.name.as_str()) {
                    for ip in ip46.into_iter() {
                        match info.query.rdtype {
                            1 => {
                                if ip.is_ipv4() {
                                    ips.push(ip);
                                }
                            },
                            28 => {
                                if ip.is_ipv6() {
                                    ips.push(ip);
                                }
                            },
                            _ => { unreachable!() }
                        }
                    }
                }

                if ! ips.is_empty() {
                    let mut res = info.query_msg.clone();
                    res.set_op_code(dns::OpCode::Query);
                    res.set_message_type(dns::MessageType::Response);

                    res.additionals_mut().clear();
                    res.name_servers_mut().clear();
                    res.extensions_mut().take();

                    let answers = res.answers_mut();
                    answers.clear();

                    for ip in ips.iter() {
                        let mut answer = dns::Record::new();
                        answer.set_name(dns::Name::from_str_relaxed(info.query.name.clone()).unwrap());
                        answer.set_dns_class(dns::Class::IN);
                        answer.set_ttl(60);
                        answer.set_rr_type(info.query.rdtype.into());

                        match info.query.rdtype {
                            1 => {
                                let ipv4 = match ip {
                                    IpAddr::V4(val) => val,
                                    _ => { unreachable!() }
                                };

                                answer.set_data(
                                    Some(dns::RData::A(dns::rdata::A(*ipv4)))
                                );
                            },
                            28 => {
                                let ipv6 = match ip {
                                    IpAddr::V6(val) => val,
                                    _ => { unreachable!() }
                                };

                                answer.set_data(
                                    Some(dns::RData::AAAA(dns::rdata::AAAA(*ipv6)))
                                );
                            },
                            _ => { unreachable!(); }
                        }

                        answers.push(answer);
                    }

                    resp = Some(res);
                }
            },
            _ => {}
        }

        resp
    })
}

fn dns_ch_hook(
    info: &DNSQueryInfo,
    opt: HitdnsOpt,
) -> PinFut<Option<dns::Message>> {
    Box::pin(async move {
        let mut resp = None;

        let queries = info.query_msg.queries();
        if let Some(query) = queries.get(0) {
            if query.query_class() == dns::Class::CH {
                let mut res = info.query_msg.clone();
                res.set_op_code(dns::OpCode::Query);
                res.set_message_type(dns::MessageType::Response);

                res.additionals_mut().clear();
                res.name_servers_mut().clear();
                res.extensions_mut().take();

                let answers = res.answers_mut();
                answers.clear();

                let name = query.name().to_string();
                if name.ends_with(".hitdns.") {
                    let mut answer = dns::Record::new();
                    answer.set_dns_class(dns::Class::CH);
                    answer.set_ttl(0);
                    answer.set_rr_type(dns::RdType::TXT);

                    let mut texts = vec![];

                    if name.contains("random") {
                        texts.push(format!("{}", fastrand::u128(..)));
                    } else if name.contains("api") {
                        if let Some(api_listen) = opt.api_listen {
                            texts.push(format!("http://{api_listen}/"));
                        }
                    } else if name.contains("dohp") {
                        let mut text = String::new();
                        for dohp_listen in opt.dohp_listen.iter() {
                            text.push_str(&format!("http://{dohp_listen}/ "));
                        }
                        if ! text.is_empty() {
                            text.pop();
                        }
                        texts.push(text);
                    } else if name.contains("listen") {
                        let mut text = String::new();
                        for listen in opt.listen.iter() {
                            text.push_str(&format!("{listen} "));
                        }
                        if ! text.is_empty() {
                            text.pop();
                        }
                        texts.push(text);
                    }

                    answer.set_data(
                        Some(dns::RData::TXT(
                            dns::rdata::TXT::new(texts)
                        ))
                    );
                    answers.push(answer);
                }
                resp = Some(res);
            }
        }

        resp
    })
}

pub type DNSHook = fn(&DNSQueryInfo, HitdnsOpt) -> PinFut<Option<dns::Message>>;

#[derive(Debug, Clone)]
pub struct DNSHookArray {
    // id -> (nice, hook)
    hooks: scc2::HashMap<usize, (i8, Arc<DNSHook>)>,
    opt: HitdnsOpt,
}
impl DNSHookArray {
    pub fn new(opt: HitdnsOpt) -> Self {
        Self {
            hooks: scc2::HashMap::new(),
            opt
        }
    }

    pub async fn add(&self, nice: i8, hook: Arc<DNSHook>) -> usize {
        static HOOK_ID_COUNTER: AtomicUsize = AtomicUsize::new(1000);

        let val = (nice, hook);

        let mut len = self.hooks.len();
        let mut id = HOOK_ID_COUNTER.fetch_add(1, Relaxed);
        while self.hooks.insert_async(id, val.clone()).await.is_err() {
            let mut incr = 1;

            let newlen = self.hooks.len();
            if newlen > len {
                incr += newlen - len;
            }
            len = newlen;

            id = HOOK_ID_COUNTER.fetch_add(incr, Relaxed);
        }

        id
    }
    pub async fn del(&self, id: usize) -> bool {
        self.hooks.remove_async(&id).await.is_some()
    }

    /// if there is needs to overwrite this DNS Query message,
    /// it will return Some with override result.
    ///
    /// anyway, this function will calls ALL associated middleware,
    /// but only "the response with minimal nice value" will be return. (if milti hook with same nice value, then return first one)
    pub async fn via(&self, info: &DNSQueryInfo) -> Option<dns::Message> {
        if self.hooks.is_empty() {
            return None;
        }

        let mut maybe_res: Option<(usize, i8, dns::Message)> = None;

        let mut hooks = vec![];
        self.hooks
            .scan_async(|k, v| {
                hooks.push((*k, v.clone()));
            })
            .await;

        for (cur_id, val) in hooks.iter() {
            let (cur_nice, hook) = val;

            if let Some(cur_res) = (hook)(info, self.opt.clone()).await {
                if let Some((_, prev_nice, _)) = maybe_res {
                    if *cur_nice >= prev_nice {
                        continue;
                    }
                }

                maybe_res = Some((*cur_id, *cur_nice, cur_res));
            }
        }

        if let Some((id, nice, res)) = maybe_res {
            log::debug!("selected hook: id={id} | nice={nice} | res = {res}");
            Some(res)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct DNSDaemonSocket {
    udp: Arc<Vec<UdpSocket>>,
    tcp: Arc<Vec<TcpListener>>,

    // plaintext HTTP with /dns-query for your reverse proxy (for example Nginx) to serve DoH.
    http: Arc<scc2::HashMap<usize, Arc<DNSOverHTTP>>>,
}

#[derive(Debug, Default)]
pub struct DNSDaemonTask {
    udp: scc2::HashMap<SocketAddr, smol::Task<anyhow::Result<()>>>,
    tcp: scc2::HashMap<SocketAddr, smol::Task<anyhow::Result<()>>>,
    http: scc2::HashMap<SocketAddr, smol::Task<anyhow::Result<()>>>,
}

#[derive(Debug)]
pub struct DNSDaemon {
    context: DNSDaemonContext,
    task: Arc<DNSDaemonTask>,
}

impl DNSDaemon {
    pub async fn new(opt: HitdnsOpt) -> anyhow::Result<Self> {
        if opt.listen.is_empty() {
            anyhow::bail!("no listen address specified!");
        };

        let mut udp = Vec::new();
        let mut tcp = Vec::new();
        let http = scc2::HashMap::new();

        for listen in opt.listen.iter() {
            udp.push(UdpSocket::bind(&listen).await.log_error()?);
            tcp.push(TcpListener::bind(&listen).await.log_error()?);
        }

        if let Some(ref hosts_filename) = opt.hosts {
            let _ = HOSTS.load(hosts_filename).await.log_error();
        }

        let resolvers = {
            let mut x: Vec<Arc<dyn DNSResolver>> = vec![];

            // always available
            for doh_url in opt.doh_upstream.iter() {
                if opt.disable_ipv6 && doh_url.contains("[") {
                    log::info!("ignore DoH server {doh_url} due to --disable-ipv6");
                    continue;
                }

                x.push(Arc::new(DNSOverHTTPS::new(
                    doh_url,
                    /*
                    opt.hosts.is_some(),
                    opt.tls_sni,
                    */
                )?));
            }

            #[cfg(feature = "doh3")]
            for doh3_url in opt.doh3_upstream.iter() {
                if opt.disable_ipv6 && doh3_url.contains("[") {
                    log::info!("ignore DoH3 server {doh3_url} due to --disable-ipv6");
                    continue;
                }

                x.push(Arc::new(DNSOverHTTPS::new_h3(
                    doh3_url,
                    /*
                    opt.hosts.is_some(),
                    opt.tls_sni,
                    */
                )?));
            }

            #[cfg(feature = "dot")]
            for dot_addr in opt.dot_upstream.iter() {
                if opt.disable_ipv6 && dot_addr.contains("[") {
                    log::info!("ignore DoT server {dot_addr} due to --disable-ipv6");
                    continue;
                }

                x.push(Arc::new(
                    DNSOverTLS::new(
                        dot_addr,
                        opt.hosts.is_some(),
                    ).await?
                ));
            }

            #[cfg(feature = "doq")]
            for doq_addr in opt.doq_upstream.iter() {
                x.push(Arc::new(DNSOverQUIC::new(doq_addr)?));
            }

            if x.is_empty() {
                if ! opt.no_default_servers {
                    x = DefaultServers::global(&opt);
                    log::info!("no upstream specified. use default servers.");
                }
            }

            if x.is_empty() {
                anyhow::bail!("No DNS Upstream provided.");
            }

            log::info!("Use {} Upstream Servers: {x:#?}", x.len());

            DNSResolverArray::from(x)
        };

        let cache = Arc::new(DNSCache::new(resolvers, opt.debug).await?);

        let hooks = Arc::new(DNSHookArray::new(opt.clone()));
        hooks.add(-1, Arc::new(dns_hosts_hook)).await;
        hooks.add(0, Arc::new(dns_ch_hook)).await;

        let context = DNSDaemonContext {
            socket: DNSDaemonSocket {
                udp: Arc::new(udp),
                tcp: Arc::new(tcp),
                http: Arc::new(http),
            },
            cache,
            opt: opt.clone(),
            hooks,
            stats: Arc::new(DNSQueryStats::new()),
        };

        let task: DNSDaemonTask = Default::default();
        context.handle_udp(&task.udp).await;
        context.handle_tcp(&task.tcp).await;
        context.handle_http(&task.http).await?;

        Ok(Self {
            context,
            task: Arc::new(task),
        })
    }

    async fn run(self) {
        let this = Arc::new(self);

        let task = &this.task;

        let ctx = &this.context;
        let socket = &ctx.socket;
        let cache = &ctx.cache;
        let opt = &ctx.opt;

        if ! opt.no_api {
            if let Some(api_listen) = opt.api_listen {
                if let Ok(api) =
                    HitdnsAPI::new(api_listen, this.clone())
                        .await
                        .log_error()
                {
                    smolscale2::spawn(async move {
                        api.run().await.unwrap();
                    })
                    .detach();
                }
            }
        }

        Lazy::force(&HITDNS_SQLITE_POOL);

        loop {
            if opt.debug {
                log::trace!(
                    "cache status: {:?}",
                    &cache.memory
                );
            }
            log::debug!(
                "cache length: {:?}",
                cache.memory.entry_count()
            );

            log::debug!(
                "smolscale2 worker threads: {:?}",
                smolscale2::running_threads()
            );
            log::debug!(
                "smolscale2 active tasks: {:?}",
                smolscale2::active_task_count()
            );

            log::trace!(
                "tcp listener: {:?}\ntcp task: {:?}",
                socket.tcp.as_ref(),
                task.tcp
            );
            log::trace!(
                "udp socket: {:?}\nudp task: {:?}",
                socket.udp.as_ref(),
                task.udp
            );

            if opt.debug {
                let mut x = vec![];
                for r in cache.resolvers.list.iter() {
                    x.push(r.dns_metrics());
                }

                log::trace!(
                    "DNSResolverArray metrics: {x:#?}"
                );
            }

            this.task.udp.scan_async(|idx, udp| {
                if udp.is_finished() {
                    panic!("#{idx} of UDP socket tasks died");
                }
            }).await;

            this.task.tcp.scan_async(|idx, tcp| {
                if tcp.is_finished() {
                    panic!("#{idx} of TCP listener tasks died");
                }
            }).await;

            this.task.http.scan_async(|idx, http| {
                if http.is_finished() {
                    panic!("#{idx} of DOHP tasks died");
                }
            }).await;

            smol::Timer::after(Duration::from_secs(10)).await;
        }
    }
}

#[derive(Debug, Clone)]
pub struct DNSDaemonContext {
    socket: DNSDaemonSocket,
    cache: Arc<DNSCache>,
    opt: HitdnsOpt,
    hooks: Arc<DNSHookArray>,
    stats: Arc<DNSQueryStats>,
}

unsafe impl Send for DNSDaemonContext {}
unsafe impl Send for DNSDaemonSocket {}
unsafe impl Send for DNSHookArray {}

unsafe impl Sync for DNSDaemonContext {}
unsafe impl Sync for DNSDaemonSocket {}
unsafe impl Sync for DNSHookArray {}

impl DNSDaemonContext {
    async fn handle_query(
        &self,
        info: &mut DNSQueryInfo,
    ) -> anyhow::Result<dns::Message> {
        if info.used_time.is_some() {
            anyhow::bail!("this DNSQueryInfo already fulfilled!");
        }

        if let Some(res) = self.hooks.via(&info).await {
            return Ok(res);
        }

        let t = Instant::now();
        let result =
            self.cache.query_with_status(
                info.query_msg.clone()
            ).await;
        info.used_time = Some(t.elapsed());

        match result {
            Ok((res, status)) => {
                info.cache_status = Some(status);
                self.stats.add_query(info.clone());
                Ok(res)
            },
            Err(e) => {
                self.stats.add_query(info.clone());
                Err(e)
            }
        }
    }

    async fn handle_udp(&self, tasks: &scc2::HashMap<SocketAddr, smol::Task<anyhow::Result<()>>>) {
        for idx in 0 .. self.socket.udp.len() {
            let addr = self.opt.listen[idx];
            if tasks.contains(&addr) {
                continue;
            }
            let udp = self.socket.udp[idx].clone();

            let this = self.clone();
            let task = smolscale2::spawn(async move { this._handle_udp(udp).await });

            let _ = tasks.insert_async(addr, task).await;
        }
    }

    async fn _handle_udp(&self, udp: UdpSocket) -> anyhow::Result<()> {
        let mut buf = vec![0u8; 65535];
        let mut msg: Vec<u8>;

        let this = self.clone();

        loop {
            let t = Instant::now();
            let (len, peer) = udp
                .recv_from(&mut buf).await
                .context("cannot recvfrom udp socket")
                .log_error()?;
            let delta = t.elapsed();

            msg = buf[..len].to_vec();

            let this = this.clone();
            let udp = udp.clone();
            smolscale2::spawn(async move {
                let req =
                    if let Ok(val) = dns::Message::from_vec(&msg).log_debug() {
                        val
                    } else {
                        return;
                    };
                

                let id = req.id();
                let mut info: DNSQueryInfo = req.into();

                info.peer = format!("udp://{peer}/?id={id}");
                info.delta = delta;

                let res =
                    this.handle_query(&mut info).await
                    .log_info().unwrap();

                udp.send_to(
                    res.to_vec()
                    .expect("bug: DNSCache.query returns invalid data")
                    .as_ref(),

                    peer
                ).await
                .log_error()
                .unwrap();
            }).detach();
        }
    }

    async fn handle_tcp(&self, tasks: &scc2::HashMap<SocketAddr, smol::Task<anyhow::Result<()>>>) {
        for idx in 0 .. self.socket.tcp.len() {
            let addr = self.opt.listen[idx];
            if tasks.contains(&addr) {
                continue;
            }

            let tcp = self.socket.tcp[idx].clone();

            let this = self.clone();
            let task = smolscale2::spawn(async move { this._handle_tcp(tcp).await });

            let _ = tasks.insert_async(addr, task).await;
        }
    }

    async fn _handle_tcp(&self, tcp: TcpListener) -> anyhow::Result<()> {
        let this = self.clone();

        loop {
            let (mut conn, peer) =
                tcp.accept().await.log_error()?;
            log::debug!("DNS Daemon accepted new TCP connection from {peer:?}");

            let this = this.clone();
            smolscale2::spawn(async move {
                let mut req_buf = vec![0u8; 65535];
                let mut req: dns::Message;

                let mut res_buf;
                let mut res: dns::Message;

                //let mut buf: Vec<u8> = vec![];

                let mut len_buf = [0u8; 2];
                let mut len: usize;

                loop {
                    let t = Instant::now();

                    // recv first 2 bytes as the length of request message
                    if let Err(_) =
                        conn.read_exact(&mut len_buf)
                        .await
                        .context("cannot recv 'length of DNS query' from tcp. maybe connection closed by peer?")
                        .log_debug()
                    {
                        break;
                    }
                    len = u16::from_be_bytes(len_buf) as usize;

                    // recv request message body
                    if let Err(_) =
                        conn.read_exact(
                            &mut req_buf[..len]
                        ).await
                        .context("cannot recv 'DNS query body' from tcp...")
                        .log_debug()
                    {
                        break;
                    }
                    req = match
                        dns::Message::from_vec(&req_buf[..len])
                        .context("received invalid DNS message from tcp client...")
                        .log_debug()
                    {
                        Ok(v) => v,
                        Err(_) => {
                            break;
                        }
                    };
                    let id = req.id();

                    let mut info: DNSQueryInfo =
                        req.into();

                    info.peer = format!("tcp://{peer}/?id={id}");
                    info.delta = t.elapsed();

                    // handle...
                    res = match
                        this.handle_query(&mut info)
                        .await
                        .context("cannot handle incoming DNS query")
                        .log_warn()
                    {
                        Ok(v) => v,
                        Err(_) => {
                            break;
                        }
                    };

                    // convert response to 'wire format'
                    res_buf = match
                        res.to_vec()
                        .context("Bug: unexpected DNSCache::query() returns invalid dns::Message")
                        .log_error()
                    {
                        Ok(v) => v,
                        Err(_) => {
                            break;
                        }
                    };

                    len = res_buf.len();
                    if len > 65535 {
                        log::error!("Bug: DNS response length too long, it must less than 65536.");
                        break;
                    }
                    len_buf = (len as u16).to_be_bytes();

                    // == concat final response message
                    // i) 2 bytes of $len
                    // ii) remaining $len bytes of body
                    res_buf =
                        len_buf.into_iter()
                        .chain( res_buf.into_iter() )
                        .collect();

                    // send response
                    if let Err(_) =
                        conn.write_all(&res_buf).await
                        .context("cannot send 'DNS response' to tcp. maybe connection closed by peer?")
                        .log_debug()
                    {
                        break;
                    }
                } // tcp connection loop
            }).detach(); // smolscale2::spawn
        } // tcp accept loop
    }

    async fn handle_http(&self, tasks: &scc2::HashMap<SocketAddr, smol::Task<anyhow::Result<()>>>) -> anyhow::Result<()> {
        for idx in 0 .. self.opt.dohp_listen.len() {
            let dl = self.opt.dohp_listen[idx];

            if tasks.contains(&dl) {
                continue;
            }

            let dohp = Arc::new(DNSOverHTTP::new(dl, self.clone()).await?);
            let _ = self.socket.http.insert(idx, dohp.clone());
            let _ = tasks.insert_async(dl, smolscale2::spawn(async move { dohp.run().await })).await;
        }

        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct HitdnsInfo {
    pub name: &'static str,
    pub version: &'static str,
    pub commit: &'static str,
    pub time: &'static str,
    pub target: &'static str,
    pub features: &'static str,
}
impl core::fmt::Display for HitdnsInfo {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        let json = serde_json::json!(self);
        if f.alternate() {
            write!(f, "{json:#}")
        } else {
            write!(f, "{json}")
        }
    }
}

pub static HITDNS_INFO: Lazy<HitdnsInfo> =
    Lazy::new(||{
        let mut info =
            HitdnsInfo {
                name: "HitDNS",
                version: "",
                commit: "",
                time: "",
                target: "",
                features: "",
            };

        if let Some(ver) = option_env!("CARGO_PKG_VERSION") {
            info.version = ver;
        }
        if let Some(t) = option_env!("VERGEN_GIT_COMMIT_TIMESTAMP") {
            let z = t.ends_with("Z");
            let mut t = t.split(".").next().unwrap_or(t).to_string();
            if z {
                if ! t.ends_with("Z") {
                    t.push('Z');
                }
            }
            info.time = Box::leak(Box::new(t));
        }
        if let Some(sha) = option_env!("VERGEN_GIT_SHA") {
            info.commit = sha;
        }
        if let Some(t) = option_env!("VERGEN_CARGO_TARGET_TRIPLE") {
            info.target = t;
        }
        if let Some(f) = option_env!("VERGEN_CARGO_FEATURES") {
            info.features = f;
        }

        info
    });

#[derive(Debug, Clone, Default, Serialize, Deserialize, clap::Parser)]
#[command(author, about, long_about)]
pub struct HitdnsOpt {
    /// show version
    #[arg(long, short='V')]
    #[serde(default)]
    pub version: bool,

    /// Test mode:
    /// * run DNS server at random port
    /// * default to RUST_LOG=debug
    /// * running stress tests and UDP/TCP packet fuzz tests
    #[arg(long)]
    #[serde(default)]
    pub test: bool,

    /// show build information then quit program.
    #[arg(long)]
    #[serde(default)]
    pub info: bool,

    /// specify the location of TOML-formatted config file. if not specified, will use command line args.
    ///
    /// NOTICE: if specified and the config file is valid, the config file will override all command line args.
    ///
    /// NOTE: for ".config" itself, it will be ignored if that read from TOML config file.
    #[arg(long)]
    #[serde(default)]
    pub config: Option<PathBuf>,

    /// specify the data dir. if not specified, will use directories to get platform-specified runtime dir.
    #[arg(long)]
    #[serde(default)]
    pub data_dir: Option<PathBuf>,

    /// specify the work thread number of async runtime. if not specified, will use same number of CPUs
    #[arg(long)]
    #[serde(default)]
    pub threads: Option<usize>,

    /// Dumps all cache entry from disk database file.
    /// if filename is "-", prints to standard output.
    #[arg(long)]
    #[serde(default)]
    pub dump: Option<PathBuf>,

    /// Loads from specified JSON dump file, and saves it to in-disk database.
    /// if filename is "-", read from standard input.
    #[arg(long)]
    #[serde(default)]
    pub load: Option<PathBuf>,

    /// Log file location
    #[arg(long)]
    #[serde(default)]
    pub log_file: Option<PathBuf>,

    /// debug mode.
    #[arg(long)]
    #[serde(default)]
    pub debug: bool,

    /// Minimum TTL of cached DNS entry.
    /// default to 3 minutes.
    #[arg(long)]
    #[serde(default)]
    pub min_ttl: Option<u32>,

    /// Maximum TTL of cached DNS entry.
    /// default to 7 days.
    #[arg(long)]
    #[serde(default)]
    pub max_ttl: Option<u32>,

    /// location of a hosts.txt file.
    /// examples of this file format, that can be found at /etc/hosts (Unix-like systems), or
    /// C:\Windows\System32\drivers\etc\hosts (Windows)
    ///
    /// specify this will override system hosts.
    #[arg(long)]
    #[serde(default)]
    pub hosts: Option<PathBuf>,

    /// Whether try to find system-side hosts.txt
    #[arg(long)]
    #[serde(default)]
    pub use_system_hosts: bool,

    /// Whether use AES cipher suite in TLS.
    /// if this is unspecified, default disable AES cipher (only use Chacha20 Poly1305)
    #[arg(long)]
    #[serde(default)]
    pub tls_aes: bool,

    /// Whether use RSA asymmetric cryptographic in TLS.
    /// if this is unspecified, default disable RSA (only use ECDSA)
    #[arg(long)]
    #[serde(default)]
    pub tls_rsa: bool,

    /// Whether enable TLS SNI extension.
    /// if this is unspecified, default disable SNI (for bypass internet censorship in few totalitarian countries)
    /// if you specified --tls-sni or --hosts or --use-system-hosts, then TLS SNI will enabled by default.
    #[arg(long)]
    #[serde(default)]
    pub tls_sni: bool,

    /// Do not try to connect IPv6 Upstream Servers, and not to bind to [::]
    /// useful for some network without IPv6 support.
    #[arg(long)]
    #[serde(default)]
    pub disable_ipv6: bool,

    /// Listen address of RFC 1035 plaintext DNS server (UDP and TCP).
    #[arg(long)]
    #[serde(default)]
    pub listen: Vec<SocketAddr>, // this is optional because --dump/--load does not need to run DNS server

    /// Listen address of localhost plaintext DoH server.
    /// for now this server supports HTTP/1.1 and HTTP/1.0
    ///
    /// if the DOHP is not explicitly disabled and the API listen address is not specified, the port number is automatically determined based on the DNS listening port: DNS_PORT - 1 (if the port number is in use, then continue decrementing until an available port number is found)
    #[arg(long)]
    #[serde(default)]
    pub dohp_listen: Vec<SocketAddr>,

    /// disable the localhost plaintext DoH server.
    #[arg(long)]
    #[serde(default)]
    pub no_dohp: bool,

    /// Specify the localhost HTTP API listen address, currently it can only be bound to 127.0.0.1 (for security reasons).
    ///
    /// for now this server supports HTTP/1.1 and HTTP/1.0
    ///
    /// if the API is not explicitly disabled and the API listen address is not specified, the port number is automatically determined based on the DNS listening port: DNS_PORT - 2 (if the port number is in use, then continue decrementing until an available port number is found)
    #[arg(long)]
    #[serde(default)]
    pub api_listen: Option<SocketAddr>,

    /// for test or convenience, allow API port to serve DOH-plaintext requests.
    ///
    /// NOTE: for security, you should not to make API and DOHP unified then export it publicly,
    ///
    /// the good idea, that is: use two ports for API and DOHP, and only make DOHP port publicly, and keep the API private (can only access from localhost)
    #[arg(long)]
    #[serde(default)]
    pub api_with_dohp: bool,

    /// disable the localhost HTTP API.
    #[arg(long)]
    #[serde(default)]
    pub no_api: bool,

    /// whether enable full stats (with all query domains)
    #[arg(long)]
    #[serde(default)]
    pub stats_full: bool,

    /// upstream URL of DoH servers.
    /// DNS over HTTPS (RFC 8484)
    #[arg(long)]
    #[serde(default)]
    pub doh_upstream: Vec<String>,

    /// whether hide the User-Agent for DoH requests
    #[arg(long)]
    #[serde(default)]
    pub doh_hide_ua: bool,

    #[cfg(feature = "doh3")]
    /// ** Experimental **
    /// upstream URL of DoH3 servers.
    /// DNS over HTTP/3
    #[arg(long)]
    #[serde(default)]
    pub doh3_upstream: Vec<String>,

    #[cfg(feature = "doh3")]
    /// only use HTTP/3 for all DoH servers
    #[arg(long)]
    #[serde(default)]
    pub doh3_only: bool,

    /// without built-in default list of global DNS resolvers.
    #[arg(long)]
    #[serde(default)]
    pub no_default_servers: bool,

    #[cfg(feature = "dot")]
    /// *Experimental*
    /// upstream address of DoT servers.
    /// DNS over TLS (RFC 7858)
    #[arg(long)]
    #[serde(default)]
    pub dot_upstream: Vec<String>,

    #[cfg(feature = "doq")]
    /// *Experimental*
    /// upstream address of DoQ servers.
    /// DNS over QUIC (RFC 9250)
    #[arg(long)]
    #[serde(default)]
    pub doq_upstream: Vec<String>,
}

pub struct DefaultServers;
impl DefaultServers {
    /// Global servers.
    pub fn global(opt: &HitdnsOpt) -> Vec<Arc<dyn DNSResolver>> {
        let mut list: Vec<Arc<dyn DNSResolver>> = vec![];

        let doh_server_urls = vec![
            // [Anycast] Cloudflare DNS
            "https://1.0.0.1/dns-query",
            "https://1.1.1.1/dns-query",
            "https://[2606:4700:4700::1001]/dns-query",
            "https://[2606:4700:4700::1111]/dns-query",

            // [Anycast] Quad9 DNS (No filter)
            "https://9.9.9.10/dns-query",
            "https://149.112.112.10/dns-query",
            "https://[2620:fe::10]/dns-query",
            "https://[2620:fe::fe:10]/dns-query",

            // [TW] TWNIC DNS 101
            "https://101.101.101.101/dns-query",

            // [DE] dns.sb
            "https://45.11.45.11/dns-query",
            "https://185.222.222.222/dns-query",
            "https://[2a09::]/dns-query",
            "https://[2a11::]/dns-query",

            // [?] Adguard DNS Un-filtered
            "https://94.140.14.140/dns-query",
            "https://94.140.14.141/dns-query",

            // [CH] dns.switch.ch
            "https://130.59.31.248/dns-query",
            "https://130.59.31.251/dns-query",
            "https://[2001:620:0:ff::2]/dns-query",
            "https://[2001:620:0:ff::3]/dns-query",
        ];
        for doh_url in doh_server_urls.iter() {
            if opt.disable_ipv6 && doh_url.contains("[") {
                continue;
            }

            #[cfg(feature = "doh3")]
            if DOH3_ONLY.load(Relaxed) {
                break;
            }

            list.push(Arc::new(
                DNSOverHTTPS::new(doh_url).unwrap(),
            ));
        }

        #[cfg(feature = "doh3")]
        {
            let doh3_server_urls = vec![
                // [Anycast] Cloudflare DNS
                "https://1.0.0.1/dns-query",
                "https://1.1.1.1/dns-query",
                "https://[2606:4700:4700::1001]/dns-query",
                "https://[2606:4700:4700::1111]/dns-query",

                // [DE] dns.sb
                "https://45.11.45.11/dns-query",
                "https://185.222.222.222/dns-query",

                // [?] Adguard DNS Un-filtered
                "https://94.140.14.140/dns-query",
            ];
            for doh3_url in doh3_server_urls.iter() {
                if opt.disable_ipv6 && doh3_url.contains("[") {
                    continue;
                }

                list.push(Arc::new(
                    DNSOverHTTPS::new_h3(doh3_url).unwrap(),
                ));
            }
        }

        list
    }

    /* ========== Regional-specified resolvers ==========
     * WARNING: All of these servers, located in some countries that under very strict Internet Censorship, such as (non-exhaustive):
     * 1. DNS-hijacking/poisoning/spoofing,
     * 2. TLS SNI-based TCP connection reset,
     * 3. IP address blocked by ACL or routing blockhole.
     */
    /// Mainland China, or RPC, aka Communist Totalitarian Dictatorship Authorities of Mainland China
    unsafe fn mainland_china() -> Vec<Arc<dyn DNSResolver>>
    {
        let doh_server_urls = vec![
            // [CN] Alibaba DNS
            "https://223.5.5.5/dns-query",
            "https://223.6.6.6/dns-query",
            // [CN] Qihu 360 DNS
            "https://180.163.249.75/dns-query",
        ];

        let mut list: Vec<Arc<dyn DNSResolver>> = vec![];

        for doh_url in doh_server_urls.iter() {
            list.push(Arc::new(
                DNSOverHTTPS::new(doh_url).unwrap(),
            ));
        }

        list
    }
}

static ENV_FILTER: Lazy<Option<env_filter::Filter>> =
    Lazy::new(|| {
        if let Ok(ref env) = std::env::var("RUST_LOG") {
            Some(
                env_filter::Builder::new()
                    .parse(env)
                    .build()
            )
        } else {
            None
        }
    });

pub static STARTED: Lazy<Instant> = Lazy::new(Instant::now);

async fn main_async() -> anyhow::Result<()> {
    Lazy::force(&STARTED);

    let opt = HITDNS_OPT.clone();

    #[cfg(not(feature = "ftlog"))]
    {
        let _ret = env_logger::builder().try_init();
        //eprintln!("env_logger: try init = {_ret:?}");
    }

    #[cfg(feature = "ftlog")]
    {
        use alloc::borrow::Cow;
        use core::fmt::Display;

        struct MyFmt;
        impl ftlog2::FtLogFormat for MyFmt {
            #[inline]
            fn msg(
                &self,
                record: &log::Record,
            ) -> Box<dyn Send + Sync + Display>
            {
                if let Some(ef) = &*ENV_FILTER {
                    if !ef.matches(record) {
                        return Box::new("");
                    }
                }

                use anstyle::AnsiColor::*;
                use anstyle::Effects;
                use log::Level::*;

                let level = record.level();
                let level_style = match level {
                    Trace => Cyan.on_default(),
                    Debug => Blue.on_default(),
                    Info => Green.on_default(),
                    Warn => Yellow.on_default(),
                    Error => Red
                        .on_default()
                        .effects(Effects::BOLD),
                };
                let level = format!(
                    "{}{}{}",
                    level_style.render(),
                    level.as_str(),
                    level_style.render_reset(),
                );

                let thread = std::thread::current()
                    .name()
                    .unwrap_or("(N/A)")
                    .to_owned();

                let line = record
                    .line()
                    .map(|n| format!(":{n}"))
                    .unwrap_or_else(String::new);

                let args = {
                    let a = record.args();

                    a.as_str()
                        .map(|s| Cow::Borrowed(s))
                        .unwrap_or_else(|| {
                            Cow::Owned(a.to_string())
                        })
                };

                let mut file = record
                    .file_static()
                    .or_else(|| record.file())
                    .unwrap_or("???")
                    .to_string();

                // compatible directory separator of Unix-style ("/") and Windows-style ("\")
                while file.contains("\\") {
                    file = file.replace("\\", "/");
                }
                while file.contains("//") {
                    file = file.replace("//", "/");
                }

                // remove prefix for all external library.
                // `cargo/registry/src/index.crates.io-6f17d22bba15001f/`
                if file.contains("cargo")
                    && file.contains("registry")
                {
                    // (for example)
                    // if original filename is "/home/test/.cargo/registry/src/index.crates.io-6f17d22bba15001f/h2-0.3.24/src/frame/settings.rs"

                    let short_file = file.split_once("cargo/registry/src/")
                    .map(|v| { v.1 })
                    // Some("index.crates.io-6f17d22bba15001f/h2-0.3.24/src/frame/settings.rs")

                    .map(|v| { v.split_once("/") })
                    .flatten()
                    // Some(("index.crates.io-6f17d22bba15001f", "h2-0.3.24/src/frame/settings.rs"))

                    .map(|v| { v.1 })
                    .unwrap_or(&file);
                    // "h2-0.3.24/src/frame/settings.rs"

                    if file.len() > short_file.len() {
                        if file.ends_with(short_file) {
                            file = format!("@{short_file}")
                        }
                    }
                }

                let out = format!("[{level}] |{thread}| ({file}{line}): {args}");
                Box::new(out)
            }
        }

        let mut flb = ftlog2::builder();

        if let Some(ref ef) = &*ENV_FILTER {
            let filter_lv: log::LevelFilter = ef.filter();
            flb = flb.max_log_level(filter_lv);
        }

        if let Some(ref lf) = opt.log_file {
            use ftlog2::appender::Duration;
            use ftlog2::appender::file::{Period, FileAppender};
            flb = flb.root(
                FileAppender::rotate_with_expire(
                    lf,
                    Period::Day,
                    Duration::days(7)
                )
            );
            flb = flb.bounded(65535, false);
        } else {
            // prevent to spam terminal
            flb = flb.bounded(4096, false);
        }

        let _ret =
            flb
            .utc()
            .time_format(TIME_FMT_JS.clone())
            .print_omitted_count(true)
            .format(MyFmt{})
            .try_init();

        //eprintln!("ftlog_logger: try init = {_ret:?}");
    }


    /* ===== handle API-with-DOHP warnings ===== */
    if opt.api_with_dohp {
        log::warn!("--api-with-dohp specified (for test or convenience?) WARNING: leaking your API interface to publicly can causes security issues! NOTE: for most common cases, it is recommended to use standalone port for DOH-plaintext");
    }

    #[cfg(feature = "doh3")]
    if opt.doh3_only {
        DOH3_ONLY.store(true, Relaxed);
    }

    if opt.stats_full {
        STATS_FULL.store(true, Relaxed);
    }

    if let Some(thrs) = opt.threads {
        smolscale2::set_threads(thrs);
    }

    if opt.info {
        println!("{:#}", &*HITDNS_INFO);
        return Ok(());
    }
    if opt.version {
        let mut ver = String::from("HitDNS");

        let v = (&*HITDNS_INFO).version;
        let s = (&*HITDNS_INFO).commit;

        if v.is_empty() {
            ver.push_str(" (version N/A)");
        } else {
            ver.push_str(&format!(" v{v}"));
        }

        if s.is_empty() {
            ver.push_str(" (Commit N/A)");
        } else {
            ver.push_str(&format!(" [{s}]"));
        }

        println!("{ver}");
        return Ok(());
    }

    if opt.dump.is_some() && opt.load.is_some() {
        return Err(anyhow::anyhow!("arguments '--dump' and '--load' is exclusive and should not specified both.")).log_error();
    }

    if let Some(ref path) = opt.dump {
        let snap = DatabaseSnapshot::export().await?;
        let json_str = format!("{:#}", snap.to_json());

        if path == &PathBuf::from("-") {
            println!("{json_str}");
        } else {
            smol::fs::write(path, json_str).await?;
        }
        log::info!("DatabaseSnapshot dumped.");
        return Ok(());
    }
    if let Some(ref path) = opt.load {
        let json: serde_json::Value =
            if path == &PathBuf::from("-") {
                let f = std::io::stdin().lock();
                serde_json::from_reader(f)?
            } else {
                let f = std::fs::File::open(path)?;
                serde_json::from_reader(f)?
            };

        let snap = DatabaseSnapshot::from_json(&json)?;
        log::info!(
            "from_json() == to_json() ? {:?}",
            snap.to_json() == json
        );

        log::info!("length = {}", snap.cache_v1.len());
        log::info!(
            "first = {:?}",
            snap.cache_v1.iter().next()
        );
        snap.import().await.log_error()?;
        log::info!("DatabaseSnapshot loaded.");

        return Ok(());
    }

    MIN_TTL.store(opt.min_ttl.unwrap(), Relaxed);
    MAX_TTL.store(opt.max_ttl.unwrap(), Relaxed);

    let daemon = DNSDaemon::new(opt.clone()).await.unwrap();

    if opt.test {
        smolscale2::spawn(daemon.run()).detach();
        test::main_async().await;
    } else {
        daemon.run().await;
    }

    Ok(())
}

fn main() -> anyhow::Result<()> {
    smolscale2::block_on(main_async())
}

