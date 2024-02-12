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

/* ==================== */

pub use std::time::{Instant, SystemTime};
pub use std::net::{SocketAddr, IpAddr};
pub use std::path::PathBuf;

pub use core::time::Duration;
pub use core::pin::Pin;
pub use core::ops::{Deref, DerefMut};

extern crate alloc;
pub use alloc::collections::VecDeque;
pub use alloc::sync::Arc;

pub mod dns {
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

pub use smol::lock::RwLock;

pub use serde::{Serialize, Deserialize};
pub use bytes::Bytes;

pub use smol::net::AsyncToSocketAddrs;

pub use smol::net::UdpSocket;
pub use smol::net::{TcpListener, TcpStream};

pub use smol::io::{AsyncReadExt, AsyncWriteExt};
pub use smol::stream::{StreamExt};

pub use smol::future::Future;
pub use smol::channel::{Sender, Receiver};

#[cfg(feature="sqlite")]
pub use sqlx::{
    sqlite::{SqlitePool, SqlitePoolOptions, SqliteConnectOptions, SqliteJournalMode, SqliteLockingMode, SqliteSynchronous},
    {Row, Value, ValueRef},
};

pub use once_cell::sync::Lazy;

pub use anyhow::Context;

// command line argument parser
pub use clap::Parser;

pub use core::fmt::Debug;
pub use core::iter::Sum;
pub use core::ops::{Add, Div};

pub use smol_timeout::TimeoutExt;

pub static HITDNS_DIR: Lazy<PathBuf> = Lazy::new(||{
    let dir = directories::ProjectDirs::from("org", "delta4chat", "hitdns").expect("Cannot get platform-specified dir (via `directories::ProjectDirs`)").data_dir().to_owned();
    std::fs::create_dir_all(&dir).expect("cannot create project dir {dir:?}");
    dir
});

/*
pub trait Average<  T: Default + Copy + From<u64>  > {
    fn average(&self: &[T]) -> T {
        average(self)
    }
}
*/

pub fn average<T>(set: &[T]) -> T
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

// a helper for wrapping non-Sized
pub async fn timeout_helper<T>(
    fut: impl Future<Output=T>,
    time: Duration
) -> Option<T> {
    let fut = async move { fut.await };
    fut.timeout(time).await
}

#[derive(Debug)]
pub struct DNSDaemon {
    udp: Arc<UdpSocket>, udp_task: smol::Task<anyhow::Result<()>>,
    tcp: Arc<TcpListener>, tcp_task: smol::Task<anyhow::Result<()>>,
    cache: Arc<DNSCache>,

    opt: HitdnsOpt,
}

impl DNSDaemon {
    pub async fn new(opt: HitdnsOpt) -> anyhow::Result<Self> {
        let udp = Arc::new(
            UdpSocket::bind(&opt.listen).await.log_error()?
        );
        let tcp = Arc::new(
            TcpListener::bind(&opt.listen).await.log_error()?
        );

        if let Some(ref hosts_filename) = opt.hosts {
            let _ =
                HOSTS.load(hosts_filename).await
                .log_error();
        }

        let resolvers = {
            let mut x: Vec<Arc<dyn DNSResolver>> = vec![];
            for doh_url in opt.doh_upstream.iter() {
                x.push(
                    Arc::new(
                        DNSOverHTTPS::new(
                            doh_url,
                            /*
                            opt.hosts.is_some(),
                            opt.tls_sni,
                            */
                        )?
                    )
                );
            }
            for dot_addr in opt.dot_upstream.iter() {
                x.push(
                    Arc::new(
                        DNSOverTLS::new(
                            dot_addr,
                            opt.hosts.is_some(),
                        ).await?
                    )
                );
            }
            for doq_addr in opt.doq_upstream.iter() {
                x.push(
                    Arc::new(
                        DNSOverQUIC::new(
                            doq_addr,
                        )?
                    )
                );
            }

            if x.is_empty() {
                x = default_servers();
                log::info!("no upstream specified. use default servers: {x:#?}");
            }

            DNSResolverArray::from(x)
        };

        let cache = Arc::new(
            DNSCache::new(resolvers, opt.debug).await?
        );
        
        Ok(Self {
            udp_task: smolscale2::spawn(
                Self::handle_udp( udp.clone(), cache.clone() )
            ),
            tcp_task: smolscale2::spawn(
                Self::handle_tcp( tcp.clone(), cache.clone() )
            ),

            udp, tcp,
            cache,
            opt,
        })
    }

    async fn handle_udp(udp: Arc<UdpSocket>, cache: Arc<DNSCache>) -> anyhow::Result<()> {
        let mut buf = vec![0u8; 65535];
        let mut msg: Vec<u8>;

        loop {
            let (len, peer) =
                udp.recv_from(&mut buf).await
                .context("cannot recvfrom udp socket")
                .log_error()?;

            msg = buf[..len].to_vec();

            let udp = udp.clone();
            let cache = cache.clone();
            smolscale2::spawn(async move {
                let req = dns::Message::from_vec(&msg).log_debug().unwrap();
                let res: dns::Message = cache.query(req).await.log_warn().unwrap();
                udp.send_to(
                    res.to_vec().expect("bug: DNSCache.query returns invalid data").as_ref(),
                    peer
                ).await.log_error().unwrap();
            }).detach();
        }
    }

    async fn handle_tcp(tcp: Arc<TcpListener>, cache: Arc<DNSCache>) -> anyhow::Result<()> {
        loop {
            let (mut conn, peer) = tcp.accept().await.log_error()?;
            log::debug!("DNS Daemon accepted new TCP connection from {peer:?}");

            let cache = cache.clone();
            smolscale2::spawn(async move {
                let mut req_buf = vec![0u8; 65535];
                let mut req: dns::Message;

                let mut res_buf;
                let mut res: dns::Message;

                //let mut buf: Vec<u8> = vec![];

                let mut len_buf = [0u8; 2];
                let mut len: usize;

                loop {
                    // recv first 2 bytes as the length of request message
                    if let Err(_) =
                        conn.read_exact(&mut len_buf).await
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

                    // handle...
                    res = match
                        cache.query(req).await
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
                } // tcp conn loop
            }).detach(); // smolscale2::spawn
        } // tcp accept loop
    }

    async fn run(&self) {
        loop {
            if self.opt.debug {
                //log::trace!("cache status: {:?}", &self.cache.memory);
            }
            log::debug!("cache length: {:?}", self.cache.memory.len());

            log::debug!("smolscale2 worker threads: {:?}", smolscale2::running_threads());
            log::debug!("smolscale2 active tasks: {:?}", smolscale2::active_task_count());

            log::trace!("tcp listener: {:?}\ntcp task: {:?}", self.tcp.as_ref(), &self.tcp_task);
            log::trace!("udp socket: {:?}\nudp task: {:?}", self.udp.as_ref(), &self.udp_task);

            if self.opt.debug {
                let mut x = vec![];
                for r in self.cache.resolvers.list.iter() {
                    x.push(r.dns_metrics().await);
                }

                log::trace!(
                    "DNSResolverArray metrics: {x:#?}"
                );
            }

            if self.tcp_task.is_finished() || self.udp_task.is_finished() {
                log::error!("listener task died");
                return;
            }

            smol::Timer::after(
                Duration::from_secs(10)
            ).await;
        }
    }
}

#[derive(Debug, Clone, clap::Parser)]
#[command(author, version, about, long_about)]
pub struct HitdnsOpt {
    /// debug mode.
    #[arg(long)]
    pub debug: bool,

    /// Minimum TTL of cached DNS entry.
    /// default to 3 minutes.
    #[arg(long, default_value="180")]
    pub min_ttl: u32,

    /// Maximum TTL of cached DNS entry.
    /// default to 7 days.
    #[arg(long, default_value="604800")]
    pub max_ttl: u32,

    /// location of a hosts.txt file.
    /// examples of this file format, that can be found at /etc/hosts (Unix-like systems), or
    /// C:\Windows\System32\drivers\etc\hosts (Windows)
    #[arg(long)]
    pub hosts: Option<PathBuf>,

    /// Whether try to find system-side hosts.txt
    #[arg(long)]
    pub use_system_hosts: bool,

    /// Whether enable TLS SNI extension.
    /// if this is unspecified, default disable SNI (for bypass internet censorship in few totalitarian countries)
    /// if you specified --tls-sni or --hosts or --use-system-hosts, then TLS SNI will enabled by default.
    #[arg(long)]
    pub tls_sni: bool,

    /// Listen address of local plaintext DNS server.
    #[arg(long)]
    pub listen: SocketAddr,

    /// upstream URL of DoH servers.
    /// DNS over HTTPS (RFC 8484)
    #[arg(long)]
    pub doh_upstream: Vec<String>,

    /// *Experimental*
    /// upstream address of DoT servers.
    /// DNS over TLS (RFC 7858)
    #[arg(long)]
    pub dot_upstream: Vec<String>,

    /// *Experimental*
    /// upstream address of DoQ servers.
    /// DNS over QUIC (RFC 9250)
    #[arg(long)]
    pub doq_upstream: Vec<String>,
}

fn default_servers() -> Vec<Arc<dyn DNSResolver>> {
    let doh_server_urls = vec![
        // Cloudflare DNS
        "https://1.0.0.1/dns-query",
        "https://1.1.1.1/dns-query",

        // Quad9 DNS
        "https://9.9.9.10/dns-query",

        // TWNIC DNS 101
        "https://101.101.101.101/dns-query",

        // dns.sb
        "https://45.11.45.11/dns-query",
        "https://185.222.222.222/dns-query",

        // Adguard DNS Un-filtered
        "https://94.140.14.140/dns-query"
    ];

    let mut list: Vec<Arc<dyn DNSResolver>> = vec![];

    for doh_url in doh_server_urls.iter() {
        list.push(
            Arc::new(
                DNSOverHTTPS::new(
                    doh_url,
                    /*
                    false, // no hosts.txt
                    false, // disable TLS SNI
                    */
                ).unwrap()
            )
        );
    }

    list
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

    MIN_TTL.store(opt.min_ttl, Relaxed);
    MAX_TTL.store(opt.max_ttl, Relaxed);

    DNSDaemon::new(opt).await.log_error()?.run().await;
    Ok(())
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    //smolscale2::set_max_threads(4);
    smolscale2::block_on(main_async())
}

