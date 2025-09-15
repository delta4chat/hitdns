//! Hit DNS library for reusable functions (for example DNS Cache, DNS Query trait, Database load/store logic).

// TODO momdify "deny" to "forbid" after splitting some utils to independence crates.
#![deny(unsafe_code)]

// TODO re-enable this after alpha developing completes
//#![warn(missing_docs)]

/// The C Language's Flat Earth Theory.
/// * this should not be used in cases other than for-test, for-fun or for-satire.
/// * so you can see what happens if your programming language does not have name-space:
/// 1. almost all C projects uses function prefix or global variable prefix to prevent name conflation.
/// 2. but this requirements other projects also uses prefixes "as a standard or guideline", which it's hardly and it's uniqueness is not guaranteed.
/// 3. also prefixes is not easy to parsed separately, so you cannot easy to listing all of items within specified name-space, and causes more different works in IDE or syntax analyzer that can be avoided if has name-space.
pub mod c_flatland {
    //pub use super::*;
    pub use super::{
        config::{self, *},
        dns::{self, *},
        query::{self, *},
        entry::{self, *},
        cache::{self, *},
        upstream::{self, *},
        resolver::{self, *},
        util::{self, *},
        asled::{self, *},
        database::{self, *},
        protocol::{
            self,
            *,
            pool::{self, *},
            tcp::{self, *},
            tls::{self, *},
            h2::{self, *},
            inbound::{
                self,
                *,
                tcp::*,
                udp::{self, *},
            },
            outbound::{self, *},
        },
        data::{
            self,
            *,
            upstreams_list::{
                self,
                *,
                dnscrypt::*,
            },
        },
        logs::{self, *},
    };
}

pub mod config;
pub mod dns;
pub mod query;
pub mod entry;
pub mod cache;
pub mod upstream;
pub mod resolver;
pub mod util;
pub mod asled;
pub mod database;
pub mod protocol;
pub mod data;
pub mod logs;

pub use config::atomic_ordering::*;

pub use core::{
    any::Any,
    cell::Cell,
    fmt::{self, Write},
    hash::{Hash, Hasher, BuildHasher, BuildHasherDefault},
    pin::Pin,
    future::Future,
    ops::{Deref, AddAssign, DivAssign},
    str::FromStr,
};

pub use std::{
    net::{SocketAddr, IpAddr, Ipv4Addr, Ipv6Addr},
    time::{SystemTime, Instant, Duration},
    sync::Arc,
    path::{Path, PathBuf},
};

pub use nohash::NoHashHasher as NoHasher;
pub type NoHasherU64 = NoHasher<u64>;

pub use {
    bytes::{Bytes, BytesMut},
    country_code_enum::CountryCode,
    http_types::Url,
    portable_atomic::{
        AtomicBool,
        AtomicU8,
        AtomicU32,
        AtomicUsize,
    },
    event_listener::{
        Event,
        listener as event_listen,
    },
    smoltimeout::TimedExt,
    asyncute::util::{AtomicChecked, AtomicDuration, AtomicRangeStrict},
    once_cell::sync::Lazy,
    scc2::LinkedList,
    futures_lite::{
        future::FutureExt,
        io::{AsyncReadExt, AsyncWriteExt},
    },
};

pub type TcpStream = async_io::Async<std::net::TcpStream>;
pub type TcpListener = async_io::Async<std::net::TcpListener>;
pub type UdpSocket = async_io::Async<std::net::UdpSocket>;

pub use futures_rustls::{
    rustls,
    TlsConnector,
};
pub type TlsStream = futures_rustls::client::TlsStream<TcpStream>;

pub use moka::future::CacheBuilder as MokaCacheBuilder;
pub type MokaCache<K, V> = moka::future::Cache<K, V, ahash::RandomState>;

pub type BoxFut<T> = Box<dyn Future<Output=T> + Send + 'static>;
pub type PinFut<T> = Pin<BoxFut<T>>;

pub trait Fut<T>: Future<Output=T> + Send {}
impl<T, F: Future<Output=T> + Send> Fut<T> for F {}

pub fn average<T, I>(iter: I) -> T
where
    T: Default + Clone + AddAssign + DivAssign + From<bool>,
    I: Iterator<Item=T>,
{
    let mut sum = T::default();
    let mut len = T::default();

    let one = T::from(true);
    let mut empty = true;
    for item in iter {
        empty = false;
        len += one.clone();
        sum += item;
    }

    if empty {
        return T::default();
    }

    sum /= len;
    sum
}

pub fn err_invalid_input<T, M>(msg: M) -> std::io::Result<T>
where
    M: Into<Box<(dyn std::error::Error + Send + Sync + 'static)>>,
{
    Err(invalid_input(msg))
}
pub fn invalid_input<M>(msg: M) -> std::io::Error
where
    M: Into<Box<(dyn std::error::Error + Send + Sync + 'static)>>,
{
    std::io::Error::new(std::io::ErrorKind::InvalidInput, msg)
}

pub fn err_invalid_data<T, M>(msg: M) -> std::io::Result<T>
where
    M: Into<Box<(dyn std::error::Error + Send + Sync + 'static)>>,
{
    Err(invalid_data(msg))
}
pub fn invalid_data<M>(msg: M) -> std::io::Error
where
    M: Into<Box<(dyn std::error::Error + Send + Sync + 'static)>>,
{
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg)
}

/// cached result from system resolver.
pub async fn cached_resolve<A>(addr: A, clear: bool) -> Arc<std::io::Result<Vec<SocketAddr>>>
where
    A: async_net::AsyncToSocketAddrs + Hash,
{
    static CACHE_HASHER_BUILD: Lazy<ahash::RandomState> = Lazy::new(ahash::RandomState::new);
    static CACHE:
        Lazy<moka::future::Cache<
            u64, // in static scope, it's impossible to use generic type A.
            Arc<std::io::Result<Vec<SocketAddr>>>,
            BuildHasherDefault<NoHasherU64>,
        >> = Lazy::new(|| {
            MokaCacheBuilder::default()
            .name("hitdns system resolve cache")
            .max_capacity(65535)
            //.async_eviction_listener(|_query, _entry, cause| {})
            .time_to_idle(Duration::from_secs(60*30)) // 30 minutes for time-to-idle
            .time_to_live(Duration::from_secs(60*60*2)) // 2 hours for time-to-live
            .build_with_hasher(Default::default())
        });

    if clear {
        CACHE.invalidate_all();
    }

    let mut hasher = CACHE_HASHER_BUILD.build_hasher();
    core::any::type_name::<A>().hash(&mut hasher);
    addr.hash(&mut hasher);
    let key = hasher.finish();

    if let Some(ret) = CACHE.get(&key).await {
        return ret;
    }

    let ret = Arc::new(async_net::resolve(addr).await);
    CACHE.insert(key, ret.clone()).await;
    ret
}

