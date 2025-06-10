//! Hit DNS library for reusable functions (for example DNS Cache, DNS Query trait, Database load/store logic).

// TODO momdify "deny" to "forbid" after splitting some utils to independence crates.
#![deny(unsafe_code)]

// TODO re-enable this after alpha developing completes
//#![warn(missing_docs)]

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

pub use core::{
    fmt::{self, Write},
    hash::{Hash, Hasher, BuildHasher},
    pin::Pin,
    future::Future,
    ops::Deref,
};

pub use std::{
    net::{SocketAddr, IpAddr},
    time::{SystemTime, Instant, Duration},
    sync::Arc,
    path::{Path, PathBuf},
};

pub use bytes::Bytes;
pub use country_code_enum::CountryCode;
pub use http_types::Url;
pub use portable_atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering::Relaxed};
pub use event_listener::{Event, listener};
pub use smoltimeout::TimedExt;
pub use asyncute::util::{AtomicChecked, AtomicDuration, AtomicRangeStrict};
pub use once_cell::sync::Lazy;
pub use scc::LinkedList;

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

/// calls system resolve but cached.
pub async fn cached_resolve<A>(addr: A) -> Arc<std::io::Result<Vec<SocketAddr>>>
where
    A: async_net::AsyncToSocketAddrs + Hash,
{
    static CACHE_HASHER_BUILD: Lazy<ahash::RandomState> = Lazy::new(ahash::RandomState::new);
    static CACHE:
        Lazy<MokaCache<
            u64,
            Arc<std::io::Result<Vec<SocketAddr>>>,
        >> = Lazy::new(|| {
            MokaCacheBuilder::default()
            .name("hitdns system resolve cache")
            .max_capacity(65535)
            //.async_eviction_listener(|_query, _entry, cause| {})
            .time_to_idle(Duration::from_secs(60*3)) // 3 minutes for time-to-idle
            .time_to_live(Duration::from_secs(60*15)) // 15 minutes for time-to-live
            .build_with_hasher(ahash::RandomState::default())
        });

    let mut hasher = CACHE_HASHER_BUILD.build_hasher();
    addr.hash(&mut hasher);
    let key = hasher.finish();

    if let Some(ret) = CACHE.get(&key).await {
        return ret;
    }

    let ret = Arc::new(async_net::resolve(addr).await);
    CACHE.insert(key, ret.clone()).await;
    ret
}
