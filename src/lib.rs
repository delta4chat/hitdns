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

pub use core::{
    fmt::{self, Write},
    hash::{Hash, Hasher},
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
pub use asyncute::util::{AtomicChecked, AtomicDuration};
pub use once_cell::sync::Lazy;

pub use moka::future::CacheBuilder as MokaCacheBuilder;
pub type MokaCache<K, V> = moka::future::Cache<K, V, ahash::RandomState>;

pub type BoxFut<T> = Box<dyn Future<Output=T> + Send + 'static>;
pub type PinFut<T> = Pin<BoxFut<T>>;

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

