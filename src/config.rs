use crate::{
    *,
    resolver::*,
};

pub static DATA_DIR: Lazy<String> = Lazy::new(make_data_dir);

/// try to get data dir, and create it if missing.
fn make_data_dir() -> String {
    let dir = get_data_dir();
    log::info!("got data dir: {:?}", &dir);

    if ! std::fs::exists(&dir).expect("unable to check whether data dir exists!") {
        std::fs::create_dir_all(&dir).expect("unable to create data dir!");
    }

    let md = std::fs::metadata(&dir).expect("unable to get metadata of data dir!");
    if ! md.file_type().is_dir() {
        panic!("the location of data dir is not path to a directory!");
    }

    dir
}

/// try to get data dir (but not to create it if missing).
fn get_data_dir() -> String {
    if let Ok(dir) = std::env::var("HITDNS_DATA_DIR") {
        return dir;
    }

    let pd =
        directories::ProjectDirs::from(
            "dev.pages.hitdns",
            "delta4chat",
            "hitdns"
        ).expect("unable to determine the location of hitdns data directory!");

    let path = pd.data_dir();
    if let Some(d) = path.to_str() {
        d.to_string()
    } else {
        log::warn!("invalid UTF-8 data dir ({:?}) return by `directories` crate! performing lossy convert to UTF-8, your platform may have misbehavior.", path);

        path.to_string_lossy().into_owned()
    }
}

#[derive(Debug)]
pub struct ProtocolConfig {
    allow_edns: AtomicBool,
}
impl ProtocolConfig {
    pub const fn global() -> &'static Self {
        static GLOBAL: ProtocolConfig =
            ProtocolConfig {
                allow_edns: AtomicBool::new(false),
            };

        &GLOBAL
    }

    pub fn allow_edns(&self) -> bool {
        self.allow_edns.load(Relaxed)
    }

    pub fn set_allow_edns(&self, allow: bool) {
        self.allow_edns.store(allow, Relaxed)
    }
}

#[derive(Debug)]
pub struct ResolverConfig {
    selector: AtomicU8,
}
impl ResolverConfig {
    pub const fn global() -> &'static Self {
        static GLOBAL: ResolverConfig =
            ResolverConfig {
                selector: AtomicU8::new(DNSUpstreamSelector::UNSPECIFIED),
            };

        &GLOBAL
    }

    pub fn selector(&self) -> DNSUpstreamSelector {
        DNSUpstreamSelector::new(self.selector.load(Relaxed)).expect("unexpected AtomicU8 has invalid value")
    }

    pub fn set_selector(&self, selector: DNSUpstreamSelector) {
        self.selector.store(selector.value(), Relaxed)
    }
}

#[derive(Debug)]
pub struct CacheConfig {
    min_ttl: AtomicU32,
    max_ttl: AtomicU32,
}
impl CacheConfig {
    pub const fn global() -> &'static Self {
        static GLOBAL: CacheConfig = CacheConfig {
            min_ttl: AtomicU32::new(30), // 30 seconds
            max_ttl: AtomicU32::new(60*60*24), // 1 day
        };

        &GLOBAL
    }

    pub fn min_ttl(&self) -> u32 {
        self.min_ttl.load(Relaxed)
    }
    pub fn set_min_ttl(&self, ttl: u32) {
        self.min_ttl.store(ttl, Relaxed)
    }

    pub fn max_ttl(&self) -> u32 {
        self.max_ttl.load(Relaxed)
    }
    pub fn set_max_ttl(&self, ttl: u32) {
        self.max_ttl.store(ttl, Relaxed)
    }
}

#[derive(Debug, Copy, Clone)]
#[non_exhaustive]
pub struct Config {
    pub protocol: &'static ProtocolConfig,
    pub resolver: &'static ResolverConfig,
    pub cache: &'static CacheConfig,
}
impl Config {
    pub const fn global() -> Self {
        Self {
            protocol: ProtocolConfig::global(),
            resolver: ResolverConfig::global(),
            cache: CacheConfig::global(),
        }
    }
}

