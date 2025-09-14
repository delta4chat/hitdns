use crate::{
    *,
    logs::{
        u8_to_loglevel,
        loglevel_to_u8,
    },
    resolver::*,
};

pub static DATA_DIR: Lazy<PathBuf> = Lazy::new(make_data_dir);
pub static LOG_DIR: Lazy<PathBuf> = Lazy::new(make_log_dir);

/// try to create directory if missing.
fn make_dir<P: AsRef<Path>>(dir: P) {
    //log::info!("got dir: {:?}", &dir);

    if ! std::fs::exists(&dir).expect("unable to check whether dir exists!") {
        std::fs::create_dir_all(&dir).expect("unable to create dir!");
    }

    let md = std::fs::metadata(&dir).expect("unable to get metadata of dir!");
    if ! md.file_type().is_dir() {
        panic!("the location of dir is not path to a directory!");
    }
}
fn make_data_dir() -> PathBuf {
    let dir = get_data_dir();
    make_dir(&dir);
    dir
}
fn make_log_dir() -> PathBuf {
    let dir = get_log_dir();
    make_dir(&dir);
    dir
}

/// try to get data directory (but not to create it if missing).
fn get_data_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("HITDNS_DATA_DIR") {
        return dir.into();
    }

    let pd =
        directories::ProjectDirs::from(
            "dev.pages.hitdns",
            "delta4chat",
            "hitdns"
        ).expect("unable to determine the location of hitdns data directory!");

    pd.data_dir().to_path_buf()
}

/// try to get logging directory
pub fn get_log_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("HITDNS_LOG_DIR") {
        return dir.into();
    }

    let mut dir = (&*config::DATA_DIR).clone();
    dir.push("hitdns-log4rs");
    dir
}

#[derive(Debug)]
pub struct LoggerConfig {
    log_extern_libs: AtomicBool,
    always_log_self: AtomicBool,
    level: AtomicU8,
}
impl LoggerConfig {
    pub const fn global() -> &'static Self {
        static GLOBAL: LoggerConfig =
            LoggerConfig {
                log_extern_libs: AtomicBool::new(true),
                always_log_self: AtomicBool::new(true),
                level: AtomicU8::new(loglevel_to_u8(log::Level::Warn)),
            };

        &GLOBAL
    }

    pub fn log_extern_libs(&self) -> bool {
        self.log_extern_libs.load(Relaxed)
    }
    pub fn set_log_extern_libs(&self, lel: bool) {
        self.log_extern_libs.store(lel, Relaxed)
    }

    pub fn always_log_self(&self) -> bool {
        self.always_log_self.load(Relaxed)
    }
    pub fn set_always_log_self(&self, als: bool) {
        self.always_log_self.store(als, Relaxed)
    }

    pub fn level(&self) -> log::Level {
        u8_to_loglevel(self.level.load(Relaxed))
        .expect("unexpected AtomicU8 value invalid")
    }
    pub fn set_level(&self, lv: log::Level) {
        self.level.store(loglevel_to_u8(lv), Relaxed)
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
    pub logger: &'static LoggerConfig,
}
impl Config {
    pub const fn global() -> Self {
        Self {
            protocol: ProtocolConfig::global(),
            resolver: ResolverConfig::global(),
            cache: CacheConfig::global(),
            logger: LoggerConfig::global(),
        }
    }
}

