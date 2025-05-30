use crate::*;

pub struct CacheConfig {
    min_ttl: AtomicU32,
    max_ttl: AtomicU32,
}

impl CacheConfig {
    pub const fn global() -> &'static Self {
        static GLOBAL: CacheConfig = CacheConfig {
            min_ttl: AtomicU32::new(0),
            max_ttl: AtomicU32::new(86400),
        };

        &GLOBAL
    }

    pub fn min_ttl(&self) -> u32 {
        self.min_ttl.load(Relaxed)
    }
    pub fn set_min_ttl(&self, ttl: u32) {
        self.min_ttl.store(ttl, Relaxed);
    }

    pub fn max_ttl(&self) -> u32 {
        self.max_ttl.load(Relaxed)
    }
    pub fn set_max_ttl(&self, ttl: u32) {
        self.max_ttl.store(ttl, Relaxed);
    }
}

