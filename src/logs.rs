use crate::*;

pub const fn u8_to_loglevel(n: u8) -> Option<log::Level> {
    use log::Level::*;

    match n {
        b'T' | 5 => Some(Trace),
        b'D' | 4 => Some(Debug),
        b'I' | 3 => Some(Info),
        b'W' | 2 => Some(Warn),
        b'E' | 1 => Some(Error),
        _        => None
    }
}

pub const fn loglevel_to_u8(lv: log::Level) -> u8 {
    use log::Level::*;

    match lv {
        Trace => b'T',
        Debug => b'D',
        Info  => b'I',
        Warn  => b'W',
        Error => b'E',
    }
}

pub fn disk_filename() -> PathBuf {
    let mut path = config::LOG_DIR.deref().clone();
    path.push("hitdns.log");
    path
}

#[cfg(feature="log4rs")]
include!("log4.rs");
