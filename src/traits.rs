use crate::*;

pub type PinFut<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

pub trait DNSResolver: Send + Sync + 'static {
    /// un-cached DNS query
    fn dns_resolve(&self, query: &DNSQuery) -> PinFut<anyhow::Result<dns::Message>>;

    /// a description for upstream, usually URL or any other.
    fn dns_upstream(&self) -> String;

    /// a protocol type of upstream
    fn dns_protocol(&self) -> &str;

    /// get analysis snapshot for this Upstream
    fn dns_metrics(&self) -> PinFut<DNSMetrics>;
}

impl core::fmt::Debug for dyn DNSResolver {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("dyn DNSResolver")
        .field("dns_upstream", &self.dns_upstream())
        .field("dns_protocol", &self.dns_protocol())
        //.field("dns_metrics", &self.dns_metrics())
        .finish()
    }
}

/*
impl<T: AsRef<DNSResolver> DNSResolver for &T
{
}
*/

/*
trait Average<T>: Sum<T> {
    fn average(&self) -> T;
}

impl Average<Duration> for dyn Iterator<Item=Duration> {
    fn average(&self) -> Duration {
        /*
        let mut secs: Vec<f64> = vec![];
        for dur in self.iter() {
            secs.push(dur.as_secs_f64());
        }*/
        let len = self.count();
        let avg = self.sum().as_secs_f64() / len as f64;
        Duration::from_secs_f64(avg)
    }
}*/

pub trait LogResult: Debug + Sized {
    fn log_generic(self, level: log::Level) -> Self;

    fn log_error(self) -> Self {
        self.log_generic(log::Level::Error)
    }

    fn log_warn(self) -> Self {
        self.log_generic(log::Level::Warn)
    }

    fn log_info(self) -> Self {
        self.log_generic(log::Level::Info)
    }

    fn log_debug(self) -> Self {
        self.log_generic(log::Level::Debug)
    }
    fn log_trace(self) -> Self {
        self.log_generic(log::Level::Trace)
    }
}

impl<T: Debug, E: Debug> LogResult for Result<T, E> {
    fn log_generic(self, level: log::Level) -> Self {
        if let Err(_) = self {
            log::log!(level, "{:?}", self);
        }
        self
    }
}
impl<T: Debug, E: Debug> LogResult for &Result<T, E> {
    fn log_generic(self, level: log::Level) -> Self {
        if let Err(_) = self {
            log::log!(level, "{:?}", self);
        }
        self
    }
}
