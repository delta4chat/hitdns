//! DNS upstream

use crate::{
    *,
    query::*,
    entry::*,
    util::*,
};

/// HTTP versions
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum HTTPVersion {
    /// HTTP/0.9
    H09 = 9,

    /// HTTP/1.0
    H10 = 10,

    /// HTTP/1.1
    H11 = 11,

    /// HTTP/2
    H2 = 20,

    /// HTTP/3
    H3 = 30,
}

/// DNS plaintext address.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DNSPlaintext {
    /// DNS over UDP plaintext
    UDP(SocketAddr),

    /// DNS over TCP plaintext
    TCP(SocketAddr),

    /// DOH over HTTP plaintext
    /// * useful for your reverse-proxy to serve DoH requests.
    /// for example:
    /// `client <===> nginx (https://doh.test/dns-query) <===> hitdns (127.0.0.1:port)`
    HTTP(Url),
}

impl DNSPlaintext {
    /// checks address whether valid.
    pub fn is_valid(&self) -> bool {
        let addr = 
            match self {
                Self::UDP(ua) => ua,
                Self::TCP(ta) => ta,
                Self::HTTP(url) => {
                    if ! url.scheme().eq_ignore_ascii_case("dohp") {
                        return false;
                    }
                    if url.port() == Some(0) {
                        return false;
                    }

                    // scheme is "dohp", and port absent or non-zero.
                    return true;
                }
            };

        addr.port() != 0
    }
}

/// DNS protocol and address
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DNSProtocol {
    /// plaintext. only for client.
    /// * hitdns does not allow plaintext outgoing packets.
    Plaintext(DNSPlaintext),

    /// DNS over HTTPS (RFC 8484).
    /// * this only includes HTTP/2 and HTTP/3.
    /// * the scheme must be `doh2://` or `doh3://`.
    /// * disallowed well-known schemes such as `https://` or `http://`.
    DoH(Url),

    /// DNS over TLS.
    /// * this only referring to TCP-based TLS.
    DoT(SocketAddr),

    /// DNS over QUIC (Server Address, Optional SNI).
    DoQ(SocketAddr, Option<dns::Name>),
}

impl DNSProtocol {
    /// whether this DNS Protocol is encrypted?
    pub const fn is_encrypted(&self) -> bool {
        match self {
            Self::Plaintext(_) => false,
            _ => true,
        }
    }

    /// checks address whether valid.
    pub fn is_valid(&self) -> bool {
        let addr =
            match self {
                Self::Plaintext(plain) => {
                    return plain.is_valid();
                },
                Self::DoH(url) => {
                    let scheme = url.scheme();
                    if scheme.eq_ignore_ascii_case("doh2") {
                        // valid
                    } else if scheme.eq_ignore_ascii_case("doh3") {
                        // valid
                    } else {
                        return false;
                    }

                    if url.port() == Some(0) {
                        return false;
                    }

                    return true;
                },
                Self::DoT(v) => v,
                Self::DoQ(addr, maybe_sni) => {
                    if let Some(sni) = maybe_sni.as_ref() {
                        if ! sni.is_fqdn() {
                            return false;
                        }
                        if sni.is_wildcard() {
                            return false;
                        }
                        if sni.num_labels() == 4 {
                            for label in sni.iter() {
                                // Iterator::all() returns true even if iterator is empty.
                                // this is no problem due to empty TLD always invalid.
                                if label.into_iter().all(u8::is_ascii_digit) {
                                    return false;
                                }
                            }
                        }
                    }

                    addr
                },
            };

        addr.port() != 0
    }

    /// format any protocol's address to URL format.
    /// * must not use well-known URL schemes.
    /// * port number is required and must not omitted.
    /// 
    /// for example:
    /// # DNS over HTTP/2 over TLS over TCP
    /// DoH/2 URL: `doh2://www.example.com:443/dns-query`
    /// # DNS over TLS over TCP
    /// DoT URL: `dot://tls.example.com:853`
    ///
    /// # DNS over HTTP/3 over QUIC over UDP
    /// DoH/3 URL: `doh3://http3.example.com:443/dns-query`
    /// # DNS over QUIC over UDP
    /// DoQ URL: `doq://quic.example.com:853`
    ///
    /// # non-encrypted DNS over UDP
    /// UDP URL: `udp://192.168.1.1:53`
    /// # non-encrypted DNS over TCP
    /// TCP URL: `tcp://172.16.0.1:53`
    ///
    /// # non-encrypted DNS over HTTP over TCP
    /// DoH(plaintext) URL: `dohp://127.0.0.1:8053` (non-fixed-path: `/dns-query` and `/resolve`)
    pub fn url(&self) -> Url {
        if ! self.is_valid() {
            panic!("unexpectedly invalid inner data of DNSProtocol");
        }

        let scheme;
        let mut note = String::new();
        let addr =
            match self {
                Self::Plaintext(plain) => {
                    use DNSPlaintext::*;
                    match plain {
                        UDP(addr) => {
                            scheme = "udp";
                            *addr
                        },
                        TCP(addr) => {
                            scheme = "tcp";
                            *addr
                        },
                        HTTP(url) => {
                            return url.clone();
                        },
                    }
                },
                Self::DoH(url) => {
                    return url.clone();
                },
                Self::DoT(addr) => {
                    scheme = "dot";
                    *addr
                },
                Self::DoQ(addr, maybe_sni) => {
                    scheme = "doq";
                    if let Some(sni) = maybe_sni {
                        let sni = sni.to_utf8();
                        note.reserve_exact(4 + sni.len());
                        note.push_str("sni=");
                        note.push_str(&sni);
                    }
                    *addr
                },
            };

        let mut url = Url::parse("dot://server.example:853").unwrap();
        url.set_scheme(scheme).expect("unexpectedly failed to set scheme");
        url.set_ip_host(addr.ip()).expect("unexpectedly failed to set ip host");
        url.set_port(Some(addr.port())).expect("unexpectedly failed to set port");
        if ! note.is_empty() {
            url.set_fragment(Some(note.as_str()));
        }

        url
    }
}

/// DNS Upstream Server.
pub trait DNSUpstream: Send + Sync {
    /// the Name of Upstream Server.
    fn name<'a>(&'a self) -> &'a str;

    /// DNS protocol used by this upstream.
    fn protocol(&self) -> DNSProtocol;

    /// the Country Code of this Upstream server itself.
    /// * usually this is the server location, hosting platform location, or GeoIP location.
    /// * if server uses IP Anycast, Web CDN or Dynamic DNS, then should use the location of server operator's organization, company/corporation, or personal.
    fn server_country(&self) -> CountryCode;

    /// the Country Code of the operator that running this Upstream.
    /// * usually this is the location of server operator's organization, company/corporation, or personal.
    /// * only the mainly entity that operates Upstream server. not any 3rd-parties.
    fn operator_country(&self) -> CountryCode;

    /// whether the logs kept in Upstream server is anonymized?
    /// * usually return true if server is zero-logging (does not kept logs).
    /// * it's should return false if this is unclear.
    fn is_anonymized_logs(&self) -> bool { false }

    /// whether this Upstream server is zero-logging?
    /// * only return true if servers that have policy that clarify claimed it does not kept logs.
    /// * it's should return false if this is unclear.
    fn is_without_logs(&self) -> bool { false }

    /// return the metrics of this upstream.
    /// * metrics is about to online status, reliability status and server latency, etc.
    fn metrics<'a>(&'a self) -> &'a DNSUpstreamMetrics;

    /// (un-cached) try to resolve DNS query using this upstream.
    fn resolve(&self, query: Arc<dyn DNSQuery>) -> PinFut<std::io::Result<DNSEntry>>;
}

impl fmt::Debug for dyn DNSUpstream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("dyn DNSUpstream")
         .field("name", &(self.name()))
         .field("protocol", &(self.protocol()))
         .field("server_country", &(self.server_country()))
         .field("operator_country", &(self.operator_country()))
         .field("is_anonymized_logs", &(self.is_anonymized_logs()))
         .field("is_without_logs", &(self.is_without_logs()))
         .field("metrics", self.metrics())
         .field("resolve", &"fn")
         .finish_non_exhaustive()
    }
}

impl PartialEq for dyn DNSUpstream {
    fn eq(&self, other: &Self) -> bool {
        self.name() == other.name()
        &&
        self.protocol() == other.protocol()
        &&
        self.server_country() == other.server_country()
        &&
        self.operator_country() == other.operator_country()
        &&
        self.is_anonymized_logs() == other.is_anonymized_logs()
        &&
        self.is_without_logs() == other.is_without_logs()
    }
}
impl Eq for dyn DNSUpstream {}

impl Hash for dyn DNSUpstream {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.name().hash(state);
        self.protocol().hash(state);
        self.server_country().hash(state);
        self.operator_country().hash(state);
        self.is_anonymized_logs().hash(state);
        self.is_without_logs().hash(state);
    }
}

impl Ord for dyn DNSUpstream {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        static RS: ahash::RandomState =
            ahash::RandomState::with_seeds(
                0xffb6fe463adb4e07,
                0xb781c06b46683c4d,
                0xfa37e657b817bf14,
                0xaeef0174bb5ca0ce,
            );

        RS.hash_one(self).cmp(&(RS.hash_one(other)))
    }
}

impl PartialOrd for dyn DNSUpstream {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// the inner of [`DNSUpstreamMetrics`].
#[derive(Debug)]
pub struct DNSUpstreamMetricsInner {
    /// whether this upstream online?
    online: Atomic<bool>,

    /// percentage of reliability of this upstream.
    /// * u8 must be within range `0..=100`: reliability `0` means all of query is failed, and `100` means all of query is successful.
    /// * this is about to the application level reliability. for example (in DoH protocol) all web servers will have 0% reliability due to that accepts HTTPS requests but unable to handle DoH requests.
    reliability: Atomic<u8>,

    /// latency map: key is the response time, and value is the latency.
    latency: MokaCache<SystemTime, Duration>,

    /// last successfully request.
    /// * this often means the last server uptime.
    /// but sometimes inaccurate for reliability, because the server select mechanism will automatic skipping offline servers.
    last_okey: AtomicDuration,

    /// last failed request.
    /// * this often means the start time of server down.
    /// * but sometimes inaccurate for reliability, because the server select mechanism will try to use some down servers if no more reliable servers (for example Ethernet down or Wi-Fi disconnected).
    last_fail: AtomicDuration,
}

/// the metrics that can able to update in place.
#[derive(Debug, Clone)]
pub struct DNSUpstreamMetrics(Arc<DNSUpstreamMetricsInner>);

impl Deref for DNSUpstreamMetrics {
    type Target = DNSUpstreamMetricsInner;

    fn deref<'a>(&'a self) -> &'a DNSUpstreamMetricsInner {
        self.0.as_ref()
    }
}

impl DNSUpstreamMetrics {
    pub const WEIGHT_RELIABILITY: f64 = 0.6;
    pub const WEIGHT_LATENCY: f64 = 0.4;

    const _WEIGHT_ASSERT: () = {
        assert!(((Self::WEIGHT_RELIABILITY + Self::WEIGHT_LATENCY) - 1.0).abs() < 0.0001);
    };

    /// create new Metrics of specified DNS Upstream.
    pub fn new() -> Self {
        // for avoid rustc remove unused _WEIGHT_ASSERT
        // (cold path)
        if Self::_WEIGHT_ASSERT == () {}

        Self(Arc::new(DNSUpstreamMetricsInner {
            online: Atomic::<bool>::new(false),
            reliability: Atomic::<u8>::new(50),
            latency: {
                MokaCacheBuilder::default()
                .name("dns upstream metrics: latency information")
                .max_capacity(10000)
                .build_with_hasher(ahash::RandomState::default())
            },
            last_okey: AtomicDuration::default(),
            last_fail: AtomicDuration::default(),
        }))
    }

    /// add new record to metrics.
    pub async fn record(&self, now: SystemTime, online: bool, maybe_latency: Option<Duration>) {
        self.online.store(online, Relaxed);

        let maybe_unix = now.duration_since(SystemTime::UNIX_EPOCH);

        let rel = self.reliability.deref();
        if online {
            let mut old = rel.load(Relaxed);
            while old < 100 {
                match
                    rel.compare_exchange(
                        old, old+1,
                        Relaxed, Relaxed
                    )
                {
                    Ok(_) => {
                        break;
                    },
                    Err(o) => {
                        old = o;
                    }
                }
            }
        } else {
            rel.checked_sub(1);
        }

        if let Ok(unix) = maybe_unix {
            if online {
                self.last_okey.set(unix);
            } else {
                self.last_fail.set(unix);
            }
        }

        if let Some(latency) = maybe_latency {
            self.latency.insert(now, latency).await;
        }
    }

    /// get last request successful time.
    pub fn last_okey(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH.checked_add(self.last_okey.get()).expect("timestamp overflow!")
    }

    /// get last request failed time.
    pub fn last_fail(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH.checked_add(self.last_fail.get()).expect("timestamp overflow!")
    }

    /// get reliability percentage of this server.
    /// * 0 = all times offline.
    /// * 100 = all times online.
    pub fn reliability(&self) -> u8 {
        self.reliability.load(Relaxed)
    }

    /// get latency in average value.
    /// * it's DNS application-layer latency between send request and received DNS response from server.
    /// * it's not ICMP ping, TCP ping, or HTTP ping.
    pub fn latency(&self) -> Duration {
        Duration::from_secs_f64(
            average(
                self.latency
                    .iter()
                    .map(|(_, v)| { v.as_secs_f64() })
            )
        )
    }

    pub fn score(&self) -> f64 {
        let rel_score = (self.reliability() as f64) / 100.0;

        let lat = self.latency().as_secs_f64();
        let lat_score =
            if lat == 0.0 {
                0.0
            } else {
                1.0 / lat
            };

        (rel_score * Self::WEIGHT_RELIABILITY) + (lat_score * Self::WEIGHT_LATENCY)
    }
}
