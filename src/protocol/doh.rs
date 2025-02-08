use crate::*;

const USER_AGENT_LIST: &'static [&'static str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36 Hutool",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/131.0.6778.103 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 OPR/114.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.79 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.5938.132 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/131.0.6778.134 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/27.0 Chrome/125.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.78 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.114 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.142 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6523.4 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.7 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.143 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
];
const USER_AGENT_LIST_LEN: usize = USER_AGENT_LIST.len();

static USER_AGENT: Lazy<String> =
    Lazy::new(|| {
        if HITDNS_OPT.doh_hide_ua {
            return String::from(USER_AGENT_LIST[fastrand::usize(0..USER_AGENT_LIST_LEN)]);
        }

        let mut ua = String::from("hitdns");

        let info = &*HITDNS_INFO;
        if ! info.version.is_empty() {
            ua.push('/');
            ua.push_str(info.version);
        }
        if ! info.commit.is_empty() {
            ua.push('+');
            ua.push_str(info.commit);
        }

        ua
    });

static DOH2_CLIENT: Lazy<reqwest_h3::Client> =
    Lazy::new(|| {
        let mut cs = RUSTLS_CLIENT_CONFIG.clone();
        cs.alpn_protocols = vec![ b"h2".to_vec() ];

        reqwest_h3::Client::builder()
            // log::trace
            .connection_verbose(true)

            // use HTTPS(rustls) only
            .use_rustls_tls()
            .min_tls_version(reqwest_h3::tls::Version::TLS_1_2)
            .https_only(true)
            .tls_sni( HOSTS.map.len() > 0 )
            .use_preconfigured_tls(cs)

            // User-Agent
            .user_agent(&*USER_AGENT)

            // HTTP/2 setting
            .http2_prior_knowledge() // use HTTP/2 only
            .http2_adaptive_window(false)
            .http2_max_frame_size(Some(65535))
            .http2_keep_alive_interval(Some(Duration::from_secs(10)))
            .http2_keep_alive_timeout(Duration::from_secs(10))
            .http2_keep_alive_while_idle(true)
            .referer(false) // do not send Referer / Referrer
            .redirect(reqwest_h3::redirect::Policy::none()) // do not follow redirects

            // connection settings
            .tcp_nodelay(true)
            .pool_idle_timeout(None)
            .pool_max_idle_per_host(5)

            // for all DNS resolve from reqwest, should redirecting to static name mapping (hosts.txt)
            .dns_resolver(Arc::new(&*HOSTS))

            // build client
            .build().unwrap()
    });

#[cfg(feature = "doh3")]
static DOH3_CLIENT: Lazy<reqwest_h3::Client> =
    Lazy::new(|| {
        let mut cs = RUSTLS_CLIENT_CONFIG.clone();
        cs.alpn_protocols = vec![ b"h3".to_vec() ];

        reqwest_h3::Client::builder()
            // log::trace
            .connection_verbose(true)

            // use HTTPS(rustls) only
            .use_rustls_tls()
            .min_tls_version(reqwest_h3::tls::Version::TLS_1_3)
            .https_only(true)
            .tls_sni( HOSTS.map.len() > 0 )
            .use_preconfigured_tls(cs)

            // User-Agent
            .user_agent(&*USER_AGENT)

            // HTTP/3 setting
            .http3_prior_knowledge() // use HTTP/3 only
            .http3_max_idle_timeout(Duration::from_secs(60))
            /*
            .http2_adaptive_window(false)
            .http2_max_frame_size(Some(65535))
            .http2_keep_alive_interval(Some(Duration::from_secs(10)))
            .http2_keep_alive_timeout(Duration::from_secs(10))
            .http2_keep_alive_while_idle(true)
            */
            .referer(false) // do not send Referer / Referrer
            .redirect(reqwest_h3::redirect::Policy::none()) // do not follow redirects

            // connection settings
            //.local_address(Some("::".parse().unwrap()))
            .pool_idle_timeout(None)
            .pool_max_idle_per_host(5)

            // for all DNS resolve from reqwest, should redirecting to static name mapping (hosts.txt)
            .dns_resolver(Arc::new(&*HOSTS))

            // build client
            .build().unwrap()
    });

#[derive(Debug, Clone)]
pub(crate) enum ClientKind {
    H2(reqwest_h3::Client),

    #[allow(dead_code)]
    H3(reqwest_h3::Client),
}
impl ClientKind {
    pub fn is_h2(&self) -> bool {
        match self {
            Self::H2(_) => true,
            _ => false
        }
    }

    pub fn is_h3(&self) -> bool {
        match self {
            Self::H3(_) => true,
            _ => false
        }
    }

    pub fn version(&self) -> u8 {
        if self.is_h2() {
            return 2;
        }
        if self.is_h3() {
            return 3;
        }
        unreachable!()
    }
}

impl AsRef<reqwest_h3::Client> for ClientKind {
    fn as_ref(&self) -> &reqwest_h3::Client {
        match self {
            Self::H2(c) => c,
            Self::H3(c) => c
        }
    }
}

#[cfg(feature = "doh3")]
pub(crate) static DOH3_ONLY: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone)]
pub struct DNSOverHTTPS {
    client: ClientKind,
    url: reqwest_h3::Url,
    metrics: Arc<DNSMetrics>,
    _task: Arc<smol::Task<()>>,
}

impl<'a> DNSOverHTTPS {
    const CONTENT_TYPE: &'static str = "application/dns-message";

    #[cfg(feature = "doh3")]
    pub fn new_h3(
        url: impl ToString,
        /*
        use_hosts: bool,
        mut tls_sni: bool,
        */
    ) -> anyhow::Result<Self> {
        let mut this = Self::new(url)?;
        this.client = ClientKind::H3(DOH3_CLIENT.clone());
        Ok(this)
    }

    pub fn new(
        url: impl ToString,
        /*
        use_hosts: bool,
        mut tls_sni: bool,
        */
    ) -> anyhow::Result<Self> {
        let url: String = url.to_string();

        let url = reqwest_h3::Url::parse(&url).log_warn()?;
        if url.scheme() != "https" {
            anyhow::bail!("DoH server URL scheme invalid.");
        }

        /*
        if use_hosts {
            if ! HOSTS.map.is_empty() {
                tls_sni = true;
            }
        }
        */

        #[allow(unused_mut)]
        let mut client = ClientKind::H2(DOH2_CLIENT.clone());

        #[cfg(feature = "doh3")]
        if DOH3_ONLY.load(Relaxed) {
            client = ClientKind::H3(DOH3_CLIENT.clone());
        }

        let metrics = Arc::new(DNSMetrics::from(&url));

        let _task = Arc::new(smolscale2::spawn(
            Self::_metrics_task(
                client.clone(),
                url.clone(),
                metrics.clone(),
            ),
        ));

        Ok(Self {
            client,
            url,
            metrics,
            _task,
        })
    }

    async fn _metrics_task(
        client: ClientKind,
        url: reqwest_h3::Url,
        metrics: Arc<DNSMetrics>,
    ) {
        let mut start;
        let mut latency;
        let mut maybe_ret;

        let mut zzz = false;

        let v = client.version();
        let mut mult: f64 = 1.0;
        loop {
            if zzz {
                if mult > 10.0 {
                    mult = 10.0;
                }
                let s = (fastrand::u16(5_000 ..= 10_000) as f64) / 1000.0;
                smol::Timer::after(Duration::from_secs_f64(s * mult)).await;
            } else {
                zzz = true;
            }

            start = Instant::now();
            maybe_ret =
                client.as_ref()
                .head(url.clone())
                .header("X-Padding", randstr(fastrand::usize(1..=50)))
                .send()
                .timeout(Duration::from_secs(10))
                .await;
            latency = start.elapsed();

            if let Some(ref ret) = maybe_ret {
                if ret.is_ok() {
                    ret.log_trace();
                    mult = 1.0;
                    log::debug!("DoH{v} server {} working. latency={latency:?}", &url);
                    metrics.up(latency);
                } else {
                    mult *= 1.1;
                    log::warn!("DoH{v} server {} down. used time: {latency:?}, ret={ret:?}", &url);
                    metrics.down();
                }
            } else {
                mult *= 1.1;
                log::warn!("DoH{v} server {} not working! timed out.", &url);
                metrics.down();
            }
        }
    }

    // un-cached DNS Query
    async fn _dns_resolve(&self, query: &DNSQuery) -> anyhow::Result<dns::Message> {
        let v = self.client.version();

        log::info!("DoH{v} un-cached Query: {query:?}");
        let start = Instant::now();
        let result = self._orig_dns_resolve(query).await;
        let latency = start.elapsed();
        log::debug!("DoH{v} un-cached Result: (server={} latency={latency:?}) {result:?}", &self.url);

        if result.is_ok() {
            self.metrics.up(latency);
        } else {
            self.metrics.down();
        }

        result
    }
    async fn _orig_dns_resolve(&self, query: &DNSQuery) -> anyhow::Result<dns::Message> {
        let v = self.client.version();

        let req: dns::Message = query.try_into().log_warn()?;

        let client = self.client.clone();
        let url = self.url.clone();

        let http_res =
            client.as_ref()
            .post(url.clone())
            .header("Content-Type", Self::CONTENT_TYPE)
            .header("Accept", Self::CONTENT_TYPE)
            .header("X-Padding", randstr(fastrand::usize(1..=50)))
            .body(req.to_vec()?)
            .send()
            .await
            .log_info()?;

        if http_res.status().as_u16() != 200 {
            anyhow::bail!("DoH{v} server {url} returns non-200 HTTP status code: {http_res:?}");
        }

        if let Some(ct) = http_res.headers().get("Content-Type") {
            if ct.as_bytes().to_ascii_lowercase() != Self::CONTENT_TYPE.as_bytes() {
                anyhow::bail!("DoH{v} server {url} returns invalid Content-Type header: {http_res:?}");
            }
        } else {
            anyhow::bail!("DoH{v} server {url} does not specify Content-Type header: {http_res:?}");
        }

        let res: Bytes = http_res.bytes().await.log_warn()?;

        if res.len() > 65535 {
            anyhow::bail!("unexpected received too large response from DoH{v} server {url}");
        }

        let response = dns::Message::from_vec(&res).log_warn()?;

        Ok(response)
    }
}

impl DNSResolver for DNSOverHTTPS {
    fn dns_resolve<'a>(&'a self, query: &'a DNSQuery) -> PinFut<'a, anyhow::Result<dns::Message>> {
        Box::pin(async {
            self._dns_resolve(query).await
        })
    }

    fn dns_upstream(&self) -> String {
        self.url.to_string()
    }

    fn dns_protocol(&self) -> &'static str {
        match self.client.version() {
            2 => "DNS over HTTP/2 over TLS over TCP",
            3 => "DNS over HTTP/3 over QUIC over UDP",
            _ => {
                unreachable!()
            }
        }
    }

    fn dns_metrics(&self) -> Arc<DNSMetrics> {
        self.metrics.clone()
    }
}
