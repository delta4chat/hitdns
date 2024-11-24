use crate::*;

static USER_AGENT: Lazy<String> =
    Lazy::new(|| {
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
    metrics: Arc<RwLock<DNSMetrics>>,
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

        let metrics = Arc::new(RwLock::new(DNSMetrics::from(&url)));

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
        metrics: Arc<RwLock<DNSMetrics>>,
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

            let metrics = metrics.clone();
            {
                let mut m = metrics.write().await;

                if let Some(ret) = &maybe_ret {
                    if ret.is_ok() {
                        ret.log_trace();
                        mult = 1.0;
                        log::debug!("DoH{v} server {} working. latency={latency:?}", &url);
                        m.up(latency);
                    } else {
                        mult *= 1.1;
                        log::warn!("DoH{v} server {} down. used time: {latency:?}, ret={ret:?}", &url);
                        m.down();
                    }
                } else {
                    mult *= 1.1;
                    log::warn!("DoH{v} server {} not working! timed out.", &url);
                    m.down();
                }
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

        let ok = result.is_ok();

        let metrics_lock = self.metrics.clone();
        smolscale2::spawn(async move {
            let mut metrics = metrics_lock.write().await;

            if ok {
                metrics.up(latency);
            } else {
                metrics.down();
            }
        }).detach();

        result
    }
    async fn _orig_dns_resolve(&self, query: &DNSQuery) -> anyhow::Result<dns::Message> {
        let v = self.client.version();

        let req: dns::Message =
            query.try_into().log_warn()?;

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
    fn dns_resolve(
        &self,
        query: &DNSQuery,
    ) -> PinFut<anyhow::Result<dns::Message>> {
        let query = query.clone();
        Box::pin(async move {
            self._dns_resolve(&query).await
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

    fn dns_metrics(&self) -> PinFut<DNSMetrics> {
        Box::pin(async move {
            self.metrics.read().await.clone()
        })
    }
}
