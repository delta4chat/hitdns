use crate::*;

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
            .user_agent(
                format!(
                    "hitdns/{}",
                    option_env!("CARGO_PKG_VERSION").unwrap_or("NA")
                )
            )

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
            .tcp_nodelay(true)
            .pool_idle_timeout(None)
            .pool_max_idle_per_host(5)

            // for all DNS resolve from reqwest, should redirecting to static name mapping (hosts.txt)
            .dns_resolver(Arc::new(&*HOSTS))

            // build client
            .build().unwrap()
    });

#[derive(Debug, Clone)]
pub struct DNSOverH3 {
    client: reqwest_h3::Client,
    url: reqwest_h3::Url,
    metrics: Arc<RwLock<DNSMetrics>>,
    _task: Arc<smol::Task<()>>,
}

impl<'a> DNSOverH3 {
    const CONTENT_TYPE: &'static str = "application/dns-message";

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
            anyhow::bail!("DoH3 server URL scheme invalid.");
        }

        /*
        if use_hosts {
            if ! HOSTS.map.is_empty() {
                tls_sni = true;
            }
        }
        */

        let client = DOH3_CLIENT.clone();

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
        client: reqwest_h3::Client,
        url: reqwest_h3::Url,
        metrics: Arc<RwLock<DNSMetrics>>,
    ) {
        let mut start;
        let mut latency;
        let mut maybe_ret;

        let mut zzz = false;

        loop {
            if zzz {
                smol::Timer::after(
                    Duration::from_secs(
                        fastrand::u64(5..=10)
                    )
                ).await;
            } else {
                zzz = true;
            }

            let url_ = url.clone();

            start = Instant::now();
            maybe_ret =
                client.head(url_)
                .header("X-Padding", randstr(fastrand::usize(1..=50)))
                .send()
                .timeout(Duration::from_secs(10))
                .await;
            latency = start.elapsed();

            let metrics = metrics.clone();
            let url_ = url.clone();
            {
                let mut m = metrics.write().await;

                if let Some(ret) = &maybe_ret {
                    if ret.is_ok() {
                        ret.log_trace();
                        log::debug!("DoH3 server {url_} working. latency={latency:?}");
                        m.up(latency);
                    } else {
                        log::warn!("DoH3 server {url_} down. used time: {latency:?}, ret={ret:?}");
                        m.down();
                    }
                } else {
                    log::warn!("DoH3 server {url_} not working! timed out.");
                    m.down();
                }

            }
        }
    }

    // un-cached DNS Query
    async fn _dns_resolve(&self, query: &DNSQuery) -> anyhow::Result<dns::Message> {
        log::info!("DoH3 un-cached Query: {query:?}");
        let start = Instant::now();
        let result = self._orig_dns_resolve(query).await;
        let latency = start.elapsed();
        log::info!("DoH3 un-cached Result: (server={} latency={latency:?}) {result:?}", &self.url);

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
        let req: dns::Message =
            query.try_into().log_warn()?;

        let client = self.client.clone();
        let url = self.url.clone();

        let http_res = client
            .post(url.clone())
            .header("Content-Type", Self::CONTENT_TYPE)
            .header("Accept", Self::CONTENT_TYPE)
            .header("X-Padding", randstr(fastrand::usize(1..=50)))
            .body(req.to_vec()?)
            .send()
            .await
            .log_info()?;

        if http_res.status().as_u16() != 200 {
            anyhow::bail!("DoH3 server {url} returns non-200 HTTP status code: {http_res:?}");
        }

        if let Some(ct) = http_res.headers().get("Content-Type") {
            if ct.as_bytes().to_ascii_lowercase() != Self::CONTENT_TYPE.as_bytes() {
                anyhow::bail!("DoH3 server {url} returns invalid Content-Type header: {http_res:?}");
            }
        } else {
            anyhow::bail!("DoH3 server {url} does not specify Content-Type header: {http_res:?}");
        }

        let res: Bytes = http_res.bytes().await.log_warn()?;

        if res.len() > 65535 {
            anyhow::bail!("unexpected received too large response from DoH3 server {url}");
        }

        let response = dns::Message::from_vec(&res).log_warn()?;

        Ok(response)
    }
}

impl DNSResolver for DNSOverH3 {
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
        "DNS over HTTP/3 over QUIC over UDP"
    }

    fn dns_metrics(&self) -> PinFut<DNSMetrics> {
        Box::pin(async move {
            self.metrics.read().await.clone()
        })
    }
}
