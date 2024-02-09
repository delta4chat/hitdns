use crate::*;

#[derive(Debug, Clone)]
pub struct DNSOverHTTPS {
    client: reqwest::Client,
    url: reqwest::Url,
    metrics: Arc<RwLock<DNSMetrics>>,
    _task: Arc<smol::Task<()>>,
}

impl<'a> DNSOverHTTPS {
    const CONTENT_TYPE: &'static str = "application/dns-message";

    pub fn new(
        url: impl ToString,
        use_hosts: bool,
        mut tls_sni: bool
    ) -> anyhow::Result<Self> {
        let url: String = url.to_string();
        let url = reqwest::Url::parse(&url).log_warn()?;

        if url.scheme() != "https" {
            anyhow::bail!("DoH server URL scheme invalid.");
        }
        
        struct DummyDNS(bool);
        impl reqwest::dns::Resolve for DummyDNS {
            // pub type Resolving = Pin<Box<dyn Future<Output = Result<Addrs, Box<dyn StdError + Send + Sync>>> + Send>>;
            fn resolve(&self, domain: hyper::client::connect::dns::Name) -> reqwest::dns::Resolving {
                if self.0 {
                    return HOSTS.resolve(domain);
                }
                let msg = format!("unexpected DNS resolve request ({domain:?}) from reqwest::Client in DoH client. this avoids infinity-recursive DNS resolving if hitdns itself as a system resolver. because TLS certificate Common Name or Alt Subject Name can be IP addresses, so you can use IP address instead of a domain name (need DoH server supports). or instead you can give a hosts.txt file by --hosts or --use-system-hosts");
                log::warn!("{}", &msg);
                Box::pin(async move {
                    let err: Box<dyn std::error::Error + Send + Sync> = Box::new(std::io::Error::new(std::io::ErrorKind::Unsupported, msg));
                    Err(err)
                })
           }
        }

        if use_hosts {
            if ! HOSTS.map.is_empty() {
                tls_sni = true;
            }
        }

        let client =
            reqwest::Client::builder()

            // log::trace
            .connection_verbose(true)

            // use HTTPS(rustls) only
            .use_rustls_tls()
            .min_tls_version(reqwest::tls::Version::TLS_1_2)
            .https_only(true)
            .tls_sni(tls_sni)

            // HTTP/2 setting
            .http2_prior_knowledge() // use HTTP/2 only
            .http2_adaptive_window(false)
            .http2_max_frame_size(Some(65535))
            .http2_keep_alive_interval(Some(Duration::from_secs(10)))
            .http2_keep_alive_timeout(Duration::from_secs(10))
            .http2_keep_alive_while_idle(true)
            .referer(false)
            .redirect(reqwest::redirect::Policy::none())

            // connection settings
            .tcp_nodelay(true)
            .pool_idle_timeout(None)
            .pool_max_idle_per_host(5)

            // for all DNS resove from reqwest, should redirecting to static name mapping (hosts.txt), or just disable it if no hosts specified
            .dns_resolver(
                Arc::new(
                    DummyDNS(use_hosts)
                )
            )

            // build client
            .build().log_warn()?;

        let metrics =
            Arc::new(RwLock::new(
                DNSMetrics::new()
            ));

        Ok(Self {
            client: client.clone(),
            url: url.clone(),
            metrics: metrics.clone(),
            _task: Arc::new(smolscale2::spawn(async move {
                let mut start;
                let mut latency;
                let mut maybe_ret;
                loop {
                    smol::Timer::after(
                        Duration::from_secs(10)
                    ).await;

                    start = Instant::now();
                    maybe_ret =
                        client.head( url.clone() )
                        .send()
                        .timeout(Duration::from_secs(10))
                        .await;
                    latency = start.elapsed();

                    let mut m = metrics.write().await;
                    if let Some(ret) = &maybe_ret {
                        if ret.is_ok() {
                            log::debug!("DoH server {url} working. latency={latency:?} ret={ret:?}");
                            m.up(latency);
                            std::mem::drop(m);
                            continue;
                        } else {
                            log::warn!("DoH server {url} down. used time: {latency:?}, ret={ret:?}");
                        }
                    }

                    if maybe_ret.is_none() {
                        log::warn!("DoH server {url} not working! timed out.");
                    }

                    m.down();
                    std::mem::drop(m);
                }
            })) // Arc::new(smolscale2::spawn(
        }) // Ok(
    }

    // un-cached DNS Query
    async fn _dns_resolve(&self, query: &DNSQuery)
        -> anyhow::Result<dns::Message>
    {
        let start = Instant::now();
        let result = self._orig_dns_resolve(query).await;
        let latency = start.elapsed();

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
    async fn _orig_dns_resolve(&self, query: &DNSQuery)
        -> anyhow::Result<dns::Message>
    {
        log::info!("DoH un-cached Query: {query:?}");

        let req: dns::Message = query.try_into().log_warn()?;

        let client = self.client.clone();
        let url = self.url.clone();

        let http_res = client.post(url.clone())
            .header("Content-Type", Self::CONTENT_TYPE)
            .header("Accept", Self::CONTENT_TYPE)
            .body(req.to_vec()?)
            .send().await.log_info()?;

        if http_res.status().as_u16() != 200 {
            anyhow::bail!("DoH server {url} returns non-200 HTTP status code: {http_res:?}");
        }

        if let Some(ct) = http_res.headers().get("Content-Type") {
            if ct.as_bytes().to_ascii_lowercase() != Self::CONTENT_TYPE.as_bytes() {
                anyhow::bail!("DoH server {url} returns invalid Content-Type header: {http_res:?}");
            }
        } else {
            anyhow::bail!("DoH server {url} does not specify Content-Type header: {http_res:?}");
        }

        let res: Bytes =
            http_res.bytes().await
            .log_warn()?;

        if res.len() > 65535 {
            anyhow::bail!("unexpected received too large response from DoH server {url}");
        }

        let response =
            dns::Message::from_vec(&res).log_warn()?;

        log::info!("DoH un-cached response {response:?}");
        Ok(response)
    }
}

impl DNSResolver for DNSOverHTTPS {
    fn dns_resolve(&self, query: &DNSQuery)
        -> PinFut<anyhow::Result<dns::Message>>
    {
        let query = query.clone();
        Box::pin(async move {
            self._dns_resolve(&query).await
        })
    }

    fn dns_upstream(&self) -> String {
        self.url.to_string()
    }

    fn dns_protocol(&self) -> &'static str {
        "DNS over HTTP/2 over TLS over TCP"
    }

    fn dns_metrics(&self) -> PinFut<DNSMetrics> {
        Box::pin(async move {
            self.metrics.read().await.clone()
        })
    }
}
