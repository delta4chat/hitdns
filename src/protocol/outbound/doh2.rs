use crate::{
    *,
    query::*,
    entry::*,
    upstream::*,
};

use dns_stamp_parser::{Props, DnsOverHttps};

static UGI_CLIENT: Lazy<ugi::Client> = Lazy::new(|| {
    ugi::Client::builder()
    .dual_stack(true)
    .dns_cache_ttl(Duration::from_secs(600))

    .alpn_protocols(["h2"])
    .http2_only()
    .h2_keepalive(Duration::from_secs(2), Duration::from_secs(5))

    .compression_mode(ugi::CompressionMode::Manual)
    .redirect(ugi::RedirectPolicy::None)
    .retry(ugi::RetryPolicy::None)

    .pool_config(ugi::PoolConfig {
        max_idle_per_host: 3,
        idle_timeout: None,
    })

    .build().expect("Failed to create global ugi::Client!")
});

#[derive(Debug, Clone)]
pub struct DoH2Upstream {
    sdns: Arc<DnsOverHttps>,
    protocol: DNSProtocol,
    url: Arc<String>,
    metrics: DNSUpstreamMetrics,
}

impl Deref for DoH2Upstream {
    type Target = DnsOverHttps;

    fn deref<'a>(&'a self) -> &'a DnsOverHttps {
        self.sdns.deref()
    }
}

impl DoH2Upstream {
    pub fn new(sdns: DnsOverHttps) -> Self {
        Self::new_arc(Arc::new(sdns))
    }

    pub fn new_arc(sdns: Arc<DnsOverHttps>) -> Self {
        let mut url = Url::parse("doh2://server.example/dns-query").unwrap();

        url.set_host(Some(sdns.hostname.as_str())).expect("unexpectedly failed to set host");
        url.set_port(
            sdns.addr.map(|addr| {
                use dns_stamp_parser::Addr::*;
                match addr {
                    SocketAddr(sa) => sa.port(),
                    Port(p) => p,
                }
            })
        ).expect("unexpectedly failed to set port");

        url.set_path(sdns.path.as_str());

        let protocol = DNSProtocol::DoH(Arc::new(url.clone()));

        let url: String = dbg!("https".chars().chain(url.as_str().chars().skip(4)).collect());
        Self {
            sdns,
            protocol,
            url: Arc::new(url),
            metrics: DNSUpstreamMetrics::new(),
        }
    }
}

impl DNSUpstream for DoH2Upstream {
    fn name<'a>(&'a self) -> &'a str {
        self.hostname.as_str()
    }

    fn protocol<'a>(&'a self) -> &'a DNSProtocol {
        &(self.protocol)
    }

    fn server_country(&self) -> Option<CountryCode> {
        // TODO
        None
    }

    fn operator_country(&self) -> Option<CountryCode> {
        // TODO
        None
    }

    // sdns link does not have such property
    fn is_anonymized_logs(&self) -> bool {
        self.is_without_logs()
    }

    fn is_without_logs(&self) -> bool {
        self.props.contains(Props::NO_LOGS)
    }

    // TODO add no-filter and no-censorship field
    //

    fn is_support_dnssec(&self) -> bool {
        self.props.contains(Props::DNSSEC)
    }

    fn metrics<'a>(&'a self) -> &'a DNSUpstreamMetrics {
        &(self.metrics)
    }

    fn resolve(&self, q: &dyn DNSQuery) -> PinFut<std::io::Result<DNSEntry>> {
        let q = q.message();
        let this = self.clone();
        Box::pin(async move {
            let dns_req = Bytes::copy_from_slice(q.to_vec().map_err(invalid_input)?.as_ref());
            let dns_req_len = {
                let mut buf = heapless::String::<5>::new(); // dns request length <= 65535
                write!(buf, "{}", dns_req.len()).map_err(std::io::Error::other)?;
                buf
            };

            let doh_resp =
                UGI_CLIENT
                .post(this.url.as_str())
                .header("content-type", "application/dns-message").expect("cannot set content-type")
                .header("content-length", dns_req_len.as_str()).expect("cannot set content-length")
                .body(dns_req)
                .await.map_err(std::io::Error::other)?;

            let dns_resp = {
                let status = doh_resp.status();
                if ! status.is_success() {
                    return err_invalid_data(format!("DoH/2 upstream server responds HTTP non-2XX status code for DNS query! code={}, query={:?}, resp={:?}", status.as_u16(), q, doh_resp));
                }

                let data = doh_resp.bytes().await.map_err(std::io::Error::other)?;
                let msg = dns::Message::from_vec(&data).map_err(invalid_data)?;
                let source = DNSResponseSource::Internet(Ok(Arc::new(this)));
                DNSEntry::new(msg, source)
            };
            Ok(dns_resp)
        })
    }
}
