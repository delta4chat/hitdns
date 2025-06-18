use crate::{
    *,
    query::*,
    entry::*,
    upstream::*,
    protocol::h2::*,
};

use dns_stamp_parser::{Props, DnsOverHttps};

#[derive(Debug, Clone)]
pub struct DoHUpstream {
    sdns: Arc<DnsOverHttps>,
    url: Arc<Url>,
    metrics: DNSUpstreamMetrics,
}

impl Deref for DoHUpstream {
    type Target = DnsOverHttps;

    fn deref<'a>(&'a self) -> &'a DnsOverHttps {
        self.sdns.deref()
    }
}

impl DoHUpstream {
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

        Self {
            sdns,
            url: Arc::new(url),
            metrics: DNSUpstreamMetrics::new(),
        }
    }
}

impl DNSUpstream for DoHUpstream {
    fn name<'a>(&'a self) -> &'a str {
        self.hostname.as_str()
    }

    fn protocol(&self) -> DNSProtocol {
        DNSProtocol::DoH(self.url.clone())
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

            let doh_req =
                http::Request::post(this.url.as_str())
                .header("content-type", "application/dns-message")
                .header("content-length", dns_req_len.as_bytes())
                .body(dns_req).map_err(std::io::Error::other)?;

            let client = H2Client::global();
            let doh_resp = client.request(doh_req).await?;

            let dns_resp = {
                let status = doh_resp.status();
                if ! status.is_success() {
                    return err_invalid_data(format!("DoH/2 upstream server responds HTTP non-2XX status code for DNS query! code={}, query={:?}, resp={:?}", status, q, doh_resp));
                }

                let msg = dns::Message::from_vec(doh_resp.body()).map_err(invalid_data)?;
                let source = DNSResponseSource::Internet(Ok(Arc::new(this)));
                DNSEntry::new(msg, source)
            };

            Ok(dns_resp)
        })
    }
}
