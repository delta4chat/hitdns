//! DNS Resolver

use crate::{
    *,
    upstream::*,
    query::*,
    entry::*,
};

// TODO metrics.rs
type DNSMetrics = ();

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum DNSUpstreamFilter {
    Name(String),
    Country(CountryCode),
    Protocol(DNSProtocol),
    AnonymizedLogs(bool),
    WithoutLogs(bool),
    All(Vec<Self>),
}

impl DNSUpstreamFilter {
    pub fn matches(&self, upstream: &dyn DNSUpstream) -> bool {
        match self {
            Self::Name(name) => {
                upstream.name() == name
            }
            Self::Country(code) => {
                upstream.server_country() == *code
                ||
                upstream.operator_country() == *code
            },
            Self::Protocol(proto) => {
                upstream.protocol() == *proto
            },
            Self::AnonymizedLogs(is) => {
                upstream.is_anonymized_logs() == *is
            },
            Self::WithoutLogs(is) => {
                upstream.is_without_logs() == *is
            },
            Self::All(v) => {
                if v.is_empty() {
                    false
                } else {
                    v.iter().all(|filter| {
                        filter.matches(upstream)
                    })
                }
            }
        }
    }
}

type Filter = Arc<DNSUpstreamFilter>;

#[derive(Debug)]
pub struct DNSResolverPolicy {
    whitelist: scc::HashIndex<Filter, bool>,
    blacklist: scc::HashIndex<Filter, bool>,
}

impl DNSResolverPolicy {
    pub fn new() -> Self {
        Self {
            whitelist: Default::default(),
            blacklist: Default::default(),
        }
    }

    pub async fn include(&self, rule: &Filter) {
        if self.whitelist.contains(rule) {
            return;
        }

        self.whitelist.insert_async(rule.clone(), true).await;
    }

    pub async fn exclude(&self, rule: &Filter) {
    }

    pub fn is_valid(&self, upstream: &dyn DNSUpstream) -> bool {
        todo!()
    }
}

#[derive(Debug)]
pub struct DNSResolverInner {
    upstreams: scc::HashIndex<Arc<dyn DNSUpstream>, DNSMetrics>,
    policy: DNSResolverPolicy,
}

#[derive(Debug, Clone)]
pub struct DNSResolver {
    inner: Arc<DNSResolverInner>,
}

impl Deref for DNSResolver {
    type Target = DNSResolverInner;

    fn deref<'a>(&'a self) -> &'a DNSResolverInner {
        self.inner.as_ref()
    }
}

impl DNSResolver {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(DNSResolverInner {
                upstreams: Default::default(),
                policy: DNSResolverPolicy::new(),
            }),
        }
    }

    pub async fn add_upstream(&self, upstream: Arc<dyn DNSUpstream>) {
        if self.upstreams.contains(&upstream) {
            return;
        }
        self.upstreams.insert_async(upstream, DNSMetrics::default()).await;
    }

    /// un-cached resolve.
    pub async fn resolve(&self, query: Arc<dyn DNSQuery>) -> std::io::Result<DNSEntry> {
        todo!()
    }
}
