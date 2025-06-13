//! DNS Resolver

use crate::{
    *,
    upstream::*,
    query::*,
    entry::*,
};

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

pub type Filter = Arc<DNSUpstreamFilter>;

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

    pub fn wlen(&self) -> usize {
        self.whitelist.len()
    }
    pub fn blen(&self) -> usize {
        self.blacklist.len()
    }
    pub fn len(&self) -> usize {
        self.wlen().checked_add(self.blen()).expect("DNSResolverPolicy: overflow in wlen + blen")
    }

    pub async fn include(&self, rule: &Filter) {
        if self.whitelist.contains(rule) {
            return;
        }

        let _ = self.whitelist.insert_async(rule.clone(), true).await;
    }

    pub async fn exclude(&self, rule: &Filter) {
        if self.blacklist.contains(rule) {
            return;
        }


        let _ = self.blacklist.insert_async(rule.clone(), true).await;
    }

    pub fn is_valid(&self, upstream: &dyn DNSUpstream) -> bool {
        let g = scc::ebr::Guard::new();

        for (bf, enable) in self.blacklist.iter(&g) {
            if ! enable {
                continue;
            }

            if bf.matches(upstream) {
                return false;
            }
        }

        for (wf, enable) in self.whitelist.iter(&g) {
            if ! enable {
                continue;
            }

            if wf.matches(upstream) {
                return true;
            }
        }

        false
    }
}

#[derive(Debug)]
pub struct DNSResolverInner {
    upstreams: scc::HashIndex<Arc<dyn DNSUpstream>, ()>,
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

        let _ = self.upstreams.insert_async(upstream, ()).await;
    }

    pub async fn select(&self, selector: DNSUpstreamSelector) -> std::io::Result<Arc<dyn DNSUpstream>> {
        todo!()
        /*
        use DNSUpstreamSelector::*;

        match selector {
            Unspecified | Best => {
            },
        }
        */
    }

    /// un-cached resolve.
    pub async fn resolve(&self, query: &Arc<dyn DNSQuery>) -> std::io::Result<DNSEntry> {
        if self.upstreams.is_empty() {
            return Err(std::io::Error::other("No upstreams exists!"))
        }
        todo!()
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum DNSUpstreamSelector {
    /// try select upstream by default unspecified algorithm (currently `Self::Best`).
    Unspecified,

    /// try select upstream by latency and reliability.
    /// * high reliability is important.
    /// * select lowest latency upstream in high reliability upstreams.
    Best,

    /// try select upstream with smallest latency.
    Fast,

    /// try select upstream with highest reliability.
    Reliable,

    /// try select upstream randomly.
    Random,

    /// try select fixed of upstream.
    Fixed,
}
