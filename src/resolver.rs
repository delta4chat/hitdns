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

    pub async fn retain(&self) {
        self.upstreams.retain_async(|upstream, _| {
            self.policy.is_valid(&**upstream)
        }).await;
    }

    pub async fn add_upstream(&self, upstream: &Arc<dyn DNSUpstream>) -> bool {
        self.retain().await;

        if self.upstreams.contains(upstream) {
            return true;
        }

        if ! self.policy.is_valid(&**upstream) {
            return false;
        }

        let _ = self.upstreams.insert_async(upstream.clone(), ()).await;

        true
    }

    pub async fn select(&self, selector: DNSUpstreamSelector) -> std::io::Result<Arc<dyn DNSUpstream>> {
        use DNSUpstreamSelector::*;

        self.retain().await;

        let mut upstreams: Vec<&Arc<dyn DNSUpstream>> = Vec::with_capacity(self.upstreams.len());

        let g = scc::ebr::Guard::new();
        for (k, _) in self.upstreams.iter(&g) {
            if upstreams.contains(&k) {
                continue;
            }
            upstreams.push(k);
        }

        let upstreams_len = upstreams.len();
        if upstreams_len == 0 {
            return err_invalid_data("empty list of DNSUpstream!");
        }

        if selector == Random {
            fastrand::shuffle(&mut upstreams);
            fastrand::shuffle(&mut upstreams);
            return Ok(upstreams[0].clone());
        }
        if selector == Fixed {
            return Ok(upstreams[0].clone());
        }

        let mut selected = None;
        let mut old;
        for new in upstreams.into_iter() {
            old =
                match selected {
                    Some(v) => v,
                    _ => {
                        selected = Some(new);
                        continue;
                    }
                };

            match selector {
                Unspecified | Best => {
                    if new.metrics().score() < old.metrics().score() {
                        continue;
                    }
                },
                Fast => {
                    if new.metrics().latency() > old.metrics().latency() {
                        continue;
                    }
                },
                Reliable => {
                    if new.metrics().reliability() < old.metrics().reliability() {
                        continue;
                    }
                },
                _ => {
                    unreachable!();
                },
            }

            selected = Some(new);
        }

        Ok(selected.expect("must select one from non-empty upstreams").clone())
    }

    /// un-cached resolve.
    pub async fn resolve(
        &self,
        query: &Arc<dyn DNSQuery>,
        selector: DNSUpstreamSelector,
    ) -> std::io::Result<DNSEntry> {
        let upstream = self.select(selector).await?;
        upstream.resolve(query.clone()).await
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
