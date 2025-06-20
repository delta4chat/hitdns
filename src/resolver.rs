//! DNS Resolver

use crate::{
    *,
    upstream::*,
    query::*,
    entry::*,
    data::upstreams_list,
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
                upstream.server_country() == Some(*code)
                ||
                upstream.operator_country() == Some(*code)
            },
            Self::Protocol(proto) => {
                upstream.protocol() == proto
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
    whitelist: scc2::HashIndex<Filter, bool>,
    blacklist: scc2::HashIndex<Filter, bool>,
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
        let g = scc2::ebr::Guard::new();

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
    upstreams: scc2::HashIndex<Arc<dyn DNSUpstream>, ()>,
    policy: DNSResolverPolicy,
    idx: AtomicUsize,
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
                idx: AtomicUsize::new(0),
            }),
        }
    }

    /// uses [`upstreams_list`]
    pub async fn new_builtin_upstreams(provider: &str) -> Self {
        let this = Self::new();

        this.policy.include(&Arc::new(DNSUpstreamFilter::WithoutLogs(true))).await;

        let loaded = this.add_builtin_upstreams(provider).await.expect("matches");
        log::info!("loaded {} upstreams from built-in upstreams list (sdns).", loaded);

        this
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

    pub async fn add_builtin_upstreams(&self, provider: &str) -> Option<usize> {
        let provider = provider.trim();

        let iter =
            if provider.eq_ignore_ascii_case("dnscrypt") {
                upstreams_list::dnscrypt::SDNS_UPSTREAM_LIST.iter()
            } else if provider.eq_ignore_ascii_case("hitdns") {
                upstreams_list::hitdns::SDNS_UPSTREAM_LIST.iter()
            } else {
                return None;
            };

        let mut i = 0;
        for upstream in iter {
            if self.add_upstream(upstream).await {
                i += 1;
            }
        }
        Some(i)
    }

    pub async fn del_upstream(&self, upstream: &Arc<dyn DNSUpstream>) -> bool {
        self.upstreams.remove_async(upstream).await
    }

    pub fn policy(&self) -> &DNSResolverPolicy {
        &(self.policy)
    }

    pub async fn select(&self, selector: DNSUpstreamSelector) -> std::io::Result<Arc<dyn DNSUpstream>> {
        use DNSUpstreamSelector::*;

        self.retain().await;

        let mut upstreams: Vec<&Arc<dyn DNSUpstream>> = Vec::with_capacity(self.upstreams.len());

        let g = scc2::ebr::Guard::new();
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
        if selector == RoundRobin {
            upstreams.sort();
            return Ok(upstreams[self.idx.fetch_add(1, Relaxed) % upstreams_len].clone());
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
    /// * this does not spawn any background tasks.
    pub async fn resolve(
        &self,
        query: &dyn DNSQuery,
        selector: DNSUpstreamSelector,
    ) -> std::io::Result<DNSEntry> {
        let upstream = self.select(selector).await?;
        upstream.resolve(query).await
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
#[non_exhaustive]
pub enum DNSUpstreamSelector {
    /// try select upstream by default unspecified algorithm.
    /// * currently it alias to `Self::Best`, but this may changed for optimization in future.
    Unspecified = Self::UNSPECIFIED,

    /// try select upstream by latency and reliability.
    /// * high-reliability is important.
    /// * but low-latency also matter.
    Best = Self::BEST,

    /// try select upstream with smallest latency.
    Fast = Self::FAST,

    /// try select upstream with highest reliability.
    Reliable = Self::RELIABLE,

    /// try select upstream randomly.
    Random = Self::RANDOM,

    /// try select upstream by circular (around back) iterating.
    /// * in some specified length, maybe duplicate index 0 if AtomicUsize overflows.
    /// * for example, have 3 upstreams (A, B, C):
    /// 1. A
    /// 2. B
    /// 3. C
    /// 4. A
    /// 5. B
    RoundRobin = Self::ROUND_ROBIN,

    /// (almost useless)
    /// try select upstream by fixed order.
    /// * for example, have 3 upstreams (A, B, C):
    /// 1. A
    /// 2. A
    /// 3. A
    /// 4. A
    /// 5. A
    Fixed = Self::FIXED,
}

impl DNSUpstreamSelector {
    pub const UNSPECIFIED: u8 = 0xff;
    pub const BEST:        u8 = b'B';
    pub const FAST:        u8 = b'F';
    pub const RELIABLE:    u8 = b'R';
    pub const RANDOM:      u8 = b'?';
    pub const ROUND_ROBIN: u8 = b';';
    pub const FIXED:       u8 = b'1';

    pub const fn new(val: u8) -> Option<Self> {
        match val {
            Self::UNSPECIFIED => Some(Self::Unspecified),
            Self::BEST        => Some(Self::Best),
            Self::FAST        => Some(Self::Fast),
            Self::RELIABLE    => Some(Self::Reliable),
            Self::RANDOM      => Some(Self::Random),
            Self::ROUND_ROBIN => Some(Self::RoundRobin),
            Self::FIXED       => Some(Self::Fixed),
            _                 => None
        }
    }

    pub const fn value(self) -> u8 {
        match self {
            Self::Unspecified => Self::UNSPECIFIED,
            Self::Best        => Self::BEST,
            Self::Fast        => Self::FAST,
            Self::Reliable    => Self::RELIABLE,
            Self::Random      => Self::RANDOM,
            Self::RoundRobin  => Self::ROUND_ROBIN,
            Self::Fixed       => Self::FIXED,
        }
    }
}
