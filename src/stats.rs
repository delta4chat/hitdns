use crate::*;

//use core::cell::Cell;
//use core::time::Duration;

use std::time::Instant;
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;

type AtomicU64 = Arc<portable_atomic::AtomicU64>;
type AtomicU128 = Arc<portable_atomic::AtomicU128>;
type AtomicF64 = Arc<portable_atomic::AtomicF64>;

pub(crate) static STATS_FULL: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Default)]
pub struct DNSQueryData {
    // last generate time in unix secs
    last_update: AtomicU64,

    // how many queries per second
    freq: AtomicF64,

    // how many queries within last 60 seconds, 5 minutes, 15 minutes, 1 hour, 12 hours, 24 hours, and total.
    queries_1m: AtomicU128,
    queries_5m: AtomicU128,
    queries_15m: AtomicU128,
    queries_60m: AtomicU128,
    queries_12h: AtomicU128,
    queries_24h: AtomicU128,
    queries_total: AtomicU128,

    // average latency (Duration::as_secs_f64) for processing DNS query (contains upstream query time if cache missing)
    avg_latency: AtomicF64,

    // total queries via UDP
    udp_queries: AtomicU128,

    // total queries via TCP
    tcp_queries: AtomicU128,

    // total queries via DoH-plaintext
    dohp_queries: AtomicU128,

    // number of cache missing
    cache_miss: AtomicU128,
    // number of cache hit (not expired)
    cache_hit: AtomicU128,
    // number of cache expired
    cache_expired: AtomicU128,

    // query numbers of specified domain
    domains: Arc<scc::HashMap<String, AtomicU128>>,

    // query numbers of specified RdType (usually 90% of A, AAAA)
    rdtypes: Arc<scc::HashMap<u16, AtomicU128>>,

    // query numbers of specified DNS Class (usually IN - Internet)
    rdclasses: Arc<scc::HashMap<u16, AtomicU128>>,
}
impl DNSQueryData {
    pub async fn to_json(&self) -> anyhow::Result<serde_json::Value> {
        let full = STATS_FULL.load(Relaxed);

        if self.last_update.load(Relaxed) == 0 {
            anyhow::bail!("no data avaliable: no any update");
        }

        let domains =
            if full {
                let mut domains = serde_json::Map::new();
                self.domains.scan_async(|domain, count|{
                    let key: String = domain.into();

                    let val: serde_json::Value =
                        count.load(Relaxed).to_string().into();

                    domains.insert(key, val);
                }).await;
                serde_json::Value::Object(domains)
            } else {
                serde_json::Value::Null
            };

        let mut rdtypes = serde_json::Map::new();
        self.rdtypes.scan_async(|rdtype, count|{
            let key: String =
                format!(
                    "{}({})",
                    dns::RdType::from(*rdtype)
                        .to_string(),
                    rdtype
                );

            let val: serde_json::Value =
                count.load(Relaxed).to_string().into();

            rdtypes.insert(key, val);
        }).await;

        let mut rdclasses = serde_json::Map::new();
        self.rdclasses.scan_async(|rdclass, count|{
            let key: String =
                format!(
                    "{}({})",
                    dns::RdClass::from(*rdclass)
                        .to_string(),
                    rdclass
                );

            let val: serde_json::Value =
                count.load(Relaxed).to_string().into();

            rdclasses.insert(key, val);
        }).await;

        let ts = self.last_update.load(Relaxed);
        let dt =
            time::OffsetDateTime::from_unix_timestamp(
                ts as i64
            )?;

        let queries_within =
            if full {
                serde_json::json!({
                    "1m": self.queries_1m.load(Relaxed).to_string(),
                    "5m": self.queries_5m.load(Relaxed).to_string(),
                    "15m": self.queries_15m.load(Relaxed).to_string(),
                    "60m": self.queries_60m.load(Relaxed).to_string(),
                    "12h": self.queries_12h.load(Relaxed).to_string(),
                    "24h": self.queries_24h.load(Relaxed).to_string(),
                    "total": self.queries_total.load(Relaxed).to_string(),
                })
            } else {
                serde_json::Value::Null
            };

        Ok(serde_json::json!({
            "last_update": {
                "timestamp": ts.to_string(),
                "string": dt.format(&TIME_FMT_JS)?,
            },
            "freq": self.freq.load(Relaxed),
            "queries_within": queries_within, 
            "queries_from": {
                "udp": self.udp_queries.load(Relaxed)
                                       .to_string(),

                "tcp": self.tcp_queries.load(Relaxed)
                                       .to_string(),

                "dohp": self.dohp_queries.load(Relaxed)
                                         .to_string(),
            },
            "cache_lookups": {
                "hit":
                    self.cache_hit.load(Relaxed)
                                  .to_string(),
                "expired":
                    self.cache_expired.load(Relaxed)
                                      .to_string(),
                "miss":
                    self.cache_miss.load(Relaxed)
                                   .to_string(),
            },
            "avg_latency": self.avg_latency.load(Relaxed),

            "queries": {
                "domains": domains,
                "rdtypes": rdtypes,
                "rdclasses": rdclasses,
            }
        }))
    }
}

#[derive(Debug, Clone)]
pub struct DNSQueryStats {
    // timestamping
    started: Instant,
    elapsed: AtomicF64,

    // all of queries with timestamp
    queries: Arc<scc::TreeIndex<Instant, DNSQueryInfo>>,

    // inner data that can `derive(Default)`
    data: DNSQueryData,
}

impl DNSQueryStats {
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
            elapsed: Default::default(),

            queries: Default::default(),

            data: Default::default(),
        }
    }

    pub async fn to_json(&self)
        -> anyhow::Result<serde_json::Value>
    {
        self.data.to_json().await
    }

    fn update(&self) {
        let elapsed = self.elapsed.load(Relaxed);
        if elapsed == 0.0 {
            log::debug!("no .elapsed so cannot calc average queries number");
            return;
        };

        /* update .freq */
        let queries = self.queries.len();
        let freq = (queries as f64) / elapsed;
        self.data.freq.store(freq, Relaxed);

        /* update queries_1m/5m/15m/60m/12h/1d */
        let mut queries_1m: u128 = 0;
        let mut queries_5m: u128 = 0;
        let mut queries_15m: u128 = 0;
        let mut queries_60m: u128 = 0;
        let mut queries_12h: u128 = 0;
        let mut queries_24h: u128 = 0;

        let mut used_times: Vec<f64> = vec![];

        {
            let g = scc::ebr::Guard::new();
            for entry in self.queries.iter(&g) {
                let (time, info) = entry;

                if let Some(ut) = info.used_time {
                    used_times.push(ut.as_secs_f64());
                }

                let elapsed_secs = time.elapsed().as_secs();

                if elapsed_secs <= 60 {
                    queries_1m += 1;
                }
                else if elapsed_secs <= 60*5 {
                    queries_5m += 1;
                }
                else if elapsed_secs <= 60*15 {
                    queries_15m += 1;
                }
                else if elapsed_secs <= 60*60 {
                    queries_60m += 1;
                }
                else if elapsed_secs <= 60*60*12 {
                    queries_12h += 1;
                }
                else if elapsed_secs <= 60*60*24 {
                    queries_24h += 1;
                }
            }
            // guard dropping now
        }

        let avg_latency: f64 = used_times.iter().sum::<f64>() / (used_times.len() as f64);

        self.data.avg_latency.store(avg_latency, Relaxed);

        self.data.queries_1m.store(queries_1m, Relaxed);
        self.data.queries_5m.store(queries_5m, Relaxed);
        self.data.queries_15m.store(queries_15m, Relaxed);
        self.data.queries_60m.store(queries_60m, Relaxed);
        self.data.queries_12h.store(queries_12h, Relaxed);
        self.data.queries_24h.store(queries_24h, Relaxed);

        self.data.queries_total.store(queries as u128, Relaxed);

        /* store .last_update */
        self.data.last_update.store(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),

            Relaxed
        );
    }

    pub fn add_query(&self, info: DNSQueryInfo) {
        let this = self.clone();
        smolscale2::spawn(async move {
            this._add_query(info).await.unwrap();
        }).detach();
    }

    pub async fn _add_query(&self, info: DNSQueryInfo) -> anyhow::Result<()> {
        let full = STATS_FULL.load(Relaxed);

        let query: DNSQuery = info.query_msg.clone().try_into()?;

        let domain = query.name.clone();
        let rdtype = query.rdtype;
        let rdclass = query.rdclass;

        if info.peer.starts_with("udp://") {
            self.data.udp_queries.fetch_add(1, Relaxed);
        } else if info.peer.starts_with("tcp://") {
            self.data.tcp_queries.fetch_add(1, Relaxed);
        } else if info.peer.starts_with("dohp://") {
            self.data.dohp_queries.fetch_add(1, Relaxed);
        }

        if full {
            let mut ret = Ok(());
            for _ in 0..10 {
                ret = self.queries
                          .insert_async(
                               Instant::now(),
                               info.clone()
                          ).await;

                if ret.is_ok() {
                    break;
                }
            }
            if ret.is_err() {
                log::warn!("cannot insert to scc::HashMap!");
            }

            self.data.domains.entry_async(domain).await
                // Entry
                .or_default()
                .get()
                // AtomicU128
                .fetch_add(1, Relaxed);
        }

        self.data.rdtypes.entry_async(rdtype).await
            // Entry
            .or_default()
            .get()
            // AtomicU128
            .fetch_add(1, Relaxed);

        self.data.rdclasses.entry_async(rdclass).await
            // Entry
            .or_default()
            .get()
            // AtomicU128
            .fetch_add(1, Relaxed);

        if let Some(status) = &info.cache_status {
            use DNSCacheStatus::*;
            match status {
                Hit(_) => {
                    self.data.cache_hit.fetch_add(1, Relaxed);
                },
                Expired(_) => {
                    self.data.cache_expired.fetch_add(1, Relaxed);
                },
                Miss => {
                    self.data.cache_miss.fetch_add(1, Relaxed);
                }
            }
        }

        /* all done */
        let new_elapsed = self.started.elapsed().as_secs_f64();

        self.elapsed.store(new_elapsed, Relaxed);

        let now = SystemTime::now()
               .duration_since(SystemTime::UNIX_EPOCH)?
               .as_secs();
        let last_update =
            self.data.last_update.load(Relaxed);

        if (now - last_update) >= 10 {
            self.update();
        }
        Ok(())
    }
}
