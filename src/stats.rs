use crate::*;

use core::cell::Cell;
use core::time::Duration;

use std::time::Instant;
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;

type AtomicU128 = Arc<portable_atomic::AtomicU128>;
type AtomicF64 = Arc<portable_atomic::AtomicF64>;

#[derive(Debug, Clone, Default)]
pub struct DNSQueryStats {
    // how many queries per second
    freq: AtomicF64,

    // how many queries within last 60 seconds, 15 minutes, 1 hour, 12 hours, and total.
    queries_1m: AtomicU128,
    queries_15m: AtomicU128,
    queries_60m: AtomicU128,
    queries_12h: AtomicU128,
    queries_total: AtomicU128,

    // all of queries with timestamp
    queries: scc::TreeIndex<Instant, DNSQueryInfo>,

    // average used time for processing DNS query (contains upstream query time if cache missing)
    avg_delay: Cell<Duration>,

    // total queries via UDP
    udp_queries: AtomicU128,

    // total queries via TCP
    tcp_queries: AtomicU128,

    // number of cache missing
    cache_miss: AtomicU128,
    // number of cache hit (not expired)
    cache_hit: AtomicU128,
    // number of cache expired
    cache_expired: AtomicU128,

    // query numbers of specified domain
    domains: scc::HashMap<String, AtomicU128>,

    // query numbers of specified RdType (usually 90% of A, AAAA)
    rdtypes: scc::HashMap<u16, AtomicU128>,

    // query numbers of specified DNS Class (usually IN - Internet)
    rdclasses: scc::HashMap<u16, AtomicU128>,
}

impl DNSQueryStats {
    pub fn new() -> Self {
        Default::default()
    }

    async fn update(&self) {

    }

    pub async fn add_query(
                     &self,
                     info: DNSQueryInfo,
                 ) -> anyhow::Result<()>
    {
        let query: DNSQuery = info.query_msg
                                  .clone()
                                  .try_into()?;

        let domain = query.name.clone();
        let rdtype = query.rdtype;
        let rdclass = query.rdclass;

        if info.peer.starts_with("udp://") {
            self.udp_queries.fetch_add(1, Relaxed);
        } else if info.peer.starts_with("tcp://") {
            self.tcp_queries.fetch_add(1, Relaxed);
        }

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
        };
        if ret.is_err() {
            log::warn!("cannot insert to scc::HashSet!");
        }

        self.domains.entry_async(domain).await
                    // Entry
                    .or_default()
                    .get()
                    // AtomicU128
                    .fetch_add(1, Relaxed);

        self.rdtypes.entry_async(rdtype).await
                    // Entry
                    .or_default()
                    .get()
                    // AtomicU128
                    .fetch_add(1, Relaxed);

        self.rdclasses.entry_async(rdclass).await
                      // Entry
                      .or_default()
                      .get()
                      // AtomicU128
                      .fetch_add(1, Relaxed);

        Ok(())
    }
}
