use crate::{
    *,
    query::*,
    entry::*,
    asled::{SledRunner, SledOperation},
};

#[derive(Debug, Clone)]
pub struct DNSDatabase {
    sled: SledRunner,
    negative_keys: MokaCache<DNSQuerySerialized, ()>,
}

impl DNSDatabase {
    pub const NS_CACHE_V1: &'static [u8] = b"hitdns_cache_v1";
    pub const NS_LOGS_V1: &'static [u8] = b"hitdns_logs_v1";
    pub const NS_STATS_V1: &'static [u8] = b"hitdns_stats_v1";

    pub fn open<P: AsRef<Path>>(path: P) -> sled::Result<Self> {
        let sled = SledRunner::open(path)?;
        Ok(Self {
            sled,
            negative_keys: {
                MokaCacheBuilder::default()
                .name("hitdns database negative keys cache")
                .max_capacity(65535)
                //.async_eviction_listener(|_query, _entry, cause| {})
                .time_to_idle(Duration::from_secs(30)) // 30 seconds for time-to-idle
                .time_to_live(Duration::from_secs(60)) // one minute for time-to-live
                .build_with_hasher(ahash::RandomState::new())
            },
        })
    }

    /// try to open DNS Database automatically using DATA_DIR
    pub fn auto_open() -> sled::Result<Self> {
        let mut path = (&*config::DATA_DIR).clone();
        path.push("hitdns-db-sled-v0.34");
        Self::open(path)
    }

    pub async fn cache_scan<Q: DNSQuery + Any + Sized>(&self) -> sled::Result<Vec<(Q, DNSEntry)>> {
        let op =
            SledOperation::new(move |db| {
                let f =
                    move || -> Cell<Option<sled::Result<Vec<(Q, DNSEntry)>>>> {
                        let tree =
                            match db.open_tree(Self::NS_CACHE_V1) {
                                Ok(v) => v,
                                Err(e) => {
                                    return Cell::new(Some(Err(e)));
                                }
                            };

                        let mut out = Vec::with_capacity(1024);
                        let mut query;
                        let mut entry;
                        for ret in tree.iter() {
                            match ret {
                                Ok((key, value)) => {
                                    let key: &[u8] = key.as_ref();

                                    query =
                                        match Q::decode(key) {
                                            Ok(v) => v,
                                            Err(e) => {
                                                log::warn!("corrupted DNSQuery format! error={:?}", e);
                                                let _ = tree.remove(key);
                                                continue;
                                            }
                                        };

                                    entry =
                                        match DNSEntry::decode(value) {
                                            Ok(v) => v,
                                            Err(e) => {
                                                log::warn!("corrupted DNSEntry format! error={:?}", e);
                                                let _ = tree.remove(key);
                                                continue;
                                            }
                                        };

                                    out.push((query, entry));
                                },
                                Err(e) => {
                                    log::warn!("failed to iterating in-disk DNS cache! error={:?}", e);
                                }
                            }
                        }

                        Cell::new(Some(Ok(out)))
                    };
                Box::new(f())
            });

        let sw_fut = self.sled.queue(op).await;
        let sw_res = sw_fut.await;
        let sw_res: &Box<dyn Any+Send> = sw_res.deref();
        let sw_res: &(dyn Any+Send) = sw_res.deref();

        let res: &Cell<Option<sled::Result<Vec<(Q, DNSEntry)>>>> = sw_res.downcast_ref().expect("bug: return type mismatch in DNSDatabase::cache_scan()");
        res.replace(None).take().expect("must have value")
    }

    pub async fn cache_get(&self, query: &dyn DNSQuery) -> sled::Result<Option<DNSEntry>> {
        let key = query.encode();

        if self.negative_keys.get(&key).await.is_some() {
            return Ok(None);
        }

        let op =
            SledOperation::new(move |db| {
                let f =
                    move || -> sled::Result<Option<DNSEntry>> {
                        db
                        .open_tree(Self::NS_CACHE_V1)?
                        .transaction(move |tree| {
                            let key: &[u8] = key.as_ref();
                            if let Some(value) = tree.get(key)? {
                                let value: &[u8] = value.as_ref();
                                match DNSEntry::decode(value) {
                                    Ok(entry) => Ok(Some(entry)),
                                    Err(_err) => {
                                        let _ = tree.remove(key)?;
                                        log::warn!(
                                            "deleting corrupted DNS Entry in disk! key={} data={}",
                                            key.escape_ascii(),
                                            value.escape_ascii(),
                                        );
                                        Ok(None)
                                    }
                                }
                            } else {
                                Ok(None)
                            }
                        }).map_err(|tx_err: sled::transaction::TransactionError<()>| {
                            use sled::transaction::TransactionError::*;
                            match tx_err {
                                Storage(err) => err,
                                Abort(_) => {
                                    unreachable!("no code for abort transaction!");
                                },
                            }
                        })
                    };
                Box::new(f())
            });

        let sw_fut = self.sled.queue(op).await;
        let sw_res = sw_fut.await;
        let sw_res: &Box<dyn Any+Send> = sw_res.deref();
        let sw_res: &(dyn Any+Send) = sw_res.deref();

        let res: &sled::Result<Option<DNSEntry>> = sw_res.downcast_ref().expect("bug: return type mismatch in DNSDatabase::cache_get()");
        res.clone() // this clone is cheap due to DNSEntry internally uses Arc.
    }

    pub async fn cache_put(&self, query: &dyn DNSQuery, entry: &DNSEntry) -> sled::Result<()> {
        let key = query.encode();
        let value = entry.encode();

        let op = {
            let key = key.clone();
            SledOperation::new(move |db| {

                let f =
                    move || -> sled::Result<()> {
                        db
                        .open_tree(Self::NS_CACHE_V1)?
                        .transaction(move |tree| {
                            let key: &[u8] = key.as_ref();
                            if let Some(old_value) = tree.get(key)? {
                                let old_value: &[u8] = old_value.as_ref();
                                if old_value == value {
                                    return Ok(());
                                }
                            }

                            tree.insert(key, &value[..])?;
                            Ok(())
                        }).map_err(|tx_err: sled::transaction::TransactionError<()>| {
                            use sled::transaction::TransactionError::*;
                            match tx_err {
                                Storage(err) => err,
                                Abort(_) => {
                                    unreachable!("no code for abort transaction!");
                                },
                            }
                        })
                    };
                Box::new(f())
            })
        };
        let sw_fut = self.sled.queue(op).await;
        let sw_res = sw_fut.await;
        let sw_res: &Box<dyn Any+Send> = sw_res.deref();
        let sw_res: &(dyn Any+Send) = sw_res.deref();

        let res: &sled::Result<()> = sw_res.downcast_ref().expect("bug: return type mismatch in DNSDatabase::cache_put()");
        if res.is_ok() {
            self.negative_keys.invalidate(&key).await;
        }
        res.clone()
    }
}
