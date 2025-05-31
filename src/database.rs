use crate::{
    *,
    query::*,
    entry::*,
    sled::{self, SledRunner, SledOperation},
};

#[derive(Debug, Clone)]
pub struct DNSDatabase {
    sled: SledRunner,
}

impl DNSDatabase {
    pub fn open<P: AsRef<Path>>(path: P) -> sled::Result<Self> {
        let sled = SledRunner::open(path)?;
        Ok(Self {
            sled,
        })
    }

    pub async fn cache_get<Q: DNSQuery>(&self, query: Q) -> sled::Result<Option<DNSEntry>> {
        let key = query.to_bytes();

        let op =
            SledOperation::new(move |db| {
                let f =
                    move || -> sled::Result<Option<DNSEntry>> {
                        db
                        .open_tree(b"hitdns_cache_v1")?
                        .transaction(|tree| {
                            let key: &[u8] = key.as_ref();
                            if let Some(value) = tree.get(key)? {
                                let value: &[u8] = value.as_ref();
                                match DNSEntry::from_bytes(value) {
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

        let res: &sled::Result<Option<DNSEntry>> = sw_res.downcast_ref().expect("bug: return type mismatch in DNSDatabase::cache_get()");
        res.clone() // this clone is cheap due to DNSEntry internally uses Arc.
    }
}
