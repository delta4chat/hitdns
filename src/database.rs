use crate::{
    *,
    query::*,
    entry::*,
    sled::*,
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

    pub async fn cache_get<Q: DNSQuery>(&self, query: Q) -> Box<sled::Result<Option<DNSEntry>>> {
        let key = query.to_bytes();
        self.sled
            .with(move |db| {
                let f = move || -> sled::Result<Option<DNSEntry>> {
                    db
                    .open_tree(b"hitdns_cache_v1")?
                    .transaction(|tree| {
                        if let Some(value) = tree.get(&key)? {
                            match DNSEntry::from_bytes(value) {
                                Ok(entry) => Ok(Some(entry)),
                                Err(err) => {
                                    tree.remove(&key);
                                    Err(err)
                                }
                            }
                        } else {
                            Ok(None)
                        }
                    }).into()
                };
                Box::new(f())
            }).into_boxed()?
            .await.downcast().expect("bug: return type mismatch in DNSDatabase::cache_get()")
    }
}
