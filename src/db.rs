use crate::*;

#[cfg(feature="sqlite")]
pub static HITDNS_SQLITE_FILENAME: Lazy<PathBuf> = Lazy::new(||{
    let mut buf = (*HITDNS_DIR).clone();
    buf.push("cache.sqlx.sqlite.db");
    buf
});

#[cfg(feature="sqlite")]
pub static HITDNS_SQLITE_POOL: Lazy<SqlitePool> = Lazy::new(||{
    let file = &*HITDNS_SQLITE_FILENAME;
    smol::block_on(async move {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .min_connections(1)
            .acquire_timeout(Duration::from_secs(10))

            .max_lifetime(None)
            .idle_timeout(None)

            .connect_with(
                SqliteConnectOptions::new()
                .filename(file)
                .create_if_missing(true)
                .read_only(false)
                .journal_mode(SqliteJournalMode::Wal)
                .locking_mode(SqliteLockingMode::Normal)
                .synchronous(SqliteSynchronous::Normal)
            ).await
            .expect("sqlx cannot connect to sqlite db");

        sqlx::query("CREATE TABLE IF NOT EXISTS hitdns_cache_v1 (query BLOB NOT NULL UNIQUE, entry BLOB NOT NULL) STRICT").execute(&pool).await.expect("sqlx cannot create table in opened sqlite db");
        pool
    })
});

#[cfg(feature="sled")]
pub static HITDNS_SLED_FILENAME: Lazy<PathBuf> = Lazy::new(||{
    let mut buf = (*HITDNS_DIR).clone();
    buf.push("hitdns.cache.sled.db");
    buf
});

#[cfg(feature="sled")]
pub static HITDNS_SLED_DB: Lazy<sled::Db> = Lazy::new(||{
    sled::Config::new()
        .path(&*HITDNS_SLED_FILENAME)
        .mode(sled::Mode::HighThroughput)
        .cache_capacity(1048576 * 8) // 8.0 MB
        .flush_every_ms(Some(1000))
        .temporary(false)
        .print_profile_on_drop(true)
        .use_compression(true)
        .compression_factor(22)
        .open().expect("cannot open sled db")
});

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseSnapshot {
    pub(crate) cache_v1:
        std::collections::HashMap<DNSQuery, Arc<DNSEntry>>,

    // other database tables may added in future
}

impl DatabaseSnapshot {
    fn init() -> Self {
        Self {
            cache_v1: Default::default(),
        }
    }

    /// export a snapshot (from a already exists database)
    pub async fn export() -> anyhow::Result<Self> {
        let dc = DNSCache::init();
        dc.load().await?;

        let mut this = Self::init();

        dc.memory.scan(
            |query, cache_entry|{
                let entry =
                    // Option< Arc<DNSEntry> >
                    cache_entry.entry.read_blocking()
                    .clone()

                    // Arc<DNSEntry>
                    .expect("unexpected got NULL value of DNS Entry from database!");

                this.cache_v1.insert(query.clone(), entry);
            }
        );

        Ok(this)
    }

    /// import to disk (from a taked snapshot)
    pub async fn import(&self) -> anyhow::Result<()> {
        for (query, entry) in self.cache_v1.iter() {
            let query: Vec<u8> =
                bincode::serialize(&query).log_error()?;
            let entry: Vec<u8> =
                bincode::serialize(&entry).log_error()?;

            #[cfg(feature="sqlite")]
            {

                sqlx::query("INSERT OR IGNORE INTO hitdns_cache_v1 VALUES (?1, ?2); UPDATE hitdns_cache_v1 SET entry = ?2 WHERE query = ?1")
                .bind(&query).bind(&entry)
                .execute(&*HITDNS_SQLITE_POOL)
                .await.log_warn()?;
            }

            #[cfg(feature="sled")]
            {
                let tree =
                    HITDNS_SLED_DB
                    .open_tree(b"hitdns_cache_v2")
                    .log_warn()?;

                tree.insert(query, entry).log_warn()?;
                tree.flush_async().await.log_error()?;
            }
        } // for in self.cache_v1.iter()

        Ok(())
    }

    pub fn to_json(&self) -> serde_json::Value {
        let mut cache_v1 = serde_json::Map::new();
        for (query, entry) in self.cache_v1.iter() {
            // DNSQuery implements core::fmt::Display
            let query: String = query.to_string();

            let mut entry: serde_json::Value =
                entry.to_json();

            {
                let obj = entry.as_object_mut().unwrap();
                obj.remove("query");
            }

            cache_v1.insert(query, entry);
        }

        serde_json::json!({
            "project": "hitdns",
            "info": "this is a database dump exported by hitdns. useful for debug, analysis, or import/migration to other databases.",
            "version": 2,
            "data": {
                "cache_v1": cache_v1,
            },
        })
    }

    pub fn from_json(json: &serde_json::Value)
        -> anyhow::Result<Self>
    {
        let map =
            match json.as_object() {
                Some(v) => v,
                None => {
                    anyhow::bail!("input JSON snapshot data invalid: type of top-level is not Object");
                }
            };

        let project =
            match map.get("project") {
                Some(v) => v,
                None => {
                    anyhow::bail!("input JSON snapshot data without '.project' field");
                }
            };

        if project.as_str() != Some("hitdns") {
            anyhow::bail!("input JSON snapshot data is not generated by 'hitdns --dump' command");
        }

        let version =
            match map.get("version") {
                Some(v) => v,
                None => {
                    anyhow::bail!("input JSON snapshot data without version number");
                }
            };

        if version != 2 {
            log::error!("Snapshot JSON version incorrectly. continue with best effect.");
        }

        let data =
            match map.get("data") {
                Some(v) => {
                    match v {
                        serde_json::Value::Object(o) => o,
                        _ => {
                            anyhow::bail!("input JSON snapshot data invalid: type of '.data' is not Object");
                        }
                    }
                },
                None => {
                    anyhow::bail!("input JSON snapshot data without '.data' field");
                }
            };

        let cache_v1 =
            match data.get("cache_v1") {
                Some(v) => {
                    match v {
                        serde_json::Value::Object(o) => o,
                        _ => {
                            anyhow::bail!("input JSON snapshot data invalid: type of '.data.cache_v1' is not Object");
                        }
                    }
                },
                None => {
                    anyhow::bail!("input JSON snapshot data without '.data.cache_v1' field");
                }
            };

        let mut this = Self::init();

        for (query, entry) in cache_v1.iter() {
            let mut entry = entry.clone();
            entry["query"] = query.as_str().into();
            let entry = DNSEntry::from_json(&entry)?;
            this.cache_v1.insert(
                entry.query.clone(),
                Arc::new(entry)
            );
        }

        Ok(this)
    }
}

