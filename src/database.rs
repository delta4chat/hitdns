use crate::{
    *,
    query::*,
    entry::*,
    util::*,
};

use async_sqlite::{
    Client as Sqlite,
    ClientBuilder as SqliteBuilder,
};
type SqliteResult<T> = Result<T, async_sqlite::Error>;

#[derive(Debug, Clone)]
pub struct DNSDatabase {
    sqlite: NonDebug<Sqlite>,
    negative_keys: MokaCache<DNSQuerySerialized, ()>,
}

macro_rules! _table_consts {
    ($($name:ident = $value:literal,)+) => {
        $(
            const $name: &'static str = $value;
        )+

        pub const TABLES: &'static [&'static str] = &[$($value,)+];
    }
}

impl DNSDatabase {
    _table_consts!(
        TABLE_CACHE = "hitdns_cache_v2",
        TABLE_STATS = "hitdns_stats_v2",
    );

    async fn sqlite_initial(&self) -> SqliteResult<()> {
        let table = Self::TABLE_CACHE;

        let mut sql = heapless::String::<512>::new();
        write!(sql,
        "
        PRAGMA journal_mode = WAL;
        CREATE TABLE IF NOT EXISTS {table} (
            query BLOB NOT NULL UNIQUE,
            entry BLOB NOT NULL
        ) STRICT;
        ").unwrap();
        self.sqlite.conn(move |conn| {
            dbg!(conn.execute_batch(dbg!(sql.as_str())))
        }).await
    }

    pub async fn open<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let this = Self {
            sqlite: NonDebug(SqliteBuilder::new().path(path).open().await.map_err(std::io::Error::other)?),
            negative_keys: {
                MokaCacheBuilder::default()
                .name("hitdns database negative keys cache")
                .max_capacity(65535)
                //.async_eviction_listener(|_query, _entry, cause| {})
                .time_to_idle(Duration::from_secs(30)) // 30 seconds for time-to-idle
                .time_to_live(Duration::from_secs(60)) // one minute for time-to-live
                .build_with_hasher(ahash::RandomState::new())
            },
        };
        this.sqlite_initial().await.map_err(std::io::Error::other)?;
        Ok(this)
    }

    /// try to open DNS Database automatically using DATA_DIR
    pub async fn auto_open() -> std::io::Result<Self> {
        let mut path = (&*config::DATA_DIR).clone();
        path.push("hitdns.db.sqlite3");
        Self::open(path).await
    }

    pub async fn cache_scan<Q: DNSQueryExt>(
        &self,
        mut yields: impl FnMut(Q, DNSEntry) -> Result<(), ()>+Send+'static,
    ) -> std::io::Result<()> {
        let table = Self::TABLE_CACHE;

        let mut sql = heapless::String::<64>::new();
        write!(sql, "SELECT * FROM {table}").unwrap();
        self.sqlite.conn(move |conn| {
            let mut stmt = conn.prepare(sql.as_str())?;
            let mut rows = stmt.query([])?;

            sql.clear();
            write!(sql, "DELETE FROM {table} WHERE query = ?").unwrap();

            while let Some(row) = dbg!(rows.next())? {
                let q = row.get_ref(0)?.as_blob()?;
                let ent = row.get_ref(1)?.as_blob()?;

                let query =
                    match Q::decode(q) {
                        Ok(v) => v,
                        Err(e) => {
                            log::warn!("deleting invalid query keys {q:?} / error: {e:?}");
                            dbg!(conn.execute(sql.as_str(), [q]));
                            continue;
                        }
                    };
                let entry =
                    match DNSEntry::decode(ent) {
                        Ok(v) => v,
                        Err(e) => {
                            log::warn!("unexpected invalid dns entry in db {q:?}={e:?} / error: {e:?}");
                            continue;
                        }
                    };

                if yields(query, entry).is_err() {
                    break;
                }
            }
            Ok(())
        }).await.map_err(std::io::Error::other)
    }

    pub async fn cache_get(&self, query: &dyn DNSQuery) -> std::io::Result<DNSEntry> {
        let key = query.encode();

        if self.negative_keys.get(&key).await.is_some() {
            return Err(std::io::Error::other("negative key hit"));
        }

        let ret = self._cache_key_get(key.clone()).await;
        if ! ret.is_ok() {
            self.negative_keys.insert(key.clone(), ()).await;
        }
        ret
    }

    async fn _cache_key_get(&self, key: DNSQuerySerialized) -> std::io::Result<DNSEntry> {
        let table = Self::TABLE_CACHE;

        let mut sql = heapless::String::<64>::new();
        write!(sql, "SELECT * FROM {table} WHERE query = ? LIMIT 1").unwrap();

        let ret = self.sqlite.conn(move |conn| {
            dbg!(conn.query_one(sql.as_str(), [key.as_slice()], |row| {
                dbg!(&row);
                let ent = row.get_ref(1)?.as_blob()?;

                Ok(DNSEntry::decode(ent))
            }))
        }).await.map_err(std::io::Error::other)?;

        ret
    }

    pub async fn cache_put(&self, query: &dyn DNSQuery, entry: &DNSEntry) -> std::io::Result<()> {
        let table = Self::TABLE_CACHE;

        let key = query.encode();
        let value = entry.encode();

        let mut sql = heapless::String::<128>::new();

        /* // old way
        write!(sql, "
        INSERT OR IGNORE INTO {table} VALUES (?1, ?2);
        UPDATE {table} SET entry = ?2 WHERE query = ?1;
        ").unwrap();
        */

        // new way
        write!(sql, "INSERT INTO {table} VALUES(?1, ?2) ON CONFLICT(query) DO UPDATE SET entry=?2").unwrap();

        let k = key.clone();
        self.sqlite.conn(move |conn| {
            dbg!(conn.execute(sql.as_str(), [k.as_slice(), value.as_slice()]))?;
            Ok(())
        }).await.map_err(std::io::Error::other)?;

        self.negative_keys.remove(&key).await;
        Ok(())
    }
}
