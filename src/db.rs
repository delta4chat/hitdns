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