use sqlx::{
};

pub struct DNSDatabase {
    sqlite3: SqlitePool,
}
