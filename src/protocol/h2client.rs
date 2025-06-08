//! Asynchronous minimized HTTP/2-only web client for privacy DNS requests.
//!
//! Goals:
//! * Full async API (non-tokio).
//! * No sync API.
//! * TLS 1.2 and TLS 1.3 support.
//! * TCP (with TLS) connection pool for reuse connections to optimize latency.
//! * Must not include cookie support.
//! * Must not include etag support.
//! * No Cache HTTP header support.

use crate::*;

use futures_tls::{
};

use h2::{
    client::handshake,
}

use non_tokio::io::Compat;

pub struct H2Session {
}

pub struct H2ClientInner {
}

pub struct H2Client {
}
