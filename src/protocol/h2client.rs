//! Asynchronous minimized HTTP/2-only web client for privacy DNS requests.
//!
//! Goals:
//! * Full async API (non-tokio).
//! * No sync API.
//! * TLS 1.2 and TLS 1.3 support.
//! * TCP (with TLS) connection pool for reuse connections to minimize latency.
//! * Must without cookie support.
//! * Must without etag support.
//! * No Cache HTTP header support.

use crate::*;

pub struct H2ClientInner {
}

pub struct H2Client {
}
