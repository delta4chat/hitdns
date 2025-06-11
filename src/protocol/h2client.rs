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

use crate::{
    *,
    protocol::tls::{
        self,
        TlsConnectInfo,
        TlsStreamPool,
    },
};

use h2::{
    client::handshake,
};

use non_tokio::io::Compat;

#[derive(Debug)]
pub struct H2ClientInner {
    tls_pools: scc::HashIndex<Arc<TlsConnectInfo>, TlsStreamPool>,
    h2_sessions: scc::HashIndex<Arc<TlsConnectInfo>, h2::client::SendRequest<Bytes>>,
}

#[derive(Debug, Clone)]
pub struct H2Client {
    inner: Arc<H2ClientInner>,
    tls_config: Arc<rustls::ClientConfig>,
}

impl Deref for H2Client {
    type Target = H2ClientInner;

    fn deref<'a>(&'a self) -> &'a H2ClientInner {
        self.inner.as_ref()
    }
}

impl H2Client {
    pub fn new() -> Self {
        Self {
            inner:
                Arc::new(H2ClientInner {
                    tls_pools: Default::default(),
                    h2_sessions: Default::default(),
                }),
            tls_config: Arc::new(tls::tls_config(b"h2")),
        }
    }

    pub async fn get_session(
        &self,
        info: &Arc<TlsConnectInfo>,
    ) -> std::io::Result<h2::client::SendRequest<Bytes>> {
        let g = scc::ebr::Guard::new();
        if let Some(sr) = self.h2_sessions.peek(info, &g) {
            Ok(sr.clone())
        } else {
            let tls_pool = TlsStreamPool::new("http2-over-tls-over-tcp", info.clone());
            {
                let tls_pool = tls_pool.clone();
                asyncute::spawn(async move {
                    tls_pool.run().await.unwrap();
                }).detach();
            }

            let _ =
                self.tls_pools.insert_async(
                    info.clone(),
                    tls_pool.clone()
                ).await;

            let tls_conn =
                Compat::new(
                    tls_pool.get_or_connect().await?
                );

            let (h2_send_request, h2_conn) =
                h2::client::handshake(tls_conn).await
                .map_err(|e| {
                    std::io::Error::other(
                        format!("unable to doing HTTP/2 handshake: {e:?}")
                    )
                })?;

            todo!()
        }
    }

    pub async fn request(&self, req: http::Request<Bytes>) -> std::io::Result<http::Response<Bytes>> {
        match req.version() {
            http::Version::HTTP_2 => {},
            _ => {
                return Err(invalid_input("unexpected http::Request is not HTTP/2 version!"));
            }
        }

        let uri = req.uri();
        match uri.scheme_str() {
            Some(scheme) => {
                if ! scheme.eq_ignore_ascii_case("https") {
                    return Err(invalid_input("unexpected http::Request scheme is not https!"));
                }
            },
            _ => {
                return Err(invalid_input("unexpected http::Request has no scheme!"));
            }
        }

        let host =
            match uri.host() {
                Some(v) => v.to_string(),
                _ => {
                    return Err(invalid_input("unexpected http::Request has no host!"));
                }
            };
        let port = uri.port_u16().unwrap_or(443);

        let resolve_ret = cached_resolve((host, port)).await;
        let addrs =
            match resolve_ret.deref().as_ref() {
                Ok(addrs) => {
                    if addrs.is_empty() {
                        return Err(
                            std::io::Error::new(
                                std::io::ErrorKind::HostUnreachable,
                                "no IP addresses resolved to provided domain name!",
                            )
                        );
                    }
                    addrs
                },
                Err(e) => {
                    return Err(
                        std::io::Error::new(
                            std::io::ErrorKind::HostUnreachable,
                            format!("{:?}", e)
                        )
                    );
                }
            };
        for addr in addrs.iter() {
            //self.get_session(addr);
        }
        
        todo!()
    }
}
