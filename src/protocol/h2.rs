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

    pub fn global() -> &'static Self {
        static GLOBAL: Lazy<H2Client> = Lazy::new(H2Client::new);

        &*GLOBAL
    }

    pub async fn get_session(
        &self,
        info: &Arc<TlsConnectInfo>,
    ) -> std::io::Result<h2::client::SendRequest<Bytes>> {
        if let Some(sr) = self.h2_sessions.peek_with(info, |_, v| { v.clone() }) {
            return Ok(sr);
        }
        
        let tls_pool =
            if let Some(pool) = self.tls_pools.peek_with(info, |_, v| { v.clone() }) {
                pool
            } else {
                let pool = TlsStreamPool::new("http2-over-tls-over-tcp", info.clone());
                {
                    // start background task for running main loop of ConnPool
                    let pool = pool.clone();
                    asyncute::spawn(async move {
                        pool.run().await.expect("unexpected pool.run() exited!");
                    }).detach();
                }

                let _ = self.tls_pools.insert_async(info.clone(), pool.clone()).await;
                pool
            };

        let tls_conn = Compat::new(tls_pool.get_or_connect().await?);

        let (h2_sess, mut h2_conn) =
            h2::client::handshake(tls_conn).await
            .map_err(|e| {
                std::io::Error::other(
                    format!("unable to doing HTTP/2 handshake: {e:?}")
                )
            })?;

        // spawn background task for HTTP/2 connection
        {
            let ping_interval = Duration::from_secs(3);
            let info = info.clone();
            let this = self.clone();
            asyncute::spawn(async move {
                let ret =
                    if let Some(mut p) = h2_conn.ping_pong() {
                        h2_conn.or(async move {
                            loop {
                                match p.ping(h2::Ping::opaque()).await {
                                    Ok(_) => {
                                        async_io::Timer::after(ping_interval).await;
                                    },
                                    Err(e) => {
                                        break Err(e);
                                    }
                                }
                            }
                        }).await
                    } else {
                        h2_conn.await
                    };

                this.h2_sessions.remove_async(&info).await;

                ret.expect("unexpected h2 connection polling returns Error");
            }).detach();
        }

        let _ = self.h2_sessions.insert_async(info.clone(), h2_sess.clone()).await;
        Ok(h2_sess)
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

        let resolve_ret = cached_resolve((host.as_str(), port), false).await;
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

        let sni =
            if host.contains('[') {
                None
            } else if IpAddr::from_str(&host).is_ok() {
                None
            } else {
                Some(
                    rustls::pki_types::DnsName::try_from(host)
                    .map_err(|_| {
                        invalid_input("unable to convert URL host to TLS SNI!")
                    })?
                )
            };

        let mut tls_info;
        let mut last_err = invalid_input("unexpected empty of addrs");
        for addr in addrs.iter().copied() {
            tls_info = Arc::new(TlsConnectInfo {
                addr,
                sni: sni.clone(),
                config: self.tls_config.clone(),
            });
            match self.get_session(&tls_info).await {
                Ok(mut sess) => {
                    // send HTTP/2 request...

                    let body = req.body().clone();
                    let body_len = body.len();
                    match sess.send_request(req.map(core::mem::drop), body_len == 0) {
                        Ok((resp_fut, mut send_stream)) => {
                            if body_len > 0 {
                                if body_len <= (u32::MAX as usize) {
                                    send_stream.reserve_capacity(body_len);
                                }
                                send_stream.send_data(body, true).map_err(std::io::Error::other)?;
                            }
                            drop(send_stream);

                            let mut resp = resp_fut.await.map_err(std::io::Error::other)?;

                            // try to get the length of response body, and used to alloc buffer.
                            let mut resp_body_len: usize = 1024;
                            if let Some(v) = resp.headers().get("content-length") {
                                match v.to_str() {
                                    Ok(s) => {
                                        if let Ok(len) = usize::from_str(s) {
                                            resp_body_len = len;
                                        }
                                    },
                                    _ => {}
                                }
                            }

                            let mut resp_body = bytes::BytesMut::with_capacity(resp_body_len);
                            let recv_stream = resp.body_mut();
                            while let Some(ret) = recv_stream.data().await {
                                match ret {
                                    Ok(bytes) => {
                                        resp_body.extend(bytes);
                                    }
                                    Err(e) => {
                                        return Err(std::io::Error::other(e));
                                    }
                                }
                            }
                            return Ok(resp.map(move |_| { resp_body.freeze() }));
                        },
                        Err(e) => {
                            return Err(std::io::Error::other(e));
                        }
                    }
                },
                Err(e) => {
                    last_err = e;
                }
            }
        }

        Err(last_err)
    }
}
