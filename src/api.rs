use crate::*;

use core::str::FromStr;
use http_types::{Mime, Response, StatusCode};
use smol::net::TcpListener;

#[derive(Debug)]
pub struct HitdnsAPI {
    listener: TcpListener,
    daemon: Arc<DNSDaemon>,
}

impl HitdnsAPI {
    pub async fn new(
        listen: SocketAddr,
        daemon: Arc<DNSDaemon>,
    ) -> anyhow::Result<Self> {
        if ! listen.ip().is_loopback() {
            anyhow::bail!("currently API does not support external access. you can specify a loopback IP such as 127.0.0.0/8 or [::1]");
        }

        let listener = TcpListener::bind(listen).await?;

        Ok(Self { listener, daemon })
    }

    fn mime_json() -> Mime {
        Mime::from_str("application/json; charset=utf-8").unwrap()
    }
    fn mime_txt() -> Mime {
        Mime::from_str("text/plain; charset=utf-8").unwrap()
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        loop {
            let (conn, peer) = self
                .listener
                .accept()
                .await
                .log_warn()?;

            let daemon = self.daemon.clone();
            smolscale2::spawn(
                async_h1b::accept_with_opts(
                    conn,
                    move |req| {
                        let daemon = daemon.clone();
                        async move {
                            log::info!("API accept HTTP request from {peer:?}");
                            let url = req.url();
                            match url.path().to_lowercase().as_str() {
                                "/snap" => {
                                    let mut res = Response::new(StatusCode::Ok);

                                    let json =
                                        match DatabaseSnapshot::export().await {
                                            Ok(ds) => {
                                                ds.to_json()
                                            },
                                            Err(err) => {
                                                res.set_status(StatusCode::InternalServerError);
                                                res.set_content_type(Self::mime_txt());
                                                res.set_body(format!("cannot take snapshot of database: {err:?}"));
                                                return res;
                                            }
                                        };

                                    res.set_content_type(Self::mime_json());
                                    res.set_body(format!("{json:#}"));

                                    res
                                },

                                "/metrics" => {
                                    let mut all_metrics = serde_json::Map::new();
                                    for ds in daemon.context.cache.resolvers.list.iter() {
                                        let upstream = ds.dns_upstream();
                                        let mut metrics = ds.dns_metrics().await.to_json();

                                        {
                                            let obj = metrics.as_object_mut().unwrap();
                                            obj.remove("upstream");
                                        }

                                        all_metrics.insert(upstream, metrics);
                                    }

                                    let all_metrics = serde_json::Value::Object(all_metrics);

                                    let mut res = Response::new(StatusCode::Ok);
                                    res.set_body(format!("{all_metrics:#}"));
                                    res.set_content_type(Self::mime_json());

                                    res
                                },

                                "/reload-cache" => {
                                    let mut res = Response::new(StatusCode::Ok);
                                    res.set_content_type(Self::mime_txt());

                                    let t = Instant::now();
                                    let ret = daemon.context.cache.load().await;
                                    let t = t.elapsed();

                                    match ret {
                                        Ok(_) => {
                                            res.set_body(format!("DNS Cache reloaded from disk db. (used time: {t:?})"));
                                        },
                                        Err(e) => {
                                            res.set_status(StatusCode::InternalServerError);
                                            res.set_body(format!("Failed to reload dns cache (used time: {t:?}): Error={e:?}"));
                                        }
                                    }

                                    res
                                },

                                #[cfg(feature = "rsinfo")]
                                "/info" => {
                                    let mut res = Response::new(StatusCode::Ok);
                                    res.set_content_type(Self::mime_json());
                                    res.set_body(
                                        format!("{:#}", rsinfo::ALL_INFO.to_json())
                                    );
                                    res
                                },

                                "/version" => {
                                    let mut res = Response::new(StatusCode::Ok);
                                    res.set_content_type(Self::mime_txt());
                                    if let Some(ver) = option_env!("CARGO_PKG_VERSION") {
                                        res.set_body(ver);
                                    } else {
                                        res.set_status(StatusCode::InternalServerError);
                                        res.set_body("N/A");
                                    }
                                    res
                                },

                                "/nonce" => {
                                    let mut res = Response::new(StatusCode::Ok);
                                    res.set_content_type(Self::mime_txt());
                                    res.set_body(HITDNS_NONCE.as_str());
                                    res
                                }

                                "/stats" => {
                                    let mut res = Response::new(StatusCode::Ok);
                                    match daemon.context.stats.to_json().await {
                                        Ok(json) => {
                                            res.set_content_type(Self::mime_json());
                                            res.set_body(format!("{json:#}"));
                                        },
                                        Err(e) => {
                                            res.set_status(StatusCode::InternalServerError);
                                            res.set_content_type(Self::mime_txt());
                                            res.set_body(format!("{e:?}"));
                                        }
                                    }

                                    res
                                },

                                _ => {
                                    let mut res = Response::new(StatusCode::NotFound);
                                    res.set_body(
"
List of avaliable commands:
GET /snap          ->  take a snapshot of database.
GET /metrics       ->  get all metrics for each resolvers.
GET /reload-cache  ->  reload DNS cache entries from disk database.
GET /version       ->  current version
GET /nonce         ->  a fixed nonce during between lifetime of this process.
GET /info          ->  get build info
GET /stats         ->  get DNS query analysis
"
                                    );
                                    res.set_content_type(Self::mime_txt());
                                    res
                                }
                            } // match
                        } // async move block
                    }, // move closure
                    async_h1b::ServerOptions::new()
                        .with_headers_timeout(Duration::from_secs(60))
                        .with_default_host("unspecified.invalid")
                ) // async_h1b::accept_with_opts
            ).detach(); // smolscale2::spawn
        }
    }
}
