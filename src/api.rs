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
            let (conn, peer) = self.listener.accept().await.log_warn()?;

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

                                        let mut metrics = ds.dns_metrics().to_json();
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
                                    let ret = daemon.context.cache.load_all().await;
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

                                "/reload-hosts" => {
                                    let mut res = Response::new(StatusCode::Ok);
                                    res.set_content_type(Self::mime_txt());

                                    let result;
                                    let elapsed;
                                    let mut backup_restore_defer;

                                    if let Some(ref hosts_filename) = daemon.context.opt.hosts {
                                        let started = Instant::now();

                                        let backup = HOSTS.take();
                                        backup_restore_defer = Defer::new(move || {
                                            HOSTS.replace(&backup);
                                        });
                                        result = HOSTS.load(hosts_filename).await;

                                        elapsed = started.elapsed();
                                    } else {
                                        res.set_status(StatusCode::InternalServerError);
                                        res.set_body("No hosts file path provided by command line or TOML config.");
                                        return res;
                                    }

                                    match result {
                                        Ok(_) => {
                                            backup_restore_defer.cancel();
                                            res.set_body(format!("Hosts reloaded from disk. (used time: {elapsed:?})"));
                                        },
                                        Err(err) => {
                                            res.set_status(StatusCode::InternalServerError);
                                            res.set_body(format!("Failed to reload Hosts (used time: {elapsed:?}): Error={err:?}"));
                                        }
                                    }

                                    res
                                },

                                "/expire-records" => {
                                    let mut res = Response::new(StatusCode::Ok);
                                    res.set_content_type(Self::mime_txt());

                                    let mut maybe_domain = None;
                                    let mut maybe_rdclass = None;
                                    let mut maybe_rdtype = None;
                                    for (key, val) in url.query_pairs() {
                                        match key.into_owned().to_ascii_lowercase().as_str() {
                                            "domain" => {
                                                if maybe_domain.is_none() {
                                                    maybe_domain = Some(val.into_owned());
                                                }
                                            },
                                            "rdclass" => {
                                                if maybe_rdclass.is_none() {
                                                    maybe_rdclass = Some(val.into_owned());
                                                }
                                            }
                                            "rdtype" => {
                                                if maybe_rdtype.is_none() {
                                                    maybe_rdtype = Some(val.into_owned());
                                                }
                                            }
                                            _ => {}
                                        }
                                    }

                                    let domain =
                                        if let Some(d) = maybe_domain {
                                            d
                                        } else {
                                            res.set_status(StatusCode::BadRequest);
                                            res.set_body("missing 'domain' in URL query string");
                                            return res;
                                        };

                                    let maybe_rdclass =
                                        if let Some(rc) = maybe_rdclass {
                                            let c: u16 =
                                                match rc.parse() {
                                                    Ok(val) => val,
                                                    Err(err) => {
                                                        res.set_status(StatusCode::BadRequest);
                                                        res.set_body(format!("unable parse 'rdclass' as unsigned 16-bit integer: {err:?}"));
                                                        return res;
                                                    }
                                                };
                                            Some(c)
                                        } else {
                                            None
                                        };

                                    let maybe_rdtype =
                                        if let Some(rt) = maybe_rdtype {
                                            let t: u16 =
                                                match rt.parse() {
                                                    Ok(val) => val,
                                                    Err(err) => {
                                                        res.set_status(StatusCode::BadRequest);
                                                        res.set_body(format!("unable parse 'rdtype' as unsigned 16-bit integer: {err:?}"));
                                                        return res;
                                                    }
                                                };
                                            Some(t)
                                        } else {
                                            None
                                        };

                                    let count = daemon.context.cache.expire(domain, maybe_rdclass, maybe_rdtype).await;
                                    res.set_body(format!("successfully expire {count} records"));

                                    res
                                },

                                "/info" => {
                                    let mut res = Response::new(StatusCode::Ok);
                                    res.set_content_type(Self::mime_json());
                                    res.set_body(format!("{:#}", &*HITDNS_INFO));
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
                                },

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

                                "/uptime" => {
                                    let uptime = STARTED.elapsed();

                                    let mut res = Response::new(StatusCode::Ok);
                                    res.set_content_type(Self::mime_txt());
                                    res.set_body(format!("{uptime:?}"));

                                    res
                                },

                                _ => {
                                    if daemon.context.opt.api_with_dohp {
                                        let dohp_res = DNSOverHTTP::handle_request(daemon.context.clone(), peer, req).await;
                                        if dohp_res.status() != StatusCode::NotFound {
                                            return dohp_res;
                                        }
                                    }

                                    let mut res = Response::new(StatusCode::NotFound);
                                    res.set_body(
"
# List of available commands:

GET /info            ->  get build info.
GET /version         ->  current version.

GET /uptime          ->  the uptime of this process.
GET /nonce           ->  a fixed nonce during between lifetime of this process.

GET /snap            ->  take a snapshot of database.
GET /metrics         ->  get all metrics for each resolvers.
GET /stats           ->  get DNS query analysis.

GET /reload-cache    ->  reload DNS cache entries from disk database.
GET /reload-hosts    ->  reload Hosts file from disk.

GET /expire-records  ->  mark the cached results for a domain (and optional rdclass/rdtype) expires immediately.

# for test or convenience, if enabled by server config (disabled by default), you can use this API as DOH-plaintext
# WARNING: leaking your API interface to publicly can causes security issues!
# NOTE: for most common cases, it is recommended to use standalone port for DOH-plaintext

(optional) GET /dns-query?dns={base64url}
(optional) POST /dns-query
(optional) GET /resolve?name={domain}&type={rdtype}
"
                                    );
                                    res.set_content_type(Self::mime_txt());
                                    res
                                }
                            } // match
                        } // async move block
                    }, // move closure
                    async_h1b::ServerOptions::new()
                        //.with_headers_timeout(Duration::from_secs(60))
                        .with_default_host("unspecified.invalid")
                ) // async_h1b::accept_with_opts
            ).detach(); // smolscale2::spawn
        }
    }
}
