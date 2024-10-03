// DNS over HTTP plaintext

use crate::*;

use core::str::FromStr;

use http_types::{Mime, Response, StatusCode, Method};
use smol::net::TcpListener;

use base64::prelude::*;

#[derive(Debug)]
pub struct DNSOverHTTP {
    listener: TcpListener,
    context: DNSDaemonContext,
}

impl DNSOverHTTP {
    pub async fn new(
        listen: SocketAddr,
        context: DNSDaemonContext,
    ) -> anyhow::Result<Self> {
        if ! listen.ip().is_loopback() {
            anyhow::bail!("currently DoH-plaintext does not support external access. you can specify a loopback IP such as 127.0.0.0/8 or [::1]");
        }

        let listener = TcpListener::bind(listen).await?;

        Ok(Self { listener, context })
    }

    fn mime_json() -> Mime {
        Mime::from_str("application/json; charset=utf-8").unwrap()
    }
    fn mime_txt() -> Mime {
        Mime::from_str("text/plain; charset=utf-8").unwrap()
    }
    fn mime_dns() -> Mime {
        Mime::from_str("application/dns-message").unwrap()
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        loop {
            let (conn, peer) = self
                .listener
                .accept()
                .await
                .log_warn()?;

            let context = self.context.clone();
            smolscale2::spawn(
                async_h1::accept(
                    conn,
                    move |mut req| {
                        let context = context.clone();
                        async move {
                            log::info!("DoH-plaintext: accept HTTP request from {peer:?}");
                            let url = req.url();
                            match url.path().to_lowercase().as_str() {
                                "/dns-query" => {
                                    let mut res = Response::new(StatusCode::Ok);
                                    res.insert_header("Access-Control-Allow-Origin", "*");

                                    match req.method() {
                                        Method::Post => {
                                            if let Some(ct) = req.header("Content-Type") {
                                                if ct.as_str().to_ascii_lowercase() != "application/dns-message" {
                                                    res.set_status(StatusCode::BadRequest);
                                                    res.set_content_type(Self::mime_txt());
                                                    res.set_body("Content-Type is wrong, it must be 'application/dns-message'");
                                                    return Ok(res);
                                                }
                                            } else {
                                                res.set_status(StatusCode::BadRequest);
                                                res.set_content_type(Self::mime_txt());
                                                res.set_body("does not specify Content-Type");
                                                return Ok(res);
                                            }

                                            if let Some(ct) = req.header("Accept") {
                                                if ct.as_str().to_ascii_lowercase() != "application/dns-message" {
                                                    res.set_status(StatusCode::BadRequest);
                                                    res.set_content_type(Self::mime_txt());
                                                    res.set_body("Accept is wrong, it must be 'application/dns-message'");
                                                    return Ok(res);
                                                }
                                            } else {
                                                res.set_status(StatusCode::BadRequest);
                                                res.set_content_type(Self::mime_txt());
                                                res.set_body("does not specify Accept");
                                                return Ok(res);
                                            }

                                            let dns_req =
                                                match req.body_bytes().await {
                                                    Ok(body) => {
                                                        match dns::Message::from_vec(&body) {
                                                            Ok(val) => val,
                                                            Err(err) => {
                                                                res.set_status(StatusCode::BadRequest);
                                                                res.set_content_type(Self::mime_txt());
                                                                res.set_body(format!("mal-formatted DNS wire format (RFC 1035): {err:?}"));
                                                                return Ok(res);
                                                            }
                                                        }
                                                    },
                                                    Err(err) => {
                                                        res.set_status(StatusCode::BadRequest);
                                                        res.set_content_type(Self::mime_txt());
                                                        res.set_body(format!("cannot read request body: {err:?}"));
                                                        return Ok(res);
                                                    }
                                                };

                                            let dns_query =
                                                match DNSQuery::try_from(dns_req.clone()) {
                                                    Ok(val) => val,
                                                    Err(err) => {
                                                        res.set_status(StatusCode::BadRequest);
                                                        res.set_content_type(Self::mime_txt());
                                                        res.set_body(format!("request dns wire is not a valid DNSQuery: {err:?}"));
                                                        return Ok(res);
                                                    }
                                                };

                                            let peer = req.peer_addr().unwrap_or("NA").replace("/", "%2F");
                                            let id = dns_req.id();

                                            let mut info = DNSQueryInfo {
                                                peer: format!("dohp://{peer}/?protocol=RFC8484&method=POST&id={id}"),
                                                query_msg: dns_req.clone(),
                                                query: dns_query,
                                                time: SystemTime::now(),
                                                delta: Default::default(),

                                                cache_status: None,
                                                used_time: None
                                            };

                                            match context.handle_query(&mut info).await.log_info() {
                                                Ok(dns_res) => {
                                                    res.set_content_type(Self::mime_dns());
                                                    res.set_body(
                                                        match dns_res.to_vec() {
                                                            Ok(val) => val,
                                                            Err(err) => {
                                                                res.set_status(StatusCode::InternalServerError);
                                                                res.set_content_type(Self::mime_txt());
                                                                res.set_body(format!("bug: DNSCache.query returns invalid data: {err:?}"));
                                                                return Ok(res);
                                                            }
                                                        }
                                                    );
                                                },
                                                Err(err) => {
                                                    res.set_status(StatusCode::InternalServerError);
                                                    res.set_content_type(Self::mime_txt());
                                                    res.set_body(format!("unable to handle DNS query: {err:?}"));
                                                }
                                            }
                                        },
                                        Method::Get => {
                                            if let Some(ct) = req.header("Accept") {
                                                if ct.as_str().to_ascii_lowercase() != "application/dns-message" {
                                                    res.set_status(StatusCode::BadRequest);
                                                    res.set_content_type(Self::mime_txt());
                                                    res.set_body("Accept is wrong, it must be 'application/dns-message'");
                                                    return Ok(res);
                                                }
                                            } else {
                                                res.set_status(StatusCode::BadRequest);
                                                res.set_content_type(Self::mime_txt());
                                                res.set_body("does not specify Accept");
                                                return Ok(res);
                                            }

                                            let mut maybe_dns: Option<String> = None;
                                            for (key, val) in url.query_pairs() {
                                                if key.into_owned().to_ascii_lowercase() == "dns" {
                                                    maybe_dns = Some(val.into_owned());
                                                    break;
                                                }
                                            }

                                            let dns =
                                                match maybe_dns {
                                                    Some(val) => val,
                                                    None => {
                                                        res.set_status(StatusCode::BadRequest);
                                                        res.set_content_type(Self::mime_txt());
                                                        res.set_body(format!("missing 'dns' in URL query string"));
                                                        return Ok(res);
                                                    }
                                                };

                                            let dns_req =
                                                match BASE64_URL_SAFE_NO_PAD.decode(dns) {
                                                    Ok(wire) => {
                                                        match dns::Message::from_vec(&wire) {
                                                            Ok(val) => val,
                                                            Err(err) => {
                                                                res.set_status(StatusCode::BadRequest);
                                                                res.set_content_type(Self::mime_txt());
                                                                res.set_body(format!("mal-formatted DNS wire format (RFC 1035): {err:?}"));
                                                                return Ok(res);
                                                            }
                                                        }
                                                    },
                                                    Err(err) => {
                                                        res.set_status(StatusCode::BadRequest);
                                                        res.set_content_type(Self::mime_txt());
                                                        res.set_body(format!("mal-formatted 'dns' base64url: {err:?}"));
                                                        return Ok(res);
                                                    }
                                                };

                                            let dns_query =
                                                match DNSQuery::try_from(dns_req.clone()) {
                                                    Ok(val) => val,
                                                    Err(err) => {
                                                        res.set_status(StatusCode::BadRequest);
                                                        res.set_content_type(Self::mime_txt());
                                                        res.set_body(format!("request dns wire is not a valid DNSQuery: {err:?}"));
                                                        return Ok(res);
                                                    }
                                                };

                                            let peer = req.peer_addr().unwrap_or("NA").replace("/", "%2F");
                                            let id = dns_req.id();

                                            let mut info = DNSQueryInfo {
                                                peer: format!("dohp://{peer}/?protocol=RFC8484&method=GET&id={id}"),
                                                query_msg: dns_req.clone(),
                                                query: dns_query,
                                                time: SystemTime::now(),
                                                delta: Default::default(),

                                                cache_status: None,
                                                used_time: None
                                            };

                                            match context.handle_query(&mut info).await.log_info() {
                                                Ok(dns_res) => {
                                                    res.set_content_type(Self::mime_dns());
                                                    res.set_body(
                                                        match dns_res.to_vec() {
                                                            Ok(val) => val,
                                                            Err(err) => {
                                                                res.set_status(StatusCode::InternalServerError);
                                                                res.set_content_type(Self::mime_txt());
                                                                res.set_body(format!("bug: DNSCache.query returns invalid data: {err:?}"));
                                                                return Ok(res);
                                                            }
                                                        }
                                                    );
                                                },
                                                Err(err) => {
                                                    res.set_status(StatusCode::InternalServerError);
                                                    res.set_content_type(Self::mime_txt());
                                                    res.set_body(format!("unable to handle DNS query: {err:?}"));
                                                }
                                            }
                                        },
                                        _ => {
                                            res.set_status(StatusCode::BadRequest);
                                            res.set_content_type(Self::mime_txt());
                                            res.set_body(format!("invalid HTTP request method, it must be POST or GET"));
                                        }
                                    }

                                    Ok(res)
                                },

                                "/resolve" => {
                                    let mut res = Response::new(StatusCode::Ok);
                                    res.insert_header("Access-Control-Allow-Origin", "*");

                                    if req.method() != Method::Get {
                                        res.set_status(StatusCode::BadRequest);
                                        res.set_content_type(Self::mime_txt());
                                        res.set_body(format!("invalid HTTP request method, it must be GET"));
                                        return Ok(res);
                                    }

                                    let mut maybe_name: Option<String> = None;
                                    let mut maybe_type: Option<String> = None;
                                    let mut maybe_ct: Option<String> = // content-type
                                        if let Some(ct) = req.header("Content-Type") {
                                            Some(ct.as_str().to_string())
                                        } else {
                                            None
                                        };

                                    let mut maybe_cd: Option<String> = None; // check disabled
                                    let mut maybe_do: Option<String> = None; // dnssec ok
                                                                             //
                                    for (key, val) in url.query_pairs() {
                                        match key.into_owned().to_ascii_lowercase().as_str() {
                                            "name" => {
                                                if maybe_name.is_none() {
                                                    maybe_name = Some(val.into_owned());
                                                }
                                            },
                                            "type" => {
                                                if maybe_type.is_none() {
                                                    maybe_type = Some(val.into_owned());
                                                }
                                            },
                                            "ct" => {
                                                if maybe_ct.is_none() {
                                                    maybe_ct = Some(val.into_owned());
                                                }
                                            },
                                            "cd" => {
                                                if maybe_cd.is_none() {
                                                    maybe_cd = Some(val.into_owned());
                                                }
                                            },
                                            "do" => {
                                                if maybe_do.is_none() {
                                                    maybe_do = Some(val.into_owned());
                                                }
                                            },
                                            _ => {}
                                        }
                                    }

                                    if maybe_name.is_none() {
                                        res.set_status(StatusCode::BadRequest);
                                        res.set_content_type(Self::mime_txt());
                                        res.set_body(format!("missing 'name' in URL query string"));
                                        return Ok(res);
                                    }
                                    let name: String = {
                                        let mut n = maybe_name.unwrap();
                                        if ! n.ends_with(".") {
                                            n.push('.');
                                        }
                                        n
                                    };

                                    let rdtype: u16 =
                                        if let Some(ref t) = maybe_type {
                                            let maybe_ti: Option<u16> = t.parse().ok();
                                            if let Some(ti) = maybe_ti {
                                                ti
                                            } else {
                                                dns::RdType::from_str(t).unwrap_or(dns::RdType::A).into()
                                            }
                                        } else {
                                            dns::RdType::A.into()
                                        };

                                    let ct: Mime =
                                        if let Some(ct) = maybe_ct {
                                            match ct.to_ascii_lowercase().as_str() {
                                                "application/dns-message" => {
                                                    Self::mime_dns()
                                                },
                                                "application/json" | "application/x-javascript" => {
                                                    Self::mime_json()
                                                },
                                                _ => {
                                                    Self::mime_json()
                                                }
                                            }
                                        } else {
                                            Self::mime_json()
                                        };

                                    let cd: bool =
                                        if let Some(c) = maybe_cd {
                                            match c.to_ascii_lowercase().as_str() {
                                                "1" | "true" => true,
                                                "0" | "false" => false,

                                                c => { ! c.is_empty() }
                                            }
                                        } else {
                                            false
                                        };


                                    let dnssec_ok: bool =
                                        if let Some(d) = maybe_do {
                                            match d.to_ascii_lowercase().as_str() {
                                                "1" | "true" => true,
                                                "0" | "false" => false,

                                                d => { ! d.is_empty() }
                                            }
                                        } else {
                                            false
                                        };

                                    let dns_query =
                                        DNSQuery {
                                            name,
                                            rdclass: dns::RdClass::IN.into(),
                                            rdtype,
                                        };

                                    let mut dns_req: dns::Message =
                                        match (&dns_query).try_into() {
                                            Ok(val) => val,
                                            Err(err) => {
                                                res.set_status(StatusCode::InternalServerError);
                                                res.set_content_type(Self::mime_txt());
                                                res.set_body(format!("unable to build dns::Message from DNSQuery: {err:?}"));
                                                return Ok(res);
                                            }
                                        };

                                    let id = dns_req.id();

                                    let mut info = DNSQueryInfo {
                                        peer: format!("dohp://{peer}/?protocol=Google&method=GET&id={id}"),
                                        query_msg: dns_req.clone(),
                                        query: dns_query,
                                        time: SystemTime::now(),
                                        delta: Default::default(),

                                        cache_status: None,
                                        used_time: None
                                    };

                                    let dns_res = match context.handle_query(&mut info).await.log_info() {
                                        Ok(dr) => dr,
                                        Err(err) => {
                                            res.set_status(StatusCode::InternalServerError);
                                            res.set_content_type(Self::mime_txt());
                                            res.set_body(format!("unable to handle DNS query: {err:?}"));
                                            return Ok(res);
                                        }
                                    };

                                    if ct == Self::mime_dns() {
                                        res.set_content_type(Self::mime_dns());
                                        res.set_body(
                                            match dns_res.to_vec() {
                                                Ok(val) => val,
                                                Err(err) => {
                                                    res.set_status(StatusCode::InternalServerError);
                                                    res.set_content_type(Self::mime_txt());
                                                    res.set_body(format!("bug: DNSCache.query returns invalid data: {err:?}"));
                                                    return Ok(res);
                                                }
                                            }
                                        );
                                    } else {
                                        todo!("json output");
                                    }

                                    Ok(res)
                                },

                                _ => {
                                    let mut res = Response::new(StatusCode::NotFound);
                                    res.insert_header("Access-Control-Allow-Origin", "*");

                                    res.set_content_type(Self::mime_txt());
                                    res.set_body(
"
List of avaliable query methods:

POST /dns-query                            -> query DNS using RFC 8484 Post: https://tools.ietf.org/html/rfc8484#page-6
GET  /dns-query?dns=[base64url]            -> query DNS using RFC 8484 Get: https://tools.ietf.org/html/rfc8484#section-4.1.1

GET  /resolve?name=[domain]&type=[rdtype]  -> query DNS using Google's JSON API: https://developers.google.com/speed/public-dns/docs/doh/json

"
                                    );
                                    Ok(res)
                                }
                            } // match
                        } // async move block
                    } // move closure
                ) // async_h1::accept
            ).detach(); // smolscale2::spawn
        }
    }
}
