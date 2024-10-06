// DNS over HTTP plaintext

#![allow(deprecated)]

use crate::*;

use core::str::FromStr;

use http_types::{Mime, Response, StatusCode, Method};
use smol::net::TcpListener;

use data_encoding::{
    BASE64, BASE64URL_NOPAD, BASE32_NOPAD,
    HEXUPPER as HEX_UPPER,
};

use bytes::Bytes;

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
                async_h1b::accept_with_opts(
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
                                                    return res;
                                                }
                                            } else {
                                                res.set_status(StatusCode::BadRequest);
                                                res.set_content_type(Self::mime_txt());
                                                res.set_body("does not specify Content-Type");
                                                return res;
                                            }

                                            if let Some(ct) = req.header("Accept") {
                                                if ct.as_str().to_ascii_lowercase() != "application/dns-message" {
                                                    res.set_status(StatusCode::BadRequest);
                                                    res.set_content_type(Self::mime_txt());
                                                    res.set_body("Accept is wrong, it must be 'application/dns-message'");
                                                    return res;
                                                }
                                            } else {
                                                res.set_status(StatusCode::BadRequest);
                                                res.set_content_type(Self::mime_txt());
                                                res.set_body("does not specify Accept");
                                                return res;
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
                                                                return res;
                                                            }
                                                        }
                                                    },
                                                    Err(err) => {
                                                        res.set_status(StatusCode::BadRequest);
                                                        res.set_content_type(Self::mime_txt());
                                                        res.set_body(format!("cannot read request body: {err:?}"));
                                                        return res;
                                                    }
                                                };

                                            let dns_query =
                                                match DNSQuery::try_from(dns_req.clone()) {
                                                    Ok(val) => val,
                                                    Err(err) => {
                                                        res.set_status(StatusCode::BadRequest);
                                                        res.set_content_type(Self::mime_txt());
                                                        res.set_body(format!("request dns wire is not a valid DNSQuery: {err:?}"));
                                                        return res;
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
                                                                return res;
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
                                                    return res;
                                                }
                                            } else {
                                                res.set_status(StatusCode::BadRequest);
                                                res.set_content_type(Self::mime_txt());
                                                res.set_body("does not specify Accept");
                                                return res;
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
                                                        return res;
                                                    }
                                                };

                                            let dns_req =
                                                match BASE64URL_NOPAD.decode(dns.as_bytes()) {
                                                    Ok(wire) => {
                                                        match dns::Message::from_vec(&wire) {
                                                            Ok(val) => val,
                                                            Err(err) => {
                                                                res.set_status(StatusCode::BadRequest);
                                                                res.set_content_type(Self::mime_txt());
                                                                res.set_body(format!("mal-formatted DNS wire format (RFC 1035): {err:?}"));
                                                                return res;
                                                            }
                                                        }
                                                    },
                                                    Err(err) => {
                                                        res.set_status(StatusCode::BadRequest);
                                                        res.set_content_type(Self::mime_txt());
                                                        res.set_body(format!("mal-formatted 'dns' base64url: {err:?}"));
                                                        return res;
                                                    }
                                                };

                                            let dns_query =
                                                match DNSQuery::try_from(dns_req.clone()) {
                                                    Ok(val) => val,
                                                    Err(err) => {
                                                        res.set_status(StatusCode::BadRequest);
                                                        res.set_content_type(Self::mime_txt());
                                                        res.set_body(format!("request dns wire is not a valid DNSQuery: {err:?}"));
                                                        return res;
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
                                                                return res;
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

                                    res
                                },

                                "/resolve" => {
                                    let mut res = Response::new(StatusCode::Ok);
                                    res.insert_header("Access-Control-Allow-Origin", "*");

                                    if req.method() != Method::Get {
                                        res.set_status(StatusCode::BadRequest);
                                        res.set_content_type(Self::mime_txt());
                                        res.set_body(format!("invalid HTTP request method, it must be GET"));
                                        return res;
                                    }

                                    let mut maybe_version: Option<String> = None;

                                    let mut maybe_name: Option<String> = None;
                                    let mut maybe_class: Option<String> = None;
                                    let mut maybe_type: Option<String> = None;

                                    let mut maybe_ct: Option<String> = // content-type
                                        if let Some(ct) = req.header("Content-Type") {
                                            Some(ct.as_str().to_string())
                                        } else {
                                            None
                                        };

                                    let mut maybe_cd: Option<String> = None; // check disabled
                                    let mut maybe_do: Option<String> = None; // dnssec ok

                                    for (key, val) in url.query_pairs() {
                                        match key.into_owned().to_ascii_lowercase().as_str() {
                                            "version" => {
                                                if maybe_version.is_none() {
                                                    maybe_version = Some(val.into_owned())
                                                }
                                            },
                                            "name" => {
                                                if maybe_name.is_none() {
                                                    maybe_name = Some(val.into_owned());
                                                }
                                            },
                                            "type" => {
                                                if maybe_type.is_none() {
                                                    let val = val.into_owned();
                                                    if ! val.is_empty() {
                                                        maybe_type = Some(val);
                                                    }
                                                }
                                            },
                                            "class" => {
                                                if maybe_class.is_none() {
                                                    let val = val.into_owned();
                                                    if ! val.is_empty() {
                                                        maybe_class = Some(val);
                                                    }
                                                }
                                            },
                                            "ct" => {
                                                if maybe_ct.is_none() {
                                                    let val = val.into_owned();
                                                    if ! val.is_empty() {
                                                        maybe_ct = Some(val);
                                                    }
                                                }
                                            },
                                            "cd" => {
                                                if maybe_cd.is_none() {
                                                    let val = val.into_owned();
                                                    if ! val.is_empty() {
                                                        maybe_cd = Some(val);
                                                    }
                                                }
                                            },
                                            "do" => {
                                                if maybe_do.is_none() {
                                                    let val = val.into_owned();
                                                    if ! val.is_empty() {
                                                        maybe_do = Some(val);
                                                    }
                                                }
                                            },
                                            _ => {}
                                        }
                                    }

                                    // version=0: latest version (currently v4)
                                    // version=1: original format from Google, defaults to this if not specified or it is not a unsigned 16-bit integer.
                                    // version=2: hitdns modified version, such as TXT array
                                    // version=3: for each TXT record, use bytes escape instead of String::from_utf8_lossy
                                    // 
                                    // other version is reserved for future use.
                                    //
                                    // NOTE: because ?class= does not breaking compatibility, so it will be accepted by v1 format
                                    let version = {
                                        let mut ver: u16 = maybe_version.unwrap_or(String::new()).parse().unwrap_or(1);
                                        if ver == 0 {
                                            ver = 4;
                                        }
                                        ver
                                    };
                                    

                                    match version {
                                        1 | 2 | 3 | 4 => {},
                                        _ => {
                                            res.set_status(StatusCode::BadRequest);
                                            res.set_content_type(Self::mime_txt());
                                            res.set_body(format!("unknown version: it should be 1, 2, 3, or 4"));
                                            return res;
                                        }
                                    }

                                    if maybe_name.is_none() {
                                        res.set_status(StatusCode::BadRequest);
                                        res.set_content_type(Self::mime_txt());
                                        res.set_body(format!("missing 'name' in URL query string"));
                                        return res;
                                    }
                                    let name: String = {
                                        let mut n = maybe_name.unwrap();
                                        if ! n.ends_with(".") {
                                            n.push('.');
                                        }
                                        n
                                    };

                                    let rdclass: u16 =
                                        if let Some(ref c) = maybe_class {
                                            let maybe_ci: Option<u16> = c.parse().ok();
                                            if let Some(ci) = maybe_ci {
                                                ci
                                            } else {
                                                if let Ok(rc) = dns::RdClass::from_str(c.to_ascii_uppercase().as_str()) {
                                                    rc.into()
                                                } else {
                                                    res.set_status(StatusCode::BadRequest);
                                                    res.set_content_type(Self::mime_txt());
                                                    res.set_body(format!("invalid value of 'class': if you need to specifiy custom rdclass, please use unsigned 16-bit integer"));
                                                    return res;
                                                }
                                            }
                                        } else {
                                            dns::RdClass::IN.into()
                                        };

                                    let rdtype: u16 =
                                        if let Some(ref t) = maybe_type {
                                            let maybe_ti: Option<u16> = t.parse().ok();
                                            if let Some(ti) = maybe_ti {
                                                ti
                                            } else {
                                                if let Ok(rt) = dns::RdType::from_str(t.to_ascii_uppercase().as_str()) {
                                                    rt.into()
                                                } else {
                                                    res.set_status(StatusCode::BadRequest);
                                                    res.set_content_type(Self::mime_txt());
                                                    res.set_body(format!("invalid value of 'type': if you need to specifiy custom rdtype, please use unsigned 16-bit integer"));
                                                    return res;
                                                }
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
                                            name: name.clone(),
                                            rdclass,
                                            rdtype,
                                        };

                                    let mut dns_req: dns::Message =
                                        match (&dns_query).try_into() {
                                            Ok(val) => val,
                                            Err(err) => {
                                                res.set_status(StatusCode::InternalServerError);
                                                res.set_content_type(Self::mime_txt());
                                                res.set_body(format!("unable to build dns::Message from DNSQuery: {err:?}"));
                                                return res;
                                            }
                                        };

                                    dns_req.set_authentic_data(dnssec_ok);
                                    dns_req.set_checking_disabled(cd);

                                    let id = dns_req.id();

                                    let mut info = DNSQueryInfo {
                                        peer: format!(
                                                  "dohp://{peer}/?protocol={}&method=GET&id={id}",
                                                  match version {
                                                      1 => "Google",
                                                      2 => "GoogleModified",
                                                      3 => "GoogleModified-BytesEscape",
                                                      4 => "GoogleModified-BytesEscape-StructuralData",
                                                      _ => { unreachable!() }
                                                  }
                                              ),
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
                                            return res;
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
                                                    return res;
                                                }
                                            }
                                        );
                                    } else {
                                        let status: u16 = dns_res.response_code().into();

                                        let mut json = serde_json::json!({
                                            "Version": version,
                                            "Status": status,

                                            "TC": dns_res.truncated(),
                                            "RD": dns_res.recursion_desired(),
                                            "RA": dns_res.recursion_available(),
                                            "AD": dns_res.authentic_data(),
                                            "CD": dns_res.checking_disabled(),

                                            "Question": [
                                                {
                                                    "name": name,
                                                    "class": rdclass,
                                                    "type": rdtype,
                                                }
                                            ],

                                            "Answer": [],
                                            "Authority": [],
                                            "Additional": [],
                                        });

                                        // Answer Section
                                        let answers = json.get_mut("Answer").unwrap().as_array_mut().unwrap();
                                        if let Err(err) = records_iter_helper(version, dns_res.answers().iter(), answers) {
                                            res.set_status(StatusCode::InternalServerError);
                                            res.set_content_type(Self::mime_txt());
                                            res.set_body(format!("{err:?}"));
                                            return res;
                                        }

                                        // Authority (aka Name Servers) Section
                                        let authority = json.get_mut("Authority").unwrap().as_array_mut().unwrap();
                                        if let Err(err) = records_iter_helper(version, dns_res.name_servers().iter(), authority) {
                                            res.set_status(StatusCode::InternalServerError);
                                            res.set_content_type(Self::mime_txt());
                                            res.set_body(format!("{err:?}"));
                                            return res;
                                        }

                                        // Additional Section
                                        let authority = json.get_mut("Additional").unwrap().as_array_mut().unwrap();
                                        if let Err(err) = records_iter_helper(version, dns_res.additionals().iter(), authority) {
                                            res.set_status(StatusCode::InternalServerError);
                                            res.set_content_type(Self::mime_txt());
                                            res.set_body(format!("{err:?}"));
                                            return res;
                                        }

                                        res.set_content_type(Self::mime_json());
                                        res.set_body(format!("{json:#}"));
                                    }

                                    res
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

GET  /resolve?name=[domain]&type=[rdtype]  -> query DNS using JSON API (modified from Google's JSON API): https://developers.google.com/speed/public-dns/docs/doh/json

"
                                    );
                                    res
                                }
                            } // match
                        } // async move block
                    }, // move closure
                    async_h1b::ServerOptions::new()
                        //.with_headers_timeout(Duration::from_secs(10))
                        .with_default_host("unspecified.invalid")
                ) // async_h1b::accept_with_opts
            ).detach(); // smolscale2::spawn
        }
    }
}

fn records_iter_helper<'a>(
    version: u16,
    input: impl Iterator<Item=&'a dns::Record>,
    output: &mut Vec<serde_json::Value>
) -> anyhow::Result<()> {
    for rr in input {
        let name = {
            let mut n = rr.name().to_ascii();
            if ! n.ends_with('.') {
                n.push('.');
            }
            n
        };
        let rdtype = rr.record_type();
        let ttl = rr.ttl();

        use dns::RdType::*;
        use dns::RecordData;

        let rdata =
            if let Some(rd) = rr.data() {
                rd.clone().into_rdata()
            } else {
                anyhow::bail!("unexpected upstream DNS resolver respond Record without RDATA: {rr:?}");
            };

        let data;
        match rdtype {
            A | AAAA => {
                let ip_str: String =
                    if rdata.is_a() {
                        if let Some(a) = rdata.as_a() {
                            a.0.to_string()
                        } else {
                            anyhow::bail!("unexpected upstream DNS resolver respond A record with non-A rdata");
                        }
                    } else if rdata.is_aaaa() {
                        if let Some(aaaa) = rdata.as_aaaa() {
                            aaaa.0.to_string()
                        } else {
                            anyhow::bail!("unexpected upstream DNS resolver respond AAAA record with non-AAAA rdata");
                        }
                    } else {
                        anyhow::bail!("Bug: matched A or AAAA but hickory-proto does not provide A or AAAA rdata: {rdata:?}");
                    };

                data = serde_json::Value::String(ip_str);
            },
            TXT => {
                let txt_data;

                if let Some(txt) = rdata.as_txt() {
                    match version {
                        // modified: returns array of TXT data, instead of use "a""b"
                        4 | 3 | 2 => {
                            let mut txt_strings = vec![];
                            for td in txt.iter() {
                                let t =
                                    match version {
                                        4 | 3 => { // escaped bytes
                                            let t = format!("{:?}", Bytes::from(td.to_vec()));

                                            // remove b" and "
                                            let mut t: String = t.chars().skip(2).collect();
                                            t.pop();

                                            t
                                        },
                                        2 => { // UTF-8 lossy
                                            String::from_utf8_lossy(td).into_owned()
                                        },
                                        _ => { unreachable!(); }
                                    };

                                txt_strings.push(
                                    serde_json::Value::String(t)
                                );
                            }

                            txt_data = serde_json::Value::Array(txt_strings);
                        },

                        // original version
                        1 => {
                            let mut txt_str = String::new();

                            let txt = txt.txt_data();
                            for td in txt.iter() {
                                let td = String::from_utf8_lossy(td).into_owned();
                                if txt.len() == 1 {
                                    txt_str = td;
                                } else {
                                    txt_str.extend(
                                        format!("{td:?}").chars()
                                    );
                                }
                            }

                            txt_data = serde_json::Value::String(txt_str);
                        },

                        _ => {
                            unreachable!();
                        }
                    }

                    data = txt_data;
                } else {
                    anyhow::bail!("unexpected upstream DNS resolver respond TXT record without text: {rr:?}");
                }
            },
            CNAME | NS | PTR => {
                if let Some(rdata) = rr.data() {
                    if let Some(cname) = rdata.as_cname() {
                        data = serde_json::Value::String(cname.0.to_ascii());
                    } else if let Some(ns) = rdata.as_ns() {
                        data = serde_json::Value::String(ns.0.to_ascii());
                    } else if let Some(ptr) = rdata.as_ptr() {
                        data = serde_json::Value::String(ptr.0.to_ascii());
                    } else {
                        anyhow::bail!("unexpected upstream DNS resolver respond CNAME/NS/PTR record with it's rdata");
                    }
                } else {
                    anyhow::bail!("unexpected upstream DNS resolver respond CNAME/NS/PTR record without domain: {rr:?}");
                }
            },
            MX => {
                if let Some(mx) = rdata.as_mx() {
                    data =
                        match version {
                            4 => {
                                serde_json::json!({
                                    "preference": mx.preference(),
                                    "exchange": mx.exchange().to_ascii()
                                })
                            },
                            _ => {
                                serde_json::Value::String(
                                    format!(
                                        "{} {}",
                                        mx.preference(),
                                        mx.exchange().to_ascii()
                                    )
                                )
                            }
                        };
                } else {
                    anyhow::bail!("unexpected upstream DNS resolver respond MX record with non-MX rdata");
                }
            },
            SOA => {
                if let Some(soa) = rdata.as_soa() {
                    data =
                        match version {
                            4 => {
                                serde_json::json!({
                                    "mname": soa.mname().to_ascii(),
                                    "rname": soa.rname().to_ascii(),
                                    "serial": soa.serial(),
                                    "refresh": soa.refresh(),
                                    "retry": soa.retry(),
                                    "expire": soa.expire(),
                                    "minimum": soa.minimum()
                                })
                            },
                            _ => {
                                serde_json::Value::String(
                                    format!(
                                        "{} {} {} {} {} {} {}",
                                        soa.mname().to_ascii(),
                                        soa.rname().to_ascii(),
                                        soa.serial(),
                                        soa.refresh(),
                                        soa.retry(),
                                        soa.expire(),
                                        soa.minimum()
                                    )
                                )
                            }
                        };
                } else {
                    anyhow::bail!("unexpected upstream DNS resolver respond SOA record with non-SOA rdata");
                }
            },
            SRV => {
                if let Some(srv) = rdata.as_srv() {
                    data =
                        match version {
                            4 => {
                                serde_json::json!({
                                    "priority": srv.priority(),
                                    "weight": srv.weight(),
                                    "port": srv.port(),
                                    "target": srv.target().to_ascii()
                                })
                            },
                            _ => {
                                serde_json::Value::String(
                                    format!(
                                        "{} {} {} {}",
                                        srv.priority(),
                                        srv.weight(),
                                        srv.port(),
                                        srv.target().to_ascii()
                                    )
                                )
                            }
                        };
                } else {
                    anyhow::bail!("unexpected upstream DNS resolver respond SRV record with non-SRV rdata");
                }
            },
            SVCB | HTTPS => {
                let svcb =
                    if let Some(svcb) = rdata.as_svcb() {
                        svcb.clone()
                    } else if let Some(https) = rdata.as_https() {
                        https.0.clone()
                    } else {
                        anyhow::bail!("unexpected upstream DNS resolver respond SVCB record with non-SVCB rdata");
                    };

                data =
                    match version {
                        4 => {
                            let mut sp = Vec::new();
                            for (key, val) in svcb.svc_params().iter() {
                                let obj =
                                    if val.is_no_default_alpn() {
                                        serde_json::json!({
                                            "key": format!("{key}")
                                        })
                                    } else {
                                        serde_json::json!({
                                            "key": format!("{key}"),
                                            "value": format!("{val}")
                                        })
                                    };
                                sp.push(obj);
                            }

                            serde_json::Value::Array(sp)
                        },
                        _ => {
                            serde_json::Value::String(
                                format!(
                                    "{} {} {}",
                                    svcb.svc_priority(),
                                    svcb.target_name(),

                                    svcb.svc_params().iter().map(
                                        |(key, val)| {
                                            if val.is_no_default_alpn() {
                                                // NO_DEFAULT_ALPN is does not have it's value
                                                format!("{key}")
                                            } else {
                                                let mut val = val.to_string();

                                                while val.contains(",,") {
                                                    val = val.replace(",,", ",");
                                                }
                                                while val.ends_with(",") {
                                                    val.pop();
                                                }

                                                format!("{key}={val}")
                                            }
                                        }
                                    )
                                    .collect::<Vec<String>>()
                                    .join(" ")
                                )
                            )
                        }
                    };
            },
            HINFO => {
                if let Some(hinfo) = rdata.as_hinfo() {
                    let cpu = hinfo.cpu().to_vec();
                    let os = hinfo.os().to_vec();

                    data =
                        match version {
                            4 => {
                                let cpu = {
                                    let c = format!("{:?}", Bytes::from(cpu));

                                    // remove b" and "
                                    let mut c: String = c.chars().skip(2).collect();
                                    c.pop();

                                    c
                                };
                                let os = {
                                    let o = format!("{:?}", Bytes::from(os));

                                    // remove b" and "
                                    let mut o: String = o.chars().skip(2).collect();
                                    o.pop();

                                    o
                                };

                                serde_json::json!({
                                    "cpu": cpu,
                                    "os": os
                                })
                            },
                            _ => {
                                serde_json::Value::String(
                                    format!(
                                        "{} {}",

                                        if let Ok(v) = String::from_utf8(cpu.clone()) {
                                            v
                                        } else {
                                            format!("{:?}", Bytes::from(cpu))
                                        },

                                        if let Ok(v) = String::from_utf8(os.clone()) {
                                            v
                                        } else {
                                            format!("{:?}", Bytes::from(os))
                                        }
                                    )
                                )
                            }
                        };
                } else {
                    anyhow::bail!("unexpected upstream DNS resolver respond HINFO record with non-HINFO rdata");
                }
            },
            _ if rdtype.is_dnssec() => {
                if let Some(dnssec) = rdata.as_dnssec() {
                    if dnssec.is_dnskey() || dnssec.is_cdnskey() {
                        let dnskey =
                            if let Some(dnskey) = dnssec.as_dnskey() {
                                dnskey
                            } else if let Some(cdnskey) = dnssec.as_cdnskey() {
                                cdnskey.deref()
                            } else {
                                anyhow::bail!("unexpected upstream DNS resolver respond DNSKEY record with non-DNSKEY rdata");
                            };

                        const DNSKEY_PROTOCOL: u8 = 0x03;

                        data =
                            match version {
                                4 => {
                                    serde_json::json!({
                                        "string": format!("{dnskey}"),

                                        "flags": {
                                            "uint16": dnskey.flags(),
                                            "info": {
                                                "zone_key": dnskey.zone_key(),
                                                "secure_entry_point": dnskey.secure_entry_point(),
                                                "revoke": dnskey.revoke(),
                                            },
                                        },
                                        "protocol": DNSKEY_PROTOCOL,
                                        "algorithm": u8::from(dnskey.algorithm()),
                                        "public_key": BASE64.encode(dnskey.public_key())
                                    })
                                },
                                _ => {
                                    serde_json::Value::String(
                                        format!(
                                            "{} {} {} {}",
                                            dnskey.flags(),
                                            DNSKEY_PROTOCOL,
                                            u8::from(dnskey.algorithm()),
                                            BASE64.encode(dnskey.public_key())
                                        )
                                    )
                                }
                            };
                    } else if dnssec.is_ds() || dnssec.is_cds() {
                        let ds =
                            if let Some(ds) = dnssec.as_ds() {
                                ds
                            } else if let Some(cds) = dnssec.as_cds() {
                                cds.deref()
                            } else {
                                anyhow::bail!("unexpected upstream DNS resolver respond DS record with non-DS rdata");
                            };

                        data =
                            match version {
                                4 => {
                                    serde_json::json!({
                                        "string": format!("{ds}"),

                                        "key_tag": ds.key_tag(),
                                        "algorithm": u8::from(ds.algorithm()),
                                        "digest_type": u8::from(ds.digest_type()),
                                        "digest": HEX_UPPER.encode(ds.digest())
                                    })
                                },
                                _ => {
                                    serde_json::Value::String(
                                        format!(
                                            "{} {} {} {}",
                                            ds.key_tag(),
                                            u8::from(ds.algorithm()),
                                            u8::from(ds.digest_type()),
                                            HEX_UPPER.encode(ds.digest())
                                        )
                                    )
                                }
                            };
                    } else if dnssec.is_sig() || dnssec.is_rrsig() { // only SIG is not tested: rarely seen in public dns
                        let sig =
                            if let Some(sig) = dnssec.as_sig() {
                                sig
                            } else if let Some(rrsig) = dnssec.as_rrsig() {
                                rrsig.deref()
                            } else {
                                anyhow::bail!("unexpected upstream DNS resolver respond SIG record with non-SIG rdata");
                            };

                        let type_covered = sig.type_covered();
                        let string =
                            format!(
                                "{} {} {} {} {} {} {} {} {}",

                                if let Unknown(tc) = type_covered {
                                    tc.to_string()
                                } else {
                                    format!("{type_covered}")
                                },
                                u8::from(sig.algorithm()),
                                sig.num_labels(),
                                sig.original_ttl(),
                                sig.sig_expiration(),
                                sig.sig_inception(),
                                sig.key_tag(),
                                sig.signer_name().to_ascii(),
                                BASE64.encode(sig.sig())
                            );

                        data =
                            match version {
                                4 => {
                                    serde_json::json!({
                                        "string": string,

                                        "type_covered": u16::from(sig.type_covered()),
                                        "algorithm": u8::from(sig.algorithm()),
                                        "num_labels": sig.num_labels(),
                                        "original_ttl": sig.original_ttl(),
                                        "sig_expiration": sig.sig_expiration(),
                                        "sig_inception": sig.sig_inception(),
                                        "key_tag": sig.key_tag(),
                                        "signer_name": sig.signer_name().to_ascii(),
                                        "sig": BASE64.encode(sig.sig())
                                    })
                                },
                                _ => {
                                    serde_json::Value::String(string)
                                }
                            };
                    } else if let Some(tsig) = dnssec.as_tsig() { // not tested: difficult to it is not easy to build query that can trigger such responses
                        data =
                            match version {
                                4 => {
                                    serde_json::json!({
                                        "string": format!("{tsig}"),

                                        "algorithm": tsig.algorithm().to_name().to_ascii(),
                                        "time": tsig.time().to_string(), // u64::MAX is not "safe integer" in javascript
                                        "fudge": tsig.fudge(),
                                        "mac": HEX_UPPER.encode(tsig.mac()),
                                    })
                                },
                                _ => {
                                    serde_json::Value::String(
                                        format!("{tsig}")
                                    )
                                }
                            };
                    } else if let Some(key) = dnssec.as_key() { // not tested: it is deprecated by RFC 3007, and rarely seen in public dns
                        data =
                            match version {
                                4 => {
                                    use dns::KeyTrust::*;
                                    use dns::KeyUsage::*;

                                    let si = key.signatory();

                                    serde_json::json!({
                                        "string": format!("{key}"),

                                        "flags": {
                                            "uint16": key.flags(),
                                            "info": {
                                                "key_trust":
                                                    match key.key_trust() {
                                                        NotAuth => "NOT_AUTH",
                                                        NotPrivate => "NOT_PRIVATE",
                                                        AuthOrPrivate => "AUTH_OR_PRIVATE",
                                                        DoNotTrust => "DO_NOT_TRUST",
                                                    },
                                                "key_usage":
                                                    match key.key_usage() {
                                                        Host => "HOST",
                                                        Zone => "ZONE",
                                                        Entity => "ENTITY",
                                                        Reserved => "RESERVED",
                                                    },
                                                "signatory": {
                                                    "zone": si.zone,
                                                    "strong": si.strong,
                                                    "unique": si.unique,
                                                    "general": si.general,
                                                },
                                            },
                                        },
                                        "protocol": u8::from(key.protocol()),
                                        "algorithm": u8::from(key.algorithm()),
                                        "public_key": BASE64.encode(key.public_key())
                                    })
                                },
                                _ => {
                                    serde_json::Value::String(
                                        format!(
                                            "{} {} {} {}",
                                            key.flags(),
                                            u8::from(key.protocol()),
                                            u8::from(key.algorithm()),
                                            BASE64.encode(key.public_key())
                                        )
                                    )
                                }
                            };
                    } else if let Some(nsec) = dnssec.as_nsec() {
                        let string =
                            format!(
                                "{} {}",
                                nsec.next_domain_name().to_ascii(),
                                nsec.type_bit_maps().iter().map(
                                    |rdtype| {
                                        if let Unknown(rt) = rdtype {
                                            rt.to_string()
                                        } else {
                                            format!("{rdtype}")
                                        }
                                    }
                                ).collect::<Vec<String>>().join(" ")
                            );

                        data =
                            match version {
                                4 => {
                                    serde_json::json!({
                                        "string": string,

                                        "next_domain_name": nsec.next_domain_name().to_ascii(),
                                        "type_bit_maps": nsec.type_bit_maps().iter().map(|v| { u16::from(*v) }).collect::<Vec<u16>>(),
                                    })
                                },
                                _ => {
                                    serde_json::Value::String(string)
                                }
                            };
                    } else if let Some(nsec3) = dnssec.as_nsec3() { // not tested: how to make a query that returns this record?
                        let salt = nsec3.salt();

                        let string =
                            format!(
                                "{} {} {} {} {} {}",
                                u8::from(nsec3.hash_algorithm()),
                                nsec3.flags(),
                                nsec3.iterations(),
                                if salt.is_empty() { String::from("-") } else { BASE32_NOPAD.encode(salt) },
                                BASE32_NOPAD.encode(nsec3.next_hashed_owner_name()),
                                nsec3.type_bit_maps().iter().map(
                                    |rdtype| {
                                        if let Unknown(rt) = rdtype {
                                            rt.to_string()
                                        } else {
                                            format!("{rdtype}")
                                        }
                                    }
                                ).collect::<Vec<String>>().join(" ")
                            );

                        data =
                            match version {
                                4 => {
                                    serde_json::json!({
                                        "string": string,

                                        "hash_algorithm": u8::from(nsec3.hash_algorithm()),
                                        "flags": {
                                            "uint8": nsec3.flags(),
                                            "info": {
                                                "opt_out": nsec3.opt_out(),
                                            }
                                        },
                                        "iterations": nsec3.iterations(),
                                        "salt": BASE32_NOPAD.encode(nsec3.salt()),
                                        "next_hashed_owner_name": BASE32_NOPAD.encode(nsec3.next_hashed_owner_name()),
                                        "type_bit_maps": nsec3.type_bit_maps().iter().map(|v| { u16::from(*v) }).collect::<Vec<u16>>(),
                                    })
                                },
                                _ => {
                                    serde_json::Value::String(string)
                                }
                            };
                    } else if let Some(nsec3param) = dnssec.as_nsec3param() {
                        let salt = nsec3param.salt();

                        let string =
                            format!(
                                "{} {} {} {}",
                                u8::from(nsec3param.hash_algorithm()),
                                nsec3param.flags(),
                                nsec3param.iterations(),
                                if salt.is_empty() { String::from("-") } else { BASE32_NOPAD.encode(salt) },
                            );

                        data =
                            match version {
                                4 => {
                                    serde_json::json!({
                                        "string": string,

                                        "hash_algorithm": u8::from(nsec3param.hash_algorithm()),
                                        "flags": {
                                            "uint8": nsec3param.flags(),
                                            "info": {
                                                "opt_out": nsec3param.opt_out(),
                                            }
                                        },
                                        "iterations": nsec3param.iterations(),
                                        "salt": BASE32_NOPAD.encode(nsec3param.salt()),
                                    })
                                },
                                _ => {
                                    serde_json::Value::String(string)
                                }
                            };
                    } else if let Some(_unknown) = dnssec.as_unknown() {
                        log::warn!("upstream DNS resolver returns unknown DNSSEC-like record: {rdata:?}");
                        data = serde_json::Value::Null;
                    } else {
                        unreachable!();
                    }
                } else {
                    anyhow::bail!("unexpected upstream DNS resolver respond DNSSEC-like record with non-DNSSEC rdata");
                }
            },
            _ => {
                data = serde_json::json!({"error": "WIP not implemented"});
            }
        } // match rdtype

        let rdclass: u16 = rr.dns_class().into();
        let rdtype: u16 = rdtype.into();

        output.push(
            serde_json::json!({
                "name": name,
                "class": rdclass,
                "type": rdtype,
                "TTL": ttl,
                "data": data,
            })
        );
    } // for each records

    Ok(())
}
