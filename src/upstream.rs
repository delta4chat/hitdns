//! DNS upstream

use crate::{
    *,
    query::*,
    entry::*,
};

/// HTTP versions
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum HTTPVersion {
    /// HTTP/0.9
    H09 = 9,

    /// HTTP/1.0
    H10 = 10,

    /// HTTP/1.1
    H11 = 11,

    /// HTTP/2
    H2 = 20,

    /// HTTP/3
    H3 = 30,
}

/// DNS plaintext address.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DNSPlaintext {
    /// DNS over UDP plaintext
    UDP(SocketAddr),

    /// DNS over TCP plaintext
    TCP(SocketAddr),

    /// DOH over HTTP plaintext
    /// * useful for your reverse-proxy to serve DoH requests.
    /// for example:
    /// `client <===> nginx (https://doh.test/dns-query) <===> hitdns (127.0.0.1:port)`
    HTTP(Url),
}

impl DNSPlaintext {
    /// checks address whether valid.
    pub fn is_valid(&self) -> bool {
        let addr = 
            match self {
                Self::UDP(ua) => ua,
                Self::TCP(ta) => ta,
                Self::HTTP(url) => {
                    if url.scheme().to_ascii_lowercase() != "dohp" {
                        return false;
                    }
                    if url.port() == Some(0) {
                        return false;
                    }

                    // scheme is "dohp", and port absent or non-zero.
                    return true;
                }
            };

        if addr.port() != 0 {
            true
        } else {
            false
        }
    }
}

/// DNS protocol and address
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DNSProtocol {
    /// plaintext. only for client.
    /// * hitdns does not allow plaintext outgoing packets.
    Plaintext(DNSPlaintext),

    /// DNS over HTTPS (RFC 8484).
    /// * this only includes HTTP/2 and HTTP/3.
    /// * the scheme must be `doh2://` or `doh3://`.
    /// * disallowed schemes such as `https://` or `http://`.
    DoH(Url),

    /// DNS over TLS.
    /// * this only referring to TCP-based TLS.
    DoT(SocketAddr),

    /// DNS over QUIC (Server Address, Optional SNI).
    DoQ(SocketAddr, Option<dns::Name>),
}

impl DNSProtocol {
    /// whether this DNS Protocol is encrypted?
    pub const fn is_encrypted(&self) -> bool {
        match self {
            Self::Plaintext(_) => false,
            _ => true,
        }
    }

    /// checks address whether valid.
    pub fn is_valid(&self) -> bool {
        let addr =
            match self {
                Self::Plaintext(plain) => {
                    return plain.is_valid();
                },
                Self::DoH(url) => {
                    match url.scheme().to_ascii_lowercase().as_str() {
                        "doh2" | "doh3" => {},
                        _ => {
                            return false;
                        }
                    }

                    if url.port() == Some(0) {
                        return false;
                    }

                    return true;
                },
                Self::DoT(v) => v,
                Self::DoQ(addr, maybe_sni) => {
                    if let Some(sni) = maybe_sni.as_ref() {
                        if ! sni.is_fqdn() {
                            return false;
                        }
                        if sni.is_wildcard() {
                            return false;
                        }
                        if sni.num_labels() == 4 {
                            if let Some(tld) = sni.iter().last() {
                                // Iterator::all() returns true even if iterator is empty.
                                // this is no problem due to empty TLD always invalid.
                                if tld.into_iter().all(u8::is_ascii_digit) {
                                    return false;
                                }
                            }
                        }
                    }

                    addr
                },
            };

        if addr.port() != 0 {
            true
        } else {
            false
        }
    }

    /// format any protocol's address to URL format.
    /// 
    /// for example:
    /// * `doh2://www.example.com/dns-query`
    /// * `dot://tls.example.com:853`
    ///
    /// * `doh3://http3.example.com/dns-query`
    /// * `dohq://quic.example.com:853`
    ///
    /// * `udp://192.168.1.1:53`
    /// * `tcp://172.16.0.1:53`
    ///
    /// * `dohp://127.0.0.1:8053`
    pub fn url(&self) -> Url {
        todo!()
    }
}

/// DNS Upstream Server.
pub trait DNSUpstream: Send + Sync {
    /// the Name of Upstream Server.
    fn name<'a>(&'a self) -> &'a str;

    /// DNS protocol used by this upstream.
    fn protocol(&self) -> DNSProtocol;

    /// the Country Code of this Upstream server itself.
    /// * usually this is the server location, hosting platform location, or GeoIP location.
    /// * if server uses IP Anycast, Web CDN or Dynamic DNS, then should use the location of server operator's organization, company/corporation, or personal.
    fn server_country(&self) -> CountryCode;

    /// the Country Code of the operator that running this Upstream.
    /// * usually this is the location of server operator's organization, company/corporation, or personal.
    /// * only the mainly entity that operates Upstream server. not any 3rd-parties.
    fn operator_country(&self) -> CountryCode;

    /// whether the logs kept in Upstream server is anonymized?
    /// * usually return true if server is zero-logging (does not kept logs).
    /// * it's should return false if this is unclear.
    fn is_anonymized_logs(&self) -> bool { false }

    /// whether this Upstream server is zero-logging?
    /// * only return true if servers that have policy that clarify claimed it does not kept logs.
    /// * it's should return false if this is unclear.
    fn is_without_logs(&self) -> bool { false }

    /// try to resolve DNS query using this upstream.
    fn resolve(&self, query: Arc<dyn DNSQuery>) -> PinFut<std::io::Result<DNSEntry>>;
}

impl fmt::Debug for dyn DNSUpstream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("dyn DNSUpstream")
         .field("name", &(self.name()))
         .field("protocol", &(self.protocol()))
         .field("server_country", &(self.server_country()))
         .field("operator_country", &(self.operator_country()))
         .field("is_anonymized_logs", &(self.is_anonymized_logs()))
         .field("is_without_logs", &(self.is_without_logs()))
         .field("resolve", &"fn")
         .finish_non_exhaustive()
    }
}

impl PartialEq for dyn DNSUpstream {
    fn eq(&self, other: &Self) -> bool {
        self.name() == other.name()
        &&
        self.protocol() == other.protocol()
        &&
        self.server_country() == other.server_country()
        &&
        self.operator_country() == other.operator_country()
        &&
        self.is_anonymized_logs() == other.is_anonymized_logs()
        &&
        self.is_without_logs() == self.is_without_logs()
    }
}
impl Eq for dyn DNSUpstream {}

impl Hash for dyn DNSUpstream {
    fn hash<H: Hasher>(&self, state: &mut H) {
        format!("{:?}", self).hash(state);
        self.name().hash(state);
        self.protocol().hash(state);
        self.server_country().hash(state);
        self.operator_country().hash(state);
        self.is_anonymized_logs().hash(state);
        self.is_without_logs().hash(state);
    }
}
