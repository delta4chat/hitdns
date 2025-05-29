//! DNS query trait and binary store format.

use crate::*;

/// Serialized format.
/// ```text
/// +---------------------+----------------+
/// |  Field Name         | Length (Bytes) |
/// +---------------------+----------------+
/// |  Version            | 1              |
/// +---------------------+----------------+
/// |  Domain Length      | 1              |
/// +---------------------+----------------+
/// |  Domain             | variable       |
/// +---------------------+----------------+
/// |  DNS Class          | 2 (big endian) |
/// +---------------------+----------------+
/// |  Record Type        | 2 (big endian) |
/// +---------------------+----------------+
/// ```
pub mod serialized {
    /// current version (0x01)
    pub const VERSION: u8 = 0x01;

    /// length information of [`Serialized`].
    pub mod len_max {
        /// version = 1 byte.
        pub const VERSION: usize = 1;

        /// domain len = 1 byte.
        pub const DOMAIN_LEN: usize = 1;

        /// domain is variable and max len is 255.
        pub const DOMAIN: usize = u8::MAX as usize;

        /// rdclass = 2 bytes (big endian)
        pub const RDCLASS: usize = 2;

        /// rdtype = 2 bytes (big endian)
        pub const RDTYPE: usize = 2;

        /// total length.
        pub const TOTAL: usize = VERSION + DOMAIN_LEN + DOMAIN + RDCLASS + RDTYPE;
    }

    /// maximum length of [`Serialized`].
    pub const LEN_MAX: usize = len_max::TOTAL;

    /// this type alias for serialized DNSQuery.
    pub type Serialized = heapless::Vec<u8, LEN_MAX>;

}

use serialized::Serialized;

/// DomainString: heapless version of String and it's max length up to 255.
pub type DomainString = heapless::String<{serialized::len_max::DOMAIN}>;

/// DNS Query.
pub trait DNSQuery: Sized {
    /// create new DNS Query from (domain, rdclass, rdtype) third-tuple.
    fn new(
        domain: dns::Name,
        rdclass: dns::RdClass,
        rdtype: dns::RdType,
    ) -> Self;

    /// query domain name.
    fn domain<'a>(&'a self) -> &'a dns::Name;

    /// query DNS class (rdclass).
    fn rdclass(&self) -> dns::RdClass;

    /// query type (rdtype).
    fn rdtype(&self) -> dns::RdType;
}

impl DNSQuery for dns::Query {
    fn new(
        domain: dns::Name,
        rdclass: dns::RdClass,
        rdtype: dns::RdType,
    ) -> Self {
        let mut this = Self::default();
        this.set_name(domain);
        this.set_query_class(rdclass);
        this.set_query_type(rdtype);
        this
    }

    fn domain<'a>(&'a self) -> &'a dns::Name {
        self.name()
    }

    fn rdclass(&self) -> dns::RdClass {
        self.query_class()
    }

    fn rdtype(&self) -> dns::RdType {
        self.query_type()
    }
}

/// the extension of [`DNSQuery`].
pub trait DNSQueryExt: DNSQuery {
    /// query domain name, encoded by UTF-8, it does not uses IDNA punycode.
    fn domain_str(&self) -> DomainString {
        let mut out = heapless::String::new();
        write!(out, "{}", self.domain()).unwrap();
        out
    }

    /// query DNS class (rdclass). raw format as unsigned 16-bit integer.
    fn rdclass_int(&self) -> u16 {
        self.rdclass().into()
    }

    /// query type (rdtype). raw format as unsigned 16-bit integer.
    fn rdtype_int(&self) -> u16 {
        self.rdtype().into()
    }

    /// convert to versioned bytes for store to database.
    fn to_bytes(&self) -> Serialized {
        let domain_str = self.domain_str();

        let domain = domain_str.as_bytes();
        let domain_len = domain.len();

        if domain_len > (u8::MAX as usize) {
            panic!("unexpected domain {:?} too long to encode!", domain_str);
        }

        let rdclass = self.rdclass_int();
        let rdtype = self.rdtype_int();

        let mut out = heapless::Vec::new();
        out.push(serialized::VERSION).unwrap();

        out.push(domain_len as u8).unwrap();
        out.extend(domain.iter().copied());

        out.extend(rdclass.to_be_bytes());
        out.extend(rdtype.to_be_bytes());

        out
    }

    /// parse DNSQuery from Serialized format.
    fn from_bytes<B: AsRef<[u8]>>(bytes: B) -> std::io::Result<Self> {
        let mut bytes = bytes.as_ref();

        if bytes.len() > serialized::LEN_MAX {
            return err_invalid_input("bytes length exceeded maximum possible length!");
        }

        if bytes.is_empty() {
            return err_invalid_input("empty bytes provided!");
        }
        let version = bytes[0];
        bytes = &bytes[1..];

        if version != serialized::VERSION {
            return err_invalid_input("version mismatch!");
        }

        if bytes.is_empty() {
            return err_invalid_input("missing domain length!");
        }
        let domain_len = bytes[0] as usize;
        bytes = &bytes[1..];

        if bytes.len() < domain_len {
            return err_invalid_input("domain too short!");
        }
        let domain = &bytes[..domain_len];
        bytes = &bytes[domain_len..];

        if bytes.len() < 2 {
            return err_invalid_input("rdclass too short!");
        }

        let rdclass = u16::from_be_bytes([ bytes[0], bytes[1] ]);
        bytes = &bytes[2..];

        if bytes.len() < 2 {
            return err_invalid_input("rdtype too short!");
        }

        let rdtype = u16::from_be_bytes([ bytes[0], bytes[1] ]);
        bytes = &bytes[2..];

        if ! bytes.is_empty() {
            return err_invalid_input("unexpected tailing junk");
        }

        match core::str::from_utf8(domain) {
            Ok(domain_str) => {
                let name = dns::Name::from_str_relaxed(domain_str).map_err(invalid_input)?;
                Ok(Self::new(name, rdclass.into(), rdtype.into()))
            },
            Err(e) => {
                return err_invalid_input(format!("domain is not valid UTF-8 data: {:?}", e));
            }
        }
    }
}

impl<T: DNSQuery> DNSQueryExt for T {}

