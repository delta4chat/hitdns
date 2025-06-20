use crate::{
    *,
    upstream::DNSUpstream,
    protocol::outbound::doh::DoHUpstream,
};

use dns_stamp_parser::*;

pub static SDNS_LIST: Lazy<Box<[DnsStamp]>> =
    Lazy::new(|| {
        let mut text = String::with_capacity(SDNS_V3.len());
        text.extend(
            SDNS_V3
            .chars()
            .map(|chr| {
                match chr {
                    '\r' | '\t'  => '\n',
                    _ => chr
                }
            })
        );

        while text.contains("\n\n") {
            text = text.replace("\n\n", "\n");
        }
        let text = text.trim();

        let sdns_len = text.bytes().filter(|c| { (*c) == b'\n' }).count();
        let mut sdns = Vec::with_capacity(sdns_len);

        let mut link;
        for line in text.split('\n') {
            link = line.trim();

            if link.is_empty() {
                // ignore empty line.
                continue;
            }
            if link.starts_with('#') {
                // ignore comment line.
                continue;
            }

            if let Some(parts) = link.split_once('#') {
                link = parts.0.trim();
            }

            match DnsStamp::decode(link) {
                Ok(v) => {
                    sdns.push(v);
                },
                Err(e) => {
                    log::error!("compile-time issue: included sdns.txt corrupted: cannot parse sdns links: error={:?}, line={:?}", e, link);
                }
            }
        }

        sdns.into_boxed_slice() // this internally calls Vec::shrink_to_fit()
    });

macro_rules! gen_sub_lists {
    ($($name:ident = $variant:path as $type:ty;)*) => {
        $(
            pub static $name: Lazy<Box<[$type]>> =
                Lazy::new(|| {
                    SDNS_LIST
                    .iter()
                    .filter_map(|sdns| {
                        if let $variant(inner) = sdns {
                            Some(inner.clone())
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<$type>>()
                    .into_boxed_slice() // this internally calls Vec::shrink_to_fit()
                });
        )*
    }
}

gen_sub_lists!(
    SDNS_DOH_LIST = DnsStamp::DnsOverHttps as DnsOverHttps;
    SDNS_ODOH_LIST = DnsStamp::ObliviousDoHRelay as DnsOverHttps; // DnsStamp::ObliviousDoHRelay(DnsOverHttps)
    SDNS_ODOHT_LIST = DnsStamp::ObliviousDoHTarget as ObliviousDoHTarget;

    SDNS_DOT_LIST = DnsStamp::DnsOverTls as DnsOverTls;
    SDNS_DOQ_LIST = DnsStamp::DnsOverQuic as DnsOverTls; // DnsStamp::DnsOverQuic(DnsOverTls)

    SDNS_DNSCRYPT_LIST = DnsStamp::DnsCrypt as DnsCrypt;
    SDNS_DNSCRYPT_RELAY_LIST = DnsStamp::AnonymizedDnsCryptRelay as AnonymizedDnsCryptRelay;

    SDNS_PLAIN_LIST = DnsStamp::DnsPlain as DnsPlain;
);

pub static SDNS_UPSTREAM_LIST: Lazy<Box<[Arc<dyn DNSUpstream>]>> =
    Lazy::new(|| {
        let len = SDNS_DOH_LIST.len() + SDNS_ODOH_LIST.len();
        let mut list: Vec<Arc<dyn DNSUpstream>> = Vec::with_capacity(len);

        for doh in SDNS_DOH_LIST.iter() {
            list.push(Arc::new(DoHUpstream::new(doh.clone())));
        }
        for odoh in SDNS_ODOH_LIST.iter() {
            list.push(Arc::new(DoHUpstream::new(odoh.clone())));
        }

        list.into_boxed_slice() // this internally calls Vec::shrink_to_fit()
    });

