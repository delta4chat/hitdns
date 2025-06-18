use crate::*;

use dns_stamp_parser::*;

/// This DNS Upstreams List is from DNSCrypt:
/// * `dnscrypt.sdns.v3.txt` format is `sdns://` URL(s) separated by newline character.
/// * <https://github.com/DNSCrypt/dnscrypt-resolvers/raw/refs/heads/master/v3/public-resolvers.md>
pub static SDNS_V3: &str = include_str!("dnscrypt.sdns.v3.txt");

pub static SDNS_LIST: Lazy<Box<[DnsStamp]>> =
    Lazy::new(|| {
        let mut text = String::with_capacity(SDNS_V3.len());
        text.extend(
            SDNS_V3
            .chars()
            .map(|chr| {
                match chr {
                    '\r' | '\t' | ' ' => '\n',
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

        let mut line_trim;
        for line in text.split('\n') {
            line_trim = line.trim();

            if line_trim.is_empty() {
                continue;
            }

            match DnsStamp::decode(line_trim) {
                Ok(v) => {
                    sdns.push(v);
                },
                Err(e) => {
                    log::error!("compile-time issue: included sdns.txt corrupted: cannot parse sdns links: error={:?}, line={:?}", e, line_trim);
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
