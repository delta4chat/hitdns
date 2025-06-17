use crate::*;

use dns_stamp_parser::DnsStamp;

/// This DNS Upstreams List is from DNSCrypt: https://github.com/DNSCrypt/dnscrypt-resolvers/raw/refs/heads/master/v3/public-resolvers.md
pub static DNSCRYPT_SDNS_V3: &str = include_str!("dnscrypt.sdns.v3.txt");

pub static DNSCRYPT_SDNS_LIST: Lazy<Vec<DnsStamp>> =
    Lazy::new(|| {
        let mut text = String::with_capacity(DNSCRYPT_SDNS_V3.len());
        text.extend(
            DNSCRYPT_SDNS_V3
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

        let sdns_len =
            text.bytes()
                .fold(
                    0usize,
                    |len, chr| {
                        if chr == b'\n' {
                            len + 1
                        } else {
                            len
                        }
                    }
                );
        let mut sdns = Vec::with_capacity(sdns_len);

        for line in text.split('\n') {
            sdns.push(
                DnsStamp::decode(line.trim())
                .expect("cannot parse sdns links!")
            );
        }

        sdns
    });

