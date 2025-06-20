/// This DNS Upstreams List is from DNSCrypt:
/// * `dnscrypt.sdns.v3.txt` format is `sdns://` URL(s) separated by newline character.
/// * <https://github.com/DNSCrypt/dnscrypt-resolvers/raw/refs/heads/master/v3/public-resolvers.md>
pub static SDNS_V3: &str = include_str!("dnscrypt.sdns.v3.txt");

include!("sdns.rs");

