/// This DNS Upstreams List is provided by hitdns:
/// * `hitdns.sdns.txt` format is `sdns://` URL(s) separated by newline character.
pub static SDNS_V3: &str = include_str!("hitdns.sdns.txt");

include!("sdns.rs");

