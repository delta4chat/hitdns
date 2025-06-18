use hitdns::{
    *,
    logs,
    protocol::{
        *,
        inbound::{
            *,
            udp::*,
        },
    },
    cache::*,
    database::*,
    resolver::*,
    data::upstreams_list::dnscrypt::*,
};

async fn main_async() {
    eprintln!("log4rs logger init: {:?}", &*logs::HANDLE);
    log::warn!("Test log");
    log::info!("sdns list: \n{}", {
        let mut s = String::new();
        for it in SDNS_LIST.iter() {
            writeln!(s, "{:?}", it);
        }
        s
    });

    let db = DNSDatabase::auto_open().unwrap();
    let resolver = DNSResolver::new();
    let cache = DNSCache::new(db, resolver);
    let udp = UdpSocket::bind(SocketAddr::from_str("127.0.0.1:10053").unwrap()).expect("cannot bind udp");
    let udp_inbound = UdpDNSInbound::new(udp, cache).expect("cannot create udp inbound");
    udp_inbound.run().await.expect("udp inbound die");
}

fn main() {
    let task = asyncute::spawn(main_async());

    let interval = Duration::from_secs(1);
    while ! task.is_finished() {
        std::thread::park_timeout(interval);
    }

    panic!("async task exited unexpectedly!");
}
