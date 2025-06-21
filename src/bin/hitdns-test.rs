use hitdns::{
    *,
    logs::*,
    protocol::{
        *,
        inbound::{
            *,
            tcp::*,
        },
    },
    cache::*,
    database::*,
    resolver::*,
    data::upstreams_list as ulist,
};

async fn main_async() {
    eprintln!("log4rs logger init: {:?}", log4rs_handle());
    log::warn!("Test log");
    log::info!("dnscrypt sdns list: \n{}", {
        let mut s = String::new();
        for it in ulist::dnscrypt::SDNS_LIST.iter() {
            writeln!(s, "{:?}", it).expect("failed to stringify sdns");
        }
        s
    });
    log::info!("hitdns sdns list: \n{}", {
        let mut s = String::new();
        for it in ulist::hitdns::SDNS_LIST.iter() {
            writeln!(s, "{:?}", it).expect("failed to stringify sdns");
        }
        s
    });

    let db = DNSDatabase::auto_open().unwrap();
    let resolver = DNSResolver::new_builtin_upstreams("hitdns").await;
    let cache = DNSCache::new(db, resolver);
    let tcp = TcpListener::bind(SocketAddr::from_str("127.0.0.1:10053").unwrap()).expect("cannot bind tcp");
    let tcp_inbound = TcpDNSInbound::new(tcp, cache).expect("cannot create tcp inbound");

    tcp_inbound.run().await.expect("tcp inbound die");
}

fn main() {
    let task = asyncute::spawn(main_async());

    let interval = Duration::from_secs(1);
    while ! task.is_finished() {
        std::thread::park_timeout(interval);
    }

    panic!("async task exited unexpectedly!");
}
