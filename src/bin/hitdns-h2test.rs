use hitdns::{
    *,
    protocol::h2::*,
};

async fn main_async() {
    loop {

    for _ in 0..10 {
        let req = dbg!(
                    http::Request::get("https://130.59.31.251/robots.txt")
                    .version(http::Version::HTTP_2)
                    .body(Bytes::new())
                  ).expect("unable construct http::Request");

        let c = dbg!(H2Client::global());
        dbg!(c.request(req).await);

        async_io::Timer::after(Duration::from_secs(1)).await;
    }

    async_io::Timer::after(Duration::from_secs(30)).await;

    }
}

fn main() {
    hitdns::logs::setup();
    let task = asyncute::spawn(main_async());

    let interval = Duration::from_secs(1);
    while ! task.is_finished() {
        std::thread::park_timeout(interval);
    }

    panic!("async task exited unexpectedly!");
}
