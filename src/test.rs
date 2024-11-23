use crate::*;
use dns::*;

fn stress_pkt_gen1() -> dns::Message {
    let q = DNSQuery {
        name: format!("{}.nx.hitdns.", fastrand::u32(..)),
        rdclass: 3, // CH
        rdtype: 1, // A
    };
    
    q.try_into().unwrap()
}
fn stress_pkt_gen2() -> dns::Message {
    let mut name = DOMAIN_LIST[ fastrand::usize(0 .. DOMAIN_LIST.len()) ].to_string();
    name.push('.');
    let q = DNSQuery {
        name,
        rdclass: 1,
        rdtype: 1,
    };
    q.try_into().unwrap()
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut out = vec![];
    while out.len() < len {
        // do not use fastrand::Rng::fill() because it's internal implemention is like to this, so there is no performance advantage
        out.extend(fastrand::u64(..).to_ne_bytes());
    }
    while out.len() > len {
        out.pop();
    }
    assert!(out.len() == len);
    out
}

fn random_pkt() -> Vec<u8> {
    random_bytes(fastrand::usize(0..1024))
}

fn generate_stress_packet(valid: bool) -> Vec<u8> {
    if ! valid {
        let mut pkt = random_pkt();
        while dns::Message::from_vec(&pkt).is_ok() {
            pkt = random_pkt();
        }
        return pkt;
    }

    let mut pkt =
        if fastrand::bool() {
            stress_pkt_gen1()
        } else {
            stress_pkt_gen2()
        };
    pkt.set_id(fastrand::u16(..));
    pkt.to_bytes().unwrap()
}

static SEND_PKT: AtomicUsize = AtomicUsize::new(0);
static RECV_PKT: AtomicUsize = AtomicUsize::new(0);

async fn stress(valid: bool, interval: Duration) {
    static ID: AtomicUsize = AtomicUsize::new(1);
    let id = ID.fetch_add(1, Relaxed);

    let addr = HITDNS_OPT.listen.unwrap();

    let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.connect(addr).unwrap();
    sock.set_nonblocking(true).unwrap();

    let mut send_pkt: usize = 0;
    let mut recv_pkt: usize = 0;

    let mut buf = [0u8; 1];
    let mut t = Instant::now();
    let mut rate = String::from("N/A");
    loop {
        if sock.recv_from(&mut buf).is_ok() {
            recv_pkt += 1; RECV_PKT.fetch_add(1, Relaxed);
        };

        sock.send(&generate_stress_packet(valid)).unwrap();
        send_pkt += 1; SEND_PKT.fetch_add(1, Relaxed);

        if t.elapsed() > Duration::from_secs(10) {
            t = Instant::now();

            if valid {
                if recv_pkt > send_pkt {
                    panic!("(stress-{id}) test failed: server unexpected responses with more packets than requested packets");
                }
                if send_pkt.abs_diff(recv_pkt) > send_pkt {
                    log::error!("(stress-{id}) test issue: [server response rate too low] sent pkts = {send_pkt} | recv pkts = {recv_pkt}");
                    smol::Timer::after(Duration::from_millis(100)).await;
                }

                if recv_pkt > 0 {
                    rate = format!("{:.3}%", 100.0 / (send_pkt as f64 / recv_pkt as f64));
                }
                log::warn!("(stress-{id}) test result: server response rate = {rate} | sent/recv ({send_pkt}/{recv_pkt})");
            } else {
                if recv_pkt != 0 {
                    panic!("(stress-{id}) test failed: server unexpected responses to invalid request packets");
                }
            }
        }

        smol::Timer::after(interval).await;
    }
}

pub async fn main_async() {
    smol::Timer::after(Duration::from_secs(3)).await;

    let stress_valid_fut = stress(true, Duration::from_millis(10));
    let stress_invalid_fut = stress(false, Duration::from_millis(50));

    smolscale2::spawn(stress_valid_fut).detach();
    smolscale2::spawn(stress_invalid_fut).detach();

    let mut rate = String::from("N/A");
    loop {
        let sp = SEND_PKT.load(Relaxed);
        let rp = RECV_PKT.load(Relaxed);

        if rp > 0 {
            rate = format!("{:.3}%", 100.0 / (sp as f64 / rp as f64));
        }

        log::warn!("stress test result: total server response rate = {rate} | total sent/recv ({sp}/{rp})");

        smol::Timer::after(Duration::from_secs(15)).await;
    }
}

static DOMAIN_LIST: Lazy<Vec<&'static str>> = Lazy::new(|| { include_str!("test.domains.txt").split("\n").filter(|x| { ! x.is_empty() }).collect() });

