//! # DNS over UDP (plaintext)
//! this is a DNS local forwarder that serve plaintext DNS request and proxy it to secure upstream DNS resolvers (for example DoH, DoT, DoQ, DNSCrypt, etc).

use crate::{
    *,
    config::*,
    query::*,
    cache::*,
    resolver::*,
};

#[derive(Debug)]
pub struct UdpDNSInboundInner {
    running: AtomicBool,
    socket: UdpSocket,
}

#[derive(Debug, Clone)]
pub struct UdpDNSInbound {
    inner: Arc<UdpDNSInboundInner>,
    cache: DNSCache,
    listen: SocketAddr,
}

impl Deref for UdpDNSInbound {
    type Target = UdpDNSInboundInner;

    fn deref<'a>(&'a self) -> &'a UdpDNSInboundInner {
        &(self.inner)
    }
}

impl UdpDNSInbound {
    pub fn new(socket: UdpSocket, cache: DNSCache) -> std::io::Result<Self> {
        let listen = socket.get_ref().local_addr()?;
        Ok(Self {
            inner:
                Arc::new(UdpDNSInboundInner {
                    running: AtomicBool::new(false),
                    socket,
                }),
            cache,
            listen,
        })
    }

    pub fn bind<A: Into<SocketAddr>>(listen: A, cache: DNSCache) -> std::io::Result<Self> {
        Self::new(UdpSocket::bind(listen)?, cache)
    }

    pub async fn handle_query(&self, mut data: Vec<u8>, peer: SocketAddr) {
        log::trace!(
            "DNS inbound received data from incoming UDP: peer={:?} | data={}",
            peer, data.escape_ascii(),
        );

        let config = Config::global();
        let allow_edns = config.protocol.allow_edns();

        let mut req =
            match dns::Message::from_vec(&data) {
                Ok(v) => v,
                Err(e) => {
                    log::debug!(
                        "received invalid DNS query from incoming UDP: peer={:?} | error={:?} | data={}",
                        peer, e, data.escape_ascii(),
                    );
                    return;
                }
            };

        // remove edns if needed.
        if ! allow_edns {
            req.extensions_mut().take();
        }

        let query: Arc<dyn DNSQuery> =
            match req.queries().first() {
                Some(q) => {
                    Arc::new(q.clone())
                },
                _ => {
                    return;
                }
            };

        use DNSCacheStatus::*;
        let entry =
            match self.cache.get(&query, config.resolver.selector()).await {
                Hit(v) => {
                    log::trace!("DNS Cache Hit: peer={:?} | query={:?} | entry={:?}", peer, query, &v);
                    v
                },
                Expired(v) => {
                    log::debug!("DNS Cache Expired: peer={:?} | query={:?} | entry={:?}", peer, query, &v);
                    v
                },
                Miss => {
                    log::info!("DNS Cache Missed: peer={:?} | query={:?}", peer, query);
                    return;
                }
            };

        let mut resp = entry.response.deref().clone();
        resp.set_id(req.id());

        // remove edns if needed.
        if ! allow_edns {
            resp.extensions_mut().take();
        }

        // calculate response TTL.
        let ttl: u32 = entry.expire_time
                            .duration_since(SystemTime::now()) // calculate TTL as Duration
                            .map(|dur| { dur.as_secs() }) // convert Duration to seconds (discard subseconds)
                            .unwrap_or(0) // handle TTL expiration
                            .try_into() // try convert u64 to u32
                            .unwrap_or(u32::MAX); // handle overflow

        // override TTL for this response.
        for record in resp.answers_mut().iter_mut() {
            // answer section
            record.set_ttl(ttl);
        }
        for record in resp.name_servers_mut().iter_mut() {
            // authority section
            record.set_ttl(ttl);
        }
        for record in resp.additionals_mut().iter_mut() {
            // additional section
            record.set_ttl(ttl);
        }

        data.clear(); // does not affect capacity (no memory reclaimed)
        let mut encoder = dns::BinEncoder::new(&mut data); // for reuse memory

        use dns::BinEncodable;
        match resp.emit(&mut encoder) {
            Ok(()) => {
                self.socket
                    .send_to(encoder.into_bytes(), peer).await
                    .expect("failed to send DNS response to UDP client");
            },
            Err(e) => {
                log::error!("unexpected hickory-proto unable serialize Message to bytes! error={:?}", e);
                return;
            }
        }
    }

    pub async fn run(&self) -> std::io::Result<()> {
        if self.running.compare_exchange(false, true, Relaxed, Relaxed).is_err() {
            return Err(
                std::io::Error::new(
                    std::io::ErrorKind::ResourceBusy,
                    "only single UdpDNSInbound::run() main loop can be run in same time!",
                )
            );
        }
        let _defer = asyncute::Defer::new(|| {
            self.running.store(false, Relaxed);
        });

        let mut buf = [0u8; 65599];
        let mut data;

        let mut len;
        let mut peer;

        let mut this;
        loop {
            (len, peer) = self.socket.recv_from(&mut buf).await?;
            data = buf[..len].to_vec();

            this = self.clone();
            asyncute::spawn(async move {
                this.handle_query(data, peer).await;
            }).detach();
        }
    }
}
