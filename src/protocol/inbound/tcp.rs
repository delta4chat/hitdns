//! # DNS over TCP (plaintext)
//! this is a DNS local forwarder that serve plaintext DNS request and proxy it to secure upstream DNS resolvers (for example DoH, DoT, DoQ, DNSCrypt, etc).

use crate::{
    *,
    config::*,
    query::*,
    cache::*,
    resolver::*,
};

#[derive(Debug)]
pub struct TcpDNSInboundInner {
    running: AtomicBool,
    listener: TcpListener,
}

#[derive(Debug, Clone)]
pub struct TcpDNSInbound {
    inner: Arc<TcpDNSInboundInner>,
    cache: DNSCache,
    listen: SocketAddr,
}

impl Deref for TcpDNSInbound {
    type Target = TcpDNSInboundInner;

    fn deref<'a>(&'a self) -> &'a TcpDNSInboundInner {
        &(self.inner)
    }
}

impl TcpDNSInbound {
    pub fn new(listener: TcpListener, cache: DNSCache) -> std::io::Result<Self> {
        let listen = listener.get_ref().local_addr()?;
        Ok(Self {
            inner:
                Arc::new(TcpDNSInboundInner {
                    running: AtomicBool::new(false),
                    listener,
                }),
            cache,
            listen,
        })
    }

    pub fn bind<A: Into<SocketAddr>>(listen: A, cache: DNSCache) -> std::io::Result<Self> {
        Self::new(TcpListener::bind(listen)?, cache)
    }

    pub async fn handle_query(&self, mut conn: TcpStream, peer: SocketAddr) {
        log::trace!("DNS inbound accept new connection from incoming TCP: peer={:?}", peer);

        let mut len_buf = [0u8; 2];
        let mut len;

        let mut buf = Vec::new();
        let mut data;

        let mut req;
        let mut query: Arc<dyn DNSQuery>;
        let mut entry;
        let mut resp;
        let mut ttl;
        let mut encoder;

        let config = Config::global();
        let mut allow_edns;
        loop {
            allow_edns = config.protocol.allow_edns();

            if let Err(e) = conn.read_exact(&mut len_buf).await {
                log::debug!(
                    "unable read length from TCPStream (may client close connection?): peer={:?}, error={:?}",
                    peer, e,
                );
                return;
            }

            len = u16::from_be_bytes(len_buf) as usize;
            buf.resize(len, 0x00);

            if let Err(e) = conn.read_exact(&mut buf[..len]).await {
                log::debug!(
                    "unable read query from TCPStream (may client close connection?): peer={:?}, error={:?}",
                    peer, e,
                );
            }
            data = &buf[..len];

            req =
                match dns::Message::from_vec(data) {
                    Ok(v) => v,
                    Err(e) => {
                    log::debug!(
                        "received invalid DNS query from TCPStream: peer={:?} | error = {:?} | data={}",
                        peer, e, data.escape_ascii(),
                    );
                    return;
                }
            };

            // remove edns if needed.
            if ! allow_edns {
                req.extensions_mut().take();
            }

            query =
                match req.queries().first() {
                    Some(q) => {
                        Arc::new(q.clone())
                    },
                    _ => {
                        return;
                    }
                };

            use DNSCacheStatus::*;
            entry =
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

            resp = entry.response.deref().clone();
            resp.set_id(req.id());

            // remove edns if needed.
            if ! allow_edns {
                resp.extensions_mut().take();
            }

            // calculate response TTL.
            ttl = entry.expire_time
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

            buf.clear(); // does not affect capacity (no memory reclaimed)
            encoder = dns::BinEncoder::new(&mut buf); // for reuse memory

            use dns::BinEncodable;
            match resp.emit(&mut encoder) {
                Ok(()) => {
                    data = encoder.into_bytes();

                    len = data.len();
                    if len > (u16::MAX as usize) {
                        log::error!("unexpected DNS upstream returned too long DNS response length > 65535");
                        return;
                    }
                    len_buf = (len as u16).to_be_bytes();

                    if let Err(e) = conn.write(&len_buf).await {
                        log::debug!(
                            "unable send length to TCP (may client close conn?): peer={:?}, error={:?}",
                            peer, e,
                        );
                        return;
                    }

                    if let Err(e) = conn.write_all(data).await {
                        log::debug!(
                            "unable send response to TCP (may client close conn?): peer={:?}, error={:?}",
                            peer, e,
                        );
                        return;
                    }
                },
                Err(e) => {
                    log::error!("unexpected hickory-proto unable serialize Message to bytes! error={:?}", e);
                    return;
                }
            }
        }
    }

    pub async fn run(&self) -> std::io::Result<()> {
        if self.running.compare_exchange(false, true, Relaxed, Relaxed).is_err() {
            return Err(
                std::io::Error::new(
                    std::io::ErrorKind::ResourceBusy,
                    "only single TcpDNSInbound::run() main loop can be run in same time!",
                )
            );
        }
        let _defer = asyncute::Defer::new(|| {
            self.running.store(false, Relaxed);
        });

        let mut conn;
        let mut peer;

        let mut this;
        loop {
            (conn, peer) = self.listener.accept().await?;

            this = self.clone();
            asyncute::spawn(async move {
                this.handle_query(conn, peer).await;
            }).detach();
        }
    }
}
