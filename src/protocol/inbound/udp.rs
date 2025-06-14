//! # DNS over UDP
//! this is a DNS local forwarder that serve plaintext DNS request and proxy it to secure upstream DNS resolvers (for example DoH, DoT, DoQ, DNSCrypt, etc).

use crate::{
    *,
    cache::*,
};

#[derive(Debug)]
pub struct UdpDNSInboundInner {
    running: AtomicBool,

    socket: UdpSocket,
    allow_edns: AtomicBool,
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
    pub fn new(socket: UdpSocket, cache: DNSCache, allow_edns: bool) -> std::io::Result<Self> {
        let listen = socket.get_ref().local_addr()?;
        Ok(Self {
            inner:
                Arc::new(UdpDNSInboundInner {
                    running: AtomicBool::new(false),

                    socket,
                    allow_edns: AtomicBool::new(allow_edns),
                }),
            cache,
            listen,
        })
    }

    pub fn allow_edns(&self) -> bool {
        self.allow_edns.load(Relaxed)
    }
    pub fn set_allow_edns(&self, allow: bool) {
        self.allow_edns.store(allow, Relaxed)
    }

    pub fn bind<A: Into<SocketAddr>>(
        listen: A,
        cache: DNSCache,
        allow_edns: bool,
    ) -> std::io::Result<Self> {
        Self::new(UdpSocket::bind(listen)?, cache, allow_edns)
    }

    pub async fn run(&self) -> std::io::Result<()> {
        let mut buf = [0u8; 65599];

        let mut len;
        let mut peer;

        let mut msg;
        let mut query;

        loop {
            (len, peer) = self.socket.recv_from(&mut buf).await?;
            msg = dns::Message::from_vec(&buf[..len]).map_err(std::io::Error::other)?;
            if ! self.allow_edns() {
                msg.extensions_mut().take();
            }
            query =
                match msg.queries().first() {
                    Some(v) => v,
                    _ => {
                        continue;
                    }
                };

            todo!();
        }
    }
}
