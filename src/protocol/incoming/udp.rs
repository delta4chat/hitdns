//! # DNS over UDP
//! this is a DNS local forwarder that serve plaintext DNS request and proxy it to secure upstream DNS resolvers (for example DoH, DoT, DoQ, DNSCrypt, etc).

use crate::*;

#[derive(Debug)]
pub struct UdpForwardedDNSInner {
    running: AtomicBool,

    socket: UdpSocket,
    allow_edns: AtomicBool,
}

#[derive(Debug, Clone)]
pub struct UdpForwardedDNS {
    inner: Arc<UdpForwardedDNSInner>,

    listen: SocketAddr,
}

impl Deref for UdpForwardedDNS {
    type Target = UdpForwardedDNSInner;

    fn deref<'a>(&'a self) -> &'a UdpForwardedDNSInner {
        &(self.inner)
    }
}

impl UdpForwardedDNS {
    pub fn new(socket: UdpSocket, allow_edns: bool) -> std::io::Result<Self> {
        let listen = socket.get_ref().local_addr()?;
        Ok(Self {
            inner:
                Arc::new(UdpForwardedDNSInner {
                    running: AtomicBool::new(false),

                    socket,
                    allow_edns: AtomicBool::new(allow_edns),
                }),
            listen,
        })
    }

    pub fn bind<A: Into<SocketAddr>>(listen: A, allow_edns: bool) -> std::io::Result<Self> {
        Self::new(UdpSocket::bind(listen)?, allow_edns)
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
