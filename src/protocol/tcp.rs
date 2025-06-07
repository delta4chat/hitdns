use crate::{
    *,
    protocol::pool::*,
};

pub fn tcp_connect(addr: &SocketAddr) -> PinFut<std::io::Result<TcpStream>> {
    Box::pin(TcpStream::connect(*addr))
}

pub type TcpStreamPoolRaw =
    ConnPool<SocketAddr, TcpStream, fn(&SocketAddr)->PinFut<std::io::Result<TcpStream>>>;

use asyncute::AtomicRangeStrict;

pub struct TcpStreamPool {
    raw: TcpStreamPoolRaw,
}

impl Deref for TcpStreamPool {
    type Target = TcpStreamPoolRaw;

    fn deref(&self) -> &TcpStreamPoolRaw {
        &(self.raw)
    }
}

impl TcpStreamPool {
    pub fn new(protocol: &str, remote: SocketAddr) -> Self {
        Self {
            raw: TcpStreamPoolRaw::new(protocol, remote, tcp_connect),
        }
    }
}
