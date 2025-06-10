use crate::{
    *,
    protocol::pool::*,
};

pub fn tcp_connect(addr: &SocketAddr) -> PinFut<std::io::Result<TcpStream>> {
    Box::pin(TcpStream::connect(*addr))
}

pub fn tcp_is_closed(conn: &TcpStream) -> bool {
    let mut inner = conn.get_ref();
    if inner.set_nonblocking(true).is_err() {
        return true;
    }

    let mut buf = [0u8; 1];
    match inner.peek(&mut buf) {
        Ok(len) => {
            return len == 0;
        },
        Err(e) => {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                return false;
            }
        }
    }

    // no result... try send...

    use std::io::Write;
    match inner.write(&[]) {
        Ok(_) => false,
        Err(e) => {
            e.kind() != std::io::ErrorKind::WouldBlock
        }
    }
}

pub type TcpStreamPoolRaw = ConnPool<SocketAddr, TcpStream>;

#[derive(Debug, Clone)]
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
            raw:
                TcpStreamPoolRaw::new(
                    protocol,
                    remote,
                    ConnManager {
                        connect: tcp_connect,
                        is_closed: tcp_is_closed,
                    },
                ),
        }
    }
}
