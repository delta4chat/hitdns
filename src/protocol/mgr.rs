// NOT FINISHED
//
// TODO: a generic connection manager for DoT and DoQ and DNSCrypt

pub trait Conn: AsyncReadExt + AsyncWriteExt {
}

/// a factory function for building "dyn Conn"
pub type ConnBuilder =
    dyn FnMut(SocketAddr) ->
        PinFut<
            anyhow::Result<
                Arc<dyn Conn>
            >
        >;

/// Connection Manager
pub(crate) struct ConnMgr {
    connector: ConnBuilder,

    min_conn: u16,
    max_conn: u16,
    conns: scc::HashMap<
        SocketAddr, VecDeque<Arc<dyn Conn>>
    >,
    interval: Duration,

    _task: Option<smol::Task<()>>,
}

impl ConnMgr {
    pub(crate) async fn new(
        remotes: impl ToString,
        connector: ConnBuilder,
    ) -> anyhow::Result<Self> {
        let addrs: String = remotes.to_string();
        let addrs: Vec<SocketAddr> = {
            let mut x = vec![];
            if ! remotes.contains(":") {
                anyhow::bail!("wrong socket address format");
            }
            if let Ok(addr) = remotes.parse() {
                // 'remotes' is a SocketAddr
                // just use it without resolving
                x.push(addr);
            } else {
                // 'remotes' maybe a [domain:port] pair.
                // try resolve it (hosts.txt)

                let mut y: Vec<&str> =
                    upstream.split(":").collect();

                let port: u16 =
                    if let Some(p) = y.pop() {
                        p.parse()?
                    } else {
                        anyhow::bail!("cannot parse remote address: no port number found");
                    };
                let host: String = y.join(":");

                if let Some(ips) =
                    HOSTS.lookup(&host).await
                {
                    for ip in ips.iter() {
                        x.push(
                            SocketAddr::new(*ip, port)
                        );
                    }
                } else {
                    anyhow::bail!("cannot parse remote address: a domain name provided, but not found in hosts.txt")
                }
            }
            x
        };

        let conns = scc::HashMap::new();
        for addr in addrs.iter() {
            conns.insert_async(
                addr,
                VecDeque::new()
            ).await.unwrap();
        }

        let mut this = Self {
            connector,
            min_conn: 3,
            max_conn: 10,
            conns,
            interval: Duration::from_secs(1),

            _task: None,
        };

        this._task = Some(
            smolscale2::spawn(this._watchdog())
        );
        Ok(this)
    }

    async fn _watchdog(&self) {
        let mut reconnecting: Vec<SocketAddr> = vec![];
        let mut ret;
        loop {
            while let Some(addr) = reconnecting.pop() {
                ret = (self.connector)(addr).await;
                if let Ok(conn) = ret {
                    let id = {
                        let rand = fastrand::u64(..);
                        let ptr =core::ptr::addr_of!(conn);
                        (rand as u128) + (ptr as u128)
                    };

                    // scc::Entry
                    self.conns
                    .get_async(addr).await.unwrap()
                    .get_mut()
                    // VecDeque
                    .push_back( (id, conn) );
                }
            }

            self.conns.scan_async(|addr, conns|{
                if conns.len() < self.min_conns {
                    reconnecting.push(addr);
                    return;
                }
                /*
                for conn in conns.iter() {
                    if conn.peek(&mut [0]).await.is_err() {
                        reconnecting.push(addr);
                        return;
                    }
                }
                */
            }).await;

            smol::Timer::after(self.interval);
        }
    }
}
