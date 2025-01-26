// NOT FINISHED
//
// TODO: a generic connection manager for DoT and DoQ and DNSCrypt

use crate::*;

#[derive(Clone)]
pub(crate) struct Pool<Conn>
where
    Conn: AsyncReadExt+AsyncWriteExt+Send+Sync+Clone
{
    pub connector: Arc<dyn Fn(SocketAddr) -> PinFut<Arc<Conn>>>,
    pub min_conn: u16,
    pub max_conn: u16,
    pub conns: scc2::HashMap<SocketAddr, VecDeque<Arc<Conn>>>,
}

impl<Conn: AsyncReadExt+AsyncWriteExt+Send+Sync+Clone> Pool<Conn> {
    pub async fn new(
        remote: impl ToString,
        connector: Arc<dyn Fn(SocketAddr) -> PinFut<Arc<Conn>>>
    ) -> anyhow::Result<Self> {
        let remote: String = remote.to_string();
        if ! remote.contains(":") {
            anyhow::bail!("invalid remote {remote:?}: no port number found");
        }

        let conns = scc2::HashMap::new();

        if let Ok(addr) = remote.parse() {
            let _ = conns.insert_async(addr, Default::default()).await;
        } else {
            let mut remote: Vec<&str> = remote.split(":").collect();

            let port: u16 = remote.pop().unwrap().parse()?;

            let host: String = remote.join(":");

            let ips =
                match HOSTS.lookup(&host).await {
                    Some(v) => v,
                    None => {
                        anyhow::bail!("provided domain {host:?} does not found in hosts.txt");
                    }
                };
            for ip in ips.into_iter() {
                let addr = SocketAddr::new(ip, port);
                let _ = conns.insert_async(
                    addr,
                    Default::default()
                ).await;
            }
        }

        let this = Self {
            connector,
            min_conn: conns.len().min(3) as u16,
            max_conn: 10,
            conns,
        };

        {
            let this = this.clone();
            smolscale2::spawn(async move {
                this._watchdog().await;
            }).detach();
        }

        Ok(this)
    }

    async fn _watchdog(&self) {
        let mut zzz = false;
        let interval = Duration::from_secs(3);
        loop {
            if zzz {
                smol::Timer::after(interval).await;
            } else {
                zzz = true;
            }

            let mut n: usize = 0;
            let mut addrs = vec![];

            self.conns.scan_async(|addr, conns| {
                addrs.push(*addr);
                n += conns.len();
            }).await;

            if n < (self.min_conn as usize) {
                let addr = addrs[fastrand::usize(0..addrs.len())];
                self.conns.get_async(&addr)
                    .await.unwrap()
                    .get_mut()

                    .push_front(
                        (self.connector)(addr).await
                    );
            }
        }
    }
}
