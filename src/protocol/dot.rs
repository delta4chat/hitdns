use crate::*;

pub use async_tls::TlsConnector;

pub type TlsStream =
    async_tls::client::TlsStream<TcpStream>;

pub type TlsSessions = Arc<
    scc::HashMap<
        SocketAddr,
        VecDeque<(u128, Arc<TlsStream>)>,
    >,
>;

/// a 'guard' for TlsStream. once this guard dropping, the inner TLS connection will be push back to shared session list (for reuse it again)
/// Why this exists? because we need to prevent "two async tasks try sending two queries to a single connection at same time"... this often causes confusion
struct TlsStreamGuard {
    id: u128,
    conn: Arc<TlsStream>,
    sess: TlsSessions,
    addr: SocketAddr,
}
impl Drop for TlsStreamGuard {
    fn drop(&mut self) {
        if let Some(mut entry) = self.sess.get(&self.addr)
        {
            entry
                .get_mut()
                .push_front((self.id, self.conn.clone()));
        }
    }
}

impl Deref for TlsStreamGuard {
    type Target = TlsStream;
    fn deref(&self) -> &TlsStream {
        self.conn.as_ref()
    }
}
impl DerefMut for TlsStreamGuard {
    fn deref_mut(&mut self) -> &mut TlsStream {
        Arc::get_mut(&mut self.conn)
            .expect("this is impossible because only one mutable reference can exists at same time")
    }
}

pub struct DNSOverTLS {
    connector: async_tls::TlsConnector,
    sessions: TlsSessions,
    upstream: String,
    _task: smol::Task<()>,
}
impl DNSOverTLS {
    pub async fn new(
        upstream: impl ToString,
        use_hosts: bool,
    ) -> anyhow::Result<Self> {
        let upstream: String = upstream.to_string();
        let addrs: Vec<SocketAddr> = {
            let mut x = vec![];
            if !upstream.contains(":") {
                anyhow::bail!("wrong DoT addr format");
            }
            if let Ok(addr) = upstream.parse() {
                x.push(addr);
            } else {
                if use_hosts {
                    let mut y: Vec<&str> =
                        upstream.split(":").collect();

                    let port: u16 = if let Some(p) =
                        y.pop()
                    {
                        p.parse()?
                    } else {
                        anyhow::bail!("cannot parse DoT upstream: no port number found");
                    };
                    let host: String = y.join(":");

                    if let Some(ips) =
                        HOSTS.lookup(&host).await
                    {
                        for ip in ips.iter() {
                            x.push(SocketAddr::new(
                                *ip, port,
                            ));
                        }
                    } else {
                        anyhow::bail!("cannot parse DoT upstream: a domain name provided, but not found in hosts.txt")
                    }
                } else {
                    anyhow::bail!("cannot parse DoT upstream: a domain name provided but without hosts.txt");
                }
            }
            x
        };

        let connector = async_tls::TlsConnector::new();
        let sessions = Arc::new(scc::HashMap::new());

        for addr in addrs.iter() {
            sessions
                .insert(*addr, VecDeque::new())
                .unwrap();
        }

        // start connection keep-alive watchdog
        let _task =
            smolscale2::spawn(Self::_conn_watchdog(
                connector.clone(),
                sessions.clone(),
            ));

        Ok(Self {
            connector,
            sessions,
            upstream,
            _task,
        })
    }

    async fn _conn_watchdog(
        connector: TlsConnector,
        sessions: TlsSessions,
    ) {
        let mut reconnecting: Vec<SocketAddr> = vec![];
        let mut ret = vec![];
        loop {
            while let Some(addr) = reconnecting.pop() {
                // connecting...
                let tcp_conn = match TcpStream::connect(
                    addr,
                )
                .await
                {
                    Ok(v) => v,
                    Err(err) => {
                        log::warn!("unable connect to DoT upstream({addr:?}): cannot establish TCP connection: {err:?}");
                        continue;
                    },
                };

                match connector
                    .connect(
                        addr.ip().to_string(),
                        tcp_conn,
                    )
                    .await
                {
                    Ok(tls_conn) => {
                        let id = {
                            let rand = fastrand::u64(..);
                            let ptr = core::ptr::addr_of!(
                                tls_conn
                            );

                            (rand as u128) + (ptr as u128)
                        };

                        log::debug!(
              "connected DoT {id}={tls_conn:?}"
            );

                        let tls_conn = Arc::new(tls_conn);

                        if let Some(mut entry) = sessions
                            .get_async(&addr)
                            .await
                        {
                            entry.get_mut().push_back((
                                id, tls_conn,
                            ));
                        }
                    },

                    Err(err) => {
                        log::warn!("unable connect to DoT upstream({addr:?}): TLS handshake failed: {err:?}");
                    },
                } // match connector.connnect
            } // while let Some(addr)

            ret.clear();
            sessions
                .scan_async(|addr, conns| {
                    let mut x = vec![];
                    for conn in conns.iter() {
                        let id = conn.0;
                        let io = conn.1.get_ref().clone();
                        x.push((id, io));
                    }
                    ret.push((*addr, x));
                })
                .await;

            for (addr, io) in ret.iter_mut() {
                if io.len() < 3 {
                    reconnecting.push(*addr);
                    continue;
                }

                for i in 0..io.len() {
                    let (id, io) = &io[i];
                    if let Err(err) =
                        io.peek(&mut [0]).await
                    {
                        log::warn!("session died: addr={addr:?} | io={io:?} | error={err:?}");
                        reconnecting.push(*addr);

                        // remove dead conn
                        sessions
                            .update_async(
                                addr,
                                |_, conns| {
                                    conns.retain(
                                        |conn| {
                                            conn.0 != *id
                                        },
                                    );
                                },
                            )
                            .await;
                    }
                }
            }
            ret.clear();

            smol::Timer::after(Duration::from_secs(1))
                .await;
        } // loop
    }

    async fn _get_conn(
        &self,
    ) -> anyhow::Result<TlsStreamGuard> {
        let mut addrs: Vec<SocketAddr> = vec![];
        self.sessions
            .scan_async(|addr, _| {
                addrs.push(*addr);
            })
            .await;

        while !addrs.is_empty() {
            let n = fastrand::usize(0..addrs.len());
            let addr = addrs.swap_remove(n);

            let idconn: Option<(u128, Arc<TlsStream>)> =
                // Option<Entry>
                self.sessions.get_async(&addr).await
                .ok_or(anyhow::Error::msg("unexpected .sessions no key {addr:?}"))?

                // Entry
                .get_mut()

                // VecDeque
                .pop_back(); // gets newly established connection for more reliability

            if let Some((id, conn)) = idconn {
                return Ok(TlsStreamGuard {
                    id,
                    conn,
                    sess: self.sessions.clone(),
                    addr,
                });
            }
        }

        anyhow::bail!("cannot select DoT server randomly");
    }

    async fn _dns_resolve(
        &self,
        query: &DNSQuery,
    ) -> anyhow::Result<dns::Message> {
        let req: dns::Message = query.try_into()?;

        let req: Vec<u8> = req.to_vec()?;
        let req_len: u16 = req.len() as u16;

        let req_buf: Vec<u8> = req_len
            .to_be_bytes()
            .into_iter()
            .chain(req.into_iter())
            .collect();

        let mut conn = self._get_conn().await?;

        conn.write_all(&req_buf).await?;

        let mut res_len = [0u8; 2];
        conn.read_exact(&mut res_len).await?;

        let res_len: usize =
            u16::from_be_bytes(res_len).into();

        let mut res = vec![0u8; res_len];
        conn.read_exact(&mut res).await?;

        std::mem::drop(conn);

        Ok(dns::Message::from_vec(&res)?)
    }
}

impl DNSResolver for DNSOverTLS {
    fn dns_resolve(
        &self,
        query: &DNSQuery,
    ) -> PinFut<anyhow::Result<dns::Message>> {
        let query = query.clone();
        Box::pin(async move {
            self._dns_resolve(&query).await
        })
    }

    fn dns_upstream(&self) -> String {
        self.upstream.clone()
    }

    fn dns_protocol(&self) -> &str {
        "DNS over TLS over TCP"
    }

    fn dns_metrics(&self) -> PinFut<DNSMetrics> {
        // TODO
        todo!()
    }
}
