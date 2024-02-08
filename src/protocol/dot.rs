use crate::*;

pub type TlsStream =async_tls::client::TlsStream<TcpStream>;
pub struct DNSOverTLS {
    connector: async_tls::TlsConnector,
    sessions: Arc<scc::HashMap<
                SocketAddr, Vec<(u128, TlsStream)>
            >>,
    upstream: String,
    _task: smol::Task<()>,
}
impl DNSOverTLS {
    pub async fn new(
        upstream: impl ToString,
        use_hosts: bool,
    ) -> anyhow::Result<Self> {
        let connector = async_tls::TlsConnector::new();
        let sessions = Arc::new(scc::HashMap::new());

        let upstream: String = upstream.to_string();
        let addrs: Vec<SocketAddr> = {
            let mut x = vec![];
            if ! upstream.contains(":") {
                anyhow::bail!("wrong DoT addr format");
            }
            if let Ok(addr) = upstream.parse() {
                x.push(addr);
            } else {
                if use_hosts {
                    let mut y: Vec<&str> =
                        upstream.split(":").collect();

                    let port: u16 =
                        if let Some(p) = y.pop() {
                            p.parse()?
                        } else {
                            anyhow::bail!("cannot parse DoT upstream: no port number found");
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
                        anyhow::bail!("cannot parse DoT upstream: a domain name provided, but not found in hosts.txt")
                    }
                } else {
                    anyhow::bail!("cannot parse DoT upstream: a domain name provided but without hosts.txt");
                }
            }
            x
        };

        for addr in addrs.iter() {
            sessions.insert(*addr, vec![]).unwrap();
        }

        let _task = {
            let connector = connector.clone();
            let sessions = sessions.clone();
            smolscale2::spawn(async move {
                let mut reconnecting: Vec<SocketAddr> = vec![];
                let mut ret = vec![];
                loop {
                    while let Some(addr) = reconnecting.pop() {
                        // connecting...
                        let tcp_conn =
                            match
                            TcpStream::connect(addr).await
                            {
                                Ok(v) => v,
                                Err(err) => {
                                    log::warn!("unable connect to DoT upstream({addr:?}): cannot establish TCP connection: {err:?}");
                                    continue;
                                }
                            };

                        match
                            connector.connect(
                                addr.ip().to_string(),
                                tcp_conn
                            ).await
                        {
                            Ok(tls_conn) => {
                                let id =
                                    fastrand::u128(..);
                                log::info!("connected DoT {id}={tls_conn:?}");
                                if let Some(mut entry) =
                                    sessions
                                        .get_async(&addr)
                                        .await
                                {
                                    entry.get_mut()
                                        .push(
                                            (id, tls_conn)
                                        );
                                }
                            },

                            Err(err) => {
                                log::warn!("unable connect to DoT upstream({addr:?}): TLS handshake failed: {err:?}");
                            }
                        }
                    }

                    ret.clear();
                    sessions.scan_async(|addr, conns| {
                        let mut x = vec![];
                        for conn in conns.iter() {
                            let id = conn.0;
                            let io =
                                conn.1.get_ref().clone();
                            x.push((id, io));
                        }
                        ret.push( (*addr, x) );
                    }).await;

                    for (addr, io) in ret.iter_mut() {
                        if io.is_empty() {
                            reconnecting.push(*addr);
                        } else {
                            for i in 0 .. io.len() {
                                let (id, io) = &io[i];
                                if let Err(err) =
                                    io.peek(&mut [0]).await
                                {
                                    log::warn!("session died: addr={addr:?} | io={io:?} | error={err:?}");
                                    reconnecting.push(*addr);
                                    // remove dead conn
                                    sessions.update_async(
                                        addr,
                                        |_, conns| {
                                            conns.retain(|conn| { conn.0 != *id });
                                        }
                                    ).await;
                                }
                            }
                        }
                    }
                    ret.clear();

                    smol::Timer::after(
                        Duration::from_secs(1)
                    ).await;
                }
            })
        };
        Ok(Self {
            connector,
            sessions,
            upstream,
            _task,
        })
    }

    async fn _dns_resolve(&self, query: &DNSQuery)
        -> anyhow::Result<dns::Message>
    {
        let msg = {
            let msg: dns::Message = query.try_into()?;
            let msg: Vec<u8> = msg.to_vec()?;
            let mut buf = msg.len().to_be_bytes().to_vec();
            buf.extend(msg);
            buf
        };

        let mut all_conns = vec![];
        self.sessions.scan_async(|_, conns| {
            for conn in conns.iter() {
                all_conns.push( conn.1.get_ref().clone() );
            }
        }).await;

        let mut res_len = [0u8; 2];
        let mut res;
        while ! all_conns.is_empty() {
            let i = fastrand::usize(0 .. all_conns.len() );
            let mut conn = all_conns.swap_remove(i);
            if let Some(Ok(_)) =
                conn.write_all(&msg)
                .timeout(Duration::from_secs(2))
                .await
            {
                if let Some(tmp) =
                    conn.read_exact(&mut res_len)
                    .timeout(Duration::from_secs(3))
                    .await
                {
                    if tmp.is_err() {
                        log::warn!("DoT upstream error: reading response length: {tmp:?}");
                        continue;
                    }
                } else {
                    continue;
                }

                let res_len: usize =
                    u16::from_be_bytes(res_len).into();
                res = vec![0u8; res_len];

                if let Some(tmp) =
                    conn.read_exact(&mut res)
                    .timeout(Duration::from_secs(5))
                    .await
                {
                    if tmp.is_err() {
                        log::warn!("DoT upstream error: reading response body: {tmp:?}");
                        continue;
                    }
                } else {
                    continue;
                }

                return Ok(dns::Message::from_vec(&res)?);
            }
        }

        anyhow::bail!("all DoT upstream timed out!")
    }
}
impl DNSResolver for DNSOverTLS {
    fn dns_resolve(&self, query: &DNSQuery)
        -> PinFut<anyhow::Result<dns::Message>>
    {
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