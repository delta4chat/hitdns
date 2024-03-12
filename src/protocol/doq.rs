use crate::*;

type QuicConns =
    Arc<scc::HashMap<u128, Arc<quinn::Connection>>>;

#[derive(Debug, Clone)]
pub struct DNSOverQUIC {
    addr: SocketAddr, // address of DoQ server

    endpoint: quinn::Endpoint,
    conns: QuicConns,

    _task: Arc<smol::Task<()>>,
}

impl DNSOverQUIC {
    pub fn new(
        addr: impl ToString,
    ) -> anyhow::Result<Self> {
        let addr: String = addr.to_string();
        let addr: SocketAddr = addr.parse()?;

        let transport_config = {
            let mut tc: quinn::TransportConfig =
                Default::default();

            tc.initial_rtt(Duration::from_millis(200));
            tc.initial_mtu(1200);
            tc.keep_alive_interval(Some(
                Duration::from_secs(10),
            ));
            tc.max_idle_timeout(Some(
                Duration::from_secs(3600).try_into()?,
            ));
            tc.max_tlps(15);

            Arc::new(tc)
        };

        let endpoint_config = {
            let mut ec: quinn::EndpointConfig =
                Default::default();

            ec.max_udp_payload_size(1200)?;

            ec
        };

        let client_config =
            quinn::ClientConfig::with_root_certificates({
                let roots: Vec<rustls::OwnedTrustAnchor> =
                    webpki_roots::TLS_SERVER_ROOTS
                    .iter()
                    .map(|x|{
                        let subject = x.subject.to_vec();
                        let spki =
                            x.subject_public_key_info
                            .to_vec();
                        let name_const =
                            match &x.name_constraints {
                                Some(v) => {
                                    Some( v.to_vec() )
                                },
                                _ => None,
                            };
                        rustls::OwnedTrustAnchor::
                        from_subject_spki_name_constraints(
                            subject,
                            spki,
                            name_const,
                        )
                    })
                    .collect();
                rustls::RootCertStore { roots }
            })
            .version(1)
            .transport_config(transport_config)
            .to_owned();

        let udp_socket = std::net::UdpSocket::bind(
            if addr.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            },
        )?;

        let mut endpoint = quinn::Endpoint::new(
            endpoint_config,
            None,
            udp_socket,
            Arc::new(quinn::AsyncStdRuntime),
        )?;
        endpoint.set_default_client_config(client_config);

        let conns = Arc::new(scc::HashMap::new());
        let _task = Arc::new(smolscale2::spawn(
            Self::_conn_task(
                endpoint.clone(),
                conns.clone(),
                addr,
            ),
        ));

        Ok(Self {
            addr,

            endpoint,
            conns,

            _task,
        })
    }

    async fn _conn_task(
        endpoint: quinn::Endpoint,
        conns: QuicConns,
        addr: SocketAddr,
    ) {
        let mut zzz = false;
        loop {
            if zzz {
                smol::Timer::after(Duration::from_secs(
                    1,
                ));
            } else {
                zzz = true;
            }

            if conns.len() >= 1 {
                continue;
            }

            let connecting =
                match
                    endpoint.connect(
                        addr, // IP:port
                        &addr.ip().to_string() // TLS SNI
                    )
                    .context("unable to start a process for connecting to QUIC remote host")
                    .log_error()
                {
                    Ok(v) => v,
                    Err(_) => {
                        continue;
                    }
                };

            if let Ok(conn) = connecting
                .await
                .context(
                    "unable connect to remote DoQ server",
                )
                .log_warn()
            {
                let ptr =
                    core::ptr::addr_of!(conn) as u128;

                let conn = Arc::new(conn);

                let mut id: u128 = 0;
                while let Err(_) = conns
                    .insert_async(id, conn.clone())
                    .await
                {
                    id = fastrand::u64(..) as u128;
                    id += ptr;
                }

                log::debug!("connected to DoQ upstream! id={id} / conn={conn:?}");
            }
        } // loop
    } // async fn _conn_task()

    async fn _dns_resolve(
        &self,
        query: &DNSQuery,
    ) -> anyhow::Result<dns::Message> {
        let req: dns::Message = query.try_into()?;
        let req_msg: Vec<u8> = {
            let msg = req.to_vec()?;
            let len = msg.len() as u16;

            len.to_be_bytes()
                .into_iter()
                .chain(msg.into_iter())
                .collect()
        };

        let mut maybe_conn_entry = None;
        for _ in 0..10 {
            maybe_conn_entry =
                self.conns.first_entry_async().await;
            if maybe_conn_entry.is_some() {
                break;
            }
        }
        let conn_entry = match maybe_conn_entry {
            Some(v) => v,
            _ => {
                anyhow::bail!("no QUIC connections");
            },
        };

        let id: u128 = *conn_entry.key();
        let conn = conn_entry.get();

        let (mut stream_tx, mut stream_rx) =
            conn.open_bi().await?;

        stream_tx.write_all(&req_msg).await?;

        let mut res_len = [0u8; 2];
        stream_rx.read_exact(&mut res_len).await?;

        let res_len: usize =
            u16::from_be_bytes(res_len).into();

        let mut res = vec![0u8; res_len];
        stream_rx.read_exact(&mut res).await?;

        Ok(dns::Message::from_vec(&res)?)
    }
}

impl DNSResolver for DNSOverQUIC {
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
        self.addr.to_string()
    }

    fn dns_protocol(&self) -> &str {
        "DNS over QUIC(v1) over UDP"
    }

    fn dns_metrics(&self) -> PinFut<DNSMetrics> {
        todo!()
    }
}
