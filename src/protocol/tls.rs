use crate::{
    *,
    protocol::pool::*,
};

pub fn rust_crypto_provider() -> Arc<rustls::crypto::CryptoProvider> {
    static PROVIDER: Lazy<Arc<rustls::crypto::CryptoProvider>> =
        Lazy::new(|| { Arc::new(rustls_rustcrypto::provider()) });

    PROVIDER.clone()
}

pub fn anypki_filtered_mozilla() -> Arc<rustls::RootCertStore> {
    static RCS: Lazy<Arc<rustls::RootCertStore>> = Lazy::new(|| {
        Arc::new(
            rustls::RootCertStore {
                roots:
                    anypki::DefaultRules::mitm_threats_extra()
                    .apply(mozilla_root_ca::RUSTLS_CERTIFICATE_DER_LIST.iter())
                    .map(|cd| {
                        webpki::anchor_from_trusted_cert(cd).expect("unexpected invalid certificate")
                    })
                    .collect()
            }
        )   
    });

    RCS.clone()
}

pub fn tls_config(alpn: &[u8]) -> rustls::ClientConfig {
    let alpn_len = alpn.len();
    if alpn_len > 255 {
        panic!("ALPN length is too long!");
    }

    let mut config =
        rustls::ClientConfig::builder_with_provider(rust_crypto_provider())
        .with_safe_default_protocol_versions().unwrap()
        .with_root_certificates(anypki_filtered_mozilla())
        .with_no_client_auth();

    config.alpn_protocols =
        if alpn_len == 0 {
            vec![]
        } else {
            vec![ alpn.to_vec() ]
        };

    config
}

#[derive(Debug)]
pub struct TlsConnectInfo {
    pub addr: SocketAddr,
    pub sni: Option<rustls::pki_types::DnsName<'static>>,
    pub config: Arc<rustls::ClientConfig>,
}

impl Hash for TlsConnectInfo {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.addr.hash(state);
        self.sni.hash(state);
        // no need to hash .config
    }
}
impl PartialEq for TlsConnectInfo {
    fn eq(&self, other: &Self) -> bool {
        self.addr == other.addr
        &&
        self.sni == other.sni
        /*
        &&
        self.config.ptr_eq(&other.config)
        */
    }
}
impl Eq for TlsConnectInfo {}

pub fn tls_connect(info: &Arc<TlsConnectInfo>) -> PinFut<std::io::Result<TlsStream<TcpStream>>> {
    let addr = info.addr;
    let config = info.config.clone();
    let server_name =
        if let Some(sni) = info.sni.as_ref() {
            rustls::pki_types::ServerName::DnsName(sni.clone())
        } else {
            rustls::pki_types::ServerName::IpAddress(addr.ip().into())
        };
    Box::pin(async move {
        let tcp_stream = TcpStream::connect(addr).await?;
        let tls_connector = TlsConnector::from(config);
        tls_connector.connect(server_name, tcp_stream).await
    })
}

pub type TlsStreamPoolRaw =
    ConnPool<
        Arc<TlsConnectInfo>,
        TlsStream<TcpStream>,
        fn(&Arc<TlsConnectInfo>)->PinFut<std::io::Result<TlsStream<TcpStream>>>
    >;

#[derive(Debug, Clone)]
pub struct TlsStreamPool {
    raw: TlsStreamPoolRaw,
}

impl Deref for TlsStreamPool {
    type Target = TlsStreamPoolRaw;

    fn deref(&self) -> &TlsStreamPoolRaw {
        &(self.raw)
    }
}

impl TlsStreamPool {
    pub fn new(protocol: &str, info: Arc<TlsConnectInfo>) -> Self {
        Self {
            raw: TlsStreamPoolRaw::new(protocol, info, tls_connect),
        }
    }
}
