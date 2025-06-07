use crate::{
    *,
    protocol::pool::*,
};

pub fn rust_crypto_provider() -> Arc<rustls::CryptoProvider> {
    static PROVIDER: Lazy<Arc<rustls::CryptoProvider>> =
        Lazy::new(|| { Arc::new(rustls_rustcrypto::provider()) });

    PROVIDER.clone()
}

pub fn anypki_filtered_mozilla() -> Arc<rustls::RootCertStore> {
    static RCS: Lazy<Arc<rustls::RootCertStore>> = Lazy::new(|| {
        let mut roots = mozilla_root_ca::rustls_trust_anchor_list();
        anypki::DefaultRules::mitm_threats_extra().retain(&mut roots);
        roots.shrink_to_fit();
        Arc::new(rustls::RootCertStore { roots })
    });

    RCS.clone()
}

pub fn tls_config() -> rustls::ClientConfig {
    rustls::ClientConfig::builder_with_provider(rustls_crypto_provider())
        .with_safe_default_protocol_versions().unwrap()
        .with_root_certificates(anypki_filtered_mozilla())
        .with_no_client_auth()
}

pub struct TlsConnectInfo {
    pub addr: SocketAddr,
    pub sni: Option<rustls::pki_types::DnsName>,
    pub config: Arc<rustls::ClientConfig>,
}

pub fn tls_connect(info: &TlsConnectInfo) -> PinFut<std::io::Result<TlsStream>> {
    let addr = info.addr;
    let config = info.config.clone();
    let server_name =
        if let Some(sni) = info.sni.as_ref() {
            sni.clone()
        } else {
            rustls::pki_types::ServerName::IpAddress(addr.ip().into())
        }
    let server_name = info.sni.clone();
    Box::pin(async move {
        let tcp_stream = TcpStream::connect(addr).await?;
        let tls_connector = TlsConnector::from(config);
        tls_connector.connect(sni).await
    })
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

impl TlsStreamPool {
    pub fn new(protocol: &str, info: TlsConnectInfo) -> Self {
        Self {
            raw: TcpStreamPoolRaw::new(protocol, info, tls_connect),
        }
    }
}
