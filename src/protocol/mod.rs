// doh.rs
pub mod doh;
pub use doh::*;

//pub mod pool; // compile error

// dot.rs
#[cfg(feature = "dot")]
pub mod dot;
#[cfg(feature = "dot")]
pub use dot::*;

// doq.rs
#[cfg(feature = "doq")]
pub mod doq;
#[cfg(feature = "doq")]
pub use doq::*;

use crate::*;
pub static RUSTLS_CRYPTO_PROVIDER: Lazy<Arc<rustls::crypto::CryptoProvider>> = Lazy::new(|| {
    use rustls::CipherSuite::*;

    let mut cp = rustls::crypto::ring::default_provider();
    let cs = &mut cp.cipher_suites;

    let ecdsa_chacha = [
        TLS13_CHACHA20_POLY1305_SHA256,
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    ];
    let rsa_chacha = [
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ];

    let ecdsa_aes = [
        TLS13_AES_256_GCM_SHA384,
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,

        TLS13_AES_128_GCM_SHA256,
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    ];
    let rsa_aes = [
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    ];

    let orig_cs = cs.clone(); // [TLS13_AES_256_GCM_SHA384, TLS13_AES_128_GCM_SHA256, TLS13_CHACHA20_POLY1305_SHA256, TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256]
    eprintln!("{orig_cs:?}");
    cs.clear();


    let chacha_len = ecdsa_chacha.len() + if HITDNS_OPT.tls_rsa { rsa_chacha.len() } else { 0 };
    //let aes_len = ecdsa_aes.len() + if HITDNS_OPT.tls_rsa { rsa_aes.len() } else { 0 };

    for i in 0..2 {
        for scs in orig_cs.iter() {
            if cs.contains(scs) {
                continue;
            }

            let s = scs.suite();

            if ecdsa_chacha.contains(&s) {
                cs.push(*scs);
                continue;
            }
            if HITDNS_OPT.tls_rsa && rsa_chacha.contains(&s) {
                cs.push(*scs);
                continue;
            }


            if i == 0 && cs.len() < chacha_len {
                continue;
            }

            if HITDNS_OPT.tls_aes {
                if ecdsa_aes.contains(&s) {
                    cs.push(*scs);
                    continue;
                }
                if HITDNS_OPT.tls_rsa && rsa_aes.contains(&s) {
                    cs.push(*scs);
                    continue;
                }
            }
        }
    }
    assert!(cs.len() >= 1);
    eprintln!("{cs:?}");

    cp.clone().install_default().unwrap();
    Arc::new(cp)
});
pub static RUSTLS_CLIENT_CONFIG: Lazy<rustls::ClientConfig> = Lazy::new(|| {
    rustls::ClientConfig::builder_with_provider(RUSTLS_CRYPTO_PROVIDER.clone())
    .with_safe_default_protocol_versions().unwrap()
    .with_webpki_verifier({
        let mut root_certs = rustls_native_certs::load_native_certs().certs;
        anypki::DefaultRules::mitm_threats_extra().retain(&mut root_certs);

        let mut rcs = rustls::RootCertStore::empty();
        for cert in root_certs.into_iter() {
            let _ = rcs.add(cert).log_error();
        }
        let scvb = rustls::client::WebPkiServerVerifier::builder(Arc::new(rcs));
        scvb.build().unwrap()
    })
    .with_no_client_auth()
});
