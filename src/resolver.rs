use rustls::sign::CertifiedKey;
use rustls::{ClientHello, ResolvesServerCert};
use std::sync::Arc;

pub struct ResolvesServerCertUsingAcme {}

impl ResolvesServerCertUsingAcme {
    pub fn new() -> Arc<dyn ResolvesServerCert> {
        Arc::new(ResolvesServerCertUsingAcme {})
    }
}

impl ResolvesServerCert for ResolvesServerCertUsingAcme {
    fn resolve(&self, client_hello: ClientHello) -> Option<CertifiedKey> {
        if client_hello.alpn() == Some(&[b"acme-tls/1"]) {
            log::info!("acme-tls/1 validator");
            return None;
        }
        {
            log::info!("normal request");
        }
        None
    }
}
