use crate::Directory;
use async_std::task::sleep;
use rustls::sign::CertifiedKey;
use rustls::{ClientHello, ResolvesServerCert};
use std::error::Error;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

#[derive(Default)]
pub struct ResolvesServerCertUsingAcme {
    certified_key: Mutex<Option<CertifiedKey>>,
}

impl ResolvesServerCertUsingAcme {
    pub fn new() -> Arc<ResolvesServerCertUsingAcme> {
        let resolver = Arc::new(ResolvesServerCertUsingAcme::default());
        resolver
    }
    pub async fn run(resolver: Arc<ResolvesServerCertUsingAcme>) {
        resolver.get_cert().await.unwrap();
    }
    async fn get_cert(&self) -> Result<(), Box<dyn Error>> {
        let _params = rcgen::CertificateParams::new(vec![]);
        let dir =
            Directory::discover("https://acme-staging-v02.api.letsencrypt.org/directory").await?;
        let account = dir.create_account().await?;
        const DOMAIN: &str = "fehrbelliner.ddns.net";
        let order = account.new_order(DOMAIN).await?;
        dbg!(&order);
        let auth = account.auth(&order.authorizations[0]).await?;
        dbg!(&auth);
        let (challenge, certified_key) = account.tls_alpn_01(&auth)?;
        self.certified_key.lock().unwrap().replace(certified_key);
        account.challenge(challenge).await?;
        sleep(Duration::from_secs(10));
        dbg!(account.auth(&order.authorizations[0]).await?);
        Ok(())
    }
}

impl ResolvesServerCert for ResolvesServerCertUsingAcme {
    fn resolve(&self, client_hello: ClientHello) -> Option<CertifiedKey> {
        if client_hello.alpn() == Some(&[b"acme-tls/1"]) {
            log::info!("acme-tls/1 validator");
            self.certified_key.lock().unwrap().clone()
        } else {
            log::info!("normal request");
            None
        }
    }
}
