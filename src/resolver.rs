use crate::{Account, ACME_TLS_ALPN_NAME};
use async_rustls::rustls::sign::CertifiedKey;
use async_rustls::rustls::{ClientHello, ResolvesServerCert};
use async_std::task::sleep;
use std::error::Error;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

pub struct ResolvesServerCertUsingAcme {
    account: Account,
    certified_key: Mutex<Option<CertifiedKey>>,
}

impl ResolvesServerCertUsingAcme {
    pub fn new(account: Account) -> Arc<ResolvesServerCertUsingAcme> {
        Arc::new(ResolvesServerCertUsingAcme {
            account,
            certified_key: Mutex::new(None),
        })
    }
    pub async fn run(resolver: Arc<ResolvesServerCertUsingAcme>) {
        resolver.get_cert().await.unwrap();
    }
    async fn get_cert(&self) -> Result<(), Box<dyn Error>> {
        let _params = rcgen::CertificateParams::new(vec![]);
        const DOMAIN: &str = "fehrbelliner.ddns.net";
        let order = self.account.new_order(DOMAIN).await?;
        dbg!(&order);
        let auth = self.account.auth(&order.authorizations[0]).await?;
        dbg!(&auth);
        let (challenge, certified_key) = self.account.tls_alpn_01(&auth)?;
        self.certified_key.lock().unwrap().replace(certified_key);
        self.account.challenge(challenge).await?;
        sleep(Duration::from_secs(10)).await;
        dbg!(self.account.auth(&order.authorizations[0]).await?);
        dbg!(self.account.new_order(DOMAIN).await?);
        Ok(())
    }
}

impl ResolvesServerCert for ResolvesServerCertUsingAcme {
    fn resolve(&self, client_hello: ClientHello) -> Option<CertifiedKey> {
        if client_hello.alpn() == Some(&[ACME_TLS_ALPN_NAME]) {
            log::info!("acme-tls/1 validator");
            self.certified_key.lock().unwrap().clone()
        } else {
            log::info!("normal request");
            None
        }
    }
}
