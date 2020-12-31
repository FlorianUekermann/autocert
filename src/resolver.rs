use crate::{Account, Identifier, Status, ACME_TLS_ALPN_NAME};
use async_rustls::rustls::sign::CertifiedKey;
use async_rustls::rustls::{ClientHello, ResolvesServerCert};
use async_std::task::sleep;
use rcgen::CertificateParams;
use std::collections::BTreeMap;
use std::error::Error;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

pub struct ResolvesServerCertUsingAcme {
    domain: String,
    account: Account,
    authorization_keys: Mutex<BTreeMap<String, CertifiedKey>>,
}

impl ResolvesServerCertUsingAcme {
    pub fn new(account: Account, domain: String) -> Arc<ResolvesServerCertUsingAcme> {
        Arc::new(ResolvesServerCertUsingAcme {
            domain,
            account,
            authorization_keys: Mutex::new(BTreeMap::new()),
        })
    }
    pub async fn run(resolver: Arc<ResolvesServerCertUsingAcme>) {
        resolver.order_next().await.unwrap();
    }
    pub(crate) async fn order_next(&self) -> Result<(), Box<dyn Error>> {
        let order = self.account.new_order(&self.domain).await?;
        dbg!(&order);
        match order.status {
            Status::Pending => {
                for auth_url in order.authorizations {
                    let auth = self.account.auth(auth_url).await?;
                    let (challenge, certified_key) = self.account.tls_alpn_01(&auth)?;
                    let Identifier::Dns(domain) = &auth.identifier;
                    self.authorization_keys
                        .lock()
                        .unwrap()
                        .insert(domain.clone(), certified_key);
                    self.account.challenge(challenge).await?;
                    dbg!(&auth);
                }
            }
            Status::Valid => {}
            Status::Invalid => unimplemented!(),
            Status::Ready => {
                self.account.finalize(order.finalize, self.csr()).await?;
                let order = self.account.new_order(&self.domain).await?;
                dbg!(order);
            }
        }
        sleep(Duration::from_secs(10)).await;
        let order = self.account.new_order(&self.domain).await?;
        dbg!(&order);
        Ok(())
    }
    fn csr(&self) -> Vec<u8> {
        let params = CertificateParams::new(vec![self.domain.clone()]);
        let cert = rcgen::Certificate::from_params(params).unwrap();
        std::fs::write("./crs.csr", cert.serialize_pem().unwrap()).unwrap();
        cert.serialize_request_der().unwrap()
    }
}

impl ResolvesServerCert for ResolvesServerCertUsingAcme {
    fn resolve(&self, client_hello: ClientHello) -> Option<CertifiedKey> {
        if client_hello.alpn() == Some(&[ACME_TLS_ALPN_NAME]) {
            let domain = client_hello.server_name().unwrap().to_owned();
            let domain: String = AsRef::<str>::as_ref(&domain).to_string();
            self.authorization_keys
                .lock()
                .unwrap()
                .get(&domain)
                .cloned()
        } else {
            log::info!("normal request");
            None
        }
    }
}
