use crate::{Account, Auth, Directory, Identifier, Order, ACME_TLS_ALPN_NAME};
use async_rustls::rustls::sign::{any_ecdsa_type, CertifiedKey};
use async_rustls::rustls::Certificate as RustlsCertificate;
use async_rustls::rustls::{ClientHello, PrivateKey, ResolvesServerCert};
use async_std::task::sleep;
use futures::future::try_join_all;
use rcgen::{CertificateParams, DistinguishedName};
use std::collections::BTreeMap;
use std::error::Error;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

pub struct ResolvesServerCertUsingAcme {
    cert_key: Mutex<Option<CertifiedKey>>,
    auth_keys: Mutex<BTreeMap<String, CertifiedKey>>,
}

impl ResolvesServerCertUsingAcme {
    pub fn new() -> Arc<ResolvesServerCertUsingAcme> {
        Arc::new(ResolvesServerCertUsingAcme {
            cert_key: Mutex::new(None),
            auth_keys: Mutex::new(BTreeMap::new()),
        })
    }
    pub async fn run(&self, directory_url: impl AsRef<str>, domains: Vec<String>) {
        self.order(directory_url, &domains).await.unwrap();
    }
    async fn order(
        &self,
        directory_url: impl AsRef<str>,
        domains: &Vec<String>,
    ) -> Result<(), Box<dyn Error>> {
        let mut params = CertificateParams::new(domains.clone());
        params.distinguished_name = DistinguishedName::new();
        let cert = rcgen::Certificate::from_params(params).unwrap();
        let pk = PrivateKey(cert.serialize_private_key_der());
        let directory = Directory::discover(directory_url).await?;
        let account = directory.create_account(Some("test-persist")).await?;
        let mut order = account.new_order(domains.clone()).await?;
        loop {
            order = match order {
                Order::Pending {
                    authorizations,
                    finalize,
                } => {
                    let auth_futures = authorizations
                        .iter()
                        .map(|url| self.authorize(&account, url));
                    try_join_all(auth_futures).await?;
                    log::info!("completed all authorizations");
                    Order::Ready { finalize }
                }
                Order::Ready { finalize } => {
                    log::info!("sending csr");
                    let csr = cert.serialize_request_der().unwrap();
                    account.finalize(finalize, csr).await?
                }
                Order::Valid { certificate } => {
                    log::info!("download certificate");
                    let cert = account.certificate(certificate).await?;
                    let cert = pem::parse(cert)?.contents;
                    let cert_key = CertifiedKey::new(
                        vec![RustlsCertificate(cert)],
                        Arc::new(any_ecdsa_type(&pk).unwrap()),
                    );
                    self.cert_key.lock().unwrap().replace(cert_key);
                    log::info!("Done");
                    return Ok(());
                }
                Order::Invalid => unimplemented!("invalid order"),
            }
        }
    }
    async fn authorize(&self, account: &Account, url: &String) -> Result<(), Box<dyn Error>> {
        let (domain, challenge_url) = match account.auth(url).await? {
            Auth::Pending {
                identifier,
                challenges,
            } => {
                let Identifier::Dns(domain) = identifier;
                log::info!("trigger challenge for {}", &domain);
                let (challenge, auth_key) = account.tls_alpn_01(&challenges, domain.clone())?;
                self.auth_keys
                    .lock()
                    .unwrap()
                    .insert(domain.clone(), auth_key);
                account.challenge(&challenge.url).await?;
                (challenge.url.clone(), domain)
            }
            Auth::Valid => return Ok(()),
            _ => unimplemented!("bad auth"),
        };
        for i in 0u64..5 {
            sleep(Duration::from_secs(1 << i)).await;
            match account.auth(url).await? {
                Auth::Pending { .. } => {
                    log::info!("authorization for {} still pending", &domain);
                    account.challenge(&challenge_url).await?
                }
                Auth::Valid => return Ok(()),
                _ => unimplemented!("bad auth"),
            }
        }
        unimplemented!("timeout")
    }
}

impl ResolvesServerCert for ResolvesServerCertUsingAcme {
    fn resolve(&self, client_hello: ClientHello) -> Option<CertifiedKey> {
        if client_hello.alpn() == Some(&[ACME_TLS_ALPN_NAME]) {
            let domain = client_hello.server_name().unwrap().to_owned();
            let domain: String = AsRef::<str>::as_ref(&domain).to_string();
            self.auth_keys.lock().unwrap().get(&domain).cloned()
        } else {
            self.cert_key.lock().unwrap().clone()
        }
    }
}
