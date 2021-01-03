use crate::acme::{Account, AcmeError, Auth, Directory, Identifier, Order, ACME_TLS_ALPN_NAME};
use async_rustls::rustls::sign::{any_ecdsa_type, CertifiedKey};
use async_rustls::rustls::Certificate as RustlsCertificate;
use async_rustls::rustls::{ClientHello, PrivateKey, ResolvesServerCert};
use async_std::task::sleep;
use futures::future::try_join_all;
use pem::PemError;
use rcgen::{CertificateParams, DistinguishedName, RcgenError, PKCS_ECDSA_P256_SHA256};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use thiserror::Error;

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
        match self.order(directory_url, &domains).await {
            Ok(_) => log::info!("successfully ordered certificate"),
            Err(err) => log::error!("ordering certificate failed: {}", err),
        };
    }
    async fn order(
        &self,
        directory_url: impl AsRef<str>,
        domains: &Vec<String>,
    ) -> Result<(), OrderError> {
        let mut params = CertificateParams::new(domains.clone());
        params.distinguished_name = DistinguishedName::new();
        params.alg = &PKCS_ECDSA_P256_SHA256;
        let cert = rcgen::Certificate::from_params(params)?;
        let pk = any_ecdsa_type(&PrivateKey(cert.serialize_private_key_der())).unwrap();
        let directory = Directory::discover(directory_url).await?;
        let account = Account::load_or_create(directory, Some("test-persist")).await?;
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
                    let csr = cert.serialize_request_der()?;
                    account.finalize(finalize, csr).await?
                }
                Order::Valid { certificate } => {
                    log::info!("download certificate");
                    let cert = account.certificate(certificate).await?;
                    let cert = pem::parse(cert)?.contents;
                    let cert_key = CertifiedKey::new(vec![RustlsCertificate(cert)], Arc::new(pk));
                    self.cert_key.lock().unwrap().replace(cert_key);
                    log::info!("Done");
                    return Ok(());
                }
                Order::Invalid => return Err(OrderError::BadOrder(order)),
            }
        }
    }
    async fn authorize(&self, account: &Account, url: &String) -> Result<(), OrderError> {
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
            auth => return Err(OrderError::BadAuth(auth)),
        };
        for i in 0u64..5 {
            sleep(Duration::from_secs(1 << i)).await;
            match account.auth(url).await? {
                Auth::Pending { .. } => {
                    log::info!("authorization for {} still pending", &domain);
                    account.challenge(&challenge_url).await?
                }
                Auth::Valid => return Ok(()),
                auth => return Err(OrderError::BadAuth(auth)),
            }
        }
        Err(OrderError::TooManyAttemptsAuth(domain))
    }
}

impl ResolvesServerCert for ResolvesServerCertUsingAcme {
    fn resolve(&self, client_hello: ClientHello) -> Option<CertifiedKey> {
        if client_hello.alpn() == Some(&[ACME_TLS_ALPN_NAME]) {
            match client_hello.server_name() {
                None => {
                    log::debug!("client did not supply SNI");
                    None
                }
                Some(domain) => {
                    let domain = domain.to_owned();
                    let domain: String = AsRef::<str>::as_ref(&domain).to_string();
                    self.auth_keys.lock().unwrap().get(&domain).cloned()
                }
            }
        } else {
            self.cert_key.lock().unwrap().clone()
        }
    }
}

#[derive(Error, Debug)]
enum OrderError {
    #[error("acme error: {0}")]
    Acme(#[from] AcmeError),
    #[error("could not parse pem: {0}")]
    Pem(#[from] PemError),
    #[error("certificate generation error: {0}")]
    Rcgen(#[from] RcgenError),
    #[error("bad order object: {0:?}")]
    BadOrder(Order),
    #[error("bad auth object: {0:?}")]
    BadAuth(Auth),
    #[error("authorization for {0} failed too many times")]
    TooManyAttemptsAuth(String),
}
