use crate::{Account, Identifier, Order, ACME_TLS_ALPN_NAME};
use async_rustls::rustls::sign::{any_ecdsa_type, CertifiedKey};
use async_rustls::rustls::Certificate as RustlsCertificate;
use async_rustls::rustls::{ClientHello, PrivateKey, ResolvesServerCert};
use rcgen::{CertificateParams, DistinguishedName};
use std::collections::BTreeMap;
use std::error::Error;
use std::sync::Arc;
use std::sync::Mutex;

pub struct ResolvesServerCertUsingAcme {
    domain: String,
    account: Account,
    csr_key: Mutex<Option<PrivateKey>>,
    cert_key: Mutex<Option<CertifiedKey>>,
    auth_keys: Mutex<BTreeMap<String, CertifiedKey>>,
}

impl ResolvesServerCertUsingAcme {
    pub fn new(account: Account, domain: String) -> Arc<ResolvesServerCertUsingAcme> {
        Arc::new(ResolvesServerCertUsingAcme {
            domain,
            account,
            csr_key: Mutex::new(None),
            cert_key: Mutex::new(None),
            auth_keys: Mutex::new(BTreeMap::new()),
        })
    }
    pub async fn run(resolver: Arc<ResolvesServerCertUsingAcme>) {
        resolver.order_next().await.unwrap();
    }
    pub(crate) async fn order_next(&self) -> Result<(), Box<dyn Error>> {
        let mut order = Some(self.account.new_order(&self.domain).await?);
        while let Some(o) = order.take() {
            dbg!(&o);
            order = match o {
                Order::Pending { authorizations } => {
                    for auth_url in authorizations {
                        let auth = self.account.auth(auth_url).await?;
                        let (challenge, auth_key) = self.account.tls_alpn_01(&auth)?;
                        let Identifier::Dns(domain) = auth.identifier.clone();
                        self.auth_keys.lock().unwrap().insert(domain, auth_key);
                        self.account.challenge(challenge).await?;
                        dbg!(&auth);
                    }
                    None
                }
                Order::Ready { finalize } => {
                    let mut params = CertificateParams::new(vec![self.domain.clone()]);
                    params.distinguished_name = DistinguishedName::new();
                    let cert = rcgen::Certificate::from_params(params).unwrap();
                    let pk = PrivateKey(cert.serialize_private_key_der());
                    self.csr_key.lock().unwrap().replace(pk);
                    let csr = cert.serialize_request_der().unwrap();
                    Some(self.account.finalize(finalize, csr).await?)
                }
                Order::Valid { certificate } => {
                    let cert = self.account.certificate(certificate).await?;
                    let cert = pem::parse(cert)?.contents;
                    let pk = self.csr_key.lock().unwrap().take().unwrap();
                    let cert_key = CertifiedKey::new(
                        vec![RustlsCertificate(cert)],
                        Arc::new(any_ecdsa_type(&pk).unwrap()),
                    );
                    self.cert_key.lock().unwrap().replace(cert_key);
                    None
                }
            }
        }
        Ok(())
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
