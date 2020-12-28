use crate::jws::{key_authorization_sha256, sign};
use async_rustls::TlsConnector;
use async_std::net::TcpStream;
use http_types::{Method, Request, Response, Url};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde::Deserialize;
use std::error::Error;
use std::str::FromStr;

mod jws;
mod resolver;
use async_rustls::webpki::DNSNameRef;
use rcgen::{Certificate, CustomExtension, PKCS_ECDSA_P256_SHA256};
pub use resolver::*;
use rustls::sign::{any_ecdsa_type, CertifiedKey};
use rustls::{ClientConfig, PrivateKey};
use std::sync::Arc;
use webpki_roots::TLS_SERVER_ROOTS;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Status {
    Pending,
    Valid,
    Invalid,
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
pub enum ChallengeType {
    #[serde(rename = "http-01")]
    Http01,
    #[serde(rename = "dns-01")]
    Dns01,
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01,
}

#[derive(Debug, Deserialize)]
pub struct Order {
    pub status: Status,
    pub authorizations: Vec<String>,
    pub finalize: String,
    pub certificate: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Auth {
    pub status: Status,
    pub identifier: Identifier,
    pub challenges: Vec<Challenge>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "camelCase")]
pub enum Identifier {
    Dns(String),
}

#[derive(Debug, Deserialize)]
pub struct Challenge {
    #[serde(rename = "type")]
    pub typ: ChallengeType,
    pub url: String,
    pub status: Status,
    pub token: String,
}

#[derive(Debug)]
pub struct Account {
    pub key_pair: EcdsaKeyPair,
    pub directory: Directory,
    pub kid: String,
}

impl Account {
    async fn request(&self, url: impl AsRef<str>, payload: &str) -> Result<String, Box<dyn Error>> {
        let body = sign(
            &self.key_pair,
            Some(&self.kid),
            self.directory.nonce().await?,
            url.as_ref(),
            payload,
        )?;
        let mut response = https(url.as_ref(), Method::Post, Some(body)).await?;
        Ok(response.body_string().await?)
    }
    pub async fn new_order(&self, domain: impl ToString) -> Result<Order, Box<dyn Error>> {
        let payload = format!(
            "{{\"identifiers\":[{{\"type\":\"dns\",\"value\":{}}}]}}",
            serde_json::to_string(&serde_json::Value::String(domain.to_string()))?
        );
        Ok(serde_json::from_str(
            &self.request(&self.directory.new_order, &payload).await?,
        )?)
    }
    pub async fn auth(&self, url: impl AsRef<str>) -> Result<Auth, Box<dyn Error>> {
        let payload = "".to_string();
        let response = self.request(url, &payload).await;
        dbg!(&response);
        Ok(serde_json::from_str(&response?)?)
    }
    pub async fn challenge(&self, challenge: &Challenge) -> Result<(), Box<dyn Error>> {
        let payload = "{}".to_string();
        dbg!(&self.request(&challenge.url, &payload).await?);
        Ok(())
    }
    pub fn tls_alpn_01<'a>(
        &self,
        auth: &'a Auth,
    ) -> Result<(&'a Challenge, CertifiedKey), Box<dyn Error>> {
        let challenge = auth
            .challenges
            .iter()
            .filter(|c| c.typ == ChallengeType::TlsAlpn01)
            .next();
        let challenge = match challenge {
            Some(challenge) => challenge,
            None => panic!("TODO: no tls challenge error"),
        };
        let domain = match &auth.identifier {
            Identifier::Dns(domain) => domain.clone(),
        };
        let mut params = rcgen::CertificateParams::new(vec![domain]);
        let key_auth = key_authorization_sha256(&self.key_pair, &*challenge.token);
        params.alg = &PKCS_ECDSA_P256_SHA256;
        params.custom_extensions = vec![CustomExtension::new_acme_identifier(&key_auth)];
        let certificate = Certificate::from_params(params)?;
        let pk = PrivateKey(certificate.serialize_private_key_der());
        let certified_key = CertifiedKey::new(
            vec![rustls::Certificate(certificate.serialize_der()?)],
            Arc::new(any_ecdsa_type(&pk).unwrap()),
        );
        Ok((challenge, certified_key))
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Directory {
    pub new_nonce: String,
    pub new_account: String,
    pub new_order: String,
}

impl Directory {
    pub async fn discover(url: impl AsRef<str>) -> Result<Self, Box<dyn Error>> {
        let body = https(url, Method::Get, None).await?.body_bytes().await?;
        Ok(serde_json::from_slice(&body)?)
    }
    pub async fn nonce(&self) -> Result<String, Box<dyn Error>> {
        let response = &https(&self.new_nonce.as_str(), Method::Head, None).await?;
        Ok(response.header("replay-nonce").unwrap().last().to_string())
    }
    pub async fn create_account(&self) -> Result<Account, Box<dyn Error>> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref()).unwrap();
        let body = sign(
            &key_pair,
            None,
            self.nonce().await?,
            &self.new_account,
            "{\"termsOfServiceAgreed\": true}",
        )?;
        let response = https(&self.new_account, Method::Post, Some(body)).await?;
        let kid = response.header("Location").unwrap().last().to_string();
        Ok(Account {
            key_pair,
            kid,
            directory: self.clone(),
        })
    }
}

async fn https(
    url: impl AsRef<str>,
    method: Method,
    body: Option<String>,
) -> Result<Response, Box<dyn Error>> {
    let mut request = Request::new(method, Url::from_str(url.as_ref())?);
    if let Some(body) = body {
        request.set_body(body);
        request.set_content_type("application/jose+json".parse().unwrap());
    }
    let host = request.host().unwrap();
    let host_port = (host, request.url().port_or_known_default().unwrap());
    let tcp = TcpStream::connect(host_port).await?;
    let domain = DNSNameRef::try_from_ascii_str(host)?;
    let mut config = ClientConfig::default();
    config
        .root_store
        .add_server_trust_anchors(&TLS_SERVER_ROOTS);
    let tls = TlsConnector::from(Arc::new(config))
        .connect(domain, tcp)
        .await?;
    let mut response = async_h1::connect(tls, request).await?;
    if !response.status().is_success() {
        let body = response.body_string().await;
        panic!("{:?}\n\n\n{:?}", &response, &body)
    }
    Ok(response)
}
