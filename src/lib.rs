use http_types::{Request, Method, Response, Url};
use async_std::net::TcpStream;
use async_tls::TlsConnector;
use std::error::Error;
use serde::Deserialize;
use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use ring::rand::SystemRandom;
use crate::jws::sign;
use std::str::FromStr;

mod jws;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum OrderStatus {
    Pending,
    Valid,
}

#[derive(Debug, Deserialize)]
pub struct Order {
    pub status: OrderStatus,
    pub authorizations: Vec<String>,
    pub finalize: String,
    pub certificate: Option<String>,
}

#[derive(Debug)]
pub struct Account {
    pub key_pair: EcdsaKeyPair,
    pub directory: Directory,
    pub kid: String,
}

impl Account {
    pub async fn new_order(&self, domain: impl ToString) -> Result<Order, Box<dyn Error>> {
        let payload = format!("{{\"identifiers\":[{{\"type\":\"dns\",\"value\":{}}}]}}", serde_json::to_string(&serde_json::Value::String(domain.to_string()))?);
        let body = sign(&self.key_pair, Some(&self.kid), self.directory.nonce().await?, &self.directory.new_order, &payload)?;
        let mut response = https(&self.directory.new_order, Method::Post, Some(body)).await?;
        Ok(serde_json::from_str(&response.body_string().await?)?)
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
        let key_pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref()).unwrap();
        let body = sign(&key_pair, None, self.nonce().await?, &self.new_account, "{\"termsOfServiceAgreed\": true}")?;
        let response = https(&self.new_account, Method::Post, Some(body)).await?;
        let kid = response.header("Location").unwrap().last().to_string();
        Ok(Account { key_pair, kid , directory: self.clone()})
    }
}

async fn https(url: impl AsRef<str>, method: Method, body: Option<String>) -> Result<Response, Box<dyn Error>> {
    let mut request = Request::new(method, Url::from_str(url.as_ref())?);
    if let Some(body) = body {
        request.set_body(body);
        request.set_content_type("application/jose+json".parse().unwrap());
    }
    let host = request.host().unwrap();
    let host_port = (host, request.url().port_or_known_default().unwrap());
    let tcp = TcpStream::connect(host_port).await?;
    let tls = TlsConnector::default().connect(host, tcp).await?;
    let mut response = async_h1::connect(tls, request).await?;
    if !response.status().is_success() {
        let body = response.body_string().await;
        panic!("{:?}\n\n\n{:?}", &response, &body)
    }
    Ok(response)
}