use crate::*;
use async_rustls::rustls::sign::{any_ecdsa_type, CertifiedKey};
use async_rustls::rustls::PrivateKey;
use async_std::path::PathBuf;
use base64::URL_SAFE_NO_PAD;
use http_types::Method;
use rcgen::{Certificate, CustomExtension, PKCS_ECDSA_P256_SHA256};
use ring::signature::EcdsaKeyPair;
use std::error::Error;
use std::sync::Arc;

#[derive(Debug)]
pub struct Account {
    pub key_pair: EcdsaKeyPair,
    pub directory: Directory,
    pub cache: Option<PathBuf>,
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
        self.request(&challenge.url, &payload).await?;
        Ok(())
    }
    pub async fn finalize(&self, url: impl AsRef<str>, csr: Vec<u8>) -> Result<(), Box<dyn Error>> {
        let payload = format!(
            "{{\"url\":\"{}\"}}",
            base64::encode_config(csr, URL_SAFE_NO_PAD)
        );
        dbg!(&payload);
        dbg!(self.request(&url, &payload).await?);
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
            vec![async_rustls::rustls::Certificate(
                certificate.serialize_der()?,
            )],
            Arc::new(any_ecdsa_type(&pk).unwrap()),
        );
        Ok((challenge, certified_key))
    }
}
