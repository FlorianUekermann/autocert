use crate::*;
use async_std::fs::create_dir_all;
use async_std::path::Path;
use http_types::Method;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde::Deserialize;
use std::error::Error;

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
    pub async fn create_account<P: AsRef<Path>>(
        self,
        cache_dir: Option<P>,
    ) -> Result<Account, Box<dyn Error>> {
        const FILE: &str = "acme_account_key";
        let alg = &ECDSA_P256_SHA256_FIXED_SIGNING;
        if let Some(cache_dir) = &cache_dir {
            create_dir_all(cache_dir).await?;
        }
        let pkcs8 = match &cache_dir {
            Some(cache_dir) => read_if_exist(cache_dir, FILE).await?,
            None => None,
        };
        let key_pair = match pkcs8 {
            Some(pkcs8) => {
                log::info!("found cached account key");
                EcdsaKeyPair::from_pkcs8(alg, &pkcs8).unwrap()
            }
            None => {
                log::info!("creating a new account key");
                let rng = SystemRandom::new();
                let pkcs8 = EcdsaKeyPair::generate_pkcs8(alg, &rng).unwrap();
                if let Some(cache_dir) = &cache_dir {
                    write(cache_dir, FILE, pkcs8.as_ref()).await?;
                }
                EcdsaKeyPair::from_pkcs8(alg, pkcs8.as_ref()).unwrap()
            }
        };
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
            cache: cache_dir.map(|p| p.as_ref().to_path_buf()),
        })
    }
}
