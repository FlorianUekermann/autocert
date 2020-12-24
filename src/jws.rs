use serde::{Serialize};
use base64::URL_SAFE_NO_PAD;
use ring::signature::{EcdsaKeyPair, KeyPair};
use ring::rand::SystemRandom;
use std::error::Error;

pub(crate) fn sign(key: &EcdsaKeyPair, kid: Option<&str>, nonce: String, url: &str, payload: &str) -> Result<String, Box<dyn Error>> {
    let jwk = match kid {
        None => Some(Jwk::new(key)),
        Some(_) => None,
    };
    let protected = Protected::base64(jwk, kid, nonce, url);
    let payload = base64::encode_config(payload, URL_SAFE_NO_PAD);
    let combined = format!("{}.{}", &protected, &payload);
    let signature = key.sign(&SystemRandom::new(), combined.as_bytes()).unwrap();
    let signature = base64::encode_config(signature.as_ref(), URL_SAFE_NO_PAD);
    let body = Body { protected, payload, signature };
    Ok(serde_json::to_string(&body).unwrap())
}

#[derive(Serialize)]
struct Body{
    protected: String,
    payload: String,
    signature: String,
}

#[derive(Serialize)]
struct Protected<'a> {
    alg: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwk: Option<Jwk>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<&'a str>,
    nonce: String,
    url: &'a str,
}

impl<'a> Protected<'a> {
    fn base64(jwk: Option<Jwk>, kid: Option<&'a str>, nonce: String, url: &'a str) -> String {
        let protected = Self{
            alg: "ES256",
            jwk,
            kid,
            nonce,
            url,
        };
        let protected = serde_json::to_vec(&protected).unwrap();
        base64::encode_config(protected, URL_SAFE_NO_PAD)
    }
}

#[derive(Serialize)]
struct Jwk {
    alg: &'static str,
    crv: &'static str,
    kty: &'static str,
    #[serde(rename = "use")]
    u: &'static str,
    x: String,
    y: String,
}

impl Jwk {
    pub(crate) fn new(key: &EcdsaKeyPair) -> Self {
        let (x, y) = key.public_key().as_ref()[1..].split_at(32);
        Self {
            alg: "ES256",
            crv: "P-256",
            kty: "EC",
            u: "sig",
            x: base64::encode_config(x, URL_SAFE_NO_PAD),
            y: base64::encode_config(y, URL_SAFE_NO_PAD),
        }
    }
}