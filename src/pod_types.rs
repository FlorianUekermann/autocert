use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Status {
    Pending,
    Valid,
    Invalid,
    Ready,
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
#[serde(tag = "status", rename_all = "camelCase")]
pub enum Order {
    Pending { authorizations: Vec<String> },
    Ready { finalize: String },
    Valid { certificate: String },
}

//    pub status: Status,
//     pub authorizations: Vec<String>,
//     pub finalize: String,
//     pub certificate: Option<String>,

#[derive(Debug, Deserialize)]
pub struct Auth {
    pub status: Status,
    pub identifier: Identifier,
    pub challenges: Vec<Challenge>,
}

#[derive(Clone, Debug, Deserialize)]
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
