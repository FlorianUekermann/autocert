use async_rustls::rustls::ClientConfig;
use async_rustls::webpki::DNSNameRef;
use async_rustls::TlsConnector;
use async_std::net::TcpStream;
use http_types::{Method, Request, Response};
use std::error::Error;
use std::sync::Arc;
use webpki_roots::TLS_SERVER_ROOTS;

pub(crate) async fn https(
    url: impl AsRef<str>,
    method: Method,
    body: Option<String>,
) -> Result<Response, Box<dyn Error>> {
    let mut request = Request::new(method, url.as_ref());
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
