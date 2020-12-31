use crate::*;
use async_rustls::rustls::{ServerConfig, Session};
use async_rustls::server::TlsStream;
use futures::{AsyncRead, AsyncWrite, AsyncWriteExt};
use std::error::Error;
use std::sync::Arc;

#[derive(Clone)]
pub struct TlsAcceptor {
    config: Arc<ServerConfig>,
    resolver: Arc<ResolvesServerCertUsingAcme>,
}

impl TlsAcceptor {
    pub fn new(mut config: ServerConfig, resolver: Arc<ResolvesServerCertUsingAcme>) -> Self {
        config.cert_resolver = resolver.clone();
        config.alpn_protocols.push(ACME_TLS_ALPN_NAME.to_vec());
        let config = Arc::new(config);
        TlsAcceptor { config, resolver }
    }
    pub async fn accept<IO>(
        &self,
        stream: IO,
    ) -> Result<Option<TlsStream<IO>>, Box<dyn Error + Send>>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let mut tls = async_rustls::TlsAcceptor::from(self.config.clone())
            .accept(stream)
            .await
            .unwrap();
        if tls.get_ref().1.get_alpn_protocol() == Some(ACME_TLS_ALPN_NAME) {
            log::info!("accepted acme");
            tls.close().await.unwrap();
            log::info!("closed acme");
            drop(tls);
            self.resolver.order_next().await.unwrap();
            Ok(None)
        } else {
            Ok(Some(tls))
        }
    }
}
