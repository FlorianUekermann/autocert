use async_rustls::TlsAcceptor;
use async_std::net::TcpListener;
use async_std::task;
use autocert::{ChallengeType, Directory, ResolvesServerCertUsingAcme};
use futures::join;
use futures::{AsyncWriteExt, StreamExt};
use log;
use rustls::{NoClientAuth, ServerConfig};
use std::error::Error;
use std::sync::Arc;

fn main() {
    simple_logger::SimpleLogger::new()
        .with_level(log::LevelFilter::Info)
        .init()
        .unwrap();

    let resolver = ResolvesServerCertUsingAcme::new();
    let clone = resolver.clone();
    task::block_on(async move {
        join!(
            async move {
                ResolvesServerCertUsingAcme::run(clone).await;
            },
            async move { serve(resolver).await.unwrap() }
        );
    });
}

async fn serve(resolver: Arc<ResolvesServerCertUsingAcme>) -> Result<(), Box<dyn Error>> {
    log::info!("binding");
    let listener = TcpListener::bind("192.168.0.103:4433").await?;
    let mut config = ServerConfig::new(NoClientAuth::new());
    config.cert_resolver = resolver;
    config.alpn_protocols.push(b"acme-tls/1".to_vec());
    let acceptor = TlsAcceptor::from(Arc::new(config));
    log::info!("listening");
    while let Some(tcp) = listener.incoming().next().await {
        let acceptor = acceptor.clone();
        let mut tls = acceptor.accept(tcp?).await?;
        log::info!("success");
        // tls.write_all(b"asdfadsfds").await?;
    }
    Ok(())
}
