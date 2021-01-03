use async_rustls::rustls::{NoClientAuth, ServerConfig};
use async_std::net::TcpListener;
use async_std::task;
use autocert::{acme::LETS_ENCRYPT_STAGING_DIRECTORY, ResolvesServerCertUsingAcme, TlsAcceptor};
use futures::StreamExt;
use futures::{join, AsyncWriteExt};
use log;
use std::error::Error;

fn main() {
    simple_logger::SimpleLogger::new()
        .with_level(log::LevelFilter::Info)
        .with_module_level("autocert", log::LevelFilter::Info)
        .init()
        .unwrap();

    let resolver = ResolvesServerCertUsingAcme::new();
    let config = ServerConfig::new(NoClientAuth::new());
    let acceptor = TlsAcceptor::new(config, resolver.clone());
    task::block_on(async move {
        join!(
            async move {
                ResolvesServerCertUsingAcme::run(
                    &resolver,
                    LETS_ENCRYPT_STAGING_DIRECTORY,
                    vec!["fehrbelliner.ddns.net".to_string()],
                )
                .await;
            },
            async move { serve(acceptor).await.unwrap() }
        );
    });
}

async fn serve(acceptor: TlsAcceptor) -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("192.168.0.103:4433").await?;
    while let Some(tcp) = listener.incoming().next().await {
        let acceptor = acceptor.clone();
        task::spawn(async move {
            if let Some(mut tls) = acceptor.accept(tcp.unwrap()).await.unwrap() {
                tls.write_all(b"hello tls").await.unwrap();
            }
        });
    }
    Ok(())
}
