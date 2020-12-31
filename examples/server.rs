use async_rustls::rustls::{NoClientAuth, ServerConfig};
use async_std::net::TcpListener;
use async_std::task;
use autocert::{
    Directory, ResolvesServerCertUsingAcme, TlsAcceptor, LETS_ENCRYPT_STAGING_DIRECTORY,
};
use futures::StreamExt;
use futures::{join, AsyncWriteExt};
use log;
use std::error::Error;

fn main() {
    simple_logger::SimpleLogger::new()
        .with_level(log::LevelFilter::Info)
        .init()
        .unwrap();

    let account = task::block_on(async {
        Directory::discover(LETS_ENCRYPT_STAGING_DIRECTORY)
            .await
            .unwrap()
            .create_account(Some("test-persist"))
            .await
            .unwrap()
    });
    let config = ServerConfig::new(NoClientAuth::new());
    let resolver = ResolvesServerCertUsingAcme::new(account, "fehrbelliner.ddns.net".to_string());
    let acceptor = TlsAcceptor::new(config, resolver.clone());
    task::block_on(async move {
        join!(
            async move {
                ResolvesServerCertUsingAcme::run(resolver).await;
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
                tls.write_all(b"asdfadsfds").await.unwrap();
            }
        });
    }
    Ok(())
}
