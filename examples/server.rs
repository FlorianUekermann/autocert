use async_rustls::rustls::{NoClientAuth, ServerConfig, Session};
use async_rustls::TlsAcceptor;
use async_std::net::TcpListener;
use async_std::task;
use autocert::{
    Directory, ResolvesServerCertUsingAcme, ACME_TLS_ALPN_NAME, LETS_ENCRYPT_STAGING_DIRECTORY,
};
use futures::join;
use futures::StreamExt;
use log;
use std::error::Error;
use std::sync::Arc;

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
    let resolver = ResolvesServerCertUsingAcme::new(account);
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
    let listener = TcpListener::bind("192.168.0.103:4433").await?;
    let mut config = ServerConfig::new(NoClientAuth::new());
    config.cert_resolver = resolver.clone();
    config.alpn_protocols.push(ACME_TLS_ALPN_NAME.to_vec());
    let acceptor = TlsAcceptor::from(Arc::new(config));
    log::info!("listening");
    while let Some(tcp) = listener.incoming().next().await {
        let acceptor = acceptor.clone();
        let mut tls = acceptor.accept(tcp?).await?;
        log::info!("success");
        dbg!(tls.get_ref().1.get_alpn_protocol() == Some(ACME_TLS_ALPN_NAME));
        // tls.write_all(b"asdfadsfds").await?;
    }
    Ok(())
}
