use async_std::net::TcpListener;
use async_std::task;
use async_tls::TlsAcceptor;
use autocert::{ChallengeType, Directory, ResolvesServerCertUsingAcme};
use futures::{try_join, AsyncReadExt, AsyncWriteExt, StreamExt};
use log;
use rustls::{NoClientAuth, ServerConfig};
use std::error::Error;

fn main() {
    simple_logger::SimpleLogger::new()
        .with_level(log::LevelFilter::Info)
        .init()
        .unwrap();

    task::block_on(async {
        try_join!(serve(), run()).unwrap();
    });
}

async fn run() -> Result<(), Box<dyn Error>> {
    let _params = rcgen::CertificateParams::new(vec![]);
    let dir = Directory::discover("https://acme-staging-v02.api.letsencrypt.org/directory").await?;
    let account = dir.create_account().await?;
    const domain: &str = "fehrbelliner.ddns.net";
    let order = account.new_order(domain).await?;
    dbg!(&order);
    let auth = account.auth(&order.authorizations[0]).await?;
    dbg!(&auth);
    let challenge = auth
        .challenges
        .iter()
        .filter(|c| c.typ == ChallengeType::TlsAlpn01)
        .next()
        .unwrap();
    dbg!(&challenge);
    account.challenge(&challenge).await?;
    Ok(())
}

async fn serve() -> Result<(), Box<dyn Error>> {
    log::info!("binding");
    let listener = TcpListener::bind("192.168.0.103:4433").await?;
    let mut config = ServerConfig::new(NoClientAuth::new());
    config.cert_resolver = ResolvesServerCertUsingAcme::new();
    let acceptor = TlsAcceptor::from(config);
    log::info!("listening");
    while let Some(tcp) = listener.incoming().next().await {
        let mut tcp = tcp?;
        let acceptor = acceptor.clone();
        let mut tls = acceptor.accept(tcp).await?;
        tls.write_all(b"asdfadsfds").await?;

        // let mut buf = [0u8; 128];
        // loop {
        //     match stream.read(&mut buf).await {
        //         Ok(n) => if n>0 {log::info!("{:?}", &buf[..n])},
        //         Err(err) => {
        //             dbg!(err);
        //             break
        //         },
        //     }
        // }
    }
    Ok(())
}
