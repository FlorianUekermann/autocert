use async_std::task;
use std::error::Error;
use autocert::{Directory};

fn main() {
    task::block_on(async {
        run().await.unwrap();
    });

}

async fn run() -> Result<(), Box<dyn Error>> {
    let _params = rcgen::CertificateParams::new(vec![]);
    let dir = Directory::discover("https://acme-staging-v02.api.letsencrypt.org/directory").await?;
    let account = dir.create_account().await?;
    account.new_order("sdmflsdfj.com").await?;
    Ok(())
}

