use async_std::task;
use autocert::Directory;
use std::error::Error;

fn main() {
    task::block_on(async {
        run().await.unwrap();
    });
}

async fn run() -> Result<(), Box<dyn Error>> {
    let _params = rcgen::CertificateParams::new(vec![]);
    let dir = Directory::discover("https://acme-staging-v02.api.letsencrypt.org/directory").await?;
    let account = dir.create_account().await?;
    let order = account.new_order("sdmflsdfj.com").await?;
    dbg!(&order);
    let auth = account.auth(&order.authorizations[0]).await?;
    dbg!(&auth);

    Ok(())
}
