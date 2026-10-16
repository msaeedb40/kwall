use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    info!("Starting KWALL Controller");
    kwall_controller::run_controller().await?;
    Ok(())
}
