use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    info!("Starting KWALL Node Agent");
    kwall_agent::run_agent().await?;
    Ok(())
}
