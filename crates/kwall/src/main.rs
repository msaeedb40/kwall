use clap::{Parser, Subcommand};
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "kwall")]
#[command(about = "KWALL - eBPF-powered Kubernetes firewall and security platform")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run the KWALL node agent
    Agent,
    /// Run the KWALL cluster controller
    Controller,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Agent => {
            info!("Launching KWALL Node Agent...");
            kwall_agent::run_agent().await?;
        }
        Commands::Controller => {
            info!("Launching KWALL Control Plane Controller...");
            kwall_controller::run_controller().await?;
        }
    }

    Ok(())
}
