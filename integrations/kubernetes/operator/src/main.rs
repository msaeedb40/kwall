//! Main entrypoint for the KWALL Kubernetes Operator daemon.

use kwall_operator::crd_gen::write_crds_to_directory;
use std::env;
use std::path::Path;
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber).ok();

    let args: Vec<String> = env::args().collect();

    // Check for --generate-crds flag
    if let Some(pos) = args.iter().position(|a| a == "--generate-crds") {
        let output_dir = args
            .get(pos + 1)
            .map(String::as_str)
            .unwrap_or("deployments/crds");
        info!("Generating CRD manifests into directory: {output_dir}");
        write_crds_to_directory(Path::new(output_dir))?;
        info!("CRD manifests generated successfully.");
        return Ok(());
    }

    info!("Starting KWALL Kubernetes Operator v0.1.0...");

    match kube::Client::try_default().await {
        Ok(client) => {
            info!("Connected to Kubernetes cluster API successfully");
            let _node_ctx = std::sync::Arc::new(kwall_operator::NodeContext {
                client: client.clone(),
            });
            let _policy_ctx = std::sync::Arc::new(kwall_operator::PolicyContext { client });

            info!("KWALL operator controllers initialized. Waiting for cluster events...");

            // Wait for shutdown signal
            tokio::signal::ctrl_c().await?;
            info!("Shutdown signal received, stopping KWALL operator.");
        }
        Err(e) => {
            warn!(
                "Could not connect to in-cluster Kubernetes API: {e}. Running in standalone mode."
            );
        }
    }

    Ok(())
}
