pub mod identity_allocator;
pub mod reconciler;

pub use identity_allocator::IdentityAllocator;
pub use reconciler::PolicyReconciler;

use anyhow::Result;
use tracing::info;

pub async fn run_controller() -> Result<()> {
    info!("Starting KWALL Control Plane Controller...");
    info!("Workload Identity Allocator active.");
    info!("Policy reconciliation engine active.");

    tokio::signal::ctrl_c().await?;
    info!("Received shutdown signal. Stopping KWALL Controller...");
    Ok(())
}
