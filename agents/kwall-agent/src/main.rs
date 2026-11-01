//! KWALL Node Agent Daemon.
//!
//! Node-level security daemon managing eBPF lifecycle, telemetry ingestion,
//! and policy enforcement.

mod health;
mod inspector;

use health::AgentHealth;
use inspector::inspect_host_environment;
use kwall_common::logging::{init_logging, LogFormat};
use kwall_common::telemetry::PipelineMetrics;
use kwall_config::AgentConfig;
use kwall_core::traits::HealthCheckable;
use kwall_event_router::event::KwallEvent;
use kwall_event_router::router::{EventHandler, EventRouter};
use std::sync::Arc;
use tokio::signal::unix::{signal, SignalKind};
use tracing::info;

struct ConsoleEventLogger;

impl EventHandler for ConsoleEventLogger {
    fn handle(&self, event: &KwallEvent) {
        info!(
            target: "kwall::events",
            event_id = %event.event_id,
            severity = %event.severity,
            source = ?event.source,
            "Received event"
        );
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 1. Load configuration
    let config = AgentConfig::default();
    config
        .validate()
        .map_err(|e| anyhow::anyhow!("Config validation failed: {e}"))?;

    // 2. Initialize structured logging
    init_logging(&config.log_level, LogFormat::Text)
        .map_err(|e| anyhow::anyhow!("Logging init failed: {e}"))?;

    info!(
        "Starting KWALL Node Agent v{}",
        kwall_core::constants::KWALL_VERSION
    );
    info!("Node identifier: {}", config.node_name);

    // 3. Inspect host kernel capabilities
    let kernel_report = inspect_host_environment()?;
    info!(
        "Kernel capability inspection completed: {:?}",
        kernel_report.kernel_release
    );

    // 4. Initialize pipeline telemetry and health monitor
    let metrics = Arc::new(PipelineMetrics::new());
    let health = Arc::new(AgentHealth::new());

    // 5. Spawn Event Router with background workers
    let handler = Arc::new(ConsoleEventLogger);
    let _router = Arc::new(EventRouter::spawn(16384, 4, handler, Arc::clone(&metrics)));
    info!("Event router worker pool initialized");

    health.mark_ready();
    info!("KWALL Agent status: {}", health.status_message());

    // 6. Graceful POSIX signal handling (SIGINT / SIGTERM)
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigterm = signal(SignalKind::terminate())?;

    tokio::select! {
        _ = sigint.recv() => {
            info!("Received SIGINT, initiating graceful shutdown...");
        }
        _ = sigterm.recv() => {
            info!("Received SIGTERM, initiating graceful shutdown...");
        }
    }

    health.mark_unready();
    info!("KWALL Node Agent successfully terminated.");
    Ok(())
}
