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

    // 6. Initialize Agent Self-Protection & Kernel Watchdog (Phase 17)
    let self_protect = Arc::new(kwall_selfprotect::SelfProtectionEngine::default());
    if let Err(e) = self_protect.watchdog.arm() {
        tracing::warn!("Kernel watchdog arming note: {e}");
    }
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let _ = self_protect.cert_manager.issue_certificate(now_ns);

    // Spawn self-protection and watchdog heartbeat loop
    let sp_engine = Arc::clone(&self_protect);
    let sp_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
        loop {
            interval.tick().await;
            let timestamp_ns = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos() as u64;
            let report = sp_engine.run_cycle(timestamp_ns);
            tracing::debug!(
                cycle = report.cycle_count,
                status = %report.status,
                watchdog = %report.watchdog_state,
                "Self-protection verification cycle completed"
            );
        }
    });

    // 7. Initialize Direct Container Runtime Interface (CRI) Integration (Phase 18)
    match kwall_cri::CriIntegrationManager::discover() {
        Ok(cri_mgr) => {
            info!(
                runtime = %cri_mgr.client.runtime_type(),
                socket = %cri_mgr.client.socket_path().display(),
                "Direct CRI streaming & pre-exec LSM integration initialized"
            );
        }
        Err(e) => {
            tracing::warn!("Direct CRI discovery note (fallback to K8s API informers): {e}");
        }
    }

    health.mark_ready();
    info!("KWALL Agent status: {}", health.status_message());

    // 7. Graceful POSIX signal handling (SIGINT / SIGTERM)
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

    sp_handle.abort();
    let _ = self_protect.watchdog.pause();
    health.mark_unready();
    info!("KWALL Node Agent successfully terminated.");
    Ok(())
}
