use crate::kernel::check_kernel_compatibility;
use crate::server::AgentIpcServer;
use kwall_common::{KwallConfig, Result};
use kwall_dataplane::{DataplaneManager, DataplaneState, EventHub};
use kwall_security::SecurityEngine;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

pub struct NodeAgent {
    config: KwallConfig,
    dataplane_state: Arc<RwLock<DataplaneState>>,
    dataplane_manager: Arc<RwLock<DataplaneManager>>,
    event_hub: Arc<EventHub>,
    security: Arc<RwLock<SecurityEngine>>,
}

impl NodeAgent {
    pub fn new(config: KwallConfig) -> Self {
        Self {
            config,
            dataplane_state: Arc::new(RwLock::new(DataplaneState::new())),
            dataplane_manager: Arc::new(RwLock::new(DataplaneManager::new())),
            event_hub: Arc::new(EventHub::new(4096)),
            security: Arc::new(RwLock::new(SecurityEngine::new(100, 500, 10, Vec::new()))),
        }
    }

    pub async fn start(&self) -> Result<()> {
        info!("Starting KWALL Node Agent...");

        // 1. Verify Kernel Compatibility
        let compat = check_kernel_compatibility()?;
        info!(
            "Kernel verification passed: {} (compatible={})",
            compat.kernel_version, compat.compatible
        );

        // 2. Initialize Dataplane & Check for Preserved State
        {
            let mut mgr = self.dataplane_manager.write().await;
            mgr.init()?;

            if mgr.has_pinned_state() {
                info!(
                    "Preserved eBPF state detected at {}. Resuming dataplane enforcement without disruption.",
                    mgr.pin_path().display()
                );
            } else {
                info!("No previous BPF state found; initializing fresh bpffs layout.");
                let _ = mgr.ensure_pin_directory();
            }

            // Attempt to load and verify eBPF bytecode if binary is present
            let default_bpf_paths = [
                std::env::var("KWALL_BPF_PATH").unwrap_or_default(),
                "/usr/lib/kwall/kwall-ebpf.o".to_string(),
                "target/bpfel-unknown-none/release/kwall-ebpf".to_string(),
            ];
            for path in &default_bpf_paths {
                if !path.is_empty() && std::path::Path::new(path).exists() {
                    match mgr.load_bpf_file(path) {
                        Ok(report) => {
                            info!(
                                "Loaded eBPF binary from {}: verified {} programs, {} maps",
                                path,
                                report.programs.len(),
                                report.maps.len()
                            );
                            break;
                        }
                        Err(e) => {
                            tracing::warn!("Failed to load eBPF binary from {}: {}", path, e);
                        }
                    }
                }
            }
        }

        // 3. Start IPC Server
        let server = AgentIpcServer::new(
            self.config.socket_path.clone(),
            Arc::clone(&self.dataplane_state),
            Arc::clone(&self.dataplane_manager),
            compat.kernel_version,
        );

        tokio::spawn(async move {
            if let Err(e) = server.run().await {
                tracing::error!("Agent IPC server exited: {}", e);
            }
        });

        info!("KWALL Node Agent successfully initialized and running.");
        Ok(())
    }

    pub fn state(&self) -> Arc<RwLock<DataplaneState>> {
        Arc::clone(&self.dataplane_state)
    }

    pub fn manager(&self) -> Arc<RwLock<DataplaneManager>> {
        Arc::clone(&self.dataplane_manager)
    }

    pub fn event_hub(&self) -> Arc<EventHub> {
        Arc::clone(&self.event_hub)
    }

    pub fn security(&self) -> Arc<RwLock<SecurityEngine>> {
        Arc::clone(&self.security)
    }
}
