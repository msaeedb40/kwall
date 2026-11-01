//! Health monitoring and readiness probes for Kubernetes.

use kwall_core::traits::HealthCheckable;
use std::sync::atomic::{AtomicBool, Ordering};

/// Agent health monitor reporting subsystem readiness and operational status.
#[derive(Debug, Default)]
pub struct AgentHealth {
    is_ready: AtomicBool,
    is_live: AtomicBool,
}

impl AgentHealth {
    pub fn new() -> Self {
        Self {
            is_ready: AtomicBool::new(false),
            is_live: AtomicBool::new(true),
        }
    }

    pub fn mark_ready(&self) {
        self.is_ready.store(true, Ordering::SeqCst);
    }

    pub fn mark_unready(&self) {
        self.is_ready.store(false, Ordering::SeqCst);
    }

    pub fn is_ready(&self) -> bool {
        self.is_ready.load(Ordering::SeqCst)
    }
}

impl HealthCheckable for AgentHealth {
    fn is_healthy(&self) -> bool {
        self.is_live.load(Ordering::SeqCst) && self.is_ready()
    }

    fn status_message(&self) -> &str {
        if self.is_healthy() {
            "Agent operational and attached to kernel hooks"
        } else if !self.is_ready() {
            "Agent initializing kernel subsystems"
        } else {
            "Agent reporting unhealthy subsystem condition"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_transitions() {
        let health = AgentHealth::new();
        assert!(!health.is_healthy());
        assert_eq!(
            health.status_message(),
            "Agent initializing kernel subsystems"
        );

        health.mark_ready();
        assert!(health.is_healthy());
        assert_eq!(
            health.status_message(),
            "Agent operational and attached to kernel hooks"
        );

        health.mark_unready();
        assert!(!health.is_healthy());
    }
}
