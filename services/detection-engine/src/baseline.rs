//! Behavioral baselining and statistical anomaly detection engine.

use crate::alert::{ThreatAlert, ThreatCategory};
use kwall_core::types::Severity;
use kwall_event_enricher::enricher::EnrichedEvent;
use kwall_event_router::event::EventPayload;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

/// Baseline profiling lifecycle state for a given workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProfileState {
    /// Actively recording observed execution patterns without raising alerts.
    Learning {
        started_at_ns: u64,
        duration_ns: u64,
    },
    /// Baseline is locked; deviations trigger security anomaly alerts.
    Enforcing,
}

/// Baseline behavioral footprint for a single container workload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadProfile {
    /// Workload identifier (e.g., namespace/pod_name or SPIFFE ID).
    pub workload_id: String,
    /// Profiling state.
    pub state: ProfileState,
    /// Known process command names observed during learning.
    pub known_commands: HashSet<String>,
    /// Known destination endpoints (e.g., "10.96.0.1:443") observed during learning.
    pub known_destinations: HashSet<String>,
    /// Total events processed during lifecycle.
    pub total_events: u64,
}

impl WorkloadProfile {
    /// Creates a new profile in learning state with a configurable duration.
    pub fn new(workload_id: String, start_time_ns: u64, learning_duration_ns: u64) -> Self {
        Self {
            workload_id,
            state: ProfileState::Learning {
                started_at_ns: start_time_ns,
                duration_ns: learning_duration_ns,
            },
            known_commands: HashSet::new(),
            known_destinations: HashSet::new(),
            total_events: 0,
        }
    }

    /// Evaluates an event against the profile, transitioning state if duration elapsed.
    pub fn evaluate(&mut self, event: &EnrichedEvent) -> Option<ThreatAlert> {
        self.total_events += 1;
        let now = event.base_event.timestamp_ns;

        // Check if learning window has expired
        if let ProfileState::Learning {
            started_at_ns,
            duration_ns,
        } = self.state
        {
            if now.saturating_sub(started_at_ns) >= duration_ns {
                self.state = ProfileState::Enforcing;
            }
        }

        match &event.base_event.payload {
            EventPayload::Process(proc) => {
                let cmd = proc.comm.clone();
                match self.state {
                    ProfileState::Learning { .. } => {
                        self.known_commands.insert(cmd);
                        None
                    }
                    ProfileState::Enforcing => {
                        if !self.known_commands.contains(&cmd) {
                            Some(ThreatAlert::new(
                                format!("anomaly-proc-{}", event.base_event.event_id),
                                now,
                                Severity::Error,
                                ThreatCategory::BehavioralAnomaly,
                                Some("T1204"),
                                format!("Unseen Binary Executed: {cmd}"),
                                format!(
                                    "Workload '{}' executed binary '{}' which was not observed during baseline learning.",
                                    self.workload_id, cmd
                                ),
                                event.src_workload.clone(),
                                serde_json::json!({
                                    "command": cmd,
                                    "filename": proc.filename,
                                    "pid": proc.pid.0,
                                    "uid": proc.uid,
                                    "known_commands_count": self.known_commands.len()
                                }),
                                "Investigate container execution history and enforce runtime process restrictions",
                            ))
                        } else {
                            None
                        }
                    }
                }
            }
            EventPayload::Network(net) => {
                let dst_endpoint = format!("{}:{}", net.dst_ip, net.dst_port);
                match self.state {
                    ProfileState::Learning { .. } => {
                        self.known_destinations.insert(dst_endpoint);
                        None
                    }
                    ProfileState::Enforcing => {
                        if !self.known_destinations.contains(&dst_endpoint) {
                            Some(ThreatAlert::new(
                                format!("anomaly-net-{}", event.base_event.event_id),
                                now,
                                Severity::Warning,
                                ThreatCategory::BehavioralAnomaly,
                                Some("T1071"),
                                format!("Novel Network Destination: {dst_endpoint}"),
                                format!(
                                    "Workload '{}' initiated outbound flow to '{}' not present in baseline profile.",
                                    self.workload_id, dst_endpoint
                                ),
                                event.src_workload.clone(),
                                serde_json::json!({
                                    "destination": dst_endpoint,
                                    "protocol": net.protocol,
                                    "known_destinations_count": self.known_destinations.len()
                                }),
                                "Verify destination IP legitimacy and restrict egress via KwallNetworkPolicy",
                            ))
                        } else {
                            None
                        }
                    }
                }
            }
            _ => None,
        }
    }
}

/// Baseline engine managing behavioral profiles across all monitored Kubernetes pods.
pub struct BaselineEngine {
    learning_duration_ns: u64,
    profiles: RwLock<HashMap<String, WorkloadProfile>>,
}

impl BaselineEngine {
    /// Creates a new BaselineEngine with a default learning duration (e.g. 1 hour).
    pub fn new(learning_duration_ns: u64) -> Self {
        Self {
            learning_duration_ns,
            profiles: RwLock::new(HashMap::new()),
        }
    }

    /// Evaluates an event against the workload's profile.
    pub fn process_event(&self, event: &EnrichedEvent) -> Option<ThreatAlert> {
        let workload_id = event
            .src_workload
            .as_ref()
            .map(|w| format!("{}/{}", w.namespace, w.pod_name))
            .unwrap_or_else(|| "host-system".to_string());

        let mut lock = self.profiles.write().ok()?;
        let profile = lock.entry(workload_id.clone()).or_insert_with(|| {
            WorkloadProfile::new(
                workload_id,
                event.base_event.timestamp_ns,
                self.learning_duration_ns,
            )
        });

        profile.evaluate(event)
    }

    /// Returns the number of tracked workload profiles.
    pub fn profile_count(&self) -> usize {
        self.profiles.read().map(|p| p.len()).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kwall_core::types::{CgroupId, EventSource, NodeId, ProcessId};
    use kwall_event_router::event::{KwallEvent, ProcessEventData};

    #[test]
    fn test_baseline_learning_and_enforcement() {
        let duration = 1_000_000_000; // 1s
        let engine = BaselineEngine::new(duration);

        let src_workload = Some(kwall_event_enricher::enricher::EnrichedWorkloadContext {
            pod_name: "test-pod-1".to_string(),
            namespace: "default".to_string(),
            workload_owner: None,
            service_account: "default".to_string(),
            spiffe_id: "spiffe://cluster.local/ns/default/sa/default".to_string(),
            labels: Default::default(),
        });

        // 1. Learning event: "nginx"
        let event1 = EnrichedEvent {
            base_event: KwallEvent {
                version: 1,
                event_id: 1,
                timestamp_ns: 100,
                node_id: NodeId(1),
                severity: Severity::Info,
                source: EventSource::TracepointProcess,
                payload: EventPayload::Process(ProcessEventData {
                    pid: ProcessId(100),
                    tgid: 100,
                    ppid: 1,
                    uid: 0,
                    gid: 0,
                    cgroup_id: CgroupId(1),
                    comm: "nginx".to_string(),
                    filename: "/usr/sbin/nginx".to_string(),
                }),
            },
            src_workload: src_workload.clone(),
            dst_workload: None,
        };
        assert!(engine.process_event(&event1).is_none());

        // 2. Event after duration expired: "nginx" should still pass
        let event2 = EnrichedEvent {
            base_event: KwallEvent {
                version: 1,
                event_id: 2,
                timestamp_ns: 100 + duration + 10,
                node_id: NodeId(1),
                severity: Severity::Info,
                source: EventSource::TracepointProcess,
                payload: EventPayload::Process(ProcessEventData {
                    pid: ProcessId(101),
                    tgid: 101,
                    ppid: 100,
                    uid: 0,
                    gid: 0,
                    cgroup_id: CgroupId(1),
                    comm: "nginx".to_string(),
                    filename: "/usr/sbin/nginx".to_string(),
                }),
            },
            src_workload: src_workload.clone(),
            dst_workload: None,
        };
        assert!(engine.process_event(&event2).is_none());

        // 3. Novel binary "cryptominer" after learning should trigger alert!
        let event3 = EnrichedEvent {
            base_event: KwallEvent {
                version: 1,
                event_id: 3,
                timestamp_ns: 100 + duration + 20,
                node_id: NodeId(1),
                severity: Severity::Notice,
                source: EventSource::TracepointProcess,
                payload: EventPayload::Process(ProcessEventData {
                    pid: ProcessId(102),
                    tgid: 102,
                    ppid: 100,
                    uid: 0,
                    gid: 0,
                    cgroup_id: CgroupId(1),
                    comm: "cryptominer".to_string(),
                    filename: "/tmp/cryptominer".to_string(),
                }),
            },
            src_workload,
            dst_workload: None,
        };
        let alert = engine.process_event(&event3).expect("Should trigger alert");
        assert_eq!(alert.category, ThreatCategory::BehavioralAnomaly);
        assert_eq!(alert.severity, Severity::Error);
        assert_eq!(alert.mitre_attack_id.as_deref(), Some("T1204"));
    }
}
