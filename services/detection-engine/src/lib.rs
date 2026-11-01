//! KWALL Security Intelligence & Threat Detection Engine.
//!
//! Provides behavioral baselining, heuristic runtime threat detectors (container escapes,
//! interactive shell execution, privilege escalation), and network anomaly analytics
//! correlated with MITRE ATT&CK techniques.

pub mod alert;
pub mod baseline;
pub mod engine;
pub mod network;
pub mod runtime;

pub use alert::{ThreatAlert, ThreatCategory};
pub use baseline::{BaselineEngine, ProfileState, WorkloadProfile};
pub use engine::{DetectionEngine, DetectionEngineConfig};
pub use network::{NetworkDetectorConfig, NetworkThreatDetector};
pub use runtime::RuntimeThreatDetector;
