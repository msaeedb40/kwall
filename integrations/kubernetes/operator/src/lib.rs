//! KWALL Kubernetes Operator and lifecycle manager.
//!
//! Provides automated node capability labeling, CRD manifest generation,
//! CRD validation controllers, and mutating/validating admission webhooks.

pub mod crd_gen;
pub mod node_controller;
pub mod policy_controller;
pub mod webhook;

pub use crd_gen::{generate_crd_yamls, write_crds_to_directory};
pub use node_controller::{compute_ebpf_labels, reconcile_node, NodeContext};
pub use policy_controller::{reconcile_network_policy, reconcile_runtime_policy, PolicyContext};
pub use webhook::{process_admission_review, AdmissionReview};
