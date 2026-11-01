//! # kwall-application-security: RASP Engine
//!
//! Application-layer Runtime Application Self-Protection (RASP) integrating:
//!
//! - **WAF Engine** (`waf`): Real-time OWASP Top 10 pattern matching on HTTP/gRPC payloads
//!   intercepted via eBPF `sk_msg`/`sk_skb` socket programs and uprobe TLS cleartext hooks.
//! - **BPF Fingerprint Compiler**: Exports compiled 4-byte rule fingerprints for direct
//!   upload into the kernel `KWALL_WAF_RULES` BPF hash map for zero-latency kernel-side blocking.

pub mod waf;

pub use waf::{
    default_rule_set, normalise_payload, AttackCategory, TlsCleartextPayload, TlsDirection,
    TlsPayloadProcessor, WafDecision, WafEngine, WafError, WafRule, WafStats,
};
