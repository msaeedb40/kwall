//! DNS protocol parsing, tunneling detection, DGA analysis, and CoreDNS bypass detection.
//!
//! Provides zero-allocation-focused wire protocol decoding for RFC 1035 DNS messages
//! and real-time behavioral heuristics for exfiltration channels.

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::RwLock;

use kwall_core::types::Severity;
use kwall_detection::alert::{ThreatAlert, ThreatCategory};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::crypto::shannon_entropy;

/// DNS parser error conditions.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DnsParseError {
    #[error("DNS packet is too short: {0} bytes")]
    PacketTooShort(usize),
    #[error("Invalid DNS label length: {0}")]
    InvalidLabelLength(usize),
    #[error("Pointer loop detected or excessive recursion during name decompression")]
    PointerLoop,
    #[error("Pointer offset out of bounds: {0}")]
    PointerOutOfBounds(usize),
    #[error("Truncated resource record")]
    TruncatedRecord,
}

/// Standard DNS Query and Record Types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DnsQueryType {
    A,
    Ns,
    Cname,
    Soa,
    Ptr,
    Mx,
    Txt,
    Aaaa,
    Srv,
    Any,
    Unknown(u16),
}

impl From<u16> for DnsQueryType {
    fn from(val: u16) -> Self {
        match val {
            1 => Self::A,
            2 => Self::Ns,
            5 => Self::Cname,
            6 => Self::Soa,
            12 => Self::Ptr,
            15 => Self::Mx,
            16 => Self::Txt,
            28 => Self::Aaaa,
            33 => Self::Srv,
            255 => Self::Any,
            other => Self::Unknown(other),
        }
    }
}

/// Decoded DNS Header according to RFC 1035.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsHeader {
    pub id: u16,
    pub is_response: bool,
    pub opcode: u8,
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub rcode: u8,
    pub qd_count: u16,
    pub an_count: u16,
    pub ns_count: u16,
    pub ar_count: u16,
}

/// Decoded DNS Question entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: DnsQueryType,
    pub qclass: u16,
}

/// Decoded DNS Resource Record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: DnsQueryType,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

impl DnsRecord {
    /// Formats IPv4 address if record type is A and rdata is 4 bytes.
    #[must_use]
    pub fn as_ipv4(&self) -> Option<Ipv4Addr> {
        if self.rtype == DnsQueryType::A && self.rdata.len() == 4 {
            Some(Ipv4Addr::new(
                self.rdata[0],
                self.rdata[1],
                self.rdata[2],
                self.rdata[3],
            ))
        } else {
            None
        }
    }

    /// Formats IPv6 address if record type is AAAA and rdata is 16 bytes.
    #[must_use]
    pub fn as_ipv6(&self) -> Option<Ipv6Addr> {
        if self.rtype == DnsQueryType::Aaaa && self.rdata.len() == 16 {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&self.rdata);
            Some(Ipv6Addr::from(octets))
        } else {
            None
        }
    }
}

/// A parsed DNS message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsMessage {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
}

/// Wire-format DNS decoder.
pub struct DnsParser;

impl DnsParser {
    /// Parses a raw UDP/TCP DNS payload into a structured `DnsMessage`.
    pub fn parse(payload: &[u8]) -> Result<DnsMessage, DnsParseError> {
        if payload.len() < 12 {
            return Err(DnsParseError::PacketTooShort(payload.len()));
        }

        let id = u16::from_be_bytes([payload[0], payload[1]]);
        let flags = u16::from_be_bytes([payload[2], payload[3]]);
        let qd_count = u16::from_be_bytes([payload[4], payload[5]]);
        let an_count = u16::from_be_bytes([payload[6], payload[7]]);
        let ns_count = u16::from_be_bytes([payload[8], payload[9]]);
        let ar_count = u16::from_be_bytes([payload[10], payload[11]]);

        let is_response = (flags & 0x8000) != 0;
        let opcode = ((flags >> 11) & 0x0F) as u8;
        let authoritative = (flags & 0x0400) != 0;
        let truncated = (flags & 0x0200) != 0;
        let recursion_desired = (flags & 0x0100) != 0;
        let recursion_available = (flags & 0x0080) != 0;
        let rcode = (flags & 0x000F) as u8;

        let header = DnsHeader {
            id,
            is_response,
            opcode,
            authoritative,
            truncated,
            recursion_desired,
            recursion_available,
            rcode,
            qd_count,
            an_count,
            ns_count,
            ar_count,
        };

        let mut offset = 12;
        let mut questions = Vec::with_capacity(qd_count as usize);

        for _ in 0..qd_count {
            let (name, next_offset) = Self::parse_name(payload, offset)?;
            offset = next_offset;
            if offset + 4 > payload.len() {
                return Err(DnsParseError::TruncatedRecord);
            }
            let qtype = u16::from_be_bytes([payload[offset], payload[offset + 1]]).into();
            let qclass = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]);
            offset += 4;
            questions.push(DnsQuestion {
                name,
                qtype,
                qclass,
            });
        }

        let mut answers = Vec::with_capacity(an_count as usize);
        for _ in 0..an_count {
            if offset >= payload.len() {
                break;
            }
            let (name, next_offset) = Self::parse_name(payload, offset)?;
            offset = next_offset;
            if offset + 10 > payload.len() {
                return Err(DnsParseError::TruncatedRecord);
            }
            let rtype = u16::from_be_bytes([payload[offset], payload[offset + 1]]).into();
            let rclass = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]);
            let ttl = u32::from_be_bytes([
                payload[offset + 4],
                payload[offset + 5],
                payload[offset + 6],
                payload[offset + 7],
            ]);
            let rdlength = u16::from_be_bytes([payload[offset + 8], payload[offset + 9]]) as usize;
            offset += 10;

            if offset + rdlength > payload.len() {
                return Err(DnsParseError::TruncatedRecord);
            }

            let rdata = payload[offset..offset + rdlength].to_vec();
            offset += rdlength;

            answers.push(DnsRecord {
                name,
                rtype,
                rclass,
                ttl,
                rdata,
            });
        }

        Ok(DnsMessage {
            header,
            questions,
            answers,
        })
    }

    /// Parses a DNS label sequence, decompressing pointer references (`0xC0XX`).
    fn parse_name(payload: &[u8], mut offset: usize) -> Result<(String, usize), DnsParseError> {
        let mut labels = Vec::new();
        let mut jumps = 0;
        let mut end_offset = None;
        let mut current_offset = offset;

        loop {
            if current_offset >= payload.len() {
                return Err(DnsParseError::TruncatedRecord);
            }

            let len_byte = payload[current_offset];
            if len_byte == 0 {
                // End of name
                if end_offset.is_none() {
                    end_offset = Some(current_offset + 1);
                }
                break;
            }

            if (len_byte & 0xC0) == 0xC0 {
                // Pointer compression
                if current_offset + 1 >= payload.len() {
                    return Err(DnsParseError::TruncatedRecord);
                }
                if jumps >= 10 {
                    return Err(DnsParseError::PointerLoop);
                }
                let ptr =
                    (((len_byte & 0x3F) as usize) << 8) | (payload[current_offset + 1] as usize);
                if ptr >= payload.len() {
                    return Err(DnsParseError::PointerOutOfBounds(ptr));
                }

                if end_offset.is_none() {
                    end_offset = Some(current_offset + 2);
                }
                current_offset = ptr;
                jumps += 1;
                continue;
            }

            // Normal label
            let label_len = len_byte as usize;
            current_offset += 1;
            if current_offset + label_len > payload.len() {
                return Err(DnsParseError::TruncatedRecord);
            }

            let label =
                String::from_utf8_lossy(&payload[current_offset..current_offset + label_len])
                    .to_ascii_lowercase();
            labels.push(label);
            current_offset += label_len;

            if end_offset.is_none() {
                offset = current_offset;
            }
        }

        let full_name = labels.join(".");
        let final_offset = end_offset.unwrap_or(offset);
        Ok((full_name, final_offset))
    }
}

/// Detects DNS Tunneling and data exfiltration patterns over DNS port 53.
pub struct DnsTunnelingDetector {
    /// Maximum allowable length for an individual label before flagging (default 50).
    pub max_label_length: usize,
    /// Maximum allowable length for an entire FQDN (default 150).
    pub max_fqdn_length: usize,
    /// Minimum Shannon entropy threshold for suspicious payload encoding (default 3.8).
    pub entropy_threshold: f64,
    /// Sliding window tracking unique subdomain counts per domain name.
    subdomain_tracker: RwLock<HashMap<String, HashSet<String>>>,
}

impl Default for DnsTunnelingDetector {
    fn default() -> Self {
        Self {
            max_label_length: 50,
            max_fqdn_length: 150,
            entropy_threshold: 3.75,
            subdomain_tracker: RwLock::new(HashMap::new()),
        }
    }
}

impl DnsTunnelingDetector {
    /// Evaluates a query domain name for DNS tunneling anomalies.
    pub fn inspect(&self, domain: &str) -> Option<ThreatAlert> {
        let labels: Vec<&str> = domain.split('.').collect();

        // 1. Long label inspection
        for &label in &labels {
            if label.len() > self.max_label_length {
                let ent = shannon_entropy(label);
                if ent >= self.entropy_threshold {
                    return Some(ThreatAlert::new(
                        format!("dns-tunnel-{}", kwall_common::utilities::current_timestamp_ns()),
                        kwall_common::utilities::current_timestamp_ns(),
                        Severity::Error,
                        ThreatCategory::DnsTunneling,
                        Some("T1071.004"),
                        "DNS Tunneling Exfiltration Detected".to_string(),
                        format!(
                            "An abnormally long DNS subdomain label ({len} chars) with high entropy ({ent:.2}) was queried: {domain}",
                            len = label.len()
                        ),
                        None,
                        serde_json::json!({
                            "domain": domain,
                            "suspicious_label": label,
                            "label_length": label.len(),
                            "entropy": ent
                        }),
                        "Enforce egress network policy blocking external DNS and isolate pod"
                            .to_string(),
                    ));
                }
            }
        }

        // 2. Full FQDN length check
        if domain.len() > self.max_fqdn_length {
            let ent = shannon_entropy(domain);
            if ent >= self.entropy_threshold {
                return Some(ThreatAlert::new(
                    format!("dns-tunnel-{}", kwall_common::utilities::current_timestamp_ns()),
                    kwall_common::utilities::current_timestamp_ns(),
                    Severity::Error,
                    ThreatCategory::DnsTunneling,
                    Some("T1071.004"),
                    "DNS Tunneling Oversized FQDN Detected".to_string(),
                    format!(
                        "An excessively long DNS query ({len} chars) with high entropy ({ent:.2}) was detected: {domain}",
                        len = domain.len()
                    ),
                    None,
                    serde_json::json!({
                        "domain": domain,
                        "domain_length": domain.len(),
                        "entropy": ent
                    }),
                    "Block domain at DNS resolver and review pod outbound connections".to_string(),
                ));
            }
        }

        // 3. Unique subdomains query burst
        if labels.len() >= 3 {
            let parent_domain = labels[labels.len() - 2..].join(".");
            let subdomain = labels[..labels.len() - 2].join(".");

            if let Ok(mut tracker) = self.subdomain_tracker.write() {
                let subs = tracker.entry(parent_domain.clone()).or_default();
                subs.insert(subdomain);
                if subs.len() > 80 {
                    let count = subs.len();
                    return Some(ThreatAlert::new(
                        format!("dns-tunnel-burst-{}", kwall_common::utilities::current_timestamp_ns()),
                        kwall_common::utilities::current_timestamp_ns(),
                        Severity::Warning,
                        ThreatCategory::DnsTunneling,
                        Some("T1071.004"),
                        "DNS High Unique Subdomain Exfiltration Burst".to_string(),
                        format!(
                            "A burst of {count} unique subdomains under parent domain '{parent_domain}' was observed"
                        ),
                        None,
                        serde_json::json!({
                            "parent_domain": parent_domain,
                            "unique_subdomain_count": count
                        }),
                        "Investigate querying workload for DNS beaconing or tunneling tools".to_string(),
                    ));
                }
            }
        }

        None
    }
}

/// Detects Domain Generation Algorithms (DGA) used by malware Command & Control (C2).
pub struct DgaDetector {
    /// Shannon entropy threshold for DGA detection.
    pub entropy_threshold: f64,
    /// Consonant to vowel ratio threshold (natural words typically 1.2 to 2.5).
    pub max_consonant_ratio: f64,
}

impl Default for DgaDetector {
    fn default() -> Self {
        Self {
            entropy_threshold: 3.5,
            max_consonant_ratio: 4.0,
        }
    }
}

impl DgaDetector {
    /// Inspects the domain name for DGA characteristics.
    pub fn inspect(&self, domain: &str) -> Option<ThreatAlert> {
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.is_empty() {
            return None;
        }

        // Check the second-level domain (SLD) or first label
        let target_label = if parts.len() >= 2 {
            parts[parts.len() - 2]
        } else {
            parts[0]
        };

        if target_label.len() < 8 {
            return None; // Short domains are unlikely to exhibit reliable statistical DGA traits
        }

        let entropy = shannon_entropy(target_label);
        let (consonants, vowels, digits) = Self::count_character_classes(target_label);

        let vowel_count = vowels.max(1) as f64;
        let consonant_ratio = (consonants as f64) / vowel_count;

        // DGA condition: high entropy and extreme consonant clusters, or heavy numeric mixing
        if (entropy >= self.entropy_threshold && consonant_ratio >= self.max_consonant_ratio)
            || (entropy >= 3.7 && digits >= 4)
        {
            return Some(ThreatAlert::new(
                format!("dga-{}", kwall_common::utilities::current_timestamp_ns()),
                kwall_common::utilities::current_timestamp_ns(),
                Severity::Error,
                ThreatCategory::DgaDomain,
                Some("T1568.002"),
                "Domain Generation Algorithm (DGA) Detected".to_string(),
                format!(
                    "Domain query '{domain}' matched DGA statistical profile (entropy: {entropy:.2}, consonant ratio: {consonant_ratio:.2})"
                ),
                None,
                serde_json::json!({
                    "domain": domain,
                    "target_label": target_label,
                    "entropy": entropy,
                    "consonant_ratio": consonant_ratio,
                    "digits": digits
                }),
                "Quarantine network endpoint and inspect memory for active C2 loaders".to_string(),
            ));
        }

        None
    }

    fn count_character_classes(s: &str) -> (usize, usize, usize) {
        let mut consonants = 0;
        let mut vowels = 0;
        let mut digits = 0;

        for c in s.chars() {
            if c.is_ascii_digit() {
                digits += 1;
            } else if c.is_ascii_alphabetic() {
                match c.to_ascii_lowercase() {
                    'a' | 'e' | 'i' | 'o' | 'u' => vowels += 1,
                    _ => consonants += 1,
                }
            }
        }

        (consonants, vowels, digits)
    }
}

/// Detects attempts to bypass authorized Kubernetes cluster CoreDNS resolvers.
pub struct DnsBypassDetector {
    /// Authorized DNS resolver IP addresses (e.g., CoreDNS Service ClusterIP, NodeLocal DNS).
    pub authorized_resolvers: HashSet<Ipv4Addr>,
}

impl DnsBypassDetector {
    /// Creates a detector with authorized resolver IPs.
    pub fn new(authorized: &[Ipv4Addr]) -> Self {
        let mut set = HashSet::new();
        for &ip in authorized {
            set.insert(ip);
        }
        Self {
            authorized_resolvers: set,
        }
    }

    /// Checks if a DNS destination IP on port 53 is an authorized resolver.
    pub fn inspect(&self, dst_ip: Ipv4Addr, dst_port: u16) -> Option<ThreatAlert> {
        if dst_port != 53 {
            return None;
        }

        if !self.authorized_resolvers.is_empty() && !self.authorized_resolvers.contains(&dst_ip) {
            return Some(ThreatAlert::new(
                format!("dns-bypass-{}", kwall_common::utilities::current_timestamp_ns()),
                kwall_common::utilities::current_timestamp_ns(),
                Severity::Warning,
                ThreatCategory::DnsResolverBypass,
                Some("T1562.001"),
                "Unauthorized DNS Resolver Bypass Attempt".to_string(),
                format!(
                    "Pod attempted to send external DNS query directly to {dst_ip}:53, bypassing cluster CoreDNS"
                ),
                None,
                serde_json::json!({
                    "destination_ip": dst_ip.to_string(),
                    "destination_port": dst_port
                }),
                "Apply KWALL network policy restricting UDP/TCP port 53 exclusively to cluster DNS"
                    .to_string(),
            ));
        }

        None
    }
}

/// Unified DNS Security Inspector orchestrating parsing and behavioral detection.
pub struct DnsInspector {
    pub tunneling_detector: DnsTunnelingDetector,
    pub dga_detector: DgaDetector,
    pub bypass_detector: DnsBypassDetector,
}

impl DnsInspector {
    /// Creates a new DNS Inspector with authorized CoreDNS resolvers.
    pub fn new(authorized_resolvers: &[Ipv4Addr]) -> Self {
        Self {
            tunneling_detector: DnsTunnelingDetector::default(),
            dga_detector: DgaDetector::default(),
            bypass_detector: DnsBypassDetector::new(authorized_resolvers),
        }
    }

    /// Evaluates raw packet payload and destination for DNS security events.
    pub fn process_packet(
        &self,
        payload: &[u8],
        dst_ip: Ipv4Addr,
        dst_port: u16,
    ) -> (Option<DnsMessage>, Vec<ThreatAlert>) {
        let mut alerts = Vec::new();

        // Check resolver bypass
        if let Some(alert) = self.bypass_detector.inspect(dst_ip, dst_port) {
            alerts.push(alert);
        }

        // Parse DNS
        let message = match DnsParser::parse(payload) {
            Ok(msg) => msg,
            Err(_) => return (None, alerts),
        };

        // Inspect questions
        for question in &message.questions {
            if let Some(alert) = self.tunneling_detector.inspect(&question.name) {
                alerts.push(alert);
            }
            if let Some(alert) = self.dga_detector.inspect(&question.name) {
                alerts.push(alert);
            }
        }

        (Some(message), alerts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_parser_valid_query() {
        // Sample DNS Query for "example.com" type A
        // Header: ID=0x1234, Flags=0x0100 (RD), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
        let packet = vec![
            0x12, 0x34, // ID
            0x01, 0x00, // Flags (RD=1)
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x00, // ANCOUNT=0
            0x00, 0x00, // NSCOUNT=0
            0x00, 0x00, // ARCOUNT=0
            // Question: 7example3com0
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00,
            0x01, // QTYPE=A (1)
            0x00, 0x01, // QCLASS=IN (1)
        ];

        let parsed = DnsParser::parse(&packet).expect("Failed to parse valid DNS query");
        assert_eq!(parsed.header.id, 0x1234);
        assert!(!parsed.header.is_response);
        assert!(parsed.header.recursion_desired);
        assert_eq!(parsed.questions.len(), 1);
        assert_eq!(parsed.questions[0].name, "example.com");
        assert_eq!(parsed.questions[0].qtype, DnsQueryType::A);
    }

    #[test]
    fn test_dns_parser_decompression() {
        // DNS Query with compression pointer
        let packet = vec![
            0xAA, 0xBB, // ID
            0x81, 0x80, // Response, RD, RA
            0x00, 0x01, // QDCOUNT=1
            0x00, 0x01, // ANCOUNT=1
            0x00, 0x00, 0x00, 0x00, // Question: 3foo3bar3com0
            0x03, b'f', b'o', b'o', 0x03, b'b', b'a', b'r', 0x03, b'c', b'o', b'm', 0x00, 0x00,
            0x01, 0x00,
            0x01, // Answer: pointer to 0x000C ("foo.bar.com"), Type A, Class IN, TTL 300, RDLENGTH 4, 1.2.3.4
            0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x04, 1, 2, 3, 4,
        ];

        let parsed = DnsParser::parse(&packet).expect("Failed to parse compressed DNS message");
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(parsed.answers[0].name, "foo.bar.com");
        assert_eq!(parsed.answers[0].as_ipv4(), Some(Ipv4Addr::new(1, 2, 3, 4)));
    }

    #[test]
    fn test_dns_tunneling_detection() {
        let detector = DnsTunnelingDetector::default();

        // Normal domain should not alert
        assert!(detector.inspect("api.kubernetes.io").is_none());

        // Tunneling: high entropy long label (> 50 chars)
        let malicious =
            "a9f8b2c1d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7.exfil.attacker.com";
        let alert = detector.inspect(malicious);
        assert!(alert.is_some());
        let a = alert.unwrap();
        assert_eq!(a.category, ThreatCategory::DnsTunneling);
        assert_eq!(a.mitre_attack_id.as_deref(), Some("T1071.004"));
    }

    #[test]
    fn test_dga_detection() {
        let detector = DgaDetector::default();

        // Normal domain
        assert!(detector.inspect("google.com").is_none());

        // DGA domain with consonant ratio and high entropy
        let dga = "xzkpwrqjtvmcb.biz";
        let alert = detector.inspect(dga);
        assert!(alert.is_some());
        let a = alert.unwrap();
        assert_eq!(a.category, ThreatCategory::DgaDomain);
        assert_eq!(a.mitre_attack_id.as_deref(), Some("T1568.002"));
    }

    #[test]
    fn test_dns_bypass_detection() {
        let authorized = [Ipv4Addr::new(10, 96, 0, 10)]; // CoreDNS
        let detector = DnsBypassDetector::new(&authorized);

        // CoreDNS query is allowed
        assert!(detector.inspect(Ipv4Addr::new(10, 96, 0, 10), 53).is_none());

        // External 8.8.8.8 query is flagged as bypass
        let alert = detector.inspect(Ipv4Addr::new(8, 8, 8, 8), 53);
        assert!(alert.is_some());
        let a = alert.unwrap();
        assert_eq!(a.category, ThreatCategory::DnsResolverBypass);
    }
}
