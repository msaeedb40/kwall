//! TLS Handshake metadata extraction, unencrypted ClientHello parsing, and JA3/JA4 fingerprinting.
//!
//! Provides zero-copy inspection of TLS connection initialization, extracting Server Name Indication (SNI),
//! cipher suites, extensions, elliptic curves, and computing standard JA3 and JA4 client hashes.
#![allow(clippy::chunks_exact_to_as_chunks)]

use std::collections::HashMap;

use kwall_core::types::Severity;
use kwall_detection::alert::{ThreatAlert, ThreatCategory};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::crypto::{md5_hex, sha256_hex};

/// TLS Handshake parser errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TlsParseError {
    #[error("Packet is too short for TLS Record: {0} bytes")]
    RecordTooShort(usize),
    #[error("Not a TLS Handshake record (content type: {0:#x})")]
    NotHandshake(u8),
    #[error("Incomplete TLS Handshake payload")]
    IncompletePayload,
    #[error("Not a ClientHello handshake message (type: {0:#x})")]
    NotClientHello(u8),
    #[error("Malformed ClientHello structure")]
    MalformedClientHello,
}

/// Extracted TLS ClientHello metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsClientHello {
    /// TLS Record layer version (e.g., 0x0303 for TLS 1.2/1.3).
    pub record_version: u16,
    /// ClientHello handshake version.
    pub client_version: u16,
    /// Effective negotiated version (considers TLS 1.3 `supported_versions` extension).
    pub effective_version: u16,
    /// Server Name Indication (SNI) host, if present.
    pub sni: Option<String>,
    /// Negotiated ALPN protocols (e.g., ["h2", "http/1.1"]).
    pub alpn: Vec<String>,
    /// List of offered cipher suites (GREASE filtered).
    pub cipher_suites: Vec<u16>,
    /// List of offered TLS extension types (GREASE filtered).
    pub extensions: Vec<u16>,
    /// List of supported elliptic curves / groups (extension 0x000a).
    pub supported_groups: Vec<u16>,
    /// List of supported EC point formats (extension 0x000b).
    pub ec_point_formats: Vec<u8>,
    /// List of supported signature hash algorithms (extension 0x000d).
    pub signature_algorithms: Vec<u16>,
}

/// Computes whether a 16-bit value is a GREASE value per RFC 8701.
#[must_use]
pub fn is_grease_u16(val: u16) -> bool {
    let high = (val >> 8) as u8;
    let low = (val & 0xFF) as u8;
    high == low && (high & 0x0F) == 0x0A
}

/// TLS Handshake binary parser.
pub struct TlsParser;

impl TlsParser {
    /// Attempts to parse a raw packet payload into a structured `TlsClientHello`.
    pub fn parse_client_hello(payload: &[u8]) -> Result<TlsClientHello, TlsParseError> {
        if payload.len() < 5 {
            return Err(TlsParseError::RecordTooShort(payload.len()));
        }

        // 1. TLS Record Header
        let content_type = payload[0];
        if content_type != 0x16 {
            // 0x16 = Handshake
            return Err(TlsParseError::NotHandshake(content_type));
        }

        let record_version = u16::from_be_bytes([payload[1], payload[2]]);
        let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;

        if payload.len() < 5 + record_len {
            return Err(TlsParseError::IncompletePayload);
        }

        let hs_data = &payload[5..5 + record_len];
        if hs_data.len() < 4 {
            return Err(TlsParseError::IncompletePayload);
        }

        // 2. Handshake Header
        let hs_type = hs_data[0];
        if hs_type != 0x01 {
            // 0x01 = ClientHello
            return Err(TlsParseError::NotClientHello(hs_type));
        }

        let hs_len =
            ((hs_data[1] as usize) << 16) | ((hs_data[2] as usize) << 8) | (hs_data[3] as usize);

        if hs_data.len() < 4 + hs_len {
            return Err(TlsParseError::IncompletePayload);
        }

        let body = &hs_data[4..4 + hs_len];
        if body.len() < 34 {
            // client_version (2) + random (32)
            return Err(TlsParseError::MalformedClientHello);
        }

        let client_version = u16::from_be_bytes([body[0], body[1]]);
        let mut offset = 34; // skip version + 32-byte random

        // Session ID
        if offset >= body.len() {
            return Err(TlsParseError::MalformedClientHello);
        }
        let session_id_len = body[offset] as usize;
        offset += 1 + session_id_len;

        // Cipher Suites
        if offset + 2 > body.len() {
            return Err(TlsParseError::MalformedClientHello);
        }
        let ciphers_len = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
        offset += 2;

        if offset + ciphers_len > body.len() {
            return Err(TlsParseError::MalformedClientHello);
        }

        let mut cipher_suites = Vec::new();
        for chunk in body[offset..offset + ciphers_len].chunks_exact(2) {
            let cs = u16::from_be_bytes([chunk[0], chunk[1]]);
            if !is_grease_u16(cs) {
                cipher_suites.push(cs);
            }
        }
        offset += ciphers_len;

        // Compression Methods
        if offset >= body.len() {
            return Err(TlsParseError::MalformedClientHello);
        }
        let comp_len = body[offset] as usize;
        offset += 1 + comp_len;

        // Extensions (optional)
        let mut extensions = Vec::new();
        let mut supported_groups = Vec::new();
        let mut ec_point_formats = Vec::new();
        let mut signature_algorithms = Vec::new();
        let mut sni = None;
        let mut alpn = Vec::new();
        let mut supported_versions = Vec::new();

        if offset + 2 <= body.len() {
            let ext_len = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
            offset += 2;

            let ext_end = (offset + ext_len).min(body.len());
            while offset + 4 <= ext_end {
                let ext_type = u16::from_be_bytes([body[offset], body[offset + 1]]);
                let ext_data_len =
                    u16::from_be_bytes([body[offset + 2], body[offset + 3]]) as usize;
                offset += 4;

                if offset + ext_data_len > ext_end {
                    break;
                }

                let ext_data = &body[offset..offset + ext_data_len];
                offset += ext_data_len;

                if !is_grease_u16(ext_type) {
                    extensions.push(ext_type);
                }

                match ext_type {
                    0x0000 => {
                        // SNI
                        sni = Self::parse_sni(ext_data);
                    }
                    0x000a => {
                        // Supported Groups / Elliptic Curves
                        if ext_data.len() >= 2 {
                            let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                            for chunk in
                                ext_data[2..(2 + list_len).min(ext_data.len())].chunks_exact(2)
                            {
                                let g = u16::from_be_bytes([chunk[0], chunk[1]]);
                                if !is_grease_u16(g) {
                                    supported_groups.push(g);
                                }
                            }
                        }
                    }
                    0x000b => {
                        // EC Point Formats
                        if !ext_data.is_empty() {
                            let list_len = ext_data[0] as usize;
                            ec_point_formats =
                                ext_data[1..(1 + list_len).min(ext_data.len())].to_vec();
                        }
                    }
                    0x000d => {
                        // Signature Algorithms
                        if ext_data.len() >= 2 {
                            let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                            for chunk in
                                ext_data[2..(2 + list_len).min(ext_data.len())].chunks_exact(2)
                            {
                                signature_algorithms.push(u16::from_be_bytes([chunk[0], chunk[1]]));
                            }
                        }
                    }
                    0x0010 => {
                        // ALPN
                        alpn = Self::parse_alpn(ext_data);
                    }
                    0x002b if !ext_data.is_empty() => {
                        // Supported Versions (TLS 1.3)
                        let list_len = ext_data[0] as usize;
                        for chunk in ext_data[1..(1 + list_len).min(ext_data.len())].chunks_exact(2)
                        {
                            let ver = u16::from_be_bytes([chunk[0], chunk[1]]);
                            if !is_grease_u16(ver) {
                                supported_versions.push(ver);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // Determine effective TLS version: if 0x0304 (TLS 1.3) is in supported_versions, it is 1.3
        let effective_version = if supported_versions.contains(&0x0304) {
            0x0304
        } else {
            client_version
        };

        Ok(TlsClientHello {
            record_version,
            client_version,
            effective_version,
            sni,
            alpn,
            cipher_suites,
            extensions,
            supported_groups,
            ec_point_formats,
            signature_algorithms,
        })
    }

    fn parse_sni(data: &[u8]) -> Option<String> {
        if data.len() < 5 {
            return None;
        }
        // server_name_list_length (2)
        // name_type (1: 0 = host_name)
        // name_length (2)
        if data[2] != 0 {
            return None;
        }
        let name_len = u16::from_be_bytes([data[3], data[4]]) as usize;
        if data.len() < 5 + name_len {
            return None;
        }
        String::from_utf8(data[5..5 + name_len].to_vec()).ok()
    }

    fn parse_alpn(data: &[u8]) -> Vec<String> {
        let mut result = Vec::new();
        if data.len() < 2 {
            return result;
        }
        let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        let mut offset = 2;
        let end = (2 + list_len).min(data.len());

        while offset < end {
            let str_len = data[offset] as usize;
            offset += 1;
            if offset + str_len > end {
                break;
            }
            if let Ok(proto) = std::str::from_utf8(&data[offset..offset + str_len]) {
                result.push(proto.to_string());
            }
            offset += str_len;
        }
        result
    }
}

/// Fingerprint generator computing JA3 and JA4 hashes for TLS clients.
pub struct TlsFingerprinter;

impl TlsFingerprinter {
    /// Computes the Salesforce JA3 fingerprint string and MD5 hash.
    ///
    /// JA3 Format: `SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat`
    #[must_use]
    pub fn compute_ja3(hello: &TlsClientHello) -> (String, String) {
        let ver = hello.client_version.to_string();

        let ciphers = hello
            .cipher_suites
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("-");

        let exts = hello
            .extensions
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("-");

        let curves = hello
            .supported_groups
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("-");

        let points = hello
            .ec_point_formats
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("-");

        let ja3_raw = format!("{ver},{ciphers},{exts},{curves},{points}");
        let ja3_hash = md5_hex(ja3_raw.as_bytes());

        (ja3_raw, ja3_hash)
    }

    /// Computes the JA4 fingerprint string.
    ///
    /// JA4 Format: `{proto}{version}{sni}{ciphers_count}{ext_count}{alpn}_{ciphers_hash}_{ext_hash}`
    #[must_use]
    pub fn compute_ja4(hello: &TlsClientHello) -> String {
        // Protocol: 't' for TCP
        let proto = "t";

        // Version: 13, 12, 11, 10, 00
        let version_str = match hello.effective_version {
            0x0304 => "13",
            0x0303 => "12",
            0x0302 => "11",
            0x0301 => "10",
            _ => "00",
        };

        // SNI: 'd' if domain, 'i' if IP, '00' if none
        let sni_str = match &hello.sni {
            Some(s) if s.parse::<std::net::IpAddr>().is_ok() => "i",
            Some(_) => "d",
            None => "00",
        };

        // Number of ciphers and extensions (2 digits, capped at 99)
        let num_ciphers = hello.cipher_suites.len().min(99);
        let num_exts = hello.extensions.len().min(99);

        // ALPN: first and last character of first ALPN string or '00'
        let alpn_str = if let Some(first_alpn) = hello.alpn.first() {
            if first_alpn.len() >= 2 {
                let first_char = first_alpn.chars().next().unwrap_or('0');
                let last_char = first_alpn.chars().last().unwrap_or('0');
                format!("{first_char}{last_char}")
            } else if first_alpn.len() == 1 {
                format!("{first_alpn}0")
            } else {
                "00".to_string()
            }
        } else {
            "00".to_string()
        };

        let part_a =
            format!("{proto}{version_str}{sni_str}{num_ciphers:02}{num_exts:02}{alpn_str}");

        // Part B: sorted ciphers hashed with SHA256 (truncated to 12 hex chars)
        let mut sorted_ciphers = hello.cipher_suites.clone();
        sorted_ciphers.sort_unstable();
        let ciphers_str = sorted_ciphers
            .iter()
            .map(|c| format!("{c:04x}"))
            .collect::<Vec<_>>()
            .join(",");
        let full_cipher_hash = sha256_hex(ciphers_str.as_bytes());
        let part_b = &full_cipher_hash[..12];

        // Part C: sorted extensions + signature algorithms hashed with SHA256 (truncated to 12 hex chars)
        let mut sorted_exts = hello.extensions.clone();
        sorted_exts.sort_unstable();
        let mut ext_elements: Vec<String> =
            sorted_exts.iter().map(|e| format!("{e:04x}")).collect();
        for sig in &hello.signature_algorithms {
            ext_elements.push(format!("{sig:04x}"));
        }
        let ext_str = ext_elements.join(",");
        let full_ext_hash = sha256_hex(ext_str.as_bytes());
        let part_c = &full_ext_hash[..12];

        format!("{part_a}_{part_b}_{part_c}")
    }
}

/// Known malicious / offensive tool JA3 database and threat detector.
pub struct TlsThreatDetector {
    /// Known malicious JA3 hashes mapped to threat profile name.
    pub malicious_ja3: HashMap<String, &'static str>,
}

impl Default for TlsThreatDetector {
    fn default() -> Self {
        let mut map = HashMap::new();
        // Cobalt Strike default beacons
        map.insert(
            "a0e9f5d64349fb13191bc781f81f42e1".to_string(),
            "Cobalt Strike Default Malleable C2 Beacon",
        );
        map.insert(
            "72a589da586844d7f0818ce684948eea".to_string(),
            "Cobalt Strike Beacon Variant",
        );
        // Metasploit Meterpreter
        map.insert(
            "b32309a26951912be7dba376398abc3b".to_string(),
            "Metasploit Meterpreter Reverse HTTPS",
        );
        // Emotet / TrickBot Banking Trojans
        map.insert(
            "4d7a28d6f22da2d1030e2001eb70fb76".to_string(),
            "Emotet / TrickBot C2 Client",
        );
        // Standard automated scripts (flagged if accessing internal zero-trust endpoints)
        map.insert(
            "b7423374e2a4f913cc3f501d49608544".to_string(),
            "Python Requests Library Client",
        );

        Self { malicious_ja3: map }
    }
}

impl TlsThreatDetector {
    /// Inspects computed JA3 and JA4 hashes against malicious threat signatures.
    #[must_use]
    pub fn inspect(
        &self,
        ja3_hash: &str,
        ja4_fingerprint: &str,
        sni: Option<&str>,
    ) -> Option<ThreatAlert> {
        if let Some(&threat_name) = self.malicious_ja3.get(ja3_hash) {
            let now = kwall_common::utilities::current_timestamp_ns();
            return Some(ThreatAlert::new(
                format!("tls-malicious-{}", now),
                now,
                Severity::Error,
                ThreatCategory::TlsFingerprintAnomaly,
                Some("T1071.001"),
                format!("Malicious TLS Client Fingerprint Detected ({threat_name})"),
                format!(
                    "Connection matched malicious JA3 fingerprint {ja3_hash} ({threat_name}) with JA4 {ja4_fingerprint} and SNI {:?}",
                    sni
                ),
                None,
                serde_json::json!({
                    "ja3_hash": ja3_hash,
                    "ja4_fingerprint": ja4_fingerprint,
                    "threat_profile": threat_name,
                    "sni": sni
                }),
                "Immediately terminate TLS session and isolate source container".to_string(),
            ));
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sample_client_hello() {
        // Construct a synthetic ClientHello
        // Record Header: Type 0x16, Version 0x0303, Length: N
        let mut body = Vec::new();
        // Client Version
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        // 32-byte Random
        body.extend_from_slice(&[0x42; 32]);
        // Session ID length 0
        body.push(0x00);
        // Cipher Suites length 4: 0x1301 (TLS_AES_128_GCM_SHA256), 0x1302 (TLS_AES_256_GCM_SHA384)
        body.extend_from_slice(&4u16.to_be_bytes());
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.extend_from_slice(&0x1302u16.to_be_bytes());
        // Compression methods: 1 byte len, 0x00
        body.push(0x01);
        body.push(0x00);

        // Extensions
        let mut ext_data = Vec::new();
        // Extension 0x0000: SNI "kwall.io"
        ext_data.extend_from_slice(&0x0000u16.to_be_bytes());
        // SNI payload: list_len=10, type=0, name_len=8, "kwall.io"
        let sni_bytes = b"kwall.io";
        let sni_ext_len = (5 + sni_bytes.len()) as u16;
        ext_data.extend_from_slice(&sni_ext_len.to_be_bytes());
        ext_data.extend_from_slice(&(sni_bytes.len() as u16 + 3).to_be_bytes()); // list len
        ext_data.push(0x00); // host_name
        ext_data.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
        ext_data.extend_from_slice(sni_bytes);

        // Extension 0x000a: Supported Groups (x25519 = 0x001d)
        ext_data.extend_from_slice(&0x000au16.to_be_bytes());
        ext_data.extend_from_slice(&4u16.to_be_bytes()); // ext len
        ext_data.extend_from_slice(&2u16.to_be_bytes()); // list len
        ext_data.extend_from_slice(&0x001du16.to_be_bytes());

        // Extension 0x000b: EC Point Formats (0)
        ext_data.extend_from_slice(&0x000bu16.to_be_bytes());
        ext_data.extend_from_slice(&2u16.to_be_bytes());
        ext_data.push(0x01); // list len
        ext_data.push(0x00); // uncompressed

        // Append extensions length and extensions
        body.extend_from_slice(&(ext_data.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext_data);

        // Handshake Header: Type 0x01 (ClientHello), Length (3 bytes)
        let mut handshake = Vec::new();
        handshake.push(0x01);
        let blen = body.len();
        handshake.push(((blen >> 16) & 0xFF) as u8);
        handshake.push(((blen >> 8) & 0xFF) as u8);
        handshake.push((blen & 0xFF) as u8);
        handshake.extend_from_slice(&body);

        // Record Header: Type 0x16, Version 0x0303, Length
        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&0x0303u16.to_be_bytes());
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        let parsed = TlsParser::parse_client_hello(&record).expect("ClientHello should parse");
        assert_eq!(parsed.client_version, 0x0303);
        assert_eq!(parsed.sni.as_deref(), Some("kwall.io"));
        assert_eq!(parsed.cipher_suites, vec![0x1301, 0x1302]);
        assert_eq!(parsed.supported_groups, vec![0x001d]);
        assert_eq!(parsed.ec_point_formats, vec![0x00]);

        // Test JA3 calculation
        let (raw_ja3, ja3_hash) = TlsFingerprinter::compute_ja3(&parsed);
        assert_eq!(raw_ja3, "771,4865-4866,0-10-11,29,0");
        assert_eq!(ja3_hash.len(), 32);

        // Test JA4 calculation
        let ja4 = TlsFingerprinter::compute_ja4(&parsed);
        assert!(ja4.starts_with("t12d020300_"));
    }

    #[test]
    fn test_malicious_ja3_detection() {
        let detector = TlsThreatDetector::default();
        let cs_hash = "a0e9f5d64349fb13191bc781f81f42e1";
        let alert = detector.inspect(cs_hash, "t13d100500_abc123_def456", Some("evil.com"));
        assert!(alert.is_some());
        let a = alert.unwrap();
        assert_eq!(a.category, ThreatCategory::TlsFingerprintAnomaly);
        assert_eq!(a.severity, Severity::Error);
    }
}
