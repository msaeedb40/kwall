//! KWALL Layer 7 Protocol Parsing & Application-Layer Security Engine.
//!
//! Provides zero-copy DNS wire protocol decoding, DNS tunneling and DGA detection,
//! HTTP/1.x stream inspection with web exploit signature filtering (SQLi, XSS, Log4Shell, Path Traversal),
//! TLS Handshake extraction with JA3/JA4 fingerprinting, and eBPF `sockops` / `sk_msg` socket redirection.

pub mod crypto;
pub mod dns;
pub mod http;
pub mod sockops;
pub mod tls;

pub use crypto::{md5_digest, md5_hex, sha256_digest, sha256_hex, shannon_entropy};
pub use dns::{
    DgaDetector, DnsBypassDetector, DnsHeader, DnsInspector, DnsMessage, DnsParseError, DnsParser,
    DnsQueryType, DnsQuestion, DnsRecord, DnsTunnelingDetector,
};
pub use http::{
    HttpAttackFinding, HttpAttackType, HttpLatencyMetrics, HttpMethod, HttpParser, HttpRequest,
    HttpResponse, HttpSecurityDetector,
};
pub use sockops::{SockFlowKey, SockOpsController, SockOpsOpcode, SockOpsStats, SocketFlowEntry};
pub use tls::{TlsClientHello, TlsFingerprinter, TlsParseError, TlsParser, TlsThreatDetector};
