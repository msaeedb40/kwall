#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
pub enum SecurityEventType {
    Unknown = 0,
    PortScan = 1,
    SynFlood = 2,
    UdpFlood = 3,
    DnsTunneling = 4,
    Cryptomining = 5,
    ContainerEscapeAttempt = 6,
    MaliciousProcessExec = 7,
    PrivilegeEscalation = 8,
    UnauthorizedSyscall = 9,
    PolicyViolation = 10,
    ArpSpoofing = 11,
    DataExfiltrationAnomaly = 12,
    MacAnomaly = 13,
    IpSpoofing = 14,
    NetworkScan = 15,
    IcmpAbuse = 16,
    ConnectionExhaustion = 17,
    HttpAbuse = 18,
    ApiAnomaly = 19,
    FileIntegrityViolation = 20,
    NamespaceEscape = 21,
    UntrustedBinary = 22,
    SignatureVerificationFailed = 23,
    LateralMovementAttempt = 24,
    VolumetricDDoS = 25,
    C2Beaconing = 26,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
pub enum Severity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
pub struct SecurityEvent {
    pub timestamp_ns: u64,
    pub event_type: u32,
    pub severity: u32,
    pub identity_id: u32,
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: [u8; 16],
    pub extra_data: [u64; 8],
}

impl Default for SecurityEvent {
    fn default() -> Self {
        Self {
            timestamp_ns: 0,
            event_type: SecurityEventType::Unknown as u32,
            severity: Severity::Info as u32,
            identity_id: 0,
            pid: 0,
            uid: 0,
            gid: 0,
            comm: [0; 16],
            extra_data: [0; 8],
        }
    }
}
