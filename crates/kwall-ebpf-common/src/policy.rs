#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
pub struct PolicyKey {
    pub src_identity: u32,
    pub dst_identity: u32,
    pub dst_port: u16,
    pub protocol: u8,
    pub direction: u8,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "user", derive(serde::Serialize, serde::Deserialize))]
pub struct PolicyValue {
    pub action: u32,
    pub policy_id: u32,
    pub priority: u32,
    pub rate_limit_pps: u32,
}
