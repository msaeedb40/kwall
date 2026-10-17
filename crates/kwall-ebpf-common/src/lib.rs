#![cfg_attr(not(test), no_std)]

pub mod events;
pub mod flow;
pub mod identity;
pub mod maps;
pub mod policy;

pub use events::*;
pub use flow::*;
pub use identity::*;
pub use maps::*;
pub use policy::*;

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, size_of};

    #[test]
    fn test_abi_sizes_and_alignments() {
        // FlowEvent must be 8-byte aligned and 88 bytes (all 64-bit offsets aligned)
        assert_eq!(size_of::<FlowEvent>(), 88);
        assert_eq!(align_of::<FlowEvent>(), 8);

        // SecurityEvent must be 8-byte aligned and 112 bytes
        assert_eq!(size_of::<SecurityEvent>(), 112);
        assert_eq!(align_of::<SecurityEvent>(), 8);

        // EndpointIdentity must be 8-byte aligned and 48 bytes
        assert_eq!(size_of::<EndpointIdentity>(), 48);
        assert_eq!(align_of::<EndpointIdentity>(), 8);

        // Conntrack structures
        assert_eq!(align_of::<ConntrackKey>(), 2);
        assert_eq!(size_of::<ConntrackValue>(), 40);
        assert_eq!(align_of::<ConntrackValue>(), 8);

        // Policy structures
        assert_eq!(size_of::<PolicyKey>(), 12);
        assert_eq!(align_of::<PolicyKey>(), 4);
        assert_eq!(size_of::<PolicyValue>(), 16);
        assert_eq!(align_of::<PolicyValue>(), 4);

        // LPM Keys
        assert_eq!(size_of::<LpmIpv4Key>(), 8);
        assert_eq!(size_of::<LpmIpv6Key>(), 20);

        // RateLimit structures
        assert_eq!(size_of::<RateLimitKey>(), 24);
        assert_eq!(size_of::<RateLimitValue>(), 32);
    }
}
