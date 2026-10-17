use kwall_ebpf_common::IDENTITY_MIN_WORKLOAD;
use std::collections::BTreeMap;

pub struct IdentityAllocator;

impl IdentityAllocator {
    pub fn allocate(namespace: &str, labels: &BTreeMap<String, String>) -> u32 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(namespace.as_bytes());
        for (k, v) in labels {
            hasher.update(k.as_bytes());
            hasher.update(b"=");
            hasher.update(v.as_bytes());
            hasher.update(b";");
        }
        let hash = hasher.finalize();
        let bytes: [u8; 4] = hash.as_bytes()[0..4].try_into().unwrap();
        let raw_id = u32::from_ne_bytes(bytes);

        // Ensure ID is in workload range (>= IDENTITY_MIN_WORKLOAD, e.g. 1000)
        (raw_id % (u32::MAX - IDENTITY_MIN_WORKLOAD)) + IDENTITY_MIN_WORKLOAD
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_allocation_determinism() {
        let mut labels = BTreeMap::new();
        labels.insert("app".into(), "frontend".into());
        labels.insert("tier".into(), "web".into());

        let id1 = IdentityAllocator::allocate("production", &labels);
        let id2 = IdentityAllocator::allocate("production", &labels);
        assert_eq!(id1, id2);
        assert!(id1 >= IDENTITY_MIN_WORKLOAD);

        let mut diff_labels = labels.clone();
        diff_labels.insert("app".into(), "backend".into());
        let id3 = IdentityAllocator::allocate("production", &diff_labels);
        assert_ne!(id1, id3);
    }
}
