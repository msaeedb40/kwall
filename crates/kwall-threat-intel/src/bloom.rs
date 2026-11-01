//! High-performance, memory-efficient Bloom filter for sub-microsecond threat lookups.

use serde::{Deserialize, Serialize};

/// High-speed Bloom Filter for fast negative membership testing of indicators.
/// If `contains(val)` returns `false`, the indicator is guaranteed NOT to be in the threat database.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatBloomFilter {
    bit_vec: Vec<u64>,
    num_bits: usize,
    num_hashes: usize,
    count: usize,
}

impl ThreatBloomFilter {
    /// Constructs a Bloom filter sized for an expected capacity `n` and target false-positive rate `p` (e.g., 0.01 for 1%).
    #[must_use]
    pub fn new(expected_elements: usize, false_positive_rate: f64) -> Self {
        let n = expected_elements.max(64) as f64;
        let p = false_positive_rate.clamp(0.0001, 0.5);

        // Optimal number of bits: m = - (n * ln(p)) / (ln(2)^2)
        let ln2 = std::f64::consts::LN_2;
        let m = (-(n * p.ln()) / (ln2 * ln2)).ceil() as usize;

        // Round up to multiple of 64 for efficient u64 word operations
        let num_bits = m.div_ceil(64) * 64;
        let num_words = num_bits / 64;

        // Optimal number of hash functions: k = (m / n) * ln(2)
        let k = (((num_bits as f64) / n) * ln2).round() as usize;
        let num_hashes = k.clamp(2, 30);

        Self {
            bit_vec: vec![0u64; num_words],
            num_bits,
            num_hashes,
            count: 0,
        }
    }

    /// Primary 64-bit FNV-1a hash function.
    fn hash1(data: &[u8]) -> u64 {
        const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
        const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;

        let mut hash = FNV_OFFSET_BASIS;
        for &byte in data {
            hash ^= u64::from(byte);
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        hash
    }

    /// Secondary 64-bit Murmur-style mixing hash function with distinct seed.
    fn hash2(data: &[u8]) -> u64 {
        const SEED: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut hash = SEED;
        for &byte in data {
            hash = hash.rotate_left(5) ^ u64::from(byte);
            hash = hash.wrapping_mul(0x517c_c1b7_2722_0a95);
        }
        // Final avalanche mix
        hash ^= hash >> 33;
        hash = hash.wrapping_mul(0xff51_afd7_ed55_8ccd);
        hash ^= hash >> 33;
        hash
    }

    /// Inserts an indicator key into the Bloom filter.
    pub fn insert(&mut self, item: &str) {
        let bytes = item.as_bytes();
        let h1 = Self::hash1(bytes);
        let h2 = Self::hash2(bytes);

        for i in 0..self.num_hashes {
            // Double hashing: g_i(x) = h1 + i * h2 (mod m)
            let combined = h1.wrapping_add((i as u64).wrapping_mul(h2));
            let bit_idx = (combined as usize) % self.num_bits;

            let word_idx = bit_idx / 64;
            let bit_in_word = bit_idx % 64;
            self.bit_vec[word_idx] |= 1u64 << bit_in_word;
        }
        self.count += 1;
    }

    /// Tests whether an item might be present in the filter.
    /// Returns `false` if definitively NOT present; returns `true` if possibly present.
    #[must_use]
    pub fn contains(&self, item: &str) -> bool {
        if self.count == 0 {
            return false;
        }

        let bytes = item.as_bytes();
        let h1 = Self::hash1(bytes);
        let h2 = Self::hash2(bytes);

        for i in 0..self.num_hashes {
            let combined = h1.wrapping_add((i as u64).wrapping_mul(h2));
            let bit_idx = (combined as usize) % self.num_bits;

            let word_idx = bit_idx / 64;
            let bit_in_word = bit_idx % 64;
            if (self.bit_vec[word_idx] & (1u64 << bit_in_word)) == 0 {
                return false;
            }
        }

        true
    }

    /// Number of items inserted into the filter.
    #[must_use]
    pub fn len(&self) -> usize {
        self.count
    }

    /// Returns true if no items have been inserted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Total allocated bits in the filter.
    #[must_use]
    pub fn num_bits(&self) -> usize {
        self.num_bits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bloom_filter_membership_and_absence() {
        let mut filter = ThreatBloomFilter::new(1000, 0.01);
        assert!(filter.is_empty());

        let malicious_ips = ["198.51.100.1", "198.51.100.2", "203.0.113.5", "192.0.2.99"];

        for ip in &malicious_ips {
            filter.insert(ip);
        }

        assert_eq!(filter.len(), 4);

        // Positive tests
        for ip in &malicious_ips {
            assert!(filter.contains(ip), "Filter should contain {ip}");
        }

        // Negative tests
        let safe_ips = ["10.0.0.1", "172.16.0.1", "127.0.0.1", "8.8.8.8"];
        for ip in &safe_ips {
            assert!(!filter.contains(ip), "Filter should NOT contain {ip}");
        }
    }
}
