//! # kwall-identity
//!
//! Workload identity, trust domains, and SPIFFE identity attestation.

pub mod spiffe;

pub use spiffe::SpiffeId;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spiffe_formatting_and_parsing() {
        let spiffe = SpiffeId::new("cluster.local", "production", "payment-service");
        let uri = spiffe.to_string();
        assert_eq!(
            uri,
            "spiffe://cluster.local/ns/production/sa/payment-service"
        );

        let parsed = SpiffeId::parse(&uri).unwrap();
        assert_eq!(parsed, spiffe);
    }

    #[test]
    fn test_invalid_spiffe_uri() {
        assert!(SpiffeId::parse("https://invalid.url").is_err());
        assert!(SpiffeId::parse("spiffe://cluster.local/invalid").is_err());
    }
}
