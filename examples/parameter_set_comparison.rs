//! Parameter Set Comparison - PASETO-PQ ML-DSA Security Levels
//!
//! This example demonstrates the different ML-DSA parameter sets available
//! in PASETO-PQ and their impact on token size and performance.
//!
//! Note: Only one parameter set can be active at compile time.
//! Change the feature in Cargo.toml to test different sets:
//!   - ml-dsa-44: 128-bit security (smallest tokens)
//!   - ml-dsa-65: 192-bit security (balanced)
//!   - ml-dsa-87: 256-bit security (maximum security)

use paseto_pq::{Claims, KeyPair, PasetoPQ, TOKEN_PREFIX_PUBLIC, TokenSizeEstimator};
use std::time::Instant;
use time::{Duration, OffsetDateTime};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== PASETO-PQ Parameter Set Analysis ===\n");

    let mut rng = rand::rng();

    // Determine active parameter set
    let param_set = if cfg!(feature = "ml-dsa-44") {
        "ML-DSA-44 (128-bit security)"
    } else if cfg!(feature = "ml-dsa-65") {
        "ML-DSA-65 (192-bit security)"
    } else if cfg!(feature = "ml-dsa-87") {
        "ML-DSA-87 (256-bit security)"
    } else {
        "Unknown (default: ML-DSA-44)"
    };

    println!("Active Parameter Set: {}\n", param_set);
    println!("Token Prefix: {}\n", TOKEN_PREFIX_PUBLIC);

    // ============================================
    // Key Generation
    // ============================================
    println!("--- Key Generation ---\n");

    let start = Instant::now();
    let keypair = KeyPair::generate(&mut rng);
    let keygen_time = start.elapsed();

    let signing_key_bytes = keypair.signing_key_to_bytes();
    let verifying_key_bytes = keypair.verifying_key_to_bytes();

    println!("Key generation time: {:?}", keygen_time);
    println!("Signing key size:    {} bytes", signing_key_bytes.len());
    println!("Verifying key size:  {} bytes", verifying_key_bytes.len());
    println!();

    // ============================================
    // Token Size Analysis
    // ============================================
    println!("--- Token Size Analysis ---\n");

    // Create sample claims
    let mut claims = Claims::new();
    claims.set_subject("user123")?;
    claims.set_issuer("param-comparison")?;
    claims.set_audience("api.example.com")?;
    claims.set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))?;

    // Estimate size
    let estimator = TokenSizeEstimator::public(&claims, None)?;
    let breakdown = estimator.breakdown();

    println!("Token Size Breakdown:");
    println!("  Prefix:    {} bytes", breakdown.prefix);
    println!("  Payload:   {} bytes", breakdown.payload);
    println!("  Signature: {} bytes", breakdown.signature_or_tag);
    println!("  Total:     {} bytes", estimator.total_bytes());
    println!();

    // Create actual token
    let start = Instant::now();
    let token = PasetoPQ::sign(keypair.signing_key(), &claims)?;
    let sign_time = start.elapsed();

    println!("Actual token size: {} bytes", token.len());
    println!("Sign time: {:?}", sign_time);
    println!();

    // ============================================
    // Size Limit Checks
    // ============================================
    println!("--- Size Limit Compatibility ---\n");

    println!(
        "Fits in Cookie (4KB):  {}",
        if estimator.fits_in_cookie() {
            "YES"
        } else {
            "NO"
        }
    );
    println!(
        "Fits in URL (2KB):     {}",
        if estimator.fits_in_url() { "YES" } else { "NO" }
    );
    println!(
        "Fits in Header (8KB):  {}",
        if estimator.fits_in_header() {
            "YES"
        } else {
            "NO"
        }
    );
    println!();

    // ============================================
    // Verification Performance
    // ============================================
    println!("--- Verification Performance ---\n");

    let start = Instant::now();
    let verified = PasetoPQ::verify(keypair.verifying_key(), &token)?;
    let verify_time = start.elapsed();

    println!("Verify time: {:?}", verify_time);
    println!("Subject: {:?}", verified.claims().subject());
    println!();

    // ============================================
    // Batch Performance
    // ============================================
    println!("--- Batch Performance (50 tokens) ---\n");

    let start = Instant::now();
    let mut tokens = Vec::with_capacity(50);
    for i in 0..50 {
        let mut c = Claims::new();
        c.set_subject(&format!("user{}", i))?;
        c.set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))?;
        tokens.push(PasetoPQ::sign(keypair.signing_key(), &c)?);
    }
    let batch_sign_time = start.elapsed();

    let start = Instant::now();
    for token in &tokens {
        let _ = PasetoPQ::verify(keypair.verifying_key(), token)?;
    }
    let batch_verify_time = start.elapsed();

    println!(
        "Batch sign time:   {:?} ({:?} avg)",
        batch_sign_time,
        batch_sign_time / 50
    );
    println!(
        "Batch verify time: {:?} ({:?} avg)",
        batch_verify_time,
        batch_verify_time / 50
    );
    println!();

    // ============================================
    // Parameter Set Comparison Table
    // ============================================
    println!("--- ML-DSA Parameter Set Reference ---\n");
    println!("Parameter Set | Security | Sig Size | Public Key | Private Key");
    println!("--------------|----------|----------|------------|------------");
    println!("ML-DSA-44     | 128-bit  | 2,420 B  | 1,312 B    | 2,560 B");
    println!("ML-DSA-65     | 192-bit  | 3,309 B  | 1,952 B    | 4,032 B");
    println!("ML-DSA-87     | 256-bit  | 4,627 B  | 2,592 B    | 4,896 B");
    println!();

    println!("Current configuration uses: {}", param_set);
    println!();

    // ============================================
    // Recommendations
    // ============================================
    println!("--- Recommendations ---\n");
    println!("ML-DSA-44: Best for network-constrained environments");
    println!("           Good for: Web tokens, mobile apps, IoT");
    println!();
    println!("ML-DSA-65: Balanced security and size (default)");
    println!("           Good for: General-purpose authentication");
    println!();
    println!("ML-DSA-87: Maximum quantum resistance");
    println!("           Good for: High-security, long-lived credentials");
    println!();

    println!("=== Parameter Set Analysis Complete ===");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parameter_set_works() {
        let mut rng = rand::rng();
        let keypair = KeyPair::generate(&mut rng);

        let mut claims = Claims::new();
        claims.set_subject("test").unwrap();
        claims
            .set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))
            .unwrap();

        let token = PasetoPQ::sign(keypair.signing_key(), &claims).unwrap();
        let verified = PasetoPQ::verify(keypair.verifying_key(), &token).unwrap();

        assert_eq!(verified.claims().subject(), Some("test"));
    }

    #[test]
    fn test_token_size_estimation() {
        let mut claims = Claims::new();
        claims.set_subject("test").unwrap();
        claims
            .set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))
            .unwrap();

        let estimator = TokenSizeEstimator::public(&claims, None).unwrap();
        assert!(estimator.total_bytes() > 0);
        assert!(estimator.fits_in_header());
    }
}
