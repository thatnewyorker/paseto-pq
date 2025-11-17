//! # ML-DSA Parameter Set Comparison Demo
//!
//! This example demonstrates the differences between ML-DSA parameter sets:
//! - ml-dsa-44: 128-bit security, smallest tokens, optimized for networks
//! - ml-dsa-65: 192-bit security, balanced approach
//! - ml-dsa-87: 256-bit security, maximum protection
//!
//! Run with different features to see the differences:
//! ```bash
//! # Default (ml-dsa-44)
//! cargo run --example parameter_set_comparison
//!
//! # High security (ml-dsa-65)
//! cargo run --example parameter_set_comparison --features balanced --no-default-features
//!
//! # Maximum security (ml-dsa-87)
//! cargo run --example parameter_set_comparison --features maximum-security --no-default-features
//! ```

use paseto_pq::{Claims, KeyPair, PasetoPQ, TokenSizeEstimator};
use std::time::Instant;
use time::{Duration, OffsetDateTime};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 ML-DSA Parameter Set Comparison");
    println!("=====================================\n");

    // Determine which parameter set is active
    let parameter_info = if cfg!(feature = "ml-dsa-44") {
        ("ML-DSA-44", "128-bit", "Network-optimized")
    } else if cfg!(feature = "ml-dsa-65") {
        ("ML-DSA-65", "192-bit", "Balanced security/performance")
    } else if cfg!(feature = "ml-dsa-87") {
        ("ML-DSA-87", "256-bit", "Maximum security")
    } else {
        ("Unknown", "Unknown", "Unknown configuration")
    };

    println!("📊 Active Parameter Set: {}", parameter_info.0);
    println!("   Security Level: {}", parameter_info.1);
    println!("   Use Case: {}", parameter_info.2);
    println!();

    // Generate keypair and measure performance
    println!("🔑 Key Generation:");
    let mut rng = rand::rng();
    let keygen_start = Instant::now();
    let keypair = KeyPair::generate(&mut rng);
    let keygen_time = keygen_start.elapsed();

    println!("   Generation time: {:?}", keygen_time);

    // Key sizes
    let signing_bytes = keypair.signing_key_to_bytes();
    let verifying_bytes = keypair.verifying_key_to_bytes();

    println!("   Private key size: {} bytes", signing_bytes.len());
    println!("   Public key size:  {} bytes", verifying_bytes.len());
    println!();

    // Create test claims
    let mut claims = Claims::new();
    claims.set_subject("elise@example.com")?;
    claims.set_issuer("conflux-auth")?;
    claims.set_audience("conflux-network")?;
    claims.set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))?;
    claims.set_jti("demo-token-123")?;
    claims.add_custom("role", "user")?;
    claims.add_custom("tenant_id", "org_demo")?;

    // Signing performance
    println!("✍️  Token Signing:");
    let sign_start = Instant::now();
    let token = PasetoPQ::sign(keypair.signing_key(), &claims)?;
    let sign_time = sign_start.elapsed();

    println!("   Sign time: {:?}", sign_time);
    println!("   Token size: {} bytes", token.len());
    println!();

    // Verification performance
    println!("✅ Token Verification:");
    let verify_start = Instant::now();
    let verified = PasetoPQ::verify(keypair.verifying_key(), &token)?;
    let verify_time = verify_start.elapsed();

    println!("   Verify time: {:?}", verify_time);
    println!("   Subject verified: {:?}", verified.claims().subject());
    println!();

    // Token size estimation
    println!("📏 Token Size Analysis:");
    let estimator = TokenSizeEstimator::public(&claims, false);
    let breakdown = estimator.breakdown();

    println!("   Estimated total: {} bytes", estimator.total_bytes());
    println!("   Actual total:    {} bytes", token.len());
    println!("   Breakdown:");
    println!("     - Prefix:      {} bytes", breakdown.prefix);
    println!("     - Payload:     {} bytes", breakdown.payload);
    println!("     - Signature:   {} bytes", breakdown.signature_or_tag);
    println!("     - Separators:  {} bytes", breakdown.separators);
    println!(
        "     - Base64 overhead: {} bytes",
        breakdown.base64_overhead
    );
    println!();

    // Network compatibility
    println!("🌐 Network Compatibility:");
    println!(
        "   Fits in HTTP cookie (4KB): {}",
        estimator.fits_in_cookie()
    );
    println!("   Fits in URL (2KB):         {}", estimator.fits_in_url());
    println!(
        "   Fits in HTTP header (8KB): {}",
        estimator.fits_in_header()
    );

    if !estimator.fits_in_cookie() {
        println!("\n   💡 Optimization suggestions:");
        for suggestion in estimator.optimization_suggestions() {
            println!("     • {}", suggestion);
        }
    }
    println!();

    // Performance comparison with different payload sizes
    println!("📈 Payload Size Impact:");
    let payload_sizes = [100, 500, 1000, 2000];

    for &size in &payload_sizes {
        let mut large_claims = Claims::new();
        large_claims.set_subject("test-user")?;
        large_claims.add_custom("large_data", "x".repeat(size))?;

        let estimator = TokenSizeEstimator::public(&large_claims, false);
        println!(
            "   {} byte payload → {} byte token",
            size,
            estimator.total_bytes()
        );
    }
    println!();

    // Batch performance test
    println!("🔄 Batch Performance (50 operations):");
    let batch_start = Instant::now();
    let mut tokens = Vec::new();

    for i in 0..50 {
        let mut batch_claims = Claims::new();
        batch_claims.set_subject(format!("user{}", i))?;
        batch_claims.set_jti(format!("batch-token-{}", i))?;

        let token = PasetoPQ::sign(keypair.signing_key(), &batch_claims)?;
        tokens.push(token);
    }
    let batch_sign_time = batch_start.elapsed();

    let batch_verify_start = Instant::now();
    for token in &tokens {
        let _verified = PasetoPQ::verify(keypair.verifying_key(), token)?;
    }
    let batch_verify_time = batch_verify_start.elapsed();

    println!(
        "   50 signs:   {:?} ({:?} per operation)",
        batch_sign_time,
        batch_sign_time / 50
    );
    println!(
        "   50 verifies: {:?} ({:?} per operation)",
        batch_verify_time,
        batch_verify_time / 50
    );
    println!();

    // Security level summary
    println!("🛡️  Security Summary:");
    println!("   Parameter Set: {}", parameter_info.0);
    println!("   Security Level: {} (post-quantum)", parameter_info.1);
    println!(
        "   Classical Equivalent: AES-{}",
        if cfg!(feature = "ml-dsa-44") {
            "128"
        } else if cfg!(feature = "ml-dsa-65") {
            "192"
        } else {
            "256"
        }
    );

    println!("   Recommended for:");
    if cfg!(feature = "ml-dsa-44") {
        println!("     • Distributed systems and networking protocols");
        println!("     • High-throughput authentication");
        println!("     • Mobile and IoT applications");
        println!("     • Most general-purpose applications");
    } else if cfg!(feature = "ml-dsa-65") {
        println!("     • Financial services and banking");
        println!("     • Healthcare and sensitive data");
        println!("     • Government applications (non-classified)");
        println!("     • Long-term document signing");
    } else {
        println!("     • Critical national infrastructure");
        println!("     • Military and defense applications");
        println!("     • Long-term archival signatures (>20 years)");
        println!("     • Maximum security requirements");
    }
    println!();

    println!("✅ Parameter set comparison completed!");
    println!("\n💡 To test different parameter sets:");
    println!(
        "   cargo run --example parameter_set_comparison --features balanced --no-default-features"
    );
    println!(
        "   cargo run --example parameter_set_comparison --features maximum-security --no-default-features"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parameter_set_detection() {
        // This test verifies that exactly one parameter set is active
        let active_sets = [
            cfg!(feature = "ml-dsa-44"),
            cfg!(feature = "ml-dsa-65"),
            cfg!(feature = "ml-dsa-87"),
        ];

        let active_count = active_sets.iter().filter(|&&x| x).count();
        assert_eq!(
            active_count, 1,
            "Exactly one ML-DSA parameter set should be active"
        );
    }

    #[test]
    fn test_key_generation_and_signing() {
        let mut rng = rand::rng();
        let keypair = KeyPair::generate(&mut rng);

        let mut claims = Claims::new();
        claims.set_subject("test").unwrap();

        let token = PasetoPQ::sign(keypair.signing_key(), &claims).unwrap();
        let verified = PasetoPQ::verify(keypair.verifying_key(), &token).unwrap();

        assert_eq!(verified.claims().subject(), Some("test"));
    }
}
