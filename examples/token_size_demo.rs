//! Token Size Demo - PASETO-PQ Token Size Analysis
//!
//! This example demonstrates the token size characteristics of PASETO-PQ
//! and how different claims affect the final token size.

use paseto_pq::{Claims, Footer, KeyPair, PasetoPQ, SymmetricKey, TokenSizeEstimator};
use time::{Duration, OffsetDateTime};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== PASETO-PQ Token Size Demo (CBOR) ===\n");

    let mut rng = rand::rng();
    let keypair = KeyPair::generate(&mut rng);
    let symmetric_key = SymmetricKey::generate(&mut rng);

    // ============================================
    // Part 1: Minimal Token Size
    // ============================================
    println!("--- Part 1: Minimal Token Size ---\n");

    let mut minimal_claims = Claims::new();
    minimal_claims.set_subject("u")?;
    minimal_claims.set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))?;

    let minimal_public = PasetoPQ::sign(keypair.signing_key(), &minimal_claims)?;
    let minimal_local = PasetoPQ::encrypt(&symmetric_key, &minimal_claims)?;

    println!("Minimal public token: {} bytes", minimal_public.len());
    println!("Minimal local token:  {} bytes", minimal_local.len());
    println!();

    // ============================================
    // Part 2: Typical Token Size
    // ============================================
    println!("--- Part 2: Typical Token Size ---\n");

    let mut typical_claims = Claims::new();
    typical_claims.set_subject("user123")?;
    typical_claims.set_issuer("auth-service")?;
    typical_claims.set_audience("api.example.com")?;
    typical_claims.set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))?;
    typical_claims.set_issued_at(OffsetDateTime::now_utc())?;
    typical_claims.set_jti("token-abc123")?;
    typical_claims.add_custom("role", "admin")?;

    let typical_public = PasetoPQ::sign(keypair.signing_key(), &typical_claims)?;
    let typical_local = PasetoPQ::encrypt(&symmetric_key, &typical_claims)?;

    println!("Typical public token: {} bytes", typical_public.len());
    println!("Typical local token:  {} bytes", typical_local.len());
    println!();

    // ============================================
    // Part 3: Token with Footer
    // ============================================
    println!("--- Part 3: Token with Footer ---\n");

    let mut footer = Footer::new();
    footer.set_kid("key-2024-01")?;
    footer.set_version("1.0.0")?;
    footer.add_custom("environment", "production")?;

    let with_footer_public =
        PasetoPQ::sign_with_footer(keypair.signing_key(), &typical_claims, Some(&footer))?;
    let with_footer_local =
        PasetoPQ::encrypt_with_footer(&symmetric_key, &typical_claims, Some(&footer))?;

    println!(
        "Public token with footer: {} bytes (+{} for footer)",
        with_footer_public.len(),
        with_footer_public.len() - typical_public.len()
    );
    println!(
        "Local token with footer:  {} bytes (+{} for footer)",
        with_footer_local.len(),
        with_footer_local.len() - typical_local.len()
    );
    println!();

    // ============================================
    // Part 4: Large Token Size
    // ============================================
    println!("--- Part 4: Large Token Size ---\n");

    let mut large_claims = Claims::new();
    large_claims.set_subject("user123")?;
    large_claims.set_issuer("auth-service")?;
    large_claims.set_audience("api.example.com")?;
    large_claims.set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))?;
    large_claims.add_custom("roles", &["admin", "user", "moderator", "editor", "viewer"])?;
    large_claims.add_custom(
        "permissions",
        &[
            "read:users",
            "write:users",
            "delete:users",
            "read:posts",
            "write:posts",
            "delete:posts",
            "read:comments",
            "write:comments",
            "delete:comments",
            "admin:system",
        ],
    )?;
    large_claims.add_custom("metadata", &"Additional metadata for the token")?;

    let large_public = PasetoPQ::sign(keypair.signing_key(), &large_claims)?;
    let large_local = PasetoPQ::encrypt(&symmetric_key, &large_claims)?;

    println!("Large public token: {} bytes", large_public.len());
    println!("Large local token:  {} bytes", large_local.len());
    println!();

    // ============================================
    // Part 5: Size Estimation
    // ============================================
    println!("--- Part 5: Size Estimation ---\n");

    let estimator = TokenSizeEstimator::public(&typical_claims, None)?;
    let actual_size = typical_public.len();
    let estimated_size = estimator.total_bytes();

    println!("Estimated size: {} bytes", estimated_size);
    println!("Actual size:    {} bytes", actual_size);
    println!(
        "Difference:     {} bytes ({:.1}%)",
        (estimated_size as i64 - actual_size as i64).abs(),
        ((estimated_size as f64 - actual_size as f64).abs() / actual_size as f64) * 100.0
    );
    println!();

    // ============================================
    // Part 6: Size Breakdown
    // ============================================
    println!("--- Part 6: Size Breakdown ---\n");

    let breakdown = estimator.breakdown();

    println!("Token Size Breakdown:");
    println!("  Prefix:         {} bytes", breakdown.prefix);
    println!("  Payload:        {} bytes", breakdown.payload);
    println!("  Signature/Tag:  {} bytes", breakdown.signature_or_tag);
    println!("  Footer:         {} bytes", breakdown.footer);
    println!("  Separators:     {} bytes", breakdown.separators);
    println!("  Base64 Overhead: {:.1}%", breakdown.base64_overhead);
    println!("  ─────────────────────────");
    println!("  Total:          {} bytes", breakdown.total());
    println!();

    // ============================================
    // Part 7: Size Limits
    // ============================================
    println!("--- Part 7: Size Limit Compatibility ---\n");

    println!("Typical public token ({} bytes):", typical_public.len());
    println!(
        "  Fits in Cookie (4KB):  {}",
        if typical_public.len() <= 4096 {
            "YES"
        } else {
            "NO"
        }
    );
    println!(
        "  Fits in URL (2KB):     {}",
        if typical_public.len() <= 2048 {
            "YES"
        } else {
            "NO"
        }
    );
    println!(
        "  Fits in Header (8KB):  {}",
        if typical_public.len() <= 8192 {
            "YES"
        } else {
            "NO"
        }
    );
    println!();

    // ============================================
    // Part 8: CBOR vs JSON Comparison
    // ============================================
    println!("--- Part 8: CBOR Efficiency ---\n");

    // CBOR serialization is typically more compact than JSON
    println!("PASETO-PQ uses CBOR serialization which is typically:");
    println!("  • 10-30% smaller than equivalent JSON");
    println!("  • More efficient for binary data");
    println!("  • Faster to parse");
    println!();

    // Show CBOR bytes for claims
    let cbor_bytes = typical_claims.to_cbor_bytes()?;
    println!("Typical claims CBOR size: {} bytes", cbor_bytes.len());
    println!();

    // ============================================
    // Summary
    // ============================================
    println!("--- Summary ---\n");
    println!("Token Type        | Minimal | Typical | Large");
    println!("------------------|---------|---------|-------");
    println!(
        "Public (ML-DSA)   | {:>7} | {:>7} | {:>5}",
        minimal_public.len(),
        typical_public.len(),
        large_public.len()
    );
    println!(
        "Local (ChaCha20)  | {:>7} | {:>7} | {:>5}",
        minimal_local.len(),
        typical_local.len(),
        large_local.len()
    );
    println!();

    println!("Note: Public tokens are much larger due to post-quantum");
    println!("signature sizes. ML-DSA signatures range from ~2.4KB to ~4.6KB");
    println!("depending on the security level.");

    println!("\n=== Token Size Demo Complete ===");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_size_estimation() {
        let mut claims = Claims::new();
        claims.set_subject("test").unwrap();
        claims
            .set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))
            .unwrap();

        let estimator = TokenSizeEstimator::public(&claims, None).unwrap();
        assert!(estimator.total_bytes() > 0);
    }

    #[test]
    fn test_local_smaller_than_public() {
        let mut rng = rand::rng();
        let keypair = KeyPair::generate(&mut rng);
        let symmetric_key = SymmetricKey::generate(&mut rng);

        let mut claims = Claims::new();
        claims.set_subject("test").unwrap();
        claims
            .set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))
            .unwrap();

        let public_token = PasetoPQ::sign(keypair.signing_key(), &claims).unwrap();
        let local_token = PasetoPQ::encrypt(&symmetric_key, &claims).unwrap();

        // Local tokens should be much smaller (no PQ signature)
        assert!(local_token.len() < public_token.len());
    }
}
