//! Footer Demo - PASETO-PQ Footer Functionality
//!
//! This example demonstrates the use of footers in PASETO-PQ tokens.
//! Footers provide a way to include authenticated but unencrypted metadata
//! alongside tokens.

use paseto_pq::{Claims, Footer, KeyPair, PasetoPQ, SymmetricKey};
use time::{Duration, OffsetDateTime};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== PASETO-PQ Footer Demo (CBOR) ===\n");

    // Generate keys
    let mut rng = rand::rng();
    let keypair = KeyPair::generate(&mut rng);
    let symmetric_key = SymmetricKey::generate(&mut rng);

    // ============================================
    // Part 1: Basic Footer Usage
    // ============================================
    println!("--- Part 1: Basic Footer Usage ---\n");

    let mut claims = Claims::new();
    claims.set_subject("user123")?;
    claims.set_issuer("footer-demo")?;
    claims.set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))?;

    // Create a footer with metadata
    let mut footer = Footer::new();
    footer.set_kid("signing-key-2024-01")?;
    footer.set_version("1.0.0")?;
    footer.set_issuer_meta("production")?;
    footer.add_custom("region", "us-east-1")?;

    // Create token with footer
    let token_with_footer =
        PasetoPQ::sign_with_footer(keypair.signing_key(), &claims, Some(&footer))?;

    println!("Token with footer created");
    println!("Token length: {} bytes", token_with_footer.len());
    println!(
        "Token parts: {} (includes footer)\n",
        token_with_footer.split('.').count()
    );

    // Verify and extract footer
    let verified = PasetoPQ::verify(keypair.verifying_key(), &token_with_footer)?;
    if let Some(footer) = verified.footer() {
        println!("Footer extracted from token:");
        println!("  Key ID: {:?}", footer.kid());
        println!("  Version: {:?}", footer.version());
        println!("  Issuer Meta: {:?}", footer.issuer_meta());
        if let Some(region) = footer.get_custom("region") {
            println!("  Region (CBOR): {:?}", region);
        }
    }
    println!();

    // ============================================
    // Part 2: Token Without Footer (comparison)
    // ============================================
    println!("--- Part 2: Token Without Footer ---\n");

    let token_without_footer = PasetoPQ::sign(keypair.signing_key(), &claims)?;

    println!("Token without footer created");
    println!("Token length: {} bytes", token_without_footer.len());
    println!("Token parts: {}\n", token_without_footer.split('.').count());

    let verified_no_footer = PasetoPQ::verify(keypair.verifying_key(), &token_without_footer)?;
    println!("Has footer: {}\n", verified_no_footer.footer().is_some());

    // ============================================
    // Part 3: Local Token with Footer
    // ============================================
    println!("--- Part 3: Local Token with Footer ---\n");

    let mut local_footer = Footer::new();
    local_footer.set_kid("encryption-key-2024")?;
    local_footer.add_custom("algorithm", "ChaCha20-Poly1305")?;
    local_footer.add_custom("encrypted_at", &OffsetDateTime::now_utc().unix_timestamp())?;

    let local_token = PasetoPQ::encrypt_with_footer(&symmetric_key, &claims, Some(&local_footer))?;

    println!("Local token with footer created");
    println!("Token length: {} bytes\n", local_token.len());

    let decrypted = PasetoPQ::decrypt(&symmetric_key, &local_token)?;
    if let Some(footer) = decrypted.footer() {
        println!("Local token footer:");
        println!("  Key ID: {:?}", footer.kid());
        if let Some(alg) = footer.get_custom("algorithm") {
            println!("  Algorithm (CBOR): {:?}", alg);
        }
    }
    println!();

    // ============================================
    // Part 4: Footer Tamper Detection
    // ============================================
    println!("--- Part 4: Footer Tamper Detection ---\n");

    // Create a token with footer
    let mut original_footer = Footer::new();
    original_footer.set_kid("secure-key")?;
    original_footer.add_custom("integrity", "protected")?;

    let secure_token =
        PasetoPQ::sign_with_footer(keypair.signing_key(), &claims, Some(&original_footer))?;

    // Try to tamper with footer
    let parts: Vec<&str> = secure_token.split('.').collect();
    if parts.len() == 6 {
        // Create a tampered footer
        let mut tampered_footer = Footer::new();
        tampered_footer.set_kid("evil-key")?;
        let tampered_footer_b64 = tampered_footer.to_base64()?;

        let tampered_token = format!(
            "{}.{}.{}.{}.{}.{}",
            parts[0], parts[1], parts[2], parts[3], parts[4], tampered_footer_b64
        );

        // Attempt verification
        match PasetoPQ::verify(keypair.verifying_key(), &tampered_token) {
            Ok(_) => println!("ERROR: Tampered token was accepted!"),
            Err(e) => println!("Tamper detection working: {}", e),
        }
    }
    println!();

    // ============================================
    // Part 5: Key Rotation with Footer
    // ============================================
    println!("--- Part 5: Key Rotation Pattern ---\n");

    // Simulate multiple key generations
    let key_ids = ["key-v1", "key-v2", "key-v3"];
    let keypairs: Vec<_> = key_ids
        .iter()
        .map(|_| KeyPair::generate(&mut rng))
        .collect();

    // Create tokens with different key IDs
    let mut tokens = Vec::new();
    for (idx, (kid, kp)) in key_ids.iter().zip(keypairs.iter()).enumerate() {
        let mut claims = Claims::new();
        claims.set_subject(&format!("user-{}", idx))?;
        claims.set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))?;

        let mut footer = Footer::new();
        footer.set_kid(kid)?;

        let token = PasetoPQ::sign_with_footer(kp.signing_key(), &claims, Some(&footer))?;
        tokens.push((token, *kid, kp));
    }

    // Verify tokens using kid to select key
    println!("Key rotation verification:");
    for (token, expected_kid, keypair) in &tokens {
        let parsed = PasetoPQ::parse_token(token)?;
        if let Some(footer) = parsed.footer() {
            let kid = footer.kid().unwrap_or("unknown");
            println!("  Token with kid='{}' -> expected '{}'", kid, expected_kid);

            // In production, you'd look up the key by kid
            let result = PasetoPQ::verify(keypair.verifying_key(), token);
            println!(
                "    Verification: {}",
                if result.is_ok() { "OK" } else { "FAILED" }
            );
        }
    }
    println!();

    // ============================================
    // Part 6: Footer Size Comparison
    // ============================================
    println!("--- Part 6: Footer Size Impact ---\n");

    let mut small_footer = Footer::new();
    small_footer.set_kid("k1")?;

    let mut large_footer = Footer::new();
    large_footer.set_kid("very-long-key-identifier-for-demonstration")?;
    large_footer.set_version("2024.01.15-beta.3")?;
    large_footer.set_issuer_meta("production-us-east-1-primary")?;
    large_footer.add_custom("trace_id", "abc123def456")?;
    large_footer.add_custom("span_id", "span-789")?;
    large_footer.add_custom("cluster", "cluster-alpha")?;

    let token_no_footer = PasetoPQ::sign(keypair.signing_key(), &claims)?;
    let token_small_footer =
        PasetoPQ::sign_with_footer(keypair.signing_key(), &claims, Some(&small_footer))?;
    let token_large_footer =
        PasetoPQ::sign_with_footer(keypair.signing_key(), &claims, Some(&large_footer))?;

    println!("Token sizes:");
    println!("  No footer:    {} bytes", token_no_footer.len());
    println!(
        "  Small footer: {} bytes (+{})",
        token_small_footer.len(),
        token_small_footer.len() - token_no_footer.len()
    );
    println!(
        "  Large footer: {} bytes (+{})",
        token_large_footer.len(),
        token_large_footer.len() - token_no_footer.len()
    );
    println!();

    println!("=== Footer Demo Complete ===");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_footer_workflow() {
        let mut rng = rand::rng();
        let keypair = KeyPair::generate(&mut rng);

        let mut claims = Claims::new();
        claims.set_subject("test").unwrap();
        claims
            .set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))
            .unwrap();

        let mut footer = Footer::new();
        footer.set_kid("test-key").unwrap();
        footer.add_custom("env", "test").unwrap();

        let token =
            PasetoPQ::sign_with_footer(keypair.signing_key(), &claims, Some(&footer)).unwrap();
        let verified = PasetoPQ::verify(keypair.verifying_key(), &token).unwrap();

        assert!(verified.footer().is_some());
        assert_eq!(verified.footer().unwrap().kid(), Some("test-key"));
    }

    #[test]
    fn test_footer_size_impact() {
        let mut rng = rand::rng();
        let keypair = KeyPair::generate(&mut rng);

        let mut claims = Claims::new();
        claims.set_subject("test").unwrap();
        claims
            .set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))
            .unwrap();

        let token_no_footer = PasetoPQ::sign(keypair.signing_key(), &claims).unwrap();

        let mut footer = Footer::new();
        footer.set_kid("key-id").unwrap();
        let token_with_footer =
            PasetoPQ::sign_with_footer(keypair.signing_key(), &claims, Some(&footer)).unwrap();

        // Token with footer should be larger
        assert!(token_with_footer.len() > token_no_footer.len());
    }
}
