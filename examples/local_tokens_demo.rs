//! Local Tokens Demo - PASETO-PQ Symmetric Encryption
//!
//! This example demonstrates the use of local (encrypted) tokens in PASETO-PQ.
//! Local tokens use symmetric encryption (ChaCha20-Poly1305) for confidentiality.

use paseto_pq::{Claims, Footer, PasetoPQ, SymmetricKey};
use time::{Duration, OffsetDateTime};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== PASETO-PQ Local Tokens Demo (CBOR) ===\n");

    let mut rng = rand::rng();

    // ============================================
    // Part 1: Basic Local Token
    // ============================================
    println!("--- Part 1: Basic Local Token ---\n");

    // Generate a symmetric key
    let symmetric_key = SymmetricKey::generate(&mut rng);
    println!("Symmetric key generated (32 bytes)");

    // Create claims
    let mut claims = Claims::new();
    claims.set_subject("user123")?;
    claims.set_issuer("local-demo")?;
    claims.set_audience("internal-api")?;
    claims.set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))?;
    claims.add_custom("roles", &["user", "manager"])?;
    claims.add_custom("permissions", &["read:data", "write:reports"])?;

    // Encrypt the token
    let token = PasetoPQ::encrypt(&symmetric_key, &claims)?;
    println!("Token encrypted successfully");
    println!("Token length: {} bytes", token.len());
    println!("Token prefix: {}", &token[..20]);
    println!();

    // Decrypt and verify
    let decrypted = PasetoPQ::decrypt(&symmetric_key, &token)?;
    println!("Token decrypted successfully");
    println!("Subject: {:?}", decrypted.claims().subject());
    println!("Issuer: {:?}", decrypted.claims().issuer());
    println!();

    // ============================================
    // Part 2: Local Token with Footer
    // ============================================
    println!("--- Part 2: Local Token with Footer ---\n");

    let mut footer = Footer::new();
    footer.set_kid("encryption-key-2024")?;
    footer.set_version("1.0.0")?;
    footer.add_custom("key_rotation_hint", "next-key-2024-q2")?;

    let token_with_footer = PasetoPQ::encrypt_with_footer(&symmetric_key, &claims, Some(&footer))?;
    println!("Token with footer created");
    println!("Token length: {} bytes", token_with_footer.len());
    println!();

    let decrypted_with_footer = PasetoPQ::decrypt(&symmetric_key, &token_with_footer)?;
    if let Some(f) = decrypted_with_footer.footer() {
        println!("Footer extracted:");
        println!("  Key ID: {:?}", f.kid());
        println!("  Version: {:?}", f.version());
    }
    println!();

    // ============================================
    // Part 3: Time-based Validation
    // ============================================
    println!("--- Part 3: Time-based Validation ---\n");

    // Create an expired token
    let mut expired_claims = Claims::new();
    expired_claims.set_subject("expired-user")?;
    expired_claims.set_expiration(OffsetDateTime::now_utc() - Duration::hours(1))?; // Expired 1 hour ago

    let expired_token = PasetoPQ::encrypt(&symmetric_key, &expired_claims)?;

    match PasetoPQ::decrypt(&symmetric_key, &expired_token) {
        Ok(_) => println!("ERROR: Expired token was accepted!"),
        Err(e) => println!("Correct: Expired token rejected - {}", e),
    }

    // Create a not-yet-valid token
    let mut future_claims = Claims::new();
    future_claims.set_subject("future-user")?;
    future_claims.set_not_before(OffsetDateTime::now_utc() + Duration::hours(1))?; // Valid in 1 hour
    future_claims.set_expiration(OffsetDateTime::now_utc() + Duration::hours(2))?;

    let future_token = PasetoPQ::encrypt(&symmetric_key, &future_claims)?;

    match PasetoPQ::decrypt(&symmetric_key, &future_token) {
        Ok(_) => println!("ERROR: Future token was accepted!"),
        Err(e) => println!("Correct: Future token rejected - {}", e),
    }
    println!();

    // ============================================
    // Part 4: Wrong Key Detection
    // ============================================
    println!("--- Part 4: Wrong Key Detection ---\n");

    let wrong_key = SymmetricKey::generate(&mut rng);

    match PasetoPQ::decrypt(&wrong_key, &token) {
        Ok(_) => println!("ERROR: Token decrypted with wrong key!"),
        Err(e) => println!("Correct: Wrong key rejected - {}", e),
    }
    println!();

    // ============================================
    // Part 5: Audience and Issuer Validation
    // ============================================
    println!("--- Part 5: Audience and Issuer Validation ---\n");

    // Valid audience and issuer
    match PasetoPQ::decrypt_with_options(
        &symmetric_key,
        &token,
        Some("internal-api"),
        Some("local-demo"),
    ) {
        Ok(_) => println!("Correct audience and issuer: OK"),
        Err(e) => println!("ERROR: {}", e),
    }

    // Wrong audience
    match PasetoPQ::decrypt_with_options(&symmetric_key, &token, Some("wrong-api"), None) {
        Ok(_) => println!("ERROR: Wrong audience was accepted!"),
        Err(e) => println!("Wrong audience rejected: {}", e),
    }

    // Wrong issuer
    match PasetoPQ::decrypt_with_options(&symmetric_key, &token, None, Some("wrong-issuer")) {
        Ok(_) => println!("ERROR: Wrong issuer was accepted!"),
        Err(e) => println!("Wrong issuer rejected: {}", e),
    }
    println!();

    // ============================================
    // Part 6: Key Derivation
    // ============================================
    println!("--- Part 6: Key Derivation ---\n");

    // Derive a key from a shared secret (e.g., from KEM)
    let shared_secret = [0x42u8; 32]; // In practice, this comes from ML-KEM
    let derived_key = SymmetricKey::derive_from_shared_secret(&shared_secret, b"local-token-key");

    let mut derived_claims = Claims::new();
    derived_claims.set_subject("derived-key-user")?;
    derived_claims.set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))?;

    let derived_token = PasetoPQ::encrypt(&derived_key, &derived_claims)?;
    let decrypted_derived = PasetoPQ::decrypt(&derived_key, &derived_token)?;

    println!("Token with derived key created and decrypted");
    println!("Subject: {:?}", decrypted_derived.claims().subject());
    println!();

    println!("=== Local Tokens Demo Complete ===");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_token_roundtrip() {
        let mut rng = rand::rng();
        let key = SymmetricKey::generate(&mut rng);

        let mut claims = Claims::new();
        claims.set_subject("test").unwrap();
        claims
            .set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))
            .unwrap();

        let token = PasetoPQ::encrypt(&key, &claims).unwrap();
        let decrypted = PasetoPQ::decrypt(&key, &token).unwrap();

        assert_eq!(decrypted.claims().subject(), Some("test"));
    }

    #[test]
    fn test_wrong_key_fails() {
        let mut rng = rand::rng();
        let key1 = SymmetricKey::generate(&mut rng);
        let key2 = SymmetricKey::generate(&mut rng);

        let mut claims = Claims::new();
        claims.set_subject("test").unwrap();
        claims
            .set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))
            .unwrap();

        let token = PasetoPQ::encrypt(&key1, &claims).unwrap();
        let result = PasetoPQ::decrypt(&key2, &token);

        assert!(result.is_err());
    }
}
