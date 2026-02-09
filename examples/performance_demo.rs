//! Performance Demo - PASETO-PQ Token Performance Characteristics
//!
//! This example demonstrates the performance characteristics of PASETO-PQ tokens
//! including key generation, signing, verification, encryption, and decryption.

use paseto_pq::{Claims, KeyPair, PasetoPQ, SymmetricKey};
use std::time::Instant;
use time::{Duration, OffsetDateTime};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== PASETO-PQ Performance Demo ===\n");

    let mut rng = rand::rng();

    // ============================================
    // Key Generation Performance
    // ============================================
    println!("--- Key Generation ---\n");

    let start = Instant::now();
    let keypair = KeyPair::generate(&mut rng);
    let keygen_time = start.elapsed();
    println!("ML-DSA keypair generation: {:?}", keygen_time);

    let start = Instant::now();
    let symmetric_key = SymmetricKey::generate(&mut rng);
    let symkey_time = start.elapsed();
    println!("Symmetric key generation: {:?}", symkey_time);
    println!();

    // ============================================
    // Token Creation Performance
    // ============================================
    println!("--- Token Creation ---\n");

    let mut claims = Claims::new();
    claims.set_subject("user123")?;
    claims.set_issuer("performance-demo")?;
    claims.set_audience("api.example.com")?;
    claims.set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))?;
    claims.add_custom("roles", &["user", "admin"])?;
    claims.add_custom("permissions", &["read:messages", "write:messages"])?;

    // Public token signing
    let start = Instant::now();
    let public_token = PasetoPQ::sign(keypair.signing_key(), &claims)?;
    let sign_time = start.elapsed();
    println!("Public token signing: {:?}", sign_time);
    println!("Public token size: {} bytes", public_token.len());

    // Local token encryption
    let start = Instant::now();
    let local_token = PasetoPQ::encrypt(&symmetric_key, &claims)?;
    let encrypt_time = start.elapsed();
    println!("Local token encryption: {:?}", encrypt_time);
    println!("Local token size: {} bytes", local_token.len());
    println!();

    // ============================================
    // Token Verification Performance
    // ============================================
    println!("--- Token Verification ---\n");

    // Public token verification
    let start = Instant::now();
    let verified = PasetoPQ::verify(keypair.verifying_key(), &public_token)?;
    let verify_time = start.elapsed();
    println!("Public token verification: {:?}", verify_time);
    println!("Verified subject: {:?}", verified.claims().subject());

    // Local token decryption
    let start = Instant::now();
    let decrypted = PasetoPQ::decrypt(&symmetric_key, &local_token)?;
    let decrypt_time = start.elapsed();
    println!("Local token decryption: {:?}", decrypt_time);
    println!("Decrypted subject: {:?}", decrypted.claims().subject());
    println!();

    // ============================================
    // Batch Operations
    // ============================================
    println!("--- Batch Operations (100 tokens) ---\n");

    // Batch signing
    let start = Instant::now();
    let mut tokens = Vec::with_capacity(100);
    for i in 0..100 {
        let mut batch_claims = Claims::new();
        batch_claims.set_subject(&format!("user{}", i))?;
        batch_claims.set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))?;
        batch_claims.set_jti(&format!("token-{}", i))?;
        let token = PasetoPQ::sign(keypair.signing_key(), &batch_claims)?;
        tokens.push(token);
    }
    let batch_sign_time = start.elapsed();
    println!("Batch sign (100 tokens): {:?}", batch_sign_time);
    println!("Average per token: {:?}", batch_sign_time / 100);

    // Batch verification
    let start = Instant::now();
    for token in &tokens {
        let _ = PasetoPQ::verify(keypair.verifying_key(), token)?;
    }
    let batch_verify_time = start.elapsed();
    println!("Batch verify (100 tokens): {:?}", batch_verify_time);
    println!("Average per token: {:?}", batch_verify_time / 100);
    println!();

    // ============================================
    // Size Comparison
    // ============================================
    println!("--- Token Size Analysis ---\n");

    // Minimal claims
    let mut minimal_claims = Claims::new();
    minimal_claims.set_subject("u")?;
    minimal_claims.set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))?;
    let minimal_token = PasetoPQ::sign(keypair.signing_key(), &minimal_claims)?;

    // Medium claims
    let mut medium_claims = Claims::new();
    medium_claims.set_subject("user123")?;
    medium_claims.set_issuer("auth-service")?;
    medium_claims.set_audience("api.example.com")?;
    medium_claims.set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))?;
    medium_claims.add_custom("role", "admin")?;
    let medium_token = PasetoPQ::sign(keypair.signing_key(), &medium_claims)?;

    // Large claims
    let mut large_claims = Claims::new();
    large_claims.set_subject("user123")?;
    large_claims.set_issuer("auth-service")?;
    large_claims.set_audience("api.example.com")?;
    large_claims.set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))?;
    large_claims.add_custom("roles", &["admin", "user", "moderator"])?;
    large_claims.add_custom("permissions", &["read", "write", "delete", "admin"])?;
    large_claims.add_custom("metadata", &"some metadata value")?;
    let large_token = PasetoPQ::sign(keypair.signing_key(), &large_claims)?;

    println!("Minimal token: {} bytes", minimal_token.len());
    println!("Medium token:  {} bytes", medium_token.len());
    println!("Large token:   {} bytes", large_token.len());
    println!();

    // ============================================
    // Summary
    // ============================================
    println!("--- Performance Summary ---\n");
    println!("Key Generation:");
    println!("  ML-DSA keypair: {:?}", keygen_time);
    println!("  Symmetric key:  {:?}", symkey_time);
    println!();
    println!("Single Operations:");
    println!("  Sign:    {:?}", sign_time);
    println!("  Verify:  {:?}", verify_time);
    println!("  Encrypt: {:?}", encrypt_time);
    println!("  Decrypt: {:?}", decrypt_time);
    println!();
    println!("Note: ML-DSA (post-quantum) signatures are larger and slower than");
    println!("classical signatures (RSA, ECDSA), but provide quantum resistance.");

    println!("\n=== Performance Demo Complete ===");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_performance_sanity() {
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
}
