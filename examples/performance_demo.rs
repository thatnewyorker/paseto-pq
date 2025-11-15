//! Performance demonstration for post-quantum PASETO tokens
//!
//! This example shows the performance characteristics of ML-DSA-65 based tokens
//! compared to what you might expect from Ed25519 tokens.
//!
//! Run with: cargo run --example performance_demo

use paseto_pq::{Claims, KeyPair, PasetoPQ};
use rand::rng;
use std::time::Instant;
use time::{Duration, OffsetDateTime};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 PASETO-PQ Performance Demo");
    println!("================================================\n");

    // Key generation benchmark
    println!("🔑 Key Generation:");
    let keygen_start = Instant::now();
    let keypair = KeyPair::generate(&mut rng);
    let keygen_time = keygen_start.elapsed();
    println!("   ML-DSA KeyGen: {:?}", keygen_time);
    println!("   Note: Ed25519 typically takes ~50-100µs\n");

    // Key size information
    let signing_bytes = keypair.signing_key_to_bytes();
    let verifying_bytes = keypair.verifying_key_to_bytes();
    println!("🗂️  Key Sizes:");
    println!("   Signing key:    {} bytes", signing_bytes.len());
    println!("   Verifying key:  {} bytes", verifying_bytes.len());
    println!("   Note: Ed25519 keys are 32 bytes each\n");

    // Create test claims
    let mut claims = Claims::new();
    claims.set_subject("user123")?;
    claims.set_issuer("my-service")?;
    claims.set_audience("api.example.com")?;
    claims.set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))?;
    claims.set_jti("unique-token-123")?;
    claims.add_custom("tenant_id", "org_abc123")?;
    claims.add_custom("roles", &["user", "admin"])?;
    claims.add_custom("permissions", &["read:messages", "write:messages"])?;

    // Token signing benchmark
    println!("✍️  Token Signing:");
    let sign_start = Instant::now();
    let token = PasetoPQ::sign(keypair.signing_key(), &claims)?;
    let sign_time = sign_start.elapsed();
    println!("   ML-DSA Sign: {:?}", sign_time);
    println!("   Note: Ed25519 typically takes ~20-50µs\n");

    // Token size information
    println!("📏 Token Size:");
    println!("   Token length: {} bytes", token.len());
    println!("   Note: Ed25519 PASETO tokens are typically ~300-500 bytes\n");

    // Token verification benchmark
    println!("✅ Token Verification:");
    let verify_start = Instant::now();
    let verified = PasetoPQ::verify(keypair.verifying_key(), &token)?;
    let verify_time = verify_start.elapsed();
    println!("   ML-DSA Verify: {:?}", verify_time);
    println!("   Note: Ed25519 typically takes ~40-80µs\n");

    // Batch operations to show sustained performance
    println!("🔄 Batch Operations (100 iterations):");

    // Batch signing
    let batch_sign_start = Instant::now();
    let mut tokens = Vec::new();
    for i in 0..100 {
        let mut batch_claims = Claims::new();
        batch_claims.set_subject(&format!("user{}", i))?;
        batch_claims.set_issuer("my-service")?;
        batch_claims.set_audience("api.example.com")?;
        batch_claims.set_jti(&format!("token-{}", i))?;

        let batch_token = PasetoPQ::sign(keypair.signing_key(), &batch_claims)?;
        tokens.push(batch_token);
    }
    let batch_sign_time = batch_sign_start.elapsed();
    println!(
        "   100 signs:    {:?} ({:?} per operation)",
        batch_sign_time,
        batch_sign_time / 100
    );

    // Batch verification
    let batch_verify_start = Instant::now();
    for token in &tokens {
        let _verified = PasetoPQ::verify(keypair.verifying_key(), token)?;
    }
    let batch_verify_time = batch_verify_start.elapsed();
    println!(
        "   100 verifies: {:?} ({:?} per operation)",
        batch_verify_time,
        batch_verify_time / 100
    );

    // Display the actual token (truncated)
    println!("\n🎫 Sample PASETO-PQ Token:");
    if token.len() > 200 {
        println!("   paseto.v1.public.{}...", &token[13..200]);
        println!("   (truncated - full length: {} chars)", token.len());
    } else {
        println!("   {}", token);
    }

    // Verify the claims
    println!("\n📋 Verified Claims:");
    let claims = verified.claims();
    println!("   Subject:  {:?}", claims.subject());
    println!("   Issuer:   {:?}", claims.issuer());
    println!("   Audience: {:?}", claims.audience());
    println!("   JTI:      {:?}", claims.jti());

    if let Some(tenant) = claims.get_custom("tenant_id") {
        println!("   Tenant:   {:?}", tenant.as_str());
    }
    if let Some(roles) = claims.get_custom("roles") {
        println!("   Roles:    {:?}", roles);
    }

    println!("🎯 Performance Summary:");
    println!("   • ML-DSA provides quantum-safe signatures");
    println!("   • ~10-100x slower than Ed25519 (expected for PQ crypto)");
    println!(
        "   • Signature size depends on parameter set (ml-dsa-44: ~2.4KB, ml-dsa-65: ~3.3KB, ml-dsa-87: ~4.6KB)"
    );
    println!("   • Still practical for authentication tokens");
    println!("   • Future-proof against quantum computers");

    println!("\n✅ Demo completed successfully!");
    Ok(())
}
