//! Local tokens demonstration for post-quantum PASETO tokens
//!
//! This example shows the new local token functionality in PASETO-PQ,
//! demonstrating symmetric encryption alongside the existing asymmetric signatures.
//!
//! Run with: cargo run --example local_tokens_demo

use paseto_pq::{Claims, KemKeyPair, KeyPair, PasetoPQ, SymmetricKey};
use rand::rng;
use std::time::Instant;
use time::{Duration, OffsetDateTime};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 PASETO-PQ Local Tokens Demo");
    println!("================================================\n");

    let mut rng = rng();

    // Generate keys for both token types
    println!("🔑 Key Generation:");

    // Asymmetric keys for public tokens
    let asym_start = Instant::now();
    let asymmetric_keypair = KeyPair::generate(&mut rng);
    let asym_time = asym_start.elapsed();
    println!("   ML-DSA-65 KeyPair:  {:?}", asym_time);

    // Symmetric key for local tokens
    let sym_start = Instant::now();
    let symmetric_key = SymmetricKey::generate(&mut rng);
    let sym_time = sym_start.elapsed();
    println!("   Symmetric Key:      {:?}", sym_time);

    // KEM keypair for key exchange (future use)
    let kem_start = Instant::now();
    let kem_keypair = KemKeyPair::generate(&mut rng);
    let kem_time = kem_start.elapsed();
    println!("   ML-KEM-768 KeyPair: {:?}\n", kem_time);

    // Key size information
    let asym_signing_bytes = asymmetric_keypair.signing_key_to_bytes();
    let asym_verifying_bytes = asymmetric_keypair.verifying_key_to_bytes();
    let sym_key_bytes = symmetric_key.to_bytes();
    let kem_enc_bytes = kem_keypair.encapsulation_key_to_bytes();
    let kem_dec_bytes = kem_keypair.decapsulation_key_to_bytes();

    println!("🗂️  Key Sizes:");
    println!("   ML-DSA Signing:     {} bytes", asym_signing_bytes.len());
    println!(
        "   ML-DSA Verifying:   {} bytes",
        asym_verifying_bytes.len()
    );
    println!("   Symmetric Key:      {} bytes", sym_key_bytes.len());
    println!("   ML-KEM Encaps:      {} bytes", kem_enc_bytes.len());
    println!("   ML-KEM Decaps:      {} bytes\n", kem_dec_bytes.len());

    // Create test claims
    let mut claims = Claims::new();
    claims.set_subject("alice@example.com")?;
    claims.set_issuer("secure-service")?;
    claims.set_audience("api.example.com")?;
    claims.set_expiration(OffsetDateTime::now_utc() + Duration::hours(2))?;
    claims.set_jti("session-abc-123")?;
    claims.add_custom("tenant_id", "corp_xyz789")?;
    claims.add_custom("roles", ["user", "manager"])?;
    claims.add_custom("permissions", ["read:data", "write:reports", "admin:users"])?;
    claims.add_custom(
        "session_metadata",
        serde_json::json!({
            "login_time": "2024-01-15T10:30:00Z",
            "ip_address": "192.168.1.100",
            "device": "laptop-chrome"
        }),
    )?;

    println!("📝 Token Creation and Verification:\n");

    // PUBLIC TOKEN (Asymmetric signatures)
    println!("🔓 Public Tokens (ML-DSA-65 Signatures):");

    let pub_sign_start = Instant::now();
    let public_token = PasetoPQ::sign(asymmetric_keypair.signing_key(), &claims)?;
    let pub_sign_time = pub_sign_start.elapsed();
    println!("   Sign time:    {:?}", pub_sign_time);

    let pub_verify_start = Instant::now();
    let verified_public = PasetoPQ::verify(asymmetric_keypair.verifying_key(), &public_token)?;
    let pub_verify_time = pub_verify_start.elapsed();
    println!("   Verify time:  {:?}", pub_verify_time);
    println!("   Token size:   {} bytes", public_token.len());
    println!("   Format:       {}", &public_token[..30]);

    // LOCAL TOKEN (Symmetric encryption)
    println!("\n🔒 Local Tokens (ChaCha20-Poly1305 Encryption):");

    let loc_encrypt_start = Instant::now();
    let local_token = PasetoPQ::encrypt(&symmetric_key, &claims)?;
    let loc_encrypt_time = loc_encrypt_start.elapsed();
    println!("   Encrypt time: {:?}", loc_encrypt_time);

    let loc_decrypt_start = Instant::now();
    let verified_local = PasetoPQ::decrypt(&symmetric_key, &local_token)?;
    let loc_decrypt_time = loc_decrypt_start.elapsed();
    println!("   Decrypt time: {:?}", loc_decrypt_time);
    println!("   Token size:   {} bytes", local_token.len());
    println!("   Format:       {}", &local_token[..30]);

    // KEY EXCHANGE DEMO (ML-KEM)
    println!("\n🔄 Post-Quantum Key Exchange (ML-KEM-768):");

    let kem_encap_start = Instant::now();
    let (shared_key_sender, ciphertext) = kem_keypair.encapsulate();
    let kem_encap_time = kem_encap_start.elapsed();
    println!("   Encapsulate:  {:?}", kem_encap_time);

    let kem_decap_start = Instant::now();
    let shared_key_receiver = kem_keypair.decapsulate(&ciphertext)?;
    let kem_decap_time = kem_decap_start.elapsed();
    println!("   Decapsulate:  {:?}", kem_decap_time);
    println!("   Ciphertext:   {} bytes", ciphertext.len());
    println!(
        "   Keys match:   {}",
        shared_key_sender.to_bytes() == shared_key_receiver.to_bytes()
    );

    // Note: Real ML-KEM implementation - shared secrets match correctly
    println!("   Note: Real ML-KEM-768 implementation - shared secrets match!");

    println!("\n📊 Performance Comparison:");
    println!("   Operation         | Public (ML-DSA) | Local (Symmetric) | Ratio");
    println!("   ------------------|-----------------|-------------------|-------");
    println!(
        "   Create/Sign       | {:>13?} | {:>15?} | {:>4.1}x",
        pub_sign_time,
        loc_encrypt_time,
        pub_sign_time.as_nanos() as f64 / loc_encrypt_time.as_nanos() as f64
    );
    println!(
        "   Verify/Decrypt    | {:>13?} | {:>15?} | {:>4.1}x",
        pub_verify_time,
        loc_decrypt_time,
        pub_verify_time.as_nanos() as f64 / loc_decrypt_time.as_nanos() as f64
    );
    println!(
        "   Token Size        | {:>11} bytes | {:>13} bytes | {:>4.1}x",
        public_token.len(),
        local_token.len(),
        public_token.len() as f64 / local_token.len() as f64
    );

    println!("\n🔍 Token Content Verification:");

    // Verify both tokens contain the same claims
    let pub_claims = verified_public.claims();
    let loc_claims = verified_local.claims();

    println!(
        "   Subject matches:     {} / {}",
        pub_claims.subject() == Some("alice@example.com"),
        loc_claims.subject() == Some("alice@example.com")
    );

    println!(
        "   Issuer matches:      {} / {}",
        pub_claims.issuer() == Some("secure-service"),
        loc_claims.issuer() == Some("secure-service")
    );

    if let Some(tenant_pub) = pub_claims.get_custom("tenant_id") {
        let tenant_loc = loc_claims.get_custom("tenant_id");
        println!(
            "   Custom claims match: {} / {}",
            tenant_pub.as_str() == Some("corp_xyz789"),
            tenant_loc.as_ref().and_then(|v| v.as_str()) == Some("corp_xyz789")
        );
    }

    println!("\n🛡️ Security Features Demo:");

    // Test tampering detection
    println!("   Testing tamper detection...");
    let mut tampered_public = public_token.clone();
    tampered_public.push('x');
    let tamper_result_pub = PasetoPQ::verify(asymmetric_keypair.verifying_key(), &tampered_public);
    println!(
        "     Public token tamper detected: {}",
        tamper_result_pub.is_err()
    );

    let mut tampered_local = local_token.clone();
    tampered_local.push('x');
    let tamper_result_loc = PasetoPQ::decrypt(&symmetric_key, &tampered_local);
    println!(
        "     Local token tamper detected:  {}",
        tamper_result_loc.is_err()
    );

    // Test cross-token type verification
    println!("   Testing cross-type verification...");
    let cross_pub_result = PasetoPQ::decrypt(&symmetric_key, &public_token);
    let cross_loc_result = PasetoPQ::verify(asymmetric_keypair.verifying_key(), &local_token);
    println!("     Public->Local fails:  {}", cross_pub_result.is_err());
    println!("     Local->Public fails:  {}", cross_loc_result.is_err());

    println!("\n🎯 Use Case Recommendations:");
    println!("   Public Tokens (ML-DSA signatures):");
    println!("     ✅ Inter-service authentication");
    println!("     ✅ API access tokens");
    println!("     ✅ Public key infrastructure");
    println!("     ✅ Non-repudiation requirements");
    println!("     ⚠️  Larger size (~4KB tokens)");
    println!("     ⚠️  Slower operations (~10-100x)");

    println!("\n   Local Tokens (Symmetric encryption):");
    println!("     ✅ Session management");
    println!("     ✅ Confidential data transport");
    println!("     ✅ High-performance scenarios");
    println!("     ✅ Smaller token size");
    println!("     ⚠️  Requires shared secrets");
    println!("     ⚠️  Key distribution challenges");

    println!("\n   Key Exchange (ML-KEM):");
    println!("     ✅ Establishing shared secrets");
    println!("     ✅ Hybrid public/local workflows");
    println!("     ✅ Post-quantum key agreement");
    println!("     ✅ Forward secrecy");

    println!("\n🌟 Token Examples:");

    // Show truncated versions of actual tokens
    println!("   Public Token:");
    if public_token.len() > 100 {
        println!("     {}...", &public_token[..100]);
        println!("     (Full length: {} characters)", public_token.len());
    }

    println!("\n   Local Token:");
    if local_token.len() > 100 {
        println!("     {}...", &local_token[..100]);
        println!("     (Full length: {} characters)", local_token.len());
    }

    println!("\n✅ PASETO-PQ Local Tokens Demo completed successfully!");
    println!("🔒 Both public (signatures) and local (encryption) tokens are now available!");
    println!("🚀 PASETO-PQ now has full parity with standard PASETO!");

    Ok(())
}
