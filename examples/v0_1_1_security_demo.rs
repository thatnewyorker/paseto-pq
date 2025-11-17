//! PASETO-PQ v0.1.2 Security Demo: Footer Authentication
//!
//! This example demonstrates the critical security improvements in version 0.1.1+,
//! specifically the implementation of proper footer authentication using
//! Pre-Authentication Encoding (PAE) per PASETO RFC Section 2.2.1.
//!
//! Run with: cargo run --example v0_1_1_security_demo

use paseto_pq::{Claims, Footer, KeyPair, PasetoPQ, SymmetricKey};
use rand::rng;
use time::OffsetDateTime;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔒 PASETO-PQ v0.1.2 Security Demo: Footer Authentication");
    println!("═══════════════════════════════════════════════════════════");
    println!();

    // Generate cryptographic keys
    let mut rng = rng();
    let keypair = KeyPair::generate(&mut rng);
    let symmetric_key = SymmetricKey::generate(&mut rng);

    // Create claims with sensitive data
    let mut claims = Claims::new();
    claims.set_subject("elise@example.com".to_string())?;
    claims.set_issuer("secure-service".to_string())?;
    claims.set_audience("api.example.com".to_string())?;
    claims.set_expiration(OffsetDateTime::now_utc() + time::Duration::hours(1))?;

    // Create footer with key management metadata
    let mut footer = Footer::new();
    footer.set_kid("prod-key-2024-001")?;
    footer.set_version("2.1")?;
    footer.add_custom("role", &"admin")?;

    println!("📋 Test Data:");
    println!("   Subject: {}", claims.subject().unwrap());
    println!("   Footer Key ID: {}", footer.kid().unwrap());
    println!(
        "   Footer Role: {}",
        footer.get_custom("role").unwrap().as_str().unwrap()
    );
    println!();

    // Demonstrate v0.1.1 Public Token Security
    println!("🔐 PUBLIC TOKEN SECURITY (ML-DSA Signatures)");
    println!("─────────────────────────────────────────────");

    // Create public token with authenticated footer
    let public_token = PasetoPQ::sign_with_footer(keypair.signing_key(), &claims, Some(&footer))?;

    println!("✅ Created public token with authenticated footer");
    println!("   Token length: {} bytes", public_token.len());

    // Verify authentic token
    let verified = PasetoPQ::verify_with_footer(keypair.verifying_key(), &public_token)?;
    println!("✅ Authentic token verified successfully");
    println!("   Subject: {}", verified.claims().subject().unwrap());
    println!(
        "   Footer Key ID: {}",
        verified.footer().unwrap().kid().unwrap()
    );

    // Demonstrate footer tampering detection
    println!("\n🚨 Testing Footer Tampering Detection...");

    // Tamper with the footer (create a different but valid footer)
    let mut tampered_footer = Footer::new();
    tampered_footer.set_kid("malicious-key-999")?;
    tampered_footer.set_version("1.0")?;
    tampered_footer.add_custom("role", &"superuser")?; // Privilege escalation attempt!

    // Replace footer in token (simulating tampering)
    let mut token_parts: Vec<&str> = public_token.split('.').collect();
    let tampered_footer_b64 = tampered_footer.to_base64()?;
    token_parts[5] = &tampered_footer_b64;
    let tampered_public_token = token_parts.join(".");

    // Attempt verification of tampered token
    match PasetoPQ::verify_with_footer(keypair.verifying_key(), &tampered_public_token) {
        Ok(_) => println!("❌ ERROR: Tampered token should have failed!"),
        Err(e) => {
            println!("✅ Footer tampering detected and rejected!");
            println!("   Error: {:?}", e);
            println!("   🛡️  v0.1.1+ PAE authentication prevented privilege escalation");
        }
    }

    println!();

    // Demonstrate v0.1.1 Local Token Security
    println!("🔐 LOCAL TOKEN SECURITY (ChaCha20-Poly1305 AEAD)");
    println!("──────────────────────────────────────────────────");

    // Create local token with authenticated footer
    let local_token = PasetoPQ::encrypt_with_footer(&symmetric_key, &claims, Some(&footer))?;

    println!("✅ Created local token with authenticated footer");
    println!("   Token length: {} bytes", local_token.len());

    // Decrypt authentic token
    match PasetoPQ::decrypt_with_footer(&symmetric_key, &local_token) {
        Ok(decrypted) => {
            println!("✅ Authentic token decrypted successfully");
            println!("   Subject: {}", decrypted.claims().subject().unwrap());
            println!(
                "   Footer Key ID: {}",
                decrypted.footer().unwrap().kid().unwrap()
            );
        }
        Err(e) => {
            println!("❌ ERROR: Authentic local token decryption failed: {:?}", e);
            return Err(e.into());
        }
    }

    // Demonstrate footer tampering detection for local tokens
    println!("\n🚨 Testing Local Token Footer Tampering...");

    // Replace footer in local token (simulating tampering)
    let mut local_token_parts: Vec<&str> = local_token.split('.').collect();
    local_token_parts[4] = &tampered_footer_b64;
    let tampered_local_token = local_token_parts.join(".");

    // Attempt decryption of tampered token
    match PasetoPQ::decrypt_with_footer(&symmetric_key, &tampered_local_token) {
        Ok(_) => println!("❌ ERROR: Tampered local token should have failed!"),
        Err(_e) => {
            println!("✅ Local token footer tampering detected!");
            println!("   Error: Decryption failed (AEAD authentication)");
            println!("   🛡️  v0.1.1+ PAE-based AAD prevented metadata tampering");
        }
    }

    println!();

    // Demonstrate PAE (Pre-Authentication Encoding) directly
    println!("🔧 PAE (PRE-AUTHENTICATION ENCODING) DEMO");
    println!("──────────────────────────────────────────");

    // Show how PAE prevents collision attacks
    let header = b"paseto.pq1.public";
    let payload1 = b"ab";
    let payload2 = b"cd";
    let combined_payload = b"abcd";

    let pae1 = paseto_pq::pae_encode(&[header, payload1, payload2]);
    let pae2 = paseto_pq::pae_encode(&[header, combined_payload, b""]);

    println!("PAE prevents collision attacks:");
    println!("   PAE([header, 'ab', 'cd']) = {} bytes", pae1.len());
    println!("   PAE([header, 'abcd', '']) = {} bytes", pae2.len());
    println!("   Results are different: {}", pae1 != pae2);
    println!("   🛡️  Length prefixing ensures unambiguous parsing");

    println!();

    // Summary
    println!("📊 SECURITY IMPROVEMENTS SUMMARY");
    println!("─────────────────────────────────");
    println!("✅ Footer Authentication: Cryptographically protected metadata");
    println!("✅ Tamper Detection: Footer modifications are detected and rejected");
    println!("✅ RFC Compliance: Full PASETO specification adherence");
    println!("✅ PAE Integration: Collision-resistant message encoding");
    println!("✅ No API Changes: Existing code works unchanged");
    println!("✅ Transparent Security: Protection works automatically");
    println!();
    println!("🚀 Upgrade to v0.1.2 for enhanced security and code quality!");

    Ok(())
}
