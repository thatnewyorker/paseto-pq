//! Simple test to debug signature verification issue in v0.1.1

use paseto_pq::{Claims, Footer, KeyPair, PasetoPQ};
use rand::rng;
use time::OffsetDateTime;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 Simple Security Test - Debug Mode");
    println!("═══════════════════════════════════════");

    // Generate keys
    let mut rng = rng();
    let keypair = KeyPair::generate(&mut rng);

    // Create simple claims
    let mut claims = Claims::new();
    claims.set_subject("test@example.com".to_string())?;
    claims.set_issuer("test-service".to_string())?;
    claims.set_expiration(OffsetDateTime::now_utc() + time::Duration::hours(1))?;

    println!("✅ Created claims");

    // Create footer with array custom field (testing the issue)
    let mut footer = Footer::new();
    footer.set_kid("test-key")?;
    footer.set_version("1.0")?;
    footer.add_custom("permissions", &["read", "write", "delete"])?;

    println!("✅ Created footer");

    // Test token creation and verification
    println!("\n🔐 Testing Token Operations:");

    // Sign token
    let token = PasetoPQ::sign_with_footer(keypair.signing_key(), &claims, Some(&footer))?;
    println!("✅ Token signed successfully");
    println!("   Token length: {} bytes", token.len());

    // Verify token
    match PasetoPQ::verify_with_footer(keypair.verifying_key(), &token) {
        Ok(verified) => {
            println!("✅ Token verified successfully");
            println!("   Subject: {}", verified.claims().subject().unwrap());
            println!(
                "   Footer Key ID: {}",
                verified.footer().unwrap().kid().unwrap()
            );
        }
        Err(e) => {
            println!("❌ ERROR: Token verification failed: {:?}", e);
            return Err(e.into());
        }
    }

    // Test without footer
    println!("\n🔐 Testing Without Footer:");

    let token_no_footer = PasetoPQ::sign_with_footer(keypair.signing_key(), &claims, None)?;
    println!("✅ Token without footer signed successfully");

    match PasetoPQ::verify_with_footer(keypair.verifying_key(), &token_no_footer) {
        Ok(verified) => {
            println!("✅ Token without footer verified successfully");
            println!("   Subject: {}", verified.claims().subject().unwrap());
            println!("   Has footer: {}", verified.footer().is_some());
        }
        Err(e) => {
            println!(
                "❌ ERROR: Token without footer verification failed: {:?}",
                e
            );
            return Err(e.into());
        }
    }

    println!("\n🎉 All tests passed!");
    Ok(())
}
