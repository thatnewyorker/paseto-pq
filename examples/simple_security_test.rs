//! Simple Security Test - PASETO-PQ Basic Security Verification
//!
//! A simple example that demonstrates basic token creation and verification.

use paseto_pq::{Claims, KeyPair, PasetoPQ};
use time::{Duration, OffsetDateTime};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== PASETO-PQ Simple Security Test ===\n");

    // Generate a new keypair
    let mut rng = rand::rng();
    let keypair = KeyPair::generate(&mut rng);

    // Create claims
    let mut claims = Claims::new();
    claims.set_subject("test@example.com")?;
    claims.set_issuer("test-service")?;
    claims.set_audience("api.example.com")?;
    claims.set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))?;

    println!("Claims created:");
    println!("  Subject: {:?}", claims.subject());
    println!("  Issuer: {:?}", claims.issuer());
    println!("  Audience: {:?}", claims.audience());
    println!();

    // Sign the token
    let token = PasetoPQ::sign(keypair.signing_key(), &claims)?;
    println!("Token created successfully");
    println!("Token length: {} bytes", token.len());
    println!("Token prefix: {}", &token[..20]);
    println!();

    // Verify the token
    let verified = PasetoPQ::verify(keypair.verifying_key(), &token)?;
    println!("Token verified successfully");
    println!("Verified subject: {:?}", verified.claims().subject());
    println!();

    // Test with wrong key
    let other_keypair = KeyPair::generate(&mut rng);
    match PasetoPQ::verify(other_keypair.verifying_key(), &token) {
        Ok(_) => println!("ERROR: Token verified with wrong key!"),
        Err(e) => println!("Correct: Wrong key rejected - {}", e),
    }

    println!("\n=== Security Test Complete ===");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_security() {
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
