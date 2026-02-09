//! Token Parsing Demo - PASETO-PQ Token Inspection
//!
//! This example demonstrates how to parse and inspect PASETO-PQ tokens
//! without performing cryptographic verification. Useful for debugging,
//! logging, and routing decisions.

use paseto_pq::{Claims, Footer, KeyPair, ParsedToken, PasetoPQ, SymmetricKey};
use time::{Duration, OffsetDateTime};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== PASETO-PQ Token Parsing Demo (CBOR) ===\n");

    let mut rng = rand::rng();
    let keypair = KeyPair::generate(&mut rng);
    let symmetric_key = SymmetricKey::generate(&mut rng);

    // ============================================
    // Part 1: Parse Public Token
    // ============================================
    println!("--- Part 1: Public Token Parsing ---\n");

    let mut claims = Claims::new();
    claims.set_subject("user123")?;
    claims.set_issuer("parsing-demo")?;
    claims.set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))?;

    let public_token = PasetoPQ::sign(keypair.signing_key(), &claims)?;

    // Parse without verification
    let parsed = ParsedToken::parse(&public_token)?;

    println!("Token parsed (no verification performed):");
    println!("  Version: {}", parsed.version());
    println!("  Purpose: {}", parsed.purpose());
    println!("  Is Public: {}", parsed.is_public());
    println!("  Is Local: {}", parsed.is_local());
    println!("  Has Footer: {}", parsed.has_footer());
    println!("  Payload Length: {} bytes", parsed.payload_length());
    println!("  Total Length: {} bytes", parsed.total_length());
    println!();

    // ============================================
    // Part 2: Parse Public Token with Footer
    // ============================================
    println!("--- Part 2: Public Token with Footer ---\n");

    let mut footer = Footer::new();
    footer.set_kid("key-2024-01")?;
    footer.set_version("1.0.0")?;
    footer.add_custom("environment", "production")?;

    let token_with_footer =
        PasetoPQ::sign_with_footer(keypair.signing_key(), &claims, Some(&footer))?;

    let parsed_with_footer = ParsedToken::parse(&token_with_footer)?;

    println!("Token with footer parsed:");
    println!("  Version: {}", parsed_with_footer.version());
    println!("  Purpose: {}", parsed_with_footer.purpose());
    println!("  Has Footer: {}", parsed_with_footer.has_footer());

    if let Some(f) = parsed_with_footer.footer() {
        println!("  Footer Key ID: {:?}", f.kid());
        println!("  Footer Version: {:?}", f.version());
        if let Some(env) = f.get_custom("environment") {
            println!("  Footer Environment: {:?}", env);
        }
    }
    println!();

    // ============================================
    // Part 3: Parse Local Token
    // ============================================
    println!("--- Part 3: Local Token Parsing ---\n");

    let local_token = PasetoPQ::encrypt(&symmetric_key, &claims)?;
    let parsed_local = ParsedToken::parse(&local_token)?;

    println!("Local token parsed:");
    println!("  Version: {}", parsed_local.version());
    println!("  Purpose: {}", parsed_local.purpose());
    println!("  Is Public: {}", parsed_local.is_public());
    println!("  Is Local: {}", parsed_local.is_local());
    println!(
        "  Payload Length: {} bytes (encrypted)",
        parsed_local.payload_length()
    );
    println!();

    // ============================================
    // Part 4: Token Format Summary
    // ============================================
    println!("--- Part 4: Token Format Summary ---\n");

    println!("Public token format summary:");
    println!("{}", parsed.format_summary());
    println!();

    println!("Public token with footer summary:");
    println!("{}", parsed_with_footer.format_summary());
    println!();

    println!("Local token summary:");
    println!("{}", parsed_local.format_summary());
    println!();

    // ============================================
    // Part 5: Routing Example
    // ============================================
    println!("--- Part 5: Routing Example ---\n");

    let tokens = vec![
        ("Token 1", public_token.as_str()),
        ("Token 2", token_with_footer.as_str()),
        ("Token 3", local_token.as_str()),
    ];

    for (name, token) in tokens {
        if let Ok(parsed) = ParsedToken::parse(token) {
            let action = match (parsed.purpose(), parsed.has_footer()) {
                ("public", false) => "Route to public key verifier",
                ("public", true) => "Route to public key verifier (check footer for key selection)",
                ("local", false) => "Route to symmetric decryptor",
                ("local", true) => "Route to symmetric decryptor (check footer for key selection)",
                _ => "Unknown token type",
            };
            println!("{}: {}", name, action);
        }
    }
    println!();

    // ============================================
    // Part 6: Error Handling
    // ============================================
    println!("--- Part 6: Error Handling ---\n");

    let invalid_tokens = [
        "",
        "not-a-token",
        "paseto.v4.public.payload",     // Wrong version
        "paseto.pq2.secret.payload",    // Unknown purpose
        "jwt.header.payload.signature", // Not PASETO
    ];

    for invalid in invalid_tokens {
        match ParsedToken::parse(invalid) {
            Ok(_) => println!("'{}': Unexpectedly parsed OK", invalid),
            Err(e) => println!(
                "'{}': {}",
                if invalid.is_empty() {
                    "(empty)"
                } else {
                    invalid
                },
                e
            ),
        }
    }
    println!();

    // ============================================
    // Part 7: Using PasetoPQ::parse_token
    // ============================================
    println!("--- Part 7: Convenience Method ---\n");

    // PasetoPQ::parse_token is equivalent to ParsedToken::parse
    let convenience_parsed = PasetoPQ::parse_token(&public_token)?;
    println!("Using PasetoPQ::parse_token():");
    println!("  Purpose: {}", convenience_parsed.purpose());
    println!("  Version: {}", convenience_parsed.version());
    println!();

    println!("=== Token Parsing Demo Complete ===");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_parsing() {
        let mut rng = rand::rng();
        let keypair = KeyPair::generate(&mut rng);

        let mut claims = Claims::new();
        claims.set_subject("test").unwrap();
        claims
            .set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))
            .unwrap();

        let token = PasetoPQ::sign(keypair.signing_key(), &claims).unwrap();
        let parsed = ParsedToken::parse(&token).unwrap();

        assert_eq!(parsed.purpose(), "public");
        assert_eq!(parsed.version(), "pq2");
        assert!(parsed.is_public());
        assert!(!parsed.is_local());
    }

    #[test]
    fn test_footer_parsing() {
        let mut rng = rand::rng();
        let keypair = KeyPair::generate(&mut rng);

        let mut claims = Claims::new();
        claims.set_subject("test").unwrap();
        claims
            .set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))
            .unwrap();

        let mut footer = Footer::new();
        footer.set_kid("test-key").unwrap();

        let token =
            PasetoPQ::sign_with_footer(keypair.signing_key(), &claims, Some(&footer)).unwrap();
        let parsed = ParsedToken::parse(&token).unwrap();

        assert!(parsed.has_footer());
        assert_eq!(parsed.footer().unwrap().kid(), Some("test-key"));
    }

    #[test]
    fn test_invalid_tokens() {
        assert!(ParsedToken::parse("").is_err());
        assert!(ParsedToken::parse("invalid").is_err());
        assert!(ParsedToken::parse("paseto.pq1.public.payload.sig").is_err()); // Old version
    }
}
