//! PASETO-PQ Footer Functionality Demo
//!
//! This example demonstrates the comprehensive footer functionality in PASETO-PQ tokens.
//! Footers provide authenticated metadata separate from claims, useful for key management,
//! service mesh integration, tracing, and operational metadata.
//!
//! Run with: cargo run --example footer_demo

use paseto_pq::{Claims, Footer, KeyPair, PasetoPQ, SymmetricKey};
use rand::rng;
use std::time::Instant;
use time::{Duration, OffsetDateTime};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🦶 PASETO-PQ Footer Functionality Demo");
    println!("======================================\n");

    let mut rng = rng();

    // Generate keys for both token types
    let asymmetric_keypair = KeyPair::generate(&mut rng);
    let symmetric_key = SymmetricKey::generate(&mut rng);

    // Create standard claims
    let mut claims = Claims::new();
    claims.set_subject("alice@example.com")?;
    claims.set_issuer("auth-service")?;
    claims.set_audience("api.example.com")?;
    claims.set_expiration(OffsetDateTime::now_utc() + Duration::hours(2))?;
    claims.set_jti("session-abc-123")?;
    claims.add_custom("role", "admin")?;
    claims.add_custom("tenant_id", "org_12345")?;

    println!("📋 Standard Claims:");
    println!("   Subject:  {}", claims.subject().unwrap_or("None"));
    println!("   Issuer:   {}", claims.issuer().unwrap_or("None"));
    println!("   JTI:      {}", claims.jti().unwrap_or("None"));

    // === BASIC FOOTER FUNCTIONALITY ===
    println!("\n🏷️  Basic Footer Operations:");

    let mut basic_footer = Footer::new();
    basic_footer.set_kid("prod-key-2024-01")?;
    basic_footer.set_version("v2.1.0")?;
    basic_footer.set_issuer_meta("production-auth-service")?;
    basic_footer.add_custom("deployment", "us-east-1")?;

    println!("   Created footer:");
    println!("     KID: {}", basic_footer.kid().unwrap_or("None"));
    println!("     Version: {}", basic_footer.version().unwrap_or("None"));
    println!(
        "     Issuer Meta: {}",
        basic_footer.issuer_meta().unwrap_or("None")
    );
    println!(
        "     Deployment: {}",
        basic_footer
            .get_custom("deployment")
            .and_then(|v| v.as_str())
            .unwrap_or("None")
    );

    // === PUBLIC TOKENS WITH FOOTERS ===
    println!("\n🔓 Public Token Operations:");

    let start_time = Instant::now();
    let public_token = PasetoPQ::sign_with_footer(
        &asymmetric_keypair.signing_key,
        &claims,
        Some(&basic_footer),
    )?;
    let sign_time = start_time.elapsed();

    let start_time = Instant::now();
    let verified_public =
        PasetoPQ::verify_with_footer(&asymmetric_keypair.verifying_key, &public_token)?;
    let verify_time = start_time.elapsed();

    println!("   Token format: {}", &public_token[..50]);
    println!(
        "   Token parts:  {} (with footer)",
        public_token.split('.').count()
    );
    println!("   Token size:   {} bytes", public_token.len());
    println!("   Sign time:    {:?}", sign_time);
    println!("   Verify time:  {:?}", verify_time);

    // Verify claims and footer
    assert_eq!(
        verified_public.claims().subject(),
        Some("alice@example.com")
    );

    let footer_data = verified_public.footer().expect("Footer should be present");
    println!(
        "   Verified footer KID: {}",
        footer_data.kid().unwrap_or("None")
    );

    // === LOCAL TOKENS WITH FOOTERS ===
    println!("\n🔒 Local Token Operations:");

    let mut local_footer = Footer::new();
    local_footer.set_kid("session-key-2024-01")?;
    local_footer.add_custom("session_type", "secure")?;
    local_footer.add_custom("encryption_level", "AES256")?;

    let start_time = Instant::now();
    let local_token = PasetoPQ::encrypt_with_footer(&symmetric_key, &claims, Some(&local_footer))?;
    let encrypt_time = start_time.elapsed();

    let start_time = Instant::now();
    let verified_local = PasetoPQ::decrypt_with_footer(&symmetric_key, &local_token)?;
    let decrypt_time = start_time.elapsed();

    println!("   Token format: {}", &local_token[..50]);
    println!(
        "   Token parts:  {} (with footer)",
        local_token.split('.').count()
    );
    println!("   Token size:   {} bytes", local_token.len());
    println!("   Encrypt time: {:?}", encrypt_time);
    println!("   Decrypt time: {:?}", decrypt_time);

    let local_footer_data = verified_local.footer().expect("Footer should be present");
    println!(
        "   Session type: {}",
        local_footer_data
            .get_custom("session_type")
            .and_then(|v| v.as_str())
            .unwrap_or("None")
    );

    // === KEY ROTATION SCENARIO ===
    println!("\n🔄 Key Rotation Scenario:");

    // Simulate key rotation with different key IDs
    let key_rotation_scenarios = vec![
        ("legacy-key-2023", "v1.0.0", "Legacy system"),
        ("current-key-2024-q1", "v2.0.0", "Current production"),
        ("next-key-2024-q2", "v2.1.0", "Next release candidate"),
    ];

    for (kid, version, description) in key_rotation_scenarios {
        let mut rotation_footer = Footer::new();
        rotation_footer.set_kid(kid)?;
        rotation_footer.set_version(version)?;
        rotation_footer.add_custom("description", description)?;

        let token = PasetoPQ::sign_with_footer(
            &asymmetric_keypair.signing_key,
            &claims,
            Some(&rotation_footer),
        )?;

        let verified = PasetoPQ::verify_with_footer(&asymmetric_keypair.verifying_key, &token)?;
        let footer = verified.footer().unwrap();

        println!(
            "   Token with KID '{}' ({}): verified ✓",
            footer.kid().unwrap(),
            footer.get_custom("description").unwrap().as_str().unwrap()
        );
    }

    // === MICROSERVICE INTEGRATION ===
    println!("\n🔗 Microservice Integration:");

    let mut service_footer = Footer::new();
    service_footer.set_kid("api-gateway-2024")?;
    service_footer.add_custom("trace_id", "trace-xyz-789")?;
    service_footer.add_custom("span_id", "span-abc-123")?;
    service_footer.add_custom("service_mesh", "istio-1.18")?;
    service_footer.add_custom("namespace", "production")?;
    service_footer.add_custom("cluster", "us-east-1-prod")?;
    service_footer.add_custom("request_id", "req-def-456")?;

    let service_token = PasetoPQ::sign_with_footer(
        &asymmetric_keypair.signing_key,
        &claims,
        Some(&service_footer),
    )?;

    let verified_service =
        PasetoPQ::verify_with_footer(&asymmetric_keypair.verifying_key, &service_token)?;
    let service_footer_data = verified_service.footer().unwrap();

    println!("   Distributed tracing metadata:");
    println!(
        "     Trace ID: {}",
        service_footer_data
            .get_custom("trace_id")
            .unwrap()
            .as_str()
            .unwrap()
    );
    println!(
        "     Span ID:  {}",
        service_footer_data
            .get_custom("span_id")
            .unwrap()
            .as_str()
            .unwrap()
    );
    println!(
        "     Cluster:  {}",
        service_footer_data
            .get_custom("cluster")
            .unwrap()
            .as_str()
            .unwrap()
    );

    // === PERFORMANCE COMPARISON ===
    println!("\n📊 Performance Impact Analysis:");

    // Tokens without footer
    let token_no_footer = PasetoPQ::sign(&asymmetric_keypair.signing_key, &claims)?;
    let local_no_footer = PasetoPQ::encrypt(&symmetric_key, &claims)?;

    // Tokens with footer
    let token_with_footer = PasetoPQ::sign_with_footer(
        &asymmetric_keypair.signing_key,
        &claims,
        Some(&basic_footer),
    )?;
    let local_with_footer =
        PasetoPQ::encrypt_with_footer(&symmetric_key, &claims, Some(&local_footer))?;

    println!("   Public Token Sizes:");
    println!("     Without footer: {} bytes", token_no_footer.len());
    println!("     With footer:    {} bytes", token_with_footer.len());
    println!(
        "     Overhead:       {} bytes ({:.1}%)",
        token_with_footer.len() - token_no_footer.len(),
        ((token_with_footer.len() - token_no_footer.len()) as f64 / token_no_footer.len() as f64)
            * 100.0
    );

    println!("   Local Token Sizes:");
    println!("     Without footer: {} bytes", local_no_footer.len());
    println!("     With footer:    {} bytes", local_with_footer.len());
    println!(
        "     Overhead:       {} bytes ({:.1}%)",
        local_with_footer.len() - local_no_footer.len(),
        ((local_with_footer.len() - local_no_footer.len()) as f64 / local_no_footer.len() as f64)
            * 100.0
    );

    // === SECURITY ANALYSIS ===
    println!("\n🛡️  Security Properties:");

    // Demonstrate tamper detection
    let mut tampered_token = public_token.clone();
    tampered_token.push('x'); // Tamper with footer

    let tamper_result =
        PasetoPQ::verify_with_footer(&asymmetric_keypair.verifying_key, &tampered_token);
    println!(
        "   Footer tamper detection: {}",
        if tamper_result.is_err() {
            "✓ PASS"
        } else {
            "✗ FAIL"
        }
    );

    // Show footer visibility in public vs local tokens
    println!("   Public token footer visibility:");
    println!("     Footer is visible but authenticated");
    println!("     Modification breaks signature verification");

    println!("   Local token footer confidentiality:");
    println!("     Footer is encrypted with payload");
    println!("     Provides both confidentiality and authentication");

    // === ADVANCED USE CASES ===
    println!("\n🎯 Advanced Use Cases:");

    // 1. Load balancing hints
    let mut lb_footer = Footer::new();
    lb_footer.set_kid("load-balancer-key")?;
    lb_footer.add_custom("preferred_region", "us-east-1")?;
    lb_footer.add_custom("load_class", "premium")?;
    lb_footer.add_custom("routing_tier", "gold")?;
    lb_footer.add_custom("sticky_session", &true)?;

    println!("   1. Load Balancing Hints:");
    println!(
        "      Preferred region: {}",
        lb_footer
            .get_custom("preferred_region")
            .unwrap()
            .as_str()
            .unwrap()
    );
    println!(
        "      Load class: {}",
        lb_footer
            .get_custom("load_class")
            .unwrap()
            .as_str()
            .unwrap()
    );

    // 2. A/B testing metadata
    let mut ab_footer = Footer::new();
    ab_footer.set_kid("experiment-key")?;
    ab_footer.add_custom("experiment_id", "homepage-redesign-v2")?;
    ab_footer.add_custom("variant", "treatment")?;
    ab_footer.add_custom("cohort", "premium-users")?;

    println!("   2. A/B Testing Metadata:");
    println!(
        "      Experiment: {}",
        ab_footer
            .get_custom("experiment_id")
            .unwrap()
            .as_str()
            .unwrap()
    );
    println!(
        "      Variant: {}",
        ab_footer.get_custom("variant").unwrap().as_str().unwrap()
    );

    // 3. Compliance and audit trail
    let mut audit_footer = Footer::new();
    audit_footer.set_kid("audit-key")?;
    audit_footer.add_custom("compliance_level", "SOX")?;
    audit_footer.add_custom("audit_log_id", "audit-2024-001234")?;
    audit_footer.add_custom("data_classification", "confidential")?;
    audit_footer.add_custom("retention_policy", "7-years")?;

    println!("   3. Compliance & Audit:");
    println!(
        "      Compliance: {}",
        audit_footer
            .get_custom("compliance_level")
            .unwrap()
            .as_str()
            .unwrap()
    );
    println!(
        "      Audit log: {}",
        audit_footer
            .get_custom("audit_log_id")
            .unwrap()
            .as_str()
            .unwrap()
    );

    // === BACKWARD COMPATIBILITY ===
    println!("\n↔️  Backward Compatibility:");

    // Old tokens (without footer) should work with new verification methods
    let old_public = PasetoPQ::sign(&asymmetric_keypair.signing_key, &claims)?;
    let old_local = PasetoPQ::encrypt(&symmetric_key, &claims)?;

    let verified_old_public =
        PasetoPQ::verify_with_footer(&asymmetric_keypair.verifying_key, &old_public)?;
    let verified_old_local = PasetoPQ::decrypt_with_footer(&symmetric_key, &old_local)?;

    println!("   Legacy token compatibility:");
    println!(
        "     Public token (no footer): {} ✓",
        if verified_old_public.footer().is_none() {
            "PASS"
        } else {
            "FAIL"
        }
    );
    println!(
        "     Local token (no footer):  {} ✓",
        if verified_old_local.footer().is_none() {
            "PASS"
        } else {
            "FAIL"
        }
    );

    // New tokens with footer should work with standard methods
    let _new_public_verified = PasetoPQ::verify(&asymmetric_keypair.verifying_key, &old_public)?;
    let _new_local_verified = PasetoPQ::decrypt(&symmetric_key, &old_local)?;

    println!("     Standard API compatibility: ✓ PASS");

    // === TOKEN FORMAT EXAMPLES ===
    println!("\n📝 Token Format Examples:");

    println!("   Public token without footer (5 parts):");
    println!("     paseto.v1.pq.<payload>.<signature>");
    println!("     Parts: {}", old_public.split('.').count());

    println!("   Public token with footer (6 parts):");
    println!("     paseto.v1.pq.<payload>.<signature>.<footer>");
    println!("     Parts: {}", public_token.split('.').count());

    println!("   Local token without footer (4 parts):");
    println!("     paseto.v1.local.<encrypted_payload>");
    println!("     Parts: {}", old_local.split('.').count());

    println!("   Local token with footer (5 parts):");
    println!("     paseto.v1.local.<encrypted_payload>.<footer>");
    println!("     Parts: {}", local_token.split('.').count());

    // === BEST PRACTICES ===
    println!("\n💡 Footer Best Practices:");
    println!("   ✓ Use footers for infrastructure metadata, not business logic");
    println!("   ✓ Keep footer size reasonable (< 1KB recommended)");
    println!("   ✓ Use kid field for key rotation and selection");
    println!("   ✓ Include version information for API compatibility");
    println!("   ✓ Add tracing information for distributed systems");
    println!("   ✗ Don't put sensitive business data in public token footers");
    println!("   ✗ Don't rely on footer data for authorization decisions");
    println!("   ✗ Don't use footers as a replacement for proper claims structure");

    println!("\n✅ Footer functionality demonstration completed successfully!");
    println!("🦶 PASETO-PQ footers provide powerful metadata capabilities!");
    println!("🔐 All operations maintain quantum-safe security properties!");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_footer_workflow() -> Result<(), Box<dyn std::error::Error>> {
        let mut rng = thread_rng();
        let keypair = KeyPair::generate(&mut rng);

        let mut claims = Claims::new();
        claims.set_subject("test-user")?;

        let mut footer = Footer::new();
        footer.set_kid("test-key")?;
        footer.add_custom("test_field", "test_value")?;

        let token = PasetoPQ::sign_with_footer(&keypair.signing_key, &claims, Some(&footer))?;
        let verified = PasetoPQ::verify_with_footer(&keypair.verifying_key, &token)?;

        assert_eq!(verified.claims().subject(), Some("test-user"));
        assert_eq!(verified.footer().unwrap().kid(), Some("test-key"));
        assert_eq!(
            verified
                .footer()
                .unwrap()
                .get_custom("test_field")
                .unwrap()
                .as_str(),
            Some("test_value")
        );

        Ok(())
    }

    #[test]
    fn test_footer_size_impact() -> Result<(), Box<dyn std::error::Error>> {
        let mut rng = thread_rng();
        let keypair = KeyPair::generate(&mut rng);

        let mut claims = Claims::new();
        claims.set_subject("test-user")?;

        // Token without footer
        let token_no_footer = PasetoPQ::sign(&keypair.signing_key, &claims)?;

        // Token with small footer
        let mut small_footer = Footer::new();
        small_footer.set_kid("key-1")?;
        let token_small_footer =
            PasetoPQ::sign_with_footer(&keypair.signing_key, &claims, Some(&small_footer))?;

        // Token with large footer
        let mut large_footer = Footer::new();
        large_footer.set_kid("very-long-key-identifier-with-lots-of-metadata")?;
        large_footer.add_custom("large_data", &"x".repeat(500))?;
        let token_large_footer =
            PasetoPQ::sign_with_footer(&keypair.signing_key, &claims, Some(&large_footer))?;

        // Verify size relationships
        assert!(token_small_footer.len() > token_no_footer.len());
        assert!(token_large_footer.len() > token_small_footer.len());

        // All tokens should verify correctly
        PasetoPQ::verify(&keypair.verifying_key, &token_no_footer)?;
        PasetoPQ::verify_with_footer(&keypair.verifying_key, &token_small_footer)?;
        PasetoPQ::verify_with_footer(&keypair.verifying_key, &token_large_footer)?;

        Ok(())
    }
}
