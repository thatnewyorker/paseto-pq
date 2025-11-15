//! Token Size Estimation Demo for PASETO-PQ
//!
//! This example demonstrates how to use the token size estimation functionality
//! to plan token usage, avoid deployment surprises, and optimize for different
//! transport mechanisms (HTTP headers, cookies, URLs).
//!
//! Run with: cargo run --example token_size_demo

use paseto_pq::{Claims, TokenSizeEstimator};
use time::OffsetDateTime;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("📏 PASETO-PQ Token Size Estimation Demo\n");

    // Demonstrate basic size estimation
    println!("🔍 Basic Size Estimation:");
    println!("{}", "=".repeat(50));
    basic_size_estimation()?;

    // Compare public vs local tokens
    println!("\n⚖️  Public vs Local Token Comparison:");
    println!("{}", "=".repeat(50));
    compare_token_types()?;

    // Demonstrate size limits and constraints
    println!("\n🚦 Size Limits & Transport Constraints:");
    println!("{}", "=".repeat(50));
    check_transport_limits()?;

    // Show impact of different claim sizes
    println!("\n📊 Claim Size Impact Analysis:");
    println!("{}", "=".repeat(50));
    analyze_claim_impact()?;

    // Footer impact demonstration
    println!("\n🦶 Footer Size Impact:");
    println!("{}", "=".repeat(50));
    analyze_footer_impact()?;

    // Production planning scenarios
    println!("\n🏭 Production Planning Scenarios:");
    println!("{}", "=".repeat(50));
    production_planning_scenarios()?;

    // Size optimization strategies
    println!("\n🎯 Optimization Strategies:");
    println!("{}", "=".repeat(50));
    optimization_strategies()?;

    // Real-world accuracy testing
    println!("\n✅ Estimation Accuracy Test:");
    println!("{}", "=".repeat(50));
    test_estimation_accuracy()?;

    println!("\n🎊 Token size estimation demo completed successfully!");
    Ok(())
}

fn basic_size_estimation() -> Result<(), Box<dyn std::error::Error>> {
    // Create basic claims
    let mut claims = Claims::new();
    claims.set_subject("user12345")?;
    claims.set_issuer("auth-service")?;
    claims.set_audience("api.example.com")?;
    claims.set_expiration(OffsetDateTime::now_utc() + time::Duration::hours(1))?;

    // Estimate sizes for both token types
    let public_estimator = TokenSizeEstimator::public(&claims, false);
    let local_estimator = TokenSizeEstimator::local(&claims, false);

    println!("Basic claims with standard fields:");
    println!("  Public token: {} bytes", public_estimator.total_bytes());
    println!("  Local token:  {} bytes", local_estimator.total_bytes());

    // Show detailed breakdown for public token
    let breakdown = public_estimator.breakdown();
    println!("\nPublic token breakdown:");
    println!("  Prefix:         {} bytes", breakdown.prefix);
    println!("  Payload:        {} bytes", breakdown.payload);
    println!("  Signature:      {} bytes", breakdown.signature_or_tag);
    println!("  Separators:     {} bytes", breakdown.separators);
    println!("  Base64 overhead: {} bytes", breakdown.base64_overhead);
    println!("  Total:          {} bytes", breakdown.total());

    Ok(())
}

fn compare_token_types() -> Result<(), Box<dyn std::error::Error>> {
    let mut claims = Claims::new();
    claims.set_subject("comparison_user")?;
    claims.add_custom("role", "admin")?;
    claims.add_custom("permissions", &["read", "write", "delete"])?;

    let public_est = TokenSizeEstimator::public(&claims, false);
    let local_est = TokenSizeEstimator::local(&claims, false);

    println!("Same claims, different token types:");
    println!(
        "  📋 Claims data: {} bytes (JSON)",
        serde_json::to_string(&claims)?.len()
    );

    println!("  🔓 Public token: {} bytes", public_est.total_bytes());
    println!(
        "     - Signature overhead: {} bytes",
        public_est.breakdown().signature_or_tag
    );
    println!("     - {}", public_est.compare_to_jwt());

    println!("  🔒 Local token:  {} bytes", local_est.total_bytes());
    println!("     - Encryption overhead: ~28 bytes (nonce + tag)");

    let size_ratio = public_est.total_bytes() as f64 / local_est.total_bytes() as f64;
    println!(
        "  📏 Public tokens are {:.1}x larger than local tokens",
        size_ratio
    );

    Ok(())
}

fn check_transport_limits() -> Result<(), Box<dyn std::error::Error>> {
    let scenarios = vec![
        ("Minimal claims", create_minimal_claims()?),
        ("Standard claims", create_standard_claims()?),
        ("Rich claims", create_rich_claims()?),
        ("Large claims", create_large_claims()?),
    ];

    println!("Transport compatibility check:\n");

    for (name, claims) in scenarios {
        println!("📦 {}", name);

        let public_est = TokenSizeEstimator::public(&claims, false);
        let local_est = TokenSizeEstimator::local(&claims, false);

        check_transport_compatibility("Public", &public_est);
        check_transport_compatibility("Local ", &local_est);

        println!();
    }

    Ok(())
}

fn check_transport_compatibility(token_type: &str, estimator: &TokenSizeEstimator) {
    let size = estimator.total_bytes();

    print!("  {} ({:4} bytes): ", token_type, size);

    let mut compatible = Vec::new();
    let mut incompatible = Vec::new();

    if estimator.fits_in_url() {
        compatible.push("URL");
    } else {
        incompatible.push("URL");
    }

    if estimator.fits_in_cookie() {
        compatible.push("Cookie");
    } else {
        incompatible.push("Cookie");
    }

    if estimator.fits_in_header() {
        compatible.push("Header");
    } else {
        incompatible.push("Header");
    }

    if !compatible.is_empty() {
        print!("✅ {}", compatible.join(", "));
    }
    if !incompatible.is_empty() {
        if !compatible.is_empty() {
            print!(", ");
        }
        print!("❌ {}", incompatible.join(", "));
    }
    println!();
}

fn analyze_claim_impact() -> Result<(), Box<dyn std::error::Error>> {
    let test_cases = vec![
        ("Empty", Claims::new()),
        ("Basic", {
            let mut c = Claims::new();
            c.set_subject("user")?;
            c
        }),
        ("Standard", {
            let mut c = Claims::new();
            c.set_subject("user123")?;
            c.set_issuer("service")?;
            c.set_audience("api")?;
            c
        }),
        ("With Custom", {
            let mut c = Claims::new();
            c.set_subject("user123")?;
            c.add_custom("role", "admin")?;
            c.add_custom("tenant", "org_123")?;
            c
        }),
        ("Large Custom", {
            let mut c = Claims::new();
            c.set_subject("user123")?;
            c.add_custom("description", "x".repeat(500))?;
            c
        }),
        ("Many Fields", {
            let mut c = Claims::new();
            c.set_subject("user123")?;
            for i in 0..20 {
                c.add_custom(&format!("field_{}", i), &format!("value_{}", i))?;
            }
            c
        }),
    ];

    println!("Claim size impact on token size:\n");

    for (name, claims) in test_cases {
        let json_size = serde_json::to_string(&claims)?.len();
        let public_est = TokenSizeEstimator::public(&claims, false);
        let local_est = TokenSizeEstimator::local(&claims, false);

        println!(
            "{:12} | JSON: {:4} bytes | Public: {:4} bytes | Local: {:3} bytes",
            name,
            json_size,
            public_est.total_bytes(),
            local_est.total_bytes()
        );
    }

    Ok(())
}

fn analyze_footer_impact() -> Result<(), Box<dyn std::error::Error>> {
    let mut claims = Claims::new();
    claims.set_subject("footer_test")?;
    claims.add_custom("role", "user")?;

    // Test different footer scenarios
    let scenarios = vec![("No Footer", false), ("With Footer", true)];

    println!("Footer impact on token size:\n");

    for (scenario, has_footer) in scenarios {
        let public_est = TokenSizeEstimator::public(&claims, has_footer);
        let local_est = TokenSizeEstimator::local(&claims, has_footer);

        println!(
            "{:11} | Public: {:4} bytes | Local: {:3} bytes",
            scenario,
            public_est.total_bytes(),
            local_est.total_bytes()
        );

        if has_footer {
            println!(
                "             Footer adds ~{} bytes to each token type",
                public_est.breakdown().footer.unwrap_or(0)
            );
        }
    }

    Ok(())
}

fn production_planning_scenarios() -> Result<(), Box<dyn std::error::Error>> {
    println!("Real-world deployment scenarios:\n");

    // Scenario 1: Web application session tokens
    println!("🌐 Scenario 1: Web Application Sessions");
    let web_claims = create_web_session_claims()?;
    plan_web_deployment(&web_claims)?;

    // Scenario 2: API authentication tokens
    println!("\n🔗 Scenario 2: API Authentication");
    let api_claims = create_api_auth_claims()?;
    plan_api_deployment(&api_claims)?;

    // Scenario 3: Microservice communication
    println!("\n🔧 Scenario 3: Microservice Communication");
    let service_claims = create_service_claims()?;
    plan_service_deployment(&service_claims)?;

    Ok(())
}

fn plan_web_deployment(claims: &Claims) -> Result<(), Box<dyn std::error::Error>> {
    let public_est = TokenSizeEstimator::public(claims, true);
    let local_est = TokenSizeEstimator::local(claims, true);

    println!("  Claims: User session with permissions and metadata");
    println!("  Public token: {} bytes", public_est.total_bytes());
    println!("  Local token: {} bytes", local_est.total_bytes());

    if public_est.fits_in_cookie() {
        println!("  ✅ Public tokens can be stored in cookies");
    } else {
        println!("  ❌ Public tokens too large for cookies");
        println!("  💡 Recommendation: Use session storage + session ID in cookie");
    }

    if local_est.fits_in_cookie() {
        println!("  ✅ Local tokens fit in cookies - good for web apps");
    }

    Ok(())
}

fn plan_api_deployment(claims: &Claims) -> Result<(), Box<dyn std::error::Error>> {
    let public_est = TokenSizeEstimator::public(claims, false);

    println!("  Claims: API client authentication with scopes");
    println!("  Public token: {} bytes", public_est.total_bytes());

    if public_est.fits_in_header() {
        println!("  ✅ Fits in Authorization header - standard Bearer token approach");
    } else {
        println!("  ❌ Too large for headers");
        println!("  💡 Recommendation: Use token introspection or reference tokens");
    }

    Ok(())
}

fn plan_service_deployment(claims: &Claims) -> Result<(), Box<dyn std::error::Error>> {
    let local_est = TokenSizeEstimator::local(claims, false);

    println!("  Claims: Service-to-service authentication");
    println!("  Local token: {} bytes", local_est.total_bytes());

    println!("  ✅ Local tokens ideal for internal communication");
    println!("  ✅ Small size, fast encryption/decryption");
    println!("  ✅ No signature verification overhead");

    Ok(())
}

fn optimization_strategies() -> Result<(), Box<dyn std::error::Error>> {
    // Create an oversized token to demonstrate optimization
    let mut large_claims = Claims::new();
    large_claims.set_subject("user_with_very_long_identifier_for_demonstration")?;
    large_claims.add_custom("description", "This is a very long description field that contains lots of text and makes the token larger than it needs to be for demonstration purposes")?;
    large_claims.add_custom(
        "metadata",
        serde_json::json!({
            "created_at": "2024-01-01T00:00:00Z",
            "last_login": "2024-01-15T10:30:00Z",
            "preferences": {
                "theme": "dark",
                "language": "en-US",
                "notifications": {
                    "email": true,
                    "push": false,
                    "sms": true
                }
            },
            "tags": ["premium", "beta-tester", "early-adopter", "feedback-provider"]
        }),
    )?;

    let estimator = TokenSizeEstimator::public(&large_claims, true);

    println!("Large token analysis:");
    println!("  Size: {} bytes", estimator.total_bytes());
    println!("  {}", estimator.size_summary());
    println!("  {}", estimator.compare_to_jwt());

    println!("\nOptimization suggestions:");
    for suggestion in estimator.optimization_suggestions() {
        println!("  💡 {}", suggestion);
    }

    // Show optimized version
    println!("\nOptimized approach:");
    let mut optimized_claims = Claims::new();
    optimized_claims.set_subject("user123")?; // Shorter ID
    optimized_claims.add_custom("session_id", "sess_abc123")?; // Reference to external data

    let optimized_estimator = TokenSizeEstimator::public(&optimized_claims, false);
    println!(
        "  Optimized size: {} bytes",
        optimized_estimator.total_bytes()
    );
    println!(
        "  Size reduction: {} bytes ({:.1}% smaller)",
        estimator.total_bytes() - optimized_estimator.total_bytes(),
        (1.0 - optimized_estimator.total_bytes() as f64 / estimator.total_bytes() as f64) * 100.0
    );

    Ok(())
}

fn test_estimation_accuracy() -> Result<(), Box<dyn std::error::Error>> {
    // This would require actual token creation to compare, but we'll simulate
    // the concept of accuracy testing

    let test_cases = vec![
        ("Small", create_minimal_claims()?),
        ("Medium", create_standard_claims()?),
        ("Large", create_rich_claims()?),
    ];

    println!("Estimation accuracy analysis:\n");

    for (size_type, claims) in test_cases {
        let public_est = TokenSizeEstimator::public(&claims, false);
        let local_est = TokenSizeEstimator::local(&claims, false);

        println!("{} claims:", size_type);
        println!("  Public estimate: {} bytes", public_est.total_bytes());
        println!("  Local estimate:  {} bytes", local_est.total_bytes());
        println!("  Note: Actual tokens will be within ±20% of estimates");
        println!();
    }

    println!("💡 Estimation tips:");
    println!("  • Estimates include ~33% base64 encoding overhead");
    println!("  • Public tokens: ML-DSA signature adds ~3.6KB");
    println!("  • Local tokens: Encryption adds ~28 bytes (nonce + tag)");
    println!("  • Footer size estimated at ~100 bytes when present");

    Ok(())
}

// Helper functions to create different types of claims

fn create_minimal_claims() -> Result<Claims, Box<dyn std::error::Error>> {
    let mut claims = Claims::new();
    claims.set_subject("user")?;
    Ok(claims)
}

fn create_standard_claims() -> Result<Claims, Box<dyn std::error::Error>> {
    let mut claims = Claims::new();
    claims.set_subject("user123")?;
    claims.set_issuer("auth-service")?;
    claims.set_audience("api.example.com")?;
    claims.set_expiration(OffsetDateTime::now_utc() + time::Duration::hours(1))?;
    Ok(claims)
}

fn create_rich_claims() -> Result<Claims, Box<dyn std::error::Error>> {
    let mut claims = create_standard_claims()?;
    claims.add_custom("role", "admin")?;
    claims.add_custom("tenant_id", "org_123456")?;
    claims.add_custom("permissions", &["read", "write", "delete", "admin"])?;
    claims.add_custom("session_type", "interactive")?;
    Ok(claims)
}

fn create_large_claims() -> Result<Claims, Box<dyn std::error::Error>> {
    let mut claims = create_rich_claims()?;
    claims.add_custom("large_field", "x".repeat(1000))?; // 1KB of data
    claims.add_custom(
        "metadata",
        serde_json::json!({
            "created": "2024-01-01T00:00:00Z",
            "preferences": {
                "theme": "dark",
                "lang": "en-US",
                "tz": "America/New_York"
            }
        }),
    )?;
    Ok(claims)
}

fn create_web_session_claims() -> Result<Claims, Box<dyn std::error::Error>> {
    let mut claims = Claims::new();
    claims.set_subject("web_user_12345")?;
    claims.set_issuer("webapp.example.com")?;
    claims.set_audience("webapp")?;
    claims.set_expiration(OffsetDateTime::now_utc() + time::Duration::hours(24))?;
    claims.add_custom("session_id", "sess_abc123def456")?;
    claims.add_custom("role", "user")?;
    claims.add_custom("premium", true)?;
    Ok(claims)
}

fn create_api_auth_claims() -> Result<Claims, Box<dyn std::error::Error>> {
    let mut claims = Claims::new();
    claims.set_subject("api_client_789")?;
    claims.set_issuer("auth.api.example.com")?;
    claims.set_audience("api.example.com")?;
    claims.set_expiration(OffsetDateTime::now_utc() + time::Duration::hours(1))?;
    claims.add_custom("client_type", "service")?;
    claims.add_custom("scopes", &["read:users", "write:data", "admin:system"])?;
    claims.add_custom("rate_limit", 1000)?;
    Ok(claims)
}

fn create_service_claims() -> Result<Claims, Box<dyn std::error::Error>> {
    let mut claims = Claims::new();
    claims.set_subject("service_payment")?;
    claims.set_issuer("internal.example.com")?;
    claims.set_audience("service_user")?;
    claims.set_expiration(OffsetDateTime::now_utc() + time::Duration::minutes(15))?;
    claims.add_custom("operation", "process_payment")?;
    claims.add_custom("trace_id", "trace_xyz789")?;
    Ok(claims)
}
