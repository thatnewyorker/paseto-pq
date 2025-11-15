//! Token Parsing Demo for PASETO-PQ
//!
//! This example demonstrates how to use the token parsing functionality for debugging,
//! logging, middleware routing, and monitoring without performing expensive cryptographic
//! operations.
//!
//! Run with: cargo run --example token_parsing_demo

use paseto_pq::{Claims, Footer, KeyPair, ParsedToken, PasetoPQ, SymmetricKey};
use std::collections::HashMap;
use time::OffsetDateTime;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔍 PASETO-PQ Token Parsing Demo\n");

    // Generate keys for creating sample tokens
    let mut rng = rand::rng();
    let keypair = KeyPair::generate(&mut rng);
    let symmetric_key = SymmetricKey::generate(&mut rng);

    // Create sample tokens
    let tokens = create_sample_tokens(&keypair, &symmetric_key)?;

    // Demonstrate parsing capabilities
    println!("📋 Token Structure Analysis:");
    println!("{}", "=".repeat(60));
    analyze_token_structures(&tokens)?;

    println!("\n🔀 Middleware Routing Simulation:");
    println!("{}", "=".repeat(60));
    simulate_middleware_routing(&tokens)?;

    println!("\n📊 Token Monitoring & Metrics:");
    println!("{}", "=".repeat(60));
    simulate_monitoring_and_metrics(&tokens)?;

    println!("\n🐛 Debugging Scenarios:");
    println!("{}", "=".repeat(60));
    demonstrate_debugging_scenarios()?;

    println!("\n🚦 Error Handling:");
    println!("{}", "=".repeat(60));
    demonstrate_error_handling()?;

    println!("\n🎯 Performance Comparison:");
    println!("{}", "=".repeat(60));
    performance_comparison(&tokens)?;

    println!("\n✅ Token parsing demo completed successfully!");
    Ok(())
}

fn create_sample_tokens(
    keypair: &KeyPair,
    symmetric_key: &SymmetricKey,
) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let mut tokens = HashMap::new();

    // Create claims for all tokens
    let mut claims = Claims::new();
    claims.set_subject("demo_user_12345")?;
    claims.set_issuer("auth-service")?;
    claims.set_audience("api.conflux.dev")?;
    claims.set_expiration(OffsetDateTime::now_utc() + time::Duration::hours(1))?;
    claims.add_custom("role", "admin")?;
    claims.add_custom("tenant_id", "org_demo_001")?;

    // Create footer for some tokens
    let mut footer = Footer::new();
    footer.set_kid("demo-key-2025")?;
    footer.set_version("v1.2.3")?;
    footer.add_custom("environment", "production")?;
    footer.add_custom("trace_id", "trace_abc123def456")?;

    // 1. Public token without footer
    let public_token = PasetoPQ::sign(keypair.signing_key(), &claims)?;
    tokens.insert("public_simple".to_string(), public_token);

    // 2. Public token with footer
    let public_token_footer =
        PasetoPQ::sign_with_footer(keypair.signing_key(), &claims, Some(&footer))?;
    tokens.insert("public_with_footer".to_string(), public_token_footer);

    // 3. Local token without footer
    let local_token = PasetoPQ::encrypt(symmetric_key, &claims)?;
    tokens.insert("local_simple".to_string(), local_token);

    // 4. Local token with footer
    let local_token_footer = PasetoPQ::encrypt_with_footer(symmetric_key, &claims, Some(&footer))?;
    tokens.insert("local_with_footer".to_string(), local_token_footer);

    // 5. Large token (for size monitoring)
    let mut large_claims = claims.clone();
    large_claims.add_custom("large_data", "x".repeat(1000))?; // 1KB of data
    large_claims.add_custom(
        "permissions",
        &(0..50).map(|i| format!("perm_{}", i)).collect::<Vec<_>>(),
    )?;
    let large_token = PasetoPQ::sign(keypair.signing_key(), &large_claims)?;
    tokens.insert("large_token".to_string(), large_token);

    Ok(tokens)
}

fn analyze_token_structures(
    tokens: &HashMap<String, String>,
) -> Result<(), Box<dyn std::error::Error>> {
    for (name, token) in tokens {
        println!("\n🎫 Token: {}", name);
        println!("{}", "-".repeat(40));

        let parsed = ParsedToken::parse(token)?;

        println!("  Format: {}", parsed.format_summary());
        println!(
            "  Purpose: {} ({})",
            parsed.purpose(),
            if parsed.is_public() {
                "signature-based"
            } else {
                "encryption-based"
            }
        );
        println!("  Version: {}", parsed.version());
        println!("  Payload size: {} bytes", parsed.payload_length());
        println!("  Total size: {} bytes", parsed.total_length());
        println!("  Has signature: {}", parsed.signature_bytes().is_some());
        println!("  Has footer: {}", parsed.has_footer());

        if let Some(footer) = parsed.footer() {
            println!("  Footer details:");
            if let Some(kid) = footer.kid() {
                println!("    Key ID: {}", kid);
            }
            if let Some(version) = footer.version() {
                println!("    Version: {}", version);
            }
            println!("    Custom fields: {}", footer.custom.len());
        }

        // Show first few characters of token for reference
        let preview = if token.len() > 80 {
            format!("{}...", &token[..80])
        } else {
            token.clone()
        };
        println!("  Preview: {}", preview);
    }

    Ok(())
}

fn simulate_middleware_routing(
    tokens: &HashMap<String, String>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Simulating API gateway routing decisions...\n");

    for (name, token) in tokens {
        let parsed = ParsedToken::parse(token)?;

        // Simulate routing logic
        let (handler, auth_type) = match parsed.purpose() {
            "pq" => ("signature_verification_service", "asymmetric"),
            "local" => ("symmetric_decryption_service", "symmetric"),
            _ => ("error_handler", "unknown"),
        };

        println!("Token: {} → Route to: {}", name, handler);
        println!("  Auth type: {}", auth_type);
        println!("  Token size: {} bytes", parsed.total_length());

        // Size-based routing decisions
        if parsed.total_length() > 2048 {
            println!("  ⚠️  Large token detected - route to high-memory handler");
        }

        // Footer-based routing
        if let Some(footer) = parsed.footer() {
            println!("  Metadata available:");
            if let Some(kid) = footer.kid() {
                println!("    Key rotation: Use key '{}'", kid);
            }
            if let Some(env) = footer.get_custom("environment") {
                println!("    Environment: {}", env.as_str().unwrap_or("unknown"));
            }
            if let Some(trace_id) = footer.get_custom("trace_id") {
                println!("    Trace context: {}", trace_id.as_str().unwrap_or("none"));
            }
        }
        println!();
    }

    Ok(())
}

fn simulate_monitoring_and_metrics(
    tokens: &HashMap<String, String>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Collecting token metrics...\n");

    let mut stats = TokenStats::new();

    for (name, token) in tokens {
        let parsed = ParsedToken::parse(token)?;
        stats.record_token(&parsed);

        println!("📈 Token: {}", name);
        println!("  Purpose: {}", parsed.purpose());
        println!("  Size: {} bytes", parsed.total_length());

        // Simulate alerts
        if parsed.total_length() > 1500 {
            println!("  🚨 ALERT: Large token size detected");
        }

        if !parsed.has_footer() {
            println!("  ℹ️  INFO: No metadata footer present");
        }
    }

    println!("\n📊 Aggregate Statistics:");
    stats.print_summary();

    Ok(())
}

fn demonstrate_debugging_scenarios() -> Result<(), Box<dyn std::error::Error>> {
    println!("Common debugging scenarios...\n");

    // Scenario 1: Mystery token from logs
    let mystery_token = "paseto.v1.local.xyz789"; // Truncated from logs
    println!("🔍 Scenario 1: Truncated token from logs");
    match ParsedToken::parse(mystery_token) {
        Ok(parsed) => {
            println!("  ✅ Successfully parsed truncated token");
            println!("  Purpose: {}", parsed.purpose());
        }
        Err(e) => {
            println!("  ❌ Parse error: {}", e);
            println!("  💡 Likely cause: Truncated in log collection");
        }
    }

    // Scenario 2: Token with unexpected format version
    let future_token = "paseto.v2.pq.ABC123.DEF456";
    println!("\n🔍 Scenario 2: Future version token");
    match ParsedToken::parse(future_token) {
        Ok(parsed) => {
            println!("  ✅ Parsed: {}", parsed.version());
        }
        Err(e) => {
            println!("  ❌ Parse error: {}", e);
            println!("  💡 Need to update parser for new version");
        }
    }

    // Scenario 3: Token purpose inspection
    let tokens_to_inspect = vec!["paseto.v1.public.ABC123.DEF456", "paseto.v1.local.XYZ789"];

    println!("\n🔍 Scenario 3: Quick purpose identification");
    for token in tokens_to_inspect {
        match ParsedToken::parse(token) {
            Ok(parsed) => {
                let preview = if token.len() > 25 {
                    &token[..25]
                } else {
                    token
                };
                println!(
                    "  Token: {} → Purpose: {} ({})",
                    preview,
                    parsed.purpose(),
                    if parsed.is_public() {
                        "verify signature"
                    } else {
                        "decrypt"
                    }
                );
            }
            Err(e) => {
                let preview = if token.len() > 25 {
                    &token[..25]
                } else {
                    token
                };
                println!("  Token: {} → Error: {}", preview, e);
            }
        }
    }

    Ok(())
}

fn demonstrate_error_handling() -> Result<(), Box<dyn std::error::Error>> {
    println!("Error handling examples...\n");

    let bad_tokens = vec![
        ("empty", ""),
        ("wrong_protocol", "jwt.v1.public.payload"),
        ("missing_parts", "paseto.v1.public"),
        ("bad_base64", "paseto.v1.public.invalid!!!"),
        ("unknown_purpose", "paseto.v1.unknown.payload"),
        ("too_many_parts", "paseto.v1.public.a.b.c.d.e.f.g"),
    ];

    for (name, token) in bad_tokens {
        println!("❌ Testing: {}", name);
        match ParsedToken::parse(token) {
            Ok(_) => println!("  Unexpected success"),
            Err(e) => {
                println!("  Error: {}", e);
                // In real middleware, you'd return appropriate HTTP status
                match e.to_string() {
                    s if s.contains("expected at least 4 parts") => {
                        println!("  → HTTP 400: Malformed token");
                    }
                    s if s.contains("Invalid protocol") => {
                        println!("  → HTTP 400: Wrong token type");
                    }
                    s if s.contains("Unsupported token format") => {
                        println!("  → HTTP 501: Version not supported");
                    }
                    _ => {
                        println!("  → HTTP 400: Invalid token format");
                    }
                }
            }
        }
        println!();
    }

    Ok(())
}

fn performance_comparison(
    tokens: &HashMap<String, String>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Performance comparison: Parsing vs Cryptographic operations\n");

    for (name, token) in tokens.iter().take(2) {
        let start = std::time::Instant::now();

        // Fast parsing (no crypto)
        for _ in 0..1000 {
            let _ = ParsedToken::parse(token)?;
        }
        let parse_time = start.elapsed();

        println!("Token: {}", name);
        println!(
            "  Parse 1000x: {:?} ({:.2}μs/parse)",
            parse_time,
            parse_time.as_micros() as f64 / 1000.0
        );
        println!("  💡 Use parsing for: routing, logging, monitoring");
        println!("  💡 Use crypto verification only when needed\n");
    }

    Ok(())
}

struct TokenStats {
    total_count: usize,
    public_count: usize,
    local_count: usize,
    with_footer_count: usize,
    total_size: usize,
    max_size: usize,
    min_size: usize,
}

impl TokenStats {
    fn new() -> Self {
        Self {
            total_count: 0,
            public_count: 0,
            local_count: 0,
            with_footer_count: 0,
            total_size: 0,
            max_size: 0,
            min_size: usize::MAX,
        }
    }

    fn record_token(&mut self, parsed: &ParsedToken) {
        self.total_count += 1;

        if parsed.is_public() {
            self.public_count += 1;
        } else {
            self.local_count += 1;
        }

        if parsed.has_footer() {
            self.with_footer_count += 1;
        }

        let size = parsed.total_length();
        self.total_size += size;
        self.max_size = self.max_size.max(size);
        self.min_size = self.min_size.min(size);
    }

    fn print_summary(&self) {
        println!("  Total tokens: {}", self.total_count);
        println!(
            "  Public tokens: {} ({:.1}%)",
            self.public_count,
            self.public_count as f64 / self.total_count as f64 * 100.0
        );
        println!(
            "  Local tokens: {} ({:.1}%)",
            self.local_count,
            self.local_count as f64 / self.total_count as f64 * 100.0
        );
        println!(
            "  With footer: {} ({:.1}%)",
            self.with_footer_count,
            self.with_footer_count as f64 / self.total_count as f64 * 100.0
        );
        println!(
            "  Average size: {:.1} bytes",
            self.total_size as f64 / self.total_count as f64
        );
        println!("  Size range: {} - {} bytes", self.min_size, self.max_size);
    }
}
