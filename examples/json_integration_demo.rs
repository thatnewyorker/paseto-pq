//! JSON Integration Demo for PASETO-PQ
//!
//! This example demonstrates how to use the JSON conversion features of PASETO-PQ
//! for easy integration with logging systems, databases, and distributed tracing.
//!
//! Run with: cargo run --example json_integration_demo

use paseto_pq::{Claims, KeyPair, PasetoPQ, SymmetricKey};
use serde_json::Value;
use std::collections::HashMap;
use time::OffsetDateTime;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 PASETO-PQ JSON Integration Demo\n");

    // Generate keys
    let mut rng = rand::rng();
    let keypair = KeyPair::generate(&mut rng);
    let symmetric_key = SymmetricKey::generate(&mut rng);

    // Create rich claims with various data types
    let mut claims = Claims::new();
    claims.set_subject("user_12345")?;
    claims.set_issuer("auth-service")?;
    claims.set_audience("api.conflux.dev")?;
    claims.set_expiration(OffsetDateTime::now_utc() + time::Duration::hours(2))?;
    claims.set_not_before(OffsetDateTime::now_utc() - time::Duration::minutes(5))?;
    claims.set_issued_at(OffsetDateTime::now_utc())?;
    claims.set_jti("token_abc123def456")?;

    // Add custom claims for business logic
    claims.add_custom("user_type", "premium")?;
    claims.add_custom("tenant_id", "org_conflux_001")?;
    claims.add_custom("roles", &["user", "admin", "api_access"])?;
    claims.add_custom("session_id", "sess_xyz789")?;
    claims.add_custom("feature_flags", &["new_ui", "beta_features"])?;
    claims.add_custom("quota_limit", 10000)?;
    claims.add_custom("last_login", "2025-01-13T22:44:26Z")?;

    println!("📋 Created claims with standard and custom fields");

    // Demonstrate JSON conversion methods
    println!("\n🔄 JSON Conversion Methods:");
    println!("{}", "=".repeat(50));

    // Method 1: Direct conversion using From trait
    let json_value: Value = claims.clone().into();
    println!("1. Direct conversion (From trait):");
    println!("   Type: serde_json::Value");
    println!("   Subject: {}", json_value["sub"]);
    println!("   Roles: {}", json_value["roles"]);

    // Method 2: to_json_value() convenience method
    let json_value_method = claims.to_json_value();
    println!("\n2. Convenience method (to_json_value):");
    println!(
        "   Same as direct conversion: {}",
        json_value == json_value_method
    );

    // Method 3: to_json_string() for compact JSON
    let json_string = claims.to_json_string()?;
    println!("\n3. Compact JSON string (to_json_string):");
    println!("   Length: {} chars", json_string.len());
    println!(
        "   Sample: {}...",
        &json_string[..100.min(json_string.len())]
    );

    // Method 4: to_json_string_pretty() for readable JSON
    let pretty_json = claims.to_json_string_pretty()?;
    println!("\n4. Pretty JSON string (to_json_string_pretty):");
    println!("   Length: {} chars", pretty_json.len());
    println!("   Preview:");
    println!("{}", pretty_json);

    // Demonstrate integration scenarios
    println!("\n🔗 Integration Scenarios:");
    println!("{}", "=".repeat(50));

    // Scenario 1: Structured Logging
    println!("\n📊 1. Structured Logging Integration:");
    simulate_structured_logging(&claims);

    // Scenario 2: Database Storage
    println!("\n💾 2. Database Integration:");
    simulate_database_integration(&claims)?;

    // Scenario 3: Distributed Tracing
    println!("\n🔍 3. Distributed Tracing Integration:");
    simulate_distributed_tracing(&claims);

    // Scenario 4: Audit Trail
    println!("\n📝 4. Audit Trail Integration:");
    simulate_audit_trail(&claims)?;

    // Demonstrate with actual tokens
    println!("\n🎫 Token Integration:");
    println!("{}", "=".repeat(50));

    // Create and verify public token
    let public_token = PasetoPQ::sign(keypair.signing_key(), &claims)?;
    let verified_public = PasetoPQ::verify(keypair.verifying_key(), &public_token)?;

    println!("\n🔓 Public Token Claims (after verification):");
    let verified_json = verified_public.claims().to_json_string_pretty()?;
    println!("{}", verified_json);

    // Create and decrypt local token
    let local_token = PasetoPQ::encrypt(&symmetric_key, &claims)?;
    let verified_local = PasetoPQ::decrypt(&symmetric_key, &local_token)?;

    println!("\n🔒 Local Token Claims (after decryption):");
    let local_json: Value = verified_local.claims().into();
    println!("Tenant ID: {}", local_json["tenant_id"]);
    println!("Feature Flags: {}", local_json["feature_flags"]);

    // Demonstrate time field formats
    println!("\n⏰ Time Field Formats:");
    println!("   Expiration: {}", json_value["exp"]);
    println!("   Not Before: {}", json_value["nbf"]);
    println!("   Issued At: {}", json_value["iat"]);
    println!("   Format: RFC3339 (ISO 8601) strings for maximum compatibility");

    println!("\n✅ JSON integration demo completed successfully!");
    Ok(())
}

fn simulate_structured_logging(claims: &Claims) {
    // Simulate structured logging with JSON
    let log_data = claims.to_json_value();

    println!("   [INFO] User authentication successful");
    println!(
        "   Fields: user_id={}, tenant={}, roles={}",
        log_data["sub"], log_data["tenant_id"], log_data["roles"]
    );

    // Simulate log aggregation system
    println!("   → Log entry ready for ELK Stack, Datadog, or similar");
    println!("   → JSON structure enables rich querying and dashboards");
}

fn simulate_database_integration(claims: &Claims) -> Result<(), Box<dyn std::error::Error>> {
    // Simulate database insertion
    let json_value = claims.to_json_value();
    let serialized = serde_json::to_vec(&json_value)?;

    println!("   INSERT INTO user_sessions (claims_json) VALUES ($1)");
    println!("   Data size: {} bytes", serialized.len());
    println!("   → Compatible with PostgreSQL JSONB, MongoDB, CouchDB");
    println!("   → Enables JSON queries: WHERE claims_json->>'tenant_id' = 'org_conflux_001'");

    // Simulate database query result processing
    let query_result = json_value.clone();
    println!("   Query result processing:");
    if let Some(roles) = query_result["roles"].as_array() {
        println!("   → User has {} roles: {:?}", roles.len(), roles);
    }

    Ok(())
}

fn simulate_distributed_tracing(claims: &Claims) {
    // Simulate adding claims to trace context
    let trace_attributes = claims.to_json_value();

    println!("   Trace ID: trace_abc123");
    println!("   Span: user_authentication");
    println!("   Attributes added from claims:");
    println!("   → user.id: {}", trace_attributes["sub"]);
    println!("   → user.tenant: {}", trace_attributes["tenant_id"]);
    println!("   → session.id: {}", trace_attributes["session_id"]);
    println!("   → Compatible with OpenTelemetry, Jaeger, Zipkin");
}

fn simulate_audit_trail(claims: &Claims) -> Result<(), Box<dyn std::error::Error>> {
    // Simulate audit trail creation
    let mut audit_entry = HashMap::new();
    audit_entry.insert(
        "timestamp",
        serde_json::json!(OffsetDateTime::now_utc().to_string()),
    );
    audit_entry.insert("event_type", serde_json::json!("token_issued"));
    audit_entry.insert("claims", claims.to_json_value());
    audit_entry.insert("source_ip", serde_json::json!("192.168.1.100"));
    audit_entry.insert("user_agent", serde_json::json!("Mozilla/5.0..."));

    let audit_json = serde_json::to_string_pretty(&audit_entry)?;
    println!("   Audit Entry:");
    println!("{}", audit_json);
    println!("   → Comprehensive audit trail with embedded claims");
    println!("   → Supports compliance requirements (SOX, GDPR, etc.)");

    Ok(())
}
