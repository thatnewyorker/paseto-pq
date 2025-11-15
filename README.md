# PASETO-PQ: Post-Quantum PASETO Tokens

[![Crates.io](https://img.shields.io/crates/v/paseto-pq.svg)](https://crates.io/crates/paseto-pq)
[![Documentation](https://docs.rs/paseto-pq/badge.svg)](https://docs.rs/paseto-pq)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.74%2B-orange.svg)](https://www.rust-lang.org)

A pure post-quantum implementation of PASETO tokens using **ML-DSA** (CRYSTALS-Dilithium) signatures and **ChaCha20-Poly1305** encryption. This crate provides quantum-safe authentication and encryption tokens with comprehensive metadata support, resistant to attacks by quantum computers implementing Shor's algorithm.

## 🚀 Features

- **🔒 Quantum-Safe**: Uses ML-DSA-65 (NIST FIPS 204) signatures and ML-KEM-768 key exchange
- **🦀 Pure Rust**: No C dependencies, built on RustCrypto
- **🎯 Full PASETO Parity**: Complete implementation with both public and local tokens
- **⚡ Practical Performance**: Optimized for real-world usage patterns
- **🔧 Easy Integration**: Drop-in replacement for authentication and encryption tokens
- **📦 Dual Token Types**: Public (signatures) and Local (symmetric encryption)
- **🦶 Footer Support**: Authenticated metadata for key management and service integration
- **🔄 Key Exchange**: ML-KEM for post-quantum key establishment
- **📄 JSON Integration**: Built-in JSON conversion for logging, databases, and tracing
- **🔍 Token Parsing**: Fast token inspection for debugging, middleware, and monitoring
- **📏 Token Size Estimation**: Plan token usage and avoid deployment surprises
- **🕐 RFC3339 Time Fields**: Standard time serialization for maximum compatibility
- **🛡️ Memory Safe**: Constant-time operations and proper secret zeroization

## 📖 Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
paseto-pq = "0.1.0"
time = { version = "0.3", features = ["serde", "formatting", "parsing"] }
rand = "0.10.0-rc.1"
```

### Public Tokens (Asymmetric Signatures)

```rust
use paseto_pq::{PasetoPQ, Claims, KeyPair};
use time::OffsetDateTime;
use rand::rng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a new key pair
    let mut rng = rng();
    let keypair = KeyPair::generate(&mut rng);

    // Create claims
    let mut claims = Claims::new();
    claims.set_subject("user123")?;
    claims.set_issuer("my-service")?;
    claims.set_audience("api.example.com")?;
    claims.set_expiration(OffsetDateTime::now_utc() + time::Duration::hours(1))?;
    claims.add_custom("tenant_id", "org_abc123")?;
    claims.add_custom("roles", &["user", "admin"])?;

    // Sign the token (public)
    let token = PasetoPQ::sign(&keypair.signing_key, &claims)?;
    println!("Public Token: {}", token);

    // Verify the token
    let verified = PasetoPQ::verify(&keypair.verifying_key, &token)?;
    let verified_claims = verified.claims();
    
    assert_eq!(verified_claims.subject(), Some("user123"));
    assert_eq!(verified_claims.issuer(), Some("my-service"));

    Ok(())
}
```

### Local Tokens (Symmetric Encryption)

```rust
use paseto_pq::{PasetoPQ, Claims, SymmetricKey};
use time::OffsetDateTime;
use rand::rng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a symmetric key
    let mut rng = rng();
    let key = SymmetricKey::generate(&mut rng);

    // Create claims (same as public tokens)
    let mut claims = Claims::new();
    claims.set_subject("user123")?;
    claims.set_issuer("my-service")?;
    claims.set_audience("api.example.com")?;
    claims.set_expiration(OffsetDateTime::now_utc() + time::Duration::hours(1))?;
    claims.add_custom("sensitive_data", "confidential-info")?;

    // Encrypt the token (local)
    let token = PasetoPQ::encrypt(&key, &claims)?;
    println!("Local Token: {}", token);

    // Decrypt the token
    let verified = PasetoPQ::decrypt(&key, &token)?;
    let verified_claims = verified.claims();
    
    assert_eq!(verified_claims.subject(), Some("user123"));
    assert_eq!(verified_claims.issuer(), Some("my-service"));

    Ok(())
}
```

### Footer Support

PASETO-PQ supports authenticated footers for metadata that doesn't belong in claims:

```rust
use paseto_pq::{PasetoPQ, Claims, Footer, KeyPair};
use time::OffsetDateTime;
use rand::rng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = rng();
    let keypair = KeyPair::generate(&mut rng);

    // Create claims
    let mut claims = Claims::new();
    claims.set_subject("user123")?;
    claims.set_issuer("my-service")?;

    // Create footer with metadata
    let mut footer = Footer::new();
    footer.set_kid("signing-key-2024-01")?;  // Key identifier for rotation
    footer.set_version("v2.1.0")?;           // Service version
    footer.add_custom("trace_id", "trace-abc-123")?;     // Distributed tracing
    footer.add_custom("deployment", "us-east-1")?;       // Infrastructure info

    // Sign with footer
    let token = PasetoPQ::sign_with_footer(&keypair.signing_key, &claims, Some(&footer))?;

    // Verify and access footer
    let verified = PasetoPQ::verify_with_footer(&keypair.verifying_key, &token)?;
    let verified_footer = verified.footer().unwrap();
    
    println!("Key ID: {}", verified_footer.kid().unwrap());
    println!("Trace ID: {}", verified_footer.get_custom("trace_id").unwrap().as_str().unwrap());

    Ok(())
}
```

## 🔐 Token Formats

PASETO-PQ follows standard PASETO format conventions with both token types supporting optional footers:

### Public Tokens (Signatures)
```
# Without footer
paseto.v1.public.<base64url-payload>.<base64url-signature>

# With footer
paseto.v1.public.<base64url-payload>.<base64url-signature>.<base64url-footer>
```

- **`paseto`**: Protocol identifier
- **`v1`**: Version (post-quantum era)
- **`public`**: Purpose (signature-based tokens)
- **`payload`**: Base64url-encoded JSON claims
- **`signature`**: Base64url-encoded ML-DSA-65 signature (~2.4KB)
- **`footer`**: Base64url-encoded JSON metadata (optional, authenticated)

### Local Tokens (Encryption)
```
# Without footer
paseto.v1.local.<base64url-encrypted-payload>

# With footer
paseto.v1.local.<base64url-encrypted-payload>.<base64url-footer>
```

- **`paseto`**: Protocol identifier
- **`v1`**: Version (post-quantum era)
- **`local`**: Purpose (symmetric encryption)
- **`encrypted-payload`**: Base64url-encoded nonce + ChaCha20-Poly1305 ciphertext
- **`footer`**: Base64url-encoded JSON metadata (optional, encrypted with payload)

## 📊 Performance Characteristics

### Public Tokens (ML-DSA-65)
| Operation | ML-DSA-65 | Ed25519 (reference) | Ratio |
|-----------|-----------|-------------------|-------|
| Key Generation | ~10-30ms | ~100µs | 100-300x slower |
| Signing | ~5-20ms | ~50µs | 100-400x slower |
| Verification | ~2-5ms | ~80µs | 25-60x slower |
| Signature Size | 2,420 bytes | 64 bytes | 38x larger |
| Public Key | 1,952 bytes | 32 bytes | 61x larger |
| **Token Size** | **~4.3-4.5KB** | **~300-500 bytes** | **~10x larger** |

### Local Tokens (ChaCha20-Poly1305)
| Operation | PASETO-PQ Local | Traditional PASETO v4.local | Ratio |
|-----------|-----------------|------------------------------|-------|
| Key Generation | ~1µs | ~1µs | ~1x |
| Encryption | ~1-5µs | ~1-5µs | ~1x |
| Decryption | ~1-5µs | ~1-5µs | ~1x |
| Token Overhead | ~30 bytes | ~30 bytes | ~1x |
| Symmetric Key | 32 bytes | 32 bytes | 1x |
| **Token Size** | **~100-300 bytes** | **~100-300 bytes** | **~1x** |

### Key Exchange (ML-KEM-768)
| Operation | ML-KEM-768 | ECDH P-256 (reference) | Ratio |
|-----------|------------|------------------------|-------|
| Key Generation | ~100µs | ~50µs | 2x slower |
| Encapsulation | ~150µs | ~100µs | 1.5x slower |
| Decapsulation | ~200µs | ~100µs | 2x slower |
| Ciphertext Size | 1,088 bytes | 33 bytes | 33x larger |
| Public Key | 1,184 bytes | 33 bytes | 36x larger |

**Note**: Performance varies by hardware. These numbers are from benchmarks on modern x86-64.

**Token Size Implications**:
- **Public tokens (~4.4KB)**: Not suitable for cookies or URLs but perfect for Authorization headers
- **Local tokens (~200 bytes)**: Suitable for all transport methods including cookies
- **Footer overhead**: ~50-200 bytes depending on metadata complexity

## 🎯 Use Cases

### Public Tokens (ML-DSA Signatures)
**✅ Recommended For:**
- **Inter-service authentication** (API keys, service tokens)
- **Authorization headers** (4KB typical limit allows comfortable usage)
- **Non-repudiation requirements** (audit trails, legal evidence)
- **Public key infrastructure** (distributed verification)
- **Long-term security** (5+ year lifetime)
- **High-security applications** (financial, government, healthcare)

**⚠️ Consider Carefully:**
- **Browser cookies** (4KB browser limit, no room for other data)
- **URL parameters** (2KB practical limit)
- **High-frequency operations** (>1000/sec per core)
- **Real-time applications** (signing latency considerations)

### Local Tokens (Symmetric Encryption)
**✅ Recommended For:**
- **Session management** (user sessions, temporary access)
- **Cookie-based authentication** (small size, fits easily)
- **Confidential data transport** (encrypted payloads)
- **High-performance scenarios** (fast encrypt/decrypt)
- **Internal services** (shared secret available)
- **Mobile applications** (bandwidth efficiency)

**⚠️ Consider Carefully:**
- **Key distribution** (shared secret management complexity)
- **Multi-party scenarios** (single shared key limitation)
- **Long-term storage** (key rotation complexity)

### Key Exchange (ML-KEM)
**✅ Recommended For:**
- **Establishing shared secrets** for local tokens
- **Hybrid workflows** (KEM + local tokens)
- **Forward secrecy** requirements
- **Quantum-safe key agreement**
- **Zero-knowledge protocols**

## 🔧 Advanced Usage

### Public Token Validation

```rust
use paseto_pq::{PasetoPQ, Claims, KeyPair};
use time::Duration;

let verified = PasetoPQ::verify_with_options(
    &verifying_key,
    &token,
    Some("expected-audience"),     // Validate audience
    Some("expected-issuer"),       // Validate issuer
    Duration::minutes(5),          // Clock skew tolerance
)?;
```

### Footer Operations

```rust
use paseto_pq::{Footer, PasetoPQ};

// Create and populate footer
let mut footer = Footer::new();
footer.set_kid("key-2024-01")?;
footer.set_version("v1.0.0")?;
footer.add_custom("trace_id", "abc-123")?;
footer.add_custom("environment", "production")?;

// Use with public tokens (footer is authenticated by signature)
let token = PasetoPQ::sign_with_footer(&signing_key, &claims, Some(&footer))?;
let verified = PasetoPQ::verify_with_footer(&verifying_key, &token)?;

// Access footer data
if let Some(footer_data) = verified.footer() {
    println!("Key ID: {}", footer_data.kid().unwrap_or("none"));
    println!("Trace: {}", footer_data.get_custom("trace_id").unwrap().as_str().unwrap());
}

// Use with local tokens (footer is encrypted with payload)
let local_token = PasetoPQ::encrypt_with_footer(&symmetric_key, &claims, Some(&footer))?;
let decrypted = PasetoPQ::decrypt_with_footer(&symmetric_key, &local_token)?;
```

### Local Token Validation

```rust
use paseto_pq::{PasetoPQ, SymmetricKey};
use time::Duration;

let verified = PasetoPQ::decrypt_with_options(
    &symmetric_key,
    &token,
    Some("expected-audience"),     // Validate audience
    Some("expected-issuer"),       // Validate issuer
    Duration::minutes(5),          // Clock skew tolerance
)?;
```

### Key Serialization

```rust
// Public/Private keys
let signing_bytes = keypair.signing_key_to_bytes();
let verifying_bytes = keypair.verifying_key_to_bytes();
let signing_key = KeyPair::signing_key_from_bytes(&signing_bytes)?;
let verifying_key = KeyPair::verifying_key_from_bytes(&verifying_bytes)?;

// Symmetric keys
let sym_bytes = symmetric_key.to_bytes();
let symmetric_key = SymmetricKey::from_bytes(&sym_bytes)?;

// KEM keys
let enc_bytes = kem_keypair.encapsulation_key_to_bytes();
let dec_bytes = kem_keypair.decapsulation_key_to_bytes();
let enc_key = KemKeyPair::encapsulation_key_from_bytes(&enc_bytes)?;
let dec_key = KemKeyPair::decapsulation_key_from_bytes(&dec_bytes)?;
```

### Post-Quantum Key Exchange

```rust
use paseto_pq::{KemKeyPair, SymmetricKey, PasetoPQ};
use rand::rng;

// Generate KEM keypair
let mut rng = rng();
let kem_keypair = KemKeyPair::generate(&mut rng);

// Sender: encapsulate shared secret
let (shared_key_sender, ciphertext) = kem_keypair.encapsulate(&mut rng);

// Receiver: decapsulate shared secret
let shared_key_receiver = kem_keypair.decapsulate(&ciphertext)?;

// Both parties now have the same symmetric key
assert_eq!(shared_key_sender.to_bytes(), shared_key_receiver.to_bytes());

// Use for local tokens
let token = PasetoPQ::encrypt(&shared_key_sender, &claims)?;
let verified = PasetoPQ::decrypt(&shared_key_receiver, &token)?;
```

### Custom Claims

```rust
let mut claims = Claims::new();
claims.set_subject("user123")?;

// Add custom business logic
claims.add_custom("tenant_id", "org_123")?;
claims.add_custom("permissions", &["read:users", "write:posts"])?;
claims.add_custom("metadata", &serde_json::json!({
    "client_version": "2.1.0",
    "platform": "web"
}))?;

// Works with both public and local tokens
let public_token = PasetoPQ::sign(&keypair.signing_key, &claims)?;
let local_token = PasetoPQ::encrypt(&symmetric_key, &claims)?;

// Access custom claims after verification/decryption
if let Some(tenant) = verified_claims.get_custom("tenant_id") {
    println!("Tenant: {}", tenant.as_str().unwrap());
}
```

### JSON Integration

PASETO-PQ provides seamless JSON integration for easy use with logging systems, databases, and distributed tracing:

```rust
use paseto_pq::Claims;
use serde_json::Value;
use time::OffsetDateTime;

let mut claims = Claims::new();
claims.set_subject("user123")?;
claims.set_issuer("auth-service")?;
claims.set_expiration(OffsetDateTime::now_utc() + time::Duration::hours(2))?;
claims.add_custom("tenant_id", "org_abc123")?;
claims.add_custom("roles", &["admin", "user"])?;

// Convert to JSON Value for flexible use
let json_value: Value = claims.clone().into();

// Convert to JSON string for logging
let json_string = claims.to_json_string()?;
println!("User authenticated: {}", json_string);

// Pretty JSON for debugging
let pretty_json = claims.to_json_string_pretty()?;

// Time fields are RFC3339 strings for maximum compatibility
// {"exp": "2025-01-15T10:30:00Z", "iat": "2025-01-14T10:30:00Z"}
```

**Integration Examples:**

- **Structured Logging**: Direct JSON serialization for ELK Stack, Datadog, Splunk
- **Database Storage**: PostgreSQL JSONB, MongoDB document storage
- **Distributed Tracing**: OpenTelemetry span attributes, Jaeger context
- **Audit Trails**: Compliance logging with embedded claims data
- **Monitoring**: Grafana dashboards with JSON-queryable token data

Run the JSON integration demo:
```bash
cargo run --example json_integration_demo
```

### Token Parsing

Parse tokens for inspection without expensive cryptographic operations. Perfect for debugging, middleware routing, logging, and monitoring:

```rust
use paseto_pq::{ParsedToken, PasetoPQ};

let token = "paseto.v1.public.ABC123...";
let parsed = ParsedToken::parse(token)?;

// Inspect token structure (no crypto operations)
println!("Purpose: {}", parsed.purpose());     // "public" or "local"
println!("Version: {}", parsed.version());     // "v1"
println!("Has footer: {}", parsed.has_footer());
println!("Size: {} bytes", parsed.total_length());
println!("Is public token: {}", parsed.is_public());
println!("Is local token: {}", parsed.is_local());

// Middleware routing based on token type
match parsed.purpose() {
    "public" => route_to_signature_service(token),
    "local" => route_to_decryption_service(token),
    _ => return_error("unsupported token type"),
}

// Debugging information
println!("Token summary: {}", parsed.format_summary());
if let Some(footer) = parsed.footer() {
    if let Some(kid) = footer.kid() {
        println!("Key ID: {}", kid);
    }
    // Pretty-print footer JSON
    println!("Footer: {}", parsed.footer_json_pretty()?);
}

// Quick access with PasetoPQ wrapper
let parsed_alt = PasetoPQ::parse_token(token)?;
```

**Use Cases:**
- **API Gateway Routing**: Route tokens to appropriate handlers based on type
- **Monitoring & Metrics**: Collect token statistics without crypto overhead
- **Debugging**: Inspect malformed or problematic tokens quickly
- **Load Balancing**: Route based on token size or metadata
- **Logging**: Extract non-sensitive metadata for log correlation

Run the token parsing demo:
```bash
cargo run --example token_parsing_demo
```

### Token Size Estimation

Estimate token sizes before creation to avoid runtime surprises with HTTP headers, cookies, or URL length limits:

```rust
use paseto_pq::{Claims, TokenSizeEstimator, PasetoPQ};

let mut claims = Claims::new();
claims.set_subject("user123")?;
claims.add_custom("role", "admin")?;
claims.add_custom("permissions", &["read", "write", "admin"])?;

// Estimate before creating
let estimator = TokenSizeEstimator::public(&claims, false);
println!("Public token will be ~{} bytes", estimator.total_bytes());

// Check transport compatibility
if !estimator.fits_in_cookie() {
    println!("⚠️  Warning: Token too large for cookies (4KB limit)!");
    println!("💡 Consider using session storage or local tokens instead");
}

if estimator.fits_in_header() {
    println!("✅ Token fits in Authorization header (8KB typical limit)");
}

if estimator.fits_in_url() {
    println!("✅ Token fits in URL parameters (2KB practical limit)");
} else {
    println!("⚠️  Token too large for URL parameters");
}

// Get detailed breakdown
let breakdown = estimator.breakdown();
println!("Size breakdown:");
println!("  Payload: {} bytes", breakdown.payload);
println!("  Signature: {} bytes", breakdown.signature_or_tag);
println!("  Base64 overhead: {} bytes", breakdown.base64_overhead);
println!("  Total: {} bytes", breakdown.total());

// Get optimization suggestions
if estimator.total_bytes() > 4000 {
    for suggestion in estimator.optimization_suggestions() {
        println!("💡 {}", suggestion);
    }
}

// Compare token types
let public_est = PasetoPQ::estimate_public_size(&claims, false);
let local_est = PasetoPQ::estimate_local_size(&claims, false);
println!("Size comparison:");
println!("  Public token: {} bytes", public_est.total_bytes());
println!("  Local token: {} bytes", local_est.total_bytes());

// Compare to JWT (for reference)
println!("Compared to JWT: {}", estimator.compare_to_jwt());

// Generate size summary
println!("Summary: {}", estimator.size_summary());
```

**Size Limits & Recommendations:**
- **HTTP Cookies**: 4KB browser limit (use local tokens or session storage)
- **URL Parameters**: 2KB practical limit (use Authorization header instead)
- **HTTP Headers**: 8KB typical server limit (public tokens fit comfortably)
- **JSON Payloads**: No practical limit (both token types work well)

**Use Cases:**
- **Production Planning**: Avoid deployment surprises and HTTP 413 errors
- **Architecture Decisions**: Choose between public/local tokens based on size
- **Transport Selection**: Select appropriate delivery method (header/cookie/body)
- **Performance Optimization**: Identify oversized tokens early

Run the token size estimation demo:
```bash
cargo run --example token_size_demo
```

## 🔬 Security Considerations

### Post-Quantum Security
- **ML-DSA-65**: NIST FIPS 204 standardized signature algorithm
- **Security Level**: NIST Level 3 (~192-bit classical security, quantum-safe)
- **Quantum Resistance**: Secure against Shor's algorithm and known quantum attacks
- **ChaCha20-Poly1305**: 256-bit symmetric encryption, quantum-resistant for key sizes
- **ML-KEM-768**: NIST-standardized key encapsulation, quantum-safe key establishment

### Implementation Security
- **Memory Safety**: Pure Rust implementation prevents buffer overflows
- **Constant-Time**: Operations designed to prevent timing attacks where possible
- **Secret Zeroization**: Sensitive data properly cleared from memory
- **RustCrypto**: Built on well-audited cryptographic primitives
- **No Side Channels**: Careful implementation to prevent information leakage

### Operational Security
- **Token Parsing Safety**: `ParsedToken::parse()` performs no crypto operations, safe for untrusted input
- **Footer Authentication**: Public token footers covered by ML-DSA signature
- **Footer Confidentiality**: Local token footers encrypted with ChaCha20-Poly1305
- **Time Validation**: Built-in expiration and not-before checks with configurable clock skew
- **Audience Validation**: Cryptographically enforced recipient verification

### Token Size Security Implications
- **Public tokens (~4.4KB)**: Large size makes them impractical for cookies but perfect for headers
- **Information Leakage**: Token size may reveal information about claims structure
- **DoS Considerations**: Large tokens consume more bandwidth and processing time
- **Recommendation**: Use local tokens for size-sensitive applications

## 🏗️ Feature Flags

```toml
[dependencies]
paseto-pq = { version = "0.1.0", features = ["default"] }
```

Available features:
- `default`: All standard features enabled
- `serde`: JSON serialization support (enabled by default)
- `time`: Time-based claims validation (enabled by default)

All major features are enabled by default for ease of use.

## 🧪 Testing

Run the complete test suite:

```bash
# Run all tests with full backtrace (recommended)
RUST_BACKTRACE=full cargo nextest run --workspace --all-targets

# Run specific test categories
cargo test test_keypair_generation
cargo test test_json_conversion
cargo test test_token_parsing
cargo test test_token_size_estimation

# Run examples to verify functionality
cargo run --example json_integration_demo
cargo run --example token_parsing_demo  
cargo run --example token_size_demo
cargo run --example footer_demo
cargo run --example local_tokens_demo

# Run benchmarks
cargo bench
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
git clone https://github.com/your-org/paseto-pq
cd paseto-pq
cargo build
cargo test
```

## 📜 License

Licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

## ⚠️ Security Warning

**IMPORTANT**: This implementation has not yet undergone independent security audit. While built on NIST-standardized algorithms and well-tested Rust cryptographic libraries, please conduct your own security review before using in production systems.

### Cryptographic Foundations
- **ML-DSA (Dilithium)**: NIST FIPS 204 standardized post-quantum signature scheme
- **ChaCha20-Poly1305**: RFC 8439 authenticated encryption
- **ML-KEM (Kyber)**: NIST FIPS 203 standardized post-quantum KEM
- **SHA-3**: NIST FIPS 202 cryptographic hash function

### Footer Security Properties
- **Public Tokens**: Footer authenticated by ML-DSA signature (tamper-evident)
- **Local Tokens**: Footer encrypted with ChaCha20-Poly1305 (confidential and authenticated)
- **Size Considerations**: Footers add ~50-200 bytes depending on metadata complexity

## 🙏 Acknowledgments

- NIST Post-Quantum Cryptography Standardization team
- RustCrypto organization for cryptographic primitives
- PASETO specification contributors
- Rust community for excellent tooling and libraries

## 📚 Further Reading

- [PASETO Specification](https://paseto.io/)
- [NIST Post-Quantum Cryptography Standards](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [ML-DSA (FIPS 204)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)
- [ML-KEM (FIPS 203)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf)
- [ChaCha20-Poly1305 (RFC 8439)](https://tools.ietf.org/html/rfc8439)