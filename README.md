# PASETO-PQ: Post-Quantum PASETO Tokens

[![Crates.io](https://img.shields.io/crates/v/paseto-pq.svg)](https://crates.io/crates/paseto-pq)
[![Documentation](https://docs.rs/paseto-pq/badge.svg)](https://docs.rs/paseto-pq)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.74%2B-orange.svg)](https://www.rust-lang.org)

A pure post-quantum implementation of PASETO-inspired tokens using **ML-DSA** (CRYSTALS-Dilithium) signatures. This crate provides quantum-safe authentication tokens that are resistant to attacks by quantum computers implementing Shor's algorithm.

## 🚀 Features

- **🔒 Quantum-Safe**: Uses ML-DSA-65 (NIST FIPS 204) signatures
- **🦀 Pure Rust**: No C dependencies, built on RustCrypto
- **🎯 PASETO-Inspired**: Familiar API for PASETO users
- **⚡ Practical Performance**: Optimized for real-world usage
- **🔧 Easy Integration**: Drop-in replacement for authentication tokens
- **📦 No-STD Support**: Works in embedded environments (optional)

## 📖 Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
paseto-pq = "0.1"
time = "0.3"
rand = "0.8"
```

### Basic Usage

```rust
use paseto_pq::{PqPaseto, Claims, KeyPair};
use time::OffsetDateTime;
use rand::thread_rng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a new key pair
    let mut rng = thread_rng();
    let keypair = KeyPair::generate(&mut rng);

    // Create claims
    let mut claims = Claims::new();
    claims.set_subject("user123")?;
    claims.set_issuer("my-service")?;
    claims.set_audience("api.example.com")?;
    claims.set_expiration(OffsetDateTime::now_utc() + time::Duration::hours(1))?;
    claims.add_custom("tenant_id", "org_abc123")?;
    claims.add_custom("roles", &["user", "admin"])?;

    // Sign the token
    let token = PqPaseto::sign(&keypair.signing_key, &claims)?;
    println!("Token: {}", token);

    // Verify the token
    let verified = PqPaseto::verify(&keypair.verifying_key, &token)?;
    let verified_claims = verified.claims();
    
    assert_eq!(verified_claims.subject(), Some("user123"));
    assert_eq!(verified_claims.issuer(), Some("my-service"));

    Ok(())
}
```

## 🔐 Token Format

PASETO-PQ uses a structured token format:

```
paseto.v1.pq.<base64url-payload>.<base64url-signature>
```

- **`paseto`**: Protocol identifier
- **`v1`**: Version (post-quantum era)
- **`pq`**: Purpose (post-quantum signatures)
- **`payload`**: Base64url-encoded JSON claims
- **`signature`**: Base64url-encoded ML-DSA-65 signature (~2.4KB)

## 📊 Performance Characteristics

| Operation | ML-DSA-65 | Ed25519 (reference) | Ratio |
|-----------|-----------|-------------------|-------|
| Key Generation | ~10ms | ~100µs | 100x slower |
| Signing | ~5-20ms | ~50µs | 100-400x slower |
| Verification | ~2-5ms | ~80µs | 25-60x slower |
| Signature Size | 2,420 bytes | 64 bytes | 38x larger |
| Public Key | 1,952 bytes | 32 bytes | 61x larger |

**Note**: Performance varies by hardware. These numbers are from benchmarks on modern x86-64.

## 🎯 Use Cases

### ✅ Recommended For:
- **Authentication tokens** (login, API access)
- **Authorization tokens** (permissions, roles)
- **Long-term security** (5+ year lifetime)
- **High-security applications** (financial, government)
- **Future-proofing** against quantum computers

### ⚠️ Consider Carefully:
- **High-frequency operations** (>1000/sec per core)
- **Bandwidth-constrained environments** (IoT, mobile)
- **Legacy system integration** (size limitations)

## 🔧 Advanced Usage

### Custom Validation

```rust
use paseto_pq::{PqPaseto, Claims, KeyPair};
use time::Duration;

let verified = PqPaseto::verify_with_options(
    &verifying_key,
    &token,
    Some("expected-audience"),     // Validate audience
    Some("expected-issuer"),       // Validate issuer
    Duration::minutes(5),          // Clock skew tolerance
)?;
```

### Key Serialization

```rust
// Export keys as bytes
let signing_bytes = keypair.signing_key_to_bytes();
let verifying_bytes = keypair.verifying_key_to_bytes();

// Import keys from bytes
let signing_key = KeyPair::signing_key_from_bytes(&signing_bytes)?;
let verifying_key = KeyPair::verifying_key_from_bytes(&verifying_bytes)?;
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

// Access custom claims after verification
if let Some(tenant) = verified_claims.get_custom("tenant_id") {
    println!("Tenant: {}", tenant.as_str().unwrap());
}
```

## 🔬 Security Considerations

### Post-Quantum Security
- **ML-DSA-65** provides **NIST Security Level 3** (~192-bit security)
- Resistant to both **classical** and **quantum** attacks
- Based on **lattice cryptography** (learning with errors)
- **Standardized** in NIST FIPS 204

### Implementation Security
- **Memory-safe** Rust implementation
- **Constant-time** operations where possible
- **Zeroization** of sensitive key material
- **Side-channel** resistance considerations

### Operational Security
- **Key rotation**: Generate new keys periodically
- **Token expiration**: Use short-lived tokens when possible
- **Audience validation**: Always validate expected audience
- **Secure storage**: Protect signing keys appropriately

## 🚦 Migration from PASETO v4

If you're migrating from traditional PASETO:

```rust
// Old PASETO v4.public (Ed25519)
// let token = sign_v4_public(&key, &claims)?;

// New PASETO-PQ (ML-DSA-65)
let token = PqPaseto::sign(&keypair.signing_key, &claims)?;
```

**Key differences**:
- 🔄 **Token format**: `v4.public.*` → `paseto.v1.pq.*`
- 📏 **Size increase**: ~300 bytes → ~4KB tokens
- ⏱️ **Performance**: ~100x slower operations
- 🔐 **Security**: Quantum-safe vs quantum-vulnerable

## 🏗️ Features Flags

```toml
[dependencies]
paseto-pq = { version = "0.1", features = ["logging"] }
```

Available features:
- **`logging`**: Enable tracing support for debugging
- **`std`**: Standard library support (enabled by default)

## 🧪 Testing

Run the test suite:

```bash
cargo test
```

Run benchmarks:

```bash
cargo bench
```

Performance demo:

```bash
cargo run --example performance_demo
```

## 🛣️ Roadmap

- [ ] **v0.2**: PASETO v5 compatibility
- [ ] **v0.3**: Additional ML-DSA parameter sets (44, 87)
- [ ] **v0.4**: Hybrid classical+PQ modes
- [ ] **v1.0**: Stable API, security audit

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
git clone https://github.com/rustcrypto/paseto-pq
cd paseto-pq
cargo test
cargo bench
```

## 📜 License

Licensed under either of:
- **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE-APACHE))
- **MIT License** ([LICENSE-MIT](LICENSE-MIT))

at your option.

## ⚠️ Security Warning

This crate has **not yet undergone an independent security audit**. While we follow best practices and use well-vetted cryptographic libraries, use in production systems should be carefully evaluated.

**USE AT YOUR OWN RISK**

## 🙏 Acknowledgments

- **PASETO** specification by [Scott Arciszewski](https://github.com/paragonie)
- **ML-DSA** implementation by [RustCrypto](https://github.com/RustCrypto)
- **CRYSTALS-Dilithium** by the original research team
- **NIST** for standardizing post-quantum cryptography

## 📚 Further Reading

- [PASETO Specification](https://paseto.io/)
- [NIST FIPS 204: ML-DSA Standard](https://csrc.nist.gov/pubs/fips/204/final)
- [Post-Quantum Cryptography FAQ](https://csrc.nist.gov/Projects/post-quantum-cryptography/faqs)
- [RustCrypto ML-DSA](https://docs.rs/ml-dsa/)

---

**Made with ❤️ for a quantum-safe future**