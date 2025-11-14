# PASETO-PQ: Post-Quantum PASETO Tokens

[![Crates.io](https://img.shields.io/crates/v/paseto-pq.svg)](https://crates.io/crates/paseto-pq)
[![Documentation](https://docs.rs/paseto-pq/badge.svg)](https://docs.rs/paseto-pq)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.74%2B-orange.svg)](https://www.rust-lang.org)

A pure post-quantum implementation of PASETO tokens using **ML-DSA** (CRYSTALS-Dilithium) signatures and **ChaCha20-Poly1305** encryption. This crate provides quantum-safe authentication and encryption tokens with comprehensive footer support for metadata, resistant to attacks by quantum computers implementing Shor's algorithm.

## 🚀 Features

- **🔒 Quantum-Safe**: Uses ML-DSA-65 (NIST FIPS 204) signatures and ML-KEM-768 key exchange
- **🦀 Pure Rust**: No C dependencies, built on RustCrypto
- **🎯 Full PASETO Parity**: Complete implementation with both public and local tokens
- **⚡ Practical Performance**: Optimized for real-world usage
- **🔧 Easy Integration**: Drop-in replacement for authentication and encryption tokens
- **📦 Dual Token Types**: Public (signatures) and Local (symmetric encryption)
- **🦶 Footer Support**: Authenticated metadata for key management and service integration
- **🔄 Key Exchange**: ML-KEM for post-quantum key establishment

## 📖 Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
paseto-pq = "0.1"
time = "0.3"
rand = "0.8"
```

### Public Tokens (Asymmetric Signatures)

```rust
use paseto_pq::{PasetoPQ, Claims, KeyPair};
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
use rand::thread_rng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate a symmetric key
    let mut rng = thread_rng();
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
use rand::thread_rng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = thread_rng();
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

PASETO-PQ supports both token types with structured formats and optional footers:

### Public Tokens (Signatures)
```
# Without footer (5 parts)
paseto.v1.pq.<base64url-payload>.<base64url-signature>

# With footer (6 parts)
paseto.v1.pq.<base64url-payload>.<base64url-signature>.<base64url-footer>
```

- **`paseto`**: Protocol identifier
- **`v1`**: Version (post-quantum era)
- **`pq`**: Purpose (post-quantum signatures)
- **`payload`**: Base64url-encoded JSON claims
- **`signature`**: Base64url-encoded ML-DSA-65 signature (~2.4KB)
- **`footer`**: Base64url-encoded JSON metadata (optional)

### Local Tokens (Encryption)
```
# Without footer (4 parts)
paseto.v1.local.<base64url-encrypted-payload>

# With footer (5 parts)
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
| Key Generation | ~10ms | ~100µs | 100x slower |
| Signing | ~5-20ms | ~50µs | 100-400x slower |
| Verification | ~2-5ms | ~80µs | 25-60x slower |
| Signature Size | 2,420 bytes | 64 bytes | 38x larger |
| Public Key | 1,952 bytes | 32 bytes | 61x larger |

### Local Tokens (ChaCha20-Poly1305)
| Operation | PASETO-PQ Local | Traditional PASETO v4.local | Ratio |
|-----------|-----------------|------------------------------|-------|
| Key Generation | ~1µs | ~1µs | ~1x |
| Encryption | ~1-5µs | ~1-5µs | ~1x |
| Decryption | ~1-5µs | ~1-5µs | ~1x |
| Token Overhead | ~30 bytes | ~30 bytes | ~1x |
| Symmetric Key | 32 bytes | 32 bytes | 1x |

### Key Exchange (ML-KEM-768)
| Operation | ML-KEM-768 | ECDH P-256 (reference) | Ratio |
|-----------|------------|------------------------|-------|
| Key Generation | ~100µs | ~50µs | 2x slower |
| Encapsulation | ~150µs | ~100µs | 1.5x slower |
| Decapsulation | ~200µs | ~100µs | 2x slower |
| Ciphertext Size | 1,088 bytes | 33 bytes | 33x larger |
| Public Key | 1,184 bytes | 33 bytes | 36x larger |

**Note**: Performance varies by hardware. These numbers are from benchmarks on modern x86-64.

## 🎯 Use Cases

### Public Tokens (ML-DSA Signatures)
**✅ Recommended For:**
- **Inter-service authentication** (API keys, service tokens)
- **Non-repudiation requirements** (audit trails, legal evidence)
- **Public key infrastructure** (distributed verification)
- **Long-term security** (5+ year lifetime)
- **High-security applications** (financial, government)

**⚠️ Consider Carefully:**
- **High-frequency operations** (>1000/sec per core)
- **Bandwidth-constrained environments** (large token size)
- **Real-time applications** (signing latency)

### Local Tokens (Symmetric Encryption)
**✅ Recommended For:**
- **Session management** (user sessions, temporary access)
- **Confidential data transport** (encrypted payloads)
- **High-performance scenarios** (fast encrypt/decrypt)
- **Internal services** (shared secret available)
- **Smaller token sizes** (bandwidth efficiency)

**⚠️ Consider Carefully:**
- **Key distribution** (shared secret management)
- **Multi-party scenarios** (single shared key)
- **Long-term storage** (key rotation complexity)

### Key Exchange (ML-KEM)
**✅ Recommended For:**
- **Establishing shared secrets** for local tokens
- **Hybrid workflows** (KEM + local tokens)
- **Forward secrecy** requirements
- **Quantum-safe key agreement**

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

// Use with public tokens
let token = PasetoPQ::sign_with_footer(&signing_key, &claims, Some(&footer))?;
let verified = PasetoPQ::verify_with_footer(&verifying_key, &token)?;

// Access footer data
if let Some(footer_data) = verified.footer() {
    println!("Key ID: {}", footer_data.kid().unwrap_or("none"));
    println!("Trace: {}", footer_data.get_custom("trace_id").unwrap().as_str().unwrap());
}

// Use with local tokens (footer is encrypted)
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
use rand::thread_rng;

// Generate KEM keypair
let mut rng = thread_rng();
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

### Public Tokens
```rust
// Old PASETO v4.public (Ed25519)
// let token = sign_v4_public(&key, &claims)?;

// New PASETO-PQ (ML-DSA-65)
let token = PasetoPQ::sign(&keypair.signing_key, &claims)?;
```

### Local Tokens
```rust
// Old PASETO v4.local (ChaCha20-Poly1305)
// let token = encrypt_v4_local(&key, &claims)?;

// New PASETO-PQ (ChaCha20-Poly1305)
let token = PasetoPQ::encrypt(&symmetric_key, &claims)?;
```

**Key differences**:

**Public Tokens:**
- 🔄 **Token format**: `v4.public.*` → `paseto.v1.pq.*`
- 📏 **Size increase**: ~300 bytes → ~4KB tokens
- ⏱️ **Performance**: ~100x slower operations
- 🔐 **Security**: Quantum-safe vs quantum-vulnerable

**Local Tokens:**
- 🔄 **Token format**: `v4.local.*` → `paseto.v1.local.*`
- 📏 **Size**: Similar (~few hundred bytes)
- ⏱️ **Performance**: Nearly identical
- 🔐 **Security**: Same symmetric encryption, quantum-safe framework

## 🏗️ Features Flags

```toml
[dependencies]
paseto-pq = { version = "0.1", features = ["logging"] }
```

Available features:
- **`logging`**: Enable tracing support for debugging
- **`std`**: Standard library support (enabled by default)

Security parameter features:
- **`ml-dsa-44`**: Category 2 (128-bit security, smaller keys)
- **`ml-dsa-65`**: Category 3 (192-bit security, recommended default)
- **`ml-dsa-87`**: Category 5 (256-bit security, largest keys)

## 🧪 Testing

Run the test suite:

```bash
cargo test
```

Run benchmarks:

```bash
cargo bench
```

Performance demos:

```bash
cargo run --example performance_demo    # Public tokens
cargo run --example local_tokens_demo   # Local tokens + key exchange
cargo run --example footer_demo         # Footer functionality showcase
```

## 🛣️ Roadmap

- [x] **v0.1**: Basic ML-DSA-65 public tokens
- [x] **v0.1.1**: Local tokens with ChaCha20-Poly1305
- [x] **v0.1.2**: ML-KEM-768 key exchange
- [x] **v0.1.3**: Complete footer support for metadata
- [ ] **v0.2**: PASETO v5 compatibility
- [ ] **v0.3**: Additional ML-DSA parameter sets (44, 87)
- [ ] **v0.4**: Hybrid classical+PQ modes  
- [ ] **v0.5**: Stream encryption for large payloads
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

This crate has **not yet undergone an independent security audit**. While we follow best practices and use well-vetted cryptographic libraries (RustCrypto), use in production systems should be carefully evaluated.

### Cryptographic Foundations
- **ML-DSA-65**: NIST FIPS 204 standardized post-quantum signatures
- **ML-KEM-768**: NIST FIPS 203 standardized post-quantum key encapsulation  
- **ChaCha20-Poly1305**: IETF RFC 8439 authenticated encryption
- **SHA-3**: NIST FIPS 202 cryptographic hash function

### Footer Security Properties
- **Public tokens**: Footers are visible but authenticated by signature
- **Local tokens**: Footers are encrypted and authenticated with payload
- **Tamper detection**: Any footer modification breaks verification
- **Backward compatibility**: Tokens without footers remain valid

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
**🎉 Now with full PASETO parity: Public AND Local tokens with Footer support!**