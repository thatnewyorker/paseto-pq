# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **BREAKING**: Full PASETO parity with both public and local token support
- Local tokens using ChaCha20-Poly1305 symmetric encryption (`paseto.v1.local.*`)
- **Footer support** for authenticated metadata in both token types
- ML-KEM-768 key exchange support (mock implementation for demonstration)
- SymmetricKey type for local token encryption/decryption
- KemKeyPair type for post-quantum key exchange
- Footer type for key identifiers, versions, and custom metadata
- Enhanced API with encrypt/decrypt methods alongside sign/verify
- sign_with_footer/encrypt_with_footer methods for metadata inclusion
- verify_with_footer/decrypt_with_footer methods for metadata extraction
- Comprehensive test suite covering both token types and footer functionality
- New local_tokens_demo example demonstrating full functionality
- New footer_demo example showcasing metadata capabilities
- Updated documentation with complete PASETO feature coverage including footers

### Changed
- **BREAKING**: Renamed `PqPaseto` struct to `PasetoPQ` for better naming consistency
- Enhanced README with full local token and footer documentation
- Performance comparisons now include both public and local tokens with/without footers
- Token format documentation covers all variants: `paseto.v1.pq.*`, `paseto.v1.local.*` with optional footers
- VerifiedToken now includes optional footer data access
- Backward compatibility maintained for tokens without footers

### Security
- Post-quantum cryptographic signatures resistant to Shor's algorithm
- ChaCha20-Poly1305 authenticated encryption for local tokens
- **Footer authentication**: Public token footers covered by ML-DSA signature
- **Footer confidentiality**: Local token footers encrypted with ChaCha20-Poly1305
- SHA-3 based key derivation for symmetric keys
- Tamper detection for footer modifications
- Memory-safe Rust implementation
- Constant-time operations where possible
- Proper zeroization of sensitive data

### Migration Guide
- **Breaking Change**: `PqPaseto` has been renamed to `PasetoPQ`
- **Migration**: Replace all instances of `PqPaseto::` with `PasetoPQ::` in your code
- **Example**: `PqPaseto::sign()` becomes `PasetoPQ::sign()`
- **Rationale**: Follows Rust naming conventions for acronyms (PascalCase)
- **Impact**: Import statements and method calls need updating, but all functionality remains identical

## [0.1.0] - 2024-12-19

### Added
- Initial release of PASETO-PQ
- ML-DSA-65 (CRYSTALS-Dilithium) signature support
- Token format: `paseto.v1.pq.<payload>.<signature>`
- Pure Rust implementation using RustCrypto libraries
- Compatible with PASETO design principles
- Full test coverage and benchmarking suite
- MIT/Apache-2.0 dual licensing

### Performance
- Key generation: ~10-30ms
- Token signing: ~5-20ms  
- Token verification: ~2-5ms
- Signature size: ~2.4KB (vs 64 bytes for Ed25519)
- Public key size: ~2KB (vs 32 bytes for Ed25519)
- Token size: ~4-5KB (vs ~300-500 bytes for Ed25519 PASETO)

### Security Notes
- **WARNING**: This implementation has not yet undergone independent security audit
- Uses NIST FIPS 204 standardized ML-DSA algorithm
- Provides NIST Security Level 3 (~192-bit classical security)
- Quantum-safe against known quantum algorithms including Shor's algorithm