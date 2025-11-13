# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial implementation of PASETO-PQ tokens using ML-DSA-65 signatures
- Support for standard PASETO claims (iss, sub, aud, exp, nbf, iat, jti, kid)
- Custom claims support with JSON serialization
- Time-based token validation with configurable clock skew tolerance
- Audience and issuer validation
- Key serialization to/from bytes
- Comprehensive test suite
- Performance benchmarks
- Documentation and examples

### Security
- Post-quantum cryptographic signatures resistant to Shor's algorithm
- Memory-safe Rust implementation
- Constant-time operations where possible
- Proper zeroization of sensitive data

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