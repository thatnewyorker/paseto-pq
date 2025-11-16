# Changelog

All notable changes to the `paseto-pq` crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive contributing guide (CONTRIBUTING.md)
- Test script for all feature combinations
- Enhanced CI configuration with feature matrix testing

### Changed
- Updated development dependencies (criterion 0.5 → 0.7, proptest 1.4 → 1.9)
- Fixed clippy warnings across all examples and benchmarks
- Improved token size estimation test for different ML-DSA parameter sets

### Fixed
- CI configuration now properly handles mutually exclusive ML-DSA features
- Benchmark code updated to use `std::hint::black_box` instead of deprecated `criterion::black_box`

## [0.1.0] - 2025-11-16

### Added
- Initial release of PASETO-PQ (Post-Quantum PASETO tokens)
- Support for ML-DSA (CRYSTALS-Dilithium) signatures in three parameter sets:
  - `ml-dsa-44`: 128-bit security (~2.4KB signatures)
  - `ml-dsa-65`: 192-bit security (~3.3KB signatures) 
  - `ml-dsa-87`: 256-bit security (~4.6KB signatures)
- Public tokens with ML-DSA signatures for authentication
- Local tokens with ChaCha20-Poly1305 for encryption
- ML-KEM-768 key exchange for secure key establishment
- Comprehensive footer support for metadata
- Token size estimation utilities
- JSON integration with serde
- Extensive examples and benchmarks
- Security-focused design with zeroization of sensitive data

### Security
- Post-quantum cryptographic algorithms resistant to quantum computer attacks
- Constant-time implementations where applicable
- Memory safety with automatic cleanup of cryptographic material
- Comprehensive input validation and error handling

### Performance
- Optimized default configuration (ml-dsa-44) for network performance
- Benchmarking suite for performance analysis
- Multiple parameter sets for security/performance trade-offs
- Efficient base64url encoding for compact token representation

### Documentation
- Comprehensive README with usage examples
- API documentation with rustdoc
- Performance characteristics and use case guidance
- Security considerations and best practices