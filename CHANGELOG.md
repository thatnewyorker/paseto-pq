# Changelog

All notable changes to the `paseto-pq` crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2] - 2025-01-03

### 🔧 Fixed

- **LINTING**: Fixed clippy warnings for better code quality
  - Replaced `len() > 0` with `!is_empty()` for clearer intent
  - Replaced `vec![a, b, c]` with `[a, b, c]` for fixed-size arrays
  - All clippy checks now pass with `-D warnings` across all feature combinations
- **CONSISTENCY**: Updated all example names from "alice" to "elise" following naming conventions

### 🧪 Testing

- **VALIDATION**: Confirmed all 67 unit tests + 15 doc tests pass
- **EXAMPLES**: Verified all examples work correctly with updated naming
- **FEATURES**: Tested clippy compliance across ml-dsa-44, ml-dsa-65, ml-dsa-87, and logging features

### 📚 Documentation

- **EXAMPLES**: Updated all demo code to use "elise@example.com" consistently
- **QUALITY**: Improved code clarity following Rust best practices

---

## [0.1.1] - 2025-01-03

### 🔒 Security

- **CRITICAL**: Implemented proper footer authentication per PASETO RFC Section 2.2.1
- **FIXED**: Footers are now cryptographically authenticated using Pre-Authentication Encoding (PAE)
- **FIXED**: Public tokens now sign `PAE([header, payload_bytes, footer_bytes])` instead of just `header.payload`
- **FIXED**: Local tokens now use `PAE([header, nonce_bytes, footer_bytes])` as AEAD Additional Authenticated Data
- **SECURITY**: Footer tampering is now properly detected and rejected for both public and local tokens

### ✨ Added

- **NEW**: `pae` module with RFC-compliant Pre-Authentication Encoding implementation
- **NEW**: `le64_encode()` function for little-endian 64-bit integer encoding
- **NEW**: `pae_encode()` function implementing PASETO RFC Section 2.2.1 specification
- **NEW**: `pae_encode_public_token()` convenience function for public token PAE creation
- **NEW**: `pae_encode_local_token()` convenience function for local token PAE creation
- **NEW**: Comprehensive test suite for PAE functionality including all RFC test vectors
- **NEW**: Security tests demonstrating footer authentication and tamper detection

### 🔧 Changed

- **BREAKING**: Footer authentication behavior - tokens with tampered footers now fail verification/decryption
- **IMPROVED**: Enhanced error messages for footer authentication failures
- **IMPROVED**: Better logging for PAE operations and footer authentication (when `logging` feature enabled)

### 📚 Documentation

- **UPDATED**: API documentation to reflect v0.1.1 security improvements
- **ADDED**: Comprehensive PAE module documentation with examples
- **ADDED**: Security-focused examples demonstrating footer authentication
- **UPDATED**: README to highlight v0.1.1 security enhancements

### 🧪 Testing

- **ADDED**: 22 new test cases for PAE functionality
- **ADDED**: 3 comprehensive security tests for v0.1.1 footer authentication
- **ADDED**: Edge case testing for PAE collision resistance and memory efficiency
- **IMPROVED**: All existing tests updated to work with new footer authentication behavior

### 🛠️ Technical Details

- **PAE Implementation**: Follows PASETO RFC Section 2.2.1 exactly with proper length prefixing
- **Memory Efficiency**: PAE implementation pre-calculates buffer sizes for optimal allocation
- **Crypto Integration**: Seamless integration between PAE and ML-DSA/ChaCha20-Poly1305 operations
- **Error Handling**: Proper error propagation for all footer authentication failure scenarios

### 🔄 Migration Notes

- **For Existing Users**: Upgrade immediately for security compliance
- **Breaking Change**: Tokens with tampered footers will now fail (this is the intended security improvement)
- **No API Changes**: All existing public APIs remain unchanged

### 🎯 Version Context

- **Previous**: v0.1.0 had incomplete footer authentication (security vulnerability)
- **Current**: v0.1.1 implements proper PAE-based footer authentication (security fix)
- **Impact**: Users should upgrade immediately for RFC compliance and security

---

## [0.1.0] - 2024-12-XX (Previous Release)

### Initial Release

- Initial implementation of post-quantum PASETO tokens using ML-DSA
- Support for public and local token types
- Footer support (with incomplete authentication - fixed in v0.1.1)
- Comprehensive token parsing and validation
- Size estimation utilities
- KEM support with ML-KEM integration

**⚠️ Security Notice**: Version 0.1.0 had incomplete footer authentication. Please upgrade to v0.1.1 immediately.

---

## Security Policy

We take security seriously. If you discover a security vulnerability, please report it responsibly:

- **Email**: thatnewyorker@gmail.com
- **Subject**: [SECURITY] paseto-pq vulnerability report
- **Response Time**: We aim to respond within 24 hours

For the footer authentication issue fixed in v0.1.1:
- **Severity**: High (footer tampering not detected)
- **Impact**: Footer metadata could be modified without detection
- **Fixed**: v0.1.1 implements proper PAE-based authentication
- **Recommendation**: Upgrade immediately

[0.1.2]: https://github.com/thatnewyorker/paseto-pq/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/thatnewyorker/paseto-pq/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/thatnewyorker/paseto-pq/releases/tag/v0.1.0
