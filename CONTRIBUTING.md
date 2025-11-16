# Contributing to PASETO-PQ

Thank you for your interest in contributing to PASETO-PQ! This guide will help you get started with contributing to our post-quantum PASETO token implementation.

## 🚀 Quick Start

### Prerequisites

- **Rust**: 1.85.0 or later (Rust 2024 edition)
- **Git**: For version control
- Basic familiarity with post-quantum cryptography concepts (helpful but not required)

### Development Setup

1. **Fork and Clone**
   ```bash
   git clone https://github.com/your-username/paseto-pq.git
   cd paseto-pq
   ```

2. **Install Dependencies**
   ```bash
   # The crate will automatically download dependencies on first build
   cargo build
   ```

3. **Run Tests**
   ```bash
   # Test with default features (ml-dsa-44)
   cargo test
   
   # Test all parameter sets individually
   cargo test --no-default-features --features ml-dsa-44
   cargo test --no-default-features --features ml-dsa-65
   cargo test --no-default-features --features ml-dsa-87
   ```

4. **Check Code Quality**
   ```bash
   # Run clippy lints
   cargo clippy --all-targets -- -D warnings
   
   # Check formatting
   cargo fmt --check
   
   # Security audit
   cargo audit
   ```

## 🛠️ Development Guidelines

### Code Style

- **Formatting**: Use `cargo fmt` to format code
- **Linting**: All clippy warnings must be fixed (`cargo clippy -- -D warnings`)
- **Documentation**: All public APIs must have rustdoc comments with examples
- **Tests**: New functionality requires comprehensive tests

### Cryptographic Code Guidelines

⚠️ **Security-Critical Code**: This crate implements cryptographic primitives. Please follow these guidelines:

1. **No Custom Crypto**: Only use established cryptographic libraries (RustCrypto)
2. **Constant-Time**: Be aware of timing attack vectors
3. **Memory Safety**: Use `zeroize` for sensitive data cleanup
4. **Review Required**: All cryptographic changes require thorough review

### Feature Development

#### ML-DSA Parameter Sets

The crate supports three mutually exclusive ML-DSA parameter sets:

- `ml-dsa-44`: 128-bit security, smallest signatures (~2.4KB)
- `ml-dsa-65`: 192-bit security, medium signatures (~3.3KB)
- `ml-dsa-87`: 256-bit security, largest signatures (~4.6KB)

When adding features, ensure they work with all parameter sets:

```bash
# Test your changes with each parameter set
for feature in ml-dsa-44 ml-dsa-65 ml-dsa-87; do
    echo "Testing with $feature"
    cargo test --no-default-features --features $feature
done
```

#### Performance Considerations

- **Benchmarks**: Add benchmarks for performance-critical code
- **Memory Usage**: Be mindful of token size impacts
- **Backwards Compatibility**: Maintain API compatibility when possible

### Testing Requirements

#### Unit Tests
- **Coverage**: Aim for high test coverage of new functionality
- **Edge Cases**: Test error conditions and edge cases
- **Security**: Include tests for security-relevant properties

#### Integration Tests
- **Round-trip**: Ensure tokens can be created and verified
- **Cross-parameter**: Test interactions between different ML-DSA parameter sets
- **Serialization**: Verify proper encoding/decoding

#### Example Tests
```rust
#[test]
fn test_new_feature() {
    let keypair = KeyPair::generate(&mut rng());
    let claims = Claims::new();
    
    // Test the feature
    let result = your_new_feature(&claims);
    assert!(result.is_ok());
    
    // Test error cases
    let invalid_input = create_invalid_input();
    assert!(your_new_feature(&invalid_input).is_err());
}
```

### Documentation

#### Code Documentation
- **Public APIs**: Must have rustdoc with examples
- **Complex Logic**: Add inline comments explaining cryptographic operations
- **Safety**: Document any `unsafe` code thoroughly

#### README Updates
- **New Features**: Update feature descriptions
- **Examples**: Add examples for new functionality
- **Performance**: Update benchmarks if relevant

## 📝 Contribution Process

### 1. Issue Discussion

For significant changes:
1. **Open an issue** to discuss the proposed change
2. **Get feedback** from maintainers before implementing
3. **Security changes** require additional review

### 2. Implementation

1. **Create a branch** from `main`: `git checkout -b feature/your-feature-name`
2. **Implement your changes** following the guidelines above
3. **Write tests** for new functionality
4. **Update documentation** as needed

### 3. Testing

Before submitting, ensure all tests pass:

```bash
# Use the test script (if working in your environment)
../../scripts/test-paseto-pq-all-features.sh --fast

# Or run tests manually:

# Test each ML-DSA parameter set
cargo test --no-default-features --features ml-dsa-44
cargo test --no-default-features --features ml-dsa-65
cargo test --no-default-features --features ml-dsa-87

# Test convenience features
cargo test --no-default-features --features performance
cargo test --no-default-features --features balanced
cargo test --no-default-features --features maximum-security

# Default features
cargo test

# Code quality checks
cargo clippy --all-targets --no-default-features --features ml-dsa-44 -- -D warnings
cargo clippy --all-targets --no-default-features --features ml-dsa-65 -- -D warnings
cargo clippy --all-targets --no-default-features --features ml-dsa-87 -- -D warnings
cargo fmt --check

# Build examples to ensure they compile
cargo build --examples --no-default-features --features ml-dsa-44
cargo build --examples --no-default-features --features ml-dsa-65
cargo build --examples --no-default-features --features ml-dsa-87
```

### 4. Pull Request

1. **Create a PR** with a clear description
2. **Link related issues** in the PR description
3. **Add tests** demonstrating the change works
4. **Update CHANGELOG.md** if applicable

#### PR Template
```markdown
## Description
Brief description of changes

## Changes Made
- [ ] Feature A added
- [ ] Tests added for feature A
- [ ] Documentation updated

## Testing
- [ ] All ML-DSA parameter sets tested
- [ ] Clippy passes with -D warnings
- [ ] Formatting checked
- [ ] Benchmarks run (if performance-related)

## Security Considerations
- [ ] No custom cryptography added
- [ ] Sensitive data properly zeroized
- [ ] Timing attack considerations reviewed
```

## 🧪 Testing Features

### Running Examples

Test examples with different parameter sets:

```bash
# Performance comparison
cargo run --example performance_demo --no-default-features --features ml-dsa-44
cargo run --example performance_demo --no-default-features --features ml-dsa-65

# Parameter set comparison
cargo run --example parameter_set_comparison --no-default-features --features ml-dsa-44
```

### Benchmarks

Run performance benchmarks:

```bash
# Basic benchmarks
cargo bench --no-default-features --features ml-dsa-44

# All parameter sets (takes longer)
for feature in ml-dsa-44 ml-dsa-65 ml-dsa-87; do
    echo "Benchmarking $feature"
    cargo bench --no-default-features --features $feature --no-run
done
```

## 🔐 Security Guidelines

### Reporting Security Issues

**Please do not report security vulnerabilities through public GitHub issues.**

For security-related issues:
1. **Email**: Send details to [security contact if available]
2. **Responsible Disclosure**: Allow time for fixes before public disclosure
3. **Coordinated Disclosure**: Work with maintainers on timeline

### Security Review Process

1. **Cryptographic Changes**: Require review from cryptography experts
2. **API Changes**: Consider security implications of new APIs
3. **Dependencies**: Audit new cryptographic dependencies

## 📦 Release Process

### Versioning

This project follows [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking API changes
- **MINOR**: New features, backwards compatible
- **PATCH**: Bug fixes, backwards compatible

### Pre-release Checklist

- [ ] All tests pass on all ML-DSA parameter sets
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Security review completed (for crypto changes)
- [ ] Performance benchmarks reviewed

## 🤝 Community

### Communication

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and discussions
- **Code Reviews**: Constructive feedback on pull requests

### Code of Conduct

- **Be respectful**: Treat all contributors with respect
- **Be constructive**: Provide helpful feedback
- **Security first**: Prioritize security in all discussions

## 📚 Resources

### Cryptography Resources
- [ML-DSA (NIST FIPS 204)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)
- [PASETO RFC Draft](https://tools.ietf.org/html/draft-paragon-paseto-rfc-01)
- [RustCrypto Project](https://github.com/RustCrypto)

### Development Resources
- [Rust Book](https://doc.rust-lang.org/book/)
- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- [Cargo Book](https://doc.rust-lang.org/cargo/)

### Post-Quantum Cryptography
- [NIST PQC Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [CRYSTALS-Dilithium](https://pq-crystals.org/dilithium/)
- [CRYSTALS-KYBER](https://pq-crystals.org/kyber/)

## 🙏 Recognition

Contributors are recognized in:
- **CHANGELOG.md**: For significant contributions
- **README.md**: For major feature contributions
- **Git history**: All contributions are permanently recorded

Thank you for helping make PASETO-PQ more secure and robust! 🦀🔐