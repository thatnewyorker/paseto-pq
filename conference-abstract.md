# PASETO-PQ Conference Presentation Abstract

## Title Options

### Option 1 (Technical Focus)
**PASETO-PQ: Post-Quantum Security Tokens Using ML-DSA and ML-KEM**

### Option 2 (Problem-Solution Focus)
**Preparing Authentication Tokens for the Quantum Era: The PASETO-PQ Protocol**

### Option 3 (Implementation Focus)
**Real-World Post-Quantum Token Security: Design and Implementation of PASETO-PQ**

---

## Abstract (Real World Crypto / Applied Crypto Venues)

**Title:** PASETO-PQ: Post-Quantum Security Tokens Using ML-DSA and ML-KEM

**Authors:** Gerard Junior Cruzado (Fusion Software)

**Abstract:**

The advent of cryptographically relevant quantum computers poses a significant threat to current authentication token systems that rely on classical public-key cryptography. This presentation introduces PASETO-PQ, a post-quantum variant of the PASETO (Platform-Agnostic SEcurity TOkens) protocol designed to provide quantum-resistant authentication and encryption for web applications and distributed systems.

PASETO-PQ addresses the quantum threat through careful integration of NIST-standardized post-quantum algorithms: ML-DSA-65 (FIPS 204) for digital signatures, ML-KEM-768 (FIPS 203) for key encapsulation, and ChaCha20-Poly1305 for symmetric encryption. The protocol maintains PASETO's security model while introducing enhancements including HKDF-based key derivation, mandatory memory zeroization, and built-in key exchange capabilities.

Key technical contributions include:
- A non-conflicting versioning scheme (pq1) that enables coexistence with classical PASETO during migration periods
- Enhanced security model with proper key derivation functions and memory safety guarantees  
- Complete specification with test vectors and security analysis
- Production-ready reference implementation in Rust with comprehensive performance benchmarks

Our implementation demonstrates practical feasibility with ML-DSA-65 signature generation in ~0.8ms and verification in ~0.4ms, while token sizes remain manageable for web deployment scenarios. The protocol has been designed for real-world constraints including HTTP cookie size limits and mobile application performance requirements.

This work provides organizations with a concrete path for transitioning authentication infrastructure to post-quantum security, addressing the "harvest now, decrypt later" threat model while maintaining compatibility with existing web security practices. We present the complete protocol specification, implementation experience, performance analysis, and discuss deployment considerations for production environments.

**Keywords:** Post-quantum cryptography, authentication tokens, ML-DSA, ML-KEM, web security

---

## Abstract (Academic Venues - CRYPTO/ASIACRYPT)

**Title:** PASETO-PQ: A Post-Quantum Authentication Token Protocol with Formal Security Analysis

**Authors:** Gerard Junior Cruzado (Fusion Software)

**Abstract:**

We present PASETO-PQ, a post-quantum secure authentication token protocol based on module lattice problems. Building upon the PASETO framework, our protocol provides quantum-resistant alternatives for both public-key authentication and symmetric encryption modes while maintaining provable security guarantees.

The protocol employs ML-DSA-65 for unforgeable digital signatures and ML-KEM-768 for IND-CCA2 secure key encapsulation, both recently standardized by NIST (FIPS 204/203). Our design includes several cryptographic enhancements: HKDF-based key derivation for domain separation, deterministic nonce generation to prevent signature faults, and a structured Pre-Authentication Encoding (PAE) function that prevents length extension attacks.

We provide a formal security analysis demonstrating that PASETO-PQ achieves:
- Existential unforgeability under chosen message attacks (EUF-CMA) for public tokens under the M-SIS assumption
- IND-CCA2 security for local tokens under the M-LWE assumption  
- Forward secrecy when combined with ML-KEM key exchange
- Resistance to quantum adversaries with up to 2^128 classical equivalent strength

Our concrete implementation achieves competitive performance with configurable signature sizes (2,420-4,627 bytes depending on ML-DSA parameter set) and key exchange ciphertexts of 1,088 bytes. We present detailed performance measurements, analyze the protocol's resistance to side-channel attacks, and discuss the security implications of the post-quantum transition for authentication systems.

The work includes complete specification, security proofs, implementation details, and comprehensive test vectors to facilitate analysis and adoption by the cryptographic community.

**Keywords:** Post-quantum cryptography, lattice-based signatures, authentication protocols, provable security

---

## Abstract (Industry Venues - RSA/Black Hat)

**Title:** Building Quantum-Safe Authentication: Practical Deployment of PASETO-PQ Tokens

**Authors:** Gerard Junior Cruzado (Fusion Software)

**Abstract:**

As quantum computing advances threaten current cryptographic infrastructure, organizations face the urgent challenge of migrating authentication systems to quantum-safe alternatives. This presentation demonstrates a practical solution: PASETO-PQ, a production-ready implementation of post-quantum authentication tokens.

PASETO-PQ addresses real-world deployment challenges that organizations will face during the post-quantum transition:

**Migration Strategy:**
- Non-conflicting versioning allows gradual migration alongside existing systems
- Clear distinction between classical and post-quantum tokens prevents accidental usage
- Backward-compatible infrastructure supports hybrid deployments

**Performance Considerations:**
- Optimized implementation achieves sub-millisecond signature operations
- Token sizes remain practical for HTTP headers and cookies
- Memory-safe design prevents key material leakage

**Security Benefits:**
- Resistance to both classical and quantum attacks
- Built-in protection against "harvest now, decrypt later" threats
- Enhanced key management with proper derivation functions

**Real-World Integration:**
- Drop-in replacement for existing token-based authentication
- Compatible with standard web security practices
- Comprehensive logging and monitoring capabilities

We demonstrate live deployment scenarios including:
- API authentication for microservices architectures
- Session management for web applications  
- Mobile app authentication with performance constraints
- Key rotation strategies for large-scale deployments

Attendees will learn practical steps for implementing post-quantum authentication in their organizations, including migration timelines, performance optimization techniques, and security assessment frameworks. We provide ready-to-use implementation code, deployment guides, and security checklists.

This session equips security professionals with concrete tools and knowledge needed to prepare their authentication infrastructure for the quantum era.

**Keywords:** Quantum-safe migration, authentication systems, deployment strategies, web security

---

## Speaker Bio

**Gerard Junior Cruzado** is a security engineer at Fusion Software specializing in cryptographic protocol design and implementation. His work focuses on practical post-quantum cryptography deployment, with expertise in lattice-based algorithms and secure software development. Gerard has contributed to several open-source cryptographic libraries and has presented research on post-quantum security at industry conferences. He holds expertise in Rust systems programming, cryptographic engineering, and security protocol analysis.

---

## Presentation Outline (45-minute talk)

### Introduction (5 minutes)
- Quantum threat timeline and impact on authentication
- Current token systems vulnerability analysis
- Need for proactive migration strategies

### PASETO-PQ Protocol Design (15 minutes)
- Core cryptographic building blocks (ML-DSA, ML-KEM, ChaCha20-Poly1305)
- Token format and versioning strategy
- Security model and threat analysis
- Key differences from classical PASETO

### Implementation and Performance (15 minutes)
- Reference implementation architecture
- Performance benchmarks and optimization techniques
- Memory safety and side-channel considerations
- Real-world deployment constraints

### Security Analysis (5 minutes)
- Formal security guarantees
- Post-quantum security assumptions
- Comparison with classical alternatives

### Deployment and Migration (5 minutes)
- Integration strategies for existing systems
- Migration timeline recommendations
- Operational considerations and best practices

### Q&A and Discussion (5 minutes)

---

## Submission Deadlines

### 2026 Conference Deadlines:
- **Real World Crypto 2026:** Submissions typically due October 2025
- **RSA Conference 2026:** Call for papers usually opens August 2025
- **CRYPTO 2026:** Submission deadline typically February 2026
- **Black Hat USA 2026:** CFP usually opens January 2026

### Submission Strategy:
1. **Target Real World Crypto first** (March 2026) - best fit for applied crypto
2. **RSA Conference backup** (May 2026) - industry audience
3. **Academic venues** (CRYPTO/ASIACRYPT) if formal proofs developed
4. **Industry practitioner events** for deployment-focused content

---

## Supporting Materials Needed

### For Submission:
- [ ] Complete RFC specification
- [ ] Reference implementation with benchmarks
- [ ] Security analysis document
- [ ] Performance comparison data
- [ ] Demo environment for live presentation

### For Presentation:
- [ ] Slide deck with clear visuals
- [ ] Live demo environment
- [ ] Code examples and integration guides
- [ ] Q&A preparation covering common concerns
- [ ] Handout with key implementation details