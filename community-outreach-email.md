# PASETO-PQ Community Outreach Email Template

## Subject Line Options

**Option 1 (Technical):** PASETO-PQ: Post-Quantum Security Tokens - RFC Draft for Community Review

**Option 2 (Direct):** Introducing PASETO-PQ: Quantum-Safe Alternative to Classical PASETO

**Option 3 (Problem-Focused):** Post-Quantum PASETO Implementation - Seeking Community Feedback

---

## Email Template

### To: Crypto Mailing Lists / Security Communities

**Subject:** PASETO-PQ: Post-Quantum Security Tokens - RFC Draft for Community Review

Hello cryptography community,

I'm writing to introduce **PASETO-PQ**, a post-quantum variant of PASETO (Platform-Agnostic SEcurity TOkens) and to seek feedback from the community before formal standardization efforts.

## 🎯 **What is PASETO-PQ?**

PASETO-PQ addresses the quantum threat to current token systems by using post-quantum cryptographic algorithms while maintaining PASETO's security model and design philosophy.

**Key Features:**
- **ML-DSA-65** signatures for public tokens (NIST FIPS 204)
- **ChaCha20-Poly1305** for local token encryption
- **ML-KEM-768** for key exchange (NIST FIPS 203)
- **Non-standard versioning** (`pq1`) to avoid confusion with classical PASETO
- **Enhanced security** with HKDF key derivation and memory zeroization

## 🔧 **Implementation Status**

- ✅ **Working Rust implementation** available
- ✅ **Complete RFC specification** drafted
- ✅ **Test vectors** and examples provided
- ✅ **Performance benchmarks** conducted
- ✅ **Memory safety** and zeroization implemented

## ⚠️ **Important Clarifications**

**PASETO-PQ is intentionally NOT compatible with standard PASETO:**
- Uses `paseto.pq1.local` and `paseto.pq1.public` token format
- Different cryptographic algorithms (post-quantum vs classical)
- Explicit versioning prevents accidental cross-usage
- Not attempting to "replace" or "hijack" original PASETO

## 🎯 **Why Now?**

1. **Quantum Threat Timeline**: Conservative estimates put cryptographically relevant quantum computers within 10-30 years
2. **Long-lived Tokens**: Some authentication tokens may outlive the classical crypto transition
3. **Harvest Now, Decrypt Later**: Adversaries may be collecting tokens for future decryption
4. **Ecosystem Preparation**: Early adoption enables testing and deployment experience

## 📋 **Seeking Community Input On**

1. **Cryptographic Choices**: Are ML-DSA-65 + ML-KEM-768 + ChaCha20-Poly1305 appropriate selections?
2. **Security Model**: Does the enhanced key derivation (HKDF) and memory safety approach sound?
3. **Versioning Strategy**: Is `pq1` clear enough to distinguish from classical PASETO?
4. **Use Cases**: What applications would benefit from post-quantum PASETO tokens?
5. **Implementation Concerns**: Any practical deployment considerations we should address?

## 📖 **Documents Available**

- **RFC Specification**: Complete technical specification (both .md and IETF .txt formats)
- **Reference Implementation**: Rust crate with full functionality
- **Security Analysis**: Post-quantum security assumptions and considerations
- **Performance Data**: Benchmarks comparing to classical alternatives

## 🤝 **Next Steps**

Based on community feedback, I plan to:
1. **Iterate** on the specification based on input
2. **Submit** as IETF Internet Draft (Informational)
3. **Present** at relevant conferences (Real World Crypto, etc.)
4. **Coordinate** with IETF working groups (LAMPS, CFRG)

## 📬 **How to Provide Feedback**

I'm particularly interested in:
- Technical review of cryptographic choices
- Security analysis of the protocol design
- Implementation experience if anyone tries the code
- Suggestions for use cases and deployment scenarios

Please reply to this email or reach out directly:
**Email:** gerard.cruzado1@gmail.com
**Organization:** Fusion Software

## 📚 **References**

- Original PASETO: https://paseto.io/
- NIST ML-DSA (FIPS 204): https://csrc.nist.gov/pubs/fips/204/final  
- NIST ML-KEM (FIPS 203): https://csrc.nist.gov/pubs/fips/203/final
- Reference Implementation: [GitHub link when ready]

Thank you for your time and consideration. I look forward to the community's insights on this approach to post-quantum token security.

Best regards,

**Gerard Junior Cruzado**  
Fusion Software  
gerard.cruzado1@gmail.com

---

*P.S. I want to emphasize respect for the original PASETO work by Scott Arciszewski and team. PASETO-PQ is intended as a complementary protocol for the post-quantum era, not a replacement or criticism of the excellent classical PASETO design.*

---

## 📝 **Customization Notes**

### For Different Audiences:

**Academic Lists (Modern Crypto, IACR):**
- Add more technical detail on lattice assumptions
- Reference recent PQ crypto research
- Mention plans for formal security proofs

**IETF Lists (CFRG, SAAG):**
- Emphasize standards compliance (FIPS 203/204)
- Focus on IETF process and working group coordination
- Mention IANA registry considerations

**Industry Lists:**
- Emphasize practical deployment concerns
- Include performance comparisons
- Discuss migration strategies from classical tokens

### Follow-up Strategy:

1. **Wait 1 week** for responses
2. **Compile feedback** into structured document
3. **Address major concerns** with specification updates
4. **Thank respondents** and share updated version
5. **Proceed to conference submissions** if feedback is positive

### Red Flags to Watch For:

- ❌ **Fundamental cryptographic concerns** about algorithm choices
- ❌ **Strong pushback** on using "PASETO" in the name
- ❌ **Lack of engagement** from crypto community
- ❌ **Suggestion to just extend original PASETO** instead

### Success Indicators:

- ✅ **Technical questions** about implementation details
- ✅ **Suggestions for improvements** rather than fundamental concerns
- ✅ **Interest in trying** the reference implementation
- ✅ **Discussion of use cases** and deployment scenarios
- ✅ **Offers to collaborate** or review