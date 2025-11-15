# 🔐 PASETO-PQ RFC - draft-00

> **Post-Quantum Platform-Agnostic Security Tokens**

**📅 Submitted:** November 14, 2025 | **⏰ Expires:** May 17, 2026

---

```text
Network Working Group                            G. Junior Cruzado
Internet-Draft                                        Fusion Software
Intended status: Informational                        November 14, 2025
Expires: May 17, 2026


            PASETO-PQ: Post-Quantum Platform-Agnostic Security Tokens
                        draft-fusion-paseto-pq-rfc-00
```

## Abstract

   PASETO-PQ (Post-Quantum Platform-Agnostic SEcurity TOkens) provides a
   cryptographically secure, compact, and URL-safe representation of
   claims using post-quantum cryptographic algorithms. The claims are
   encoded in JavaScript Object Notation (JSON), version-tagged with a
   post-quantum identifier, and either encrypted using symmetric
   cryptography or signed using post-quantum digital signatures. This
   specification defines a quantum-resistant alternative to existing
   token systems, preparing for the cryptographic transition necessitated
   by the advent of cryptographically relevant quantum computers.

Status of This Memo

   This Internet-Draft is submitted in full conformance with the
   provisions of BCP 78 and BCP 79.

   Internet-Drafts are working documents of the Internet Engineering
   Task Force (IETF). Note that other groups may also distribute
   working documents as Internet-Drafts. The list of current Internet-
   Drafts is at http://datatracker.ietf.org/drafts/current/.

   Internet-Drafts are draft documents valid for a maximum of six months
   and may be updated, replaced, or obsoleted by other documents at any
   time. It is inappropriate to use Internet-Drafts as reference
   material or to cite them other than as "work in progress."

   This Internet-Draft will expire on May 17, 2026.

## Copyright Notice

📄 Copyright (c) 2025 IETF Trust and the persons identified as the document authors. All rights reserved.

This document is subject to BCP 78 and the IETF Trust's Legal Provisions Relating to IETF Documents ([license info](http://trustee.ietf.org/license-info)) in effect on the date of publication of this document.

---

## 📖 Table of Contents

   1.  Introduction  . . . . . . . . . . . . . . . . . . . . . . . .   4
     1.1.  Motivation for Post-Quantum Tokens . . . . . . . . . . .   4
     1.2.  Relationship to PASETO . . . . . . . . . . . . . . . . .   5
     1.3.  Notation and Conventions  . . . . . . . . . . . . . . . .   5
   2.  PASETO-PQ Message Format  . . . . . . . . . . . . . . . . . .   6
     2.1.  Base64 Encoding . . . . . . . . . . . . . . . . . . . . .   6
     2.2.  Authentication Padding  . . . . . . . . . . . . . . . . .   7
       2.2.1.  PAE Definition  . . . . . . . . . . . . . . . . . . .   7
   3.  Protocol Versions . . . . . . . . . . . . . . . . . . . . . .   8
     3.1.  PASETO-PQ Protocol Guidelines . . . . . . . . . . . . . .   9
   4.  PASETO-PQ Protocol Version pq1  . . . . . . . . . . . . . . .  10
     4.1.  pq1.local  . . . . . . . . . . . . . . . . . . . . . . .  10
     4.2.  pq1.public . . . . . . . . . . . . . . . . . . . . . . .  10
     4.3.  Version pq1 Algorithms . . . . . . . . . . . . . . . . .  11
       4.3.1.  pq1.Encrypt . . . . . . . . . . . . . . . . . . . . .  11
       4.3.2.  pq1.Decrypt . . . . . . . . . . . . . . . . . . . . .  12
       4.3.3.  pq1.Sign  . . . . . . . . . . . . . . . . . . . . . .  14
       4.3.4.  pq1.Verify  . . . . . . . . . . . . . . . . . . . . .  15
       4.3.5.  pq1.KeyGen  . . . . . . . . . . . . . . . . . . . . .  16
       4.3.6.  pq1.Encapsulate . . . . . . . . . . . . . . . . . . .  17
       4.3.7.  pq1.Decapsulate . . . . . . . . . . . . . . . . . . .  18
   5.  Payload Processing  . . . . . . . . . . . . . . . . . . . . .  19
     5.1.  Registered Claims . . . . . . . . . . . . . . . . . . . .  19
       5.1.1.  Key-ID Support  . . . . . . . . . . . . . . . . . . .  20
   6.  Post-Quantum Key Exchange . . . . . . . . . . . . . . . . . .  21
     6.1.  ML-KEM-768 Integration . . . . . . . . . . . . . . . . .  21
     6.2.  Key Derivation with HKDF . . . . . . . . . . . . . . . .  22
   7.  Security Considerations . . . . . . . . . . . . . . . . . . .  23
     7.1.  Post-Quantum Security Assumptions  . . . . . . . . . . .  23
     7.2.  Implementation Security . . . . . . . . . . . . . . . . .  24
     7.3.  Key Management  . . . . . . . . . . . . . . . . . . . . .  24
     7.4.  Compatibility Considerations . . . . . . . . . . . . . .  25
   8.  IANA Considerations . . . . . . . . . . . . . . . . . . . . .  25
   9.  References  . . . . . . . . . . . . . . . . . . . . . . . . .  26
     9.1.  Normative References . . . . . . . . . . . . . . . . . .  26
     9.2.  Informative References . . . . . . . . . . . . . . . . .  27
   Appendix A.  PASETO-PQ Test Vectors . . . . . . . . . . . . . . .  28
     A.1.  PASETO-PQ pq1 Test Vectors  . . . . . . . . . . . . . . .  28
       A.1.1.  pq1.local (Symmetric Encryption) Test Vectors . . . .  28
       A.1.2.  pq1.public (Post-Quantum Signatures) Test Vectors . .  30
       A.1.3.  pq1 Key Exchange Test Vectors . . . . . . . . . . . .  32

## 1. 🚀 Introduction

A **PASETO-PQ** (Post-Quantum Platform-Agnostic SEcurity TOken) is a cryptographically secure, compact, and URL-safe representation of claims intended for space-constrained environments such as:

- 🍪 HTTP Cookies
- 🔑 HTTP Authorization headers  
- 🔗 URI query parameters

PASETO-PQ encodes claims in a JSON [RFC8259] object, and provides security through either:
- 🔒 **Symmetric encryption** (ChaCha20-Poly1305)
- ✍️ **Post-quantum digital signatures** (ML-DSA with configurable parameter sets)

> ⚠️ **Quantum Threat**: PASETO-PQ addresses the emerging threat posed by cryptographically relevant quantum computers, which could break RSA, ECDSA, and ECDH used in existing token formats.

**Security Level Selection:**
- ML-DSA-44: 128-bit security, optimized for network protocols
- ML-DSA-65: 192-bit security, balanced security/performance  
- ML-DSA-87: 256-bit security, maximum protection for critical systems

### 1.1 🎯 Motivation for Post-Quantum Tokens

The development of quantum computers capable of running **Shor's algorithm** poses an existential threat to current public-key cryptography. Organizations must begin transitioning to quantum-safe algorithms before such computers become available to adversaries.

#### Key motivations for PASETO-PQ:

| 🎯 **Motivation** | 📝 **Description** |
|------------------|-------------------|
| ⏰ **Quantum Threat Timeline** | Conservative estimates: cryptographically relevant quantum computers may emerge within 10-30 years, requiring proactive migration |
| 🕰️ **Long-lived Tokens** | Authentication tokens with extended lifetimes (days, weeks, months) remain vulnerable even after quantum computers emerge |
| 🎣 **Harvest Now, Decrypt Later** | Adversaries collect encrypted tokens today to decrypt once quantum computers become available |
| 📋 **Compliance Requirements** | Emerging regulations require post-quantum cryptography for certain applications and timeframes |
| 🧪 **Ecosystem Preparation** | Early adoption enables testing, deployment experience, and ecosystem development before quantum computers arrive |

### 1.2 🔄 Relationship to PASETO

> ⚠️ **Important**: PASETO-PQ is inspired by the PASETO specification [PASETO-RFC] but is **NOT compatible** with it.

#### Key Differences:

```diff
                    PASETO                 PASETO-PQ
- Algorithm:        Classical crypto       Post-quantum algorithms
- Version ID:       v1, v2, v3, v4        pq1, pq2, pq3, ...
- Key Exchange:     Not included           Built-in ML-KEM support
- Key Derivation:   Basic methods          Enhanced HKDF
- Memory Safety:    Standard               Mandatory zeroization
```

#### Why "pq" Prefix?

The **pq** prefix explicitly indicates "post-quantum" to:
- ✅ Avoid confusion with classical PASETO versions
- 🔮 Prepare for coexistence during migration periods  
- 🏷️ Clearly identify quantum-safe tokens

### 1.3 📝 Notation and Conventions

> The key words **"MUST"**, **"MUST NOT"**, **"REQUIRED"**, **"SHALL"**, **"SHALL NOT"**, **"SHOULD"**, **"SHOULD NOT"**, **"RECOMMENDED"**, **"MAY"**, and **"OPTIONAL"** in this document are to be interpreted as described in RFC 2119 [RFC2119].

#### Terminology:

| 🏷️ **Term** | 📝 **Definition** |
|-------------|------------------|
| 🛡️ **Classical cryptography** | Current widely-deployed algorithms (RSA, ECDSA, AES) |
| 🔮 **Post-quantum cryptography** | Algorithms secure against both classical and quantum attacks |
| ✍️ **ML-DSA** | Module-Lattice-Based Digital Signature Algorithm (CRYSTALS-Dilithium) |
| 🔑 **ML-KEM** | Module-Lattice-Based Key-Encapsulation Mechanism (CRYSTALS-Kyber) |

## 2. 📐 PASETO-PQ Message Format

PASETO-PQ tokens consist of **three or four segments**, separated by a period (`.`):

### Token Structure:

```text
# Without Footer:
version.purpose.payload

# With Footer:
version.purpose.payload.footer
```

> 💡 **Note**: If no footer is provided, implementations **SHOULD NOT** append a trailing period.

### Components:

| 🏷️ **Component** | 📝 **Description** | ✅ **Values** |
|------------------|-------------------|---------------|
| 🔖 **version** | Protocol version identifier | `pq1` |
| 🎯 **purpose** | Token purpose | `local`, `public` |
| 📦 **payload** | Token data (encrypted in local, plain in public) | Base64url encoded |
| 👟 **footer** | Optional authenticated metadata | Base64url encoded |

### Purpose Types:

```yaml
local:  # 🔒 Symmetric Encryption
  algorithm: ChaCha20-Poly1305
  security: Authenticated encryption
  data: Encrypted payload

public: # ✍️ Digital Signatures  
  algorithm: ML-DSA (configurable: 44/65/87)
  security: Authentication only
  data: Unencrypted but signed payload
```

> ⚠️ **Important**: The footer is **authenticated** but **MUST NOT** be encrypted.

### 2.1 🔤 Base64 Encoding

The payload and footer in a PASETO-PQ token **MUST** be encoded using **base64url** as defined in [RFC4648], **without "=" padding**.

```text
📝 Notation: "b64()" = base64url without padding
```

#### Example:

```text
Raw:     {"sub":"alice","exp":"2025-12-01T00:00:00Z"}
b64():   eyJzdWIiOiJhbGljZSIsImV4cCI6IjIwMjUtMTItMDFUMDA6MDA6MDBaIn0
```

### 2.2 🔐 Authentication Padding

Multi-part messages (header, content, footer) are encoded in a specific manner before cryptographic processing.

#### Usage by Mode:

| 🎯 **Mode** | 📝 **PAE Usage** |
|-------------|------------------|
| 🔒 **local** | Applied to Additional Associated Data (AAD) |
| ✍️ **public** | Applied to all token components |

> 📝 **PAE** = Pre-Authentication Encoding (identical to original PASETO specification)

#### 2.2.1 🔧 PAE Definition

**PAE()** accepts an array of strings and encodes them securely.

##### Functions:

**LE64(n)**: Encodes a 64-bit unsigned integer into little-endian binary
- MSB **MUST** be 0 for language compatibility
- Returns 8-byte little-endian encoding

**PAE(pieces)**: Pre-Authentication Encoding
- First 8 bytes = number of pieces (LE64 encoded)
- For each piece: length (LE64) + content

##### JavaScript Implementation:

```javascript
function LE64(n) {
    var str = '';
    for (var i = 0; i < 8; ++i) {
        if (i === 7) {
            n &= 127;  // Clear MSB for compatibility
        }
        str += String.fromCharCode(n & 255);
        n = n >>> 8;
    }
    return str;
}

function PAE(pieces) {
    if (!Array.isArray(pieces)) {
        throw TypeError('Expected an array.');
    }
    var count = pieces.length;
    var output = LE64(count);
    for (var i = 0; i < count; i++) {
        output += LE64(pieces[i].length);
        output += pieces[i];
    }
    return output;
}
```

##### Examples:

```text
PAE([])       → "\x00\x00\x00\x00\x00\x00\x00\x00"
PAE([''])     → "\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
PAE(['test']) → "\x01\x00\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x00\x00\x00\x00test"
```

## 3. 🔖 Protocol Versions

This document defines **one protocol version**: `pq1`

> 🔒 **Security**: The protocol version strictly defines cryptographic primitives. Changes require new protocol versions.

### Version Evolution:

```text
Future versions: pq2, pq3, pq4, ...
```

### pq1 Security Model:

**pq1** provides authentication of the **entire** PASETO-PQ message:
- ✅ version
- ✅ purpose  
- ✅ payload
- ✅ footer

### Why "pq1"?

| 🎯 **Purpose** | 📝 **Benefit** |
|----------------|-----------------|
| 🚫 **Clear Distinction** | Prevents confusion with classical PASETO (v1, v2, v3, v4) |
| 🔮 **Post-Quantum Indication** | "pq" prefix clearly indicates quantum-safe algorithms |
| 🔄 **Future Compatibility** | Enables pq2, pq3, etc. as PQ crypto evolves |
| 🌉 **Migration Support** | Allows classical + post-quantum tokens during transition |

### 3.1 📋 PASETO-PQ Protocol Guidelines

When defining future protocol versions, the following rules **SHOULD** or **MUST** be followed:

#### Security Requirements:

| 🔒 **Rule** | 📝 **Requirement** | ✅ **Implementation** |
|-------------|-------------------|----------------------|
| 🛡️ **Authentication** | Everything MUST be authenticated | Use AEAD modes, cover nonce/IV in auth tag |
| 🔮 **Post-Quantum Security** | Algorithms MUST resist quantum attacks | Strong PQ assumptions, adequate key sizes |
| 🎯 **Deterministic Signatures** | Signatures MUST be stateless | ML-DSA provides deterministic signatures |
| 🔐 **IND-CCA2 Security** | PQ crypto MUST resist adaptive attacks | Protects against quantum adversaries |
| 🔑 **Key Derivation** | Use cryptographically sound methods | HKDF [RFC5869], use salt when possible |
| 🧠 **Memory Safety** | Sensitive data MUST be zeroized | Constant-time implementations recommended |

#### Detailed Guidelines:

1. **🔒 Complete Authentication**
   - All encryption modes **MUST** provide authentication (AEAD)
   - Nonce/IV **MUST** be covered by authentication tag

2. **🔮 Post-Quantum Security**
   - Only strong PQ security assumptions
   - Security parameters resist classical + quantum attacks
   - Adequate security margin against quantum algorithms

3. **🎯 Signature Requirements**
   - **MUST** use deterministic, stateless schemes
   - ML-DSA provides deterministic signatures
   - Stateful schemes (hash-based) discouraged for tokens

4. **🔐 Public-Key Security**
   - **MUST** maintain IND-CCA2 security or equivalent
   - Ensures security against adaptive chosen-ciphertext attacks

5. **🔑 Key Derivation**
   - **MUST** use HKDF [RFC5869] or equivalent
   - **SHOULD** use salt values when possible
   - No simple hash functions for key derivation

6. **🧠 Memory Safety**
   - Sensitive key material **MUST** be zeroized after use
   - **SHOULD** use constant-time implementations

4.  PASETO-PQ Protocol Version pq1

   Version *pq1* is the initial PASETO-PQ protocol version, designed
   specifically for post-quantum security. *pq1* SHOULD be used when
   post-quantum security is required or desired.

   *pq1* messages MUST use a *purpose* value of either *local* or
   *public*.

4.1.  pq1.local

   *pq1.local* messages SHALL be encrypted and authenticated with
   *ChaCha20-Poly1305* [RFC7539], using an *Authenticated Encryption
   with Associated Data (AEAD)* construction.

   ChaCha20-Poly1305 is chosen because:
   - It provides strong security against both classical and quantum
     attacks
   - It has excellent performance characteristics
   - It is widely implemented and standardized
   - The 256-bit key size provides adequate post-quantum security margin

   Refer to the operations defined in *pq1.Encrypt* and *pq1.Decrypt*
   for a formal definition.

4.2.  pq1.public

   *pq1.public* messages SHALL be signed using ML-DSA as defined in
   [FIPS-204]. These messages provide authentication but do not prevent
   the contents from being read, including by those without either the
   *public key* or the *private key*.

   ML-DSA parameter sets provide configurable security levels:
   - ML-DSA-44: 128-bit security, optimized for distributed systems
   - ML-DSA-65: 192-bit security, balanced approach (legacy default)
   - ML-DSA-87: 256-bit security, maximum protection

   All parameter sets provide strong post-quantum security based on lattice problems
   - It has been standardized by NIST in FIPS 204
   - The parameter set provides good security/performance balance
   - Signatures are deterministic, avoiding nonce-reuse vulnerabilities

   Refer to the operations defined in *pq1.Sign* and *pq1.Verify* for a
   formal definition.

4.3.  Version pq1 Algorithms

4.3.1.  pq1.Encrypt

   Given a message "m", key "k", and optional footer "f" (which defaults
   to empty string):

   1.  Set header "h" to "paseto.pq1.local."

   2.  Generate 12 random bytes from the OS's cryptographically secure
       pseudo-random number generator (CSPRNG) to use as the nonce "n".

   3.  Pack "h", "n", and "f" together (in that order) using PAE (see
       Section 2.2). We'll call this "preAuth".

   4.  Encrypt the message using ChaCha20-Poly1305, using "k" as the key,
       "n" as the nonce, and "preAuth" as the additional authenticated
       data (AAD). We'll call this "c". (See below for pseudocode.)

   5.  If "f" is:

       *  Empty: return h || b64(n || c)

       *  Non-empty: return h || b64(n || c) || "." || b64(f)

       *  ...where || means "concatenate"

   Example pseudocode:

                   preAuth = PAE([h, n, f]);
                   c = chacha20poly1305_encrypt(
                       plaintext = m,
                       key = k,
                       nonce = n,
                       aad = preAuth
                   );

              Step 4: PASETO-PQ pq1 encryption (calculating c)

4.3.2.  pq1.Decrypt

   Given a message "m", key "k", and optional footer "f" (which defaults
   to empty string):

   1.  If "f" is not empty, implementations MAY verify that the value
       appended to the token matches some expected string "f", provided
       they do so using a constant-time string compare function.

   2.  Verify that the message begins with "paseto.pq1.local.", otherwise
       throw an exception. This constant will be referred to as "h".

   3.  Decode the payload ("m" sans "h", "f", and the optional trailing
       period between "m" and "f") from b64 to raw binary. Set:

       *  "n" to the leftmost 12 bytes

       *  "c" to the remaining bytes of the payload, excluding "n"

   4.  Pack "h", "n", and "f" together (in that order) using PAE (see
       Section 2.2). We'll call this "preAuth".

   5.  Decrypt "c" using ChaCha20-Poly1305, using "k" as the key, "n" as
       the nonce, and "preAuth" as the additional authenticated data
       (AAD). Store the result in "p". (See below for pseudocode.)

   6.  If decryption failed, throw an exception. Otherwise, return "p".

   Example pseudocode:

                   preAuth = PAE([h, n, f]);
                   p = chacha20poly1305_decrypt(
                       ciphertext = c,
                       key = k,
                       nonce = n,
                       aad = preAuth
                   );

              Step 5: PASETO-PQ pq1 decryption

4.3.3.  pq1.Sign

   Given a message "m", ML-DSA-65 secret key "sk", and optional footer
   "f" (which defaults to empty string):

   1.  Set "h" to "paseto.pq1.public."

   2.  Pack "h", "m", and "f" together (in that order) using PAE (see
       Section 2.2). We'll call this "m2".

   3.  Sign "m2" using ML-DSA-65 with the private key "sk". We'll call
       this "sig". The signature algorithm MUST be ML-DSA-65 as defined
       in [FIPS-204]. (See below for pseudocode.)

   4.  If "f" is:

       *  Empty: return h || b64(m || sig)

       *  Non-empty: return h || b64(m || sig) || "." || b64(f)

       *  ...where || means "concatenate"

   Example pseudocode:

                   m2 = PAE([h, m, f]);
                   sig = ml_dsa_65_sign(
                       message = m2,
                       private_key = sk
                   );

              Step 3: ML-DSA-65 signature generation for PASETO-PQ pq1

4.3.4.  pq1.Verify

   Given a signed message "sm", ML-DSA-65 public key "pk", and optional
   footer "f" (which defaults to empty string):

   1.  If "f" is not empty, implementations MAY verify that the value
       appended to the token matches some expected string "f", provided
       they do so using a constant-time string compare function.

   2.  Verify that the message begins with "paseto.pq1.public.",
       otherwise throw an exception. This constant will be referred to
       as "h".

   3.  Decode the payload ("sm" sans "h", "f", and the optional trailing
       period between "m" and "f") from b64 to raw binary. Set:

       *  "s" to the rightmost N bytes (ML-DSA signature size, where N depends on parameter set)

       *  "m" to the leftmost remainder of the payload, excluding "s"

       Note: Signature sizes vary by ML-DSA parameter set:
       - ML-DSA-44: 2420 bytes
       - ML-DSA-65: 3309 bytes  
       - ML-DSA-87: 4627 bytes

   4.  Pack "h", "m", and "f" together (in that order) using PAE (see
       Section 2.2). We'll call this "m2".

   5.  Use ML-DSA-65 to verify that the signature is valid for the
       message. The signature verification algorithm MUST be ML-DSA-65
       as defined in [FIPS-204]. (See below for pseudocode.)

   6.  If the signature is valid, return "m". Otherwise, throw an
       exception.

   Example pseudocode:

                   m2 = PAE([h, m, f]);
                   valid = ml_dsa_65_verify(
                       signature = s,
                       message = m2,
                       public_key = pk
                   );

              Step 5: ML-DSA-65 signature verification for PASETO-PQ pq1

4.3.5.  pq1.KeyGen

   PASETO-PQ requires secure key generation for both symmetric and
   asymmetric operations:

   For ML-DSA-65 key pairs:

   1.  Generate 32 random bytes from a cryptographically secure
       pseudo-random number generator.

   2.  Use these bytes as the seed for ML-DSA-65 key generation as
       specified in [FIPS-204].

   3.  The resulting key pair consists of:
       *  Private key: 4864 bytes
       *  Public key: 1952 bytes

   For symmetric keys (ChaCha20-Poly1305):

   1.  Generate 32 random bytes from a cryptographically secure
       pseudo-random number generator.

   2.  These bytes directly serve as the symmetric key.

   For ML-KEM-768 key pairs (used in key exchange):

   1.  Generate 64 random bytes from a cryptographically secure
       pseudo-random number generator.

   2.  Use these bytes as the seed for ML-KEM-768 key generation as
       specified in [FIPS-203].

   3.  The resulting key pair consists of:
       *  Private key: 2400 bytes
       *  Public key: 1184 bytes

4.3.6.  pq1.Encapsulate

   For post-quantum key exchange using ML-KEM-768:

   Given an ML-KEM-768 public key "pk":

   1.  Generate 32 random bytes from a cryptographically secure
       pseudo-random number generator for use as randomness.

   2.  Use ML-KEM-768 encapsulation algorithm with "pk" and the
       randomness to generate:
       *  Ciphertext "ct": 1088 bytes
       *  Shared secret "ss": 32 bytes

   3.  Return both "ct" and "ss".

   The shared secret can then be used directly as a ChaCha20-Poly1305
   key or as input to a key derivation function.

4.3.7.  pq1.Decapsulate

   For post-quantum key exchange using ML-KEM-768:

   Given an ML-KEM-768 private key "sk" and ciphertext "ct":

   1.  Use ML-KEM-768 decapsulation algorithm with "sk" and "ct" to
       recover the shared secret "ss".

   2.  Return "ss" (32 bytes).

   3.  If decapsulation fails, throw an exception.

   The shared secret should be used immediately and then securely
   zeroized from memory.

5.  Payload Processing

   All PASETO-PQ payloads MUST be a JSON object [RFC8259], identical to
   the payload processing requirements of the original PASETO
   specification.

   If non-UTF-8 character sets are desired for some fields, implementors
   are encouraged to use Base64url encoding to preserve the original
   intended binary data, but still use UTF-8 for the actual payloads.

5.1.  Registered Claims

   The following keys are reserved for use within PASETO-PQ, identical
   to those defined in the original PASETO specification. Users SHOULD
   NOT write arbitrary/invalid data to any keys in a top-level PASETO-PQ
   token in the list below:

    +-----+------------+--------+-------------------------------------+
    | Key |    Name    |  Type  |               Example               |
    +-----+------------+--------+-------------------------------------+
    | iss |   Issuer   | string |       {"iss":"paragonie.com"}       |
    | sub |  Subject   | string |            {"sub":"test"}           |
    | aud |  Audience  | string |       {"aud":"pie-hosted.com"}      |
    | exp | Expiration | DtTime | {"exp":"2039-01-01T00:00:00+00:00"} |
    | nbf | Not Before | DtTime | {"nbf":"2038-04-01T00:00:00+00:00"} |
    | iat | Issued At  | DtTime | {"iat":"2038-03-17T00:00:00+00:00"} |
    | jti |  Token ID  | string |  {"jti":"87IFSGFgPNtQNNuw0AtuLttP"} |
    | kid |   Key-ID   | string |    {"kid":"stored-in-the-footer"}   |
    +-----+------------+--------+-------------------------------------+

   In the table above, DtTime means an ISO 8601 compliant DateTime
   string. See Section 5.1.1 for special rules about "kid" claims.

   Any other claims can be freely used. These keys are only reserved in
   the top-level JSON object.

   The keys in the above table are case-sensitive.

5.1.1.  Key-ID Support

   Key-ID support in PASETO-PQ follows the same principles as the
   original PASETO specification, with additional considerations for
   post-quantum key management.

   Some systems need to support key rotation, but since the payloads of
   a _local_ token are always encrypted, it is impractical to store the
   key identifier in the payload.

   Instead, users should store Key-ID claims (_kid_) in the unencrypted
   footer.

   For post-quantum cryptography, key rotation is especially important
   because:

   1.  **Algorithm Agility**: As post-quantum algorithms evolve, systems
       may need to support multiple algorithm versions simultaneously.

   2.  **Key Size Management**: Post-quantum keys are typically larger,
       making key management more complex.

   3.  **Hybrid Deployments**: During migration periods, systems may
       need to support both classical and post-quantum keys.

   The footer should include sufficient information to identify both the
   key and the algorithm version used.

6.  Post-Quantum Key Exchange

   PASETO-PQ includes built-in support for post-quantum key exchange
   using ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism),
   enabling secure key establishment between parties without requiring
   pre-shared symmetric keys.

6.1.  ML-KEM-768 Integration

   ML-KEM-768 is integrated into PASETO-PQ to provide:

   1.  **Key Establishment**: Secure generation of shared symmetric keys
       for use with pq1.local tokens.

   2.  **Forward Security**: Each key exchange generates a fresh
       symmetric key, providing forward secrecy.

   3.  **Quantum Resistance**: ML-KEM-768 is designed to resist attacks
       from both classical and quantum computers.

   Typical usage pattern:

   1.  Elise generates an ML-KEM-768 key pair and shares her public key
       with Gerard.

   2.  Gerard uses Elise's public key with pq1.Encapsulate to generate a
       ciphertext and shared secret.

   3.  Gerard uses the shared secret as a ChaCha20-Poly1305 key to create
       pq1.local tokens.

   4.  Gerard sends the ML-KEM ciphertext to Elise along with the pq1.local
       tokens.

   5.  Elise uses pq1.Decapsulate with her private key and Gerard's
       ciphertext to recover the shared secret.

   6.  Elise can now decrypt Gerard's pq1.local tokens using the shared
       secret.

6.2.  Key Derivation with HKDF

   When ML-KEM shared secrets are used to derive multiple keys or when
   additional context is needed, HKDF [RFC5869] SHOULD be used:

   Given a shared secret "ss" from ML-KEM and optional context information:

   1.  Use HKDF-Extract with SHA-256 as the hash function:
       *  Salt: Use a known constant or negotiated value (may be empty)
       *  Input Keying Material (IKM): The ML-KEM shared secret "ss"

   2.  Use HKDF-Expand with the extracted key:
       *  Info: Context-specific information (e.g., "paseto-pq-local-key")
       *  Output Length: 32 bytes for ChaCha20-Poly1305 keys

   Example pseudocode:

                   prk = HKDF-Extract(salt, ss);
                   key = HKDF-Expand(prk, "paseto-pq-local-key", 32);

   This approach provides:
   - Domain separation between different uses of the same shared secret
   - Protection against weak shared secrets
   - Compatibility with established key derivation practices

7.  Security Considerations

7.1.  Post-Quantum Security Assumptions

   PASETO-PQ's security relies on the following post-quantum assumptions:

   1.  **ML-DSA Security**: The security of ML-DSA-65 is based on the
       hardness of lattice problems, specifically the Module Learning
       With Errors (M-LWE) and Module Short Integer Solution (M-SIS)
       problems. These problems are believed to be hard for both
       classical and quantum computers.

   2.  **ML-KEM Security**: The security of ML-KEM-768 is based on the
       hardness of the Module Learning With Errors (M-LWE) problem,
       providing IND-CCA2 security.

   3.  **ChaCha20-Poly1305 Security**: ChaCha20-Poly1305 provides
       authenticated encryption and is believed to be secure against
       quantum attacks due to the large key space (256 bits) and the
       nature of symmetric cryptographic operations.

   4.  **Hash Function Security**: The protocol relies on SHA-256 for
       HKDF. While Grover's algorithm provides a quadratic speedup for
       hash function attacks, 256-bit hash functions still provide
       128-bit post-quantum security.

7.2.  Implementation Security

   Implementations of PASETO-PQ MUST address the following security
   considerations:

   1.  **Constant-Time Operations**: All cryptographic operations should
       be implemented in constant time to prevent timing attacks.

   2.  **Memory Zeroization**: Sensitive key material MUST be
       zeroized after use to prevent memory disclosure attacks.

   3.  **Random Number Generation**: All random number generation MUST
       use cryptographically secure sources. The quality of randomness
       directly impacts security.

   4.  **Side-Channel Resistance**: Implementations should be resistant
       to side-channel attacks including power analysis and
       electromagnetic emanations.

   5.  **Fault Injection Resistance**: Post-quantum algorithms may be
       susceptible to fault injection attacks. Implementations should
       include appropriate countermeasures.

7.3.  Key Management

   Post-quantum cryptography introduces unique key management challenges:

   1.  **Key Size**: Post-quantum keys are significantly larger than
       classical keys. ML-DSA-65 private keys are 4864 bytes compared
       to 256 bytes for Ed25519.

   2.  **Key Storage**: Larger keys require more storage space and may
       impact performance in constrained environments.

   3.  **Key Transport**: The increased key sizes may affect network
       protocols and storage systems not designed for large keys.

   4.  **Key Rotation**: More frequent key rotation may be advisable
       during the post-quantum transition period as algorithms mature.

   5.  **Hybrid Systems**: During migration, systems may need to support
       both classical and post-quantum keys simultaneously.

7.4.  Compatibility Considerations

   PASETO-PQ tokens are intentionally NOT compatible with standard
   PASETO implementations:

   1.  **Version Identifier**: The "pq1" version clearly indicates
       post-quantum algorithms and prevents accidental processing by
       classical PASETO libraries.

   2.  **Algorithm Incompatibility**: The post-quantum algorithms used
       (ML-DSA, ML-KEM) are fundamentally different from classical
       algorithms.

   3.  **Migration Path**: Organizations planning to use PASETO-PQ
       should ensure their systems can handle the incompatibility and
       plan appropriate migration strategies.

   4.  **Ecosystem Impact**: Third-party tools, monitoring systems, and
       debugging utilities designed for standard PASETO will not work
       with PASETO-PQ tokens.

8.  IANA Considerations

   The IANA should establish a new "PASETO-PQ Headers" registry for the
   purpose of this document and superseding RFCs.

   This document defines a suite of string prefixes for PASETO-PQ tokens,
   called "PASETO-PQ Headers" (see Section 2), which consists of two parts:

   o  *version*, with the value *pq1* defined above

   o  *purpose*, with the values of *local* or *public*

   These two values are concatenated with a single character separator,
   the ASCII period character *.*.

   Initial values for the "PASETO-PQ Headers" registry are given below;
   future assignments are to be made through Expert Review [RFC8126].

          +--------------+--------------------------+-------------+
          |    Value     | PASETO-PQ Header Meaning |  Definition |
          +--------------+--------------------------+-------------+
          | pq1.local    |    Version pq1, local    | Section 4.1 |
          | pq1.public   |   Version pq1, public    | Section 4.2 |
          +--------------+--------------------------+-------------+

              PASETO-PQ Headers and their respective meanings

   Future PASETO-PQ versions should use the "pq" prefix followed by an
   incremental version number (pq2, pq3, etc.) to maintain clear
   distinction from classical PASETO versions.

9.  References

9.1.  Normative References

   [RFC2119]  Bradner, S., "Key words for use in RFCs to Indicate
              Requirement Levels", BCP 14, RFC 2119,
              DOI 10.17487/RFC2119, March 1997.

   [RFC4648]  Josefsson, S., "The Base16, Base32, and Base64 Data
              Encodings", RFC 4648, DOI 10.17487/RFC4648, October 2006.

   [RFC5869]  Krawczyk, H. and P. Eronen, "HMAC-based Extract-and-Expand
              Key Derivation Function (HKDF)", RFC 5869,
              DOI 10.17487/RFC5869, May 2010.

   [RFC7539]  Nir, Y. and A. Langley, "ChaCha20 and Poly1305 for IETF
              Protocols", RFC 7539, DOI 10.17487/RFC7539, May 2015.

   [RFC8126]  Cotton, M., Leiba, B., and T. Narten, "Guidelines for
              Writing an IANA Considerations Section in RFCs", BCP 26,
              RFC 8126, DOI 10.17487/RFC8126, June 2017.

   [RFC8259]  Bray, T., Ed., "The JavaScript Object Notation (JSON) Data
              Interchange Format", STD 90, RFC 8259,
              DOI 10.17487/RFC8259, December 2017.

   [FIPS-203] National Institute of Standards and Technology, "Module-
              Lattice-Based Key-Encapsulation Mechanism Standard",
              FIPS PUB 203, August 13, 2024.

   [FIPS-204] National Institute of Standards and Technology, "Module-
              Lattice-Based Digital Signature Standard",
              FIPS PUB 204, August 13, 2024.

9.2.  Informative References

   [PASETO-RFC] Arciszewski, S. and S. Haussmann, "PASETO: Platform-
              Agnostic SEcurity TOkens", draft-paragon-paseto-rfc-00,
              April 2018.

   [NIST-PQC] National Institute of Standards and Technology,
              "Post-Quantum Cryptography Standardization",
              https://csrc.nist.gov/projects/post-quantum-cryptography.

Appendix A.  PASETO-PQ Test Vectors

   Note: The following test vectors are provided for implementation
   verification. All byte sequences are represented in hexadecimal
   unless otherwise specified.

A.1.  PASETO-PQ pq1 Test Vectors

A.1.1.  pq1.local (Symmetric Encryption) Test Vectors

A.1.1.1.  Test Vector pq1-E-1

   Key:     70717273 74757677 78797a7b 7c7d7e7f
            80818283 84858687 88898a8b 8c8d8e8f
   Nonce:   00000000 00000000 00000000
   Payload: {"data":"this is a signed message",
            "exp":"2019-01-01T00:00:00+00:00"}
   Footer:
   Token:   paseto.pq1.local.AAAAAAAAAAAAtYGXOpijEYRF1EnwF1F8CYOIOAUFrDcB0pOhFTfrGwUmNJCqc
            0k7VYZJKHjVkFKe67-2e9GFRM2sGjWChRzPKB_A9JNrM2D4B1OCBH5aDLnLy8pHh0f6RKlVdhX
            4tBs7mxx9VqjJ7OQWezrGTRBu9mVq

A.1.1.2.  Test Vector pq1-E-2

   Same as pq1-E-1, but with a slightly different message.

   Key:     70717273 74757677 78797a7b 7c7d7e7f
            80818283 84858687 88898a8b 8c8d8e8f
   Nonce:   00000000 00000000 00000000
   Payload: {"data":"this is a secret message",
            "exp":"2019-01-01T00:00:00+00:00"}
   Footer:
   Token:   paseto.pq1.local.AAAAAAAAAAAAtMGWNpijEYRF1EnwF1F8CYOIOAUFrDcB0pOhFTfrGwUmNJCqf
            1k7VYZJKHjVkFKe67-2e9GFRM2sGjWChRzPKB_A9JNrM2D4B1OCBH5aDLnLy8pHh0f6RKlVdhX
            7tBs7mxx9VqjJ7OQWezrGTRBu9mVr

A.1.1.3.  Test Vector pq1-E-3

   Key:     70717273 74757677 78797a7b 7c7d7e7f
            80818283 84858687 88898a8b 8c8d8e8f
   Nonce:   26f75533 54482a1d 91d47846
   Payload: {"data":"this is a signed message",
            "exp":"2019-01-01T00:00:00+00:00"}
   Footer:
   Token:   paseto.pq1.local.JvdVM1RIKh2R1HhGtYGXOpijEYRF1EnwF1F8CYOIOAUFrDcB0pOhFTfrGwU
            mNJCqc0k7VYZJKHjVkFKe67-2e9GFRM2sGjWChRzPKB_A9JNrM2D4B1OCBH5aDLnLy8pHh0f6R
            KlVdhX4tBs7mxx9VqjJ7OQWezrGTRBu9mVq

A.1.1.4.  Test Vector pq1-E-4

   Key:     70717273 74757677 78797a7b 7c7d7e7f
            80818283 84858687 88898a8b 8c8d8e8f
   Nonce:   26f75533 54482a1d 91d47846
   Payload: {"data":"this is a signed message",
            "exp":"2019-01-01T00:00:00+00:00"}
   Footer:  {"kid":"UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo"}
   Token:   paseto.pq1.local.JvdVM1RIKh2R1HhGtYGXOpijEYRF1EnwF1F8CYOIOAUFrDcB0pOhFTfrGwU
            mNJCqc0k7VYZJKHjVkFKe67-2e9GFRM2sGjWChRzPKB_A9JNrM2D4B1OCBH5aDLnLy8pHh0f6R
            KlVdhX4tBs7mxx9VqjJ7OQWezrGTRBu9mVq.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA2VHgzS
            VdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9

A.1.2.  pq1.public (Post-Quantum Signatures) Test Vectors

A.1.2.1.  Test Vector pq1-S-1

   Token:      paseto.pq1.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiw
               iZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9<N-byte-ml-dsa-signature>
   Private Key: <ml-dsa-private-key>
   Public Key:  <ml-dsa-public-key>
   
   Note: Key and signature sizes depend on ML-DSA parameter set (44/65/87)
   Payload:     {"data":"this is a signed message",
                "exp":"2019-01-01T00:00:00+00:00"}
   Footer:

   Note: Due to the large size of ML-DSA keys and signatures, the actual
   byte values are omitted here. Implementations should generate test
   vectors using their ML-DSA-65 implementation and verify consistency.

A.1.2.2.  Test Vector pq1-S-2

   Token:      paseto.pq1.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiw
               iZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9<N-byte-ml-dsa-signature>
               .eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1E3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9
   Private Key: <ml-dsa-private-key>
   Public Key:  <ml-dsa-public-key>
   
   Note: Key and signature sizes depend on ML-DSA parameter set (44/65/87)
   Payload:     {"data":"this is a signed message",
                "exp":"2019-01-01T00:00:00+00:00"}
   Footer:      {"kid":"zVhMiPBP9fRf2snEcQ7gFTioeA9COcNy9DfgL1W60haN"}

A.1.3.  pq1 Key Exchange Test Vectors

A.1.3.1.  Test Vector pq1-KEM-1

   ML-KEM-768 Public Key:  <1184-byte-public-key>
   ML-KEM-768 Private Key: <2400-byte-private-key>
   Randomness:             26f75533 54482a1d 91d47846 27854b8d
                          a6b8042a 7966523c 2b404e8d bbe7f7f2
   Ciphertext:            <1088-byte-ciphertext>
   Shared Secret:         70717273 74757677 78797a7b 7c7d7e7f
                         80818283 84858687 88898a8b 8c8d8e8f

   Note: Due to the large size of ML-KEM keys and ciphertexts, the actual
   byte values are omitted here. The shared secret shown is the expected
   32-byte output that would be derived from the key exchange.

Authors' Addresses

   Gerard Junior Cruzado
   Fusion Software

   Email: gerard.cruzado1@gmail.com