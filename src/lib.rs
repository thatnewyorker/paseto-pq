//! # PASETO-PQ: Post-Quantum PASETO Tokens
//!
//! A pure post-quantum implementation of PASETO-inspired tokens using ML-DSA (CRYSTALS-Dilithium)
//! for digital signatures. This crate provides quantum-safe authentication tokens that are
//! resistant to attacks by quantum computers.
//!
//! ## Design Principles
//!
//! - **Post-Quantum Only**: Uses ML-DSA-65 (NIST FIPS 204) for all signatures
//! - **PASETO-Inspired**: Follows PASETO's security model but with PQ algorithms
//! - **Greenfield**: No legacy compatibility, designed for quantum-safe future
//! - **Memory Safety**: Automatic zeroization of sensitive keys on drop
//! - **Cryptographic Hygiene**: Proper HKDF key derivation and secure random generation
//! - **Binary-First**: Uses CBOR for efficient binary serialization (v0.2.0+)
//!
//! ## ⚠️ Non-Standard Token Format
//!
//! **IMPORTANT**: This crate uses a **non-standard** token versioning scheme that diverges
//! from the official PASETO specification. The tokens use `pq2` to clearly indicate
//! post-quantum algorithms with CBOR serialization, avoiding confusion with standard PASETO versions.
//!
//! ### Token Format
//!
//! ```text
//! paseto.pq2.public.<base64url-encoded-cbor-payload>.<base64url-encoded-ml-dsa-signature>
//! paseto.pq2.local.<base64url-encoded-encrypted-cbor-payload>
//! ```
//!
//! ### Breaking Change from v0.1.x
//!
//! Version 0.2.0 introduces CBOR serialization replacing JSON. Tokens generated with v0.1.x
//! (using `pq1` prefix and JSON) are **NOT** compatible with v0.2.0+ (`pq2` prefix and CBOR).
//!
//! ### Interoperability Warning
//!
//! These tokens are **NOT** compatible with standard PASETO libraries or tooling.
//! If you need interoperability with existing PASETO ecosystems, this crate is not suitable.
//! The `pq2` versioning scheme clearly indicates "post-quantum era" tokens with CBOR,
//! distinguishing them from the classical algorithms defined in the PASETO specification.
//!
//! Consider this crate for:
//! - Greenfield applications requiring post-quantum security
//! - Internal systems where PASETO compatibility is not required
//! - Future migration paths when post-quantum PASETO standards emerge
//!
//! ## Example Usage
//!
//! ```rust,no_run
//! use paseto_pq::{PasetoPQ, Claims, KeyPair};
//! use time::OffsetDateTime;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Generate a new key pair
//! let mut rng = rand::rng();
//! let keypair = KeyPair::generate(&mut rng);
//!
//! // Create claims
//! let mut claims = Claims::new();
//! claims.set_subject("user123")?;
//! claims.set_issuer("my-service")?;
//! claims.set_audience("api.example.com")?;
//! claims.set_expiration(OffsetDateTime::now_utc() + time::Duration::hours(1))?;
//! claims.add_custom("tenant_id", "org_abc123")?;
//! claims.add_custom("roles", &["user", "admin"])?;
//!
//! // Sign the token
//! let token = PasetoPQ::sign(keypair.signing_key(), &claims)?;
//!
//! // Verify the token
//! let verified = PasetoPQ::verify(keypair.verifying_key(), &token)?;
//! let verified_claims = verified.claims();
//! assert_eq!(verified_claims.subject(), Some("user123"));
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::fmt;
use std::io::Cursor;

use anyhow::Result;
pub mod pae;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::aead::AeadCore;
use ciborium::Value as CborValue;
// Conditional compilation for ML-DSA parameter set selection
#[cfg(all(
    feature = "ml-dsa-44",
    not(any(feature = "ml-dsa-65", feature = "ml-dsa-87"))
))]
use ml_dsa::MlDsa44 as MlDsaParam;

#[cfg(all(
    feature = "ml-dsa-65",
    not(any(feature = "ml-dsa-44", feature = "ml-dsa-87"))
))]
use ml_dsa::MlDsa65 as MlDsaParam;

#[cfg(all(
    feature = "ml-dsa-87",
    not(any(feature = "ml-dsa-44", feature = "ml-dsa-65"))
))]
use ml_dsa::MlDsa87 as MlDsaParam;

// Compilation guards to ensure exactly one parameter set is selected
#[cfg(not(any(feature = "ml-dsa-44", feature = "ml-dsa-65", feature = "ml-dsa-87")))]
compile_error!(
    "Exactly one ML-DSA parameter set must be selected. Choose one of: \
    'ml-dsa-44' (128-bit, default), 'ml-dsa-65' (192-bit), or 'ml-dsa-87' (256-bit). \
    Example: cargo build --features ml-dsa-44"
);

#[cfg(any(
    all(feature = "ml-dsa-44", feature = "ml-dsa-65"),
    all(feature = "ml-dsa-44", feature = "ml-dsa-87"),
    all(feature = "ml-dsa-65", feature = "ml-dsa-87"),
    all(feature = "ml-dsa-44", feature = "ml-dsa-65", feature = "ml-dsa-87")
))]
compile_error!(
    "Multiple ML-DSA parameter sets selected. Choose exactly one: \
    'ml-dsa-44', 'ml-dsa-65', or 'ml-dsa-87'. \
    Note: 'performance', 'balanced', and 'maximum-security' features are aliases."
);

use chacha20poly1305::aead::AeadMutInPlace;
use chacha20poly1305::aead::OsRng as AeadOsRng;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use ml_dsa::KeyGen;
use ml_dsa::Signature as MlDsaSignature;
use ml_dsa::SigningKey as MlDsaSigningKey;
use ml_dsa::VerifyingKey as MlDsaVerifyingKey;
use ml_dsa::signature::{SignatureEncoding, Signer, Verifier};
use ml_kem::KemCore;
use ml_kem::kem::{Decapsulate, Encapsulate};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use time::OffsetDateTime;
#[cfg(feature = "logging")]
use tracing::{debug, instrument};
use zeroize::Zeroize;

// Re-export ml_kem types that are used in our public API
pub use ml_kem::MlKem768;
type KemParam = MlKem768;

pub struct PasetoPQ;

pub struct KeyPair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

/// ML-DSA signing key (private)
pub struct SigningKey(MlDsaSigningKey<MlDsaParam>);

/// ML-DSA verifying key (public)
pub struct VerifyingKey(MlDsaVerifyingKey<MlDsaParam>);

/// Symmetric key for local (encrypted) tokens
pub struct SymmetricKey([u8; 32]);

/// ML-KEM key pair for key encapsulation
pub struct KemKeyPair {
    pub encapsulation_key: EncapsulationKey,
    pub decapsulation_key: DecapsulationKey,
}

/// ML-KEM encapsulation key (public)
pub struct EncapsulationKey(<KemParam as KemCore>::EncapsulationKey);

/// ML-KEM decapsulation key (private)
pub struct DecapsulationKey(<KemParam as KemCore>::DecapsulationKey);

/// Footer containing optional metadata for tokens (CBOR serialized)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Footer {
    /// Key identifier for key rotation and selection
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    /// Token version for compatibility tracking
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    /// Issuer-specific metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_meta: Option<String>,

    /// Additional custom metadata
    #[serde(flatten)]
    pub custom: HashMap<String, CborValue>,
}

impl Footer {
    /// Create a new empty footer
    pub fn new() -> Self {
        Self {
            kid: None,
            version: None,
            issuer_meta: None,
            custom: HashMap::new(),
        }
    }

    /// Set the key identifier
    pub fn set_kid(&mut self, kid: &str) -> Result<(), PqPasetoError> {
        self.kid = Some(kid.to_string());
        Ok(())
    }

    /// Set the version
    pub fn set_version(&mut self, version: &str) -> Result<(), PqPasetoError> {
        self.version = Some(version.to_string());
        Ok(())
    }

    /// Set issuer metadata
    pub fn set_issuer_meta(&mut self, issuer_meta: &str) -> Result<(), PqPasetoError> {
        self.issuer_meta = Some(issuer_meta.to_string());
        Ok(())
    }

    /// Add custom footer field
    pub fn add_custom<T: Serialize + ?Sized>(
        &mut self,
        key: &str,
        value: &T,
    ) -> Result<(), PqPasetoError> {
        let cbor_value = value_to_cbor(value)?;
        self.custom.insert(key.to_string(), cbor_value);
        Ok(())
    }

    /// Get custom footer field
    pub fn get_custom(&self, key: &str) -> Option<&CborValue> {
        self.custom.get(key)
    }

    /// Get key identifier
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    /// Get version
    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
    }

    /// Get issuer metadata
    pub fn issuer_meta(&self) -> Option<&str> {
        self.issuer_meta.as_deref()
    }

    /// Serialize footer to base64url-encoded CBOR
    pub fn to_base64(&self) -> Result<String, PqPasetoError> {
        let cbor = cbor_to_vec(self)?;
        Ok(URL_SAFE_NO_PAD.encode(&cbor))
    }

    /// Deserialize footer from base64url-encoded CBOR
    pub(crate) fn from_base64(encoded: &str) -> Result<Self, PqPasetoError> {
        let bytes = URL_SAFE_NO_PAD.decode(encoded)?;
        let footer = cbor_from_slice(&bytes)?;
        Ok(footer)
    }
}

impl Default for Footer {
    fn default() -> Self {
        Self::new()
    }
}

/// Claims contained within a token (CBOR serialized)
///
/// Time fields are serialized as Unix timestamps (i64) for CBOR efficiency.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// Token issuer
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,

    /// Token subject
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,

    /// Token audience
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,

    /// Token expiration time (Unix timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,

    /// Token not-before time (Unix timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,

    /// Token issued-at time (Unix timestamp)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,

    /// Token identifier (jti)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,

    /// Key identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    /// Custom claims
    #[serde(flatten)]
    pub custom: HashMap<String, CborValue>,
}

/// Verified token containing validated claims and optional footer
#[derive(Debug, Clone)]
pub struct VerifiedToken {
    claims: Claims,
    footer: Option<Footer>,
    raw_token: String,
}

/// Parsed token structure for inspection without cryptographic operations
///
/// This struct allows you to examine token metadata (purpose, version, footer)
/// without performing expensive cryptographic verification or decryption.
/// Useful for debugging, logging, middleware, and routing decisions.
///
/// # Example
///
/// ```rust,no_run
/// use paseto_pq::ParsedToken;
///
/// let token = "paseto.pq2.public.ABC123...";
/// let parsed = ParsedToken::parse(token)?;
///
/// println!("Purpose: {}", parsed.purpose()); // "public"
/// println!("Version: {}", parsed.version()); // "pq2"
/// println!("Has footer: {}", parsed.has_footer());
///
/// // Use for routing decisions
/// match parsed.purpose() {
///     "public" => println!("Public token - needs verification"),
///     "local" => println!("Local token - needs decryption"),
///     _ => println!("Unsupported token type"),
/// }
/// # Ok::<(), paseto_pq::PqPasetoError>(())
/// ```
#[derive(Debug, Clone)]
pub struct ParsedToken {
    purpose: String,
    version: String,
    payload: Vec<u8>,
    signature_or_tag: Option<Vec<u8>>, // For public tokens (signature) or local tokens (auth tag)
    footer: Option<Footer>,
    raw_token: String,
}

/// Token size breakdown showing individual components
///
/// This struct provides detailed information about how token size is distributed
/// across different components, useful for optimization and debugging.
#[derive(Debug, Clone)]
pub struct TokenSizeBreakdown {
    /// Size of the token prefix (e.g., "paseto.pq2.public")
    pub prefix: usize,
    /// Size of the base64-encoded payload
    pub payload: usize,
    /// Size of the base64-encoded signature (public) or auth tag (local)
    pub signature_or_tag: usize,
    /// Size of the base64-encoded footer (0 if no footer)
    pub footer: usize,
    /// Number of dot separators
    pub separators: usize,
    /// Approximate base64 encoding overhead percentage
    pub base64_overhead: f32,
}

/// Token size estimator for capacity planning
///
/// Use this to estimate token sizes before creating them, useful for:
/// - Ensuring tokens fit in cookies (4KB limit)
/// - URL length constraints
/// - HTTP header size limits
/// - Bandwidth optimization
#[derive(Debug, Clone)]
pub struct TokenSizeEstimator {
    breakdown: TokenSizeBreakdown,
}

/// Errors that can occur during token operations
#[derive(Debug, thiserror::Error)]
pub enum PqPasetoError {
    #[error("Invalid token format: {0}")]
    InvalidFormat(String),

    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    #[error("Token has expired")]
    TokenExpired,

    #[error("Token is not yet valid (nbf claim)")]
    TokenNotYetValid,

    #[error("Invalid audience: expected {expected}, got {actual}")]
    InvalidAudience { expected: String, actual: String },

    #[error("Invalid issuer: expected {expected}, got {actual}")]
    InvalidIssuer { expected: String, actual: String },

    #[error("CBOR serialization error: {0}")]
    SerializationError(String),

    #[error("Base64 decoding error: {0}")]
    Base64Error(#[from] base64::DecodeError),

    #[error("Time parsing error: {0}")]
    TimeError(#[from] time::error::ComponentRange),

    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Decryption error: {0}")]
    DecryptionError(String),

    #[error("Token parsing error: {0}")]
    TokenParsingError(String),
}

// CBOR serialization helper functions

/// Serialize a value to CBOR bytes
fn cbor_to_vec<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, PqPasetoError> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf)
        .map_err(|e| PqPasetoError::SerializationError(e.to_string()))?;
    Ok(buf)
}

/// Deserialize a value from CBOR bytes
fn cbor_from_slice<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, PqPasetoError> {
    ciborium::from_reader(Cursor::new(bytes))
        .map_err(|e| PqPasetoError::SerializationError(e.to_string()))
}

/// Convert a serializable value to CborValue
fn value_to_cbor<T: Serialize + ?Sized>(value: &T) -> Result<CborValue, PqPasetoError> {
    // Serialize to bytes, then deserialize as CborValue
    let bytes = cbor_to_vec(value)?;
    cbor_from_slice(&bytes)
}

// Constants for token formatting
//
// IMPORTANT: These prefixes use a non-standard versioning scheme!
// The "pq2" here indicates "post-quantum era" tokens with CBOR serialization,
// NOT the classical algorithms defined in the official PASETO specification.
//
// This creates intentional incompatibility with standard PASETO tooling
// to prevent accidental mixing of classical and post-quantum tokens.
//
// Version history:
// - pq1: Initial post-quantum tokens with JSON serialization (v0.1.x)
// - pq2: CBOR serialization for binary efficiency (v0.2.0+)

/// Token prefix for public (signature-based) post-quantum tokens
///
/// Uses `pq2` versioning to clearly distinguish from standard PASETO tokens
/// and indicate CBOR serialization format.
pub const TOKEN_PREFIX_PUBLIC: &str = "paseto.pq2.public";

/// Token prefix for local (symmetric encryption) post-quantum tokens
///
/// Uses `pq2` versioning to clearly distinguish from standard PASETO tokens
/// and indicate CBOR serialization format.
pub const TOKEN_PREFIX_LOCAL: &str = "paseto.pq2.local";

const MAX_TOKEN_SIZE: usize = 1024 * 1024; // 1MB max token size
const SYMMETRIC_KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;

impl KeyPair {
    /// Generate a new post-quantum key pair
    #[cfg_attr(feature = "logging", instrument(skip(rng)))]
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let keypair = MlDsaParam::key_gen(rng);

        #[cfg(feature = "logging")]
        debug!("Generated new ML-DSA key pair");

        Self {
            signing_key: SigningKey(keypair.signing_key().clone()),
            verifying_key: VerifyingKey(keypair.verifying_key().clone()),
        }
    }

    /// Get a reference to the signing key
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Get a reference to the verifying key
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Export the signing key as bytes (expanded form).
    ///
    /// Note: This uses the expanded key format. For new applications,
    /// consider storing the seed instead via `KeyPair::seed()`.
    #[allow(deprecated)]
    pub fn signing_key_to_bytes(&self) -> Vec<u8> {
        let expanded = self.signing_key.0.to_expanded();
        expanded.to_vec()
    }

    /// Import a signing key from bytes (expanded form).
    ///
    /// Note: This expects the expanded key format.
    #[allow(deprecated)]
    pub fn signing_key_from_bytes(bytes: &[u8]) -> Result<SigningKey, PqPasetoError> {
        use ml_dsa::ExpandedSigningKey;
        let expanded = ExpandedSigningKey::<MlDsaParam>::try_from(bytes).map_err(|e| {
            PqPasetoError::CryptoError(format!("Invalid signing key bytes: {:?}", e))
        })?;
        let sk = MlDsaSigningKey::<MlDsaParam>::from_expanded(&expanded);
        Ok(SigningKey(sk))
    }

    /// Create a full keypair from signing key bytes.
    ///
    /// This derives the verifying key from the signing key, which is useful
    /// when you only have the signing key stored and need to reconstruct
    /// the full keypair for verification operations.
    ///
    /// # Arguments
    /// * `signing_key_bytes` - The expanded signing key bytes
    ///
    /// # Returns
    /// A full `KeyPair` with both signing and verifying keys
    ///
    /// # Errors
    /// Returns `PqPasetoError::CryptoError` if the bytes are invalid
    #[allow(deprecated)]
    pub fn keypair_from_signing_key_bytes(signing_key_bytes: &[u8]) -> Result<Self, PqPasetoError> {
        use ml_dsa::ExpandedSigningKey;
        use ml_dsa::signature::Keypair as _;

        let expanded =
            ExpandedSigningKey::<MlDsaParam>::try_from(signing_key_bytes).map_err(|e| {
                PqPasetoError::CryptoError(format!("Invalid signing key bytes: {:?}", e))
            })?;
        let signing_key = MlDsaSigningKey::<MlDsaParam>::from_expanded(&expanded);
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            signing_key: SigningKey(signing_key),
            verifying_key: VerifyingKey(verifying_key),
        })
    }

    /// Export the verifying key as bytes
    pub fn verifying_key_to_bytes(&self) -> Vec<u8> {
        use ml_dsa::signature::digest::typenum::Unsigned;
        self.verifying_key.0.encode().to_vec()
    }

    /// Import a verifying key from bytes
    pub fn verifying_key_from_bytes(bytes: &[u8]) -> Result<VerifyingKey, PqPasetoError> {
        use ml_dsa::EncodedVerifyingKey;
        let encoded = EncodedVerifyingKey::<MlDsaParam>::try_from(bytes).map_err(|e| {
            PqPasetoError::CryptoError(format!("Invalid verifying key bytes: {:?}", e))
        })?;
        let vk = MlDsaVerifyingKey::<MlDsaParam>::decode(&encoded);
        Ok(VerifyingKey(vk))
    }
}

impl SymmetricKey {
    /// Generate a new random symmetric key
    #[cfg_attr(feature = "logging", instrument(skip(rng)))]
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let mut key = [0u8; SYMMETRIC_KEY_SIZE];
        rng.fill_bytes(&mut key);

        #[cfg(feature = "logging")]
        debug!("Generated new symmetric key");

        Self(key)
    }

    /// Create a symmetric key from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqPasetoError> {
        if bytes.len() != SYMMETRIC_KEY_SIZE {
            return Err(PqPasetoError::CryptoError(format!(
                "Invalid key size: expected {}, got {}",
                SYMMETRIC_KEY_SIZE,
                bytes.len()
            )));
        }
        let mut key = [0u8; SYMMETRIC_KEY_SIZE];
        key.copy_from_slice(bytes);
        Ok(Self(key))
    }

    /// Export the key as bytes
    pub fn to_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Derive a symmetric key from a shared secret using HKDF
    ///
    /// This provides cryptographically secure key derivation from ML-KEM shared secrets,
    /// using HKDF-SHA256 with proper domain separation.
    #[cfg_attr(feature = "logging", instrument(skip(shared_secret)))]
    pub fn derive_from_shared_secret(shared_secret: &[u8], info: &[u8]) -> Self {
        let hk = Hkdf::<Sha256>::new(None, shared_secret);
        let mut key = [0u8; SYMMETRIC_KEY_SIZE];
        // Use info as context for domain separation
        hk.expand(info, &mut key)
            .expect("HKDF expand should not fail with 32-byte output");
        Self(key)
    }
}

impl KemKeyPair {
    /// Generate a new ML-KEM key pair
    #[cfg_attr(feature = "logging", instrument(skip(_rng)))]
    pub fn generate<R: CryptoRng + RngCore>(_rng: &mut R) -> Self {
        let (dk, ek) = KemParam::generate(&mut AeadOsRng);

        #[cfg(feature = "logging")]
        debug!("Generated new ML-KEM key pair");

        Self {
            encapsulation_key: EncapsulationKey(ek),
            decapsulation_key: DecapsulationKey(dk),
        }
    }

    /// Export the encapsulation key as bytes
    pub fn encapsulation_key_to_bytes(&self) -> Vec<u8> {
        use ml_kem::EncodedSizeUser;
        self.encapsulation_key.0.as_bytes().to_vec()
    }

    /// Import an encapsulation key from bytes
    pub fn encapsulation_key_from_bytes(bytes: &[u8]) -> Result<EncapsulationKey, PqPasetoError> {
        use ml_kem::{EncodedSizeUser, array::Array};
        if bytes.len() != 1184 {
            return Err(PqPasetoError::CryptoError(format!(
                "Invalid encapsulation key size: expected 1184, got {}",
                bytes.len()
            )));
        }
        let array: Array<u8, _> = Array::try_from(bytes)
            .map_err(|_| PqPasetoError::CryptoError("Invalid key format".to_string()))?;
        let ek = <KemParam as KemCore>::EncapsulationKey::from_bytes(&array);
        Ok(EncapsulationKey(ek))
    }

    /// Export the decapsulation key as bytes
    pub fn decapsulation_key_to_bytes(&self) -> Vec<u8> {
        use ml_kem::EncodedSizeUser;
        self.decapsulation_key.0.as_bytes().to_vec()
    }

    /// Import a decapsulation key from bytes
    pub fn decapsulation_key_from_bytes(bytes: &[u8]) -> Result<DecapsulationKey, PqPasetoError> {
        use ml_kem::{EncodedSizeUser, array::Array};
        if bytes.len() != 2400 {
            return Err(PqPasetoError::CryptoError(format!(
                "Invalid decapsulation key size: expected 2400, got {}",
                bytes.len()
            )));
        }
        let array: Array<u8, _> = Array::try_from(bytes)
            .map_err(|_| PqPasetoError::CryptoError("Invalid key format".to_string()))?;
        let dk = <KemParam as KemCore>::DecapsulationKey::from_bytes(&array);
        Ok(DecapsulationKey(dk))
    }

    /// Encapsulate: generate a shared secret and ciphertext using the encapsulation key
    pub fn encapsulate(encapsulation_key: &EncapsulationKey) -> (Vec<u8>, Vec<u8>) {
        let (ciphertext, shared_secret) = encapsulation_key.0.encapsulate(&mut AeadOsRng).unwrap();
        (
            shared_secret.as_slice().to_vec(),
            ciphertext.as_slice().to_vec(),
        )
    }

    /// Decapsulate: recover shared secret from ciphertext using the decapsulation key
    pub fn decapsulate(
        decapsulation_key: &DecapsulationKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, PqPasetoError> {
        use ml_kem::array::Array;
        if ciphertext.len() != 1088 {
            return Err(PqPasetoError::CryptoError(format!(
                "Invalid ciphertext size: expected 1088, got {}",
                ciphertext.len()
            )));
        }
        let ct_array: Array<u8, _> = Array::try_from(ciphertext)
            .map_err(|_| PqPasetoError::CryptoError("Invalid ciphertext format".to_string()))?;
        let ct = ml_kem::Ciphertext::<KemParam>::from(ct_array);
        let shared_secret = decapsulation_key
            .0
            .decapsulate(&ct)
            .map_err(|_| PqPasetoError::CryptoError("Decapsulation failed".to_string()))?;
        Ok(shared_secret.as_slice().to_vec())
    }
}

impl Claims {
    /// Create a new empty claims set
    pub fn new() -> Self {
        Self {
            iss: None,
            sub: None,
            aud: None,
            exp: None,
            nbf: None,
            iat: None,
            jti: None,
            kid: None,
            custom: HashMap::new(),
        }
    }

    /// Set the issuer claim
    pub fn set_issuer(&mut self, issuer: &str) -> Result<(), PqPasetoError> {
        self.iss = Some(issuer.to_string());
        Ok(())
    }

    /// Set the subject claim
    pub fn set_subject(&mut self, subject: &str) -> Result<(), PqPasetoError> {
        self.sub = Some(subject.to_string());
        Ok(())
    }

    /// Set the audience claim
    pub fn set_audience(&mut self, audience: &str) -> Result<(), PqPasetoError> {
        self.aud = Some(audience.to_string());
        Ok(())
    }

    /// Set the expiration time
    pub fn set_expiration(&mut self, expiration: OffsetDateTime) -> Result<(), PqPasetoError> {
        self.exp = Some(expiration.unix_timestamp());
        Ok(())
    }

    /// Set the not-before time
    pub fn set_not_before(&mut self, not_before: OffsetDateTime) -> Result<(), PqPasetoError> {
        self.nbf = Some(not_before.unix_timestamp());
        Ok(())
    }

    /// Set the issued-at time
    pub fn set_issued_at(&mut self, issued_at: OffsetDateTime) -> Result<(), PqPasetoError> {
        self.iat = Some(issued_at.unix_timestamp());
        Ok(())
    }

    /// Set the token identifier (jti)
    pub fn set_jti(&mut self, jti: &str) -> Result<(), PqPasetoError> {
        self.jti = Some(jti.to_string());
        Ok(())
    }

    /// Set the key identifier
    pub fn set_kid(&mut self, kid: &str) -> Result<(), PqPasetoError> {
        self.kid = Some(kid.to_string());
        Ok(())
    }

    /// Add a custom claim
    pub fn add_custom<T: Serialize + ?Sized>(
        &mut self,
        key: &str,
        value: &T,
    ) -> Result<(), PqPasetoError> {
        let cbor_value = value_to_cbor(value)?;
        self.custom.insert(key.to_string(), cbor_value);
        Ok(())
    }

    /// Get a custom claim
    pub fn get_custom(&self, key: &str) -> Option<&CborValue> {
        self.custom.get(key)
    }

    /// Validate time-based claims
    pub fn validate_time(
        &self,
        now: OffsetDateTime,
        clock_skew: time::Duration,
    ) -> Result<(), PqPasetoError> {
        let now_ts = now.unix_timestamp();
        let skew_secs = clock_skew.whole_seconds();

        // Check expiration
        if let Some(exp) = self.exp {
            if now_ts > exp + skew_secs {
                return Err(PqPasetoError::TokenExpired);
            }
        }

        // Check not-before
        if let Some(nbf) = self.nbf {
            if now_ts < nbf - skew_secs {
                return Err(PqPasetoError::TokenNotYetValid);
            }
        }

        Ok(())
    }

    /// Get the issuer
    pub fn issuer(&self) -> Option<&str> {
        self.iss.as_deref()
    }
    /// Get the subject
    pub fn subject(&self) -> Option<&str> {
        self.sub.as_deref()
    }
    /// Get the audience
    pub fn audience(&self) -> Option<&str> {
        self.aud.as_deref()
    }
    /// Get the expiration as OffsetDateTime
    pub fn expiration(&self) -> Option<OffsetDateTime> {
        self.exp
            .and_then(|ts| OffsetDateTime::from_unix_timestamp(ts).ok())
    }
    /// Get the not-before as OffsetDateTime
    pub fn not_before(&self) -> Option<OffsetDateTime> {
        self.nbf
            .and_then(|ts| OffsetDateTime::from_unix_timestamp(ts).ok())
    }
    /// Get the issued-at as OffsetDateTime
    pub fn issued_at(&self) -> Option<OffsetDateTime> {
        self.iat
            .and_then(|ts| OffsetDateTime::from_unix_timestamp(ts).ok())
    }
    /// Get the token identifier
    pub fn jti(&self) -> Option<&str> {
        self.jti.as_deref()
    }
    /// Get the key identifier
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    /// Serialize claims to CBOR bytes
    ///
    /// This method provides direct access to the CBOR representation of claims,
    /// useful for logging, debugging, or custom storage.
    pub fn to_cbor_bytes(&self) -> Result<Vec<u8>, PqPasetoError> {
        cbor_to_vec(self)
    }

    /// Deserialize claims from CBOR bytes
    pub fn from_cbor_bytes(bytes: &[u8]) -> Result<Self, PqPasetoError> {
        cbor_from_slice(bytes)
    }

    /// Convert claims to a CborValue for inspection
    pub fn to_cbor_value(&self) -> Result<CborValue, PqPasetoError> {
        value_to_cbor(self)
    }
}

impl Default for Claims {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenSizeBreakdown {
    /// Calculate total token size
    pub fn total(&self) -> usize {
        self.prefix + self.payload + self.signature_or_tag + self.footer + self.separators
    }
}

impl TokenSizeEstimator {
    /// Estimate the size of a public token
    ///
    /// # Arguments
    /// * `claims` - The claims to be included in the token
    /// * `footer` - Optional footer metadata
    ///
    /// # Returns
    /// A `TokenSizeEstimator` with size breakdown information
    pub fn public(claims: &Claims, footer: Option<&Footer>) -> Result<Self, PqPasetoError> {
        // Serialize claims to CBOR to get actual size
        let payload_bytes = cbor_to_vec(claims)?;
        let payload_b64_len = base64_encoded_len(payload_bytes.len());

        // ML-DSA signature sizes vary by parameter set
        #[cfg(feature = "ml-dsa-44")]
        let signature_size = 2420;
        #[cfg(feature = "ml-dsa-65")]
        let signature_size = 3309;
        #[cfg(feature = "ml-dsa-87")]
        let signature_size = 4627;

        let signature_b64_len = base64_encoded_len(signature_size);

        let footer_b64_len = if let Some(f) = footer {
            let footer_bytes = cbor_to_vec(f)?;
            base64_encoded_len(footer_bytes.len())
        } else {
            0
        };

        let separators = if footer.is_some() { 4 } else { 3 };

        let raw_size = payload_bytes.len() + signature_size;
        let encoded_size = payload_b64_len + signature_b64_len;
        let base64_overhead = ((encoded_size as f32 / raw_size as f32) - 1.0) * 100.0;

        Ok(Self {
            breakdown: TokenSizeBreakdown {
                prefix: TOKEN_PREFIX_PUBLIC.len(),
                payload: payload_b64_len,
                signature_or_tag: signature_b64_len,
                footer: footer_b64_len,
                separators,
                base64_overhead,
            },
        })
    }

    /// Estimate the size of a local (encrypted) token
    ///
    /// # Arguments
    /// * `claims` - The claims to be included in the token
    /// * `footer` - Optional footer metadata
    ///
    /// # Returns
    /// A `TokenSizeEstimator` with size breakdown information
    pub fn local(claims: &Claims, footer: Option<&Footer>) -> Result<Self, PqPasetoError> {
        // Serialize claims to CBOR to get actual size
        let payload_bytes = cbor_to_vec(claims)?;
        // Encrypted payload = nonce (12) + ciphertext (same as plaintext) + tag (16)
        let encrypted_len = NONCE_SIZE + payload_bytes.len() + 16;
        let payload_b64_len = base64_encoded_len(encrypted_len);

        let footer_b64_len = if let Some(f) = footer {
            let footer_bytes = cbor_to_vec(f)?;
            base64_encoded_len(footer_bytes.len())
        } else {
            0
        };

        let separators = if footer.is_some() { 2 } else { 1 };

        let raw_size = encrypted_len;
        let base64_overhead = ((payload_b64_len as f32 / raw_size as f32) - 1.0) * 100.0;

        Ok(Self {
            breakdown: TokenSizeBreakdown {
                prefix: TOKEN_PREFIX_LOCAL.len(),
                payload: payload_b64_len,
                signature_or_tag: 0, // Included in payload for local tokens
                footer: footer_b64_len,
                separators,
                base64_overhead,
            },
        })
    }

    /// Get total estimated token size in bytes
    pub fn total_bytes(&self) -> usize {
        self.breakdown.total()
    }

    /// Check if token fits in a typical browser cookie (4KB)
    pub fn fits_in_cookie(&self) -> bool {
        self.total_bytes() <= 4096
    }

    /// Check if token fits in a reasonable URL (2KB recommended max)
    pub fn fits_in_url(&self) -> bool {
        self.total_bytes() <= 2048
    }

    /// Check if token fits in typical HTTP header limits (8KB)
    pub fn fits_in_header(&self) -> bool {
        self.total_bytes() <= 8192
    }

    /// Get detailed breakdown
    pub fn breakdown(&self) -> &TokenSizeBreakdown {
        &self.breakdown
    }

    /// Get optimization suggestions based on token size
    pub fn optimization_suggestions(&self) -> Vec<String> {
        let mut suggestions = Vec::new();
        let total = self.total_bytes();

        if total > 4096 {
            suggestions.push(
                "Token exceeds cookie size limit (4KB). Consider reducing custom claims.".into(),
            );
        }

        if self.breakdown.footer > 100 {
            suggestions.push(
                "Large footer detected. Consider moving metadata to claims or external storage."
                    .into(),
            );
        }

        if !self.fits_in_url() {
            suggestions.push(
                "Token too large for URL parameters. Use Authorization header instead.".into(),
            );
        }

        if suggestions.is_empty() {
            suggestions.push("Token size is within recommended limits.".into());
        }

        suggestions
    }

    /// Compare estimated size to JWT equivalent (rough estimate)
    pub fn compare_to_jwt(&self) -> String {
        // JWT with RSA-2048 signature is roughly 300-500 bytes for header+signature
        // Our ML-DSA signatures are much larger
        let jwt_estimate = self.breakdown.payload + 400; // Rough JWT estimate
        let pq_size = self.total_bytes();

        format!(
            "PQ-PASETO: {} bytes, Estimated JWT: {} bytes (PQ is {}x larger due to post-quantum signatures)",
            pq_size,
            jwt_estimate,
            pq_size / jwt_estimate.max(1)
        )
    }

    /// Get a summary string
    pub fn size_summary(&self) -> String {
        format!(
            "Total: {} bytes (prefix: {}, payload: {}, sig/tag: {}, footer: {}, separators: {})",
            self.total_bytes(),
            self.breakdown.prefix,
            self.breakdown.payload,
            self.breakdown.signature_or_tag,
            self.breakdown.footer,
            self.breakdown.separators
        )
    }
}

/// Calculate base64url encoded length (no padding)
fn base64_encoded_len(input_len: usize) -> usize {
    // Base64 expands 3 bytes to 4 characters, no padding
    (input_len * 4 + 2) / 3
}

impl ParsedToken {
    /// Parse a token string without cryptographic verification
    ///
    /// This is useful for:
    /// - Inspecting token metadata before verification
    /// - Routing decisions based on token type
    /// - Debugging and logging
    /// - Checking token format validity
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use paseto_pq::ParsedToken;
    ///
    /// let token = "paseto.pq2.public.ABC123...";
    /// let parsed = ParsedToken::parse(token)?;
    ///
    /// if parsed.is_public() {
    ///     println!("This is a public token");
    /// }
    /// # Ok::<(), paseto_pq::PqPasetoError>(())
    /// ```
    pub fn parse(token: &str) -> Result<Self, PqPasetoError> {
        if token.len() > MAX_TOKEN_SIZE {
            return Err(PqPasetoError::TokenParsingError("Token too large".into()));
        }

        // Split into parts
        let parts: Vec<&str> = token.split('.').collect();

        if parts.len() < 4 {
            return Err(PqPasetoError::TokenParsingError(
                "Token must have at least 4 parts".into(),
            ));
        }

        if parts[0] != "paseto" {
            return Err(PqPasetoError::TokenParsingError(
                "Token must start with 'paseto'".into(),
            ));
        }

        let version = parts[1].to_string();
        if version != "pq2" {
            return Err(PqPasetoError::TokenParsingError(format!(
                "Unsupported version: {} (expected 'pq2')",
                version
            )));
        }

        let purpose = parts[2].to_string();

        match purpose.as_str() {
            "public" => {
                // Public token: paseto.pq2.public.payload.signature[.footer]
                if parts.len() < 5 {
                    return Err(PqPasetoError::TokenParsingError(
                        "Public token must have at least 5 parts".into(),
                    ));
                }

                let payload = URL_SAFE_NO_PAD.decode(parts[3]).map_err(|e| {
                    PqPasetoError::TokenParsingError(format!("Invalid payload: {}", e))
                })?;

                let signature = URL_SAFE_NO_PAD.decode(parts[4]).map_err(|e| {
                    PqPasetoError::TokenParsingError(format!("Invalid signature: {}", e))
                })?;

                let footer = if parts.len() > 5 {
                    Some(Footer::from_base64(parts[5])?)
                } else {
                    None
                };

                Ok(Self {
                    purpose,
                    version,
                    payload,
                    signature_or_tag: Some(signature),
                    footer,
                    raw_token: token.to_string(),
                })
            }
            "local" => {
                // Local token: paseto.pq2.local.encrypted_payload[.footer]
                let payload = URL_SAFE_NO_PAD.decode(parts[3]).map_err(|e| {
                    PqPasetoError::TokenParsingError(format!("Invalid payload: {}", e))
                })?;

                let footer = if parts.len() > 4 {
                    Some(Footer::from_base64(parts[4])?)
                } else {
                    None
                };

                Ok(Self {
                    purpose,
                    version,
                    payload,
                    signature_or_tag: None,
                    footer,
                    raw_token: token.to_string(),
                })
            }
            _ => Err(PqPasetoError::TokenParsingError(format!(
                "Unknown purpose: {}",
                purpose
            ))),
        }
    }

    /// Get the token purpose ("public" or "local")
    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    /// Get the token version
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Check if token has a footer
    pub fn has_footer(&self) -> bool {
        self.footer.is_some()
    }

    /// Get the footer if present
    pub fn footer(&self) -> Option<&Footer> {
        self.footer.as_ref()
    }

    /// Get raw payload bytes
    pub fn payload_bytes(&self) -> &[u8] {
        &self.payload
    }

    /// Get signature bytes (for public tokens)
    pub fn signature_bytes(&self) -> Option<&[u8]> {
        self.signature_or_tag.as_deref()
    }

    /// Get payload length
    pub fn payload_length(&self) -> usize {
        self.payload.len()
    }

    /// Get total token length
    pub fn total_length(&self) -> usize {
        self.raw_token.len()
    }

    /// Get raw token string
    pub fn raw_token(&self) -> &str {
        &self.raw_token
    }

    /// Deserialize footer to CBOR value for inspection
    pub fn footer_cbor(&self) -> Option<Result<CborValue, PqPasetoError>> {
        self.footer.as_ref().map(|f| value_to_cbor(f))
    }

    /// Check if this is a public token
    pub fn is_public(&self) -> bool {
        self.purpose == "public"
    }

    /// Check if this is a local token
    pub fn is_local(&self) -> bool {
        self.purpose == "local"
    }

    /// Format a human-readable summary
    pub fn format_summary(&self) -> String {
        format!(
            "PASETO Token:\n  Version: {}\n  Purpose: {}\n  Payload: {} bytes\n  Has Footer: {}\n  Total Length: {} bytes",
            self.version,
            self.purpose,
            self.payload.len(),
            self.has_footer(),
            self.raw_token.len()
        )
    }
}

impl VerifiedToken {
    /// Get the verified claims
    pub fn claims(&self) -> &Claims {
        &self.claims
    }

    /// Get the footer if present
    pub fn footer(&self) -> Option<&Footer> {
        self.footer.as_ref()
    }

    /// Get the raw token string
    pub fn raw_token(&self) -> &str {
        &self.raw_token
    }

    /// Consume and return the claims
    pub fn into_claims(self) -> Claims {
        self.claims
    }

    /// Consume and return all parts
    pub fn into_parts(self) -> (Claims, Option<Footer>, String) {
        (self.claims, self.footer, self.raw_token)
    }
}

impl PasetoPQ {
    /// Get the public token prefix
    ///
    /// Returns "paseto.pq2.public" for CBOR-serialized post-quantum tokens.
    pub fn public_token_prefix() -> &'static str {
        TOKEN_PREFIX_PUBLIC
    }

    /// Get the local token prefix
    ///
    /// Returns "paseto.pq2.local" for CBOR-serialized post-quantum tokens.
    pub fn local_token_prefix() -> &'static str {
        TOKEN_PREFIX_LOCAL
    }

    /// Check if this implementation uses standard PASETO format
    ///
    /// Always returns `false` - this is a post-quantum variant with CBOR.
    pub fn is_standard_paseto_compatible() -> bool {
        false
    }

    /// Parse a token without cryptographic operations
    ///
    /// Useful for inspecting token metadata, routing, or debugging.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use paseto_pq::PasetoPQ;
    ///
    /// let token = "paseto.pq2.public.ABC123...";
    /// let parsed = PasetoPQ::parse_token(token)?;
    ///
    /// println!("Token purpose: {}", parsed.purpose());
    /// println!("Has footer: {}", parsed.has_footer());
    /// # Ok::<(), paseto_pq::PqPasetoError>(())
    /// ```
    pub fn parse_token(token: &str) -> Result<ParsedToken, PqPasetoError> {
        ParsedToken::parse(token)
    }

    /// Estimate public token size before creation
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use paseto_pq::{PasetoPQ, Claims};
    ///
    /// let mut claims = Claims::new();
    /// claims.set_subject("user123").unwrap();
    ///
    /// let estimator = PasetoPQ::estimate_public_size(&claims, None)?;
    /// println!("Estimated size: {} bytes", estimator.total_bytes());
    /// println!("Fits in cookie: {}", estimator.fits_in_cookie());
    /// # Ok::<(), paseto_pq::PqPasetoError>(())
    /// ```
    pub fn estimate_public_size(
        claims: &Claims,
        footer: Option<&Footer>,
    ) -> Result<TokenSizeEstimator, PqPasetoError> {
        TokenSizeEstimator::public(claims, footer)
    }

    /// Estimate local token size before creation
    pub fn estimate_local_size(
        claims: &Claims,
        footer: Option<&Footer>,
    ) -> Result<TokenSizeEstimator, PqPasetoError> {
        TokenSizeEstimator::local(claims, footer)
    }

    /// Sign claims to create a new public token
    pub fn sign(signing_key: &SigningKey, claims: &Claims) -> Result<String, PqPasetoError> {
        Self::sign_with_footer(signing_key, claims, None)
    }

    /// Sign claims with optional footer to create a new public token
    #[cfg_attr(feature = "logging", instrument(skip(signing_key)))]
    pub fn sign_with_footer(
        signing_key: &SigningKey,
        claims: &Claims,
        footer: Option<&Footer>,
    ) -> Result<String, PqPasetoError> {
        // Serialize claims to CBOR bytes (not base64 for PAE)
        let payload_bytes = cbor_to_vec(claims)?;

        #[cfg(feature = "logging")]
        debug!("Serialized claims to {} CBOR bytes", payload_bytes.len());

        // Serialize footer to CBOR bytes (empty if None)
        let footer_bytes = match footer {
            Some(f) => cbor_to_vec(f)?,
            None => Vec::new(), // Empty bytes for no footer
        };

        // Create PAE message for signing (RFC Section 2.2.1)
        // PAE([header, payload_bytes, footer_bytes])
        let header = TOKEN_PREFIX_PUBLIC.as_bytes();
        let pae_message =
            crate::pae::pae_encode_public_token(header, &payload_bytes, &footer_bytes);

        #[cfg(feature = "logging")]
        debug!(
            "Created PAE message of {} bytes for signing",
            pae_message.len()
        );

        // Sign the PAE-encoded message with ML-DSA
        let signature = signing_key.0.sign(&pae_message);
        let signature_bytes = signature.to_bytes();

        // Base64url encode components for token construction
        let encoded_payload = URL_SAFE_NO_PAD.encode(&payload_bytes);
        let encoded_signature = URL_SAFE_NO_PAD.encode(signature_bytes);

        // Construct final token with optional footer
        let token = match footer {
            Some(f) => {
                let footer_b64 = f.to_base64()?;
                format!(
                    "{}.{}.{}.{}",
                    TOKEN_PREFIX_PUBLIC, encoded_payload, encoded_signature, footer_b64
                )
            }
            None => format!(
                "{}.{}.{}",
                TOKEN_PREFIX_PUBLIC, encoded_payload, encoded_signature
            ),
        };

        #[cfg(feature = "logging")]
        debug!(
            "Generated pq2 CBOR token with {} byte signature{}",
            signature_bytes.len(),
            if footer.is_some() { " with footer" } else { "" }
        );

        Ok(token)
    }

    /// Encrypt claims to create a new local token
    #[cfg_attr(feature = "logging", instrument(skip(symmetric_key)))]
    pub fn encrypt(symmetric_key: &SymmetricKey, claims: &Claims) -> Result<String, PqPasetoError> {
        Self::encrypt_with_footer(symmetric_key, claims, None)
    }

    /// Encrypt claims with optional footer to create a new local token
    #[cfg_attr(feature = "logging", instrument(skip(symmetric_key)))]
    pub fn encrypt_with_footer(
        symmetric_key: &SymmetricKey,
        claims: &Claims,
        footer: Option<&Footer>,
    ) -> Result<String, PqPasetoError> {
        // Serialize claims to CBOR bytes
        let payload_bytes = cbor_to_vec(claims)?;

        #[cfg(feature = "logging")]
        debug!("Serialized claims to {} CBOR bytes", payload_bytes.len());

        // Create cipher
        let mut cipher = ChaCha20Poly1305::new((&symmetric_key.0).into());

        // Generate random nonce
        let nonce = ChaCha20Poly1305::generate_nonce(&mut AeadOsRng);

        // Serialize footer to CBOR bytes (empty if None)
        let footer_bytes = match footer {
            Some(f) => cbor_to_vec(f)?,
            None => Vec::new(), // Empty bytes for no footer
        };

        // Create PAE-encoded AAD for footer authentication (RFC Section 2.2.1)
        // PAE([header, nonce_bytes, footer_bytes])
        let header = TOKEN_PREFIX_LOCAL.as_bytes();
        let nonce_bytes = nonce.as_slice();
        let aad = crate::pae::pae_encode_local_token(header, nonce_bytes, &footer_bytes);

        #[cfg(feature = "logging")]
        debug!(
            "Created PAE AAD of {} bytes for footer authentication",
            aad.len()
        );

        // Encrypt with authenticated additional data
        let mut buffer = payload_bytes.clone();
        let tag = cipher
            .encrypt_in_place_detached(&nonce, &aad, &mut buffer)
            .map_err(|e| PqPasetoError::EncryptionError(e.to_string()))?;

        // Combine nonce + ciphertext + tag
        let mut encrypted_data = Vec::with_capacity(NONCE_SIZE + buffer.len() + 16);
        encrypted_data.extend_from_slice(nonce.as_slice());
        encrypted_data.extend_from_slice(&buffer);
        encrypted_data.extend_from_slice(tag.as_slice());

        // Base64url encode
        let encoded_payload = URL_SAFE_NO_PAD.encode(&encrypted_data);

        // Construct final token with optional footer
        let token = match footer {
            Some(f) => {
                let footer_b64 = f.to_base64()?;
                format!("{}.{}.{}", TOKEN_PREFIX_LOCAL, encoded_payload, footer_b64)
            }
            None => format!("{}.{}", TOKEN_PREFIX_LOCAL, encoded_payload),
        };

        #[cfg(feature = "logging")]
        debug!(
            "Generated pq2 CBOR encrypted token{}",
            if footer.is_some() { " with footer" } else { "" }
        );

        Ok(token)
    }

    /// Decrypt a local token and extract claims
    pub fn decrypt(
        symmetric_key: &SymmetricKey,
        token: &str,
    ) -> Result<VerifiedToken, PqPasetoError> {
        Self::decrypt_with_footer(symmetric_key, token)
    }

    /// Decrypt a local token with footer support and extract claims
    #[cfg_attr(feature = "logging", instrument(skip(symmetric_key)))]
    pub fn decrypt_with_footer(
        symmetric_key: &SymmetricKey,
        token: &str,
    ) -> Result<VerifiedToken, PqPasetoError> {
        // Basic size check
        if token.len() > MAX_TOKEN_SIZE {
            return Err(PqPasetoError::InvalidFormat("Token too large".into()));
        }

        // Split token into parts (4 parts without footer, 5 parts with footer)
        let parts: Vec<&str> = token.splitn(5, '.').collect();
        let (encoded_payload, footer) = if parts.len() == 5 {
            // Token with footer: paseto.pq2.local.payload.footer
            if parts[0] != "paseto" || parts[1] != "pq2" || parts[2] != "local" {
                return Err(PqPasetoError::InvalidFormat(
                    "Invalid token format - expected 'paseto.pq2.local'".into(),
                ));
            }
            let footer = Footer::from_base64(parts[4])?;
            (parts[3], Some(footer))
        } else if parts.len() == 4 {
            // Token without footer: paseto.pq2.local.payload
            if parts[0] != "paseto" || parts[1] != "pq2" || parts[2] != "local" {
                return Err(PqPasetoError::InvalidFormat(
                    "Invalid token format - expected 'paseto.pq2.local'".into(),
                ));
            }
            (parts[3], None)
        } else {
            return Err(PqPasetoError::InvalidFormat(
                "Expected 4 or 5 parts separated by '.' for local token".into(),
            ));
        };

        // Decode encrypted payload
        let encrypted_data = URL_SAFE_NO_PAD.decode(encoded_payload).map_err(|e| {
            PqPasetoError::InvalidFormat(format!("Invalid payload encoding: {}", e))
        })?;

        // Split nonce, ciphertext, and tag
        if encrypted_data.len() < NONCE_SIZE + 16 {
            return Err(PqPasetoError::DecryptionError(
                "Encrypted data too short for nonce and tag".into(),
            ));
        }

        let nonce = Nonce::from_slice(&encrypted_data[..NONCE_SIZE]);
        let ciphertext_with_tag = &encrypted_data[NONCE_SIZE..];

        // Split ciphertext and authentication tag (last 16 bytes)
        if ciphertext_with_tag.len() < 16 {
            return Err(PqPasetoError::DecryptionError(
                "Encrypted data too short for authentication tag".into(),
            ));
        }

        let tag_start = ciphertext_with_tag.len() - 16;
        let mut ciphertext = ciphertext_with_tag[..tag_start].to_vec();
        let tag = &ciphertext_with_tag[tag_start..];

        // Serialize footer to CBOR bytes (empty if None)
        let footer_bytes = match &footer {
            Some(f) => cbor_to_vec(f)?,
            None => Vec::new(), // Empty bytes for no footer
        };

        // Reconstruct PAE-encoded AAD for footer validation
        // PAE([header, nonce_bytes, footer_bytes])
        let header = TOKEN_PREFIX_LOCAL.as_bytes();
        let nonce_bytes = nonce.as_slice();
        let aad = crate::pae::pae_encode_local_token(header, nonce_bytes, &footer_bytes);

        #[cfg(feature = "logging")]
        debug!(
            "Reconstructed PAE AAD of {} bytes for footer validation",
            aad.len()
        );

        // Create cipher and decrypt with PAE AAD (footer tampering now detected!)
        let mut cipher = ChaCha20Poly1305::new((&symmetric_key.0).into());

        // Convert tag slice to GenericArray
        use chacha20poly1305::aead::generic_array::GenericArray;
        let tag_array = GenericArray::from_slice(tag);

        let payload_bytes = cipher
            .decrypt_in_place_detached(nonce, &aad, &mut ciphertext, tag_array)
            .map_err(|e| {
                PqPasetoError::DecryptionError(format!(
                    "Decryption failed (footer authentication failed): {}",
                    e
                ))
            })
            .map(|_| ciphertext)?;

        #[cfg(feature = "logging")]
        debug!("pq2 CBOR decryption successful with footer authentication");

        // Parse claims from CBOR
        let claims: Claims = cbor_from_slice(&payload_bytes)?;

        // Basic time validation (with default 30s clock skew tolerance)
        claims.validate_time(OffsetDateTime::now_utc(), time::Duration::seconds(30))?;

        Ok(VerifiedToken {
            claims,
            footer,
            raw_token: token.to_string(),
        })
    }

    /// Decrypt a local token with custom validation options
    pub fn decrypt_with_options(
        symmetric_key: &SymmetricKey,
        token: &str,
        expected_audience: Option<&str>,
        expected_issuer: Option<&str>,
    ) -> Result<VerifiedToken, PqPasetoError> {
        let verified = Self::decrypt_with_footer(symmetric_key, token)?;

        // Validate audience if specified
        if let Some(expected) = expected_audience {
            match verified.claims.audience() {
                Some(actual) if actual == expected => {}
                Some(actual) => {
                    return Err(PqPasetoError::InvalidAudience {
                        expected: expected.to_string(),
                        actual: actual.to_string(),
                    });
                }
                None => {
                    return Err(PqPasetoError::InvalidAudience {
                        expected: expected.to_string(),
                        actual: "(none)".to_string(),
                    });
                }
            }
        }

        // Validate issuer if specified
        if let Some(expected) = expected_issuer {
            match verified.claims.issuer() {
                Some(actual) if actual == expected => {}
                Some(actual) => {
                    return Err(PqPasetoError::InvalidIssuer {
                        expected: expected.to_string(),
                        actual: actual.to_string(),
                    });
                }
                None => {
                    return Err(PqPasetoError::InvalidIssuer {
                        expected: expected.to_string(),
                        actual: "(none)".to_string(),
                    });
                }
            }
        }

        Ok(verified)
    }

    /// Verify a token and extract claims
    pub fn verify(
        verifying_key: &VerifyingKey,
        token: &str,
    ) -> Result<VerifiedToken, PqPasetoError> {
        Self::verify_with_footer(verifying_key, token)
    }

    /// Verify a token with footer support and extract claims
    #[cfg_attr(feature = "logging", instrument(skip(verifying_key)))]
    pub fn verify_with_footer(
        verifying_key: &VerifyingKey,
        token: &str,
    ) -> Result<VerifiedToken, PqPasetoError> {
        // Basic size check
        if token.len() > MAX_TOKEN_SIZE {
            return Err(PqPasetoError::InvalidFormat("Token too large".into()));
        }

        // Split token into parts (5 parts without footer, 6 parts with footer)
        let parts: Vec<&str> = token.splitn(6, '.').collect();
        let (encoded_payload, encoded_signature, footer) = if parts.len() == 6 {
            // Token with footer: paseto.pq2.public.payload.signature.footer
            if parts[0] != "paseto" || parts[1] != "pq2" || parts[2] != "public" {
                return Err(PqPasetoError::InvalidFormat(
                    "Invalid token format - expected 'paseto.pq2.public'".into(),
                ));
            }
            let footer = Footer::from_base64(parts[5])?;
            (parts[3], parts[4], Some(footer))
        } else if parts.len() == 5 {
            // Token without footer: paseto.pq2.public.payload.signature
            if parts[0] != "paseto" || parts[1] != "pq2" || parts[2] != "public" {
                return Err(PqPasetoError::InvalidFormat(
                    "Invalid token format - expected 'paseto.pq2.public'".into(),
                ));
            }
            (parts[3], parts[4], None)
        } else {
            return Err(PqPasetoError::InvalidFormat(
                "Expected 5 or 6 parts separated by '.' for public token".into(),
            ));
        };

        // Decode payload bytes
        let payload_bytes = URL_SAFE_NO_PAD.decode(encoded_payload).map_err(|e| {
            PqPasetoError::InvalidFormat(format!("Invalid payload encoding: {}", e))
        })?;

        // Serialize footer to bytes for PAE (empty if None)
        let footer_bytes = match &footer {
            Some(f) => cbor_to_vec(f)?,
            None => Vec::new(), // Empty bytes for no footer
        };

        // Reconstruct PAE message that was signed
        // PAE([header, payload_bytes, footer_bytes])
        let header = TOKEN_PREFIX_PUBLIC.as_bytes();
        let pae_message =
            crate::pae::pae_encode_public_token(header, &payload_bytes, &footer_bytes);

        #[cfg(feature = "logging")]
        debug!(
            "Reconstructed PAE message of {} bytes for verification",
            pae_message.len()
        );

        // Decode signature
        let signature_bytes = URL_SAFE_NO_PAD.decode(encoded_signature).map_err(|e| {
            PqPasetoError::InvalidFormat(format!("Invalid signature encoding: {}", e))
        })?;

        // Reconstruct signature
        let encoded_sig = ml_dsa::EncodedSignature::<MlDsaParam>::try_from(
            signature_bytes.as_slice(),
        )
        .map_err(|e| PqPasetoError::CryptoError(format!("Invalid signature bytes: {:?}", e)))?;
        let signature = MlDsaSignature::<MlDsaParam>::decode(&encoded_sig)
            .ok_or_else(|| PqPasetoError::CryptoError("Failed to decode signature".into()))?;

        // Verify signature against PAE message (footer tampering now detected!)
        verifying_key
            .0
            .verify(&pae_message, &signature)
            .map_err(|_| PqPasetoError::SignatureVerificationFailed)?;

        #[cfg(feature = "logging")]
        debug!("pq2 CBOR signature verification successful with footer authentication");

        // Parse claims from CBOR
        let claims: Claims = cbor_from_slice(&payload_bytes)?;

        // Basic time validation (with default 30s clock skew tolerance)
        claims.validate_time(OffsetDateTime::now_utc(), time::Duration::seconds(30))?;

        Ok(VerifiedToken {
            claims,
            footer,
            raw_token: token.to_string(),
        })
    }

    /// Verify a token with custom validation options
    pub fn verify_with_options(
        verifying_key: &VerifyingKey,
        token: &str,
        expected_audience: Option<&str>,
        expected_issuer: Option<&str>,
    ) -> Result<VerifiedToken, PqPasetoError> {
        let verified = Self::verify_with_footer(verifying_key, token)?;

        // Validate audience if specified
        if let Some(expected) = expected_audience {
            match verified.claims.audience() {
                Some(actual) if actual == expected => {}
                Some(actual) => {
                    return Err(PqPasetoError::InvalidAudience {
                        expected: expected.to_string(),
                        actual: actual.to_string(),
                    });
                }
                None => {
                    return Err(PqPasetoError::InvalidAudience {
                        expected: expected.to_string(),
                        actual: "(none)".to_string(),
                    });
                }
            }
        }

        // Validate issuer if specified
        if let Some(expected) = expected_issuer {
            match verified.claims.issuer() {
                Some(actual) if actual == expected => {}
                Some(actual) => {
                    return Err(PqPasetoError::InvalidIssuer {
                        expected: expected.to_string(),
                        actual: actual.to_string(),
                    });
                }
                None => {
                    return Err(PqPasetoError::InvalidIssuer {
                        expected: expected.to_string(),
                        actual: "(none)".to_string(),
                    });
                }
            }
        }

        Ok(verified)
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("type", &"ML-DSA")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifyingKey")
            .field("type", &"ML-DSA")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyPair")
            .field("signing_key", &self.signing_key)
            .field("verifying_key", &self.verifying_key)
            .finish()
    }
}

impl fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SymmetricKey")
            .field("size", &32)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for EncapsulationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncapsulationKey")
            .field("type", &"ML-KEM-768")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for DecapsulationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecapsulationKey")
            .field("type", &"ML-KEM-768")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for KemKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KemKeyPair")
            .field("encapsulation_key", &self.encapsulation_key)
            .field("decapsulation_key", &self.decapsulation_key)
            .finish()
    }
}

// Zeroization on drop for security-sensitive types

impl Drop for SigningKey {
    fn drop(&mut self) {
        // ML-DSA signing key is already zeroized by the library
        // (when built with the zeroize feature)
    }
}

impl Drop for VerifyingKey {
    fn drop(&mut self) {
        // Verifying keys are public, no zeroization needed
    }
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        // Individual keys handle their own cleanup
    }
}

impl Drop for EncapsulationKey {
    fn drop(&mut self) {
        // Encapsulation keys are public, no zeroization needed
    }
}

impl Drop for DecapsulationKey {
    fn drop(&mut self) {
        // ML-KEM decapsulation key is already zeroized by the library
        // (when built with the zeroize feature)
    }
}

impl Drop for KemKeyPair {
    fn drop(&mut self) {
        // Individual keys handle their own cleanup
    }
}

impl Drop for SymmetricKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Duration;

    fn create_test_keypair() -> KeyPair {
        let mut rng = rand::rng();
        KeyPair::generate(&mut rng)
    }

    fn create_test_symmetric_key() -> SymmetricKey {
        let mut rng = rand::rng();
        SymmetricKey::generate(&mut rng)
    }

    #[test]
    fn test_keypair_generation() {
        let keypair = create_test_keypair();

        // Test that we can export and reimport keys
        let sk_bytes = keypair.signing_key_to_bytes();
        let vk_bytes = keypair.verifying_key_to_bytes();

        assert!(!sk_bytes.is_empty());
        assert!(!vk_bytes.is_empty());

        // Reimport keys
        let sk = KeyPair::signing_key_from_bytes(&sk_bytes).unwrap();
        let vk = KeyPair::verifying_key_from_bytes(&vk_bytes).unwrap();

        // Create a test token with reimported keys
        let mut claims = Claims::new();
        claims.set_subject("test").unwrap();
        claims
            .set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))
            .unwrap();

        let token = PasetoPQ::sign(&sk, &claims).unwrap();
        let verified = PasetoPQ::verify(&vk, &token).unwrap();
        assert_eq!(verified.claims().subject(), Some("test"));
    }

    #[test]
    fn test_basic_sign_and_verify() {
        let keypair = create_test_keypair();

        let mut claims = Claims::new();
        claims.set_subject("user123").unwrap();
        claims.set_issuer("test-issuer").unwrap();
        claims.set_audience("test-audience").unwrap();
        claims
            .set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))
            .unwrap();
        claims.add_custom("role", "admin").unwrap();

        let token = PasetoPQ::sign(keypair.signing_key(), &claims).unwrap();

        // Verify token starts with correct prefix
        assert!(token.starts_with("paseto.pq2.public."));

        let verified = PasetoPQ::verify(keypair.verifying_key(), &token).unwrap();
        assert_eq!(verified.claims().subject(), Some("user123"));
        assert_eq!(verified.claims().issuer(), Some("test-issuer"));
        assert_eq!(verified.claims().audience(), Some("test-audience"));
    }

    #[test]
    fn test_time_validation() {
        let keypair = create_test_keypair();

        // Test expired token
        let mut expired_claims = Claims::new();
        expired_claims.set_subject("expired").unwrap();
        expired_claims
            .set_expiration(OffsetDateTime::now_utc() - Duration::hours(1))
            .unwrap();

        let expired_token = PasetoPQ::sign(keypair.signing_key(), &expired_claims).unwrap();
        let result = PasetoPQ::verify(keypair.verifying_key(), &expired_token);
        assert!(matches!(result, Err(PqPasetoError::TokenExpired)));

        // Test not-yet-valid token
        let mut future_claims = Claims::new();
        future_claims.set_subject("future").unwrap();
        future_claims
            .set_not_before(OffsetDateTime::now_utc() + Duration::hours(1))
            .unwrap();
        future_claims
            .set_expiration(OffsetDateTime::now_utc() + Duration::hours(2))
            .unwrap();

        let future_token = PasetoPQ::sign(keypair.signing_key(), &future_claims).unwrap();
        let result = PasetoPQ::verify(keypair.verifying_key(), &future_token);
        assert!(matches!(result, Err(PqPasetoError::TokenNotYetValid)));
    }

    #[test]
    fn test_audience_and_issuer_validation() {
        let keypair = create_test_keypair();

        let mut claims = Claims::new();
        claims.set_subject("user").unwrap();
        claims.set_issuer("my-service").unwrap();
        claims.set_audience("my-api").unwrap();
        claims
            .set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))
            .unwrap();

        let token = PasetoPQ::sign(keypair.signing_key(), &claims).unwrap();

        // Valid audience and issuer
        let result = PasetoPQ::verify_with_options(
            keypair.verifying_key(),
            &token,
            Some("my-api"),
            Some("my-service"),
        );
        assert!(result.is_ok());

        // Invalid audience
        let result =
            PasetoPQ::verify_with_options(keypair.verifying_key(), &token, Some("wrong-api"), None);
        assert!(matches!(result, Err(PqPasetoError::InvalidAudience { .. })));

        // Invalid issuer
        let result = PasetoPQ::verify_with_options(
            keypair.verifying_key(),
            &token,
            None,
            Some("wrong-issuer"),
        );
        assert!(matches!(result, Err(PqPasetoError::InvalidIssuer { .. })));
    }

    #[test]
    fn test_signature_verification_failure() {
        let keypair1 = create_test_keypair();
        let keypair2 = create_test_keypair();

        let mut claims = Claims::new();
        claims.set_subject("test").unwrap();
        claims
            .set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))
            .unwrap();

        let token = PasetoPQ::sign(keypair1.signing_key(), &claims).unwrap();

        // Verify with wrong key should fail
        let result = PasetoPQ::verify(keypair2.verifying_key(), &token);
        assert!(matches!(
            result,
            Err(PqPasetoError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn test_malformed_tokens() {
        let keypair = create_test_keypair();

        // Too few parts
        let result = PasetoPQ::verify(keypair.verifying_key(), "paseto.pq2.public");
        assert!(matches!(result, Err(PqPasetoError::InvalidFormat(_))));

        // Wrong prefix
        let result = PasetoPQ::verify(keypair.verifying_key(), "paseto.v4.public.payload.sig");
        assert!(matches!(result, Err(PqPasetoError::InvalidFormat(_))));

        // Invalid base64
        let result = PasetoPQ::verify(keypair.verifying_key(), "paseto.pq2.public.!!!.sig");
        assert!(matches!(result, Err(PqPasetoError::InvalidFormat(_))));
    }

    #[test]
    fn test_symmetric_key_generation() {
        let key = create_test_symmetric_key();
        assert_eq!(key.to_bytes().len(), 32);

        // Test from_bytes
        let key2 = SymmetricKey::from_bytes(key.to_bytes()).unwrap();
        assert_eq!(key.to_bytes(), key2.to_bytes());
    }

    #[test]
    fn test_kem_keypair_generation() {
        let mut rng = rand::rng();
        let keypair = KemKeyPair::generate(&mut rng);

        // Test encapsulation and decapsulation
        let (shared_secret1, ciphertext) = KemKeyPair::encapsulate(&keypair.encapsulation_key);
        let shared_secret2 =
            KemKeyPair::decapsulate(&keypair.decapsulation_key, &ciphertext).unwrap();

        assert_eq!(shared_secret1, shared_secret2);
    }

    #[test]
    fn test_basic_encrypt_and_decrypt() {
        let key = create_test_symmetric_key();

        let mut claims = Claims::new();
        claims.set_subject("user123").unwrap();
        claims.set_issuer("test-issuer").unwrap();
        claims.set_audience("test-audience").unwrap();
        claims
            .set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))
            .unwrap();
        claims.add_custom("role", "admin").unwrap();

        let token = PasetoPQ::encrypt(&key, &claims).unwrap();

        // Verify token starts with correct prefix
        assert!(token.starts_with("paseto.pq2.local."));

        let verified = PasetoPQ::decrypt(&key, &token).unwrap();
        assert_eq!(verified.claims().subject(), Some("user123"));
        assert_eq!(verified.claims().issuer(), Some("test-issuer"));
        assert_eq!(verified.claims().audience(), Some("test-audience"));
    }

    #[test]
    fn test_local_token_time_validation() {
        let key = create_test_symmetric_key();

        // Test expired token
        let mut expired_claims = Claims::new();
        expired_claims.set_subject("expired").unwrap();
        expired_claims
            .set_expiration(OffsetDateTime::now_utc() - Duration::hours(1))
            .unwrap();

        let expired_token = PasetoPQ::encrypt(&key, &expired_claims).unwrap();
        let result = PasetoPQ::decrypt(&key, &expired_token);
        assert!(matches!(result, Err(PqPasetoError::TokenExpired)));

        // Test not-yet-valid token
        let mut future_claims = Claims::new();
        future_claims.set_subject("future").unwrap();
        future_claims
            .set_not_before(OffsetDateTime::now_utc() + Duration::hours(1))
            .unwrap();
        future_claims
            .set_expiration(OffsetDateTime::now_utc() + Duration::hours(2))
            .unwrap();

        let future_token = PasetoPQ::encrypt(&key, &future_claims).unwrap();
        let result = PasetoPQ::decrypt(&key, &future_token);
        assert!(matches!(result, Err(PqPasetoError::TokenNotYetValid)));
    }

    #[test]
    fn test_local_token_audience_and_issuer_validation() {
        let key = create_test_symmetric_key();

        let mut claims = Claims::new();
        claims.set_subject("user").unwrap();
        claims.set_issuer("my-service").unwrap();
        claims.set_audience("my-api").unwrap();
        claims
            .set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))
            .unwrap();

        let token = PasetoPQ::encrypt(&key, &claims).unwrap();

        // Valid audience and issuer
        let result =
            PasetoPQ::decrypt_with_options(&key, &token, Some("my-api"), Some("my-service"));
        assert!(result.is_ok());

        // Invalid audience
        let result = PasetoPQ::decrypt_with_options(&key, &token, Some("wrong-api"), None);
        assert!(matches!(result, Err(PqPasetoError::InvalidAudience { .. })));

        // Invalid issuer
        let result = PasetoPQ::decrypt_with_options(&key, &token, None, Some("wrong-issuer"));
        assert!(matches!(result, Err(PqPasetoError::InvalidIssuer { .. })));
    }

    #[test]
    fn test_local_token_tamper_detection() {
        let key = create_test_symmetric_key();

        let mut claims = Claims::new();
        claims.set_subject("user").unwrap();
        claims
            .set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))
            .unwrap();

        let token = PasetoPQ::encrypt(&key, &claims).unwrap();

        // Tamper with payload
        let parts: Vec<&str> = token.split('.').collect();
        let tampered = format!(
            "{}.{}.{}.{}",
            parts[0], parts[1], parts[2], "tampered_payload"
        );

        let result = PasetoPQ::decrypt(&key, &tampered);
        assert!(result.is_err());
    }

    #[test]
    fn test_malformed_local_tokens() {
        let key = create_test_symmetric_key();

        // Too few parts
        let result = PasetoPQ::decrypt(&key, "paseto.pq2.local");
        assert!(matches!(result, Err(PqPasetoError::InvalidFormat(_))));

        // Wrong prefix
        let result = PasetoPQ::decrypt(&key, "paseto.v4.local.payload");
        assert!(matches!(result, Err(PqPasetoError::InvalidFormat(_))));
    }

    #[test]
    fn test_mixed_token_types() {
        let keypair = create_test_keypair();
        let sym_key = create_test_symmetric_key();

        let mut claims = Claims::new();
        claims.set_subject("test").unwrap();
        claims
            .set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))
            .unwrap();

        let public_token = PasetoPQ::sign(keypair.signing_key(), &claims).unwrap();
        let local_token = PasetoPQ::encrypt(&sym_key, &claims).unwrap();

        // Try to decrypt a public token (should fail)
        let result = PasetoPQ::decrypt(&sym_key, &public_token);
        assert!(matches!(result, Err(PqPasetoError::InvalidFormat(_))));

        // Try to verify a local token (should fail)
        let result = PasetoPQ::verify(keypair.verifying_key(), &local_token);
        assert!(matches!(result, Err(PqPasetoError::InvalidFormat(_))));
    }

    #[test]
    fn test_footer_basic_functionality() {
        let mut footer = Footer::new();
        footer.set_kid("key-123").unwrap();
        footer.set_version("1.0").unwrap();
        footer.set_issuer_meta("meta-data").unwrap();
        footer.add_custom("custom_field", "custom_value").unwrap();

        assert_eq!(footer.kid(), Some("key-123"));
        assert_eq!(footer.version(), Some("1.0"));
        assert_eq!(footer.issuer_meta(), Some("meta-data"));
        assert!(footer.get_custom("custom_field").is_some());
    }

    #[test]
    fn test_public_token_with_footer() {
        let keypair = create_test_keypair();

        let mut claims = Claims::new();
        claims.set_subject("user123").unwrap();
        claims
            .set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))
            .unwrap();

        let mut footer = Footer::new();
        footer.set_kid("key-abc").unwrap();
        footer.set_version("1.0.0").unwrap();
        footer.add_custom("region", "us-east").unwrap();

        let token =
            PasetoPQ::sign_with_footer(keypair.signing_key(), &claims, Some(&footer)).unwrap();

        // Token should have 6 parts with footer
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 6);

        let verified = PasetoPQ::verify_with_footer(keypair.verifying_key(), &token).unwrap();
        assert_eq!(verified.claims().subject(), Some("user123"));
        assert!(verified.footer().is_some());
        let verified_footer = verified.footer().unwrap();
        assert_eq!(verified_footer.kid(), Some("key-abc"));
        assert_eq!(verified_footer.version(), Some("1.0.0"));
    }

    #[test]
    fn test_local_token_with_footer() {
        let key = create_test_symmetric_key();

        let mut claims = Claims::new();
        claims.set_subject("user123").unwrap();
        claims
            .set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))
            .unwrap();

        let mut footer = Footer::new();
        footer.set_kid("key-xyz").unwrap();
        footer.set_version("2.0.0").unwrap();

        let token = PasetoPQ::encrypt_with_footer(&key, &claims, Some(&footer)).unwrap();

        // Token should have 5 parts with footer
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 5);

        let verified = PasetoPQ::decrypt_with_footer(&key, &token).unwrap();
        assert_eq!(verified.claims().subject(), Some("user123"));
        assert!(verified.footer().is_some());
        let verified_footer = verified.footer().unwrap();
        assert_eq!(verified_footer.kid(), Some("key-xyz"));
        assert_eq!(verified_footer.version(), Some("2.0.0"));
    }

    #[test]
    fn test_footer_serialization() {
        let mut footer = Footer::new();
        footer.set_kid("test-kid").unwrap();
        footer.set_version("1.0").unwrap();
        footer.add_custom("num", &42i32).unwrap();

        let b64 = footer.to_base64().unwrap();
        let decoded = Footer::from_base64(&b64).unwrap();

        assert_eq!(decoded.kid(), Some("test-kid"));
        assert_eq!(decoded.version(), Some("1.0"));
    }

    #[test]
    fn test_footer_tamper_detection() {
        let keypair = create_test_keypair();

        let mut claims = Claims::new();
        claims.set_subject("user").unwrap();
        claims
            .set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))
            .unwrap();

        let mut footer = Footer::new();
        footer.set_kid("original-key").unwrap();

        let token =
            PasetoPQ::sign_with_footer(keypair.signing_key(), &claims, Some(&footer)).unwrap();

        // Tamper with footer
        let parts: Vec<&str> = token.split('.').collect();
        let mut tampered_footer = Footer::new();
        tampered_footer.set_kid("tampered-key").unwrap();
        let tampered_footer_b64 = tampered_footer.to_base64().unwrap();

        let tampered_token = format!(
            "{}.{}.{}.{}.{}.{}",
            parts[0], parts[1], parts[2], parts[3], parts[4], tampered_footer_b64
        );

        let result = PasetoPQ::verify(keypair.verifying_key(), &tampered_token);
        assert!(matches!(
            result,
            Err(PqPasetoError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn test_backward_compatibility_rejection() {
        // Tokens with pq1 prefix should be rejected
        let keypair = create_test_keypair();

        // Old format token (pq1)
        let old_token = "paseto.pq1.public.payload.signature";
        let result = PasetoPQ::verify(keypair.verifying_key(), old_token);
        assert!(matches!(result, Err(PqPasetoError::InvalidFormat(_))));

        let key = create_test_symmetric_key();
        let old_local = "paseto.pq1.local.payload";
        let result = PasetoPQ::decrypt(&key, old_local);
        assert!(matches!(result, Err(PqPasetoError::InvalidFormat(_))));
    }

    #[test]
    fn test_claims_cbor_conversion() {
        let mut claims = Claims::new();
        claims.set_subject("user123").unwrap();
        claims.set_issuer("test-issuer").unwrap();
        claims.add_custom("role", "admin").unwrap();
        claims
            .add_custom("permissions", &vec!["read", "write"])
            .unwrap();

        // Convert to CBOR bytes
        let cbor_bytes = claims.to_cbor_bytes().unwrap();
        assert!(!cbor_bytes.is_empty());

        // Convert back
        let decoded = Claims::from_cbor_bytes(&cbor_bytes).unwrap();
        assert_eq!(decoded.subject(), Some("user123"));
        assert_eq!(decoded.issuer(), Some("test-issuer"));
    }

    #[test]
    fn test_claims_with_time_fields() {
        let mut claims = Claims::new();
        let now = OffsetDateTime::now_utc();
        let exp = now + Duration::hours(1);
        let nbf = now - Duration::minutes(5);

        claims.set_issued_at(now).unwrap();
        claims.set_expiration(exp).unwrap();
        claims.set_not_before(nbf).unwrap();

        // Verify timestamps are stored correctly
        assert!(claims.iat.is_some());
        assert!(claims.exp.is_some());
        assert!(claims.nbf.is_some());

        // Verify we can get them back as OffsetDateTime
        let iat = claims.issued_at().unwrap();
        let exp_back = claims.expiration().unwrap();
        let nbf_back = claims.not_before().unwrap();

        // Timestamps should be within 1 second (due to precision)
        assert!((iat.unix_timestamp() - now.unix_timestamp()).abs() <= 1);
        assert!((exp_back.unix_timestamp() - exp.unix_timestamp()).abs() <= 1);
        assert!((nbf_back.unix_timestamp() - nbf.unix_timestamp()).abs() <= 1);
    }

    #[test]
    fn test_token_parsing_public_tokens() {
        let keypair = create_test_keypair();

        let mut claims = Claims::new();
        claims.set_subject("user123").unwrap();
        claims
            .set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))
            .unwrap();

        let token = PasetoPQ::sign(keypair.signing_key(), &claims).unwrap();
        let parsed = ParsedToken::parse(&token).unwrap();

        assert_eq!(parsed.purpose(), "public");
        assert_eq!(parsed.version(), "pq2");
        assert!(parsed.is_public());
        assert!(!parsed.is_local());
        assert!(!parsed.has_footer());
    }

    #[test]
    fn test_token_parsing_public_tokens_with_footer() {
        let keypair = create_test_keypair();

        let mut claims = Claims::new();
        claims.set_subject("user123").unwrap();
        claims
            .set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))
            .unwrap();

        let mut footer = Footer::new();
        footer.set_kid("test-key").unwrap();

        let token =
            PasetoPQ::sign_with_footer(keypair.signing_key(), &claims, Some(&footer)).unwrap();
        let parsed = ParsedToken::parse(&token).unwrap();

        assert_eq!(parsed.purpose(), "public");
        assert_eq!(parsed.version(), "pq2");
        assert!(parsed.has_footer());
        assert_eq!(parsed.footer().unwrap().kid(), Some("test-key"));
    }

    #[test]
    fn test_token_parsing_local_tokens() {
        let key = create_test_symmetric_key();

        let mut claims = Claims::new();
        claims.set_subject("user123").unwrap();
        claims
            .set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))
            .unwrap();

        let token = PasetoPQ::encrypt(&key, &claims).unwrap();
        let parsed = ParsedToken::parse(&token).unwrap();

        assert_eq!(parsed.purpose(), "local");
        assert_eq!(parsed.version(), "pq2");
        assert!(parsed.is_local());
        assert!(!parsed.is_public());
        assert!(!parsed.has_footer());
    }

    #[test]
    fn test_token_parsing_local_tokens_with_footer() {
        let key = create_test_symmetric_key();

        let mut claims = Claims::new();
        claims.set_subject("user123").unwrap();
        claims
            .set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))
            .unwrap();

        let mut footer = Footer::new();
        footer.set_kid("encryption-key").unwrap();

        let token = PasetoPQ::encrypt_with_footer(&key, &claims, Some(&footer)).unwrap();
        let parsed = ParsedToken::parse(&token).unwrap();

        assert_eq!(parsed.purpose(), "local");
        assert!(parsed.has_footer());
        assert_eq!(parsed.footer().unwrap().kid(), Some("encryption-key"));
    }

    #[test]
    fn test_token_parsing_error_cases() {
        // Empty token
        let result = ParsedToken::parse("");
        assert!(result.is_err());

        // Invalid prefix
        let result = ParsedToken::parse("jwt.v1.public.payload");
        assert!(result.is_err());

        // Wrong version
        let result = ParsedToken::parse("paseto.pq1.public.payload.sig");
        assert!(matches!(result, Err(PqPasetoError::TokenParsingError(_))));

        // Unknown purpose
        let result = ParsedToken::parse("paseto.pq2.secret.payload");
        assert!(matches!(result, Err(PqPasetoError::TokenParsingError(_))));
    }

    #[test]
    fn test_token_size_estimation_public_tokens() {
        let mut claims = Claims::new();
        claims.set_subject("user123").unwrap();
        claims.set_issuer("test-issuer").unwrap();
        claims.set_audience("test-audience").unwrap();
        claims
            .set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))
            .unwrap();

        let estimator = TokenSizeEstimator::public(&claims, None).unwrap();

        // Basic sanity checks
        assert!(estimator.total_bytes() > 0);
        assert!(estimator.breakdown().prefix == TOKEN_PREFIX_PUBLIC.len());
        assert!(estimator.breakdown().payload > 0);
        assert!(estimator.breakdown().signature_or_tag > 0);
        assert!(estimator.breakdown().footer == 0);

        // Actually create the token and compare
        let keypair = create_test_keypair();
        let token = PasetoPQ::sign(keypair.signing_key(), &claims).unwrap();

        // Estimation should be close (within 10% is reasonable for base64 variations)
        let actual_size = token.len();
        let estimated_size = estimator.total_bytes();
        let diff = (actual_size as i64 - estimated_size as i64).abs();
        assert!(
            diff < (estimated_size as i64 / 10),
            "Estimated {} but actual was {} (diff {})",
            estimated_size,
            actual_size,
            diff
        );
    }

    #[test]
    fn test_token_size_estimation_local_tokens() {
        let mut claims = Claims::new();
        claims.set_subject("user123").unwrap();
        claims
            .set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))
            .unwrap();

        let estimator = TokenSizeEstimator::local(&claims, None).unwrap();

        assert!(estimator.total_bytes() > 0);
        assert!(estimator.breakdown().prefix == TOKEN_PREFIX_LOCAL.len());

        let key = create_test_symmetric_key();
        let token = PasetoPQ::encrypt(&key, &claims).unwrap();

        let actual_size = token.len();
        let estimated_size = estimator.total_bytes();
        let diff = (actual_size as i64 - estimated_size as i64).abs();
        assert!(
            diff < (estimated_size as i64 / 10),
            "Estimated {} but actual was {} (diff {})",
            estimated_size,
            actual_size,
            diff
        );
    }

    #[test]
    fn test_token_size_estimation_with_footer() {
        let mut claims = Claims::new();
        claims.set_subject("user").unwrap();
        claims
            .set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))
            .unwrap();

        let mut footer = Footer::new();
        footer.set_kid("test-key-id").unwrap();
        footer.set_version("1.0.0").unwrap();

        let estimator = TokenSizeEstimator::public(&claims, Some(&footer)).unwrap();
        assert!(estimator.breakdown().footer > 0);
    }

    #[test]
    fn test_token_size_estimation_convenience_methods() {
        let mut claims = Claims::new();
        claims.set_subject("user").unwrap();
        claims
            .set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))
            .unwrap();

        let estimator = TokenSizeEstimator::public(&claims, None).unwrap();

        // These are basic tokens, should fit everywhere
        // Note: PQ tokens are much larger than classical tokens
        assert!(estimator.fits_in_header());
    }

    #[test]
    fn test_token_size_estimation_optimization_suggestions() {
        let mut claims = Claims::new();
        claims.set_subject("user").unwrap();
        claims
            .set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))
            .unwrap();

        let estimator = TokenSizeEstimator::public(&claims, None).unwrap();
        let suggestions = estimator.optimization_suggestions();

        assert!(!suggestions.is_empty());
    }

    #[test]
    fn test_token_size_breakdown_total() {
        let breakdown = TokenSizeBreakdown {
            prefix: 18,
            payload: 100,
            signature_or_tag: 3000,
            footer: 50,
            separators: 4,
            base64_overhead: 33.0,
        };

        assert_eq!(breakdown.total(), 18 + 100 + 3000 + 50 + 4);
    }

    #[test]
    fn test_token_parsing_debugging_methods() {
        let keypair = create_test_keypair();

        let mut claims = Claims::new();
        claims.set_subject("test").unwrap();
        claims
            .set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))
            .unwrap();

        let token = PasetoPQ::sign(keypair.signing_key(), &claims).unwrap();
        let parsed = ParsedToken::parse(&token).unwrap();

        let summary = parsed.format_summary();
        assert!(summary.contains("pq2"));
        assert!(summary.contains("public"));
    }

    #[test]
    fn test_symmetric_key_zeroization() {
        let key = create_test_symmetric_key();
        let key_bytes = key.to_bytes().to_vec();

        // After drop, internal key should be zeroized
        // (We can't actually verify this without unsafe code,
        // but the test ensures the Drop impl runs without panic)
        drop(key);

        // Just verify we got valid key bytes before drop
        assert_eq!(key_bytes.len(), 32);
    }

    #[test]
    fn test_key_operations_with_drop_cleanup() {
        // Create keys in a scope to test drop
        {
            let _keypair = create_test_keypair();
            let _sym_key = create_test_symmetric_key();
            let mut rng = rand::rng();
            let _kem_keypair = KemKeyPair::generate(&mut rng);
        }
        // Keys should be dropped and zeroized without panic
    }

    #[test]
    fn test_token_versioning_configuration() {
        assert_eq!(PasetoPQ::public_token_prefix(), "paseto.pq2.public");
        assert_eq!(PasetoPQ::local_token_prefix(), "paseto.pq2.local");
        assert!(!PasetoPQ::is_standard_paseto_compatible());
    }

    #[test]
    fn test_actual_token_contains_correct_prefix() {
        let keypair = create_test_keypair();
        let sym_key = create_test_symmetric_key();

        let mut claims = Claims::new();
        claims.set_subject("test").unwrap();
        claims
            .set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))
            .unwrap();

        let public_token = PasetoPQ::sign(keypair.signing_key(), &claims).unwrap();
        let local_token = PasetoPQ::encrypt(&sym_key, &claims).unwrap();

        assert!(
            public_token.starts_with("paseto.pq2.public."),
            "Public token should start with paseto.pq2.public."
        );
        assert!(
            local_token.starts_with("paseto.pq2.local."),
            "Local token should start with paseto.pq2.local."
        );
    }

    #[test]
    fn test_hkdf_implementation() {
        let shared_secret = [0x42u8; 32];
        let info = b"test-context";

        let key1 = SymmetricKey::derive_from_shared_secret(&shared_secret, info);
        let key2 = SymmetricKey::derive_from_shared_secret(&shared_secret, info);

        // Same inputs should produce same key
        assert_eq!(key1.to_bytes(), key2.to_bytes());

        // Different context should produce different key
        let key3 = SymmetricKey::derive_from_shared_secret(&shared_secret, b"different-context");
        assert_ne!(key1.to_bytes(), key3.to_bytes());

        // Different secret should produce different key
        let different_secret = [0x43u8; 32];
        let key4 = SymmetricKey::derive_from_shared_secret(&different_secret, info);
        assert_ne!(key1.to_bytes(), key4.to_bytes());
    }

    #[test]
    fn test_footer_authentication_security() {
        let keypair = create_test_keypair();

        let mut claims = Claims::new();
        claims.set_subject("secure-user").unwrap();
        claims
            .set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))
            .unwrap();

        let mut footer = Footer::new();
        footer.set_kid("key-v1").unwrap();
        footer.set_version("1.0").unwrap();
        footer.add_custom("tenant", "acme").unwrap();

        let token =
            PasetoPQ::sign_with_footer(keypair.signing_key(), &claims, Some(&footer)).unwrap();

        // Verify original works
        let verified = PasetoPQ::verify(keypair.verifying_key(), &token).unwrap();
        assert!(verified.footer().is_some());
        assert_eq!(verified.footer().unwrap().kid(), Some("key-v1"));

        // Now try to tamper with footer
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 6, "Token with footer should have 6 parts");

        // Create tampered footer
        let mut tampered_footer = Footer::new();
        tampered_footer.set_kid("tampered-key").unwrap();
        tampered_footer.set_version("evil").unwrap();
        let tampered_b64 = tampered_footer.to_base64().unwrap();

        // Reconstruct token with tampered footer
        let tampered_token = format!(
            "{}.{}.{}.{}.{}.{}",
            parts[0], parts[1], parts[2], parts[3], parts[4], tampered_b64
        );

        // Should fail signature verification
        let result = PasetoPQ::verify(keypair.verifying_key(), &tampered_token);
        assert!(
            matches!(result, Err(PqPasetoError::SignatureVerificationFailed)),
            "Footer tampering should be detected"
        );
    }

    #[test]
    fn test_pae_integration() {
        let keypair = create_test_keypair();
        let sym_key = create_test_symmetric_key();

        let mut claims = Claims::new();
        claims.set_subject("pae-test").unwrap();
        claims
            .set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))
            .unwrap();

        let mut footer = Footer::new();
        footer.set_kid("pae-key").unwrap();

        // Test public token with footer
        let public_token =
            PasetoPQ::sign_with_footer(keypair.signing_key(), &claims, Some(&footer)).unwrap();
        let verified_public = PasetoPQ::verify(keypair.verifying_key(), &public_token).unwrap();
        assert_eq!(verified_public.footer().unwrap().kid(), Some("pae-key"));

        // Test local token with footer
        let local_token = PasetoPQ::encrypt_with_footer(&sym_key, &claims, Some(&footer)).unwrap();
        let verified_local = PasetoPQ::decrypt(&sym_key, &local_token).unwrap();
        assert_eq!(verified_local.footer().unwrap().kid(), Some("pae-key"));
    }

    #[test]
    fn test_security_improvements() {
        let keypair = create_test_keypair();
        let sym_key = create_test_symmetric_key();

        let mut claims = Claims::new();
        claims.set_subject("security-test").unwrap();
        claims
            .set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))
            .unwrap();

        let mut footer = Footer::new();
        footer.set_kid("secure-key-id").unwrap();

        // Create tokens with footers
        let public_token =
            PasetoPQ::sign_with_footer(keypair.signing_key(), &claims, Some(&footer)).unwrap();
        let local_token = PasetoPQ::encrypt_with_footer(&sym_key, &claims, Some(&footer)).unwrap();

        // Verify tokens have correct structure
        assert!(public_token.starts_with("paseto.pq2.public."));
        assert!(local_token.starts_with("paseto.pq2.local."));

        // Verify footer tampering is detected for both token types
        let public_parts: Vec<&str> = public_token.split('.').collect();
        let local_parts: Vec<&str> = local_token.split('.').collect();

        let mut bad_footer = Footer::new();
        bad_footer.set_kid("evil-key").unwrap();
        let bad_footer_b64 = bad_footer.to_base64().unwrap();

        let tampered_public = format!(
            "{}.{}.{}.{}.{}.{}",
            public_parts[0],
            public_parts[1],
            public_parts[2],
            public_parts[3],
            public_parts[4],
            bad_footer_b64
        );

        let tampered_local = format!(
            "{}.{}.{}.{}.{}",
            local_parts[0], local_parts[1], local_parts[2], local_parts[3], bad_footer_b64
        );

        // Both should fail due to footer tampering
        assert!(matches!(
            PasetoPQ::verify(keypair.verifying_key(), &tampered_public),
            Err(PqPasetoError::SignatureVerificationFailed)
        ));

        assert!(matches!(
            PasetoPQ::decrypt(&sym_key, &tampered_local),
            Err(PqPasetoError::DecryptionError(_))
        ));
    }

    #[test]
    fn test_hkdf_vs_simple_hash_difference() {
        // Verify HKDF produces different output than simple hashing
        use sha2::{Digest, Sha256};

        let secret = [0x42u8; 32];
        let info = b"test-info";

        // HKDF derivation
        let hkdf_key = SymmetricKey::derive_from_shared_secret(&secret, info);

        // Simple hash (not what we use, but showing they're different)
        let mut hasher = Sha256::new();
        hasher.update(&secret);
        hasher.update(info);
        let simple_hash: [u8; 32] = hasher.finalize().into();

        // They should be different (HKDF is more secure)
        assert_ne!(hkdf_key.to_bytes(), &simple_hash);
    }

    #[test]
    fn test_cbor_is_more_compact_than_json() {
        let mut claims = Claims::new();
        claims.set_subject("user123").unwrap();
        claims.set_issuer("my-service").unwrap();
        claims.set_audience("my-api").unwrap();
        claims
            .set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))
            .unwrap();
        claims.add_custom("role", "admin").unwrap();
        claims
            .add_custom("permissions", &vec!["read", "write", "delete"])
            .unwrap();

        let cbor_bytes = claims.to_cbor_bytes().unwrap();

        // CBOR should produce reasonable-sized output
        // (actual comparison would require JSON serialization which we removed)
        assert!(!cbor_bytes.is_empty());
        assert!(cbor_bytes.len() < 500, "CBOR should be compact");
    }

    #[test]
    fn test_keypair_from_signing_key_bytes() {
        let original = create_test_keypair();
        let sk_bytes = original.signing_key_to_bytes();

        // Reconstruct full keypair from signing key bytes
        let reconstructed = KeyPair::keypair_from_signing_key_bytes(&sk_bytes).unwrap();

        // Verify both keys work together
        let mut claims = Claims::new();
        claims.set_subject("test").unwrap();
        claims
            .set_expiration(OffsetDateTime::now_utc() + Duration::hours(1))
            .unwrap();

        // Sign with reconstructed signing key
        let token = PasetoPQ::sign(reconstructed.signing_key(), &claims).unwrap();

        // Verify with both original and reconstructed verifying keys
        let verified1 = PasetoPQ::verify(original.verifying_key(), &token).unwrap();
        let verified2 = PasetoPQ::verify(reconstructed.verifying_key(), &token).unwrap();

        assert_eq!(verified1.claims().subject(), Some("test"));
        assert_eq!(verified2.claims().subject(), Some("test"));
    }
}
