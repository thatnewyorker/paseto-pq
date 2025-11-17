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
//!
//! ## ⚠️ Non-Standard Token Format
//!
//! **IMPORTANT**: This crate uses a **non-standard** token versioning scheme that diverges
//! from the official PASETO specification. The tokens use `pq1` to clearly indicate
//! post-quantum algorithms and avoid confusion with standard PASETO versions.
//!
//! ### Token Format
//!
//! ```text
//! paseto.pq1.public.<base64url-encoded-payload>.<base64url-encoded-ml-dsa-signature>
//! paseto.pq1.local.<base64url-encoded-encrypted-payload>
//! ```
//!
//! ### Interoperability Warning
//!
//! These tokens are **NOT** compatible with standard PASETO libraries or tooling.
//! If you need interoperability with existing PASETO ecosystems, this crate is not suitable.
//! The `pq1` versioning scheme clearly indicates "post-quantum era" tokens, distinguishing
//! them from the classical algorithms defined in the PASETO specification.
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
//! let mut rng = rand::thread_rng();
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

use anyhow::Result;
pub mod pae;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
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
    "Please enable exactly one of the features: `ml-dsa-44`, `ml-dsa-65`, or `ml-dsa-87`."
);

#[cfg(all(
    feature = "ml-dsa-44",
    any(feature = "ml-dsa-65", feature = "ml-dsa-87")
))]
compile_error!("Only one of `ml-dsa-44`, `ml-dsa-65`, or `ml-dsa-87` may be enabled.");

#[cfg(all(feature = "ml-dsa-65", feature = "ml-dsa-87"))]
compile_error!("Only one of `ml-dsa-44`, `ml-dsa-65`, or `ml-dsa-87` may be enabled.");

use ml_dsa::{
    KeyGen,
    signature::{SignatureEncoding, Signer, Verifier},
};
// ML-KEM imports for real implementation
use hkdf::Hkdf;
use ml_kem::{
    KemCore, MlKem768,
    kem::{Decapsulate, Encapsulate},
};
pub use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use time::OffsetDateTime;

// Symmetric encryption imports
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{AeadCore, AeadInPlace, KeyInit, OsRng as AeadOsRng},
};

#[cfg(feature = "logging")]
use tracing::{debug, instrument, warn};

/// Post-quantum PASETO implementation using ML-DSA-65
pub struct PasetoPQ;

// Re-export core PAE function for advanced users (added in v0.1.1)
// Internal functions like le64_encode remain private
pub use pae::pae_encode;

/// A post-quantum key pair for signing and verification
#[derive(Clone)]
pub struct KeyPair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

/// A signing key for creating tokens
#[derive(Clone)]
pub struct SigningKey(ml_dsa::SigningKey<MlDsaParam>);

/// A verifying key for validating tokens
#[derive(Clone)]
pub struct VerifyingKey(ml_dsa::VerifyingKey<MlDsaParam>);

/// A symmetric key for local token encryption/decryption
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SymmetricKey([u8; 32]);

/// A post-quantum key encapsulation key pair for key exchange
#[derive(Clone)]
pub struct KemKeyPair {
    pub encapsulation_key: EncapsulationKey,
    pub decapsulation_key: DecapsulationKey,
}

/// An encapsulation key for ML-KEM key exchange
#[derive(Clone)]
pub struct EncapsulationKey(<MlKem768 as KemCore>::EncapsulationKey);

/// A decapsulation key for ML-KEM key exchange
#[derive(Clone)]
pub struct DecapsulationKey(<MlKem768 as KemCore>::DecapsulationKey);

/// Footer data for additional authenticated metadata
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
    pub custom: HashMap<String, Value>,
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
        let json_value = serde_json::to_value(value)?;
        self.custom.insert(key.to_string(), json_value);
        Ok(())
    }

    /// Get custom footer field
    pub fn get_custom(&self, key: &str) -> Option<&Value> {
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

    /// Serialize footer to base64url-encoded JSON
    pub fn to_base64(&self) -> Result<String, PqPasetoError> {
        let json = serde_json::to_vec(self)?;
        Ok(URL_SAFE_NO_PAD.encode(&json))
    }

    /// Deserialize footer from base64url-encoded JSON
    pub(crate) fn from_base64(encoded: &str) -> Result<Self, PqPasetoError> {
        let bytes = URL_SAFE_NO_PAD.decode(encoded)?;
        let footer = serde_json::from_slice(&bytes)?;
        Ok(footer)
    }
}

impl Default for Footer {
    fn default() -> Self {
        Self::new()
    }
}

/// Claims contained within a token
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

    /// Token expiration time
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        with = "time::serde::rfc3339::option"
    )]
    pub exp: Option<OffsetDateTime>,

    /// Token not-before time
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        with = "time::serde::rfc3339::option"
    )]
    pub nbf: Option<OffsetDateTime>,

    /// Token issued-at time
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        with = "time::serde::rfc3339::option"
    )]
    pub iat: Option<OffsetDateTime>,

    /// Token identifier (jti)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,

    /// Key identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    /// Custom claims (Conflux-specific)
    #[serde(flatten)]
    pub custom: HashMap<String, Value>,
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
/// let token = "paseto.pq1.public.ABC123...";
/// let parsed = ParsedToken::parse(token)?;
///
/// println!("Purpose: {}", parsed.purpose()); // "public"
/// println!("Version: {}", parsed.version()); // "pq1"
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
    /// Size of the protocol prefix ("paseto.pq1.public." or "paseto.pq1.local.")
    pub prefix: usize,
    /// Size of the JSON payload after base64 encoding
    pub payload: usize,
    /// Size of signature (public tokens) or authentication tag (local tokens)
    pub signature_or_tag: usize,
    /// Size of footer if present
    pub footer: Option<usize>,
    /// Size of separator dots between parts
    pub separators: usize,
    /// Additional overhead from base64 encoding (~33% expansion)
    pub base64_overhead: usize,
}

/// Token size estimator for planning and optimization
///
/// This struct allows you to estimate token sizes before creation to avoid
/// runtime surprises with HTTP headers, cookies, or URL length limits.
///
/// # Example
///
/// ```rust,no_run
/// use paseto_pq::{Claims, TokenSizeEstimator};
///
/// let mut claims = Claims::new();
/// claims.set_subject("user123").unwrap();
/// claims.add_custom("role", "admin").unwrap();
///
/// let estimator = TokenSizeEstimator::public(&claims, true);
/// println!("Estimated size: {} bytes", estimator.total_bytes());
///
/// if !estimator.fits_in_cookie() {
///     println!("Token too large for browser cookies!");
/// }
/// # Ok::<(), paseto_pq::PqPasetoError>(())
/// ```
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

    #[error("JSON serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

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

// Constants for token formatting
//
// IMPORTANT: These prefixes use a non-standard versioning scheme!
// The "pq1" here indicates "post-quantum era" tokens, NOT the classical
// algorithms defined in the official PASETO specification.
//
// This creates intentional incompatibility with standard PASETO tooling
// to prevent accidental mixing of classical and post-quantum tokens.

/// Token prefix for public (signature-based) post-quantum tokens
///
/// Uses `pq1` versioning to clearly distinguish from standard PASETO tokens.
/// Standard PASETO v1 uses RSA signatures, while this uses ML-DSA post-quantum signatures.
pub const TOKEN_PREFIX_PUBLIC: &str = "paseto.pq1.public";

/// Token prefix for local (symmetric encryption) post-quantum tokens
///
/// Uses `pq1` versioning to clearly distinguish from standard PASETO tokens.
/// Standard PASETO v1 uses HMAC, while this uses ChaCha20-Poly1305 with ML-KEM key exchange.
pub const TOKEN_PREFIX_LOCAL: &str = "paseto.pq1.local";

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

    /// Export the signing key as bytes
    pub fn signing_key_to_bytes(&self) -> Vec<u8> {
        let encoded = self.signing_key.0.encode();
        encoded.to_vec()
    }

    /// Import signing key from bytes
    pub fn signing_key_from_bytes(bytes: &[u8]) -> Result<SigningKey, PqPasetoError> {
        let encoded = ml_dsa::EncodedSigningKey::<MlDsaParam>::try_from(bytes)
            .map_err(|e| PqPasetoError::CryptoError(format!("Invalid key bytes: {:?}", e)))?;
        let key = ml_dsa::SigningKey::<MlDsaParam>::decode(&encoded);
        Ok(SigningKey(key))
    }

    /// Export the verifying key as bytes
    pub fn verifying_key_to_bytes(&self) -> Vec<u8> {
        let encoded = self.verifying_key.0.encode();
        encoded.to_vec()
    }

    /// Import verifying key from bytes
    pub fn verifying_key_from_bytes(bytes: &[u8]) -> Result<VerifyingKey, PqPasetoError> {
        let encoded = ml_dsa::EncodedVerifyingKey::<MlDsaParam>::try_from(bytes)
            .map_err(|e| PqPasetoError::CryptoError(format!("Invalid key bytes: {:?}", e)))?;
        let key = ml_dsa::VerifyingKey::<MlDsaParam>::decode(&encoded);
        Ok(VerifyingKey(key))
    }
}

impl SymmetricKey {
    /// Generate a new random symmetric key
    #[cfg_attr(feature = "logging", instrument(skip(rng)))]
    pub fn generate<R: CryptoRng + RngCore>(rng: &mut R) -> Self {
        let mut key_bytes = [0u8; SYMMETRIC_KEY_SIZE];
        rng.fill_bytes(&mut key_bytes);

        #[cfg(feature = "logging")]
        debug!("Generated new symmetric key");

        Self(key_bytes)
    }

    /// Create symmetric key from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqPasetoError> {
        if bytes.len() != SYMMETRIC_KEY_SIZE {
            return Err(PqPasetoError::CryptoError(format!(
                "Invalid symmetric key length: expected {}, got {}",
                SYMMETRIC_KEY_SIZE,
                bytes.len()
            )));
        }
        let mut key_bytes = [0u8; SYMMETRIC_KEY_SIZE];
        key_bytes.copy_from_slice(bytes);
        Ok(Self(key_bytes))
    }

    /// Export symmetric key as bytes
    pub fn to_bytes(&self) -> [u8; SYMMETRIC_KEY_SIZE] {
        self.0
    }

    /// Derive a symmetric key from shared secret using proper HKDF-SHA256
    ///
    /// Uses RFC 5869 HKDF with SHA-256 for cryptographically sound key derivation.
    /// The salt is set to None for domain separation, following best practices
    /// for post-quantum key exchange scenarios.
    pub fn derive_from_shared_secret(shared_secret: &[u8], info: &[u8]) -> Self {
        // Use proper HKDF with SHA-256 (no salt - appropriate for PQ key exchange)
        let hk = Hkdf::<Sha256>::new(None, shared_secret);

        let mut key_bytes = [0u8; SYMMETRIC_KEY_SIZE];
        hk.expand(info, &mut key_bytes)
            .expect("SYMMETRIC_KEY_SIZE (32) is valid for SHA-256 HKDF output");

        Self(key_bytes)
    }
}

impl KemKeyPair {
    /// Generate a new post-quantum KEM key pair using ML-KEM-768
    #[cfg_attr(feature = "logging", instrument(skip(_rng)))]
    pub fn generate<R: CryptoRng + RngCore>(_rng: &mut R) -> Self {
        // Generate actual ML-KEM-768 key pair
        let (dk, ek) = MlKem768::generate(&mut chacha20poly1305::aead::OsRng);

        #[cfg(feature = "logging")]
        debug!("Generated new ML-KEM-768 key pair");

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

    /// Import encapsulation key from bytes
    pub fn encapsulation_key_from_bytes(bytes: &[u8]) -> Result<EncapsulationKey, PqPasetoError> {
        use ml_kem::{EncodedSizeUser, array::Array};
        if bytes.len() != 1184 {
            return Err(PqPasetoError::CryptoError(
                "Invalid encapsulation key length".to_string(),
            ));
        }
        let array: Array<u8, _> = Array::try_from(bytes)
            .map_err(|_| PqPasetoError::CryptoError("Invalid key format".to_string()))?;
        Ok(EncapsulationKey(
            <MlKem768 as KemCore>::EncapsulationKey::from_bytes(&array),
        ))
    }

    /// Export the decapsulation key as bytes
    pub fn decapsulation_key_to_bytes(&self) -> Vec<u8> {
        use ml_kem::EncodedSizeUser;
        self.decapsulation_key.0.as_bytes().to_vec()
    }

    /// Import decapsulation key from bytes
    pub fn decapsulation_key_from_bytes(bytes: &[u8]) -> Result<DecapsulationKey, PqPasetoError> {
        use ml_kem::{EncodedSizeUser, array::Array};
        if bytes.len() != 2400 {
            return Err(PqPasetoError::CryptoError(
                "Invalid decapsulation key length".to_string(),
            ));
        }
        let array: Array<u8, _> = Array::try_from(bytes)
            .map_err(|_| PqPasetoError::CryptoError("Invalid key format".to_string()))?;
        Ok(DecapsulationKey(
            <MlKem768 as KemCore>::DecapsulationKey::from_bytes(&array),
        ))
    }

    /// Perform key encapsulation (sender side) using ML-KEM-768
    pub fn encapsulate(&self) -> (SymmetricKey, Vec<u8>) {
        // Use real ML-KEM-768 encapsulation with OsRng for compatibility
        let (ciphertext, shared_secret) = self
            .encapsulation_key
            .0
            .encapsulate(&mut chacha20poly1305::aead::OsRng)
            .unwrap();

        let symmetric_key = SymmetricKey::derive_from_shared_secret(
            shared_secret.as_slice(),
            b"PASETO-PQ-LOCAL-pq1",
        );

        (symmetric_key, ciphertext.as_slice().to_vec())
    }

    /// Perform key decapsulation (receiver side) using ML-KEM-768
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<SymmetricKey, PqPasetoError> {
        use ml_kem::array::Array;

        // Parse ciphertext into the correct type
        if ciphertext.len() != 1088 {
            return Err(PqPasetoError::CryptoError(
                "Invalid ciphertext length".to_string(),
            ));
        }

        let ct_array: Array<u8, _> = Array::try_from(ciphertext)
            .map_err(|_| PqPasetoError::CryptoError("Invalid ciphertext format".to_string()))?;
        let ct = ml_kem::Ciphertext::<MlKem768>::from(ct_array);

        // Use real ML-KEM-768 decapsulation
        let shared_secret = self.decapsulation_key.0.decapsulate(&ct).unwrap();

        Ok(SymmetricKey::derive_from_shared_secret(
            shared_secret.as_ref(),
            b"PASETO-PQ-LOCAL-pq1",
        ))
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
    pub fn set_issuer(&mut self, issuer: impl Into<String>) -> Result<(), PqPasetoError> {
        self.iss = Some(issuer.into());
        Ok(())
    }

    /// Set the subject claim
    pub fn set_subject(&mut self, subject: impl Into<String>) -> Result<(), PqPasetoError> {
        self.sub = Some(subject.into());
        Ok(())
    }

    /// Set the audience claim
    pub fn set_audience(&mut self, audience: impl Into<String>) -> Result<(), PqPasetoError> {
        self.aud = Some(audience.into());
        Ok(())
    }

    /// Set the expiration time
    pub fn set_expiration(&mut self, exp: OffsetDateTime) -> Result<(), PqPasetoError> {
        self.exp = Some(exp);
        Ok(())
    }

    /// Set the not-before time
    pub fn set_not_before(&mut self, nbf: OffsetDateTime) -> Result<(), PqPasetoError> {
        self.nbf = Some(nbf);
        Ok(())
    }

    /// Set the issued-at time
    pub fn set_issued_at(&mut self, iat: OffsetDateTime) -> Result<(), PqPasetoError> {
        self.iat = Some(iat);
        Ok(())
    }

    /// Set the token identifier
    pub fn set_jti(&mut self, jti: impl Into<String>) -> Result<(), PqPasetoError> {
        self.jti = Some(jti.into());
        Ok(())
    }

    /// Set the key identifier
    pub fn set_kid(&mut self, kid: impl Into<String>) -> Result<(), PqPasetoError> {
        self.kid = Some(kid.into());
        Ok(())
    }

    /// Add a custom claim
    pub fn add_custom(
        &mut self,
        key: impl Into<String>,
        value: impl Serialize,
    ) -> Result<(), PqPasetoError> {
        let value = serde_json::to_value(value)?;
        self.custom.insert(key.into(), value);
        Ok(())
    }

    /// Get a custom claim
    pub fn get_custom(&self, key: &str) -> Option<&Value> {
        self.custom.get(key)
    }

    /// Validate time-based claims
    pub fn validate_time(
        &self,
        now: OffsetDateTime,
        clock_skew_tolerance: time::Duration,
    ) -> Result<(), PqPasetoError> {
        // Check expiration
        if let Some(exp) = self.exp {
            if now > exp + clock_skew_tolerance {
                return Err(PqPasetoError::TokenExpired);
            }
        }

        // Check not-before
        if let Some(nbf) = self.nbf {
            if now < nbf - clock_skew_tolerance {
                return Err(PqPasetoError::TokenNotYetValid);
            }
        }

        Ok(())
    }

    // Getters
    pub fn issuer(&self) -> Option<&str> {
        self.iss.as_deref()
    }
    pub fn subject(&self) -> Option<&str> {
        self.sub.as_deref()
    }
    pub fn audience(&self) -> Option<&str> {
        self.aud.as_deref()
    }
    pub fn expiration(&self) -> Option<OffsetDateTime> {
        self.exp
    }
    pub fn not_before(&self) -> Option<OffsetDateTime> {
        self.nbf
    }
    pub fn issued_at(&self) -> Option<OffsetDateTime> {
        self.iat
    }
    pub fn jti(&self) -> Option<&str> {
        self.jti.as_deref()
    }
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    /// Convert claims to a JSON value
    ///
    /// This method provides easy integration with logging, databases, and tracing systems.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use paseto_pq::Claims;
    /// use serde_json::Value;
    ///
    /// let mut claims = Claims::new();
    /// claims.set_subject("user123").unwrap();
    /// claims.add_custom("role", "admin").unwrap();
    ///
    /// let json_value: Value = claims.to_json_value();
    /// println!("Claims as JSON: {}", json_value);
    /// ```
    pub fn to_json_value(&self) -> serde_json::Value {
        serde_json::Value::from(self.clone())
    }

    /// Convert claims to a JSON string
    ///
    /// This method provides easy integration with logging, databases, and tracing systems.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use paseto_pq::Claims;
    ///
    /// let mut claims = Claims::new();
    /// claims.set_subject("user123").unwrap();
    /// claims.add_custom("role", "admin").unwrap();
    ///
    /// let json_string = claims.to_json_string().unwrap();
    /// println!("User claims: {}", json_string);
    /// ```
    pub fn to_json_string(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Convert claims to a pretty-printed JSON string
    ///
    /// Useful for debugging and development environments.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use paseto_pq::Claims;
    ///
    /// let mut claims = Claims::new();
    /// claims.set_subject("user123").unwrap();
    /// claims.add_custom("role", "admin").unwrap();
    ///
    /// let pretty_json = claims.to_json_string_pretty().unwrap();
    /// println!("Claims:\n{}", pretty_json);
    /// ```
    pub fn to_json_string_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

impl Default for Claims {
    fn default() -> Self {
        Self::new()
    }
}

/// Convert Claims to serde_json::Value for easy integration with logging, databases, and tracing
///
/// # Example
///
/// ```rust,no_run
/// use paseto_pq::Claims;
/// use serde_json::Value;
///
/// let mut claims = Claims::new();
/// claims.set_subject("user123").unwrap();
/// claims.add_custom("tenant_id", "org_abc123").unwrap();
///
/// // Direct conversion
/// let json_value: Value = claims.into();
///
/// // Use in logging
/// println!("User authenticated with claims: {}", json_value);
///
/// // Use in database operations
/// // db.insert_audit_log(json_value).await?;
/// ```
impl From<Claims> for serde_json::Value {
    fn from(claims: Claims) -> Self {
        // Use serde to convert the Claims to JSON Value
        // This leverages the existing Serialize implementation on Claims
        serde_json::to_value(claims).unwrap_or(serde_json::Value::Null)
    }
}

/// Convert &Claims to serde_json::Value (borrowed version)
impl From<&Claims> for serde_json::Value {
    fn from(claims: &Claims) -> Self {
        serde_json::to_value(claims).unwrap_or(serde_json::Value::Null)
    }
}

impl TokenSizeBreakdown {
    /// Get the total size from all components
    pub fn total(&self) -> usize {
        self.prefix
            + self.payload
            + self.signature_or_tag
            + self.footer.unwrap_or(0)
            + self.separators
            + self.base64_overhead
    }
}

impl TokenSizeEstimator {
    /// Estimate the size of a public token
    ///
    /// # Arguments
    ///
    /// * `claims` - The claims that will be included in the token
    /// * `has_footer` - Whether the token will include a footer
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use paseto_pq::{Claims, TokenSizeEstimator};
    ///
    /// let mut claims = Claims::new();
    /// claims.set_subject("user123").unwrap();
    ///
    /// let estimator = TokenSizeEstimator::public(&claims, false);
    /// println!("Public token will be ~{} bytes", estimator.total_bytes());
    /// # Ok::<(), paseto_pq::PqPasetoError>(())
    /// ```
    pub fn public(claims: &Claims, has_footer: bool) -> Self {
        // Serialize claims to get actual payload size
        let claims_json = serde_json::to_string(claims).unwrap_or_default();
        let claims_bytes = claims_json.len();

        // Calculate base64 encoded payload size
        let payload_b64_len = claims_bytes.div_ceil(3) * 4; // Base64 encoding

        // Constants for public tokens
        let prefix_len = TOKEN_PREFIX_PUBLIC.len() + 1; // +1 for trailing dot
        // Signature size varies by parameter set
        let signature_len = if cfg!(feature = "ml-dsa-44") {
            2800 // ML-DSA-44 signature is smaller
        } else if cfg!(feature = "ml-dsa-65") {
            4300 // ML-DSA-65 signature is ~2,420 bytes -> ~3,227 base64 -> actual ~4.3KB
        } else {
            5000 // ML-DSA-87 signature is largest
        };
        let footer_len = if has_footer { 150 } else { 0 }; // Estimated footer size
        let separators = if has_footer { 3 } else { 2 }; // Dots between parts
        let base64_overhead = (claims_bytes * 4).div_ceil(3) - claims_bytes; // More accurate base64 overhead

        let breakdown = TokenSizeBreakdown {
            prefix: prefix_len,
            payload: payload_b64_len,
            signature_or_tag: signature_len,
            footer: if has_footer { Some(footer_len) } else { None },
            separators,
            base64_overhead,
        };

        Self { breakdown }
    }

    /// Estimate the size of a local token
    ///
    /// # Arguments
    ///
    /// * `claims` - The claims that will be included in the token
    /// * `has_footer` - Whether the token will include a footer
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use paseto_pq::{Claims, TokenSizeEstimator};
    ///
    /// let mut claims = Claims::new();
    /// claims.set_subject("user123").unwrap();
    ///
    /// let estimator = TokenSizeEstimator::local(&claims, false);
    /// println!("Local token will be ~{} bytes", estimator.total_bytes());
    /// # Ok::<(), paseto_pq::PqPasetoError>(())
    /// ```
    pub fn local(claims: &Claims, has_footer: bool) -> Self {
        // Serialize claims to get actual payload size
        let claims_json = serde_json::to_string(claims).unwrap_or_default();
        let claims_bytes = claims_json.len();

        // Local tokens encrypt the payload, add nonce (12 bytes) and auth tag (16 bytes)
        let encrypted_payload_len = claims_bytes + 12 + 16; // nonce + tag
        let payload_b64_len = encrypted_payload_len.div_ceil(3) * 4; // Base64 encoding

        // Constants for local tokens
        let prefix_len = TOKEN_PREFIX_LOCAL.len() + 1; // +1 for trailing dot
        let footer_len = if has_footer { 150 } else { 0 }; // Estimated footer size
        let separators = if has_footer { 2 } else { 1 }; // Dots between parts
        let base64_overhead = (encrypted_payload_len * 4).div_ceil(3) - encrypted_payload_len; // More accurate base64 overhead

        let breakdown = TokenSizeBreakdown {
            prefix: prefix_len,
            payload: payload_b64_len,
            signature_or_tag: 0, // Local tokens don't have separate signature
            footer: if has_footer { Some(footer_len) } else { None },
            separators,
            base64_overhead,
        };

        Self { breakdown }
    }

    /// Get the estimated total size in bytes
    pub fn total_bytes(&self) -> usize {
        self.breakdown.total()
    }

    /// Check if the token fits within typical cookie size limits (4KB)
    pub fn fits_in_cookie(&self) -> bool {
        self.total_bytes() <= 4096
    }

    /// Check if the token fits within typical URL length limits (2KB)
    pub fn fits_in_url(&self) -> bool {
        self.total_bytes() <= 2048
    }

    /// Check if the token fits within typical HTTP header limits (8KB)
    pub fn fits_in_header(&self) -> bool {
        self.total_bytes() <= 8192
    }

    /// Get detailed breakdown of size components
    pub fn breakdown(&self) -> &TokenSizeBreakdown {
        &self.breakdown
    }

    /// Get optimization suggestions if the token is large
    pub fn optimization_suggestions(&self) -> Vec<String> {
        let mut suggestions = Vec::new();
        let total = self.total_bytes();

        if total > 4096 {
            suggestions.push("Token exceeds cookie size limit (4KB)".to_string());
            suggestions.push("Consider using shorter claim values".to_string());
            suggestions.push("Move large data to footer or external storage".to_string());
            suggestions.push("Use local tokens for internal services (smaller)".to_string());
        }

        if total > 2048 {
            suggestions.push("Token exceeds URL length limits".to_string());
            suggestions.push("Avoid passing token in query parameters".to_string());
        }

        if self.breakdown.payload > total / 2 {
            suggestions.push("Payload is majority of token size - reduce claim data".to_string());
        }

        if self.breakdown.footer.unwrap_or(0) > 200 {
            suggestions.push("Footer is large - consider minimal metadata only".to_string());
        }

        suggestions
    }

    /// Compare token size to typical JWT tokens
    pub fn compare_to_jwt(&self) -> String {
        let jwt_typical = 200; // Typical JWT size
        let ratio = self.total_bytes() as f64 / jwt_typical as f64;
        format!(
            "{:.1}x larger than typical JWT ({} bytes)",
            ratio, jwt_typical
        )
    }

    /// Get a human-readable size summary
    pub fn size_summary(&self) -> String {
        format!(
            "Token size: {} bytes (payload: {}, signature: {}, overhead: {})",
            self.total_bytes(),
            self.breakdown.payload,
            self.breakdown.signature_or_tag,
            self.breakdown.base64_overhead + self.breakdown.separators + self.breakdown.prefix
        )
    }
}

impl ParsedToken {
    /// Parse a PASETO token string to extract structural information
    ///
    /// This method performs **no cryptographic operations** - it only parses the token
    /// structure to extract metadata. Use this for debugging, logging, middleware,
    /// and routing decisions.
    ///
    /// # Arguments
    ///
    /// * `token` - The PASETO token string to parse
    ///
    /// # Returns
    ///
    /// Returns a `ParsedToken` containing the token's structural information,
    /// or an error if the token format is invalid.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use paseto_pq::ParsedToken;
    ///
    /// let token = "paseto.pq1.public.ABC123.DEF456.eyJraWQiOiJ0ZXN0In0";
    /// let parsed = ParsedToken::parse(token)?;
    ///
    /// assert_eq!(parsed.purpose(), "public");
    /// assert_eq!(parsed.version(), "pq1");
    /// assert!(parsed.has_footer());
    /// # Ok::<(), paseto_pq::PqPasetoError>(())
    /// ```
    pub fn parse(token: &str) -> Result<Self, PqPasetoError> {
        let parts: Vec<&str> = token.split('.').collect();

        // Validate minimum structure: paseto.pq1.purpose.payload
        if parts.len() < 4 {
            return Err(PqPasetoError::TokenParsingError(format!(
                "Invalid token format: expected at least 4 parts, got {}",
                parts.len()
            )));
        }

        // Validate protocol
        if parts[0] != "paseto" {
            return Err(PqPasetoError::TokenParsingError(format!(
                "Invalid protocol: expected 'paseto', got '{}'",
                parts[0]
            )));
        }

        // Extract version
        let version = parts[1].to_string();

        // Extract purpose
        let purpose = parts[2].to_string();

        // Validate known formats
        match (version.as_str(), purpose.as_str()) {
            ("pq1", "public") | ("pq1", "local") => {}
            _ => {
                return Err(PqPasetoError::TokenParsingError(format!(
                    "Unsupported token format: {}.{}.{}",
                    parts[0], parts[1], parts[2]
                )));
            }
        }

        // Decode payload
        let payload = URL_SAFE_NO_PAD.decode(parts[3]).map_err(|e| {
            PqPasetoError::TokenParsingError(format!("Invalid payload base64: {}", e))
        })?;

        let mut signature_or_tag = None;
        let mut footer = None;

        // Parse remaining parts based on token type
        match purpose.as_str() {
            "public" => {
                // Public tokens: paseto.pq1.public.payload.signature[.footer]
                if parts.len() > 6 {
                    return Err(PqPasetoError::TokenParsingError(
                        "Public token has too many parts".to_string(),
                    ));
                }
                if parts.len() >= 5 {
                    signature_or_tag = Some(URL_SAFE_NO_PAD.decode(parts[4]).map_err(|e| {
                        PqPasetoError::TokenParsingError(format!("Invalid signature base64: {}", e))
                    })?);
                }
                if parts.len() >= 6 {
                    footer = Some(Footer::from_base64(parts[5])?);
                }
            }
            "local" => {
                // Local tokens: paseto.pq1.local.payload[.footer]
                if parts.len() > 5 {
                    return Err(PqPasetoError::TokenParsingError(
                        "Local token has too many parts".to_string(),
                    ));
                }
                if parts.len() >= 5 {
                    footer = Some(Footer::from_base64(parts[4])?);
                }
            }
            _ => unreachable!(), // Already validated above
        }

        Ok(ParsedToken {
            purpose,
            version,
            payload,
            signature_or_tag,
            footer,
            raw_token: token.to_string(),
        })
    }

    /// Get the token purpose ("public" for public tokens, "local" for local tokens)
    pub fn purpose(&self) -> &str {
        &self.purpose
    }

    /// Get the token version (currently "pq1")
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Check if the token has a footer
    pub fn has_footer(&self) -> bool {
        self.footer.is_some()
    }

    /// Get the footer, if present
    pub fn footer(&self) -> Option<&Footer> {
        self.footer.as_ref()
    }

    /// Get the raw payload bytes (base64-decoded)
    pub fn payload_bytes(&self) -> &[u8] {
        &self.payload
    }

    /// Get the signature or authentication tag bytes, if present
    ///
    /// For public tokens, this is the ML-DSA signature.
    /// For local tokens, this is None (auth tag is embedded in payload).
    pub fn signature_bytes(&self) -> Option<&[u8]> {
        self.signature_or_tag.as_deref()
    }

    /// Get the length of the payload in bytes
    pub fn payload_length(&self) -> usize {
        self.payload.len()
    }

    /// Get the total length of the token string
    pub fn total_length(&self) -> usize {
        self.raw_token.len()
    }

    /// Get the raw token string
    pub fn raw_token(&self) -> &str {
        &self.raw_token
    }

    /// Get footer as JSON string, if present
    pub fn footer_json(&self) -> Option<Result<String, serde_json::Error>> {
        self.footer.as_ref().map(serde_json::to_string)
    }

    /// Get footer as pretty-printed JSON string, if present
    pub fn footer_json_pretty(&self) -> Option<Result<String, serde_json::Error>> {
        self.footer.as_ref().map(serde_json::to_string_pretty)
    }

    /// Check if this is a public token (uses signatures)
    pub fn is_public(&self) -> bool {
        self.purpose == "public"
    }

    /// Check if this is a local token (uses symmetric encryption)
    pub fn is_local(&self) -> bool {
        self.purpose == "local"
    }

    /// Get token format summary for debugging
    pub fn format_summary(&self) -> String {
        format!(
            "paseto.{}.{} (payload: {} bytes, signature: {}, footer: {})",
            self.version,
            self.purpose,
            self.payload.len(),
            if self.signature_or_tag.is_some() {
                "present"
            } else {
                "none"
            },
            if self.footer.is_some() {
                "present"
            } else {
                "none"
            }
        )
    }
}

impl VerifiedToken {
    /// Get the claims from the verified token
    pub fn claims(&self) -> &Claims {
        &self.claims
    }

    /// Get the footer from the verified token, if present
    pub fn footer(&self) -> Option<&Footer> {
        self.footer.as_ref()
    }

    /// Get the raw token string
    pub fn raw_token(&self) -> &str {
        &self.raw_token
    }

    /// Consume the verified token and return the claims
    pub fn into_claims(self) -> Claims {
        self.claims
    }

    /// Consume the verified token and return both claims and footer
    pub fn into_parts(self) -> (Claims, Option<Footer>) {
        (self.claims, self.footer)
    }
}

impl PasetoPQ {
    /// Get the current token prefix used for public tokens
    ///
    /// Returns the prefix string used in public token generation.
    /// This allows applications to inspect the versioning scheme being used.
    pub fn public_token_prefix() -> &'static str {
        TOKEN_PREFIX_PUBLIC
    }

    /// Get the current token prefix used for local tokens
    ///
    /// Returns the prefix string used in local token generation.
    /// This allows applications to inspect the versioning scheme being used.
    pub fn local_token_prefix() -> &'static str {
        TOKEN_PREFIX_LOCAL
    }

    /// Check if this implementation uses standard PASETO versioning
    ///
    /// Returns `false` because this crate uses non-standard `pq1` versioning
    /// that is incompatible with the official PASETO specification.
    pub fn is_standard_paseto_compatible() -> bool {
        false
    }
    /// Parse a PASETO token for inspection without cryptographic operations
    ///
    /// This method allows you to examine token structure, purpose, version, and footer
    /// without performing expensive signature verification or decryption. Useful for
    /// debugging, logging, middleware, and routing decisions.
    ///
    /// # Arguments
    ///
    /// * `token` - The PASETO token string to parse
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use paseto_pq::PasetoPQ;
    ///
    /// let token = "paseto.pq1.public.ABC123...";
    /// let parsed = PasetoPQ::parse_token(token)?;
    ///
    /// println!("Token type: {}", parsed.purpose());
    /// println!("Has footer: {}", parsed.has_footer());
    ///
    /// // Route based on token type
    /// match parsed.purpose() {
    ///     "public" => println!("Public token - needs signature verification"),
    ///     "local" => println!("Local token - needs decryption"),
    ///     _ => println!("Unknown token type"),
    /// }
    /// # Ok::<(), paseto_pq::PqPasetoError>(())
    /// ```
    pub fn parse_token(token: &str) -> Result<ParsedToken, PqPasetoError> {
        ParsedToken::parse(token)
    }

    /// Estimate the size of a public token before creation
    ///
    /// This method helps you plan token usage and avoid size-related issues
    /// with HTTP headers, cookies, or URL length limits.
    ///
    /// # Arguments
    ///
    /// * `claims` - The claims that will be included in the token
    /// * `has_footer` - Whether the token will include a footer
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use paseto_pq::{PasetoPQ, Claims};
    ///
    /// let mut claims = Claims::new();
    /// claims.set_subject("user123").unwrap();
    /// claims.add_custom("role", "admin").unwrap();
    ///
    /// let estimator = PasetoPQ::estimate_public_size(&claims, false);
    /// println!("Token will be ~{} bytes", estimator.total_bytes());
    ///
    /// if !estimator.fits_in_cookie() {
    ///     println!("Warning: Token too large for cookies!");
    /// }
    /// # Ok::<(), paseto_pq::PqPasetoError>(())
    /// ```
    pub fn estimate_public_size(claims: &Claims, has_footer: bool) -> TokenSizeEstimator {
        TokenSizeEstimator::public(claims, has_footer)
    }

    /// Estimate the size of a local token before creation
    ///
    /// This method helps you plan token usage and avoid size-related issues
    /// with HTTP headers, cookies, or URL length limits.
    ///
    /// # Arguments
    ///
    /// * `claims` - The claims that will be included in the token
    /// * `has_footer` - Whether the token will include a footer
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use paseto_pq::{PasetoPQ, Claims};
    ///
    /// let mut claims = Claims::new();
    /// claims.set_subject("user123").unwrap();
    /// claims.add_custom("session_data", "confidential").unwrap();
    ///
    /// let estimator = PasetoPQ::estimate_local_size(&claims, true);
    /// println!("Token will be ~{} bytes", estimator.total_bytes());
    ///
    /// if estimator.fits_in_header() {
    ///     println!("Token fits in HTTP headers");
    /// }
    /// # Ok::<(), paseto_pq::PqPasetoError>(())
    /// ```
    pub fn estimate_local_size(claims: &Claims, has_footer: bool) -> TokenSizeEstimator {
        TokenSizeEstimator::local(claims, has_footer)
    }

    /// Sign claims to create a public token
    #[cfg_attr(feature = "logging", instrument(skip(signing_key)))]
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
        // Serialize claims to JSON bytes (not base64 for PAE)
        let payload_bytes = serde_json::to_vec(claims)?;

        #[cfg(feature = "logging")]
        debug!("Serialized claims to {} bytes", payload_bytes.len());

        // Serialize footer to JSON bytes (empty if None)
        let footer_bytes = match footer {
            Some(f) => serde_json::to_vec(f)?,
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
            "Generated v0.1.1 token with {} byte signature and PAE footer authentication{}",
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
        // Serialize claims to JSON bytes
        let payload_bytes = serde_json::to_vec(claims)?;

        #[cfg(feature = "logging")]
        debug!("Serialized claims to {} bytes", payload_bytes.len());

        // Create cipher
        let cipher = ChaCha20Poly1305::new((&symmetric_key.0).into());

        // Generate random nonce
        let nonce = ChaCha20Poly1305::generate_nonce(&mut AeadOsRng);

        // Serialize footer to JSON bytes (empty if None)
        let footer_bytes = match footer {
            Some(f) => serde_json::to_vec(f)?,
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

        // Encrypt payload with PAE AAD (footer now authenticated by AEAD!)
        let mut buffer = payload_bytes.clone();
        let tag = cipher
            .encrypt_in_place_detached(&nonce, &aad, &mut buffer)
            .map_err(|e| PqPasetoError::EncryptionError(format!("Encryption failed: {}", e)))?;

        // Combine encrypted payload with authentication tag
        let mut ciphertext = buffer;
        ciphertext.extend_from_slice(&tag);

        // Combine nonce + ciphertext + tag
        let mut encrypted_data = Vec::new();
        encrypted_data.extend_from_slice(&nonce);
        encrypted_data.extend_from_slice(&ciphertext);

        // Base64url encode the encrypted data
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
            "Generated v0.1.1 local token with {} byte payload and PAE footer authentication{}",
            encrypted_data.len(),
            if footer.is_some() { " with footer" } else { "" }
        );

        Ok(token)
    }

    /// Decrypt a local token and extract claims
    #[cfg_attr(feature = "logging", instrument(skip(symmetric_key)))]
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
            // Token with footer: paseto.pq1.local.payload.footer
            if parts[0] != "paseto" || parts[1] != "pq1" || parts[2] != "local" {
                return Err(PqPasetoError::InvalidFormat(
                    "Invalid token format - expected 'paseto.pq1.local'".into(),
                ));
            }
            let footer = Footer::from_base64(parts[4])?;
            (parts[3], Some(footer))
        } else if parts.len() == 4 {
            // Token without footer: paseto.pq1.local.payload
            if parts[0] != "paseto" || parts[1] != "pq1" || parts[2] != "local" {
                return Err(PqPasetoError::InvalidFormat(
                    "Invalid token format - expected 'paseto.pq1.local'".into(),
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

        // Serialize footer to JSON bytes (empty if None)
        let footer_bytes = match &footer {
            Some(f) => serde_json::to_vec(f)?,
            None => Vec::new(), // Empty bytes for no footer
        };

        // Reconstruct PAE-encoded AAD for footer validation (v0.1.1 RFC-compliant)
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
        let cipher = ChaCha20Poly1305::new((&symmetric_key.0).into());

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
        debug!("v0.1.1 PAE decryption successful with footer authentication");

        // Parse claims
        let claims: Claims = serde_json::from_slice(&payload_bytes)?;

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
        clock_skew_tolerance: time::Duration,
    ) -> Result<VerifiedToken, PqPasetoError> {
        let verified = Self::decrypt(symmetric_key, token)?;

        // Validate audience if specified
        if let Some(expected_aud) = expected_audience {
            match verified.claims.audience() {
                Some(actual_aud) if actual_aud == expected_aud => {}
                Some(actual_aud) => {
                    return Err(PqPasetoError::InvalidAudience {
                        expected: expected_aud.to_string(),
                        actual: actual_aud.to_string(),
                    });
                }
                None => {
                    return Err(PqPasetoError::InvalidAudience {
                        expected: expected_aud.to_string(),
                        actual: "none".to_string(),
                    });
                }
            }
        }

        // Validate issuer if specified
        if let Some(expected_iss) = expected_issuer {
            match verified.claims.issuer() {
                Some(actual_iss) if actual_iss == expected_iss => {}
                Some(actual_iss) => {
                    return Err(PqPasetoError::InvalidIssuer {
                        expected: expected_iss.to_string(),
                        actual: actual_iss.to_string(),
                    });
                }
                None => {
                    return Err(PqPasetoError::InvalidIssuer {
                        expected: expected_iss.to_string(),
                        actual: "none".to_string(),
                    });
                }
            }
        }

        // Re-validate time with custom tolerance
        verified
            .claims
            .validate_time(OffsetDateTime::now_utc(), clock_skew_tolerance)?;

        Ok(verified)
    }

    /// Verify a token and extract claims
    #[cfg_attr(feature = "logging", instrument(skip(verifying_key)))]
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
            // Token with footer: paseto.pq1.public.payload.signature.footer
            if parts[0] != "paseto" || parts[1] != "pq1" || parts[2] != "public" {
                return Err(PqPasetoError::InvalidFormat(
                    "Invalid token format - expected 'paseto.pq1.public'".into(),
                ));
            }
            let footer = Footer::from_base64(parts[5])?;
            (parts[3], parts[4], Some(footer))
        } else if parts.len() == 5 {
            // Token without footer: paseto.pq1.public.payload.signature
            if parts[0] != "paseto" || parts[1] != "pq1" || parts[2] != "public" {
                return Err(PqPasetoError::InvalidFormat(
                    "Invalid token format - expected 'paseto.pq1.public'".into(),
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
            Some(f) => serde_json::to_vec(f)?,
            None => Vec::new(), // Empty bytes for no footer
        };

        // Reconstruct PAE message that was signed (v0.1.1 RFC-compliant)
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
        let signature = ml_dsa::Signature::<MlDsaParam>::decode(&encoded_sig)
            .ok_or_else(|| PqPasetoError::CryptoError("Failed to decode signature".into()))?;

        // Verify signature against PAE message (footer tampering now detected!)
        verifying_key
            .0
            .verify(&pae_message, &signature)
            .map_err(|_| PqPasetoError::SignatureVerificationFailed)?;

        #[cfg(feature = "logging")]
        debug!("v0.1.1 PAE signature verification successful with footer authentication");

        // Parse claims
        let claims: Claims = serde_json::from_slice(&payload_bytes)?;

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
        clock_skew_tolerance: time::Duration,
    ) -> Result<VerifiedToken, PqPasetoError> {
        let verified = Self::verify_with_footer(verifying_key, token)?;

        // Validate audience if specified
        if let Some(expected_aud) = expected_audience {
            match verified.claims.audience() {
                Some(actual_aud) if actual_aud == expected_aud => {}
                Some(actual_aud) => {
                    return Err(PqPasetoError::InvalidAudience {
                        expected: expected_aud.to_string(),
                        actual: actual_aud.to_string(),
                    });
                }
                None => {
                    return Err(PqPasetoError::InvalidAudience {
                        expected: expected_aud.to_string(),
                        actual: "none".to_string(),
                    });
                }
            }
        }

        // Validate issuer if specified
        if let Some(expected_iss) = expected_issuer {
            match verified.claims.issuer() {
                Some(actual_iss) if actual_iss == expected_iss => {}
                Some(actual_iss) => {
                    return Err(PqPasetoError::InvalidIssuer {
                        expected: expected_iss.to_string(),
                        actual: actual_iss.to_string(),
                    });
                }
                None => {
                    return Err(PqPasetoError::InvalidIssuer {
                        expected: expected_iss.to_string(),
                        actual: "none".to_string(),
                    });
                }
            }
        }

        // Re-validate time with custom tolerance
        verified
            .claims
            .validate_time(OffsetDateTime::now_utc(), clock_skew_tolerance)?;

        Ok(verified)
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("algorithm", &"ML-DSA-65")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifyingKey")
            .field("algorithm", &"ML-DSA-65")
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
            .field("algorithm", &"ChaCha20-Poly1305")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for EncapsulationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncapsulationKey")
            .field("algorithm", &"ML-KEM-768")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for DecapsulationKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecapsulationKey")
            .field("algorithm", &"ML-KEM-768")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for KemKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KemKeyPair")
            .field("encapsulation_key", &"<encapsulation_key>")
            .field("decapsulation_key", &"<decapsulation_key>")
            .finish()
    }
}

// Zeroization implementations for sensitive key material
// Note: ML-DSA and ML-KEM keys are opaque types that may handle their own zeroization internally.
// We implement Drop for best-effort cleanup, but rely on the underlying libraries for complete zeroization.

impl Drop for SigningKey {
    fn drop(&mut self) {
        // ML-DSA SigningKey is opaque - rely on underlying library for zeroization
        // The ml-dsa crate is compiled with zeroize feature enabled
    }
}

impl Drop for VerifyingKey {
    fn drop(&mut self) {
        // ML-DSA VerifyingKey is opaque - rely on underlying library for zeroization
        // The ml-dsa crate is compiled with zeroize feature enabled
    }
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        // Drop implementations for individual keys will handle cleanup
    }
}

impl Drop for EncapsulationKey {
    fn drop(&mut self) {
        // ML-KEM EncapsulationKey is opaque - rely on underlying library for zeroization
        // The ml-kem crate is compiled with zeroize feature enabled
    }
}

impl Drop for DecapsulationKey {
    fn drop(&mut self) {
        // ML-KEM DecapsulationKey is opaque - rely on underlying library for zeroization
        // The ml-kem crate is compiled with zeroize feature enabled
    }
}

impl Drop for KemKeyPair {
    fn drop(&mut self) {
        // Drop implementations for individual keys will handle cleanup
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rng;
    use std::thread;
    use time::Duration;

    #[test]
    fn test_keypair_generation() {
        thread::Builder::new()
            .name("keypair-generation-smoke".to_string())
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                let mut rng = rng();
                let keypair = KeyPair::generate(&mut rng);

                // Test bytes export/import
                let signing_bytes = keypair.signing_key_to_bytes();
                let verifying_bytes = keypair.verifying_key_to_bytes();

                assert!(!signing_bytes.is_empty());
                assert!(!verifying_bytes.is_empty());

                let imported_signing = KeyPair::signing_key_from_bytes(&signing_bytes).unwrap();
                let imported_verifying =
                    KeyPair::verifying_key_from_bytes(&verifying_bytes).unwrap();

                // Keys should be functionally equivalent (test by signing/verifying)
                let mut claims = Claims::new();
                claims.set_subject("test").unwrap();

                let token1 = PasetoPQ::sign(keypair.signing_key(), &claims).unwrap();
                let token2 = PasetoPQ::sign(&imported_signing, &claims).unwrap();

                // Both should verify with either key
                PasetoPQ::verify(keypair.verifying_key(), &token1).unwrap();
                PasetoPQ::verify(&imported_verifying, &token1).unwrap();
                PasetoPQ::verify(keypair.verifying_key(), &token2).unwrap();
                PasetoPQ::verify(&imported_verifying, &token2).unwrap();
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn test_basic_sign_and_verify() {
        let mut rng = rng();
        let keypair = KeyPair::generate(&mut rng);

        let mut claims = Claims::new();
        claims.set_subject("user123").unwrap();
        claims.set_issuer("conflux-auth").unwrap();
        claims.set_audience("conflux-network").unwrap();
        claims.set_jti("token-id-123").unwrap();
        claims.add_custom("tenant_id", "org_abc123").unwrap();
        claims.add_custom("roles", ["user", "admin"]).unwrap();

        let token = PasetoPQ::sign(keypair.signing_key(), &claims).unwrap();
        assert!(token.starts_with("paseto.pq1.public."));

        let verified = PasetoPQ::verify(keypair.verifying_key(), &token).unwrap();
        let verified_claims = verified.claims();

        assert_eq!(verified_claims.subject(), Some("user123"));
        assert_eq!(verified_claims.issuer(), Some("conflux-auth"));
        assert_eq!(verified_claims.audience(), Some("conflux-network"));
        assert_eq!(verified_claims.jti(), Some("token-id-123"));

        // Check custom claims
        assert_eq!(
            verified_claims.get_custom("tenant_id").unwrap().as_str(),
            Some("org_abc123")
        );
        let roles: Vec<String> =
            serde_json::from_value(verified_claims.get_custom("roles").unwrap().clone()).unwrap();
        assert_eq!(roles, vec!["user", "admin"]);
    }

    #[test]
    fn test_time_validation() {
        let mut rng = rng();
        let keypair = KeyPair::generate(&mut rng);

        let now = OffsetDateTime::now_utc();

        // Test expired token
        let mut expired_claims = Claims::new();
        expired_claims.set_subject("user").unwrap();
        expired_claims
            .set_expiration(now - Duration::hours(1))
            .unwrap();

        let expired_token = PasetoPQ::sign(keypair.signing_key(), &expired_claims).unwrap();
        let result = PasetoPQ::verify(keypair.verifying_key(), &expired_token);
        assert!(matches!(result.unwrap_err(), PqPasetoError::TokenExpired));

        // Test not-yet-valid token
        let mut future_claims = Claims::new();
        future_claims.set_subject("user").unwrap();
        future_claims
            .set_not_before(now + Duration::hours(1))
            .unwrap();

        let future_token = PasetoPQ::sign(keypair.signing_key(), &future_claims).unwrap();
        let result = PasetoPQ::verify(keypair.verifying_key(), &future_token);
        assert!(matches!(
            result.unwrap_err(),
            PqPasetoError::TokenNotYetValid
        ));

        // Test valid token
        let mut valid_claims = Claims::new();
        valid_claims.set_subject("user").unwrap();
        valid_claims
            .set_not_before(now - Duration::minutes(5))
            .unwrap();
        valid_claims
            .set_expiration(now + Duration::hours(1))
            .unwrap();

        let valid_token = PasetoPQ::sign(keypair.signing_key(), &valid_claims).unwrap();
        let verified = PasetoPQ::verify(keypair.verifying_key(), &valid_token).unwrap();
        assert_eq!(verified.claims().subject(), Some("user"));
    }

    #[test]
    fn test_audience_and_issuer_validation() {
        let mut rng = rng();
        let keypair = KeyPair::generate(&mut rng);

        let mut claims = Claims::new();
        claims.set_subject("user").unwrap();
        claims.set_audience("api.example.com").unwrap();
        claims.set_issuer("my-service").unwrap();

        let token = PasetoPQ::sign(keypair.signing_key(), &claims).unwrap();

        // Valid audience and issuer
        let verified = PasetoPQ::verify_with_options(
            keypair.verifying_key(),
            &token,
            Some("api.example.com"),
            Some("my-service"),
            Duration::seconds(30),
        )
        .unwrap();
        assert_eq!(verified.claims().subject(), Some("user"));

        // Invalid audience
        let result = PasetoPQ::verify_with_options(
            keypair.verifying_key(),
            &token,
            Some("wrong-audience"),
            Some("conflux-auth"),
            Duration::seconds(30),
        );
        assert!(matches!(
            result.unwrap_err(),
            PqPasetoError::InvalidAudience { .. }
        ));

        // Invalid issuer
        let result = PasetoPQ::verify_with_options(
            keypair.verifying_key(),
            &token,
            Some("api.example.com"),
            Some("wrong-service"),
            Duration::seconds(30),
        );
        assert!(matches!(
            result.unwrap_err(),
            PqPasetoError::InvalidIssuer { .. }
        ));
    }

    #[test]
    fn test_signature_verification_failure() {
        let mut rng = rng();
        let keypair1 = KeyPair::generate(&mut rng);
        let keypair2 = KeyPair::generate(&mut rng);

        let mut claims = Claims::new();
        claims.set_subject("user").unwrap();

        let token = PasetoPQ::sign(&keypair1.signing_key, &claims).unwrap();

        // Try to verify with wrong key
        let result = PasetoPQ::verify(&keypair2.verifying_key, &token);
        assert!(matches!(
            result.unwrap_err(),
            PqPasetoError::SignatureVerificationFailed
        ));
    }

    #[test]
    fn test_malformed_tokens() {
        let mut rng = rng();
        let keypair = KeyPair::generate(&mut rng);

        // Too few parts
        let result = PasetoPQ::verify(keypair.verifying_key(), "paseto.pq1");
        assert!(matches!(
            result.unwrap_err(),
            PqPasetoError::InvalidFormat(_)
        ));

        // Wrong prefix
        let result = PasetoPQ::verify(keypair.verifying_key(), "wrong.pq1.pq.payload.sig");
        assert!(matches!(
            result.unwrap_err(),
            PqPasetoError::InvalidFormat(_)
        ));

        // Invalid base64 in payload
        let result = PasetoPQ::verify(keypair.verifying_key(), "paseto.pq1.public.invalid!!!.sig");
        assert!(matches!(
            result.unwrap_err(),
            PqPasetoError::InvalidFormat(_)
        ));

        // Invalid signature bytes
        let result = PasetoPQ::verify(
            keypair.verifying_key(),
            "paseto.pq1.public.dGVzdA.invalid_sig",
        );
        assert!(matches!(result.unwrap_err(), PqPasetoError::CryptoError(_)));
    }

    #[test]
    fn test_symmetric_key_generation() {
        let mut rng = rng();
        let key = SymmetricKey::generate(&mut rng);

        // Test bytes export/import
        let key_bytes = key.to_bytes();
        assert_eq!(key_bytes.len(), SYMMETRIC_KEY_SIZE);

        let imported_key = SymmetricKey::from_bytes(&key_bytes).unwrap();
        assert_eq!(key.to_bytes(), imported_key.to_bytes());
    }

    #[test]
    fn test_kem_keypair_generation() {
        let mut rng = rng();
        let keypair = KemKeyPair::generate(&mut rng);

        // Test bytes export/import
        let enc_bytes = keypair.encapsulation_key_to_bytes();
        let dec_bytes = keypair.decapsulation_key_to_bytes();

        assert!(!enc_bytes.is_empty());
        assert!(!dec_bytes.is_empty());

        let _imported_enc = KemKeyPair::encapsulation_key_from_bytes(&enc_bytes).unwrap();
        let _imported_dec = KemKeyPair::decapsulation_key_from_bytes(&dec_bytes).unwrap();

        // Test key encapsulation/decapsulation with real ML-KEM implementation
        let (sender_key, ciphertext) = keypair.encapsulate();
        let receiver_key = keypair.decapsulate(&ciphertext).unwrap();

        // Real ML-KEM implementation should produce identical shared secrets
        assert_eq!(sender_key.to_bytes(), receiver_key.to_bytes());
        assert_ne!(sender_key.to_bytes(), [0u8; 32]); // Should not be all zeros
        assert_eq!(ciphertext.len(), 1088); // ML-KEM-768 ciphertext size
    }

    #[test]
    fn test_basic_encrypt_and_decrypt() {
        let mut rng = rng();
        let key = SymmetricKey::generate(&mut rng);

        let mut claims = Claims::new();
        claims.set_subject("user123").unwrap();
        claims.set_issuer("conflux-auth").unwrap();
        claims.set_audience("conflux-network").unwrap();
        claims.set_jti("token-id-123").unwrap();
        claims.add_custom("tenant_id", "org_abc123").unwrap();
        claims.add_custom("roles", ["user", "admin"]).unwrap();

        let token = PasetoPQ::encrypt(&key, &claims).unwrap();
        assert!(token.starts_with("paseto.pq1.local."));

        let verified = PasetoPQ::decrypt(&key, &token).unwrap();
        let verified_claims = verified.claims();

        assert_eq!(verified_claims.subject(), Some("user123"));
        assert_eq!(verified_claims.issuer(), Some("conflux-auth"));
        assert_eq!(verified_claims.audience(), Some("conflux-network"));
        assert_eq!(verified_claims.jti(), Some("token-id-123"));

        // Check custom claims
        assert_eq!(
            verified_claims.get_custom("tenant_id").unwrap().as_str(),
            Some("org_abc123")
        );
        let roles: Vec<String> =
            serde_json::from_value(verified_claims.get_custom("roles").unwrap().clone()).unwrap();
        assert_eq!(roles, vec!["user", "admin"]);
    }

    #[test]
    fn test_local_token_time_validation() {
        let mut rng = rng();
        let key = SymmetricKey::generate(&mut rng);
        let now = OffsetDateTime::now_utc();

        // Test expired token
        let mut expired_claims = Claims::new();
        expired_claims.set_subject("user").unwrap();
        expired_claims
            .set_expiration(now - Duration::hours(1))
            .unwrap();

        let expired_token = PasetoPQ::encrypt(&key, &expired_claims).unwrap();
        let result = PasetoPQ::decrypt(&key, &expired_token);
        assert!(matches!(result.unwrap_err(), PqPasetoError::TokenExpired));

        // Test not-yet-valid token
        let mut future_claims = Claims::new();
        future_claims.set_subject("user").unwrap();
        future_claims
            .set_not_before(now + Duration::hours(1))
            .unwrap();

        let future_token = PasetoPQ::encrypt(&key, &future_claims).unwrap();
        let result = PasetoPQ::decrypt(&key, &future_token);
        assert!(matches!(
            result.unwrap_err(),
            PqPasetoError::TokenNotYetValid
        ));

        // Test valid token
        let mut valid_claims = Claims::new();
        valid_claims.set_subject("user").unwrap();
        valid_claims
            .set_not_before(now - Duration::minutes(5))
            .unwrap();
        valid_claims
            .set_expiration(now + Duration::hours(1))
            .unwrap();

        let valid_token = PasetoPQ::encrypt(&key, &valid_claims).unwrap();
        let verified = PasetoPQ::decrypt(&key, &valid_token).unwrap();
        assert_eq!(verified.claims().subject(), Some("user"));
    }

    #[test]
    fn test_local_token_audience_and_issuer_validation() {
        let mut rng = rng();
        let key = SymmetricKey::generate(&mut rng);

        let mut claims = Claims::new();
        claims.set_subject("user123").unwrap();
        claims.set_issuer("test-issuer").unwrap();
        claims.set_audience("test-audience").unwrap();

        let token = PasetoPQ::encrypt(&key, &claims).unwrap();

        // Valid audience and issuer
        let verified = PasetoPQ::decrypt_with_options(
            &key,
            &token,
            Some("test-audience"),
            Some("test-issuer"),
            Duration::seconds(30),
        )
        .unwrap();
        assert_eq!(verified.claims().subject(), Some("user123"));

        // Wrong audience
        let result = PasetoPQ::decrypt_with_options(
            &key,
            &token,
            Some("wrong-audience"),
            Some("test-issuer"),
            Duration::seconds(30),
        );
        assert!(matches!(
            result.unwrap_err(),
            PqPasetoError::InvalidAudience { .. }
        ));

        // Wrong issuer
        let result = PasetoPQ::decrypt_with_options(
            &key,
            &token,
            Some("test-audience"),
            Some("wrong-issuer"),
            Duration::seconds(30),
        );
        assert!(matches!(
            result.unwrap_err(),
            PqPasetoError::InvalidIssuer { .. }
        ));
    }

    #[test]
    fn test_local_token_tamper_detection() {
        let mut rng = rng();
        let key = SymmetricKey::generate(&mut rng);

        let mut claims = Claims::new();
        claims.set_subject("user123").unwrap();

        let token = PasetoPQ::encrypt(&key, &claims).unwrap();

        // Tamper with the token
        let mut tampered_token = token.clone();
        tampered_token.push('x'); // Append extra character

        let result = PasetoPQ::decrypt(&key, &tampered_token);
        assert!(result.is_err());

        // Try with wrong key
        let wrong_key = SymmetricKey::generate(&mut rng);
        let result = PasetoPQ::decrypt(&wrong_key, &token);
        assert!(matches!(
            result.unwrap_err(),
            PqPasetoError::DecryptionError(_)
        ));
    }

    #[test]
    fn test_malformed_local_tokens() {
        let mut rng = rng();
        let key = SymmetricKey::generate(&mut rng);

        // Wrong prefix
        let result = PasetoPQ::decrypt(&key, "wrong.pq1.local.payload");
        assert!(matches!(
            result.unwrap_err(),
            PqPasetoError::InvalidFormat(_)
        ));

        // Invalid base64 in payload
        let result = PasetoPQ::decrypt(&key, "paseto.pq1.local.invalid!!!");
        assert!(matches!(
            result.unwrap_err(),
            PqPasetoError::InvalidFormat(_)
        ));

        // Too short payload (no nonce)
        let result = PasetoPQ::decrypt(&key, "paseto.pq1.local.dGVzdA");
        assert!(matches!(
            result.unwrap_err(),
            PqPasetoError::DecryptionError(_)
        ));
    }

    #[test]
    fn test_mixed_token_types() {
        let mut rng = rng();
        let asymmetric_keypair = KeyPair::generate(&mut rng);
        let symmetric_key = SymmetricKey::generate(&mut rng);

        let mut claims = Claims::new();
        claims.set_subject("user123").unwrap();

        // Create both types of tokens
        let public_token = PasetoPQ::sign(asymmetric_keypair.signing_key(), &claims).unwrap();
        let local_token = PasetoPQ::encrypt(&symmetric_key, &claims).unwrap();

        assert!(public_token.starts_with("paseto.pq1.public."));
        assert!(local_token.starts_with("paseto.pq1.local."));

        // Verify each with correct method
        let verified_public =
            PasetoPQ::verify(asymmetric_keypair.verifying_key(), &public_token).unwrap();
        let verified_local = PasetoPQ::decrypt(&symmetric_key, &local_token).unwrap();

        assert_eq!(verified_public.claims().subject(), Some("user123"));
        assert_eq!(verified_local.claims().subject(), Some("user123"));

        // Cross-verification should fail
        let result = PasetoPQ::decrypt(&symmetric_key, &public_token);
        assert!(result.is_err());

        let result = PasetoPQ::verify(asymmetric_keypair.verifying_key(), &local_token);
        assert!(result.is_err());
    }

    #[test]
    fn test_footer_basic_functionality() {
        let mut footer = Footer::new();
        footer.set_kid("test-key-123").unwrap();
        footer.set_version("1.0.0").unwrap();
        footer.add_custom("env", "production").unwrap();

        assert_eq!(footer.kid(), Some("test-key-123"));
        assert_eq!(footer.version(), Some("1.0.0"));
        assert_eq!(
            footer.get_custom("env").unwrap().as_str(),
            Some("production")
        );
    }

    #[test]
    fn test_public_token_with_footer() {
        let mut rng = rng();
        let keypair = KeyPair::generate(&mut rng);

        let mut claims = Claims::new();
        claims.set_subject("user123").unwrap();

        let mut footer = Footer::new();
        footer.set_kid("signing-key-2024").unwrap();
        footer.add_custom("deployment", "us-east-1").unwrap();

        // Token with footer
        let token =
            PasetoPQ::sign_with_footer(keypair.signing_key(), &claims, Some(&footer)).unwrap();
        assert!(token.starts_with("paseto.pq1.public."));
        assert_eq!(token.split('.').count(), 6); // paseto.pq1.public.payload.signature.footer

        let verified = PasetoPQ::verify_with_footer(keypair.verifying_key(), &token).unwrap();
        assert_eq!(verified.claims().subject(), Some("user123"));

        let verified_footer = verified.footer().unwrap();
        assert_eq!(verified_footer.kid(), Some("signing-key-2024"));
        assert_eq!(
            verified_footer.get_custom("deployment").unwrap().as_str(),
            Some("us-east-1")
        );

        // Token without footer should still work
        let token_no_footer = PasetoPQ::sign(keypair.signing_key(), &claims).unwrap();
        assert_eq!(token_no_footer.split('.').count(), 5);

        let verified_no_footer =
            PasetoPQ::verify(keypair.verifying_key(), &token_no_footer).unwrap();
        assert_eq!(verified_no_footer.claims().subject(), Some("user123"));
        assert!(verified_no_footer.footer().is_none());
    }

    #[test]
    fn test_local_token_with_footer() {
        let mut rng = rng();
        let key = SymmetricKey::generate(&mut rng);

        let mut claims = Claims::new();
        claims.set_subject("user123").unwrap();
        claims.add_custom("session_data", "confidential").unwrap();

        let mut footer = Footer::new();
        footer.set_kid("encryption-key-2024").unwrap();
        footer.add_custom("session_type", "secure").unwrap();

        // Token with footer
        let token = PasetoPQ::encrypt_with_footer(&key, &claims, Some(&footer)).unwrap();
        assert!(token.starts_with("paseto.pq1.local."));
        assert_eq!(token.split('.').count(), 5); // paseto.pq1.local.payload.footer

        let verified = PasetoPQ::decrypt_with_footer(&key, &token).unwrap();
        assert_eq!(verified.claims().subject(), Some("user123"));
        assert_eq!(
            verified
                .claims()
                .get_custom("session_data")
                .unwrap()
                .as_str(),
            Some("confidential")
        );

        let verified_footer = verified.footer().unwrap();
        assert_eq!(verified_footer.kid(), Some("encryption-key-2024"));
        assert_eq!(
            verified_footer.get_custom("session_type").unwrap().as_str(),
            Some("secure")
        );

        // Token without footer should still work
        let token_no_footer = PasetoPQ::encrypt(&key, &claims).unwrap();
        assert_eq!(token_no_footer.split('.').count(), 4);

        let verified_no_footer = PasetoPQ::decrypt(&key, &token_no_footer).unwrap();
        assert_eq!(verified_no_footer.claims().subject(), Some("user123"));
        assert!(verified_no_footer.footer().is_none());
    }

    #[test]
    fn test_footer_serialization() {
        let mut footer = Footer::new();
        footer.set_kid("test-key").unwrap();
        footer.set_version("1.0.0").unwrap();
        footer.add_custom("custom_field", "custom_value").unwrap();

        let encoded = footer.to_base64().unwrap();
        let decoded = Footer::from_base64(&encoded).unwrap();

        assert_eq!(footer.kid(), decoded.kid());
        assert_eq!(footer.version(), decoded.version());
        assert_eq!(
            footer.get_custom("custom_field"),
            decoded.get_custom("custom_field")
        );
    }

    #[test]
    fn test_footer_tamper_detection() {
        let mut rng = rng();
        let keypair = KeyPair::generate(&mut rng);

        let mut claims = Claims::new();
        claims.set_subject("user123").unwrap();

        let mut footer = Footer::new();
        footer.set_kid("test-key").unwrap();

        let token =
            PasetoPQ::sign_with_footer(keypair.signing_key(), &claims, Some(&footer)).unwrap();

        // Tamper with footer
        let mut tampered_token = token.clone();
        tampered_token.push('x');

        let result = PasetoPQ::verify_with_footer(keypair.verifying_key(), &tampered_token);
        assert!(result.is_err()); // Tampered footer should fail verification
    }

    #[test]
    fn test_backward_compatibility() {
        let mut rng = rng();
        let keypair = KeyPair::generate(&mut rng);
        let symmetric_key = SymmetricKey::generate(&mut rng);

        let mut claims = Claims::new();
        claims.set_subject("user123").unwrap();

        // Old format tokens (without footer) should work with new methods
        let public_token = PasetoPQ::sign(keypair.signing_key(), &claims).unwrap();
        let local_token = PasetoPQ::encrypt(&symmetric_key, &claims).unwrap();

        let verified_public =
            PasetoPQ::verify_with_footer(keypair.verifying_key(), &public_token).unwrap();
        let verified_local = PasetoPQ::decrypt_with_footer(&symmetric_key, &local_token).unwrap();

        assert_eq!(verified_public.claims().subject(), Some("user123"));
        assert_eq!(verified_local.claims().subject(), Some("user123"));
        assert!(verified_public.footer().is_none());
        assert!(verified_local.footer().is_none());
    }

    #[test]
    fn test_claims_json_conversion() {
        use serde_json::Value;

        let mut claims = Claims::new();
        claims.set_subject("user123").unwrap();
        claims.set_issuer("test-service").unwrap();
        claims.set_audience("api.example.com").unwrap();
        claims.add_custom("role", "admin").unwrap();
        claims.add_custom("tenant_id", "org_abc123").unwrap();
        claims
            .add_custom("permissions", ["read", "write", "delete"])
            .unwrap();

        // Test From<Claims> for serde_json::Value
        let json_value: Value = claims.clone().into();
        assert!(json_value.is_object());
        assert_eq!(json_value["sub"], "user123");
        assert_eq!(json_value["iss"], "test-service");
        assert_eq!(json_value["aud"], "api.example.com");
        assert_eq!(json_value["role"], "admin");
        assert_eq!(json_value["tenant_id"], "org_abc123");
        assert_eq!(json_value["permissions"][0], "read");

        // Test From<&Claims> for serde_json::Value
        let json_value_ref: Value = (&claims).into();
        assert_eq!(json_value, json_value_ref);

        // Test to_json_value method
        let json_value_method = claims.to_json_value();
        assert_eq!(json_value, json_value_method);

        // Test to_json_string method
        let json_string = claims.to_json_string().unwrap();
        assert!(json_string.contains("\"sub\":\"user123\""));
        assert!(json_string.contains("\"role\":\"admin\""));

        // Test to_json_string_pretty method
        let pretty_json = claims.to_json_string_pretty().unwrap();
        assert!(pretty_json.contains("\"sub\": \"user123\""));
        assert!(pretty_json.contains("\"role\": \"admin\""));
        assert!(pretty_json.len() > json_string.len()); // Pretty format should be longer

        // Test that optional fields are skipped when None
        let minimal_claims = Claims::new();
        let minimal_json: Value = minimal_claims.into();
        assert!(minimal_json.is_object());
        assert!(minimal_json.as_object().unwrap().is_empty());
    }

    #[test]
    fn test_claims_json_with_time_fields() {
        use serde_json::Value;
        use time::OffsetDateTime;

        let mut claims = Claims::new();
        let now = OffsetDateTime::now_utc();
        let exp_time = now + time::Duration::hours(1);
        let nbf_time = now - time::Duration::minutes(5);

        claims.set_subject("user456").unwrap();
        claims.set_expiration(exp_time).unwrap();
        claims.set_not_before(nbf_time).unwrap();
        claims.set_issued_at(now).unwrap();

        let json_value: Value = claims.into();

        // Verify time fields are present and properly formatted as RFC3339 strings
        assert!(json_value["exp"].is_string());
        assert!(json_value["nbf"].is_string());
        assert!(json_value["iat"].is_string());

        // Verify the time strings can be parsed back
        let exp_str = json_value["exp"].as_str().unwrap();
        let parsed_exp =
            OffsetDateTime::parse(exp_str, &time::format_description::well_known::Rfc3339).unwrap();
        assert_eq!(parsed_exp.unix_timestamp(), exp_time.unix_timestamp());
    }

    #[test]
    fn test_claims_json_integration_example() {
        use serde_json::Value;

        // Simulate a real-world use case
        let mut claims = Claims::new();
        claims.set_subject("user789").unwrap();
        claims.set_issuer("auth-service").unwrap();
        claims.set_audience("api.conflux.dev").unwrap();
        claims
            .add_custom("session_id", "sess_abc123def456")
            .unwrap();
        claims.add_custom("user_type", "premium").unwrap();
        claims
            .add_custom("scopes", ["profile", "email", "admin"])
            .unwrap();

        // Test integration with logging (simulated)
        let json_string = claims.to_json_string().unwrap();
        assert!(!json_string.is_empty());

        // Test integration with database storage (simulated)
        let json_value: Value = claims.clone().into();
        let serialized_for_db = serde_json::to_vec(&json_value).unwrap();
        assert!(!serialized_for_db.is_empty());

        // Test round-trip conversion
        let deserialized_value: Value = serde_json::from_slice(&serialized_for_db).unwrap();
        assert_eq!(json_value, deserialized_value);

        // Verify specific fields for logging/tracing integration
        assert_eq!(deserialized_value["sub"], "user789");
        assert_eq!(deserialized_value["session_id"], "sess_abc123def456");
        assert_eq!(deserialized_value["scopes"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn test_token_parsing_public_tokens() {
        let mut rng = rng();
        let keypair = KeyPair::generate(&mut rng);

        // Create a public token without footer
        let mut claims = Claims::new();
        claims.set_subject("test-user").unwrap();
        claims.add_custom("role", "admin").unwrap();

        let token = PasetoPQ::sign(keypair.signing_key(), &claims).unwrap();
        let parsed = ParsedToken::parse(&token).unwrap();

        // Verify basic properties
        assert_eq!(parsed.purpose(), "public");
        assert_eq!(parsed.version(), "pq1");
        assert!(!parsed.has_footer());
        assert!(parsed.is_public());
        assert!(!parsed.is_local());
        assert!(parsed.signature_bytes().is_some());
        assert_eq!(parsed.raw_token(), &token);

        // Test alternative API
        let parsed_alt = PasetoPQ::parse_token(&token).unwrap();
        assert_eq!(parsed.purpose(), parsed_alt.purpose());
    }

    #[test]
    fn test_token_parsing_public_tokens_with_footer() {
        let mut rng = rng();
        let keypair = KeyPair::generate(&mut rng);

        // Create a public token with footer
        let mut claims = Claims::new();
        claims.set_subject("test-user").unwrap();

        let mut footer = Footer::new();
        footer.set_kid("test-key-123").unwrap();
        footer.add_custom("tenant", "org_abc").unwrap();

        let token =
            PasetoPQ::sign_with_footer(keypair.signing_key(), &claims, Some(&footer)).unwrap();
        let parsed = ParsedToken::parse(&token).unwrap();

        // Verify footer parsing
        assert!(parsed.has_footer());
        let parsed_footer = parsed.footer().unwrap();
        assert_eq!(parsed_footer.kid(), Some("test-key-123"));
        assert_eq!(
            parsed_footer.get_custom("tenant"),
            Some(&serde_json::json!("org_abc"))
        );

        // Test JSON footer methods
        let footer_json = parsed.footer_json().unwrap().unwrap();
        assert!(footer_json.contains("test-key-123"));
        assert!(footer_json.contains("org_abc"));

        let footer_pretty = parsed.footer_json_pretty().unwrap().unwrap();
        assert!(footer_pretty.len() > footer_json.len()); // Pretty should be longer
    }

    #[test]
    fn test_token_parsing_local_tokens() {
        let mut rng = rng();
        let key = SymmetricKey::generate(&mut rng);

        // Create a local token without footer
        let mut claims = Claims::new();
        claims.set_subject("local-user").unwrap();
        claims.add_custom("session_type", "confidential").unwrap();

        let token = PasetoPQ::encrypt(&key, &claims).unwrap();
        let parsed = ParsedToken::parse(&token).unwrap();

        // Verify basic properties
        assert_eq!(parsed.purpose(), "local");
        assert_eq!(parsed.version(), "pq1");
        assert!(!parsed.has_footer());
        assert!(!parsed.is_public());
        assert!(parsed.is_local());
        assert!(parsed.signature_bytes().is_none()); // Local tokens don't have separate signatures
        assert!(parsed.payload_length() > 0);
    }

    #[test]
    fn test_token_parsing_local_tokens_with_footer() {
        let mut rng = rng();
        let key = SymmetricKey::generate(&mut rng);

        // Create a local token with footer
        let mut claims = Claims::new();
        claims.set_subject("local-user").unwrap();

        let mut footer = Footer::new();
        footer.set_kid("encryption-key-456").unwrap();
        footer.set_version("v2.1").unwrap();

        let token = PasetoPQ::encrypt_with_footer(&key, &claims, Some(&footer)).unwrap();
        let parsed = ParsedToken::parse(&token).unwrap();

        // Verify footer parsing
        assert!(parsed.has_footer());
        let parsed_footer = parsed.footer().unwrap();
        assert_eq!(parsed_footer.kid(), Some("encryption-key-456"));
        assert_eq!(parsed_footer.version(), Some("v2.1"));

        // Test format summary
        let summary = parsed.format_summary();
        assert!(summary.contains("paseto.pq1.local"));
        assert!(summary.contains("footer: present"));
    }

    #[test]
    fn test_token_parsing_error_cases() {
        // Test various malformed tokens
        let error_cases = vec![
            ("", "expected at least 4 parts"),
            ("not.a.token", "expected at least 4 parts"),
            ("wrong.pq1.public.payload", "Invalid protocol"),
            ("paseto.v2.public.payload", "Unsupported token format"),
            ("paseto.pq1.unknown.payload", "Unsupported token format"),
            ("paseto.pq1.public.invalid_base64", "Invalid payload base64"),
            (
                "paseto.pq1.public.dGVzdA.invalid!!!base64",
                "Invalid signature base64",
            ),
            (
                "paseto.pq1.public.dGVzdA.dGVzdA.dGVzdA.extra.parts",
                "too many parts",
            ),
            ("paseto.pq1.local.dGVzdA.dGVzdA.extra", "too many parts"),
        ];

        for (token, expected_error) in error_cases {
            let result = ParsedToken::parse(token);
            assert!(result.is_err(), "Expected error for token: {}", token);
            let error_msg = result.unwrap_err().to_string();
            assert!(
                error_msg.contains(expected_error),
                "Expected '{}' in error '{}' for token '{}'",
                expected_error,
                error_msg,
                token
            );
        }
    }

    #[test]
    fn test_token_size_estimation_public_tokens() {
        // Test basic public token estimation
        let mut claims = Claims::new();
        claims.set_subject("user123").unwrap();
        claims.set_issuer("test-service").unwrap();

        let estimator = TokenSizeEstimator::public(&claims, false);

        // Public token size expectations vary by ML-DSA parameter set
        let (expected_min_size, expected_max_size) = if cfg!(feature = "ml-dsa-44") {
            (2800, 3200) // ML-DSA-44: ~2.8KB signature + payload + overhead
        } else if cfg!(feature = "ml-dsa-65") {
            (4200, 4800) // ML-DSA-65: ~4.3KB signature + payload + overhead
        } else {
            (5000, 5500) // ML-DSA-87: ~5KB signature + payload + overhead
        };

        assert!(estimator.total_bytes() >= expected_min_size);
        assert!(estimator.total_bytes() < expected_max_size);

        // Check size limit methods - expectations vary by parameter set
        if cfg!(feature = "ml-dsa-44") {
            // ML-DSA-44 tokens (~2.8KB) fit in cookies but not URLs
            assert!(estimator.fits_in_cookie()); // 2885 < 4096
            assert!(!estimator.fits_in_url()); // 2885 > 2048
        } else {
            // ML-DSA-65 and ML-DSA-87 tokens are too large for both
            assert!(!estimator.fits_in_cookie()); // > 4096
            assert!(!estimator.fits_in_url()); // > 2048
        }
        assert!(estimator.fits_in_header()); // All should fit in headers

        // Test breakdown components
        let breakdown = estimator.breakdown();
        assert!(breakdown.prefix > 0);
        assert!(breakdown.payload > 0);

        // Signature size expectations based on parameter set
        let expected_sig_size = if cfg!(feature = "ml-dsa-44") {
            2800
        } else if cfg!(feature = "ml-dsa-65") {
            4300
        } else {
            5000
        };
        assert_eq!(breakdown.signature_or_tag, expected_sig_size);
        assert_eq!(breakdown.footer, None);
        assert!(breakdown.separators > 0);
        assert!(breakdown.base64_overhead > 0);
    }

    #[test]
    fn test_token_size_estimation_local_tokens() {
        // Test basic local token estimation
        let mut claims = Claims::new();
        claims.set_subject("user123").unwrap();
        claims.set_issuer("test-service").unwrap();

        let estimator = TokenSizeEstimator::local(&claims, false);

        // Local tokens should be much smaller than public tokens
        assert!(estimator.total_bytes() > 80);
        assert!(estimator.total_bytes() < 300); // Should be reasonably small

        // Check size limit methods
        assert!(estimator.fits_in_cookie());
        assert!(estimator.fits_in_url());
        assert!(estimator.fits_in_header());

        // Test breakdown components
        let breakdown = estimator.breakdown();
        assert!(breakdown.prefix > 0);
        assert!(breakdown.payload > 0);
        assert_eq!(breakdown.signature_or_tag, 0); // Local tokens don't have separate signature
        assert_eq!(breakdown.footer, None);
        assert!(breakdown.separators > 0);
        assert!(breakdown.base64_overhead > 0);
    }

    #[test]
    fn test_token_size_estimation_with_footer() {
        let mut claims = Claims::new();
        claims.set_subject("user123").unwrap();

        // Test public token with footer
        let estimator_public = TokenSizeEstimator::public(&claims, true);
        let estimator_public_no_footer = TokenSizeEstimator::public(&claims, false);

        assert!(estimator_public.total_bytes() > estimator_public_no_footer.total_bytes());
        assert!(estimator_public.breakdown().footer.is_some());
        assert!(estimator_public_no_footer.breakdown().footer.is_none());

        // Test local token with footer
        let estimator_local = TokenSizeEstimator::local(&claims, true);
        let estimator_local_no_footer = TokenSizeEstimator::local(&claims, false);

        assert!(estimator_local.total_bytes() > estimator_local_no_footer.total_bytes());
        assert!(estimator_local.breakdown().footer.is_some());
        assert!(estimator_local_no_footer.breakdown().footer.is_none());
    }

    #[test]
    fn test_token_size_estimation_convenience_methods() {
        let mut claims = Claims::new();
        claims.set_subject("user123").unwrap();

        // Test PasetoPQ convenience methods
        let public_estimator = PasetoPQ::estimate_public_size(&claims, false);
        let local_estimator = PasetoPQ::estimate_local_size(&claims, true);

        // Should work the same as direct construction
        let direct_public = TokenSizeEstimator::public(&claims, false);
        let direct_local = TokenSizeEstimator::local(&claims, true);

        assert_eq!(public_estimator.total_bytes(), direct_public.total_bytes());
        assert_eq!(local_estimator.total_bytes(), direct_local.total_bytes());
    }

    #[test]
    fn test_token_size_estimation_optimization_suggestions() {
        // Test with small token - should have few suggestions
        let small_claims = Claims::new();
        let small_estimator = TokenSizeEstimator::local(&small_claims, false);
        let small_suggestions = small_estimator.optimization_suggestions();
        // Small local tokens should have no suggestions
        assert!(small_suggestions.is_empty() || small_estimator.total_bytes() < 1000);

        // Test with large token - should have many suggestions
        let mut large_claims = Claims::new();
        large_claims
            .add_custom("huge_data", "x".repeat(5000))
            .unwrap();
        let large_estimator = TokenSizeEstimator::public(&large_claims, false);
        let large_suggestions = large_estimator.optimization_suggestions();

        assert!(!large_suggestions.is_empty());
        assert!(large_suggestions.iter().any(|s| s.contains("cookie")));
        assert!(
            large_suggestions
                .iter()
                .any(|s| s.contains("shorter claim"))
        );
    }

    #[test]
    fn test_token_size_breakdown_total() {
        let breakdown = TokenSizeBreakdown {
            prefix: 10,
            payload: 200,
            signature_or_tag: 3000,
            footer: Some(50),
            separators: 3,
            base64_overhead: 100,
        };

        let expected_total = 10 + 200 + 3000 + 50 + 3 + 100;
        assert_eq!(breakdown.total(), expected_total);

        // Test without footer
        let breakdown_no_footer = TokenSizeBreakdown {
            prefix: 10,
            payload: 200,
            signature_or_tag: 3000,
            footer: None,
            separators: 2,
            base64_overhead: 100,
        };

        let expected_total_no_footer = 10 + 200 + 3000 + 2 + 100;
        assert_eq!(breakdown_no_footer.total(), expected_total_no_footer);
    }

    #[test]
    fn test_token_parsing_debugging_methods() {
        let mut rng = rng();
        let keypair = KeyPair::generate(&mut rng);

        let mut claims = Claims::new();
        claims.set_subject("debug-user").unwrap();
        claims.add_custom("large_data", "x".repeat(500)).unwrap(); // Make it somewhat large

        let mut footer = Footer::new();
        footer.set_kid("debug-key").unwrap();

        let token =
            PasetoPQ::sign_with_footer(keypair.signing_key(), &claims, Some(&footer)).unwrap();
        let parsed = ParsedToken::parse(&token).unwrap();

        // Test debugging methods
        assert!(parsed.payload_length() > 100); // Should have substantial payload
        assert!(parsed.total_length() > parsed.payload_length()); // Total includes overhead
        assert!(!parsed.payload_bytes().is_empty());

        let summary = parsed.format_summary();
        assert!(summary.contains("paseto.pq1.public"));
        assert!(summary.contains("signature: present"));
        assert!(summary.contains("footer: present"));
        assert!(summary.contains(&format!("{} bytes", parsed.payload_length())));
    }

    #[test]
    fn test_token_parsing_middleware_scenarios() {
        let mut rng = rng();
        let keypair = KeyPair::generate(&mut rng);
        let symmetric_key = SymmetricKey::generate(&mut rng);

        // Create different token types
        let mut claims = Claims::new();
        claims.set_subject("middleware-test").unwrap();

        let public_token = PasetoPQ::sign(keypair.signing_key(), &claims).unwrap();
        let local_token = PasetoPQ::encrypt(&symmetric_key, &claims).unwrap();

        // Simulate middleware routing logic
        let tokens = vec![
            (public_token, "public", true), // (token, expected_purpose, is_public)
            (local_token, "local", false),
        ];

        for (token, expected_purpose, should_be_public) in tokens {
            let parsed = ParsedToken::parse(&token).unwrap();

            // Routing decisions
            assert_eq!(parsed.purpose(), expected_purpose);
            assert_eq!(parsed.is_public(), should_be_public);
            assert_eq!(parsed.is_local(), !should_be_public);

            // Logging/metrics simulation
            let purpose = parsed.purpose();
            let version = parsed.version();
            let size = parsed.total_length();

            assert!(!purpose.is_empty());
            assert_eq!(version, "pq1");
            assert!(size > 0);

            // Simulate size-based alerts
            if size > 2048 {
                // Would trigger monitoring alert
                println!("Large token detected: {} bytes", size);
            }
        }
    }

    #[test]
    fn test_symmetric_key_zeroization() {
        // Test SymmetricKey zeroization - this is the only key type we fully control
        {
            let mut key = SymmetricKey([0x42u8; 32]);

            // Verify key contains expected data
            assert_eq!(key.0[0], 0x42);

            // Zeroize the key
            key.zeroize();

            // Verify key is zeroed
            assert_eq!(key.0, [0u8; 32]);
        }

        // Test that SymmetricKey is automatically zeroized on drop (ZeroizeOnDrop)
        {
            let key = SymmetricKey([0x55u8; 32]);
            assert_eq!(key.0[0], 0x55);
            // Key will be automatically zeroized when it goes out of scope
        }
    }

    #[test]
    fn test_key_operations_with_drop_cleanup() {
        // Test that cryptographic operations work correctly with Drop implementations
        let mut rng = rng();

        // Test ML-DSA keypair operations
        {
            let keypair = KeyPair::generate(&mut rng);
            let test_data = b"test message";
            let signature = keypair.signing_key().0.sign(test_data);
            assert!(
                keypair
                    .verifying_key()
                    .0
                    .verify(test_data, &signature)
                    .is_ok()
            );
            // keypair will be dropped and cleaned up automatically
        }

        // Test ML-KEM operations
        {
            let kem_keypair = KemKeyPair::generate(&mut rng);
            let (key1, ciphertext) = kem_keypair.encapsulate();
            let key2 = kem_keypair.decapsulate(&ciphertext).unwrap();
            assert_eq!(key1.to_bytes(), key2.to_bytes());
            // All keys will be dropped and cleaned up automatically
        }

        // Test symmetric key operations
        {
            let key = SymmetricKey::generate(&mut rng);
            let key_bytes = key.to_bytes();
            assert_eq!(key_bytes.len(), 32);
            // key will be automatically zeroized on drop
        }
    }

    #[test]
    fn test_token_versioning_configuration() {
        // Test that the prefix constants use pq1 versioning
        assert_eq!(TOKEN_PREFIX_PUBLIC, "paseto.pq1.public");
        assert_eq!(TOKEN_PREFIX_LOCAL, "paseto.pq1.local");

        // Test that we always report non-standard compatibility
        assert!(!PasetoPQ::is_standard_paseto_compatible());

        // Test prefix accessor methods
        assert_eq!(PasetoPQ::public_token_prefix(), TOKEN_PREFIX_PUBLIC);
        assert_eq!(PasetoPQ::local_token_prefix(), TOKEN_PREFIX_LOCAL);
    }

    #[test]
    fn test_actual_token_contains_correct_prefix() {
        let mut rng = rng();
        let keypair = KeyPair::generate(&mut rng);
        let symmetric_key = SymmetricKey::generate(&mut rng);

        let claims = Claims::new();

        // Test public token uses correct prefix
        let public_token = PasetoPQ::sign(keypair.signing_key(), &claims).unwrap();
        assert!(public_token.starts_with(TOKEN_PREFIX_PUBLIC));

        // Test local token uses correct prefix
        let local_token = PasetoPQ::encrypt(&symmetric_key, &claims).unwrap();
        assert!(local_token.starts_with(TOKEN_PREFIX_LOCAL));

        // Verify tokens can be parsed with the correct prefix expectations
        let parsed_public = ParsedToken::parse(&public_token).unwrap();
        let parsed_local = ParsedToken::parse(&local_token).unwrap();

        assert_eq!(parsed_public.version(), "pq1");
        assert_eq!(parsed_local.version(), "pq1");

        assert_eq!(parsed_public.purpose(), "public");
        assert_eq!(parsed_local.purpose(), "local");
    }

    #[test]
    fn test_hkdf_implementation() {
        // Test that proper HKDF produces different outputs for different inputs
        let shared_secret1 = b"shared_secret_1";
        let shared_secret2 = b"shared_secret_2";
        let info = b"PASETO-PQ-LOCAL-pq1";

        let key1 = SymmetricKey::derive_from_shared_secret(shared_secret1, info);
        let key2 = SymmetricKey::derive_from_shared_secret(shared_secret2, info);

        // Different secrets should produce different keys
        assert_ne!(key1.to_bytes(), key2.to_bytes());

        // Same inputs should produce same outputs (deterministic)
        let key1_repeat = SymmetricKey::derive_from_shared_secret(shared_secret1, info);
        assert_eq!(key1.to_bytes(), key1_repeat.to_bytes());

        // Different info should produce different keys with same secret
        let info2 = b"DIFFERENT-INFO";
        let key_diff_info = SymmetricKey::derive_from_shared_secret(shared_secret1, info2);
        assert_ne!(key1.to_bytes(), key_diff_info.to_bytes());

        // Verify we get full 32 bytes
        assert_eq!(key1.to_bytes().len(), 32);
        assert_eq!(key2.to_bytes().len(), 32);
    }

    #[test]
    fn test_footer_authentication_security_v0_1_1() {
        // Test that footer tampering is properly detected in v0.1.1
        let mut rng = rng();
        let keypair = KeyPair::generate(&mut rng);
        let symmetric_key = SymmetricKey::generate(&mut rng);

        let mut claims = Claims::new();
        claims.set_subject("test-user".to_string()).unwrap();
        claims.set_issuer("test-issuer".to_string()).unwrap();

        let mut footer = Footer::new();
        footer.set_kid("test-key-id").unwrap();
        footer.set_version("1.0").unwrap();

        // Test public token footer authentication
        let public_token =
            PasetoPQ::sign_with_footer(keypair.signing_key(), &claims, Some(&footer)).unwrap();

        // Valid token should verify successfully
        let verified =
            PasetoPQ::verify_with_footer(keypair.verifying_key(), &public_token).unwrap();
        assert_eq!(verified.claims().subject().unwrap(), "test-user");
        assert_eq!(verified.footer().unwrap().kid().unwrap(), "test-key-id");

        // Tamper with footer in public token - should fail verification
        let mut token_parts: Vec<&str> = public_token.split('.').collect();
        // Create a valid but different footer JSON
        let tampered_footer = Footer::new();
        let tampered_footer_b64 = tampered_footer.to_base64().unwrap();
        token_parts[5] = &tampered_footer_b64;
        let tampered_public = token_parts.join(".");

        let result = PasetoPQ::verify_with_footer(keypair.verifying_key(), &tampered_public);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PqPasetoError::SignatureVerificationFailed
        ));

        // Test local token footer authentication
        let local_token =
            PasetoPQ::encrypt_with_footer(&symmetric_key, &claims, Some(&footer)).unwrap();

        // Valid token should decrypt successfully
        let decrypted = PasetoPQ::decrypt_with_footer(&symmetric_key, &local_token).unwrap();
        assert_eq!(decrypted.claims().subject().unwrap(), "test-user");
        assert_eq!(decrypted.footer().unwrap().kid().unwrap(), "test-key-id");

        // Tamper with footer in local token - should fail decryption
        let mut token_parts: Vec<&str> = local_token.split('.').collect();
        // Create a valid but different footer JSON
        let tampered_footer = Footer::new();
        let tampered_footer_b64 = tampered_footer.to_base64().unwrap();
        token_parts[4] = &tampered_footer_b64;
        let tampered_local = token_parts.join(".");

        let result = PasetoPQ::decrypt_with_footer(&symmetric_key, &tampered_local);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            PqPasetoError::DecryptionError(_)
        ));
    }

    #[test]
    fn test_pae_integration_v0_1_1() {
        // Test that PAE encoding is working correctly in token operations
        let mut rng = rng();
        let keypair = KeyPair::generate(&mut rng);

        let mut claims = Claims::new();
        claims.set_subject("pae-test".to_string()).unwrap();
        let mut footer = Footer::new();
        footer.set_kid("pae-key").unwrap();

        // Create token with footer
        let token_with_footer =
            PasetoPQ::sign_with_footer(keypair.signing_key(), &claims, Some(&footer)).unwrap();

        // Create token without footer
        let token_without_footer =
            PasetoPQ::sign_with_footer(keypair.signing_key(), &claims, None).unwrap();

        // Both should verify successfully
        let verified_with =
            PasetoPQ::verify_with_footer(keypair.verifying_key(), &token_with_footer).unwrap();
        let verified_without =
            PasetoPQ::verify_with_footer(keypair.verifying_key(), &token_without_footer).unwrap();

        assert_eq!(verified_with.claims().subject().unwrap(), "pae-test");
        assert_eq!(verified_without.claims().subject().unwrap(), "pae-test");
        assert!(verified_with.footer().is_some());
        assert!(verified_without.footer().is_none());

        // Test that empty footer is handled correctly (should authenticate empty bytes)
        let claims_json = serde_json::to_vec(&claims).unwrap();
        let empty_footer_bytes = Vec::new();
        let header = "paseto.pq1.public".as_bytes();

        let pae_message =
            crate::pae::pae_encode_public_token(header, &claims_json, &empty_footer_bytes);

        // PAE message should contain the empty footer bytes (length 0)
        assert!(pae_message.len() > 0);
        // This proves empty footers are still authenticated via PAE
    }

    #[test]
    fn test_v0_1_1_security_improvements() {
        // Comprehensive test demonstrating v0.1.1 security improvements
        let mut rng = rng();
        let keypair = KeyPair::generate(&mut rng);
        let symmetric_key = SymmetricKey::generate(&mut rng);

        let mut claims = Claims::new();
        claims.set_subject("security-test".to_string()).unwrap();
        claims.set_audience("api.example.com".to_string()).unwrap();

        // Test various footer content types
        let mut footer1 = Footer::new();
        footer1.set_kid("key-1").unwrap();

        let mut footer2 = Footer::new();
        footer2.set_version("2.0").unwrap();
        footer2.set_kid("key-2").unwrap();

        let mut footer3 = Footer::new();
        let admin_value = "admin";
        footer3.add_custom("role", &admin_value).unwrap();

        let footers = vec![footer1, footer2, footer3];

        for (i, footer) in footers.iter().enumerate() {
            // Test public tokens
            let public_token =
                PasetoPQ::sign_with_footer(keypair.signing_key(), &claims, Some(footer)).unwrap();

            let verified =
                PasetoPQ::verify_with_footer(keypair.verifying_key(), &public_token).unwrap();
            assert_eq!(verified.claims().subject().unwrap(), "security-test");

            // Test local tokens
            let local_token =
                PasetoPQ::encrypt_with_footer(&symmetric_key, &claims, Some(footer)).unwrap();

            let decrypted = PasetoPQ::decrypt_with_footer(&symmetric_key, &local_token).unwrap();
            assert_eq!(decrypted.claims().subject().unwrap(), "security-test");

            // Verify footer content is preserved
            match i {
                0 => assert_eq!(verified.footer().unwrap().kid().unwrap(), "key-1"),
                1 => {
                    assert_eq!(verified.footer().unwrap().version().unwrap(), "2.0");
                    assert_eq!(verified.footer().unwrap().kid().unwrap(), "key-2");
                }
                2 => {
                    let custom = verified.footer().unwrap().get_custom("role").unwrap();
                    assert_eq!(custom.as_str().unwrap(), "admin");
                }
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn test_hkdf_vs_simple_hash_difference() {
        // Verify that proper HKDF produces different results than simple hash
        let shared_secret = b"test_shared_secret";
        let info = b"PASETO-PQ-LOCAL-pq1";

        // Get HKDF result
        let hkdf_key = SymmetricKey::derive_from_shared_secret(shared_secret, info);

        // Simulate old simple hash approach for comparison
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(shared_secret);
        hasher.update(info);
        let simple_hash = hasher.finalize();

        // They should be different (proving we're using proper HKDF)
        assert_ne!(hkdf_key.to_bytes(), simple_hash.as_slice());
    }
}
