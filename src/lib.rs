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
//!
//! ## Token Format
//!
//! ```text
//! paseto.v1.pq.<base64url-encoded-payload>.<base64url-encoded-ml-dsa-signature>
//! ```
//!
//! ## Example Usage
//!
//! ```rust,no_run
//! use paseto_pq::{PqPaseto, Claims, KeyPair};
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
//! let token = PqPaseto::sign(&keypair.signing_key, &claims)?;
//!
//! // Verify the token
//! let verified = PqPaseto::verify(&keypair.verifying_key, &token)?;
//! let verified_claims = verified.claims();
//! assert_eq!(verified_claims.subject(), Some("user123"));
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;
use std::fmt;

use anyhow::Result;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ml_dsa::{
    signature::{SignatureEncoding, Signer, Verifier},
    KeyGen, MlDsa65,
};
pub use rand_core::{CryptoRngCore, OsRng};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

#[cfg(feature = "logging")]
use tracing::{debug, instrument, warn};

/// Post-quantum PASETO implementation using ML-DSA-65
pub struct PqPaseto;

/// A post-quantum key pair for signing and verification
#[derive(Clone)]
pub struct KeyPair {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

/// A signing key for creating tokens
#[derive(Clone)]
pub struct SigningKey(ml_dsa::SigningKey<MlDsa65>);

/// A verifying key for validating tokens
#[derive(Clone)]
pub struct VerifyingKey(ml_dsa::VerifyingKey<MlDsa65>);

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<OffsetDateTime>,

    /// Token not-before time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<OffsetDateTime>,

    /// Token issued-at time
    #[serde(skip_serializing_if = "Option::is_none")]
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

/// Verified token containing validated claims
#[derive(Debug, Clone)]
pub struct VerifiedToken {
    claims: Claims,
    raw_token: String,
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
}

// Constants
const TOKEN_PREFIX: &str = "paseto.v1.pq";
const MAX_TOKEN_SIZE: usize = 1024 * 1024; // 1MB max token size

impl KeyPair {
    /// Generate a new post-quantum key pair
    #[cfg_attr(feature = "logging", instrument)]
    pub fn generate<R: CryptoRngCore>(rng: &mut R) -> Self {
        let keypair = MlDsa65::key_gen(rng);

        #[cfg(feature = "logging")]
        debug!("Generated new ML-DSA-65 key pair");

        Self {
            signing_key: SigningKey(keypair.signing_key().clone()),
            verifying_key: VerifyingKey(keypair.verifying_key().clone()),
        }
    }

    /// Export the signing key as bytes
    pub fn signing_key_to_bytes(&self) -> Vec<u8> {
        let encoded = self.signing_key.0.encode();
        encoded.to_vec()
    }

    /// Import signing key from bytes
    pub fn signing_key_from_bytes(bytes: &[u8]) -> Result<SigningKey, PqPasetoError> {
        let encoded = ml_dsa::EncodedSigningKey::<MlDsa65>::try_from(bytes)
            .map_err(|e| PqPasetoError::CryptoError(format!("Invalid key bytes: {:?}", e)))?;
        let key = ml_dsa::SigningKey::<MlDsa65>::decode(&encoded);
        Ok(SigningKey(key))
    }

    /// Export the verifying key as bytes
    pub fn verifying_key_to_bytes(&self) -> Vec<u8> {
        let encoded = self.verifying_key.0.encode();
        encoded.to_vec()
    }

    /// Import verifying key from bytes
    pub fn verifying_key_from_bytes(bytes: &[u8]) -> Result<VerifyingKey, PqPasetoError> {
        let encoded = ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(bytes)
            .map_err(|e| PqPasetoError::CryptoError(format!("Invalid key bytes: {:?}", e)))?;
        let key = ml_dsa::VerifyingKey::<MlDsa65>::decode(&encoded);
        Ok(VerifyingKey(key))
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
}

impl Default for Claims {
    fn default() -> Self {
        Self::new()
    }
}

impl VerifiedToken {
    /// Get the verified claims
    pub fn claims(&self) -> &Claims {
        &self.claims
    }

    /// Get the raw token string
    pub fn raw_token(&self) -> &str {
        &self.raw_token
    }

    /// Extract the claims, consuming the verified token
    pub fn into_claims(self) -> Claims {
        self.claims
    }
}

impl PqPaseto {
    /// Sign claims to create a new token
    #[cfg_attr(feature = "logging", instrument(skip(signing_key)))]
    pub fn sign(signing_key: &SigningKey, claims: &Claims) -> Result<String, PqPasetoError> {
        // Serialize claims to JSON
        let payload = serde_json::to_vec(claims)?;

        #[cfg(feature = "logging")]
        debug!("Serialized claims to {} bytes", payload.len());

        // Base64url encode the payload
        let encoded_payload = URL_SAFE_NO_PAD.encode(&payload);

        // Create the message to sign (prefix + payload)
        let message = format!("{}.{}", TOKEN_PREFIX, encoded_payload);
        let message_bytes = message.as_bytes();

        // Sign with ML-DSA
        let signature = signing_key.0.sign(message_bytes);
        let signature_bytes = signature.to_bytes();

        // Base64url encode the signature
        let encoded_signature = URL_SAFE_NO_PAD.encode(&signature_bytes);

        // Construct final token
        let token = format!("{}.{}.{}", TOKEN_PREFIX, encoded_payload, encoded_signature);

        #[cfg(feature = "logging")]
        debug!(
            "Generated token with {} byte signature",
            signature_bytes.len()
        );

        Ok(token)
    }

    /// Verify a token and extract claims
    #[cfg_attr(feature = "logging", instrument(skip(verifying_key)))]
    pub fn verify(
        verifying_key: &VerifyingKey,
        token: &str,
    ) -> Result<VerifiedToken, PqPasetoError> {
        // Basic size check
        if token.len() > MAX_TOKEN_SIZE {
            return Err(PqPasetoError::InvalidFormat("Token too large".into()));
        }

        // Split token into parts
        let parts: Vec<&str> = token.splitn(5, '.').collect();
        if parts.len() != 5 {
            return Err(PqPasetoError::InvalidFormat(
                "Expected 5 parts separated by '.'".into(),
            ));
        }

        // Verify protocol version (paseto.v1.pq.payload.signature)
        if parts[0] != "paseto" || parts[1] != "v1" || parts[2] != "pq" {
            return Err(PqPasetoError::InvalidFormat(
                "Invalid token format - expected 'paseto.v1.pq'".into(),
            ));
        }

        let encoded_payload = parts[3];
        let encoded_signature = parts[4];

        // Reconstruct message that was signed
        let message = format!("{}.{}.{}.{}", parts[0], parts[1], parts[2], encoded_payload);
        let message_bytes = message.as_bytes();

        // Decode signature
        let signature_bytes = URL_SAFE_NO_PAD.decode(encoded_signature).map_err(|e| {
            PqPasetoError::InvalidFormat(format!("Invalid signature encoding: {}", e))
        })?;

        // Reconstruct signature
        let encoded_sig = ml_dsa::EncodedSignature::<MlDsa65>::try_from(signature_bytes.as_slice())
            .map_err(|e| PqPasetoError::CryptoError(format!("Invalid signature bytes: {:?}", e)))?;
        let signature = ml_dsa::Signature::<MlDsa65>::decode(&encoded_sig)
            .ok_or_else(|| PqPasetoError::CryptoError("Failed to decode signature".into()))?;

        // Verify signature
        verifying_key
            .0
            .verify(message_bytes, &signature)
            .map_err(|_| PqPasetoError::SignatureVerificationFailed)?;

        #[cfg(feature = "logging")]
        debug!("Signature verification successful");

        // Decode and parse payload
        let payload_bytes = URL_SAFE_NO_PAD.decode(encoded_payload).map_err(|e| {
            PqPasetoError::InvalidFormat(format!("Invalid payload encoding: {}", e))
        })?;

        let claims: Claims = serde_json::from_slice(&payload_bytes)?;

        // Basic time validation (with default 30s clock skew tolerance)
        claims.validate_time(OffsetDateTime::now_utc(), time::Duration::seconds(30))?;

        Ok(VerifiedToken {
            claims,
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
        let verified = Self::verify(verifying_key, token)?;

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
            .field("algorithm", &"ML-DSA-65")
            .field("signing_key", &"[REDACTED]")
            .field("verifying_key", &self.verifying_key)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;
    use time::Duration;

    #[test]
    fn test_keypair_generation() {
        let mut rng = thread_rng();
        let keypair = KeyPair::generate(&mut rng);

        // Test bytes export/import
        let signing_bytes = keypair.signing_key_to_bytes();
        let verifying_bytes = keypair.verifying_key_to_bytes();

        assert!(!signing_bytes.is_empty());
        assert!(!verifying_bytes.is_empty());

        let imported_signing = KeyPair::signing_key_from_bytes(&signing_bytes).unwrap();
        let imported_verifying = KeyPair::verifying_key_from_bytes(&verifying_bytes).unwrap();

        // Keys should be functionally equivalent (test by signing/verifying)
        let mut claims = Claims::new();
        claims.set_subject("test").unwrap();

        let token1 = PqPaseto::sign(&keypair.signing_key, &claims).unwrap();
        let token2 = PqPaseto::sign(&imported_signing, &claims).unwrap();

        // Both should verify with either key
        PqPaseto::verify(&keypair.verifying_key, &token1).unwrap();
        PqPaseto::verify(&imported_verifying, &token1).unwrap();
        PqPaseto::verify(&keypair.verifying_key, &token2).unwrap();
        PqPaseto::verify(&imported_verifying, &token2).unwrap();
    }

    #[test]
    fn test_basic_sign_and_verify() {
        let mut rng = thread_rng();
        let keypair = KeyPair::generate(&mut rng);

        let mut claims = Claims::new();
        claims.set_subject("user123").unwrap();
        claims.set_issuer("conflux-auth").unwrap();
        claims.set_audience("conflux-network").unwrap();
        claims.set_jti("token-id-123").unwrap();
        claims.add_custom("tenant_id", "org_abc123").unwrap();
        claims.add_custom("roles", &["user", "admin"]).unwrap();

        let token = PqPaseto::sign(&keypair.signing_key, &claims).unwrap();
        assert!(token.starts_with("paseto.v1.pq."));

        let verified = PqPaseto::verify(&keypair.verifying_key, &token).unwrap();
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
        let mut rng = thread_rng();
        let keypair = KeyPair::generate(&mut rng);

        let now = OffsetDateTime::now_utc();

        // Test expired token
        let mut expired_claims = Claims::new();
        expired_claims.set_subject("user").unwrap();
        expired_claims
            .set_expiration(now - Duration::hours(1))
            .unwrap();

        let expired_token = PqPaseto::sign(&keypair.signing_key, &expired_claims).unwrap();
        let result = PqPaseto::verify(&keypair.verifying_key, &expired_token);
        assert!(matches!(result.unwrap_err(), PqPasetoError::TokenExpired));

        // Test not-yet-valid token
        let mut future_claims = Claims::new();
        future_claims.set_subject("user").unwrap();
        future_claims
            .set_not_before(now + Duration::hours(1))
            .unwrap();

        let future_token = PqPaseto::sign(&keypair.signing_key, &future_claims).unwrap();
        let result = PqPaseto::verify(&keypair.verifying_key, &future_token);
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

        let valid_token = PqPaseto::sign(&keypair.signing_key, &valid_claims).unwrap();
        let verified = PqPaseto::verify(&keypair.verifying_key, &valid_token).unwrap();
        assert_eq!(verified.claims().subject(), Some("user"));
    }

    #[test]
    fn test_audience_and_issuer_validation() {
        let mut rng = thread_rng();
        let keypair = KeyPair::generate(&mut rng);

        let mut claims = Claims::new();
        claims.set_subject("user").unwrap();
        claims.set_audience("api.example.com").unwrap();
        claims.set_issuer("my-service").unwrap();

        let token = PqPaseto::sign(&keypair.signing_key, &claims).unwrap();

        // Valid audience and issuer
        let verified = PqPaseto::verify_with_options(
            &keypair.verifying_key,
            &token,
            Some("api.example.com"),
            Some("my-service"),
            Duration::seconds(30),
        )
        .unwrap();
        assert_eq!(verified.claims().subject(), Some("user"));

        // Invalid audience
        let result = PqPaseto::verify_with_options(
            &keypair.verifying_key,
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
        let result = PqPaseto::verify_with_options(
            &keypair.verifying_key,
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
        let mut rng = thread_rng();
        let keypair1 = KeyPair::generate(&mut rng);
        let keypair2 = KeyPair::generate(&mut rng);

        let mut claims = Claims::new();
        claims.set_subject("user").unwrap();

        let token = PqPaseto::sign(&keypair1.signing_key, &claims).unwrap();

        // Try to verify with wrong key
        let result = PqPaseto::verify(&keypair2.verifying_key, &token);
        assert!(matches!(
            result.unwrap_err(),
            PqPasetoError::SignatureVerificationFailed
        ));
    }

    #[test]
    fn test_malformed_tokens() {
        let mut rng = thread_rng();
        let keypair = KeyPair::generate(&mut rng);

        // Too few parts
        let result = PqPaseto::verify(&keypair.verifying_key, "paseto.v1");
        assert!(matches!(
            result.unwrap_err(),
            PqPasetoError::InvalidFormat(_)
        ));

        // Wrong prefix
        let result = PqPaseto::verify(&keypair.verifying_key, "wrong.v1.pq.payload.sig");
        assert!(matches!(
            result.unwrap_err(),
            PqPasetoError::InvalidFormat(_)
        ));

        // Invalid base64 in payload
        let result = PqPaseto::verify(&keypair.verifying_key, "paseto.v1.pq.invalid!!!.sig");
        assert!(matches!(result.unwrap_err(), PqPasetoError::CryptoError(_)));

        // Invalid signature bytes
        let result = PqPaseto::verify(&keypair.verifying_key, "paseto.v1.pq.dGVzdA.invalid_sig");
        assert!(matches!(result.unwrap_err(), PqPasetoError::CryptoError(_)));
    }
}
