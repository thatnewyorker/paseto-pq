//! Pre-Authentication Encoding (PAE) for PASETO RFC compliance
//!
//! This module implements the Pre-Authentication Encoding specification from
//! PASETO RFC Section 2.2.1. PAE is used to authenticate footers in both
//! public and local PASETO tokens.
//!
//! Added in v0.1.1 for proper footer authentication security.

// Error type not needed for PAE module

/// Encode a 64-bit unsigned integer as little-endian bytes
///
/// This is a core primitive for PAE encoding as specified in PASETO RFC Section 2.2.1.
///
/// # Arguments
/// * `n` - The 64-bit integer to encode
///
/// # Returns
/// An 8-byte array containing the little-endian representation
///
/// # Example
/// ```
/// use paseto_pq::pae::le64_encode;
///
/// let encoded = le64_encode(42);
/// assert_eq!(encoded, [42, 0, 0, 0, 0, 0, 0, 0]);
/// ```
pub fn le64_encode(n: u64) -> [u8; 8] {
    n.to_le_bytes()
}

/// Pre-Authentication Encoding as specified in PASETO RFC Section 2.2.1
///
/// PAE encodes a list of byte strings in a way that prevents collision attacks
/// and ensures unambiguous parsing. The encoding format is:
///
/// `PAE(pieces) = le64(pieces.length) || pieces[0].length || pieces[0] || ... || pieces[n].length || pieces[n]`
///
/// Where `||` denotes concatenation and `le64()` is little-endian 64-bit encoding.
///
/// # Arguments
/// * `pieces` - A slice of byte string references to encode
///
/// # Returns
/// A Vec<u8> containing the PAE-encoded result
///
/// # Security
/// This function is critical for PASETO security. It ensures that:
/// - Headers, payloads, and footers cannot be confused with each other
/// - Footer tampering is cryptographically detectable
/// - The encoding is unambiguous and collision-resistant
///
/// # Example
/// ```
/// use paseto_pq::pae::pae_encode;
///
/// let result = pae_encode(&[b"hello", b"world"]);
/// // Result contains: [2,0,0,0,0,0,0,0, 5,0,0,0,0,0,0,0, b"hello", 5,0,0,0,0,0,0,0, b"world"]
/// ```
pub fn pae_encode(pieces: &[&[u8]]) -> Vec<u8> {
    // Calculate total size to pre-allocate vector
    let mut total_size = 8; // 8 bytes for piece count
    for piece in pieces {
        total_size += 8; // 8 bytes for each piece length
        total_size += piece.len(); // plus the piece data itself
    }

    let mut result = Vec::with_capacity(total_size);

    // Encode number of pieces as little-endian u64
    let piece_count = pieces.len() as u64;
    result.extend_from_slice(&le64_encode(piece_count));

    // Encode each piece with its length prefix
    for piece in pieces {
        let piece_len = piece.len() as u64;
        result.extend_from_slice(&le64_encode(piece_len));
        result.extend_from_slice(piece);
    }

    result
}

/// Convenience function to create PAE encoding for PASETO public tokens
///
/// This creates the PAE message used for signing public tokens:
/// `PAE([header, payload_bytes, footer_bytes])`
///
/// # Arguments
/// * `header` - The PASETO header (e.g., "paseto.pq1.public")
/// * `payload_bytes` - The serialized payload bytes (not base64)
/// * `footer_bytes` - The serialized footer bytes (empty slice if no footer)
///
/// # Returns
/// A Vec<u8> containing the PAE-encoded message ready for signing
pub fn pae_encode_public_token(
    header: &[u8],
    payload_bytes: &[u8],
    footer_bytes: &[u8],
) -> Vec<u8> {
    pae_encode(&[header, payload_bytes, footer_bytes])
}

/// Convenience function to create PAE encoding for PASETO local tokens
///
/// This creates the PAE message used as Additional Authenticated Data (AAD)
/// for local token encryption: `PAE([header, nonce_bytes, footer_bytes])`
///
/// # Arguments
/// * `header` - The PASETO header (e.g., "paseto.pq1.local")
/// * `nonce_bytes` - The encryption nonce bytes
/// * `footer_bytes` - The serialized footer bytes (empty slice if no footer)
///
/// # Returns
/// A Vec<u8> containing the PAE-encoded AAD for AEAD encryption
pub fn pae_encode_local_token(header: &[u8], nonce_bytes: &[u8], footer_bytes: &[u8]) -> Vec<u8> {
    pae_encode(&[header, nonce_bytes, footer_bytes])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_le64_encode_zero() {
        let result = le64_encode(0);
        assert_eq!(result, [0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_le64_encode_small_number() {
        let result = le64_encode(42);
        assert_eq!(result, [42, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_le64_encode_large_number() {
        let result = le64_encode(0x123456789ABCDEF0);
        assert_eq!(result, [0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12]);
    }

    #[test]
    fn test_le64_encode_max_value() {
        let result = le64_encode(u64::MAX);
        assert_eq!(result, [0xFF; 8]);
    }

    #[test]
    fn test_pae_encode_empty() {
        let result = pae_encode(&[]);
        // Should contain just the count (0 as le64)
        assert_eq!(result, [0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_pae_encode_single_empty_piece() {
        let result = pae_encode(&[b""]);
        let expected = vec![
            1, 0, 0, 0, 0, 0, 0, 0, // count = 1
            0, 0, 0, 0, 0, 0, 0,
            0, // length = 0
               // no data bytes for empty piece
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_pae_encode_single_piece() {
        let result = pae_encode(&[b"test"]);
        let expected = vec![
            1, 0, 0, 0, 0, 0, 0, 0, // count = 1
            4, 0, 0, 0, 0, 0, 0, 0, // length = 4
            b't', b'e', b's', b't', // "test"
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_pae_encode_multiple_pieces() {
        let result = pae_encode(&[b"hello", b"world"]);
        let expected = vec![
            2, 0, 0, 0, 0, 0, 0, 0, // count = 2
            5, 0, 0, 0, 0, 0, 0, 0, // length = 5
            b'h', b'e', b'l', b'l', b'o', // "hello"
            5, 0, 0, 0, 0, 0, 0, 0, // length = 5
            b'w', b'o', b'r', b'l', b'd', // "world"
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_pae_encode_with_empty_middle_piece() {
        let result = pae_encode(&[b"first", b"", b"third"]);
        let expected = vec![
            3, 0, 0, 0, 0, 0, 0, 0, // count = 3
            5, 0, 0, 0, 0, 0, 0, 0, // length = 5
            b'f', b'i', b'r', b's', b't', // "first"
            0, 0, 0, 0, 0, 0, 0, 0, // length = 0
            // no data for empty piece
            5, 0, 0, 0, 0, 0, 0, 0, // length = 5
            b't', b'h', b'i', b'r', b'd', // "third"
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_pae_encode_binary_data() {
        let binary_data = &[0x00, 0xFF, 0x42, 0x13];
        let result = pae_encode(&[binary_data]);
        let expected = vec![
            1, 0, 0, 0, 0, 0, 0, 0, // count = 1
            4, 0, 0, 0, 0, 0, 0, 0, // length = 4
            0x00, 0xFF, 0x42, 0x13, // binary data
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_pae_encode_large_piece() {
        let large_piece = vec![b'A'; 1000];
        let result = pae_encode(&[&large_piece]);

        // Check structure without comparing entire content
        assert_eq!(result.len(), 8 + 8 + 1000); // count + length + data
        assert_eq!(&result[0..8], &[1, 0, 0, 0, 0, 0, 0, 0]); // count = 1
        assert_eq!(&result[8..16], &le64_encode(1000)); // length = 1000
        assert!(result[16..].iter().all(|&b| b == b'A')); // all 'A's
    }

    // PASETO RFC test vectors
    #[test]
    fn test_pae_encode_rfc_vector_1() {
        // From PASETO RFC: PAE([]) should produce 8 zero bytes
        let result = pae_encode(&[]);
        assert_eq!(result, [0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_pae_encode_rfc_vector_2() {
        // From PASETO RFC: PAE([""])
        let result = pae_encode(&[b""]);
        let expected = vec![
            1, 0, 0, 0, 0, 0, 0, 0, // count = 1
            0, 0, 0, 0, 0, 0, 0, 0, // length = 0
        ];
        assert_eq!(result, expected);
    }

    #[test]
    fn test_pae_encode_rfc_vector_3() {
        // From PASETO RFC: PAE(["test"])
        let result = pae_encode(&[b"test"]);
        let expected = vec![
            1, 0, 0, 0, 0, 0, 0, 0, // count = 1
            4, 0, 0, 0, 0, 0, 0, 0, // length = 4
            b't', b'e', b's', b't', // "test"
        ];
        assert_eq!(result, expected);
    }

    // Convenience function tests
    #[test]
    fn test_pae_encode_public_token() {
        let header = b"paseto.pq1.public";
        let payload = b"{\"sub\":\"test\"}";
        let footer = b"{\"kid\":\"test-key\"}";

        let result = pae_encode_public_token(header, payload, footer);
        let expected = pae_encode(&[header, payload, footer]);

        assert_eq!(result, expected);
    }

    #[test]
    fn test_pae_encode_public_token_no_footer() {
        let header = b"paseto.pq1.public";
        let payload = b"{\"sub\":\"test\"}";
        let footer = b""; // empty footer

        let result = pae_encode_public_token(header, payload, footer);
        let expected = pae_encode(&[header, payload, footer]);

        assert_eq!(result, expected);
    }

    #[test]
    fn test_pae_encode_local_token() {
        let header = b"paseto.pq1.local";
        let nonce = &[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
        ];
        let footer = b"{\"version\":\"1.0\"}";

        let result = pae_encode_local_token(header, nonce, footer);
        let expected = pae_encode(&[header, nonce, footer]);

        assert_eq!(result, expected);
    }

    #[test]
    fn test_pae_encode_local_token_no_footer() {
        let header = b"paseto.pq1.local";
        let nonce = &[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
        ];
        let footer = b""; // empty footer

        let result = pae_encode_local_token(header, nonce, footer);
        let expected = pae_encode(&[header, nonce, footer]);

        assert_eq!(result, expected);
    }

    // Edge case and security tests
    #[test]
    fn test_pae_prevents_collision_attack() {
        // This test ensures PAE prevents collision attacks where
        // different input arrangements could produce the same output

        let result1 = pae_encode(&[b"ab", b"cd"]);
        let result2 = pae_encode(&[b"a", b"bcd"]);
        let result3 = pae_encode(&[b"abc", b"d"]);

        // All should be different due to explicit length encoding
        assert_ne!(result1, result2);
        assert_ne!(result1, result3);
        assert_ne!(result2, result3);
    }

    #[test]
    fn test_pae_is_deterministic() {
        let empty: &[u8] = &[];
        let input = &[b"test" as &[u8], b"data" as &[u8], empty];
        let result1 = pae_encode(input);
        let result2 = pae_encode(input);

        assert_eq!(result1, result2);
    }

    #[test]
    fn test_pae_handles_large_count() {
        // Test with many small pieces
        let pieces: Vec<&[u8]> = vec![b"x"; 100];
        let result = pae_encode(&pieces);

        // Should start with count = 100
        assert_eq!(&result[0..8], &le64_encode(100));

        // Total size should be: 8 (count) + 100 * (8 + 1) = 908 bytes
        assert_eq!(result.len(), 8 + 100 * 9);
    }

    #[test]
    fn test_pae_memory_efficiency() {
        // Test that pre-allocation works correctly
        let pieces = &[
            b"short" as &[u8],
            b"medium-length" as &[u8],
            b"very-long-piece-that-takes-more-space" as &[u8],
        ];
        let result = pae_encode(pieces);

        // Verify the result is correct (implicitly tests memory handling)
        let expected_len = 8 + // count
            (8 + 5) + // "short"
            (8 + 13) + // "medium-length"
            (8 + 37); // "very-long-piece-that-takes-more-space"

        assert_eq!(result.len(), expected_len);
    }
}
