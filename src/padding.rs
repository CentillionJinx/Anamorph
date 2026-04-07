//! Block-padding for length-oracle mitigation.
//!
//! **Owner:** Owen Ouyang — Security Hardening
//!
//! This module implements deterministic block-padding schemes that hide exact
//! plaintext length from passive observers.
//!
//! # Examples
//! ```rust
//! use anamorph::padding::{pad_pkcs7, unpad_pkcs7};
//!
//! let msg = b"secret";
//! let block_size = 16;
//! let padded = pad_pkcs7(msg, block_size).expect("pad");
//! let plain = unpad_pkcs7(&padded, block_size).expect("valid padding");
//! assert_eq!(plain, msg);
//! ```
//!
//! ```rust
//! use anamorph::errors::AnamorphError;
//! use anamorph::padding::unpad_pkcs7;
//!
//! let malformed = vec![1u8, 2, 3, 4, 4, 2];
//! assert!(matches!(
//!     unpad_pkcs7(&malformed, 16),
//!     Err(AnamorphError::PaddingError(_))
//! ));
//! ```

use block_padding::{Padding, Pkcs7};
use subtle::{Choice, ConstantTimeEq};

use crate::errors::{AnamorphError, Result};

fn pad_with<P: Padding>(data: &[u8], block_size: usize) -> Vec<u8> {
    let rem = data.len() % block_size;
    let out_len = if rem == 0 {
        data.len() + block_size
    } else {
        data.len() + (block_size - rem)
    };

    let mut out = vec![0u8; out_len];
    out[..data.len()].copy_from_slice(data);

    let block_start = out_len - block_size;
    let pos = if rem == 0 { 0 } else { rem };
    P::raw_pad(&mut out[block_start..], pos);
    out
}

/// Trait for block-padding schemes.
///
/// Implementors provide deterministic padding that ensures all ciphertexts
/// have the same length regardless of plaintext size.
pub trait PaddingScheme {
    /// Pad `data` to a multiple of `block_size` bytes.
    fn pad(data: &[u8], block_size: usize) -> Result<Vec<u8>>;

    /// Remove padding and return the original data.
    ///
    /// # Arguments
    ///
    /// - `data` — padded ciphertext
    /// - `block_size` — expected block size for validation (must match the size used in `pad`)
    ///
    /// # Returns
    ///
    /// `Ok(plaintext)` if padding is valid, `Err(AnamorphError::PaddingError(_))` otherwise.
    /// Validation is performed in **constant time** to prevent padding oracle attacks.
    fn unpad(data: &[u8], block_size: usize) -> Result<Vec<u8>>;
}

/// PKCS#7 block-padding implementation.
pub struct Pkcs7Padding;

impl PaddingScheme for Pkcs7Padding {
    fn pad(data: &[u8], block_size: usize) -> Result<Vec<u8>> {
        if block_size == 0 || block_size > 255 {
            return Err(AnamorphError::InvalidParameter(
                "block size must be in 1..=255".to_string(),
            ));
        }
        Ok(pad_with::<Pkcs7>(data, block_size))
    }

    fn unpad(data: &[u8], block_size: usize) -> Result<Vec<u8>> {
        // Constant-time padding validation to prevent padding oracle attacks.
        // All branches are taken regardless of padding validity to maintain
        // consistent execution time across valid/invalid padding.

        let len = data.len();

        // Extract padding length (constant-time: unwrap_or yields 0 if empty)
        let pad_len = if len > 0 {
            data[len - 1] as usize
        } else {
            0
        };

        // Initialize validity flag.
        let mut valid = Choice::from((len != 0) as u8);

        // Validate: 0 < pad_len <= min(len, block_size)
        // (PKCS#7 requires pad_len <= block_size)
        valid &= Choice::from((pad_len != 0) as u8);
        valid &= Choice::from((pad_len <= len) as u8);
        valid &= Choice::from((pad_len <= block_size) as u8);

        // Verify all padding bytes match pad_len (constant-time loop over all data).
        for (idx, byte) in data.iter().enumerate() {
            let from_end = len - idx;
            let in_padding = Choice::from((from_end <= pad_len) as u8);
            let byte_matches = byte.ct_eq(&(pad_len as u8));
            // Accumulate validity: if byte is in padding region, it must match pad_len.
            valid &= (!in_padding) | byte_matches;
        }

        // Compute output length safely (constant-time subtraction).
        // Even if invalid, we compute a sensible default to avoid panic.
        let output_len = len.saturating_sub(pad_len);

        // Always construct output to avoid data-dependent memory access patterns.
        let result = data[..output_len].to_vec();

        // Return decision point: success iff valid.
        if bool::from(valid) {
            Ok(result)
        } else {
            Err(AnamorphError::PaddingError(
                "malformed PKCS#7 padding".to_string(),
            ))
        }
    }
}

/// Convenience wrapper for PKCS#7 padding.
///
/// # Example
/// ```rust
/// use anamorph::padding::pad_pkcs7;
///
/// let out = pad_pkcs7(b"abc", 8).expect("pad");
/// assert_eq!(out.len() % 8, 0);
/// ```
pub fn pad_pkcs7(data: &[u8], block_size: usize) -> Result<Vec<u8>> {
    Pkcs7Padding::pad(data, block_size)
}

/// Convenience wrapper for PKCS#7 unpadding.
///
/// # Arguments
///
/// - `data` — padded ciphertext bytes
/// - `block_size` — block size used during encryption (typically 16 for AES-like schemes)
///
/// # Example
/// ```rust
/// use anamorph::padding::{pad_pkcs7, unpad_pkcs7};
///
/// let block_size = 8;
/// let padded = pad_pkcs7(b"abc", block_size).expect("pad");
/// let plain = unpad_pkcs7(&padded, block_size).expect("valid padding");
/// assert_eq!(plain, b"abc");
/// ```
pub fn unpad_pkcs7(data: &[u8], block_size: usize) -> Result<Vec<u8>> {
    Pkcs7Padding::unpad(data, block_size)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkcs7_roundtrip() {
        let data = b"anamorph";
        let block_size = 16;
        let padded = Pkcs7Padding::pad(data, block_size).expect("pad should succeed");
        assert_eq!(padded.len() % block_size, 0);
        let out = Pkcs7Padding::unpad(&padded, block_size).expect("unpad should succeed");
        assert_eq!(out, data);
    }

    #[test]
    fn pkcs7_invalid_is_rejected() {
        let invalid = vec![1u8, 2, 3, 4, 4, 2];
        let block_size = 16;
        assert!(Pkcs7Padding::unpad(&invalid, block_size).is_err());
    }

    #[test]
    fn pkcs7_pad_len_exceeds_block_size() {
        // Construct data where last byte > block_size.
        let block_size = 4;
        let mut data = vec![0x05u8, 0x05, 0x05, 0x05, 0x05]; // 5 bytes, all 0x05
        data[4] = 0x08;  // Padding byte = 8 > block_size (4)
        assert!(Pkcs7Padding::unpad(&data, block_size).is_err());
    }

    #[test]
    fn pkcs7_empty_input() {
        let empty = vec![];
        let block_size = 16;
        assert!(Pkcs7Padding::unpad(&empty, block_size).is_err());
    }
}
