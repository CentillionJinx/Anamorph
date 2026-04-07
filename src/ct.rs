//! Constant-time helpers for secret-dependent arithmetic.
//!
//! This module keeps the private-exponent Montgomery ladder / modular
//! exponentiation path constant-time with respect to the exponent.
//! It does not make the full protocol constant-time: callers still use
//! variable-time `BigUint` conversions, serialization, and some public
//! comparisons at higher layers.
//!
//! **Owner:** Owen Ouyang — Security Hardening
//!
//! This module wraps core operations from the `subtle` crate to keep secret-
//! dependent branching out of higher-level code.

use crypto_bigint::{
    modular::{BoxedMontyForm, BoxedMontyParams},
    BoxedUint,
};
use num_bigint::BigUint;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroize;

use crate::errors::{AnamorphError, Result};

/// Constant-time comparison of two byte slices.
///
/// Returns `Choice(1)` when equal, otherwise `Choice(0)`.
pub fn ct_eq(a: &[u8], b: &[u8]) -> Choice {
    let max_len = a.len().max(b.len());
    let mut a_padded = vec![0u8; max_len];
    let mut b_padded = vec![0u8; max_len];

    a_padded[..a.len()].copy_from_slice(a);
    b_padded[..b.len()].copy_from_slice(b);

    let same_len = Choice::from((a.len() == b.len()) as u8);
    let out = same_len & a_padded.ct_eq(&b_padded);

    a_padded.zeroize();
    b_padded.zeroize();

    out
}

/// Constant-time comparison of two byte slices as a `bool`.
pub fn ct_eq_bool(a: &[u8], b: &[u8]) -> bool {
    bool::from(ct_eq(a, b))
}

/// Constant-time comparison for big integers with fixed-width encoding.
///
/// The caller provides `width` (in bytes), typically derived from the modulus
/// size, so both values are compared on equal-length encodings.
pub fn ct_eq_biguint_fixed(a: &BigUint, b: &BigUint, width: usize) -> Choice {
    let mut a_bytes = a.to_bytes_be();
    let mut b_bytes = b.to_bytes_be();
    let mut valid = Choice::from((a_bytes.len() <= width) as u8);
    valid &= Choice::from((b_bytes.len() <= width) as u8);

    let mut a_fixed = vec![0u8; width];
    let mut b_fixed = vec![0u8; width];

    if a_bytes.len() <= width {
        let a_off = width - a_bytes.len();
        a_fixed[a_off..].copy_from_slice(&a_bytes);
    }
    a_bytes.zeroize();

    if b_bytes.len() <= width {
        let b_off = width - b_bytes.len();
        b_fixed[b_off..].copy_from_slice(&b_bytes);
    }
    b_bytes.zeroize();

    let out = valid & a_fixed.ct_eq(&b_fixed);

    a_fixed.zeroize();
    b_fixed.zeroize();

    out
}

/// Modular exponentiation using runtime Montgomery parameters.
///
/// The exponent is supplied as a `BigUint` and encoded to fixed precision
/// based on `modulus` width before entering the CT Montgomery path.
/// The surrounding `BigUint` conversion is still variable-time.
pub fn ct_modpow_biguint(base: &BigUint, exponent: &BigUint, modulus: &BigUint) -> Result<BigUint> {
    let bits = modulus.bits() as u32;
    let exp = boxed_uint_from_biguint(exponent, bits)?;
    ct_modpow_boxed(base, &exp, modulus)
}

/// Modular exponentiation using runtime Montgomery parameters.
///
/// The modular exponentiation itself is constant-time with respect to the
/// secret exponent, but the final conversion back to `BigUint` uses a
/// variable-time byte trim for interoperability with existing call sites.
pub fn ct_modpow_boxed(base: &BigUint, exponent: &BoxedUint, modulus: &BigUint) -> Result<BigUint> {
    let bits = modulus.bits() as u32;
    let mod_boxed = boxed_uint_from_biguint(modulus, bits)?;
    let mod_odd = Option::from(mod_boxed.to_odd())
        .ok_or_else(|| AnamorphError::InvalidParameter("modulus must be odd".to_string()))?;
    let params = BoxedMontyParams::new(mod_odd);

    let base_boxed = boxed_uint_from_biguint(base, bits)?;
    let out = BoxedMontyForm::new(base_boxed, &params)
        .pow(exponent)
        .retrieve();
    let mut out_bytes = out.to_be_bytes();
    let result = BigUint::from_bytes_be(&out_bytes);
    out_bytes.zeroize();

    Ok(result)
}

fn boxed_uint_from_biguint(value: &BigUint, bits_precision: u32) -> Result<BoxedUint> {
    let mut bytes = value.to_bytes_be();
    let parsed = BoxedUint::from_be_slice(&bytes, bits_precision)
        .map_err(|_| AnamorphError::InvalidParameter("integer does not fit precision".to_string()));
    bytes.zeroize();
    parsed
}

/// Selects `b` when `choice == 1`, otherwise selects `a`, in constant time.
pub fn ct_select<T: ConditionallySelectable>(a: &T, b: &T, choice: Choice) -> T {
    T::conditional_select(a, b, choice)
}

/// Conditionally swaps `a` and `b` in constant time when `choice == 1`.
pub fn ct_swap<T: ConditionallySelectable>(a: &mut T, b: &mut T, choice: Choice) {
    T::conditional_swap(a, b, choice);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_eq_works() {
        assert!(bool::from(ct_eq(b"abc", b"abc")));
        assert!(!bool::from(ct_eq(b"abc", b"abd")));
        assert!(!bool::from(ct_eq(b"abc", b"ab")));
        assert!(ct_eq_bool(b"xyz", b"xyz"));
    }

    #[test]
    fn select_and_swap_work() {
        let mut a = 10u32;
        let mut b = 20u32;

        let selected = ct_select(&a, &b, Choice::from(1));
        assert_eq!(selected, 20);

        ct_swap(&mut a, &mut b, Choice::from(1));
        assert_eq!(a, 20);
        assert_eq!(b, 10);
    }
}
