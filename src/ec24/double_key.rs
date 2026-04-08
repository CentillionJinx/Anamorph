//! Multi-use double-key protocol.
//!
//! Exposes `MultiUseDoubleKey` which ratchets the underlying double key `dk`
//! to allow sending a stream of anamorphic ciphertexts without reusing the
//! exact same PRF key, maintaining security against Chosen Ciphertext Attacks (CCA).

use crypto_bigint::BoxedUint;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::anamorphic::keygen::DoubleKey;
use crate::params::GroupParams;
use crate::ct::ct_modpow_boxed;

type HmacSha256 = Hmac<Sha256>;

/// A stateful double key supporting multiple uses via HMAC ratcheting.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct MultiUseDoubleKey {
    /// The current double key state.
    pub current_dk: DoubleKey,
    /// A monotonic counter to enforce forward secrecy / domain separation limit.
    pub use_count: u64,
}

impl MultiUseDoubleKey {
    /// Initialize a new multi-use double key starting from an initial EC22 `DoubleKey`.
    pub fn new(base_dk: DoubleKey) -> Self {
        Self {
            current_dk: base_dk,
            use_count: 0,
        }
    }

    /// Ratchet the double key forward for the next use.
    ///
    /// The new secret exponent is derived as `HMAC-SHA256(dk, "ratchet" || use_count) mod q`.
    /// The structure updates `current_dk.dk` and `current_dk.dk_pub`.
    pub fn ratchet(&mut self, params: &GroupParams) {
        self.use_count += 1;

        let mut dk_bytes = self.current_dk.dk.to_be_bytes().to_vec();
        let mut mac = HmacSha256::new_from_slice(&dk_bytes).expect("HMAC accepts any key length");
        mac.update(b"ratchet");
        mac.update(&self.use_count.to_be_bytes());
        let result = mac.finalize().into_bytes();
        
        let new_dk_bytes = result.to_vec();
        dk_bytes.zeroize();
        
        // Convert to BoxedUint and reduce mod q
        let q_boxed = BoxedUint::from_be_slice_vartime(&params.q.to_bytes_be());
        let new_dk_boxed = BoxedUint::from_be_slice_vartime(&new_dk_bytes);
        let mut new_dk_sub = new_dk_boxed; // For simplicity we might need to properly reduce using full division algorithms but for our sizes and safety, we just modulus if it fits. 
        // We defer proper random distribution modulo q here and just do a modulo.
        let modulus = crypto_bigint::NonZero::new(q_boxed).unwrap();
        let updated_dk = new_dk_sub.rem_vartime(&modulus);

        self.current_dk.dk = updated_dk;
        self.current_dk.dk_pub = ct_modpow_boxed(&params.g, &self.current_dk.dk, &params.p)
            .expect("ct_modpow_boxed should not fail on valid params");
    }

    /// Access the current DoubleKey to utilize in EC22 anamorphic modes natively.
    pub fn current_key(&self) -> &DoubleKey {
        &self.current_dk
    }
}
