//! The EC24 Extension to the Unsynchronized Robustly Anamorphic ElGamal scheme.
//!
//! This module implements improvements over the EC22 base scheme, notably:
//! - **Multi-Use Double Keys:** Resolves the one-shot limitation, allowing continuous covert communication using deterministic key ratcheting.
//! - **Covert-Message Presence Indicator:** Enables receivers to quickly detect if a ciphertext carries a covert payload without full decryption attempt.

pub mod double_key;
pub mod indicator;

pub use double_key::MultiUseDoubleKey;
pub use indicator::verify_covert_indicator;
