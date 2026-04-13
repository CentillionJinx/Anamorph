//! Anamorphic-mode ElGamal (EC22 base scheme): `aGen`, `aEnc`, `aDec`.
//!
//! The anamorphic mode embeds a covert message inside a syntactically
//! normal ElGamal ciphertext.  The covert message is invisible to an
//! adversary who possesses the normal secret key — it can only be
//! recovered by a party who also holds the **double key**.
//!
//! ## Encryption Modes
//!
//! | Mode | Function | Extraction | Covert size |
//! |------|----------|------------|-------------|
//! | PRF | [`aencrypt`] | Candidate verification | Bounded by msg space |
//! | DH Stream | [`encrypt::aencrypt_stream`] | Direct (per-byte) | Arbitrary |
//! | DH XOR | [`encrypt::aencrypt_xor`] | Direct (XOR) | Arbitrary |

pub mod keygen;
pub mod encrypt;
pub mod decrypt;

pub use keygen::{akeygen, akeygen_from_params, DoubleKey};
pub use encrypt::{
    aencrypt_legacy,
    aencrypt,
    aencrypt_stream_legacy,
    aencrypt_stream,
    aencrypt_xor_legacy,
    aencrypt_xor,
};
pub use decrypt::{
    adecrypt_legacy,
    adecrypt,
    adecrypt_search,
    adecrypt_stream_legacy,
    adecrypt_stream,
    adecrypt_xor_legacy,
    adecrypt_xor,
};
