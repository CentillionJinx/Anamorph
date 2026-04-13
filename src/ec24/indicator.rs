//! Covert-message presence indicator for EC24 extensions.
//!
//! Enables receivers to confidently state if a normal-seeming ciphertext
//! carries an anamorphic payload.

use num_bigint::BigUint;

use crate::anamorphic::decrypt::verify_covert_presence;
use crate::anamorphic::keygen::DoubleKey;
use crate::errors::Result;
use crate::normal::decrypt::{
    deserialize_ciphertext_for_modulus,
    verify_and_extract_packet_body,
};
use crate::normal::encrypt::SECURE_PACKET_DOMAIN_ANAMORPHIC_PRF;

/// Verifies whether the specified ciphertext carries an anamorphic payload 
/// formatted using the EC24 covert-message presence indicator.
///
/// This function validates secure packet framing and MAC first, then checks
/// PRF-mode covert presence by testing `g^{H(dk, m')} == c1 (mod p)`.
pub fn verify_covert_indicator(
    dk: &DoubleKey,
    packet: &[u8],
    mac_key: &[u8],
    candidate_covert: &[u8],
    p: &BigUint,
    q: &BigUint,
    g: &BigUint,
) -> Result<bool> {
    let body = verify_and_extract_packet_body(
        packet,
        mac_key,
        SECURE_PACKET_DOMAIN_ANAMORPHIC_PRF,
    )?;
    let ct = deserialize_ciphertext_for_modulus(&body[2..], p)?;

    Ok(verify_covert_presence(
        dk,
        &ct,
        candidate_covert,
        p,
        q,
        g,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anamorphic::{aencrypt, akeygen};

    const TEST_MAC_KEY: &[u8] = b"0123456789abcdef";
    const TEST_BLOCK_SIZE: usize = 8;

    #[test]
    fn test_verify_covert_indicator_positive_and_negative() {
        let (pk, _sk, dk) = akeygen(128).expect("akeygen");
        let packet = aencrypt(
            &pk, &dk,
            b"hello", b"secret",
            TEST_MAC_KEY, TEST_BLOCK_SIZE,
        )
        .expect("aencrypt");

        let present = verify_covert_indicator(
            &dk, &packet,
            TEST_MAC_KEY,
            b"secret",
            &pk.params.p,
            &pk.params.q,
            &pk.params.g,
        )
        .expect("indicator present");
        let absent = verify_covert_indicator(
            &dk,
            &packet,
            TEST_MAC_KEY,
            b"wrong",
            &pk.params.p,
            &pk.params.q,
            &pk.params.g,
        )
        .expect("indicator absent");

        assert!(present);
        assert!(!absent);
    }

    #[test]
    fn test_verify_covert_indicator_rejects_tampered_packet() {
        let (pk, _sk, dk) = akeygen(128).expect("akeygen");
        let mut packet = aencrypt(
            &pk, &dk,
            b"hello", b"secret",
            TEST_MAC_KEY, TEST_BLOCK_SIZE,
        )
        .expect("aencrypt");
        let last = packet.len() - 1;
        packet[last] ^= 0x01;

        let result = verify_covert_indicator(
            &dk,
            &packet,
            TEST_MAC_KEY,
            b"secret",
            &pk.params.p,
            &pk.params.q,
            &pk.params.g,
        );
        assert!(result.is_err());
    }
}
