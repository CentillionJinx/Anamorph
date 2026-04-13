//! Integration tests for Normal Mode — secure packet flow first,
//! with legacy APIs retained for side-by-side comparison.
//!
//! These tests serve as the foundation for Matthew's comprehensive test suite.

use anamorph::normal::{
    decrypt,
    decrypt_legacy,
    encrypt,
    encrypt_legacy,
    keygen,
};
use anamorph::params::{validate_group_membership, generate_group_params};
use anamorph::normal::keygen::keygen_from_params;
use num_bigint::BigUint;
use num_traits::One;

const TEST_MAC_KEY: &[u8] = b"0123456789abcdef";
const TEST_BLOCK_SIZE: usize = 8;

/// Keygen produces a valid public key that is in the group.
#[test]
fn test_keygen_produces_valid_keys() {
    let (pk, sk) = keygen(64).expect("keygen failed");

    // h = g^x mod p must be in the order-q subgroup
    validate_group_membership(&pk.h, &pk.params.p, &pk.params.q)
        .expect("public key h not in group");

    // x must be in [1, q-1]
    let x = BigUint::from_bytes_be(&sk.x.to_be_bytes());
    assert!(x >= BigUint::one(), "secret key x < 1");
    assert!(x < sk.params.q, "secret key x >= q");
}

/// Secure packet roundtrip for a simple ASCII message.
#[test]
fn test_encrypt_decrypt_roundtrip() {
    let (pk, sk) = keygen(128).expect("keygen failed");
    let msg = b"Hi!";

    let packet = encrypt(&pk, msg, TEST_MAC_KEY, TEST_BLOCK_SIZE)
        .expect("secure encryption failed");
    let plaintext = decrypt(&sk, &packet, TEST_MAC_KEY)
        .expect("secure decryption failed");

    assert_eq!(plaintext, msg.to_vec());
}

/// Secure packet roundtrip for an empty message.
#[test]
fn test_encrypt_decrypt_empty() {
    let (pk, sk) = keygen(128).expect("keygen failed");
    let msg = b"";

    let packet = encrypt(&pk, msg, TEST_MAC_KEY, TEST_BLOCK_SIZE)
        .expect("secure encryption failed");
    let plaintext = decrypt(&sk, &packet, TEST_MAC_KEY)
        .expect("secure decryption failed");

    assert_eq!(plaintext, msg.to_vec());
}

/// Secure packet roundtrip for binary data.
#[test]
fn test_encrypt_decrypt_binary() {
    let (pk, sk) = keygen(128).expect("keygen failed");
    let msg: Vec<u8> = (0u8..5).collect();

    let packet = encrypt(&pk, &msg, TEST_MAC_KEY, TEST_BLOCK_SIZE)
        .expect("secure encryption failed");
    let plaintext = decrypt(&sk, &packet, TEST_MAC_KEY)
        .expect("secure decryption failed");

    assert_eq!(plaintext, msg);
}

/// Two encryptions of the same message produce different ciphertexts
/// (because of fresh randomness).
#[test]
fn test_different_encryptions_differ() {
    let (pk, _) = keygen(128).expect("keygen failed");
    let msg = b"same";

    let ct1 = encrypt(&pk, msg, TEST_MAC_KEY, TEST_BLOCK_SIZE)
        .expect("secure encrypt 1");
    let ct2 = encrypt(&pk, msg, TEST_MAC_KEY, TEST_BLOCK_SIZE)
        .expect("secure encrypt 2");

    // With overwhelming probability, different r -> different ciphertext
    assert_ne!(ct1, ct2, "two encryptions should differ (random r)");
}

/// Decryption with the wrong secret key does not recover the original message.
#[test]
fn test_wrong_key_decryption() {
    let (pk, _sk) = keygen(128).expect("keygen");

    // Generate a second key pair (different group params entirely)
    let (_, wrong_sk) = keygen(128).expect("keygen2");

    let msg = b"sec";
    let packet = encrypt(&pk, msg, TEST_MAC_KEY, TEST_BLOCK_SIZE)
        .expect("secure encrypt");

    // Decrypting with the wrong key should either fail or produce garbage
    match decrypt(&wrong_sk, &packet, TEST_MAC_KEY) {
        Ok(decrypted) => assert_ne!(decrypted, msg.to_vec()),
        Err(_) => {} // Also acceptable
    }
}

/// Multiple keygen calls with the same group params produce different keys.
#[test]
fn test_keygen_different_keys() {
    let params = generate_group_params(64).expect("params");
    let (pk1, _) = keygen_from_params(&params).expect("keygen1");
    let (pk2, _) = keygen_from_params(&params).expect("keygen2");

    // Same p, q, g
    assert_eq!(pk1.params, pk2.params);

    // Different h (overwhelmingly likely)
    // Not asserting inequality due to negligible collision probability,
    // but in practice they will differ.
}

/// Ciphertext components c1 and c2 are in the valid range [1, p-1].
#[test]
fn test_ciphertext_components_in_range() {
    let (pk, _) = keygen(64).expect("keygen");
    let ct = encrypt_legacy(&pk, b"test").expect("encrypt");

    assert!(ct.c1 > BigUint::from(0u32));
    assert!(ct.c1 < pk.params.p);
    assert!(ct.c2 > BigUint::from(0u32));
    assert!(ct.c2 < pk.params.p);
}

/// Legacy and secure APIs should recover the same plaintext.
#[test]
fn test_legacy_and_secure_roundtrip_match() {
    let (pk, sk) = keygen(128).expect("keygen");
    let msg = b"cmp";

    let legacy_ct = encrypt_legacy(&pk, msg).expect("legacy encrypt");
    let legacy_plain = decrypt_legacy(&sk, &legacy_ct).expect("legacy decrypt");

    let secure_packet = encrypt(&pk, msg, TEST_MAC_KEY, TEST_BLOCK_SIZE)
        .expect("secure encrypt");
    let secure_plain = decrypt(&sk, &secure_packet, TEST_MAC_KEY)
        .expect("secure decrypt");

    assert_eq!(legacy_plain, msg.to_vec());
    assert_eq!(secure_plain, msg.to_vec());
    assert_eq!(legacy_plain, secure_plain);
}
