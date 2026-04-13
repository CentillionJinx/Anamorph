//! Integration tests for Anamorphic Mode (EC22 base scheme).
//!
//! Tests cover all three encryption modes (PRF, DH stream, DH XOR) and
//! verify correctness, indistinguishability, and coercion resistance.

use anamorph::anamorphic::{
    adecrypt_legacy,
    adecrypt,
    adecrypt_stream_legacy,
    adecrypt_stream,
    adecrypt_xor,
    aencrypt_legacy,
    aencrypt,
    aencrypt_stream_legacy,
    aencrypt_stream,
    aencrypt_xor_legacy,
    aencrypt_xor,
    akeygen,
};
use anamorph::anamorphic::decrypt::{adecrypt_search, verify_covert_presence};
use anamorph::normal::{decrypt_legacy, encrypt_legacy};
use num_bigint::BigUint;

const TEST_MAC_KEY: &[u8] = b"0123456789abcdef";
const TEST_BLOCK_SIZE: usize = 8;

// =========================================================================
// aGen tests
// =========================================================================

/// aGen produces valid keys, double key, and DH public value.
#[test]
fn test_akeygen_produces_double_key() {
    let (pk, sk, dk) = akeygen(64).expect("akeygen");

    // Public key in group
    anamorph::params::validate_group_membership(&pk.h, &pk.params.p, &pk.params.q)
        .expect("pk.h in group");

    // Double key exponent in valid range
    let dk_value = BigUint::from_bytes_be(&dk.dk.to_be_bytes());
    assert!(dk_value >= BigUint::from(1u32));
    assert!(dk_value < pk.params.q);

    // dk_pub = g^dk mod p
    let expected_dk_pub = anamorph::ct::ct_modpow_boxed(&pk.params.g, &dk.dk, &pk.params.p)
        .expect("dk_pub");
    assert_eq!(dk.dk_pub, expected_dk_pub);

    // Keys share the same group params
    assert_eq!(pk.params, sk.params);
}

/// DH shared secret is consistent between sender and receiver.
#[test]
fn test_dh_shared_secret() {
    use num_bigint::RandBigInt;
    use num_traits::One;

    let (pk, _, dk) = akeygen(64).expect("akeygen");

    let mut rng = rand::thread_rng();
    let r = rng.gen_biguint_range(&BigUint::one(), &pk.params.q);

    // Sender: dk_pub^r mod p
    let sender_shared = dk.dk_pub.modpow(&r, &pk.params.p);

    // Receiver: c1^dk mod p (where c1 = g^r)
    let c1 = pk.params.g.modpow(&r, &pk.params.p);
    let receiver_shared = dk.shared_secret(&c1, &pk.params.p);

    assert_eq!(sender_shared, receiver_shared);
}

// =========================================================================
// PRF mode tests
// =========================================================================

/// PRF aEnc -> normal Dec recovers the normal message.
#[test]
fn test_prf_aencrypt_normal_decrypt() {
    let (pk, sk, dk) = akeygen(128).expect("akeygen");
    let packet = aencrypt(
        &pk,
        &dk,
        b"pub",
        b"hid",
        TEST_MAC_KEY,
        TEST_BLOCK_SIZE,
    )
    .expect("aencrypt secure");
    let decrypted = adecrypt(&sk, &dk, &packet, TEST_MAC_KEY, b"hid")
        .expect("adecrypt secure");
    assert_eq!(decrypted.normal_msg, b"pub".to_vec());
}

/// PRF aEnc -> aDec successfully verifies the covert message.
#[test]
fn test_prf_aencrypt_covert_verification() {
    let (pk, sk, dk) = akeygen(128).expect("akeygen");
    let packet = aencrypt(
        &pk,
        &dk,
        b"hello",
        b"secret",
        TEST_MAC_KEY,
        TEST_BLOCK_SIZE,
    )
    .expect("aencrypt secure");

    let result = adecrypt(&sk, &dk, &packet, TEST_MAC_KEY, b"secret")
        .expect("adecrypt secure");
    assert_eq!(result.normal_msg, b"hello".to_vec());
    assert_eq!(result.covert_msg, Some(b"secret".to_vec()));
}

/// PRF aDec with wrong candidate returns None for covert.
#[test]
fn test_prf_wrong_candidate() {
    let (pk, sk, dk) = akeygen(64).expect("akeygen");
    let ct = aencrypt_legacy(&pk, &dk, b"norm", b"real").expect("aencrypt");

    let result = adecrypt_legacy(&sk, &dk, &ct, b"fake").expect("adecrypt");
    assert_eq!(result.normal_msg, b"norm".to_vec());
    assert_eq!(result.covert_msg, None);
}

/// PRF brute-force search finds the covert message.
#[test]
fn test_prf_search() {
    let (pk, sk, dk) = akeygen(64).expect("akeygen");
    let ct = aencrypt_legacy(&pk, &dk, b"hay", b"nd").expect("aencrypt");

    let candidates: Vec<Vec<u8>> = vec![
        b"w1".to_vec(), b"w2".to_vec(), b"nd".to_vec(), b"w3".to_vec(),
    ];
    let result = adecrypt_search(&sk, &dk, &ct, &candidates).expect("search");
    assert_eq!(result.covert_msg, Some(b"nd".to_vec()));
}

/// verify_covert_presence correctly identifies covert messages.
#[test]
fn test_verify_covert_presence_function() {
    let (pk, _, dk) = akeygen(64).expect("akeygen");
    let ct = aencrypt_legacy(&pk, &dk, b"norm", b"cov").expect("aencrypt");

    assert!(verify_covert_presence(
        &dk, &ct, b"cov", &pk.params.p, &pk.params.q, &pk.params.g
    ));
    assert!(!verify_covert_presence(
        &dk, &ct, b"wrong", &pk.params.p, &pk.params.q, &pk.params.g
    ));
}

// =========================================================================
// DH stream mode tests
// =========================================================================

/// DH stream mode: roundtrip for a single covert byte.
#[test]
fn test_stream_single_byte_roundtrip() {
    let (pk, sk, dk) = akeygen(128).expect("akeygen");
    let covert = vec![0x42_u8];
    let packets = aencrypt_stream(
        &pk,
        &dk,
        b"hi",
        &covert,
        TEST_MAC_KEY,
        TEST_BLOCK_SIZE,
        Some(131072),
    )
    .expect("aencrypt_stream secure");
    assert_eq!(packets.len(), 1);

    let result = adecrypt_stream(&sk, &dk, &packets, TEST_MAC_KEY)
        .expect("adecrypt_stream secure");
    assert_eq!(result.normal_msg, b"hi".to_vec());
    assert_eq!(result.covert_msg, Some(covert));
}

/// DH stream mode: all ciphertexts decrypt to the same normal message.
#[test]
fn test_stream_all_cts_same_normal() {
    let (pk, sk, dk) = akeygen(128).expect("akeygen");
    let packets = aencrypt_stream(
        &pk,
        &dk,
        b"hi",
        &[0x00],
        TEST_MAC_KEY,
        TEST_BLOCK_SIZE,
        Some(131072),
    )
    .expect("aencrypt_stream secure");

    for packet in &packets {
        let single_packet = vec![packet.clone()];
        let decoded = adecrypt_stream(&sk, &dk, &single_packet, TEST_MAC_KEY)
            .expect("stream decrypt secure");
        assert_eq!(decoded.normal_msg, b"hi".to_vec());
    }
}

/// DH stream mode: empty covert message produces empty vector.
#[test]
fn test_stream_empty_covert() {
    let (pk, sk, dk) = akeygen(64).expect("akeygen");
    let cts = aencrypt_stream_legacy(&pk, &dk, b"hi", &[], None)
        .expect("aencrypt_stream");
    assert!(cts.is_empty());

    let result = adecrypt_stream_legacy(&sk, &dk, &cts).expect("adecrypt_stream");
    assert_eq!(result.covert_msg, Some(Vec::new()));
}

// =========================================================================
// DH XOR mode tests
// =========================================================================

/// DH XOR mode: full roundtrip with arbitrary-length covert message.
#[test]
fn test_xor_roundtrip() {
    let (pk, sk, dk) = akeygen(128).expect("akeygen");
    let covert_msg = b"arbitrary length covert message!";

    let packet = aencrypt_xor(
        &pk,
        &dk,
        b"hi",
        covert_msg,
        TEST_MAC_KEY,
        TEST_BLOCK_SIZE,
    )
    .expect("aencrypt_xor secure");

    let result = adecrypt_xor(&sk, &dk, &packet, TEST_MAC_KEY)
        .expect("adecrypt_xor secure");

    assert_eq!(result.normal_msg, b"hi".to_vec());
    assert_eq!(result.covert_msg, Some(covert_msg.to_vec()));
}

/// DH XOR mode: normal decryption ignores covert data.
#[test]
fn test_xor_normal_decrypt_unaffected() {
    let (pk, sk, dk) = akeygen(64).expect("akeygen");
    let (ct, _) = aencrypt_xor_legacy(&pk, &dk, b"hi", b"hidden stuff")
        .expect("aencrypt_xor");

    let decrypted = decrypt_legacy(&sk, &ct).expect("decrypt");
    assert_eq!(decrypted, b"hi".to_vec());
}

/// DH XOR mode: different covert messages produce different encrypted blobs.
#[test]
fn test_xor_different_coverts() {
    let (pk, _, dk) = akeygen(64).expect("akeygen");
    let (_, enc1) = aencrypt_xor_legacy(&pk, &dk, b"hi", b"aaa").expect("xor1");
    let (_, enc2) = aencrypt_xor_legacy(&pk, &dk, b"hi", b"bbb").expect("xor2");
    // Encrypted covert blobs differ (different source messages)
    assert_ne!(enc1, enc2);
}

/// DH XOR mode: empty covert message.
#[test]
fn test_xor_empty_covert() {
    let (pk, sk, dk) = akeygen(128).expect("akeygen");
    let packet = aencrypt_xor(
        &pk,
        &dk,
        b"hi",
        b"",
        TEST_MAC_KEY,
        TEST_BLOCK_SIZE,
    )
    .expect("xor secure");
    let result = adecrypt_xor(&sk, &dk, &packet, TEST_MAC_KEY)
        .expect("xor secure decrypt");
    assert_eq!(result.covert_msg, Some(Vec::new()));
}

/// Legacy and secure PRF APIs should recover identical visible/covert plaintexts.
#[test]
fn test_legacy_and_secure_prf_compare() {
    let (pk, sk, dk) = akeygen(128).expect("akeygen");

    let legacy_ct = aencrypt_legacy(&pk, &dk, b"msg", b"cov").expect("legacy aencrypt");
    let legacy = adecrypt_legacy(&sk, &dk, &legacy_ct, b"cov").expect("legacy adecrypt");

    let secure_packet = aencrypt(
        &pk,
        &dk,
        b"msg",
        b"cov",
        TEST_MAC_KEY,
        TEST_BLOCK_SIZE,
    )
    .expect("secure aencrypt");
    let secure = adecrypt(&sk, &dk, &secure_packet, TEST_MAC_KEY, b"cov")
        .expect("secure adecrypt");

    assert_eq!(legacy.normal_msg, b"msg".to_vec());
    assert_eq!(legacy.covert_msg, Some(b"cov".to_vec()));
    assert_eq!(secure.normal_msg, legacy.normal_msg);
    assert_eq!(secure.covert_msg, legacy.covert_msg);
}

// =========================================================================
// Indistinguishability
// =========================================================================

/// Anamorphic ciphertexts are structurally identical to normal ciphertexts.
#[test]
fn test_ciphertext_format_matches_normal() {
    let (pk, _sk, dk) = akeygen(64).expect("akeygen");

    let normal_ct = encrypt_legacy(&pk, b"msg").expect("normal encrypt");
    let anamorphic_ct = aencrypt_legacy(&pk, &dk, b"msg", b"cov").expect("anamorphic encrypt");

    // Both c1 and c2 in [1, p-1] — same type, same range
    assert!(anamorphic_ct.c1 > BigUint::from(0u32));
    assert!(anamorphic_ct.c1 < pk.params.p);
    assert!(anamorphic_ct.c2 > BigUint::from(0u32));
    assert!(anamorphic_ct.c2 < pk.params.p);

    assert!(normal_ct.c1 > BigUint::from(0u32));
    assert!(normal_ct.c1 < pk.params.p);
}
