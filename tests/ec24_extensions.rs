//! Integration tests for the EC24 robustness extensions.
//!
//! Tests the multi-use double-key ratcheting protocol and the
//! covert-message presence indicator.

use anamorph::anamorphic::{
    akeygen, aencrypt, adecrypt, aencrypt_xor, adecrypt_xor,
};
use anamorph::anamorphic::decrypt::verify_covert_presence;
use anamorph::ec24::MultiUseDoubleKey;
use anamorph::normal::{encrypt, decrypt};

// =========================================================================
// Multi-Use Double Key (Ratcheting)
// =========================================================================

/// Each ratchet step must produce a different ciphertext for the same
/// covert message, proving that the underlying dk has changed.
#[test]
fn test_ratchet_produces_distinct_ciphertexts() {
    let (pk, _sk, dk) = akeygen(64).expect("akeygen");
    let mut multi_dk = MultiUseDoubleKey::new(dk);

    let ct0 = aencrypt(&pk, multi_dk.current_key(), b"msg", b"cov")
        .expect("enc round 0");

    multi_dk.ratchet(&pk.params);

    let ct1 = aencrypt(&pk, multi_dk.current_key(), b"msg", b"cov")
        .expect("enc round 1");

    // Same normal + covert inputs → different ciphertext after ratchet.
    assert_ne!(ct0, ct1, "ratcheted key must produce different ciphertext");
}

/// The covert message must be recoverable from every ratchet round
/// when both sender and receiver ratchet in lockstep.
#[test]
fn test_ratchet_roundtrip_lockstep() {
    let (pk, sk, dk) = akeygen(64).expect("akeygen");
    let mut sender_dk = MultiUseDoubleKey::new(dk.clone());
    let mut receiver_dk = MultiUseDoubleKey::new(dk);

    for round in 0..5 {
        let covert = format!("covert-{round}");
        let ct = aencrypt(
            &pk,
            sender_dk.current_key(),
            b"normal",
            covert.as_bytes(),
        )
        .expect("sender encrypt");

        // Both parties verify covert presence
        let present = verify_covert_presence(
            receiver_dk.current_key(),
            &ct,
            covert.as_bytes(),
            &pk.params.p,
            &pk.params.q,
            &pk.params.g,
        );
        assert!(present, "covert should be detectable in round {round}");

        // Receiver recovers both messages
        let result = adecrypt(
            &sk,
            receiver_dk.current_key(),
            &ct,
            covert.as_bytes(),
        )
        .expect("receiver decrypt");
        assert_eq!(result.normal_msg, b"normal".to_vec());
        assert_eq!(
            result.covert_msg.as_ref().unwrap(),
            covert.as_bytes(),
            "covert recovery failed in round {round}"
        );

        // Both ratchet forward
        sender_dk.ratchet(&pk.params);
        receiver_dk.ratchet(&pk.params);
    }
}

/// After ratcheting, the OLD key should no longer verify presence
/// for new ciphertexts, preventing replay across epochs.
#[test]
fn test_ratchet_forward_secrecy() {
    let (pk, _sk, dk) = akeygen(64).expect("akeygen");
    let mut multi_dk = MultiUseDoubleKey::new(dk.clone());
    let old_dk = dk; // snapshot of epoch 0

    multi_dk.ratchet(&pk.params);

    let ct = aencrypt(&pk, multi_dk.current_key(), b"msg", b"cov")
        .expect("encrypt with ratcheted key");

    // Old (pre-ratchet) key should NOT verify presence
    let stale_check = verify_covert_presence(
        &old_dk,
        &ct,
        b"cov",
        &pk.params.p,
        &pk.params.q,
        &pk.params.g,
    );
    assert!(
        !stale_check,
        "old dk should not verify ciphertext from ratcheted epoch"
    );

    // Current key SHOULD verify
    let current_check = verify_covert_presence(
        multi_dk.current_key(),
        &ct,
        b"cov",
        &pk.params.p,
        &pk.params.q,
        &pk.params.g,
    );
    assert!(current_check, "current dk should verify");
}

/// use_count must advance monotonically with each ratchet.
#[test]
fn test_ratchet_use_count() {
    let (pk, _, dk) = akeygen(64).expect("akeygen");
    let mut multi_dk = MultiUseDoubleKey::new(dk);
    assert_eq!(multi_dk.use_count, 0);

    for expected in 1..=10 {
        multi_dk.ratchet(&pk.params);
        assert_eq!(multi_dk.use_count, expected);
    }
}

// =========================================================================
// Multi-Use Double Key with XOR Mode
// =========================================================================

/// XOR mode should also work across ratchet rounds.
#[test]
fn test_ratchet_xor_mode() {
    let (pk, sk, dk) = akeygen(64).expect("akeygen");
    let mut sender_dk = MultiUseDoubleKey::new(dk.clone());
    let mut receiver_dk = MultiUseDoubleKey::new(dk);

    for round in 0..3 {
        let covert = format!("xor-covert-{round}");
        let (ct, enc) = aencrypt_xor(
            &pk,
            sender_dk.current_key(),
            b"normal",
            covert.as_bytes(),
        )
        .expect("XOR encrypt");

        let result = adecrypt_xor(&sk, receiver_dk.current_key(), &ct, &enc)
            .expect("XOR decrypt");
        assert_eq!(result.normal_msg, b"normal".to_vec());
        assert_eq!(
            result.covert_msg.as_ref().unwrap(),
            covert.as_bytes(),
            "XOR covert recovery failed in round {round}"
        );

        sender_dk.ratchet(&pk.params);
        receiver_dk.ratchet(&pk.params);
    }
}

// =========================================================================
// Presence Indicator
// =========================================================================

/// verify_covert_presence must return true for anamorphic ciphertexts
/// with the correct candidate, and false for wrong candidates.
#[test]
fn test_presence_indicator_correct_candidate() {
    let (pk, _, dk) = akeygen(64).expect("akeygen");
    let ct = aencrypt(&pk, &dk, b"hello", b"secret").expect("aencrypt");

    assert!(verify_covert_presence(
        &dk, &ct, b"secret",
        &pk.params.p, &pk.params.q, &pk.params.g,
    ));
    assert!(!verify_covert_presence(
        &dk, &ct, b"wrong",
        &pk.params.p, &pk.params.q, &pk.params.g,
    ));
}

/// verify_covert_presence must return false for a normal (non-anamorphic)
/// ciphertext, even when given the correct dk.
#[test]
fn test_presence_indicator_normal_ct() {
    let (pk, _, dk) = akeygen(64).expect("akeygen");
    let ct = encrypt(&pk, b"hello").expect("normal encrypt");

    // No covert payload was embedded, so any candidate should fail.
    assert!(!verify_covert_presence(
        &dk, &ct, b"anything",
        &pk.params.p, &pk.params.q, &pk.params.g,
    ));
}

/// Indistinguishability under normal decryption: both normal and
/// anamorphic ciphertexts decrypt identically with the secret key alone.
#[test]
fn test_ec24_indistinguishability() {
    let (pk, sk, dk) = akeygen(64).expect("akeygen");
    let mut multi_dk = MultiUseDoubleKey::new(dk);

    let normal_ct = encrypt(&pk, b"msg").expect("normal encrypt");

    multi_dk.ratchet(&pk.params);
    let ec24_ct = aencrypt(&pk, multi_dk.current_key(), b"msg", b"hidden")
        .expect("ec24 encrypt");

    let n_dec = decrypt(&sk, &normal_ct).expect("normal decrypt");
    let a_dec = decrypt(&sk, &ec24_ct).expect("ec24 decrypt");

    assert_eq!(n_dec, a_dec, "both must decrypt to the same normal message");
    assert_eq!(n_dec, b"msg".to_vec());
}

// =========================================================================
// Type-1 Coercion with EC24 Multi-Use Key
// =========================================================================

/// Under Type-1 coercion with a ratcheted key, the adversary still
/// sees only the normal plaintext.
#[test]
fn test_type1_coercion_ec24_ratcheted() {
    let (pk, sk, dk) = akeygen(64).expect("akeygen");
    let mut multi_dk = MultiUseDoubleKey::new(dk);

    // Ratchet a few times
    multi_dk.ratchet(&pk.params);
    multi_dk.ratchet(&pk.params);

    let ct = aencrypt(&pk, multi_dk.current_key(), b"safe", b"HELP")
        .expect("encrypt");

    // Adversary with sk only
    let adversary = decrypt(&sk, &ct).expect("adversary decrypt");
    assert_eq!(adversary, b"safe".to_vec());

    // Receiver with same ratchet state
    let receiver = adecrypt(&sk, multi_dk.current_key(), &ct, b"HELP")
        .expect("receiver decrypt");
    assert_eq!(receiver.normal_msg, b"safe".to_vec());
    assert_eq!(receiver.covert_msg, Some(b"HELP".to_vec()));
}
