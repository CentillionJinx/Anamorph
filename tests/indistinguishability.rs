//! property-based tests for the EC22 indistinguishability.
//!
//! check the raw legacy PRF ciphertexts:
//!     anamorphic ciphertexts should still look like normal ElGamal ciphertexts
//!     to someone who only sees the ciphertext and uses ordinary decryption.
//! 
//! suite checks simple proxies:
//! - normal and anamorphic raw ciphertexts have the same public shape
//! - both decrypt to the same visible message under normal decryption
//! - the covert message is only recovered with the right hidden key material
//! - normal ciphertexts are not falsely treated as covert

use std::sync::OnceLock;

use anamorph::anamorphic::keygen::akeygen_from_params;
use anamorph::anamorphic::{adecrypt_legacy, aencrypt_legacy, akeygen, DoubleKey};
use anamorph::normal::{decrypt_legacy, encrypt_legacy};
use anamorph::normal::encrypt::{encode_message, Ciphertext};
use anamorph::normal::keygen::{PublicKey, SecretKey};
use num_bigint::BigUint;
use proptest::prelude::*;
use proptest::test_runner::Config;

const FIXTURE_BITS: usize = 1024;
const MAX_VISIBLE_LEN: usize = 160;
const MAX_COVERT_LEN: usize = 256;
const FAST_CASES: u32 = 1024;
const FRESH_KEY_CASES: u32 = 16;


/// reused fixture for multiple tests since key generation is expensive
fn fixture() -> &'static (PublicKey, SecretKey, DoubleKey) {
    static FIXTURE: OnceLock<(PublicKey, SecretKey, DoubleKey)> = OnceLock::new();
    FIXTURE.get_or_init(|| akeygen(FIXTURE_BITS).expect("fixture key generation"))
}

/// check that the wrong double key is not accidentally the same as the correct one
fn wrong_dk_fixture() -> &'static DoubleKey {
    static WRONG_DK: OnceLock<DoubleKey> = OnceLock::new();
    WRONG_DK.get_or_init(|| {
        let (pk, _, correct_dk) = fixture();

        loop {
            let (_, _, candidate) =
                akeygen_from_params(&pk.params).expect("wrong-dk fixture generation");
            if candidate.dk_pub != correct_dk.dk_pub {
                break candidate;
            }
        }
    })
}

/// visible messages are filtered through the real encoding boundary.
fn visible_msg_strategy() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=MAX_VISIBLE_LEN).prop_filter(
        "message must be encodable under the fixture modulus",
        |msg| {
            let (pk, _, _) = fixture();
            encode_message(msg, &pk.params.p).is_ok()
        },
    )
}

/// covert payloads use a mix of edge cases and randomized values.
fn covert_strategy() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        Just(Vec::new()),
        Just(vec![0]),
        Just(vec![1]),
        Just(vec![0xff]),
        prop::collection::vec(any::<u8>(), 0..=MAX_COVERT_LEN),
    ]
}

fn wrong_candidate(original: &[u8]) -> Vec<u8> {
    if original.is_empty() {
        vec![1]
    } else {
        let mut out = original.to_vec();
        out[0] ^= 1;
        out
    }
}

fn component_is_publicly_well_formed(value: &BigUint, p: &BigUint) -> bool {
    *value > BigUint::from(0u32) && *value < *p
}

fn fixed_width_bytes(value: &BigUint, p: &BigUint) -> Vec<u8> {
    let width = ((p.bits() + 7) / 8) as usize;
    let raw = value.to_bytes_be();
    let mut out = vec![0u8; width];
    if raw.len() <= width {
        out[width - raw.len()..].copy_from_slice(&raw);
    }
    out
}

fn same_public_shape(lhs: &Ciphertext, rhs: &Ciphertext, p: &BigUint) -> bool {
    fixed_width_bytes(&lhs.c1, p).len() == fixed_width_bytes(&rhs.c1, p).len()
        && fixed_width_bytes(&lhs.c2, p).len() == fixed_width_bytes(&rhs.c2, p).len()
}

proptest! {
    #![proptest_config(Config {
        cases: FAST_CASES,
        max_shrink_iters: 5000,
        .. Config::default()
    })]

    // the public shape of the ciphertext should not reveal whether it is normal or anamorphic
    #[test]
    fn legacy_prf_ciphertexts_match_normal_public_shape(
        msg in visible_msg_strategy(),
        covert in covert_strategy()
    ) {
        let (pk, _, dk) = fixture();
        let normal_ct = encrypt_legacy(pk, &msg).expect("normal encrypt");
        let anamorphic_ct = aencrypt_legacy(pk, dk, &msg, &covert).expect("anamorphic encrypt");

        prop_assert!(component_is_publicly_well_formed(&normal_ct.c1, &pk.params.p));
        prop_assert!(component_is_publicly_well_formed(&normal_ct.c2, &pk.params.p));
        prop_assert!(component_is_publicly_well_formed(&anamorphic_ct.c1, &pk.params.p));
        prop_assert!(component_is_publicly_well_formed(&anamorphic_ct.c2, &pk.params.p));
        prop_assert!(same_public_shape(&normal_ct, &anamorphic_ct, &pk.params.p));
    }

    // ordinary decryptor using only the normal secret key should see the same overt plaintext, whether the ciphertext was normal or anamorphic.
    #[test]
    fn legacy_prf_anamorphic_and_normal_decrypt_to_same_visible_message(
        msg in visible_msg_strategy(),
        covert in covert_strategy()
    ) {
        let (pk, sk, dk) = fixture();
        let normal_ct = encrypt_legacy(pk, &msg).expect("normal encrypt");
        let anamorphic_ct = aencrypt_legacy(pk, dk, &msg, &covert).expect("anamorphic encrypt");

        let normal_plain = decrypt_legacy(sk, &normal_ct).expect("normal decrypt");
        let anamorphic_plain = decrypt_legacy(sk, &anamorphic_ct).expect("anamorphic normal decrypt");

        prop_assert_eq!(normal_plain.as_slice(), msg.as_slice());
        prop_assert_eq!(anamorphic_plain.as_slice(), msg.as_slice());
        prop_assert_eq!(normal_plain.as_slice(), anamorphic_plain.as_slice());
    }

    // the double key plus the correct candidate can recover covert content,
    // but a wrong candidate does not change the visible plaintext and does not validate as the embedded covert message.
    #[test]
    fn legacy_prf_covert_information_is_hidden_from_wrong_candidate_checks(
        msg in visible_msg_strategy(),
        covert in covert_strategy()
    ) {
        let (pk, sk, dk) = fixture();
        let ct = aencrypt_legacy(pk, dk, &msg, &covert).expect("anamorphic encrypt");
        let wrong = wrong_candidate(&covert);

        let good = adecrypt_legacy(sk, dk, &ct, &covert).expect("good candidate");
        let bad = adecrypt_legacy(sk, dk, &ct, &wrong).expect("bad candidate");

        prop_assert_eq!(good.normal_msg.as_slice(), msg.as_slice());
        prop_assert_eq!(bad.normal_msg.as_slice(), msg.as_slice());
        prop_assert_eq!(good.covert_msg.as_ref(), Some(&covert));
        prop_assert_ne!(wrong.as_slice(), covert.as_slice());
        prop_assert_ne!(bad.covert_msg.as_ref(), Some(&covert));
    }

    // using the wrong double key still yields the same visible plaintext but must not recover the covert payload.
    #[test]
    fn legacy_prf_wrong_double_key_cannot_recover_covert(
        msg in visible_msg_strategy(),
        covert in covert_strategy()
    ) {
        let (pk, sk, dk) = fixture();
        let wrong_dk = wrong_dk_fixture();
        let ct = aencrypt_legacy(pk, dk, &msg, &covert).expect("anamorphic encrypt");

        let good = adecrypt_legacy(sk, dk, &ct, &covert).expect("good dk");
        let wrong = adecrypt_legacy(sk, wrong_dk, &ct, &covert).expect("wrong dk");

        prop_assert_eq!(good.normal_msg.as_slice(), msg.as_slice());
        prop_assert_eq!(wrong.normal_msg.as_slice(), msg.as_slice());
        prop_assert_eq!(good.covert_msg.as_ref(), Some(&covert));
        prop_assert_eq!(wrong.covert_msg, None);
    }

    // normal ciphertext should not be classified as covert just because the observer guesses some candidate payload.
    #[test]
    fn normal_legacy_ciphertext_is_not_classified_as_covert(
        msg in visible_msg_strategy(),
        candidate in covert_strategy()
    ) {
        let (pk, sk, dk) = fixture();
        let normal_ct = encrypt_legacy(pk, &msg).expect("normal encrypt");
        let decoded = adecrypt_legacy(sk, dk, &normal_ct, &candidate).expect("covert check on normal ct");

        prop_assert_eq!(decoded.normal_msg.as_slice(), msg.as_slice());
        prop_assert_eq!(decoded.covert_msg, None);
    }
}

proptest! {
    #![proptest_config(Config {
        cases: FRESH_KEY_CASES,
        max_shrink_iters: 1000,
        .. Config::default()
    })]

    // fresh keys should also produce anamorphic ciphertexts that match the normal public shape
    #[test]
    fn legacy_prf_public_shape_holds_with_fresh_keys(
        msg in prop::collection::vec(any::<u8>(), 0..=32),
        covert in prop::collection::vec(any::<u8>(), 0..=32)
    ) {
        let (pk, _sk, dk) = akeygen(256).expect("fresh key generation");
        prop_assume!(encode_message(&msg, &pk.params.p).is_ok());

        let normal_ct = encrypt_legacy(&pk, &msg).expect("normal encrypt");
        let anamorphic_ct = aencrypt_legacy(&pk, &dk, &msg, &covert).expect("anamorphic encrypt");

        prop_assert!(component_is_publicly_well_formed(&anamorphic_ct.c1, &pk.params.p));
        prop_assert!(component_is_publicly_well_formed(&anamorphic_ct.c2, &pk.params.p));
        prop_assert!(same_public_shape(&normal_ct, &anamorphic_ct, &pk.params.p));
    }
}
