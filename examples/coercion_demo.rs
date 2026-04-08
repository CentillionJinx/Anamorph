//! # Live Coercion Simulation Demo
//!
//! **Phase 4 — Finalization & Demo**
//!
//! This example simulates the full threat model from the README:
//!
//! 1. **Type-1 Coercion (PRF):** Adversary extracts receiver's secret key.
//! 2. **Type-1 Coercion (XOR):** Same, with the DH-XOR covert channel.
//! 3. **Type-2 Coercion (PRF):** Adversary dictates the normal plaintext.
//! 4. **Type-2 Coercion (XOR):** Same, with the DH-XOR covert channel.
//! 5. **EC24 Multi-Use Double Key Ratcheting:** Demonstrates that consecutive
//!    anamorphic transmissions use fresh randomness via key ratcheting.
//! 6. **EC24 Presence Indicator:** Demonstrates receiver-side detection of
//!    covert payload presence.
//!
//! Run with:
//! ```bash
//! cargo run --example coercion_demo
//! ```

use anamorph::anamorphic::{
    akeygen, aencrypt, adecrypt, aencrypt_xor, adecrypt_xor,
};
use anamorph::anamorphic::decrypt::verify_covert_presence;
use anamorph::ec24::MultiUseDoubleKey;
use anamorph::normal::{encrypt, decrypt};

fn main() {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║       PROJECT ANAMORPH — LIVE COERCION SIMULATION          ║");
    println!("║       Anamorphic ElGamal (EC22 + EC24 Extensions)          ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    // =====================================================================
    // Setup: Generate keys
    // Note: 64-bit primes are used for speed — messages must be short
    // (< 7 bytes to fit within the group element encoding).
    // Production deployments would use 2048-bit primes.
    // =====================================================================
    println!("━━━ Key Generation ━━━");
    let (pk, sk, dk) = akeygen(64).expect("anamorphic key generation failed");
    println!("  ✓ Public key (pk), Secret key (sk), Double key (dk) generated.");
    println!("  ✓ Group: {}-bit safe prime", pk.params.p.bits());
    println!();

    // =====================================================================
    // Scenario 1: Type-1 Coercion — PRF Mode
    // =====================================================================
    println!("━━━ Scenario 1: Type-1 Coercion (PRF Mode) ━━━");
    println!("  Threat: Adversary extracts receiver's secret key (sk).");
    println!();

    let normal_msg = b"ok";
    let covert_msg = b"SOS";

    let ct = aencrypt(&pk, &dk, normal_msg, covert_msg)
        .expect("anamorphic encryption failed");

    // Adversary's view
    let adversary_plaintext = decrypt(&sk, &ct).expect("adversary decryption");
    println!("  [ADVERSARY] Decrypted with extracted sk:");
    println!("    → \"{}\"", String::from_utf8_lossy(&adversary_plaintext));
    assert_eq!(&adversary_plaintext, normal_msg);

    // Can the adversary detect the covert channel? NO.
    println!("  [ADVERSARY] Can detect covert channel? NO ✗");
    println!("    (Ciphertext is indistinguishable from normal ElGamal)");

    // Receiver's view
    let receiver_result = adecrypt(&sk, &dk, &ct, covert_msg)
        .expect("anamorphic decryption failed");
    println!("  [RECEIVER] Decrypted with sk + dk:");
    println!("    → Normal:  \"{}\"", String::from_utf8_lossy(&receiver_result.normal_msg));
    println!("    → Covert:  \"{}\"", String::from_utf8_lossy(
        receiver_result.covert_msg.as_ref().unwrap()));
    assert_eq!(receiver_result.covert_msg.as_ref().unwrap(), covert_msg);
    println!("  ✓ Covert message recovered despite key extraction!");
    println!();

    // =====================================================================
    // Scenario 2: Type-1 Coercion — XOR Mode
    // =====================================================================
    println!("━━━ Scenario 2: Type-1 Coercion (XOR Mode) ━━━");
    println!("  Threat: Adversary extracts sk. Covert data in sideband.");
    println!();

    let covert_xor = b"51N 0W";
    let (ct_xor, covert_enc) = aencrypt_xor(&pk, &dk, normal_msg, covert_xor)
        .expect("XOR encryption failed");

    let adversary_xor = decrypt(&sk, &ct_xor).expect("adversary decrypt XOR");
    println!("  [ADVERSARY] Decrypted with extracted sk:");
    println!("    → \"{}\"", String::from_utf8_lossy(&adversary_xor));
    println!("  [ADVERSARY] Sees sideband bytes but cannot decrypt without dk.");
    println!("    → Sideband (encrypted): {:02x?}", &covert_enc);

    let receiver_xor = adecrypt_xor(&sk, &dk, &ct_xor, &covert_enc)
        .expect("receiver XOR decrypt");
    println!("  [RECEIVER] Recovered covert:");
    println!("    → \"{}\"", String::from_utf8_lossy(
        receiver_xor.covert_msg.as_ref().unwrap()));
    assert_eq!(receiver_xor.covert_msg.as_ref().unwrap(), covert_xor);
    println!("  ✓ Arbitrary-length covert message recovered!");
    println!();

    // =====================================================================
    // Scenario 3: Type-2 Coercion — PRF Mode
    // =====================================================================
    println!("━━━ Scenario 3: Type-2 Coercion (PRF Mode) ━━━");
    println!("  Threat: Adversary dictates the plaintext the sender must encrypt.");
    println!();

    let dictated = b"yes";
    let covert_type2 = b"NO";

    let ct_type2 = aencrypt(&pk, &dk, dictated, covert_type2)
        .expect("type-2 encryption");

    let adversary_type2 = decrypt(&sk, &ct_type2).expect("adversary type-2 decrypt");
    println!("  [ADVERSARY] Verifies dictated message was sent:");
    println!("    → \"{}\"  ✓ Compliance confirmed.", String::from_utf8_lossy(&adversary_type2));
    assert_eq!(&adversary_type2, dictated);

    let receiver_type2 = adecrypt(&sk, &dk, &ct_type2, covert_type2)
        .expect("receiver type-2 decrypt");
    println!("  [RECEIVER] Recovered covert despite dictated normal:");
    println!("    → Normal:  \"{}\"", String::from_utf8_lossy(&receiver_type2.normal_msg));
    println!("    → Covert:  \"{}\"", String::from_utf8_lossy(
        receiver_type2.covert_msg.as_ref().unwrap()));
    assert_eq!(receiver_type2.covert_msg.as_ref().unwrap(), covert_type2);
    println!("  ✓ Sender covertly resisted despite Type-2 coercion!");
    println!();

    // =====================================================================
    // Scenario 4: Type-2 Coercion — XOR Mode
    // =====================================================================
    println!("━━━ Scenario 4: Type-2 Coercion (XOR Mode) ━━━");
    println!("  Threat: Adversary dictates plaintext. Covert via DH-XOR.");
    println!();

    let covert_type2_xor = b"51N 0W";
    let (ct_t2x, covert_t2x_enc) = aencrypt_xor(&pk, &dk, dictated, covert_type2_xor)
        .expect("type-2 XOR encryption");

    let adversary_t2x = decrypt(&sk, &ct_t2x).expect("adversary type-2 XOR");
    println!("  [ADVERSARY] Verifies compliance:");
    println!("    → \"{}\"  ✓", String::from_utf8_lossy(&adversary_t2x));
    assert_eq!(&adversary_t2x, dictated);

    let receiver_t2x = adecrypt_xor(&sk, &dk, &ct_t2x, &covert_t2x_enc)
        .expect("receiver type-2 XOR decrypt");
    println!("  [RECEIVER] Recovered covert payload:");
    println!("    → \"{}\"", String::from_utf8_lossy(
        receiver_t2x.covert_msg.as_ref().unwrap()));
    assert_eq!(receiver_t2x.covert_msg.as_ref().unwrap(), covert_type2_xor);
    println!("  ✓ Coordinates exfiltrated under dictation!");
    println!();

    // =====================================================================
    // Scenario 5: Indistinguishability — Normal vs Anamorphic
    // =====================================================================
    println!("━━━ Scenario 5: Ciphertext Indistinguishability ━━━");
    println!("  Both normal and anamorphic ciphertexts share the same type.");
    println!();

    let normal_ct = encrypt(&pk, b"msg").expect("normal encrypt");
    let anamorphic_ct = aencrypt(&pk, &dk, b"msg", b"hid").expect("anamorphic encrypt");

    let n_dec = decrypt(&sk, &normal_ct).expect("normal decrypt");
    let a_dec = decrypt(&sk, &anamorphic_ct).expect("anamorphic decrypt");

    println!("  Normal     ct → \"{}\"", String::from_utf8_lossy(&n_dec));
    println!("  Anamorphic ct → \"{}\"", String::from_utf8_lossy(&a_dec));
    assert_eq!(n_dec, a_dec);
    println!("  Both decrypt to the same message.");
    println!("  Same Rust type: Ciphertext {{ c1: BigUint, c2: BigUint }}");
    println!("  ✓ Adversary CANNOT distinguish the two ciphertexts!");
    println!();

    // =====================================================================
    // Scenario 6: EC24 — Multi-Use Double Key Ratcheting
    // =====================================================================
    println!("━━━ Scenario 6: EC24 Multi-Use Double Key ━━━");
    println!("  EC22 limitation: double key established once at keygen.");
    println!("  EC24 fix: HMAC ratcheting allows safe reuse.");
    println!();

    let mut multi_dk = MultiUseDoubleKey::new(dk.clone());

    let mut prev_ct = None;
    for i in 0..3 {
        let ct_i = aencrypt(&pk, multi_dk.current_key(), b"hi", b"OK")
            .expect("multi-use encrypt");

        // Each ratcheted key produces a DIFFERENT ciphertext
        if let Some(ref prev) = prev_ct {
            assert_ne!(&ct_i, prev,
                "ratcheted key must produce different ciphertext");
        }

        let dec_i = adecrypt(&sk, multi_dk.current_key(), &ct_i, b"OK")
            .expect("multi-use decrypt");
        assert_eq!(dec_i.covert_msg.as_ref().unwrap(), b"OK");

        println!("  Round {}: use_count={}, covert recovered ✓",
            i + 1, multi_dk.use_count);

        prev_ct = Some(ct_i);
        multi_dk.ratchet(&pk.params);
    }
    println!("  ✓ 3 rounds of ratcheted covert communication — all recovered!");
    println!();

    // =====================================================================
    // Scenario 7: EC24 — Covert Presence Indicator
    // =====================================================================
    println!("━━━ Scenario 7: EC24 Covert Presence Indicator ━━━");
    println!("  Receiver can detect if a ciphertext carries a covert payload");
    println!("  without full decryption attempt.");
    println!();

    let anamorphic_ct2 = aencrypt(&pk, &dk, b"hi", b"sec")
        .expect("anamorphic encrypt for presence");
    let normal_ct2 = encrypt(&pk, b"hi").expect("normal encrypt for presence");

    // PRF presence check
    let has_covert = verify_covert_presence(
        &dk, &anamorphic_ct2, b"sec",
        &pk.params.p, &pk.params.q, &pk.params.g,
    );
    let no_covert = verify_covert_presence(
        &dk, &normal_ct2, b"sec",
        &pk.params.p, &pk.params.q, &pk.params.g,
    );

    println!("  Anamorphic ct carries covert \"sec\"? → {}", if has_covert { "YES ✓" } else { "NO ✗" });
    println!("  Normal ct carries covert \"sec\"?     → {}", if no_covert { "YES ✗ (false positive!)" } else { "NO ✓" });
    assert!(has_covert);
    assert!(!no_covert);
    println!("  ✓ Presence indicator correctly differentiates!");
    println!();

    // =====================================================================
    // Summary
    // =====================================================================
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║                   SIMULATION COMPLETE                      ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║  ✓ Type-1 Coercion (PRF + XOR): Covert survives key       ║");
    println!("║    extraction. Adversary sees only normal plaintext.       ║");
    println!("║  ✓ Type-2 Coercion (PRF + XOR): Covert survives dictated  ║");
    println!("║    plaintext. Adversary's compliance check passes.         ║");
    println!("║  ✓ Indistinguishability: Normal and anamorphic ciphertexts ║");
    println!("║    are structurally identical.                             ║");
    println!("║  ✓ EC24 Multi-Use: Ratcheted double keys provide fresh    ║");
    println!("║    randomness across multiple transmissions.               ║");
    println!("║  ✓ EC24 Presence: Receiver can detect covert payload      ║");
    println!("║    without full decryption.                                ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
}
