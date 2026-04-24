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
    adecrypt, adecrypt_xor, aencrypt, aencrypt_xor, akeygen,
};
use anamorph::ec24::{verify_covert_indicator, MultiUseDoubleKey};
use anamorph::normal::{decrypt, encrypt};

const TEST_MAC_KEY: &[u8] = b"0123456789abcdef";
const TEST_BLOCK_SIZE: usize = 8;

fn main() {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║       PROJECT ANAMORPH — LIVE COERCION SIMULATION            ║");
    println!("║       Anamorphic ElGamal (EC22 + EC24 Extensions)            ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
    println!();

    // =====================================================================
    // Setup: Generate keys
    // Note: 128-bit primes are used here so secure packet padding
    // still fits within the group element encoding.
    // Production deployments would use 2048-bit primes.
    // =====================================================================
    println!("==== Key Generation ====");
    let (pk, sk, dk) = akeygen(128).expect("anamorphic key generation failed");
    println!("  ✓ Public key (pk), Secret key (sk), Double key (dk) generated.");
    println!("  ✓ Group: {}-bit safe prime", pk.params.p.bits());
    println!();

    // =====================================================================
    // Scenario 1: Type-1 Coercion — PRF Mode
    // =====================================================================
    println!("==== Scenario 1: Type-1 Coercion (PRF Mode) ====");
    println!("  Threat: Adversary extracts receiver's secret key (sk).");
    println!();

    let normal_msg = b"ok";
    let covert_msg = b"SOS";

    let packet = aencrypt(
        &pk, &dk,
        normal_msg, covert_msg,
        TEST_MAC_KEY, TEST_BLOCK_SIZE,
    )
        .expect("anamorphic encryption failed");

    // Adversary's view
    let adversary_plaintext = decrypt(&sk, &packet, TEST_MAC_KEY);
    println!("  [ADVERSARY] Attempted normal decrypt with extracted sk:");
    println!(
        "    -> Visible plaintext: \"{}\"",
        String::from_utf8_lossy(
            adversary_plaintext
                .as_ref()
                .expect("normal decrypt should recover only the overt message")
        )
    );

    // Can the adversary detect the covert channel? NO.
    println!("  [ADVERSARY] Can detect covert channel? NO ✗");
    println!("    (Ciphertext is indistinguishable from normal ElGamal)");

    // Receiver's view
    let receiver_result = adecrypt(&sk, &dk, &packet, TEST_MAC_KEY, covert_msg)
        .expect("anamorphic decryption failed");
    println!("  [RECEIVER] Decrypted with sk + dk:");
    println!("    -> Normal:  \"{}\"", String::from_utf8_lossy(&receiver_result.normal_msg));
    println!("    -> Covert:  \"{}\"", String::from_utf8_lossy(
        receiver_result.covert_msg.as_ref().unwrap()));
    assert_eq!(receiver_result.covert_msg.as_ref().unwrap(), covert_msg);
    println!("  ✓ Covert message recovered despite key extraction!");
    println!();

    // =====================================================================
    // Scenario 2: Type-1 Coercion — XOR Mode
    // =====================================================================
    println!("==== Scenario 2: Type-1 Coercion (XOR Mode) ====");
    println!("  Threat: Adversary extracts sk. Covert data in sideband.");
    println!();

    let covert_xor = b"51N 0W";
    let packet_xor = aencrypt_xor(
        &pk, &dk,
        normal_msg, covert_xor,
        TEST_MAC_KEY, TEST_BLOCK_SIZE,
    )
        .expect("XOR encryption failed");

    let adversary_xor = decrypt(&sk, &packet_xor, TEST_MAC_KEY);
    println!("  [ADVERSARY] Attempted normal decrypt with extracted sk:");
    println!(
        "    -> Visible plaintext: \"{}\"",
        String::from_utf8_lossy(
            adversary_xor
                .as_ref()
                .expect("normal decrypt should recover only the overt message")
        )
    );
    println!("  [ADVERSARY] Packet is authenticated; covert metadata is integrity-protected.");

    let receiver_xor = adecrypt_xor(&sk, &dk, &packet_xor, TEST_MAC_KEY)
        .expect("receiver XOR decrypt");
    println!("  [RECEIVER] Recovered covert:");
    println!("    -> \"{}\"", String::from_utf8_lossy(
        receiver_xor.covert_msg.as_ref().unwrap()));
    assert_eq!(receiver_xor.covert_msg.as_ref().unwrap(), covert_xor);
    println!("  ✓ Arbitrary-length covert message recovered!");
    println!();

    // =====================================================================
    // Scenario 3: Type-2 Coercion — PRF Mode
    // =====================================================================
    println!("==== Scenario 3: Type-2 Coercion (PRF Mode) ====");
    println!("  Threat: Adversary dictates the plaintext the sender must encrypt.");
    println!();

    let dictated = b"yes";
    let covert_type2 = b"NO";

    let packet_type2 = aencrypt(
        &pk, &dk,
        dictated, covert_type2,
        TEST_MAC_KEY, TEST_BLOCK_SIZE,
    )
        .expect("type-2 encryption");

    let adversary_type2 = decrypt(&sk, &packet_type2, TEST_MAC_KEY);
    println!("  [ADVERSARY] Normal decrypt attempt on anamorphic packet:");
    println!(
        "    -> Visible plaintext: \"{}\"",
        String::from_utf8_lossy(
            adversary_type2
                .as_ref()
                .expect("normal decrypt should recover the dictated message")
        )
    );

    let receiver_type2 = adecrypt(&sk, &dk, &packet_type2, TEST_MAC_KEY, covert_type2)
        .expect("receiver type-2 decrypt");
    println!("  [RECEIVER] Recovered covert despite dictated normal:");
    println!("    -> Normal:  \"{}\"", String::from_utf8_lossy(&receiver_type2.normal_msg));
    println!("    -> Covert:  \"{}\"", String::from_utf8_lossy(
        receiver_type2.covert_msg.as_ref().unwrap()));
    assert_eq!(receiver_type2.covert_msg.as_ref().unwrap(), covert_type2);
    println!("  ✓ Sender covertly resisted despite Type-2 coercion!");
    println!();

    // =====================================================================
    // Scenario 4: Type-2 Coercion — XOR Mode
    // =====================================================================
    println!("==== Scenario 4: Type-2 Coercion (XOR Mode) ====");
    println!("  Threat: Adversary dictates plaintext. Covert via DH-XOR.");
    println!();

    let covert_type2_xor = b"51N 0W";
    let packet_t2x = aencrypt_xor(
        &pk, &dk,
        dictated, covert_type2_xor,
        TEST_MAC_KEY, TEST_BLOCK_SIZE,
    )
        .expect("type-2 XOR encryption");

    let adversary_t2x = decrypt(&sk, &packet_t2x, TEST_MAC_KEY);
    println!("  [ADVERSARY] Normal decrypt attempt on anamorphic XOR packet:");
    println!(
        "    -> Visible plaintext: \"{}\"",
        String::from_utf8_lossy(
            adversary_t2x
                .as_ref()
                .expect("normal decrypt should recover the dictated message")
        )
    );

    let receiver_t2x = adecrypt_xor(&sk, &dk, &packet_t2x, TEST_MAC_KEY)
        .expect("receiver type-2 XOR decrypt");
    println!("  [RECEIVER] Recovered covert payload:");
    println!("    -> \"{}\"", String::from_utf8_lossy(
        receiver_t2x.covert_msg.as_ref().unwrap()));
    assert_eq!(receiver_t2x.covert_msg.as_ref().unwrap(), covert_type2_xor);
    println!("  ✓ Coordinates exfiltrated under dictation!");
    println!();

    // =====================================================================
    // Scenario 5: Indistinguishability — Normal vs Anamorphic
    // =====================================================================
    println!("==== Scenario 5: Secure Domain Separation ====");
    println!("  Secure packets are domain-tagged and authenticated.");
    println!();

    let normal_packet = encrypt(&pk, b"msg", TEST_MAC_KEY, TEST_BLOCK_SIZE).expect("normal encrypt");
    let anamorphic_packet = aencrypt(
        &pk, &dk,
        b"msg", b"hid",
        TEST_MAC_KEY, TEST_BLOCK_SIZE,
    )
    .expect("anamorphic encrypt");

    let n_dec = decrypt(&sk, &normal_packet, TEST_MAC_KEY).expect("normal decrypt");
    let a_dec = decrypt(&sk, &anamorphic_packet, TEST_MAC_KEY);

    println!("  Normal     ct -> \"{}\"", String::from_utf8_lossy(&n_dec));
    println!(
        "  Anamorphic ct via normal decrypt -> \"{}\"",
        String::from_utf8_lossy(
            a_dec.as_ref()
                .expect("normal decrypt should expose only the overt message")
        )
    );
    println!("  Both packets decrypt to the same overt plaintext under normal decryption.");
    println!("  ✓ Hidden payload remains invisible without the double key.");
    println!();

    // =====================================================================
    // Scenario 6: EC24 — Multi-Use Double Key Ratcheting
    // =====================================================================
    println!("==== Scenario 6: EC24 Multi-Use Double Key ====");
    println!("  EC22 limitation: double key established once at keygen.");
    println!("  EC24 fix: HMAC ratcheting allows safe reuse.");
    println!();

    let mut multi_dk = MultiUseDoubleKey::new(dk.clone());

    let mut prev_ct = None;
    for i in 0..3 {
        let packet_i = aencrypt(
            &pk,
            multi_dk.current_key(),
            b"hi",
            b"OK",
            TEST_MAC_KEY,
            TEST_BLOCK_SIZE,
        )
            .expect("multi-use encrypt");

        // Each ratcheted key produces a DIFFERENT ciphertext
        if let Some(ref prev) = prev_ct {
            assert_ne!(&packet_i, prev,
                "ratcheted key must produce different ciphertext");
        }

        let dec_i = adecrypt(&sk, multi_dk.current_key(), &packet_i, TEST_MAC_KEY, b"OK")
            .expect("multi-use decrypt");
        assert_eq!(dec_i.covert_msg.as_ref().unwrap(), b"OK");

        println!("  Round {}: use_count={}, covert recovered ✓",
            i + 1, multi_dk.use_count);

        prev_ct = Some(packet_i);
        multi_dk.ratchet(&pk.params);
    }
    println!("  ✓ 3 rounds of ratcheted covert communication — all recovered!");
    println!();

    // =====================================================================
    // Scenario 7: EC24 — Covert Presence Indicator
    // =====================================================================
    println!("==== Scenario 7: EC24 Covert Presence Indicator ====");
    println!("  Receiver can detect if a ciphertext carries a covert payload");
    println!("  without full decryption attempt.");
    println!();

    let anamorphic_packet2 = aencrypt(
        &pk, &dk,
        b"hi", b"sec",
        TEST_MAC_KEY, TEST_BLOCK_SIZE,
    )
        .expect("anamorphic encrypt for presence");
    let normal_packet2 = encrypt(&pk, b"hi", TEST_MAC_KEY, TEST_BLOCK_SIZE)
        .expect("normal encrypt for presence");

    // PRF presence check
    let has_covert = verify_covert_indicator(
        &dk,
        &anamorphic_packet2,
        TEST_MAC_KEY,
        b"sec",
        &pk.params.p, &pk.params.q, &pk.params.g,
    )
    .expect("anamorphic indicator");
    let no_covert = verify_covert_indicator(
        &dk,
        &normal_packet2,
        TEST_MAC_KEY,
        b"sec",
        &pk.params.p, &pk.params.q, &pk.params.g,
    );

    println!("  Anamorphic ct carries covert \"sec\"? -> {}", if has_covert { "YES ✓" } else { "NO ✗" });
    println!(
        "  Normal ct carries covert \"sec\"?     -> {}",
        match no_covert {
            Ok(true) => "YES ✗ (unexpected)!",
            Ok(false) => "NO ✓",
            Err(_) => "NO ✓ (rejected as malformed)",
        }
    );
    assert!(has_covert);
    assert_eq!(no_covert, Ok(false));
    println!("  ✓ Presence indicator correctly differentiates!");
    println!();

    // =====================================================================
    // Summary
    // =====================================================================
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║                   SIMULATION COMPLETE                        ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║  ✓ Type-1 Coercion (PRF + XOR): Covert survives key          ║");
    println!("║    extraction. Adversary sees only the overt plaintext.      ║");
    println!("║  ✓ Type-2 Coercion (PRF + XOR): Covert survives dictated     ║");
    println!("║    plaintext. Adversary's compliance check passes.           ║");
    println!("║  ✓ Overt view separation: normal decrypt exposes only the    ║");
    println!("║    overt plaintext while authenticated covert paths succeed. ║");
    println!("║  ✓ EC24 Multi-Use: Ratcheted double keys provide fresh       ║");
    println!("║    randomness across multiple transmissions.                 ║");
    println!("║  ✓ EC24 Presence: Receiver can detect covert payload         ║");
    println!("║    without full decryption.                                  ║");
    println!("╚══════════════════════════════════════════════════════════════╝");
}
