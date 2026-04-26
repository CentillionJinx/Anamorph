# Step-by-Step Implementation Guide

This document outlines the complete sequence for building the Anamorph cryptographic system, from foundational setup to advanced security hardening and benchmarking.

## Phase 1: Foundation & Project Scaffold
**Objective:** Set up the Rust project and implement core mathematical primitives.
1. **Initialize Workspace:** Create the Rust crate `anamorph` with `cargo new`.
2. **Configure Dependencies:** Add `num-bigint`, `rand`, `hmac`, `sha2`, `zeroize`, and `argon2` to `Cargo.toml`.
3. **Mathematical Primitives (`params.rs`):**
   - Implement `generate_safe_prime(bit_size)` for generating $p = 2q + 1$.
   - Implement `find_generator(p, q)` for the subgroup of order $q$.
   - Implement `validate_group_membership()` to prevent subgroup attacks.
4. **Error Handling (`errors.rs`):** Define `AnamorphError` covering padding, integrity, and math errors.

## Phase 2: Normal Mode (Standard ElGamal)
**Objective:** Establish the baseline encryption system.
1. **Key Generation (`normal/keygen.rs`):** Implement `keygen()` to output `PublicKey` and `SecretKey`.
2. **Encryption (`normal/encrypt.rs`):** Implement standard `encrypt(pk, m)` yielding $(c_1, c_2)$.
3. **Decryption (`normal/decrypt.rs`):** Implement `decrypt(sk, c)` to recover message $m$.
4. **Testing (`tests/normal_mode.rs`):** Write unit tests verifying successful roundtrips and key validity.

## Phase 3: Anamorphic Mode (EC22 Base)
**Objective:** Implement the covert communication channel.
1. **Anamorphic Keygen (`anamorphic/keygen.rs`):** Implement `akeygen()` which extends normal keygen to also output a `DoubleKey` $dk$.
2. **Anamorphic Encryption (`anamorphic/encrypt.rs`):** Implement `aencrypt(pk, dk, m_normal, m_covert)`. Map the covert payload to the encryption randomness $r$ via a hash-to-group function.
3. **Anamorphic Decryption (`anamorphic/decrypt.rs`):** Implement `adecrypt(sk, dk, c)` to recover $m_{covert}$ by reversing the randomness mapping.
4. **Testing (`tests/anamorphic_mode.rs`):** Ensure `aencrypt` ciphertexts decrypt to $m_{normal}$ via `decrypt()`, but reveal $m_{covert}$ via `adecrypt()`.

## Phase 4: EC24 Robustness Extensions
**Objective:** Address the limitations of the EC22 protocol.
1. **Double Key Ratcheting (`ec24/double_key.rs`):** Implement multi-use double keys utilizing `argon2` KDF to allow dynamic re-establishment without re-keying.
2. **Presence Indicator (`ec24/indicator.rs`):** Implement a cryptographic indicator allowing the receiver to definitively check if a ciphertext contains a covert payload.

## Phase 5: Security Hardening (CCA Defense)
**Objective:** Secure the protocol against Chosen-Ciphertext Attacks and side-channels.
1. **HMAC Integrity (`integrity.rs`):** Implement an Encrypt-then-MAC strategy using `hmac` and `sha2` to authenticate packets.
2. **Block Padding (`padding.rs`):** Implement PKCS#7 block-padding to standardize plaintext sizes and mitigate length oracle attacks.
3. **Constant-Time Operations (`ct.rs`):** Wrap secret-dependent comparison and selection logic using the `subtle` crate to thwart timing attacks.

## Phase 6: Benchmarking & Verification
**Objective:** Prove performance and indistinguishability.
1. **Micro-Benchmarking (`benches/`):** Create Criterion benchmarks (`core.rs`, `slow_setup.rs`, `slow_stream.rs`) to measure the performance overhead of anamorphic mode relative to normal mode.
2. **Property Testing (`tests/indistinguishability.rs`):** Use `proptest` to automatically verify that thousands of randomized anamorphic ciphertexts remain structurally identical to normal ciphertexts.
3. **Coercion Simulation (`tests/coercion_simulation.rs`):** Script end-to-end tests simulating Type-1 and Type-2 coercion attacks, confirming that $m_{covert}$ cannot be extracted by the adversary.
