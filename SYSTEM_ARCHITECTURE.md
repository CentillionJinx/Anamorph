# System Architecture Documentation

## 1. Project Overview
Project Anamorph is a Rust-based implementation of the Unsynchronized Robustly Anamorphic ElGamal encryption scheme. It enables covert communication channels hidden within syntactically normal ElGamal ciphertexts, effectively resisting both Type-1 (Receiver coercion) and Type-2 (Sender coercion) attacks.

## 2. Development Environment
The implementation is developed and verified on the following system configuration:
- **OS:** Kali GNU/Linux Rolling x86_64
- **Kernel:** Linux 6.19.11+kali-amd64
- **Hardware:** ASUS Zenbook Duo (Intel Core Ultra 9 285H @ 5.40 GHz, 32GB RAM)
- **Environment:** KDE Plasma 6.5.4 (Wayland)
- **Compiler:** Rust ≥ 1.76 (stable)

## 3. Core Architecture
The system is divided into several modular components to separate the mathematical primitives from the protocol logic and security hardening layers.

### 3.1. Mathematical Primitives (`src/params.rs`)
- Responsible for generating safe primes ($p = 2q + 1$).
- Identifies generators for the subgroup of order $q$.
- Validates group membership for public keys and ciphertexts.
- Uses arbitrary-precision integers (`num-bigint`) for group operations.

### 3.2. Normal Mode (`src/normal/`)
Standard ElGamal implementation providing the baseline for indistinguishability.
- `keygen.rs`: Generates standard ElGamal keypairs $(pk, sk)$.
- `encrypt.rs`: Implements standard $Enc(pk, m)$ yielding ciphertexts $(c_1, c_2)$.
- `decrypt.rs`: Standard decryption $Dec(sk, c)$.

### 3.3. Anamorphic Mode (`src/anamorphic/`)
The base EC22 covert channel implementation.
- `keygen.rs`: Augmented key generation $aGen(\lambda)$ that produces $(pk, sk, dk)$, establishing the shared anamorphic double key $dk$.
- `encrypt.rs`: $aEnc(pk, dk, m_{normal}, m_{covert})$ embeds the covert payload into the encryption randomness.
- `decrypt.rs`: $aDec(sk, dk, c)$ recovers both normal and covert messages.

### 3.4. EC24 Robustness Extension (`src/ec24/`)
Extensions to address EC22 limitations.
- `double_key.rs`: Multi-use double keys that can be re-established without full key regeneration.
- `indicator.rs`: Covert-message presence indicator allowing receivers to definitively detect embedded payloads.

### 3.5. Security Hardening
- `integrity.rs`: HMAC-SHA256 based message authentication (MAC) to secure against Chosen-Ciphertext Attacks (CCA).
- `padding.rs`: PKCS#7 block-padding to mitigate length oracle vulnerabilities.
- `ct.rs`: Constant-time operation wrappers using the `subtle` crate to prevent timing side-channels.

## 4. Threat Model & Security Posture
The architecture guarantees indistinguishability under full key extraction. When a dictator extracts the receiver's secret key (Type-1), the anamorphic ciphertext decrypts to the normal message, and the covert payload remains undetectable. 
