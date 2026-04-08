//! # Project Anamorph
//!
//! The first open Rust implementation of the **Unsynchronized Robustly
//! Anamorphic ElGamal** scheme (EUROCRYPT 2022, extended by EUROCRYPT 2024).
//!
//! ## Modules
//!
//! - [`normal`]  — Standard ElGamal: `Gen`, `Enc`, `Dec`
//! - [`anamorphic`] — Anamorphic ElGamal (EC22): `aGen`, `aEnc`, `aDec`
//! - [`params`]  — Safe-prime generation & group-parameter validation
//! - [`errors`]  — Unified error types
//! - [`padding`]  — Block-padding for length-oracle mitigation
//! - [`ct`]       — Constant-time helpers
//! - [`hardening`] — Low-level HMAC helpers

pub mod errors;
pub mod params;

pub mod normal;
pub mod anamorphic;
pub mod ec24;

pub mod hardening;
pub mod padding;
pub mod ct;
