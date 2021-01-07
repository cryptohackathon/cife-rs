//! Attribute based encryption (ABE) schemes.
//!
//! CiFEr, the C implementation, supports three different schemes:
//!
//! - GPSW, a KP-ABE scheme by [Goyal, Pandey, Sahai, Waters,
//! 2006](https://eprint.iacr.org/2006/309)
//! - FAME, a CP-ABE scheme by [Shashank Agrawal and Melissa Chase,
//! 2017](https://eprint.iacr.org/2017/807).
//! - DIPPE, a IPPE based scheme by [Yan Michalevsky and Marc Joye,
//! 2018](https://eprint.iacr.org/2018/753).
//!
//! Currently, CiFE-rs, this Rust implementation, aims to fully implement the DIPPE scheme,
//! and is made available in the [`dippe`] module.

#[cfg(feature = "dippe")]
pub mod dippe;
