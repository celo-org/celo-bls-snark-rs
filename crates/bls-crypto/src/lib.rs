//! # BLS Cryptography
//!
//! This crate implements cryptographic operations for BLS signatures

pub(crate) mod bls;
pub use bls::{PrivateKey, PublicKey, PublicKeyCache, Signature};

/// Traits and implementations for hashing arbitrary data to an elliptic curve's group element
pub mod hash_to_curve;
pub use hash_to_curve::HashToCurve;

/// Hash function implementations using a CRH followed by a XOF.
pub mod hashers;
pub use hashers::Hasher;

#[cfg(feature = "ffi")]
pub mod ffi;

#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers;

use log::error;
use thiserror::Error;

/// Convenience result alias
pub type BlsResult<T> = std::result::Result<T, BLSError>;

/// Domain separator for signing messages
pub const SIG_DOMAIN: &[u8] = b"ULforxof";

/// Domain separator for Proofs of Posession
pub const POP_DOMAIN: &[u8] = b"ULforpop";

/// Domain separator for public inputs to the snark
pub const OUT_DOMAIN: &[u8] = b"ULforout";

#[derive(Debug, Error)]
/// Error type
pub enum BLSError {
    /// Error
    #[error("signature verification failed")]
    VerificationFailed,

    /// An IO error
    #[error("io error {0}")]
    IoError(#[from] std::io::Error),

    /// Error while hashing
    #[error("error in hasher {0}")]
    HashingError(#[from] Box<dyn std::error::Error>),

    /// Personalization string cannot be larger than 8 bytes
    #[error("domain length is too large: {0}")]
    DomainTooLarge(usize),

    /// Hashing to curve failed
    #[error("Could not hash to curve")]
    HashToCurveError,

    /// Serialization error in Zexe
    #[error(transparent)]
    SerializationError(#[from] algebra::SerializationError),
}
