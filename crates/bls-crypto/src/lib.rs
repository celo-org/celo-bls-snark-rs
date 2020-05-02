//! # BLS Cryptography
//!
//! This crate implements cryptographic operations for BLS signatures
/// BLS signing
pub(crate) mod bls;
pub use bls::{PrivateKey, PublicKey, PublicKeyCache, Signature};

/// Hashing to curve utilities
pub mod hash_to_curve;
pub use hash_to_curve::HashToCurve;

/// Useful hash functions
pub mod hashers;
pub use hashers::XOF;

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
    #[error("Could not hash to curve")]
    HashToCurveError,
    #[error("{0}")]
    SerializationError(#[from] algebra::SerializationError),
}
