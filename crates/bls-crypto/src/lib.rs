//! # BLS Cryptography
//!
//! This crate implements cryptographic operations for BLS signatures.
//!
//! It supports:
//! - signing and verifying BLS signatures
//! - aggregating BLS signatures and public keys
//! - batch verification of `n` BLS signatures with `n+1` pairings instead of `2n`
//! - SNARK-friendly hashing utilizing a Pedersen CRH via the `composite` hasher module
//!
//! # Example
//!
//! ```rust
//! use bls_crypto::{PrivateKey, PublicKey, Signature};
//! use bls_crypto::{
//!     OUT_DOMAIN,
//!     hash_to_curve::{HashToCurve, try_and_increment::DIRECT_HASH_TO_G1}
//! };
//!
//! let rng = &mut rand::thread_rng();
//! let message = &b"hello"[..];
//! let extra_data = &[];
//! let hasher = &*DIRECT_HASH_TO_G1;
//!
//! // generate a few private keys
//! let keys = (0..10).map(|_| PrivateKey::generate(rng)).collect::<Vec<_>>();
//!
//! // sign each message
//! let sigs = keys
//!     .iter()
//!     .map(|key| key.sign(message, extra_data, hasher).unwrap())
//!     .collect::<Vec<_>>();
//!
//! // gets the public keys
//! let public_keys = keys.iter().map(|key| key.to_public()).collect::<Vec<_>>();
//!
//! // Each signature can be verified individually against the key
//! public_keys.iter().zip(&sigs).for_each(|(pubkey, sig)| {
//!     pubkey.verify(message, extra_data, &sig, hasher).unwrap();
//! });
//!
//! // The aggregate signature can be verified against the aggregate public key
//! let aggregate_sig = Signature::aggregate(&sigs);
//! let aggregate_public_key = PublicKey::aggregate(&public_keys);
//! aggregate_public_key.verify(message, extra_data, &aggregate_sig, hasher).unwrap();
//! ```
//!
//! # Notes
//!
//! Currently the supported curves are BLS12-377 with signatures on G1 and public keys on G2.
//! In a future iteration, this will be abstracted to support any curve which implements
//! algebra's `PairingEngine` trait. We will also support public keys on G1 and signatures on G2.

pub mod bls;
pub use bls::{PrivateKey, PublicKey, PublicKeyCache, Signature};

/// Traits and implementations for hashing arbitrary data to an elliptic curve's group element
pub mod hash_to_curve;
pub use hash_to_curve::HashToCurve;

/// Hash function implementations using a CRH followed by a XOF.
pub mod hashers;
pub use hashers::Hasher;

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

    /// There must be the same number of keys and messages
    #[error("there must be the same number of keys and messages")]
    UnevenNumKeysMessages,

    /// Serialization error in Zexe
    #[error(transparent)]
    SerializationError(#[from] ark_serialize::SerializationError),
}
