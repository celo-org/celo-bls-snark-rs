/// Implements BLS signatures as specified in https://crypto.stanford.edu/~dabo/pubs/papers/BLSmultisig.html.
pub mod ffi;

mod secret;
pub use secret::PrivateKey;

mod public;
pub use public::PublicKey;

mod signature;
pub use signature::Signature;

mod cache;
pub use cache::PublicKeyCache;

use thiserror::Error;

pub static SIG_DOMAIN: &[u8] = b"ULforxof";
pub static POP_DOMAIN: &[u8] = b"ULforpop";

#[derive(Debug, Error)]
pub enum BLSError {
    #[error("signature verification failed")]
    VerificationFailed,
    #[error("could not hash to curve (msg: {0:?}, extra data: {1:?})")]
    HashToCurveFailed(Vec<u8>, Vec<u8>),
}
