//! FFI Bindings for BLS Signatures and SNARKs over the BLS12-377 Curve

use bls_crypto::bls;

type PublicKey = bls::PublicKey;
type Signature = bls::Signature;
type PrivateKey = bls::PrivateKey;
type PublicKeyCache = bls::PublicKeyCache;

use bls_crypto::hash_to_curve::try_and_increment::{COMPOSITE_HASH_TO_G1, DIRECT_HASH_TO_G1};
use core::fmt::Display;
use once_cell::sync::Lazy;

pub(crate) mod cache;
pub mod serialization;
pub mod signatures;
pub mod snark;
pub mod utils;

pub fn convert_result_to_bool<T, E: Display, F: Fn() -> Result<T, E>>(f: F) -> bool {
    if let Err(e) = f() {
        log::error!("SNARK library error: {}", e);
        return false;
    }
    true
}

#[no_mangle]
/// Initializes the lazily evaluated hashers.
pub extern "C" fn init() {
    Lazy::force(&COMPOSITE_HASH_TO_G1);
    Lazy::force(&DIRECT_HASH_TO_G1);
}
