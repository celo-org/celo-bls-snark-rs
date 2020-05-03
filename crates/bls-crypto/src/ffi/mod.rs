//! FFI Bindings for BLS Signatures over the BLS12-377 Curve

use crate::bls;

type PublicKey = bls::PublicKey;
type Signature = bls::Signature;
type PrivateKey = bls::PrivateKey;
type PublicKeyCache = bls::PublicKeyCache;

use crate::hash_to_curve::try_and_increment::{COMPOSITE_HASH_TO_G1, DIRECT_HASH_TO_G1};
use core::fmt::Display;
use once_cell::sync::Lazy;

pub mod serialization;
pub mod signatures;
pub(crate) mod utils;

#[no_mangle]
/// Initializes the lazily evaluated hashers.
pub extern "C" fn init() {
    Lazy::force(&COMPOSITE_HASH_TO_G1);
    Lazy::force(&DIRECT_HASH_TO_G1);
}

fn convert_result_to_bool<T, E: Display, F: Fn() -> Result<T, E>>(f: F) -> bool {
    if let Err(e) = f() {
        log::error!("BLS library error: {}", e.to_string());
        return false;
    }
    true
}
