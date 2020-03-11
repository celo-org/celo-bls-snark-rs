mod encoding;
pub mod epoch_block;
pub mod gadgets;
use encoding::EncodingError;
use epoch_block::EpochBlock;

#[macro_use]
extern crate log;

use bls_crypto::PublicKey;

use std::{
    fmt::Display,
    os::raw::{c_int, c_uint, c_ushort},
    slice,
};

fn convert_result_to_bool<T, E: Display, F: Fn() -> Result<T, E>>(f: F) -> bool {
    match f() {
        Err(e) => {
            error!("SNARK library error: {}", e.to_string());
            false
        }
        _ => true,
    }
}

#[no_mangle]
pub extern "C" fn encode_epoch_block_to_bytes(
    in_epoch_index: c_ushort,
    in_maximum_non_signers: c_uint,
    in_aggregated_public_key: *const PublicKey,
    in_added_public_keys: *const *const PublicKey,
    in_added_public_keys_len: c_int,
    out_bytes: *mut *mut u8,
    out_len: *mut c_int,
) -> bool {
    convert_result_to_bool::<_, EncodingError, _>(|| {
        let aggregated_public_key = unsafe { &*in_aggregated_public_key };
        let added_public_keys_ptrs = unsafe {
            slice::from_raw_parts(in_added_public_keys, in_added_public_keys_len as usize)
        };
        let added_public_keys = added_public_keys_ptrs
            .to_vec()
            .into_iter()
            .map(|pk| unsafe { &*pk })
            .collect::<Vec<&PublicKey>>();

        let mut encoded = EpochBlock::new(
            in_epoch_index as u16,
            in_maximum_non_signers as u32,
            &aggregated_public_key,
            &added_public_keys,
        )
        .encode_to_bytes()?;
        encoded.shrink_to_fit();
        unsafe {
            *out_bytes = encoded.as_mut_ptr();
            *out_len = encoded.len() as c_int;
        }
        std::mem::forget(encoded);
        Ok(())
    })
}
