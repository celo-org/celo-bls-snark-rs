use crate::{
    cache::PUBLIC_KEY_CACHE,
    convert_result_to_bool,
    utils::{Message, MessageFFI},
    PrivateKey, PublicKey, Signature, COMPOSITE_HASH_TO_G1, DIRECT_HASH_TO_G1,
};
use ark_ec::ProjectiveCurve;
use ark_ff::ToBytes;
use bls_crypto::hash_to_curve::try_and_increment_cip22::COMPOSITE_HASH_TO_G1_CIP22;
use bls_crypto::hashers::{DirectHasher, COMPOSITE_HASHER};
use bls_crypto::Hasher;
use bls_crypto::{BLSError, HashToCurve, POP_DOMAIN, SIG_DOMAIN};
use std::{os::raw::c_int, slice};

/// # Safety
///
/// out_private_key must initialized to memory that can contain a pointer.
#[no_mangle]
pub unsafe extern "C" fn generate_private_key(out_private_key: *mut *mut PrivateKey) -> bool {
    let mut rng = rand::thread_rng();
    let key = PrivateKey::generate(&mut rng);
    *out_private_key = Box::into_raw(Box::new(key));

    true
}

#[no_mangle]
pub extern "C" fn private_key_to_public_key(
    in_private_key: *const PrivateKey,
    out_public_key: *mut *mut PublicKey,
) -> bool {
    convert_result_to_bool::<_, std::io::Error, _>(|| {
        let private_key = unsafe { &*in_private_key };
        let public_key = private_key.to_public();
        unsafe {
            *out_public_key = Box::into_raw(Box::new(public_key));
        }

        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn sign_message(
    in_private_key: *const PrivateKey,
    in_message: *const u8,
    in_message_len: c_int,
    in_extra_data: *const u8,
    in_extra_data_len: c_int,
    should_use_composite: bool,
    should_use_cip22: bool,
    out_signature: *mut *mut Signature,
) -> bool {
    convert_result_to_bool::<_, BLSError, _>(|| {
        let private_key = unsafe { &*in_private_key };
        let message = unsafe { slice::from_raw_parts(in_message, in_message_len as usize) };
        let extra_data =
            unsafe { slice::from_raw_parts(in_extra_data, in_extra_data_len as usize) };
        let signature = match (should_use_composite, should_use_cip22) {
            (true, true) => private_key.sign(message, extra_data, &*COMPOSITE_HASH_TO_G1_CIP22)?,
            (false, true) => return Err(BLSError::HashToCurveError),
            (true, false) => private_key.sign(message, extra_data, &*COMPOSITE_HASH_TO_G1)?,
            (false, false) => private_key.sign(message, extra_data, &*DIRECT_HASH_TO_G1)?,
        };
        unsafe {
            *out_signature = Box::into_raw(Box::new(signature));
        }

        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn sign_pop(
    in_private_key: *const PrivateKey,
    in_message: *const u8,
    in_message_len: c_int,
    out_signature: *mut *mut Signature,
) -> bool {
    convert_result_to_bool::<_, BLSError, _>(|| {
        let private_key = unsafe { &*in_private_key };
        let message = unsafe { slice::from_raw_parts(in_message, in_message_len as usize) };
        let signature = private_key.sign_pop(message, &*DIRECT_HASH_TO_G1)?;
        unsafe {
            *out_signature = Box::into_raw(Box::new(signature));
        }

        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn hash_direct(
    in_message: *const u8,
    in_message_len: c_int,
    out_hash: *mut *mut u8,
    out_len: *mut c_int,
    use_pop: bool,
) -> bool {
    convert_result_to_bool::<_, BLSError, _>(|| {
        let message = unsafe { slice::from_raw_parts(in_message, in_message_len as usize) };
        let domain = if use_pop { POP_DOMAIN } else { SIG_DOMAIN };
        let hash = DIRECT_HASH_TO_G1.hash(domain, message, &[])?;
        let mut obj_bytes = vec![];
        hash.into_affine().write(&mut obj_bytes)?;
        obj_bytes.shrink_to_fit();
        unsafe {
            *out_hash = obj_bytes.as_mut_ptr();
            *out_len = obj_bytes.len() as c_int;
        }
        std::mem::forget(obj_bytes);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn hash_direct_with_attempt(
    in_message: *const u8,
    in_message_len: c_int,
    out_hash: *mut *mut u8,
    out_len: *mut c_int,
    out_attempt: *mut c_int,
    use_pop: bool,
) -> bool {
    convert_result_to_bool::<_, BLSError, _>(|| {
        let message = unsafe { slice::from_raw_parts(in_message, in_message_len as usize) };
        let domain = if use_pop { POP_DOMAIN } else { SIG_DOMAIN };
        let (hash, c) = DIRECT_HASH_TO_G1.hash_with_attempt(domain, message, &[])?;
        let mut obj_bytes = vec![];
        hash.into_affine().write(&mut obj_bytes)?;
        obj_bytes.shrink_to_fit();
        unsafe {
            *out_hash = obj_bytes.as_mut_ptr();
            *out_len = obj_bytes.len() as c_int;
            *out_attempt = c as c_int;
        }
        std::mem::forget(obj_bytes);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn hash_composite(
    in_message: *const u8,
    in_message_len: c_int,
    in_extra_data: *const u8,
    in_extra_data_len: c_int,
    out_hash: *mut *mut u8,
    out_len: *mut c_int,
) -> bool {
    convert_result_to_bool::<_, BLSError, _>(|| {
        let message = unsafe { slice::from_raw_parts(in_message, in_message_len as usize) };
        let extra_data =
            unsafe { slice::from_raw_parts(in_extra_data, in_extra_data_len as usize) };
        let hash = COMPOSITE_HASH_TO_G1.hash(SIG_DOMAIN, message, extra_data)?;
        let mut obj_bytes = vec![];
        hash.write(&mut obj_bytes)?;
        obj_bytes.shrink_to_fit();
        unsafe {
            *out_hash = obj_bytes.as_mut_ptr();
            *out_len = obj_bytes.len() as c_int;
        }
        std::mem::forget(obj_bytes);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn hash_crh(
    in_message: *const u8,
    in_message_len: c_int,
    hash_bytes: c_int,
    out_hash: *mut *mut u8,
    out_len: *mut c_int,
) -> bool {
    convert_result_to_bool::<_, BLSError, _>(|| {
        let message = unsafe { slice::from_raw_parts(in_message, in_message_len as usize) };
        let hash = COMPOSITE_HASHER.crh(SIG_DOMAIN, message, hash_bytes as usize)?;
        let mut obj_bytes = vec![];
        hash.write(&mut obj_bytes)?;
        obj_bytes.shrink_to_fit();
        unsafe {
            *out_hash = obj_bytes.as_mut_ptr();
            *out_len = obj_bytes.len() as c_int;
        }
        std::mem::forget(obj_bytes);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn hash_direct_first_step(
    in_message: *const u8,
    in_message_len: c_int,
    hash_bytes: c_int,
    out_hash: *mut *mut u8,
    out_len: *mut c_int,
) -> bool {
    convert_result_to_bool::<_, BLSError, _>(|| {
        let message = unsafe { slice::from_raw_parts(in_message, in_message_len as usize) };
        let hash = DirectHasher.hash(SIG_DOMAIN, message, hash_bytes as usize)?;
        let mut obj_bytes = vec![];
        hash.write(&mut obj_bytes)?;
        obj_bytes.shrink_to_fit();
        unsafe {
            *out_hash = obj_bytes.as_mut_ptr();
            *out_len = obj_bytes.len() as c_int;
        }
        std::mem::forget(obj_bytes);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn hash_composite_cip22(
    in_message: *const u8,
    in_message_len: c_int,
    in_extra_data: *const u8,
    in_extra_data_len: c_int,
    out_hash: *mut *mut u8,
    out_len: *mut c_int,
    attempt_counter: *mut u8,
) -> bool {
    convert_result_to_bool::<_, BLSError, _>(|| {
        let message = unsafe { slice::from_raw_parts(in_message, in_message_len as usize) };
        let extra_data =
            unsafe { slice::from_raw_parts(in_extra_data, in_extra_data_len as usize) };
        let (hash, counter) =
            COMPOSITE_HASH_TO_G1_CIP22.hash_with_attempt_cip22(SIG_DOMAIN, message, extra_data)?;
        let mut obj_bytes = vec![];
        hash.write(&mut obj_bytes)?;
        obj_bytes.shrink_to_fit();
        unsafe {
            *out_hash = obj_bytes.as_mut_ptr();
            *out_len = obj_bytes.len() as c_int;
            *attempt_counter = counter as u8;
        }
        std::mem::forget(obj_bytes);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn verify_signature(
    in_public_key: *const PublicKey,
    in_message: *const u8,
    in_message_len: c_int,
    in_extra_data: *const u8,
    in_extra_data_len: c_int,
    in_signature: *const Signature,
    should_use_composite: bool,
    should_use_cip22: bool,
    out_verified: *mut bool,
) -> bool {
    convert_result_to_bool::<_, BLSError, _>(|| {
        let public_key = unsafe { &*in_public_key };
        let message = unsafe { slice::from_raw_parts(in_message, in_message_len as usize) };
        let extra_data =
            unsafe { slice::from_raw_parts(in_extra_data, in_extra_data_len as usize) };
        let signature = unsafe { &*in_signature };
        let verified = match (should_use_composite, should_use_cip22) {
            (true, true) => public_key
                .verify(message, extra_data, signature, &*COMPOSITE_HASH_TO_G1_CIP22)
                .is_ok(),
            (false, true) => return Err(BLSError::HashToCurveError),
            (true, false) => public_key
                .verify(message, extra_data, signature, &*COMPOSITE_HASH_TO_G1)
                .is_ok(),
            (false, false) => public_key
                .verify(message, extra_data, signature, &*DIRECT_HASH_TO_G1)
                .is_ok(),
        };
        unsafe { *out_verified = verified };

        Ok(())
    })
}

#[no_mangle]
/// Receives a list of messages composed of:
/// 1. the data
/// 1. the public keys which signed on the data
/// 1. the signature produced by the public keys
///
/// It will create the aggregate signature from all messages and execute batch
/// verification against each (data, publickey) pair. Internally calls `Signature::batch_verify`
///
/// The verification equation can be found in pg.11 from
/// https://eprint.iacr.org/2018/483.pdf: "Batch verification"
pub extern "C" fn batch_verify_signature(
    messages_ptr: *const MessageFFI,
    messages_len: usize,
    should_use_composite: bool,
    should_use_cip22: bool,
    verified: *mut bool,
) -> bool {
    convert_result_to_bool::<_, BLSError, _>(|| {
        // Get the pointers slice
        let messages: &[MessageFFI] = unsafe { slice::from_raw_parts(messages_ptr, messages_len) };

        // Get the data from the underlying pointers in the right format
        let messages = messages.iter().map(Message::from).collect::<Vec<_>>();

        let asig = Signature::aggregate(messages.iter().map(|m| m.sig));

        let pubkeys = messages.iter().map(|m| m.public_key).collect::<Vec<_>>();
        let messages = messages
            .iter()
            .map(|m| (m.data, m.extra))
            .collect::<Vec<_>>();

        let is_verified = match (should_use_composite, should_use_cip22) {
            (true, true) => asig
                .batch_verify(
                    &pubkeys,
                    SIG_DOMAIN,
                    &messages,
                    &*COMPOSITE_HASH_TO_G1_CIP22,
                )
                .is_ok(),
            (false, true) => return Err(BLSError::HashToCurveError),
            (true, false) => asig
                .batch_verify(&pubkeys, SIG_DOMAIN, &messages, &*COMPOSITE_HASH_TO_G1)
                .is_ok(),
            (false, false) => asig
                .batch_verify(&pubkeys, SIG_DOMAIN, &messages, &*DIRECT_HASH_TO_G1)
                .is_ok(),
        };

        unsafe { *verified = is_verified };
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn verify_pop(
    in_public_key: *const PublicKey,
    in_message: *const u8,
    in_message_len: c_int,
    in_signature: *const Signature,
    out_verified: *mut bool,
) -> bool {
    convert_result_to_bool::<_, BLSError, _>(|| {
        let public_key = unsafe { &*in_public_key };
        let message = unsafe { slice::from_raw_parts(in_message, in_message_len as usize) };
        let signature = unsafe { &*in_signature };
        let verified = public_key
            .verify_pop(message, signature, &*DIRECT_HASH_TO_G1)
            .is_ok();
        unsafe { *out_verified = verified };

        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn aggregate_public_keys(
    in_public_keys: *const *const PublicKey,
    in_public_keys_len: c_int,
    out_public_key: *mut *mut PublicKey,
) -> bool {
    convert_result_to_bool::<_, BLSError, _>(|| {
        let public_keys_ptrs =
            unsafe { slice::from_raw_parts(in_public_keys, in_public_keys_len as usize) };
        let public_keys = public_keys_ptrs
            .to_vec()
            .into_iter()
            .map(|pk| unsafe { &*pk }.clone())
            .collect::<Vec<PublicKey>>();

        let mut cache = PUBLIC_KEY_CACHE.lock().expect("mutex poisoned");
        let aggregated_public_key = cache.aggregate(public_keys);

        unsafe {
            *out_public_key = Box::into_raw(Box::new(aggregated_public_key));
        }

        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn aggregate_public_keys_subtract(
    in_aggregated_public_key: *const PublicKey,
    in_public_keys: *const *const PublicKey,
    in_public_keys_len: c_int,
    out_public_key: *mut *mut PublicKey,
) -> bool {
    convert_result_to_bool::<_, BLSError, _>(|| {
        let aggregated_public_key = unsafe { &*in_aggregated_public_key };
        let public_keys_ptrs =
            unsafe { slice::from_raw_parts(in_public_keys, in_public_keys_len as usize) };
        let public_keys = public_keys_ptrs
            .to_vec()
            .into_iter()
            .map(|pk| unsafe { &*pk }.clone())
            .collect::<Vec<PublicKey>>();

        let mut cache = PUBLIC_KEY_CACHE.lock().expect("mutex poisoned");
        let aggregated_public_key_to_subtract = cache.aggregate(public_keys);
        let prepared_aggregated_public_key = PublicKey::from(
            *aggregated_public_key.as_ref() - *aggregated_public_key_to_subtract.as_ref(),
        );

        unsafe {
            *out_public_key = Box::into_raw(Box::new(prepared_aggregated_public_key));
        }

        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn aggregate_signatures(
    in_signatures: *const *const Signature,
    in_signatures_len: c_int,
    out_signature: *mut *mut Signature,
) -> bool {
    convert_result_to_bool::<_, BLSError, _>(|| {
        let signatures_ptrs =
            unsafe { slice::from_raw_parts(in_signatures, in_signatures_len as usize) };
        let signatures = signatures_ptrs
            .to_vec()
            .into_iter()
            .map(|sig| unsafe { &*sig }.clone())
            .collect::<Vec<Signature>>();
        let aggregated_signature = Signature::aggregate(&signatures[..]);
        unsafe {
            *out_signature = Box::into_raw(Box::new(aggregated_signature));
        }

        Ok(())
    })
}
