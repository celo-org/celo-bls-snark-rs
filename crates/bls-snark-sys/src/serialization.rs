use super::{convert_result_to_bool, PrivateKey, PublicKey, Signature};
use crate::cache::PUBLIC_KEY_CACHE;
use ark_bls12_377::{Fq, Fq2, G1Affine, G2Affine};
use ark_ec::AffineCurve;
use ark_ff::FromBytes;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bls_crypto::BLSError;
use std::{os::raw::c_int, slice};

// Serialization & deserialization

#[no_mangle]
pub extern "C" fn deserialize_private_key(
    in_private_key_bytes: *const u8,
    in_private_key_bytes_len: c_int,
    out_private_key: *mut *mut PrivateKey,
) -> bool {
    deserialize(
        in_private_key_bytes,
        in_private_key_bytes_len,
        out_private_key,
    )
}

#[no_mangle]
pub extern "C" fn serialize_private_key(
    in_private_key: *const PrivateKey,
    out_bytes: *mut *mut u8,
    out_len: *mut c_int,
) -> bool {
    serialize(in_private_key, out_bytes, out_len)
}

#[no_mangle]
pub extern "C" fn deserialize_public_key(
    in_public_key_bytes: *const u8,
    in_public_key_bytes_len: c_int,
    out_public_key: *mut *mut PublicKey,
) -> bool {
    deserialize(in_public_key_bytes, in_public_key_bytes_len, out_public_key)
}

#[no_mangle]
pub extern "C" fn deserialize_public_key_cached(
    in_public_key_bytes: *const u8,
    in_public_key_bytes_len: c_int,
    out_public_key: *mut *mut PublicKey,
) -> bool {
    convert_result_to_bool::<_, BLSError, _>(|| {
        let mut cache = PUBLIC_KEY_CACHE.lock().expect("mutex poisoned");
        let bytes =
            unsafe { slice::from_raw_parts(in_public_key_bytes, in_public_key_bytes_len as usize) };
        let key = cache.deserialize(bytes.to_vec())?;
        unsafe {
            *out_public_key = Box::into_raw(Box::new(key));
        }

        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn serialize_public_key(
    in_public_key: *const PublicKey,
    out_bytes: *mut *mut u8,
    out_len: *mut c_int,
) -> bool {
    serialize(in_public_key, out_bytes, out_len)
}

#[no_mangle]
pub extern "C" fn serialize_public_key_uncompressed(
    in_public_key: *const PublicKey,
    out_bytes: *mut *mut u8,
    out_len: *mut c_int,
) -> bool {
    serialize_uncompressed(in_public_key, out_bytes, out_len)
}

#[no_mangle]
pub extern "C" fn deserialize_signature(
    in_signature_bytes: *const u8,
    in_signature_bytes_len: c_int,
    out_signature: *mut *mut Signature,
) -> bool {
    deserialize(in_signature_bytes, in_signature_bytes_len, out_signature)
}

#[no_mangle]
pub extern "C" fn serialize_signature(
    in_signature: *const Signature,
    out_bytes: *mut *mut u8,
    out_len: *mut c_int,
) -> bool {
    serialize(in_signature, out_bytes, out_len)
}

#[no_mangle]
pub extern "C" fn serialize_signature_uncompressed(
    in_signature: *const Signature,
    out_bytes: *mut *mut u8,
    out_len: *mut c_int,
) -> bool {
    serialize_uncompressed(in_signature, out_bytes, out_len)
}

fn deserialize<T: CanonicalDeserialize>(
    in_bytes: *const u8,
    in_bytes_len: c_int,
    out: *mut *mut T,
) -> bool {
    convert_result_to_bool::<_, BLSError, _>(|| {
        let bytes = unsafe { slice::from_raw_parts(in_bytes, in_bytes_len as usize) };
        #[allow(clippy::redundant_slicing)]
        let key: T = CanonicalDeserialize::deserialize(&mut &bytes[..])?;
        unsafe {
            *out = Box::into_raw(Box::new(key));
        }

        Ok(())
    })
}

fn serialize<T: CanonicalSerialize>(
    in_obj: *const T,
    out_bytes: *mut *mut u8,
    out_len: *mut c_int,
) -> bool {
    convert_result_to_bool::<_, BLSError, _>(|| {
        let obj = unsafe { &*in_obj };
        let mut obj_bytes = vec![];
        obj.serialize(&mut obj_bytes)?;
        obj_bytes.shrink_to_fit();
        unsafe {
            *out_bytes = obj_bytes.as_mut_ptr();
            *out_len = obj_bytes.len() as c_int;
        }
        std::mem::forget(obj_bytes);

        Ok(())
    })
}

fn serialize_uncompressed<T: CanonicalSerialize>(
    in_obj: *const T,
    out_bytes: *mut *mut u8,
    out_len: *mut c_int,
) -> bool {
    convert_result_to_bool::<_, BLSError, _>(|| {
        let obj = unsafe { &*in_obj };
        let mut obj_bytes = vec![];
        obj.serialize_uncompressed(&mut obj_bytes)?;
        obj_bytes.shrink_to_fit();
        unsafe {
            *out_bytes = obj_bytes.as_mut_ptr();
            *out_len = obj_bytes.len() as c_int;
        }
        std::mem::forget(obj_bytes);

        Ok(())
    })
}

// Compression

#[no_mangle]
pub extern "C" fn compress_signature(
    in_signature: *const u8,
    in_signature_len: c_int,
    out_signature: *mut *mut u8,
    out_len: *mut c_int,
) -> bool {
    convert_result_to_bool::<_, BLSError, _>(|| {
        let signature = unsafe { slice::from_raw_parts(in_signature, in_signature_len as usize) };
        let x = Fq::read(&signature[0..48]).unwrap();
        let y = Fq::read(&signature[48..96]).unwrap();
        let affine = G1Affine::new(x, y, false);
        let sig = Signature::from(affine.into_projective());
        let mut obj_bytes = vec![];
        sig.serialize(&mut obj_bytes)?;
        obj_bytes.shrink_to_fit();
        unsafe {
            *out_signature = obj_bytes.as_mut_ptr();
            *out_len = obj_bytes.len() as c_int;
        }
        std::mem::forget(obj_bytes);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn compress_pubkey(
    in_pubkey: *const u8,
    in_pubkey_len: c_int,
    out_pubkey: *mut *mut u8,
    out_len: *mut c_int,
) -> bool {
    convert_result_to_bool::<_, BLSError, _>(|| {
        let pubkey = unsafe { slice::from_raw_parts(in_pubkey, in_pubkey_len as usize) };
        let x = Fq2::read(&pubkey[0..96]).unwrap();
        let y = Fq2::read(&pubkey[96..192]).unwrap();
        let affine = G2Affine::new(x, y, false);
        let pk = PublicKey::from(affine.into_projective());

        let mut obj_bytes = vec![];
        pk.serialize(&mut obj_bytes)?;
        obj_bytes.shrink_to_fit();

        unsafe {
            *out_pubkey = obj_bytes.as_mut_ptr();
            *out_len = obj_bytes.len() as c_int;
        }
        std::mem::forget(obj_bytes);
        Ok(())
    })
}

// Destructors

/// # Safety
///
/// This function must only be called on a valid PrivateKey instance pointer.
#[no_mangle]
pub unsafe extern "C" fn destroy_private_key(private_key: *mut PrivateKey) -> bool {
    if private_key.is_null() {
        return false;
    }
    Box::from_raw(private_key);
    true
}

/// # Safety
///
/// This function must only be called on a valid vector pointer.
#[no_mangle]
pub unsafe extern "C" fn free_vec(bytes: *mut u8, len: c_int) -> bool {
    if bytes.is_null() {
        return false;
    }
    Vec::from_raw_parts(bytes, len as usize, len as usize);
    true
}

/// # Safety
///
/// This function must only be called on a valid PublicKey instance pointer.
#[no_mangle]
pub unsafe extern "C" fn destroy_public_key(public_key: *mut PublicKey) -> bool {
    if public_key.is_null() {
        return false;
    }
    Box::from_raw(public_key);
    true
}

/// # Safety
///
/// This function must only be called on a valid Signature instance pointer.
#[no_mangle]
pub unsafe extern "C" fn destroy_signature(signature: *mut Signature) -> bool {
    if signature.is_null() {
        return false;
    }
    Box::from_raw(signature);
    true
}
