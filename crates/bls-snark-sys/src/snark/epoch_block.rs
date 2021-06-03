use crate::convert_result_to_bool;
use ark_bls12_377::G2Affine;
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bls_crypto::PublicKey;
use epoch_snark::{EncodingError, EpochBlock};
use std::{
    convert::TryFrom,
    os::raw::{c_int, c_uchar, c_uint, c_ushort},
    slice,
};

/// Each pubkey is a BLS G2Projective element
const PUBKEY_BYTES: usize = 96;

#[no_mangle]
pub extern "C" fn encode_epoch_block_to_bytes_cip22(
    in_epoch_index: c_ushort,
    in_round_number: c_uchar,
    in_epoch_entropy: *const u8,
    in_parent_entropy: *const u8,
    in_maximum_non_signers: c_uint,
    in_maximum_validators: c_uint,
    in_added_public_keys: *const *const PublicKey,
    in_added_public_keys_len: c_int,
    out_bytes: *mut *mut u8,
    out_len: *mut c_int,
    out_extra_data_bytes: *mut *mut u8,
    out_extra_data_len: *mut c_int,
) -> bool {
    convert_result_to_bool::<_, EncodingError, _>(|| {
        let added_public_keys_ptrs = unsafe {
            slice::from_raw_parts(in_added_public_keys, in_added_public_keys_len as usize)
        };
        let added_public_keys = added_public_keys_ptrs
            .to_vec()
            .into_iter()
            .map(|pk| unsafe { &*pk }.clone())
            .collect::<Vec<PublicKey>>();

        let epoch_entropy = unsafe { read_epoch_entropy(in_epoch_entropy) };
        let parent_entropy = unsafe { read_epoch_entropy(in_parent_entropy) };
        let epoch_block = EpochBlock::new(
            in_epoch_index as u16,
            in_round_number as u8,
            epoch_entropy,
            parent_entropy,
            in_maximum_non_signers as u32,
            in_maximum_validators as usize,
            added_public_keys,
        );
        let (mut encoded_inner, mut encoded_extra_data) =
            epoch_block.encode_inner_to_bytes_cip22()?;
        encoded_inner.shrink_to_fit();
        encoded_extra_data.shrink_to_fit();
        unsafe {
            *out_bytes = encoded_inner.as_mut_ptr();
            *out_len = encoded_inner.len() as c_int;
            *out_extra_data_bytes = encoded_extra_data.as_mut_ptr();
            *out_extra_data_len = encoded_extra_data.len() as c_int;
        }
        std::mem::forget(encoded_inner);
        std::mem::forget(encoded_extra_data);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn encode_epoch_block_to_bytes(
    in_epoch_index: c_ushort,
    in_maximum_non_signers: c_uint,
    in_added_public_keys: *const *const PublicKey,
    in_added_public_keys_len: c_int,
    out_bytes: *mut *mut u8,
    out_len: *mut c_int,
) -> bool {
    convert_result_to_bool::<_, EncodingError, _>(|| {
        let added_public_keys_ptrs = unsafe {
            slice::from_raw_parts(in_added_public_keys, in_added_public_keys_len as usize)
        };
        let added_public_keys = added_public_keys_ptrs
            .to_vec()
            .into_iter()
            .map(|pk| unsafe { &*pk }.clone())
            .collect::<Vec<PublicKey>>();

        let epoch_block = EpochBlock::new(
            in_epoch_index as u16,
            0u8,  // The round number is not used prior to CIP22
            None, // The epoch entropy is not used prior to CIP22
            None, // The parent entropy is not used prior to CIP22
            in_maximum_non_signers as u32,
            added_public_keys.len(),
            added_public_keys,
        );
        let mut encoded = epoch_block.encode_to_bytes()?;
        encoded.shrink_to_fit();
        unsafe {
            *out_bytes = encoded.as_mut_ptr();
            *out_len = encoded.len() as c_int;
        }
        std::mem::forget(encoded);
        Ok(())
    })
}

/// Data structure received from consumers of the FFI interface describing
/// an epoch block.
#[repr(C)]
pub struct EpochBlockFFI {
    /// The epoch's index
    pub index: u16,
    /// The round number from consensus
    pub round: u8,
    /// The epoch's entropy value, derived from the epoch block hash.
    pub epoch_entropy: *const u8,
    /// The parent epoch's entropy value.
    pub parent_entropy: *const u8,
    /// Pointer to the public keys array
    pub pubkeys: *const u8,
    /// The number of public keys to be read from the pointer
    pub pubkeys_num: usize,
    /// Maximum number of non signers for that epoch
    pub maximum_non_signers: u32,
    /// Maximum number of validators
    pub maximum_validators: usize,
}

impl TryFrom<&EpochBlockFFI> for EpochBlock {
    type Error = EncodingError;

    fn try_from(src: &EpochBlockFFI) -> Result<EpochBlock, Self::Error> {
        let pubkeys = unsafe { read_pubkeys(src.pubkeys, src.pubkeys_num as usize)? };
        let epoch_entropy = unsafe { read_epoch_entropy(src.epoch_entropy) };
        let parent_entropy = unsafe { read_epoch_entropy(src.parent_entropy) };
        Ok(EpochBlock {
            index: src.index,
            round: src.round,
            epoch_entropy,
            parent_entropy,
            maximum_non_signers: src.maximum_non_signers,
            maximum_validators: src.maximum_validators,
            new_public_keys: pubkeys,
        })
    }
}

/// Reads `len` bytes starting from the pointer's location
///
/// # Safety
///
/// This WILL read invalid data if you give it a larger `num` argument
/// than expected. Use with caution.
pub unsafe fn read_slice<C: CanonicalDeserialize>(
    ptr: *const u8,
    len: usize,
) -> Result<C, EncodingError> {
    let mut data = slice::from_raw_parts(ptr, len);
    Ok(C::deserialize(&mut data)?)
}

/// Reads `num` * `PUBKEY_BYTES` bytes starting from the pointer's location
///
/// # Safety
///
/// This WILL read invalid data if you give it a larger `num` argument
/// than expected. Use with caution.
unsafe fn read_serialized_pubkeys<'a>(ptr: *const u8, num: usize) -> &'a [u8] {
    slice::from_raw_parts(ptr, num * PUBKEY_BYTES)
}

/// Serializes the inner G2 elements of the pubkeys to a vector
pub fn serialize_pubkeys(pubkeys: &[PublicKey]) -> Result<Vec<u8>, EncodingError> {
    let mut v = Vec::new();
    for p in pubkeys {
        p.as_ref().into_affine().serialize(&mut v)?
    }
    Ok(v)
}

/// Reads `num` PublicKey elements starting from the memory that the pointer points to.
///
/// # Safety
/// This WILL NOT fail if the `num` variable is larger than the expected elements, and will
/// simply return an array of `PublicKeys` whose internals will be whatever data was in the memory.
/// Use with caution.
unsafe fn read_pubkeys(ptr: *const u8, num: usize) -> Result<Vec<PublicKey>, EncodingError> {
    let mut data = read_serialized_pubkeys(ptr, num);
    let mut pubkeys = Vec::new();
    for _ in 0..num {
        let key = G2Affine::deserialize(&mut data)?;
        let key = key.into_projective();
        pubkeys.push(PublicKey::from(key))
    }
    Ok(pubkeys)
}

/// Reads `ENTROPY_BYTES` byte epoch entropy value from the given pointer location.
///
/// # Safety
///
/// This WILL read invalid data if the given pointer locates less than `ENTROPY_BYTES`
/// bytes of data. Use with caution.
unsafe fn read_epoch_entropy(ptr: *const u8) -> Option<Vec<u8>> {
    if ptr.is_null() {
        None
    } else {
        Some(slice::from_raw_parts(ptr, EpochBlock::ENTROPY_BYTES).to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snark::test_helpers::TestCircuit;
    use ark_bls12_377::{Bls12_377, Fr, G2Projective};
    use ark_ec::ProjectiveCurve;
    use ark_ff::UniformRand;
    use ark_groth16::{create_proof_no_zk, generate_random_parameters, Proof, VerifyingKey};
    use ark_serialize::CanonicalSerialize;

    #[test]
    fn ffi_block_conversion() {
        let num_keys = 10;
        let pubkeys = rand_pubkeys(num_keys);
        let epoch_entropy = Some((0..EpochBlock::ENTROPY_BYTES).map(|n| n as u8).collect());
        let parent_entropy = Some(
            (EpochBlock::ENTROPY_BYTES..2 * EpochBlock::ENTROPY_BYTES)
                .map(|n| n as u8)
                .collect(),
        );
        let block = EpochBlock {
            index: 1,
            round: 5,
            epoch_entropy,
            parent_entropy,
            maximum_non_signers: 19,
            maximum_validators: pubkeys.len(),
            new_public_keys: pubkeys,
        };
        let src = block;
        let serialized_pubkeys = serialize_pubkeys(&src.new_public_keys).unwrap();
        let ffi_block = EpochBlockFFI {
            index: src.index,
            round: src.round,
            epoch_entropy: &src.epoch_entropy.as_ref().unwrap()[0],
            parent_entropy: &src.parent_entropy.as_ref().unwrap()[0],
            maximum_non_signers: src.maximum_non_signers,
            maximum_validators: src.new_public_keys.len(),
            pubkeys_num: src.new_public_keys.len(),
            pubkeys: &serialized_pubkeys[0] as *const u8,
        };
        let block_from_ffi = EpochBlock::try_from(&ffi_block).unwrap();
        assert_eq!(block_from_ffi, src);
    }

    #[test]
    fn ffi_block_conversion_without_entropy() {
        let num_keys = 10;
        let pubkeys = rand_pubkeys(num_keys);
        let epoch_entropy = None;
        let parent_entropy = None;
        let block = EpochBlock {
            index: 1,
            round: 5,
            epoch_entropy,
            parent_entropy,
            maximum_non_signers: 19,
            maximum_validators: pubkeys.len(),
            new_public_keys: pubkeys,
        };
        let src = block;
        let serialized_pubkeys = serialize_pubkeys(&src.new_public_keys).unwrap();
        let ffi_block = EpochBlockFFI {
            index: src.index,
            round: src.round,
            epoch_entropy: std::ptr::null(),
            parent_entropy: std::ptr::null(),
            maximum_non_signers: src.maximum_non_signers,
            maximum_validators: src.new_public_keys.len(),
            pubkeys_num: src.new_public_keys.len(),
            pubkeys: &serialized_pubkeys[0] as *const u8,
        };
        let block_from_ffi = EpochBlock::try_from(&ffi_block).unwrap();
        assert_eq!(block_from_ffi, src);
    }

    #[test]
    fn groth_verifying_key_from_pointer() {
        let rng = &mut rand::thread_rng();
        let c = TestCircuit::<Bls12_377>(None);
        let params = generate_random_parameters(c, rng).unwrap();
        let vk = params.vk;
        let mut serialized = vec![];
        vk.serialize(&mut serialized).unwrap();
        let ptr = &serialized[0] as *const u8;
        let deserialized: VerifyingKey<Bls12_377> =
            unsafe { read_slice(ptr, serialized.len()).unwrap() };
        assert_eq!(deserialized, vk);

        // reading a bigger slice is fine
        let deserialized: VerifyingKey<Bls12_377> =
            unsafe { read_slice(ptr, 2 * serialized.len()).unwrap() };
        assert_eq!(deserialized, vk);

        // reading a smaller slice is not
        unsafe { read_slice::<VerifyingKey<Bls12_377>>(ptr, serialized.len() - 1).unwrap_err() };
    }

    #[test]
    fn groth_proof_from_pointer() {
        let rng = &mut rand::thread_rng();
        let c = TestCircuit::<Bls12_377>(None);
        let params = generate_random_parameters(c, rng).unwrap();
        let c = TestCircuit::<Bls12_377>(Some(Fr::rand(rng)));
        let proof = create_proof_no_zk(c, &params).unwrap();
        let mut serialized = vec![];
        proof.serialize(&mut serialized).unwrap();
        let ptr = &serialized[0] as *const u8;
        let deserialized: Proof<Bls12_377> = unsafe { read_slice(ptr, serialized.len()).unwrap() };
        assert_eq!(deserialized, proof);

        // reading a bigger slice is fine (although still mis-use of the code)
        let deserialized: Proof<Bls12_377> =
            unsafe { read_slice(ptr, 2 * serialized.len()).unwrap() };
        assert_eq!(deserialized, proof);

        // reading a smaller slice is not
        unsafe { read_slice::<Proof<Bls12_377>>(ptr, serialized.len() - 1).unwrap_err() };
    }

    #[test]
    fn pubkeys_from_pointer() {
        let num_keys = 10;
        let pubkeys = rand_pubkeys(num_keys);
        let serialized = serialize_pubkeys(&pubkeys).unwrap();
        let ptr = &serialized[0] as *const u8;
        let deserialized_from_ptr = unsafe { read_pubkeys(ptr, num_keys).unwrap() };
        assert_eq!(deserialized_from_ptr, pubkeys);
    }

    #[test]
    fn invalid_pubkey_len_panic() {
        let num_keys = 10;
        let pubkeys = rand_pubkeys(num_keys);
        let serialized = serialize_pubkeys(&pubkeys).unwrap();
        let ptr = &serialized[0] as *const u8;
        // We read a bunch of junk data, hence why this MUST
        // be unsafe :)
        unsafe { read_pubkeys(ptr, 99).unwrap_err() };
    }

    fn rand_pubkeys(num_keys: usize) -> Vec<PublicKey> {
        let rng = &mut rand::thread_rng();
        let mut points = (0..num_keys)
            .map(|_| G2Projective::rand(rng))
            .collect::<Vec<_>>();
        // for the purposes of the test, we'll normalize these points to compare them with affine ones
        // which are already normalized due to the `into_affine()` method
        G2Projective::batch_normalization(&mut points);
        points
            .iter()
            .map(|p| PublicKey::from(*p))
            .collect::<Vec<_>>()
    }
}
