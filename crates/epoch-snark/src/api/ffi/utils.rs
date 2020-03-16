use super::{CPCurve, Parameters};
use crate::convert_result_to_bool;
use crate::epoch_block::{EpochBlock, EpochTransition};
use algebra::{bls12_377::G2Affine, AffineCurve, CanonicalDeserialize};
use bls_crypto::PublicKey;
use groth16::{Proof, VerifyingKey};
use std::slice;

// Each pubkey is a BLS G2Projective element
pub(super) const PROOF_BYTES: u32 = 900; // todo: find this
pub(super) const VK_BYTES: u32 = 900; // todo: find this
const PUBKEY_BYTES: usize = 96;

pub(super) fn read_slice<C: CanonicalDeserialize>(ptr: *const u8, len: u32) -> Result<C, ()> {
    let data: Vec<u8> = unsafe { slice::from_raw_parts(ptr, len as usize).to_vec() };
    let ret = C::deserialize(&mut &data[..]).unwrap();
    Ok(ret)
}

// Assume that we can deserialize the pubkeys from geth...somehow
// this function must be tested extensively
pub(super) fn read_pubkeys(ptr: *const u8, num: u32) -> Result<Vec<PublicKey>, ()> {
    let len = num as usize * PUBKEY_BYTES;
    let data: Vec<u8> = unsafe { slice::from_raw_parts(ptr, len as usize).to_vec() };
    let mut pubkeys = Vec::new();
    for i in 0..num {
        // this might be suboptimal
        let key = G2Affine::deserialize(&mut &data[..]).unwrap();
        let key = key.into_projective();
        pubkeys.push(PublicKey::from_pk(key))
    }

    Ok(pubkeys)
}

/// Geth must send us this structure with serialized pubkeys and an index
#[repr(C)]
pub struct EpochBlockFFI {
    pub index: u16,
    pub pubkeys: *const u8,
    pub pubkeys_num: u8,
    pub maximum_non_signers: u32,
}

impl From<&EpochBlockFFI> for EpochBlock {
    fn from(src: &EpochBlockFFI) -> EpochBlock {
        let pubkeys = read_pubkeys(src.pubkeys, src.pubkeys_num as u32).unwrap();
        EpochBlock {
            index: src.index,
            maximum_non_signers: src.maximum_non_signers,
            new_public_keys: pubkeys,
        }
    }
}
