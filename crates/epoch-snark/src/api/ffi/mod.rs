mod utils;
use utils::{read_slice, EpochBlockFFI, PROOF_BYTES, VK_BYTES};

use crate::api::{CPCurve, Parameters};
use crate::convert_result_to_bool;
use crate::epoch_block::{EpochBlock, EpochTransition};
use algebra::{bls12_377::G2Affine, AffineCurve, CanonicalDeserialize};

#[no_mangle]
/// # Safety
///
/// VK and Proof must be valid pointers
/// The vector of pubkeys inside EpochBlockFFI must point to valid memory
pub unsafe extern "C" fn verify(
    // serialized VK
    vk: *const u8,
    // serialized Proof
    proof: *const u8,
    first_epoch: EpochBlockFFI,
    last_epoch: EpochBlockFFI,
) -> bool {
    let first_epoch = EpochBlock::from(&first_epoch);
    let last_epoch = EpochBlock::from(&last_epoch);
    let vk = read_slice(vk, VK_BYTES).unwrap();
    let proof = read_slice(proof, PROOF_BYTES).unwrap();

    super::verifier::verify(&vk, &first_epoch, &last_epoch, proof).is_ok()
}
