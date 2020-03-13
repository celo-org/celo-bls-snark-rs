use super::{BLSCurve, CPCurve, CPField, CPFrParams};
use crate::epoch_block::{hash_first_last_epoch_block, EpochBlock};
use crate::gadgets::pack;
use groth16::{prepare_verifying_key, verify_proof, Proof, VerifyingKey};
use r1cs_core::SynthesisError;

/// The verifier only needs to check that the edges were calculated correctly
pub fn verify(
    vk: &VerifyingKey<CPCurve>,
    first_epoch: &EpochBlock,
    last_epoch: &EpochBlock,
    proof: Proof<CPCurve>,
) -> Result<(), SynthesisError> {
    // Hash the first-last block together
    let hash = hash_first_last_epoch_block(first_epoch, last_epoch).unwrap();
    // packs them
    let public_inputs = pack::<CPField, CPFrParams>(&hash);
    // verifies the BLS proof by using the First/Last epoch as public inputs over CP
    verify_proof(&prepare_verifying_key(vk), &proof, &public_inputs)?;
    Ok(())
}
