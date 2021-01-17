use super::{BWCurve, BWField, BWFrParams};
use crate::encoding::EncodingError;
use crate::epoch_block::{hash_first_last_epoch_block, EpochBlock};
use crate::gadgets::pack;
use ark_groth16::{prepare_verifying_key, verify_proof, Proof, VerifyingKey};
use ark_relations::r1cs::SynthesisError;
use thiserror::Error;
use tracing::info;

#[derive(Debug, Error)]
/// Error raised while verifying the SNARK proof
pub enum VerificationError {
    #[error("Verification failed")]
    VerificationFailed,
    #[error("Synthesis Error: {0}")]
    ZexeSynthesisError(#[from] SynthesisError),
    #[error("Encoding Error: {0}")]
    EpochEncodingError(#[from] EncodingError),
}

/// Given the Verifying Key for the circuit and the SNARK proof and _only the first and last epoch_,
/// this function ensures that the state transition between epochs has been calculated correctly.
pub fn verify(
    vk: &VerifyingKey<BWCurve>,
    first_epoch: &EpochBlock,
    last_epoch: &EpochBlock,
    proof: &Proof<BWCurve>,
) -> Result<(), VerificationError> {
    info!("Verifying proof");
    // Hash the first-last block together
    let hash = hash_first_last_epoch_block(first_epoch, last_epoch)?;
    // packs them
    let public_inputs = pack::<BWField, BWFrParams>(&hash)?;
    // verifies the BLS proof by using the First/Last epoch as public inputs over CP
    if verify_proof(&prepare_verifying_key(vk), proof, &public_inputs)? {
        Ok(())
    } else {
        Err(VerificationError::VerificationFailed)
    }
}
