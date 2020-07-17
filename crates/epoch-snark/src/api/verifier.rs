use super::{CPCurve, CPField, CPFrParams};
use crate::encoding::{EncodingError, encode_public_key};
use crate::epoch_block::{hash_first_last_epoch_block, EpochBlock};
use crate::gadgets::pack;
use groth16::{prepare_verifying_key, verify_proof, Proof, VerifyingKey};
use r1cs_core::SynthesisError;
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
    vk: &VerifyingKey<CPCurve>,
    first_epoch: &EpochBlock,
    last_epoch: &EpochBlock,
    proof: &Proof<CPCurve>,
) -> Result<(), VerificationError> {
    info!("Verifying proof");
    // Hash the first-last block together
    let hash = hash_first_last_epoch_block(first_epoch, last_epoch)?;
    // packs them
    let mut public_inputs = pack::<CPField, CPFrParams>(&hash)?;
    public_inputs.push(CPField::one());
    // verifies the BLS proof by using the First/Last epoch as public inputs over CP
    if verify_proof(&prepare_verifying_key(vk), proof, &public_inputs)? {
        Ok(())
    } else {
        Err(VerificationError::VerificationFailed)
    }
}
