use super::{BLSCurve, CPCurve, Parameters};
use crate::{
    epoch_block::{EpochBlock, EpochTransition},
    gadgets::{single_update::SingleUpdate, EpochData, HashToBits, ValidatorSetUpdate},
};
use bls_crypto::{hash::composite::CRH, hash::XOF, CompositeHasher, PublicKey, Signature};
use bls_gadgets::bytes_to_bits;

use algebra::{bls12_377::G1Projective, Zero};
use groth16::{create_random_proof, Proof as Groth16Proof};
use r1cs_core::SynthesisError;

pub fn prove(
    parameters: &Parameters,
    num_validators: u32,
    initial_epoch: &EpochBlock,
    transitions: &[EpochTransition],
    rng: &mut impl rand::Rng,
) -> Result<Groth16Proof<CPCurve>, SynthesisError> {
    let composite_hasher = CompositeHasher::new().unwrap();
    // Generate the CRH per epoch
    let mut message_bits = Vec::with_capacity(transitions.len());
    let mut epochs = Vec::with_capacity(transitions.len());
    for transition in transitions {
        let block = &transition.block;
        let epoch_bytes = block.encode_to_bytes().unwrap();
        let crh_bytes = composite_hasher.crh(&[], &epoch_bytes, 0).unwrap();
        // The verifier should run both the crh and the xof here to generate a
        // valid statement for the verify
        message_bits.push(
            bytes_to_bits(&crh_bytes, 384)
                .iter()
                .map(|b| Some(*b))
                .collect(),
        );
        epochs.push(to_update(transition));
    }

    // Generate proof of correct calculation of the CRH->Blake hashes
    // to make Hash to G1 cheaper
    let circuit = HashToBits { message_bits };
    let hash_proof = create_random_proof(circuit, &parameters.hash_to_bits, rng)?;

    // Generate the BLS proof
    let asig = transitions.iter().fold(G1Projective::zero(), |acc, epoch| {
        acc + epoch.aggregate_signature.get_sig()
    });

    let circuit = ValidatorSetUpdate::<BLSCurve> {
        initial_epoch: to_epoch_data(initial_epoch),
        epochs,
        aggregated_signature: Some(asig),
        num_validators: num_validators,
        proof: hash_proof.clone(),
        verifying_key: parameters.vk().1.clone(),
    };
    let bls_proof = create_random_proof(circuit, &parameters.epochs, rng)?;

    Ok(bls_proof)
}

fn to_epoch_data(block: &EpochBlock) -> EpochData<BLSCurve> {
    EpochData {
        index: Some(block.index),
        maximum_non_signers: Some(block.maximum_non_signers),
        aggregated_pub_key: Some(block.aggregated_public_key.get_pk()),
        public_keys: block
            .new_public_keys
            .iter()
            .map(|pubkey| Some(pubkey.get_pk()))
            .collect(),
    }
}

fn to_update(transition: &EpochTransition) -> SingleUpdate<BLSCurve> {
    SingleUpdate {
        epoch_data: to_epoch_data(&transition.block),
        signed_bitmap: transition
            .bitmap
            .iter()
            .map(|b| Some(*b))
            .collect::<Vec<_>>(),
    }
}