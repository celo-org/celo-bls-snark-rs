use ark_bls12_377::{
    constraints::PairingVar, Bls12_377, Fr as BlsFr, FrParameters as BlsFrParameters,
    Parameters as Bls12_377_Parameters,
};
use ark_bw6_761::{Fr, FrParameters};
use ark_ec::bls12::Bls12Parameters;
use ark_ff::FpParameters;
use ark_groth16::{
    constraints::{Groth16VerifierGadget, ProofVar, VerifyingKeyVar},
    Groth16,
};

use ark_crypto_primitives::{
    prf::blake2s::{constraints::evaluate_blake2s_with_parameters, Blake2sWithParameterBlock},
    snark::SNARKGadget as NIZKVerifierGadget,
};
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

type FrVar = FpVar<Fr>;
type Bool = Boolean<<Bls12_377_Parameters as Bls12Parameters>::Fp>;

use crate::gadgets::{HashToBitsHelper, MultipackGadget};
use ark_crypto_primitives::snark::BooleanInputVar;
use bls_crypto::OUT_DOMAIN;

/// Contains the first and last epoch's bits, along with auxiliary CRH and XOF bits
/// which are used for verifying the CRH -> XOF hash calculation
pub struct EpochBits {
    /// The first epoch's bits
    pub first_epoch_bits: Vec<Bool>,
    /// The last epoch's bits
    pub last_epoch_bits: Vec<Bool>,
    /// The CRH bits for all intermediate state transitions
    pub crh_bits: Vec<Bool>,
    /// The XOF bits for all intermediate state transitions
    pub xof_bits: Vec<Bool>,
}

impl EpochBits {
    /// Verify that the intermediate proofs are computed correctly and that the edges are correctly calculated
    pub fn verify(
        &self,
        helper: Option<HashToBitsHelper<Bls12_377>>,
        cs: ConstraintSystemRef<<Bls12_377_Parameters as Bls12Parameters>::Fp>,
    ) -> Result<(), SynthesisError> {
        // Only verify the proof if it was provided
        if let Some(helper) = helper {
            self.verify_proof(&helper, cs)?;
        }
        self.verify_edges()?;
        Ok(())
    }

    /// Generates constrained hash outputs on the first and last
    /// epoch bits
    fn verify_edges(&self) -> Result<Vec<FrVar>, SynthesisError> {
        // Verify the edges
        let mut xof_bits = vec![];
        let first_and_last_bits = [self.first_epoch_bits.clone(), self.last_epoch_bits.clone()];
        for bits in first_and_last_bits.iter() {
            let mut message = bits.to_owned();
            message.reverse();
            let message_rounded_len = 8 * ((message.len() + 7) / 8);
            message.resize(message_rounded_len, Bool::constant(false));

            let mut personalization = [0; 8];
            personalization.copy_from_slice(OUT_DOMAIN);

            let blake2s_parameters = Blake2sWithParameterBlock {
                digest_length: 32,
                key_length: 0,
                fan_out: 1,
                depth: 1,
                leaf_length: 0,
                node_offset: 0,
                xof_digest_length: 0,
                node_depth: 0,
                inner_length: 0,
                salt: [0; 8],
                personalization,
            };
            let xof_result =
                evaluate_blake2s_with_parameters(&message, &blake2s_parameters.parameters())?;
            let xof_bits_i = xof_result
                .into_iter()
                .map(|n| n.to_bits_le())
                .flatten()
                .collect::<Vec<Bool>>();
            xof_bits.extend_from_slice(&xof_bits_i);
        }

        // Make the edges public inputs
        // packed over BW6_761 Fr.
        let packed = MultipackGadget::pack::<_, FrParameters>(
            &xof_bits,
            FrParameters::CAPACITY as usize,
            true,
        )?;

        Ok(packed)
    }

    /// Ensure that the intermediate BH and Blake2 hashes match
    fn verify_proof(
        &self,
        helper: &HashToBitsHelper<Bls12_377>,
        cs: ConstraintSystemRef<<Bls12_377_Parameters as Bls12Parameters>::Fp>,
    ) -> Result<(), SynthesisError> {
        // Verify the proof
        let proof = ProofVar::<_, PairingVar>::new_witness(cs, || Ok(helper.proof.clone()))?;

        // Allocate the VK
        let verifying_key = VerifyingKeyVar::<_, PairingVar>::new_constant(
            proof.a.cs(),
            helper.verifying_key.clone(),
        )?;

        // The public inputs are the CRH and XOF bits split in `Fr::CAPACITY` chunks
        // encoded in LE
        let packed_crh_bits = le_chunks(&self.crh_bits, BlsFrParameters::CAPACITY);
        let packed_xof_bits = le_chunks(&self.xof_bits, BlsFrParameters::CAPACITY);

        let public_inputs: Vec<Vec<Bool>> = [packed_crh_bits, packed_xof_bits].concat();

        let _ = <Groth16VerifierGadget<_, PairingVar> as NIZKVerifierGadget<
            BlsFr,
            Fr,
            Groth16<Bls12_377>,
        >>::verify(&verifying_key, &BooleanInputVar::new(public_inputs), &proof)?;

        Ok(())
    }
}

/// Returns a vector of vectors of constrained booleans
/// all of the same size given a vector of constrained
/// booleans
fn le_chunks(iter: &[Bool], chunk_size: u32) -> Vec<Vec<Bool>> {
    iter.chunks(chunk_size as usize)
        .map(|b| {
            let mut b = b.to_vec();
            b.reverse();
            b
        })
        .collect::<Vec<_>>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{epoch_block::hash_to_bits, gadgets::pack};
    use bls_gadgets::utils::{
        bytes_le_to_bits_be,
        test_helpers::{print_unsatisfied_constraints, run_profile_constraints},
    };

    use ark_relations::r1cs::ConstraintSystem;
    use rand::RngCore;

    #[test]
    fn correct_blake2_hash() {
        run_profile_constraints(correct_blake2_hash_inner);
    }
    #[tracing::instrument(target = "r1cs")]
    fn correct_blake2_hash_inner() {
        let rng = &mut rand::thread_rng();
        let mut first_bytes = vec![0; 32];
        rng.fill_bytes(&mut first_bytes);
        let mut last_bytes = vec![0; 32];
        rng.fill_bytes(&mut last_bytes);

        let both_blake_bits = [first_bytes.clone(), last_bytes.clone()]
            .iter()
            .map(|b| hash_to_bits(b))
            .flatten()
            .collect::<Vec<bool>>();

        let cs = ConstraintSystem::<Fr>::new_ref();
        // encode each epoch's bytes to LE and pass them to the constraint system
        let first_epoch_bits = bytes_le_to_bits_be(&first_bytes, 256);
        let last_epoch_bits = bytes_le_to_bits_be(&last_bytes, 256);
        let bits = EpochBits {
            crh_bits: vec![],
            xof_bits: vec![],
            first_epoch_bits: first_epoch_bits
                .iter()
                .map(|b| Boolean::new_input(cs.clone(), || Ok(*b)))
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            last_epoch_bits: last_epoch_bits
                .iter()
                .map(|b| Boolean::new_input(cs.clone(), || Ok(*b)))
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
        };

        let packed = bits.verify_edges().unwrap();

        print_unsatisfied_constraints(cs.clone());
        assert!(cs.is_satisfied().unwrap());

        // get the inner packed value
        let inner = packed
            .into_iter()
            .map(|i| i.value().unwrap())
            .collect::<Vec<_>>();
        // pack our bits to Fr as well, and see if they match
        let public_inputs = pack::<Fr, FrParameters>(&both_blake_bits).unwrap();
        assert_eq!(inner, public_inputs);
    }
}
