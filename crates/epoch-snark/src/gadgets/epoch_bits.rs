use algebra::{
    curves::bls12::Bls12Parameters,
    bls12_377::{Bls12_377, Fr as BlsFr, FrParameters as BlsFrParameters, Parameters as Bls12_377_Parameters},
    bw6_761::{Fr, FrParameters},
    FpParameters,
};
use r1cs_std::bls12_377::PairingVar;
use r1cs_std::prelude::*;

use r1cs_core::{ConstraintSystemRef, SynthesisError};

// Groth16 Specific imports
use crypto_primitives::{
    nizk::{
        constraints::NIZKVerifierGadget,
        groth16::{
            constraints::{Groth16VerifierGadget, ProofVar, VerifyingKeyVar},
            Groth16,
        },
    },
    prf::blake2s::{constraints::evaluate_blake2s_with_parameters, Blake2sWithParameterBlock},
};

use r1cs_std::fields::fp::FpVar;
type FrVar = FpVar<Fr>;
type Bool = Boolean<<Bls12_377_Parameters as Bls12Parameters>::Fp>;

use crate::gadgets::{HashToBits, HashToBitsHelper, MultipackGadget};
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
        cs: ConstraintSystemRef<<Bls12_377_Parameters as Bls12Parameters>::Fp>
    ) -> Result<(), SynthesisError> {
        // Only verify the proof if it was provided
        if let Some(helper) = helper {
            self.verify_proof(&helper, cs)?;
        }
        self.verify_edges()?;
        Ok(())
    }

    fn verify_edges(
        &self,
    ) -> Result<Vec<FrVar>, SynthesisError> {
        // Verify the edges
        let mut xof_bits = vec![];
        let first_and_last_bits = [self.first_epoch_bits.clone(), self.last_epoch_bits.clone()];
        for (_i, bits) in first_and_last_bits.iter().enumerate() {
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
            let xof_result = evaluate_blake2s_with_parameters(
                &message,
                &blake2s_parameters.parameters(),
            )?;
            let mut xof_bits_i = xof_result
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
        cs: ConstraintSystemRef<<Bls12_377_Parameters as Bls12Parameters>::Fp>
    ) -> Result<(), SynthesisError> {
        // Verify the proof
        let proof = ProofVar::<_, PairingVar>::new_witness(cs, 
        || {
            Ok(helper.proof.clone())
        })?;

        // Allocate the VK
        let verifying_key = VerifyingKeyVar::<_, PairingVar>::new_constant(
            proof.a.cs().unwrap_or(ConstraintSystemRef::None),
            helper.verifying_key.clone(),
        )?;

        // The public inputs are the CRH and XOF bits split in `Fr::CAPACITY` chunks
        // encoded in LE
        let packed_crh_bits = le_chunks(&self.crh_bits, BlsFrParameters::CAPACITY);
        let packed_xof_bits = le_chunks(&self.xof_bits, BlsFrParameters::CAPACITY);

        let public_inputs: Vec<Vec<Bool>> = [packed_crh_bits, packed_xof_bits].concat();

        <Groth16VerifierGadget<_, PairingVar> as NIZKVerifierGadget<
            Groth16<Bls12_377, HashToBits, BlsFr>,
            Fr,
        >>::verify(
            &verifying_key,
            public_inputs.iter(),
            &proof,
        )?;

        Ok(())
    }
}

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
    use bls_gadgets::utils::bytes_to_bits;
    use rand::RngCore;

    use crate::epoch_block::hash_to_bits;
    use crate::gadgets::pack;
    use r1cs_core::{ConstraintSystem, ConstraintLayer};
    use algebra::PrimeField;
    use tracing_subscriber::layer::SubscriberExt;

/*    fn to_bool<F: PrimeField>(cs: ConstraintSystemRef<F>, iter: &[bool]) -> Result<Vec<Boolean<F>>, SynthesisError> {
        iter.iter().map(|b| Bool::new_witness(cs.clone(), || Ok(*b))).collect::<Result<Vec<_>, _>>()
    }*/

    #[test]
    fn correct_blake2_hash() {
        let mut layer = ConstraintLayer::default();
        layer.mode = r1cs_core::TracingMode::OnlyConstraints;
        let subscriber = tracing_subscriber::Registry::default().with(layer);
        tracing::subscriber::set_global_default(subscriber).unwrap();

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

        let mut cs = ConstraintSystem::<Fr>::new_ref();
        // encode each epoch's bytes to LE and pass them to the constraint system
        let first_epoch_bits = bytes_to_bits(&first_bytes, 256);
        let last_epoch_bits = bytes_to_bits(&last_bytes, 256);
        let bits = EpochBits {
            crh_bits: vec![],
            xof_bits: vec![],
            first_epoch_bits: first_epoch_bits.iter().map(|b| Boolean::new_witness(cs.clone(), || Ok(*b))).collect::<Result<Vec<_>, _>>().unwrap(), //to_bool(&first_epoch_bits),
            last_epoch_bits: last_epoch_bits.iter().map(|b| Boolean::new_witness(cs.clone(), || Ok(*b))).collect::<Result<Vec<_>, _>>().unwrap(),//to_bool(&last_epoch_bits),
        };

        let packed = bits.verify_edges().unwrap();
        if !cs.is_satisfied().unwrap() {
            println!("=========================================================");
            println!("Unsatisfied constraints:");
            println!("{}", cs.which_is_unsatisfied().unwrap().unwrap());
            println!("=========================================================");
        }
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
