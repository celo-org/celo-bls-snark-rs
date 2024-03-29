use ark_bls12_377::{Fr, FrParameters};
use ark_ff::FpParameters;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use tracing::{debug, info, span, trace, Level};

use crate::gadgets::constrain_bool;
use bls_crypto::SIG_DOMAIN;
use bls_gadgets::hash_to_bits;

use super::MultipackGadget;

#[derive(Clone)]
/// Gadget which converts its inputs to Boolean constraints, applies blake2x to them
/// and then packs both the boolean constraints and the blake2x constraints in Fr elements
///
/// Utilizes the `hash_to_bits` call under the hood
///
/// This is used as a helper gadget to enforce that the provided XOF bits inputs
/// are correctly calculated from the CRH in the SNARK
pub struct HashToBits {
    pub message_bits: Vec<Vec<Option<bool>>>,
}

impl HashToBits {
    /// Initializes an empty vector of bits. This is called when running the trusted setup
    pub fn empty<P: FpParameters>(num_epochs: usize) -> Self {
        let modulus_bit_rounded = (((P::MODULUS_BITS + 7) / 8) * 8) as usize;
        HashToBits {
            message_bits: vec![vec![None; modulus_bit_rounded]; num_epochs],
        }
    }
}

impl ConstraintSynthesizer<Fr> for HashToBits {
    #[allow(clippy::cognitive_complexity)] // false positive triggered by the info!("generating constraints") log
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let span = span!(Level::TRACE, "HashToBits");
        info!("generating constraints");
        let _enter = span.enter();
        let mut personalization = [0; 8];
        personalization.copy_from_slice(SIG_DOMAIN);

        let mut all_bits = vec![];
        let mut xof_bits = vec![];
        for (i, message_bits) in self.message_bits.iter().enumerate() {
            trace!(epoch = i, "hashing to bits");
            let bits = constrain_bool(message_bits, cs.clone())?;
            let hash = hash_to_bits(&bits[..], 512, personalization, true)?;
            all_bits.extend_from_slice(&bits);
            xof_bits.extend_from_slice(&hash);
        }

        // Pack them as public inputs
        debug!(capacity = FrParameters::CAPACITY, "packing CRH bits");
        MultipackGadget::pack::<Fr, FrParameters>(
            &all_bits[..],
            FrParameters::CAPACITY as usize,
            true,
        )?;
        debug!(capacity = FrParameters::CAPACITY, "packing XOF bits");
        MultipackGadget::pack::<Fr, FrParameters>(
            &xof_bits,
            FrParameters::CAPACITY as usize,
            true,
        )?;

        info!("constraints generated");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gadgets::pack;
    use bls_crypto::hashers::{DirectHasher, Hasher};
    use bls_gadgets::utils::{bits_le_to_bytes_le, bytes_le_to_bits_le};

    use ark_bls12_377::Bls12_377;
    use ark_bw6_761::FrParameters as BW6_761FrParameters;
    use ark_groth16::{
        create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
    };
    use rand::RngCore;

    // applies the XOF to the input
    fn hash_to_bits_fn(message: &[bool]) -> Vec<bool> {
        let mut personalization = [0; 8];
        personalization.copy_from_slice(SIG_DOMAIN);
        let message = bits_le_to_bytes_le(message);
        let hash_result = DirectHasher.xof(&personalization, &message, 64).unwrap();
        bytes_le_to_bits_le(&hash_result, 512)
    }

    #[test]
    fn test_verify_crh_to_xof() {
        let rng = &mut rand::thread_rng();
        // generate an empty circuit for 3 epochs
        let num_epochs = 3;
        // Trusted Setup -- USES THE BW6_761FrParameters!
        let params = {
            let empty = HashToBits::empty::<BW6_761FrParameters>(num_epochs);
            generate_random_parameters::<Bls12_377, _, _>(empty, rng).unwrap()
        };

        // Prover generates the input and the proof
        // Each message must be 384 bits.
        let (proof, input) = {
            let mut message_bits = Vec::new();
            for _ in 0..num_epochs {
                // say we have some input
                let mut input = vec![0; 64];
                rng.fill_bytes(&mut input);
                let bits = bytes_le_to_bits_le(&input, 384)
                    .iter()
                    .map(|b| Some(*b))
                    .collect::<Vec<_>>();
                message_bits.push(bits);
            }

            // generate the proof
            let circuit = HashToBits {
                message_bits: message_bits.clone(),
            };
            let proof = create_random_proof(circuit, &params, rng).unwrap();

            (proof, message_bits)
        };

        // verifier takes the input, hashes it and packs it
        // (both the crh and the xof bits are public inputs!)
        let public_inputs = {
            let mut message_bits = Vec::new();
            let mut xof_bits = Vec::new();
            for message in &input {
                let bits = message.iter().map(|m| m.unwrap()).collect::<Vec<_>>();
                xof_bits.extend_from_slice(&hash_to_bits_fn(&bits));
                message_bits.extend_from_slice(&bits);
            }
            // The public inputs are the CRH and XOF bits split in `Fr::CAPACITY` chunks
            // encoded in LE
            let packed_crh_bits = pack::<Fr, FrParameters>(&message_bits).unwrap();
            let packed_xof_bits = pack::<Fr, FrParameters>(&xof_bits).unwrap();
            [packed_crh_bits, packed_xof_bits].concat()
        };

        let pvk = prepare_verifying_key(&params.vk);
        assert!(verify_proof(&pvk, &proof, &public_inputs).unwrap());
    }
}
