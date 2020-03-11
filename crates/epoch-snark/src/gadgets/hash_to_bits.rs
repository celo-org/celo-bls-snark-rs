use algebra::{
    bls12_377::{Fr, FrParameters},
    FpParameters,
};
use r1cs_core::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};

use super::{constrain_bool, MultipackGadget};
use bls_crypto::bls::keys::SIG_DOMAIN;
use bls_gadgets::hash_to_bits;

#[derive(Clone)]
/// Gadget which
/// 1. Converts its inputs to Boolean constraints
/// 1. Applies blake2x to them
/// 1. Packs both the boolean constraints and the blake2x constraints in Fr elements
///
/// Utilizes the `hash_to_bits` call under the hood
///
/// This is used as a helper gadget to enforce that the provided XOF bits inputs
/// are correctly calculated from the CRH in the SNARK
pub struct HashToBits {
    pub message_bits: Vec<Vec<Option<bool>>>,
}

impl HashToBits {
    /// To be used when generating the trusted setup parameters
    pub fn empty<P: FpParameters>(num_epochs: usize) -> Self {
        let modulus_bit_rounded = (((P::MODULUS_BITS + 7) / 8) * 8) as usize;
        HashToBits {
            message_bits: vec![vec![None; modulus_bit_rounded]; num_epochs],
        }
    }
}

impl ConstraintSynthesizer<Fr> for HashToBits {
    fn generate_constraints<CS: ConstraintSystem<Fr>>(
        self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        let mut personalization = [0; 8];
        personalization.copy_from_slice(SIG_DOMAIN);

        let mut all_bits = vec![];
        let mut xof_bits = vec![];
        for (i, message_bits) in self.message_bits.iter().enumerate() {
            let bits = constrain_bool(&mut cs.ns(|| i.to_string()), &message_bits)?;
            let hash = hash_to_bits(
                cs.ns(|| format!("{}: hash to bits", i)),
                &bits,
                512,
                personalization,
                true,
            )?;
            all_bits.extend_from_slice(&bits);
            xof_bits.extend_from_slice(&hash);
        }

        // Pack them as public inputs
        MultipackGadget::pack(
            cs.ns(|| "pack messages"),
            &all_bits,
            FrParameters::CAPACITY as usize,
            true,
        )?;
        MultipackGadget::pack(
            cs.ns(|| "pack xof bits"),
            &xof_bits,
            FrParameters::CAPACITY as usize,
            true,
        )?;

        Ok(())
    }
}
