use algebra::{fields::sw6::Fr, curves::bls12_377::{
    G1Projective,
    G2Projective,
}, ProjectiveCurve};
use r1cs_core::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};
use crate::gadgets::{
    hash_to_group::HashToGroupGadget,
    y_to_bit::YToBitGadget,
    validator::ValidatorUpdateGadget,
    bls::BlsVerifyGadget,
};
use r1cs_std::{
    alloc::AllocGadget,
    groups::curves::short_weierstrass::bls12::G1Gadget
};
use algebra::curves::bls12_377::Bls12_377Parameters;
use r1cs_std::bits::boolean::Boolean;

struct SingleUpdate {
    maximum_non_signers: Option<Fr> ,
    old_pub_keys: Vec<Option<G1Projective>>,
    removed_validators_bitmap: Vec<Option<bool>>,
    new_pub_keys: Vec<Option<G1Projective>>,
    signed_bitmap: Vec<Option<bool>>,
    signature: Option<G2Projective>,
}

struct ValidatorSetUpdate {
    maximum_removed_validators: usize,
    num_validators: usize,
    updates: Vec<SingleUpdate>,
}

impl ConstraintSynthesizer<Fr> for ValidatorSetUpdate {
    fn generate_constraints<CS: ConstraintSystem<Fr>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        for (i, update) in self.updates.into_iter().enumerate() {
            let mut old_pub_keys_vars = vec![];
            {
                assert_eq!(self.num_validators, update.old_pub_keys.len());
                for (j, maybe_pk) in update.old_pub_keys.iter().enumerate() {
                    let pk_var = G1Gadget::<Bls12_377Parameters>::alloc(
                        cs.ns(|| format!("{}: old pub key {}", i, j)),
                        || Ok(maybe_pk.unwrap().clone())
                    )?;
                    old_pub_keys_vars.push(pk_var);
                }
            }

            let mut new_pub_keys_vars = vec![];
            {
                assert_eq!(self.num_validators, update.new_pub_keys.len());
                for (j, maybe_pk) in update.new_pub_keys.iter().enumerate() {
                    let pk_var = G1Gadget::<Bls12_377Parameters>::alloc(
                        cs.ns(|| format!("{}: new pub key {}", i, j)),
                        || Ok(maybe_pk.unwrap().clone())
                    )?;
                    new_pub_keys_vars.push(pk_var);
                }
            }

            let mut removed_validators_bitmap_vars = vec![];
            {
                assert_eq!(self.num_validators, update.removed_validators_bitmap.len());
                for (j, maybe_bit) in update.removed_validators_bitmap.iter().enumerate() {
                    let bit_var = Boolean::alloc(
                        cs.ns(|| format!("{}: removed validator bit {}", i, j)),
                        || Ok(maybe_bit.unwrap().clone())
                    )?;
                    removed_validators_bitmap_vars.push(bit_var);
                }
            }

            let updated_validator_set = ValidatorUpdateGadget::<Bls12_377Parameters>::update(
                cs.ns(|| format!("validator update {}", i)),
                old_pub_keys_vars,
                new_pub_keys_vars,
                removed_validators_bitmap_vars,
                self.maximum_removed_validators as u64,
            )?;
        }

        Ok(())
    }
}