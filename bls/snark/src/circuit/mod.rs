use algebra::{fields::sw6::Fr, curves::bls12_377::{
    G1Projective,
    G2Projective,
}};
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
    new_pub_keys: Vec<Option<G1Projective>>,
    signed_bitmap: Vec<Option<bool>>,
    signature: Option<G2Projective>,
}

struct ValidatorSetUpdate {
    num_validators: usize,
    updates: Vec<SingleUpdate>,
}

impl ConstraintSynthesizer<Fr> for ValidatorSetUpdate {
    fn generate_constraints<CS: ConstraintSystem<Fr>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        for (i, update) in self.updates.into_iter().enumerate() {
            let mut new_pub_keys_vars = vec![];
            {
                assert_eq!(self.num_validators, update.new_pub_keys.len());
                for (j, maybe_pk) in update.new_pub_keys.iter().enumerate() {
                    let pk_var = G1Gadget::<Bls12_377Parameters>::alloc(
                        cs.ns(|| format!("{}: new pub key {}", i, j)),
                        || maybe_pk.clone().ok_or(SynthesisError::AssignmentMissing)
                    )?;
                    new_pub_keys_vars.push(pk_var);
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use groth16::{
        create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
    };
    use crate::circuit::{ValidatorSetUpdate, SingleUpdate};
    use algebra::curves::sw6::SW6;
    use rand::thread_rng;

    #[test]
    fn test_circuit() {
        let num_validators = 10;
        let rng = &mut thread_rng();
        let params = {
            let update = SingleUpdate {
                maximum_non_signers: None,
                new_pub_keys: vec![None; num_validators],
                signed_bitmap: vec![None; num_validators],
                signature: None,
            };
            let c = ValidatorSetUpdate {
                num_validators: num_validators,
                updates: vec![update],
            };
            println!("generating parameters");
            let p = generate_random_parameters::<SW6, _, _>(c, rng).unwrap();
            println!("generated parameters");
            p
        };
    }
}