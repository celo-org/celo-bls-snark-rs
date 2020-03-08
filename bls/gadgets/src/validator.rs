use algebra::curves::models::bls12::Bls12Parameters;
use r1cs_core::{ConstraintSystem, SynthesisError};
use r1cs_std::{
    boolean::Boolean, groups::curves::short_weierstrass::bls12::G2Gadget, select::CondSelectGadget,
};
use std::marker::PhantomData;

use crate::enforce_maximum_occurrences_in_bitmap;

/// Gadget for checking that validator diffs are computed correctly
pub struct ValidatorUpdateGadget<P: Bls12Parameters> {
    parameters_type: PhantomData<P>,
}

impl<P: Bls12Parameters> ValidatorUpdateGadget<P> {
    /// Enforces that the validator set is transitioned correctly according to the bitmap
    /// and that no more than `maximum_removed_validators` pubkeys were removed.
    ///
    /// Notes:
    /// - We assume that the number of validators **does not** change over time.
    /// - A 1 in the bitmap means that the old validator is replaced by the new one
    ///
    /// # Panics
    /// - If `old_pub_keys.len() != `removed_validators_bitmap.len()`
    /// - If `new_pub_keys.len() != `removed_validators_bitmap.len()`
    pub fn update<CS: ConstraintSystem<P::Fp>>(
        mut cs: CS,
        old_pub_keys: &[G2Gadget<P>],
        new_pub_keys: &[G2Gadget<P>],
        removed_validators_bitmap: &[Boolean],
        maximum_removed_validators: u64,
    ) -> Result<Vec<G2Gadget<P>>, SynthesisError> {
        assert_eq!(old_pub_keys.len(), removed_validators_bitmap.len());
        assert_eq!(new_pub_keys.len(), removed_validators_bitmap.len());
        // check that no more than `maximum_removed_validators` 1s exist in
        // the provided bitmap
        enforce_maximum_occurrences_in_bitmap(
            &mut cs,
            removed_validators_bitmap,
            maximum_removed_validators,
            true,
        )?;

        // check that the new_pub_keys are correctly computed from the
        // bitmap and the old pubkeys
        let new_validator_set = Self::enforce_validator_set(
            &mut cs,
            old_pub_keys,
            new_pub_keys,
            removed_validators_bitmap,
        )?;
        Ok(new_validator_set)
    }

    /// Checks that if the i_th bit in the provided bitmap is set to 1:
    /// the i_th validator in the old pubkeys array is replaced
    /// with the i_th validator in the new pubkeys array
    fn enforce_validator_set<CS: ConstraintSystem<P::Fp>>(
        cs: &mut CS,
        old_pub_keys: &[G2Gadget<P>],
        new_pub_keys: &[G2Gadget<P>],
        removed_validators_bitmap: &[Boolean],
    ) -> Result<Vec<G2Gadget<P>>, SynthesisError> {
        let mut new_validator_set = Vec::with_capacity(old_pub_keys.len());
        for (i, (pk, bit)) in old_pub_keys
            .iter()
            .zip(removed_validators_bitmap)
            .enumerate()
        {
            // if the bit is 1, the validator is replaced
            let new_pub_key = G2Gadget::<P>::conditionally_select(
                cs.ns(|| format!("cond_select {}", i)),
                bit,
                &new_pub_keys[i],
                pk,
            )?;
            new_validator_set.push(new_pub_key);
        }
        Ok(new_validator_set)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::borrow::Borrow;

    use algebra::{
        bls12_377::{Bls12_377, Parameters as Bls12_377Parameters},
        curves::{bls12::Bls12Parameters, short_weierstrass_jacobian::GroupProjective},
        PairingEngine, ProjectiveCurve, UniformRand,
    };
    use r1cs_std::{
        alloc::AllocGadget, boolean::Boolean, groups::GroupGadget,
        test_constraint_system::TestConstraintSystem,
    };

    fn cs_update<E: PairingEngine, P: Bls12Parameters>(
        old_pubkeys: &[E::G2Projective],
        new_pubkeys: &[E::G2Projective],
        bitmap: &[bool],
        max_removed_validators: u64,
        satisfied: bool,
    ) -> Vec<GroupProjective<P::G2Parameters>>
    where
        // TODO: Is there a way to remove this awkward type bound?
        E::G2Projective: Borrow<GroupProjective<P::G2Parameters>>,
    {
        let mut cs = TestConstraintSystem::<P::Fp>::new();

        // convert the arguments to constraints
        let old_pub_keys = pubkeys_to_constraints::<P, E>(&mut cs, old_pubkeys, "old");
        let new_pub_keys = pubkeys_to_constraints::<P, E>(&mut cs, new_pubkeys, "new");
        let bitmap = bitmap
            .into_iter()
            .map(|b| Boolean::constant(*b))
            .collect::<Vec<_>>();

        // check the result and return the inner data
        let gadget: Vec<G2Gadget<P>> = ValidatorUpdateGadget::<P>::update::<_>(
            cs.ns(|| "validator update"),
            &old_pub_keys,
            &new_pub_keys,
            &bitmap,
            max_removed_validators,
        )
        .unwrap();
        assert_eq!(cs.is_satisfied(), satisfied);
        gadget
            .into_iter()
            .map(|x| x.get_value().unwrap())
            .collect::<Vec<_>>()
    }

    #[test]
    fn all_validators_removed() {
        let (_, old_pubkeys) = keygen_mul::<Bls12_377>(5);
        let (_, new_pubkeys) = keygen_mul::<Bls12_377>(5);
        let result = cs_update::<Bls12_377, Bls12_377Parameters>(
            &old_pubkeys,
            &new_pubkeys,
            &[true; 5],
            5,
            true,
        );
        assert_eq!(new_pubkeys, result);
    }

    #[test]
    fn one_validator_removed() {
        let (_, mut old_pubkeys) = keygen_mul::<Bls12_377>(5);
        let (_, new_pubkeys) = keygen_mul::<Bls12_377>(5);
        let result = cs_update::<Bls12_377, Bls12_377Parameters>(
            &old_pubkeys,
            &new_pubkeys,
            &[true, false, false, false, false],
            3,
            true,
        );
        // the first pubkey was replaced with the 1st pubkey from the
        // new set
        old_pubkeys[0] = new_pubkeys[0];
        assert_eq!(old_pubkeys, result);
    }

    #[test]
    fn some_validators_removed() {
        let (_, old_pubkeys) = keygen_mul::<Bls12_377>(5);
        let (_, mut new_pubkeys) = keygen_mul::<Bls12_377>(5);
        let result = cs_update::<Bls12_377, Bls12_377Parameters>(
            &old_pubkeys,
            &new_pubkeys,
            &[false, true, true, false, true],
            3,
            true,
        );
        // all validators were replaced except the 1st and 4th
        new_pubkeys[0] = old_pubkeys[0];
        new_pubkeys[3] = old_pubkeys[3];
        assert_eq!(new_pubkeys, result);
    }

    #[test]
    fn cannot_remove_more_validators_than_allowed() {
        let (_, old_pubkeys) = keygen_mul::<Bls12_377>(5);
        let (_, new_pubkeys) = keygen_mul::<Bls12_377>(5);
        cs_update::<Bls12_377, Bls12_377Parameters>(
            &old_pubkeys,
            &new_pubkeys,
            &[true; 5], // tries to remove all 5, when only 4 are allowed
            4,
            false,
        );
    }

    #[test]
    #[should_panic]
    fn bad_bitmap_length() {
        let (_, old_pubkeys) = keygen_mul::<Bls12_377>(5);
        let (_, new_pubkeys) = keygen_mul::<Bls12_377>(5);
        cs_update::<Bls12_377, Bls12_377Parameters>(
            &old_pubkeys,
            &new_pubkeys,
            &[true; 3],
            5,
            false,
        );
    }

    #[test]
    #[should_panic]
    fn new_validator_set_wrong_size() {
        let (_, old_pubkeys) = keygen_mul::<Bls12_377>(5);
        let (_, new_pubkeys) = keygen_mul::<Bls12_377>(4);
        cs_update::<Bls12_377, Bls12_377Parameters>(
            &old_pubkeys,
            &new_pubkeys,
            &[true; 5],
            5,
            false,
        );
    }

    fn pubkeys_to_constraints<P: Bls12Parameters, E: PairingEngine>(
        cs: &mut TestConstraintSystem<P::Fp>,
        pubkeys: &[E::G2Projective],
        personalization: &str,
    ) -> Vec<G2Gadget<P>>
    where
        E::G2Projective: Borrow<GroupProjective<P::G2Parameters>>,
    {
        pubkeys
            .iter()
            .enumerate()
            .map(|(i, x)| {
                G2Gadget::<P>::alloc(
                    &mut cs.ns(|| format!("alloc {} {}", personalization, i)),
                    || Ok(*x),
                )
                .unwrap()
            })
            .collect()
    }

    fn keygen_mul<E: PairingEngine>(num: usize) -> (Vec<E::Fr>, Vec<E::G2Projective>) {
        let rng = &mut rand::thread_rng();
        let generator = E::G2Projective::prime_subgroup_generator();

        let mut secret_keys = Vec::new();
        let mut public_keys = Vec::new();
        for _ in 0..num {
            let secret_key = E::Fr::rand(rng);
            let public_key = generator.mul(secret_key);
            secret_keys.push(secret_key);
            public_keys.push(public_key);
        }
        (secret_keys, public_keys)
    }
}
