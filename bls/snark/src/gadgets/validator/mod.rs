use algebra::{Field, PrimeField, Group};
use r1cs_core::{ConstraintSystem, SynthesisError, LinearCombination};
use r1cs_std::{
    Assignment,
    fields::{
        fp::FpGadget,
    },
    groups::GroupGadget,
    alloc::AllocGadget,
    boolean::Boolean,
    bits::ToBitsGadget,
};
use std::marker::PhantomData;

pub struct ValidatorUpdateGadget<
    G: Group,
    ConstraintF: Field + PrimeField,
    GG: GroupGadget<G, ConstraintF>,
> {
    group_type: PhantomData<G>,
    constraint_field_type: PhantomData<ConstraintF>,
    group_gadget_type: PhantomData<GG>,
}

impl<
        G: Group,
        ConstraintF: Field + PrimeField,
        GG: GroupGadget<G, ConstraintF>,
    > ValidatorUpdateGadget<G, ConstraintF, GG>
{
    // this will be much better when we can bound removed_validators_bitmap
    pub fn update<CS: ConstraintSystem<ConstraintF>>(
        mut cs: CS,
        old_pub_keys: Vec<GG>,
        new_pub_keys: Vec<GG>,
        removed_validators_bitmap: Vec<Boolean>,
        maximum_removed_validators: u128,
    ) -> Result<Vec<GG>, SynthesisError> {
        assert_eq!(old_pub_keys.len(), removed_validators_bitmap.len());

        let mut num_removed_validators_num = Some(0);
        let mut num_removed_validators_lc = LinearCombination::zero();

        let mut new_validator_set = vec![];
        for (i, pk) in old_pub_keys.iter().enumerate() {
            let new_pub_key = GG::conditionally_select(
                &mut cs.ns(|| format!("cond_select {}", i)),
                &removed_validators_bitmap[i],
                &new_pub_keys[i],
                pk,
            )?;
            new_validator_set.push(new_pub_key);

            num_removed_validators_lc = num_removed_validators_lc + &removed_validators_bitmap[i].lc(CS::one(), ConstraintF::one());
            if removed_validators_bitmap[i].get_value().is_none() {
                num_removed_validators_num = None;
            }

            if num_removed_validators_num.is_some() {
                num_removed_validators_num = Some(num_removed_validators_num.get()? + if removed_validators_bitmap[i].get_value().get()? { 0 } else { 1 });
            }
        }

        let num_removed_validators = FpGadget::alloc(
            &mut cs.ns(|| "num removed validators"),
            || Ok(ConstraintF::from(num_removed_validators_num.get()? as u128))
        )?;

        let num_removed_validators_bits = &num_removed_validators.to_bits(
            &mut cs.ns(|| "num removed validators to bits"),
        )?;
        Boolean::enforce_smaller_or_equal_than::<_, _, ConstraintF, _>(
            &mut cs.ns(|| "enforce maximum removed validators"),
            num_removed_validators_bits,
            ConstraintF::from(maximum_removed_validators).into_repr(),
        )?;


        Ok(new_validator_set)
    }
}

#[cfg(test)]
mod test {
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    use algebra::{
        curves::{
            bls12_377::{
                G1Projective as Bls12_377G1Projective,
            },
            ProjectiveCurve,
        },
        fields::bls12_377::Fr as Bls12_377Fr,
        fields::sw6::Fr as SW6Fr,
        UniformRand,
    };
    use r1cs_core::ConstraintSystem;
    use r1cs_std::{
        groups::bls12::bls12_377::{G1Gadget as Bls12_377G1Gadget},
        test_constraint_system::TestConstraintSystem,
        alloc::AllocGadget,
        boolean::Boolean,
    };

    use super::ValidatorUpdateGadget;
    use r1cs_std::groups::curves::short_weierstrass::bls12::G1Gadget;
    use algebra::curves::bls12_377::Bls12_377Parameters;

    #[test]
    fn test_validator_update() {
        let rng = &mut XorShiftRng::from_seed([0x5d, 0xbe, 0x62, 0x59, 0x8d, 0x31, 0x3d, 0x76, 0x32, 0x37, 0xdb, 0x17, 0xe5, 0xbc, 0x06, 0x54]);
        let secret_key = Bls12_377Fr::rand(rng);
        let secret_key2 = Bls12_377Fr::rand(rng);
        let secret_key3 = Bls12_377Fr::rand(rng);

        let generator = Bls12_377G1Projective::prime_subgroup_generator();
        let pub_key = generator.clone() * &secret_key;
        let pub_key2 = generator.clone() * &secret_key2;
        let pub_key3 = generator.clone() * &secret_key3;

        {
            let mut cs = TestConstraintSystem::<SW6Fr>::new();

            let old_pub_keys = vec![pub_key.clone(), pub_key2.clone()]
                .iter().enumerate()
                .map(|(i, x)| G1Gadget::<Bls12_377Parameters>::alloc(
                &mut cs.ns(|| format!("alloc old {}", i)),
                    || Ok(x),
                ).unwrap()
            ).collect();
            let new_pub_keys = vec![pub_key3.clone(), Bls12_377G1Projective::zero()]
                .iter().enumerate()
                .map(|(i, x)| G1Gadget::<Bls12_377Parameters>::alloc(
                    &mut cs.ns(|| format!("alloc new {}", i)),
                    || Ok(x),
                ).unwrap()
            ).collect();

            let bitmap = vec![Boolean::constant(true), Boolean::constant(false)];

            ValidatorUpdateGadget::<Bls12_377G1Projective, SW6Fr, Bls12_377G1Gadget>::update(
                cs.ns(|| "validator update"),
                old_pub_keys,
                new_pub_keys,
                bitmap,
                1,
            ).unwrap();

            println!("number of constraints: {}", cs.num_constraints());

            assert!(cs.is_satisfied());
        }

        {
            let mut cs = TestConstraintSystem::<SW6Fr>::new();

            let old_pub_keys = vec![pub_key.clone(), pub_key2.clone()]
                .iter().enumerate()
                .map(|(i, x)| G1Gadget::<Bls12_377Parameters>::alloc(
                    &mut cs.ns(|| format!("alloc old {}", i)),
                    || Ok(x),
                ).unwrap()
                ).collect();
            let new_pub_keys = vec![pub_key3.clone(), Bls12_377G1Projective::zero()]
                .iter().enumerate()
                .map(|(i, x)| G1Gadget::<Bls12_377Parameters>::alloc(
                    &mut cs.ns(|| format!("alloc new {}", i)),
                    || Ok(x),
                ).unwrap()
                ).collect();

            let bitmap = vec![Boolean::constant(true), Boolean::constant(false)];

            ValidatorUpdateGadget::<Bls12_377G1Projective, SW6Fr, Bls12_377G1Gadget>::update(
                cs.ns(|| "validator update"),
                old_pub_keys,
                new_pub_keys,
                bitmap,
                2,
            ).unwrap();

            println!("number of constraints: {}", cs.num_constraints());

            assert!(cs.is_satisfied());
        }

        {
            let mut cs = TestConstraintSystem::<SW6Fr>::new();

            let old_pub_keys = vec![pub_key.clone(), pub_key2.clone()]
                .iter().enumerate()
                .map(|(i, x)| G1Gadget::<Bls12_377Parameters>::alloc(
                    &mut cs.ns(|| format!("alloc old {}", i)),
                    || Ok(x),
                ).unwrap()
                ).collect();
            let new_pub_keys = vec![pub_key3.clone(), Bls12_377G1Projective::zero()]
                .iter().enumerate()
                .map(|(i, x)| G1Gadget::<Bls12_377Parameters>::alloc(
                    &mut cs.ns(|| format!("alloc new {}", i)),
                    || Ok(x),
                ).unwrap()
                ).collect();

            let bitmap = vec![Boolean::constant(true), Boolean::constant(false)];

            ValidatorUpdateGadget::<Bls12_377G1Projective, SW6Fr, Bls12_377G1Gadget>::update(
                cs.ns(|| "validator update"),
                old_pub_keys,
                new_pub_keys,
                bitmap,
                0,
            ).unwrap();

            println!("number of constraints: {}", cs.num_constraints());

            assert!(!cs.is_satisfied());
        }
    }
}
