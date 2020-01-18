use algebra::{
    Field, PrimeField,
    curves::{
        models::{
            bls12::Bls12Parameters,
        }
    },
};
use r1cs_core::{SynthesisError, LinearCombination};
use r1cs_std::{
    Assignment,
    fields::{
        fp::FpGadget,
    },
    groups::{
        curves::{
            short_weierstrass::bls12::{
                G2Gadget,
            },
        },
    },
    alloc::AllocGadget,
    boolean::Boolean,
    bits::{
        ToBitsGadget,
    },
    select::CondSelectGadget,
};
use std::{
    marker::PhantomData
};

use crate::gadgets::y_to_bit::YToBitGadget;

pub struct ValidatorUpdateGadget<
    P: Bls12Parameters,
> {
    parameters_type: PhantomData<P>,
}

impl<
        P: Bls12Parameters,
    > ValidatorUpdateGadget<P>
{
    // this will be much better when we can bound removed_validators_bitmap
    pub fn update<CS: r1cs_core::ConstraintSystem<P::Fp>>(
        mut cs: CS,
        old_pub_keys: Vec<G2Gadget<P>>,
        new_pub_keys: Vec<G2Gadget<P>>,
        removed_validators_bitmap: Vec<Boolean>,
        maximum_removed_validators: u64,
    ) -> Result<Vec<G2Gadget<P>>, SynthesisError> {
        assert_eq!(old_pub_keys.len(), removed_validators_bitmap.len());

        let mut num_removed_validators_num = Some(0);
        let mut num_removed_validators_lc = LinearCombination::zero();

        let mut new_validator_set = vec![];
        for (i, pk) in old_pub_keys.iter().enumerate() {
            let new_pub_key = G2Gadget::<P>::conditionally_select(
                cs.ns(|| format!("cond_select {}", i)),
                &removed_validators_bitmap[i],
                &new_pub_keys[i],
                pk,
            )?;
            new_validator_set.push(new_pub_key);

            num_removed_validators_lc = num_removed_validators_lc + &removed_validators_bitmap[i].lc(CS::one(), P::Fp::one());
            if removed_validators_bitmap[i].get_value().is_none() {
                num_removed_validators_num = None;
            }

            if num_removed_validators_num.is_some() {
                num_removed_validators_num = Some(num_removed_validators_num.get()? + if removed_validators_bitmap[i].get_value().get()? { 0 } else { 1 });
            }
        }

        let num_removed_validators = FpGadget::alloc(
            &mut cs.ns(|| "num removed validators"),
            || Ok(P::Fp::from_repr(num_removed_validators_num.get()?.into()))
        )?;

        let num_removed_validators_bits = &num_removed_validators.to_bits(
            &mut cs.ns(|| "num removed validators to bits"),
        )?;
        Boolean::enforce_smaller_or_equal_than::<_, _, P::Fp, _>(
            &mut cs.ns(|| "enforce maximum removed validators"),
            num_removed_validators_bits,
            P::Fp::from_repr(maximum_removed_validators.into()).into_repr(),
        )?;

        Ok(new_validator_set)
    }

    pub fn to_bits<CS: r1cs_core::ConstraintSystem<P::Fp>>(
        mut cs: CS,
        validator_set: Vec<G2Gadget<P>>,
    ) -> Result<Vec<Boolean>, SynthesisError> {
        let mut bits = vec![];
        for (i, pk) in validator_set.iter().enumerate() {
            let x_c0_bits = pk.x.c0.to_bits(cs.ns(|| format!("unpack x c0 {}", i)))?;
            bits.extend_from_slice(&x_c0_bits);
            let x_c1_bits = pk.x.c1.to_bits(cs.ns(|| format!("unpack x c1 {}", i)))?;
            bits.extend_from_slice(&x_c1_bits);
            let y_bit = YToBitGadget::<P>::y_to_bit_g2(
                cs.ns(|| format!("y to bit {}", i)),
                pk,
            )?;
            bits.push(y_bit);
        }
        Ok(bits)
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
                Bls12_377Parameters,
            },
            models::bls12::Bls12Parameters,
            ProjectiveCurve,
        },
        fields::{
            bls12_377::Fr as Bls12_377Fr,
            sw6::Fr as SW6Fr,
            PrimeField,
        },
        UniformRand,
    };
    use r1cs_core::ConstraintSystem;
    use r1cs_std::{
        Assignment,
        groups::{
            curves::short_weierstrass::bls12::G1Gadget,
        },
        fields::FieldGadget,
        test_constraint_system::TestConstraintSystem,
        alloc::AllocGadget,
        boolean::Boolean,
    };

    use super::ValidatorUpdateGadget;

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

            ValidatorUpdateGadget::<Bls12_377Parameters>::update(
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

            ValidatorUpdateGadget::<Bls12_377Parameters>::update(
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

            ValidatorUpdateGadget::<Bls12_377Parameters>::update(
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

    #[test]
    fn test_to_bits() {
        let rng = &mut XorShiftRng::from_seed([0x5d, 0xbe, 0x62, 0x59, 0x8d, 0x31, 0x3d, 0x76, 0x32, 0x37, 0xdb, 0x17, 0xe5, 0xbc, 0x06, 0x54]);
        for i in 0..10 {
            let secret_key = Bls12_377Fr::rand(rng);
            let secret_key2 = Bls12_377Fr::rand(rng);
            let secret_key3 = Bls12_377Fr::rand(rng);

            let generator = Bls12_377G1Projective::prime_subgroup_generator();
            let pub_key = generator.clone() * &secret_key;
            let pub_key2 = generator.clone() * &secret_key2;
            let pub_key3 = generator.clone() * &secret_key3;

            let half = <Bls12_377Parameters as Bls12Parameters>::Fp::modulus_minus_one_div_two();

            {
                let mut cs = TestConstraintSystem::<SW6Fr>::new();

                let validator_set = vec![pub_key.clone(), pub_key2.clone(), pub_key3.clone()]
                    .iter().enumerate()
                    .map(|(i, g)| G1Gadget::<Bls12_377Parameters>::alloc(
                        &mut cs.ns(|| format!("alloc pk {}", i)),
                        || Ok(g),
                    ).unwrap()
                    ).collect::<Vec<G1Gadget<Bls12_377Parameters>>>();

                let bits = ValidatorUpdateGadget::<Bls12_377Parameters>::to_bits(
                    cs.ns(|| "validator update"),
                    validator_set.clone(),
                ).unwrap();

                for i in 0..validator_set.len() {
                    assert_eq!(validator_set[i].y.get_value().get().unwrap().into_repr() > half, bits[377 + 378 * i].get_value().get().unwrap());
                }

                if i == 0 {
                    println!("number of constraints: {}", cs.num_constraints());
                }

                assert!(cs.is_satisfied());
            }
        }
    }
}
