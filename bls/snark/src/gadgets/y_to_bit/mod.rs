use algebra::{
    Field, PrimeField,
    curves::{
        edwards_sw6::{
            EdwardsProjective,
        },
        models::{
            bls12::Bls12Parameters,
        }
    },
    fields::{
        sw6::Fr as SW6Fr
    },
};
use r1cs_core::{SynthesisError};
use r1cs_std::{
    Assignment,
    fields::{
        fp::FpGadget,
        FieldGadget,
    },
    groups::{
        curves::{
            short_weierstrass::bls12::{
                G1Gadget,
                G2Gadget,
            },
            twisted_edwards::edwards_sw6::{
                EdwardsSWGadget,
            }
        },
    },
    alloc::AllocGadget,
    boolean::Boolean,
    bits::{
        ToBitsGadget,
    },
};
use dpc::{
    gadgets::{
        crh::pedersen::{PedersenCRHGadget},
    }
};
use std::{
    ops::Neg,
    marker::PhantomData
};

type CRHGadget = PedersenCRHGadget<EdwardsProjective, SW6Fr, EdwardsSWGadget>;

pub struct YToBitGadget<
    P: Bls12Parameters,
> {
    parameters_type: PhantomData<P>,
}

impl<
        P: Bls12Parameters,
    > YToBitGadget<P>
{

    pub fn y_to_bit_g1<CS: r1cs_core::ConstraintSystem<P::Fp>>(
        mut cs: CS,
        pk: &G1Gadget<P>,
    ) -> Result<Boolean, SynthesisError> {
        let half_plus_one_neg = (P::Fp::from_repr(P::Fp::modulus_minus_one_div_two()) + &P::Fp::one()).neg();
        let y_bit = Boolean::alloc(
            cs.ns(|| "alloc y bit"),
            || {
                if pk.y.get_value().is_some() {
                    let half = P::Fp::modulus_minus_one_div_two();
                    Ok(pk.y.get_value().get()?.into_repr() > half)
                } else {
                    Err(SynthesisError::AssignmentMissing)
                }
            },
        )?;
        let y_adjusted = FpGadget::alloc(
            cs.ns(|| "alloc y"),
            || {
                if pk.y.get_value().is_some() {
                    let half = P::Fp::modulus_minus_one_div_two();
                    let y_value = pk.y.get_value().get()?;
                    if y_value.into_repr() > half {
                        Ok(y_value - &(P::Fp::from_repr(half) + &P::Fp::one()))
                    } else {
                        Ok(y_value)
                    }

                } else {
                    Err(SynthesisError::AssignmentMissing)
                }
            }
        )?;
        let y_bit_lc = y_bit.lc(CS::one(), half_plus_one_neg);
        cs.enforce(
            || "check y bit",
            |lc| lc + (P::Fp::one(), CS::one()),
            |lc| pk.y.get_variable() + y_bit_lc + lc,
            |lc| y_adjusted.get_variable() + lc,
        );
        let y_adjusted_bits = &y_adjusted.to_bits(
            cs.ns(|| "y adjusted to bits"),
        )?;
        Boolean::enforce_smaller_or_equal_than::<_, _, P::Fp, _>(
            cs.ns(|| "enforce smaller than modulus minus one div two"),
            y_adjusted_bits,
            P::Fp::modulus_minus_one_div_two(),
        )?;
        Ok(y_bit)
    }

    pub fn y_to_bit_g2<CS: r1cs_core::ConstraintSystem<P::Fp>>(
        mut cs: CS,
        pk: &G2Gadget<P>,
    ) -> Result<Boolean, SynthesisError> {
        let half_plus_one_neg = (P::Fp::from_repr(P::Fp::modulus_minus_one_div_two()) + &P::Fp::one()).neg();
        let y_c1_bit = Boolean::alloc(
            cs.ns(|| "alloc y c1 bit"),
            || {
                if pk.y.c1.get_value().is_some() {
                    let half = P::Fp::modulus_minus_one_div_two();
                    Ok(pk.y.c1.get_value().get()?.into_repr() > half)
                } else {
                    Err(SynthesisError::AssignmentMissing)
                }
            },
        )?;
        let y_c0_bit = Boolean::alloc(
            cs.ns(|| "alloc y c0 bit"),
            || {
                if pk.y.c0.get_value().is_some() {
                    let half = P::Fp::modulus_minus_one_div_two();
                    Ok(pk.y.c0.get_value().get()?.into_repr() > half)
                } else {
                    Err(SynthesisError::AssignmentMissing)
                }
            },
        )?;
        let y_eq_bit = Boolean::alloc(
            cs.ns(|| "alloc y eq bit"),
            || {
                if pk.y.c0.get_value().is_some() {
                    let half = P::Fp::modulus_minus_one_div_two();
                    Ok(pk.y.c0.get_value().get()?.into_repr() == half)
                } else {
                    Err(SynthesisError::AssignmentMissing)
                }
            },
        )?;
        let y_bit = Boolean::alloc(
            cs.ns(|| "alloc y bit"),
            || {
                if pk.y.c1.get_value().is_some() {
                    let half = P::Fp::modulus_minus_one_div_two();
                    if pk.y.c1.get_value().get()?.into_repr() > half {
                        Ok(true)
                    } else if pk.y.c1.get_value().get()?.into_repr() == half && pk.y.c0.get_value().get()?.into_repr() > half {
                        Ok(true)
                    } else {
                        Ok(false)
                    }
                } else {
                    Err(SynthesisError::AssignmentMissing)
                }
            },
        )?;
        let y_c1_adjusted = FpGadget::alloc(
            cs.ns(|| "alloc y c1"),
            || {
                if pk.y.get_value().is_some() {
                    let half = P::Fp::modulus_minus_one_div_two();
                    let y_value = pk.y.c1.get_value().get()?;
                    if y_value.into_repr() > half {
                        Ok(y_value - &(P::Fp::from_repr(half) + &P::Fp::one()))
                    } else {
                        Ok(y_value)
                    }

                } else {
                    Err(SynthesisError::AssignmentMissing)
                }
            }
        )?;
        let y_c0_adjusted = FpGadget::alloc(
            cs.ns(|| "alloc y c0"),
            || {
                if pk.y.get_value().is_some() {
                    let half = P::Fp::modulus_minus_one_div_two();
                    let y_value = pk.y.c0.get_value().get()?;
                    if y_value.into_repr() > half {
                        Ok(y_value - &(P::Fp::from_repr(half) + &P::Fp::one()))
                    } else {
                        Ok(y_value)
                    }

                } else {
                    Err(SynthesisError::AssignmentMissing)
                }
            }
        )?;
        let y_c1_bit_lc = y_c1_bit.lc(CS::one(), half_plus_one_neg);
        cs.enforce(
            || "check y bit c1",
            |lc| lc + (P::Fp::one(), CS::one()),
            |lc| pk.y.c1.get_variable() + y_c1_bit_lc + lc,
            |lc| y_c1_adjusted.get_variable() + lc,
        );
        let y_c1_adjusted_bits = &y_c1_adjusted.to_bits(
            cs.ns(|| "y c1 adjusted to bits"),
        )?;
        Boolean::enforce_smaller_or_equal_than::<_, _, P::Fp, _>(
            cs.ns(|| "enforce y c1 smaller than modulus minus one div two"),
            y_c1_adjusted_bits,
            P::Fp::modulus_minus_one_div_two(),
        )?;
        let y_c0_bit_lc = y_c0_bit.lc(CS::one(), half_plus_one_neg);
        cs.enforce(
            || "check y bit c0",
            |lc| lc + (P::Fp::one(), CS::one()),
            |lc| pk.y.c0.get_variable() + y_c0_bit_lc + lc,
            |lc| y_c0_adjusted.get_variable() + lc,
        );
        let y_c0_adjusted_bits = &y_c0_adjusted.to_bits(
            cs.ns(|| "y c0 adjusted to bits"),
        )?;
        Boolean::enforce_smaller_or_equal_than::<_, _, P::Fp, _>(
            cs.ns(|| "enforce y c0 smaller than modulus minus one div two"),
            y_c0_adjusted_bits,
            P::Fp::modulus_minus_one_div_two(),
        )?;

        // (1-a)*(b*c) == o - a
        // a is c1
        // b is y_eq
        // c is c0

        let bc = Boolean::and(
            cs.ns(|| "and bc"),
            &y_eq_bit,
            &y_c0_bit,
        )?;

        cs.enforce(
            || "enforce y bit derived correctly",
            |lc| lc + (P::Fp::one(), CS::one()) + y_c1_bit.lc(CS::one(), P::Fp::one().neg()),
            |_| bc.lc(CS::one(), P::Fp::one()),
            |lc| lc + y_bit.lc(CS::one(), P::Fp::one()) + y_c1_bit.lc(CS::one(), P::Fp::one().neg()),
        );

        Ok(y_bit)
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
                G2Projective as Bls12_377G2Projective,
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
            curves::short_weierstrass::bls12::{G1Gadget, G2Gadget},
        },
        fields::FieldGadget,
        test_constraint_system::TestConstraintSystem,
        alloc::AllocGadget,
        boolean::Boolean,
    };

    use super::YToBitGadget;

    #[test]
    fn test_y_to_bit_g1() {
        let rng = &mut XorShiftRng::from_seed([0x5d, 0xbe, 0x62, 0x59, 0x8d, 0x31, 0x3d, 0x76, 0x32, 0x37, 0xdb, 0x17, 0xe5, 0xbc, 0x06, 0x54]);
        for i in 0..10 {
            let secret_key = Bls12_377Fr::rand(rng);

            let generator = Bls12_377G1Projective::prime_subgroup_generator();
            let pub_key = generator.clone() * &secret_key;

            let half = <Bls12_377Parameters as Bls12Parameters>::Fp::modulus_minus_one_div_two();

            {
                let mut cs = TestConstraintSystem::<SW6Fr>::new();

                let pk = G1Gadget::<Bls12_377Parameters>::alloc(
                    &mut cs.ns(|| "alloc"),
                    || Ok(pub_key),
                ).unwrap();

                let y_bit = YToBitGadget::<Bls12_377Parameters>::y_to_bit_g1(
                    cs.ns(|| "y to bit"),
                    &pk,
                ).unwrap();

                assert_eq!(pk.y.get_value().get().unwrap().into_repr() > half, y_bit.get_value().get().unwrap());

                if i == 0 {
                    println!("number of constraints: {}", cs.num_constraints());
                }

                assert!(cs.is_satisfied());
            }
        }
    }

    #[test]
    fn test_y_to_bit_g2() {
        let rng = &mut XorShiftRng::from_seed([0x5d, 0xbe, 0x62, 0x59, 0x8d, 0x31, 0x3d, 0x76, 0x32, 0x37, 0xdb, 0x17, 0xe5, 0xbc, 0x06, 0x54]);
        for i in 0..10 {
            let secret_key = Bls12_377Fr::rand(rng);

            let generator = Bls12_377G2Projective::prime_subgroup_generator();
            let pub_key = generator.clone() * &secret_key;

            let half = <Bls12_377Parameters as Bls12Parameters>::Fp::modulus_minus_one_div_two();

            {
                let mut cs = TestConstraintSystem::<SW6Fr>::new();

                let pk = G2Gadget::<Bls12_377Parameters>::alloc(
                    &mut cs.ns(|| "alloc"),
                    || Ok(pub_key),
                ).unwrap();

                let y_bit = YToBitGadget::<Bls12_377Parameters>::y_to_bit_g2(
                    cs.ns(|| "y to bit"),
                    &pk,
                ).unwrap();

                if pk.y.c1.get_value().get().unwrap().into_repr() > half || (pk.y.c1.get_value().get().unwrap().into_repr() == half && pk.y.c0.get_value().get().unwrap().into_repr() > half) {
                    assert_eq!(true, y_bit.get_value().get().unwrap());
                } else {
                    assert_eq!(false, y_bit.get_value().get().unwrap());
                }

                if i == 0 {
                    println!("number of constraints: {}", cs.num_constraints());
                }

                if !cs.is_satisfied() {
                    println!("{}", cs.which_is_unsatisfied().unwrap());
                }
                assert!(cs.is_satisfied());
            }
        }
    }
}
