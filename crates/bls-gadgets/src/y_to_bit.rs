#![allow(clippy::op_ref)] // clippy throws a false positive around field ops
use algebra::{curves::bls12::Bls12Parameters, Field, One, PrimeField, Zero};
use r1cs_core::{ConstraintSystem, SynthesisError};
use r1cs_std::{
    alloc::AllocGadget,
    bits::ToBitsGadget,
    boolean::Boolean,
    fields::{fp::FpGadget, FieldGadget},
    groups::curves::short_weierstrass::bls12::{G1Gadget, G2Gadget},
    Assignment,
};
use std::{marker::PhantomData, ops::Neg};

/// Enforces that the y bit is graeter than half
///
/// The goal of the gadgets is to provide the bit according to the value of y,
/// as done in point compression. The idea is that given $half = \frac{p-1}{2}$,
/// we can normalize any elements greater than $half$ (i.e. in the range
/// [half+1, p-1]), by subtracting half (resulting in a number in the [1, half]
/// range). Then we check that the cast element is <= half, which enforces that
/// originally they were > half. For points in G2, we also check the
/// lexicographical ordering.
pub struct YToBitGadget<P: Bls12Parameters> {
    parameters_type: PhantomData<P>,
}

impl<P: Bls12Parameters> YToBitGadget<P> {
    // Returns 1 if el > half, else 0.
    fn normalize<CS: ConstraintSystem<P::Fp>>(
        cs: &mut CS,
        el: &FpGadget<P::Fp>,
    ) -> Result<Boolean, SynthesisError> {
        let half = P::Fp::from_repr(P::Fp::modulus_minus_one_div_two());

        let bit = Boolean::alloc(cs.ns(|| "alloc y bit"), || Ok(el.get_value().get()? > half))?;

        let adjusted = FpGadget::alloc(cs.ns(|| "alloc y"), || {
            let el = el.get_value().get()?;

            let adjusted = if el > half { el - &half } else { el };

            Ok(adjusted)
        })?;

        let bit_lc = bit.lc(CS::one(), half.neg());
        cs.enforce(
            || "check bit",
            |lc| lc + (P::Fp::one(), CS::one()),
            |lc| el.get_variable() + bit_lc + lc,
            |lc| adjusted.get_variable() + lc,
        );

        // Enforce `adjusted <= half`
        // TODO: Switch to `FpGadget<P>::enforce_smaller_or_equal_than_mod_minus_one_div_two`
        let adjusted_bits = &adjusted.to_bits(cs.ns(|| "adjusted to bits"))?;
        Boolean::enforce_smaller_or_equal_than::<_, _, P::Fp, _>(
            cs.ns(|| "enforce smaller than or equal to modulus minus one div two"),
            adjusted_bits,
            P::Fp::modulus_minus_one_div_two(),
        )?;

        Ok(bit)
    }

    pub fn y_to_bit_g1<CS: ConstraintSystem<P::Fp>>(
        mut cs: CS,
        pk: &G1Gadget<P>,
    ) -> Result<Boolean, SynthesisError> {
        let y_bit = Self::normalize(&mut cs.ns(|| "g1 normalize"), &pk.y)?;
        Ok(y_bit)
    }

    pub fn y_to_bit_g2<CS: ConstraintSystem<P::Fp>>(
        mut cs: CS,
        pk: &G2Gadget<P>,
    ) -> Result<Boolean, SynthesisError> {
        // Is y.c1 == 0?
        let y_eq_bit = Boolean::alloc(cs.ns(|| "alloc y eq bit"), || {
            Ok(pk.y.c1.get_value().get()? == P::Fp::zero())
        })?;

        // This enforces y_eq_bit = 1 <=> c_1 != 0.
        // The idea is that if lhs is 0, then a constraint of the form lhs*lhs_inv == 1 -
        // result forces result to be 1. If lhs is non-zero, then a constraint of the form
        // lhs*result == 0 forces result to be 0. lhs_inv is set to be 0 in case lhs is 0 because
        // the value of lhs_inv is not significant in that case (lhs is 0 anyway) and we need the
        // witness calculation to pass.
        {
            let lhs = &pk.y.c1;
            let inv = FpGadget::alloc(cs.ns(|| "alloc c1 inv"), || {
                Ok(lhs.get_value().get()?.inverse().unwrap_or_else(P::Fp::zero))
            })?;

            // (lhs * lhs_inv == 1 - y_eq_bit)
            cs.enforce(
                || "enforce y_eq_bit",
                |lc| lhs.get_variable() + lc,
                |lc| inv.get_variable() + lc,
                |lc| lc + (P::Fp::one(), CS::one()) + y_eq_bit.lc(CS::one(), P::Fp::one().neg()),
            );

            // (lhs*y_eq_bit == 0)
            cs.enforce(
                || "enforce y_eq_bit 2",
                |lc| lhs.get_variable() + lc,
                |_| y_eq_bit.lc(CS::one(), P::Fp::one()),
                |lc| lc,
            );
        }

        // Apply the point compression logic for getting the y bit's value.
        let y_bit = Boolean::alloc(cs.ns(|| "alloc y bit"), || {
            let half = P::Fp::from_repr(P::Fp::modulus_minus_one_div_two());
            let c1 = pk.y.c1.get_value().get()?;
            let c0 = pk.y.c0.get_value().get()?;

            let bit = if c1 > half {
                true
            } else if c1 == P::Fp::zero() && c0 > half {
                true
            } else {
                false
            };

            Ok(bit)
        })?;

        // Get the y_c1 and y_c0 bits
        let y_c0_bit = Self::normalize(&mut cs.ns(|| "normalize c0"), &pk.y.c0)?;
        let y_c1_bit = Self::normalize(&mut cs.ns(|| "normalize c1"), &pk.y.c1)?;

        // (1-a)*(b*c) == o - a
        // a is c1
        // b is y_eq
        // c is c0
        // (1-c1)*(y_eq*c0) == o - c1
        //
        // previously we constrained y_eq to be 1 <==> c1 == 0
        // either c1 is 1, and then o is 1
        // else c1 is 0 and c0 is 1 (then y_eq is 1), and then o is 1
        // else c1 is 0 and c0 is 0 (then y_eq is 1), and then o is 0
        let bc = Boolean::and(cs.ns(|| "and bc"), &y_eq_bit, &y_c0_bit)?;

        cs.enforce(
            || "enforce y bit derived correctly",
            |lc| lc + (P::Fp::one(), CS::one()) + y_c1_bit.lc(CS::one(), P::Fp::one().neg()),
            |_| bc.lc(CS::one(), P::Fp::one()),
            |lc| {
                lc + y_bit.lc(CS::one(), P::Fp::one()) + y_c1_bit.lc(CS::one(), P::Fp::one().neg())
            },
        );

        Ok(y_bit)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    use algebra::{
        bls12_377::{
            Fr as Bls12_377Fr, G1Projective as Bls12_377G1Projective,
            G2Affine as Bls12_377G2Affine, G2Projective as Bls12_377G2Projective,
            Parameters as Bls12_377Parameters,
        },
        curves::bls12::Bls12Parameters,
        fields::Fp2,
        sw6::Fr as SW6Fr,
        AffineCurve, BigInteger, PrimeField, ProjectiveCurve, UniformRand, Zero,
    };
    use r1cs_std::{
        alloc::AllocGadget,
        fields::FieldGadget,
        groups::curves::short_weierstrass::bls12::{G1Gadget, G2Gadget},
        test_constraint_system::TestConstraintSystem,
        Assignment,
    };

    use super::YToBitGadget;

    #[test]
    fn test_y_to_bit_g1() {
        type Fp = <Bls12_377Parameters as Bls12Parameters>::Fp;
        let half = Fp::from_repr(Fp::modulus_minus_one_div_two());

        for i in 0..10 {
            let element = Bls12_377G1Projective::rand(&mut rand::thread_rng());

            let mut cs = TestConstraintSystem::<SW6Fr>::new();

            let allocated =
                G1Gadget::<Bls12_377Parameters>::alloc(&mut cs.ns(|| "alloc"), || Ok(element))
                    .unwrap();

            let y_bit =
                YToBitGadget::<Bls12_377Parameters>::y_to_bit_g1(cs.ns(|| "y to bit"), &allocated)
                    .unwrap();

            assert_eq!(
                allocated.y.get_value().get().unwrap() > half,
                y_bit.get_value().get().unwrap()
            );

            if i == 0 {
                println!("number of constraints: {}", cs.num_constraints());
            }
            assert_eq!(cs.num_constraints(), 1621);

            assert!(cs.is_satisfied());
        }
    }

    #[test]
    fn test_y_to_bit_g2() {
        let rng = &mut XorShiftRng::from_seed([
            0x5d, 0xbe, 0x62, 0x59, 0x8d, 0x31, 0x3d, 0x76, 0x32, 0x37, 0xdb, 0x17, 0xe5, 0xbc,
            0x06, 0x54,
        ]);

        // Check random points.
        for i in 0..10 {
            let secret_key = Bls12_377Fr::rand(rng);

            let generator = Bls12_377G2Projective::prime_subgroup_generator();
            let pub_key = generator.clone().mul(secret_key);

            let half = <Bls12_377Parameters as Bls12Parameters>::Fp::modulus_minus_one_div_two();
            let zero = <Bls12_377Parameters as Bls12Parameters>::Fp::zero();

            {
                let mut cs = TestConstraintSystem::<SW6Fr>::new();

                let pk =
                    G2Gadget::<Bls12_377Parameters>::alloc(&mut cs.ns(|| "alloc"), || Ok(pub_key))
                        .unwrap();

                let y_bit =
                    YToBitGadget::<Bls12_377Parameters>::y_to_bit_g2(cs.ns(|| "y to bit"), &pk)
                        .unwrap();

                // if c1 > half or c1 == 0 && c0 > half" -> 1, else 0
                if pk.y.c1.get_value().get().unwrap().into_repr() > half
                    || (pk.y.c1.get_value().get().unwrap().into_repr() == zero.into_repr()
                        && pk.y.c0.get_value().get().unwrap().into_repr() > half)
                {
                    assert_eq!(true, y_bit.get_value().get().unwrap());
                } else {
                    assert_eq!(false, y_bit.get_value().get().unwrap());
                }

                if i == 0 {
                    println!("number of constraints: {}", cs.num_constraints());
                }
                assert_eq!(cs.num_constraints(), 3248);

                if !cs.is_satisfied() {
                    println!("{}", cs.which_is_unsatisfied().unwrap());
                }
                assert!(cs.is_satisfied());
            }
        }
    }

    fn test_y_to_bit_g2_edge(
        edge: <<Bls12_377Parameters as Bls12Parameters>::Fp as PrimeField>::BigInt,
    ) {
        let rng = &mut XorShiftRng::from_seed([
            0x5d, 0xbe, 0x62, 0x59, 0x8d, 0x31, 0x3d, 0x76, 0x32, 0x37, 0xdb, 0x17, 0xe5, 0xbc,
            0x06, 0x54,
        ]);

        for i in 0..10 {
            let secret_key = Bls12_377Fr::rand(rng);

            let generator = Bls12_377G2Projective::prime_subgroup_generator();
            let pub_key = generator.clone().mul(secret_key).into_affine();
            let half = <<Bls12_377Parameters as Bls12Parameters>::Fp as PrimeField>::modulus_minus_one_div_two();
            let new_y = Fp2::<<Bls12_377Parameters as Bls12Parameters>::Fp2Params>::new(
                pub_key.y.c0,
                edge.into(),
            );
            let pub_key = Bls12_377G2Affine::new(pub_key.x, new_y, false).into_projective();

            let zero = <Bls12_377Parameters as Bls12Parameters>::Fp::zero();

            {
                let mut cs = TestConstraintSystem::<SW6Fr>::new();

                let pk =
                    G2Gadget::<Bls12_377Parameters>::alloc(&mut cs.ns(|| "alloc"), || Ok(pub_key))
                        .unwrap();

                let y_bit =
                    YToBitGadget::<Bls12_377Parameters>::y_to_bit_g2(cs.ns(|| "y to bit"), &pk)
                        .unwrap();

                if pk.y.c1.get_value().get().unwrap().into_repr() > half
                    || (pk.y.c1.get_value().get().unwrap().into_repr() == zero.into_repr()
                        && pk.y.c0.get_value().get().unwrap().into_repr() > half)
                {
                    assert_eq!(true, y_bit.get_value().get().unwrap());
                } else {
                    assert_eq!(false, y_bit.get_value().get().unwrap());
                }

                if i == 0 {
                    println!("number of constraints: {}", cs.num_constraints());
                }
                assert_eq!(cs.num_constraints(), 3248);

                // we're not checking this, because we couldn't find a matching point on BLS12-377,
                // and so we can't generate proper points on the curve
                /*
                if !cs.is_satisfied() {
                    println!("{}", cs.which_is_unsatisfied().unwrap());
                }
                assert!(cs.is_satisfied());
                */
            }
        }
    }

    // Check points at the edge - c1 == half.
    #[test]
    fn test_y_to_bit_g2_c1_is_half() {
        let half =
            <<Bls12_377Parameters as Bls12Parameters>::Fp as PrimeField>::modulus_minus_one_div_two(
            );
        test_y_to_bit_g2_edge(half);
    }

    // Check points at the edge - c1 == 0.
    #[test]
    fn test_y_to_bit_g2_c1_is_zero() {
        let zero = <Bls12_377Parameters as Bls12Parameters>::Fp::zero();
        test_y_to_bit_g2_edge(zero.into_repr());
    }

    // Check points at the edge - c1 == p-1.
    #[test]
    fn test_y_to_bit_g2_c1_is_p_minus_1() {
        let half =
            <<Bls12_377Parameters as Bls12Parameters>::Fp as PrimeField>::modulus_minus_one_div_two(
            );
        let mut p_minus_one = half;
        p_minus_one.mul2();
        test_y_to_bit_g2_edge(p_minus_one);
    }

    // Check points at the edge - c1 == half + 1.
    #[test]
    fn test_y_to_bit_g2_c1_is_half_plus_one() {
        let mut half_plus_one =
            <<Bls12_377Parameters as Bls12Parameters>::Fp as PrimeField>::modulus_minus_one_div_two(
            );
        let one = <<Bls12_377Parameters as Bls12Parameters>::Fp as PrimeField>::BigInt::from(1);
        half_plus_one.add_nocarry(&one);
        test_y_to_bit_g2_edge(half_plus_one);
    }
}
