#![allow(clippy::op_ref)] // clippy throws a false positive around field ops
use algebra::{
    bls12_377::Parameters as Bls12_377_Parameters,
    curves::bls12::Bls12Parameters, 
    PrimeField, Zero
};
use r1cs_core::{SynthesisError, Variable, lc, ConstraintSystemRef, LinearCombination};
use r1cs_std::{
    R1CSVar,
    alloc::AllocVar,
    boolean::Boolean,
    fields::{fp::FpVar},
    groups::curves::short_weierstrass::bls12::{G1Var, G2Var},
    Assignment,
};

/// The goal of the gadget is to provide the bit according to the value of y,
/// as done in point compression. The idea is that given $half = \frac{p-1}{2}$,
/// we can normalize any elements greater than $half$ (i.e. in the range
/// [half+1, p-1]), by subtracting half (resulting in a number in the [1, half]
/// range). Then we check that the cast element is <= half, which enforces that
/// originally they were > half. For points in G2, we also check the
/// lexicographical ordering.
pub trait YToBitGadget<P: Bls12Parameters> {
    fn y_to_bit(&self) -> Result<Boolean<P::Fp>, SynthesisError>;
}

pub trait FpUtils<F: PrimeField> {
    fn is_eq_zero(
        &self,
    ) -> Result<Boolean<F>, SynthesisError>; 
    fn normalize(
        &self,
    ) -> Result<Boolean<F>, SynthesisError>;
}

impl YToBitGadget<Bls12_377_Parameters> for G1Var<Bls12_377_Parameters> 
{
    fn y_to_bit(
        &self,
    ) -> Result<Boolean<<Bls12_377_Parameters as Bls12Parameters>::Fp>, SynthesisError> {
        let y_bit = self.y.normalize()?;
        Ok(y_bit)
    }
}

impl YToBitGadget<Bls12_377_Parameters> for G2Var<Bls12_377_Parameters> {
    fn y_to_bit(
        &self,
    ) -> Result<Boolean<<Bls12_377_Parameters as Bls12Parameters>::Fp>, SynthesisError> {
        // Apply the point compression logic for getting the y bit's value.
        let y_bit = Boolean::new_witness(self.cs().unwrap_or(ConstraintSystemRef::None), || {
            let half = <Bls12_377_Parameters as Bls12Parameters>::Fp::from_repr(<Bls12_377_Parameters as Bls12Parameters>::Fp::modulus_minus_one_div_two()).get()?;
            let c1 = self.y.c1.value()?;
            let c0 = self.y.c0.value()?;

            let bit = c1 > half || (c1 == <Bls12_377_Parameters as Bls12Parameters>::Fp::zero() && c0 > half);
            Ok(bit)
        })?;

        // Get the y_c1 and y_c0 bits
        let y_c0_bit = self.y.c0.normalize()?;
        let y_c1_bit = self.y.c1.normalize()?;

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
        let y_eq_bit = self.y.c1.is_eq_zero()?;
        let bc = Boolean::and(&y_eq_bit, &y_c0_bit)?;

        self.cs().unwrap_or(ConstraintSystemRef::None).enforce_constraint(
            LinearCombination::from(Variable::One) - y_c1_bit.lc(),
            bc.lc(),
            y_bit.lc() - y_c1_bit.lc(),
        )?;

        Ok(y_bit)
    }
}

impl<F: PrimeField> FpUtils<F> for FpVar<F> {
    fn is_eq_zero(
        &self,
    ) -> Result<Boolean<F>, SynthesisError> {
        let bit = Boolean::new_witness(self.cs().unwrap_or(ConstraintSystemRef::None),
            || { Ok(self.value()? == F::zero())
        })?;

        match self {
            Self::Constant(_) => Ok(bit),
            Self::Var(self_val) => {
                // This enforces bit = 1 <=> el == 0.
                // The idea is that if el is 0, then a constraint of the form `el * el_inv == 1 - result`
                // forces result to be 1. If el is non-zero, then a constraint of the form
                // `el*result == 0` forces result to be 0. inv is set to be 0 in case el is 0 because
                // the value of el_inv is not significant in that case (el is 0 anyway) and we need the
                // witness calculation to pass.
                let inv = FpVar::new_witness(self.cs().unwrap_or(ConstraintSystemRef::None), 
                    || { Ok(self.value()?.inverse().unwrap_or(F::zero()))
                })?;

                // (el * inv == 1 - bit)
                self.cs().unwrap_or(ConstraintSystemRef::None).enforce_constraint(
                    LinearCombination::from(self_val.variable) + lc!(),
                    match inv { 
                        Self::Constant(_) => unreachable!(),
                        Self::Var(v) => LinearCombination::from(v.variable) + lc!(),
                    },
                    LinearCombination::from(Variable::One) - bit.lc(),
                )?;

                // (lhs * bit == 0)
                self.cs().unwrap_or(ConstraintSystemRef::None).enforce_constraint(
                    LinearCombination::from(self_val.variable),
                    bit.lc(),
                    lc!(),
                )?;

                Ok(bit)
            }
        }
    }

    // Returns 1 if el > half, else 0.
    fn normalize(
        &self,
    ) -> Result<Boolean<F>, SynthesisError> {
        let half = F::from_repr(F::modulus_minus_one_div_two()).get()?;

        let bit = Boolean::new_witness(self.cs().unwrap_or(ConstraintSystemRef::None), 
            || Ok(self.value()? > half))?;

        match self {
            Self::Constant(_) => Ok(bit),
            Self::Var(self_val) => {
                let adjusted = FpVar::new_witness(
                    self.cs().unwrap_or(ConstraintSystemRef::None),
                    || {
                    let el = self.value()?;

                    let adjusted = if el > half { el - &half } else { el };

                    Ok(adjusted)
                })?;

                let adjusted_var = match adjusted {
                    Self::Var(ref v) => v.variable,
                    _ => unreachable!(),
                };

                self.cs().unwrap_or(ConstraintSystemRef::None).enforce_constraint(
                    lc!() +  LinearCombination::from(Variable::One),
                    LinearCombination::from(self_val.variable) + (bit.lc() * half.neg()),
                    LinearCombination::from(adjusted_var)
                )?;

                // Enforce `adjusted <= half`
                FpVar::enforce_smaller_or_equal_than_mod_minus_one_div_two(
                    &adjusted,
                )?;

                Ok(bit)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use r1cs_std::groups::CurveVar;
    use r1cs_std::alloc::AllocationMode;
    use algebra::{
        bls12_377::{G1Projective, G2Affine, G2Projective, Parameters},
        bw6_761::Fr as BW6_761Fr,
        curves::bls12::Bls12Parameters,
        fields::Fp2,
        AffineCurve, BigInteger, PrimeField, UniformRand, Zero,
    };
    use r1cs_core::ConstraintSystem;
    use r1cs_std::{
        alloc::AllocVar,
        groups::curves::short_weierstrass::bls12::{G1Var, G2Var},
    };

    type Fp = <Parameters as Bls12Parameters>::Fp;

    #[test]
    fn test_y_to_bit_g1() {
        let half = Fp::from_repr(Fp::modulus_minus_one_div_two()).unwrap();
        let rng = &mut rand::thread_rng();

        for _ in 0..10 {
            let element = G1Projective::rand(rng);

            let cs = ConstraintSystem::<BW6_761Fr>::new_ref();

            let allocated =
                G1Var::<Parameters>::new_variable_omit_prime_order_check(cs.clone(), || Ok(element), AllocationMode::Witness).unwrap();

            let y_bit = allocated.y_to_bit().unwrap();

            assert_eq!(
                allocated.y.value().unwrap() > half,
                y_bit.value().unwrap()
            );

//            assert_eq!(cs.num_constraints(), 1621);
            if !cs.is_satisfied().unwrap() {
                println!("{:?}", cs.which_is_unsatisfied().unwrap());
            }
            assert!(cs.is_satisfied().unwrap());
        }
    }

    #[test]
    fn test_y_to_bit_g2() {
        let half = Fp::from_repr(Fp::modulus_minus_one_div_two()).unwrap();
        let zero = <Parameters as Bls12Parameters>::Fp::zero();
        let rng = &mut rand::thread_rng();

        // Check random points.
        for _ in 0..10 {
            let element = G2Projective::rand(rng);

            let cs = ConstraintSystem::<BW6_761Fr>::new_ref();

            let allocated =
                G2Var::<Parameters>::new_witness(cs.clone(), || Ok(element)).unwrap();

            let y_bit = allocated.y_to_bit().unwrap();

            let c1 = allocated.y.c1.value().unwrap();
            let c0 = allocated.y.c0.value().unwrap();

            if c1 > half || (c1 == zero && c0 > half) {
                assert_eq!(true, y_bit.value().unwrap());
            } else {
                assert_eq!(false, y_bit.value().unwrap());
            }

  //          assert_eq!(cs.num_constraints(), 3248);
            if !cs.is_satisfied().unwrap() {
                println!("{:?}", cs.which_is_unsatisfied().unwrap());
            }
            assert!(cs.is_satisfied().unwrap());
        }
    }

    fn test_y_to_bit_g2_edge(edge: <<Parameters as Bls12Parameters>::Fp as PrimeField>::BigInt) {
        let half = Fp::from_repr(Fp::modulus_minus_one_div_two()).unwrap();
        let zero = <Parameters as Bls12Parameters>::Fp::zero();
        let rng = &mut rand::thread_rng();

        for _ in 0..10 {
            let element = G2Projective::rand(rng);
            // we edit the key with a specific vaue for y.c1
            let new_y =
                Fp2::<<Parameters as Bls12Parameters>::Fp2Params>::new(element.y.c0, edge.into());
            let element = G2Affine::new(element.x, new_y, false).into_projective();

            let cs = ConstraintSystem::<BW6_761Fr>::new_ref();

            let allocated =
                G2Var::<Parameters>::new_witness(cs.clone(), || Ok(element)).unwrap();

            let y_bit = allocated.y_to_bit().unwrap();

            let c1 = allocated.y.c1.value().unwrap();
            let c0 = allocated.y.c0.value().unwrap();

            if c1 > half || (c1 == zero && c0 > half) {
                assert_eq!(true, y_bit.value().unwrap());
            } else {
                assert_eq!(false, y_bit.value().unwrap());
            }

    //        assert_eq!(cs.num_constraints(), 3248);
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

    // Check points at the edge - c1 == half.
    #[test]
    fn test_y_to_bit_g2_c1_is_half() {
        let half = <<Parameters as Bls12Parameters>::Fp as PrimeField>::modulus_minus_one_div_two();
        test_y_to_bit_g2_edge(half);
    }

    // Check points at the edge - c1 == 0.
    #[test]
    fn test_y_to_bit_g2_c1_is_zero() {
        let zero = <Parameters as Bls12Parameters>::Fp::zero();
        test_y_to_bit_g2_edge(zero.into_repr());
    }

    // Check points at the edge - c1 == p-1.
    #[test]
    fn test_y_to_bit_g2_c1_is_p_minus_1() {
        let half = <<Parameters as Bls12Parameters>::Fp as PrimeField>::modulus_minus_one_div_two();
        let mut p_minus_one = half;
        p_minus_one.mul2();
        test_y_to_bit_g2_edge(p_minus_one);
    }

    // Check points at the edge - c1 == half + 1.
    #[test]
    fn test_y_to_bit_g2_c1_is_half_plus_one() {
        let mut half_plus_one =
            <<Parameters as Bls12Parameters>::Fp as PrimeField>::modulus_minus_one_div_two();
        let one = <<Parameters as Bls12Parameters>::Fp as PrimeField>::BigInt::from(1);
        half_plus_one.add_nocarry(&one);
        test_y_to_bit_g2_edge(half_plus_one);
    }
}
