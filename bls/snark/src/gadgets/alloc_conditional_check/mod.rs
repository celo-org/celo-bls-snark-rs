use r1cs_core::{ConstraintSystem, SynthesisError, LinearCombination};
use algebra::curves::models::bls12::Bls12Parameters; use std::marker::PhantomData; use std::borrow::Borrow;
use r1cs_std::groups::curves::short_weierstrass::AffineGadget;
use r1cs_std::fields::FieldGadget;
use algebra::fields::sw6::{Fr as SW6Fr};
use algebra::{curves::{
    short_weierstrass_jacobian::{GroupAffine as SWAffine, GroupProjective as SWProjective},
    bls12_377::g1::Bls12_377G1Parameters,
    SWModelParameters,
    ProjectiveCurve,
}, BitIterator, Field, PrimeField, Group};
use std::ops::Neg;
use r1cs_std::{
    eq::ConditionalEqGadget,
    Assignment,
    fields::fp::FpGadget,
    alloc::AllocGadget,
    bits::boolean::{Boolean, AllocatedBit},
    groups::curves::short_weierstrass::bls12::G1Gadget,
};
use algebra::curves::bls12_377::{Bls12_377Parameters, G1Projective};

pub struct AllocPointConditionalGadget<
    P: SWModelParameters,
    ConstraintF: Field,
    F: FieldGadget<P::BaseField, ConstraintF>,
> {
    parameters_type: PhantomData<P>,
    field_type: PhantomData<ConstraintF>,
    field_gadget_type: PhantomData<F>,
}

impl<
    P: SWModelParameters,
    ConstraintF: PrimeField,
    F: FieldGadget<P::BaseField, ConstraintF>,
> AllocPointConditionalGadget<P, ConstraintF, F> {
    pub fn alloc_conditional<FN, T, CS: ConstraintSystem<ConstraintF>>(
        mut cs: CS,
        condition: &Boolean,
        value_gen: FN,
    ) -> Result<AffineGadget<P, ConstraintF, F>, SynthesisError>
        where
            FN: FnOnce() -> Result<T, SynthesisError>,
            T: Borrow<SWProjective<P>>,
    {
        let (x, y) = match value_gen() {
            Ok(ge) => {
                let ge = ge.borrow().into_affine();
                (Ok(ge.x), Ok(ge.y))
            },
            _ => (
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
            ),
        };

        // Perform on-curve check.
        let b = P::COEFF_B;
        let a = P::COEFF_A;

        let x = F::alloc(&mut cs.ns(|| "x"), || x)?;
        let y = F::alloc(&mut cs.ns(|| "y"), || y)?;

        // Check that y^2 = x^3 + ax +b
        // We do this by checking that y^2 - b = x * (x^2 +a)
        let x2 = x.square(&mut cs.ns(|| "x^2"))?;
        let y2 = y.square(&mut cs.ns(|| "y^2"))?;

        let x2_plus_a = x2.add_constant(cs.ns(|| "x^2 + a"), &a)?;
        let y2_minus_b = y2.add_constant(cs.ns(|| "y^2 - b"), &b.neg())?;

        let actual_result = x2_plus_a.mul(cs.ns(|| "calc_actual_result"), &x)?;

        y2_minus_b.conditional_enforce_equal(cs.ns(|| "on curve check"), &actual_result, &condition)?;

        Ok(AffineGadget::new(x, y))
    }
}
/*
pub struct AllocPointConditionalGadget {
}

impl AllocPointConditionalGadget {
    pub fn alloc_conditional<FN, CS: ConstraintSystem<SW6Fr>>(
        mut cs: CS,
        value_gen: FN,
    ) -> Result<G1Gadget<Bls12_377Parameters>, SynthesisError>
        where
            FN: FnOnce() -> Result<G1Projective, SynthesisError>,
    {
        let (x, y) = match value_gen() {
            Ok(ge) => {
                let ge = ge.borrow().into_affine();
                (Ok(ge.x), Ok(ge.y))
            },
            _ => (
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
            ),
        };

        // perform on-curve check.
        let b = <Bls12_377G1Parameters as SWModelParameters>::COEFF_B;
        let a = <Bls12_377G1Parameters as SWModelParameters>::COEFF_A;

        let x = FpGadget::<SW6Fr>::alloc(&mut cs.ns(|| "x"), || x)?;
        let y = FpGadget::<SW6Fr>::alloc(&mut cs.ns(|| "y"), || y)?;

        // check that y^2 = x^3 + ax +b
        // we do this by checking that y^2 - b = x * (x^2 +a)
        let x2 = x.square(&mut cs.ns(|| "x^2"))?;
        let y2 = y.square(&mut cs.ns(|| "y^2"))?;

        let x2_plus_a = x2.add_constant(cs.ns(|| "x^2 + a"), &a)?;
        let y2_minus_b = y2.add_constant(cs.ns(|| "y^2 - b"), &b.neg())?;

        let actual_result = x2_plus_a.mul(cs.ns(|| "calc_actual_result"), &x)?;
        let x_possible_inv = FpGadget::<SW6Fr>::alloc(&mut cs.ns(|| "x possible inverse"), || {
            let x_val = x.get_value().get()?;
            if x_val.is_zero() {
                Ok(x_val)
            } else {
                Ok(x_val.inverse().unwrap())
            }
        })?;
        let x_possible_bool = x.mul(cs.ns(|| "x mul"), &x_possible_inv)?;
        let x_bool = Boolean::alloc(
            cs.ns(|| "x bool"),
            || {
                let x_val = x.get_value().get()?;
                Ok(!x_val.is_zero())
            }
        )?;
        cs.enforce(
            || "check x bool ok",
            |_| x_bool.lc(CS::one(), SW6Fr::one()),
            |lc| lc + (SW6Fr::one(), CS::one()),
            |lc| x_possible_bool.get_variable() + lc,
        );
        y2_minus_b.conditional_enforce_equal(cs.ns(|| "on curve check"), &actual_result, &x_bool)?;

        Ok(G1Gadget::<Bls12_377Parameters>::new(x, y))
    }
}
*/
