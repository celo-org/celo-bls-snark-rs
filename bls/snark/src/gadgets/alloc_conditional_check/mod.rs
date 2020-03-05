use r1cs_core::{ConstraintSystem, SynthesisError};
use r1cs_std::groups::curves::short_weierstrass::AffineGadget;
use r1cs_std::fields::FieldGadget;
use r1cs_std::{
    bits::boolean::Boolean,
};

use std::marker::PhantomData; 
use std::borrow::Borrow;
use algebra::{
    curves::{
        short_weierstrass_jacobian::GroupProjective as SWProjective,
        SWModelParameters,
        ProjectiveCurve,
    }, 
    Field, PrimeField
};
use std::ops::Neg;

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

        let infinity = Boolean::Constant(false);
        Ok(AffineGadget::new(x, y, infinity))
    }
}