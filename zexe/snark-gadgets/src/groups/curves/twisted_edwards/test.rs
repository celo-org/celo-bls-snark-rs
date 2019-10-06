use rand;

use crate::{
    boolean::Boolean,
    groups::{test::group_test, GroupGadget},
    utils::{AllocGadget, CondSelectGadget},
};

use algebra::{
    curves::{models::TEModelParameters, twisted_edwards_extended::GroupAffine as TEAffine},
    BitIterator, Group, PairingEngine, PrimeField,
};

use snark::ConstraintSystem;
use crate::groups::curves::twisted_edwards::MontgomeryAffineGadget;
use crate::fields::FieldGadget;

pub(crate) fn edwards_test<E, P, GG, CS>(cs: &mut CS)
where
    E: PairingEngine,
    P: TEModelParameters,
    GG: GroupGadget<TEAffine<P>, E, Value = TEAffine<P>>,
    CS: ConstraintSystem<E>,
{
    let a: TEAffine<P> = rand::random();
    let b: TEAffine<P> = rand::random();
    let gadget_a = GG::alloc(&mut cs.ns(|| "a"), || Ok(a)).unwrap();
    let gadget_b = GG::alloc(&mut cs.ns(|| "b"), || Ok(b)).unwrap();
    assert_eq!(gadget_a.get_value().unwrap(), a);
    assert_eq!(gadget_b.get_value().unwrap(), b);
    group_test::<E, TEAffine<P>, GG, _>(
        &mut cs.ns(|| "GroupTest(a, b)"),
        gadget_a.clone(),
        gadget_b,
    );

    // Check mul_bits
    let scalar: <TEAffine<P> as Group>::ScalarField = rand::random();
    let native_result = a.mul(&scalar);

    let mut scalar: Vec<bool> = BitIterator::new(scalar.into_repr()).collect();
    // Get the scalar bits into little-endian form.
    scalar.reverse();
    let input = Vec::<Boolean>::alloc(cs.ns(|| "Input"), || Ok(scalar)).unwrap();
    let zero = GG::zero(cs.ns(|| "zero")).unwrap();
    let result = gadget_a
        .mul_bits(cs.ns(|| "mul_bits"), &zero, input.iter())
        .unwrap();
    let gadget_value = result.get_value().expect("Gadget_result failed");
    assert_eq!(native_result, gadget_value);
}

pub(crate) fn edwards_constraint_costs<E, P, GG, CS>(cs: &mut CS)
where
    E: PairingEngine,
    P: TEModelParameters,
    GG: GroupGadget<TEAffine<P>, E, Value = TEAffine<P>>,
    CS: ConstraintSystem<E>,
{
    use crate::boolean::AllocatedBit;

    let bit = AllocatedBit::alloc(&mut cs.ns(|| "bool"), || Ok(true))
        .unwrap()
        .into();

    let a: TEAffine<P> = rand::random();
    let b: TEAffine<P> = rand::random();
    let gadget_a = GG::alloc(&mut cs.ns(|| "a"), || Ok(a)).unwrap();
    let gadget_b = GG::alloc(&mut cs.ns(|| "b"), || Ok(b)).unwrap();
    let alloc_cost = cs.num_constraints();
    let _ =
        GG::conditionally_select(&mut cs.ns(|| "cond_select"), &bit, &gadget_a, &gadget_b).unwrap();
    let cond_select_cost = cs.num_constraints() - alloc_cost;

    let _ = gadget_a.add(&mut cs.ns(|| "ab"), &gadget_b).unwrap();
    let add_cost = cs.num_constraints() - cond_select_cost - alloc_cost;
    assert_eq!(cond_select_cost, <GG as CondSelectGadget<_>>::cost());
    assert_eq!(add_cost, GG::cost_of_add());
}

pub(crate) fn edwards_montgomery_test<E, P, GG, F, CS>(cs: &mut CS)
    where
        E: PairingEngine,
        P: TEModelParameters,
        GG: GroupGadget<TEAffine<P>, E, Value = TEAffine<P>>,
        F: FieldGadget<P::BaseField, E>,
        CS: ConstraintSystem<E>,
{
    let a: TEAffine<P> = rand::random();
    let b: TEAffine<P> = rand::random();
    let gadget_a = GG::alloc(&mut cs.ns(|| "a"), || Ok(a)).unwrap();
    let gadget_b = GG::alloc(&mut cs.ns(|| "b"), || Ok(b)).unwrap();
    assert_eq!(gadget_a.get_value().unwrap(), a);
    assert_eq!(gadget_b.get_value().unwrap(), b);

    let a_mont = MontgomeryAffineGadget::<P, E, F>::from_edwards(cs.ns(|| "a mont"), &a).unwrap();
    let a_edwards = GroupGadget::<TEAffine<P>, E>::get_value(&a_mont.into_edwards(cs.ns(|| "a edwards")).unwrap()).unwrap();
    assert_eq!(a, a_edwards);

    let b_mont = MontgomeryAffineGadget::<P, E, F>::from_edwards(cs.ns(|| "b mont"), &b).unwrap();

    let a_plus_b_mont = a_mont.add(cs.ns(|| "a + b"), &b_mont).unwrap();
    let a_plus_b_edwards = GroupGadget::<TEAffine<P>, E>::get_value(&a_plus_b_mont.into_edwards(cs.ns(|| "a + b edwards")).unwrap()).unwrap();

    let native_result = a + &b;
    assert_eq!(native_result, a_plus_b_edwards);

    let result = gadget_a
        .add(cs.ns(|| "add"), &gadget_b)
        .unwrap();
    let gadget_value = result.get_value().expect("Gadget_result failed");
    assert_eq!(native_result, gadget_value);
}
