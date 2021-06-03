use ark_ec::PairingEngine;
use ark_ff::Field;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};

// circuit proving knowledge of a square root
// when generating the Setup, the element inside is None
#[derive(Clone, Debug)]
pub struct TestCircuit<E: PairingEngine>(pub Option<E::Fr>);
impl<E: PairingEngine> ConstraintSynthesizer<E::Fr> for TestCircuit<E> {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<E::Fr>,
    ) -> std::result::Result<(), SynthesisError> {
        // allocate a private input `x`
        // this can be made public with `alloc_input`, which would then require
        // that the verifier provides it
        let x = FpVar::<E::Fr>::new_witness(cs.clone(), || {
            self.0.ok_or(SynthesisError::AssignmentMissing)
        })
        .unwrap();
        // 1 input!
        let out = FpVar::<E::Fr>::new_input(cs.clone(), || {
            self.0
                .map(|x| x.square())
                .ok_or(SynthesisError::AssignmentMissing)
        })
        .unwrap();
        // x * x = x^2
        let x_var = match x {
            FpVar::Var(v) => v,
            _ => unreachable!(),
        };
        let out_var = match out {
            FpVar::Var(v) => v,
            _ => unreachable!(),
        };
        cs.enforce_constraint(
            lc!() + x_var.variable,
            lc!() + x_var.variable,
            lc!() + out_var.variable,
        )?;
        // add some dummy constraints to make the circuit a bit bigger
        // we do this so that we can write a failing test for our MPC
        // where the params are smaller than the circuit size
        // (7 in this case, since we allocated 3 constraints, plus 4 below)
        for _ in 0..4 {
            let _ = FpVar::<E::Fr>::new_witness(cs.clone(), || {
                self.0.ok_or(SynthesisError::AssignmentMissing)
            })
            .unwrap();
        }
        Ok(())
    }
}
