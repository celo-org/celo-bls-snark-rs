use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::{
    lc,
    r1cs::{LinearCombination, SynthesisError, Variable},
};

pub trait Bitmap<F: PrimeField> {
    /// Enforces that there are no more than `max_occurrences` of `value` (0 or 1)
    /// present in the provided bitmap
    fn enforce_maximum_occurrences_in_bitmap(
        &self,
        max_occurrences: &FpVar<F>,
        value: bool,
    ) -> Result<(), SynthesisError>;
}

impl<F: PrimeField> Bitmap<F> for [Boolean<F>] {
    #[tracing::instrument(target = "r1cs")]
    fn enforce_maximum_occurrences_in_bitmap(
        &self,
        max_occurrences: &FpVar<F>,
        value: bool,
    ) -> Result<(), SynthesisError> {
        let mut value_fp = F::one();
        if !value {
            // using the opposite value if we are counting 0s
            value_fp = value_fp.neg();
        }
        // If we're in setup mode, we skip the bit counting part since the bitmap
        // will be empty
        let is_setup = self.cs().is_in_setup_mode();

        let mut occurrences = 0;
        let mut occurrences_lc = LinearCombination::zero();
        // For each bit, increment the number of occurences if the bit matched `value`
        // We calculate both the number of occurrences
        // and a linear combination over it, in order to do 2 things:
        // 1. enforce that occurrences < maximum_occurences
        // 2. enforce that occurrences was calculated correctly from the bitmap
        for bit in self {
            // Update the constraints
            if !value {
                // add 1 here only for zeros
                occurrences_lc += (F::one(), Variable::One);
            }
            occurrences_lc = occurrences_lc + bit.lc() * value_fp;

            // Update our count
            if !is_setup {
                let got_value = bit.value()?;
                occurrences += (got_value == value) as u8;
            }
        }

        // Rebind `occurrences` to a constraint
        let occurrences = FpVar::new_witness(self.cs(), || Ok(F::from(occurrences)))?;

        // Enforce `occurences <= max_occurences`
        occurrences.enforce_cmp(&max_occurrences, std::cmp::Ordering::Less, true)?;

        let occurrences_var = match occurrences {
            FpVar::Var(v) => v.variable,
            _ => unreachable!(),
        };
        // Enforce that we have correctly counted the number of occurrences
        self.cs().enforce_constraint(
            occurrences_lc,
            lc!() + (F::one(), Variable::One),
            lc!() + occurrences_var,
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_helpers::{print_unsatisfied_constraints, run_profile_constraints};

    use ark_bls12_377::{Bls12_377, Fq, Fr};
    use ark_groth16::{
        create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof,
    };
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef};
    use std::assert;

    #[test]
    // "I know of a bitmap that has at most 2 zeros"
    fn groth16_ok() {
        let rng = &mut rand::thread_rng();

        #[derive(Clone)]
        struct BitmapGadget {
            bitmap: Vec<Option<bool>>,
            max_occurrences: u64,
            value: bool,
        }

        impl ConstraintSynthesizer<Fr> for BitmapGadget {
            fn generate_constraints(
                self,
                cs: ConstraintSystemRef<Fr>,
            ) -> Result<(), SynthesisError> {
                let bitmap = self
                    .bitmap
                    .iter()
                    .map(|b| Boolean::new_witness(cs.clone(), || Ok(b.unwrap())).unwrap())
                    .collect::<Vec<_>>();
                let max_occurrences =
                    FpVar::<Fr>::new_witness(cs, || Ok(Fr::from(self.max_occurrences)))?;
                bitmap.enforce_maximum_occurrences_in_bitmap(&max_occurrences, self.value)
            }
        }

        let params = {
            let empty = BitmapGadget {
                bitmap: vec![None; 10],
                max_occurrences: 2,
                value: false,
            };
            generate_random_parameters::<Bls12_377, _, _>(empty, rng).unwrap()
        };

        // all true bitmap, max occurences of 2 zeros allowed
        let bitmap = vec![Some(true); 10];
        let circuit = BitmapGadget {
            bitmap,
            max_occurrences: 2,
            value: false,
        };

        // since our Test constraint system is satisfied, the groth16 proof
        // should also work
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.clone().generate_constraints(cs.clone()).unwrap();
        print_unsatisfied_constraints(cs.clone());
        assert!(cs.is_satisfied().unwrap());
        let proof = create_random_proof(circuit, &params, rng).unwrap();

        let pvk = prepare_verifying_key(&params.vk);
        assert!(verify_proof(&pvk, &proof, &[]).unwrap());
    }

    #[tracing::instrument(target = "r1cs")]
    fn cs_enforce_value(bitmap: &[bool], max_number: u64, is_one: bool) -> ConstraintSystemRef<Fq> {
        let cs = ConstraintSystem::<Fq>::new_ref();
        let bitmap = bitmap
            .iter()
            .map(|b| Boolean::new_witness(cs.clone(), || Ok(*b)).unwrap())
            .collect::<Vec<_>>();
        let max_occurrences =
            FpVar::<Fq>::new_witness(cs.clone(), || Ok(Fq::from(max_number))).unwrap();
        bitmap[..]
            .enforce_maximum_occurrences_in_bitmap(&max_occurrences, is_one)
            .unwrap();
        cs
    }

    mod zeros {
        use super::*;

        #[test]
        fn one_zero_allowed() {
            run_profile_constraints(|| {
                let cs = cs_enforce_value(&[false], 1, false);
                print_unsatisfied_constraints(cs.clone());
                assert!(cs.is_satisfied().unwrap());
            });
        }

        #[test]
        fn no_zeros_allowed() {
            run_profile_constraints(|| {
                let cs = cs_enforce_value(&[false], 0, false);
                print_unsatisfied_constraints(cs.clone());
                assert!(!cs.is_satisfied().unwrap());
            });
        }

        #[test]

        fn three_zeros_allowed() {
            run_profile_constraints(|| {
                let cs = cs_enforce_value(&[false, true, true, false, false], 3, false);
                print_unsatisfied_constraints(cs.clone());
                assert!(cs.is_satisfied().unwrap());
            });
        }

        #[test]
        fn four_zeros_not_allowed() {
            run_profile_constraints(|| {
                let cs = cs_enforce_value(&[false, false, true, false, false], 3, false);
                print_unsatisfied_constraints(cs.clone());
                assert!(!cs.is_satisfied().unwrap());
            });
        }
    }

    mod ones {
        use super::*;

        #[test]
        fn one_one_allowed() {
            run_profile_constraints(|| {
                let cs = cs_enforce_value(&[true], 1, true);
                print_unsatisfied_constraints(cs.clone());
                assert!(cs.is_satisfied().unwrap());
            });
        }

        #[test]
        fn no_ones_allowed() {
            run_profile_constraints(|| {
                let cs = cs_enforce_value(&[true], 0, true);
                print_unsatisfied_constraints(cs.clone());
                assert!(!cs.is_satisfied().unwrap());
            });
        }

        #[test]
        fn three_ones_allowed() {
            run_profile_constraints(|| {
                let cs = cs_enforce_value(&[false, true, true, true, false], 3, true);
                print_unsatisfied_constraints(cs.clone());
                assert!(cs.is_satisfied().unwrap());
            });
        }

        #[test]
        fn four_ones_not_allowed() {
            run_profile_constraints(|| {
                let cs = cs_enforce_value(&[true, true, true, true, false], 3, true);
                print_unsatisfied_constraints(cs.clone());
                assert!(!cs.is_satisfied().unwrap());
            });
        }
    }
}
