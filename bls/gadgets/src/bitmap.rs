use algebra::PrimeField;
use r1cs_core::{ConstraintSystem, LinearCombination, SynthesisError};
use r1cs_std::{
    bits::ToBitsGadget,
    fields::{fp::FpGadget, FieldGadget},
    prelude::*,
    Assignment,
};

/// Enforces that there are no more than `max_zeros` present in the provided bitmap
pub fn enforce_maximum_zeros_in_bitmap<F: PrimeField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    bitmap: &[Boolean],
    max_zeros: u64,
) -> Result<(), SynthesisError> {
    // If we're in setup mode, we skip the bit counting part since the bitmap
    // will be empty
    let is_setup = bitmap.iter().all(|bit| bit.get_value().is_none());

    // Calculate the number of zeros
    let mut num_zeros = 0;
    let mut num_zeros_lc = LinearCombination::zero();
    // For each bit, increment the number of zeros
    // if the bit was a 0. We calculate both the number of zeros
    // and a linear combination over it, in order to do 2 things:
    // 1. enforce that num_zeros < maximum_zeros
    // 2. enforce that num_zeros was calculated correctly from the bitmap
    for bit in bitmap {
        // Update the constraints
        num_zeros_lc += (F::one(), CS::one());
        let zero_lc = bit.lc(CS::one(), F::one().neg());
        num_zeros_lc = num_zeros_lc + zero_lc;

        // Update our count
        if !is_setup {
            let is_zero = !bit.get_value().get()?;
            num_zeros += is_zero as u8;
        }
    }
    // Rebind `num_zeros` to a constraint
    let num_zeros = FpGadget::alloc(&mut cs.ns(|| "num zeros"), || Ok(F::from(num_zeros)))?;

    let num_zeros_bits = &num_zeros.to_bits(&mut cs.ns(|| "num zeros to bits"))?;
    Boolean::enforce_smaller_or_equal_than::<_, _, F, _>(
        &mut cs.ns(|| "enforce maximum number of zeros"),
        num_zeros_bits,
        F::from(max_zeros).into_repr(),
    )?;

    // Enforce that we have correctly counted the number of zeros
    cs.enforce(
        || "enforce num zeros lc equal to num",
        |_| num_zeros_lc,
        |lc| lc + (F::one(), CS::one()),
        |lc| num_zeros.get_variable() + lc,
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use r1cs_std::test_constraint_system::TestConstraintSystem;
    use algebra::bls12_377::Fq;

    fn cs_enforce(
        bitmap: &[bool],
        max_zeros: u64,
    ) -> TestConstraintSystem<Fq> {
        let mut cs = TestConstraintSystem::<Fq>::new();
        let bitmap = bitmap
            .into_iter()
            .map(|b| Boolean::constant(*b))
            .collect::<Vec<_>>();
        enforce_maximum_zeros_in_bitmap(&mut cs, &bitmap, max_zeros).unwrap();
        cs
    }

    #[test]
    fn one() {
        assert!(cs_enforce(&[true], 0).is_satisfied());
    }

    #[test]
    fn no_zeros_allowed() {
        assert!(!cs_enforce(&[false], 0).is_satisfied());
    }

    #[test]
    fn three_zeros_allowed() {
        assert!(cs_enforce(&[false, true, true, false, false], 3).is_satisfied());
    }

    #[test]
    fn four_zeros_not_allowed() {
        assert!(!cs_enforce(&[false, false, true, false, false], 3).is_satisfied());
    }

}
