use algebra::{bls12_377::Bls12_377, bw6_761::Fr, PairingEngine};
use r1cs_core::{ConstraintSystem, SynthesisError};
use r1cs_std::{
    bls12_377::{G1Gadget, G2Gadget, PairingGadget},
    boolean::Boolean,
    fields::fp::FpGadget,
};

use super::{constrain_bool, EpochData};
use bls_gadgets::BlsVerifyGadget;
use tracing::{span, Level};
use crate::encoding::PREVIOUS_EPOCH_HASH_BITS;

// Instantiate the BLS Verification gadget
type BlsGadget = BlsVerifyGadget<Bls12_377, Fr, PairingGadget>;
type FrGadget = FpGadget<Fr>;

#[derive(Clone, Debug)]
/// An epoch block transition which includes the new epoch block's metadata, as well as
/// the bitmap of the validators which signed on the new epoch block.
pub struct SingleUpdate<E: PairingEngine> {
    /// The new epoch block's metadata
    pub epoch_data: EpochData<E>,
    /// Bitmap of the validators who signed on the next epoch block
    pub signed_bitmap: Vec<Option<bool>>,
}

impl<E: PairingEngine> SingleUpdate<E> {
    /// Returns an empty update. This function is used when running the trusted setup.
    pub fn empty(num_validators: usize, maximum_non_signers: usize) -> Self {
        Self {
            epoch_data: EpochData::<E>::empty(num_validators, maximum_non_signers),
            signed_bitmap: vec![None; num_validators],
        }
    }
}

/// A [`SingleUpdate`] is constrained to a `ConstrainedEpoch` via [`SingleUpdate.constrain`]
///
/// [`SingleUpdate`]: struct.SingleUpdate.html
/// [`SingleUpdate.constrain`]: struct.SingleUpdate.html#method.constrain
pub struct ConstrainedEpoch {
    /// The new validators for this epoch
    pub new_pubkeys: Vec<G2Gadget>,
    /// The new threshold needed for signatures
    pub new_max_non_signers: FrGadget,
    /// The epoch's G1 Hash
    pub message_hash: G1Gadget,
    /// The aggregate pubkey based on the bitmap of the validators
    /// of the previous epoch
    pub aggregate_pk: G2Gadget,
    /// The epoch's index
    pub index: FrGadget,
    /// Serialized epoch data containing the index, max non signers, aggregated pubkey and the pubkeys array
    pub bits: Vec<Boolean>,
    /// Aux data for proving the CRH->XOF hash outside of BW6_761
    pub xof_bits: Vec<Boolean>,
    /// Aux data for proving the CRH->XOF hash outside of BW6_761
    pub crh_bits: Vec<Boolean>,
}

impl ConstrainedEpoch {
    pub fn extract_previous_hash_bits(&self) -> Vec<Boolean> {
        self.xof_bits[0..PREVIOUS_EPOCH_HASH_BITS].to_vec()
    }
}

impl SingleUpdate<Bls12_377> {
    /// Ensures that enough validators are present on the bitmap and generates
    /// the epoch's G1 Hash and Aggregated Public Key
    ///
    /// # Panics
    ///
    /// - If `num_validators != self.epoch_data.public_keys.len()`
    pub fn constrain<CS: ConstraintSystem<Fr>>(
        &self,
        cs: &mut CS,
        previous_epoch_hash: &[Boolean],
        previous_pubkeys: &[G2Gadget],
        previous_epoch_index: &FrGadget,
        previous_max_non_signers: &FrGadget,
        num_validators: u32,
        generate_constraints_for_hash: bool,
    ) -> Result<ConstrainedEpoch, SynthesisError> {
        let span = span!(Level::TRACE, "SingleUpdate");
        let _enter = span.enter();
        // the number of validators across all epochs must be consistent
        assert_eq!(num_validators as usize, self.epoch_data.public_keys.len());

        // Get the constrained epoch data
        let epoch_data = self.epoch_data.constrain(
            &mut cs.ns(|| "constrain"),
            previous_epoch_hash,
            previous_epoch_index,
            generate_constraints_for_hash,
        )?;

        // convert the bitmap to constraints
        let signed_bitmap = constrain_bool(&mut cs.ns(|| "signed bitmap"), &self.signed_bitmap)?;

        // Verify that the bitmap is consistent with the pubkeys read from the
        // previous epoch and prepare the message hash and the aggregate pk
        let (message_hash, aggregated_public_key) = BlsGadget::enforce_bitmap(
            cs.ns(|| "verify signature partial"),
            previous_pubkeys,
            &signed_bitmap,
            &epoch_data.message_hash,
            &previous_max_non_signers,
        )?;

        Ok(ConstrainedEpoch {
            new_pubkeys: epoch_data.pubkeys,
            new_max_non_signers: epoch_data.maximum_non_signers,
            message_hash,
            aggregate_pk: aggregated_public_key,
            index: epoch_data.index,
            bits: epoch_data.bits,
            xof_bits: epoch_data.xof_bits,
            crh_bits: epoch_data.crh_bits,
        })
    }
}

#[cfg(test)]
pub mod test_helpers {
    use super::*;
    use crate::gadgets::test_helpers::to_option_iter;
    use algebra::ProjectiveCurve;

    pub fn generate_single_update<E: PairingEngine>(
        index: u16,
        maximum_non_signers: u32,
        public_keys: &[E::G2Projective],
        bitmap: &[bool],
    ) -> SingleUpdate<E> {
        let epoch_data = EpochData::<E> {
            index: Some(index),
            maximum_non_signers,
            public_keys: to_option_iter(public_keys),
        };

        SingleUpdate::<E> {
            epoch_data,
            signed_bitmap: to_option_iter(bitmap),
        }
    }

    pub fn generate_dummy_update<E: PairingEngine>(num_validators: u32) -> SingleUpdate<E> {
        let bitmap = (0..num_validators).map(|_| true).collect::<Vec<_>>();
        let public_keys = (0..num_validators)
            .map(|_| E::G2Projective::prime_subgroup_generator())
            .collect::<Vec<_>>();
        let epoch_data = EpochData::<E> {
            index: Some(0),
            maximum_non_signers: 0u32,
            public_keys: to_option_iter(public_keys.as_slice()),
        };

        SingleUpdate::<E> {
            epoch_data,
            signed_bitmap: to_option_iter(&bitmap),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_helpers::generate_single_update;
    use super::*;
    use crate::gadgets::to_fr;
    use algebra::UniformRand;
    use bls_gadgets::utils::test_helpers::alloc_vec;
    use r1cs_std::test_constraint_system::TestConstraintSystem;

    fn pubkeys<E: PairingEngine>(num: usize) -> Vec<E::G2Projective> {
        let rng = &mut rand::thread_rng();
        (0..num)
            .map(|_| E::G2Projective::rand(rng))
            .collect::<Vec<_>>()
    }

    #[test]
    fn test_enough_pubkeys_for_update() {
        let mut cs = TestConstraintSystem::<Fr>::new();
        single_update_enforce(&mut cs, 5, 5, 1, 2, 1, &[true, true, true, true, false]);
        assert!(cs.is_satisfied());
    }

    #[test]
    fn not_enough_pubkeys_for_update() {
        let mut cs = TestConstraintSystem::<Fr>::new();
        // 2 false in the bitmap when only 1 allowed
        single_update_enforce(&mut cs, 5, 5, 4, 5, 1, &[true, true, false, true, false]);
        assert!(!cs.is_satisfied());
        let not_satisfied = cs.which_is_unsatisfied();
        assert_eq!(not_satisfied.unwrap(), "constrain epoch 2/verify signature partial/enforce maximum number of occurrences/enforce smaller than/enforce smaller than/enforce smaller than");
    }

    #[test]
    #[should_panic]
    fn validator_number_cannot_change() {
        let mut cs = TestConstraintSystem::<Fr>::new();
        single_update_enforce(&mut cs, 5, 6, 0, 0, 0, &[]);
    }

    fn single_update_enforce<CS: ConstraintSystem<Fr>>(
        cs: &mut CS,
        prev_n_validators: usize,
        n_validators: usize,
        prev_index: u16,
        index: u16,
        maximum_non_signers: u32,
        bitmap: &[bool],
    ) -> ConstrainedEpoch {
        // convert to constraints
        let prev_validators = alloc_vec(cs, &pubkeys::<Bls12_377>(n_validators));
        let prev_index = to_fr(&mut cs.ns(|| "prev index to fr"), Some(prev_index)).unwrap();
        let prev_max_non_signers = to_fr(
            &mut cs.ns(|| "prev max non signers to fr"),
            Some(maximum_non_signers),
        )
        .unwrap();

        // generate the update via the helper
        let next_epoch = generate_single_update(
            index,
            maximum_non_signers,
            &pubkeys::<Bls12_377>(n_validators),
            bitmap,
        );

        // enforce
        next_epoch
            .constrain(
                &mut cs.ns(|| "constrain epoch 2"),
                &[],
                &prev_validators,
                &prev_index,
                &prev_max_non_signers,
                prev_n_validators as u32,
                false,
            )
            .unwrap()
    }
}
