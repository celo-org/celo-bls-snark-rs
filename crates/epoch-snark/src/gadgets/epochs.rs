//! # Validator Set Update Circuit
//!
//! Prove the validator state transition function for the BLS 12-377 curve.

use crate::gadgets::{g2_to_bits, single_update::SingleUpdate, EpochBits, EpochData};
use bls_gadgets::{BlsVerifyGadget, FpUtils};

use ark_bls12_377::{
    constraints::{Fq2Var, G1PreparedVar, G1Var, G2PreparedVar, G2Var, PairingVar},
    Bls12_377, G1Projective, G2Projective, Parameters as Bls12_377_Parameters,
};
use ark_bw6_761::Fr;
use ark_ec::{bls12::Bls12Parameters, PairingEngine, ProjectiveCurve};
use ark_groth16::{Proof, VerifyingKey};
use ark_r1cs_std::{
    alloc::AllocationMode, fields::fp::FpVar, pairing::PairingVar as _, prelude::*, Assignment,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use tracing::{debug, info, span, Level};

// Initialize BLS verification gadget
type BlsGadget = BlsVerifyGadget<Bls12_377, Fr, PairingVar>;
type FrVar = FpVar<Fr>;
type Bool = Boolean<<Bls12_377_Parameters as Bls12Parameters>::Fp>;

#[derive(Clone, Debug)]
/// Contains the initial epoch block, followed by a list of epoch block transitions. The
/// aggregated signature is calculated over all epoch blokc changes. Providing the hash helper
/// will not constrain the CRH->XOF calculation.
pub struct ValidatorSetUpdate<E: PairingEngine> {
    pub initial_epoch: EpochData<E>,
    /// The number of validators over all the epochs
    pub num_validators: u32,
    /// A list of all the updates for multiple epochs
    pub epochs: Vec<SingleUpdate<E>>,
    /// The aggregated signature of all the validators over all the epoch changes
    pub aggregated_signature: Option<E::G1Projective>,
    /// The optional hash to bits proof data. If provided, the circuit **will not**
    /// constrain the inner CRH->XOF hashes in BW6_761 and instead it will be verified
    /// via the helper's proof which is in BLS12-377.
    pub hash_helper: Option<HashToBitsHelper<E>>,
}

#[derive(Clone, Debug)]
/// The proof and verifying key which will be used to verify the CRH->XOF conversion
pub struct HashToBitsHelper<E: PairingEngine> {
    /// The Groth16 proof satisfying the CRH->XOF conversion
    pub proof: Proof<E>,
    /// The VK produced by the trusted setup
    pub verifying_key: VerifyingKey<E>,
}

impl<E: PairingEngine> ValidatorSetUpdate<E> {
    /// Initializes an empty validator set update. This is used when running the trusted setup.
    #[tracing::instrument(target = "r1cs")]
    pub fn empty(
        num_validators: usize,
        num_epochs: usize,
        maximum_non_signers: usize,
        vk: Option<VerifyingKey<E>>,
    ) -> Self {
        let empty_update = SingleUpdate::empty(num_validators, maximum_non_signers);
        let hash_helper = vk.map(|vk| HashToBitsHelper {
            proof: Proof::<E>::default(),
            verifying_key: vk,
        });

        ValidatorSetUpdate {
            initial_epoch: EpochData::empty(num_validators, maximum_non_signers),
            num_validators: num_validators as u32,
            epochs: vec![empty_update; num_epochs],
            aggregated_signature: None,
            hash_helper,
        }
    }
}

impl ConstraintSynthesizer<Fr> for ValidatorSetUpdate<Bls12_377> {
    /// Enforce that the signatures over the epochs have been calculated
    /// correctly, and then compress the public inputs
    #[tracing::instrument(target = "r1cs")]
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let span = span!(Level::TRACE, "ValidatorSetUpdate");
        let _enter = span.enter();
        info!("generating constraints");
        // Verify signatures
        let epoch_bits = self.enforce(cs)?;
        let cs = epoch_bits.first_epoch_bits.cs();
        // Compress public inputs
        epoch_bits.verify(self.hash_helper, cs)?;
        info!("constraints generated");

        Ok(())
    }
}

impl ValidatorSetUpdate<Bls12_377> {
    /// Verify in the constraint system the aggregate BLS
    /// signature after constraining the epoch hashes and aggregate
    /// public keys for each epoch
    #[tracing::instrument(target = "r1cs")]
    fn enforce(
        &self,
        cs: ConstraintSystemRef<<Bls12_377_Parameters as Bls12Parameters>::Fp>,
    ) -> Result<EpochBits, SynthesisError> {
        let span = span!(Level::TRACE, "ValidatorSetUpdate_enforce");
        let _enter = span.enter();

        debug!("converting initial EpochData to_bits");
        // Constrain the initial epoch and get its bits
        let (
            _,
            _,
            first_epoch_bits,
            _,
            first_epoch_index,
            first_epoch_entropy,
            _,
            initial_maximum_non_signers,
            initial_pubkey_vars,
        ) = self.initial_epoch.to_bits(cs)?;

        // Constrain all intermediate epochs, and get the aggregate pubkey and epoch hash
        // from each one, to be used for the batch verification
        debug!("verifying intermediate epochs");
        let (
            last_epoch_bits,
            crh_bits,
            xof_bits,
            prepared_aggregated_public_keys,
            prepared_message_hashes,
        ) = self.verify_intermediate_epochs(
            first_epoch_index,
            first_epoch_entropy,
            initial_pubkey_vars,
            initial_maximum_non_signers,
        )?;

        // Verify the aggregate BLS signature
        debug!("verifying bls signature");
        self.verify_signature(
            &prepared_aggregated_public_keys,
            &prepared_message_hashes,
            first_epoch_bits.cs(),
        )?;

        Ok(EpochBits {
            first_epoch_bits,
            last_epoch_bits,
            crh_bits,
            xof_bits,
        })
    }

    /// Ensure that all epochs's bitmaps have been correctly computed
    /// and generates the witness data necessary for the final BLS Sig
    /// verification and witness compression
    #[allow(clippy::type_complexity)]
    #[tracing::instrument(target = "r1cs")]
    fn verify_intermediate_epochs(
        &self,
        first_epoch_index: FrVar,
        first_epoch_entropy: FrVar,
        initial_pubkey_vars: Vec<G2Var>,
        initial_max_non_signers: FrVar,
    ) -> Result<
        (
            Vec<Bool>,
            Vec<Bool>,
            Vec<Bool>,
            Vec<G2PreparedVar>,
            Vec<G1PreparedVar>,
        ),
        SynthesisError,
    > {
        let span = span!(Level::TRACE, "verify_intermediate_epochs");
        let _enter = span.enter();

        let dummy_pk = G2Var::new_variable_omit_prime_order_check(
            first_epoch_index.cs(),
            || Ok(G2Projective::prime_subgroup_generator()),
            AllocationMode::Constant,
        )?;
        let dummy_message = G1Var::new_variable_omit_prime_order_check(
            first_epoch_index.cs(),
            || Ok(G1Projective::prime_subgroup_generator()),
            AllocationMode::Constant,
        )?;

        // Trivially satisfy entropy circuit logic if the first epoch does not
        // contain entropy. Done to support earlier versions of Celo.
        // Assumes all epochs past a single version will contain entropy
        let entropy_bit = first_epoch_entropy.is_eq_zero()?.not();

        let mut prepared_aggregated_public_keys = vec![];
        let mut prepared_message_hashes = vec![];
        let mut last_epoch_bits = vec![];
        let mut previous_epoch_index = first_epoch_index;
        let mut previous_pubkey_vars = initial_pubkey_vars;
        let mut previous_max_non_signers = initial_max_non_signers;
        let mut previous_epoch_entropy = first_epoch_entropy;
        let mut all_crh_bits = vec![];
        let mut all_xof_bits = vec![];
        for (i, epoch) in self.epochs.iter().enumerate() {
            let span = span!(Level::TRACE, "index", i);
            let _enter = span.enter();
            let constrained_epoch = epoch.constrain(
                &previous_pubkey_vars,
                &previous_epoch_index,
                &previous_epoch_entropy,
                &previous_max_non_signers,
                &entropy_bit,
                self.num_validators,
                self.hash_helper.is_none(), // generate all constraints in BW6_761 if no helper was provided
            )?;

            // If zero, indicates the current epoch is a "dummy" value, and so
            // some values shouldn't be updated in this loop
            let index_bit = constrained_epoch.index.is_eq_zero()?.not();

            // Update the randomness for the next iteration
            previous_epoch_entropy = FrVar::conditionally_select(
                &index_bit,
                &constrained_epoch.epoch_entropy,
                &previous_epoch_entropy,
            )?;
            // Update the pubkeys for the next iteration
            previous_epoch_index = FrVar::conditionally_select(
                &index_bit,
                &constrained_epoch.index,
                &previous_epoch_index,
            )?;
            previous_pubkey_vars = constrained_epoch
                .new_pubkeys
                .iter()
                .zip(previous_pubkey_vars.iter())
                .map(|(new_pk, old_pk)| G2Var::conditionally_select(&index_bit, new_pk, old_pk))
                .collect::<Result<Vec<_>, _>>()?;
            previous_max_non_signers = FrVar::conditionally_select(
                &index_bit,
                &constrained_epoch.new_max_non_signers,
                &previous_max_non_signers,
            )?;

            let aggregate_pk = G2Var::conditionally_select(
                &index_bit,
                &constrained_epoch.aggregate_pk,
                &dummy_pk,
            )?;

            let prepared_aggregate_pk = PairingVar::prepare_g2(&aggregate_pk)?;

            let message_hash = G1Var::conditionally_select(
                &index_bit,
                &constrained_epoch.message_hash,
                &dummy_message,
            )?;

            let prepared_message_hash = PairingVar::prepare_g1(&message_hash)?;

            // Save the aggregated pubkey / message hash pair for the BLS batch verification
            prepared_aggregated_public_keys.push(prepared_aggregate_pk);
            prepared_message_hashes.push(prepared_message_hash);

            // Save the xof/crh and the last epoch's bits for compressing the public inputs
            all_crh_bits.extend_from_slice(&constrained_epoch.crh_bits);
            all_xof_bits.extend_from_slice(&constrained_epoch.xof_bits);
            if i == self.epochs.len() - 1 {
                let last_apk = BlsGadget::enforce_aggregated_all_pubkeys(
                    &previous_pubkey_vars, // These are now the last epoch new pubkeys
                )?;
                let affine_x = last_apk.x.mul_by_inverse(&last_apk.z)?;
                let affine_y = last_apk.y.mul_by_inverse(&last_apk.z)?;
                let last_apk_affine = G2Var::new(affine_x, affine_y, Fq2Var::one());
                let last_apk_bits = g2_to_bits(&last_apk_affine)?;
                last_epoch_bits = constrained_epoch.combined_last_epoch_bits;
                last_epoch_bits.extend_from_slice(&last_apk_bits);

                // make sure the last epoch index is not zero
                index_bit.enforce_equal(&Boolean::Constant(true))?;
            }
            debug!("epoch {} constrained", i);
        }

        debug!("intermediate epochs verified");

        Ok((
            last_epoch_bits,
            all_crh_bits,
            all_xof_bits,
            prepared_aggregated_public_keys,
            prepared_message_hashes,
        ))
    }

    // Verify the aggregate signature
    #[tracing::instrument(target = "r1cs")]
    fn verify_signature(
        &self,
        pubkeys: &[G2PreparedVar],
        messages: &[G1PreparedVar],
        cs: ConstraintSystemRef<<Bls12_377_Parameters as Bls12Parameters>::Fp>,
    ) -> Result<(), SynthesisError> {
        let aggregated_signature = G1Var::new_variable_omit_prime_order_check(
            cs,
            || self.aggregated_signature.get(),
            AllocationMode::Witness,
        )?;
        BlsGadget::batch_verify_prepared(&pubkeys, &messages, &aggregated_signature)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gadgets::single_update::test_helpers::generate_single_update;
    use bls_gadgets::utils::test_helpers::{
        print_unsatisfied_constraints, run_profile_constraints,
    };

    use ark_bls12_377::G1Projective;
    use ark_ec::ProjectiveCurve;
    use ark_relations::r1cs::ConstraintSystem;
    use bls_crypto::test_helpers::{keygen_batch, keygen_mul, sign_batch, sum};

    type Curve = Bls12_377;
    type Entropy = Option<Vec<u8>>;

    // let's run our tests with 7 validators and 2 faulty ones
    mod epoch_batch_verification {
        use super::*;
        use crate::epoch_block::hash_first_last_epoch_block;
        use crate::gadgets::single_update::test_helpers::generate_dummy_update;
        use crate::{BWField, BWFrParams, EpochBlock};
        use ark_serialize::CanonicalSerialize;
        use blake2s_simd::blake2s;
        use bls_crypto::PublicKey;

        fn epoch_data_to_block(data: &EpochData<Curve>) -> EpochBlock {
            EpochBlock::new(
                data.index.unwrap(),
                data.round.unwrap(),
                data.epoch_entropy.clone(),
                data.parent_entropy.clone(),
                data.maximum_non_signers,
                data.public_keys.len(),
                data.public_keys
                    .iter()
                    .map(|p| PublicKey::from(p.unwrap()))
                    .collect(),
            )
        }

        #[tracing::instrument(target = "r1cs")]
        fn test_epochs(
            faults: u32,
            num_epochs: usize,
            initial_entropy: Entropy,
            entropy: Vec<(Entropy, Entropy)>,
            bitmaps: Vec<Vec<bool>>,
            include_dummy_epochs: bool,
            expected_hashes: Option<Vec<String>>,
        ) -> bool {
            let num_validators = 3 * faults + 1;
            let initial_validator_set = keygen_mul::<Curve>(num_validators as usize);
            let initial_epoch = generate_single_update::<Curve>(
                0,
                0,
                initial_entropy,
                None, // parent entropy of initial epoch should be ignored
                faults,
                &initial_validator_set.1,
                &[],
            )
            .epoch_data;

            // Generate validators for each of the epochs
            let validators = keygen_batch::<Curve>(num_epochs, num_validators as usize);
            // Generate `num_epochs` epochs
            let mut epochs = validators
                .1
                .iter()
                .zip(entropy)
                .enumerate()
                .map(
                    |(epoch_index, (epoch_validators, (parent_entropy, entropy)))| {
                        generate_single_update::<Curve>(
                            epoch_index as u16 + 1,
                            0u8,
                            entropy,
                            parent_entropy,
                            faults,
                            epoch_validators,
                            &bitmaps[epoch_index],
                        )
                    },
                )
                .collect::<Vec<_>>();

            // The i-th validator set, signs on the i+1th epoch's G1 hash
            let mut signers = vec![initial_validator_set.0];
            signers.extend_from_slice(&validators.0[..validators.1.len() - 1]);

            // Filter the private keys which had a 1 in the boolean per epoch
            let mut signers_filtered = Vec::new();
            for i in 0..signers.len() {
                let mut epoch_signers_filtered = Vec::new();
                let epoch_signers = &signers[i];
                let epoch_bitmap = &bitmaps[i];
                for (j, epoch_signer) in epoch_signers.iter().enumerate() {
                    if epoch_bitmap[j] {
                        epoch_signers_filtered.push(*epoch_signer);
                    }
                }
                signers_filtered.push(epoch_signers_filtered);
            }

            use crate::gadgets::test_helpers::hash_epoch;
            let epoch_hashes = epochs
                .iter()
                .map(|update| hash_epoch(&update.epoch_data))
                .collect::<Vec<G1Projective>>();

            // dummy sig is the same as the message, since sk is 1.
            let dummy_message = G1Projective::prime_subgroup_generator();
            let dummy_sig = dummy_message;

            let mut asigs = sign_batch::<Bls12_377>(&signers_filtered, &epoch_hashes);

            if include_dummy_epochs {
                epochs = [
                    &epochs[0..3],
                    &[
                        generate_dummy_update(num_validators),
                        generate_dummy_update(num_validators),
                    ],
                    &[epochs[3].clone()],
                ]
                .concat();

                asigs = [&asigs[0..3], &[dummy_sig, dummy_sig], &[asigs[3]]].concat();
            }
            let aggregated_signature = sum(&asigs);

            let valset = ValidatorSetUpdate::<Curve> {
                initial_epoch: initial_epoch.clone(),
                epochs: epochs.clone(),
                num_validators,
                aggregated_signature: Some(aggregated_signature),
                hash_helper: None,
            };

            let cs = ConstraintSystem::<Fr>::new_ref();
            let epoch_bits = valset.enforce(cs.clone()).unwrap();
            epoch_bits.verify(None, cs.clone()).unwrap();
            let hash = hash_first_last_epoch_block(
                &epoch_data_to_block(&initial_epoch),
                &epoch_data_to_block(&epochs[epochs.len() - 1].epoch_data),
            )
            .unwrap();
            let public_inputs = crate::gadgets::pack::<BWField, BWFrParams>(&hash).unwrap();
            assert_eq!(
                cs.borrow().unwrap().instance_assignment[1..].to_vec(),
                public_inputs
            );
            cs.inline_all_lcs();
            if let Some(expected_hashes) = expected_hashes {
                let matrices = cs.to_matrices().unwrap();
                let mut serialized_matrix = vec![];
                matrices.a.serialize(&mut serialized_matrix).unwrap();
                assert_eq!(
                    blake2s(&serialized_matrix).to_hex().to_string(),
                    expected_hashes[0],
                );
                matrices.b.serialize(&mut serialized_matrix).unwrap();
                assert_eq!(
                    blake2s(&serialized_matrix).to_hex().to_string(),
                    expected_hashes[1],
                );
                matrices.c.serialize(&mut serialized_matrix).unwrap();
                assert_eq!(
                    blake2s(&serialized_matrix).to_hex().to_string(),
                    expected_hashes[2],
                );
            }

            print_unsatisfied_constraints(cs.clone());
            cs.is_satisfied().unwrap()
        }

        #[test]
        fn test_multiple_epochs() {
            run_profile_constraints(test_multiple_epochs_inner);
        }
        #[tracing::instrument(target = "r1cs")]
        fn test_multiple_epochs_inner() {
            let num_faults = 2;
            let num_epochs = 4;
            // no more than `faults` 0s exist in the bitmap
            // (i.e. at most `faults` validators who do not sign on the next validator set)
            let bitmaps = vec![
                vec![true, true, false, true, true, true, true],
                vec![true, true, false, true, true, true, true],
                vec![true, true, true, true, false, false, true],
                vec![true, true, true, true, true, true, true],
            ];
            let initial_entropy = None;
            let entropy = vec![(None, None), (None, None), (None, None), (None, None)];
            let include_dummy_epochs = false;

            assert!(test_epochs(
                num_faults,
                num_epochs,
                initial_entropy,
                entropy,
                bitmaps,
                include_dummy_epochs,
                None,
            ));
        }

        #[test]
        fn test_multiple_epochs_with_dummy() {
            run_profile_constraints(test_multiple_epochs_with_dummy_inner);
        }
        #[tracing::instrument(target = "r1cs")]
        fn test_multiple_epochs_with_dummy_inner() {
            let num_faults = 2;
            let num_epochs = 4;
            // no more than `faults` 0s exist in the bitmap
            // (i.e. at most `faults` validators who do not sign on the next validator set)
            let bitmaps = vec![
                vec![true, true, false, true, true, true, true],
                vec![true, true, false, true, true, true, true],
                vec![true, true, true, true, false, false, true],
                vec![true, true, true, true, true, true, true],
            ];
            let initial_entropy = None;
            let entropy = vec![(None, None), (None, None), (None, None), (None, None)];
            let include_dummy_epochs = true;

            assert!(test_epochs(
                num_faults,
                num_epochs,
                initial_entropy,
                entropy,
                bitmaps,
                include_dummy_epochs,
                None,
            ));
        }

        #[test]
        fn test_multiple_epochs_with_entropy() {
            run_profile_constraints(test_multiple_epochs_with_entropy_inner);
        }
        #[tracing::instrument(target = "r1cs")]
        fn test_multiple_epochs_with_entropy_inner() {
            let num_faults = 2;
            let num_epochs = 4;
            // no more than `faults` 0s exist in the bitmap
            // (i.e. at most `faults` validators who do not sign on the next validator set)
            let bitmaps = vec![
                vec![true, true, false, true, true, true, true],
                vec![true, true, false, true, true, true, true],
                vec![true, true, true, true, false, false, true],
                vec![true, true, true, true, true, true, true],
            ];
            let initial_entropy = Some(vec![1u8; EpochData::<Curve>::ENTROPY_BYTES]);
            let entropy = vec![
                (
                    Some(vec![1u8; EpochData::<Curve>::ENTROPY_BYTES]),
                    Some(vec![2u8; EpochData::<Curve>::ENTROPY_BYTES]),
                ),
                (
                    Some(vec![2u8; EpochData::<Curve>::ENTROPY_BYTES]),
                    Some(vec![3u8; EpochData::<Curve>::ENTROPY_BYTES]),
                ),
                (
                    Some(vec![3u8; EpochData::<Curve>::ENTROPY_BYTES]),
                    Some(vec![4u8; EpochData::<Curve>::ENTROPY_BYTES]),
                ),
                (
                    Some(vec![4u8; EpochData::<Curve>::ENTROPY_BYTES]),
                    Some(vec![5u8; EpochData::<Curve>::ENTROPY_BYTES]),
                ),
            ];
            let include_dummy_epochs = false;

            #[cfg(feature = "compat")]
            let expected_matrices_hashes = Some(vec![
                "5ae20d76f27795a498b9e9f1d4035475bc137ad70cb75500c9cf3210f8cc10fa".to_string(),
                "58c12fa7ca9130918f4c86c6ebe870426d9ca7ae4571d6d1f9f190e2b497d41c".to_string(),
                "2f860526de1066469a151cd44e803866d947dc28668fdcd6c0a8098128223b21".to_string(),
            ]);
            #[cfg(not(feature = "compat"))]
            let expected_matrices_hashes = None;
            assert!(test_epochs(
                num_faults,
                num_epochs,
                initial_entropy,
                entropy,
                bitmaps,
                include_dummy_epochs,
                expected_matrices_hashes,
            ));
        }

        #[test]
        fn test_multiple_epochs_with_wrong_entropy() {
            run_profile_constraints(test_multiple_epochs_with_wrong_entropy_inner);
        }
        #[tracing::instrument(target = "r1cs")]
        fn test_multiple_epochs_with_wrong_entropy_inner() {
            let num_faults = 2;
            let num_epochs = 4;
            // no more than `faults` 0s exist in the bitmap
            // (i.e. at most `faults` validators who do not sign on the next validator set)
            let bitmaps = vec![
                vec![true, true, false, true, true, true, true],
                vec![true, true, false, true, true, true, true],
                vec![true, true, true, true, false, false, true],
                vec![true, true, true, true, true, true, true],
            ];
            let initial_entropy = Some(vec![1u8; EpochData::<Curve>::ENTROPY_BYTES]);
            let entropy = vec![
                (
                    Some(vec![1u8; EpochData::<Curve>::ENTROPY_BYTES]),
                    Some(vec![2u8; EpochData::<Curve>::ENTROPY_BYTES]),
                ),
                (
                    Some(vec![2u8; EpochData::<Curve>::ENTROPY_BYTES]),
                    Some(vec![3u8; EpochData::<Curve>::ENTROPY_BYTES]),
                ),
                // parent entropy does not match previous entropy
                (
                    Some(vec![5u8; EpochData::<Curve>::ENTROPY_BYTES]),
                    Some(vec![4u8; EpochData::<Curve>::ENTROPY_BYTES]),
                ),
                (
                    Some(vec![4u8; EpochData::<Curve>::ENTROPY_BYTES]),
                    Some(vec![5u8; EpochData::<Curve>::ENTROPY_BYTES]),
                ),
            ];
            let include_dummy_epochs = false;

            assert!(!test_epochs(
                num_faults,
                num_epochs,
                initial_entropy,
                entropy,
                bitmaps,
                include_dummy_epochs,
                None,
            ));
        }

        #[test]
        fn test_multiple_epochs_with_wrong_entropy_dummy() {
            run_profile_constraints(test_multiple_epochs_with_wrong_entropy_dummy_inner);
        }
        #[tracing::instrument(target = "r1cs")]
        fn test_multiple_epochs_with_wrong_entropy_dummy_inner() {
            let num_faults = 2;
            let num_epochs = 4;
            // no more than `faults` 0s exist in the bitmap
            // (i.e. at most `faults` validators who do not sign on the next validator set)
            let bitmaps = vec![
                vec![true, true, false, true, true, true, true],
                vec![true, true, false, true, true, true, true],
                vec![true, true, true, true, false, false, true],
                vec![true, true, true, true, true, true, true],
            ];
            let initial_entropy = Some(vec![1u8; EpochData::<Curve>::ENTROPY_BYTES]);
            let entropy = vec![
                (
                    Some(vec![1u8; EpochData::<Curve>::ENTROPY_BYTES]),
                    Some(vec![2u8; EpochData::<Curve>::ENTROPY_BYTES]),
                ),
                (
                    Some(vec![2u8; EpochData::<Curve>::ENTROPY_BYTES]),
                    Some(vec![3u8; EpochData::<Curve>::ENTROPY_BYTES]),
                ),
                (
                    Some(vec![3u8; EpochData::<Curve>::ENTROPY_BYTES]),
                    Some(vec![4u8; EpochData::<Curve>::ENTROPY_BYTES]),
                ),
                // parent entropy does not match previous entropy
                (
                    Some(vec![6u8; EpochData::<Curve>::ENTROPY_BYTES]),
                    Some(vec![5u8; EpochData::<Curve>::ENTROPY_BYTES]),
                ),
            ];
            // dummy blocks inserted just before the last epoch
            // epoch blocks should verify as if the dummy blocks were not there
            let include_dummy_epochs = true;

            assert!(!test_epochs(
                num_faults,
                num_epochs,
                initial_entropy,
                entropy,
                bitmaps,
                include_dummy_epochs,
                None,
            ));
        }

        #[test]
        fn test_multiple_epochs_with_no_initial_entropy() {
            run_profile_constraints(test_multiple_epochs_with_no_initial_entropy_inner);
        }
        #[tracing::instrument(target = "r1cs")]
        fn test_multiple_epochs_with_no_initial_entropy_inner() {
            let num_faults = 2;
            let num_epochs = 4;
            // no more than `faults` 0s exist in the bitmap
            // (i.e. at most `faults` validators who do not sign on the next validator set)
            let bitmaps = vec![
                vec![true, true, false, true, true, true, true],
                vec![true, true, false, true, true, true, true],
                vec![true, true, true, true, false, false, true],
                vec![true, true, true, true, true, true, true],
            ];
            // all entropy should be ignored
            let initial_entropy = None;
            let entropy = vec![
                (
                    Some(vec![1u8; EpochData::<Curve>::ENTROPY_BYTES]),
                    Some(vec![2u8; EpochData::<Curve>::ENTROPY_BYTES]),
                ),
                (
                    Some(vec![2u8; EpochData::<Curve>::ENTROPY_BYTES]),
                    Some(vec![3u8; EpochData::<Curve>::ENTROPY_BYTES]),
                ),
                // parent entropy does not match previous entropy
                (
                    Some(vec![5u8; EpochData::<Curve>::ENTROPY_BYTES]),
                    Some(vec![4u8; EpochData::<Curve>::ENTROPY_BYTES]),
                ),
                (
                    Some(vec![4u8; EpochData::<Curve>::ENTROPY_BYTES]),
                    Some(vec![5u8; EpochData::<Curve>::ENTROPY_BYTES]),
                ),
            ];
            let include_dummy_epochs = false;

            assert!(test_epochs(
                num_faults,
                num_epochs,
                initial_entropy,
                entropy,
                bitmaps,
                include_dummy_epochs,
                None,
            ));
        }
    }
}
