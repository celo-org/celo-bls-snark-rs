use crate::Bitmap;
use ark_ec::{PairingEngine, ProjectiveCurve};
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocationMode, boolean::Boolean, eq::EqGadget, fields::fp::FpVar, fields::FieldVar,
    groups::CurveVar, pairing::PairingVar, R1CSVar,
};
use ark_relations::r1cs::SynthesisError;
use std::marker::PhantomData;
use std::ops::AddAssign;
use tracing::{debug, span, trace, Level};

/// BLS Signature Verification Gadget.
///
/// Implements BLS Verification as written in [BDN18](https://eprint.iacr.org/2018/483.pdf)
/// in a Pairing-based SNARK.
pub struct BlsVerifyGadget<E, F, P> {
    /// The curve being used
    pairing_engine_type: PhantomData<E>,
    /// The field we're operating on
    constraint_field_type: PhantomData<F>,
    /// The pairing gadget we use, which MUST match our pairing engine
    pairing_gadget_type: PhantomData<P>,
}

impl<E, F, P> BlsVerifyGadget<E, F, P>
where
    E: PairingEngine,
    F: PrimeField,
    P: PairingVar<E, F>,
    P::G2Var: for<'a> AddAssign<&'a P::G2Var>,
{
    /// Enforces verification of a BLS Signature against a list of public keys and a bitmap indicating
    /// which of these pubkeys signed.
    ///
    /// A maximum number of non_signers is also provided to
    /// indicate our threshold
    ///
    /// The verification equation can be found in pg.11 from
    /// https://eprint.iacr.org/2018/483.pdf: "Multi-Signature Verification"
    #[tracing::instrument(target = "r1cs")]
    pub fn verify(
        pub_keys: &[P::G2Var],
        signed_bitmap: &[Boolean<F>],
        message_hash: &P::G1Var,
        signature: &P::G1Var,
        maximum_non_signers: &FpVar<F>,
        padding_pk: &P::G2Var,
    ) -> Result<(), SynthesisError> {
        let span = span!(Level::TRACE, "BlsVerifyGadget_verify");
        let _enter = span.enter();
        // Get the message hash and the aggregated public key based on the bitmap
        // and allowed number of non-signers
        let (message_hash, aggregated_pk) = Self::enforce_bitmap(
            pub_keys,
            signed_bitmap,
            message_hash,
            maximum_non_signers,
            padding_pk,
        )?;

        let prepared_aggregated_pk = P::prepare_g2(&aggregated_pk)?;

        let prepared_message_hash = P::prepare_g1(&message_hash)?;

        // Prepare the signature and get the generator
        let (prepared_signature, prepared_g2_neg_generator) =
            Self::prepare_signature_neg_generator(&signature)?;

        // e(σ, g_2^-1) * e(H(m), apk) == 1_{G_T}
        Self::enforce_bls_equation(
            &[prepared_signature, prepared_message_hash],
            &[prepared_g2_neg_generator, prepared_aggregated_pk],
        )?;

        Ok(())
    }

    /// Enforces batch verification of a an aggregate BLS Signature against a
    /// list of (pubkey, message) tuples.
    ///
    /// The verification equation can be found in pg.11 from
    /// https://eprint.iacr.org/2018/483.pdf: "Batch verification"
    #[tracing::instrument(target = "r1cs")]
    pub fn batch_verify(
        aggregated_pub_keys: &[P::G2Var],
        message_hashes: &[P::G1Var],
        aggregated_signature: &P::G1Var,
    ) -> Result<(), SynthesisError> {
        debug!("batch verifying BLS signature");
        let prepared_message_hashes = message_hashes
            .iter()
            .map(|message_hash| P::prepare_g1(&message_hash))
            .collect::<Result<Vec<_>, _>>()?;
        let prepared_aggregated_pub_keys = aggregated_pub_keys
            .iter()
            .map(|pubkey| P::prepare_g2(&pubkey))
            .collect::<Result<Vec<_>, _>>()?;

        Self::batch_verify_prepared(
            &prepared_aggregated_pub_keys,
            &prepared_message_hashes,
            aggregated_signature,
        )
    }

    /// Batch verification against prepared messages
    #[tracing::instrument(target = "r1cs")]
    pub fn batch_verify_prepared(
        prepared_aggregated_pub_keys: &[P::G2PreparedVar],
        prepared_message_hashes: &[P::G1PreparedVar],
        aggregated_signature: &P::G1Var,
    ) -> Result<(), SynthesisError> {
        // Prepare the signature and get the generator
        let (prepared_signature, prepared_g2_neg_generator) =
            Self::prepare_signature_neg_generator(aggregated_signature)?;

        // Create the vectors which we'll batch verify
        let mut prepared_g1s = vec![prepared_signature];
        let mut prepared_g2s = vec![prepared_g2_neg_generator];
        prepared_g1s.extend_from_slice(&prepared_message_hashes);
        prepared_g2s.extend_from_slice(&prepared_aggregated_pub_keys);

        // Enforce the BLS check
        // e(σ, g_2^-1) * e(H(m0), pk_0) * e(H(m1), pk_1) ...  * e(H(m_n), pk_n)) == 1_{G_T}
        Self::enforce_bls_equation(&prepared_g1s, &prepared_g2s)?;

        Ok(())
    }

    /// Returns a gadget which checks that an aggregate pubkey is correctly calculated
    /// by the sum of the pub keys which had a 1 in the bitmap
    ///
    /// # Panics
    /// If signed_bitmap length != pub_keys length
    #[tracing::instrument(target = "r1cs")]
    pub fn enforce_aggregated_pubkeys(
        pub_keys: &[P::G2Var],
        signed_bitmap: &[Boolean<F>],
        padding_pk: &P::G2Var,
    ) -> Result<P::G2Var, SynthesisError> {
        // Bitmap and Pubkeys must be of the same length
        assert_eq!(signed_bitmap.len(), pub_keys.len());

        let mut aggregated_pk = P::G2Var::zero();
        for (pk, bit) in pub_keys.iter().zip(signed_bitmap) {
            // Disallow the padding pk
            pk.conditional_enforce_not_equal(padding_pk, bit)?;
            // If bit = 1, add pk
            let adder = bit.select(pk, &P::G2Var::zero())?;
            aggregated_pk += &adder;
        }

        Ok(aggregated_pk)
    }

    /// Returns a gadget which checks that an aggregate pubkey is correctly calculated
    /// by the sum of the pub keys
    #[tracing::instrument(target = "r1cs")]
    pub fn enforce_aggregated_all_pubkeys(
        pub_keys: &[P::G2Var],
    ) -> Result<P::G2Var, SynthesisError> {
        let mut aggregated_pk = P::G2Var::zero();
        for pk in pub_keys.iter() {
            // Add the pubkey to the sum
            // aggregated_pk += pk
            aggregated_pk += pk;
        }

        Ok(aggregated_pk)
    }

    /// Enforces that the provided bitmap contains no more than `maximum_non_signers`
    /// 0s. Also returns a gadget of the prepared message hash and a gadget for the aggregate public key
    ///
    /// # Panics
    /// If signed_bitmap length != pub_keys length (due to internal call to `enforced_aggregated_pubkeys`)
    #[tracing::instrument(target = "r1cs")]
    pub fn enforce_bitmap(
        pub_keys: &[P::G2Var],
        signed_bitmap: &[Boolean<F>],
        message_hash: &P::G1Var,
        maximum_non_signers: &FpVar<F>,
        padding_pk: &P::G2Var,
    ) -> Result<(P::G1Var, P::G2Var), SynthesisError> {
        trace!("enforcing bitmap");
        signed_bitmap.enforce_maximum_occurrences_in_bitmap(maximum_non_signers, false)?;

        let aggregated_pk = Self::enforce_aggregated_pubkeys(pub_keys, signed_bitmap, padding_pk)?;

        Ok((message_hash.clone(), aggregated_pk))
    }

    /// Verifying BLS signatures requires preparing a G1 Signature and
    /// preparing a negated G2 generator
    #[tracing::instrument(target = "r1cs")]
    fn prepare_signature_neg_generator(
        signature: &P::G1Var,
    ) -> Result<(P::G1PreparedVar, P::G2PreparedVar), SynthesisError> {
        // Ensure the signature is prepared
        let prepared_signature = P::prepare_g1(signature)?;

        // Allocate the generator on G2
        let g2_generator = P::G2Var::new_variable_omit_prime_order_check(
            signature.cs(),
            || Ok(E::G2Projective::prime_subgroup_generator()),
            AllocationMode::Constant,
        )?;
        // and negate it for the purpose of verification
        let g2_neg_generator = g2_generator.negate()?;
        let prepared_g2_neg_generator = P::prepare_g2(&g2_neg_generator)?;

        Ok((prepared_signature, prepared_g2_neg_generator))
    }

    /// Multiply the pairings together and check that their product == 1 in G_T, which indicates
    /// that the verification has passed.
    ///
    /// Each G1 element is paired with the corresponding G2 element.
    /// Fails if the 2 slices have different lengths.
    #[tracing::instrument(target = "r1cs")]
    fn enforce_bls_equation(
        g1: &[P::G1PreparedVar],
        g2: &[P::G2PreparedVar],
    ) -> Result<(), SynthesisError> {
        trace!("enforcing BLS equation");
        let bls_equation = P::product_of_pairings(g1, g2)?;
        let gt_one = &P::GTVar::one();
        bls_equation.enforce_equal(gt_one)?;
        Ok(())
    }
}

#[cfg(test)]
mod verify_one_message {
    use super::*;
    use crate::utils::test_helpers::{print_unsatisfied_constraints, run_profile_constraints};
    use bls_crypto::test_helpers::*;

    use ark_bls12_377::{
        constraints::{G1Var, G2Var, PairingVar as Bls12_377PairingGadget},
        Bls12_377, Fr as Bls12_377Fr, G1Projective, G2Projective,
    };
    use ark_bw6_761::Fr as BW6_761Fr;
    use ark_ec::ProjectiveCurve;
    use ark_ff::{One, UniformRand, Zero};
    use ark_r1cs_std::{alloc::AllocVar, boolean::Boolean};
    use ark_relations::r1cs::{ConstraintSystem, ConstraintSystemRef};

    // converts the arguments to constraints and checks them against the `verify` function
    #[tracing::instrument(target = "r1cs")]
    fn cs_verify<E: PairingEngine, F: PrimeField, P: PairingVar<E, F>>(
        message_hash: E::G1Projective,
        pub_keys: &[E::G2Projective],
        signature: E::G1Projective,
        bitmap: &[bool],
        num_non_signers: u64,
        padding_pk: &P::G2Var,
    ) -> ConstraintSystemRef<F> {
        let cs = ConstraintSystem::<F>::new_ref();

        let message_hash_var = P::G1Var::new_variable_omit_prime_order_check(
            cs.clone(),
            || Ok(message_hash),
            AllocationMode::Witness,
        )
        .unwrap();
        let signature_var = P::G1Var::new_variable_omit_prime_order_check(
            cs.clone(),
            || Ok(signature),
            AllocationMode::Witness,
        )
        .unwrap();

        let pub_keys = pub_keys
            .iter()
            .map(|pub_key| {
                P::G2Var::new_variable_omit_prime_order_check(
                    cs.clone(),
                    || Ok(*pub_key),
                    AllocationMode::Witness,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let bitmap = bitmap
            .iter()
            .map(|b| Boolean::new_witness(cs.clone(), || Ok(*b)).unwrap())
            .collect::<Vec<_>>();

        let max_occurrences =
            &FpVar::<F>::new_witness(cs.clone(), || Ok(F::from(num_non_signers))).unwrap();
        BlsVerifyGadget::<E, F, P>::verify(
            &pub_keys,
            &bitmap[..],
            &message_hash_var,
            &signature_var,
            &max_occurrences,
            padding_pk,
        )
        .unwrap();

        cs
    }

    #[test]
    fn batch_verify_ok() {
        run_profile_constraints(batch_verify_ok_inner);
    }
    #[tracing::instrument(target = "r1cs")]
    fn batch_verify_ok_inner() {
        // generate 5 (aggregate sigs, message hash pairs)
        // verify them all in 1 call
        let batch_size = 5;
        let num_keys = 7;
        let rng = &mut rand::thread_rng();

        // generate some random messages
        let messages = (0..batch_size)
            .map(|_| G1Projective::rand(rng))
            .collect::<Vec<_>>();
        // keygen for multiple rounds (7 keys per round)
        let (secret_keys, public_keys_batches) = keygen_batch::<Bls12_377>(batch_size, num_keys);
        // get the aggregate public key for each rounds
        let aggregate_pubkeys = public_keys_batches
            .iter()
            .map(|pks| sum(pks))
            .collect::<Vec<_>>();
        // the keys from each epoch sign the messages from the corresponding epoch
        let asigs = sign_batch::<Bls12_377>(&secret_keys, &messages);
        // get the complete aggregate signature
        let asig = sum(&asigs);

        // allocate the constraints
        let cs = ConstraintSystem::<BW6_761Fr>::new_ref();
        let messages = messages
            .iter()
            .map(|element| {
                G1Var::new_variable_omit_prime_order_check(
                    cs.clone(),
                    || Ok(*element),
                    AllocationMode::Witness,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let aggregate_pubkeys = aggregate_pubkeys
            .iter()
            .map(|element| {
                G2Var::new_variable_omit_prime_order_check(
                    cs.clone(),
                    || Ok(*element),
                    AllocationMode::Witness,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let asig = G1Var::new_variable_omit_prime_order_check(
            cs.clone(),
            || Ok(asig),
            AllocationMode::Witness,
        )
        .unwrap();

        // check that verification is correct
        BlsVerifyGadget::<Bls12_377, BW6_761Fr, Bls12_377PairingGadget>::batch_verify(
            &aggregate_pubkeys,
            &messages,
            &asig,
        )
        .unwrap();
        print_unsatisfied_constraints(cs.clone());
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    // Verifies signatures over BLS12_377 with Sw6 field (384 bits).
    fn one_signature_ok() {
        run_profile_constraints(one_signature_ok_inner);
    }
    // Verifies signatures over BLS12_377 with Sw6 field (384 bits).
    #[tracing::instrument(target = "r1cs")]
    fn one_signature_ok_inner() {
        let (secret_key, pub_key) = keygen::<Bls12_377>();
        let rng = &mut rng();
        let message_hash = G1Projective::rand(rng);
        let signature = message_hash.mul(secret_key.into_repr());
        let fake_signature = G1Projective::rand(rng);

        // good sig passes
        let cs = cs_verify::<Bls12_377, BW6_761Fr, Bls12_377PairingGadget>(
            message_hash,
            &[pub_key],
            signature,
            &[true],
            0,
            &G2Var::constant(G2Projective::prime_subgroup_generator()),
        );
        print_unsatisfied_constraints(cs.clone());
        assert!(cs.is_satisfied().unwrap());
        assert_eq!(cs.num_constraints(), 18702);

        // random sig fails
        let cs = cs_verify::<Bls12_377, BW6_761Fr, Bls12_377PairingGadget>(
            message_hash,
            &[pub_key],
            fake_signature,
            &[true],
            0,
            &G2Var::constant(G2Projective::prime_subgroup_generator()),
        );
        print_unsatisfied_constraints(cs.clone());
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn multiple_signatures_ok() {
        run_profile_constraints(multiple_signatures_ok_inner);
    }
    #[tracing::instrument(target = "r1cs")]
    fn multiple_signatures_ok_inner() {
        let rng = &mut rng();
        let message_hash = G1Projective::rand(rng);
        let (sk, pk) = keygen::<Bls12_377>();
        let (sk2, pk2) = keygen::<Bls12_377>();
        let (sigs, asig) = sign::<Bls12_377>(message_hash, &[sk, sk2]);

        // good aggregate sig passes
        let cs = cs_verify::<Bls12_377, BW6_761Fr, Bls12_377PairingGadget>(
            message_hash,
            &[pk, pk2],
            asig,
            &[true, true],
            1,
            &G2Var::constant(G2Projective::prime_subgroup_generator()),
        );
        print_unsatisfied_constraints(cs.clone());
        assert!(cs.is_satisfied().unwrap());

        // using the single sig if second guy is OK as long as
        // we tolerate 1 non-signers
        let cs = cs_verify::<Bls12_377, BW6_761Fr, Bls12_377PairingGadget>(
            message_hash,
            &[pk, pk2],
            sigs[0],
            &[true, false],
            1,
            &G2Var::constant(G2Projective::prime_subgroup_generator()),
        );
        print_unsatisfied_constraints(cs.clone());
        assert!(cs.is_satisfied().unwrap());

        // bitmap set to false on the second one fails since we don't tolerate
        // >0 failures
        let cs = cs_verify::<Bls12_377, BW6_761Fr, Bls12_377PairingGadget>(
            message_hash,
            &[pk, pk2],
            asig,
            &[true, false],
            0,
            &G2Var::constant(G2Projective::prime_subgroup_generator()),
        );
        print_unsatisfied_constraints(cs.clone());
        assert!(!cs.is_satisfied().unwrap());
        let cs = cs_verify::<Bls12_377, BW6_761Fr, Bls12_377PairingGadget>(
            message_hash,
            &[pk, pk2],
            sigs[0],
            &[true, false],
            0,
            &G2Var::constant(G2Projective::prime_subgroup_generator()),
        );
        print_unsatisfied_constraints(cs.clone());
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    #[should_panic]
    fn multiple_signatures_with_padding_in_activated_bit_location_fails() {
        run_profile_constraints(
            multiple_signatures_with_padding_in_activated_bit_location_fails_inner,
        );
    }
    #[tracing::instrument(target = "r1cs")]
    fn multiple_signatures_with_padding_in_activated_bit_location_fails_inner() {
        let rng = &mut rng();
        let message_hash = G1Projective::rand(rng);
        let (sk, pk) = (Bls12_377Fr::one(), G2Projective::prime_subgroup_generator());
        let (sk2, pk2) = keygen::<Bls12_377>();
        let (_, asig) = sign::<Bls12_377>(message_hash, &[sk, sk2]);

        // good aggregate sig passes
        let cs = cs_verify::<Bls12_377, BW6_761Fr, Bls12_377PairingGadget>(
            message_hash,
            &[pk, pk2],
            asig,
            &[true, true],
            1,
            &G2Var::constant(G2Projective::prime_subgroup_generator()),
        );
        print_unsatisfied_constraints(cs.clone());
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn zero_succeeds() {
        run_profile_constraints(zero_succeeds_inner);
    }
    #[tracing::instrument(target = "r1cs")]
    fn zero_succeeds_inner() {
        let rng = &mut rng();
        let message_hash = G1Projective::rand(rng);
        let generator = G2Projective::prime_subgroup_generator();

        // if the first key is a bad one, it should fail, since the pubkey
        // won't be on the curve
        let sk = Bls12_377Fr::zero();
        let pk = generator.clone().mul(sk.into_repr());
        let (sk2, pk2) = keygen::<Bls12_377>();

        let (sigs, _) = sign::<Bls12_377>(message_hash, &[sk, sk2]);

        let cs = cs_verify::<Bls12_377, BW6_761Fr, Bls12_377PairingGadget>(
            message_hash,
            &[pk, pk2],
            sigs[1],
            &[false, true],
            3,
            &G2Var::constant(G2Projective::prime_subgroup_generator()),
        );
        print_unsatisfied_constraints(cs.clone());
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn doubling_succeeds() {
        run_profile_constraints(doubling_succeeds_inner);
    }
    #[tracing::instrument(target = "r1cs")]
    fn doubling_succeeds_inner() {
        let rng = &mut rng();
        let message_hash = G1Projective::rand(rng);

        // if the first key is a bad one, it should fail, since the pubkey
        // won't be on the curve
        let (sk, pk) = keygen::<Bls12_377>();

        let (sigs, _) = sign::<Bls12_377>(message_hash, &[sk, sk]);

        let cs = cs_verify::<Bls12_377, BW6_761Fr, Bls12_377PairingGadget>(
            message_hash,
            &[pk, pk],
            sigs[0] + sigs[1],
            &[true, true],
            3,
            &G2Var::constant(G2Projective::prime_subgroup_generator()),
        );
        print_unsatisfied_constraints(cs.clone());
        assert!(cs.is_satisfied().unwrap());
    }
}
