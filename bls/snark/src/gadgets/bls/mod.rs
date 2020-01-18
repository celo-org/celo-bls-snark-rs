use algebra::{Field, PairingEngine, ProjectiveCurve, PrimeField};
use r1cs_core::{ConstraintSystem, SynthesisError, LinearCombination};
use r1cs_std::{
    Assignment,
    fields::{
        FieldGadget,
        fp::FpGadget,
    },
    groups::GroupGadget,
    pairing::PairingGadget,
    alloc::AllocGadget,
    eq::EqGadget,
    boolean::Boolean,
    select::CondSelectGadget,
};
use std::marker::PhantomData;
use crate::gadgets::smaller_than::SmallerThanGadget;

pub struct BlsVerifyGadget<
    PairingE: PairingEngine,
    ConstraintF: Field + PrimeField,
    P: PairingGadget<PairingE, ConstraintF>,
> {
    pairing_engine_type: PhantomData<PairingE>,
    constraint_field_type: PhantomData<ConstraintF>,
    pairing_type: PhantomData<P>,
}

impl<
    PairingE: PairingEngine,
    ConstraintF: Field + PrimeField,
    P: PairingGadget<PairingE, ConstraintF>,
> BlsVerifyGadget<PairingE, ConstraintF, P>
{
    pub fn verify<CS: ConstraintSystem<ConstraintF>>(
        mut cs: CS,
        pub_keys: &[P::G2Gadget],
        signed_bitmap: &[Boolean],
        message_hash: P::G1Gadget,
        signature: P::G1Gadget,
        maximum_non_signers: FpGadget<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        let (prepared_aggregated_pk, prepared_message_hash) = Self::verify_partial(
            cs.ns(|| "verify partial"),
            pub_keys,
            signed_bitmap,
            message_hash,
            maximum_non_signers,
        )?;
        let prepared_signature = P::prepare_g1(cs.ns(|| "prepared signature"), &signature)?;

        let g2_neg_generator = P::G2Gadget::alloc(cs.ns(|| "G2 generator"), || {
            Ok(PairingE::G2Projective::prime_subgroup_generator())
        })?
            .negate(cs.ns(|| "negate g2 generator"))?;
        let prepared_g2_neg_generator =
            P::prepare_g2(cs.ns(|| "prepared g2 neg generator"), &g2_neg_generator)?;
        let bls_equation = P::product_of_pairings(
            cs.ns(|| "verify BLS signature"),
            &[prepared_signature, prepared_message_hash],
            &[prepared_g2_neg_generator, prepared_aggregated_pk],
        )?;
        let gt_one = &P::GTGadget::one(&mut cs.ns(|| "GT one"))?;
        bls_equation.enforce_equal(&mut cs.ns(|| "BLS equation is one"), gt_one)?;

        Ok(())
    }

    pub fn batch_verify<CS: ConstraintSystem<ConstraintF>>(
        mut cs: CS,
        prepared_aggregated_pub_keys: &[P::G2PreparedGadget],
        prepared_message_hashes: &[P::G1PreparedGadget],
        aggregated_signature: P::G1Gadget,
    ) -> Result<(), SynthesisError> {
        let prepared_signature = P::prepare_g1(cs.ns(|| "prepared signature"), &aggregated_signature)?;

        let g2_neg_generator = P::G2Gadget::alloc(cs.ns(|| "G2 generator"), || {
            Ok(PairingE::G2Projective::prime_subgroup_generator())
        })?
            .negate(cs.ns(|| "negate g2 generator"))?;
        let prepared_g2_neg_generator =
            P::prepare_g2(cs.ns(|| "prepared g2 neg generator"), &g2_neg_generator)?;
        let mut prepared_g2s = vec![prepared_g2_neg_generator];
        prepared_g2s.extend_from_slice(prepared_aggregated_pub_keys);
        let mut prepared_g1s = vec![prepared_signature];
        prepared_g1s.extend_from_slice(prepared_message_hashes);
        let bls_equation = P::product_of_pairings(
            cs.ns(|| "verify BLS signature"),
            &prepared_g1s,
            &prepared_g2s,
        )?;
        let gt_one = &P::GTGadget::one(&mut cs.ns(|| "GT one"))?;
        bls_equation.enforce_equal(&mut cs.ns(|| "BLS equation is one"), gt_one)?;

        Ok(())
    }

    pub fn verify_partial<CS: ConstraintSystem<ConstraintF>>(
        mut cs: CS,
        pub_keys: &[P::G2Gadget],
        signed_bitmap: &[Boolean],
        message_hash: P::G1Gadget,
        maximum_non_signers: FpGadget<ConstraintF>,
    ) -> Result<(P::G2PreparedGadget, P::G1PreparedGadget), SynthesisError> {
        assert_eq!(signed_bitmap.len(), pub_keys.len());
        let generator = PairingE::G2Projective::prime_subgroup_generator();
        let generator_var =
            P::G2Gadget::alloc(cs.ns(|| "generator"), || Ok(generator))?;

        let mut aggregated_pk = generator_var.clone();

        let mut num_non_signers_num = Some(0);
        let mut num_non_signers_lc = LinearCombination::zero();
        for (i, pk) in pub_keys.iter().enumerate() {
            let added = aggregated_pk.add(
                cs.ns(|| format!("add pk {}", i)),
                pk,
            )?;

            aggregated_pk = P::G2Gadget::conditionally_select(
                &mut cs.ns(|| format!("cond_select {}", i)),
                &signed_bitmap[i],
                &added,
                &aggregated_pk,
            )?;

            if i == pub_keys.len() - 1 {
                aggregated_pk = aggregated_pk.sub(
                    cs.ns(|| "add neg generator"),
                    &generator_var,
                )?;
            }

            num_non_signers_lc += (ConstraintF::one(), CS::one());
            num_non_signers_lc = num_non_signers_lc + &signed_bitmap[i].lc(CS::one(), ConstraintF::one().neg());
            if signed_bitmap[i].get_value().is_none() {
                num_non_signers_num = None;
            }

            if num_non_signers_num.is_some() {
                num_non_signers_num = Some(num_non_signers_num.get()? + if signed_bitmap[i].get_value().get()? { 0 } else { 1 });
            }
        }

        let num_non_signers = FpGadget::alloc(
            &mut cs.ns(|| "num signers"),
            || Ok(ConstraintF::from(num_non_signers_num.get()? as u128))
        )?;

        SmallerThanGadget::<ConstraintF>::enforce_smaller_than(
            cs.ns(|| "enforce enough signers"),
            &num_non_signers,
            &maximum_non_signers,
        )?;

        let prepared_aggregated_pk =
            P::prepare_g2(cs.ns(|| "prepared aggregaed pk"), &aggregated_pk)?;
        let prepared_message_hash =
            P::prepare_g1(cs.ns(|| "prepared message hash"), &message_hash)?;

        Ok((prepared_aggregated_pk, prepared_message_hash))
    }
}

#[cfg(test)]
mod test {
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    use algebra::{
        curves::{
            bls12_377::{
                Bls12_377, G1Projective as Bls12_377G1Projective,
                G1Affine as Bls12_377G1Affine,
                G2Projective as Bls12_377G2Projective,
            },
            AffineCurve,
            ProjectiveCurve,
        },
        fields::bls12_377::Fr as Bls12_377Fr,
        fields::sw6::Fr as SW6Fr,
        fields::Field,
        UniformRand,
    };
    use r1cs_core::ConstraintSystem;
    use r1cs_std::{
        groups::bls12::bls12_377::{G1Gadget as Bls12_377G1Gadget, G2Gadget as Bls12_377G2Gadget},
        pairing::bls12_377::PairingGadget as Bls12_377PairingGadget,
        test_constraint_system::TestConstraintSystem,
        alloc::AllocGadget,
        boolean::Boolean,
        fields::FieldGadget,
    };

    use super::BlsVerifyGadget;
    use r1cs_std::fields::fp::FpGadget;
    use std::str::FromStr;
    use crate::gadgets::smaller_than::SmallerThanGadget;
    use crate::gadgets::alloc_conditional_check::AllocPointConditionalGadget;

    #[test]
    fn test_signature() {
        let rng = &mut XorShiftRng::from_seed([0x5d, 0xbe, 0x62, 0x59, 0x8d, 0x31, 0x3d, 0x76, 0x32, 0x37, 0xdb, 0x17, 0xe5, 0xbc, 0x06, 0x54]);
        let message_hash = Bls12_377G2Projective::rand(rng);
        let secret_key = Bls12_377Fr::rand(rng);

        let generator = Bls12_377G1Projective::prime_subgroup_generator();
        let pub_key = generator * &secret_key;
        let signature = message_hash * &secret_key;
        let fake_signature = Bls12_377G2Projective::rand(rng);

        {
            let mut cs = TestConstraintSystem::<SW6Fr>::new();
            let message_hash_var =
                Bls12_377G2Gadget::alloc(cs.ns(|| "message_hash"), || Ok(message_hash)).unwrap();
            let pub_key_var =
                Bls12_377G1Gadget::alloc(cs.ns(|| "pub_key"), || Ok(pub_key)).unwrap();
            let signature_var =
                Bls12_377G2Gadget::alloc(cs.ns(|| "signature"), || Ok(signature)).unwrap();

            let bitmap = vec![Boolean::constant(true)];
            let maximum_non_signers_plus_one = FpGadget::alloc(
                cs.ns(|| "maximum non signers plus one"),
                || Ok(SW6Fr::from_str("1").unwrap()),
            ).unwrap();
            BlsVerifyGadget::<Bls12_377, SW6Fr, Bls12_377PairingGadget>::verify(
                cs.ns(|| "verify sig"),
                &[pub_key_var],
                &bitmap,
                message_hash_var,
                signature_var,
                maximum_non_signers_plus_one,
            ).unwrap();

            println!("number of constraints: {}", cs.num_constraints());

            assert!(cs.is_satisfied());
        }
        {
            let mut cs = TestConstraintSystem::<SW6Fr>::new();
            let message_hash_var =
                Bls12_377G2Gadget::alloc(cs.ns(|| "message_hash"), || Ok(message_hash)).unwrap();
            let pub_key_var =
                Bls12_377G1Gadget::alloc(cs.ns(|| "pub_key"), || Ok(pub_key)).unwrap();
            let signature_var =
                Bls12_377G2Gadget::alloc(cs.ns(|| "signature"), || Ok(fake_signature)).unwrap();

            let bitmap = vec![Boolean::constant(true)];
            let maximum_non_signers_plus_one = FpGadget::alloc(
                cs.ns(|| "maximum non signers plus one"),
                || Ok(SW6Fr::from_str("1").unwrap()),
            ).unwrap();
            BlsVerifyGadget::<Bls12_377, SW6Fr, Bls12_377PairingGadget>::verify(
                cs.ns(|| "verify sig"),
                &[pub_key_var],
                &bitmap,
                message_hash_var,
                signature_var,
                maximum_non_signers_plus_one,
            ).unwrap();

            assert!(!cs.is_satisfied());
        }
    }

    #[test]
    fn test_signature_bitmap() {
        let rng = &mut XorShiftRng::from_seed([0x5d, 0xbe, 0x62, 0x59, 0x8d, 0x31, 0x3d, 0x76, 0x32, 0x37, 0xdb, 0x17, 0xe5, 0xbc, 0x06, 0x54]);
        let message_hash = Bls12_377G2Projective::rand(rng);
        let secret_key = Bls12_377Fr::rand(rng);
        let secret_key2 = Bls12_377Fr::rand(rng);

        let generator = Bls12_377G1Projective::prime_subgroup_generator();
        let pub_key = generator.clone() * &secret_key;
        let pub_key2 = generator.clone() * &secret_key2;
        let signature = message_hash.clone() * &secret_key;
        let signature2 = message_hash.clone() * &secret_key2;
        let aggregated_signature = signature + &signature2;

        {
            let mut cs = TestConstraintSystem::<SW6Fr>::new();
            let message_hash_var =
                Bls12_377G2Gadget::alloc(cs.ns(|| "message_hash"), || Ok(message_hash)).unwrap();
            let pub_key_var =
                Bls12_377G1Gadget::alloc(cs.ns(|| "pub_key"), || Ok(pub_key)).unwrap();
            let pub_key2_var =
                Bls12_377G1Gadget::alloc(cs.ns(|| "pub_key2"), || Ok(pub_key2)).unwrap();
            let signature_var =
                Bls12_377G2Gadget::alloc(cs.ns(|| "aggregated signature"), || Ok(aggregated_signature)).unwrap();

            let bitmap = vec![Boolean::constant(true), Boolean::constant(true)];
            let maximum_non_signers_plus_one = FpGadget::alloc(
                cs.ns(|| "maximum non signers plus one"),
                || Ok(SW6Fr::from_str("1").unwrap()),
            ).unwrap();
            BlsVerifyGadget::<Bls12_377, SW6Fr, Bls12_377PairingGadget>::verify(
                cs.ns(|| "verify sig"),
                &[pub_key_var, pub_key2_var],
                &bitmap,
                message_hash_var,
                signature_var,
                maximum_non_signers_plus_one,
            ).unwrap();

            println!("number of constraints: {}", cs.num_constraints());

            assert!(cs.is_satisfied());
        }

        {
            let mut cs = TestConstraintSystem::<SW6Fr>::new();
            let message_hash_var =
                Bls12_377G2Gadget::alloc(cs.ns(|| "message_hash"), || Ok(message_hash)).unwrap();
            let pub_key_var =
                Bls12_377G1Gadget::alloc(cs.ns(|| "pub_key"), || Ok(pub_key)).unwrap();
            let pub_key2_var =
                Bls12_377G1Gadget::alloc(cs.ns(|| "pub_key2"), || Ok(pub_key2)).unwrap();
            let signature_var =
                Bls12_377G2Gadget::alloc(cs.ns(|| "aggregated signature"), || Ok(aggregated_signature)).unwrap();

            let bitmap = vec![Boolean::constant(true), Boolean::constant(false)];
            let maximum_non_signers_plus_one = FpGadget::alloc(
                cs.ns(|| "maximum non signers plus one"),
                || Ok(SW6Fr::from_str("1").unwrap()),
            ).unwrap();
            BlsVerifyGadget::<Bls12_377, SW6Fr, Bls12_377PairingGadget>::verify(
                cs.ns(|| "verify sig"),
                &[pub_key_var, pub_key2_var],
                &bitmap,
                message_hash_var,
                signature_var,
                maximum_non_signers_plus_one,
            ).unwrap();

            println!("number of constraints: {}", cs.num_constraints());

            assert!(!cs.is_satisfied());
        }

        {
            let mut cs = TestConstraintSystem::<SW6Fr>::new();
            let message_hash_var =
                Bls12_377G2Gadget::alloc(cs.ns(|| "message_hash"), || Ok(message_hash)).unwrap();
            let pub_key_var =
                Bls12_377G1Gadget::alloc(cs.ns(|| "pub_key"), || Ok(pub_key)).unwrap();
            let pub_key2_var =
                Bls12_377G1Gadget::alloc(cs.ns(|| "pub_key2"), || Ok(pub_key2)).unwrap();
            let signature_var =
                Bls12_377G2Gadget::alloc(cs.ns(|| "signature"), || Ok(signature)).unwrap();

            let bitmap = vec![Boolean::constant(true), Boolean::constant(false)];
            let maximum_non_signers_plus_one = FpGadget::alloc(
                cs.ns(|| "maximum non signers plus one"),
                || Ok(SW6Fr::from_str("2").unwrap()),
            ).unwrap();
            BlsVerifyGadget::<Bls12_377, SW6Fr, Bls12_377PairingGadget>::verify(
                cs.ns(|| "verify sig"),
                &[pub_key_var, pub_key2_var],
                &bitmap,
                message_hash_var,
                signature_var,
                maximum_non_signers_plus_one,
            ).unwrap();

            println!("number of constraints: {}", cs.num_constraints());

            assert!(cs.is_satisfied());
        }

        {
            let mut cs = TestConstraintSystem::<SW6Fr>::new();
            let message_hash_var =
                Bls12_377G2Gadget::alloc(cs.ns(|| "message_hash"), || Ok(message_hash)).unwrap();
            let pub_key_var =
                Bls12_377G1Gadget::alloc(cs.ns(|| "pub_key"), || Ok(pub_key)).unwrap();
            let pub_key2_var =
                Bls12_377G1Gadget::alloc(cs.ns(|| "pub_key2"), || Ok(pub_key2)).unwrap();
            let signature_var =
                Bls12_377G2Gadget::alloc(cs.ns(|| "signature"), || Ok(signature)).unwrap();

            let bitmap = vec![Boolean::constant(true), Boolean::constant(false)];
            let maximum_non_signers_plus_one = FpGadget::alloc(
                cs.ns(|| "maximum non signers plus one"),
                || Ok(SW6Fr::from_str("3").unwrap()),
            ).unwrap();
            BlsVerifyGadget::<Bls12_377, SW6Fr, Bls12_377PairingGadget>::verify(
                cs.ns(|| "verify sig"),
                &[pub_key_var, pub_key2_var],
                &bitmap,
                message_hash_var,
                signature_var,
                maximum_non_signers_plus_one,
            ).unwrap();

            println!("number of constraints: {}", cs.num_constraints());

            assert!(cs.is_satisfied());
        }
    }

    #[test]
    fn test_signature_zero() {
        let rng = &mut XorShiftRng::from_seed([0x5d, 0xbe, 0x62, 0x59, 0x8d, 0x31, 0x3d, 0x76, 0x32, 0x37, 0xdb, 0x17, 0xe5, 0xbc, 0x06, 0x54]);
        let message_hash = Bls12_377G2Projective::rand(rng);
        let secret_key = Bls12_377Fr::zero();
        let secret_key2 = Bls12_377Fr::rand(rng);

        let generator = Bls12_377G1Projective::prime_subgroup_generator();
        let pub_key = generator.clone() * &secret_key;
        let pub_key2 = generator * &secret_key2;
        let signature = message_hash.clone() * &secret_key;
        let signature2 = message_hash * &secret_key2;

        {
            let mut cs = TestConstraintSystem::<SW6Fr>::new();
            let message_hash_var =
                Bls12_377G2Gadget::alloc(cs.ns(|| "message_hash"), || Ok(message_hash)).unwrap();
            let pub_key_var =
                Bls12_377G1Gadget::alloc(cs.ns(|| "pub_key"), || Ok(pub_key)).unwrap();
            let pub_key2_var =
                Bls12_377G1Gadget::alloc(cs.ns(|| "pub_key2"), || Ok(pub_key2)).unwrap();
            let signature_var =
                Bls12_377G2Gadget::alloc(cs.ns(|| "signature"), || Ok(signature2)).unwrap();

            let bitmap = vec![Boolean::constant(false), Boolean::constant(true)];
            let maximum_non_signers_plus_one = FpGadget::alloc(
                cs.ns(|| "maximum non signers plus one"),
                || Ok(SW6Fr::from_str("2").unwrap()),
            ).unwrap();
            BlsVerifyGadget::<Bls12_377, SW6Fr, Bls12_377PairingGadget>::verify(
                cs.ns(|| "verify sig"),
                &[pub_key_var, pub_key2_var],
                &bitmap,
                message_hash_var,
                signature_var,
                maximum_non_signers_plus_one,
            ).unwrap();

            println!("number of constraints: {}", cs.num_constraints());

            assert!(cs.is_satisfied());
        }

        {
            let mut cs = TestConstraintSystem::<SW6Fr>::new();
            let message_hash_var =
                Bls12_377G2Gadget::alloc(cs.ns(|| "message_hash"), || Ok(message_hash)).unwrap();
            let pub_key_var =
                Bls12_377G1Gadget::alloc(cs.ns(|| "pub_key"), || Ok(pub_key)).unwrap();
            let pub_key2_var =
                Bls12_377G1Gadget::alloc(cs.ns(|| "pub_key2"), || Ok(pub_key2)).unwrap();
            let signature_var =
                Bls12_377G2Gadget::alloc(cs.ns(|| "signature"), || Ok(signature2)).unwrap();

            let bitmap = vec![Boolean::constant(false), Boolean::constant(true)];
            let maximum_non_signers_plus_one = FpGadget::alloc(
                cs.ns(|| "maximum non signers plus one"),
                || Ok(SW6Fr::from_str("2").unwrap()),
            ).unwrap();
            BlsVerifyGadget::<Bls12_377, SW6Fr, Bls12_377PairingGadget>::verify(
                cs.ns(|| "verify sig"),
                &[pub_key_var, pub_key2_var],
                &bitmap,
                message_hash_var,
                signature_var,
                maximum_non_signers_plus_one,
            ).unwrap();

            println!("number of constraints: {}", cs.num_constraints());

            assert!(cs.is_satisfied());
        }
    }
}
