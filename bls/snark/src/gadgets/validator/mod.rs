use algebra::{Group, Field, PairingEngine, ProjectiveCurve};
use r1cs_core::{ConstraintSystem, SynthesisError};
use r1cs_std::{
    fields::FieldGadget,
    groups::GroupGadget,
    pairing::PairingGadget,
    alloc::AllocGadget,
    eq::EqGadget,
    boolean::Boolean,
    select::CondSelectGadget,
};
pub struct ValidatorUpdateGadget<
    G: Group,
    ConstraintF: Field,
    GG: GroupGadget<G, ConstraintF>,
> {
}

impl<
        PairingE: PairingEngine,
        ConstraintF: Field,
        P: PairingGadget<PairingE, ConstraintF>,
    > BlsVerifyGadget<PairingE, ConstraintF, P>
{
    pub fn update<CS: ConstraintSystem<ConstraintF>>(
        mut cs: CS,
        old_pub_keys: Vec<P::G1Gadget>,
        new_pub_keys: Vec<P::G1Gadget>,
        removed_validators_bitmap: Vec<Boolean>,
    ) -> Result<Vec<P::G1Gadget>, SynthesisError> {
        assert_eq!(bitmap.len(), pub_keys.len());
        let zero = P::G1Gadget::zero(cs.ns(|| "init zero"))?;
        let mut aggregated_pk = zero.clone();
        for (i, pk) in pub_keys.iter().enumerate() {
            let selected_point = P::G1Gadget::conditionally_select(
                &mut cs.ns(|| "cond_select"),
                &bitmap[i],
                pk,
                &zero,
            )?;
            aggregated_pk = aggregated_pk.add(
                cs.ns(|| format!("add pk {}", i)),
                &selected_point,
            )?;
        }
        let prepared_aggregated_pk =
            P::prepare_g1(cs.ns(|| "prepared aggregaed pk"), &aggregated_pk)?;
        let prepared_message_hash =
            P::prepare_g2(cs.ns(|| "prepared message hash"), &message_hash)?;
        let prepared_signature = P::prepare_g2(cs.ns(|| "prepared signature"), &signature)?;
        let g1_neg_generator = P::G1Gadget::alloc(cs.ns(|| "G1 generator"), || {
            Ok(PairingE::G1Projective::prime_subgroup_generator())
        })?
        .negate(cs.ns(|| "negate g1 generator"))?;
        let prepared_g1_neg_generator =
            P::prepare_g1(cs.ns(|| "prepared g1 neg generator"), &g1_neg_generator)?;
        let bls_equation = P::product_of_pairings(
            cs.ns(|| "verify BLS signature"),
            &[prepared_g1_neg_generator, prepared_aggregated_pk],
            &[prepared_signature, prepared_message_hash],
        )?;
        let gt_one = &P::GTGadget::one(&mut cs.ns(|| "GT one"))?;
        bls_equation.enforce_equal(&mut cs.ns(|| "BLS equation is one"), gt_one)?;
        Ok(())
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
                G2Projective as Bls12_377G2Projective,
            },
            ProjectiveCurve,
        },
        fields::bls12_377::Fr as Bls12_377Fr,
        fields::sw6::Fr as SW6Fr,
        UniformRand,
    };
    use r1cs_core::ConstraintSystem;
    use r1cs_std::{
        groups::bls12::bls12_377::{G1Gadget as Bls12_377G1Gadget, G2Gadget as Bls12_377G2Gadget},
        pairing::bls12_377::PairingGadget as Bls12_377PairingGadget,
        test_constraint_system::TestConstraintSystem,
        alloc::AllocGadget,
    };

    use super::BlsVerifyGadget;

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

            BlsVerifyGadget::<Bls12_377, SW6Fr, Bls12_377PairingGadget>::verify(
                cs.ns(|| "verify sig"),
                [pub_key_var].to_vec(),
                message_hash_var,
                signature_var,
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

            BlsVerifyGadget::<Bls12_377, SW6Fr, Bls12_377PairingGadget>::verify(
                cs.ns(|| "verify sig"),
                [pub_key_var].to_vec(),
                message_hash_var,
                signature_var,
            ).unwrap();

            assert!(!cs.is_satisfied());
        }
    }
}
