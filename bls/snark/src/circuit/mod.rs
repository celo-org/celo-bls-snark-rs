use algebra::{fields::{
    PrimeField,
    sw6::{Fr, FrParameters},
    bls12_377::{Fr as BlsFr, FrParameters as BlsFrParameters},
}, curves::{
    ProjectiveCurve,
    bls12_377::{
        Bls12_377,
        G1Projective,
        G2Projective,
    }
}, FpParameters, ToBytes, FromBytes, biginteger::BigInteger};
use r1cs_core::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};
use crate::gadgets::{
    hash_to_group::HashToGroupGadget,
    y_to_bit::YToBitGadget,
    validator::ValidatorUpdateGadget,
    bls::BlsVerifyGadget,
};
use r1cs_std::{Assignment, eq::EqGadget, alloc::AllocGadget, groups::{
    GroupGadget,
    curves::short_weierstrass::bls12::{G1Gadget, G2Gadget}
}, ToBitsGadget, fields::{
    FieldGadget,
    fp::FpGadget,
}, pairing::bls12_377::PairingGadget};
use algebra::curves::bls12_377::Bls12_377Parameters;
use r1cs_std::bits::boolean::Boolean;
use r1cs_std::bits::uint32::UInt32;
use crate::gadgets::hash_to_group::{MultipackGadget, HashToBitsGadget};
use groth16::{Proof, VerifyingKey};
use crypto_primitives::nizk::{
    constraints::NIZKVerifierGadget,
    groth16::{
        Groth16,
        constraints::{Groth16VerifierGadget, ProofGadget, VerifyingKeyGadget}
    }
};
use crate::encoding::{bits_to_bytes, bytes_to_bits};
use bls_zexe::{
    curve::hash::try_and_increment::TryAndIncrement,
    hash::{
        XOF,
        composite::CompositeHasher
    }
};
use bls_zexe::bls::keys::SIG_DOMAIN;
use r1cs_std::bits::uint8::UInt8;
use bls_zexe::curve::hash::HashToG2;
use crypto_primitives::FixedLengthCRHGadget;
use bls_zexe::hash::composite::CRH;
use r1cs_std::groups::curves::twisted_edwards::edwards_sw6::EdwardsSWGadget;
use algebra::curves::edwards_sw6::EdwardsProjective;
use crypto_primitives::crh::bowe_hopwood::constraints::BoweHopwoodPedersenCRHGadget;

type CRHGadget = BoweHopwoodPedersenCRHGadget<EdwardsProjective, Fr, EdwardsSWGadget>;

#[derive(Clone)]
pub struct HashToBits {
    pub message_bits: Vec<Vec<Option<bool>>>,
    pub hash_batch_size: usize,
}

impl ConstraintSynthesizer<BlsFr> for HashToBits {
    fn generate_constraints<CS: ConstraintSystem<BlsFr>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        for i in 0..self.hash_batch_size {
            let bits = self.message_bits[i].iter().enumerate().map(|(j, b)| Boolean::alloc(
                cs.ns(|| format!("{}: bit {}", i, j)),
                || b.ok_or(SynthesisError::AssignmentMissing)
            )).collect::<Vec<_>>();
            let bits = if bits.iter().any(|x| x.is_err()) {
                Err(SynthesisError::AssignmentMissing)
            } else {
                let bits_bools = bits.into_iter().map(|b| b.unwrap()).collect::<Vec<_>>();
                if bits_bools.iter().all(|b| b.get_value().is_some()) {
                    let epoch_bytes = bits_to_bytes(&bits_bools.iter().map(|b| b.get_value().unwrap()).collect::<Vec<_>>());
                    //println!("hash to bits bytes: {}", hex::encode(&epoch_bytes));
                }
                Ok(bits_bools)
            }?;
            let packed_message = MultipackGadget::pack(
                cs.ns(|| format!("{}: pack message", i)),
                &bits,
                BlsFrParameters::CAPACITY as usize,
                true,
            )?;
            packed_message.iter().for_each(|b| {
                if b.value.is_some() {
                    //println!("hash to bits message: {}", b.value.unwrap());
                }
            });
            let hash = HashToBitsGadget::hash_to_bits(
                cs.ns(|| format!("{}: hash to bits", i)),
                &packed_message,
                bits.len(),
                BlsFrParameters::CAPACITY as usize,
                BlsFrParameters::CAPACITY as usize,
            )?;
            hash.iter().for_each(|b| {
                if b.value.is_some() {
                    //println!("hash to bits hash: {}", b.value.unwrap());
                }
            });
        }
        println!("num constraints: {}", cs.num_constraints());
        Ok(())
    }
}

#[derive(Clone)]
pub struct SingleUpdate {
    pub maximum_non_signers: Option<u32> ,
    pub new_pub_keys: Vec<Option<G1Projective>>,
    pub signed_bitmap: Vec<Option<bool>>,
    pub signature: Option<G2Projective>,
}

#[derive(Clone)]
pub struct HashProof {
    pub proof: Proof<Bls12_377>,
}

#[derive(Clone)]
pub struct ValidatorSetUpdate {
    pub initial_public_keys: Vec<Option<G1Projective>>,
    pub initial_maximum_non_signers: Option<u32> ,
    pub num_validators: usize,
    pub hash_batch_size: usize,
    pub hash_proofs: Vec<HashProof>,
    pub updates: Vec<SingleUpdate>,
    pub packed_size: usize,
    pub verifying_key: VerifyingKey<Bls12_377>,
}

impl ConstraintSynthesizer<Fr> for ValidatorSetUpdate {
    fn generate_constraints<CS: ConstraintSystem<Fr>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let composite_hasher = CompositeHasher::new().unwrap();
        let try_and_increment = TryAndIncrement::new(&composite_hasher);

        let crh_params =
            <CRHGadget as FixedLengthCRHGadget<CRH, Fr>>::ParametersGadget::alloc(
                &mut cs.ns(|| "pedersen parameters"),
                || {
                    match CompositeHasher::setup_crh() {
                        Ok(x) => Ok(x),
                        Err(e) => {
                            println!("error: {}", e);
                            Err(SynthesisError::AssignmentMissing)
                        },
                    }
                }
            )?;

        let verifying_key = VerifyingKeyGadget::<_, _, PairingGadget>::alloc(
            cs.ns(|| "allocate verifying key"),
            || Ok(self.verifying_key.clone()),
        )?;
        let mut current_pub_keys_vars = vec![];
        for (j, maybe_pk) in self.initial_public_keys.iter().enumerate() {
            let pk_var = G1Gadget::<Bls12_377Parameters>::alloc_input(
                cs.ns(|| format!("initial: pub key {}", j)),
                || maybe_pk.clone().ok_or(SynthesisError::AssignmentMissing)
            )?;
            current_pub_keys_vars.push(pk_var);
        }
        let mut current_maximum_non_signers = FpGadget::<Fr>::alloc_input(
            cs.ns(|| "initial: maximum non signers"),
            || {
                let non_signers = self.initial_maximum_non_signers.ok_or(SynthesisError::AssignmentMissing)?;
                Ok(Fr::from_repr(<FrParameters as FpParameters>::BigInt::from(non_signers as u64)))
            },
        )?;
        let mut prepared_aggregated_public_keys = vec![];
        let mut prepared_message_hashes = vec![];
        let mut aggregated_signature = None;
        for (c, chunk) in self.updates.chunks(self.hash_batch_size).enumerate() {
            let mut public_inputs = vec![];
            for (i, update) in chunk.into_iter().enumerate() {
                let mut new_pub_keys_vars = vec![];
                {
                    assert_eq!(self.num_validators, update.new_pub_keys.len());
                    for (j, maybe_pk) in update.new_pub_keys.iter().enumerate() {
                        let pk_var = G1Gadget::<Bls12_377Parameters>::alloc(
                            cs.ns(|| format!("{}, {}: new pub key {}", c, i, j)),
                            || maybe_pk.clone().ok_or(SynthesisError::AssignmentMissing)
                        )?;
                        new_pub_keys_vars.push(pk_var);
                    }
                }
                let maximum_non_signers = FpGadget::<Fr>::alloc(
                    cs.ns(|| format!("{}, {}: maximum non signers", c, i)),
                    || {
                        let non_signers = update.maximum_non_signers.ok_or(SynthesisError::AssignmentMissing)?;
                        Ok(Fr::from_repr(<FrParameters as FpParameters>::BigInt::from(non_signers as u64)))
                    },
                )?;
                let signed_bitmap = update.signed_bitmap.iter().enumerate().map(|(j, b)| Boolean::alloc(
                    cs.ns(|| format!("{}, {}: signed bitmap {}", c, i, j)),
                    || b.ok_or(SynthesisError::AssignmentMissing)
                )).collect::<Vec<_>>();
                let signed_bitmap = if signed_bitmap.iter().any(|b| b.is_err()) {
                    Err(SynthesisError::Unsatisfiable)
                } else {
                    Ok(signed_bitmap.iter().map(|b| b.as_ref().unwrap().clone()).collect::<Vec<_>>())
                }?;
                let signature = G2Gadget::<Bls12_377Parameters>::alloc(
                    cs.ns(|| format!("{}, {}: signature", c, i)),
                    || update.signature.ok_or(SynthesisError::AssignmentMissing)
                )?;

                let mut epoch_bits = vec![];

                let maximum_non_signers_bits = maximum_non_signers.to_bits(
                    cs.ns(|| format!("{}, {}: maximum non signers bits", c, i))
                )?;
                let maximum_non_signers_bits = maximum_non_signers_bits.into_iter().rev().take(32).collect::<Vec<_>>();
                epoch_bits.extend_from_slice(&maximum_non_signers_bits);
                let validator_set_bits = ValidatorUpdateGadget::<Bls12_377Parameters>::to_bits(
                    cs.ns(|| format!("{}, {}: validator set to bits", c, i)),
                    new_pub_keys_vars.clone(),
                )?;
                epoch_bits.extend_from_slice(&validator_set_bits);


//                println!("num constraints: {}", cs.num_constraints());
//                let packed_message_xof_bits = HashToBitsGadget::hash_to_bits(
//                    cs.ns(|| format!("{}: hash to bits", i)),
//                    &packed_message,
//                    epoch_bits.len(),
//                )?;
                let xof_target_bits = 768;
                let attempt_val: u8 = {
                    if epoch_bits.iter().any(|x| x.get_value().is_none()) {
                        0
                    } else {
                        let epoch_bytes = bits_to_bytes(&epoch_bits.iter().map(|b| b.get_value().unwrap()).collect::<Vec<_>>());
                        let (_, attempt_val) = try_and_increment.hash_with_attempt::<Bls12_377Parameters>(SIG_DOMAIN, &epoch_bytes, &[]).unwrap();
                        attempt_val as u8
                    }
                };
                let attempt = UInt8::alloc(
                    cs.ns(|| format!("{}, {}: attempt", c, i)),
                    || Ok(attempt_val),
                )?;
                let epoch_bits = &[
                    epoch_bits.as_slice(),
                    attempt.into_bits_le().into_iter().rev().collect::<Vec<_>>().as_slice(),
                ].concat().to_vec();

                let input_bytes: Vec<UInt8> = epoch_bits.into_iter().map(|b| b.clone()).rev().collect::<Vec<_>>().chunks(8).map(|chunk| {
                    let mut chunk_padded = chunk.clone().to_vec();
                    if chunk_padded.len() < 8 {
                        chunk_padded.resize(8, Boolean::constant(false));
                    }
                    UInt8::from_bits_le(&chunk_padded)
                }).collect();

                let crh_result = <CRHGadget as FixedLengthCRHGadget<CRH, Fr>>::check_evaluation_gadget(
                    &mut cs.ns(|| format!("{}, {}: pedersen evaluation", c, i)),
                    &crh_params,
                    &input_bytes,
                )?;

                let mut crh_bits = crh_result.x.to_bits(
                    cs.ns(|| format!("{}, {}: crh bits", c, i)),
                )?;

                let crh_bits_len = crh_bits.len();
                let crh_bits_len_rounded = ((crh_bits_len + 7)/8)*8;


                let mut first_bits = crh_bits[0..8 - (crh_bits_len_rounded - crh_bits_len)].to_vec();
                first_bits.reverse();
                let mut crh_bits= crh_bits[8 - (crh_bits_len_rounded - crh_bits_len)..].to_vec();

                crh_bits.reverse();
                crh_bits.extend_from_slice(&first_bits);
                for i in 0..(crh_bits_len_rounded - crh_bits_len) {
                    crh_bits.push(Boolean::constant(false));
                }

                //let crh_bits = crh_bits.chunks(8).rev().flatten().map(|b| b.clone()).collect::<Vec<_>>();
                let crh_bits = crh_bits.iter().rev().map(|b| b.clone()).collect::<Vec<_>>();

                let packed_message = crh_bits.chunks(BlsFrParameters::CAPACITY as usize).into_iter().map(|b| {
                    b.iter().rev().map(|z| z.clone()).collect::<Vec<_>>()
                }).collect::<Vec<_>>();

                public_inputs.extend_from_slice(&packed_message);

                let modulus_bit_rounded = (((FrParameters::MODULUS_BITS + 7)/8)*8) as usize;
                let packed_xof_bits = if epoch_bits.iter().any(|x| x.get_value().is_none()) {
                    let hash_bits = vec![false; xof_target_bits];
                    let hash_bits_vec = [
                        &hash_bits[..FrParameters::MODULUS_BITS as usize], //.iter().rev().map(|b| *b).collect::<Vec<bool>>()[..],
                        &hash_bits[modulus_bit_rounded..modulus_bit_rounded+FrParameters::MODULUS_BITS as usize],
                        &[hash_bits[modulus_bit_rounded+FrParameters::MODULUS_BITS as usize]][..],
                    ].concat().chunks(BlsFrParameters::CAPACITY as usize).into_iter().map(|x| x.to_vec()).collect::<Vec<_>>();
                    hash_bits_vec
                } else {
                    let epoch_bytes = bits_to_bytes(&epoch_bits.iter().map(|b| b.get_value().unwrap()).collect::<Vec<_>>());
                    let crh_bytes = composite_hasher.crh( SIG_DOMAIN, &epoch_bytes, xof_target_bits/8).unwrap();
                    let hash = composite_hasher.xof( SIG_DOMAIN, &crh_bytes, xof_target_bits/8).unwrap();
                    let hash_bits = bytes_to_bits(&hash, xof_target_bits).iter().rev().map(|b| *b).collect::<Vec<bool>>();
                    let hash_bits = &[
                        &hash_bits[..FrParameters::MODULUS_BITS as usize], //.iter().rev().map(|b| *b).collect::<Vec<bool>>()[..],
                        &hash_bits[modulus_bit_rounded..modulus_bit_rounded+FrParameters::MODULUS_BITS as usize],
                        &[hash_bits[modulus_bit_rounded+FrParameters::MODULUS_BITS as usize]][..],
                    ].concat().to_vec();
                    let fp_chunks = hash_bits.chunks(BlsFrParameters::CAPACITY as usize).into_iter().map(|bs| {
                        bs.iter().map(|z| z.clone()).collect::<Vec<_>>()
                    }).collect::<Vec<_>>();
                    fp_chunks
                };
                let xof_bits_results = packed_xof_bits.iter().enumerate().map(|(k, x)| {
                    Vec::<Boolean>::alloc(
                        cs.ns(|| format!("{}, {}: allocate xof bits {}", c, i, k)),
                        || Ok(x.clone()),
                    )
                }).collect::<Vec<_>>();
                let xof_bits_packed = if xof_bits_results.iter().any(|x| x.is_err()) {
                    Err(SynthesisError::Unsatisfiable)
                } else {
                    Ok(xof_bits_results.into_iter().map(|x| x.unwrap()).collect::<Vec<_>>())
                }?;
                public_inputs.extend_from_slice(&xof_bits_packed.iter().map(|x| {{
                    x.iter().rev().map(|y| y.clone()).collect::<Vec<_>>()
                }}).collect::<Vec<_>>());
                for public_input in public_inputs.iter() {
                    if public_input.iter().all(|x| x.get_value().is_some()) {
                        let bools = public_input.iter().map(|b| b.get_value().unwrap()).collect::<Vec<_>>();
                        let bytes = bits_to_bytes(&bools);
                        let bytes_reverse = bits_to_bytes(&bools.into_iter().rev().collect::<Vec<_>>());
                    }
                }

                let message_hash = HashToGroupGadget::hash_to_group(
                    cs.ns(|| format!("{}, {}: hash to group", c, i)),
                    &xof_bits_packed.into_iter().map(|b| b.clone()).flatten().collect::<Vec<_>>(),
                    BlsFrParameters::CAPACITY as usize,
                )?;

                let (prepared_aggregated_public_key, prepared_message_hash) = BlsVerifyGadget::<Bls12_377, Fr, PairingGadget>::verify_partial(
                    cs.ns(|| format!("{}, {}: verify signature", c, i)),
                    &current_pub_keys_vars,
                    signed_bitmap.as_slice(),
                    message_hash,
                    current_maximum_non_signers.clone(),
                )?;
                prepared_aggregated_public_keys.push(prepared_aggregated_public_key);
                prepared_message_hashes.push(prepared_message_hash);
                if aggregated_signature.is_none() {
                    aggregated_signature = Some(signature);
                } else {
                    aggregated_signature = Some(aggregated_signature.unwrap().add(
                        cs.ns(|| format!("{}, {}: add signature", c, i)),
                        &signature,
                    )?);
                }

                current_pub_keys_vars = new_pub_keys_vars;
                current_maximum_non_signers = maximum_non_signers;
            }
            let proof = ProofGadget::<_, _, PairingGadget>::alloc::<_, Proof<Bls12_377>, _>(
                cs.ns(|| format!("alloc proof {}", c)),
                || Ok(self.hash_proofs[c].proof.clone()),
            )?;
            /*
            if public_inputs.iter().all(|p| p.get_value().is_some()) {
                public_inputs.iter().for_each(|p| {
                    println!("attempt public input: {}", p.get_value().unwrap());
                });
            }
            */
            //println!("public input len: {}", public_inputs.len());
            <Groth16VerifierGadget::<_, _, PairingGadget> as NIZKVerifierGadget<Groth16<Bls12_377, HashToBits, BlsFr>, Fr>>::check_verify(
                cs.ns(|| format!("verify proof for chunk {}", c)),
                &verifying_key,
                public_inputs.iter(),
                &proof,
            )?;
        }
        BlsVerifyGadget::<Bls12_377, Fr, PairingGadget>::batch_verify(
            cs.ns(|| format!("batch verify BLS")),
            &prepared_aggregated_public_keys,
            &prepared_message_hashes,
            aggregated_signature.unwrap(),
        )?;
        for (j, pk) in current_pub_keys_vars.iter().enumerate() {
            let pk_var = G1Gadget::<Bls12_377Parameters>::alloc_input(
                cs.ns(|| format!("final pub key {}", j)),
                || pk.get_value().get(),
            )?;
            pk.enforce_equal(
                cs.ns(|| format!("final pub key equal {}", j)),
                &pk_var,
            )?;
        }

        println!("num constraints: {}", cs.num_constraints());
        Ok(())
    }
}

//#[cfg(test)]
//mod test {
//    use groth16::{create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof, VerifyingKey, Proof};
//    use crate::circuit::{ValidatorSetUpdate, SingleUpdate, HashProof, HashToBits};
//    use algebra::{
//        PrimeField,
//        fields::{
//            FpParameters,
//            sw6::{Fr, FrParameters},
//            bls12_377::{Fr as BlsFr, FrParameters as BlsFrParameters},
//        },
//        curves::{
//            ProjectiveCurve,
//            sw6::SW6
//        }
//    };
//    use rand::thread_rng;
//    use algebra::{
//        biginteger::BigInteger,
//        curves::bls12_377::{Bls12_377, G1Projective, Bls12_377Parameters}
//    };
//    use crate::encoding::{encode_epoch_block_to_bits, encode_zero_value_public_key, encode_epoch_block_to_bytes, bits_to_bytes, bytes_to_bits};
//    use bls_zexe::bls::keys::{PublicKey, PrivateKey, Signature};
//    use r1cs_std::bits::boolean::Boolean;
//    use bls_zexe::hash::{
//        XOF,
//        composite::CompositeHasher
//    };
//    use bls_zexe::curve::hash::{
//        HashToG2,
//        try_and_increment::TryAndIncrement
//    };
//    use bls_zexe::bls::keys::SIG_DOMAIN;
//    use r1cs_std::test_constraint_system::TestConstraintSystem;
//    use r1cs_core::{ConstraintSynthesizer, ConstraintSystem};
//
//    #[test]
//    fn test_circuit_proof() {
//        let composite_hasher = CompositeHasher::new().unwrap();
//        let try_and_increment = TryAndIncrement::new(&composite_hasher);
//
//        let num_validators = 10;
//        let num_bits_in_hash = 768;
//        let hash_batch_size = 1;
//        let num_epochs = 1 as usize;
//        if num_epochs % hash_batch_size != 0 {
//            panic!("hash_batch_size must divide num_epochs");
//        }
//        let num_proofs = num_epochs / hash_batch_size;
//        let packed_size = ((377*2+1 + BlsFrParameters::CAPACITY - 1)/BlsFrParameters::CAPACITY) as usize;
//        let rng = &mut thread_rng();
//        let epoch_bits = encode_epoch_block_to_bits(0, &vec![
//            PublicKey::from_pk(&G1Projective::prime_subgroup_generator()); num_validators
//        ]).unwrap();
//        let epoch_bits_len = epoch_bits.len() + 8;
//
//        let private_keys = (0..num_validators).map(|i| {
//            PrivateKey::generate(rng)
//        }).collect::<Vec<_>>();
//        let public_keys = private_keys.iter().map(|k| k.to_public()).collect::<Vec<_>>();
//
//        let new_private_keys = (0..num_validators).map(|i| {
//            PrivateKey::generate(rng)
//        }).collect::<Vec<_>>();
//        let new_public_keys = new_private_keys.iter().map(|k| k.to_public()).collect::<Vec<_>>();
//        let maximum_non_signers = 6;
//        let epoch_bits = encode_epoch_block_to_bits(maximum_non_signers, &new_public_keys).unwrap();
//        let epoch_bytes = bits_to_bytes(&epoch_bits);
//        let (message_g2, attempt) = try_and_increment.hash_with_attempt::<Bls12_377Parameters>(SIG_DOMAIN, &epoch_bytes, &[]).unwrap();
//        let epoch_bits_with_attempt = &[
//            epoch_bits.as_slice(),
//            (0..8).map(|i| ((attempt as u8 & u8::pow(2, i)) >> i) == 1).into_iter().rev().collect::<Vec<_>>().as_slice(),
//        ].concat().to_vec();
//        let signatures = private_keys[..5].iter().map(|p| p.sign(&epoch_bytes, &[], &try_and_increment).unwrap()).collect::<Vec<_>>();
//        let signatures_refs = signatures.iter().map(|s| s).collect::<Vec<_>>();
//        let aggregated_signature = Signature::aggregate(&signatures_refs);
//
//        let epoch_bytes = bits_to_bytes(&epoch_bits_with_attempt);
//        let xof_target_bits = 768;
//        let crh_bytes = composite_hasher.crh( SIG_DOMAIN, &epoch_bytes, xof_target_bits/8).unwrap();
//        let modulus_bit_rounded = (((FrParameters::MODULUS_BITS + 7)/8)*8) as usize;
//        let crh_bits = bytes_to_bits(&crh_bytes, modulus_bit_rounded).into_iter().rev().collect::<Vec<_>>();
//
//        let (hash_params, hash_proof) = {
//            let hash_params = {
//                let c = HashToBits {
//                    message_bits: vec![vec![None; epoch_bits_len]],
//                    hash_batch_size: hash_batch_size,
//                };
//                println!("generating parameters for hash to bits");
//                let p = generate_random_parameters::<Bls12_377, _, _>(c, rng).unwrap();
//                println!("generated parameters for hash to bits");
//                p
//            };
//
//            let c = HashToBits {
//                message_bits: vec![epoch_bits_with_attempt.into_iter().map(|b| Some(*b)).collect::<Vec<_>>()],
//                hash_batch_size: hash_batch_size,
//            };
//
//
//            let epoch_chunks = crh_bits.chunks(BlsFrParameters::CAPACITY as usize);
//            let epoch_chunks = epoch_chunks.into_iter().map(|c| {
//                BlsFr::from_repr(<BlsFrParameters as FpParameters>::BigInt::from_bits(c))
//            }).collect::<Vec<_>>();
//
//            let hash = composite_hasher.xof(SIG_DOMAIN, &crh_bytes, xof_target_bits/8).unwrap();
//
//            let hash_bits = bytes_to_bits(&hash, xof_target_bits).iter().rev().map(|b| *b).collect::<Vec<bool>>();
//            let modulus_bit_rounded = (((FrParameters::MODULUS_BITS + 7)/8)*8) as usize;
//            let hash_bits = &[
//                &hash_bits[..FrParameters::MODULUS_BITS as usize], //.iter().rev().map(|b| *b).collect::<Vec<bool>>()[..],
//                &hash_bits[modulus_bit_rounded..modulus_bit_rounded+FrParameters::MODULUS_BITS as usize],
//                &[hash_bits[modulus_bit_rounded+FrParameters::MODULUS_BITS as usize]][..],
//            ].concat().to_vec();
//            let fp_chunks = hash_bits.chunks(BlsFrParameters::CAPACITY as usize);
//            let fp_chunks = fp_chunks.into_iter().map(|c| {
//                BlsFr::from_repr(<BlsFrParameters as FpParameters>::BigInt::from_bits(c))
//            }).collect::<Vec<_>>();
//
//            let mut cs = TestConstraintSystem::<BlsFr>::new();
//            c.clone().generate_constraints(&mut cs).unwrap();
//            if !cs.is_satisfied() {
//                println!("which: {}", cs.which_is_unsatisfied().unwrap());
//            }
//            assert!(cs.is_satisfied());
//            let public_inputs_for_hash = &[
//                epoch_chunks,
//                fp_chunks,
//            ].concat();
//            let prepared_verifying_key = prepare_verifying_key(&hash_params.vk);
//
//            let p = create_random_proof(c, &hash_params, rng).unwrap();
//            assert!(verify_proof(&prepared_verifying_key, &p, public_inputs_for_hash.as_slice()).unwrap());
//            //println!("verified public input len: {}", public_inputs_for_hash.len());
//            public_inputs_for_hash.iter().for_each(|p| {
//                //println!("verified public input: {}", p);
//            });
//            (hash_params, p)
//        };
//
//        let (params, update_proof) = {
//            let update = SingleUpdate {
//                maximum_non_signers: Some(maximum_non_signers),
//                new_pub_keys: new_public_keys.iter().map(|pk| Some(pk.get_pk())).collect::<Vec<_>>(),
//                signed_bitmap: vec![Some(true), Some(true), Some(true), Some(true), Some(true), Some(false), Some(false),Some(false),Some(false),Some(false)],
//                signature: Some(aggregated_signature.get_sig()),
//            };
//            let c = ValidatorSetUpdate {
//                initial_public_keys: public_keys.iter().map(|pk| Some(pk.get_pk())).collect::<Vec<_>>(),
//                initial_maximum_non_signers: Some(maximum_non_signers),
//                num_validators: num_validators,
//                hash_batch_size: hash_batch_size,
//                hash_proofs: vec![hash_proof].iter().map(|p| HashProof { proof: p.clone() }).collect::<Vec<_>>(),
//                updates: vec![update],
//                packed_size: packed_size,
//                verifying_key: hash_params.vk.clone(),
//            };
//            let mut cs = TestConstraintSystem::<Fr>::new();
//            c.clone().generate_constraints(&mut cs).unwrap();
//            if !cs.is_satisfied() {
//                println!("which: {}", cs.which_is_unsatisfied().unwrap());
//            }
//            assert!(cs.is_satisfied());
//
//            let params = {
//                let empty_update = SingleUpdate {
//                    maximum_non_signers: None,
//                    new_pub_keys: vec![None; num_validators],
//                    signed_bitmap: vec![None; num_validators],
//                    signature: None,
//                };
//                let empty_hash_proof = HashProof {
//                    proof: Proof::<Bls12_377>::default(),
//                };
//                let c = ValidatorSetUpdate {
//                    initial_public_keys: vec![None; num_validators],
//                    initial_maximum_non_signers: None,
//                    num_validators: num_validators,
//                    hash_batch_size: hash_batch_size,
//                    hash_proofs: vec![empty_hash_proof; num_proofs],
//                    updates: vec![empty_update; num_epochs],
//                    packed_size: packed_size,
//                    verifying_key: hash_params.vk.clone(),
//                };
//                println!("generating parameters");
//                let p = generate_random_parameters::<SW6, _, _>(c, rng).unwrap();
//                println!("generated parameters");
//                p
//            };
//
//            let p = create_random_proof(c, &params, rng).unwrap();
//            (params, p)
//        };
//
//        let prepared_verifying_key = prepare_verifying_key(&params.vk);
//        let public_inputs = [
//            public_keys.iter().map(|pk| {
//                let affine = pk.get_pk().into_affine();
//                vec![affine.x, affine.y]
//            }).flatten().collect::<Vec<_>>().as_slice(),
//            &[Fr::from(maximum_non_signers as u64)],
//            new_public_keys.iter().map(|pk| {
//                let affine = pk.get_pk().into_affine();
//                vec![affine.x, affine.y]
//            }).flatten().collect::<Vec<_>>().as_slice(),
//        ].concat().to_vec();
//        public_inputs.iter().for_each(|x| {
//            //println!("public input: {}", x);
//        });
//        assert!(verify_proof(&prepared_verifying_key, &update_proof, public_inputs.as_slice()).unwrap())
//    }
//}