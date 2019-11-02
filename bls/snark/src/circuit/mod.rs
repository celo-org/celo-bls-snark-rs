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
use bls_zexe::hash::{
    XOF,
    composite::CompositeHasher
};
use bls_zexe::bls::keys::SIG_DOMAIN;
use r1cs_std::bits::uint8::UInt8;

struct HashToBits {
    message_bits: Vec<Option<bool>>,
    hash_batch_size: usize,
}

impl ConstraintSynthesizer<BlsFr> for HashToBits {
    fn generate_constraints<CS: ConstraintSystem<BlsFr>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        for i in 0..self.hash_batch_size {
            let bits = self.message_bits.iter().enumerate().map(|(j, b)| Boolean::alloc(
                cs.ns(|| format!("{}: bit {}", i, j)),
                || b.ok_or(SynthesisError::AssignmentMissing)
            )).collect::<Vec<_>>();
            let bits = if bits.iter().any(|x| x.is_err()) {
                Err(SynthesisError::AssignmentMissing)
            } else {
                Ok(bits.into_iter().map(|b| b.unwrap()).collect::<Vec<_>>())
            }?;
            let packed_message = MultipackGadget::pack(
                cs.ns(|| format!("{}: pack message", i)),
                &bits,
                BlsFrParameters::CAPACITY as usize,
            )?;
            let hash = HashToBitsGadget::hash_to_bits(
                cs.ns(|| format!("{}: hash to bits", i)),
                &packed_message,
                self.message_bits.len(),
                BlsFrParameters::CAPACITY as usize,
                BlsFrParameters::CAPACITY as usize,
            )?;
        }
        Ok(())
    }
}

#[derive(Clone)]
struct SingleUpdate {
    attempt: Option<u8>,
    maximum_non_signers: Option<u32> ,
    new_pub_keys: Vec<Option<G1Projective>>,
    signed_bitmap: Vec<Option<bool>>,
    signature: Option<G2Projective>,
}

#[derive(Clone)]
struct HashProof {
    proof: Proof<Bls12_377>,
}

struct ValidatorSetUpdate {
    initial_public_keys: Vec<Option<G1Projective>>,
    initial_maximum_non_signers: Option<u32> ,
    num_validators: usize,
    hash_batch_size: usize,
    hash_proofs: Vec<HashProof>,
    updates: Vec<SingleUpdate>,
    packed_size: usize,
    verifying_key: VerifyingKey<Bls12_377>,
}

impl ConstraintSynthesizer<Fr> for ValidatorSetUpdate {
    fn generate_constraints<CS: ConstraintSystem<Fr>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let composite_hasher = CompositeHasher::new().unwrap();
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
                let signed_bitmap = update.signed_bitmap.iter().map(|b| Boolean::alloc(
                    cs.ns(|| format!("{}, {}: signed bitmap", c, i)),
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
                let attempt = UInt8::alloc(
                    cs.ns(|| format!("{}, {}: attempt", c, i)),
                    || update.attempt.get(),
                )?;
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
                let packed_message = MultipackGadget::pack(
                    cs.ns(|| format!("{}, {}: pack message", c, i)),
                    &epoch_bits,
                    BlsFrParameters::CAPACITY as usize,
                )?;
                public_inputs.extend_from_slice(&packed_message);
//                println!("num constraints: {}", cs.num_constraints());
//                let packed_message_xof_bits = HashToBitsGadget::hash_to_bits(
//                    cs.ns(|| format!("{}: hash to bits", i)),
//                    &packed_message,
//                    epoch_bits.len(),
//                )?;
                let packed_xof_bits = if epoch_bits.iter().any(|x| x.get_value().is_none()) {
                    vec![None; self.packed_size]
                } else {
                    let epoch_bytes = bits_to_bytes(&epoch_bits.iter().map(|b| b.get_value().unwrap()).collect::<Vec<_>>());
                    let xof_target_bits = self.packed_size;
                    let hash = composite_hasher.hash( SIG_DOMAIN, &epoch_bytes, xof_target_bits).unwrap();
                    let hash_bits = bytes_to_bits(&hash, xof_target_bits);
                    let fp_chunks = hash_bits.chunks(BlsFrParameters::CAPACITY as usize);
                    fp_chunks.into_iter().map(|c| Some(Fr::from_repr(<FrParameters as FpParameters>::BigInt::from_bits(c)))).collect::<Vec<_>>()
                };
                let xof_bits_results = packed_xof_bits.iter().enumerate().map(|(k, x)| {
                    FpGadget::<Fr>::alloc(
                        cs.ns(|| format!("{}, {}: allocate xof bits {}", c, i, k)),
                        || {
                            let bls_fr = x.ok_or(SynthesisError::AssignmentMissing)?;
                            let mut bls_fr_bytes = vec![];
                            bls_fr.write(&mut bls_fr_bytes).unwrap();
                            let sw6_fr = Fr::read(bls_fr_bytes.as_slice());
                            sw6_fr.map_err(|e| {
                                println!("error: {}", e);
                                SynthesisError::Unsatisfiable
                            })
                        },
                    )
                }).collect::<Vec<_>>();
                let xof_bits_packed = if xof_bits_results.iter().any(|x| x.is_err()) {
                    Err(SynthesisError::Unsatisfiable)
                } else {
                    Ok(xof_bits_results.into_iter().map(|x| x.unwrap()).collect::<Vec<_>>())
                }?;
                public_inputs.extend_from_slice(&xof_bits_packed);

                let message_hash = HashToGroupGadget::hash_to_group(
                    cs.ns(|| format!("{}, {}: hash to group", c, i)),
                    &xof_bits_packed,
                    BlsFrParameters::CAPACITY as usize,
                )?;
                BlsVerifyGadget::<Bls12_377, Fr, PairingGadget>::verify(
                    cs.ns(|| format!("{}, {}: verify signature", c, i)),
                    &current_pub_keys_vars,
                    signed_bitmap.as_slice(),
                    message_hash,
                    signature,
                    current_maximum_non_signers.clone(),
                )?;
                current_pub_keys_vars = new_pub_keys_vars;
                current_maximum_non_signers = maximum_non_signers;
            }
            let proof = ProofGadget::<_, _, PairingGadget>::alloc::<_, Proof<Bls12_377>, _>(
                cs.ns(|| format!("alloc proof {}", c)),
                || Ok(self.hash_proofs[c].proof.clone()),
            )?;
            <Groth16VerifierGadget::<_, _, PairingGadget> as NIZKVerifierGadget<Groth16<Bls12_377, HashToBits, BlsFr>, Fr>>::check_verify(
                cs.ns(|| format!("verify chunk {}", c)),
                &verifying_key,
                public_inputs.iter(),
                &proof,
            )?;
        }
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

#[cfg(test)]
mod test {
    use groth16::{create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof, VerifyingKey, Proof};
    use crate::circuit::{ValidatorSetUpdate, SingleUpdate, HashProof, HashToBits};
    use algebra::{
        fields::{
            FpParameters,
            sw6::{Fr, FrParameters},
            bls12_377::{Fr as BlsFr, FrParameters as BlsFrParameters},
        },
        curves::{
            ProjectiveCurve,
            sw6::SW6
        }
    };
    use rand::thread_rng;
    use algebra::curves::bls12_377::{Bls12_377, G1Projective};
    use crate::encoding::{encode_epoch_block_to_bits, encode_zero_value_public_key};
    use bls_zexe::bls::keys::PublicKey;
    use r1cs_std::bits::boolean::Boolean;

    #[test]
    fn test_circuit_setup() {
        let num_validators = 10;
        let num_bits_in_hash = 768;
        let hash_batch_size = 1;
        let num_epochs = 1 as usize;
        if num_epochs % hash_batch_size != 0 {
            panic!("hash_batch_size must divide num_epochs");
        }
        let num_proofs = num_epochs / hash_batch_size;
        let packed_size = ((377*2+1 + BlsFrParameters::CAPACITY - 1)/BlsFrParameters::CAPACITY) as usize;
        let rng = &mut thread_rng();
        let hash_params = {
            let epoch_bits = encode_epoch_block_to_bits(0, 0, &vec![
                 PublicKey::from_pk(&G1Projective::prime_subgroup_generator()); num_validators
            ]).unwrap();
            let epoch_bits_len = epoch_bits.len();
            let c = HashToBits {
                message_bits: vec![None; epoch_bits.len()],
                hash_batch_size: hash_batch_size,
            };
            println!("generating parameters for hash to bits");
            let p = generate_random_parameters::<Bls12_377, _, _>(c, rng).unwrap();
            println!("generated parameters for hash to bits");
            p
        };
        let params = {
            let empty_update = SingleUpdate {
                attempt: None,
                maximum_non_signers: None,
                new_pub_keys: vec![None; num_validators],
                signed_bitmap: vec![None; num_validators],
                signature: None,
            };
            let empty_hash_proof = HashProof {
                proof: Proof::<Bls12_377>::default(),
            };
            println!("gamma len: {}", hash_params.vk.gamma_abc_g1.len());
            let c = ValidatorSetUpdate {
                initial_public_keys: vec![None; num_validators],
                initial_maximum_non_signers: None,
                num_validators: num_validators,
                hash_batch_size: hash_batch_size,
                hash_proofs: vec![empty_hash_proof; num_proofs],
                updates: vec![empty_update; num_epochs],
                packed_size: packed_size,
                verifying_key: hash_params.vk,
            };
            println!("generating parameters");
            let p = generate_random_parameters::<SW6, _, _>(c, rng).unwrap();
            println!("generated parameters");
            p
        };
    }

    #[test]
    fn test_circuit_proof() {
        let num_validators = 10;
        let num_bits_in_hash = 768;
        let hash_batch_size = 1;
        let num_epochs = 1 as usize;
        if num_epochs % hash_batch_size != 0 {
            panic!("hash_batch_size must divide num_epochs");
        }
        let num_proofs = num_epochs / hash_batch_size;
        let packed_size = ((377*2+1 + BlsFrParameters::CAPACITY - 1)/BlsFrParameters::CAPACITY) as usize;
        let rng = &mut thread_rng();
        let epoch_bits = encode_epoch_block_to_bits(0, 0, &vec![
            PublicKey::from_pk(&G1Projective::prime_subgroup_generator()); num_validators
        ]).unwrap();
        let epoch_bits_len = epoch_bits.len();
        let hash_params = {
            let c = HashToBits {
                message_bits: vec![None; epoch_bits.len()],
                hash_batch_size: hash_batch_size,
            };
            println!("generating parameters for hash to bits");
            let p = generate_random_parameters::<Bls12_377, _, _>(c, rng).unwrap();
            println!("generated parameters for hash to bits");
            p
        };
        let params = {
            let empty_update = SingleUpdate {
                attempt: None,
                maximum_non_signers: None,
                new_pub_keys: vec![None; num_validators],
                signed_bitmap: vec![None; num_validators],
                signature: None,
            };
            let empty_hash_proof = HashProof {
                proof: Proof::<Bls12_377>::default(),
            };
            let c = ValidatorSetUpdate {
                initial_public_keys: vec![None; num_validators],
                initial_maximum_non_signers: None,
                num_validators: num_validators,
                hash_batch_size: hash_batch_size,
                hash_proofs: vec![empty_hash_proof; num_proofs],
                updates: vec![empty_update; num_epochs],
                packed_size: packed_size,
                verifying_key: hash_params.vk.clone(),
            };
            println!("generating parameters");
            let p = generate_random_parameters::<SW6, _, _>(c, rng).unwrap();
            println!("generated parameters");
            p
        };

        let hash_proof = {
            let c = HashToBits {
                message_bits: vec![Some(true); epoch_bits.len()],
                hash_batch_size: hash_batch_size,
            };
            let p = create_random_proof(c, &hash_params, rng).unwrap();
            p
        };
    }
}