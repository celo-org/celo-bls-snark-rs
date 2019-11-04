#[macro_use]
extern crate bench_utils;

use groth16::{create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof, VerifyingKey, Proof};
use bls_snark::circuit::{ValidatorSetUpdate, SingleUpdate, HashProof, HashToBits};
use algebra::{
    PrimeField,
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
use algebra::{
    biginteger::BigInteger,
    curves::bls12_377::{Bls12_377, G1Projective, Bls12_377Parameters}
};
use bls_snark::encoding::{encode_epoch_block_to_bits, encode_zero_value_public_key, encode_epoch_block_to_bytes, bits_to_bytes, bytes_to_bits};
use bls_zexe::bls::keys::{PublicKey, PrivateKey, Signature};
use r1cs_std::bits::boolean::Boolean;
use bls_zexe::hash::{
    XOF,
    composite::CompositeHasher
};
use bls_zexe::curve::hash::{
    HashToG2,
    try_and_increment::TryAndIncrement
};
use bls_zexe::bls::keys::SIG_DOMAIN;
use r1cs_std::test_constraint_system::TestConstraintSystem;
use r1cs_core::{ConstraintSynthesizer, ConstraintSystem};
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

    let composite_hasher = CompositeHasher::new().unwrap();
    let try_and_increment = TryAndIncrement::new(&composite_hasher);

    let num_validators: usize = args[1].parse().unwrap();
    let num_bits_in_hash = 768;
    let hash_batch_size: usize = args[2].parse().unwrap();
    let num_epochs: usize = args[3].parse().unwrap();
    if num_epochs % hash_batch_size != 0 {
        panic!("hash_batch_size must divide num_epochs");
    }
    let num_proofs = num_epochs / hash_batch_size;
    let packed_size = ((377*2+1 + BlsFrParameters::CAPACITY - 1)/BlsFrParameters::CAPACITY) as usize;
    let rng = &mut thread_rng();
    let epoch_bits = encode_epoch_block_to_bits(0, &vec![
        PublicKey::from_pk(&G1Projective::prime_subgroup_generator()); num_validators
    ]).unwrap();
    let epoch_bits_len = epoch_bits.len() + 8;

    let private_keys = (0..num_validators).map(|i| {
        PrivateKey::generate(rng)
    }).collect::<Vec<_>>();
    let public_keys = private_keys.iter().map(|k| k.to_public()).collect::<Vec<_>>();

    let hash_params_time = start_timer!(|| "hash params");
    let hash_params = {
        let c = HashToBits {
            message_bits: vec![vec![None; epoch_bits_len]; hash_batch_size],
            hash_batch_size: hash_batch_size,
        };
        println!("generating parameters for hash to bits");
        let p = generate_random_parameters::<Bls12_377, _, _>(c, rng).unwrap();
        println!("generated parameters for hash to bits");
        p
    };
    end_timer!(hash_params_time);

    let params_time = start_timer!(|| "params");
    let params = {
        let empty_update = SingleUpdate {
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

    end_timer!(params_time);

    let maximum_non_signers = num_validators as u32 - 4;
    let mut message_bits = vec![];
    let mut new_public_keys_epochs = vec![];
    let mut new_signatures_epochs = vec![];

    let mut current_private_keys = private_keys.clone();
    for i in 0..num_epochs {
        let new_private_keys = (0..num_validators).map(|i| {
            PrivateKey::generate(rng)
        }).collect::<Vec<_>>();
        let new_public_keys = new_private_keys.iter().map(|k| k.to_public()).collect::<Vec<_>>();
        let epoch_bits = encode_epoch_block_to_bits(maximum_non_signers, &new_public_keys).unwrap();
        let epoch_bytes = bits_to_bytes(&epoch_bits);
        let (message_g2, attempt) = try_and_increment.hash_with_attempt::<Bls12_377Parameters>(SIG_DOMAIN, &epoch_bytes, &[]).unwrap();
        let epoch_bits_with_attempt = &[
            epoch_bits.as_slice(),
            (0..8).map(|i| ((attempt as u8 & u8::pow(2, i)) >> i) == 1).into_iter().rev().collect::<Vec<_>>().as_slice(),
        ].concat().to_vec();
        let signatures = current_private_keys[..5].iter().map(|p| p.sign(&epoch_bytes, &[], &try_and_increment).unwrap()).collect::<Vec<_>>();
        let signatures_refs = signatures.iter().map(|s| s).collect::<Vec<_>>();
        let aggregated_signature = Signature::aggregate(&signatures_refs);

        message_bits.push(epoch_bits_with_attempt.clone());
        new_public_keys_epochs.push(new_public_keys);
        new_signatures_epochs.push(aggregated_signature);

        current_private_keys = new_private_keys.clone();
    }

    let mut hash_proofs = vec![];
    for chunk in message_bits.chunks(hash_batch_size) {
        let hash_to_bits_time = start_timer!(|| "hash to bits");
        let c = HashToBits {
            message_bits: chunk.iter().map(|x| x.iter().map(|y| Some(y.clone())).collect::<Vec<_>>()).collect::<Vec<_>>(),
            hash_batch_size: hash_batch_size,
        };

        let mut public_inputs_for_hash = vec![];
        for j in 0..chunk.len() {
            let epoch_bits_with_attempt = &chunk[j];
            let epoch_bytes = bits_to_bytes(&epoch_bits_with_attempt);
            let epoch_chunks = epoch_bits_with_attempt.chunks(BlsFrParameters::CAPACITY as usize);
            let epoch_chunks = epoch_chunks.into_iter().map(|c| {
                BlsFr::from_repr(<BlsFrParameters as FpParameters>::BigInt::from_bits(c))
            }).collect::<Vec<_>>();
            let xof_target_bits = 768;
            let hash = composite_hasher.hash( SIG_DOMAIN, &epoch_bytes, xof_target_bits/8).unwrap();
            let hash_bits = bytes_to_bits(&hash, xof_target_bits).iter().rev().map(|b| *b).collect::<Vec<bool>>();
            let modulus_bit_rounded = (((FrParameters::MODULUS_BITS + 7)/8)*8) as usize;
            let hash_bits = &[
                &hash_bits[..FrParameters::MODULUS_BITS as usize], //.iter().rev().map(|b| *b).collect::<Vec<bool>>()[..],
                &hash_bits[modulus_bit_rounded..modulus_bit_rounded+FrParameters::MODULUS_BITS as usize],
                &[hash_bits[modulus_bit_rounded+FrParameters::MODULUS_BITS as usize]][..],
            ].concat().to_vec();
            let fp_chunks = hash_bits.chunks(BlsFrParameters::CAPACITY as usize);
            let fp_chunks = fp_chunks.into_iter().map(|c| {
                BlsFr::from_repr(<BlsFrParameters as FpParameters>::BigInt::from_bits(c))
            }).collect::<Vec<_>>();

            public_inputs_for_hash.extend_from_slice(&epoch_chunks);
            public_inputs_for_hash.extend_from_slice(&fp_chunks);
        }

        let mut cs = TestConstraintSystem::<BlsFr>::new();
        c.clone().generate_constraints(&mut cs).unwrap();
        if !cs.is_satisfied() {
            println!("which: {}", cs.which_is_unsatisfied().unwrap());
        }
        assert!(cs.is_satisfied());
        let prepared_verifying_key = prepare_verifying_key(&hash_params.vk);

        let p = create_random_proof(c, &hash_params, rng).unwrap();
        assert!(verify_proof(&prepared_verifying_key, &p, public_inputs_for_hash.as_slice()).unwrap());
        //println!("verified public input len: {}", public_inputs_for_hash.len());
        public_inputs_for_hash.iter().for_each(|p| {
            //println!("verified public input: {}", p);
        });
        hash_proofs.push(p);
        end_timer!(hash_to_bits_time);
    }

    let update_proof_time = start_timer!(|| "update");
    let update_proof = {
        let mut updates = vec![];
        for i in 0..num_epochs {
            let update = SingleUpdate {
                maximum_non_signers: Some(maximum_non_signers),
                new_pub_keys: new_public_keys_epochs[i].iter().map(|pk| Some(pk.get_pk())).collect::<Vec<_>>(),
                signed_bitmap: [
                    &[Some(true), Some(true), Some(true), Some(true), Some(true)],
                    vec![Some(false); num_validators - 5].as_slice(),
                ].concat(),
                signature: Some(new_signatures_epochs[i].get_sig()),
            };
            updates.push(update);
        }
        let c = ValidatorSetUpdate {
            initial_public_keys: public_keys.iter().map(|pk| Some(pk.get_pk())).collect::<Vec<_>>(),
            initial_maximum_non_signers: Some(maximum_non_signers),
            num_validators: num_validators,
            hash_batch_size: hash_batch_size,
            hash_proofs: hash_proofs.iter().map(|p| HashProof { proof: p.clone() }).collect::<Vec<_>>(),
            updates: updates,
            packed_size: packed_size,
            verifying_key: hash_params.vk.clone(),
        };
        let mut cs = TestConstraintSystem::<Fr>::new();
        c.clone().generate_constraints(&mut cs).unwrap();
        if !cs.is_satisfied() {
            println!("which: {}", cs.which_is_unsatisfied().unwrap());
        }
        assert!(cs.is_satisfied());


        let p = create_random_proof(c, &params, rng).unwrap();
        p
    };
    end_timer!(update_proof_time);

    let prepared_verifying_key = prepare_verifying_key(&params.vk);
    let public_inputs = [
        public_keys.iter().map(|pk| {
            let affine = pk.get_pk().into_affine();
            vec![affine.x, affine.y]
        }).flatten().collect::<Vec<_>>().as_slice(),
        &[Fr::from(maximum_non_signers as u64)],
        new_public_keys_epochs.last().unwrap().iter().map(|pk| {
            let affine = pk.get_pk().into_affine();
            vec![affine.x, affine.y]
        }).flatten().collect::<Vec<_>>().as_slice(),
    ].concat().to_vec();
    public_inputs.iter().for_each(|x| {
        //println!("public input: {}", x);
    });
    assert!(verify_proof(&prepared_verifying_key, &update_proof, public_inputs.as_slice()).unwrap())
}