#[macro_use]
extern crate bench_utils;

use groth16::{create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof, Proof};
use bls_snark::circuit::{ValidatorSetUpdate, SingleUpdate, HashProof, HashToBits, OUT_DOMAIN};
use blake2s_simd::Params;
use algebra::{
    Zero,
    PrimeField,
    sw6::{Fr, FrParameters, SW6},
    bls12_377::{Fr as BlsFr, FrParameters as BlsFrParameters},
    FpParameters,
    BigInteger,
    bls12_377::{Bls12_377, G1Projective, G2Projective, Parameters as Bls12_377Parameters},
};
use rand::thread_rng;
use bls_snark::encoding::{encode_epoch_block_to_bits, bits_to_bytes, bytes_to_bits};
use bls_crypto::bls::keys::{PublicKey, PrivateKey, Signature};
use bls_crypto::hash::{
    XOF,
    composite::CompositeHasher
};
use bls_crypto::curve::hash::{
    try_and_increment::TryAndIncrement
};
use bls_crypto::bls::keys::SIG_DOMAIN;
use r1cs_std::test_constraint_system::TestConstraintSystem;
use r1cs_core::{ConstraintSynthesizer};
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

    let composite_hasher = CompositeHasher::new().unwrap();
    let try_and_increment = TryAndIncrement::new(&composite_hasher);

    let num_validators: usize = args[1].parse().unwrap();
    let num_bits_in_hash = 512;
    let num_epochs: usize = args[2].parse().unwrap();
    let rng = &mut thread_rng();
    let modulus_bit_rounded = (((FrParameters::MODULUS_BITS + 7)/8)*8) as usize;

    let private_keys = (0..num_validators).map(|_| {
        PrivateKey::generate(rng)
    }).collect::<Vec<_>>();
    let pubs = private_keys.iter().map(|k| k.to_public()).collect::<Vec<_>>();
    let public_keys = pubs.iter().map(|k| k).collect::<Vec<_>>();
    let aggregated_key = public_keys.iter().fold(G2Projective::zero(), |acc, x| acc + &x.get_pk());

    let hash_params_time = start_timer!(|| "hash params");
    let hash_params = {
        let c = HashToBits {
            message_bits: vec![vec![None; modulus_bit_rounded]; num_epochs],
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
            epoch_index: None,
            maximum_non_signers: None,
            new_aggregated_pub_key: None,
            new_pub_keys: vec![None; num_validators],
            signed_bitmap: vec![None; num_validators],
        };
        let empty_hash_proof = HashProof {
            proof: Proof::<Bls12_377>::default(),
        };
        let c = ValidatorSetUpdate {
            initial_epoch_index: None,
            initial_aggregated_pub_key: None,
            initial_public_keys: vec![None; num_validators],
            initial_maximum_non_signers: None,
            num_validators: num_validators,
            hash_proof: empty_hash_proof,
            updates: vec![empty_update; num_epochs],
            verifying_key: hash_params.vk.clone(),
            aggregated_signature: None,
        };
        println!("generating parameters");
        let p = generate_random_parameters::<SW6, _, _>(c, rng).unwrap();
        println!("generated parameters");
        p
    };

    end_timer!(params_time);

    let maximum_non_signers = num_validators as u32 - 4;
    let mut first_epoch_bits = vec![];
    let mut last_epoch_bits = vec![];
    let mut message_crh_bits = vec![];
    let mut new_aggregated_key_epochs = vec![];
    let mut new_public_keys_epochs = vec![];
    let mut new_signatures_epochs = vec![];

    let mut current_private_keys = private_keys.clone();
    for i in 0..num_epochs {
        let new_private_keys = (0..num_validators).map(|_| {
            PrivateKey::generate(rng)
        }).collect::<Vec<_>>();
        let new_pubs = new_private_keys.iter().map(|k| k.to_public()).collect::<Vec<_>>();
        let new_public_keys = new_pubs.iter().map(|k| k).collect::<Vec<_>>();
        let new_aggregated_key = new_public_keys.iter().fold(G2Projective::zero(), |acc, x| acc + &x.get_pk());
        let epoch_bits = encode_epoch_block_to_bits(i as u16 + 1, maximum_non_signers, &PublicKey::from_pk(&new_aggregated_key), &new_public_keys).unwrap();
        let epoch_bytes = bits_to_bytes(&epoch_bits);
        let (_, attempt) = try_and_increment.hash_with_attempt::<Bls12_377Parameters>(SIG_DOMAIN, &epoch_bytes, &[]).unwrap();
        let epoch_bits_with_attempt = &[
            epoch_bits.as_slice(),
            (0..8).map(|i| ((attempt as u8 & u8::pow(2, i)) >> i) == 1).into_iter().rev().collect::<Vec<_>>().as_slice(),
        ].concat().to_vec();
        let epoch_bytes_with_attempt = bits_to_bytes(&epoch_bits_with_attempt);
        let signatures = current_private_keys[..5].iter().map(|p| p.sign(&epoch_bytes, &[], &try_and_increment).unwrap()).collect::<Vec<_>>();
        let signatures_refs = signatures.iter().map(|s| s).collect::<Vec<_>>();
        let aggregated_signature = Signature::aggregate(&signatures_refs);

        let crh_bytes = composite_hasher.crh( SIG_DOMAIN, &epoch_bytes_with_attempt, num_bits_in_hash/8).unwrap();
        let crh_bits = bytes_to_bits(&crh_bytes, modulus_bit_rounded);

        if i == 0 {
            let epoch_bits = encode_epoch_block_to_bits(0 as u16, maximum_non_signers, &PublicKey::from_pk(&aggregated_key), &public_keys).unwrap();
            first_epoch_bits = epoch_bits;
        }
        if i == num_epochs - 1 {
            last_epoch_bits = epoch_bits.clone();
        }

        message_crh_bits.push(crh_bits.clone());
        new_aggregated_key_epochs.push(new_aggregated_key);
        new_public_keys_epochs.push(new_pubs);
        new_signatures_epochs.push(aggregated_signature);

        current_private_keys = new_private_keys.clone();
    }

    let hash_to_bits_time = start_timer!(|| "hash to bits");
    let c = HashToBits {
        message_bits: message_crh_bits.iter().map(|x| x.iter().map(|y| Some(y.clone())).collect::<Vec<_>>()).collect::<Vec<_>>(),
    };

    let mut public_inputs_for_hash = vec![];
    let mut all_crh_bits = vec![];
    let mut all_xof_bits = vec![];
    for crh_bits in message_crh_bits.iter() {
        let crh_bytes = bits_to_bytes(crh_bits);
        all_crh_bits.extend_from_slice(&crh_bits);

        let xof_target_bits = 512;
        let hash = composite_hasher.xof( SIG_DOMAIN, &crh_bytes, xof_target_bits/8).unwrap();
        let hash_bits = bytes_to_bits(&hash, xof_target_bits).iter().rev().map(|b| *b).collect::<Vec<bool>>();
        let hash_bits = &[
            &hash_bits[..FrParameters::MODULUS_BITS as usize], //.iter().rev().map(|b| *b).collect::<Vec<bool>>()[..],
            &[hash_bits[FrParameters::MODULUS_BITS as usize]][..],
        ].concat().to_vec();

        all_xof_bits.extend_from_slice(hash_bits);
    }
    let both_bits = [first_epoch_bits.clone(), last_epoch_bits.clone()];
    let mut both_blake_bits = vec![];
    for epoch_bits in both_bits.iter() {
        let epoch_bytes = bits_to_bytes(epoch_bits);

        let hash = Params::new()
            .hash_length(32)
            .personal(OUT_DOMAIN)
            .to_state()
            .update(&epoch_bytes)
            .finalize()
            .as_ref()
            .to_vec();
        let hash_bits = bytes_to_bits(&hash, 256).iter().rev().map(|b| *b).collect::<Vec<bool>>();

        both_blake_bits.push(hash_bits.clone());
    }
    let epoch_chunks = all_crh_bits.chunks(BlsFrParameters::CAPACITY as usize);
    let epoch_chunks = epoch_chunks.into_iter().map(|c| {
        BlsFr::from_repr(<BlsFrParameters as FpParameters>::BigInt::from_bits(c))
    }).collect::<Vec<_>>();

    let fp_chunks = all_xof_bits.chunks(BlsFrParameters::CAPACITY as usize);
    let fp_chunks = fp_chunks.into_iter().map(|c| {
        BlsFr::from_repr(<BlsFrParameters as FpParameters>::BigInt::from_bits(c))
    }).collect::<Vec<_>>();

    public_inputs_for_hash.extend_from_slice(&epoch_chunks);
    public_inputs_for_hash.extend_from_slice(&fp_chunks);

    /*
    for c in public_inputs_for_hash.iter() {
        println!("public input for hash: {}", c);
    }
    */

    let mut cs = TestConstraintSystem::<BlsFr>::new();
    c.clone().generate_constraints(&mut cs).unwrap();
    if !cs.is_satisfied() {
        println!("which: {}", cs.which_is_unsatisfied().unwrap());
    }
    assert!(cs.is_satisfied());
    let prepared_verifying_key = prepare_verifying_key(&hash_params.vk);

    let hash_proof = create_random_proof(c, &hash_params, rng).unwrap();
    assert!(verify_proof(&prepared_verifying_key, &hash_proof, public_inputs_for_hash.as_slice()).unwrap());
    //println!("verified public input len: {}", public_inputs_for_hash.len());
    public_inputs_for_hash.iter().for_each(|_| {
        //println!("verified public input: {}", p);
    });
    end_timer!(hash_to_bits_time);

    let update_proof_time = start_timer!(|| "update");
    let update_proof = {
        let mut updates = vec![];
        for i in 0..num_epochs {
            let update = SingleUpdate {
                epoch_index: Some(i as u16 + 1),
                maximum_non_signers: Some(maximum_non_signers),
                new_aggregated_pub_key: Some(new_aggregated_key_epochs[i]),
                new_pub_keys: new_public_keys_epochs[i].iter().map(|pk| Some(pk.get_pk())).collect::<Vec<_>>(),
                signed_bitmap: [
                    &[Some(true), Some(true), Some(true), Some(true), Some(true)],
                    vec![Some(false); num_validators - 5].as_slice(),
                ].concat(),
            };
            updates.push(update);
        }
        let aggregated_signature = new_signatures_epochs.iter().fold(G1Projective::zero(), |acc, s| acc + &s.get_sig());
        let c = ValidatorSetUpdate {
            initial_epoch_index: Some(0),
            initial_aggregated_pub_key: Some(aggregated_key),
            initial_public_keys: public_keys.iter().map(|pk| Some(pk.get_pk())).collect::<Vec<_>>(),
            initial_maximum_non_signers: Some(maximum_non_signers),
            num_validators: num_validators,
            hash_proof: HashProof { proof: hash_proof.clone() },
            updates: updates,
            verifying_key: hash_params.vk.clone(),
            aggregated_signature: Some(aggregated_signature),
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

    let public_inputs = both_blake_bits.concat();
    let public_inputs = public_inputs.chunks(FrParameters::CAPACITY as usize);
    let public_inputs = public_inputs.into_iter().map(|c| {
        Fr::from_repr(<FrParameters as FpParameters>::BigInt::from_bits(c))
    }).collect::<Vec<_>>();
    assert!(verify_proof(&prepared_verifying_key, &update_proof, public_inputs.as_slice()).unwrap());

    println!("Done!");
}
