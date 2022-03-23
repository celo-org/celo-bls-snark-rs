use ark_ec::PairingEngine;
use bls_crypto::{PublicKey, Signature, hash_to_curve::try_and_increment_cip22::COMPOSITE_HASH_TO_G1_CIP22};
use std::slice;
use warp::Reply;
use ark_groth16::data_structures::ProvingKey as Groth16Parameters;
use serde::{Serialize, Deserialize};
use epoch_snark::{Parameters, BLSCurve};
use ark_std::{end_timer, start_timer};
use epoch_snark::{prove, verify, BWCurve, EpochBlock, EpochTransition};
use std::sync::Arc;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ethers::{types::U256, providers::*};

type Result<T> = std::result::Result<T, warp::Rejection>;

const MAX_VALIDATORS: usize = 150;
const MAX_TRANSITIONS: usize = 143;
const EPOCH_DURATION: u64 = 17280;

#[derive(Deserialize)]
pub struct ProofRequest {
    pub node_url: String,
    pub start_epoch: u64,
    pub end_epoch: u64,
}

#[derive(Serialize)]
pub struct ProofStartResponse {
    pub id: String,
}


pub async fn create_proof_handler(body: ProofRequest, proving_key: Arc<Groth16Parameters<BWCurve>>) -> Result<impl Reply> {
    let provider = Arc::new(Provider::<Http>::try_from(body.node_url.as_ref()).unwrap());

    let futs = (body.start_epoch as u64..=body.end_epoch)
        .step_by(1)
        .enumerate()
        .map(|(i, epoch_index)| {
            let provider = provider.clone();
            async move {
                let num = epoch_index*EPOCH_DURATION;
                let previous_num = num - EPOCH_DURATION as u64;
                println!("nums: {}, {}", previous_num, num);

                let block = provider.get_block(num).await.expect("could not get block").unwrap();
                let parent_block = provider.get_block(num - EPOCH_DURATION as u64).await.expect("could not get parent epoch block").unwrap();
                //println!("block: {:?}", block);
                let previous_validators = provider.get_validators_bls_public_keys(previous_num+1).await.expect("could not get validators");
                let previous_validators_keys = previous_validators.into_iter().map(|s| PublicKey::deserialize(&mut hex::decode(&s[2..]).unwrap().as_slice())).collect::<std::result::Result<Vec<_>, _>>().unwrap();
                let validators = provider.get_validators_bls_public_keys(num+1).await.expect("could not get validators");
                let validators_keys = validators.into_iter().map(|s| PublicKey::deserialize(&mut hex::decode(&s[2..]).unwrap().as_slice())).collect::<std::result::Result<Vec<_>, _>>().unwrap();
                //println!("valiators keys: {}", validators_keys.len());
                println!("valiators: {}", previous_validators_keys == validators_keys);

                let epoch_snark_data = block.epoch_snark_data.unwrap();
                // Get the bitmap / signature
                let bitmap = {
                    let bitmap_num = U256::from(&epoch_snark_data.bitmap.0[..]);
                    let mut bitmap = Vec::new();
                    for i in 0..MAX_VALIDATORS {
                        bitmap.push(bitmap_num.bit(i));
                    }
                    bitmap
                };
                //println!("bitmap: {:?}", bitmap);

                let signature = epoch_snark_data.signature;
                let aggregate_signature = Signature::deserialize(&mut &signature.0[..])
                    .expect("could not deserialize signature - your header snark data is corrupt");
                let block_hash = block.hash.unwrap();
                let parent_hash = parent_block.hash.unwrap();
                let entropy = unsafe { Some(slice::from_raw_parts(block_hash.as_ptr(), EpochBlock::ENTROPY_BYTES).to_vec()) };
                let parent_entropy = unsafe { Some(slice::from_raw_parts(parent_hash.as_ptr(), EpochBlock::ENTROPY_BYTES).to_vec()) };
                let num_non_signers = MAX_VALIDATORS as u32 - ((2*validators_keys.len()+ 2)/3) as u32;

                let mut new_public_keys = validators_keys.clone();
                if MAX_VALIDATORS > new_public_keys.len() {
                    let difference = MAX_VALIDATORS - new_public_keys.len();
                    let generator = PublicKey::from(EpochBlock::padding_pk());
                    for _ in 0..difference {
                        new_public_keys.push(generator.clone());
                    }
                }
                println!("new pub keys len {}", new_public_keys.len());

                let mut round = 0;
                let mut found_signature = false;
                for i in 0..=255u8 {
                    let epoch_block = EpochBlock {
                        index: epoch_index as u16,
                        maximum_non_signers: num_non_signers,
                        new_public_keys: new_public_keys.clone(),
                        epoch_entropy: entropy.clone(),
                        parent_entropy: parent_entropy.clone(),
                        maximum_validators: MAX_VALIDATORS,
                        round: i,
                    };
                    let (mut encoded_inner, mut encoded_extra_data) =
                    epoch_block.encode_inner_to_bytes_cip22().unwrap();
                    let mut participating_keys = vec![];
                    for (j, b) in bitmap.iter().enumerate() {
                        if *b {
                            participating_keys.push(previous_validators_keys[j].clone());
                        }
                    }
                    let aggregated_key = PublicKey::aggregate(&participating_keys);
                    if aggregated_key.verify(
                        &encoded_inner,
                        &encoded_extra_data,
                        &aggregate_signature,
                        &*COMPOSITE_HASH_TO_G1_CIP22,
                    ).is_ok() {
                        round = i;
                        found_signature = true;
                        break;
                    }
                };
                if !found_signature {
                    panic!("could not have found signatures for epoch {}: num non signers {}, num keys {}", epoch_index, num_non_signers, validators_keys.len());
                }
                println!("epoch {}: num non signers {}, num keys {}", epoch_index, num_non_signers, validators_keys.len());
                
                // construct the epoch block transition
                EpochTransition {
                    block: EpochBlock {
                        index: epoch_index as u16,
                        maximum_non_signers: num_non_signers,
                        new_public_keys: new_public_keys.clone(),
                        epoch_entropy: entropy,
                        parent_entropy,
                        maximum_validators: MAX_VALIDATORS,
                        round,
                    },
                    aggregate_signature,
                    bitmap,
                }
            }
        })
        .collect::<Vec<_>>();
    let mut transitions = futures_util::future::join_all(futs).await;
    let first_epoch = transitions.remove(0).block;

    let params = Parameters::<BWCurve, BLSCurve> {
        epochs: (*proving_key).clone(),
        hash_to_bits: None,
    };

    // Prover generates the proof given the params
    let time = start_timer!(|| "Generate proof");
    let proof = prove(
        &params,
        MAX_VALIDATORS as u32,
        &first_epoch,
        &transitions,
        MAX_TRANSITIONS,
    ).unwrap();
    end_timer!(time);

    // Verifier checks the proof
    let time = start_timer!(|| "Verify proof");
    let res = verify(&params.epochs.vk, &first_epoch, &transitions.last().unwrap().block, &proof);
    end_timer!(time);
    assert!(res.is_ok());

    let mut proof_bytes = vec![];
    proof.serialize(&mut proof_bytes).unwrap();

    Ok(hex::encode(&proof_bytes))
}