use ark_groth16::data_structures::ProvingKey as Groth16Parameters;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bench_utils::{end_timer, start_timer};
use bls_crypto::{
    hash_to_curve::try_and_increment_cip22::COMPOSITE_HASH_TO_G1_CIP22, PublicKey, Signature,
};
use epoch_snark::{prove, verify, BWCurve, EpochBlock, EpochTransition};
use epoch_snark::{BLSCurve, Parameters};
use ethers::{providers::*, types::U256};
use serde::{Deserialize, Serialize};
use std::slice;
use std::sync::Arc;
use tracing::{debug, info};
use uuid::Uuid;
use warp::Reply;

use crate::{
    create_proof, error::Error, get_all_proofs, get_existing_proof, EPOCH_DURATION,
    MAX_TRANSITIONS, MAX_VALIDATORS, MIN_CIP22_EPOCH,
};

type Result<T> = std::result::Result<T, warp::Rejection>;

#[derive(Deserialize, Clone)]
pub struct ProofRequest {
    pub start_epoch: u64,
    pub end_epoch: u64,
}

#[derive(Deserialize)]
pub struct ProofGetRequest {
    pub start_epoch: u64,
    pub end_epoch: u64,
}

#[derive(Serialize)]
pub struct ProofStartResponse {
    pub id: String,
}

#[derive(Serialize, Clone)]
pub struct ProofEndResponse {
    pub proof: String,
    pub first_epoch_index: i32,
    pub first_epoch: String,
    pub last_epoch_index: i32,
    pub last_epoch: String,
}

#[derive(Serialize)]
pub struct ProofGetResponse {
    pub response: Option<ProofEndResponse>,
}

#[derive(Serialize)]
pub struct ProofListResponse {
    pub response: Option<Vec<ProofEndResponse>>,
}

pub async fn create_proof_inner_and_catch_errors(
    body: ProofRequest,
    proving_key: Arc<Groth16Parameters<BWCurve>>,
    node_url: String,
) -> eyre::Result<()> {
    let start_epoch = body.start_epoch;
    let end_epoch = body.end_epoch;
    if start_epoch < MIN_CIP22_EPOCH {
        return Err(Error::EpochTooSmallError.into());
    }
    info!("Processing epochs {} to {}", start_epoch, end_epoch);
    let existing_proof = get_existing_proof(start_epoch as i32, end_epoch as i32)?;
    if existing_proof.is_some() {
        return Ok(());
    }
    let partial_request = ProofRequest {
        start_epoch,
        end_epoch,
    };
    let (proof_bytes, first_epoch_block, last_epoch_block) =
        create_proof_inner(partial_request, proving_key.clone(), node_url.clone()).await?;
    let mut first_epoch_block_bytes = vec![];
    first_epoch_block
        .serialize(&mut first_epoch_block_bytes)
        .unwrap();
    let mut last_epoch_block_bytes = vec![];
    last_epoch_block
        .serialize(&mut last_epoch_block_bytes)
        .unwrap();

    create_proof(
        first_epoch_block.index as i32,
        &first_epoch_block_bytes,
        last_epoch_block.index as i32,
        &last_epoch_block_bytes,
        &proof_bytes,
    )?;
    info!("Done processing epochs {} to {}", start_epoch, end_epoch);
    Ok(())
}

pub async fn create_proof_inner(
    body: ProofRequest,
    proving_key: Arc<Groth16Parameters<BWCurve>>,
    node_url: String,
) -> std::result::Result<(Vec<u8>, EpochBlock, EpochBlock), Error> {
    let provider =
        Arc::new(Provider::<Http>::try_from(node_url.as_ref()).map_err(|_| Error::DataFetchError)?);

    let futs = (body.start_epoch as u64..=body.end_epoch)
        .step_by(1)
        .enumerate()
        .map(|(_, epoch_index)| {
            let provider = provider.clone();
            async move {
                let num = epoch_index * EPOCH_DURATION;
                let previous_num = num - EPOCH_DURATION as u64;
                debug!("nums: {}, {}", previous_num, num);

                let block = provider
                    .get_block(num)
                    .await
                    .map_err(|_| Error::DataFetchError)?
                    .expect("could not get parent epoch block");
                let parent_block = provider
                    .get_block(num - EPOCH_DURATION as u64)
                    .await
                    .map_err(|_| Error::DataFetchError)?
                    .expect("could not get parent epoch block");
                let previous_validators = provider
                    .get_validators_bls_public_keys(previous_num + 1)
                    .await
                    .map_err(|_| Error::DataFetchError)?;
                let previous_validators_keys = previous_validators
                    .into_iter()
                    .map(|s| PublicKey::deserialize(&mut hex::decode(&s[2..]).unwrap().as_slice()))
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(|_| Error::DataFetchError)?;
                let validators = provider
                    .get_validators_bls_public_keys(num + 1)
                    .await
                    .map_err(|_| Error::DataFetchError)?;
                let validators_keys = validators
                    .into_iter()
                    .map(|s| PublicKey::deserialize(&mut hex::decode(&s[2..]).unwrap().as_slice()))
                    .collect::<std::result::Result<Vec<_>, _>>()
                    .map_err(|_| Error::DataFetchError)?;

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

                let signature = epoch_snark_data.signature;
                let aggregate_signature = Signature::deserialize(&mut &signature.0[..])
                    .expect("could not deserialize signature - your header snark data is corrupt");
                let block_hash = block.hash.unwrap();
                let parent_hash = parent_block.hash.unwrap();
                let entropy = unsafe {
                    Some(
                        slice::from_raw_parts(block_hash.as_ptr(), EpochBlock::ENTROPY_BYTES)
                            .to_vec(),
                    )
                };
                let parent_entropy = unsafe {
                    Some(
                        slice::from_raw_parts(parent_hash.as_ptr(), EpochBlock::ENTROPY_BYTES)
                            .to_vec(),
                    )
                };
                let num_non_signers =
                    MAX_VALIDATORS as u32 - ((2 * validators_keys.len() + 2) / 3) as u32;

                let mut new_public_keys = validators_keys.clone();
                if MAX_VALIDATORS > new_public_keys.len() {
                    let difference = MAX_VALIDATORS - new_public_keys.len();
                    let generator = PublicKey::from(EpochBlock::padding_pk());
                    for _ in 0..difference {
                        new_public_keys.push(generator.clone());
                    }
                }

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
                    let (encoded_inner, encoded_extra_data) = epoch_block
                        .encode_inner_to_bytes_cip22()
                        .map_err(|_| Error::DataGenerationError)?;
                    let mut participating_keys = vec![];
                    for (j, b) in bitmap.iter().enumerate() {
                        if *b {
                            participating_keys.push(previous_validators_keys[j].clone());
                        }
                    }
                    let aggregated_key = PublicKey::aggregate(&participating_keys);
                    if aggregated_key
                        .verify(
                            &encoded_inner,
                            &encoded_extra_data,
                            &aggregate_signature,
                            &*COMPOSITE_HASH_TO_G1_CIP22,
                        )
                        .is_ok()
                    {
                        round = i;
                        found_signature = true;
                        break;
                    }
                }
                if !found_signature {
                    return Err(Error::CouldNotFindSignatureError);
                }
                debug!(
                    "epoch {}: num non signers {}, num keys {}",
                    epoch_index,
                    num_non_signers,
                    validators_keys.len()
                );

                // construct the epoch block transition
                Ok(EpochTransition {
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
                })
            }
        })
        .collect::<Vec<_>>();

    let params = Parameters::<BWCurve, BLSCurve> {
        epochs: (*proving_key).clone(),
        hash_to_bits: None,
    };

    let mut transitions = futures_util::future::join_all(futs)
        .await
        .into_iter()
        .collect::<std::result::Result<Vec<_>, Error>>()?;
    let first_epoch_block = transitions.remove(0).block;
    let time = start_timer!(|| "Generate proof");

    let proof_plumo = prove(
        &params,
        MAX_VALIDATORS as u32,
        &first_epoch_block,
        &transitions,
        MAX_TRANSITIONS,
    )
    .map_err(|_| Error::ProofGenerationError)?;
    end_timer!(time);

    let last_epoch_block = transitions.last().unwrap().block.clone();
    // Verifier checks the proof
    let time = start_timer!(|| "Verify proof");
    verify(
        &params.epochs.vk,
        &first_epoch_block,
        &last_epoch_block,
        &proof_plumo,
    )
    .map_err(|_| Error::ProofVerificationError)?;
    end_timer!(time);

    let mut proof_bytes = vec![];
    proof_plumo.serialize(&mut proof_bytes).unwrap();

    Ok((proof_bytes, first_epoch_block, last_epoch_block))
}

pub async fn create_proof_handler(
    body: ProofRequest,
    sender: std::sync::mpsc::SyncSender<(String, ProofRequest)>,
) -> Result<impl Reply> {
    let proof_id = Uuid::new_v4().to_string();
    sender.send((proof_id.clone(), body)).unwrap();
    Ok(warp::reply::json(&ProofStartResponse { id: proof_id }))
}

pub async fn create_proof_get_handler(body: ProofGetRequest) -> Result<impl Reply> {
    let possible_proof = get_existing_proof(body.start_epoch as i32, body.end_epoch as i32)
        .map_err(|_| Error::CouldNotCheckProofStatusError)?;
    Ok(warp::reply::json(&ProofGetResponse {
        response: possible_proof.map(|p| ProofEndResponse {
            proof: hex::encode(&p.proof),
            first_epoch_index: p.first_epoch_index as i32,
            first_epoch: hex::encode(&p.first_epoch),
            last_epoch_index: p.last_epoch_index as i32,
            last_epoch: hex::encode(&p.last_epoch),
        }),
    }))
}

pub async fn create_proof_list_handler() -> Result<impl Reply> {
    let possible_proofs = get_all_proofs().map_err(|_| Error::CouldNotCheckProofStatusError)?;
    Ok(warp::reply::json(&ProofListResponse {
        response: possible_proofs.map(|p| {
            p.into_iter()
                .map(|pr| ProofEndResponse {
                    proof: hex::encode(&pr.proof),
                    first_epoch_index: pr.first_epoch_index as i32,
                    first_epoch: hex::encode(&pr.first_epoch),
                    last_epoch_index: pr.last_epoch_index as i32,
                    last_epoch: hex::encode(&pr.last_epoch),
                })
                .collect::<Vec<_>>()
        }),
    }))
}
