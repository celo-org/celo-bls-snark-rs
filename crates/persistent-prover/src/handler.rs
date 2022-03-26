use ark_groth16::data_structures::ProvingKey as Groth16Parameters;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bench_utils::{end_timer, start_timer};
use bls_crypto::{
    hash_to_curve::try_and_increment_cip22::COMPOSITE_HASH_TO_G1_CIP22, PublicKey, Signature,
};
use epoch_snark::{prove, verify, BWCurve, EpochBlock, EpochTransition};
use epoch_snark::{BLSCurve, Parameters};
use ethers::{providers::*, types::U256};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::slice;
use std::sync::Arc;
use std::sync::Mutex;
use uuid::Uuid;
use warp::Reply;

use crate::error::Error;

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

#[derive(Deserialize)]
pub struct ProofStatusRequest {
    pub id: String,
}

#[derive(Serialize)]
pub struct ProofStartResponse {
    pub id: String,
}

#[derive(Serialize, Clone)]
pub struct ProofEndResponse {
    pub id: String,
    pub proofs: Vec<String>,
    pub epochs: Vec<String>,
}

#[derive(Serialize)]
pub struct ProofStatusResponse {
    pub id: String,
    pub response: Option<ProofEndResponse>,
    pub error: Option<Error>,
}

lazy_static! {
    static ref PROOFS_IN_PROGRESS: Mutex<HashMap<String, Option<std::result::Result<ProofEndResponse, Error>>>> =
        Mutex::new(HashMap::new());
}

pub async fn create_proof_inner_and_catch_errors(
    id: String,
    body: ProofRequest,
    proving_key: Arc<Groth16Parameters<BWCurve>>,
) {
    let result = create_proof_inner(body, proving_key).await;
    let mut key = PROOFS_IN_PROGRESS
        .lock()
        .map_err(|_| Error::CouldNotLockMutexError)
        .unwrap();

    match result {
        Ok((proofs, epochs)) => {
            *(key.get_mut(&id).unwrap()) = Some(Ok(ProofEndResponse {
                id: id.clone(),
                proofs: proofs
                    .into_iter()
                    .map(|proof| hex::encode(&proof))
                    .collect::<Vec<_>>(),
                epochs: epochs
                    .into_iter()
                    .map(|block| {
                        let mut block_bytes = vec![];
                        block.serialize(&mut block_bytes).unwrap();
                        hex::encode(&block_bytes)
                    })
                    .collect::<Vec<_>>(),
            }));
        }
        Err(e) => {
            *(key.get_mut(&id).unwrap()) = Some(Err(e));
        }
    }
}

pub async fn create_proof_inner(
    body: ProofRequest,
    proving_key: Arc<Groth16Parameters<BWCurve>>,
) -> std::result::Result<(Vec<Vec<u8>>, Vec<EpochBlock>), Error> {
    let provider = Arc::new(
        Provider::<Http>::try_from(body.node_url.as_ref()).map_err(|_| Error::DataFetchError)?,
    );

    let futs = (body.start_epoch as u64..=body.end_epoch)
        .step_by(1)
        .enumerate()
        .map(|(_, epoch_index)| {
            let provider = provider.clone();
            async move {
                let num = epoch_index * EPOCH_DURATION;
                let previous_num = num - EPOCH_DURATION as u64;
                println!("nums: {}, {}", previous_num, num);

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
                //println!("block: {:?}", block);
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
                println!(
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
    let mut first_epoch = transitions.remove(0).block;
    let mut proofs = vec![];
    let mut epochs = vec![];
    epochs.push(first_epoch.clone());
    for transitions_chunk in transitions.chunks(MAX_TRANSITIONS) {
        let time = start_timer!(|| "Generate proof");

        let proof = prove(
            &params,
            MAX_VALIDATORS as u32,
            &first_epoch,
            &transitions_chunk,
            MAX_TRANSITIONS,
        )
        .map_err(|_| Error::ProofGenerationError)?;
        end_timer!(time);

        // Verifier checks the proof
        let time = start_timer!(|| "Verify proof");
        verify(
            &params.epochs.vk,
            &first_epoch,
            &transitions_chunk.last().unwrap().block,
            &proof,
        )
        .map_err(|_| Error::ProofVerificationError)?;
        end_timer!(time);

        let mut proof_bytes = vec![];
        proof.serialize(&mut proof_bytes).unwrap();
        proofs.push(proof_bytes);

        first_epoch = transitions_chunk.last().unwrap().block.clone();
        epochs.push(first_epoch.clone());
    }

    Ok((proofs, epochs))
}

pub async fn create_proof_handler(
    body: ProofRequest,
    sender: std::sync::mpsc::SyncSender<(String, ProofRequest)>,
) -> Result<impl Reply> {
    let id = Uuid::new_v4().to_string();
    PROOFS_IN_PROGRESS
        .lock()
        .map_err(|_| Error::CouldNotLockMutexError)?
        .insert(id.clone(), None);
    sender.send((id.clone(), body)).unwrap();
    Ok(warp::reply::json(&ProofStartResponse { id }))
}

pub async fn create_proof_status_handler(body: ProofStatusRequest) -> Result<impl Reply> {
    let progress = PROOFS_IN_PROGRESS
        .lock()
        .map_err(|_| Error::CouldNotLockMutexError)?[&body.id]
        .clone();
    let (response, error) = match progress {
        None => (None, None),
        Some(r) => match r {
            Ok(proof_response) => (Some(proof_response), None),
            Err(e) => (None, Some(e)),
        },
    };
    Ok(warp::reply::json(&ProofStatusResponse {
        id: body.id.clone(),
        response,
        error,
    }))
}
