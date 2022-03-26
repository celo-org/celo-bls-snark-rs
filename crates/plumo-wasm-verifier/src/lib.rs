use ark_groth16::{Proof, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bls_crypto::{hash_to_curve::try_and_increment::DIRECT_HASH_TO_G1, PublicKey, Signature};
use epoch_snark::{verify, BWCurve, EpochBlock};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use wasm_bindgen::{prelude::*, JsValue};

#[derive(Serialize, Deserialize)]
pub struct ProofData {
    pub vk: String,
    pub proofs: Vec<String>,
    pub epochs: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct ValidatorSet {
    pub initial: Vec<String>,
    pub last: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct BlockData {
    pub bitmap: String,
    pub seal: String,
    pub validators: Vec<String>,
    pub message: String,
}

#[wasm_bindgen]
pub fn plumo_verify(proof_data_val: &JsValue) -> Result<JsValue, JsValue> {
    std::panic::set_hook(Box::new(console_error_panic_hook::hook));

    let proof_data: ProofData = proof_data_val.into_serde().unwrap();
    let vk = VerifyingKey::<BWCurve>::deserialize(&*hex::decode(&proof_data.vk).unwrap()).unwrap();
    let epochs = proof_data
        .epochs
        .iter()
        .map(|epoch| EpochBlock::deserialize(&*hex::decode(epoch).unwrap()).unwrap())
        .collect::<Vec<_>>();
    let proofs = proof_data
        .proofs
        .iter()
        .map(|proof| Proof::<BWCurve>::deserialize(&*hex::decode(proof).unwrap()).unwrap())
        .collect::<Vec<_>>();
    for (two_epochs, proof) in epochs.windows(2).zip(proofs.iter()) {
        let (first_epoch, last_epoch) = (&two_epochs[0], &two_epochs[1]);
        verify(&vk, first_epoch, last_epoch, proof).unwrap();
    }

    let initial_validators = epochs
        .first()
        .unwrap()
        .new_public_keys
        .iter()
        .map(|p| {
            let mut bytes = vec![];
            p.serialize(&mut bytes).unwrap();
            hex::encode(&bytes)
        })
        .collect::<Vec<_>>();
    let last_validators = epochs
        .last()
        .unwrap()
        .new_public_keys
        .iter()
        .map(|p| {
            let mut bytes = vec![];
            p.serialize(&mut bytes).unwrap();
            hex::encode(&bytes)
        })
        .collect::<Vec<_>>();

    Ok(JsValue::from_serde(&ValidatorSet {
        initial: initial_validators,
        last: last_validators,
    })
    .unwrap())
}

#[wasm_bindgen]
pub fn block_verify(block_data_val: &JsValue) -> Result<(), JsValue> {
    std::panic::set_hook(Box::new(console_error_panic_hook::hook));

    let block_data: BlockData = block_data_val.into_serde().unwrap();
    let bitmap = BigUint::from_bytes_be(&hex::decode(&block_data.bitmap).unwrap());
    let seal = Signature::deserialize(&*hex::decode(&block_data.seal).unwrap()).unwrap();
    let mut participating = vec![];
    for (i, validator) in block_data.validators.iter().enumerate() {
        if bitmap.bit(i as u64) {
            participating.push(PublicKey::deserialize(&*hex::decode(&validator).unwrap()).unwrap());
        }
    }
    let aggregated_pk = PublicKey::aggregate(&participating);
    aggregated_pk
        .verify(
            &hex::decode(block_data.message).unwrap(),
            &[],
            &seal,
            &*DIRECT_HASH_TO_G1,
        )
        .unwrap();

    Ok(())
}
