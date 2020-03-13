use algebra::{
    bls12_377::{Bls12_377, G1Projective},
    ProjectiveCurve,
};

use bls_crypto::{PublicKey, Signature};
use bls_gadgets::test_helpers::{keygen_batch, keygen_mul};
use epoch_snark::epoch_block::{EpochBlock, EpochTransition};

// Returns the initial epoch and a list of signed `num_epochs` state transitions
pub fn generate_test_data(
    num_validators: usize,
    faults: usize,
    num_epochs: usize,
) -> (EpochBlock, Vec<EpochTransition>, EpochBlock) {
    let bitmaps = generate_bitmaps(num_epochs, num_validators, faults);
    let initial_validator_set = keygen_mul::<Bls12_377>(num_validators as usize);
    // Generate the initial epoch. This was proven to be correct either via
    // the previous epoch proof, or it's the genesis block
    let initial_pubkeys = initial_validator_set
        .1
        .iter()
        .map(|pk| PublicKey::from_pk(*pk))
        .collect::<Vec<_>>();
    let first_epoch = generate_block(0, faults, &initial_pubkeys);

    // Generate keys for the validators of each epoch
    let validators = keygen_batch::<Bls12_377>(num_epochs, num_validators as usize);
    // generate the block for i+1th epoch
    let pubkeys = validators
        .1
        .iter()
        .map(|epoch_keys| {
            epoch_keys
                .iter()
                .map(|pk| PublicKey::from_pk(*pk))
                .collect()
        })
        .collect::<Vec<Vec<_>>>();

    // Signers will be from the 1st to the last-1 epoch
    let mut signers = vec![initial_validator_set.0];
    signers.extend_from_slice(&validators.0[..validators.0.len() - 1]);
    // sign each state transition
    let mut transitions = vec![];
    for (i, signers_epoch) in signers.iter().enumerate() {
        let block = generate_block(i + 1, faults, &pubkeys[i]);
        // TODO: Figure out how to hash the epoch.
        let hash = G1Projective::prime_subgroup_generator();

        // A subset of the i-th validator set, signs on the i+1th epoch's G1 hash
        let bitmap_epoch = &bitmaps[i];
        let asig = {
            let mut asig = G1Projective::prime_subgroup_generator();
            for sk in signers_epoch {
                if bitmap_epoch[i] {
                    asig += hash.mul(*sk)
                }
            }
            asig -= G1Projective::prime_subgroup_generator();
            asig
        };
        let asig = Signature::from_sig(asig);

        let transition = EpochTransition {
            block,
            aggregate_signature: asig,
            bitmap: bitmap_epoch.to_vec(),
        };
        transitions.push(transition);
    }
    let last_epoch = transitions[transitions.len()].block.clone();

    (first_epoch.clone(), transitions, last_epoch)
}

fn generate_block(index: usize, non_signers: usize, pubkeys: &[PublicKey]) -> EpochBlock {
    let aggregated_public_key = PublicKey::aggregate(&pubkeys);
    EpochBlock {
        index: index as u16,
        maximum_non_signers: non_signers as u32,
        aggregated_public_key,
        new_public_keys: pubkeys.to_vec(),
    }
}

// generates `num_epochs` bitmaps with `num_validators - faults` 1 bits set and `faults` 0 bits set
fn generate_bitmaps(num_epochs: usize, num_validators: usize, faults: usize) -> Vec<Vec<bool>> {
    let mut ret = Vec::new();
    for _ in 0..num_epochs {
        let mut bitmap = vec![true; num_validators];
        for i in 0..faults {
            bitmap[i] = false;
        }
        ret.push(bitmap)
    }
    ret
}
