use ark_bls12_377::{Bls12_377, G1Projective};
use ark_ec::ProjectiveCurve;
use ark_ff::{PrimeField, Zero};

use bls_crypto::test_helpers::{keygen_batch, keygen_mul};
use bls_crypto::{PublicKey, Signature};
use epoch_snark::{EpochBlock, EpochTransition};

// Returns the initial epoch and a list of signed `num_epochs` state transitions
pub fn generate_test_data(
    num_validators: usize,
    faults: usize,
    num_epochs: usize,
) -> (EpochBlock, Vec<EpochTransition>, EpochBlock) {
    let bitmaps = generate_bitmaps(num_epochs, num_validators, faults);
    let initial_validator_set = keygen_mul::<Bls12_377>(num_validators);
    // Generate the initial epoch. This was proven to be correct either via
    // the previous epoch proof, or it's the genesis block
    let initial_pubkeys = initial_validator_set
        .1
        .iter()
        .map(|pk| PublicKey::from(*pk))
        .collect::<Vec<_>>();
    let first_epoch = generate_block(
        0,
        0,
        &[1u8; EpochBlock::ENTROPY_BYTES],
        &[2u8; EpochBlock::ENTROPY_BYTES],
        faults,
        num_validators,
        &initial_pubkeys,
    );

    // Generate keys for the validators of each epoch
    let validators = keygen_batch::<Bls12_377>(num_epochs, num_validators);
    // generate the block for i+1th epoch
    let pubkeys = validators
        .1
        .iter()
        .map(|epoch_keys| epoch_keys.iter().map(|pk| PublicKey::from(*pk)).collect())
        .collect::<Vec<Vec<_>>>();

    // Signers will be from the 1st to the last-1 epoch
    let mut signers = vec![initial_validator_set.0];
    signers.extend_from_slice(&validators.0[..validators.0.len() - 1]);
    // sign each state transition
    let mut transitions = vec![];
    for (i, signers_epoch) in signers.iter().enumerate() {
        let block: EpochBlock = generate_block(
            i + 1,
            i + 10,
            &[(i + 2) as u8; EpochBlock::ENTROPY_BYTES],
            &[(i + 1) as u8; EpochBlock::ENTROPY_BYTES],
            faults,
            num_validators,
            &pubkeys[i],
        );
        let hash = block.hash_to_g1_cip22().unwrap();

        // A subset of the i-th validator set, signs on the i+1th epoch's G1 hash
        let bitmap_epoch = &bitmaps[i];
        let asig = {
            let mut asig = G1Projective::zero();
            for (j, sk) in signers_epoch.iter().enumerate() {
                if bitmap_epoch[j] {
                    asig += hash.mul(sk.into_repr())
                }
            }
            asig
        };
        let asig = Signature::from(asig);

        let transition = EpochTransition {
            block,
            aggregate_signature: asig,
            bitmap: bitmap_epoch.to_vec(),
        };
        transitions.push(transition);
    }
    let last_epoch = transitions[transitions.len() - 1].block.clone();

    (first_epoch, transitions, last_epoch)
}

fn generate_block(
    index: usize,
    round: usize,
    epoch_entropy: &[u8],
    parent_entropy: &[u8],
    non_signers: usize,
    max_validators: usize,
    pubkeys: &[PublicKey],
) -> EpochBlock {
    EpochBlock {
        index: index as u16,
        round: round as u8,
        epoch_entropy: Some(epoch_entropy.to_vec()),
        parent_entropy: Some(parent_entropy.to_vec()),
        maximum_non_signers: non_signers as u32,
        maximum_validators: max_validators,
        new_public_keys: pubkeys.to_vec(),
    }
}

// generates `num_epochs` bitmaps with `num_validators - faults` 1 bits set and `faults` 0 bits set
fn generate_bitmaps(num_epochs: usize, num_validators: usize, faults: usize) -> Vec<Vec<bool>> {
    let mut ret = Vec::new();
    for _ in 0..num_epochs {
        let mut bitmap = vec![true; num_validators];
        for b in bitmap.iter_mut().take(faults) {
            *b = false;
        }
        ret.push(bitmap)
    }
    ret
}
