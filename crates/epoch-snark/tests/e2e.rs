use ark_serialize::CanonicalSerialize;
use epoch_snark::{prove, trusted_setup, verify};

mod fixtures;
use fixtures::generate_test_data;

#[test]
#[ignore] // This test makes CI run out of memory and takes too long. It works though!
fn prover_verifier_groth16() {
    let rng = &mut rand::thread_rng();
    let num_transitions = 2;
    let faults = 1;
    let num_validators = 3 * faults + 1;

    let hashes_in_bls12_377 = false;

    // Trusted setup
    let params = trusted_setup(
        num_validators,
        num_transitions,
        faults,
        rng,
        hashes_in_bls12_377,
    )
    .unwrap();

    // Create the state to be proven (first epoch + `num_transitions` transitions.
    // Note: This is all data which should be fetched via the Celo blockchain
    let (first_epoch, transitions, last_epoch) =
        generate_test_data(num_validators, faults, num_transitions);

    // Prover generates the proof given the params
    let proof = prove(
        &params,
        num_validators as u32,
        &first_epoch,
        &transitions,
        num_transitions,
    )
    .unwrap();

    // Verifier checks the proof
    let res = verify(&params.epochs.vk, &first_epoch, &last_epoch, &proof);
    assert!(res.is_ok());

    // Serialize the proof / vk
    let mut serialized_vk = vec![];
    params.epochs.vk.serialize(&mut serialized_vk).unwrap();
    let mut serialized_proof = vec![];
    proof.serialize(&mut serialized_proof).unwrap();
    dbg!(hex::encode(&serialized_vk));
    dbg!(hex::encode(&serialized_proof));

    let mut first_pubkeys = vec![];
    first_epoch
        .new_public_keys
        .serialize(&mut first_pubkeys)
        .unwrap();
    let mut last_pubkeys = vec![];
    last_epoch
        .new_public_keys
        .serialize(&mut last_pubkeys)
        .unwrap();
    dbg!(hex::encode(&first_pubkeys));
    dbg!(hex::encode(&last_pubkeys));
}

#[test]
#[ignore] // This test makes CI run out of memory and takes too long. It works though!
fn prover_verifier_groth16_with_dummy() {
    let rng = &mut rand::thread_rng();
    let num_transitions = 2;
    let max_transitions = num_transitions + 10;
    let faults = 1;
    let num_validators = 3 * faults + 1;

    let hashes_in_bls12_377 = false;

    // Trusted setup
    let params = trusted_setup(
        num_validators,
        max_transitions,
        faults,
        rng,
        hashes_in_bls12_377,
    )
    .unwrap();

    // Create the state to be proven (first epoch + `num_transitions` transitions.
    // Note: This is all data which should be fetched via the Celo blockchain
    let (first_epoch, transitions, last_epoch) =
        generate_test_data(num_validators, faults, num_transitions);

    // Prover generates the proof given the params
    let proof = prove(
        &params,
        num_validators as u32,
        &first_epoch,
        &transitions,
        max_transitions,
    )
    .unwrap();

    // Verifier checks the proof
    let res = verify(&params.epochs.vk, &first_epoch, &last_epoch, &proof);
    assert!(res.is_ok());

    // Serialize the proof / vk
    let mut serialized_vk = vec![];
    params.epochs.vk.serialize(&mut serialized_vk).unwrap();
    let mut serialized_proof = vec![];
    proof.serialize(&mut serialized_proof).unwrap();
    dbg!(hex::encode(&serialized_vk));
    dbg!(hex::encode(&serialized_proof));

    let mut first_pubkeys = vec![];
    first_epoch
        .new_public_keys
        .serialize(&mut first_pubkeys)
        .unwrap();
    let mut last_pubkeys = vec![];
    last_epoch
        .new_public_keys
        .serialize(&mut last_pubkeys)
        .unwrap();
    dbg!(hex::encode(&first_pubkeys));
    dbg!(hex::encode(&last_pubkeys));
}
