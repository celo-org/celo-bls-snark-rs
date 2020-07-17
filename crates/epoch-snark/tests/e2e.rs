use bench_utils::{end_timer, start_timer};
use algebra::serialize::CanonicalSerialize;
use epoch_snark::{prove, trusted_setup, verify, ValidatorSetUpdate, BLSCurve, CPCurve, CPField, CPFrParams, to_update, to_epoch_data, hash_first_last_epoch_block, pack};
use tracing::{info, span, Level};

mod fixtures;
use fixtures::generate_test_data;


#[test]
#[ignore] // This test makes CI run out of memory and takes too long. It works though!
fn prover_verifier_groth16() {
    let rng = &mut rand::thread_rng();
    let num_transitions = 2;
    let faults = 1;
    let num_validators = 3 * faults + 1;

    let hashes_in_bls12_377 = true;

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

    let prove_time = start_timer!(|| "Groth16 prove time");
    // Prover generates the proof given the params
    let proof = prove(&params, num_validators as u32, &first_epoch, &transitions).unwrap();
    end_timer!(prove_time);

    // Verifier checks the proof
    let verify_time = start_timer!(|| "Groth16 verify time");
    let res = verify(&params.epochs.vk, &first_epoch, &last_epoch, &proof);
    end_timer!(verify_time);
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

use algebra::{UniformRand, One};
use algebra::{bw6_761::Fr, BW6_761};
use blake2::Blake2s;
use core::ops::MulAssign;
use poly_commit::marlin_pc::MarlinKZG10;

use marlin::Marlin;
use groth16::KeypairAssembly;
use r1cs_core::{ConstraintSystem, ConstraintSynthesizer};
use bls_crypto::Signature;

type MultiPC = MarlinKZG10<BW6_761>;
type MarlinInst = Marlin<Fr, MultiPC, Blake2s>;

#[test]
fn prover_verifier_marlin() {
    let rng = &mut rand::thread_rng();
    let num_transitions = 2;
    let faults = 1;
    let num_validators = 3 * faults + 1;

    let hashes_in_bls12_377 = false;

    type MultiPC = MarlinKZG10<BW6_761>;
    type MarlinInst = Marlin<Fr, MultiPC, Blake2s>;
    let universal_srs = MarlinInst::universal_setup(514023, 514019, 2570867, rng).unwrap();


    info!(
        "Generating parameters for {} validators and {} epochs",
        num_validators, num_transitions
    );

    let span = span!(Level::TRACE, "setup");
    let _enter = span.enter();

    info!("BLS");
    let empty_epochs =
        ValidatorSetUpdate::empty(num_validators, num_transitions, faults, None);

    let mut assembly = KeypairAssembly::<BW6_761> {
        num_inputs: 0,
        num_aux: 0,
        num_constraints: 0,
        at: vec![],
        bt: vec![],
        ct: vec![],
    };

    // Allocate the "one" input variable
    assembly.alloc_input(|| "", || Ok(Fr::one())).unwrap();

    empty_epochs.clone().generate_constraints(&mut assembly).unwrap();
    println!("constraints: {}", assembly.num_constraints());

    let (index_pk, index_vk) = MarlinInst::index(&universal_srs, empty_epochs).unwrap();

    // Create the state to be proven (first epoch + `num_transitions` transitions.
    // Note: This is all data which should be fetched via the Celo blockchain
    let (first_epoch, transitions, last_epoch) =
        generate_test_data(num_validators, faults, num_transitions);

    let epochs = transitions
        .iter()
        .map(|transition| to_update(transition))
        .collect::<Vec<_>>();

    let asig = Signature::aggregate(transitions.iter().map(|epoch| &epoch.aggregate_signature));

    let circuit = ValidatorSetUpdate::<BLSCurve> {
        initial_epoch: to_epoch_data(&first_epoch),
        epochs,
        aggregated_signature: Some(*asig.as_ref()),
        num_validators: num_validators as u32,
        hash_helper: None,
    };

    let prove_time = start_timer!(|| "Marlin prove time");
    let proof = MarlinInst::prove(&index_pk, circuit, rng).unwrap();
    end_timer!(prove_time);
    println!("Called prover");

    let hash = hash_first_last_epoch_block(&first_epoch, &last_epoch).unwrap();
    // packs them
    let public_inputs = pack::<CPField, CPFrParams>(&hash).unwrap();
    let verify_time = start_timer!(|| "Marlin verify time");
    assert!(MarlinInst::verify(&index_vk, &public_inputs, &proof, rng).unwrap());
    end_timer!(verify_time);

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