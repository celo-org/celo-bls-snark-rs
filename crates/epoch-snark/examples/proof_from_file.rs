use epoch_snark::{prove, verify, Parameters, BWCurve};
use std::io::BufReader;
use std::fs::File;
use ark_groth16::data_structures::ProvingKey as Groth16Parameters;
use ark_serialize::CanonicalDeserialize;


use std::env;

#[path = "../tests/fixtures.rs"]
mod fixtures;
use fixtures::generate_test_data;

use tracing_subscriber::{
    filter::EnvFilter,
    fmt::{time::ChronoUtc, Subscriber},
};

use ark_std::{end_timer, start_timer};

fn main() {
    Subscriber::builder()
        .with_timer(ChronoUtc::rfc3339())
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let mut args = env::args();
    args.next().unwrap(); // discard the program name
    let num_validators = args
        .next()
        .expect("num validators was expected")
        .parse()
        .expect("NaN");
    let num_epochs = args
        .next()
        .expect("num epochs was expected")
        .parse()
        .expect("NaN");
    let faults = (num_validators - 1) / 3;

    let mut file = BufReader::new(File::open("prover_key").expect("Cannot open prover key file"));
    println!("Read parameters");
    let epoch_proving_key = Groth16Parameters::<BWCurve>::deserialize_unchecked(&mut file).unwrap();

    let params = Parameters {
        epochs: epoch_proving_key,
        hash_to_bits: None,
    };

    // Create the state to be proven (first - last and in between)
    // Note: This is all data which should be fetched via the Celo blockchain
    let (first_epoch, transitions, last_epoch) =
        generate_test_data(num_validators, faults, num_epochs);

    // Prover generates the proof given the params
    let time = start_timer!(|| "Generate proof");
    let proof = prove(
        &params,
        num_validators as u32,
        &first_epoch,
        &transitions,
        num_epochs,
    )
    .unwrap();
    end_timer!(time);

    // Verifier checks the proof
    let time = start_timer!(|| "Verify proof");
    let res = verify(&params.epochs.vk, &first_epoch, &last_epoch, &proof);
    end_timer!(time);
    assert!(res.is_ok());
}
