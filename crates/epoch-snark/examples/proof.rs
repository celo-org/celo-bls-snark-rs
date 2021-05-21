use epoch_snark::{prove, trusted_setup, verify, Parameters, BWCurve};
use std::env;
use std::fs::File;
use std::io::BufReader;
use groth16::Parameters as Groth16Parameters;
use algebra::CanonicalDeserialize;
use algebra::BW6_761;
use phase2::parameters::MPCParameters;
use setup_utils::{CheckForCorrectness, SubgroupCheckMode, UseCompression};


#[path = "../tests/fixtures.rs"]
mod fixtures;
use fixtures::generate_test_data;

use tracing_subscriber::{
    filter::EnvFilter,
    fmt::{time::ChronoUtc, Subscriber},
};

use bench_utils::{end_timer, start_timer};

fn main() {
    Subscriber::builder()
        .with_timer(ChronoUtc::rfc3339())
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let rng = &mut rand::thread_rng();
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
    let hashes_in_bls12_377 = false; /*: bool = args
        .next()
        .expect("expected flag for generating or not constraints inside BLS12_377")
        .parse()
        .expect("not a bool");*/
    let faults = (num_validators - 1) / 3;

    // Trusted setup
    let time = start_timer!(|| "Trusted setup");
    let params =
        trusted_setup(num_validators, num_epochs, faults, rng, hashes_in_bls12_377).unwrap();
    end_timer!(time);

    /*let mut file = BufReader::new(File::open("prover_key").expect("Cannot open prover key file"));
    let mpc_params = MPCParameters::<BW6_761>::read_fast(
        file,
        UseCompression::No,
        CheckForCorrectness::Full,
        true,
        SubgroupCheckMode::Auto,
    )
    .expect("should have read parameters");*/
    println!("Read parameters");
    //let epoch_proving_key = Groth16Parameters::<BWCurve>::deserialize(&mut file).unwrap();

    /*let params = Parameters {
        epochs: mpc_params.params,
        hash_to_bits: None,
    };*/

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
    //println!("Time to generate proof was: {:?}", time);

    // Verifier checks the proof
    let time = start_timer!(|| "Verify proof");
    let res = verify(&params.epochs.vk, &first_epoch, &last_epoch, &proof);
    end_timer!(time);
    //println!("Time to verify proof was: {:?}", time);
    assert!(res.is_ok());
}
