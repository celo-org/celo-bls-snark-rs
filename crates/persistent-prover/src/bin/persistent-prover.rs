use ark_ec::PairingEngine;
use epoch_snark::{prove, verify, Parameters, BWCurve};
use ark_groth16::{data_structures::ProvingKey as Groth16Parameters, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use ark_std::Zero;
use gumdrop::Options;
use std::{
    convert::TryFrom,
    fs::File,
    io::{BufReader, BufWriter},
    path::PathBuf,
    sync::Arc,
};
use std::env;
use persistent_prover::{handler, types::HeaderExtra};

use tracing_subscriber::{
    filter::EnvFilter,
    fmt::{time::ChronoUtc, Subscriber},
};
use tracing::info;
use ethers::{types::U256, utils::rlp};
use ethers::providers::*;

use ark_std::{end_timer, start_timer};
use serde::{Deserialize, Serialize};
use warp::{Filter, Rejection, http::StatusCode, Reply};
use std::convert::Infallible;

fn with_proving_key<E: PairingEngine>(proving_key: Arc<Groth16Parameters<E>>) -> impl Filter<Extract = (Arc<Groth16Parameters<E>>,), Error = Infallible> + Clone {
    warp::any().map(move || proving_key.clone())
}

#[derive(Debug, Options)]
struct ProverOptions {
    #[options(help = "use fake proving key for debug purposes")]
    fake_proving_key: bool,
}

#[tokio::main]
async fn main() {
    let opts = ProverOptions::parse_args_default_or_exit();

    Subscriber::builder()
        .with_timer(ChronoUtc::rfc3339())
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let mut file = BufReader::new(File::open("prover_key").expect("Cannot open prover key file"));
    println!("Read parameters");
    let epoch_proving_key = if !opts.fake_proving_key  {
        Groth16Parameters::<BWCurve>::deserialize_unchecked(&mut file).unwrap()
    } else {
        Groth16Parameters::<BWCurve> {
            vk: VerifyingKey::<BWCurve> {
                alpha_g1: <BWCurve as PairingEngine>::G1Affine::zero(),
                beta_g2: <BWCurve as PairingEngine>::G2Affine::zero(),
                gamma_g2: <BWCurve as PairingEngine>::G2Affine::zero(),
                delta_g2: <BWCurve as PairingEngine>::G2Affine::zero(),
                gamma_abc_g1: vec![],
            },
            beta_g1: <BWCurve as PairingEngine>::G1Affine::zero(),
            delta_g1: <BWCurve as PairingEngine>::G1Affine::zero(),
            a_query: vec![],
            b_g1_query: vec![],
            b_g2_query: vec![],
            h_query: vec![],
            l_query: vec![],
        }
    };
    let epoch_proving_key = Arc::new(epoch_proving_key);
    println!("Done read parameters");

    let health_route = warp::path!("health")
    .map(|| StatusCode::OK);

    let proof_route = warp::path!("proof")
        .and(warp::post())
        .and(warp::body::json())
        .and(with_proving_key(epoch_proving_key.clone()))
        .and_then(handler::create_proof_handler);

    let routes = health_route
    .or(proof_route)
    .with(warp::cors().allow_any_origin());

    println!("Serving");
    warp::serve(routes).run(([127, 0, 0, 1], 8000)).await;
}