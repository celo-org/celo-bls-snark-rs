use ark_ec::PairingEngine;
use epoch_snark::{prove, verify, Parameters, BWCurve};
use ark_groth16::data_structures::ProvingKey as Groth16Parameters;
use ark_serialize::CanonicalDeserialize;
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


#[tokio::main]
async fn main() {
    Subscriber::builder()
        .with_timer(ChronoUtc::rfc3339())
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let mut file = BufReader::new(File::open("prover_key").expect("Cannot open prover key file"));
    println!("Read parameters");
    let epoch_proving_key = Groth16Parameters::<BWCurve>::deserialize_unchecked(&mut file).unwrap();
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