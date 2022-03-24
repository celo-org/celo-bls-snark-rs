use ark_ec::PairingEngine;
use ark_ff::Zero;
use ark_groth16::{data_structures::ProvingKey as Groth16Parameters, VerifyingKey};
use ark_relations::r1cs::*;
use ark_serialize::CanonicalDeserialize;
use epoch_snark::BWCurve;
use gumdrop::Options;
use persistent_prover::handler;
use std::convert::Infallible;
use std::{fs::File, io::BufReader, sync::Arc};
use tracing_subscriber::{
    fmt::{fmt, time::ChronoUtc},
    layer::SubscriberExt,
    EnvFilter,
};
use warp::{http::StatusCode, Filter};

fn with_proving_key<E: PairingEngine>(
    proving_key: Arc<Groth16Parameters<E>>,
) -> impl Filter<Extract = (Arc<Groth16Parameters<E>>,), Error = Infallible> + Clone {
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
    let layer = ConstraintLayer::new(ark_relations::r1cs::TracingMode::OnlyConstraints);

    tracing::subscriber::set_global_default(
        fmt()
            .with_timer(ChronoUtc::rfc3339())
            .with_env_filter(EnvFilter::from_default_env())
            .finish()
            .with(layer),
    )
    .unwrap();

    let mut file = BufReader::new(File::open("prover_key").expect("Cannot open prover key file"));
    println!("Read parameters");
    let epoch_proving_key = if !opts.fake_proving_key {
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

    let health_route = warp::path!("health").map(|| StatusCode::OK);

    let proof_route = warp::path!("proof_create")
        .and(warp::post())
        .and(warp::body::json())
        .and(with_proving_key(epoch_proving_key.clone()))
        .and_then(handler::create_proof_handler);

    let proof_status_route = warp::path!("proof_status")
        .and(warp::post())
        .and(warp::body::json())
        .and_then(handler::create_proof_status_handler);

    let routes = health_route
        .or(proof_route)
        .or(proof_status_route)
        .with(warp::cors().allow_any_origin());

    println!("Serving");
    warp::serve(routes).run(([127, 0, 0, 1], 8000)).await;
}
