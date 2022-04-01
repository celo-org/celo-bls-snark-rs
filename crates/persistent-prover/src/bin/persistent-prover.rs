use ark_ec::PairingEngine;
use ark_ff::Zero;
use ark_groth16::{data_structures::ProvingKey as Groth16Parameters, VerifyingKey};
use ark_serialize::CanonicalDeserialize;
use epoch_snark::BWCurve;
use ethers::prelude::BlockNumber;
use ethers::providers::*;
use gumdrop::Options;
use persistent_prover::{
    error::Error,
    get_aligned_epoch_index, get_epoch_index, get_existing_proof,
    handler::{self, ProofRequest},
    MAX_TRANSITIONS, MIN_CIP22_EPOCH,
};
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::mpsc::sync_channel;
use std::thread;
use std::thread::sleep;
use std::time::Duration;
use std::{
    fs::File,
    io::BufReader,
    sync::{Arc, Mutex},
};
use tracing::{error, info};
use uuid::Uuid;
use warp::{http::StatusCode, Filter};

fn with_sender(
    sender: std::sync::mpsc::SyncSender<(String, ProofRequest)>,
) -> impl Filter<Extract = (std::sync::mpsc::SyncSender<(String, ProofRequest)>,), Error = Infallible>
       + Clone {
    warp::any().map(move || sender.clone())
}

#[derive(Debug, Options)]
struct ProverOptions {
    #[options(help = "use fake proving key for debug purposes")]
    fake_proving_key: bool,
    #[options(help = "node URL", default = "http://localhost:8545")]
    node_url: String,
    #[options(help = "proving key location", default = "prover_key")]
    proving_key_path: String,
}

fn insert_task_if_not_exists(
    proofs_in_progress: Arc<Mutex<HashMap<(u64, u64), bool>>>,
    start_epoch: u64,
    end_epoch: u64,
) {
    if proofs_in_progress
        .lock()
        .expect("should have locked mutex")
        .contains_key(&(start_epoch, end_epoch))
    {
        error!(
            "Already generating proof for epochs {}-{}",
            start_epoch, end_epoch,
        );
    }
    proofs_in_progress
        .lock()
        .expect("should have locked mutex")
        .insert((start_epoch, end_epoch), true);
}

fn remove_task(
    proofs_in_progress: Arc<Mutex<HashMap<(u64, u64), bool>>>,
    start_epoch: u64,
    end_epoch: u64,
) {
    proofs_in_progress
        .lock()
        .expect("should have locked mutex")
        .remove(&(start_epoch, end_epoch));
}

fn check_task_in_progress(
    proofs_in_progress: Arc<Mutex<HashMap<(u64, u64), bool>>>,
    start_epoch: u64,
    end_epoch: u64,
) -> bool {
    proofs_in_progress
        .lock()
        .expect("should have locked mutex")
        .contains_key(&(start_epoch, end_epoch))
}

#[tokio::main]
async fn main() {
    let opts = ProverOptions::parse_args_default_or_exit();
    tracing_subscriber::fmt::init();

    let mut file =
        BufReader::new(File::open(opts.proving_key_path).expect("Cannot open prover key file"));
    info!("Read parameters");
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
    info!("Done read parameters");

    let (sender, receiver) = sync_channel(1000);
    let node_url_for_thread = opts.node_url.clone();

    let proofs_in_progress: Arc<Mutex<HashMap<(u64, u64), bool>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let proofs_in_progress_for_processing = proofs_in_progress.clone();
    thread::spawn(move || {
        let proofs_in_progress = proofs_in_progress_for_processing;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        loop {
            let (id, body): (String, ProofRequest) = receiver.recv().unwrap();

            match rt.block_on(crate::handler::create_proof_inner_and_catch_errors(
                body.clone(),
                epoch_proving_key.clone(),
                node_url_for_thread.clone(),
            )) {
                Err(e) => {
                    error!(
                        "Failed generating proof for id {}, epochs {}-{}: {}",
                        id,
                        body.start_epoch,
                        body.end_epoch,
                        e.to_string()
                    );
                }
                Ok(()) => {
                    info!(
                        "Finished generating proof for id {}, epochs {}-{}",
                        id, body.start_epoch, body.end_epoch
                    );
                }
            };
            remove_task(proofs_in_progress.clone(), body.start_epoch, body.end_epoch);
        }
    });

    let proofs_in_progress_for_checking = proofs_in_progress.clone();
    let sender_for_thread = sender.clone();
    thread::spawn(move || {
        let proofs_in_progress = proofs_in_progress_for_checking;
        let sender = sender_for_thread;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        loop {
            let check_for_new_epoch = || -> eyre::Result<()> {
                let provider = Arc::new(Provider::<Http>::try_from(opts.node_url.as_ref())?);
                let latest_block = rt
                    .block_on(provider.get_block(BlockNumber::Latest))
                    .map_err(|_| Error::DataFetchError)?;
                if let Some(block) = latest_block {
                    let epoch_index =
                        get_epoch_index(block.number.ok_or(Error::DataFetchError)?.as_u64());
                    let aligned_start_epoch_index = get_aligned_epoch_index(epoch_index);

                    let send_if_needed = |start_epoch, end_epoch| -> eyre::Result<()> {
                        let existing_proof =
                            get_existing_proof(start_epoch as i32, end_epoch as i32)?;

                        if existing_proof.is_none()
                            && !check_task_in_progress(
                                proofs_in_progress.clone(),
                                start_epoch,
                                end_epoch,
                            )
                        {
                            info!("Found new epoch {}, starting proof generation", epoch_index);
                            let proof_id = Uuid::new_v4().to_string();

                            insert_task_if_not_exists(
                                proofs_in_progress.clone(),
                                start_epoch,
                                end_epoch,
                            );

                            sender.send((
                                proof_id.clone(),
                                ProofRequest {
                                    start_epoch,
                                    end_epoch,
                                },
                            ))?;
                        }

                        Ok(())
                    };
                    for older_epoch_index in
                        (MIN_CIP22_EPOCH..aligned_start_epoch_index).step_by(MAX_TRANSITIONS)
                    {
                        send_if_needed(
                            older_epoch_index,
                            older_epoch_index + MAX_TRANSITIONS as u64,
                        )?;
                    }
                    send_if_needed(aligned_start_epoch_index, epoch_index)?;
                }
                Ok(())
            };

            if let Err(e) = check_for_new_epoch() {
                error!("Could not check for new epoch: {}", e.to_string());
            }
            sleep(Duration::from_secs(60));
        }
    });

    let health_route = warp::path!("health").map(|| StatusCode::OK);

    let proof_route = warp::path!("proof_create")
        .and(warp::post())
        .and(warp::body::json())
        .and(with_sender(sender.clone()))
        .and_then(handler::create_proof_handler);

    let proof_status_route = warp::path!("proof_get")
        .and(warp::post())
        .and(warp::body::json())
        .and_then(handler::create_proof_get_handler);

    let proof_list_route = warp::path!("proof_list")
        .and(warp::get())
        .and_then(handler::create_proof_list_handler);

    let routes = health_route
        .or(proof_route)
        .or(proof_status_route)
        .or(proof_list_route)
        .with(warp::cors().allow_any_origin());

    info!("Serving");
    warp::serve(routes).run(([127, 0, 0, 1], 8000)).await;
}
