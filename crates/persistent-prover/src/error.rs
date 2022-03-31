use serde::Serialize;
use thiserror::Error;

#[derive(Error, Debug, Clone, Serialize)]
pub enum Error {
    #[error("error generating proof")]
    ProofGenerationError,
    #[error("error fetching data")]
    DataFetchError,
    #[error("error generating data")]
    DataGenerationError,
    #[error("error verifying proof")]
    ProofVerificationError,
    #[error("could not find signature")]
    CouldNotFindSignatureError,
    #[error("could not lock mutex")]
    CouldNotLockMutexError,
    #[error("could not check proof status")]
    CouldNotCheckProofStatusError,
    #[error("epoch too small")]
    EpochTooSmallError,
}

impl warp::reject::Reject for Error {}

impl warp::reply::Reply for Error {
    fn into_response(self) -> warp::reply::Response {
        warp::reply::with_status(
            self.to_string(),
            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
        )
        .into_response()
    }
}
