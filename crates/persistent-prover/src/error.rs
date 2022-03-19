use warp::{Rejection, Reply, http::StatusCode};
use serde::Serialize;
use thiserror::Error;
use std::convert::Infallible;

#[derive(Error, Debug)]
pub enum Error {
    #[error("error generating proof")]
    ProofGenerationError,
}

#[derive(Serialize)]
struct ErrorResponse {
    message: String,
}

pub async fn handle_rejection(err: Rejection) -> std::result::Result<impl Reply, Infallible> {
    let code;
    let message;

    if err.is_not_found() {
            code = StatusCode::NOT_FOUND;
            message = "Not Found";
    } else if let Some(_) = err.find::<warp::filters::body::BodyDeserializeError>() {
            code = StatusCode::BAD_REQUEST;
            message = "Invalid Body";
    } else if let Some(e) = err.find::<Error>() {
            match e {
                _ => {
                    eprintln!("unhandled application error: {:?}", err);
                    code = StatusCode::INTERNAL_SERVER_ERROR;
                    message = "Internal Server Error";
                }
            }
    } else if let Some(_) = err.find::<warp::reject::MethodNotAllowed>() {
            code = StatusCode::METHOD_NOT_ALLOWED;
            message = "Method Not Allowed";
    } else {
            eprintln!("unhandled error: {:?}", err);
            code = StatusCode::INTERNAL_SERVER_ERROR;
            message = "Internal Server Error";
    }

    let json = warp::reply::json(&ErrorResponse {
            message: message.into(),
    });

    Ok(warp::reply::with_status(json, code))
}