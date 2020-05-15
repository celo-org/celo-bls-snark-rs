//! # BLS Epoch SNARK
//!
//! This crate implements a SNARK as specified in the [Plumo
//! paper](https://docs.zkproof.org/pages/standards/accepted-workshop3/proposal-plumo_celolightclient.pdf).
//!
//! The state transition function which is being enforced is summarized below:
//!
//! - Assume `N` block headers
//! - Assume `S_i` total signers per header, where `i in 1..N`
//!
//! The SNARK proves that given the first and last block header, all intermediate transitions
//! have been signed by at least 2/3rds of the previous header's signers.
//!
//! In other words, the `i`th header must contain at least `2 / 3 * S_{i-1}` signatures. Each
//! header then specifies a new set of signers, and this procedure is repeated until the last
//! header. The signatures in each header are BLS signatures which can be batch verified, so the
//! SNARK proves the correct verification of an aggregate BLS signature across the signers of all
//! blocks.
//!
//! A presentation of this mechanism can be found [here](https://www.youtube.com/watch?v=2e0XpWgFKLg).

/// High level methods for generating public parameters & producing and verifying SNARK proofs for
/// a headerchain of blocks
mod api;
pub use api::*;

mod encoding;
pub use encoding::EncodingError;

mod epoch_block;
pub use epoch_block::{EpochBlock, EpochTransition};

mod gadgets;
pub use gadgets::ValidatorSetUpdate;
