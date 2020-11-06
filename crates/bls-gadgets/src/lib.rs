//! # BLS Gadgets
//!
//! This module provides gadgets for constructing R1CS involving BLS Signatures
//! over the BLS12-377 curve.

mod bls;
pub use bls::BlsVerifyGadget;

mod bitmap;
pub(crate) use bitmap::Bitmap;

mod y_to_bit;
pub use y_to_bit::{FpUtils, YToBitGadget};

mod hash_to_group;
pub use hash_to_group::{hash_to_bits, HashToGroupGadget};

/// Utility functions which do not involve generating constraints
pub mod utils;
