mod prover;
pub use prover::prove;

mod setup;
pub use setup::{trusted_setup, Parameters};

mod verifier;
pub use verifier::{verify, VerificationError};

// Instantiate certain types to avoid confusion
use algebra::{bls12_377, sw6};
type BLSCurve = bls12_377::Bls12_377;
type CPField = sw6::Fr;
type CPCurve = sw6::SW6;
type CPFrParams = sw6::FrParameters;
