mod prover;
pub use prover::prove;

mod setup;
pub use setup::trusted_setup;

mod verifier;
pub use verifier::{verify, VerificationError};

// Instantiate certain types to avoid confusion
use algebra::{bls12_377, cp6_782};
type BLSCurve = bls12_377::Bls12_377;
type CPField = cp6_782::Fr;
type CPCurve = cp6_782::CP6_782;
type CPFrParams = cp6_782::FrParameters;
