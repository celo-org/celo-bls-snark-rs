mod prover;
pub use prover::prove;

mod setup;
pub use setup::{trusted_setup, Parameters};

mod verifier;
pub use verifier::{verify, VerificationError};

// Instantiate certain types to avoid confusion
pub type BLSCurve = ark_bls12_377::Bls12_377;
pub type BLSCurveG1 = ark_bls12_377::G1Projective;
pub type BLSCurveG2 = ark_bls12_377::G2Projective;
type CPField = ark_bw6_761::Fr;
pub type CPCurve = ark_bw6_761::BW6_761;
type CPFrParams = ark_bw6_761::FrParameters;
