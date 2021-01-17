/// Prover Verifier Generator
///
/// Setup: Trusted setup over Groth16 for the Hash To Bits and the Epoch Transition circuits
use crate::gadgets::{HashToBits, ValidatorSetUpdate};

use ark_ec::PairingEngine;
use ark_relations::r1cs::SynthesisError;
use rand::Rng;

use super::{BLSCurve, BWCurve, BWFrParams};

use ark_groth16::{generate_random_parameters, ProvingKey as Groth16Parameters};
use tracing::{info, span, Level};

type Result<T> = std::result::Result<T, SynthesisError>;

/// Public parameters for the BLS and for the CRH->XOF SNARKs
pub struct Parameters<CP: PairingEngine, BLS: PairingEngine> {
    pub epochs: Groth16Parameters<CP>,
    pub hash_to_bits: Option<Groth16Parameters<BLS>>,
}

/// Initializes the Hash To Bits and Validator Set Update circuits with random parameters
/// seeded by the provided RNG over BLS12-377 and BW6_761.
///
/// `hashes_in_bls_12377` should be set to `true` if you're using the 2-SNARK technique,
/// which will perform 2 setups, one for the CRH->XOF hashes in BLS12-377 and the rest
/// of the circuit in BW6_761. If set to `false, only 1 setup will be done (at the expense
/// of having a longer proving time due to CRH->XOF hashes being done in BW6_761)
pub fn trusted_setup<R: Rng>(
    num_validators: usize,
    num_epochs: usize,
    maximum_non_signers: usize,
    rng: &mut R,
    hashes_in_bls12_377: bool,
) -> Result<Parameters<BWCurve, BLSCurve>> {
    setup(
        num_validators,
        num_epochs,
        maximum_non_signers,
        rng,
        |c, rng| generate_random_parameters(c, rng),
        |c, rng| generate_random_parameters(c, rng),
        hashes_in_bls12_377,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn runs_setup() {
        let rng = &mut rand::thread_rng();
        assert!(trusted_setup(3, 2, 1, rng, false).is_ok())
    }
}

/// Performs a Groth16 setup over the 2 provided Pairing-friendly curves for the Hash to Bits and Validator set update circuits
/// The consumer may provide the setup function, which can be one which performs a private-trusted setup, or one which outputs
/// parameters which were computed via an [MPC](https://eprint.iacr.org/2017/1050)
///
/// If you do not know what this means, use the `trusted_setup` function
fn setup<CP, BLS, F, G, R>(
    num_validators: usize,
    num_epochs: usize,
    maximum_non_signers: usize,
    rng: &mut R,
    hash_to_bits_setup: F,
    validator_setup_fn: G,
    hashes_in_bls12_377: bool,
) -> Result<Parameters<CP, BLS>>
where
    CP: PairingEngine,
    BLS: PairingEngine,
    R: Rng,
    F: FnOnce(HashToBits, &mut R) -> Result<Groth16Parameters<BLS>>,
    G: FnOnce(ValidatorSetUpdate<BLS>, &mut R) -> Result<Groth16Parameters<CP>>,
{
    info!(
        "Generating parameters for {} validators and {} epochs",
        num_validators, num_epochs
    );

    let span = span!(Level::TRACE, "setup");
    let _enter = span.enter();

    let (vk, hash_to_bits) = if hashes_in_bls12_377 {
        info!("CRH->XOF");
        let empty_hash_to_bits = HashToBits::empty::<BWFrParams>(num_epochs);
        let hash_to_bits = hash_to_bits_setup(empty_hash_to_bits, rng)?;
        (Some(hash_to_bits.vk.clone()), Some(hash_to_bits))
    } else {
        (None, None)
    };

    info!("BLS");
    let empty_epochs =
        ValidatorSetUpdate::empty(num_validators, num_epochs, maximum_non_signers, vk);
    let epochs = validator_setup_fn(empty_epochs, rng)?;

    Ok(Parameters {
        epochs,
        hash_to_bits,
    })
}
