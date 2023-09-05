use core::panic;

use super::{PublicKey, Signature};

use ark_bls12_377::{Fr, G1Projective};
use ark_ff::{Field, PrimeField};
use ark_std::log2;

use crate::{BLSError, HashToCurve};

use rand::RngCore;

#[derive(Default)]
pub struct Batch {
    entries: Vec<(PublicKey, Signature)>,
    message: Vec<u8>,
    extra_data: Vec<u8>,
}

const SECURITY_BOUND: usize = 128;

/// Returns a byte count for sizing small exponents up to the maximum size of an Fr field element.
fn byte_count_from_target_batch_size(size: usize, target_security: usize) -> usize {
    let target_byte_count = (target_security + (log2(size) as usize) + 7) / 8;
    let field_byte_count = Fr::size_in_bits() / 8;

    std::cmp::min(target_byte_count, field_byte_count)
}

impl Batch {
    /// Constructs a new strict batch verifier context for a given message.
    pub fn new(message: &[u8], extra_data: &[u8]) -> Batch {
        Batch {
            entries: vec![],
            message: message.to_vec(),
            extra_data: extra_data.to_vec(),
        }
    }

    pub fn add(&mut self, public_key: PublicKey, signature: Signature) {
        self.entries.push((public_key, signature));
    }

    pub fn verify<H: HashToCurve<Output = G1Projective>>(
        &self,
        hash_to_g1: &H,
    ) -> Result<(), BLSError> {
        let mut public_keys = vec![];
        let mut signatures = vec![];

        let exp_size = byte_count_from_target_batch_size(self.entries.len(), SECURITY_BOUND);

        let exponents = self
            .entries
            .iter()
            .map(|(pk, sig)| {
                // arkworks math routines require owned copies
                public_keys.push(pk.clone());
                signatures.push(sig.clone());

                // Now that the batch is being verified, we can know how large the exponents need to be.
                let mut random_bytes = vec![0; exp_size];
                rand::thread_rng().fill_bytes(&mut random_bytes);

                Fr::from_random_bytes(&random_bytes).unwrap()
            })
            .collect::<Vec<_>>();

        let batch_pubkey = match PublicKey::batch(&exponents, public_keys) {
            Some(bpk) => bpk,
            None => {
                panic!("Uneven number of exponents and public keys")
            }
        };

        let batch_sig = match Signature::batch(&exponents, signatures) {
            Some(bsig) => bsig,
            None => {
                panic!("Uneven number of exponents and signatures")
            }
        };

        batch_pubkey.verify(&self.message, &self.extra_data, &batch_sig, hash_to_g1)
    }

    /// Verifies each signature in the batch individually, returning an error if any of them fails to verify.
    pub fn verify_each<H: HashToCurve<Output = G1Projective>>(
        &self,
        hash_to_g1: &H,
    ) -> Result<(), BLSError> {
        for (pk, sig) in self.entries.iter() {
            let result = pk.verify(&self.message, &self.extra_data, sig, hash_to_g1);
            result?
        }
        Ok(())
    }
}
