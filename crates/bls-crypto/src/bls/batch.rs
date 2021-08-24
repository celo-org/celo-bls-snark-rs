use super::{PublicKey, Signature};

// use algebra::{bls12_377::G1Projective, Field, PrimeField, ToBytes};
use ark_bls12_377::{Fr, G1Projective};
use ark_ff::{Field, PrimeField, ToBytes};
use ark_std::log2;

use blake2s_simd::{Params};

use crate::{BLSError, HashToCurve};

use rand::RngCore;

#[derive(Default)]
pub struct Batch {
    entries: Vec<(PublicKey, Signature, PreExponent)>,
    message: Vec<u8>,
    extra_data: Vec<u8>,
}

type PreExponent = [u8; 32];

impl Batch {
    /// Constructs a new strict batch verifier context for a given message.
    pub fn new(message: &[u8], extra_data: &[u8]) -> Batch {
        Batch {
            entries: Vec::<(PublicKey, Signature, PreExponent)>::new(),
            message: message.to_vec(),
            extra_data: extra_data.to_vec(),
        }
    }

    pub fn add(&mut self, public_key: &PublicKey, signature: &Signature) {
        let mut random_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut random_bytes);

        self.entries.push((public_key.to_owned(), signature.to_owned(), random_bytes));
    }

    pub fn verify<H: HashToCurve<Output = G1Projective>>(
        &self,
        hash_to_g1: &H,
    ) -> Result<(), BLSError> {
        let mut public_keys = vec![];
        let mut signatures = vec![];

        // convert bits to bytes
        let security_bound = (128 + (log2(self.entries.len()) as usize) + 7) / 8;

        // let field_size = algebra::bls12_377::Fr::size_in_bits() / 8; // => 31
        let exp_size = std::cmp::min(security_bound, 31);

        let exponents = self.entries.iter().map(|(pk, sig, preexp)| {
            public_keys.push(pk);
            signatures.push(sig);

            // Now that the batch is being verified, we can know how large the exponents need to be.
            Fr::from_random_bytes(&preexp[0..exp_size]).unwrap()
        }).collect::<Vec<_>>();

        let batch_pubkey = PublicKey::batch(&exponents, &public_keys);
        let batch_sig = Signature::batch(&exponents, &signatures);

        batch_pubkey.verify(&self.message, &self.extra_data, &batch_sig, hash_to_g1)
    }
}
