use super::{PublicKey, Signature};

// use algebra::{bls12_377::G1Projective, Field, PrimeField, ToBytes};
use ark_bls12_377::{Fr, G1Projective};
use ark_ff::{Field, PrimeField, ToBytes};

use blake2s_simd::{Params, State};

use crate::{BLSError, HashToCurve};

#[derive(Default)]
pub struct Batch {
    entries: Vec<(PublicKey, Signature)>,
    message: Vec<u8>,
    extra_data: Vec<u8>,
    size: usize,
}

impl Batch {
    /// Constructs a new strict batch verifier context for a given message.
    pub fn new(message: &[u8], extra_data: &[u8]) -> Batch {
        Batch {
            entries: Vec::<(PublicKey, Signature)>::new(),
            message: message.to_vec(),
            extra_data: extra_data.to_vec(),
            size: 0,
        }
    }

    pub fn add(&mut self, public_key: &PublicKey, signature: &Signature) {
        self.entries
            .push((public_key.to_owned(), signature.to_owned()));
        self.size += 1
    }

    pub fn verify<H: HashToCurve<Output = G1Projective>>(
        &self,
        hash_to_g1: &H,
    ) -> Result<(), BLSError> {
        let mut public_keys = Vec::<&PublicKey>::new();
        let mut signatures = Vec::<&Signature>::new();

        let mut hash_states = Vec::<State>::new();
        let mut hash_inputs = Vec::<Vec<u8>>::new();

        self.entries.iter().for_each(|(pk, sig)| {
            public_keys.push(&pk);
            signatures.push(&sig);

            hash_states.push(
                Params::new()
                    .personal(b"bvblssig")
                    .hash_length(32)
                    .to_state(),
            );

            // r <- H(pk || m || ad || sig)
            let mut input = vec![];
            pk.as_ref().write(&mut input).unwrap();
            self.message.write(&mut input).unwrap();
            self.extra_data.write(&mut input).unwrap();
            sig.as_ref().write(&mut input).unwrap();
            hash_inputs.push(input);
        });

        let security_bound = (128 + ((self.size as f64).log2().ceil() as usize) + 7) / 8; // in bytes
        // let field_size = algebra::bls12_377::Fr::size_in_bits() / 8; // => 31
        let exp_size = std::cmp::min(security_bound, 31); // 32 bytes is the maximum output of blake2s anyway

        blake2s_simd::many::update_many(hash_states.iter_mut().zip(hash_inputs.iter()));

        let r = hash_states
            .iter_mut()
            .map(|s| {
                let f = s.finalize();
                let bytes = f.as_array();
                Fr::from_random_bytes(&bytes[0..exp_size]).unwrap()
            })
            .collect::<Vec<_>>();

        let batch_pubkey = PublicKey::batch(&r, &public_keys);
        let batch_sig = Signature::batch(&r, &signatures);

        batch_pubkey.verify(&self.message, &self.extra_data, &batch_sig, hash_to_g1)
    }
}
