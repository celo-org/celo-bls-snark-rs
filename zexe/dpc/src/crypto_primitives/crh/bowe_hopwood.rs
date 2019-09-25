use crate::Error;
use rand::Rng;
use rayon::prelude::*;
use std::{
    fmt::{Debug, Formatter, Result as FmtResult},
    marker::PhantomData,
};

use super::{
    FixedLengthCRH,
    pedersen::{PedersenCRH, PedersenWindow},
};
use algebra::{
    fields::PrimeField,
    groups::Group,
    biginteger::BigInteger,
};

#[derive(Clone, Default)]
pub struct BoweHopwoodPedersenParameters<G: Group> {
    pub generators: Vec<G>,
}

pub struct BoweHopwoodPedersenCRH<G: Group, W: PedersenWindow> {
    group:  PhantomData<G>,
    window: PhantomData<W>,
}

impl<G: Group, W: PedersenWindow> BoweHopwoodPedersenCRH<G, W> {
    pub fn create_generators<R: Rng>(rng: &mut R) -> Vec<G> {
        let mut generators_powers = Vec::new();
        for _ in 0..W::NUM_WINDOWS {
            let base = G::rand(rng);
            generators_powers.push(base);
        }
        generators_powers
    }
}

impl<G: Group, W: PedersenWindow> FixedLengthCRH for BoweHopwoodPedersenCRH<G, W> {
    const INPUT_SIZE_BITS: usize = PedersenCRH::<G, W>::INPUT_SIZE_BITS;
    type Output = G;
    type Parameters = BoweHopwoodPedersenParameters<G>;

    fn setup<R: Rng>(rng: &mut R) -> Result<Self::Parameters, Error> {
        fn calculate_num_windows<G: Group>() -> u32 {
            let upper_limit = G::ScalarField::modulus_minus_one_div_two();
            let mut c = 0;
            let mut range = <G::ScalarField as PrimeField>::BigInt::from(2_u64);
            while range < upper_limit {
                range.muln(4);
                c += 1;
            }

            c
        }

        let num_windows = calculate_num_windows::<G>();

        let time = timer_start!(|| format!(
            "BoweHopwoodPedersenCRH::Setup: {} {}-bit windows; {{0,1}}^{{{}}} -> G",
            W::NUM_WINDOWS,
            W::WINDOW_SIZE,
            W::WINDOW_SIZE*W::NUM_WINDOWS
        ));
        let generators = Self::create_generators(rng);
        timer_end!(time);
        Ok(Self::Parameters {
            generators
        })
    }

    fn evaluate(parameters: &Self::Parameters, input: &[u8]) -> Result<Self::Output, Error> {
        let eval_time = timer_start!(|| "PedersenCRH::Eval");

        if (input.len() * 8) > W::WINDOW_SIZE * W::NUM_WINDOWS {
            panic!(
                "incorrect input length {:?} for window params {:?}x{:?}",
                input.len(),
                W::WINDOW_SIZE,
                W::NUM_WINDOWS
            );
        }

        let mut padded_input = Vec::with_capacity(input.len());
        let mut input = input;
        // Pad the input if it is not the current length.
        if (input.len() * 8) < W::WINDOW_SIZE * W::NUM_WINDOWS {
            let current_length = input.len();
            padded_input.extend_from_slice(input);
            for _ in current_length..((W::WINDOW_SIZE * W::NUM_WINDOWS) / 8) {
                padded_input.push(0u8);
            }
            input = padded_input.as_slice();
        }

        assert_eq!(
            parameters.generators.len(),
            W::NUM_WINDOWS,
            "Incorrect pp of size {:?}x{:?} for window params {:?}x{:?}",
            parameters.generators[0].len(),
            parameters.generators.len(),
            W::WINDOW_SIZE,
            W::NUM_WINDOWS
        );

        // Compute sum of h_i^{m_i} for all i.
        let result = bytes_to_bits(input)
            .par_chunks(W::WINDOW_SIZE)
            .zip(&parameters.generators)
            .map(|(bits, generator_powers)| {
                let mut encoded = G::zero();
                for (bit, base) in bits.iter().zip(generator_powers.iter()) {
                    if *bit {
                        encoded = encoded + base;
                    }
                }
                encoded
            })
            .reduce(|| G::zero(), |a, b| a + &b);
        timer_end!(eval_time);

        Ok(result)
    }
}

pub fn bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::with_capacity(bytes.len() * 8);
    for byte in bytes {
        for i in 0..8 {
            let bit = (*byte >> i) & 1;
            bits.push(bit == 1)
        }
    }
    bits
}

impl<G: Group> Debug for BoweHopwoodPedersenParameters<G> {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "Pedersen Hash Parameters {{\n")?;
        for (i, g) in self.generators.iter().enumerate() {
            write!(f, "\t  Generator {}: {:?}\n", i, g)?;
        }
        write!(f, "}}\n")
    }
}
