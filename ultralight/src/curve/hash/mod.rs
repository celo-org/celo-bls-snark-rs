pub mod try_and_increment;

use crate::hash::PRF;

use failure::Error;
use std::{
    ops::{Mul, Neg, Add, Div},
};

use algebra::{
    biginteger::BigInteger,
    fields::{
        Field,
        Fp2,
        fp6_3over2::Fp6,
        fp12_2over3over2::Fp12,
        BitIterator,
        PrimeField,
        FpParameters,
    },
    curves::{
        AffineCurve,
        ProjectiveCurve,
        models::{
            ModelParameters,
            bls12::{
                Bls12Parameters,
                G2Affine,
                G2Projective,
            }
        }
    },
    PairingEngine,
};

pub trait HashToG2 {
    fn hash<P: Bls12Parameters>(&self, message: &[u8]) -> Result<G2Projective<P>, Error>;
}
