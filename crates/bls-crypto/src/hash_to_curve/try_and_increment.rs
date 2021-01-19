use bench_utils::{end_timer, start_timer};
use byteorder::WriteBytesExt;
use log::trace;
use std::marker::PhantomData;

use super::HashToCurve;
use crate::hashers::{
    composite::{CompositeHasher, COMPOSITE_HASHER, CRH},
    DirectHasher, Hasher,
};
use crate::BLSError;

use ark_bls12_377::Parameters;
use ark_ec::{
    bls12::Bls12Parameters,
    models::{
        short_weierstrass_jacobian::{GroupAffine, GroupProjective},
        SWModelParameters,
    },
};
use ark_ff::Zero;
use ark_serialize::CanonicalSerialize;

use crate::hash_to_curve::hash_length;
use once_cell::sync::Lazy;

const NUM_TRIES: u8 = 255;

/// Composite (Bowe-Hopwood CRH, Blake2x XOF) Try-and-Increment hasher for BLS 12-377.
pub static COMPOSITE_HASH_TO_G1: Lazy<
    TryAndIncrement<CompositeHasher<CRH>, <Parameters as Bls12Parameters>::G1Parameters>,
> = Lazy::new(|| TryAndIncrement::new(&*COMPOSITE_HASHER));

/// Direct (Blake2s CRH, Blake2x XOF) Try-and-Increment hasher for BLS 12-377.
/// Equivalent to Blake2xs.
pub static DIRECT_HASH_TO_G1: Lazy<
    TryAndIncrement<DirectHasher, <Parameters as Bls12Parameters>::G1Parameters>,
> = Lazy::new(|| TryAndIncrement::new(&DirectHasher));

/// A try-and-increment method for hashing to G1 and G2. See page 521 in
/// https://link.springer.com/content/pdf/10.1007/3-540-45682-1_30.pdf.
#[derive(Clone)]
pub struct TryAndIncrement<'a, H, P> {
    hasher: &'a H,
    curve_params: PhantomData<P>,
}

impl<'a, H, P> TryAndIncrement<'a, H, P>
where
    H: Hasher<Error = BLSError>,
    P: SWModelParameters,
{
    /// Instantiates a new Try-and-increment hasher with the provided hashing method
    /// and curve parameters based on the type
    pub fn new(h: &'a H) -> Self {
        TryAndIncrement {
            hasher: h,
            curve_params: PhantomData,
        }
    }
}

impl<'a, H, P> HashToCurve for TryAndIncrement<'a, H, P>
where
    H: Hasher<Error = BLSError>,
    P: SWModelParameters,
{
    type Output = GroupProjective<P>;

    fn hash(
        &self,
        domain: &[u8],
        message: &[u8],
        extra_data: &[u8],
    ) -> Result<Self::Output, BLSError> {
        self.hash_with_attempt(domain, message, extra_data)
            .map(|res| res.0)
    }
}

impl<'a, H, P> TryAndIncrement<'a, H, P>
where
    H: Hasher<Error = BLSError>,
    P: SWModelParameters,
{
    /// Hash with attempt takes the input, appends a counter
    pub fn hash_with_attempt(
        &self,
        domain: &[u8],
        message: &[u8],
        extra_data: &[u8],
    ) -> Result<(GroupProjective<P>, usize), BLSError> {
        let num_bytes = GroupAffine::<P>::zero().serialized_size();
        let hash_loop_time = start_timer!(|| "try_and_increment::hash_loop");
        let hash_bytes = hash_length(num_bytes);

        let mut counter = [0; 1];
        for c in 0..NUM_TRIES {
            (&mut counter[..]).write_u8(c as u8)?;
            let candidate_hash = self.hasher.hash(
                domain,
                &[&counter, extra_data, &message].concat(),
                hash_bytes,
            )?;

            // handle the Celo deployed bit extraction logic
            #[cfg(feature = "compat")]
            let candidate_hash = {
                use super::YSignFlags;
                use ark_serialize::Flags;

                let mut candidate_hash = candidate_hash[..num_bytes].to_vec();
                let positive_flag = candidate_hash[num_bytes - 1] & 2 != 0;
                if positive_flag {
                    candidate_hash[num_bytes - 1] |= YSignFlags::PositiveY(false).u8_bitmask();
                } else {
                    candidate_hash[num_bytes - 1] &= !YSignFlags::PositiveY(false).u8_bitmask();
                }
                candidate_hash
            };

            if let Some(p) = super::from_random_bytes::<P>(&candidate_hash[..num_bytes]) {
                trace!(
                    "succeeded hashing \"{}\" to curve in {} tries",
                    hex::encode(message),
                    c
                );
                end_timer!(hash_loop_time);

                let scaled = p.scale_by_cofactor();
                if scaled.is_zero() {
                    continue;
                }

                return Ok((scaled, c as usize));
            }
        }
        Err(BLSError::HashToCurveError)
    }
}
