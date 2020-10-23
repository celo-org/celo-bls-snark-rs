use crate::{
    utils::{bits_to_bytes, bytes_to_bits, is_setup},
    YToBitGadget,
};
use bls_crypto::{
    hashers::{
        composite::{CompositeHasher, CRH},
        DirectHasher, Hasher,
    },
    SIG_DOMAIN,
};
use r1cs_std::alloc::AllocVar;
use r1cs_std::alloc::AllocationMode;
use std::ops::Sub;
// Imported for the BLS12-377 API
use algebra::{
    bls12_377::{Fq as Bls12_377_Fq, Parameters as Bls12_377_Parameters},
};
use tracing_subscriber::layer::SubscriberExt;

use algebra::{
    curves::{
        bls12::{G1Affine, G1Projective},
        models::bls12::Bls12Parameters,
        short_weierstrass_jacobian::{GroupAffine, GroupProjective},
        SWModelParameters,
    },
    AffineCurve, BigInteger, BitIteratorBE, PrimeField, ProjectiveCurve,
};
use crypto_primitives::{
    crh::{
        bowe_hopwood::constraints::CRHGadget as BHHash, FixedLengthCRHGadget
    },
    prf::{blake2s::constraints::evaluate_blake2s_with_parameters, Blake2sWithParameterBlock},
};
use r1cs_core::{SynthesisError, ConstraintSystemRef, ConstraintLayer};
use r1cs_std::{
    bits::ToBitsGadget, boolean::Boolean,
    groups::bls12::G1Var, groups::CurveVar, uint8::UInt8, Assignment, R1CSVar, eq::EqGadget
};
use std::{borrow::Borrow, marker::PhantomData};
use tracing::{debug, span, trace, Level};
use algebra::ed_on_bw6_761::EdwardsParameters;

// The deployed Celo version's hash-to-curve takes the sign bit from position 377.
#[cfg(feature = "compat")]
const SIGN_BIT_POSITION: usize = 377;
// Zexe's upstream logic takes the sign bit from position 383.
#[cfg(not(feature = "compat"))]
const SIGN_BIT_POSITION: usize = 383;

// The bits from the hash which will be interpreted as the x coordinate of a group element
const X_BITS: usize = 377;

/// Parameters for Blake2x as specified in: https://blake2.net/blake2x.pdf
/// • “Key length” is set to 0 (even if the root hash was keyed)
/// • “Fanout” is set to 0 (unlimited)
/// • “Maximal depth” is set to 0
/// • “Leaf maximal byte length” is set to 32 for BLAKE2Xs, and 64 for BLAKE2Xb
/// • “XOF digest length” is set to the length of the final output digest
/// • “Node depth” is set to 0 (leaves)
/// • “Inner hash byte length” is set to 32 for BLAKE2Xs and 64 for BLAKE2Xb
fn blake2xs_params(
    hash_length: u16,
    offset: u32,
    personalization: [u8; 8],
) -> Blake2sWithParameterBlock {
    Blake2sWithParameterBlock {
        digest_length: 32,
        key_length: 0,
        fan_out: 0,
        depth: 0,
        leaf_length: 32,
        node_offset: offset,
        xof_digest_length: hash_length / 8, // need to convert to bytes
        node_depth: 0,
        inner_length: 32,
        salt: [0; 8],
        personalization,
    }
}

/// Gadget which enforces correct calculation of hashing to group of arbitrary data, implementing
/// the "try and increment" method. For more information on the method, refer to the [non-gadget
/// implementation][hash_to_group].
///
/// Currently this gadget only exposes hashing to BLS12-377's G1.
///
/// [hash_to_group]: ../bls_crypto/hash_to_curve/try_and_increment/index.html
pub struct HashToGroupGadget<P, F: PrimeField> {
    parameters_type: PhantomData<P>,
    field_type: PhantomData<F>,
}

// If we're on Bls12-377, we can have a nice public API for the whole hash to group operation
// by taking the input, compressing it via an instantiation of Pedersen Hash with a CRH over Edwards BW6_761
// and then hashing it to bits and to group
impl HashToGroupGadget<Bls12_377_Parameters, Bls12_377_Fq> {
    /// Returns the G1 constrained hash of the message with the provided counter.
    ///
    /// If `generate_constraints_for_hash` is set to `false`, then constraints will not
    /// be generated for the CRH -> XOF conversion. You may want to set this to `false` if
    /// calculations inside BW6_761 are considered too expensive. In that case, you MUST verify
    /// that they were calculated properly.
    ///
    /// For that reason, this function also returns the CRH bits and the XOF bits,
    /// so that they can be used to verify the correct calculation of the XOF from
    /// the CRH in a separate proof.
    #[allow(clippy::type_complexity)]
    pub fn enforce_hash_to_group(
        counter: UInt8<Bls12_377_Fq>,
        message: &[UInt8<Bls12_377_Fq>],
        generate_constraints_for_hash: bool,
    ) -> Result<(G1Var<Bls12_377_Parameters>, Vec<Boolean<Bls12_377_Fq>>, Vec<Boolean<Bls12_377_Fq>>), SynthesisError> {
        let span = span!(Level::TRACE, "enforce_hash_to_group",);
        let _enter = span.enter();

        // combine the counter with the message
        let mut input = vec![counter];
        input.extend_from_slice(message);
        // compress the input
//        println!("gadget pedersen input: {:?}", message);
        let crh_bits = Self::pedersen_hash(&input)?;
//        println!("crh_bits gadget: {:?}", crh_bits.value()?);

        // Hash to bits
        let mut personalization = [0; 8];
        personalization.copy_from_slice(SIG_DOMAIN);
        // We want 378 random bits for hashing to curve, so we get 512 from the hash and will
        // discard any unneeded ones. We do not generate constraints.
        let xof_bits = hash_to_bits(
            &crh_bits,
            512,
            personalization,
            generate_constraints_for_hash,
        )?;
//        println!("xof_bits gadget: {:?}", xof_bits.value()?); 
//        println!("xof_bits len: {:?}", xof_bits.value()?.len());

        let hash = Self::hash_to_group(&xof_bits)?;

        debug!("message and counter have been hashed to G1");
        Ok((hash, crh_bits, xof_bits))
    }

    /// Compress the input by passing it through a Pedersen hash
    fn pedersen_hash(
        input: &[UInt8<Bls12_377_Fq>],
    ) -> Result<Vec<Boolean<Bls12_377_Fq>>, SynthesisError> {
        // We setup by getting the Parameters over the provided CRH
        let crh_params =
            <BHHash<EdwardsParameters, _> as FixedLengthCRHGadget<CRH, _>>::ParametersVar::new_constant(
                input.cs().unwrap_or(ConstraintSystemRef::None),
                CompositeHasher::<CRH>::setup_crh()
                    .map_err(|_| SynthesisError::AssignmentMissing)?,
            )?;

        let pedersen_hash =
            <BHHash<EdwardsParameters, _> as FixedLengthCRHGadget<CRH, _>>::evaluate(
                &crh_params,
                &input,
            )?;

        let mut crh_bits = pedersen_hash.x.to_bits_le().unwrap();
        crh_bits.reverse();
        // The hash must be front-padded to the nearest multiple of 8 for the LE encoding
        loop {
            if crh_bits.len() % 8 == 0 {
                break;
            }
            crh_bits.insert(0, Boolean::constant(false));
        }
        Ok(crh_bits)
    }
}

/// Hashes the message to produce a `hash_length` hash with the provided personalization
///
/// This uses Blake2s under the hood and is expensive for large messages.
/// Consider reducing the input size by passing it through a Collision Resistant Hash function
/// such as Pedersen.
///
/// If `generate_constraints_for_hash = false`, then no constraints will be generated.
///
/// # Panics
///
/// If the provided hash_length is not a multiple of 256.
#[tracing::instrument(target = "r1cs")]
pub fn hash_to_bits<F: PrimeField>(
    message: &[Boolean<F>],
    hash_length: u16,
    personalization: [u8; 8],
    generate_constraints_for_hash: bool,
) -> Result<Vec<Boolean<F>>, SynthesisError> {
    let span = span!(
        Level::TRACE,
        "hash_to_bits",
        hash_length,
        generate_constraints_for_hash
    );
    let _enter = span.enter();
    let xof_bits = if generate_constraints_for_hash {
        trace!("generating hash with constraints");
        // Reverse the message to LE
        let mut message = message.to_vec();
        message.reverse();
        // Blake2s outputs 256 bit hashes so the desired output hash length
        // must be a multiple of that.
        assert_eq!(hash_length % 256, 0, "invalid hash length size");
        let iterations = hash_length / 256;
        let mut xof_bits = Vec::new();
        // Run Blake on the message N times, each time offset by `i`
        // to get a `hash_length` hash. The hash is in LE.
        for i in 0..iterations {
            trace!(blake_iteration = i);
            // calculate the hash (Vec<Boolean>)
            let blake2s_parameters = blake2xs_params(hash_length, i.into(), personalization);
            let xof_result = evaluate_blake2s_with_parameters(
                &message,
                &blake2s_parameters.parameters(),
            )?;
            // convert hash result to LE bits
            let xof_bits_i = xof_result
                .into_iter()
                .map(|n| n.to_bits_le())
                .flatten()
                .collect::<Vec<Boolean<F>>>();
            xof_bits.extend_from_slice(&xof_bits_i);
        }
        xof_bits
    } else {
        trace!("generating hash without constraints");
        let bits = if is_setup(&message) {
            vec![false; 512]
        } else {
            let message = message
                .iter()
                .map(|m| m.value())
                .collect::<Result<Vec<_>, _>>()?;
            let message = bits_to_bytes(&message);
            let mut hash_result = DirectHasher.xof(&personalization, &message, 64).unwrap();
            hash_result.reverse();
            let mut bits = bytes_to_bits(&hash_result, 512);
            bits
        };

        bits.iter()
        .enumerate()
        .map(|(_j, b)| Boolean::new_witness(message[..].cs().unwrap_or(ConstraintSystemRef::None), || Ok(b)))
        .collect::<Result<Vec<_>, _>>()?
//        constrain_bool(message[0].cs().unwrap_or(ConstraintSystemRef::None), &bits)?
    };

    Ok(xof_bits)
}

impl<P: Bls12Parameters> HashToGroupGadget<P, Bls12_377_Fq> {
    // Receives the output of `HashToBitsGadget::hash_to_bits` in Little Endian
    // decodes the G1 point and then multiplies it by the curve's cofactor to
    // get the hash
    //#[tracing::instrument(target = "r1cs")]
    fn hash_to_group(
        xof_bits: &[Boolean<Bls12_377_Fq>],
    ) -> Result<G1Var<Bls12_377_Parameters>, SynthesisError> {
        let span = span!(Level::TRACE, "HashToGroupGadget",);
        let _enter = span.enter();

        println!("hash to group gadget input: {:?}", xof_bits.value());
//        let xof_bits = [&xof_bits[..X_BITS], &[xof_bits[SIGN_BIT_POSITION]]].concat();
        let x_bits = &xof_bits[..X_BITS];
//        let greatest = &x_bits[X_BITS];
        let sign_bit = &xof_bits[SIGN_BIT_POSITION];
        trace!("getting G1 point from bits");
        let expected_point_before_cofactor =
            <G1Var::<Bls12_377_Parameters> /*as CurveVar<GroupAffine<_>, _>*/>::new_variable_omit_prime_order_check(
                x_bits.cs().unwrap_or(ConstraintSystemRef::None),
                || {
                // if we're in setup mode, just return an error
                // TODO: setup should also be checked on sign bit
                if is_setup(&x_bits) {
                    return Err(SynthesisError::AssignmentMissing);
                }

//                let x_bits = &xof_bits[..X_BITS];
//                let greatest = xof_bits[X_BITS];

                // get the bits from the Boolean constraints
                // we assume that these are already encoded as LE
                let mut bits = x_bits
                    .iter()
                    .map(|x| x.value())
                    .collect::<Result<Vec<bool>, _>>()?;

                // `BigInt::from_bits` takes BigEndian representations so we need to
                // reverse them since they are read in LE
 //               bits.reverse();
//                println!("bits in gadget: {:?}", bits);
                let big = <<Bls12_377_Parameters as Bls12Parameters>::Fp as PrimeField>::BigInt::from_bits(&bits);

                let x = <Bls12_377_Parameters as Bls12Parameters>::Fp::from_repr(big).get()?;
                let sign_bit_value = sign_bit.value()?;
//                println!("before getting point: {:?}", x);

                // Converts the point read from the xof bits to a G1 element
                // with point decompression
                let p = GroupAffine::<<Bls12_377_Parameters as Bls12Parameters>::G1Parameters>::get_point_from_x(x, sign_bit_value)
                    .ok_or(SynthesisError::AssignmentMissing)?;
//                println!("after getting point, affine: {:?}", p);
//                println!("bitmap: {}", p.x.to_bits_le()?);

//                let proj = p.into_projective();
//                println!("affine->projective: {:?}", proj);

//                let after = proj.into_affine();
//                println!("affine->projective->affine: {:?}", after);
                Ok(p.into_projective())
            }, AllocationMode::Witness)?;

        trace!("compressing y");
        println!("point gadget after converting to var: {:?}", expected_point_before_cofactor.value()?.into_affine());
        // Point compression on the G1 Gadget
        let (compressed_point, compressed_sign_bit): (Vec<Boolean<Bls12_377_Fq>>, Boolean<Bls12_377_Fq>) = {
            // Convert x to LE
            let mut bits: Vec<Boolean<Bls12_377_Fq>> =
                expected_point_before_cofactor.x.to_bits_le()?;
           bits.reverse();

            // Get a constraint about the y point's sign
            let greatest_bit = expected_point_before_cofactor.y_to_bit()?;

            (bits, greatest_bit)
        };

 //       println!("{}    {}", compressed_point.len(), x_bits.len());
        for (_i, (a,b)) in compressed_point.iter()
            .zip(x_bits.iter())
            .enumerate() 
        {
      //      println!("a: {:?}, b: {:?}", a.value()?, b.value()?);
            a.enforce_equal(&b)?;
        }
     //   println!("a: {:?}", compressed_sign_bit.value()?);
     //   println!("b: {:?}", sign_bit.value()?);
        compressed_sign_bit.enforce_equal(&sign_bit)?;

        trace!("scaling by G1 cofactor");

 //       println!("point gadget before cofactor: {:?}", expected_point_before_cofactor.value()?.into_affine());

        let scaled_point = Self::scale_by_cofactor_g1(
            &expected_point_before_cofactor,
        )?;

        Ok(scaled_point)
    }

    fn scale_by_cofactor_g1(
        p: &G1Var<Bls12_377_Parameters>,
    ) -> Result<G1Var<Bls12_377_Parameters>, SynthesisError>
    where
        G1Projective<Bls12_377_Parameters>: Borrow<GroupProjective<<Bls12_377_Parameters as Bls12Parameters>::G1Parameters>>,
    {
        // get the cofactor's bits
        let mut x_bits = BitIteratorBE::new(P::G1Parameters::COFACTOR)
            .map(Boolean::constant)
            .collect::<Vec<Boolean<Bls12_377_Fq>>>();

        // Zexe's mul_bits requires that inputs _MUST_ be in LE form, so we have to reverse
        x_bits.reverse();

        // return p * cofactor - [g]_1
        let generator = G1Var::<Bls12_377_Parameters>::new_constant(
            p.cs().unwrap_or(ConstraintSystemRef::None),
            G1Projective::<Bls12_377_Parameters>::prime_subgroup_generator(),
        )?;
        let scaled = p
            .scalar_mul_le(x_bits.iter())?
            .sub(&generator);
        Ok(scaled)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use bls_crypto::hashers::composite::COMPOSITE_HASHER;
    use bls_crypto::hash_to_curve::HashToCurve;
    use algebra::bls12_377;
    use r1cs_std::groups::CurveVar;
    use r1cs_core::ConstraintSystem;

    use bls_crypto::hash_to_curve::try_and_increment::COMPOSITE_HASH_TO_G1;
    use r1cs_std::bits::uint8::UInt8;
    use rand::{thread_rng, RngCore};

    #[test]
    fn test_hash_to_group() {
        let mut layer = ConstraintLayer::default();
        layer.mode = r1cs_core::TracingMode::OnlyConstraints;
        let subscriber = tracing_subscriber::Registry::default().with(layer);
        tracing::subscriber::set_global_default(subscriber).unwrap();

        let mut rng = thread_rng();
        // test for various input sizes
        for length in &[10] /*, 25, 50, 100, 200, 300]*/ {
            // fill a buffer with random elements
            let mut input = vec![0; *length];
           rng.fill_bytes(&mut input);
            // check that they get hashed properly
            dbg!(length);
            hash_to_group(&input);
        }
    }

    fn hash_to_group(input: &[u8]) {
        let try_and_increment = &*COMPOSITE_HASH_TO_G1;
        let (expected_hash, attempt) = try_and_increment
            .hash_with_attempt(SIG_DOMAIN, input, &[])
            .unwrap();
        let hasher = &*COMPOSITE_HASHER;
//        let bits = hasher.hash(SIG_DOMAIN, input, 64);
//        println!("gadget hash: {:?}", bits);

        let mut cs = ConstraintSystem::<bls12_377::Fq>::new_ref();

        let counter = UInt8::new_witness(cs.clone(), || Ok(attempt as u8)).unwrap();
        let input = input
            .iter()
            .enumerate()
            .map(|(i, num)| {
                UInt8::new_witness(cs.clone(), || Ok(num)).unwrap()
            })
            .collect::<Vec<_>>();

        let hash = HashToGroupGadget::<bls12_377::Parameters, bls12_377::Fq>::enforce_hash_to_group(
            counter,
            &input,
            false,
        )
        .unwrap()
        .0;

        if !cs.is_satisfied().unwrap() {
            println!("=========================================================");
            println!("Unsatisfied constraints:");
            println!("{}", cs.which_is_unsatisfied().unwrap().unwrap());
            println!("=========================================================");
        }

        assert!(cs.is_satisfied().unwrap());
        assert_eq!(expected_hash, hash.value().unwrap());
    }
}
