use crate::utils::{bits_le_to_bytes_le, bytes_le_to_bits_le};
use crate::YToBitGadget;
use ark_bls12_377::{Fq as Bls12_377_Fq, Parameters as Bls12_377_Parameters};
use ark_crypto_primitives::{
    crh::{bowe_hopwood::constraints::CRHGadget as BHHash, FixedLengthCRHGadget},
    prf::{blake2s::constraints::evaluate_blake2s_with_parameters, Blake2sWithParameterBlock},
};
use ark_ec::{
    bls12::G1Projective,
    models::bls12::Bls12Parameters,
    short_weierstrass_jacobian::{GroupAffine, GroupProjective},
    AffineCurve, SWModelParameters,
};
use ark_ed_on_bw6_761::EdwardsParameters;
use ark_ff::{BigInteger, BitIteratorLE, PrimeField};
use ark_r1cs_std::groups::curves::twisted_edwards::AffineVar;
use ark_r1cs_std::{
    alloc::{AllocVar, AllocationMode},
    bits::ToBitsGadget,
    boolean::Boolean,
    eq::EqGadget,
    fields::fp::FpVar,
    groups::bls12::G1Var,
    groups::CurveVar,
    uint8::UInt8,
    Assignment, R1CSVar,
};
use ark_relations::r1cs::SynthesisError;
use bls_crypto::{
    hashers::{
        composite::{CompositeHasher, CRH},
        DirectHasher, Hasher,
    },
    SIG_DOMAIN,
};
use std::{borrow::Borrow, marker::PhantomData};
use tracing::{debug, span, trace, Level};

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
    #[tracing::instrument(target = "r1cs")]
    pub fn enforce_hash_to_group(
        counter: UInt8<Bls12_377_Fq>,
        message: &[UInt8<Bls12_377_Fq>],
        extra_data: &[UInt8<Bls12_377_Fq>],
        generate_constraints_for_hash: bool,
    ) -> Result<
        (
            G1Var<Bls12_377_Parameters>,
            Vec<Boolean<Bls12_377_Fq>>,
            Vec<Boolean<Bls12_377_Fq>>,
        ),
        SynthesisError,
    > {
        let span = span!(Level::TRACE, "enforce_hash_to_group",);
        let _enter = span.enter();

        // compress the input
        let crh_bits = Self::pedersen_hash(&message)?;

        // combine the counter with the inner hash
        let mut input = counter.to_bits_le()?;

        // add extra data to input
        for v in extra_data {
            input.extend_from_slice(&v.to_bits_le()?);
        }

        input.extend_from_slice(&crh_bits);

        // Hash to bits
        let mut personalization = [0; 8];
        personalization.copy_from_slice(SIG_DOMAIN);
        // We want 378 random bits for hashing to curve, so we get 512 from the hash and will
        // discard any unneeded ones. We do not generate constraints.
        let xof_bits = hash_to_bits(&input, 512, personalization, generate_constraints_for_hash)?;

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
            <BHHash<EdwardsParameters, FpVar<Bls12_377_Fq>> as FixedLengthCRHGadget<
                CRH,
                Bls12_377_Fq,
            >>::ParametersVar::new_constant(
                input.cs(),
                CompositeHasher::<CRH>::setup_crh()
                    .map_err(|_| SynthesisError::AssignmentMissing)?,
            )?;

        let pedersen_hash: AffineVar<EdwardsParameters, FpVar<Bls12_377_Fq>> =
            <BHHash<EdwardsParameters, FpVar<Bls12_377_Fq>> as FixedLengthCRHGadget<
                CRH,
                Bls12_377_Fq,
            >>::evaluate(&crh_params, &input)?;

        let mut crh_bits = pedersen_hash.x.to_bits_le()?;
        // The hash must be front-padded to the nearest multiple of 8 for the LE encoding
        loop {
            if crh_bits.len() % 8 == 0 {
                break;
            }
            crh_bits.push(Boolean::constant(false));
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
        let message = message.to_vec();
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

            let xof_result =
                evaluate_blake2s_with_parameters(&message, &blake2s_parameters.parameters())?;
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
        let bits = if message.cs().is_in_setup_mode() {
            vec![false; 512]
        } else {
            let message = message
                .iter()
                .map(|m| m.value())
                .collect::<Result<Vec<_>, _>>()?;
            let message = bits_le_to_bytes_le(&message);
            let hash_result = DirectHasher.xof(&personalization, &message, 64).unwrap();
            bytes_le_to_bits_le(&hash_result, 512)
        };

        bits.iter()
            .map(|b| Boolean::new_witness(message[..].cs(), || Ok(b)))
            .collect::<Result<Vec<_>, _>>()?
    };

    Ok(xof_bits)
}

impl<P: Bls12Parameters> HashToGroupGadget<P, Bls12_377_Fq> {
    /// Receives the output of `HashToBitsGadget::hash_to_bits` in Little Endian
    /// decodes the G1 point and then multiplies it by the curve's cofactor to
    /// get the hash
    fn hash_to_group(
        xof_bits: &[Boolean<Bls12_377_Fq>],
    ) -> Result<G1Var<Bls12_377_Parameters>, SynthesisError> {
        let span = span!(Level::TRACE, "HashToGroupGadget",);
        let _enter = span.enter();
        let xof_bits = xof_bits.to_vec();

        let x_bits = &xof_bits[..X_BITS];
        let sign_bit = &xof_bits[SIGN_BIT_POSITION];
        trace!("getting G1 point from bits");
        let expected_point_before_cofactor =
            <G1Var<Bls12_377_Parameters>>::new_variable_omit_prime_order_check(
                x_bits.cs(),
                || {
                    // if we're in setup mode, just return an error
                    if x_bits.cs().is_in_setup_mode() {
                        return Err(SynthesisError::AssignmentMissing);
                    }

                    // get the bits from the Boolean constraints
                    // we assume that these are already encoded as LE
                    let bits = x_bits
                        .iter()
                        .map(|x| x.value())
                        .collect::<Result<Vec<bool>, _>>()?;

                    let big = <<Bls12_377_Parameters as Bls12Parameters>::Fp as PrimeField>::BigInt::from_bits_le(&bits);

                    let x = <Bls12_377_Parameters as Bls12Parameters>::Fp::from_repr(big).get()?;
                    let sign_bit_value = sign_bit.value()?;

                    // Converts the point read from the xof bits to a G1 element
                    // with point decompression
                    let p = GroupAffine::<<Bls12_377_Parameters as Bls12Parameters>::G1Parameters>::get_point_from_x(x, sign_bit_value)
                    .ok_or(SynthesisError::AssignmentMissing)?;

                    Ok(p.into_projective())
                },
                AllocationMode::Witness,
            )?;

        trace!("compressing y");
        // Point compression on the G1 Gadget
        let (compressed_point, compressed_sign_bit): (
            Vec<Boolean<Bls12_377_Fq>>,
            Boolean<Bls12_377_Fq>,
        ) = {
            // Convert x to LE
            let bits: Vec<Boolean<Bls12_377_Fq>> = expected_point_before_cofactor.x.to_bits_le()?;

            // Get a constraint about the y point's sign
            let greatest_bit = expected_point_before_cofactor.y_to_bit()?;

            (bits, greatest_bit)
        };

        // Check point equal to itself after being compressed
        for (a, b) in compressed_point.iter().zip(x_bits.iter()) {
            a.enforce_equal(&b)?;
        }
        compressed_sign_bit.enforce_equal(&sign_bit)?;

        trace!("scaling by G1 cofactor");
        let scaled_point = Self::scale_by_cofactor_g1(&expected_point_before_cofactor)?;

        Ok(scaled_point)
    }

    /// Checks that the result is equal to the given point
    /// multiplied by the cofactor in g1
    fn scale_by_cofactor_g1(
        p: &G1Var<Bls12_377_Parameters>,
    ) -> Result<G1Var<Bls12_377_Parameters>, SynthesisError>
    where
        G1Projective<Bls12_377_Parameters>:
            Borrow<GroupProjective<<Bls12_377_Parameters as Bls12Parameters>::G1Parameters>>,
    {
        // get the cofactor's bits
        let cofactor_bits = BitIteratorLE::new(P::G1Parameters::COFACTOR)
            .map(Boolean::constant)
            .collect::<Vec<Boolean<Bls12_377_Fq>>>();

        // return p * cofactor
        let scaled = p.scalar_mul_le(cofactor_bits.iter())?;
        Ok(scaled)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::utils::test_helpers::{print_unsatisfied_constraints, run_profile_constraints};

    use ark_r1cs_std::bits::uint8::UInt8;
    use ark_relations::r1cs::ConstraintSystem;
    use bls_crypto::hash_to_curve::try_and_increment_cip22::COMPOSITE_HASH_TO_G1_CIP22;
    use rand::{thread_rng, RngCore};

    #[test]
    fn test_hash_to_group() {
        run_profile_constraints(test_hash_to_group_inner);
    }
    fn test_hash_to_group_inner() {
        let mut rng = thread_rng();
        // test for various input sizes
        for length in &[10, 25, 50, 100, 200, 300] {
            // fill a buffer with random elements
            let mut input = vec![0; *length];
            rng.fill_bytes(&mut input);
            let mut extra_input = vec![0; *length];
            rng.fill_bytes(&mut extra_input);
            // check that they get hashed properly
            dbg!(length);
            hash_to_group(&input, &extra_input);
        }
    }

    #[tracing::instrument(target = "r1cs")]
    fn hash_to_group(input: &[u8], extra_input: &[u8]) {
        let try_and_increment = &*COMPOSITE_HASH_TO_G1_CIP22;
        let (expected_hash, attempt) = try_and_increment
            .hash_with_attempt_cip22(SIG_DOMAIN, input, extra_input)
            .unwrap();

        let cs = ConstraintSystem::<ark_bls12_377::Fq>::new_ref();
        let counter = UInt8::new_witness(cs.clone(), || Ok(attempt as u8)).unwrap();
        let input = input
            .iter()
            .map(|num| UInt8::new_witness(cs.clone(), || Ok(num)).unwrap())
            .collect::<Vec<_>>();
        let extra_input = extra_input
            .iter()
            .map(|num| UInt8::new_witness(cs.clone(), || Ok(num)).unwrap())
            .collect::<Vec<_>>();

        let hash =
            HashToGroupGadget::<ark_bls12_377::Parameters, ark_bls12_377::Fq>::enforce_hash_to_group(
                counter,
                &input,
                &extra_input,
                true,
            )
            .unwrap()
            .0;

        print_unsatisfied_constraints(cs.clone());
        assert!(cs.is_satisfied().unwrap());
        assert_eq!(expected_hash, hash.value().unwrap());
    }
}
