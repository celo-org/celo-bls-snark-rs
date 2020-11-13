use algebra::{
    bls12_377::{Bls12_377, Fq as Bls12_377_Fq, Parameters as Bls12_377_Parameters},
    bw6_761::Fr,
    curves::bls12::Bls12Parameters,
    One, PairingEngine,
};
use bls_crypto::{hash_to_curve::try_and_increment::COMPOSITE_HASH_TO_G1, SIG_DOMAIN};
use bls_gadgets::{FpUtils, HashToGroupGadget};
use r1cs_core::{ConstraintSystemRef, SynthesisError};
use r1cs_std::{
    alloc::AllocationMode,
    bls12_377::{G1Var, G2Var},
    fields::fp::FpVar,
    prelude::*,
    Assignment,
};

use super::{bytes_to_fr, fr_to_bits, g2_to_bits};
use tracing::{span, trace, Level};

type FrVar = FpVar<Fr>;
type Bool = Boolean<<Bls12_377_Parameters as Bls12Parameters>::Fp>;
type U8 = UInt8<<Bls12_377_Parameters as Bls12Parameters>::Fp>;

/// An epoch block using optional types so that it can be used to instantiate the
/// trusted setup. Its non-gadget compatible equivalent is [`EpochBlock`]
///
/// [`EpochBlock`]: struct.EpochBlock.html
#[derive(Clone, Debug, Default)]
pub struct EpochData<E: PairingEngine> {
    /// The allowed non-signers for the epoch + 1
    pub maximum_non_signers: u32,
    /// The index of the initial epoch
    pub index: Option<u16>,
    /// Unpredicatble value to add entropy to the epoch data,
    pub epoch_entropy: Option<Vec<u8>>,
    /// Entropy value for the previous epoch.
    pub parent_entropy: Option<Vec<u8>>,
    /// The public keys at the epoch
    pub public_keys: Vec<Option<E::G2Projective>>,
}

/// Output type of EpochData.to_bits including bit representation and gadgets.
type EpochDataToBits = (Vec<Bool>, FrVar, FrVar, FrVar, FrVar, Vec<G2Var>);
type InnerEpochDataToBits = (
    Vec<Bool>,
    Vec<Bool>,
    Vec<Bool>,
    FrVar,
    FrVar,
    FrVar,
    FrVar,
    Vec<G2Var>,
);

/// [`EpochData`] is constrained to a `ConstrainedEpochData` via [`EpochData.constrain`]
///
/// [`EpochData`]: struct.EpochData.html
/// [`EpochData.constrain`]: struct.EpochData.html#method.constrain
pub struct ConstrainedEpochData {
    /// The epoch's index
    pub index: FrVar,
    /// Unpredicatble value to add entropy to the epoch data,
    pub epoch_entropy: FrVar,
    /// Entropy value for the previous epoch.
    pub parent_entropy: FrVar,
    /// The new threshold needed for signatures
    pub maximum_non_signers: FrVar,
    /// The epoch's G1 Hash
    pub message_hash: G1Var,
    /// The new validators for this epoch
    pub pubkeys: Vec<G2Var>,
    /// Serialized epoch data containing the index, max non signers, aggregated pubkey and the pubkeys array
    pub bits: Vec<Bool>,
    /// Aux data for proving the CRH->XOF hash outside of BW6_761
    pub crh_bits: Vec<Bool>,
    /// Aux data for proving the CRH->XOF hash outside of BW6_761
    pub xof_bits: Vec<Bool>,
}

impl<E: PairingEngine> EpochData<E> {
    /// Each epoch entropy value is 128 bits.
    pub const ENTROPY_BYTES: usize = 16;

    /// Initializes an empty epoch, to be used for the setup
    pub fn empty(num_validators: usize, maximum_non_signers: usize) -> Self {
        EpochData::<E> {
            index: None,
            epoch_entropy: None,
            parent_entropy: None,
            maximum_non_signers: maximum_non_signers as u32,
            public_keys: vec![None; num_validators],
        }
    }
}

impl EpochData<Bls12_377> {
    /// Ensures that the epoch's index is equal to `previous_index + 1`. Enforces that
    /// the epoch's G1 hash is correctly calculated, and also provides auxiliary data for
    /// verifying the CRH->XOF hash outside of BW6_761.
    pub fn constrain(
        &self,
        previous_index: &FrVar,
        generate_constraints_for_hash: bool,
    ) -> Result<ConstrainedEpochData, SynthesisError> {
        let span = span!(Level::TRACE, "EpochData");
        let _enter = span.enter();
        println!("c");

        // TODO(#185): Add a constraint that the parent_entropy match the previous epoch's entropy.
        let (
            bits,
            extra_data_bits,
            combined_bits,
            index,
            epoch_entropy,
            parent_entropy,
            maximum_non_signers,
            pubkeys,
        ) = self.to_bits_inner(previous_index.cs())?;
        println!("b");
        Self::enforce_next_epoch(previous_index, &index)?;

        println!("a");

        // Hash to G1
        let (message_hash, crh_bits, xof_bits) =
            Self::hash_bits_to_g1(&bits, &extra_data_bits, generate_constraints_for_hash)?;

        Ok(ConstrainedEpochData {
            bits: combined_bits,
            index,
            epoch_entropy,
            parent_entropy,
            maximum_non_signers,
            pubkeys,
            message_hash,
            crh_bits,
            xof_bits,
        })
    }

    /// Encodes the epoch to bits (index and non-signers encoded as LE)
    pub fn to_bits(
        &self,
        cs: ConstraintSystemRef<Bls12_377_Fq>,
    ) -> Result<EpochDataToBits, SynthesisError> {
        println!("Z");
        let index = FpVar::new_witness(cs.clone(), || Ok(Fr::from(self.index.get()?)))?;
        println!("X");
        let index_bits = fr_to_bits(&index, 16)?;
        println!("Y");

        let maximum_non_signers =
            FpVar::new_witness(index.cs(), || Ok(Fr::from(self.maximum_non_signers)))?;

        let maximum_non_signers_bits = fr_to_bits(&maximum_non_signers, 32)?;

        let empty_entropy = vec![0u8; Self::ENTROPY_BYTES];
        let epoch_entropy = match &self.epoch_entropy {
            Some(v) => v,
            None => &empty_entropy,
        };
        let epoch_entropy_var = bytes_to_fr(cs.clone(), Some(&epoch_entropy))?;
        let epoch_entropy_bits = fr_to_bits(&epoch_entropy_var, 8 * Self::ENTROPY_BYTES)?;

        let parent_entropy = match &self.parent_entropy {
            Some(v) => v,
            None => &empty_entropy,
        };
        let parent_entropy_var = bytes_to_fr(cs.clone(), Some(&parent_entropy))?;
        let parent_entropy_bits = fr_to_bits(&parent_entropy_var, 8 * Self::ENTROPY_BYTES)?;

        let mut epoch_bits: Vec<Bool> = [
            index_bits,
            epoch_entropy_bits,
            parent_entropy_bits,
            maximum_non_signers_bits,
        ]
        .concat();

        let mut pubkey_vars = Vec::with_capacity(self.public_keys.len());
        for maybe_pk in self.public_keys.iter() {
            let pk_var = G2Var::new_variable_omit_prime_order_check(
                index.cs(),
                || maybe_pk.get(),
                AllocationMode::Witness,
            )?;

            // extend our epoch bits by the pubkeys
            let pk_bits = g2_to_bits(&pk_var)?;
            epoch_bits.extend_from_slice(&pk_bits);

            // save the allocated pubkeys
            pubkey_vars.push(pk_var);
        }

        Ok((
            epoch_bits,
            index,
            epoch_entropy_var,
            parent_entropy_var,
            maximum_non_signers,
            pubkey_vars,
        ))
    }

    /// Encodes the inner epoch to bits (index and non-signers encoded as LE)
    pub fn to_bits_inner(
        &self,
        cs: ConstraintSystemRef<Bls12_377_Fq>,
    ) -> Result<InnerEpochDataToBits, SynthesisError> {
        let index = FpVar::new_witness(cs.clone(), || Ok(Fr::from(self.index.get()?)))?;
        println!("before");
        let index_bits = fr_to_bits(&index, 16)?;
        println!("after");

        let maximum_non_signers =
            FpVar::new_witness(index.cs(), || Ok(Fr::from(self.maximum_non_signers)))?;
        println!("A");

        let maximum_non_signers_bits = fr_to_bits(&maximum_non_signers, 32)?;
        println!("A1");

        let empty_entropy = vec![0u8; Self::ENTROPY_BYTES];
        let epoch_entropy = match &self.epoch_entropy {
            Some(v) => v,
            None => &empty_entropy,
        };
        let epoch_entropy_var = bytes_to_fr(cs.clone(), Some(&epoch_entropy))?;
        let epoch_entropy_bits = fr_to_bits(&epoch_entropy_var, 8 * Self::ENTROPY_BYTES)?;

        let parent_entropy = match &self.parent_entropy {
            Some(v) => v,
            None => &empty_entropy,
        };
        let parent_entropy_var = bytes_to_fr(cs.clone(), Some(&parent_entropy))?;
        let parent_entropy_bits = fr_to_bits(&parent_entropy_var, 8 * Self::ENTROPY_BYTES)?;

        let mut epoch_bits: Vec<Bool> =
            [epoch_entropy_bits.clone(), parent_entropy_bits.clone()].concat();

        let extra_data_bits: Vec<Bool> =
            [index_bits.clone(), maximum_non_signers_bits.clone()].concat();

        let mut combined_bits: Vec<Bool> = [
            index_bits,
            epoch_entropy_bits,
            parent_entropy_bits,
            maximum_non_signers_bits,
        ]
        .concat();

        let mut pubkey_vars = Vec::with_capacity(self.public_keys.len());
        for maybe_pk in self.public_keys.iter() {
            let pk_var = G2Var::new_variable_omit_prime_order_check(
                index.cs(),
                || maybe_pk.get(),
                AllocationMode::Witness,
            )?;

            // extend our epoch bits by the pubkeys
            let pk_bits = g2_to_bits(&pk_var)?;
            epoch_bits.extend_from_slice(&pk_bits);
            combined_bits.extend_from_slice(&pk_bits);

            // save the allocated pubkeys
            pubkey_vars.push(pk_var);
        }

        Ok((
            epoch_bits,
            extra_data_bits,
            combined_bits,
            index,
            epoch_entropy_var,
            parent_entropy_var,
            maximum_non_signers,
            pubkey_vars,
        ))
    }

    /// Enforces that `index = previous_index + 1`
    fn enforce_next_epoch(previous_index: &FrVar, index: &FrVar) -> Result<(), SynthesisError> {
        trace!("enforcing next epoch");
        let previous_plus_one = previous_index + Fr::one();

        let index_bit = index.is_eq_zero()?.not();

        index.conditional_enforce_equal(&previous_plus_one, &index_bit)?;
        Ok(())
    }

    /// Packs the provided bits in U8s, and calculates the hash and the counter
    /// Also returns the auxiliary CRH and XOF bits for potential compression from consumers
    fn hash_bits_to_g1(
        epoch_bits: &[Bool],
        epoch_extra_data_bits: &[Bool],
        generate_constraints_for_hash: bool,
    ) -> Result<(G1Var, Vec<Bool>, Vec<Bool>), SynthesisError> {
        trace!("hashing epoch to g1");
        // Reverse to LE
        let mut epoch_bits = epoch_bits.to_vec();
        epoch_bits.reverse();
        let mut epoch_extra_data_bits = epoch_extra_data_bits.to_vec();
        epoch_extra_data_bits.reverse();

        let is_setup = epoch_bits.cs().is_in_setup_mode();

        // Pack them to Uint8s
        let input_bytes_var: Vec<U8> = epoch_bits
            .chunks(8)
            .map(|chunk| {
                let mut chunk = chunk.to_vec();
                if chunk.len() < 8 {
                    chunk.resize(8, Bool::constant(false));
                }
                UInt8::from_bits_le(&chunk)
            })
            .collect();
        let input_extra_data_bytes_var: Vec<U8> = epoch_extra_data_bits
            .chunks(8)
            .map(|chunk| {
                let mut chunk = chunk.to_vec();
                if chunk.len() < 8 {
                    chunk.resize(8, Bool::constant(false));
                }
                UInt8::from_bits_le(&chunk)
            })
            .collect();

        // Get the inner values
        let counter = if is_setup {
            0
        } else {
            // find the counter value for the hash
            let input_bytes = input_bytes_var
                .iter()
                .map(|b| b.value())
                .collect::<Result<Vec<_>, _>>()?;
            let input_extra_data_bytes = input_extra_data_bytes_var
                .iter()
                .map(|b| b.value())
                .collect::<Result<Vec<_>, _>>()?;

            let (_, counter) = COMPOSITE_HASH_TO_G1
                .hash_with_attempt_cip22(SIG_DOMAIN, &input_bytes, &input_extra_data_bytes)
                .map_err(|_| SynthesisError::Unsatisfiable)?;
            counter
        };

        let counter_var = UInt8::new_witness(epoch_bits.cs(), || Ok(counter as u8))?;
        HashToGroupGadget::enforce_hash_to_group(
            counter_var,
            &input_bytes_var,
            &input_extra_data_bytes_var,
            generate_constraints_for_hash,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::epoch_block::EpochBlock;
    use bls_crypto::PublicKey;
    use bls_gadgets::utils::test_helpers::print_unsatisfied_constraints;

    use algebra::{
        bls12_377::{Bls12_377, G2Projective as Bls12_377G2Projective},
        UniformRand,
    };
    use r1cs_core::ConstraintSystem;

    fn test_epoch(index: u16) -> EpochData<Bls12_377> {
        let rng = &mut rand::thread_rng();
        let pubkeys = (0..10)
            .map(|_| Some(Bls12_377G2Projective::rand(rng)))
            .collect::<Vec<_>>();
        EpochData::<Bls12_377> {
            index: Some(index),
            epoch_entropy: Some(vec![index as u8; EpochData::<Bls12_377>::ENTROPY_BYTES]),
            parent_entropy: Some(vec![
                (index - 1) as u8;
                EpochData::<Bls12_377>::ENTROPY_BYTES
            ]),
            maximum_non_signers: 12,
            public_keys: pubkeys,
        }
    }

    #[test]
    fn test_enforce() {
        let epoch = test_epoch(10);
        let cs = ConstraintSystem::<Fr>::new_ref();
        let index = FrVar::new_witness(cs.clone(), || Ok(Fr::from(9u32))).unwrap();
        epoch.constrain(&index, false).unwrap();
        print_unsatisfied_constraints(cs.clone());
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_hash_epoch_to_g1() {
        let epoch = test_epoch(10);
        let mut pubkeys = Vec::new();
        for pk in &epoch.public_keys {
            pubkeys.push(PublicKey::from(pk.unwrap()));
        }

        // Calculate the hash from our to_bytes function
        let (epoch_bytes, extra_data_bytes) = EpochBlock::new(
            epoch.index.unwrap(),
            epoch.epoch_entropy.as_ref().map(|v| v.to_vec()),
            epoch.parent_entropy.as_ref().map(|v| v.to_vec()),
            epoch.maximum_non_signers,
            pubkeys,
        )
        .encode_inner_to_bytes()
        .unwrap();
        let (hash, _) = COMPOSITE_HASH_TO_G1
            .hash_with_attempt_cip22(SIG_DOMAIN, &epoch_bytes, &extra_data_bytes)
            .unwrap();

        // compare it with the one calculated in the circuit from its bytes
        let cs = ConstraintSystem::<Fr>::new_ref();
        let (bits, extra_data_bits, _, _, _, _, _, _) = epoch.to_bits_inner(cs.clone()).unwrap();
        let ret = EpochData::hash_bits_to_g1(&bits, &extra_data_bits, true).unwrap();
        print_unsatisfied_constraints(cs.clone());
        assert!(cs.is_satisfied().unwrap());
        assert_eq!(ret.0.value().unwrap(), hash);
    }

    #[test]
    fn enforce_next_epoch() {
        for (index1, index2, expected) in &[
            (0u16, 1u16, true),
            (1, 3, false),
            (3, 1, false),
            (100, 101, true),
            (1, 0, true),
            (5, 0, true),
        ] {
            let cs = ConstraintSystem::<Fr>::new_ref();
            let epoch1 = FrVar::new_witness(cs.clone(), || Ok(Fr::from(*index1))).unwrap();
            let epoch2 = FrVar::new_witness(cs.clone(), || Ok(Fr::from(*index2))).unwrap();
            EpochData::enforce_next_epoch(&epoch1, &epoch2).unwrap();
            print_unsatisfied_constraints(cs.clone());
            assert_eq!(cs.is_satisfied().unwrap(), *expected);
        }
    }

    #[test]
    fn epoch_to_bits_ok() {
        let epoch = test_epoch(18);
        let mut pubkeys = Vec::new();
        for pk in &epoch.public_keys {
            pubkeys.push(PublicKey::from(pk.unwrap()));
        }

        // calculate the bits from our helper function
        let bits = EpochBlock::new(
            epoch.index.unwrap(),
            epoch.epoch_entropy.as_ref().map(|v| v.to_vec()),
            epoch.parent_entropy.as_ref().map(|v| v.to_vec()),
            epoch.maximum_non_signers,
            pubkeys.clone(),
        )
        .encode_to_bits()
        .unwrap();

        // calculate wrong bits
        let bits_wrong = EpochBlock::new(
            epoch.index.unwrap(),
            epoch.epoch_entropy.as_ref().map(|v| v.to_vec()),
            epoch.parent_entropy.as_ref().map(|v| v.to_vec()),
            epoch.maximum_non_signers,
            pubkeys,
        )
        .encode_to_bits_with_aggregated_pk()
        .unwrap();

        // calculate the bits from the epoch
        let cs = ConstraintSystem::<Fr>::new_ref();
        let ret = epoch.to_bits(cs).unwrap();

        // compare with the result
        let bits_inner = ret.0.iter().map(|x| x.value().unwrap()).collect::<Vec<_>>();
        assert_eq!(bits_inner, bits);
        assert_ne!(bits_inner, bits_wrong);
    }
}
