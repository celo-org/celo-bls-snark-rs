use algebra::{
    bls12_377::{Bls12_377, Parameters},
    sw6::Fr,
    One, PairingEngine,
};
use r1cs_core::{ConstraintSystem, SynthesisError};
use r1cs_std::prelude::*;
use r1cs_std::{
    bls12_377::{G1Gadget, G2Gadget},
    fields::fp::FpGadget,
    Assignment,
};

use bls_crypto::{
    bls::keys::SIG_DOMAIN, curve::hash::try_and_increment::TryAndIncrement,
    hash::composite::CompositeHasher,
};
use bls_gadgets::HashToGroupGadget;

use super::{fr_to_bits, g2_to_bits, to_fr};

type FrGadget = FpGadget<Fr>;

/// An epoch (either the first one or any in between)
#[derive(Clone, Debug, Default)]
pub struct EpochData<E: PairingEngine> {
    /// The index of the initial epoch
    pub index: Option<u16>,
    /// The allowed non-signers for the epoch
    pub maximum_non_signers: Option<u32>,
    /// The aggregated pubkey of the epoch's validators
    pub aggregated_pub_key: Option<E::G2Projective>,
    /// The public keys at the epoch
    pub public_keys: Vec<Option<E::G2Projective>>,
}

pub struct ConstrainedEpochData {
    /// Serialized epoch data containing the index, max non signers, aggregated pubkey and the pubkeys array
    pub bits: Vec<Boolean>,
    pub index: FrGadget,
    pub message_hash: G1Gadget,
    pub pubkeys: Vec<G2Gadget>,
    pub crh_bits: Vec<Boolean>,
    pub xof_bits: Vec<Boolean>,
}

impl<E: PairingEngine> EpochData<E> {
    // Initializes an empty epoch, to be used for the setup
    pub fn empty(num_validators: usize) -> Self {
        EpochData::<E> {
            index: None,
            maximum_non_signers: None,
            aggregated_pub_key: None,
            public_keys: vec![None; num_validators],
        }
    }
}

impl EpochData<Bls12_377> {
    pub fn constrain<CS: ConstraintSystem<Fr>>(
        &self,
        cs: &mut CS,
        previous_index: &FrGadget,
    ) -> Result<ConstrainedEpochData, SynthesisError> {
        let (bits, index, pubkeys) = self.to_bits(cs)?;
        Self::enforce_next_epoch(&mut cs.ns(|| "enforce next epoch"), previous_index, &index)?;

        // Hash to G1
        let (message_hash, crh_bits, xof_bits) =
            Self::hash_bits_to_g1(&mut cs.ns(|| "hash epoch to g1 bits"), &bits)?;

        Ok(ConstrainedEpochData {
            bits,
            index,
            pubkeys,
            message_hash,
            crh_bits,
            xof_bits,
        })
    }

    /// Encodes the epoch to bits (index and non-signers encoded as LE)
    pub fn to_bits<CS: ConstraintSystem<Fr>>(
        &self,
        cs: &mut CS,
    ) -> Result<(Vec<Boolean>, FrGadget, Vec<G2Gadget>), SynthesisError> {
        let index = to_fr(&mut cs.ns(|| "index"), self.index.get()?)?;
        let index_bits = fr_to_bits(&mut cs.ns(|| "index bits"), &index, 16)?;

        let current_maximum_non_signers = {
            let current_maximum_non_signers = to_fr(
                &mut cs.ns(|| "max non signers"),
                self.maximum_non_signers.get()?,
            )?;
            fr_to_bits(
                &mut cs.ns(|| "max non signers bits"),
                &current_maximum_non_signers,
                32,
            )?
        };

        let aggregated_key_bits = {
            let aggregated_key = G2Gadget::alloc(cs.ns(|| "aggregated pub key"), || {
                self.aggregated_pub_key.get()
            })?;
            g2_to_bits(&mut cs.ns(|| "aggregated pubkey to bits"), &aggregated_key)?
        };

        let mut epoch_bits: Vec<Boolean> =
            [index_bits, current_maximum_non_signers, aggregated_key_bits].concat();

        let mut pubkey_vars = Vec::with_capacity(self.public_keys.len());
        for (j, maybe_pk) in self.public_keys.iter().enumerate() {
            let pk_var = G2Gadget::alloc(cs.ns(|| format!("pub key {}", j)), || maybe_pk.get())?;

            // extend our epoch bits by the pubkeys
            let pk_bits = g2_to_bits(&mut cs.ns(|| format!("pubkey to bits {}", j)), &pk_var)?;
            epoch_bits.extend_from_slice(&pk_bits);

            // save the allocated pubkeys
            pubkey_vars.push(pk_var);
        }

        Ok((epoch_bits, index, pubkey_vars))
    }

    /// Enforces that `index = previous_index + 1`
    fn enforce_next_epoch<CS: ConstraintSystem<Fr>>(
        cs: &mut CS,
        previous_index: &FrGadget,
        index: &FrGadget,
    ) -> Result<(), SynthesisError> {
        let previous_plus_one =
            previous_index.add_constant(cs.ns(|| "previous plus_one"), &Fr::one())?;
        index.enforce_equal(cs.ns(|| "index enforce equal"), &previous_plus_one)?;
        Ok(())
    }

    /// Packs the provided bits in U8s, and calculates the hash and the counter
    /// Also returns the auxiliary CRH and XOF bits for potential compression from consumers
    fn hash_bits_to_g1<CS: ConstraintSystem<Fr>>(
        cs: &mut CS,
        epoch_bits: &[Boolean],
    ) -> Result<(G1Gadget, Vec<Boolean>, Vec<Boolean>), SynthesisError> {
        // Reverse to LE
        let mut epoch_bits = epoch_bits.to_vec();
        epoch_bits.reverse();

        // Pack them to Uint8s
        let input_bytes_var: Vec<UInt8> = epoch_bits
            .chunks(8)
            .map(|chunk| {
                let mut chunk = chunk.to_vec();
                if chunk.len() < 8 {
                    chunk.resize(8, Boolean::constant(false));
                }
                UInt8::from_bits_le(&chunk)
            })
            .collect();

        // Get the inner values
        let result = {
            // find the counter value for the hash
            let composite_hasher = CompositeHasher::new().unwrap();
            let try_and_increment = TryAndIncrement::new(&composite_hasher);
            let input_bytes = input_bytes_var
                .iter()
                .map(|b| b.get_value().get())
                .collect::<Result<Vec<_>, _>>()?;
            let (_, counter) = try_and_increment
                .hash_with_attempt::<Parameters>(SIG_DOMAIN, &input_bytes, &[])
                .map_err(|_| SynthesisError::Unsatisfiable)?;

            let counter_var =
                UInt8::alloc(&mut cs.ns(|| "alloc counter"), || Ok(counter as u8)).unwrap();
            HashToGroupGadget::<Parameters>::enforce_hash_to_group(
                &mut cs.ns(|| "hash to group"),
                counter_var,
                &input_bytes_var,
            )?
        };

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use algebra::{
        bls12_377::{Bls12_377, G2Projective as Bls12_377G2Projective},
        UniformRand,
    };
    use r1cs_core::ConstraintSystem;
    use r1cs_std::test_constraint_system::TestConstraintSystem;

    use crate::epoch_block::EpochBlock;
    use bls_crypto::PublicKey;

    fn test_epoch(index: u16) -> EpochData<Bls12_377> {
        let rng = &mut rand::thread_rng();
        let aggregated_pub_key = Some(Bls12_377G2Projective::rand(rng));
        let pubkeys = (0..10)
            .map(|_| Some(Bls12_377G2Projective::rand(rng)))
            .collect::<Vec<_>>();
        EpochData::<Bls12_377> {
            index: Some(index),
            maximum_non_signers: Some(12),
            aggregated_pub_key,
            public_keys: pubkeys,
        }
    }

    #[test]
    fn test_enforce() {
        let epoch = test_epoch(10);
        let mut cs = TestConstraintSystem::<Fr>::new();
        let index = to_fr(&mut cs.ns(|| "index"), 9u32).unwrap();
        epoch
            .constrain(&mut cs.ns(|| "constraint"), &index)
            .unwrap();
        assert!(cs.is_satisfied());
    }

    #[test]
    fn test_hash_epoch_to_g1() {
        let epoch = test_epoch(10);
        let mut pubkeys = Vec::new();
        for pk in &epoch.public_keys {
            pubkeys.push(PublicKey::from_pk(&pk.unwrap()));
        }
        let pubkeys: Vec<&PublicKey> = pubkeys.iter().map(|x| x).collect();

        // Calculate the hash from our to_bytes function
        let epoch_bytes = EpochBlock::new(
            epoch.index.unwrap(),
            epoch.maximum_non_signers.unwrap(),
            &PublicKey::from_pk(&epoch.aggregated_pub_key.unwrap()),
            &pubkeys,
        )
        .encode_to_bytes()
        .unwrap();
        let composite_hasher = CompositeHasher::new().unwrap();
        let try_and_increment = TryAndIncrement::new(&composite_hasher);
        let (hash, _) = try_and_increment
            .hash_with_attempt::<Parameters>(SIG_DOMAIN, &epoch_bytes, &[])
            .unwrap();

        // compare it with the one calculated in the circuit from its bytes
        let mut cs = TestConstraintSystem::<Fr>::new();
        let bits = epoch.to_bits(&mut cs.ns(|| "epoch2bits")).unwrap().0;
        let ret = EpochData::hash_bits_to_g1(&mut cs.ns(|| "hash epoch bits"), &bits).unwrap();
        assert_eq!(ret.0.get_value().unwrap(), hash);
    }

    #[test]
    fn enforce_next_epoch() {
        for (index1, index2, expected) in &[
            (0u16, 1u16, true),
            (1, 3, false),
            (3, 1, false),
            (100, 101, true),
        ] {
            let mut cs = TestConstraintSystem::<Fr>::new();
            let epoch1 = to_fr(&mut cs.ns(|| "1"), *index1).unwrap();
            let epoch2 = to_fr(&mut cs.ns(|| "2"), *index2).unwrap();
            EpochData::enforce_next_epoch(&mut cs, &epoch1, &epoch2).unwrap();
            assert_eq!(cs.is_satisfied(), *expected);
        }
    }

    #[test]
    fn epoch_to_bits_ok() {
        let epoch = test_epoch(18);

        let mut pubkeys = Vec::new();
        for pk in &epoch.public_keys {
            pubkeys.push(PublicKey::from_pk(&pk.unwrap()));
        }
        let pubkeys: Vec<&PublicKey> = pubkeys.iter().map(|x| x).collect();

        // calculate the bits from our helper function
        let bits = EpochBlock::new(
            epoch.index.unwrap(),
            epoch.maximum_non_signers.unwrap(),
            &PublicKey::from_pk(&epoch.aggregated_pub_key.unwrap()),
            &pubkeys,
        )
        .encode_to_bits()
        .unwrap();

        // calculate the bits from the epoch
        let mut cs = TestConstraintSystem::<Fr>::new();
        let ret = epoch.to_bits(&mut cs).unwrap();

        // compare with the result
        let bits_inner = ret
            .0
            .iter()
            .map(|x| x.get_value().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(bits_inner, bits,);
    }
}
