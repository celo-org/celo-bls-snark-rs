use crate::{BLSError, BlsResult, HashToCurve, PrivateKey, Signature, POP_DOMAIN, SIG_DOMAIN};

use ark_bls12_377::{Bls12_377, Fq12, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use ark_ff::{One, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};

use std::{
    borrow::Borrow,
    io::{Read, Write},
    ops::Neg,
};

/// A BLS public key on G2
#[derive(Clone, Eq, Debug, PartialEq, Hash)]
pub struct PublicKey(pub(super) G2Projective);

impl From<G2Projective> for PublicKey {
    fn from(pk: G2Projective) -> PublicKey {
        PublicKey(pk)
    }
}

impl From<&PrivateKey> for PublicKey {
    fn from(pk: &PrivateKey) -> PublicKey {
        PublicKey::from(G2Projective::prime_subgroup_generator().mul(pk.as_ref().into_repr()))
    }
}

impl AsRef<G2Projective> for PublicKey {
    fn as_ref(&self) -> &G2Projective {
        &self.0
    }
}

impl PublicKey {
    /// Sums the provided public keys to produce the aggregate public key.
    pub fn aggregate<P: Borrow<PublicKey>>(public_keys: impl IntoIterator<Item = P>) -> PublicKey {
        public_keys
            .into_iter()
            .map(|s| s.borrow().0)
            .sum::<G2Projective>()
            .into()
    }

    /// Verifies the provided signature against the message-extra_data pair using the
    /// `hash_to_g1` hasher.
    ///
    /// Uses the `SIG_DOMAIN` under the hood.
    pub fn verify<H: HashToCurve<Output = G1Projective>>(
        &self,
        message: &[u8],
        extra_data: &[u8],
        signature: &Signature,
        hash_to_g1: &H,
    ) -> BlsResult<()> {
        self.verify_sig(SIG_DOMAIN, message, extra_data, signature, hash_to_g1)
    }

    /// Verifies the provided proof of possession signature against the message using the
    /// `hash_to_g1` hasher.
    ///
    /// Uses the `POP_DOMAIN` under the hood.
    pub fn verify_pop<H: HashToCurve<Output = G1Projective>>(
        &self,
        message: &[u8],
        signature: &Signature,
        hash_to_g1: &H,
    ) -> BlsResult<()> {
        self.verify_sig(POP_DOMAIN, &message, &[], signature, hash_to_g1)
    }

    fn verify_sig<H: HashToCurve<Output = G1Projective>>(
        &self,
        domain: &[u8],
        message: &[u8],
        extra_data: &[u8],
        signature: &Signature,
        hash_to_g1: &H,
    ) -> BlsResult<()> {
        let pairing = Bls12_377::product_of_pairings(&vec![
            (
                signature.as_ref().into_affine().into(),
                G2Affine::prime_subgroup_generator().neg().into(),
            ),
            (
                hash_to_g1
                    .hash(domain, message, extra_data)?
                    .into_affine()
                    .into(),
                self.0.into_affine().into(),
            ),
        ]);
        if pairing == Fq12::one() {
            Ok(())
        } else {
            Err(BLSError::VerificationFailed)
        }
    }
}

impl CanonicalSerialize for PublicKey {
    fn serialize<W: Write>(&self, writer: W) -> Result<(), SerializationError> {
        self.0.into_affine().serialize(writer)
    }

    fn serialize_uncompressed<W: Write>(&self, writer: W) -> Result<(), SerializationError> {
        self.0.into_affine().serialize_uncompressed(writer)
    }

    fn serialized_size(&self) -> usize {
        self.0.into_affine().serialized_size()
    }
}

impl CanonicalDeserialize for PublicKey {
    fn deserialize<R: Read>(reader: R) -> Result<Self, SerializationError> {
        Ok(PublicKey::from(
            G2Affine::deserialize(reader)?.into_projective(),
        ))
    }

    fn deserialize_uncompressed<R: Read>(reader: R) -> Result<Self, SerializationError> {
        Ok(PublicKey::from(
            G2Affine::deserialize_uncompressed(reader)?.into_projective(),
        ))
    }
}
