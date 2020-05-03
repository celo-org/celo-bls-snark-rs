use crate::{BLSError, BlsResult, HashToCurve, PrivateKey, Signature, POP_DOMAIN, SIG_DOMAIN};

use algebra::{
    bls12_377::{Bls12_377, Fq12, G1Projective, G2Affine, G2Projective},
    AffineCurve, CanonicalDeserialize, CanonicalSerialize, One, PairingEngine, ProjectiveCurve,
    SerializationError, Zero,
};

use std::{
    hash::{Hash, Hasher},
    io::{Read, Write},
    ops::Neg,
};

/// A BLS public key on G2
#[derive(Clone, Eq, Debug)]
pub struct PublicKey(pub(super) G2Projective);

impl From<G2Projective> for PublicKey {
    fn from(pk: G2Projective) -> PublicKey {
        PublicKey(pk)
    }
}

impl From<&PrivateKey> for PublicKey {
    fn from(pk: &PrivateKey) -> PublicKey {
        PublicKey::from(G2Projective::prime_subgroup_generator().mul(*pk.as_ref()))
    }
}

impl AsRef<G2Projective> for PublicKey {
    fn as_ref(&self) -> &G2Projective {
        &self.0
    }
}

impl PublicKey {
    pub fn aggregate(public_keys: &[PublicKey]) -> PublicKey {
        let mut apk = G2Projective::zero();
        for pk in public_keys.iter() {
            apk += pk.as_ref();
        }
        apk.into()
    }

    pub fn verify<H: HashToCurve<Output = G1Projective>>(
        &self,
        message: &[u8],
        extra_data: &[u8],
        signature: &Signature,
        hash_to_g1: &H,
    ) -> BlsResult<()> {
        self.verify_sig(SIG_DOMAIN, message, extra_data, signature, hash_to_g1)
    }

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

impl PartialEq for PublicKey {
    fn eq(&self, other: &Self) -> bool {
        // This byte-level equality operator differs from the (much slower) semantic
        // equality operator in G2Projective.  We require byte-level equality here
        // for HashSet to work correctly.  HashSet requires that item equality
        // implies hash equality.
        let a = self.as_ref();
        let b = other.as_ref();
        a.x == b.x && a.y == b.y && a.z == b.z
    }
}

impl Hash for PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Only hash based on `y` for slight speed improvement
        self.0.y.hash(state);
        // self.pk.x.hash(state);
        // self.pk.z.hash(state);
    }
}

impl CanonicalSerialize for PublicKey {
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), SerializationError> {
        self.0.into_affine().serialize(writer)
    }

    fn serialize_uncompressed<W: Write>(&self, writer: &mut W) -> Result<(), SerializationError> {
        self.0.into_affine().serialize_uncompressed(writer)
    }

    fn serialized_size(&self) -> usize {
        self.0.into_affine().serialized_size()
    }
}

impl CanonicalDeserialize for PublicKey {
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self, SerializationError> {
        Ok(PublicKey::from(
            G2Affine::deserialize(reader)?.into_projective(),
        ))
    }

    fn deserialize_uncompressed<R: Read>(reader: &mut R) -> Result<Self, SerializationError> {
        Ok(PublicKey::from(
            G2Affine::deserialize_uncompressed(reader)?.into_projective(),
        ))
    }
}
