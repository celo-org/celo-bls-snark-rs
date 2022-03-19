use ark_serialize::CanonicalDeserialize;
use bls_crypto::{PublicKey as BlsPubkey, Signature};
use ethers::{
    types::*,
    utils::rlp::{self, Decodable, DecoderError, Rlp},
};

pub const VANITY: usize = 32;

#[derive(Clone, Debug)]
pub struct AggregatedSeal {
    pub bitmap: Vec<bool>,
    pub round: u64,
    pub signature: Signature,
}

impl Decodable for AggregatedSeal {
    fn decode(r: &Rlp) -> Result<Self, DecoderError> {
        let bitmap: U256 = r.val_at(0)?;

        let mut bits = Vec::new();
        for i in 0..256 {
            bits.push(bitmap.bit(i));
        }

        let signature: Vec<u8> = r.val_at(1)?;
        let signature = Signature::deserialize(&mut &signature[..])
            .expect("could not deserialize signature - your header extras are corrupt");

        Ok(Self {
            bitmap: bits,
            signature,
            round: r.val_at(2)?,
        })
    }
}

#[derive(Clone, Debug)]
pub struct HeaderExtra {
    pub added_validators: Vec<Address>,
    pub added_validators_pubkeys: Vec<BlsPubkey>,
    pub removed_validators: U256,
    pub seal: Vec<u8>,
    pub aggregated_seal: AggregatedSeal,
    pub parent_aggregated_seal: AggregatedSeal,
}

impl Decodable for HeaderExtra {
    fn decode(r: &Rlp) -> Result<Self, rlp::DecoderError> {
        // Skip the first vanity bytes
        let r = Rlp::new(&r.as_raw()[VANITY..]);

        let added_validators: Vec<Address> = r.list_at(0)?;

        let added_validators_pubkeys: Vec<Vec<u8>> = r.list_at(1)?;
        let added_validators_pubkeys: Vec<BlsPubkey> = added_validators_pubkeys
            .into_iter()
            .map(|bytes| {
                BlsPubkey::deserialize(&mut &bytes[..]).expect(
                    "could not deserialize validator pubkey - your header extras are corrupt",
                )
            })
            .collect();

        let removed_validators = r.val_at::<U256>(2)?;
        let seal: Vec<u8> = r.val_at(3)?;
        let aggregated_seal: AggregatedSeal = r.val_at(4)?;
        let parent_aggregated_seal: AggregatedSeal = r.val_at(5)?;

        Ok(Self {
            added_validators,
            added_validators_pubkeys,
            removed_validators,
            seal,
            aggregated_seal,
            parent_aggregated_seal,
        })
    }
}