use super::PublicKey;
use ark_bls12_377::G2Projective;
use ark_ff::Zero;
use ark_serialize::{CanonicalDeserialize, SerializationError};

use lru::LruCache;
use std::{
    collections::HashSet,
    hash::{Hash, Hasher},
};

/// Allows deserializing and aggregation of public keys while holding a cache to improve
/// performance. Aggregation assumes that the aggregated public key changes slowly.
pub struct PublicKeyCache {
    /// The current keys in the validator set
    keys: HashSet<WrappedPublicKey>,
    /// The aggregated public key of all validators
    pub combined: PublicKey,
    /// An in-memory mapping of serialized pubkey byte arrays to their deserialized
    /// group element representation
    pub de: LruCache<Vec<u8>, PublicKey>,
}

impl Default for PublicKeyCache {
    fn default() -> Self {
        Self::new()
    }
}

impl PublicKeyCache {
    /// Initializes an empty cache
    pub fn new() -> Self {
        Self {
            keys: HashSet::new(),
            combined: PublicKey(G2Projective::zero()),
            de: LruCache::new(512),
        }
    }

    /// Clears the deserialization cache's keys
    pub fn clear_cache(&mut self) {
        self.keys = HashSet::new();
        self.combined = PublicKey(G2Projective::zero());
        self.de.clear();
    }

    /// Returns the PublicKey corresponding to the serialized data from the cache, or deserializes
    /// the element, saves it to the cache for later use and returns it
    pub fn deserialize(&mut self, data: Vec<u8>) -> Result<PublicKey, SerializationError> {
        let cached_result = self.de.get(&data);
        match cached_result {
            // cache hit
            Some(cached_result) => Ok(cached_result.clone()),
            // cache miss
            None => {
                let generated_result = PublicKey::deserialize(&mut &data[..])?;
                self.de.put(data, generated_result.clone());
                Ok(generated_result)
            }
        }
    }

    /// The set of public keys changes slowly, so for speed this method computes the
    /// difference from the last call and does an incremental update of the combined key
    pub fn aggregate(&mut self, public_keys: Vec<PublicKey>) -> PublicKey {
        let mut keys: HashSet<WrappedPublicKey> = HashSet::with_capacity(public_keys.len());
        for key in public_keys {
            keys.insert(WrappedPublicKey(key));
        }

        let mut combined = self.combined.0;

        // Subtract any keys which are no longer present
        for key in self.keys.difference(&keys) {
            combined -= key.0.as_ref();
        }

        // Add the new keys
        for key in keys.difference(&self.keys) {
            combined += key.0.as_ref();
        }

        self.keys = keys;
        self.combined = PublicKey(combined);

        self.combined.clone()
    }
}

// Helper type with faster equality semantics when used with HashSet
#[derive(Eq, Clone, Debug)]
struct WrappedPublicKey(PublicKey);

impl PartialEq for WrappedPublicKey {
    fn eq(&self, other: &Self) -> bool {
        // This byte-level equality operator differs from the (much slower) semantic
        // equality operator in G2Projective.  We require byte-level equality here
        // for HashSet to work correctly.  HashSet requires that item equality
        // implies hash equality.
        let a = self.0.as_ref();
        let b = other.0.as_ref();
        a.x == b.x && a.y == b.y && a.z == b.z
    }
}

impl Hash for WrappedPublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Only hash based on `y` for slight speed improvement
        self.0.as_ref().y.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use ark_serialize::CanonicalSerialize;

    fn rand_pubkey() -> PublicKey {
        PublicKey(G2Projective::rand(&mut rand::thread_rng()))
    }

    #[test]
    fn deserializer() {
        let mut cache = PublicKeyCache::new();

        let pubkeys = (0..10).map(|_| rand_pubkey()).collect::<Vec<_>>();
        let serialized = pubkeys
            .iter()
            .map(|p| {
                let mut w = vec![];
                p.serialize(&mut w).unwrap();
                w
            })
            .collect::<Vec<_>>();

        let de = serialized
            .iter()
            .map(|ser| cache.deserialize(ser.clone()).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(de, pubkeys);
    }

    #[test]
    fn caches_deserialized_pubkeys() {
        let mut cache = PublicKeyCache::new();

        let pubkey = rand_pubkey();

        let mut serialized = vec![];
        pubkey.serialize(&mut serialized).unwrap();

        assert!(cache.de.is_empty());

        cache.deserialize(serialized.clone()).unwrap();

        assert_eq!(cache.de.get(&serialized).unwrap(), &pubkey);
    }

    #[test]
    fn aggregation() {
        let mut cache = PublicKeyCache::new();

        let pubkeys = (0..10).map(|_| rand_pubkey()).collect::<Vec<_>>();

        let apubkey = cache.aggregate(pubkeys.clone());
        assert_eq!(apubkey, PublicKey::aggregate(&pubkeys));
    }
}
