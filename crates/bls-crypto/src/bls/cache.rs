use super::PublicKey;
use algebra::{bls12_377::G2Projective, CanonicalDeserialize, SerializationError, Zero};

use lru::LruCache;
use std::collections::HashSet;

pub struct PublicKeyCache {
    /// The current keys in the validator set
    pub keys: HashSet<PublicKey>,
    /// The aggregated public key of all validators
    pub combined: PublicKey,
    /// A mapping from
    pub de: LruCache<Vec<u8>, PublicKey>,
}

impl Default for PublicKeyCache {
    fn default() -> Self { Self::new() }
}

impl PublicKeyCache {
    /// Initializes an empty cache
    pub fn new() -> Self {
        Self {
            keys: HashSet::new(),
            combined: PublicKey(G2Projective::zero()),
            de: LruCache::new(128),
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
        let mut keys: HashSet<PublicKey> = HashSet::with_capacity(public_keys.len());
        for key in public_keys {
            keys.insert(key);
        }

        let mut combined = self.combined.0;

        for key in self.keys.difference(&keys) {
            combined -= key.as_ref();
        }

        for key in keys.difference(&self.keys) {
            combined += key.as_ref();
        }

        self.keys = keys;
        self.combined = PublicKey(combined);

        self.combined.clone()
    }
}
