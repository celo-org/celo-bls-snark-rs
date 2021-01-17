use super::encoding::{encode_public_key, encode_u16, encode_u32, encode_u8, EncodingError};
use ark_bls12_377::{G1Projective, G2Projective};
use ark_ec::ProjectiveCurve;
use blake2s_simd::Params;
use bls_crypto::{
    hash_to_curve::{try_and_increment_cip22::COMPOSITE_HASH_TO_G1_CIP22, HashToCurve},
    PublicKey, Signature, OUT_DOMAIN, SIG_DOMAIN,
};
use bls_gadgets::utils::{bits_be_to_bytes_le, bytes_le_to_bits_le};

#[derive(Debug, Clone, Copy)]
pub enum EpochType {
    First,
    Last,
}

/// A header as parsed after being fetched from the Celo Blockchain
/// It contains information about the new epoch, as well as an aggregated
/// signature and bitmap from the validators from the previous block that
/// signed on it
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochTransition {
    /// The new epoch block which is being processed
    pub block: EpochBlock,
    /// The aggregate signature produced over the `EpochBlock`
    /// by the validators of the previous epoch
    pub aggregate_signature: Signature,
    /// The bitmap which determined the state transition
    pub bitmap: Vec<bool>,
}

/// Metadata about the next epoch
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EpochBlock {
    /// The block number
    pub index: u16,
    /// The round number from consensus
    pub round: u8,
    /// The entropy from this epoch, derived from the epoch block hash.
    /// Note: After encoding without epoch entropy is no longer supported,
    /// this can be made non-optional.
    pub epoch_entropy: Option<Vec<u8>>,
    /// The entropy from the parent epoch.
    /// Note: After encoding without epoch entropy is no longer supported,
    /// this can be made non-optional.
    pub parent_entropy: Option<Vec<u8>>,
    /// The maximum allowed number of signers that may be absent
    pub maximum_non_signers: u32,
    /// The maximum allowed number of validators
    pub maximum_validators: usize,
    /// The public keys of the new validators
    pub new_public_keys: Vec<PublicKey>,
}

impl EpochBlock {
    /// Each epoch entropy value is 128 bits.
    pub const ENTROPY_BYTES: usize = 16;

    /// Creates a new epoch block
    pub fn new(
        index: u16,
        round: u8,
        epoch_entropy: Option<Vec<u8>>,
        parent_entropy: Option<Vec<u8>>,
        maximum_non_signers: u32,
        maximum_validators: usize,
        new_public_keys: Vec<PublicKey>,
    ) -> Self {
        Self {
            index,
            round,
            epoch_entropy,
            parent_entropy,
            maximum_non_signers,
            maximum_validators,
            new_public_keys,
        }
    }

    /// Encodes the block to bytes and then proceeds to hash it to BLS12-377's G1
    /// group using `SIG_DOMAIN` as a domain separator
    pub fn hash_to_g1_cip22(&self) -> Result<G1Projective, EncodingError> {
        let (input, extra_data_input) = self.encode_inner_to_bytes_cip22()?;
        let expected_hash: G1Projective =
            COMPOSITE_HASH_TO_G1_CIP22.hash(SIG_DOMAIN, &input, &extra_data_input)?;
        Ok(expected_hash)
    }

    /// Encodes the block to bytes and then hashes it with Blake2
    pub fn blake2_first_epoch_cip22(&self) -> Result<Vec<bool>, EncodingError> {
        Ok(hash_to_bits(&self.encode_first_epoch_to_bytes_cip22()?))
    }

    pub fn padding_pk() -> G2Projective {
        G2Projective::prime_subgroup_generator()
    }

    /// Encodes the block appended with the aggregate signature to bytes and then hashes it with Blake2
    pub fn blake2_last_epoch_with_aggregated_pk_cip22(&self) -> Result<Vec<bool>, EncodingError> {
        Ok(hash_to_bits(
            &self.encode_last_epoch_to_bytes_with_aggregated_pk_cip22()?,
        ))
    }

    /// Encodes the block to LE bits
    pub fn encode_to_bits(&self) -> Result<Vec<bool>, EncodingError> {
        let mut epoch_bits = vec![];
        epoch_bits.extend_from_slice(&encode_u16(self.index)?);
        epoch_bits.extend_from_slice(&encode_u32(self.maximum_non_signers)?);
        for added_public_key in &self.new_public_keys {
            epoch_bits.extend_from_slice(encode_public_key(&added_public_key)?.as_slice());
        }
        Ok(epoch_bits)
    }

    /// Encodes the block to LE bits
    pub fn encode_to_bits_cip22(&self, epoch_type: EpochType) -> Result<Vec<bool>, EncodingError> {
        let mut epoch_bits = vec![];
        epoch_bits.extend_from_slice(&encode_u16(self.index)?);
        // The first epoch doesn't need the current entropy and the last epoch doesn't need the
        // parent entropy.
        match epoch_type {
            EpochType::First => epoch_bits
                .extend_from_slice(&Self::encode_entropy_cip22(self.parent_entropy.as_ref())),
            EpochType::Last => epoch_bits
                .extend_from_slice(&Self::encode_entropy_cip22(self.epoch_entropy.as_ref())),
        }
        epoch_bits.extend_from_slice(&encode_u32(self.maximum_non_signers)?);
        for added_public_key in &self.new_public_keys {
            epoch_bits.extend_from_slice(encode_public_key(&added_public_key)?.as_slice());
        }
        if self.maximum_validators > self.new_public_keys.len() {
            let difference = self.maximum_validators - self.new_public_keys.len();
            let padding_pk = PublicKey::from(Self::padding_pk());
            for _ in 0..difference {
                epoch_bits.extend_from_slice(encode_public_key(&padding_pk)?.as_slice());
            }
        }
        Ok(epoch_bits)
    }

    pub fn encode_entropy_cip22(entropy: Option<&Vec<u8>>) -> Vec<bool> {
        let entropy_bytes = match entropy {
            Some(entropy) => entropy.clone(),
            None => vec![0u8; Self::ENTROPY_BYTES * 8],
        };
        // Add the bits of the epoch entropy, interpreted as a little-endian number, in little-endian ordering.
        bytes_le_to_bits_le(&entropy_bytes, Self::ENTROPY_BYTES * 8)
    }

    /// Encodes the block to LE bits
    pub fn encode_inner_to_bits_cip22(&self) -> Result<(Vec<bool>, Vec<bool>), EncodingError> {
        let mut epoch_bits = vec![];
        let mut extra_data_bits = vec![];
        extra_data_bits.extend_from_slice(&encode_u16(self.index)?);
        extra_data_bits.extend_from_slice(&encode_u8(self.round)?);
        extra_data_bits.extend_from_slice(&encode_u32(self.maximum_non_signers)?);
        epoch_bits.extend_from_slice(&Self::encode_entropy_cip22(self.epoch_entropy.as_ref()));
        epoch_bits.extend_from_slice(&Self::encode_entropy_cip22(self.parent_entropy.as_ref()));
        for added_public_key in &self.new_public_keys {
            epoch_bits.extend_from_slice(encode_public_key(&added_public_key)?.as_slice());
        }
        if self.maximum_validators > self.new_public_keys.len() {
            let difference = self.maximum_validators - self.new_public_keys.len();
            let padding_pk = PublicKey::from(Self::padding_pk());
            for _ in 0..difference {
                epoch_bits.extend_from_slice(encode_public_key(&padding_pk)?.as_slice());
            }
        }
        Ok((epoch_bits, extra_data_bits))
    }

    /// Encodes the block with the aggregated public key from the vector of pubkeys to LE bits
    pub fn encode_last_epoch_to_bits_with_aggregated_pk_cip22(
        &self,
    ) -> Result<Vec<bool>, EncodingError> {
        let mut epoch_bits = self.encode_to_bits_cip22(EpochType::Last)?;
        let aggregated_pk = PublicKey::aggregate(&self.new_public_keys);
        epoch_bits.extend_from_slice(encode_public_key(&aggregated_pk)?.as_slice());
        Ok(epoch_bits)
    }

    /// Encodes the block to LE bytes
    pub fn encode_first_epoch_to_bytes_cip22(&self) -> Result<Vec<u8>, EncodingError> {
        Ok(bits_be_to_bytes_le(
            &self.encode_to_bits_cip22(EpochType::First)?,
        ))
    }

    /// Encodes the block to LE bytes
    pub fn encode_to_bytes(&self) -> Result<Vec<u8>, EncodingError> {
        Ok(bits_be_to_bytes_le(&self.encode_to_bits()?))
    }

    /// Encodes the block with the aggregated public key from the vector of pubkeys to LE bytes
    pub fn encode_last_epoch_to_bytes_with_aggregated_pk_cip22(
        &self,
    ) -> Result<Vec<u8>, EncodingError> {
        Ok(bits_be_to_bytes_le(
            &self.encode_last_epoch_to_bits_with_aggregated_pk_cip22()?,
        ))
    }

    /// Encodes an inner block to LE bytes
    pub fn encode_inner_to_bytes_cip22(&self) -> Result<(Vec<u8>, Vec<u8>), EncodingError> {
        let (inner_bits, extra_data_bits) = self.encode_inner_to_bits_cip22()?;
        Ok((
            bits_be_to_bytes_le(&inner_bits),
            bits_be_to_bytes_le(&extra_data_bits),
        ))
    }
}

/// Serializes the first and last epoch to bytes, hashes them with Blake2 personalized to
/// `OUT_DOMAIN` and returns the LE bit representation
pub fn hash_first_last_epoch_block(
    first: &EpochBlock,
    last: &EpochBlock,
) -> Result<Vec<bool>, EncodingError> {
    let h1 = first.blake2_first_epoch_cip22()?;
    let h2 = last.blake2_last_epoch_with_aggregated_pk_cip22()?;
    Ok([h1, h2].concat())
}

/// Blake2 hash of the input personalized to `OUT_DOMAIN`
pub fn hash_to_bits(bytes: &[u8]) -> Vec<bool> {
    let hash = Params::new()
        .hash_length(32)
        .personal(OUT_DOMAIN)
        .to_state()
        .update(&bytes)
        .finalize()
        .as_ref()
        .to_vec();
    bytes_le_to_bits_le(&hash, 256)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::ProjectiveCurve;

    static EXPECTED_ENCODING_WITH_ENTROPY: &str = "fdd542ddf4fdd764cddfee7f0933f1b9bc93330f9c7d44ce979da3ccdcef4ea6aa816263a3b4b8e1628000ce81c0d4594601f03d928fd309504ded4a7d22c66dae6d5fd50794fac540f980c4c197150774108e8ac25822fb171ec7f90212eeaf16eaa6efbf266bfe76ff4b9889cfe59d9c79e0ec2372beec1c65e67e7732550d141b1ba5c50d170304700e04a6ce320a80ef917c9c4e806a6a57ea13316e736dfbaa3ea0d42f06ca07240ebeac38a083705414c612d9bff038ce1790707fb550377dff3559f3b7fb5fc24c7c2eefe4cc03671f91f365e72833f7bb93a96aa0d8d8282d6eb8182080732030759651007c8fe4e374025453bb529f88719b6bdb57f501a57e31503e2071f065c5011d84a3a23096c8fe85c771be8084fbab85bae9fbafc99abfddff1266e2737927671e38fb889c2f3b4799b9df9d4c5503c5c6466971c3c500019c0381a9b38c02e07b241fa713a09ada95fa448cdb5cdbbeaa0f28f58b81f20189832f2b0ee8201c1585b144f62f3c8ef30524dc5f2dd44ddf7f4dd6fcedfe9730139fcb3b39f3c0d947e47cd939caccfdee64aa1a2836364a8b1b2e0608e01c084c9d651400df23f9389d00d5d4aed42762dce6daf6557d40a95f0c940f481c7c59714007e1a8288c25b27fe1719c2f20e1fe6aa16efafe6bb2e66ff7bf8499f85cdec99907ce3e22e7cbce5166ee772753d540b1b1515adc70314000e74060ea2ca300f81ec9c7e904a8a676a53e11e336d7b6afea034afd62a07c40e2e0cb8a033a084745612c91fd0b8fe37c0109f7570b75d3f75f93357fbbff25ccc4e7f24ece3c70f611395f768e3273bf3b99aa068a8d8dd2e2868b010238070253671905c0f7483e4e274035b52bf58918b7b9b67d551f50ea1703e50312075f561cd041382a0a6389ec5f781ce70b48b8bf5aa89bbeff9aacf9dbfd2f61263e977772e681b38fc8f9b2739499fbddc95435506c6c9416375c0c10c03910983acb2800be47f2713a01aaa95da94fc4b8cdb5edabfa8052bf18281f9038f8b2e2800ec25151184b64ffc2e3385f40c2fdd542ddf4fdd764cddfee7f0933f1b9bc93330f9c7d44ce979da3ccdcef4ea6aa816263a3b4b8e1628000ce81c0d4594601f03d928fd309504ded4a7d22c66dae6d5fd50794fac540f980c4c197150774108e8ac25822fb171ec7f90212eeaf16eaa6efbf266bfe76ff4b9889cfe59d9c79e0ec2372beec1c65e67e7732550d141b1ba5c50d170304700e04a6ce320a80ef917c9c4e806a6a57ea13316e736dfbaa3ea0d42f06ca07240ebeac38a083705414c612d9bff038ce179030000000f0dfdfdfdfdfdfdfdfdfdfdfdfdfdfdf1f8007";
    static EXPECTED_ENCODING_WITH_ENTROPY_PADDED: &str = "fdd542ddf4fdd764cddfee7f0933f1b9bc93330f9c7d44ce979da3ccdcef4ea6aa816263a3b4b8e1628000ce81c0d4594601f03d928fd309504ded4a7d22c66dae6d5fd50794fac540f980c4c197150774108e8ac25822fb171ec7f90212eeaf16eaa6efbf266bfe76ff4b9889cfe59d9c79e0ec2372beec1c65e67e7732550d141b1ba5c50d170304700e04a6ce320a80ef917c9c4e806a6a57ea13316e736dfbaa3ea0d42f06ca07240ebeac38a083705414c612d9bff038ce1790707fb550377dff3559f3b7fb5fc24c7c2eefe4cc03671f91f365e72833f7bb93a96aa0d8d8282d6eb8182080732030759651007c8fe4e374025453bb529f88719b6bdb57f501a57e31503e2071f065c5011d84a3a23096c8fe85c771be8084fbab85bae9fbafc99abfddff1266e2737927671e38fb889c2f3b4799b9df9d4c5503c5c6466971c3c500019c0381a9b38c02e07b241fa713a09ada95fa448cdb5cdbbeaa0f28f58b81f20189832f2b0ee8201c1585b144f62f3c8ef30524dc5f2dd44ddf7f4dd6fcedfe9730139fcb3b39f3c0d947e47cd939caccfdee64aa1a2836364a8b1b2e0608e01c084c9d651400df23f9389d00d5d4aed42762dce6daf6557d40a95f0c940f481c7c59714007e1a8288c25b27fe1719c2f20e1fe6aa16efafe6bb2e66ff7bf8499f85cdec99907ce3e22e7cbce5166ee772753d540b1b1515adc70314000e74060ea2ca300f81ec9c7e904a8a676a53e11e336d7b6afea034afd62a07c40e2e0cb8a033a084745612c91fd0b8fe37c0109f7570b75d3f75f93357fbbff25ccc4e7f24ece3c70f611395f768e3273bf3b99aa068a8d8dd2e2868b010238070253671905c0f7483e4e274035b52bf58918b7b9b67d551f50ea1703e50312075f561cd041382a0a6389ec5f781ce70b48b8bf5aa89bbeff9aacf9dbfd2f61263e977772e681b38fc8f9b2739499fbddc95435506c6c9416375c0c10c03910983acb2800be47f2713a01aaa95da94fc4b8cdb5edabfa8052bf18281f9038f8b2e2800ec25151184b64ffc2e3385f40c2fdd542ddf4fdd764cddfee7f0933f1b9bc93330f9c7d44ce979da3ccdcef4ea6aa816263a3b4b8e1628000ce81c0d4594601f03d928fd309504ded4a7d22c66dae6d5fd50794fac540f980c4c197150774108e8ac25822fb171ec7f90212eeaf16eaa6efbf266bfe76ff4b9889cfe59d9c79e0ec2372beec1c65e67e7732550d141b1ba5c50d170304700e04a6ce320a80ef917c9c4e806a6a57ea13316e736dfbaa3ea0d42f06ca07240ebeac38a083705414c612d9bff038ce1790707fb550377dff3559f3b7fb5fc24c7c2eefe4cc03671f91f365e72833f7bb93a96aa0d8d8282d6eb8182080732030759651007c8fe4e374025453bb529f88719b6bdb57f501a57e31503e2071f065c5011d84a3a23096c8fe85c771be808401000080fffefefefefefefefefefefefefefefe003c00";
    static EXPECTED_ENCODING_WITHOUT_ENTROPY: &str = "fdd542ddf4fdd764cddfee7f0933f1b9bc93330f9c7d44ce979da3ccdcef4ea6aa816263a3b4b8e1628000ce81c0d4594601f03d928fd309504ded4a7d22c66dae6d5fd50794fac540f980c4c197150774108e8ac25822fb171ec7f90212eeaf16eaa6efbf266bfe76ff4b9889cfe59d9c79e0ec2372beec1c65e67e7732550d141b1ba5c50d170304700e04a6ce320a80ef917c9c4e806a6a57ea13316e736dfbaa3ea0d42f06ca07240ebeac38a083705414c612d9bff038ce1790707fb550377dff3559f3b7fb5fc24c7c2eefe4cc03671f91f365e72833f7bb93a96aa0d8d8282d6eb8182080732030759651007c8fe4e374025453bb529f88719b6bdb57f501a57e31503e2071f065c5011d84a3a23096c8fe85c771be8084fbab85bae9fbafc99abfddff1266e2737927671e38fb889c2f3b4799b9df9d4c5503c5c6466971c3c500019c0381a9b38c02e07b241fa713a09ada95fa448cdb5cdbbeaa0f28f58b81f20189832f2b0ee8201c1585b144f62f3c8ef30524dc5f2dd44ddf7f4dd6fcedfe9730139fcb3b39f3c0d947e47cd939caccfdee64aa1a2836364a8b1b2e0608e01c084c9d651400df23f9389d00d5d4aed42762dce6daf6557d40a95f0c940f481c7c59714007e1a8288c25b27fe1719c2f20e1fe6aa16efafe6bb2e66ff7bf8499f85cdec99907ce3e22e7cbce5166ee772753d540b1b1515adc70314000e74060ea2ca300f81ec9c7e904a8a676a53e11e336d7b6afea034afd62a07c40e2e0cb8a033a084745612c91fd0b8fe37c0109f7570b75d3f75f93357fbbff25ccc4e7f24ece3c70f611395f768e3273bf3b99aa068a8d8dd2e2868b010238070253671905c0f7483e4e274035b52bf58918b7b9b67d551f50ea1703e50312075f561cd041382a0a6389ec5f781ce70b48b8bf5aa89bbeff9aacf9dbfd2f61263e977772e681b38fc8f9b2739499fbddc95435506c6c9416375c0c10c03910983acb2800be47f2713a01aaa95da94fc4b8cdb5edabfa8052bf18281f9038f8b2e2800ec25151184b64ffc2e3385f40c2fdd542ddf4fdd764cddfee7f0933f1b9bc93330f9c7d44ce979da3ccdcef4ea6aa816263a3b4b8e1628000ce81c0d4594601f03d928fd309504ded4a7d22c66dae6d5fd50794fac540f980c4c197150774108e8ac25822fb171ec7f90212eeaf16eaa6efbf266bfe76ff4b9889cfe59d9c79e0ec2372beec1c65e67e7732550d141b1ba5c50d170304700e04a6ce320a80ef917c9c4e806a6a57ea13316e736dfbaa3ea0d42f06ca07240ebeac38a083705414c612d9bff038ce17903000000030000000000000000000000000000000008007";
    static EXPECTED_ENCODING_BEFORE_DONUT: &str = "fdd542ddf4fdd764cddfee7f0933f1b9bc93330f9c7d44ce979da3ccdcef4ea6aa816263a3b4b8e1628000ce81c0d4594601f03d928fd309504ded4a7d22c66dae6d5fd50794fac540f980c4c197150774108e8ac25822fb171ec7f90212eeaf16eaa6efbf266bfe76ff4b9889cfe59d9c79e0ec2372beec1c65e67e7732550d141b1ba5c50d170304700e04a6ce320a80ef917c9c4e806a6a57ea13316e736dfbaa3ea0d42f06ca07240ebeac38a083705414c612d9bff038ce1790707fb550377dff3559f3b7fb5fc24c7c2eefe4cc03671f91f365e72833f7bb93a96aa0d8d8282d6eb8182080732030759651007c8fe4e374025453bb529f88719b6bdb57f501a57e31503e2071f065c5011d84a3a23096c8fe85c771be8084fbab85bae9fbafc99abfddff1266e2737927671e38fb889c2f3b4799b9df9d4c5503c5c6466971c3c500019c0381a9b38c02e07b241fa713a09ada95fa448cdb5cdbbeaa0f28f58b81f20189832f2b0ee8201c1585b144f62f3c8ef30524dc5f2dd44ddf7f4dd6fcedfe9730139fcb3b39f3c0d947e47cd939caccfdee64aa1a2836364a8b1b2e0608e01c084c9d651400df23f9389d00d5d4aed42762dce6daf6557d40a95f0c940f481c7c59714007e1a8288c25b27fe1719c2f20e1fe6aa16efafe6bb2e66ff7bf8499f85cdec99907ce3e22e7cbce5166ee772753d540b1b1515adc70314000e74060ea2ca300f81ec9c7e904a8a676a53e11e336d7b6afea034afd62a07c40e2e0cb8a033a084745612c91fd0b8fe37c0109f7570b75d3f75f93357fbbff25ccc4e7f24ece3c70f611395f768e3273bf3b99aa068a8d8dd2e2868b010238070253671905c0f7483e4e274035b52bf58918b7b9b67d551f50ea1703e50312075f561cd041382a0a6389ec5f781ce70b48b8bf5aa89bbeff9aacf9dbfd2f61263e977772e681b38fc8f9b2739499fbddc95435506c6c9416375c0c10c03910983acb2800be47f2713a01aaa95da94fc4b8cdb5edabfa8052bf18281f9038f8b2e2800ec25151184b64ffc2e3385f40c2fdd542ddf4fdd764cddfee7f0933f1b9bc93330f9c7d44ce979da3ccdcef4ea6aa816263a3b4b8e1628000ce81c0d4594601f03d928fd309504ded4a7d22c66dae6d5fd50794fac540f980c4c197150774108e8ac25822fb171ec7f90212eeaf16eaa6efbf266bfe76ff4b9889cfe59d9c79e0ec2372beec1c65e67e7732550d141b1ba5c50d170304700e04a6ce320a80ef917c9c4e806a6a57ea13316e736dfbaa3ea0d42f06ca07240ebeac38a083705414c612d9bff038ce179030000000308007";

    #[test]
    fn encode_to_bytes() -> Result<(), EncodingError> {
        let pubkeys = (0..10)
            .map(|_| ark_bls12_377::G2Projective::prime_subgroup_generator().into())
            .collect::<Vec<_>>();
        let epoch = EpochBlock::new(
            120u16,
            5u8,
            Some(vec![255u8; EpochBlock::ENTROPY_BYTES]),
            Some(vec![254u8; EpochBlock::ENTROPY_BYTES]),
            3,
            pubkeys.len(),
            pubkeys,
        );
        assert_eq!(
            hex::encode(epoch.encode_first_epoch_to_bytes_cip22()?),
            EXPECTED_ENCODING_WITH_ENTROPY
        );
        Ok(())
    }

    #[test]
    fn encode_to_bytes_without_entropy() -> Result<(), EncodingError> {
        let pubkeys = (0..10)
            .map(|_| ark_bls12_377::G2Projective::prime_subgroup_generator().into())
            .collect::<Vec<_>>();
        let epoch = EpochBlock::new(120u16, 5u8, None, None, 3, pubkeys.len(), pubkeys);
        assert_eq!(
            hex::encode(epoch.encode_first_epoch_to_bytes_cip22()?),
            EXPECTED_ENCODING_WITHOUT_ENTROPY
        );
        Ok(())
    }

    #[test]
    /// Tests against encodings that were generated from commit 67aa80c1ce5ac5a4e2fe3377ba8b869e982a4f96,
    /// the version deployed before the Donut hardfork.
    fn encode_to_bytes_before_donut() -> Result<(), EncodingError> {
        let pubkeys = (0..10)
            .map(|_| ark_bls12_377::G2Projective::prime_subgroup_generator().into())
            .collect::<Vec<_>>();
        let epoch = EpochBlock::new(120u16, 10u8, None, None, 3, pubkeys.len(), pubkeys);
        assert_eq!(
            hex::encode(epoch.encode_to_bytes()?),
            EXPECTED_ENCODING_BEFORE_DONUT
        );
        Ok(())
    }

    #[test]
    fn encode_to_bytes_padded() -> Result<(), EncodingError> {
        let pubkeys = (0..10)
            .map(|_| ark_bls12_377::G2Projective::prime_subgroup_generator().into())
            .collect::<Vec<_>>();
        let epoch = EpochBlock::new(
            120u16,
            5u8,
            Some(vec![255u8; EpochBlock::ENTROPY_BYTES]),
            Some(vec![254u8; EpochBlock::ENTROPY_BYTES]),
            3,
            pubkeys.len() + 1,
            pubkeys,
        );
        assert_eq!(
            hex::encode(epoch.encode_first_epoch_to_bytes_cip22()?),
            EXPECTED_ENCODING_WITH_ENTROPY_PADDED
        );
        assert_eq!(
            EXPECTED_ENCODING_WITH_ENTROPY.len() + 190, // one more public key
            EXPECTED_ENCODING_WITH_ENTROPY_PADDED.len()
        );
        Ok(())
    }
}
