extern crate hex;

use crate::hash::PRF;

use blake2s_simd::Params;
use byteorder::{WriteBytesExt, LittleEndian};
use std::error::Error;

pub struct DirectHasher {
}

impl DirectHasher {
    pub fn new() -> Result<DirectHasher, Box<dyn Error>> {
        Ok(DirectHasher {})
    }

}

fn xof_digest_length_to_node_offset(node_offset: usize, xof_digest_length: usize) -> Result<u64, Box<dyn Error>> {
    let mut xof_digest_length_bytes: [u8; 2] = [0; 2];
    (&mut xof_digest_length_bytes[..]).write_u16::<LittleEndian>(xof_digest_length as u16)?;
    let offset = (node_offset | ((xof_digest_length_bytes[0] as usize) << 32) | ((xof_digest_length_bytes[1] as usize) << 40)) as u64;
    Ok(offset)
}

impl PRF for DirectHasher {
    fn crh(&self, domain: &[u8], message: &[u8], xof_digest_length: usize) -> Result<Vec<u8>, Box<dyn Error>> {
        let hash_result = Params::new()
            .hash_length(32)
            .node_offset(xof_digest_length_to_node_offset(0, xof_digest_length)?)
            .personal(domain)
            .to_state()
            .update(message)
            .finalize()
            .as_ref()
            .to_vec();
        return Ok(hash_result.to_vec());
    }

    fn xof(&self, domain: &[u8], hashed_message: &[u8], xof_digest_length: usize) -> Result<Vec<u8>, Box<dyn Error>> {
        if domain.len() > 8 {
            return Err(format!("domain length is too large: {}", domain.len()).into());
        }
        let num_hashes = (xof_digest_length + 32 - 1) / 32;

        let mut result = vec![];
        for i in 0..num_hashes {
            let mut hash_result = Params::new()
                .hash_length(32)
                .max_leaf_length(32)
                .inner_hash_length(32)
                .fanout(0)
                .max_depth(0)
                .personal(domain)
                .node_offset(xof_digest_length_to_node_offset(i, xof_digest_length)?)
                .to_state()
                .update(hashed_message)
                .finalize()
                .as_ref()
                .to_vec();
            result.append(&mut hash_result);
        }

        Ok(result)
    }

    // Implements blake2x as described in: https://blake2.net/blake2x.pdf
    fn hash(&self, domain: &[u8], message: &[u8], xof_digest_length: usize) -> Result<Vec<u8>, Box<dyn Error>> {
        let prepared_message = self.crh(domain, message, xof_digest_length)?;
        self.xof(domain, &prepared_message, xof_digest_length)
    }
}

#[cfg(test)]
mod test {
    use super::DirectHasher as Hasher;
    use crate::hash::PRF;
    use rand::{Rng, SeedableRng, XorShiftRng};

    #[test]
    fn test_crh_empty() {
        let msg: Vec<u8> = vec![];
        let hasher = Hasher::new().unwrap();
        let _result = hasher.crh(&[],&msg, 96).unwrap();
    }

    #[test]
    fn test_crh_random() {
        let hasher = Hasher::new().unwrap();
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let mut msg: Vec<u8> = vec![0; 32];
        for i in msg.iter_mut() {
            *i = rng.gen();
        }
        let _result = hasher.crh(&[],&msg, 96).unwrap();
    }

    #[test]
    fn test_xof_random_96() {
        let hasher = Hasher::new().unwrap();
        let mut rng = XorShiftRng::from_seed([0x2dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let mut msg: Vec<u8> = vec![0; 32];
        for i in msg.iter_mut() {
            *i = rng.gen();
        }
        let result = hasher.crh(&[], &msg, 96).unwrap();
        let _xof_result = hasher.xof(b"ULforxof", &result, 96).unwrap();
    }

    #[test]
    fn test_hash_random() {
        let hasher = Hasher::new().unwrap();
        let mut rng = XorShiftRng::from_seed([0x2dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let mut msg: Vec<u8> = vec![0; 9820 * 4 / 8];
        for i in msg.iter_mut() {
            *i = rng.gen();
        }
        let _result = hasher.hash(b"ULforxof", &msg, 96).unwrap();
    }

    #[test]
    fn test_blake2s_test_vectors() {
        let hasher = Hasher::new().unwrap();
        let bytes = hasher.hash(b"", &hex::decode("7f8a56d8b5fb1f038ffbfce79f185f4aad9d603094edb85457d6c84d6bc02a82644ee42da51e9c3bb18395f450092d39721c32e7f05ec4c1f22a8685fcb89721738335b57e4ee88a3b32df3762503aa98e4a9bd916ed385d265021391745f08b27c37dc7bc6cb603cc27e19baf47bf00a2ab2c32250c98d79d5e1170dee4068d9389d146786c2a0d1e08ade5").unwrap(), 96).unwrap();
        assert_eq!(hex::encode(&bytes), "87009aa74342449e10a3fd369e736fcb9ad1e7bd70ef007e6e2394b46c094074c86adf6c980be077fa6c4dc4af1ca0450a4f00cdd1a87e0c4f059f512832c2d92a1cde5de26d693ccd246a1530c0d6926185f9330d3524710b369f6d2976a44d");
    }
}
