use failure::Error;
use dpc::crypto_primitives::crh::{
    FixedLengthCRH,
    pedersen::{PedersenCRH, PedersenWindow, PedersenParameters}
};
use algebra::{
    bytes::ToBytes,
    curves::edwards_bls12::EdwardsAffine as Edwards
};
use rand::{
    Rng,
    SeedableRng,
    chacha::ChaChaRng
};

use sha2::{Sha256, Digest};
use byteorder::{
    ReadBytesExt,
    WriteBytesExt,
    LittleEndian
};


type CRH = PedersenCRH<Edwards, Window>;
type CRHParameters = PedersenParameters<Edwards>;

#[derive(Clone)]
struct Window;

impl PedersenWindow for Window {
    const WINDOW_SIZE: usize = 4;
    const NUM_WINDOWS: usize = 9820; //(100*385+384*2+1)/4 ~ 9820
}



pub struct Hasher {
    parameters: CRHParameters,
    output_size_in_bits: usize,
}

impl Hasher {

    pub fn new(output_size_in_bits: usize) -> Result<Hasher, Error> {
        Ok(Hasher {
            parameters: Hasher::setup_crh()?,
            output_size_in_bits: output_size_in_bits,
        })
    }

    fn prng() -> Result<impl Rng, Error> {
        let mut hasher = Sha256::new();
        hasher.input(b"ULTRALIGHT PRNG SEED");
        let mut seed = vec![];
        let hash_result = hasher.result();
        for i in 0..hash_result.len()/4 {
            let mut buf = &hash_result[i..i+4];
            let num = buf.read_u32::<LittleEndian>()?;
            seed.push(num);
        }
        Ok(ChaChaRng::from_seed(&seed))
    }


    fn setup_crh() -> Result<CRHParameters, Error> {
        let mut rng = Hasher::prng()?;
        CRH::setup::<_>(&mut rng)
    }

    fn crh(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let h = CRH::evaluate(&self.parameters, message)?;
        let mut res = vec![];
        h.write(&mut res)?;
        Ok(res)
    }

    fn prf(&self, hashed_message: &[u8]) -> Result<Vec<u8>, Error> {
        let output_size_in_bits = self.output_size_in_bits;
        let num_hashes = (output_size_in_bits + 256 - 1)/256;
        let last_bits_to_keep = match output_size_in_bits % 256 {
            0 => 256,
            x => x
        };
        let last_byte_position = last_bits_to_keep/8;
        let last_byte_mask = (1 << (last_bits_to_keep % 8)) - 1;
        //println!("output_size_in_bits: {}, num_hashes: {}, last_bits_to_keep: {}, last_byte_position: {}, last_byte_mask: {}", output_size_in_bits, num_hashes, last_bits_to_keep, last_byte_position, last_byte_mask);
        let mut counter: [u8; 4] = [0; 4];

        let mut result = vec![];
        for i in 0..num_hashes {
            let mut hasher = Sha256::new();
            (&mut counter[..]).write_u32::<LittleEndian>(i as u32)?;
            hasher.input(&counter);
            hasher.input(hashed_message);
            let mut hash_result = hasher.result().to_vec();
            if (i == num_hashes - 1) {
                let mut current_index = 0;
                for j in hash_result.iter_mut() {
                    if (current_index == last_byte_position) {
                        //println!("last byte: {}", *j);
                        *j = *j & last_byte_mask;
                    } else if (current_index > last_byte_position) {
                        *j = 0;
                    }
                    current_index+=1;
                }
            }
            result.append(&mut hash_result);
        }

        Ok(result)
    }

    fn hash(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let hashed_message = self.crh(message)?;
        self.prf(&hashed_message)
    }
}

#[cfg(test)]
mod test {
    use super::{Hasher};
    use rand::{Rng, SeedableRng, XorShiftRng};

    #[test]
    fn test_crh_empty() {
        let msg: Vec<u8> = vec![];
        let hasher = Hasher::new(256).unwrap();
        let result = hasher.crh(&msg).unwrap();
        //println!("crh result: {:x?}", &result);
    }

    #[test]
    fn test_crh_random() {
        let hasher = Hasher::new(256).unwrap();
        let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let mut msg: Vec<u8> = vec![0; 32];
        for i in msg.iter_mut() {
            *i = rng.gen();
        }
        let result = hasher.crh(&msg).unwrap();
        //println!("crh result: {:x?}", &result);
    }

    #[test]
    fn test_prf_random_768() {
        let hasher = Hasher::new(768).unwrap();
        let mut rng = XorShiftRng::from_seed([0x2dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let mut msg: Vec<u8> = vec![0; 32];
        for i in msg.iter_mut() {
            *i = rng.gen();
        }
        let result = hasher.crh(&msg).unwrap();
        let prf_result = hasher.prf(&result).unwrap();
        //println!("prf result: {:?}", &prf_result);
    }

    #[test]
    fn test_prf_random_769() {
        let hasher = Hasher::new(769).unwrap();
        let mut rng = XorShiftRng::from_seed([0x0dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let mut msg: Vec<u8> = vec![0; 32];
        for i in msg.iter_mut() {
            *i = rng.gen();
        }
        let result = hasher.crh(&msg).unwrap();
        let prf_result = hasher.prf(&result).unwrap();
        //println!("prf result: {:?}", &prf_result);
    }

    #[test]
    fn test_prf_random_760() {
        let hasher = Hasher::new(760).unwrap();
        let mut rng = XorShiftRng::from_seed([0x2dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let mut msg: Vec<u8> = vec![0; 32];
        for i in msg.iter_mut() {
            *i = rng.gen();
        }
        let result = hasher.crh(&msg).unwrap();
        let prf_result = hasher.prf(&result).unwrap();
        //println!("prf result: {:?}", &prf_result);
    }

    #[test]
    fn test_hash_random() {
        let hasher = Hasher::new(760).unwrap();
        let mut rng = XorShiftRng::from_seed([0x2dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let mut msg: Vec<u8> = vec![0; 9820*4/8];
        for i in msg.iter_mut() {
            *i = rng.gen();
        }
        let result = hasher.hash(&msg).unwrap();
        //println!("hash result: {:?}", &result);
    }

    #[test]
    #[should_panic]
    fn test_invalid_message() {
        let hasher = Hasher::new(760).unwrap();
        let mut rng = XorShiftRng::from_seed([0x2dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let mut msg: Vec<u8> = vec![0; 9820*4/8 + 1];
        for i in msg.iter_mut() {
            *i = rng.gen();
        }
        let result = hasher.hash(&msg).unwrap();
        //println!("hash result: {:?}", &result);
    }

}
