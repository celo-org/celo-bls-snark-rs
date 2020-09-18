pub mod epoch_block;
use epoch_block::{read_slice, EpochBlockFFI};

#[cfg(test)]
mod test_helpers;

use crate::convert_result_to_bool;
use epoch_snark::EpochBlock;
use std::convert::TryFrom;

#[no_mangle]
/// Verifies a Groth16 proof about the validity of the epoch transitions
/// between the provided `first_epoch` and `last_epoch` blocks.
///
/// All elements are assumed to be sent as serialized byte arrays
/// of **compressed elements**. There are no assumptions made about
/// the length of the verifying key or the proof, so that must be
/// provided by the caller.
///
/// # Safety
/// 1. VK and Proof must be valid pointers
/// 1. The vector of pubkeys inside EpochBlockFFI must point to valid memory
pub unsafe extern "C" fn verify(
    // Serialized verifying key
    vk: *const u8,
    // Length of serialized verifying key
    vk_len: u32,
    // Serialized proof
    proof: *const u8,
    // Length of serialized proof
    proof_len: u32,
    // First epoch data (pubkeys serialized)
    first_epoch: EpochBlockFFI,
    // Last epoch data (pubkeys serialized)
    last_epoch: EpochBlockFFI,
) -> bool {
    convert_result_to_bool(|| {
        let first_epoch = EpochBlock::try_from(&first_epoch)?;
        let last_epoch = EpochBlock::try_from(&last_epoch)?;
        let vk = read_slice(vk, vk_len as usize)?;
        let proof = read_slice(proof, proof_len as usize)?;

        epoch_snark::verify(&vk, &first_epoch, &last_epoch, &proof)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snark::EpochBlockFFI;

    #[test]
    // Trimmed down version of the other E2E groth test to ensure
    // that the verifier works correctly for a proof which we have verified on our own
    // TODO(#185) Include epoch entropy values here when a new proof is available.
    fn simple_verifier_groth16() {
        let serialized_proof = hex::decode(PROOF).unwrap();
        let serialized_vk = hex::decode(VK).unwrap();

        // Get the corresponding pointers
        let proof_ptr = &serialized_proof[0] as *const u8;
        let vk_ptr = &serialized_vk[0] as *const u8;

        let first_pubkeys = hex::decode(FIRST_PUBKEYS).unwrap();
        let last_pubkeys = hex::decode(LAST_PUBKEYS).unwrap();

        let first_epoch = EpochBlockFFI {
            index: 0,
            epoch_entropy: std::ptr::null(),
            parent_entropy: std::ptr::null(),
            maximum_non_signers: 1,
            pubkeys_num: 4,
            pubkeys: &first_pubkeys[0] as *const u8,
        };

        let last_epoch = EpochBlockFFI {
            index: 2,
            epoch_entropy: std::ptr::null(),
            parent_entropy: std::ptr::null(),
            maximum_non_signers: 1,
            pubkeys_num: 4,
            pubkeys: &last_pubkeys[0] as *const u8,
        };

        // Make the verification
        let res = unsafe {
            verify(
                vk_ptr,
                serialized_vk.len() as u32,
                proof_ptr,
                serialized_proof.len() as u32,
                first_epoch,
                last_epoch,
            )
        };
        assert!(res);
    }

    const PROOF: &str = "ef4cf0bca93ef33d946b4d7f1fc4284db6cc38dcae001b840139f5f65931f8f5fec71264475296b596e6be49912b155101c868e3eb0c302f6c4cfed1646a1c539a2e1a2cd057098c5caa9ae280581818d9bac2538cf093d3981095a83795a60034b16ee64558fc411616e5c93d85702b9ef5a3717391421dad10a758563151a323ee9205830a62c7c202b8efd708c7dbd8507888d5e67de9afb8f01a44576a8d07afee6371745cff068158494c6417bc94e914332b9f538a93889bb48eca0000771f6780a848ecaf14a348069833cf87c115696c6fa06053826a3bf9b9d5c13c4908eac10c660c49fa464ed35ab0d6b0236dcf8d9f89a6993314295d4b618528acf36458daf822cb04cbbc2b997d74c6e7c98fea0edb164c3a3531f520511601";

    const VK: &str = "30d721b1097a32eb233d0d992cf96947c3d16eda34d1e4202ca73f9941d3e1c703d66260b8fbc7ce2e64611fd9635125670cca28e36bd1be8e42f5a01f1c6f618a9dfd948a765ad0e0ad79ffcea20eb59094659154e6d966cafa7376ca3daa80ba9f61778070ff3ecb01f004f02002b6f8ab9abfe93cc82fe233bf60715d309fe21ff07b66b49e618f3b04b0ed10f528534ea9b193c54913930426a237ea14634c14809d62eca682f3f5a225da11086b06a480b2516892b1f485d1a48291f080f97b21f6aef284ba2d014af525e924886b9d2b5c1abec17bcbc48b28d0afb946ddee1d1a932ea02eac55a21979640e6bc59855ddeb84a52277edb3ce148807d3b1f515f59b8797d3a4b3c587f428411a0b1cb829d5e9846f84312b7edfa91400418a0940b86a2d6dd9db894629c09b55aa8f346a2879b18ee8fb85495cd400f6eca54680110d3a30460e31150e8c6b224cea6468d5e841b78cbea8a112a02692c375ac4b6b43ec75602d95254fc36aa24e6d603f631c6ba0e147535ff6ebfc0003000000000000004da984eca399ce809fecfa8247ce841055d98b10473166a6999a53854c2dfa04879eecc31e095f4d61fdb91795483f7d891b0bf79162e4831f46d1b21236457940dfc23d9ef5bec9d91b949f586707b5890c60c050b390921f226edcd8c10d805eb23fc80122474368478f3e88f4e4486b615a280ccfe99de4e36f5f9e03175eafe461169554090afa2dddd793c6f9575aa5aefc0f18efb40f03b887acdc912b812e9703bd847363592b02ad5bea8483bfa118ad9391509bafe5890b6eb681004f2605b2b02aae6154034413a2793d488cecc97443ae0fddaa39316498349159eb0ca3184ecae5b5d028bba0e1d11b50045921dbb5e0d4479b4a0c2a3527a3721d959e78b54243980d2329f20df969cfa68df0639cfbdeacc7ce0d0e04040381";

    const FIRST_PUBKEYS: &str = "45a3ed64a457fbc0e875b0d6dcc372216f96571eefd7a07d373a4de2b73cbebe6b7d43025a4306d356f5fc189ea720013295a3110785f5f7783e7e22a582b810ffdc5e3b10a61c38d3ee0f70ddc59294dd03d4753c7a3500f3c1456d19571981d13b719de39cbf8c84a840484820d3b80836bfa161971f0c32dcd6b23d72adf3d817b9e648082d7e1c0a39fb6393390153ba4ca1ec7fb74a7c4c4f77c2399a214535b303c629b298fa946bbb4c7325ed3a7ac15fe8fdb311287cb06b75ba94813e511d58c8c12709103dfd66c13797c404509da9659f6395b318866b448a2150ffbc4f3f4524d3c5fc453e7020f7a2009ea4bdceed84a0431f153aa834a947bb1ed239f95d9c32c3110e0937687012e44d5e68cadefdc10f7bea106bfcb07881b66e28d8b7fb1418bf311830eba1b0cffe5ec9348ec6b54f2bb21434dce17176279d5525694499b6988b4ecaa8232000f473f369e191669fa3e5ff781f3040fd3b16f694b6bb6798d7f3067c62d49180022cbb9f33f964bb4ddfb20019c85780";

    const LAST_PUBKEYS: &str = "d764f62c103729199d656f4bc760e415a364472e94024adaa094a31ac77bd4e3f9e5a4d3d889ac52f771c2abacf2520129c1fbae55a607962d89d046a10913d970f6fd65f6b39fff73662911b1b20eb4491fb891eba353f282d191cbe28267013319c74ebf0ac8f1e719a69eb6f88be921399d03eadcc40d05c00890057a723edfbaff1f68ef4d34eb7983da89d4b5001cf381e1853d867fe1fd2c99f9f9440cb9b03e985791f87435ba5b341621d2c0fb31deef8d9f4fe29f569188597467819ec3d6f924d17bcabeae3485c9400d56363d27e2fc1c00de28a1fc65ca7f7101b34bccffd566d3f06dcdc5160747020166bc4f8122b647af14e7adfb26446809805e1942082805b191602fd4f4a44b5ccd01129d634c8aa080d504646ae27501e1f2c6f70e5ae7081aa5177f5b3c0108128e248110a9116aeb69e8b03ff092089db6821fb638e1f879f19810a1a52e01bea4cfcc8c8dff610d6afa9dfb6e693d1fc8a2e4673101e346044a5b55074547884d5a76704d16937e2dab23ebb41581";
}
