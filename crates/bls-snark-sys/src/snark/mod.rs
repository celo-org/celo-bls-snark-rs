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

    // Without entropy
    const PROOF: &str = "62a94218e54fa53e515d8930ef1123d8e4565113d1722aeec9889758193f725b9345884ebc9ae9f7189fcef2c4017d068e0a992fcf04630ce420d3728a32ae4cf22f797a6a9c19286fb7e6bc90a5f19f2f4b36ac37c2b1485a0cb940fd8e15809e6fbc702b2233c5051e019283749b7bc2500194a3b2f8a2ae9e4c76d765f628e6cc83c17b1188301cabe8a0414c848a3e242306b43d12d826dba139468879effc479cf2e7f36b640c824f1e487a23ec56982da63eb76752efd3b722bc7ac98063085219dfd864b51ad03b12ab3b379998b49b906a55c54a4df948e1f97964b1eb6a9202457d13e9045595cff66629db9b9ee966cb295c5ce8c383555f9465635d33189042ab5de54961eba4ea9eabb280cd72fcb1714c627f248b5a261e3a00";

    const VK: &str = "25b7ed2b29b7fcda6b47fb75df6ab16f8692c797a0d4eb87da9d6d9a28a137cc6ac5a16e064633ab3206fd4bebaac118e88fd8c6cd986c1f5877cec21c33193059095bb48367bceb70798f5e05814ae8be0f858618c1318c06340fa4fd7d53804b9f9d779f5fddeeea6e88dcec411ce4e6bb9712e105f168a9e1f7d386abe72468633c22eff3b6a216da777e45b881d794ba703068763e116f42e1c73e6f0855fb015eec150db11d4e258bb4a410fe2c1f7dd27df9427fdeb6c5a42b572fc30079b655535e6f1c8d56b8c37434c35f566b6c275748bf340497f0311bf176fe36693f9ac25355af9a656b0c5628d00c764890dd6772b42c06af28cfee5f46b4d4feac9383061019a5896ecea530f37f079e6deb7a3814600a7061435d81ea0201a7241a68fa43c2fd7d2b5050f14bcedbcbb199dc2fd08e6334910b56e17efd761641bc5138cb88ce9a9802a33a8c9a548226d37450cbbeafce16a6a5c4eff923a506c09fb2e5f69cc864351c8732300507959c5a00444fd1f0aec8fb6a090300030000000000000034a33166bb98b1472f480964bd93ebe4ea74b30033a50e1480fbf22496f6f3ea2dc9d0f44245e1c493a5e6bf002130b2197adc2986d78f154f296b1ca0087f9191b47b08aea5f593c65cd355fd100f237a3c0622c4e6f2178044547e62f773806b0ce067218659cf14e1e521a7acdbbd21f0f538ab6b86a9cc811362e5e4b2b398a7ed527e7a675a1544c8a43dab040f720cc3587a5941c9758615b6f4628b6e67035a9c4041bdcca2b06f53d71e9680b10262347d84f4a616935c00eef93e00a1617f278d542f84f31492f555f3f160145b38e8bc9db682a0cc45b5532a842d31861c9eafaf6946fcfb26d3d3d1c80fb95e0687532d9dea5d7331bfe433a00da87c1e96b3a92d38e0d94dc6002e4a91e0f1f3c86e7caeb1d95b37b7b5af0a80";

    const FIRST_PUBKEYS: &str = "507927aa5b4f8468185503b0f449460581237e09003bcf57ab2d4f92efed806f8f297998366ac7eb7a24289158e32e01143da099ee2c4860a8cef577d2de34f150bb862bb4a3979ae8f6e65a05a6a2294e85023086112a14a7718f3f1b1a4e819661f44187ce20e100c25a11c6403835af1d22a470257c3ee1f035c45e8191bbf97e124beb6c414f68091de21cf08700c781b6d1c83b39e4ba4dad9d64e2f6d09374093466663357469ff6f43f9e7987de1b381de5183a06f8b28d65442a1881a274c0be8d80b63036b31c3d852d6377fdcf2190caab35ed1472cea19421f854f0395b763156b6297bceb0a9d6985901aef2e7401fe741ea2626af25ef6005f5068f8a3f4a0187e59906e488baaa1308b980ce6f5e346aba6ea61b4a3ddaa100dc85ea20b9785b270dc4324a01a629b58cdb820fb959061bdac8da0bda1bc41930a574a2e4e0ca54cbea55f631205f01abb3521c478e08e9c1ba22445c8e948003847c6f2e3e3ae210a8762e48ac32f107c79a38519c34d972648b0fc3e08181";

    const LAST_PUBKEYS: &str = "6d5ff910e6940e278916e24bcfd396c333f0b3cf84cd483e0abedafd572369749efe8935a1ee9785feabb78dd300ab00c3d9b7dd9901672fc17d25c3e75d32308ebf22a393d9680d9bc5baf5372cf76872e04497186944aacdb564d214f884009851bf321720db6996112141903c90408689905c8a373e36eba6071b647af1f171bf5046e3916f60383078ef5977fb002d75cd113daa768cfd6c0c72b999d4f884c58c1cd4d0e0ac5ba2a7dcbfa4aa81053665b0fbc90d38fff6182a117ba0808f46becddc50dad5f5e728de07cb7744d799af5dd9777eb094502f43b083f1dad7d012bf55a8a13eccf24e101c9a7101055fe1d73ffb4b401bdc529ed54614f55417ee4430f1c0c7b67184d37c3de0089ca63b1cb090db5e659ba3e807464081bbbdd4e92f3dc34590ac3557955f25def659c0a16e30c3923d388968991a2c972bcfab13a0a44c5b4e2bdcf85d63280042caab9ab6b8fc7c3e3b4b542b02095433955f853557cefed9388ac72f0bca0fc1241ec0a41f966f15b83be6b5a5ba00";

    // With entropy
    const ENTROPY_PROOF: &str = "2d687f19a50a9fa448f0b8fe66fdebef79fcf7aa3a28dbe99b3cf9c9b5ccbd8e3112e70f6adc6dbd1f7842ce8c979a8df231913885c1f49c4d7a5061cc86818eb0236aed6ac7249771d52d5c4afb9786594ac90e85ce74baf3e03d2b4486558041504a292703a08bb354d3a72d6833eadcfc0091a2485c28eb276fe9db1db7f3a556f43d4653644c4d674cfeb404746b96e0b4319c509275a833e4b74994c2cd577b24cc69f8c8d1878d198bcce0d859c08b123d79ad55f5e79d5c9187a0e68012d9d0ceb60bc128699eadeca80b4aa64975bc2362903b5c5962fe3e206b099ef94d47c2855c147e47ad504615bc296d69c45fe5d9919dd9461ee35d0d444a2b3f70c88d9ee94162357fbef002826cf5d107bc2840a7f5a4fadd012ca5c84700";

    const ENTROPY_VK: &str = "cb08a9edbe0d663c0b974db1e10214a3a1360c43b24965ec1ccec41a3b71bb68970ea85fcced35eb96a513fe9d331c78aeac9876a836d5ea5979d0fe8df90e1df97935983d5c8a98a0fd4b0674817ed93a446e283c6e46cd5516040bc53f1681a80f0158393d08d12c3585162db176da7abdcd88c19030101f63803284c87ab12d19e4327887f5f895142a2b1bce30f7fbfeb183aacb39932c9273222b6a682c614d9f0863b2675d4f5a8cec5324ee7f36601c1bd0cc5324449498664d77ee006320fa22379f656182343cb1271411f2beb6a5cedb09108769058b3ce866f95c320bf6a47a35c9be80f4f2c3eb25f12fbeeeca87d469dab31cbc2319f7a33d8a49ad54a7d18f4a5c67776888a616886440c4d2f385a25340e4aa445d04dbb80024b2dae75842cd9bd079ddf5e3c4fac428e3c26341fc6ab9dc781dce7099f0ea9270a6c8d5ae327e003351bfa24983fe12c0ec6a810d54b921bcf249942ff8920d852eb9a48cf4f40da2eb26ee3bc341665820b30d88a30558b232237659860003000000000000000c5108166bb171dfc32916917d28f54f2bac7dae9d66ba6e0ac2da6e288d19e033964ba7fe020f93fe0d43dddcf340f7085280216890b70ba3c1f534d1575090a57597ab507a178dd48188a5b439ac6734b1636efba3ff29e5eb32a2a8857c8070bcb52afe7a1d7b2a7726564c31b12a58f21bc0712a236a3883b531189b4f27a20e05e419c5b41b0ecd4f8d3361f62fae6a087541fefd687a5760fc21291accd0ca27caa60237bee8b513acd1a9aa374edb5ffa08bb8150f761166e23f2f980a7e9e08c7acc5427c7b073f6710d380b06dafe912c5711f679e1dc4aae84a43c329e3ca35b35a7c288681d0d864658d5e117641773f513512cf8dd320898033a965d7632ad13881aa9591159deaff218ca980b3e9e8c71b84462789501712a80";

    const ENTROPY_FIRST_PUBKEYS: &str = "c9739cc7138839932a0242198c9010931d637e12ef14a721f5c899a931b9f4768cf99d7b2dd1e4155d84c445b6e35f0098e50851f002ce88e54ed9e85585c9734e7e9a5ad62ce9c31bd9bfc07d8e05966672991b41c975eb18b0016a54b872807f34bc397312f9fec5bf4b54a3d7d109e24e7d8ebc767a1650fc7d0499a9b4b63803e4339e411ecae3a7a3c807c9de00bc04db8dfc67ca24a076ea89c527d3728a4303a0730d5e9eaa62c0ddfd7ca60f3ef3c40d822e925deaa4de618add7181401a944e07a02fececa63b80dc599f55dd3f3bb3694397a53d4ba966e1fd855a5869995066e1305c56d80df5d22a1800c4532a8a2e4ed60cdfcba9656e31f1f2f4995d7455728ce345bace27bf82b83cb52895c03c242c1f81762074b6b338013a640d0ef661b36b7c1d16bb0db7b504ad56849e462ec2f2fb6e634a2ecf97b5973061fcc9793bbd4196e8e43aa11a01f390ff5210a56c58488abb85f25306034c4b254379fac8694627a93d8464e48c87f8f562080b5484e3fa81bb28dc0880";

    const ENTROPY_LAST_PUBKEYS: &str = "3e2b12102137fb22b4090758fa401402c38395ccb298b0293ce92aae1b0ee94dca8f584f3711f9215e09956675db23018b096ef962d45776b1b2297659f72654718d9c966992de74603e6a4b4f9a772593fb7eee81c80172bcc066f602356700f71a26d968d8d72879a545f23b786d77647651ac4d53664c5c1fa4bd12ce361b7c9453977bed702dd47a7e60163929010874597b5c576e5f0833f6e0eed0ef092b390a5e603c119e31b959abb0da91dfb9f8f261beaaaedb1174aa52792bc3008aae6c635b6d8928242bed6b6a9593997b37592f9d9979243089585a882b2a487d94619b4034296b9b1342ab4db69300923962be630dfafef037b7396b8def0334f350b74c0ffa7b87fc376512c3b3bb49c14e7999f7245debac1a6b5b5b8b8154565226aff2d54773d5f319a4d9d3122fabbeee1236aee23584b2f4c74049b70f4813a08938e6536df886ddca3691001b7225731da891b5491530d818168bd953a9b7abdbb55881e4001acbc92a03c55c26535e5966e16dab9b387e89f58801";

    const FIRST_EPOCH_ENTROPY: &str = "01010101010101010101010101010101";
    const FIRST_PARENT_ENTROPY: &str = "02020202020202020202020202020202";
    const LAST_EPOCH_ENTROPY: &str = "03030303030303030303030303030303";
    const LAST_PARENT_ENTROPY: &str = "02020202020202020202020202020202";

    #[test]
    // Trimmed down version of the other E2E groth test to ensure
    // that the verifier works correctly for a proof which we have verified on our own
    fn simple_verifier_groth16_with_entropy() {
        let serialized_proof = hex::decode(ENTROPY_PROOF).unwrap();
        let serialized_vk = hex::decode(ENTROPY_VK).unwrap();

        // Get the corresponding pointers
        let proof_ptr = &serialized_proof[0] as *const u8;
        let vk_ptr = &serialized_vk[0] as *const u8;

        let first_pubkeys = hex::decode(ENTROPY_FIRST_PUBKEYS).unwrap();
        let last_pubkeys = hex::decode(ENTROPY_LAST_PUBKEYS).unwrap();

        let first_epoch_entropy = hex::decode(FIRST_EPOCH_ENTROPY).unwrap();
        let first_parent_entropy = hex::decode(FIRST_PARENT_ENTROPY).unwrap();

        let first_epoch = EpochBlockFFI {
            index: 0,
            epoch_entropy: &first_epoch_entropy[0] as *const u8,
            parent_entropy: &first_parent_entropy[0] as *const u8,
            maximum_non_signers: 1,
            pubkeys_num: 4,
            pubkeys: &first_pubkeys[0] as *const u8,
        };

        let last_epoch_entropy = hex::decode(LAST_EPOCH_ENTROPY).unwrap();
        let last_parent_entropy = hex::decode(LAST_PARENT_ENTROPY).unwrap();

        let last_epoch = EpochBlockFFI {
            index: 2,
            epoch_entropy: &last_epoch_entropy[0] as *const u8,
            parent_entropy: &last_parent_entropy[0] as *const u8,
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
}
