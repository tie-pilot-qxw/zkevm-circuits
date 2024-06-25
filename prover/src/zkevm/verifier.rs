use halo2_proofs::halo2curves::bn256::Fr;
use halo2_proofs::plonk::{keygen_pk, verify_proof};
use halo2_proofs::poly::commitment::{Params, ParamsProver};
use halo2_proofs::poly::kzg::commitment::KZGCommitmentScheme;
use halo2_proofs::poly::kzg::multiopen::VerifierSHPLONK;
use halo2_proofs::poly::kzg::strategy::SingleStrategy;
use halo2_proofs::transcript::{Blake2bRead, Challenge255, TranscriptReadBuffer};
use halo2_proofs::{
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::VerifyingKey,
    poly::kzg::commitment::ParamsKZG,
};
use log::info;

use zkevm_circuits::super_circuit::SuperCircuit;
use zkevm_circuits::util::log2_ceil;

use crate::io::{read_params, try_to_read};
use crate::proof::Proof;
use crate::util::deserialize_vk;

#[derive(Debug)]
pub struct Verifier<
    const MAX_NUM_ROW: usize,
    const MAX_CODESIZE: usize,
    const NUM_STATE_HI_COL: usize,
    const NUM_STATE_LO_COL: usize,
> {
    params: ParamsKZG<Bn256>,
    vk: VerifyingKey<G1Affine>,
}

impl<
        const MAX_NUM_ROW: usize,
        const MAX_CODESIZE: usize,
        const NUM_STATE_HI_COL: usize,
        const NUM_STATE_LO_COL: usize,
    > Verifier<MAX_NUM_ROW, MAX_CODESIZE, NUM_STATE_HI_COL, NUM_STATE_LO_COL>
{
    pub fn new(params: ParamsKZG<Bn256>, vk: VerifyingKey<G1Affine>) -> Self {
        Self { params, vk }
    }

    pub fn from_dirs(params_dir: &str, assets_dir: &str) -> Self {
        let degree = log2_ceil(MAX_NUM_ROW);
        let param_file_name = format!("k{}.params", degree);
        let vk_file_name = format!("k{}.vk", degree);

        let params = read_params(params_dir, &param_file_name).unwrap();
        let raw_vk = try_to_read(assets_dir, &vk_file_name);

        let vk = deserialize_vk::<
            SuperCircuit<_, MAX_NUM_ROW, MAX_CODESIZE, NUM_STATE_HI_COL, NUM_STATE_LO_COL>,
        >(raw_vk.as_ref().unwrap(), ());

        Self::new(params, vk)
    }

    pub fn verify_chunk_proof(&self, proof: Proof) -> bool {
        // Verify the proof
        let instances = proof.instances();
        let instance_refs: Vec<&[Fr]> = instances.iter().map(|v| &v[..]).collect();
        let mut verifier_transcript =
            Blake2bRead::<_, G1Affine, Challenge255<_>>::init(proof.proof());
        let strategy = SingleStrategy::new(&self.params);

        match verify_proof::<
            KZGCommitmentScheme<Bn256>,
            VerifierSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
            SingleStrategy<'_, Bn256>,
        >(
            &self.params.verifier_params(),
            &self.vk,
            strategy,
            &[&instance_refs],
            &mut verifier_transcript,
        ) {
            Ok(_p) => true,
            Err(e) => {
                info!("verify failed: {}", e.to_string());
                false
            }
        }
    }
}

mod test {
    use crate::proof::Proof;
    use crate::zkevm::Verifier;

    const DEPLOY_MAX_NUM_ROW_FOR_TEST: usize = 21000;
    const DEPLOY_MAX_CODE_SIZE_FOR_TEST: usize = 7000;

    const NUM_STATE_HI_COL: usize = 9;

    const NUM_STATE_LO_COL: usize = 9;

    /// 运行此test时，可以先运行dump_params_and_vk_proof生成params，vk，proof文件后测试
    #[ignore]
    #[test]
    fn test_verify() {
        let param_dir = "./src/zkevm/test_data";
        let asset_dir = "./src/zkevm/test_data";

        let verifier = Verifier::<
            DEPLOY_MAX_NUM_ROW_FOR_TEST,
            DEPLOY_MAX_CODE_SIZE_FOR_TEST,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        >::from_dirs(param_dir, asset_dir);

        let proof = Proof::from_json_file("./src/zkevm/test_data", "k15");
        let result = verifier.verify_chunk_proof(proof.unwrap());
        assert!(result)
    }
}
