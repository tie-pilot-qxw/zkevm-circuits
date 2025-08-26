#[cfg(test)]
mod test {
    use std::sync::Arc;
    use std::thread::JoinHandle;

    use crate::{
        batch, chunk,
        proof::{batch::BatchProof, chunk::ChunkProof},
    };
    use anyhow::Result;
    use ark_std::{end_timer, start_timer};

    use crate::constants::{
        AGG_DEGREE_FOR_TEST, MAX_NUM_ROW_FOR_TEST, NUM_STATE_HI_COL, NUM_STATE_LO_COL,
    };
    use eth_types::geth_types::ChunkData;

    type SuperCircuitJit = snark_verifier_sdk::halo2::Jit<
        zkevm_circuits::super_circuit::SuperCircuit<
            halo2_proofs::halo2curves::bn256::Fr,
            MAX_NUM_ROW_FOR_TEST,
            NUM_STATE_HI_COL,
            NUM_STATE_LO_COL,
        >,
    >;
    type AggregationCircuitJit =
        snark_verifier_sdk::evm::Jit<snark_verifier_sdk::halo2::aggregation::AggregationCircuit>;

    #[derive(Clone)]
    struct ChunkProver {
        chunk: Arc<chunk::Prover<MAX_NUM_ROW_FOR_TEST, NUM_STATE_HI_COL, NUM_STATE_LO_COL>>,
        jit_chunk: Option<SuperCircuitJit>,
    }

    impl ChunkProver {
        fn load(params_dir: &str, assets_dir: &str, jit: Option<SuperCircuitJit>) -> Self {
            let chunk = chunk::Prover::<MAX_NUM_ROW_FOR_TEST, NUM_STATE_HI_COL, NUM_STATE_LO_COL>::from_dirs(
                params_dir, assets_dir,
            );

            Self {
                chunk: Arc::new(chunk),
                jit_chunk: jit.clone(),
            }
        }
    }

    #[derive(Clone)]
    struct BatchProver {
        chunk: Arc<batch::prover::Prover<AGG_DEGREE_FOR_TEST>>,
        jit_chunk: Option<AggregationCircuitJit>,
    }

    impl BatchProver {
        fn load(params_dir: &str, assets_dir: &str, jit: Option<AggregationCircuitJit>) -> Self {
            let chunk = batch::prover::Prover::from_dirs(params_dir, assets_dir);

            Self {
                chunk: Arc::new(chunk),
                jit_chunk: jit.clone(),
            }
        }
    }

    trait Prove<I, O> {
        fn prove(&mut self, input: I) -> Result<O>;
    }

    impl Prove<ChunkData, ChunkProof> for ChunkProver {
        fn prove(&mut self, chunk_data: ChunkData) -> Result<ChunkProof> {
            self.chunk
                .gen_chunk_proof(chunk_data, self.jit_chunk.as_mut())
        }
    }

    impl Prove<Vec<ChunkProof>, BatchProof> for BatchProver {
        fn prove(&mut self, chunk_proofs: Vec<ChunkProof>) -> Result<BatchProof> {
            self.chunk
                .gen_agg_evm_proof(chunk_proofs, None, self.jit_chunk.as_mut())
        }
    }

    mod worker_pool {

        use super::*;
        use crossbeam_channel as mpmc;

        pub struct Message<T> {
            pub id: usize,
            pub data: T,
        }

        pub struct WorkerPool<I, O> {
            worker_handles: Vec<JoinHandle<()>>,
            pub(super) publisher: mpmc::Sender<Message<I>>,
            pub(super) receiver: mpmc::Receiver<Message<Result<O>>>,
            id_allocator: usize,
        }

        impl<I, O> WorkerPool<I, O>
        where
            I: Send + 'static,
            O: Send + 'static,
        {
            pub fn launch<P>(n_workers: usize, prover: P) -> Self
            where
                P: Prove<I, O> + Clone + Send + 'static,
            {
                let (publisher, work_receiver) = mpmc::unbounded::<Message<I>>();
                let (result_sender, result_receiver) = mpmc::unbounded::<Message<Result<O>>>();

                let workers = (0..n_workers)
                    .map(|worker_id| {
                        let receiver = work_receiver.clone();
                        let sender = result_sender.clone();

                        let mut prover = prover.clone();
                        std::thread::spawn(move || {
                            while let Ok(msg) = receiver.recv() {
                                println!("Worker {worker_id} 开始证明生成 {}", msg.id);
                                let result = prover.prove(msg.data);
                                sender
                                    .send(Message {
                                        id: msg.id,
                                        data: result,
                                    })
                                    .expect("send result failure")
                            }
                        })
                    })
                    .collect::<Vec<_>>();

                Self {
                    worker_handles: workers,
                    publisher,
                    receiver: result_receiver,
                    id_allocator: 0,
                }
            }

            pub fn submit(&mut self, input: I) -> usize {
                let id = self.id_allocator;
                self.id_allocator += 1;

                self.publisher
                    .send(Message { id, data: input })
                    .expect("submit task failure");

                id
            }

            pub fn recv(&mut self) -> std::result::Result<Message<Result<O>>, mpmc::RecvError> {
                self.receiver.recv()
            }

            pub fn shutdown(self) {
                drop(self.publisher);
                drop(self.receiver);

                self.worker_handles
                    .into_iter()
                    .for_each(|handle| handle.join().expect("join worker thread failure"));
            }
        }
    }

    const PARAMS_DIR: &'static str = "./test_data/params";
    const ASSETS_DIR: &'static str = "./test_data/assets";

    type ChunkWorkers = worker_pool::WorkerPool<ChunkData, ChunkProof>;
    type BatchWorkers = worker_pool::WorkerPool<Vec<ChunkProof>, BatchProof>;

    mod adapter {
        use super::*;
        pub struct Adapter {
            handle: std::thread::JoinHandle<()>,
        }

        impl Adapter {
            pub fn launch(
                chunk_workers: &super::ChunkWorkers,
                batch_workers: &super::BatchWorkers,
            ) -> Self {
                let chunk_receiver = chunk_workers.receiver.clone();
                let batch_publisher = batch_workers.publisher.clone();

                let handle = std::thread::spawn(move || {
                    let mut buffer = Vec::new();
                    let mut counter = 0;

                    while let Ok(chunk_proof_msg) = chunk_receiver.recv() {
                        match chunk_proof_msg.data {
                            Ok(chunk_proof) => {
                                buffer.push(chunk_proof);

                                if buffer.len() == 1 {
                                    batch_publisher
                                        .send(worker_pool::Message {
                                            id: counter,
                                            data: std::mem::take(&mut buffer),
                                        })
                                        .expect("send batch of ChunkProof failure");
                                    counter += 1;
                                }
                            }
                            Err(err) => {
                                println!("ChunkProver发生错误，丢弃：{:?}", err)
                            }
                        }
                    }
                });

                Self { handle }
            }

            pub fn shutdown(self) {
                self.handle.join().expect("join handle error");
            }
        }
    }

    fn start_queries(chunk_prover: ChunkProver, batch_prover: BatchProver) {
        let chunk_data_path = "./test_data/chunk_data.json";

        let chunk_data_file =
            std::fs::File::open(chunk_data_path).expect("open chunk_data.json failure");
        let chunk_data: ChunkData =
            serde_json::from_reader(chunk_data_file).expect("parse chunk_data json failure");

        let mut chunk_workers = worker_pool::WorkerPool::launch(2, chunk_prover);
        let mut batch_workers = worker_pool::WorkerPool::launch(2, batch_prover);
        let adapter = adapter::Adapter::launch(&chunk_workers, &batch_workers);

        let rounds = 4;

        let begin_warmup = start_timer!(|| "Warm up by generate one proof");
        chunk_workers.submit(chunk_data.clone());
        let _ = batch_workers.recv().expect("recv error");
        end_timer!(begin_warmup);

        let mut rng = rand_core::OsRng;

        let begin_rounds = start_timer!(|| format!("Generate proof for {} rounds", rounds));
        for i in 0..rounds {
            use rand_core::TryRngCore;

            std::thread::sleep(std::time::Duration::from_millis(
                rng.try_next_u64().unwrap() % 20_000,
            ));
            chunk_workers.submit(chunk_data.clone());
            println!("发射证明生成任务 {i}");
        }

        for _ in 0..rounds {
            let r = batch_workers.recv().expect("recv error");
            println!("收到证明 {}", r.id);
        }

        end_timer!(begin_rounds);

        chunk_workers.shutdown();
        batch_workers.shutdown();
        adapter.shutdown()
    }

    #[test]
    fn test_continuous_queries() {
        let (jit, scheduler_handle) = super::super::create_all_file::make_jit();
        let chunk_prover = ChunkProver::load(PARAMS_DIR, ASSETS_DIR, Some(jit.clone()));
        let batch_prover = BatchProver::load(PARAMS_DIR, ASSETS_DIR, Some(jit.alternative_rt()));
        start_queries(chunk_prover, batch_prover);
        scheduler_handle.shutdown();
    }

    #[test]
    fn test_cpu_continuous_queries() {
        let chunk_prover = ChunkProver::load(PARAMS_DIR, ASSETS_DIR, None);
        let batch_prover = BatchProver::load(PARAMS_DIR, ASSETS_DIR, None);
        start_queries(chunk_prover, batch_prover);
    }
}
