// Copyright (C) SAFIT. All rights reserved.
// Copyright (C) BABEC. All rights reserved.
// Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.
//
// SPDX-License-Identifier: Apache-2.0

//! benchmark create_proof for super_circuit

use zkevm_circuits::constant::MAX_NUM_ROW;
use zkevm_circuits::util::chunk_data_test;

use crate::{run_benchmark, run_benchmark_with_config};
use halo2_proofs::zkpoly_compiler::driver::{self, DiskMemoryInfo, MemoryInfo};
use halo2_proofs::zkpoly_runtime::debug::statistics::Statistics;
use std::path::PathBuf;

#[test]
fn bench_super_circuit() {
    let machine_code = trace_parser::assemble_file("test_data/1.txt");
    let trace = trace_parser::trace_program(&machine_code, &[]);

    let chunk_data = &chunk_data_test(trace, &machine_code, &[], false, Default::default());

    #[cfg(feature = "fast_test")]
    let degree = 11;
    #[cfg(not(feature = "fast_test"))]
    let degree = std::env::var("K")
        .map(|x| x.parse().unwrap_or_else(|_| panic!("invalid K")))
        .unwrap_or(19);

    // run benchmark
    let (proof_time, statistics) =
        run_benchmark::<MAX_NUM_ROW>("super_circuit", chunk_data, degree);

    println!("Duration: {:?}, Statistics: {:#?}", proof_time, &statistics);
}

#[cfg(test)]
mod ablation_study {
    use eth_types::geth_types::ChunkData;
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;
    use std::fs;
    use std::path::Path;

    use super::*;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
    /// At each stage, a new feature is switched on based on configuration of last stage
    enum AblationStage {
        Base,
        Belady,
        HeuristicGraphScheduling,
        SliceableSubgraph,
    }

    #[derive(Clone, Serialize, Deserialize)]
    struct ExperimentResult {
        proof_time: std::time::Duration,
        statistics: Vec<(String, f64)>,
    }

    #[derive(Serialize, Deserialize)]
    struct ProgressDataSerializeable {
        results: Vec<(u32, AblationStage, ExperimentResult)>,
    }

    #[derive(Serialize, Deserialize)]
    struct ProgressData {
        results: HashMap<(u32, AblationStage), ExperimentResult>,
    }

    impl ProgressData {
        fn new() -> Self {
            Self {
                results: HashMap::new(),
            }
        }

        fn export(&self) -> ProgressDataSerializeable {
            ProgressDataSerializeable {
                results: self
                    .results
                    .iter()
                    .map(|((k, s), e)| (k.clone(), s.clone(), e.clone()))
                    .collect(),
            }
        }

        fn import(s: ProgressDataSerializeable) -> Self {
            Self {
                results: s.results.into_iter().map(|(k, s, e)| ((k, s), e)).collect(),
            }
        }

        fn load_or_create(path: &Path) -> std::io::Result<Self> {
            if path.exists() {
                let content = fs::read_to_string(path)?;
                let progress_data: ProgressDataSerializeable = serde_json::from_str(&content)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                Ok(Self::import(progress_data))
            } else {
                Ok(ProgressData::new())
            }
        }

        fn save(&self, path: &Path) -> std::io::Result<()> {
            let content = serde_json::to_string_pretty(&self.export())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            fs::write(path, content)
        }

        fn get_missing_experiments(
            &self,
            degrees: &[u32],
            stages: &[AblationStage],
        ) -> Vec<(u32, AblationStage)> {
            let mut missing = Vec::new();
            for &degree in degrees {
                for &stage in stages {
                    if !self.results.contains_key(&(degree, stage)) {
                        missing.push((degree, stage));
                    }
                }
            }
            missing
        }
    }

    struct Params {
        degree: u32,
        config: driver::Config,
        hardware_info: driver::HardwareInfo,
    }

    struct Updater<'p> {
        stage: AblationStage,
        config: &'p mut driver::Config,
    }

    impl<'p> Updater<'p> {
        fn update_if(
            &mut self,
            ge_stage: AblationStage,
            update: impl FnOnce(driver::Config) -> driver::Config,
        ) {
            *self.config = if self.stage >= ge_stage {
                update(std::mem::take(self.config))
            } else {
                std::mem::take(self.config)
            }
        }
    }

    impl Params {
        fn of(degree: u32, stage: AblationStage) -> Self {
            if degree < 19 {
                panic!("minimal degree is 19 in order to hold all constraints");
            }

            let cpu_capacity = (200 * 2u32.pow(degree - 19)).min(400);

            let hardware_info =
                driver::HardwareInfo::new(MemoryInfo::new(cpu_capacity as u64 * 2u64.pow(30)))
                    .with_gpu(MemoryInfo::new(28 * 2u64.pow(30)))
                    .with_disk(DiskMemoryInfo::new(Some(PathBuf::from("/data/tmp"))));

            let mut config = driver::Config::default()
                .with_sliceable_subgraph(None)
                .with_scheduler_alg(driver::GraphSchedulingAlgorithm::PlainTopologySort)
                .with_memory_planning(
                    driver::MemoryPlanningConfig::default()
                        .with_smithereen_space(2u64.pow(28))
                        .with_criterion(driver::CriterionChoice::Epsilon)
                        .with_gpu_allocator(driver::GpuAllocatorChoice::Slab),
                );

            let mut updater = Updater {
                config: &mut config,
                stage,
            };

            use AblationStage::*;
            updater.update_if(Belady, |c| {
                c.map_memory_planning(|c| c.with_criterion(driver::CriterionChoice::Belady))
            });
            updater.update_if(HeuristicGraphScheduling, |c| {
                // c.with_scheduler_alg(driver::GraphSchedulingAlgorithm::SethiUllman)
                c
            });
            updater.update_if(SliceableSubgraph, |c| {
                c.with_sliceable_subgraph_on(
                    driver::SubgraphSlicingConfig::default()
                        .with_chunk_len(2u64.pow((degree - 3).max(18)))
                        .with_minimum_order(10),
                )
            });

            Self {
                degree,
                config,
                hardware_info,
            }
        }

        fn run(
            &self,
            chunk_data: &ChunkData,
            debug_dir: PathBuf,
            kernel_dir: PathBuf,
        ) -> (std::time::Duration, Statistics) {
            let options = driver::DebugOptions::minimal(debug_dir)
                .with_type2_visualizer(driver::Type2DebugVisualizer::Cytoscape)
                .with_log(true);
            options.prepare_dir();

            // run benchmark
            let (proof_time, statistics) = run_benchmark_with_config::<MAX_NUM_ROW>(
                "super_circuit",
                chunk_data,
                self.degree,
                &self.hardware_info,
                &options,
                &self.config,
                true,
                true,
                false,
                kernel_dir,
            );

            println!(
                "Degree: {}, Duration: {:?}, Statistics: {:#?}",
                self.degree, proof_time, statistics
            );

            (proof_time, statistics.unwrap())
        }
    }

    fn run_degrees_stages(
        degrees: Vec<u32>,
        stages: Vec<AblationStage>,
        directory: &str,
        progress_file_path: PathBuf,
    ) {
        let machine_code = trace_parser::assemble_file("test_data/1.txt");
        let trace = trace_parser::trace_program(&machine_code, &[]);

        let chunk_data = &chunk_data_test(trace, &machine_code, &[], false, Default::default());

        // Load existing progress or create new one
        let mut progress_data = match ProgressData::load_or_create(&progress_file_path) {
            Ok(data) => data,
            Err(e) => {
                eprintln!("Failed to load progress data: {:?}, starting fresh", e);
                ProgressData::new()
            }
        };

        // Find missing experiments
        let missing_experiments = progress_data.get_missing_experiments(&degrees, &stages);

        println!("Found {} missing experiments", missing_experiments.len());

        // Run missing experiments
        for (degree, stage) in missing_experiments {
            let name = format!("Degree{}_{:?}", degree, stage);
            println!("Running experiment: {}", name);

            let parent_dir = PathBuf::from(format!("{}/{}", directory, name));
            let params = Params::of(degree, stage);
            let (proof_time, statistics) =
                params.run(chunk_data, parent_dir.clone(), parent_dir.join("kernels"));

            // Convert statistics to export format
            let stats_export = statistics.export();

            // Add result to progress data
            let result = ExperimentResult {
                proof_time,
                statistics: stats_export,
            };
            progress_data.results.insert((degree, stage), result);

            // Save progress after each experiment
            if let Err(e) = progress_data.save(&progress_file_path) {
                eprintln!("Failed to save progress: {:?}", e);
            }
        }

        println!("Ablation study completed!");
    }

    #[test]
    fn run_scale_test() {
        let degrees = vec![19, 20, 21, 22, 23];
        let stages = vec![AblationStage::SliceableSubgraph];
        run_degrees_stages(
            degrees,
            stages,
            "scale_test",
            "scale_test_progress.json".into(),
        );
    }

    #[test]
    fn run_ablation_study() {
        // Define degrees and stages to test
        let degrees = vec![19, 21];
        let stages = vec![
            AblationStage::Base,
            AblationStage::Belady,
            AblationStage::HeuristicGraphScheduling,
            // AblationStage::SliceableSubgraph,
        ];

        run_degrees_stages(
            degrees,
            stages,
            "ablation",
            "ablation_study_progress.json".into(),
        );
    }

    fn progress_data() -> ProgressData {
        ProgressData {
            results: [(
                (19, AblationStage::Base),
                ExperimentResult {
                    proof_time: std::time::Duration::from_secs(2),
                    statistics: vec![("nothing".to_string(), 2.0)],
                },
            )]
            .into_iter()
            .collect(),
        }
    }

    #[test]
    fn test_progress_data_save() {
        let pd = progress_data();

        pd.save(&PathBuf::from("./test_progress_data_save.json"))
            .unwrap();
    }

    #[test]
    fn test_save_load_progress_data() {
        let pd = progress_data();

        let path = PathBuf::from("./test_progress_data_save.json");
        pd.save(&path).unwrap();

        let load = ProgressData::load_or_create(&path).unwrap();
        assert_eq!(load.results.len(), 1);
    }
}
