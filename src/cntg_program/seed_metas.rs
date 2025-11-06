/// Logs metadata of seeds
use crate::cntg_program::CNTGProgram;
use crate::deopt::Deopt;
use crate::execution::Executor;
use crate::feedback::clang_coverage::CodeCoverage;
use csv::Writer;
use eyre::{Result, eyre, Error};
use serde::{Serialize, Serializer, Deserialize, Deserializer};
use std::option::Option;
use std::path::{PathBuf, Path};
use std::time::{Duration, Instant};
use std::vec::Vec;
use std::fs;


/// Flattened duration serializer for csv
fn duration_as_seconds<S>(d: &Duration, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_str(&d.as_secs_f64().to_string())
}
/// Flattened duration deserializer for csv
pub fn seconds_as_duration<'de, D>(d: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(d)?;
    let secs: f64 = s.parse().map_err(serde::de::Error::custom)?;
    Ok(Duration::from_secs_f64(secs))
}


/// Stores metadata of generated seeds.
///
/// Serializes into a table with each column being a meta property of seeds
#[derive(Debug)]
pub struct SeedMetas {
    start_time: Option<Instant>,
    seed_metas: Vec<SeedMeta>,
}

#[derive(Serialize, Deserialize, Debug)]
struct SeedMeta {
    pub seed_path: PathBuf,
    #[serde(serialize_with = "duration_as_seconds")]
    #[serde(deserialize_with = "seconds_as_duration")]
    duration_since_start: Duration,
    pub cumulative_branch_coverage: Option<f32>,
}

impl SeedMetas {
    pub fn new(start_time: &Instant) -> SeedMetas {
        SeedMetas{
            start_time: Some(start_time.to_owned()),
            seed_metas: Vec::new(),
        }
    }

    /// Add a generated seed's meta data
    pub fn add(&mut self, seed_path: &Path, generation_time: Instant, branch_coverage: Option<f32>) -> Result<()> {
        if self.start_time.is_none() {
            return Err(eyre!("To add new seeds with this method, SeedMetas must be initialized with a start time"));
        }
        self.seed_metas.push(
            SeedMeta{
                seed_path: seed_path.to_path_buf(),
                duration_since_start: generation_time - self.start_time.unwrap(),
                cumulative_branch_coverage: branch_coverage,
            }
        );
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.seed_metas.len()
    }

    /// Write seed metadata to path
    pub fn write_to(&self, path: &Path) -> Result<()> {
        let mut writer =  Writer::from_path(path)?;
        for seed_meta in &self.seed_metas {
            writer.serialize(seed_meta)?;
        }
        writer.flush()?;
        Ok(())
    }

    /// Update the cumulative_coverage of seeds
    ///
    /// Coverage computation can be batched for speed up. `batch_size` seeds
    /// will be fused together, and their coverage will be computed together.
    pub fn update_cov(&mut self, deopt: &Deopt, batch_size: usize) -> Result<()> {
        // Ensure seed metas are processed in chronological order
        self.seed_metas
            .sort_by_key(|m| m.duration_since_start);

        // Iterate over each seed_meta sequentially for future modification
        let workspace_dir = deopt.get_library_work_dir()?.join("coverage");
        let _ = fs::remove_dir_all(&workspace_dir);
        let mut cumulative_profile_exists = false;
        let cumulative_profile_path = workspace_dir.join("cumulative_profile.profdata");
        for (batch_id, seed_meta_batch) in &mut self.seed_metas.chunks_mut(batch_size).enumerate() {
            // Set up coverage environment
            let seed_paths: Vec<_> = seed_meta_batch.iter().map(|seed_meta| seed_meta.seed_path.clone()).collect();
            let mut program = CNTGProgram::new(seed_paths.clone(), batch_size, deopt);
            let stems: Vec<_> = seed_paths.iter().map(|seed_path| seed_path.file_stem()).collect();
            let lower_stem = seed_paths.first().unwrap().file_stem().unwrap().to_str().unwrap_or("unknown");
            let higher_stem = seed_paths.last().unwrap().file_stem().unwrap().to_str().unwrap_or("unknown");
            let seed_dir = workspace_dir.join(batch_id.to_string() + "_" + lower_stem + "_" + &higher_stem);
            match fs::remove_dir_all(&seed_dir) {
                Ok(_) => (),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                Err(e) => return Err(eyre!(e)),
            }
            fs::create_dir_all(&seed_dir)?;

            // Compile program
            let executor = Executor::new(&deopt)?;
            program.chdir(&seed_dir)?;
            program.synthesis(&seed_dir)?;
            program.compile(&seed_dir)?;

            // Execute program
            let (tx, rx) = std::sync::mpsc::channel();
            let handle = std::thread::spawn({
                let local_executor = executor.clone();
                let local_seed_dir = seed_dir.clone();
                move || {
                    let result = local_executor.collect_cntg_cov_all_cores(&local_seed_dir);
                    tx.send(result).unwrap();
                }
            });
            match rx.recv_timeout(Duration::from_secs(30)) {
                Ok(Err(err)) => {
                    log::warn!("Failed to collect coverage for batch {batch_id}");
                    continue;
                },
                Err(_) => {
                    log::warn!("Execution of batch {batch_id} timed out!");
                    continue;
                },
                Ok(Ok(_)) => {}
            }

            // Parse and record
            let seed_profdata_path: PathBuf = seed_dir.join("default.profdata");
            let coverage: CodeCoverage;
            if cumulative_profile_exists {
                log::debug!("Merging profile data...");
                Executor::merge_profdata(&vec![cumulative_profile_path.clone(), seed_profdata_path.clone()], &cumulative_profile_path)?;
                coverage = executor.obtain_cov_summary_from_profdata(&cumulative_profile_path)?;
            } else {
                coverage = executor.obtain_cov_summary_from_profdata(&seed_profdata_path)?;
                fs::copy(&seed_profdata_path, &cumulative_profile_path)?;
                cumulative_profile_exists = true;
            }
            let coverage_summary = coverage.get_total_summary();
            seed_meta_batch.iter_mut().for_each(|seed_meta| seed_meta.cumulative_branch_coverage = Some(coverage_summary.get_percent_branch_covered()));

            log::debug!("Cumulative coverage from seed {} to {} is {}", &lower_stem, &higher_stem, &coverage_summary.get_percent_branch_covered());
        }
        Ok(())
    }
}


impl TryFrom<&Path> for SeedMetas {
    type Error = Error;

    /// Load seed_meta from csv
    fn try_from(path: &Path) -> Result<Self, Self::Error> {
        let mut reader = csv::Reader::from_path(path)?;
        let mut seed_metas = Vec::new();

        for result in reader.deserialize() {
            let record: SeedMeta = result?;
            seed_metas.push(record);
        }

        Ok(SeedMetas { start_time: None, seed_metas })
    }
}
