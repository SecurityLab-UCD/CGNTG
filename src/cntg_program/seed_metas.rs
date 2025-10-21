/// Logs metadata of seeds
use crate::cntg_program::CNTGProgram;
use crate::deopt::Deopt;
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
    cumulative_branch_coverage: Option<f32>,
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

    /// Write seed metadata to path
    pub fn write_to(&self, path: &Path) -> Result<()> {
        let mut writer =  Writer::from_path(path)?;
        for seed_meta in &self.seed_metas {
            writer.serialize(seed_meta)?;
        }
        writer.flush()?;
        Ok(())
    }

    pub fn update_cov(&mut self, deopt: &Deopt) -> Result<()> {
        // Ensure seed metas are processed in chronological order
        self.seed_metas
            .sort_by_key(|m| m.duration_since_start);

        // Iterate over each seed_meta sequentially for future modification
        let workspace_dir = deopt.get_library_work_dir()?.join("coverage");
        for mut seed_meta in &mut self.seed_metas {
            let seed_path = seed_meta.seed_path.clone();
            let mut program = CNTGProgram::new(vec![seed_path.clone()], 1, deopt);
            let stem = seed_path.file_stem().ok_or_else(|| eyre!("Invalid seed path"))?;
            let seed_dir = workspace_dir.join(stem);
            match fs::remove_dir_all(&seed_dir) {
                Ok(_) => (),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                Err(e) => return Err(eyre!(e)),
            }
            fs::create_dir_all(&seed_dir)?;
            program.chdir(&seed_dir)?;
            program.synthesis(&seed_dir)?;
            program.compile(&seed_dir)?;
        }

        todo!();
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
