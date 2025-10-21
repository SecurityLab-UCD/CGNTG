/// Logs metadata of seeds
use std::path::{PathBuf, Path};
use std::time::{Duration, Instant};
use std::vec::Vec;
use std::option::Option;
use std::error::Error;
use serde::{Serialize, Serializer};
use csv::Writer;


/// Flattened duration serializer for csv
fn duration_as_seconds<S>(d: &Duration, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_str(&d.as_secs_f64().to_string())
}

/// Stores metadata of generated seeds.
///
/// Serializes into a table with each column being a meta property of seeds
pub struct SeedMetas {
    start_time: Instant,
    seed_metas: Vec<SeedMeta>,
}

#[derive(Serialize, Debug)]
struct SeedMeta {
    seed_path: PathBuf,
    #[serde(serialize_with = "duration_as_seconds")]
    duration_since_start: Duration,
    branch_coverage: Option<f32>,
}

impl SeedMetas {
    pub fn new(start_time: &Instant) -> SeedMetas {
        SeedMetas{
            start_time: start_time.to_owned(),
            seed_metas: Vec::new(),
        }
    }

    /// Add a generated seed's meta data
    pub fn add(&mut self, seed_path: &Path, generation_time: Instant, branch_coverage: Option<f32>) {
        self.seed_metas.push(
            SeedMeta{
                seed_path: seed_path.to_path_buf(),
                duration_since_start: generation_time - self.start_time,
                branch_coverage,
            }
        );
    }

    /// Write seed metadata to path
    pub fn write_to(&self, path: &Path) -> Result<(), Box<dyn Error>> {
        let mut writer =  Writer::from_path(path)?;
        for seed_meta in &self.seed_metas {
            writer.serialize(seed_meta)?;
        }
        writer.flush()?;
        Ok(())
    }
}
