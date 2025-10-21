/// Logs metadata of seeds
use std::path::{PathBuf, Path};
use std::time::{Duration, Instant};
use std::vec::Vec;
use std::option::Option;
use serde::{Serialize, Serializer, Deserialize, Deserializer};
use csv::Writer;


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
    seed_path: PathBuf,
    #[serde(serialize_with = "duration_as_seconds")]
    #[serde(deserialize_with = "seconds_as_duration")]
    duration_since_start: Duration,
    branch_coverage: Option<f32>,
}

impl SeedMetas {
    pub fn new(start_time: &Instant) -> SeedMetas {
        SeedMetas{
            start_time: Some(start_time.to_owned()),
            seed_metas: Vec::new(),
        }
    }

    /// Add a generated seed's meta data
    pub fn add(&mut self, seed_path: &Path, generation_time: Instant, branch_coverage: Option<f32>) -> Result<(), &str> {
        if self.start_time.is_none() {
            return Err("To add new seeds with this method, SeedMetas must be initialized with a start time");
        }
        self.seed_metas.push(
            SeedMeta{
                seed_path: seed_path.to_path_buf(),
                duration_since_start: generation_time - self.start_time.unwrap(),
                branch_coverage,
            }
        );
        Ok(())
    }

    /// Write seed metadata to path
    pub fn write_to(&self, path: &Path) -> Result<(), &str> {
        let mut writer =  Writer::from_path(path).map_err(|e| "Failed to create writer at path")?;
        for seed_meta in &self.seed_metas {
            writer.serialize(seed_meta).map_err(|e| "Failed to serialize seed")?;
        }
        writer.flush().map_err(|e| "Failed to flush csv writer")?;
        Ok(())
    }
}


impl TryFrom<&Path> for SeedMetas {
    type Error = &'static str;

    /// Load seed_meta from csv
    fn try_from(path: &Path) -> Result<Self, Self::Error> {
        let mut reader = csv::Reader::from_path(path).map_err(|_| "Path is invalid")?;
        let mut seed_metas = Vec::new();

        for result in reader.deserialize() {
            let record: SeedMeta = result.map_err(|_| "Failed to deserialize file")?;
            seed_metas.push(record);
        }

        Ok(SeedMetas { start_time: None, seed_metas })
    }
}
