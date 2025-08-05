use crate::deopt::Deopt;
use std::path::PathBuf;
use eyre::{Context, Result};

/// CNTGProgram represents a single executable created from multiple API combination programs.
/// Unlike LibFuzzer, this keeps the original main() functions and fuses them into one binary.
pub struct CNTGProgram {
    /// programs to fuse into a single executable
    programs: Vec<PathBuf>,
    /// number of CPU cores used to parallelly process
    core: usize,
    /// Deopt
    pub deopt: Deopt,
}

impl CNTGProgram {
    pub fn new(
        programs: Vec<PathBuf>,
        core: usize,
        deopt: Deopt,
    ) -> Self {
        Self {
            programs,
            core,
            deopt,
        }
    }

    fn init(&self) -> Result<()> {
        let cntg_dir = self.deopt.get_library_cntg_dir()?;
        if cntg_dir.exists() {
            std::fs::remove_dir_all(cntg_dir)?;
        }
        let dst_dir = self.deopt.get_library_driver_dir()?;
        if dst_dir.exists() {
            std::fs::remove_dir_all(&dst_dir)?;
        }
        Ok(())
    }

    // clone the programs to a tmp directory to avoid editing the raw programs
    fn clone_programs(&self) -> Result<Vec<PathBuf>> {
        let mut new_programs = Vec::new();
        let tmp_dir = self.deopt.get_library_driver_dir()?;
        
        for (id, program) in self.programs.iter().enumerate() {
            let mut dst_path = tmp_dir.clone();
            dst_path.push(format!("id_{number:>0width$}.cc", number = id, width = 6));
            std::fs::copy(program, &dst_path)
                .context(format!("Unable to copy {program:?} to {dst_path:?}"))?;
            new_programs.push(dst_path);
        }
        Ok(new_programs)
    }

    pub fn transform(&mut self) -> Result<()> {
        self.init()?;
        self.programs = self.clone_programs()?;
        
        log::info!("Transform the correct programs to CNTG programs!");
        
        for program in &self.programs {
            log::trace!("transform {program:?}");
            let mut transformer = crate::program::transform::Transformer::new_cntg(program, &self.deopt)?;
            transformer.preprocess()?;
        }
        Ok(())
    }
}