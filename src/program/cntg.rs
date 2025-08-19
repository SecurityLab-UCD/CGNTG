use crate::deopt::Deopt;
use std::path::{Path, PathBuf};
use eyre::{Context, Result, eyre};

/// CNTGProgram represents a single executable created from multiple API combination programs.
/// Unlike LibFuzzer, this keeps the original main() functions and fuses them into one binary.
pub struct CNTGProgram {
    /// programs to fuse into a single executable
    programs: Vec<PathBuf>,
    /// number of programs coalesced to a huge executable
    batch: usize,
    /// Deopt
    pub deopt: Deopt,
}

impl CNTGProgram {
    pub fn new(
        programs: Vec<PathBuf>,
        batch_size: usize,
        deopt: Deopt,
    ) -> Self {
        Self {
            programs,
            batch: batch_size,
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
        // TODO: Parallel processing to speed up transformation.
        self.init()?;
        self.programs = self.clone_programs()?;
        
        log::info!("Transform the correct programs to CNTG programs!");
        Ok(())
        // Currently CNTGProgram does not seem to need preprocessing. It is also incompatible with the fuzzer preprocessing.
        //for program in &self.programs {
        //    log::trace!("transform {program:?}");
        //    let mut transformer = crate::program::transform::Transformer::new_cntg(program, &self.deopt)?;
        //    transformer.preprocess()?;
        //}
        //Ok(())
    }

    /// Synthesize the separate CNTG drivers/seeds into a large programs.
    /// 
    /// Each program contains `self.batch` number of seeds and a large core that calls functions in each seed sequentially.
    pub fn synthesis(&mut self) -> Result<()> {
        log::info!("synthesis huge CNTG cores!");
        let driver_dir = self.deopt.get_library_driver_dir()?;
        let drivers: Vec<PathBuf> = crate::deopt::utils::read_sort_dir(&driver_dir)?
            .iter()
            .filter(|x| x.extension().is_some() && x.extension().unwrap().to_string_lossy() == "cc")
            .cloned()
            .collect();

        let mut batch = Vec::new();
        let mut batch_id = Vec::new();
        let mut core_id = 0;

        for (i, driver) in drivers.iter().enumerate() {
            batch.push(driver.clone());
            batch_id.push(i);
            if batch.len() == self.batch || i == drivers.len() - 1 {
                let core_content = self.synthesis_batch(&batch_id)?;
                self.fuse_core(core_content, core_id, &batch, &batch_id)?;
                batch.clear();
                batch_id.clear();
                core_id += 1;
            }
        }
        Ok(())
    }

    /// Write 
    fn synthesis_batch(&mut self, batch_id: &Vec<usize>) -> Result<String> {
        let mut stmts = String::new();
        stmts.push_str(crate::deopt::utils::format_library_header_strings(
            &self.deopt,
        ));
        stmts.push_str("\n\n");

        let lib = self.deopt.project_name.clone();
        for id in batch_id {
            stmts.push_str(&format!(
                "int test_{lib}_api_sequence_{id}();\n",
            ));
        }
        stmts.push_str("\n\n");

        stmts.push_str(
            "int main(int argc, char* argv[])\n{\n",
        );
        for (i, id) in batch_id.iter().enumerate() {
            stmts.push_str(&format!("\tstd::cout << \"Running program {i}...\" << std::endl;\n"));
            stmts.push_str(&format!(
                "\ttest_{}_api_sequence_{id}();\n",
                lib
            ));
        }
        stmts.push_str("\treturn 0;\n");
        stmts.push_str("}\n");
        Ok(stmts)
    }


    /// Write the single core with multiple drivers' source files, renaming driver functions to link with core.
    fn fuse_core(
        &self,
        core_content: String,
        core_id: usize,
        drivers: &[PathBuf],
        driver_id: &[usize],
    ) -> Result<()> {
        let core_dir = self.get_core_dir(core_id)?;
        crate::deopt::utils::create_dir_if_nonexist(&core_dir)?;
        // write the condensed core
        let core_path: PathBuf = [core_dir.clone(), "core.cc".into()].iter().collect();
        std::fs::write(core_path, core_content)?;

        for (id, driver) in drivers.iter().enumerate() {
            // write each unit driver with new driver id.
            let dst_driver: PathBuf = [core_dir.clone(), driver.file_name().unwrap().into()]
                .iter()
                .collect();
            self.change_driver_id(driver, &dst_driver, driver_id[id])?;
        }
        Ok(())
    }

    fn get_core_dir(&self, core_id: usize) -> Result<PathBuf> {
        let core_dir: PathBuf = [
            self.deopt.get_library_cntg_dir()?,
            format!("Core_{core_id:0>width$}", width = 3).into(),
        ]
        .iter()
        .collect();
        Ok(core_dir)
    }

    fn change_driver_id(
        &self,
        src_driver: &Path,
        dst_driver: &Path,
        driver_id: usize,
    ) -> Result<()> {
        let buf = std::fs::read_to_string(src_driver)?;
        let library_name = self.deopt.project_name.clone();
        let function_name = format!("test_{}_api_sequence", library_name);
        let buf = buf.replace(
            &function_name,
            &format!("{}_{}", function_name, driver_id),
        );
        std::fs::write(dst_driver, buf)?;
        Ok(())
    }

    pub fn compile(&self) -> Result<()> {
        let executor = crate::execution::Executor::new(&self.deopt)?;
        std::thread::scope(|s| {
            let mut handles = Vec::<std::thread::ScopedJoinHandle::<()>>::new();
            for dir in std::fs::read_dir(self.deopt.get_library_cntg_dir().unwrap()).unwrap() {
                handles.push(
                    s.spawn(|| {
                        let core_dir = dir.unwrap().path();
                        if core_dir.is_dir() {
                            log::info!("Compile to Core: {core_dir:?}");
                            let core_binary = get_core_path(&core_dir);
                            executor.compile_lib_fuzzers(
                                &core_dir,
                                &core_binary,
                                crate::execution::Compile::CoverageNoFuzz,
                            ).unwrap();
                            self.deopt.copy_library_init_file(&core_dir).unwrap();
                        }
                    })
                );
            }
            for handle in handles {
                let result = handle.join();
                if result.is_err() {
                    return Err(eyre!(""));
                }
            }
            return Ok(());
        })
    }
}

pub fn get_core_path(core_dir: &Path) -> PathBuf {
    [core_dir.to_path_buf(), "core".into()].iter().collect()
}
