/// This module contains CNTGProgram, used for coverage collection for
/// specifically CNTG programs
///
/// CNTG programs generated via ApiCombination mode differs from fuzzers in that
/// CNTG programs require a main method.

pub mod seed_metas;

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
        deopt: &Deopt,
    ) -> Self {
        Self {
            programs,
            batch: batch_size,
            deopt: deopt.clone(),
        }
    }

    /// Initialize the default directories by clearing old data
    pub fn reset(&self) -> Result<()> {
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

    /// Clone the programs to dst_dir and work on the cloned programs from now
    /// on.
    ///
    /// Returns cloned program paths
    pub fn chdir(&mut self, dst_dir: &Path) -> Result<Vec<PathBuf>> {
        let mut new_programs = Vec::new();
        for (id, program) in self.programs.iter().enumerate() {
            let dst_path = dst_dir.join(format!("id_{number:>0width$}.cc", number = id, width = 6));
            std::fs::copy(program, &dst_path)
                .context(format!("Unable to copy {program:?} to {dst_path:?}"))?;
            new_programs.push(dst_path);
        }
        self.programs = new_programs.clone();
        Ok(new_programs)
    }

    /// Synthesize the separate CNTG drivers/seeds into a large programs.
    ///
    /// Each program contains `self.batch` number of seeds and a large core that calls functions in each seed sequentially.
    pub fn synthesis(&mut self, outdir: &Path) -> Result<()> {
        log::info!("synthesis huge CNTG cores!");

        let mut batch = Vec::new();
        let mut batch_id = Vec::new();
        let mut core_id = 0;
        dbg!("Start");

        for (i, driver) in self.programs.clone().iter().enumerate() {
            batch.push(driver.clone());
            batch_id.push(i);
            if batch.len() == self.batch || i == self.programs.len() - 1 {
                let core_content = self.synthesis_batch(&batch_id)?;
                dbg!("Core content obtained");
                self.fuse_core(outdir, core_content, core_id, &batch, &batch_id)?;
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
        outdir: &Path,
        core_content: String,
        core_id: usize,
        drivers: &[PathBuf],
        driver_id: &[usize],
    ) -> Result<()> {
        let core_dir = self.get_core_dir(outdir, core_id)?;
        crate::deopt::utils::create_dir_if_nonexist(&core_dir)?;
        // write the condensed core
        let core_path: PathBuf = [core_dir.clone(), "core.cc".into()].iter().collect();
        let new_core_content=format!("#include <cstddef>\n{}",core_content);
        dbg!(&core_path);
        std::fs::write(core_path, new_core_content)?;

        for (id, driver) in drivers.iter().enumerate() {
            // write each unit driver with new driver id.
            let dst_driver: PathBuf = [core_dir.clone(), driver.file_name().unwrap().into()]
                .iter()
                .collect();
            self.change_driver_id(driver, &dst_driver, driver_id[id])?;
        }
        Ok(())
    }

    fn get_core_dir(&self, outdir: &Path, core_id: usize) -> Result<PathBuf> {
        //let core_dir: PathBuf = [
        //    //self.deopt.get_library_cntg_dir()?,
        //    format!("Core_{core_id:0>width$}", width = 3).into(),
        //]
        //.iter()
        //.collect();
        Ok(outdir.join(format!("Core_{core_id:0>width$}", width = 3)))
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

    /// Compile all cores in cores_dir
    ///
    /// Each core should be in a folder generated by synthesis:
    /// <cores_dir>/Core_<id>/core.cc
    pub fn compile(&self, cores_dir: &Path) -> Result<()> {
        let executor = crate::execution::Executor::new(&self.deopt)?;
        std::thread::scope(|s| {
            let mut handles = Vec::<std::thread::ScopedJoinHandle::<()>>::new();
            for dir in std::fs::read_dir(cores_dir).unwrap() {
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
