use clap::{Parser, Subcommand};
use eyre::Result;
use prompt_fuzz::deopt::{self, Deopt};
use prompt_fuzz::execution::Executor;
use prompt_fuzz::program::cntg::CNTGProgram;
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};
use std::io::Write;


/// Command Parser
#[derive(Parser, Debug)]
#[command(author="Anonymous", name = "LLMFuzzer-harness", version, about="The harness to invoke each component in PromptFuzz", long_about = None)]
pub struct Config {
    /// Target project to proceed
    project: String,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Fuse the api combination in seeds to a single executable.
    FuseSeeds {
        /// the path of seeds to fuse
        seed_dir: Option<PathBuf>,
        /// The batch size of files to be fused together
        #[clap(short, long)]
        batch_size: Option<usize>,
    },
    /// Collect coverage for CNTG fused programs
    CollectCoverage,
    /// Report coverage for CNTG fused programs
    ReportCoverage,
    /// Create seeds, fuse them, and report coverage. Pass fuzzer arguments after the command.
    All {
        #[clap(raw = true)]
        fuzzer_args: Vec<String>,
    },
}

fn fuse_seeds(
    project: String,
    seed_dir: &Option<PathBuf>,
    batch_size: Option<usize>,
) -> Result<()> {
    let deopt = Deopt::new(project)?;
    let test_dir: PathBuf = if let Some(seed_dir) = seed_dir {
        seed_dir.clone()
    } else {
        deopt.get_library_seed_dir()?
    };
    let programs = crate::deopt::utils::read_sort_dir(&test_dir)?;
    dbg!(&programs);

    let batch_size = batch_size.unwrap_or(100);

    let mut cntg_program = CNTGProgram::new(programs, batch_size, &deopt);
    cntg_program.transform()?;
    cntg_program.synthesis()?;
    cntg_program.compile()?;
    Ok(())
}

fn collect_coverage(project: String) -> Result<()> {
    let deopt = Deopt::new(project)?;
    let cntg_dir = deopt.get_library_cntg_dir()?;
    
    if !cntg_dir.exists() {
        eyre::bail!("CNTG directory not found: {cntg_dir:?}. Please run 'fuse-seeds' first.");
    }
    
    let executor = Executor::new(&deopt)?;
    executor.collect_cntg_cov_all_cores(&cntg_dir)?;
    
    log::info!("CNTG coverage collection completed successfully");
    Ok(())
}

fn report_coverage(project: String) -> Result<()> {
    let deopt = Deopt::new(project)?;
    let cntg_dir = deopt.get_library_cntg_dir()?;
    if !cntg_dir.exists() {
        eyre::bail!("CNTG directory not found: {cntg_dir:?}. Please run 'fuse-seeds' first.");
    }

    // 1. Collect coverage
    let executor = Executor::new(&deopt)?;
    executor.collect_cntg_cov_all_cores(&cntg_dir)?;
    log::info!("CNTG coverage collection completed successfully");

    // 2. Report coverage
    let profdata_path: PathBuf = [cntg_dir.clone(), "default.profdata".into()].iter().collect();
    if !profdata_path.exists() {
        eyre::bail!("default.profdata not found in {cntg_dir:?}.");
    }

    let cov_lib = crate::deopt::utils::get_cov_lib_path(&deopt, true);

    let output = Command::new("llvm-cov")
        .arg("report")
        .arg(cov_lib)
        .arg(format!("--instr-profile={}", profdata_path.to_string_lossy()))
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()?;

    if !output.status.success() {
        eyre::bail!("llvm-cov report failed!");
    }

    let mut cov_report_path = deopt.get_library_output_dir()?;
    cov_report_path.push("coverage_report.txt");
    std::fs::write(cov_report_path, &output.stdout)?;
    std::io::stdout().write_all(&output.stdout)?;

    Ok(())
}

fn create_seeds(project: &str, fuzzer_args: &[String]) -> Result<()> {
    let mut cmd = Command::new("cargo");
    cmd.arg("run")
        .arg("--bin")
        .arg("fuzzer")
        .arg("--")
        .arg(project)
        .args(fuzzer_args);

    let status = cmd.status()?;
    if !status.success() {
        eyre::bail!("Failed to create seeds for {project}");
    }
    Ok(())
}

fn all(project: String, fuzzer_args: &[String]) -> Result<()> {
    // 1. Create seeds
    create_seeds(&project, fuzzer_args)?;

    // 2. Fuse seeds
    fuse_seeds(project.clone(), &None, None)?;

    // 3. Report coverage
    report_coverage(project)
}

fn main() -> ExitCode {
    let config = Config::parse();
    prompt_fuzz::config::Config::init_test(&config.project);
    let project = config.project.clone();
    match &config.command {
        Commands::FuseSeeds {
            seed_dir,
            batch_size,
        } => {
            if let Err(err) = fuse_seeds(project, seed_dir, *batch_size) {
                log::error!("Failed to fuse seeds: {}", err);
                return ExitCode::FAILURE;
            }
        }
        Commands::CollectCoverage => {
            if let Err(err) = collect_coverage(project) {
                log::error!("Failed to collect coverage: {}", err);
                return ExitCode::FAILURE;
            }
            return ExitCode::SUCCESS;
        }
        Commands::ReportCoverage => {
            if let Err(err) = report_coverage(project) {
                log::error!("Failed to report coverage: {}", err);
                return ExitCode::FAILURE;
            }
            return ExitCode::SUCCESS;
        }
        Commands::All { fuzzer_args } => {
            if let Err(err) = all(project, fuzzer_args) {
                log::error!("Failed to run all: {}", err);
                return ExitCode::FAILURE;
            }
            return ExitCode::SUCCESS;
        }
    };
    ExitCode::SUCCESS
}
