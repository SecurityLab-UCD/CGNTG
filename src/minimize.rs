use crate::{deopt::Deopt, feedback::observer::Observer, program::Program};
use eyre::Result;
use std::collections::HashSet;
use std::path::PathBuf;
fn extract_api_pairs_from_program(program: &Program) -> HashSet<(String, String)> {
    // This logic is borrowed from fuzzer.rs
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(tree_sitter_cpp::language())
        .expect("Failed to load C++ grammar");
    let tree = parser.parse(&program.statements, None).unwrap();
    let mut calls = Vec::new();
    extract_calls_recursive(tree.root_node(), &program.statements, &mut calls);
    calls
        .windows(2)
        .map(|w| (w[0].clone(), w[1].clone()))
        .collect()
}

// Helper for the helper
fn extract_calls_recursive(node: tree_sitter::Node, source: &str, calls: &mut Vec<String>) {
    if node.kind() == "call_expression" {
        if let Some(function_node) = node.child_by_field_name("function") {
            if let Ok(func_name) = function_node.utf8_text(source.as_bytes()) {
                calls.push(func_name.to_string());
            }
        }
    }
    for child in node.children(&mut node.walk()) {
        extract_calls_recursive(child, source, calls);
    }
}

/// Minimize seed programs by unique API pairs
pub fn minimize_by_api_pairs(deopt: &Deopt) -> Result<()> {
    let succ_seeds_dir = deopt.get_library_succ_seed_dir()?;
    let final_seeds_dir = deopt.get_library_seed_dir()?;

    // 1. Get all successful programs and the API pairs they contain.
    let mut programs_with_pairs: Vec<(PathBuf, HashSet<(String, String)>)> = Vec::new();
    for file in crate::deopt::utils::read_sort_dir(&succ_seeds_dir)? {
        let program = Program::load_from_path(&file)?;
        let pairs = extract_api_pairs_from_program(&program);
        if !pairs.is_empty() {
            programs_with_pairs.push((file, pairs));
        }
    }

    // 2. Sort programs by the number of pairs they have, descending.
    programs_with_pairs.sort_by(|a, b| b.1.len().cmp(&a.1.len()));

    // 3. Greedily select programs that cover new API pairs.
    let mut covered_pairs: HashSet<(String, String)> = HashSet::new();
    let mut final_seeds = Vec::new();

    for (program_path, pairs) in programs_with_pairs {
        // Check if this program adds any new pair
        if pairs.iter().any(|p| !covered_pairs.contains(p)) {
            final_seeds.push(program_path);
            for pair in pairs {
                covered_pairs.insert(pair);
            }
        }
    }

    // 4. Clean up the old seed directory and copy the new minimized set.
    if final_seeds_dir.exists() {
        std::fs::remove_dir_all(&final_seeds_dir)?;
    }
    std::fs::create_dir_all(&final_seeds_dir)?;
    let num = final_seeds.len();
    for seed_path in final_seeds {
        let dest_path = final_seeds_dir.join(seed_path.file_name().unwrap());
        std::fs::copy(&seed_path, &dest_path)?;
        log::info!("Kept unique API seed: {:?}", dest_path);
    }

    log::info!(
        "Minimized seeds by API pairs. Kept {} seeds covering {} unique pairs.",
        num,
        covered_pairs.len()
    );

    Ok(())
}

/// Minimize seed programs by unique branches
pub fn minimize(deopt: &Deopt) -> Result<()> {
    let seeds_dir = deopt.get_library_succ_seed_dir()?;
    // first sort seeds by coverge.
    let mut program_coverage: Vec<(PathBuf, f32)> = Vec::new();
    for file in crate::deopt::utils::read_sort_dir(&seeds_dir)? {
        let program = Program::load_from_path(&file)?;
        let coverage_rate = Observer::compute_coverage_for_program(program.id, deopt)?;
        program_coverage.push((file, coverage_rate));
    }
    program_coverage.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

    // iterate the sorted seeds, only the seeds still triger unique branch(s) are retained.
    let mut observer = Observer::new(deopt);
    for (program_path, _) in program_coverage {
        let program = Program::load_from_path(&program_path)?;
        let seed = deopt.get_seed_path_by_id(program.id)?;
        let coverage = deopt.get_seed_coverage(program.id)?;
        let unique_branches = observer.has_unique_branch(&coverage);
        if unique_branches.is_empty() {
            if seed.exists() {
                log::info!(
                    "Program Seed triggers no unique branch and has been removed: {program_path:?}"
                );
                std::fs::remove_file(seed)?;
            }
            continue;
        }
        log::info!("{program_path:?} is an unique seed");
        if !seed.exists() {
            std::fs::copy(program_path, seed)?;
        }
        let new_exp_branches = observer.has_new_branch(&coverage);
        observer.merge_new_branch(&new_exp_branches);
    }

    log::info!("{}", observer.dump_global_states());
    Ok(())
}
