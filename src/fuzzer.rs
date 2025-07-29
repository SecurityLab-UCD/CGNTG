use crate::{
    config::{self, get_config, get_handler_type, get_library_name, HandlerType},
    deopt::Deopt,
    execution::{
        logger::{init_gtl, ProgramLogger},
        Executor,
    },
    feedback::{
        observer::Observer,
        schedule::{rand_choose_combination, Schedule},
    },
    minimize::minimize,
    program::{ libfuzzer::LibFuzzer, rand::rand_comb_len, serde::Deserializer, Program},
    request::{
        self,
        prompt::{Prompt},
    },
};
use tree_sitter::{Parser, TreeCursor};

use eyre::Result;
use std::collections::{ HashSet};

use std::io::{ Write};
pub struct Fuzzer {
    pub deopt: Deopt,
    pub executor: Executor,
    pub observer: Observer,
    schedule: Schedule,
    /// LLM model handler
    handler: Box<dyn request::Handler>,
    pub quiet_round: usize,
}

impl Fuzzer {
    /// create a new fuzzer
    pub fn new() -> Result<Self> {
        let deopt = Deopt::new(get_library_name())?;
        let executor = Executor::new(&deopt)?;
        let observer = Observer::new(&deopt);
        // 根据配置选择handler类型
        let handler: Box<dyn request::Handler> = match get_handler_type() {
            HandlerType::Openai => {
                log::info!("Using OpenAI handler");
                Box::<request::openai::OpenAIHanler>::default()
            }
            HandlerType::Http => {
                log::info!("Using HTTP handler");
                Box::new(request::http::HttpHandler::new().unwrap())
            }
        };

        init_gtl();
        let fuzzer = Self {
            deopt,
            executor,
            observer,
            schedule: Schedule::new(),
            handler,
            quiet_round: 0,
        };
        Ok(fuzzer)
    }

    fn sync_quiet_round(&mut self, content: &str) -> Result<()> {
        if let Some(idx) = content.find("[Mutate Loop]: loop:") {
            let mut de = Deserializer::from_input(&content[idx..]);
            de.consume_token_until("quiet_round:")?;
            let quiet_round = de.parse_number::<usize>()?;
            self.quiet_round = quiet_round;
        }
        Ok(())
    }

    // When the execution stopped or crashed by internal's bugs, sync from the previous state.
    pub fn sync_from_previous_state(&mut self, logger: &mut ProgramLogger) -> Result<()> {
        let mut is_the_last = false;
        for file in crate::deopt::utils::read_sort_dir(&self.deopt.get_library_output_dir()?)?
            .iter()
            .rev()
        {
            if file.is_dir() {
                continue;
            }
            if let Some(ext) = file.extension() {
                if ext == "log" {
                    if !is_the_last {
                        is_the_last = true;
                        continue;
                    }
                    log::info!("Find a previous exection: {file:?}");
                    log::info!("Restore the states from the previous execution!");
                    let log_str = std::fs::read_to_string(file)?;
                    let sync_logger = ProgramLogger::snyc_from_str(&log_str)?;
                    self.deopt.seed_id = sync_logger.get_gc_total();
                    _ = std::mem::replace(logger, sync_logger);
                    let observer = Observer::sync_from_previous(&mut self.deopt)?;
                    _ = std::mem::replace(&mut self.observer, observer);
                    Schedule::snyc_from_str(&self.deopt);
                    self.sync_quiet_round(&log_str)?;
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    pub fn transform_seeds_to_fuzzers(&self) -> Result<()> {
        let programs = crate::deopt::utils::read_sort_dir(&self.deopt.get_library_seed_dir()?)?;
        let core = get_config().cores;
        let fuzzer_size = programs.len();
        let mut libfuzzer = LibFuzzer::new(
            programs.clone(),
            fuzzer_size,
            core,
            self.deopt.clone(),
            false,
        );
        libfuzzer.transform()?;
        libfuzzer.synthesis()?;
        libfuzzer.compile()?;
        let mut libfuzzer = LibFuzzer::new(programs, fuzzer_size, core, self.deopt.clone(), true);
        libfuzzer.transform()?;
        libfuzzer.synthesis()?;
        libfuzzer.compile()?;
        Ok(())
    }

    pub fn generate_until_n_success(
        &mut self,
        prompt: &mut Prompt,
        logger: &mut ProgramLogger,
    ) -> Result<Vec<Program>> {
        log::trace!(
            "Generate until {} sucess programs",
            get_config().fuzz_round_succ
        );
        let mut succ_programs = Vec::new();

        while succ_programs.len() < get_config().fuzz_round_succ {
            let mut programs = self.handler.generate(prompt)?;
            for program in &mut programs {
                program.id = self.deopt.inc_seed_id();
            }

            log::debug!(
                "LLM generated {} programs. Sanitize those programs!",
                programs.len()
            );
            let check_res = self
                .executor
                .check_programs_are_correct(&programs, &self.deopt)?;
            // Check each generated programs, and save thems according where they contains errors.
            for (i, program) in programs.iter().enumerate() {
                let has_err = check_res
                    .get(i)
                    .unwrap_or_else(|| panic!("cannot obtain check_res at `{i}`"));
                // save as error programs
                if let Some(err_msg) = has_err {
                    self.deopt.save_err_program(program, err_msg)?;
                    logger.log_err(err_msg);
                } else {
                    succ_programs.push(program.clone());
                    logger.log_succ();
                }
            }
            logger.print_succ_round();
            // if the combiantion continusely failed in a long time, shuffle the prompt to escape the bad combination;
            if self
                .schedule
                .should_shuffle(logger.get_rc_succ(), logger.get_rc_total())
            {
                log::info!("Fuzzer stuck in the current prompt, choose a new one.");
                break;
            }
        }
        
        Ok(succ_programs)
    }
    pub fn generate_and_validate_api_sequences(
        &mut self,
        prompt: &mut Prompt,
        logger: &mut ProgramLogger,
    ) -> Result<Vec<Program>> {
        log::trace!(
            "Generate until {} sucess programs",
            get_config().fuzz_round_succ
        );
        let mut succ_programs = Vec::new();

        while succ_programs.len() < get_config().fuzz_round_succ {
            let mut programs = self.handler.generate(prompt)?;
            for program in &mut programs {
                program.id = self.deopt.inc_seed_id();
            }
            log::debug!(
                "LLM generated {} programs. Sanitize those programs!",
                programs.len()
            );
            for program in programs {
                let error = self.executor.validate_api_sequence(&program, &self.deopt)?;
                if let Some(err) = error {
                    self.deopt.save_err_program(&program, &err)?;
                    logger.log_err(&err);
                } else {
                    succ_programs.push(program);
                    logger.log_succ();
                }
            }
            logger.print_succ_round();
            if self
                .schedule
                .should_shuffle(logger.get_rc_succ(), logger.get_rc_total())
            {
                log::info!("Fuzzer stuck in the current prompt, choose a new one.");
                break;
            }
        }

        Ok(succ_programs)
    }
    fn extract_calls_recursive(source: &str, cursor: &mut TreeCursor, calls: &mut Vec<String>) {
        let node = cursor.node();

        if node.kind() == "call_expression" {
            if let Some(function_node) = node.child_by_field_name("function") {
                let func_name = function_node
                    .utf8_text(source.as_bytes())
                    .unwrap()
                    .to_string();
                calls.push(func_name);
            }
        }

        if cursor.goto_first_child() {
            Self::extract_calls_recursive(source, cursor, calls);
            while cursor.goto_next_sibling() {
                Self::extract_calls_recursive(source, cursor, calls);
            }
            cursor.goto_parent();
        }
    }
    fn extract_function_calls(source: &str) -> Vec<String> {
        let mut parser = Parser::new();
        parser
            .set_language(tree_sitter_cpp::language())
            .expect("Failed to load C++ grammar");

        let tree = parser.parse(source, None).expect("Failed to parse code");
        let root_node = tree.root_node();

        let mut calls = Vec::new();
        let mut cursor = root_node.walk();
        Self::extract_calls_recursive(source, &mut cursor, &mut calls);
        calls
    }

    fn extract_2gram_pairs(calls: &[String]) -> Vec<(String, String)> {
        calls
            .windows(2)
            .filter_map(|w| {
                if let [a, b] = &w {
                    Some((a.clone(), b.clone()))
                } else {
                    None
                }
            })
            .collect()
    }
    fn mutate_prompt(&mut self, prompt: &mut Prompt) -> Result<()> {
        let api_coverage = self.observer.compute_library_api_coverage()?;
        self.schedule.update_energies(api_coverage);
        self.schedule.update_prompt(prompt, &mut self.deopt)?;
        Ok(())
    }

    pub fn is_converge(&self) -> bool {
        if self.quiet_round >= get_config().fuzz_converge_round {
            return true;
        }
        false
    }

    pub fn is_stuck(&self, len: usize) -> bool {
        len == 0
    }

    pub fn should_recheck(&self) -> bool {
        if self.quiet_round >= get_config().fuzz_converge_round / 2 && get_config().recheck {
            return true;
        }
        false
    }
    // pub fn  extract_api_pairs(&self, program: &Program) -> Result<Vec<(String, String)>> {
    //     let string= program.statements.clone();
    // }

    pub fn fuzz_loop(&mut self) -> Result<()> {
        let mut logger = ProgramLogger::default();
        let initial_combination = rand_choose_combination(rand_comb_len());
        // let mut prompt = if let Some(prompt) = load_prompt(&self.deopt) {
        //     prompt
        // } else {
        //     Prompt::from_combination(initial_combination)
        // };
        for a in initial_combination.iter() {
            log::debug!("Initial combination: {}", a.name);
        }
        let mut prompt = Prompt::from_combination(initial_combination);
        let mut loop_cnt = 0;
        let mut has_checked = false;

       // self.sync_from_previous_state(&mut logger)?;

        if get_config().generation_mode == config::GenerationModeP::FuzzDriver {
            log::info!("Using FuzzDriver mode, initial prompt: {prompt:?}");
            loop {
                if self.is_converge() {
                    break;
                }
                let programs = self.generate_until_n_success(&mut prompt, &mut logger)?;
                let is_stuck = self.is_stuck(programs.len());
                let mut has_new = false;
                for mut program in programs {
                    self.deopt.save_succ_program(&program)?;
                    let coverage = self.deopt.get_seed_coverage(program.id)?;
                    let unique_branches = self.observer.has_unique_branch(&coverage);
                    has_new = !unique_branches.is_empty();
                    program.update_quality(unique_branches, &self.deopt)?;
                    self.deopt.update_seed_queue(program, &coverage, has_new)?;
                    self.observer.merge_coverage(&coverage);
                }
                if !get_config().disable_power_schedule {
                    self.mutate_prompt(&mut prompt)?;
                } else {
                    let new_comb = rand_choose_combination(config::DEFAULT_COMB_LEN);
                    prompt = Prompt::from_combination(new_comb);
                }

                if has_new {
                    self.quiet_round = 0;
                } else if !is_stuck {
                    self.quiet_round += 1;
                }
                // As the corpus is also evolved, we recheck the seeds on the evolved corpus to eliminate the error programs that was not catched before.
                if self.should_recheck() && !has_checked {
                    self.executor.recheck_seed(&mut self.deopt)?;
                    self.observer.recompute_global_coverage()?;
                    self.deopt.load_programs_from_seeds()?;
                    has_checked = true;
                    self.quiet_round = 0;
                    crate::mutation::prompt_shuffle(&mut prompt);
                }
                loop_cnt += 1;
                logger.reset_round();
                log::info!(
                    "[Mutate Loop]: loop: {loop_cnt}, quiet_round: {}, {}",
                    self.quiet_round,
                    self.observer.dump_global_states()
                );
            }
        } else if get_config().generation_mode == config::GenerationModeP::ApiCombination {
            //    log::info!("Using api combination mode, initial prompt: {prompt:?}");
            self.schedule.initialize_energies_for_api_mode();
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open("output111.txt")?;
            loop {
                if self.is_converge() {
                    break;
                }
                let programs =
                    self.generate_and_validate_api_sequences(&mut prompt, &mut logger)?;
            
                
                if programs.is_empty() {
                    log::debug!("No programs generated successfully, continue to next round.");
                    self.schedule.update_prompt_for_api_mode(&mut prompt)?;
                    loop_cnt += 1;
                    continue;
                }
                let program_len = programs.len();
                log::debug!(
                    "LLM generated {} successful programs. Sanitize those programs!",
                    program_len
                );
                //  下面都是跑的
                let is_stuck = self.is_stuck(programs.len());
                let mut round_newly_discovered_pairs: HashSet<(String, String)> = HashSet::new();

                for program in programs {
                    self.deopt.save_succ_program(&program)?;
                    println!("Program ID: {}", program.id);
                    let cpp_code = &program.statements;
                    let calls = Self::extract_function_calls(cpp_code);
                    let pairs = Self::extract_2gram_pairs(&calls);

                    let mut discovered_pairs_guard =
                        self.observer.discovered_api_pairs.write().unwrap();
                    for pair in pairs {
                        // log::debug!("Discovered API pair: {:?}", pair);
                        if discovered_pairs_guard.insert(pair.clone()) {
                            writeln!(file, "{:?}", pair)?;
                            round_newly_discovered_pairs.insert(pair);
                        }
                    }
                }

                let has_new_in_round = !round_newly_discovered_pairs.is_empty();
                if has_new_in_round {
                    self.quiet_round = 0;
                    log::debug!(
                        "Discovered {} new API pairs in this round.",
                        round_newly_discovered_pairs.len()
                    );
                    self.schedule
                        .update_energies_from_api_pairs(&round_newly_discovered_pairs);
                } else if !is_stuck {
                    self.quiet_round += 1;
                }
                self.schedule.update_prompt_for_api_mode(&mut prompt)?;
                loop_cnt += 1;
                logger.reset_round();
                log::info!(
                    "[Mutate Loop]: loop: {loop_cnt}, quiet_round: {}, discovered_api_pairs: {}",
                    self.quiet_round,
                    self.observer.discovered_api_pairs.read().unwrap().len()
                );
                if round_newly_discovered_pairs.len() < 1 && program_len != 0 {
                    break;
                }
            }
        }
        log::info!("Fuzzing loop finished. Starting minimization...");

        match get_config().generation_mode {
            config::GenerationModeP::FuzzDriver => {
                log::info!("Minimizing corpus by branch coverage...");
                minimize(&self.deopt)?;
            }
            config::GenerationModeP::ApiCombination => {
                log::info!("Minimizing corpus by unique API pairs...");
                // We need to import the new function
                use crate::minimize::minimize_by_api_pairs;
                minimize_by_api_pairs(&self.deopt)?;
            }
        }

        log::info!("Minimization complete!");
        Ok(())
    }

    pub fn fuzzer_run(&self) -> Result<()> {
        self.transform_seeds_to_fuzzers()?;
        self.executor.run_libfuzzer(false, None, None)?;
        self.executor.run_libfuzzer(true, None, None)?;
        Ok(())
    }
}

impl Drop for Fuzzer {
    fn drop(&mut self) {
        log::info!("Config: {:#?}", get_config());
    }
}
