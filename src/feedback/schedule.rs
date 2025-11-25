use std::{collections::HashMap, collections::HashSet, f32::consts::E};

use petgraph::algo;

use crate::{
    deopt::Deopt, minimize, mutation::mutate_prompt, program::{
        gadget::{FuncGadget, get_func_gadget, get_func_gadgets},
        get_exec_counter_value, load_exec_counter,
        rand::{prob_coin, rand_comb_len, weighted_choose},
        set_exec_counter_value,
    }, request::prompt::{
        Prompt, get_prompt_counter_value, load_prompt_counter, set_prompt_counter_value
    }
};

pub struct Seed {
    name: String,
    coverage: f32,
    exec_count: u32,
    prompt_count: u32,
    energy: f32,
    sampling_weight: f32,
}

impl Seed {
    pub fn new(
        name: &str,
        coverage: f32,
        exec_count: u32,
        prompt_count: u32,
        exponent: u32,
    ) -> Self {
        let mut seed = Self {
            name: name.to_string(),
            coverage,
            exec_count,
            prompt_count,
            energy: 0_f32,
            sampling_weight: 0_f32,
        };
        seed.compute_energy(exponent);
        seed
    }
    pub fn new_for_api_mode(name: &str) -> Self {
        Self {
            name: name.to_string(),
            coverage: 0.0,   // In API mode, coverage is not used
            exec_count: 0,   // In API mode, exec_count is not used
            prompt_count: 0, // In API mode, prompt_count is not used
            energy: 1.0, // Assign a base energy value to all APIs to ensure they have a chance to be selected
            sampling_weight: 1_f32,
        }
    }
    pub fn compute_energy(&mut self, exponent: u32) -> f32 {
        let top: f32 = 1_f32 - self.coverage;
        let count = 1 + self.exec_count;
        let round = 1 + self.prompt_count;
        let bottom: f32 = ((count * round).pow(exponent)) as f32;
        let energy = top / bottom;
        self.energy = energy;
        energy
    }
}

fn sigmoid_function(succ_rate: f32, threshold: f32, steepness: f32) -> f32 {
    let exponent = steepness * (threshold - succ_rate);
    1.0 / (1.0 + E.powf(exponent))
}

fn should_deterministic_mutate(deopt: &Deopt) -> bool {
    let seed_num = deopt.seed_queue.len();
    let prob = seed_num as f32 / 100.0_f32;
    let prob = prob.min(0.8_f32);
    let coin = prob_coin(prob);
    log::info!(
        "Number of current unique seeds: {}, prob: {prob}, coin: {coin}",
        deopt.seed_queue.len()
    );
    coin
}

pub struct Schedule {
    seeds: HashMap<String, Seed>,
    exponent: u32,
    pub loop_count:u32
}

impl Default for Schedule {
    fn default() -> Self {
        Self::new()
    }
}

impl Schedule {
    pub fn new() -> Self {
        Self {
            seeds: HashMap::new(),
            exponent: 1,
            loop_count: 0,
        }
    }
    pub fn increment_loop(&mut self) {
        self.loop_count += 1;
    }
    pub fn get_seed_by_name(&self, name: &str) -> Option<&Seed> {
        self.seeds.get(name)
    }

    pub fn snyc_from_str(deopt: &Deopt) {
        let p_counter = load_prompt_counter(deopt);
        let e_counter = load_exec_counter(deopt);
        for (key, value) in e_counter {
            set_exec_counter_value(key, value);
        }
        for (key, value) in p_counter {
            set_prompt_counter_value(key, value);
        }
    }
    //initial the energies for API mode
    pub fn initialize_energies_for_api_mode(&mut self) {
        self.seeds.clear();
        for gadget in get_func_gadgets() {
            let api_name = gadget.get_func_name();
            let seed = Seed::new_for_api_mode(api_name);
            self.seeds.insert(api_name.to_string(), seed);
        }
    }
    // Compute the energy for each library API. The high energy means the high probablity to be choosed in prompt.
    pub fn update_energies(&mut self, api_coverage: &HashMap<String, f32>) {
        self.seeds.clear();
        for gadget in get_func_gadgets() {
            let api_name = gadget.get_func_name();
            let coverage = api_coverage.get(api_name).unwrap();
            let prompt_count = get_prompt_counter_value(api_name).unwrap_or(0);
            let exec_count = get_exec_counter_value(api_name).unwrap_or(0);
            let seed = Seed::new(api_name, *coverage, exec_count, prompt_count, self.exponent);
            self.seeds.insert(api_name.to_string(), seed);
        }
        let energies_str: Vec<f32> = self.seeds.values().map(|x| x.energy).collect();
        log::debug!(
            "energies: {}",
            serde_json::to_string(&energies_str).unwrap()
        );
    }
    pub fn energy_normalization_for_one_seed(&mut self, seed: &Seed)->f32  {
        let current_energy=seed.energy;
        let max_energy= self.seeds.values().map(|x| x.energy).fold(f32::MIN, f32::max);
        let min_energy= self.seeds.values().map(|x| x.energy).fold(f32::MAX, f32::min);
        let normalized_energy=(current_energy - min_energy)/(max_energy - min_energy);

        normalized_energy
    }
    pub fn energy_normalization(&mut self,epsilon:f32) {

        let max_energy = self.seeds.values().map(|x| x.energy).fold(f32::MIN, f32::max);
        let min_energy = self.seeds.values().map(|x| x.energy).fold(f32::MAX, f32::min);
        for seed in self.seeds.values_mut() {
            let current_energy = seed.energy;
            seed.sampling_weight = epsilon+(1_f32-epsilon)*(current_energy - min_energy) / (max_energy - min_energy);
        }
    }
    pub fn energy_condense(&mut self,num:f32) {
        for seed in self.seeds.values_mut() {
            seed.sampling_weight = seed.sampling_weight.powf(num);
        }

    }

    /// s_t = sigma_t / mu_t
    pub fn calculate_energy_skewness(&self) -> f32 {
        let n = self.seeds.len() as f32;
        if n == 0.0 {
            return 0.0; 
        }
        let sum_energy: f32 = self.seeds.values().map(|x| x.sampling_weight).sum();
        let mean = sum_energy / n;

        if mean == 0.0 {
            return 0.0; 
        }
        // (1/N) * sum((E - mu)^2)
        let variance = self.seeds.values()
            .map(|x| (x.sampling_weight - mean).powi(2)) 
            .sum::<f32>() / n;

        let std_dev = variance.sqrt();
        //  s_t = sigma_t / mu_t
        let s_t = std_dev / mean;

        s_t
    }
    pub fn calculate_alpha_t(alpha_min: f32, s_t: f32) -> f32 {
        alpha_min + (1.0 - alpha_min) * (-s_t).exp()
    }

    pub fn update_energies_from_api_pairs(&mut self, api_pairs: &HashSet<(String, String,String)>) {
        if api_pairs.is_empty() {
            log::warn!("No API pairs found to update energies.");
            return;
        }
        for (api1, api2,api3) in api_pairs {
            if let Some(seed) = self.seeds.get_mut(api1) {
                seed.energy += 1.0;
            
            }
            if let Some(seed) = self.seeds.get_mut(api2) {
                seed.energy += 1.0;
            }
            if let Some(seed) = self.seeds.get_mut(api3) {
                seed.energy += 1.0;
            }
        }
        log::debug!("Updated energies from API pairs: {}", api_pairs.len());
        let energies_str: Vec<f32> = self.seeds.values().map(|x| x.energy).collect();
        
        log::debug!(
            "energies: {}",
            serde_json::to_string(&energies_str).unwrap()
        );
        
        self.energy_normalization(0.01_f32);
        let s_t=self.calculate_energy_skewness();
        let alpha_t=Schedule::calculate_alpha_t(0.5_f32,s_t);
        self.energy_condense(alpha_t);
        let sample_str: Vec<f32> = self.seeds.values().map(|x| x.sampling_weight).collect();
        log::debug!(
            "sampling weights: {}",
            serde_json::to_string(&sample_str).unwrap()
        );
    }
    pub fn update_prompt(&self, prompt: &mut Prompt, deopt: &mut Deopt) -> eyre::Result<()> {
        if should_deterministic_mutate(deopt) {
            mutate_prompt(prompt, self, deopt);
        } else {
            let combination = self.assemble_high_energy_combiantion();
            prompt.set_combination(combination);
        }
        Ok(())
    }

    pub fn update_prompt_for_api_mode(&self, prompt: &mut Prompt) -> eyre::Result<()> {
        let combination = self.assemble_high_energy_combiantion();
        prompt.set_combination(combination);
        Ok(())
    }

    pub fn should_delete(&self, succ_rate: f32) -> bool {
        let threshold = 0.1_f32;
        let steepness = 10_f32;
        let delete_prob = 1_f32 - sigmoid_function(succ_rate, threshold, steepness);
        prob_coin(delete_prob)
    }

    pub fn should_shuffle(&self, succ: usize, total: usize) -> bool {
        // we expect per 20 programs should have a succ one.
        if succ == 0 && total >= 10 {
            return true;
        }
        if succ == 0 && total < 10 {
            return false;
        }
        if succ * 10 < total {
            return true;
        }
        false
    }

    pub fn assemble_high_energy_combiantion(&self) -> Vec<&'static FuncGadget> {
        log::info!("random assemble new prompt combination with their engies.");
        let len = rand_comb_len();
        let mut comb: Vec<&str> = Vec::new();
        let mut gadgets = Vec::new();
        while comb.len() < len {
            let api = self.choose_api_by_energy();
            if comb.contains(&api) {
                continue;
            }
            // 打印本次选中的API及其能量
            if let Some(seed) = self.seeds.get(api) {
                log::info!("choose api: {} energy: {}", api, seed.energy);
            }
            comb.push(api);
            let gadget =
                get_func_gadget(api).unwrap_or_else(|| panic!("cannot found api {api} in gadgets"));
            gadgets.push(gadget);
        }

        gadgets
    }

    pub fn choose_api_by_energy(&self) -> &str {
        let values: Vec<&Seed> = self.seeds.values().collect();
        let energies: Vec<f32> = values.iter().map(|x| x.sampling_weight).collect();
        let choose = weighted_choose(energies);
        let mut choose_seed = values[choose];
        
  
        let max_prob = 0.3_f32;
        let steepness = 0.1_f32; 
        let midpoint = 50.0_f32; 
        println!("loop count: {}", self.loop_count);
      //  let replace_with_lowest_prob = max_prob / (1.0 + E.powf(steepness * (self.loop_count as f32 - midpoint)));
        let replace_with_lowest_prob = 0_f32;
        
        if prob_coin(replace_with_lowest_prob) {
            let mut min_energy = f32::MAX;
            for seed in &values {
                if seed.energy < min_energy {
                    min_energy = seed.energy;
                    choose_seed = seed;
                }
            }
            log::info!("Loop {}: Replaced with lowest energy API: {} (energy: {}), prob: {:.4}", 
                    self.loop_count, choose_seed.name, choose_seed.energy, replace_with_lowest_prob);
        }
        &choose_seed.name
    }

    pub fn choose_low_energy_api(&self, combination: &Vec<String>) -> usize {
        let mut energies: Vec<f32> = Vec::new();
        for api_name in combination {
            let energy = self
                .seeds
                .get(api_name)
                .unwrap_or_else(|| panic!("no seed named {api_name} in Schedule"))
                .energy;
            energies.push(energy);
        }
        weighted_choose(energies)
    }
}

pub fn rand_choose_combination(len: usize) -> Vec<&'static FuncGadget> {
    let mut combination: Vec<&'static FuncGadget> = Vec::new();
    let func_gagdets = get_func_gadgets();
    while combination.len() < len {
        let idx: usize = rand::random::<usize>() % func_gagdets.len();
        let gadget = &func_gagdets[idx];
        if combination
            .iter()
            .any(|x| x.get_func_name() == gadget.get_func_name())
        {
            continue;
        }
        combination.push(gadget);
    }
    combination
}
