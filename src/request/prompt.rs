use crate::config::Config;
use crate::execution::logger::ProgramError;
use async_openai::types::{
    ChatCompletionRequestMessage, ChatCompletionRequestSystemMessageArgs,
    ChatCompletionRequestUserMessageArgs,
};
use once_cell::sync::OnceCell;
use std::collections::VecDeque;
use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
    path::PathBuf,
    sync::RwLock,
};
#[derive(Debug, Clone)]
pub enum ProgramTask {
    Generate,
    Repair {
        failed_code: String,
        error: ProgramError,
    },
}
#[derive(Clone, Debug)]
pub struct Prompt {
    pub gadgets: Vec<&'static FuncGadget>,
    pub successful_examples: VecDeque<String>,
    pub task: ProgramTask,
}

impl Prompt {
    pub fn new(gadgets: Vec<&'static FuncGadget>) -> Self {
        Self {
            gadgets,
            successful_examples: VecDeque::new(),
            task: ProgramTask::Generate,
        }
    }
    pub fn set_repair_task(&mut self, failed_code: String, error: ProgramError) {
        self.task = ProgramTask::Repair {
            failed_code: (failed_code),
            error: (error),
        }
    }

    pub fn set_generate_task(&mut self) {
        self.task = ProgramTask::Generate;
    }
}

impl Display for Prompt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.serialize())
    }
}

static COUNTER: OnceCell<RwLock<HashMap<String, u32>>> = OnceCell::new();

// Count the times of functions have been prompted.
pub fn get_prompt_counter_value(key: &str) -> Option<u32> {
    let guard = COUNTER
        .get_or_init(|| RwLock::new(HashMap::new()))
        .read()
        .unwrap();
    guard.get(key).copied()
}

pub fn set_prompt_counter_value(key: String, value: u32) {
    let mut guard = COUNTER
        .get_or_init(|| RwLock::new(HashMap::new()))
        .write()
        .unwrap();
    guard.insert(key, value);
}

pub fn save_prompt_counter() {
    let deopt = Deopt::new(get_library_name()).unwrap();
    let counter_path: PathBuf = [
        deopt.get_library_misc_dir().unwrap(),
        "prompt_counter.json".into(),
    ]
    .iter()
    .collect();
    let guard = COUNTER
        .get_or_init(|| RwLock::new(HashMap::new()))
        .read()
        .unwrap();
    let json = serde_json::to_string(&*guard).unwrap();
    std::fs::write(counter_path, json).unwrap();
}

pub fn load_prompt_counter(deopt: &Deopt) -> HashMap<String, u32> {
    let counter_path: PathBuf = [
        deopt.get_library_misc_dir().unwrap(),
        "prompt_counter.json".into(),
    ]
    .iter()
    .collect();
    let content = std::fs::read_to_string(counter_path).unwrap();
    let counter: HashMap<String, u32> = serde_json::from_str(&content).unwrap();
    counter
}

pub fn update_prompt_counter(combination: &Vec<&FuncGadget>) {
    for func in combination {
        let func_name = func.get_func_name();
        let count = get_prompt_counter_value(func_name).unwrap_or(0);
        set_prompt_counter_value(func_name.to_string(), count + 1);
        save_prompt_counter();
    }
}

impl Prompt {
    /// Format the generative style prompt
    pub fn from_combination(combination: Vec<&'static FuncGadget>) -> Self {
        update_prompt_counter(&combination);
        save_prompt(&combination);
        log::info!("selected combination: {}", combination_to_str(&combination));
        Prompt::new(combination)
    }

    pub fn set_combination(&mut self, combination: Vec<&'static FuncGadget>) {
        log::info!("set combination: {}", combination_to_str(&combination));
        save_prompt(&combination);
        update_prompt_counter(&combination);
        self.gadgets = combination
    }
    pub fn add_successful_example(&mut self, example_code: String) {
        const MAX_EXAMPLES: usize = 2;
        if self.successful_examples.len() >= MAX_EXAMPLES {
            // 移除最旧的样例 (FIFO)
            self.successful_examples.pop_front();
        }
        // 在末尾加入最新的样例
        self.successful_examples.push_back(example_code);
    }

    /// from generative prompt to API combination vec.
    pub fn get_combination(&self) -> eyre::Result<Vec<&'static FuncGadget>> {
        Ok(self.gadgets.clone())
    }

    pub fn get_combination_mut(&mut self) -> &mut Vec<&'static FuncGadget> {
        &mut self.gadgets
    }

    /// format to chat kind prompt.
    pub fn to_chatgpt_message(&self) -> Vec<ChatCompletionRequestMessage> {
        let config = config::get_config();
        let ctx = get_combination_definitions(&self.gadgets);

        if config.generation_mode == config::GenerationModeP::FuzzDriver {
            log::debug!("Using FuzzDriver generation mode");
            let sys_msg = get_sys_gen_message(ctx, &config);
            log::trace!("System role: {sys_msg}");
            let user_msg = config::get_user_chat_template()
                .replace("{combinations}", &combination_to_str(&self.gadgets));
            let sys_msg = ChatCompletionRequestSystemMessageArgs::default()
                .content(sys_msg)
                .build()
                .unwrap()
                .into();
            let user_msg = ChatCompletionRequestUserMessageArgs::default()
                .content(user_msg)
                .build()
                .unwrap()
                .into();
            vec![sys_msg, user_msg]
        } else {
            log::debug!("Using ApiCombination generation mode");
            let sys_msg = get_sys_gen_message(ctx, &config);
            // 也使用带上下文的消息
            let user_msg_content = match &self.task {
                &ProgramTask::Generate => {
                    let successful_examples = if !self.successful_examples.is_empty() {
                        let examples_code = self
                            .successful_examples
                            .iter()
                            .cloned()
                            .collect::<Vec<String>>()
                            .join("\n\n---\n\n");
                        format!(
                            "Here are some successful examples:\n```cpp\n{}\n```",
                            examples_code
                        )
                    } else {
                        String::new()
                    };

                    config::get_user_gen_template()
                        .replace("{combinations}", &combination_to_str(&self.gadgets))
                        .replace("{successful_examples}", &successful_examples)
                }

                ProgramTask::Repair { failed_code, error } => {
                    let (error_type_str, error_details_str) = match error {
                        ProgramError::Syntax(e) => ("Syntax Error", e.clone()),
                        ProgramError::Link(e) => ("Link Error", e.clone()),
                        ProgramError::Execute(e) => ("Execution Error", e.clone()),
                        ProgramError::Hang(e) => ("Execution Hang", e.clone()),
                        _ => ("Other Error", error.to_string()),
                    };

                    // 使用您在 config.rs 中定义的模板
                    config::ERROR_REPAIR_TEMPLATE
                        .replace("{error_code}", failed_code)
                        .replace("{error_type}", error_type_str)
                        .replace("{error_details}", &error_details_str)
                }
            };
            log::debug!("user Prompt:{:?}", user_msg_content);
            // let user_msg = config::get_user_gen_template()
            //     .replace("{combinations}", &combination_to_str(&self.gadgets))
            //     .replace("{successful_examples}", &successful_examples); // **注入样例**
            //log::debug!("user Prompt:{:?}", user_msg);
            let sys_msg = ChatCompletionRequestSystemMessageArgs::default()
                .content(sys_msg)
                .build()
                .unwrap()
                .into();
            let user_msg = ChatCompletionRequestUserMessageArgs::default()
                .content(user_msg_content)
                .build()
                .unwrap()
                .into();
            vec![sys_msg, user_msg]
        }
    }
}

/// get the message of the system role for generative tasks.
pub fn get_sys_gen_message(ctx: String, config: &Config) -> String {
    let deopt = Deopt::new(get_library_name()).unwrap();
    let mode = config.generation_mode.clone();
    let mut template = match mode {
        config::GenerationModeP::FuzzDriver => config::SYSTEM_GEN_TEMPLATE.to_string(),
        config::GenerationModeP::ApiCombination => config::SYSTEM_API_TEMPLATE.to_string(),
    };
    let mut ctx_template =
        config::SYSTEM_CONTEXT_TEMPLATE.replace("{project}", &get_library_name());
    if let Some(desc) = deopt.config.desc {
        ctx_template.insert_str(0, &desc);
    }
    let ctx_template = ctx_template.replace("{headers}", &get_include_sys_headers_str());
    let ctx_template = ctx_template.replace("{APIs}", &dump_func_gadgets_tostr());
    let ctx_template = ctx_template.replace("{context}", &ctx);
    template.push_str("\n\n");
    template.push_str(&ctx_template);
    template
}

/// get the type definitions in args of the apis of the combination.
fn get_combination_definitions(combination: &Vec<&FuncGadget>) -> String {
    let mut context = Vec::new();
    let mut unique_tys = HashSet::new();
    for func in combination {
        for arg in func.get_alias_arg_types() {
            unique_tys.insert(get_unsugared_unqualified_type(arg));
        }
        unique_tys.insert(get_unsugared_unqualified_type(func.get_alias_ret_type()));
    }
    // insert the force types
    let deopt = crate::deopt::Deopt::new(get_library_name()).unwrap();
    if let Some(force_types) = &deopt.config.force_types {
        for ty in force_types {
            unique_tys.insert(ty.to_string());
        }
    }

    let mut visited: HashSet<String> = HashSet::new();
    for ty in unique_tys {
        if let Some(def) = get_type_definition(&ty, &mut visited) {
            context.push(def);
        }
    }
    context.join("\n\n")
}

pub fn combination_to_str(combination: &Vec<&FuncGadget>) -> String {
    let mut signatures = Vec::new();
    for func in combination {
        signatures.push(func.gen_signature());
    }
    signatures.join(",\n    ")
}

pub fn save_prompt(combination: &[&FuncGadget]) {
    let funcs: Vec<String> = combination
        .iter()
        .map(|x| x.get_func_name().to_string())
        .collect();
    let deopt = Deopt::new(get_library_name()).unwrap();
    let counter_path: PathBuf = [deopt.get_library_misc_dir().unwrap(), "prompt.json".into()]
        .iter()
        .collect();
    std::fs::write(counter_path, serde_json::to_string(&funcs).unwrap()).unwrap();
}

pub fn load_prompt(deopt: &Deopt) -> Option<Prompt> {
    let counter_path: PathBuf = [deopt.get_library_misc_dir().unwrap(), "prompt.json".into()]
        .iter()
        .collect();
    if counter_path.exists() {
        log::debug!("Loading prompt from the previous execution");
        let content = std::fs::read_to_string(counter_path).unwrap();
        let funcs: Vec<String> = serde_json::from_str(&content).unwrap();
        let combination: Vec<&FuncGadget> =
            funcs.iter().map(|x| get_func_gadget(x).unwrap()).collect();
        let prompt = Prompt::from_combination(combination);
        return Some(prompt);
    }
    None
}

use crate::{
    analysis::header::get_include_sys_headers_str,
    config::{self, get_library_name},
    deopt::Deopt,
    program::{
        gadget::{
            ctype::get_unsugared_unqualified_type, dump_func_gadgets_tostr, get_func_gadget,
            typed_gadget::get_type_definition, FuncGadget,
        },
        serde::Serialize,
    },
};
impl Serialize for Prompt {
    fn serialize(&self) -> String {
        combination_to_str(&self.gadgets)
    }
}
