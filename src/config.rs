use std::sync::{RwLock, RwLockReadGuard};

use once_cell::sync::OnceCell;

pub const CONNECT_TIMEOUT: u64 = 1;

// LLM Service Interface configure options
pub static OPENAI_MODEL_NAME: OnceCell<String> = OnceCell::new();

pub static OPENAI_CONTEXT_LIMIT: OnceCell<Option<u32>> = OnceCell::new();

pub static OPENAI_PROXY_BASE: OnceCell<Option<String>> = OnceCell::new();

// General model configure options.
pub const MUTATE_LINE: usize = 3;

pub const MAX_TOKENS: u16 = 2048_u16;

pub const MAX_INST_TOKENS: u16 = 256_u16;

pub const MUTATE_SEED_ROUND: u8 = 0;

pub const RETRY_N: u8 = 5;

pub const MAX_SAMPLE_LEN: usize = 20;

pub const DEFAULT_COMB_LEN: usize = 5;

pub static CONFIG_INSTANCE: OnceCell<RwLock<Config>> = OnceCell::new();

pub const FDP_PATH: &str = "src/extern";

// Program check options
pub const EXECUTION_TIMEOUT: u64 = 180;

pub const SANITIZATION_TIMEOUT: u64 = 1200;

pub const MIN_FUZZ_TIME: u64 = 60;

pub const MAX_FUZZ_TIME: u64 = 600;

pub const MAX_CONTEXT_APIS: usize = 100;
// recover the report of UBSan, or we can use UBSAN_OPTIONS=symbolize=1:print_stacktrace=1:halt_on_error=1 instead.
pub const SANITIZER_FLAGS: [&str; 7] = [
    "-fsanitize=fuzzer",
    "-g",
    "-O1",
    "-fsanitize=address,undefined",
    "-ftrivial-auto-var-init=zero",
    "-fsanitize-trap=undefined",
    "-fno-sanitize-recover=undefined",
];

pub const FUZZER_FLAGS: [&str; 5] = [
    "-fsanitize=fuzzer",
    "-O1",
    "-g",
    "-fsanitize=address,undefined",
    "-ftrivial-auto-var-init=zero",
];
pub const NORMAL_FLAGS: &[&str] = &[];
pub const COVERAGE_FLAGS: [&str; 9] = [
    "-g",
    "-fsanitize=fuzzer",
    "-fprofile-instr-generate",
    "-fcoverage-mapping",
    "-Wl,--no-as-needed",
    "-Wl,-ldl",
    "-Wl,-lm",
    "-Wno-unused-command-line-argument",
    "-ftrivial-auto-var-init=zero",
];
pub const COVERAGE_FLAGS_NO_FUZZ: [&str; 8] = [
    "-g",
    "-fprofile-instr-generate",
    "-fcoverage-mapping",
    "-Wl,--no-as-needed",
    "-Wl,-ldl",
    "-Wl,-lm",
    "-Wno-unused-command-line-argument",
    "-ftrivial-auto-var-init=zero",
];
#[derive(Debug, Clone, PartialEq, ValueEnum)]
pub enum GenerationModeP {
    //Generate a fuzz driver
    FuzzDriver,
    //Generate API combinations
    ApiCombination,
}

pub const ASAN_OPTIONS: [&str; 2] = ["exitcode=168", "alloc_dealloc_mismatch=0"];

pub fn get_openai_model_name() -> String {
    OPENAI_MODEL_NAME.get().unwrap().to_string()
}

pub fn get_openai_context_limit() -> &'static Option<u32> {
    OPENAI_CONTEXT_LIMIT.get().unwrap()
}

pub fn get_openai_proxy() -> &'static Option<String> {
    OPENAI_PROXY_BASE.get().unwrap()
}

pub fn init_openai_env() {
    let model =
        std::env::var("OPENAI_MODEL_NAME").unwrap_or_else(|_| panic!("OPENAI_MODEL_NAME not set"));

    let context_limit = std::env::var("OPENAI_CONTEXT_LIMIT")
        .ok()
        .and_then(|s| s.parse::<u32>().ok());

    let proxy_base = std::env::var("OPENAI_PROXY_BASE")
        .ok()
        .and_then(|s| s.parse::<String>().ok());

    OPENAI_MODEL_NAME.set(model).unwrap();
    OPENAI_CONTEXT_LIMIT.set(context_limit).unwrap();
    OPENAI_PROXY_BASE.set(proxy_base).unwrap();
}

pub fn get_config() -> RwLockReadGuard<'static, Config> {
    CONFIG_INSTANCE.get().unwrap().read().unwrap()
}

pub fn get_library_name() -> String {
    let config = CONFIG_INSTANCE.get().unwrap().read().unwrap();
    let target = config.target.clone();
    target
}

pub fn get_sample_num() -> u8 {
    let config = CONFIG_INSTANCE.get().unwrap().read().unwrap();
    config.n_sample
}

pub fn get_handler_type() -> HandlerType {
    let config = CONFIG_INSTANCE.get().unwrap().read().unwrap();
    config.handler_type.clone()
}

pub fn get_minimize_compile_flag() -> &'static str {
    static MIN_FLAG: OnceCell<String> = OnceCell::new();
    MIN_FLAG.get_or_init(|| {
        let mut minimize_flag: String = "-fsanitize-coverage-ignorelist=".into();
        let bl_file = Deopt::get_coverage_bl_file_name().unwrap();
        minimize_flag.push_str(&bl_file);
        minimize_flag
    })
}
pub fn parse_config() -> eyre::Result<()> {
    let config = Config::parse();
    CONFIG_INSTANCE.set(RwLock::new(config)).unwrap();
    let deopt = Deopt::new(get_library_name())?;
    let data = deopt.get_library_data_dir()?;
    if !data.exists() {
        eyre::bail!(
            "Cannot find the entry {} in `data` dir, please prepare it in anvance.",
            deopt.config.project_name
        );
    }
    let lib = deopt.get_library_build_lib_path()?;
    if !lib.exists() {
        eyre::bail!("Cannot find the build library {} in `output/build` dir, please build it by build.sh in anvance.", deopt.config.project_name);
    }
    Ok(())
}

use clap::{Parser, ValueEnum};

use crate::Deopt;

/// Handler类型选择
#[derive(Debug, Clone, ValueEnum, PartialEq)]
pub enum HandlerType {
    /// 使用OpenAI官方客户端
    Openai,
    /// 使用HTTP客户端
    Http,
}
/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author="Anonymous", name = "LLMFuzzer", version, about="A LLM based Fuzer", long_about = None)]
pub struct Config {
    //which generation mode to use
    #[arg(long = "gen-mode", default_value = "api-combination", value_enum)]
    pub generation_mode: GenerationModeP,
    /// The target project you decide to fuzz. Available: ["cJSON", "c-ares", "libvpx", "libaom", "libpng", "cre2", "curl", "lcms", "libjpeg-turbo", "libmagic", "libtiff", "sqlite3", "zlib", "libpcap"]
    pub target: String,
    /// Sample N outputs per LLM's request, max: 128
    #[arg(short, long, default_value = "10")]
    pub n_sample: u8,
    /// Sampling temperature. Higher values means the model will take more risks. Try 1 for more creative applications, and 0 (argmax sampling) for ones with a well-defined answer.
    #[arg(short, long, default_value = "1")]
    pub temperature: f32,
    /// whether use the power schedule to mutate prompt. true for purly random mutation of prompt.
    #[arg(short, long, default_value = "false")]
    pub disable_power_schedule: bool,
    /// The number of successful programs should be generated for a prompt. Once satisfy, a round is finished.
    #[arg(long = "fr", default_value = "1")]
    pub fuzz_round_succ: usize,
    /// How number of round without new coverage is considered as converge.
    #[arg(long = "fc", default_value = "10")]
    pub fuzz_converge_round: usize,
    /// number of cores used to parallely run the fuzzers.
    #[arg(short, long, default_value = "1")]
    pub cores: usize,
    /// The maximum of cpu cores used in the sanitization phase.
    #[arg(short, long, default_value = "0")]
    pub max_cores: usize,
    #[arg(short, long, default_value = "false")]
    pub exponent_branch: bool,
    /// Whether to recheck the seeds during the fuzz loop is a decision that is strongly recommended. Enabling this option can help reduce false positives, but it may come at the cost of increased execution time.
    #[arg(short, long, default_value = "false")]
    pub recheck: bool,
    /// Run condensed fuzzers after the fuzz loop
    #[arg(long, default_value = "false")]
    pub fuzzer_run: bool,
    /// Select the handler type for LLM requests
    #[arg(long = "handler", default_value = "openai")]
    pub handler_type: HandlerType,
    /// Timeout in minutes for the seed generation phase
    #[arg(long)]
    pub seed_gen_timeout: Option<u64>,
    /// Number of rounds over which the convergence condition is calculated for
    /// ApiCombination mode
    #[arg(long, default_value = "3")]
    pub quiet_round: usize,
    /// Minimum number of newly discovered pairs that indicate that the
    /// generator has not converged in ApiCombination mode
    #[arg(long, default_value = "3")]
    pub num_new_pairs: usize,
    /// Enable Chain of Thought (CoT) mode for API combination generation. In CoT mode, LLM first generates an execution plan in natural language, then generates code based on that plan. This can improve correctness for complex libraries.
    #[arg(long = "cot", default_value = "false")]
    pub enable_cot: bool,
}

impl Config {
    pub fn init_test(target: &str) {
        let config = Config {
            generation_mode: GenerationModeP::FuzzDriver,
            target: target.to_string(),
            n_sample: 10,
            temperature: 0.6,
            cores: 10,
            max_cores: 0,
            fuzz_round_succ: 1,
            fuzz_converge_round: 10,
            exponent_branch: false,
            recheck: false,
            fuzzer_run: false,
            disable_power_schedule: false,
            handler_type: HandlerType::Openai,
            seed_gen_timeout: None,
            quiet_round: 3,
            num_new_pairs: 3,
            enable_cot: false,
        };
        let _ = CONFIG_INSTANCE.set(RwLock::new(config));
        crate::init_debug_logger().unwrap();
    }
}

/// custom configuration of each project
#[derive(Debug, Default, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct LibConfig {
    ///the project name that used in build.sh
    pub project_name: String,
    /// the name of the static linked library.
    pub static_lib_name: String,
    /// the name of the static linked library.
    pub dyn_lib_name: String,
    /// vec of functions that are banned.
    pub ban: Option<Vec<String>>,
    /// if the fuzzer input should be terminated with null.
    pub null_term: Option<bool>,
    /// The extra c flags passed to compiler
    pub extra_c_flags: Option<Vec<String>>,
    /// The landmark corpus prompt as example of input.
    pub landmark: Option<bool>,
    /// The types need to be forced added into prompt
    pub force_types: Option<Vec<String>>,
    /// Whether this library should be fuzzed in fork mode.
    pub fuzz_fork: Option<bool>,
    /// The short description of this library to let LLM know what the library is.
    pub desc: Option<String>,
    /// The statements used to initialize the library.
    pub spec: Option<String>,
    /// The additional initialization file used in setup.
    pub init_file: Option<String>,
    /// The extra ASAN options used for libraries.
    pub asan_option: Option<String>,
    /// Whether disable fmemopen.
    pub disable_fmemopen: Option<bool>,
    /// Memory limit passed to libfuzzer
    pub rss_limit_mb: Option<usize>,
}

impl LibConfig {
    pub fn should_terminate_with_null(&self) -> bool {
        if let Some(term) = &self.null_term {
            return *term;
        }
        false
    }
}

/// Template of generative prompt in system role. 
pub const SYSTEM_GEN_TEMPLATE: &str = "Act as a C++ langauge Developer, write a fuzz driver that follow user's instructions.
The prototype of fuzz dirver is: `extern \"C\" int LLVMFuzzerTestOneInput(const uint8_t data, size_t size)`.
\n";
pub const SYSTEM_API_TEMPLATE: &str = "Act as an API usage synthesizer. Generate valid combinations of available APIs from the target library, ensuring there are no logical or syntactical errors in the code.
";

/// Template of providing the context of library's structures. 
pub const SYSTEM_CONTEXT_TEMPLATE: &str = "
The fuzz dirver should focus on the usage of the {project} library, and several essential aspects of the library are provided below.
Here are the system headers included in {project}. You can utilize the public elements of these headers:
----------------------
{headers}
----------------------

Here are the APIs exported from {project}. You are encouraged to use any of the following APIs once you need to create, initialize or destory variables:
----------------------
{APIs}
----------------------

Here are the custom types declared in {project}. Ensure that the variables you use do not violate declarations:
----------------------
{context}
----------------------
";
pub const ERROR_REPAIR_TEMPLATE: &str =
"The previous attempt to generate code failed with the following error:

Error code:{error_code}
Error Type: {error_type}
Error Details:{error_details}
Please regenerate a new program to repair the error without changing the logic, do not redefine main function and any other parameters even if the error is not defined, and do not change the function name.
If error type is execution error without error details, you can regard it as Segmentation fault (core dumped)
Do not include if branches or loops; the function should be a straight-line sequence of API calls.
";

pub const USER_API_TEMPLATE: &str = "Your task is to write a complete, logically correct C++ function named `int test_{project}_api_sequence()` using the {project} library.

The API sequence should focus on the usage of the {project} library, and several essential aspects of the library are provided below.

Here are the system headers included in {project}. You can utilize the public elements of these headers:
----------------------
{headers}
----------------------

Here are the APIs exported from {project}. You are encouraged to use any of the following APIs once you need to create, initialize or destroy variables:
----------------------
{APIs}
----------------------

Here are the custom types declared in {project}. Ensure that the variables you use do not violate declarations:
----------------------
{context}
----------------------

Use the following APIs in your function:
{combinations}
Here are some successful examples:
{successful_examples}
Function Requirements:
1. The function must return `66` on success.  
2. Do not include if branches or loops; the function should be a straight-line sequence of API calls.
3. You must not redefine or include the {project} library.  
4. Do not use `std::memset`; use plain `memset`.  do not create new functions, use the existing APIs.
5. The function must end with:
   API sequence test completed successfully
6. When you enter a new phase, use `// step ...` to indicate the phase. different operations are in different steps, steps cannot exceed 4

Below is project's specific rules:
{project_rules}

Code Quality Rules:
- The function must be self-contained: declare, initialize, and clean up all variables and resources.
- The API sequence should follow a realistic and complete usage pattern:
  - Initialize → Configure → Operate → Validate → Cleanup
- Ensure that data flows meaningfully between API calls (no dummy or unused variables).
- Do not use placeholders like `// your code here`.
- No comments needed — just clean and understandable code.
- If you have to write any helper functions, begin them with static
Output Instructions:

Only output the function body `int test_{project}_api_sequence() { ... }`  
No `#include` directives or `main()` function.

Example Outline:
```cpp
int test_{project}_api_sequence() {
    // Step 1: Declarations
    // Step 2: Setup
    // Step 3: Core operations
    // Step ...
    // step ... : Cleanup
    return 66;
}
```";

pub const USER_GEN_TEMPLATE: &str = "Create a C language program step by step by using {project} library APIs and following the instructions below:
1. Here are several APIs in {project}. Specific an event that those APIs could achieve together, if the input is a byte stream of {project}' output data.
{combinations}; 
2. Complete the LLVMFuzzerTestOneInput function to achieve this event by using those APIs. Each API should be called at least once, if possible.
3. The input data and its size are passed as parameters of LLVMFuzzerTestOneInput: `const uint8_t *data` and `size_t size`. They must be consumed by the {project} APIs.
4. Once you need a `FILE *` variable to read the input data, using `FILE * in_file = fmemopen((void *)data, size, \"rb\")` to produce a `FILE *` variable.
   Once you need a `FILE *` variable to write output data, using `FILE * out_file = fopen(\"output_file\", \"wb\")` to produce a `FILE *` variable.
5. Once you need a `int` type file descriptor, using `fileno(in_file)` or `fileno(out_file)` to produce a file descriptor for reading or writing. 
6. Once you just need a string of file name, directly using \"input_file\" or \"output_file\" as the file name.
7. Release all allocated resources before return.
";

/// Chain of Thought - Phase 1: Generate execution plan in natural language
pub const USER_API_COT_PLAN_TEMPLATE: &str = "

Use the following APIs in your plan:
{combinations}

**IMPORTANT: Do NOT write code in this step. Only write a detailed natural language execution plan.**

Please create a detailed execution plan (in natural language, not code) for generating a C function `int test_{project}_api_sequence()` that uses the above APIs.

Your execution plan should:
1. List the main API names (not their full declarations - they're already in library headers)
2. If auxiliary/helper APIs are needed (for setup/cleanup), just mention their names
3. Describe step-by-step how to use these APIs following the pattern: Initialize → Configure → Operate → Cleanup
4. Explain the logic and data flow between API calls
5. Be detailed enough that code can be generated from it in the next phase

**CRITICAL:** In the next phase, the generated code will:
- Include the library header file (e.g., #include <lcms2.h>)
- All types, structs, and function prototypes are ALREADY defined in the library headers
- The code should NOT redeclare types, use extern blocks, or redefine function prototypes
- Only the function implementation should be written

Requirements for the final code (describe how to meet these in your plan):
- Function must return 66 on success
- No if branches or loops; straight-line sequence of API calls only
- Must not redefine types or function declarations (library headers provide everything)
- Do not use std::memset; use plain memset
- Do not create new functions, use existing APIs
- Function must end with: API sequence test completed successfully
- Divide into steps (no more than 3 steps)
- Every build function should not pass 0 or NULL as parameters

Output format:
Write a natural language description explaining:
- What variables need to be declared (e.g., \"cmsHPROFILE hProfile\")
- What each step should do
- How data flows between API calls
- What cleanup is needed

**Do NOT write actual C/C++ code, type definitions, or function prototypes. Only write the execution plan in natural language.**

";

/// Chain of Thought - Phase 2: Generate code based on the execution plan
pub const USER_API_COT_CODE_TEMPLATE: &str = "
Based on the following execution plan, write a complete, logically correct C++ function named `int test_{project}_api_sequence()`.
Do not include if branches or loops; the function should be a straight-line sequence of API calls. Return 66 on success.
Execution Plan:
{execution_plan}

CRITICAL CODE GENERATION RULES:
1. DO NOT declare or redefine any types, structs, or typedefs - All types are already defined in the included library headers
2. DO NOT use extern \"C\" blocks** - The library headers already handle this
3. DO NOT redeclare any function prototypes** - All functions are already declared in the included headers
4. ONLY write the function implementation** - Start directly with: `int test_{project}_api_sequence() {{`
5. DO NOT include any #ifdef, #ifndef, or preprocessor directives** in your code

Your code should ONLY contain:
- The function signature: `int test_{project}_api_sequence()`
- Variable declarations inside the function
- API calls
- Return statement

Below is project's specific rules, the code you generate must follow these rules:
{project_rules}

Here are some successful examples for reference:
{successful_examples}

Again do not include if branches or loops; the function should be a straight-line sequence of API calls.
code example outline:
```cpp
int test_{project}_api_sequence() {{
    // Step 1:
    // Step 2: 
    // Step 3: 
    //printf
    return 66;
}}

Remember: DO NOT declare types, use extern blocks, or redeclare functions. Only write the function body.
";

pub fn get_project_rules() -> String {
    let library_name = get_library_name();
    
    let mut template =match get_config().enable_cot {
        true => USER_API_COT_CODE_TEMPLATE.to_string(),
        false => USER_API_TEMPLATE.to_string(),      
    }; 
    if library_name == "cre2" {
        template = template.replace("{project_rules}", "
        1. Do not use CRE2_ANCHOR_UNANCHORED，use CRE2_UNANCHORED instead.
        2. Do not use CRE2_ANCHOR_NONE
        3.int cre2_full_match(const char * , const cre2_string_t * , cre2_string_t * , int ), Please note that cre2_full_match only have 4 parameters, not 5
        4. Please note cre2_decl cre2_set *cre2_set_new(cre2_options_t *opt, cre2_anchor_t anchor) and no known conversion from 'int' to 'cre2_anchor_t' for 2nd argument
        ");
    }
    if library_name=="zlib"{
        template = template.replace("{project_rules}", "
        1. Do not redefine z_stream_s
        2. Note that #define zlib_version zlibVersion()
        3. If you want to use Z_DEFAULT_WBITS,use MAX_WBITS instead
        ");
    }
    if library_name=="lcms"{
        template = template.replace("{project_rules}", "
        1. Never assign handles (cmsHANDLE, cmsMLU*, cmsToneCurve*, etc.) to integer or malloc() values. Always use official creation APIs (e.g., cmsCIECAM02Init, cmsMLUalloc).
        2. When create cmsViewingConditions, the parameter is cmsCIEXYZ* whitePoint, cmsUInt32Number  surround, not cmsCIEXYZ whitePoint
        ");
    }
    if library_name=="libpng"{
        template = template.replace("{project_rules}", "
        1. Never declare variables of type png_info or png_struct directly (e.g., 'png_info info;' is wrong)
        2. Always use pointer types: png_structp, png_infop
        3. Do not use sizeof() on opaque types like png_info or png_struct
        4. Use PNG_LIBPNG_VER_STRING (not version numbers) as the first parameter of png_create_write_struct/png_create_read_struct
        5. CRITICAL: For png_create_write_struct/png_create_read_struct, ALWAYS pass NULL for the 3rd and 4th parameters (error/warning callbacks)
        6. NEVER use png_error, png_warning, or png_benign_error as callback parameters - they will cause compilation errors
        7. Example: png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL) - note all NULLs
        8. Use png_create_info_struct() to create info structures
        9. For png_destroy_read_struct, the 2nd and 3rd parameters must be different pointers. Use NULL for the 3rd if you only have one info_ptr
        10. Example: png_destroy_read_struct(&png_ptr, &info_ptr, NULL) - NOT (&png_ptr, &info_ptr, &info_ptr)
        11. Only access structures through official API functions (png_get_*, png_set_*)
        ");
    }
    if library_name=="libpcap"{
        template = template.replace("{project_rules}", "
        1. Pay fuly attention to the double free problem
        ");
    }
    if library_name=="sqlite3"{
        template = template.replace("{project_rules}", "
        1. Always use sqlite3_open() or sqlite3_open_v2() to open a database; never directly assign sqlite3* pointers to integers or malloc() results.
        2. Always use sqlite3_prepare_v2() to prepare SQL statements before execution; do not reuse prepared statements (ppStmt) across different queries.
        3. Always call sqlite3_step() to execute a prepared statement; check the return value (SQLITE_ROW, SQLITE_DONE, or error codes).
        4. Always call sqlite3_finalize() to release prepared statements (sqlite3_stmt*) when done.
        5. Always call sqlite3_close() or sqlite3_close_v2() to close the database connection when finished.
        6. Do not modify sqlite3 opaque structures directly; always use official API functions (sqlite3_get_*, sqlite3_set_*, etc.).
        7. Use sqlite3_bind_*() functions (sqlite3_bind_int, sqlite3_bind_text, etc.) to safely bind parameters to prepared statements.
        8. Always check the return value of sqlite3_step() for error handling; do not assume success.
        9. Do not open the same database file multiple times without closing the previous connection first.
        10. Call sqlite3_reset() before re-executing a prepared statement with different parameters.
        ");
    }
    if library_name=="cJSON"{
        template = template.replace("{project_rules}", "
        1. Always use official cJSON creation APIs (cJSON_CreateObject(), cJSON_CreateArray(), cJSON_CreateString(), cJSON_CreateNumber(), etc.) to create objects; never directly assign cJSON* pointers to malloc() results.
        2. Do not directly modify cJSON structure members; use official API functions (cJSON_AddItemToObject(), cJSON_AddItemToArray(), cJSON_SetNumberValue(), etc.).
        3. Always call cJSON_Delete() to release cJSON objects when done; this recursively frees all child objects.
        4. Use cJSON_GetObjectItem() or cJSON_GetObjectItemCaseSensitive() to safely access object members.
        5. Always check if the returned pointer from cJSON_GetObjectItem() is NULL before accessing its properties.
        6. Use type-checking functions (cJSON_IsString(), cJSON_IsNumber(), cJSON_IsBool(), cJSON_IsArray(), cJSON_IsObject()) before accessing field values.
        7. For string values, use item->valuestring; do not assume it is non-NULL without type checking.
        8. For numeric values, use item->valuedouble or cJSON_GetNumberValue() depending on the data type.
        9. Use cJSON_Print() or cJSON_PrintUnformatted() to serialize to string, and free the returned string with free().
        10. Never assign the same cJSON object to multiple parents; use cJSON_Duplicate() to create a copy if needed.
        ");
    }
    template
}
pub const RAW_RULE: &str = "
{project_rules}
";
pub fn get_raw_project_rules() -> String {
    let library_name = get_library_name();
    
    let mut template = RAW_RULE.to_string();
    if library_name == "cre2" {
        template = template.replace("{project_rules}", "
        1. Do not use CRE2_ANCHOR_UNANCHORED，use CRE2_UNANCHORED instead.
        2. Do not use CRE2_ANCHOR_NONE
        3.int cre2_full_match(const char * , const cre2_string_t * , cre2_string_t * , int ), Please note that cre2_full_match only have 4 parameters, not 5
        4. Please note cre2_decl cre2_set *cre2_set_new(cre2_options_t *opt, cre2_anchor_t anchor) and no known conversion from 'int' to 'cre2_anchor_t' for 2nd argument
        ");
    }
    if library_name=="zlib"{
        template = template.replace("{project_rules}", "
        1. Do not redefine z_stream_s
        2. Note that #define zlib_version zlibVersion()
        3. If you want to use Z_DEFAULT_WBITS,use MAX_WBITS instead
        ");
    }
    if library_name=="lcms"{
        template = template.replace("{project_rules}", "
        1. Never assign handles (cmsHANDLE, cmsMLU*, cmsToneCurve*, etc.) to integer or malloc() values. Always use official creation APIs (e.g., cmsCIECAM02Init, cmsMLUalloc).
        2. When create cmsViewingConditions, the parameter is cmsCIEXYZ* whitePoint, cmsUInt32Number  surround, not cmsCIEXYZ whitePoint
        3. cmsToneCurve Curve[3] will cause error, you should use offical API to build
        4. When generating or modifying IT8/CGATS inputs, always ensure the memory buffer length is greater than 0 (len > 0) and include a valid file header (e.g., CGATS or IT8) to avoid triggering cmsIT8LoadFromMem assertions.
        ");
    }
    if library_name=="sqlite3"{
        template = template.replace("{project_rules}", "
        1. Always use sqlite3_open() or sqlite3_open_v2() to open a database; never directly assign sqlite3* pointers to integers or malloc() results.
        2. Always use sqlite3_prepare_v2() to prepare SQL statements before execution; do not reuse prepared statements (ppStmt) across different queries.
        3. Always call sqlite3_step() to execute a prepared statement; check the return value (SQLITE_ROW, SQLITE_DONE, or error codes).
        4. Always call sqlite3_finalize() to release prepared statements (sqlite3_stmt*) when done.
        5. Always call sqlite3_close() or sqlite3_close_v2() to close the database connection when finished.
        6. Do not modify sqlite3 opaque structures directly; always use official API functions (sqlite3_get_*, sqlite3_set_*, etc.).
        7. Use sqlite3_bind_*() functions (sqlite3_bind_int, sqlite3_bind_text, etc.) to safely bind parameters to prepared statements.
        8. Always check the return value of sqlite3_step() for error handling; do not assume success.
        9. Do not open the same database file multiple times without closing the previous connection first.
        10. Call sqlite3_reset() before re-executing a prepared statement with different parameters.
        ");
    }
    if library_name=="cJSON"{
        template = template.replace("{project_rules}", "
        1. Always use official cJSON creation APIs (cJSON_CreateObject(), cJSON_CreateArray(), cJSON_CreateString(), cJSON_CreateNumber(), etc.) to create objects; never directly assign cJSON* pointers to malloc() results.
        2. Do not directly modify cJSON structure members; use official API functions (cJSON_AddItemToObject(), cJSON_AddItemToArray(), cJSON_SetNumberValue(), etc.).
        3. Always call cJSON_Delete() to release cJSON objects when done; this recursively frees all child objects.
        4. Use cJSON_GetObjectItem() or cJSON_GetObjectItemCaseSensitive() to safely access object members.
        5. Always check if the returned pointer from cJSON_GetObjectItem() is NULL before accessing its properties.
        6. Use type-checking functions (cJSON_IsString(), cJSON_IsNumber(), cJSON_IsBool(), cJSON_IsArray(), cJSON_IsObject()) before accessing field values.
        7. For string values, use item->valuestring; do not assume it is non-NULL without type checking.
        8. For numeric values, use item->valuedouble or cJSON_GetNumberValue() depending on the data type.
        9. Use cJSON_Print() or cJSON_PrintUnformatted() to serialize to string, and free the returned string with free().
        10. Never assign the same cJSON object to multiple parents; use cJSON_Duplicate() to create a copy if needed.
        ");
    }

    template
}
pub fn get_sys_gen_template() -> &'static str {
    let config = get_config();
    let generation_mode = config.generation_mode.clone();
    let template = match generation_mode {
        GenerationModeP::FuzzDriver => SYSTEM_GEN_TEMPLATE,
        GenerationModeP::ApiCombination => SYSTEM_API_TEMPLATE,
    };
    pub static TEMPLATE: OnceCell<String> = OnceCell::new();
    TEMPLATE.get_or_init(|| template.to_string())
}

pub fn get_user_gen_template() -> &'static str {
    pub static GTEMPLATE: OnceCell<String> = OnceCell::new();
    let generation_mode = get_config().generation_mode.clone();
    let user_template = match generation_mode {
        GenerationModeP::FuzzDriver => USER_GEN_TEMPLATE,
        GenerationModeP::ApiCombination => USER_API_TEMPLATE,
    };
    GTEMPLATE.get_or_init(|| {
        let config = get_config();
        let template = user_template.to_string();
        template.replace("{project}", &config.target)
    })
}

/// Get Chain of Thought plan template (Phase 1)
pub fn get_user_cot_plan_template() -> String {
    let config = get_config();
    USER_API_COT_PLAN_TEMPLATE
        .replace("{project}", &config.target)
}

/// Get Chain of Thought code template (Phase 2)
pub fn get_user_cot_code_template() -> String {
    let config = get_config();
    USER_API_COT_CODE_TEMPLATE
        .replace("{project}", &config.target)
}

/// Check if CoT mode is enabled
pub fn is_cot_enabled() -> bool {
    get_config().enable_cot
}

pub fn get_user_chat_template() -> String {
    let library_name = get_library_name();
    let deopt = Deopt::new(library_name).unwrap();
    let mut template = get_user_gen_template().to_string();
    if let Some(landmark) = deopt.get_library_landmark_corpus() {
        template.insert_str(0, &format!("The input data is: {landmark}\n\n\n."));
    }
    if let Some(init) = &deopt.config.spec {
        template.push_str(&format!("\nThe begining of the fuzz driver is: \n{init}"))
    }
    if let Some(disable_fmemopen) = &deopt.config.disable_fmemopen {
        if *disable_fmemopen {
            template = template.replace(
                "fmemopen((void *)data, size, \"rb\")",
                "fopen(\"input_file\", \"rb\")",
            );
        }
    }
    template
}
