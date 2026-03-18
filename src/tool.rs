use crate::error::{RuntimeError, StartupError};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::{
    collections::HashMap,
    path::{Component, Path, PathBuf},
    process::Stdio,
    sync::{Arc, LazyLock},
    time::Duration,
};
use tokio::process::Command as TokioCommand;
use tracing::{debug, warn};
use unicode_normalization::UnicodeNormalization;
use which::which;

pub const MAX_ARG_LENGTH: usize = 64 * 1024;
pub const MAX_ARGS_COUNT: usize = 256;

const SHELL_METACHARACTERS: &[char] = &[';', '|', '&', '`', '(', ')', '<', '>', '\n', '\r', '\\'];
const DANGEROUS_FOR_ALL: &[char] = &[';', '|', '&', '`', '(', ')', '<', '>', '\n', '\r'];

const DANGEROUS_ARG_PATTERNS: &[&str] = &[
    "-exec",
    "-execdir",
    "-ok",
    "-okdir",
    "-delete",
    "-printf",
    "-fprintf",
    "-fprint",
    "-fls",
    "-prune",
    "-quit",
    "-eval",
    "-evaluate",
    "-c",
    "-e",
    "--command",
    "--to-command",
    "--eval",
    "--evaluate",
    "-system",
    "-shell",
    "-run",
    "-cmd",
    "-execute",
    "--execute",
    "-exec=",
    "--checkpoint-action",
    "--use-compress-program",
    "--to-program",
    "--transform",
    "--suffix",
    "--rsync-path",
    "--shell",
    "--exclude-from",
    "--include-from",
    "--exec-path",
    "--upload-pack",
    "--receive-pack",
    "--git-dir",
    "--work-tree",
    "--config",
    "--core.editor",
    "--core.pager",
    "+",
    "--cmd",
    "-S",
    "--session",
    "-P",
    "--pager",
    "-F",
    "-M",
    "--manpath",
    "-x",
    "--exec",
    "-n",
    "--interval",
    "-i",
    "-s",
    "--init-file",
    "--rcfile",
    "-n",
    "--noediting",
    "-m",
    "--module",
    "-p",
    "-n",
    "-i",
    "-r",
    "-B",
    "-R",
    "-F",
    "-E",
    "--run",
    "--begin",
    "--end",
    "-l",
    "--require",
    "BEGIN",
    "END",
    "system(",
    "getline",
    "close(",
    "fflush(",
    "e",
    "r",
    "w",
    "/!/{",
    "--upload-file",
    "--output",
    "-o",
    "-O",
    "--post-file",
    "--header",
    "--proxy",
    "EXEC:",
    "SYSTEM:",
    "SHELL:",
    "-o",
    "--output",
    "-f",
    "--follow-forks",
    "--eval-command",
    "-x",
    "--batch",
    "new-session",
    "send-keys",
    "run-shell",
    "-X",
    "-o",
    "-S",
    "-F",
    "--config",
    "--ssh-command",
    "-v",
    "--volume",
    "--privileged",
    "--cap-add",
    "--security-opt",
    "--device",
    "--mount",
    "exec",
    "run",
    "-f",
    "--filename",
    "run",
    "exec",
    "link",
    "--script-shell",
    "install",
    "--editable",
    "-m",
    "--module",
    "-a",
    "--args",
    "--overwrite",
    "--force",
    "-f",
    "--no-preserve",
    "--preserve",
    "-popen",
    "-subprocess",
    "-flask",
    "spawn",
    "fork",
    "pipe",
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "PATH=",
    "USER=",
    "--helper",
    "--helper-path",
    "--plugin",
    "--extension",
    "--script",
    "--lua",
    "--js",
    "--perl",
    "--python",
];

static PLACEHOLDER_RE: LazyLock<Result<Regex, regex::Error>> =
    LazyLock::new(|| Regex::new(r"\{([a-zA-Z_]\w*)\}"));

// =============================================================================
// Binary Resolution Trait (for mocking)
// =============================================================================

pub trait BinaryResolver: Send + Sync {
    fn resolve(&self, binary: &str) -> Option<PathBuf>;
}

pub struct DefaultBinaryResolver;

impl BinaryResolver for DefaultBinaryResolver {
    fn resolve(&self, binary: &str) -> Option<PathBuf> {
        which(binary).ok()
    }
}

// =============================================================================
// Command Definition Structures
// =============================================================================

#[derive(Debug, Clone)]
pub struct CommandDef {
    pub name: String,
    pub template: String,
    pub binary: String,
    pub arg_templates: Vec<ArgTemplate>,
    pub all_placeholders: Vec<String>,
    pub needs_path_validation: bool,
    pub resolved_binary_path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
enum ArgSegment {
    Static(String),
    Placeholder(String),
}

#[derive(Debug, Clone)]
pub struct ArgTemplate {
    segments: Vec<ArgSegment>,
}

impl ArgTemplate {
    pub fn from_token(token: &str) -> Result<Self, StartupError> {
        let regex = PLACEHOLDER_RE
            .as_ref()
            .map_err(|e| StartupError::RegexError(e.to_string()))?;
        let mut segments = Vec::new();
        let mut last_end = 0;

        for caps in regex.captures_iter(token) {
            let start = caps
                .get(0)
                .ok_or_else(|| StartupError::RegexError("Invalid capture".into()))?
                .start();
            let end = caps
                .get(0)
                .ok_or_else(|| StartupError::RegexError("Invalid capture".into()))?
                .end();

            if start > last_end {
                segments.push(ArgSegment::Static(token[last_end..start].to_string()));
            }

            let ph_name = caps
                .get(1)
                .ok_or_else(|| StartupError::RegexError("Invalid placeholder".into()))?
                .as_str()
                .to_string();
            segments.push(ArgSegment::Placeholder(ph_name));
            last_end = end;
        }

        if last_end < token.len() {
            segments.push(ArgSegment::Static(token[last_end..].to_string()));
        }

        if segments.is_empty() {
            segments.push(ArgSegment::Static(token.to_string()));
        }

        Ok(Self { segments })
    }

    pub fn build(
        &self,
        placeholder_values: &HashMap<String, String>,
    ) -> Result<String, RuntimeError> {
        let mut result = String::new();
        for segment in &self.segments {
            match segment {
                ArgSegment::Static(text) => result.push_str(text),
                ArgSegment::Placeholder(name) => {
                    let value = placeholder_values
                        .get(name)
                        .ok_or_else(|| RuntimeError::MissingParam(name.clone()))?;
                    result.push_str(value);
                }
            }
        }
        Ok(result)
    }

    fn get_placeholder_names(&self) -> Vec<&str> {
        self.segments
            .iter()
            .filter_map(|s| match s {
                ArgSegment::Placeholder(name) => Some(name.as_str()),
                _ => None,
            })
            .collect()
    }
}

pub fn parse_command_def(input: &str) -> Result<CommandDef, String> {
    let (name, template) = input.split_once('|').ok_or("Format: name|\"cmd {arg}\"")?;
    let name = name.trim().to_string();

    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
    {
        return Err(format!("Invalid name: {name}"));
    }

    let template = template.trim().trim_matches('"').trim_matches('\'');
    let tokens =
        shell_words::split(template).map_err(|e| format!("Failed to parse template: {e}"))?;

    if tokens.is_empty() {
        return Err("Empty template".to_string());
    }

    let binary = tokens[0].clone();
    let mut arg_templates = Vec::new();
    let mut all_placeholders_map = HashMap::new();
    let mut all_placeholders = Vec::new();

    for tok in tokens.iter().skip(1) {
        let arg_template =
            ArgTemplate::from_token(tok).map_err(|e| format!("Invalid template: {e}"))?;
        for ph in arg_template.get_placeholder_names() {
            if all_placeholders_map.contains_key(ph) {
                return Err(format!("Duplicate placeholder: {{{ph}}}"));
            }
            all_placeholders_map.insert(ph.to_string(), true);
            all_placeholders.push(ph.to_string());
        }
        arg_templates.push(arg_template);
    }

    let needs_path_validation = all_placeholders
        .iter()
        .any(|p| matches!(p.as_str(), "path" | "file" | "dir" | "filepath"));

    Ok(CommandDef {
        name,
        template: template.to_string(),
        binary,
        arg_templates,
        all_placeholders,
        needs_path_validation,
        resolved_binary_path: None,
    })
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DynParams {
    #[serde(flatten)]
    pub values: HashMap<String, String>,
}

#[derive(Clone)]
pub struct CmdTool {
    pub def: CommandDef,
    pub config: Arc<crate::config::SecurityConfig>,
    pub binary_resolver: Arc<dyn BinaryResolver>,
}

impl CmdTool {
    pub fn new(def: CommandDef, config: Arc<crate::config::SecurityConfig>) -> Self {
        Self {
            def,
            config,
            binary_resolver: Arc::new(DefaultBinaryResolver),
        }
    }

    pub fn schema(&self) -> Result<Arc<Map<String, Value>>, RuntimeError> {
        let mut props = Map::new();
        let mut required = Vec::new();

        for ph in &self.def.all_placeholders {
            props.insert(
                ph.clone(),
                json!({ "type": "string", "description": format!("Value for {{{ph}}}") }),
            );
            required.push(ph.clone());
        }

        let obj = json!({ "type": "object", "properties": props, "required": required, "additionalProperties": false });
        obj.as_object()
            .ok_or_else(|| RuntimeError::ExecutionFailed("Invalid schema".into()))
            .map(|o| Arc::new(o.clone()))
    }

    pub fn check_binary_startup(&mut self) -> Result<(), StartupError> {
        let bin = &self.def.binary;
        let resolved = self.binary_resolver.resolve(bin);
        self.def.resolved_binary_path = resolved.clone();

        if resolved.is_none() && !self.config.allow_missing_binaries {
            return Err(StartupError::BinaryNotFound(
                bin.clone(),
                self.def.name.clone(),
            ));
        }

        if !self.config.allow_dangerous
            && let Some(rp) = resolved
        {
            let bn = rp
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| {
                    StartupError::BlacklistedBinary("unknown".into(), self.def.name.clone())
                })?
                .to_lowercase();

            if self.config.blacklist.iter().any(|b| b.to_lowercase() == bn) {
                warn!(target: "audit", event = "blacklist_violation", binary = %bn, command = %self.def.name);
                return Err(StartupError::BlacklistedBinary(bn, self.def.name.clone()));
            }
        }

        Ok(())
    }

    fn validate_binary_at_runtime(&self) -> Result<(), RuntimeError> {
        if self.config.allow_dangerous {
            return Ok(());
        }

        if let Some(cached_path) = &self.def.resolved_binary_path {
            match std::fs::metadata(cached_path) {
                Ok(meta) if meta.is_file() => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        if meta.permissions().mode() & 0o111 == 0 {
                            return Err(RuntimeError::ExecutionFailed(
                                "Binary is not executable".into(),
                            ));
                        }
                    }
                    Ok(())
                }
                Ok(_) => Err(RuntimeError::ExecutionFailed("Binary is not a file".into())),
                Err(_) => Err(RuntimeError::ExecutionFailed(
                    "Binary no longer exists".into(),
                )),
            }
        } else if self.config.allow_missing_binaries {
            if let Ok(rp) = which(&self.def.binary) {
                let bn = rp
                    .file_name()
                    .and_then(|n| n.to_str())
                    .ok_or_else(|| RuntimeError::ExecutionFailed("Invalid binary".into()))?
                    .to_lowercase();

                if self.config.blacklist.iter().any(|b| b.to_lowercase() == bn) {
                    warn!(target: "audit", event = "blacklist_runtime", binary = %bn);
                    return Err(RuntimeError::ExecutionFailed(format!(
                        "Blacklisted binary '{bn}' at runtime"
                    )));
                }
            }
            Ok(())
        } else {
            match which(&self.def.binary) {
                Ok(rp) => {
                    let bn = rp
                        .file_name()
                        .and_then(|n| n.to_str())
                        .ok_or_else(|| RuntimeError::ExecutionFailed("Invalid binary".into()))?
                        .to_lowercase();

                    if self.config.blacklist.iter().any(|b| b.to_lowercase() == bn) {
                        warn!(target: "audit", event = "blacklist_runtime", binary = %bn);
                        return Err(RuntimeError::ExecutionFailed(format!(
                            "Blacklisted binary '{bn}' at runtime"
                        )));
                    }
                    Ok(())
                }
                Err(_) => Err(RuntimeError::ExecutionFailed(format!(
                    "Binary '{}' not found",
                    self.def.binary
                ))),
            }
        }
    }

    pub fn validate_path_arg(&self, value: &str, placeholder: &str) -> Result<(), RuntimeError> {
        if !self.config.validate_paths || !self.def.needs_path_validation {
            return Ok(());
        }
        if matches!(placeholder, "path" | "file" | "dir" | "filepath") {
            validate_path_secure(value, self.config.base_path.as_deref())?;
        }
        Ok(())
    }

    pub async fn run(&self, params: &DynParams) -> Result<String, RuntimeError> {
        let mut placeholder_values = HashMap::with_capacity(self.def.all_placeholders.len());

        for ph in &self.def.all_placeholders {
            let val = params
                .values
                .get(ph)
                .ok_or_else(|| RuntimeError::MissingParam(ph.clone()))?;
            validate_placeholder_value(val, ph)?;
            self.validate_path_arg(val, ph)?;
            placeholder_values.insert(ph.clone(), val.clone());
        }

        let mut final_args = Vec::with_capacity(self.def.arg_templates.len());
        for arg_template in &self.def.arg_templates {
            let built_arg = arg_template.build(&placeholder_values)?;
            final_args.push(built_arg);
        }

        if final_args.len() > MAX_ARGS_COUNT {
            return Err(RuntimeError::ExecutionFailed(format!(
                "Too many arguments (max {MAX_ARGS_COUNT})"
            )));
        }

        self.validate_binary_at_runtime()?;

        debug!(
            "Executing: {:?} + {} args",
            self.def.binary,
            final_args.len()
        );

        let output =
            run_command_with_timeout(&self.def.binary, &final_args, self.config.cmd_timeout)
                .await?;

        let (out, err) = (
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );

        let icon = if output.status.success() {
            "[+]"
        } else {
            "[-]"
        };

        Ok(format!(
            "{} {}\nSTDOUT:\n{}\nSTDERR:\n{}",
            icon,
            self.def.template,
            if out.is_empty() { "(empty)" } else { &out },
            if err.is_empty() { "(empty)" } else { &err }
        ))
    }
}

// =============================================================================
// Validation Functions
// =============================================================================

pub fn normalize_path_lexical(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::ParentDir => {
                result.pop();
            }
            Component::CurDir => {}
            _ => result.push(comp.as_os_str()),
        }
    }
    result
}

pub fn urlencoding_decode(input: &str) -> String {
    urlencoding::decode(input)
        .unwrap_or_else(|_| input.into())
        .into_owned()
}

/// Recursively decode URL-encoded strings to handle double/triple encoding attacks
pub fn urlencoding_decode_recursive(input: &str) -> String {
    let mut result = input.to_string();
    let mut iterations = 0;
    const MAX_ITERATIONS: usize = 5;

    loop {
        let decoded = urlencoding_decode(&result);
        if decoded == result || iterations >= MAX_ITERATIONS {
            break;
        }
        result = decoded;
        iterations += 1;
    }

    result
}

pub fn normalize_unicode(input: &str) -> String {
    input.nfc().collect()
}

pub fn normalize_unicode_nfd(input: &str) -> String {
    input.nfd().collect()
}

fn normalize_unicode_both(input: &str) -> (String, String) {
    (normalize_unicode(input), normalize_unicode_nfd(input))
}

pub fn contains_path_traversal_chars(s: &str) -> bool {
    const DANGEROUS: &[char] = &['`', '\n', '\r', '\t', '\u{202E}', '\u{200B}'];
    s.contains(DANGEROUS)
        || s.contains("..")
        || s.contains("//")
        || s.contains("\\\\")
        || s.chars().any(|c| c.is_control() && !matches!(c, ' '))
}

fn is_inside_quotes(s: &str, pos: usize) -> bool {
    let mut in_single = false;
    let mut in_double = false;
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;

    while i < chars.len() && i < pos {
        let c = chars[i];
        if c == '\\' && i + 1 < chars.len() {
            i += 2;
            continue;
        }
        if c == '\'' && !in_double {
            in_single = !in_single;
        } else if c == '"' && !in_single {
            in_double = !in_double;
        }
        i += 1;
    }
    in_single || in_double
}

pub fn validate_dangerous_patterns(value: &str, placeholder: &str) -> Result<(), RuntimeError> {
    let normalized = normalize_unicode(value);

    for pattern in DANGEROUS_ARG_PATTERNS {
        let mut start_idx = 0;
        while let Some(pos) = normalized[start_idx..].find(pattern) {
            let absolute_pos = start_idx + pos;
            let is_word_boundary = if absolute_pos == 0 {
                true
            } else {
                let prev_char = normalized.chars().nth(absolute_pos - 1);
                prev_char.is_none_or(|c| c.is_whitespace() || c == '"' || c == '\'')
            };

            if is_word_boundary && !is_inside_quotes(&normalized, absolute_pos) {
                warn!(target: "audit", event = "dangerous_pattern", placeholder = %placeholder, pattern = %pattern);
                return Err(RuntimeError::InvalidArgument(
                    placeholder.into(),
                    format!("contains dangerous command pattern '{}'", pattern),
                ));
            }
            start_idx = absolute_pos + pattern.len();
        }
    }
    Ok(())
}

pub fn validate_shell_metachar_contextual(
    value: &str,
    placeholder: &str,
) -> Result<(), RuntimeError> {
    let is_path_placeholder = matches!(placeholder, "path" | "file" | "dir" | "filepath");

    for (i, c) in value.chars().enumerate() {
        if is_inside_quotes(value, i) {
            continue;
        }
        if DANGEROUS_FOR_ALL.contains(&c) {
            warn!(target: "audit", event = "injection_attempt", placeholder = %placeholder);
            return Err(RuntimeError::InvalidArgument(
                placeholder.into(),
                "contains dangerous shell metacharacters".into(),
            ));
        }
        if !is_path_placeholder && SHELL_METACHARACTERS.contains(&c) {
            return Err(RuntimeError::InvalidArgument(
                placeholder.into(),
                "contains shell metacharacters".into(),
            ));
        }
    }
    Ok(())
}

fn safe_canonicalize(path: &Path) -> std::io::Result<PathBuf> {
    if path.exists() {
        std::fs::canonicalize(path)
    } else if let Some(parent) = path.parent() {
        if parent.exists() {
            std::fs::canonicalize(parent).map(|p| {
                p.join(
                    path.file_name()
                        .map(|n| n.to_os_string())
                        .unwrap_or_default(),
                )
            })
        } else {
            Ok(normalize_path_lexical(path))
        }
    } else {
        Ok(normalize_path_lexical(path))
    }
}

pub fn validate_placeholder_value(value: &str, placeholder: &str) -> Result<(), RuntimeError> {
    validate_argument(value, placeholder)?;

    if value == "--" {
        warn!(target: "audit", event = "injection_attempt", placeholder = %placeholder);
        return Err(RuntimeError::InvalidArgument(
            placeholder.into(),
            "'--' is not allowed".into(),
        ));
    }

    validate_dangerous_patterns(value, placeholder)?;

    // Check for encoded traversal patterns BEFORE decoding
    if value.contains("%2e")
        || value.contains("%2E")
        || value.contains("%2f")
        || value.contains("%2F")
    {
        warn!(target: "audit", event = "encoded_traversal_attempt", placeholder = %placeholder);
        return Err(RuntimeError::InvalidArgument(
            placeholder.into(),
            "contains encoded path traversal characters".into(),
        ));
    }

    let decoded = urlencoding_decode_recursive(value);
    let (normalized_nfc, normalized_nfd) = normalize_unicode_both(&decoded);

    for normalized in [&normalized_nfc, &normalized_nfd] {
        if contains_path_traversal_chars(normalized) {
            warn!(target: "audit", event = "injection_attempt", placeholder = %placeholder);
            return Err(RuntimeError::InvalidArgument(
                placeholder.into(),
                "contains dangerous characters".into(),
            ));
        }
        if normalized.starts_with([';', '|', '&', '`', '(', ')', '<', '>']) {
            return Err(RuntimeError::InvalidArgument(
                placeholder.into(),
                "starts with dangerous character".into(),
            ));
        }
    }

    validate_shell_metachar_contextual(&normalized_nfc, placeholder)?;

    let is_flag_placeholder = placeholder.ends_with("_flag") || placeholder.ends_with("_opt");
    if !is_flag_placeholder
        && normalized_nfc.starts_with('-')
        && normalized_nfc.len() > 1
        && !normalized_nfc.contains('/')
        && !normalized_nfc.starts_with("--")
    {
        let second_char = normalized_nfc.chars().nth(1);
        if second_char.is_some_and(|c| c.is_alphabetic()) {
            return Err(RuntimeError::InvalidArgument(
                placeholder.into(),
                "looks like command flag, use *_flag suffix".into(),
            ));
        }
    }

    Ok(())
}

pub fn validate_path_secure(input: &str, base_path: Option<&Path>) -> Result<(), RuntimeError> {
    if input.contains('\0') {
        return Err(RuntimeError::PathTraversal(
            "Path contains null byte".into(),
        ));
    }

    // Check for encoded traversal patterns BEFORE decoding
    if input.contains("%2e")
        || input.contains("%2E")
        || input.contains("%2f")
        || input.contains("%2F")
    {
        warn!(target: "audit", event = "encoded_traversal_attempt", len = input.len());
        return Err(RuntimeError::PathTraversal(
            "Path contains encoded traversal characters".into(),
        ));
    }

    let decoded = urlencoding_decode_recursive(input);
    let (normalized_nfc, normalized_nfd) = normalize_unicode_both(&decoded);

    for normalized in [&normalized_nfc, &normalized_nfd] {
        if contains_path_traversal_chars(normalized) {
            warn!(target: "audit", event = "traversal_attempt", len = input.len());
            return Err(RuntimeError::PathTraversal(
                "Path contains traversal characters".into(),
            ));
        }
        if normalized
            .chars()
            .any(|c| DANGEROUS_FOR_ALL.contains(&c) || SHELL_METACHARACTERS.contains(&c))
        {
            warn!(target: "audit", event = "traversal_attempt");
            return Err(RuntimeError::PathTraversal(
                "Path contains shell metacharacters".into(),
            ));
        }
    }

    let trimmed = normalized_nfc.trim_matches(|c| c == '"' || c == '\'');
    let path = Path::new(&trimmed);

    if base_path.is_none() {
        if path.is_relative() || path.components().next().is_none() {
            warn!(target: "audit", event = "traversal_attempt", reason = "relative_no_base");
            return Err(RuntimeError::PathTraversal(
                "Relative paths forbidden without --base-path".into(),
            ));
        }
        if path.components().any(|c| matches!(c, Component::ParentDir)) {
            return Err(RuntimeError::PathTraversal(
                "Parent directory traversal (..) forbidden".into(),
            ));
        }
        return Ok(());
    }

    let base = base_path.ok_or_else(|| {
        RuntimeError::PathTraversal("Base path is required but not provided".into())
    })?;
    let target_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    };

    let candidate = safe_canonicalize(&target_path)
        .map_err(|e| RuntimeError::PathTraversal(format!("Cannot resolve path: {e}")))?;
    let base_canonical = safe_canonicalize(base)
        .map_err(|e| RuntimeError::PathTraversal(format!("Invalid base path: {e}")))?;

    let candidate_nfc = candidate.to_string_lossy();
    let candidate_nfd: String = candidate_nfc.nfd().collect();
    let base_nfc = base_canonical.to_string_lossy();
    let base_nfd: String = base_nfc.nfd().collect();

    if !candidate.starts_with(&base_canonical)
        && !Path::new(&candidate_nfd).starts_with(Path::new(&base_nfd))
    {
        warn!(target: "audit", event = "traversal_attempt", attempted = %candidate.display());
        return Err(RuntimeError::PathTraversal(format!(
            "Path '{}' outside base '{}'",
            candidate.display(),
            base_canonical.display()
        )));
    }

    Ok(())
}

pub fn validate_argument(value: &str, arg_name: &str) -> Result<(), RuntimeError> {
    if value.len() > MAX_ARG_LENGTH {
        return Err(RuntimeError::InvalidArgument(
            arg_name.into(),
            format!("exceeds max length {MAX_ARG_LENGTH}"),
        ));
    }
    if value.contains('\0') {
        return Err(RuntimeError::InvalidArgument(
            arg_name.into(),
            "contains null byte".into(),
        ));
    }
    Ok(())
}

pub fn mask_sensitive_args(
    args: &HashMap<String, String>,
    sensitive_keys: &[String],
) -> HashMap<String, String> {
    args.iter()
        .map(|(k, v)| {
            if sensitive_keys
                .iter()
                .any(|sk| k.to_lowercase().contains(sk.as_str()))
            {
                (k.clone(), "[REDACTED]".to_string())
            } else {
                (k.clone(), v.clone())
            }
        })
        .collect()
}

pub fn is_sensitive_header(name: &str) -> bool {
    let nl = name.to_lowercase();
    const SEN: &[&str] = &[
        "authorization",
        "x-api-key",
        "x-auth",
        "x-token",
        "x-secret",
        "cookie",
        "set-cookie",
        "proxy-authorization",
        "www-authenticate",
    ];
    if SEN.iter().any(|&p| p == nl) {
        return true;
    }
    const KW: &[&str] = &[
        "key",
        "secret",
        "token",
        "auth",
        "credential",
        "password",
        "pass",
    ];
    KW.iter().any(|&k| nl.contains(k))
}

pub async fn run_command_with_timeout(
    binary: &str,
    args: &[String],
    timeout_dur: Duration,
) -> Result<std::process::Output, RuntimeError> {
    let mut cmd = TokioCommand::new(binary);
    cmd.args(args);
    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());
    cmd.kill_on_drop(true);

    let child = cmd
        .spawn()
        .map_err(|e| RuntimeError::ExecutionFailed(format!("Spawn failed: {e}")))?;

    tokio::time::timeout(timeout_dur, child.wait_with_output())
        .await
        .map_err(|_| RuntimeError::Timeout(timeout_dur))?
        .map_err(|e| RuntimeError::ExecutionFailed(format!("Wait failed: {e}")))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // =============================================================================
    // Command Definition Tests
    // =============================================================================

    #[test]
    fn test_parse_command_def_valid_simple() {
        let input = r#"echo|"echo {message}""#;
        let result = parse_command_def(input);
        assert!(result.is_ok());
        let cmd = result.unwrap();
        assert_eq!(cmd.name, "echo");
        assert_eq!(cmd.binary, "echo");
        assert_eq!(cmd.all_placeholders, vec!["message"]);
    }

    #[test]
    fn test_parse_command_def_valid_multiple_args() {
        let input = r#"grep|"grep {pattern} {file}""#;
        let result = parse_command_def(input);
        assert!(result.is_ok());
        let cmd = result.unwrap();
        assert_eq!(cmd.name, "grep");
        assert_eq!(cmd.all_placeholders.len(), 2);
        assert!(cmd.all_placeholders.contains(&"pattern".to_string()));
        assert!(cmd.all_placeholders.contains(&"file".to_string()));
    }

    #[test]
    fn test_parse_command_def_invalid_no_pipe() {
        let input = r#"echo "echo {message}""#;
        let result = parse_command_def(input);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_command_def_invalid_name_chars() {
        let input = r#"echo!|"echo {message}""#;
        let result = parse_command_def(input);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid name"));
    }

    #[test]
    fn test_parse_command_def_duplicate_placeholder() {
        let input = r#"test|"echo {msg} {msg}""#;
        let result = parse_command_def(input);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Duplicate placeholder"));
    }

    #[test]
    fn test_parse_command_def_path_validation_flag() {
        let input = r#"cat|"cat {path}""#;
        let result = parse_command_def(input).unwrap();
        assert!(result.needs_path_validation);
        let input2 = r#"echo|"echo {message}""#;
        let result2 = parse_command_def(input2).unwrap();
        assert!(!result2.needs_path_validation);
    }

    // =============================================================================
    // ArgTemplate Tests
    // =============================================================================

    #[test]
    fn test_arg_template_static_only() {
        let template = ArgTemplate::from_token("hello").unwrap();
        let values = HashMap::new();
        let result = template.build(&values).unwrap();
        assert_eq!(result, "hello");
    }

    #[test]
    fn test_arg_template_placeholder_only() {
        let template = ArgTemplate::from_token("{username}").unwrap();
        let mut values = HashMap::new();
        values.insert("username".to_string(), "john".to_string());
        let result = template.build(&values).unwrap();
        assert_eq!(result, "john");
    }

    #[test]
    fn test_arg_template_mixed() {
        let template = ArgTemplate::from_token("user:{username}:id").unwrap();
        let mut values = HashMap::new();
        values.insert("username".to_string(), "alice".to_string());
        let result = template.build(&values).unwrap();
        assert_eq!(result, "user:alice:id");
    }

    #[test]
    fn test_arg_template_missing_placeholder() {
        let template = ArgTemplate::from_token("{username}").unwrap();
        let values = HashMap::new();
        let result = template.build(&values);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), RuntimeError::MissingParam(_)));
    }

    #[test]
    fn test_arg_template_multiple_placeholders() {
        let template = ArgTemplate::from_token("{first}_{last}").unwrap();
        let mut values = HashMap::new();
        values.insert("first".to_string(), "John".to_string());
        values.insert("last".to_string(), "Doe".to_string());
        let result = template.build(&values).unwrap();
        assert_eq!(result, "John_Doe");
    }

    // =============================================================================
    // Path Validation Tests
    // =============================================================================

    #[test]
    fn test_validate_path_traversal_blocked() {
        let result = validate_path_secure("../etc/passwd", None);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            RuntimeError::PathTraversal(_)
        ));
    }

    #[test]
    fn test_validate_path_double_slash_blocked() {
        let result = validate_path_secure("etc//passwd", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_path_null_byte_blocked() {
        let result = validate_path_secure("file\0.txt", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_path_secure_relative_without_base() {
        let result = validate_path_secure("safe/file.txt", None);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Relative paths forbidden")
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_validate_path_secure_absolute() {
        let result = validate_path_secure("/usr/bin/test", None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_path_with_base_inside() {
        let base = Path::new("/safe/base");
        let result = validate_path_secure("subdir/file.txt", Some(base));
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_path_shell_metacharacters_blocked() {
        let result = validate_path_secure("file;rm -rf /", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_normalize_path_lexical_parent_dir() {
        let path = Path::new("/home/user/../other/file.txt");
        let normalized = normalize_path_lexical(path);
        assert_eq!(normalized, Path::new("/home/other/file.txt"));
    }

    #[test]
    fn test_normalize_path_lexical_current_dir() {
        let path = Path::new("/home/./user/file.txt");
        let normalized = normalize_path_lexical(path);
        assert_eq!(normalized, Path::new("/home/user/file.txt"));
    }

    // =============================================================================
    // Dangerous Pattern Tests
    // =============================================================================

    #[test]
    fn test_validate_dangerous_patterns_exec_blocked() {
        let result = validate_dangerous_patterns("-exec rm -rf /", "cmd");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_dangerous_patterns_system_blocked() {
        let result = validate_dangerous_patterns("system('rm -rf /')", "cmd");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_dangerous_patterns_safe_string() {
        let result = validate_dangerous_patterns("\"hello world\"", "message");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_dangerous_patterns_eval_blocked() {
        let result = validate_dangerous_patterns("--eval code", "cmd");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_dangerous_patterns_word_boundary() {
        let result = validate_dangerous_patterns("myexec", "cmd");
        assert!(result.is_ok());
    }

    // =============================================================================
    // Shell Metacharacter Tests
    // =============================================================================

    #[test]
    fn test_validate_shell_metachar_semicolon_blocked() {
        let result = validate_shell_metachar_contextual("hello; world", "arg");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_shell_metachar_pipe_blocked() {
        let result = validate_shell_metachar_contextual("cmd1 | cmd2", "arg");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_shell_metachar_backtick_blocked() {
        let result = validate_shell_metachar_contextual("`whoami`", "arg");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_shell_metachar_safe_string() {
        let result = validate_shell_metachar_contextual("hello world", "arg");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_shell_metachar_inside_quotes_allowed() {
        let result = validate_shell_metachar_contextual("'hello;world'", "path");
        assert!(result.is_ok());
    }

    // =============================================================================
    // Placeholder Value Validation Tests
    // =============================================================================

    #[test]
    fn test_validate_placeholder_value_double_dash_blocked() {
        let result = validate_placeholder_value("--", "arg");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_placeholder_value_starts_with_dangerous() {
        let result = validate_placeholder_value(";rm", "arg");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_placeholder_value_flag_detection() {
        let result = validate_placeholder_value("-h", "arg");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("*_flag"));
    }

    #[test]
    fn test_validate_placeholder_value_flag_allowed_with_suffix() {
        let result = validate_placeholder_value("-h", "verbose_flag");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_placeholder_value_max_length() {
        let long_value = "a".repeat(MAX_ARG_LENGTH + 1);
        let result = validate_placeholder_value(&long_value, "arg");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_placeholder_value_null_byte() {
        let result = validate_placeholder_value("test\0value", "arg");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_placeholder_value_unicode_normalization() {
        let result = validate_placeholder_value("normal text", "arg");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_placeholder_value_dangerous_flag_always_blocked() {
        let result = validate_placeholder_value("-x", "verbose_flag");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("dangerous"));
    }

    // =============================================================================
    // Security Bypass Attempt Tests (Expanded)
    // =============================================================================

    #[test]
    fn test_validate_bypass_unicode_homoglyph() {
        let result = validate_placeholder_value("test\u{0430}", "arg");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_bypass_null_byte_injection() {
        let result = validate_placeholder_value("file.txt\0;rm -rf /", "path");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_bypass_url_encoded_traversal() {
        let result = validate_placeholder_value("..%2Fetc%2Fpasswd", "path");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_bypass_double_encoded() {
        // %252e = %2e after first decode = . after second decode
        // %252f = %2f after first decode = / after second decode
        let result = validate_placeholder_value("%252e%252e%252f", "path");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_bypass_newline_injection() {
        let result = validate_placeholder_value("file.txt\nrm -rf /", "path");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_bypass_carriage_return() {
        let result = validate_placeholder_value("file.txt\rrm -rf /", "path");
        assert!(result.is_err());
    }

    // =============================================================================
    // Utility Function Tests
    // =============================================================================

    #[test]
    fn test_urlencoding_decode() {
        let encoded = "hello%20world";
        let decoded = urlencoding_decode(encoded);
        assert_eq!(decoded, "hello world");
    }

    #[test]
    fn test_urlencoding_decode_invalid() {
        let invalid = "hello%ZZworld";
        let decoded = urlencoding_decode(invalid);
        assert_eq!(decoded, "hello%ZZworld");
    }

    #[test]
    fn test_urlencoding_decode_recursive() {
        // Double-encoded: %252e%252e = %2e%2e = ..
        let double_encoded = "%252e%252e";
        let decoded = urlencoding_decode_recursive(double_encoded);
        assert_eq!(decoded, "..");
    }

    #[test]
    fn test_normalize_unicode() {
        let input = "café";
        let normalized = normalize_unicode(input);
        assert_eq!(normalized.len(), input.len());
    }

    #[test]
    fn test_contains_path_traversal_chars() {
        assert!(contains_path_traversal_chars("../test"));
        assert!(contains_path_traversal_chars("test//path"));
        assert!(!contains_path_traversal_chars("safe/path"));
    }

    #[test]
    fn test_is_inside_quotes_single() {
        assert!(is_inside_quotes("'hello;world'", 7));
        assert!(!is_inside_quotes("'hello';world", 8));
    }

    #[test]
    fn test_is_inside_quotes_double() {
        assert!(is_inside_quotes("\"hello;world\"", 7));
        assert!(!is_inside_quotes("\"hello\";world", 8));
    }

    #[test]
    fn test_is_inside_quotes_escaped() {
        assert!(is_inside_quotes("'hello\\';world'", 8));
    }

    // =============================================================================
    // Sensitive Data Tests
    // =============================================================================

    #[test]
    fn test_mask_sensitive_args_password() {
        let mut args = HashMap::new();
        args.insert("password".to_string(), "secret123".to_string());
        args.insert("username".to_string(), "admin".to_string());
        let sensitive_keys = vec!["password".to_string()];
        let masked = mask_sensitive_args(&args, &sensitive_keys);
        assert_eq!(masked.get("password").unwrap(), "[REDACTED]");
        assert_eq!(masked.get("username").unwrap(), "admin");
    }

    #[test]
    fn test_mask_sensitive_args_case_insensitive() {
        let mut args = HashMap::new();
        args.insert("Password".to_string(), "secret".to_string());
        let sensitive_keys = vec!["password".to_string()];
        let masked = mask_sensitive_args(&args, &sensitive_keys);
        assert_eq!(masked.get("Password").unwrap(), "[REDACTED]");
    }

    #[test]
    fn test_is_sensitive_header_authorization() {
        assert!(is_sensitive_header("Authorization"));
        assert!(is_sensitive_header("authorization"));
    }

    #[test]
    fn test_is_sensitive_header_api_key() {
        assert!(is_sensitive_header("X-API-Key"));
        assert!(is_sensitive_header("x-api-key"));
    }

    #[test]
    fn test_is_sensitive_header_not_sensitive() {
        assert!(!is_sensitive_header("Content-Type"));
        assert!(!is_sensitive_header("User-Agent"));
    }

    #[test]
    fn test_is_sensitive_header_keyword_match() {
        assert!(is_sensitive_header("X-Secret-Token"));
        assert!(is_sensitive_header("My-Password-Header"));
    }

    // =============================================================================
    // Command Definition Structure Tests
    // =============================================================================

    #[test]
    fn test_command_def_clone() {
        let input = r#"ls|"ls {path}""#;
        let def = parse_command_def(input).unwrap();
        let cloned = def.clone();
        assert_eq!(def.name, cloned.name);
        assert_eq!(def.template, cloned.template);
    }

    #[test]
    fn test_command_def_all_placeholders_unique() {
        let input = r#"test|"cmd {a} {b} {c}""#;
        let def = parse_command_def(input).unwrap();
        assert_eq!(def.all_placeholders.len(), 3);
        let unique: std::collections::HashSet<_> = def.all_placeholders.iter().collect();
        assert_eq!(unique.len(), 3);
    }

    // =============================================================================
    // Edge Cases
    // =============================================================================

    #[test]
    fn test_empty_template_error() {
        let input = r#"test|""#;
        let result = parse_command_def(input);
        assert!(result.is_err());
    }

    #[test]
    fn test_whitespace_in_name() {
        let input = r#"test cmd|"cmd {arg}""#;
        let result = parse_command_def(input);
        assert!(result.is_err());
    }

    #[test]
    fn test_underscore_in_name() {
        let input = r#"test_cmd|"cmd {arg}""#;
        let result = parse_command_def(input);
        assert!(result.is_ok());
    }

    #[test]
    fn test_dash_in_name() {
        let input = r#"test-cmd|"cmd {arg}""#;
        let result = parse_command_def(input);
        assert!(result.is_ok());
    }

    #[test]
    fn test_single_quotes_template() {
        let input = r#"echo|'echo {message}'"#;
        let result = parse_command_def(input);
        assert!(result.is_ok());
    }

    #[test]
    fn test_complex_template_with_special_chars() {
        let input = r#"find|"find {path} -name {pattern}""#;
        let result = parse_command_def(input);
        assert!(result.is_ok());
        let def = result.unwrap();
        assert_eq!(def.binary, "find");
        assert_eq!(def.all_placeholders.len(), 2);
    }

    #[test]
    fn test_arg_template_empty_token() {
        let template = ArgTemplate::from_token("").unwrap();
        let values = HashMap::new();
        let result = template.build(&values).unwrap();
        assert_eq!(result, "");
    }

    #[test]
    fn test_validate_path_empty_string() {
        let result = validate_path_secure("", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_dangerous_patterns_empty() {
        let result = validate_dangerous_patterns("", "arg");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_shell_metachar_empty() {
        let result = validate_shell_metachar_contextual("", "arg");
        assert!(result.is_ok());
    }

    // =============================================================================
    // Binary Resolver Mock Tests
    // =============================================================================

    #[test]
    fn test_binary_resolver_trait() {
        struct MockResolver;
        impl BinaryResolver for MockResolver {
            fn resolve(&self, _binary: &str) -> Option<PathBuf> {
                Some(PathBuf::from("/mock/binary"))
            }
        }

        let resolver = Arc::new(MockResolver);
        let result = resolver.resolve("test");
        assert_eq!(result, Some(PathBuf::from("/mock/binary")));
    }
}
