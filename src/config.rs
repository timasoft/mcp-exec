use crate::tool::CommandDef;
use clap::{Parser, ValueEnum};
use std::{fmt::Display, path::PathBuf, sync::Arc, time::Duration};

#[derive(ValueEnum, Clone, Debug, Default, PartialEq)]
pub enum Transport {
    #[default]
    Stdio,
    StreamableHttp,
}

impl Display for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Transport::Stdio => write!(f, "stdio"),
            Transport::StreamableHttp => write!(f, "streamable-http"),
        }
    }
}

#[derive(ValueEnum, Clone, Debug, Default, PartialEq, Eq, Hash)]
pub enum LogLevel {
    #[default]
    Info,
    Debug,
    Trace,
    Warn,
    Error,
}

#[derive(Parser, Debug)]
#[command(name = "mcp-exec", version, about = "MCP server for command templates")]
pub struct Args {
    #[arg(short, long = "cmd", value_parser = crate::tool::parse_command_def, value_name = "NAME|\"TEMPLATE\"")]
    pub commands: Vec<CommandDef>,
    #[arg(
        short = 'B',
        long = "blacklist",
        default_value = "rm,dd,mkfs,chmod,chown,sudo,su,curl,wget,sh,bash,dash,zsh,\
        python,python3,perl,ruby,node,lua,php,awk,sed,gawk,\
        git,ssh,scp,rsync,tar,zip,unzip,gzip,bzip2,\
        find,xargs,env,nice,timeout,strace,ltrace,\
        ncat,netcat,nc,telnet,ftp,sftp,rbash,rsh",
        help = "Comma-separated list of blacklisted binaries."
    )]
    pub dangerous: String,
    #[arg(
        long = "allow-dangerous",
        short = 'D',
        action = clap::ArgAction::SetTrue,
        help = "Allow execution of blacklisted binaries. USE WITH CAUTION."
    )]
    pub allow_dangerous: bool,
    #[arg(
        long = "no-validate-paths",
        action = clap::ArgAction::SetTrue,
        help = "Disable path traversal protection for path-like placeholders."
    )]
    pub no_validate_paths: bool,
    #[arg(
        long = "allow-missing-binaries",
        action = clap::ArgAction::SetTrue,
        help = "Allow commands whose binaries are not in PATH."
    )]
    pub allow_missing_binaries: bool,
    #[arg(
        long = "base-path",
        help = "Restrict path-like arguments to be within this base directory."
    )]
    pub base_path: Option<PathBuf>,
    #[arg(
        long = "sensitive-keys",
        default_value = "password,token,secret,key,auth,credential",
        help = "Comma-separated list of argument names to mask in logs."
    )]
    pub sensitive_keys: String,
    #[arg(
        long = "cmd-timeout",
        default_value = "30",
        value_parser = clap::value_parser!(u64),
        help = "Maximum execution time for commands in seconds."
    )]
    pub cmd_timeout_secs: u64,
    #[arg(
        long = "log-level",
        value_enum,
        default_value_t = LogLevel::Info,
        env = "MCP_EXEC_LOG"
    )]
    pub log_level: LogLevel,
    #[arg(short, long = "dry-run", action = clap::ArgAction::SetTrue)]
    pub dry_run: bool,
    #[arg(short, long, value_enum, default_value_t = Transport::Stdio)]
    pub transport: Transport,
    #[arg(short, long, default_value = "127.0.0.1:3344")]
    pub bind: String,
    #[arg(
        long = "auth-token",
        env = "MCP_EXEC_AUTH_TOKEN",
        help = "Optional Bearer token for authentication."
    )]
    pub auth_token: Option<String>,
    #[arg(
        short,
        long,
        help = "Enable stateful sessions (default: false).",
        env = "MCP_EXEC_STATEFUL"
    )]
    pub stateful: bool,
    #[arg(
        long = "rate-limit-rps",
        default_value = "10",
        value_parser = clap::value_parser!(u32),
        help = "Maximum requests per second (Rate Limiting)."
    )]
    pub rate_limit_rps: u32,
    #[arg(
        long = "rate-limit-burst",
        default_value = "20",
        value_parser = clap::value_parser!(u32),
        help = "Burst size for rate limiting."
    )]
    pub rate_limit_burst: u32,
    #[arg(
        long = "max-concurrent",
        default_value = "50",
        value_parser = clap::value_parser!(usize),
        help = "Maximum concurrent command executions."
    )]
    pub max_concurrent: usize,
    #[arg(
        long = "circuit-threshold",
        default_value = "10",
        value_parser = clap::value_parser!(usize),
        help = "Circuit breaker failure threshold."
    )]
    pub circuit_threshold: usize,
    #[arg(
        long = "circuit-timeout",
        default_value = "60",
        value_parser = clap::value_parser!(u64),
        help = "Circuit breaker timeout in seconds."
    )]
    pub circuit_timeout_secs: u64,
}

#[derive(Clone, Debug)]
pub struct SecurityConfig {
    pub blacklist: Arc<Vec<String>>,
    pub allow_dangerous: bool,
    pub validate_paths: bool,
    pub allow_missing_binaries: bool,
    pub base_path: Option<PathBuf>,
    pub sensitive_keys: Arc<Vec<String>>,
    pub cmd_timeout: Duration,
}

impl SecurityConfig {
    pub fn from_args(args: &Args) -> Self {
        Self {
            blacklist: Arc::new(
                args.dangerous
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect(),
            ),
            allow_dangerous: args.allow_dangerous,
            validate_paths: !args.no_validate_paths,
            allow_missing_binaries: args.allow_missing_binaries,
            base_path: args.base_path.clone(),
            sensitive_keys: Arc::new(
                args.sensitive_keys
                    .split(',')
                    .map(|s| s.trim().to_lowercase())
                    .collect(),
            ),
            cmd_timeout: Duration::from_secs(args.cmd_timeout_secs),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ServerLimits {
    pub rate_limit_rps: u32,
    pub rate_limit_burst: u32,
    pub max_concurrent: usize,
    pub circuit_threshold: usize,
    pub circuit_timeout_secs: u64,
}

impl ServerLimits {
    pub fn from_args(args: &Args) -> Self {
        Self {
            rate_limit_rps: args.rate_limit_rps,
            rate_limit_burst: args.rate_limit_burst,
            max_concurrent: args.max_concurrent,
            circuit_threshold: args.circuit_threshold,
            circuit_timeout_secs: args.circuit_timeout_secs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_display() {
        assert_eq!(Transport::Stdio.to_string(), "stdio");
        assert_eq!(Transport::StreamableHttp.to_string(), "streamable-http");
    }

    #[test]
    fn test_log_level_default() {
        assert_eq!(LogLevel::default(), LogLevel::Info);
    }

    #[test]
    fn test_args_parse_commands() {
        let args = Args::parse_from([
            "mcp-exec",
            "--cmd",
            r#"echo|"echo {message}""#,
            "--cmd",
            r#"ls|"ls {path}""#,
        ]);
        assert_eq!(args.commands.len(), 2);
        assert_eq!(args.commands[0].name, "echo");
        assert_eq!(args.commands[1].name, "ls");
    }

    #[test]
    fn test_args_default_blacklist() {
        let args = Args::parse_from(["mcp-exec", "--cmd", r#"echo|"echo {msg}""#]);
        assert!(args.dangerous.contains("rm"));
        assert!(args.dangerous.contains("sudo"));
        assert!(args.dangerous.contains("bash"));
    }

    #[test]
    fn test_args_default_values() {
        let args = Args::parse_from(["mcp-exec", "--cmd", r#"echo|"echo {msg}""#]);
        assert!(!args.allow_dangerous);
        assert!(!args.no_validate_paths);
        assert!(!args.allow_missing_binaries);
        assert!(!args.dry_run);
        assert_eq!(args.transport, Transport::Stdio);
        assert_eq!(args.bind, "127.0.0.1:3344");
        assert_eq!(args.cmd_timeout_secs, 30);
        assert_eq!(args.rate_limit_rps, 10);
        assert_eq!(args.rate_limit_burst, 20);
        assert_eq!(args.max_concurrent, 50);
    }

    #[test]
    fn test_args_custom_values() {
        let args = Args::parse_from([
            "mcp-exec",
            "--cmd",
            r#"echo|"echo {msg}""#,
            "--allow-dangerous",
            "--no-validate-paths",
            "--allow-missing-binaries",
            "--dry-run",
            "--transport",
            "streamable-http",
            "--bind",
            "0.0.0.0:8080",
            "--cmd-timeout",
            "120",
            "--log-level",
            "debug",
        ]);
        assert!(args.allow_dangerous);
        assert!(args.no_validate_paths);
        assert!(args.allow_missing_binaries);
        assert!(args.dry_run);
        assert_eq!(args.transport, Transport::StreamableHttp);
        assert_eq!(args.bind, "0.0.0.0:8080");
        assert_eq!(args.cmd_timeout_secs, 120);
        assert_eq!(args.log_level, LogLevel::Debug);
    }

    #[test]
    fn test_security_config_from_args() {
        let args = Args::parse_from([
            "mcp-exec",
            "--cmd",
            r#"echo|"echo {msg}""#,
            "--allow-dangerous",
            "--no-validate-paths",
            "--base-path",
            "/home/user",
            "--cmd-timeout",
            "60",
        ]);
        let config = SecurityConfig::from_args(&args);
        assert!(config.allow_dangerous);
        assert!(!config.validate_paths);
        assert_eq!(config.base_path, Some(PathBuf::from("/home/user")));
        assert_eq!(config.cmd_timeout, Duration::from_secs(60));
    }

    #[test]
    fn test_server_limits_from_args_custom() {
        let args = Args::parse_from([
            "mcp-exec",
            "--cmd",
            r#"echo|"echo {msg}""#,
            "--rate-limit-rps",
            "100",
            "--rate-limit-burst",
            "200",
            "--max-concurrent",
            "75",
            "--circuit-threshold",
            "20",
            "--circuit-timeout",
            "180",
        ]);
        let limits = ServerLimits::from_args(&args);
        assert_eq!(limits.rate_limit_rps, 100);
        assert_eq!(limits.rate_limit_burst, 200);
        assert_eq!(limits.max_concurrent, 75);
        assert_eq!(limits.circuit_threshold, 20);
        assert_eq!(limits.circuit_timeout_secs, 180);
    }

    #[test]
    fn test_sensitive_keys_default() {
        let args = Args::parse_from(["mcp-exec", "--cmd", r#"echo|"echo {msg}""#]);
        let config = SecurityConfig::from_args(&args);
        assert!(config.sensitive_keys.contains(&"password".to_string()));
        assert!(config.sensitive_keys.contains(&"token".to_string()));
        assert!(config.sensitive_keys.contains(&"secret".to_string()));
    }

    #[test]
    fn test_blacklist_parsing() {
        let args = Args::parse_from([
            "mcp-exec",
            "--cmd",
            r#"echo|"echo {msg}""#,
            "--blacklist",
            "custom1,custom2,custom3",
        ]);
        let config = SecurityConfig::from_args(&args);
        assert!(config.blacklist.contains(&"custom1".to_string()));
        assert!(config.blacklist.contains(&"custom2".to_string()));
        assert!(config.blacklist.contains(&"custom3".to_string()));
    }

    #[test]
    fn test_blacklist_whitespace_trimmed() {
        let args = Args::parse_from([
            "mcp-exec",
            "--cmd",
            r#"echo|"echo {msg}""#,
            "--blacklist",
            "cmd1, cmd2 , cmd3",
        ]);
        let config = SecurityConfig::from_args(&args);
        assert!(config.blacklist.contains(&"cmd1".to_string()));
        assert!(config.blacklist.contains(&"cmd2".to_string()));
        assert!(config.blacklist.contains(&"cmd3".to_string()));
    }
}
