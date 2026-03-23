use crate::{
    config::{SecurityConfig, ServerLimits},
    error::{RuntimeError, StartupError},
    tool::{CmdTool, CommandDef, is_regex_placeholder, mask_sensitive_args},
};
use governor::{
    Quota, RateLimiter,
    clock::DefaultClock,
    middleware::NoOpMiddleware,
    state::{InMemoryState, direct::NotKeyed},
};
use rmcp::{
    handler::server::ServerHandler,
    model::{
        CallToolRequestParams, CallToolResult, Content, ErrorData as McpError, Implementation,
        InitializeRequestParams, InitializeResult, ListToolsResult, PaginatedRequestParams,
        ProtocolVersion, ServerCapabilities, ServerInfo, Tool,
    },
    service::{RequestContext, RoleServer},
};
use serde_json::{Map, Value, json};
use std::{
    collections::HashMap,
    env,
    num::NonZeroU32,
    sync::Arc,
    sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;
use tracing::{error, info, warn};

type RateLimiterType = RateLimiter<NotKeyed, InMemoryState, DefaultClock, NoOpMiddleware>;

pub struct CircuitBreaker {
    failure_count: AtomicUsize,
    is_open: AtomicBool,
    last_failure_elapsed: AtomicU64,
    threshold: usize,
    timeout_ms: u64,
    start_time: Instant,
}

impl CircuitBreaker {
    pub fn new(threshold: usize, timeout: Duration) -> Self {
        Self {
            failure_count: AtomicUsize::new(0),
            is_open: AtomicBool::new(false),
            last_failure_elapsed: AtomicU64::new(0),
            threshold,
            timeout_ms: timeout.as_millis() as u64,
            start_time: Instant::now(),
        }
    }

    pub fn can_execute(&self) -> bool {
        if !self.is_open.load(Ordering::Acquire) {
            return true;
        }
        let now_elapsed = self.start_time.elapsed().as_millis() as u64;
        let last_elapsed = self.last_failure_elapsed.load(Ordering::Acquire);
        if now_elapsed - last_elapsed > self.timeout_ms {
            self.is_open.store(false, Ordering::Release);
            self.failure_count.store(0, Ordering::Release);
            return true;
        }
        false
    }

    pub fn record_success(&self) {
        self.failure_count.store(0, Ordering::Release);
        self.is_open.store(false, Ordering::Release);
    }

    pub fn record_failure(&self) {
        let count = self.failure_count.fetch_add(1, Ordering::AcqRel) + 1;
        let now_elapsed = self.start_time.elapsed().as_millis() as u64;
        self.last_failure_elapsed
            .store(now_elapsed, Ordering::Release);
        if count >= self.threshold {
            self.is_open.store(true, Ordering::Release);
            warn!(
                "Circuit breaker OPENED - {} failures exceeded threshold",
                count
            );
        }
    }
}

#[derive(Clone)]
pub struct ExecServer {
    pub tools: Arc<HashMap<String, CmdTool>>,
    pub capabilities: ServerCapabilities,
    pub instructions: Option<String>,
    pub sensitive_keys: Arc<Vec<String>>,
    pub rate_limiter: Arc<RateLimiterType>,
    pub concurrency_semaphore: Arc<Semaphore>,
    pub circuit_breaker: Arc<CircuitBreaker>,
    pub concurrent_requests: Arc<AtomicUsize>,
    pub max_concurrent: usize,
}

impl ExecServer {
    pub fn new(
        mut cmds: Vec<CommandDef>,
        config: SecurityConfig,
        limits: &ServerLimits,
    ) -> Result<Self, StartupError> {
        let tc = cmds.len();
        let mut tools = HashMap::with_capacity(tc);
        let carc = Arc::new(config.clone());
        let sk = config.sensitive_keys.clone();

        for def in cmds.drain(..) {
            let mut tool = CmdTool::new(def.clone(), Arc::clone(&carc));
            tool.check_binary_startup()?;
            tools.insert(def.name.clone(), tool);
        }

        let quota = Quota::per_second(
            NonZeroU32::new(limits.rate_limit_rps)
                .ok_or_else(|| StartupError::InvalidConfig("Invalid rate limit".into()))?,
        )
        .allow_burst(
            NonZeroU32::new(limits.rate_limit_burst)
                .ok_or_else(|| StartupError::InvalidConfig("Invalid burst".into()))?,
        );

        let rl = Arc::new(RateLimiter::direct(quota));
        let cs = Arc::new(Semaphore::new(limits.max_concurrent));
        let cb = Arc::new(CircuitBreaker::new(
            limits.circuit_threshold,
            Duration::from_secs(limits.circuit_timeout_secs),
        ));

        Ok(Self {
            tools: Arc::new(tools),
            capabilities: ServerCapabilities::builder().enable_tools().build(),
            instructions: Some(format!(
                "mcp-secure-exec: {tc} command templates with security"
            )),
            sensitive_keys: sk,
            rate_limiter: rl,
            concurrency_semaphore: cs,
            circuit_breaker: cb,
            concurrent_requests: Arc::new(AtomicUsize::new(0)),
            max_concurrent: limits.max_concurrent,
        })
    }
}

impl ServerHandler for ExecServer {
    fn get_info(&self) -> ServerInfo {
        match serde_json::from_value(json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "serverInfo": { "name": env!("CARGO_PKG_NAME"), "version": env!("CARGO_PKG_VERSION") },
            "instructions": self.instructions
        })) {
            Ok(info) => info,
            Err(e) => {
                error!("Failed to create ServerInfo: {}", e);
                serde_json::from_value(json!({
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "serverInfo": { "name": "mcp-secure-exec", "version": "0.1.0" },
                    "instructions": null
                }))
                .unwrap_or_else(|fallback_err| {
                    panic!("Fallback ServerInfo must be valid: {}", fallback_err)
                })
            }
        }
    }

    async fn initialize(
        &self,
        _req: InitializeRequestParams,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, McpError> {
        let impl_ = Implementation::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        let mut result = InitializeResult::new(self.capabilities.clone());
        result.protocol_version = ProtocolVersion::V_2024_11_05;
        result.server_info = impl_;
        result.instructions = self.instructions.clone();
        Ok(result)
    }

    async fn list_tools(
        &self,
        _req: Option<PaginatedRequestParams>,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        let tools: Vec<Tool> = self
            .tools
            .values()
            .filter_map(|t| {
                t.schema().ok().map(|schema| {
                    Tool::new(
                        t.def.name.clone(),
                        format!("Template: `{}`", t.def.template),
                        schema,
                    )
                })
            })
            .collect();
        Ok(ListToolsResult::with_all_items(tools))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        if !self.circuit_breaker.can_execute() {
            warn!(target: "audit", event = "circuit_open");
            return Err(RuntimeError::CircuitOpen.into());
        }

        let cur = self.concurrent_requests.load(Ordering::Relaxed);
        if cur >= self.max_concurrent {
            warn!(target: "audit", event = "overloaded");
            return Err(RuntimeError::ServerOverloaded.into());
        }

        if self.rate_limiter.check().is_err() {
            warn!(target: "audit", event = "rate_limit");
            return Err(McpError::internal_error("Rate limit", None));
        }

        let _p = self
            .concurrency_semaphore
            .acquire()
            .await
            .map_err(|_| McpError::internal_error("Shutdown", None))?;

        self.concurrent_requests.fetch_add(1, Ordering::Relaxed);

        struct CG(Arc<AtomicUsize>);
        impl Drop for CG {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::Relaxed);
            }
        }
        let _g = CG(self.concurrent_requests.clone());

        let tool =
            self.tools.as_ref().get(&request.name[..]).ok_or_else(|| {
                McpError::invalid_params(format!("Unknown: {}", request.name), None)
            })?;

        let args: Map<String, Value> = request.arguments.unwrap_or_default();
        let params: crate::tool::DynParams = serde_json::from_value(Value::Object(args))
            .map_err(|e| McpError::invalid_params(format!("Bad args: {e}"), None))?;

        // Log with regex parameter awareness
        let logged = mask_sensitive_args(&params.values, &self.sensitive_keys);
        let regex_params: Vec<&String> = params
            .values
            .keys()
            .filter(|k| is_regex_placeholder(k))
            .collect();
        if !regex_params.is_empty() {
            info!(target: "audit", tool = %request.name, regex_params = ?regex_params, "regex parameters detected");
        }
        info!(target: "audit", tool = %request.name, args = ?logged, "invoked");

        match tool.run(&params).await {
            Ok(out) => {
                self.circuit_breaker.record_success();
                Ok(CallToolResult::success(vec![Content::text(out)]))
            }
            Err(e) => {
                self.circuit_breaker.record_failure();
                error!(target: "audit", tool = %request.name, error = %e, "failed");
                Err(e.into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{Args, SecurityConfig, ServerLimits},
        tool::parse_command_def,
    };
    use clap::Parser;
    use std::{path::PathBuf, time::Duration};

    // =============================================================================
    // Circuit Breaker Tests (Stabilized Timing)
    // =============================================================================

    #[test]
    fn test_circuit_breaker_initial_state() {
        let cb = CircuitBreaker::new(3, Duration::from_secs(60));
        assert!(cb.can_execute());
    }

    #[test]
    fn test_circuit_breaker_opens_after_threshold() {
        let cb = CircuitBreaker::new(3, Duration::from_secs(60));
        cb.record_failure();
        cb.record_failure();
        assert!(cb.can_execute());
        cb.record_failure();
        assert!(!cb.can_execute());
    }

    #[test]
    fn test_circuit_breaker_success_resets() {
        let cb = CircuitBreaker::new(3, Duration::from_secs(60));
        cb.record_failure();
        cb.record_failure();
        cb.record_success();
        assert!(cb.can_execute());
    }

    #[test]
    fn test_circuit_breaker_timeout_closes() {
        // Increased timeout margin for CI stability
        let cb = CircuitBreaker::new(2, Duration::from_millis(200));
        cb.record_failure();
        cb.record_failure();
        assert!(!cb.can_execute());
        std::thread::sleep(Duration::from_millis(250));
        assert!(cb.can_execute());
    }

    #[test]
    fn test_circuit_breaker_multiple_cycles() {
        let cb = CircuitBreaker::new(2, Duration::from_millis(100));
        // First cycle
        cb.record_failure();
        cb.record_failure();
        assert!(!cb.can_execute());
        // Wait for timeout
        std::thread::sleep(Duration::from_millis(150));
        assert!(cb.can_execute());
        // Second cycle
        cb.record_failure();
        cb.record_failure();
        assert!(!cb.can_execute());
    }

    // =============================================================================
    // Security Config Tests
    // =============================================================================

    #[test]
    fn test_security_config_default_blacklist() {
        let args = Args::parse_from(["mcp-secure-exec", "--cmd", r#"ls|"ls {path}""#]);
        let config = SecurityConfig::from_args(&args);
        assert!(config.blacklist.contains(&"rm".to_string()));
        assert!(config.blacklist.contains(&"dd".to_string()));
        assert!(config.blacklist.contains(&"sudo".to_string()));
    }

    #[test]
    fn test_security_config_allow_dangerous() {
        let args = Args::parse_from([
            "mcp-secure-exec",
            "--cmd",
            r#"ls|"ls {path}""#,
            "--allow-dangerous",
        ]);
        let config = SecurityConfig::from_args(&args);
        assert!(config.allow_dangerous);
    }

    #[test]
    fn test_security_config_no_validate_paths() {
        let args = Args::parse_from([
            "mcp-secure-exec",
            "--cmd",
            r#"ls|"ls {path}""#,
            "--no-validate-paths",
        ]);
        let config = SecurityConfig::from_args(&args);
        assert!(!config.validate_paths);
    }

    #[test]
    fn test_security_config_base_path() {
        let args = Args::parse_from([
            "mcp-secure-exec",
            "--cmd",
            r#"ls|"ls {path}""#,
            "--base-path",
            "/safe/dir",
        ]);
        let config = SecurityConfig::from_args(&args);
        assert_eq!(config.base_path, Some(PathBuf::from("/safe/dir")));
    }

    #[test]
    fn test_security_config_cmd_timeout() {
        let args = Args::parse_from([
            "mcp-secure-exec",
            "--cmd",
            r#"ls|"ls {path}""#,
            "--cmd-timeout",
            "60",
        ]);
        let config = SecurityConfig::from_args(&args);
        assert_eq!(config.cmd_timeout, Duration::from_secs(60));
    }

    #[test]
    fn test_security_config_sensitive_keys() {
        let args = Args::parse_from([
            "mcp-secure-exec",
            "--cmd",
            r#"ls|"ls {path}""#,
            "--sensitive-keys",
            "password,api_key,secret",
        ]);
        let config = SecurityConfig::from_args(&args);
        assert!(config.sensitive_keys.contains(&"password".to_string()));
        assert!(config.sensitive_keys.contains(&"api_key".to_string()));
        assert!(config.sensitive_keys.contains(&"secret".to_string()));
    }

    // =============================================================================
    // Server Limits Tests
    // =============================================================================

    #[test]
    fn test_server_limits_from_args() {
        let args = Args::parse_from([
            "mcp-secure-exec",
            "--cmd",
            r#"ls|"ls {path}""#,
            "--rate-limit-rps",
            "50",
            "--rate-limit-burst",
            "100",
            "--max-concurrent",
            "25",
            "--circuit-threshold",
            "15",
            "--circuit-timeout",
            "120",
        ]);
        let limits = ServerLimits::from_args(&args);
        assert_eq!(limits.rate_limit_rps, 50);
        assert_eq!(limits.rate_limit_burst, 100);
        assert_eq!(limits.max_concurrent, 25);
        assert_eq!(limits.circuit_threshold, 15);
        assert_eq!(limits.circuit_timeout_secs, 120);
    }

    #[test]
    fn test_server_limits_default_values() {
        let args = Args::parse_from(["mcp-secure-exec", "--cmd", r#"ls|"ls {path}""#]);
        let limits = ServerLimits::from_args(&args);
        assert_eq!(limits.rate_limit_rps, 10);
        assert_eq!(limits.rate_limit_burst, 20);
        assert_eq!(limits.max_concurrent, 50);
        assert_eq!(limits.circuit_threshold, 10);
        assert_eq!(limits.circuit_timeout_secs, 60);
    }

    // =============================================================================
    // ExecServer Tests
    // =============================================================================

    #[test]
    fn test_exec_server_new_success() {
        let cmds = vec![parse_command_def(r#"echo|"echo {message}""#).unwrap()];
        let config = SecurityConfig::from_args(&Args::parse_from([
            "mcp-secure-exec",
            "--cmd",
            r#"echo|"echo {message}""#,
            "--allow-missing-binaries",
        ]));
        let limits = ServerLimits::from_args(&Args::parse_from([
            "mcp-secure-exec",
            "--cmd",
            r#"echo|"echo {message}""#,
        ]));
        let result = ExecServer::new(cmds, config, &limits);
        assert!(result.is_ok());
        let server = result.unwrap();
        assert_eq!(server.tools.len(), 1);
        assert!(server.tools.contains_key("echo"));
    }

    #[test]
    fn test_exec_server_new_blacklisted_binary() {
        let cmds = vec![parse_command_def(r#"rm|"rm {path}""#).unwrap()];
        let config = SecurityConfig::from_args(&Args::parse_from([
            "mcp-secure-exec",
            "--cmd",
            r#"rm|"rm {path}""#,
        ]));
        let limits = ServerLimits::from_args(&Args::parse_from([
            "mcp-secure-exec",
            "--cmd",
            r#"rm|"rm {path}""#,
        ]));
        let result = ExecServer::new(cmds, config, &limits);
        assert!(result.is_err());
    }

    #[test]
    fn test_exec_server_new_blacklisted_allowed() {
        let cmds = vec![parse_command_def(r#"rm|"rm {path}""#).unwrap()];
        let config = SecurityConfig::from_args(&Args::parse_from([
            "mcp-secure-exec",
            "--cmd",
            r#"rm|"rm {path}""#,
            "--allow-dangerous",
            "--allow-missing-binaries",
        ]));
        let limits = ServerLimits::from_args(&Args::parse_from([
            "mcp-secure-exec",
            "--cmd",
            r#"rm|"rm {path}""#,
        ]));
        let result = ExecServer::new(cmds, config, &limits);
        // With allow-missing-binaries, this should succeed even if binary doesn't exist
        assert!(result.is_ok());
    }

    #[test]
    fn test_exec_server_multiple_tools() {
        let cmds = vec![
            parse_command_def(r#"echo|"echo {message}""#).unwrap(),
            parse_command_def(r#"cat|"cat {path}""#).unwrap(),
            parse_command_def(r#"wc|"wc {file}""#).unwrap(),
        ];
        let config = SecurityConfig::from_args(&Args::parse_from([
            "mcp-secure-exec",
            "--cmd",
            r#"echo|"echo {message}""#,
            "--cmd",
            r#"cat|"cat {path}""#,
            "--cmd",
            r#"wc|"wc {file}""#,
            "--allow-missing-binaries",
        ]));
        let limits = ServerLimits::from_args(&Args::parse_from([
            "mcp-secure-exec",
            "--cmd",
            r#"echo|"echo {message}""#,
        ]));
        let result = ExecServer::new(cmds, config, &limits);
        assert!(result.is_ok());
        let server = result.unwrap();
        assert_eq!(server.tools.len(), 3);
    }

    #[test]
    fn test_exec_server_get_info() {
        let cmds = vec![parse_command_def(r#"echo|"echo {message}""#).unwrap()];
        let config = SecurityConfig::from_args(&Args::parse_from([
            "mcp-secure-exec",
            "--cmd",
            r#"echo|"echo {message}""#,
            "--allow-missing-binaries",
        ]));
        let limits = ServerLimits::from_args(&Args::parse_from([
            "mcp-secure-exec",
            "--cmd",
            r#"echo|"echo {message}""#,
        ]));
        let server = ExecServer::new(cmds, config, &limits).unwrap();
        let info = server.get_info();
        assert_eq!(info.server_info.name, "mcp-secure-exec");
    }

    // =============================================================================
    // Rate Limiter Tests
    // =============================================================================

    #[tokio::test]
    async fn test_rate_limiter_basic() {
        let quota =
            Quota::per_second(NonZeroU32::new(5).unwrap()).allow_burst(NonZeroU32::new(5).unwrap());
        let limiter = Arc::new(RateLimiter::direct(quota));

        // Should allow first 5 requests
        for _ in 0..5 {
            assert!(limiter.check().is_ok());
        }
        // 6th should be rate limited
        assert!(limiter.check().is_err());
    }

    // =============================================================================
    // Concurrency Tests
    // =============================================================================

    #[test]
    fn test_concurrent_requests_counter() {
        let counter = Arc::new(AtomicUsize::new(0));
        counter.fetch_add(1, Ordering::Relaxed);
        assert_eq!(counter.load(Ordering::Relaxed), 1);
        counter.fetch_add(1, Ordering::Relaxed);
        assert_eq!(counter.load(Ordering::Relaxed), 2);
        counter.fetch_sub(1, Ordering::Relaxed);
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    // =============================================================================
    // Error Conversion Tests
    // =============================================================================

    #[test]
    fn test_runtime_error_to_mcp_error() {
        use crate::error::RuntimeError;
        let err = RuntimeError::MissingParam("test".to_string());
        let mcp_err: McpError = err.into();
        assert!(mcp_err.to_string().contains("Missing parameter"));
    }

    #[test]
    fn test_startup_error_to_mcp_error() {
        use crate::error::StartupError;
        let err = StartupError::BinaryNotFound("ls".to_string(), "list".to_string());
        let mcp_err: McpError = err.into();
        assert!(mcp_err.to_string().contains("not found"));
    }
}
