use rmcp::model::ErrorData as McpError;
use std::time::Duration;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum StartupError {
    #[error(
        "Binary '{0}' not found in PATH for command '{1}'. \
        Use --allow-missing-binaries to bypass (NOT RECOMMENDED)."
    )]
    BinaryNotFound(String, String),
    #[error(
        "SECURITY: Blacklisted binary '{0}' detected in command '{1}'.\n\
        This binary is blocked by default due to potential data loss or system compromise.\n\
        If you ABSOLUTELY trust this command and understand the risks:\n\
        1. Review the command template carefully\n\
        2. Restart with: --allow-dangerous\n\
        WARNING: Using --allow-dangerous disables critical security protections."
    )]
    BlacklistedBinary(String, String),
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
    #[error("Invalid regex pattern: {0}")]
    RegexError(String),
}

#[derive(Error, Debug)]
pub enum RuntimeError {
    #[error("Missing parameter: {0}")]
    MissingParam(String),
    #[error("Execution failed: {0}")]
    ExecutionFailed(String),
    #[error("Path traversal detected: {0}")]
    PathTraversal(String),
    #[error("Invalid argument '{0}': {1}")]
    InvalidArgument(String, String),
    #[error("Command timed out after {0:?}")]
    Timeout(Duration),
    #[error("Server overloaded - too many concurrent requests")]
    ServerOverloaded,
    #[error("Service temporarily unavailable (circuit breaker open)")]
    CircuitOpen,
}

impl From<RuntimeError> for McpError {
    fn from(err: RuntimeError) -> Self {
        match err {
            RuntimeError::ServerOverloaded | RuntimeError::CircuitOpen => {
                McpError::internal_error(err.to_string(), None)
            }
            _ => McpError::invalid_params(err.to_string(), None),
        }
    }
}

impl From<StartupError> for McpError {
    fn from(err: StartupError) -> Self {
        McpError::internal_error(err.to_string(), None)
    }
}
