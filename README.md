# mcp-exec

Secure MCP server for executing user-defined shell commands via templates.

## Overview

`mcp-exec` is a robust Model Context Protocol (MCP) server designed to safely expose shell command functionality to AI clients. It bridges the gap between LLMs and system operations by enforcing strict security policies, input validation, and execution limits. The server supports multiple transport layers, allowing integration via standard input/output or modern HTTP streams.

## Data Access Modes

The server supports two primary transport mechanisms for MCP communication:

1. **Stdio**: Ideal for local integrations and piping within existing workflows.
2. **Streamable HTTP**: Suitable for remote connections, supporting stateful sessions.

## Features

- **Command Templating Engine**: Define safe command structures with named placeholders for arguments.
- **Strict Input Validation**: Prevents path traversal, shell injection, and dangerous pattern usage.
- **Multi-Transport Support**: Seamlessly switch between Stdio and Streamable HTTP transports.
- **Rate Limiting & Concurrency Control**: Protects resources with configurable request limits and concurrent execution caps.
- **Circuit Breaker Protection**: Automatically halts execution during repeated failures to prevent cascading errors.
- **Comprehensive Audit Logging**: Tracks command invocations and security events with redacted sensitive data.

## Installation

### Docker Compose Integration

```yaml
services:
  mcp-exec:
    image: timasoft/mcp-exec:0.1.0
    container_name: mcp-exec
    restart: unless-stopped
    environment:
      - MCP_EXEC_COMMANDS=echo|"echo {message}"
      - MCP_EXEC_TRANSPORT=stdio
      - MCP_EXEC_LOG_LEVEL=info
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp
```

**Important notes about configuration:**

- **Security Context**: Always run with `no-new-privileges` and read-only filesystem where possible.
- **Command Definition**: Commands must be defined via environment variables or CLI arguments; no commands are allowed by default.
- **Network Binding**: When using HTTP transport, ensure the bind address is restricted to localhost unless explicitly needed.
- **Sensitive Data**: Use `MCP_EXEC_SENSITIVE_KEYS` to ensure secrets are not logged in plain text.

Make sure to:
1. Define at least one command template using `MCP_EXEC_COMMANDS`.
2. Set the appropriate transport mode for your client integration.
3. Verify binary availability within the container environment.

After adding the service, run:
```bash
docker-compose up -d
docker-compose logs -f mcp-exec
```

### Nix

If you're using Nix or NixOS, you can build and run the application directly:

**Stdio mode (local MCP client):**
```bash
nix run github:timasoft/mcp-exec -- --cmd 'echo|"echo {message}"' --cmd 'date|"date"' --transport stdio
```

**Streamable HTTP mode (remote server):**
```bash
nix run github:timasoft/mcp-exec -- --cmd 'status|"systemctl status {service}"' --transport streamable-http --bind 127.0.0.1:3344 --auth-token your_secret_token
```

**With path restrictions and security hardening:**
```bash
nix run github:timasoft/mcp-exec -- --cmd 'cat|"cat {path}"' --base-path /home/user --cmd-timeout 10 --log-level debug
```

### From Source

1. Install Rust toolchain:
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

2. Install the project:
   ```bash
   cargo install mcp-exec
   ```

3. Run the application:

   **Stdio mode (for local MCP clients like Claude Desktop):**
   ```bash
   mcp-exec --cmd 'echo|"echo {message}"' --cmd 'ls|"ls -la {path}"' --base-path /home/user
   ```

   **Streamable HTTP mode (for remote integrations):**
   ```bash
   mcp-exec --cmd 'uptime|"uptime"' --transport streamable-http --bind 0.0.0.0:3344 --auth-token secure_token
   ```

   **Environment variable configuration (recommended):**
   ```bash
   export MCP_EXEC_COMMANDS='echo|"echo {msg}"'
   export MCP_EXEC_TRANSPORT=stdio
   export MCP_EXEC_LOG_LEVEL=info
   mcp-exec
   ```

   **Dry-run validation (test configuration without starting server):**
   ```bash
   mcp-exec --cmd 'test|"echo {arg}"' --dry-run
   ```

> **Note**: To install from a local repository instead of crates.io, use:
> ```bash
> cargo install --path .
> ```
> Or for a specific git repository:
> ```bash
> cargo install --git https://github.com/timasoft/mcp-exec.git
> ```

## Configuration

### Environment Variables

All configuration options can be set via environment variables. CLI arguments take precedence over environment variables. Multiple commands can be specified using semicolon delimiter in `MCP_EXEC_COMMANDS`.

#### Command & Tool Configuration

| Variable | Description | Default |
|----------|-------------|---------|
| `MCP_EXEC_COMMANDS` | Command definitions in format `name\|"template"` (semicolon-delimited for multiple) | *Required* |
| `MCP_EXEC_DANGEROUS` | Comma-separated list of restricted binaries | `rm,dd,mkfs,chmod,chown,sudo,su,curl,wget,sh,bash,dash,zsh,python,python3,perl,ruby,node,lua,php,awk,sed,gawk,git,ssh,scp,rsync,tar,zip,unzip,gzip,bzip2,find,xargs,env,nice,timeout,strace,ltrace,ncat,netcat,nc,telnet,ftp,sftp,rbash,rsh` |
| `MCP_EXEC_ALLOW_DANGEROUS` | Allow execution of restricted binaries (`true`/`false`) | `false` |
| `MCP_EXEC_BASE_PATH` | Restrict path-like arguments to this directory | *None* |
| `MCP_EXEC_NO_VALIDATE_PATHS` | Disable path traversal protection (`true`/`false`) | `false` |
| `MCP_EXEC_ALLOW_MISSING_BINARIES` | Allow commands whose binaries are not in PATH (`true`/`false`) | `false` |

#### Security & Logging

| Variable | Description | Default |
|----------|-------------|---------|
| `MCP_EXEC_SENSITIVE_KEYS` | Comma-separated list of argument names to mask in logs | `password,token,secret,key,auth,credential` |
| `MCP_EXEC_AUTH_TOKEN` | Optional Bearer token for HTTP authentication | *None* |
| `MCP_EXEC_LOG_LEVEL` | Logging verbosity level | `info` |
| `MCP_EXEC_DRY_RUN` | Validate configuration and exit (`true`/`false`) | `false` |

#### Transport & Network

| Variable | Description | Default |
|----------|-------------|---------|
| `MCP_EXEC_TRANSPORT` | Communication protocol | `stdio` |
| `MCP_EXEC_BIND` | Network address for HTTP server | `127.0.0.1:3344` |
| `MCP_EXEC_STATEFUL` | Enable stateful sessions for HTTP transport (`true`/`false`) | `false` |

#### Performance & Limits

| Variable | Description | Default |
|----------|-------------|---------|
| `MCP_EXEC_CMD_TIMEOUT_SECS` | Maximum execution time per command in seconds | `30` |
| `MCP_EXEC_RATE_LIMIT_RPS` | Maximum requests per second | `10` |
| `MCP_EXEC_RATE_LIMIT_BURST` | Burst size for rate limiting | `20` |
| `MCP_EXEC_MAX_CONCURRENT` | Maximum concurrent command executions | `50` |
| `MCP_EXEC_CIRCUIT_THRESHOLD` | Circuit breaker failure threshold | `10` |
| `MCP_EXEC_CIRCUIT_TIMEOUT_SECS` | Circuit breaker timeout in seconds | `60` |

> **Default Security Posture**: `MCP_EXEC_DANGEROUS` includes common system utilities like `rm`, `sudo`, and shells to prevent accidental system damage.

### Command Line Arguments

```bash
Usage: mcp-exec [OPTIONS]

Options:
  -c, --cmd <NAME|"TEMPLATE">
          Define a command tool (can be repeated; use ';' separator) [env: MCP_EXEC_COMMANDS=]
  -B, --blacklist <DANGEROUS>
          Comma-separated list of blacklisted binaries. [env: MCP_EXEC_DANGEROUS=] [default: rm,dd,mkfs,chmod,chown,sudo,su,curl,wget,sh,bash,dash,zsh,python,python3,perl,ruby,node,lua,php,awk,sed,gawk,git,ssh,scp,rsync,tar,zip,unzip,gzip,bzip2,find,xargs,env,nice,timeout,strace,ltrace,ncat,netcat,nc,telnet,ftp,sftp,rbash,rsh]
  -D, --allow-dangerous
          Allow execution of blacklisted binaries. USE WITH CAUTION. [env: MCP_EXEC_ALLOW_DANGEROUS=]
      --no-validate-paths
          Disable path traversal protection for path-like placeholders. [env: MCP_EXEC_NO_VALIDATE_PATHS=]
      --allow-missing-binaries
          Allow commands whose binaries are not in PATH. [env: MCP_EXEC_ALLOW_MISSING_BINARIES=]
      --base-path <BASE_PATH>
          Restrict path-like arguments to be within this base directory. [env: MCP_EXEC_BASE_PATH=]
      --sensitive-keys <SENSITIVE_KEYS>
          Comma-separated list of argument names to mask in logs. [env: MCP_EXEC_SENSITIVE_KEYS=] [default: password,token,secret,key,auth,credential]
      --cmd-timeout <CMD_TIMEOUT_SECS>
          Maximum execution time for commands in seconds. [env: MCP_EXEC_CMD_TIMEOUT_SECS=] [default: 30]
      --log-level <LOG_LEVEL>
          [env: MCP_EXEC_LOG_LEVEL=] [default: info] [possible values: info, debug, trace, warn, error]
  -d, --dry-run
          [env: MCP_EXEC_DRY_RUN=]
  -t, --transport <TRANSPORT>
          [env: MCP_EXEC_TRANSPORT=] [default: stdio] [possible values: stdio, streamable-http]
  -b, --bind <BIND>
          [env: MCP_EXEC_BIND=] [default: 127.0.0.1:3344]
      --auth-token <AUTH_TOKEN>
          Optional Bearer token for authentication. [env: MCP_EXEC_AUTH_TOKEN=]
  -s, --stateful
          Enable stateful sessions (default: false). [env: MCP_EXEC_STATEFUL=]
      --rate-limit-rps <RATE_LIMIT_RPS>
          Maximum requests per second (Rate Limiting). [env: MCP_EXEC_RATE_LIMIT_RPS=] [default: 10]
      --rate-limit-burst <RATE_LIMIT_BURST>
          Burst size for rate limiting. [env: MCP_EXEC_RATE_LIMIT_BURST=] [default: 20]
      --max-concurrent <MAX_CONCURRENT>
          Maximum concurrent command executions. [env: MCP_EXEC_MAX_CONCURRENT=] [default: 50]
      --circuit-threshold <CIRCUIT_THRESHOLD>
          Circuit breaker failure threshold. [env: MCP_EXEC_CIRCUIT_THRESHOLD=] [default: 10]
      --circuit-timeout <CIRCUIT_TIMEOUT_SECS>
          Circuit breaker timeout in seconds. [env: MCP_EXEC_CIRCUIT_TIMEOUT_SECS=] [default: 60]
  -h, --help
          Print help
  -V, --version
          Print version
```

## Usage Examples

### Stdio Mode

**Basic Echo Tool**
```bash
mcp-exec --cmd 'echo|"echo {message}"' --log-level debug
```

**Environment Variable Configuration**
```bash
export MCP_EXEC_COMMANDS='echo|"echo {message}"'
export MCP_EXEC_LOG_LEVEL=debug
mcp-exec
```

**File Listing with Path Validation**
```bash
mcp-exec --cmd 'ls|"ls -la {path}"' --base-path /home/user
```

**Multiple Tools Configuration**
```bash
mcp-exec --cmd 'date|"date"' --cmd 'uptime|"uptime"' --transport stdio
```

OR
```bash
mcp-exec --cmd 'date|"date";uptime|"uptime"' --transport stdio
```

### Streamable HTTP Mode

**Remote Server with Authentication**
```bash
mcp-exec --cmd 'status|"systemctl status {service}"' --transport streamable-http --auth-token secure_token
```

**Environment Variable HTTP Configuration**
```bash
export MCP_EXEC_TRANSPORT=streamable-http
export MCP_EXEC_AUTH_TOKEN=my_secret_token
export MCP_EXEC_COMMANDS='status|"systemctl status {service}"'
mcp-exec
```

**Health Check Verification**
```bash
curl http://127.0.0.1:3344/health
```

### Dry-Run Validation
```bash
mcp-exec --cmd 'test|"echo {arg}"' --dry-run
```

```bash
MCP_EXEC_DRY_RUN=true MCP_EXEC_COMMANDS='test|"echo {arg}"' mcp-exec
```

## MCP Client Integration

### For Claude Desktop:
- `stdio` - Use for local subprocess execution in `claude_desktop_config.json`.
- `streamable-http` - Use for remote server connections via URL.
- `auth-token` - Required if `MCP_EXEC_AUTH_TOKEN` is set on the server.

### For IDE Extensions:
- `transport` - Ensure the client supports the selected transport protocol.
- `commands` - Verify tool names match the `--cmd` name definition exactly.

Install MCP Clients using:
```bash
npm install -g @modelcontextprotocol/inspector
```

## Architecture

`mcp-exec` follows a layered security architecture designed to isolate command execution from the MCP protocol handling.

### Stdio Transport
- Direct pipe communication between client and server.
- Minimal overhead, suitable for local agents.
- Inherits parent process environment and permissions.
- Terminates when stdin is closed.

### HTTP Transport
- Implements Streamable HTTP Server spec for MCP.
- Supports optional Bearer token authentication.
- Includes `/health` endpoint for load balancer checks.

### Core Features
- **Security Layer**: Validates arguments against injection patterns and path traversal attempts.
- **Execution Engine**: Spawns processes with timeout enforcement and output capture.
- **Rate Limiter**: Token bucket algorithm to prevent abuse.
- **Circuit Breaker**: Opens circuit after threshold failures to protect stability.
- **Audit System**: Logs all invocations with sensitive data masking.

## Troubleshooting

### Enable Debug Logging
```bash
mcp-exec --cmd 'test|"echo test"' --log-level trace
```

```bash
MCP_EXEC_LOG_LEVEL=trace mcp-exec --cmd 'test|"echo test"'
```

### Verify Binary Availability
- **Check PATH**: `which <binary>` or `echo $PATH`
- **Allow Missing**: Use `--allow-missing-binaries` for testing

### Health Check Failure
- **Verify Binding**: Ensure `--bind` address is accessible from the checker.
- **Check Logs**: Review stdout/stderr for startup errors like `FATAL: Binary not found`.
- **Firewall**: Confirm port 3344 (or custom bind) is not blocked by host firewall.

## Security

`mcp-exec` is designed with security as a primary concern. However, please note:

- Never use `--allow-dangerous` unless you fully understand the risks.
- Always use `--base-path` when exposing file operations.
- Enable `MCP_EXEC_AUTH_TOKEN` for HTTP transport.
