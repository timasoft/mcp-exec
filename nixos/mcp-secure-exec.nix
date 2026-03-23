{ config, lib, pkgs, ... }:

let
  cfg = config.services.mcp-secure-exec;
  inherit (lib) types mkOption mkEnableOption mkIf mkMerge literalExpression;

  # =============================================================================
  # Helper: Escape string for systemd ExecStart (single-quote wrapping)
  # systemd parses ExecStart similar to shell, but with its own rules.
  # Safest: wrap in single quotes, escape internal single quotes as '\''
  # =============================================================================
  escapeSystemdArg = s:
    let
      escaped = lib.replaceStrings [ "'" ] [ "'\\''" ] s;
    in
    "'${escaped}'";

  # =============================================================================
  # Escape template for --cmd argument: name|"template"
  # =============================================================================
  escapeCmdArg = name: template:
    let
      noDollar = lib.replaceStrings [ "$" ] [ "\\$" ] template;
      escapedTpl = lib.replaceStrings [ "\"" ] [ "\\\"" ] noDollar;
      formatted = "${name}|\"${escapedTpl}\"";
    in
    escapeSystemdArg formatted;

  escapePathArg = path: escapeSystemdArg (toString path);

  mkCliArgs = [
    "--transport" cfg.transport
  ] ++ (
    if cfg.transport == "streamable-http" then
      [ "--bind" (escapeSystemdArg cfg.bind) ]
    else
      [ ]
  ) ++ lib.optionals cfg.stateful [ "--stateful" ]
    ++ lib.optionals cfg.allowDangerous [ "--allow-dangerous" ]
    ++ lib.optionals (!cfg.validatePaths) [ "--no-validate-paths" ]
    ++ lib.optionals cfg.allowMissingBinaries [ "--allow-missing-binaries" ]
    ++ lib.optionals (cfg.basePath != null && !cfg.restrictFilesystem) [ "--base-path" (escapePathArg cfg.basePath) ]
    ++ [
      "--blacklist" (escapeSystemdArg (lib.concatStringsSep "," cfg.blacklist))
      "--sensitive-keys" (escapeSystemdArg (lib.concatStringsSep "," cfg.sensitiveKeys))
      "--cmd-timeout" (toString cfg.cmdTimeoutSecs)
      "--log-level" cfg.logLevel
      "--rate-limit-rps" (toString cfg.rateLimitRps)
      "--rate-limit-burst" (toString cfg.rateLimitBurst)
      "--max-concurrent" (toString cfg.maxConcurrent)
      "--circuit-threshold" (toString cfg.circuitThreshold)
      "--circuit-timeout" (toString cfg.circuitTimeoutSecs)
    ] ++ cfg.extraArgs;

  mkCmdArgs = lib.concatMap (c: [ "--cmd" (escapeCmdArg c.name c.template) ]) cfg.commands;

  mkEnvVars = mkIf (cfg.authTokenFile != null) {
    MCP_EXEC_AUTH_TOKEN = "\${file:${cfg.authTokenFile}}";
  };

  mkFileSystemAccess = mkIf cfg.restrictFilesystem {
    ReadWritePaths = lib.optionals (cfg.basePath != null) [ cfg.basePath ];
  };
in
{
  options.services.mcp-secure-exec = {
    enable = mkEnableOption "MCP server for secure, sandboxed command execution with template-based tool exposure.";

    package = mkOption {
      type = types.nullOr types.package;
      default = null;
      example = literalExpression "inputs.mcp-secure-exec.packages.${pkgs.system}.default";
      description = ''
        Package providing the `mcp-secure-exec` binary.

        This option is automatically populated when the module is imported
        from the mcp-secure-exec flake. Set manually only if you need to
        override the default package (e.g., custom build or alternative source).
      '';
    };

    extraPackages = mkOption {
      type = types.listOf types.package;
      default = [ ];
      example = literalExpression "with pkgs; [ bat git fd ripgrep exa ]";
      description = ''
        Additional packages to add to the service's `PATH`.

        Binaries from these packages become available for use in command templates
        without requiring absolute paths. This is the declarative way to extend
        available tools for registered commands.
      '';
    };

    commands = mkOption {
      type = types.listOf (types.submodule {
        options = {
          name = mkOption {
            type = types.strMatching "^[a-zA-Z0-9_-]+$";
            description = ''
              Identifier for the tool as exposed via MCP.

              Must be alphanumeric with underscores or dashes. This name is used
              by clients to invoke the command template.
            '';
          };
          template = mkOption {
            type = types.str;
            description = ''
              Shell command template with `{placeholder}` arguments.

              Placeholders like `{message}`, `{path}`, or `{file}` are replaced
              with client-provided values at runtime. The template is executed
              in a restricted environment with automatic escaping of special
              characters (`$`, `"`, `'`, `{`, `}`, `%`) to prevent injection.
            '';
          };
        };
      });
      default = [ ];
      example = [
        { name = "echo"; template = "echo {message}"; }
        { name = "cat"; template = "cat {path}"; }
      ];
      description = ''
        List of command tools to register with the MCP server.

        Each entry defines a parameterized command that clients can invoke.
        The actual binary must be available in `PATH` (via `extraPackages` or
        system-wide) unless `allowMissingBinaries = true`.
      '';
    };

    transport = mkOption {
      type = types.enum [ "stdio" "streamable-http" ];
      default = "stdio";
      description = ''
        MCP transport protocol.

        - `stdio`: Communicates via standard input/output. Suitable for local
          usage, e.g., when spawned by an MCP client running on the same host.
        - `streamable-http`: Listens on a TCP socket for HTTP-based MCP
          connections. Requires setting `bind` and optionally `openFirewall`.
      '';
    };

    bind = mkOption {
      type = types.str;
      default = "127.0.0.1:3344";
      example = "0.0.0.0:8080";
      description = ''
        Bind address for `streamable-http` transport.

        Format: `IP:PORT`. Use `127.0.0.1` to restrict access to localhost,
        or `0.0.0.0` to listen on all interfaces (requires firewall configuration).
      '';
    };

    openFirewall = mkEnableOption "Automatically open the TCP port specified in `bind` in the system firewall.";

    authTokenFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      example = "/var/lib/mcp-secure-exec/token";
      description = ''
        Path to a file containing a bearer token for HTTP authentication.

        When set, the token is loaded into the environment variable
        `MCP_EXEC_AUTH_TOKEN` using systemd's `${file:...}` syntax, which
        ensures the file is read at service startup with proper permissions.

        Clients must include `Authorization: Bearer <token>` in HTTP requests.
        This option is ignored for `stdio` transport.
      '';
    };

    stateful = mkEnableOption ''
      Enable stateful session tracking for `streamable-http` transport.

      When enabled, the server maintains session state across requests, which
      may be required for certain MCP client features. Disabling this (default)
      runs the server in stateless mode.
    '';

    blacklist = mkOption {
      type = types.listOf types.str;
      default = [
        "rm" "dd" "mkfs" "chmod" "chown" "sudo" "su" "curl" "wget"
        "sh" "bash" "dash" "zsh" "python" "python3" "perl" "ruby"
        "node" "lua" "php" "awk" "sed" "gawk" "git" "ssh" "scp"
        "rsync" "tar" "zip" "unzip" "gzip" "bzip2" "find" "xargs"
        "env" "nice" "timeout" "strace" "ltrace" "ncat" "netcat"
        "nc" "telnet" "ftp" "sftp" "rbash" "rsh"
      ];
      example = [ "rm" "dd" "mkfs" ];
      description = ''
        List of binary names to blacklist (case-insensitive).

        Commands whose resolved binary name matches any entry in this list
        will be rejected at runtime, unless `allowDangerous = true`.
      '';
    };

    allowDangerous = mkEnableOption "Allow execution of blacklisted binaries.";

    validatePaths = mkOption {
      type = types.bool;
      default = true;
      description = ''
        Enable application-level path traversal protection for `{path}` and `{file}` placeholders.

        When enabled (default), the binary validates that client-provided values
        for path-like placeholders do not contain `..` segments or escape the
        intended directory via absolute paths.
      '';
    };

    allowMissingBinaries = mkEnableOption ''
      Skip validation that command binaries exist in `PATH` at service startup.

      By default, the service checks that each command's binary is resolvable
      during initialization, failing fast if not. Enable this option if binaries
      may be mounted or become available later.
    '';

    basePath = mkOption {
      type = types.nullOr types.path;
      default = null;
      example = "/srv/mcp-data";
      description = ''
        Base directory for path-like arguments.

        When `restrictFilesystem = false` (default):
        - The `--base-path` flag is passed to the binary for application-level validation

        When `restrictFilesystem = true`:
        - The `--base-path` flag is NOT passed to the binary
        - This value configures systemd's `ReadWritePaths` to grant write access
      '';
    };

    sensitiveKeys = mkOption {
      type = types.listOf types.str;
      default = [ "password" "token" "secret" "key" "auth" "credential" ];
      example = [ "password" "api_key" "secret" ];
      description = ''
        Argument names to redact in logs (case-insensitive).

        When a command template includes a placeholder whose name matches
        any entry in this list, its value is masked in debug/trace logs.
      '';
    };

    restrictFilesystem = mkEnableOption ''
      Delegate filesystem access control to systemd sandboxing.

      When enabled:
      - `basePath` is NOT passed to the binary as `--base-path`
      - systemd enforces read-only access via `ProtectSystem=strict`
      - Only paths in `ReadWritePaths` (set to `basePath` if provided) are writable

      When disabled (default):
      - The service runs with standard user permissions
      - `basePath` is passed to the binary for application-level validation only
    '';

    protectHome = mkEnableOption ''
      Make `/home`, `/root`, and `/run/user` inaccessible via systemd's `ProtectHome=true`.
    '';

    cmdTimeoutSecs = mkOption {
      type = types.ints.positive;
      default = 30;
      example = 60;
      description = ''
        Maximum execution time for a single command, in seconds.

        Commands exceeding this limit are terminated with `SIGKILL`.
      '';
    };

    rateLimitRps = mkOption {
      type = types.ints.positive;
      default = 10;
      example = 50;
      description = ''
        Maximum sustained requests per second per client.

        Part of a token bucket rate limiter. Excess requests are rejected
        with HTTP 429 (for `streamable-http`) or delayed (for `stdio`).
      '';
    };

    rateLimitBurst = mkOption {
      type = types.ints.positive;
      default = 20;
      example = 100;
      description = ''
        Burst capacity for the rate limiter.

        Allows short spikes up to this many requests before enforcing the
        `rateLimitRps` limit.
      '';
    };

    maxConcurrent = mkOption {
      type = types.ints.positive;
      default = 50;
      example = 200;
      description = ''
        Maximum number of commands executed concurrently.

        Prevents resource exhaustion from parallel client requests.
      '';
    };

    circuitThreshold = mkOption {
      type = types.ints.positive;
      default = 10;
      example = 5;
      description = ''
        Number of consecutive failures before the circuit breaker opens.

        When triggered, further requests are short-circuited for
        `circuitTimeoutSecs` to allow backend recovery.
      '';
    };

    circuitTimeoutSecs = mkOption {
      type = types.ints.positive;
      default = 60;
      example = 30;
      description = ''
        Duration (in seconds) the circuit breaker remains open before
        allowing test requests to resume normal operation.
      '';
    };

    logLevel = mkOption {
      type = types.enum [ "info" "debug" "trace" "warn" "error" ];
      default = "info";
      description = ''
        Logging verbosity.

        - `error`: Only errors
        - `warn`: Warnings and errors
        - `info`: Normal operational messages (default)
        - `debug`: Detailed debugging information
        - `trace`: Extremely verbose, including argument values
      '';
    };

    dryRun = mkEnableOption ''
      Validate configuration and exit without starting the server.

      Useful for CI/CD pipelines or pre-deployment checks. When enabled,
      the service performs all startup validations and exits with code 0 on success.
    '';

    user = mkOption {
      type = types.str;
      default = "mcp-secure-exec";
      description = ''
        System user to run the service as.

        Should be an unprivileged, dedicated user. The module creates this
        user automatically with `isSystemUser = true` and no home directory.
      '';
    };

    group = mkOption {
      type = types.str;
      default = "mcp-secure-exec";
      description = ''
        System group for the service. Created automatically if it does not exist.
      '';
    };

    extraGroups = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [ "docker" "render" ];
      description = ''
        Supplementary groups to add the service user to.

        Use sparingly—each additional group expands filesystem and resource
        access. Prefer explicit `ReadWritePaths` over group-based permissions.
      '';
    };

    extraArgs = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [ "--custom-flag" "value" ];
      description = ''
        Additional CLI arguments passed directly to `mcp-secure-exec`.

        Use for experimental or advanced flags not yet exposed as module options.
        Arguments are appended after module-managed flags, allowing overrides.
      '';
    };

    serviceConfig = mkOption {
      type = types.attrs;
      default = { };
      example = literalExpression ''
        {
          LimitNOFILE = 65536;
          Environment = [ "CUSTOM_VAR=value" ];
        }
      '';
      description = ''
        Additional systemd service options to merge into the unit configuration.

        Use this to customize resource limits, environment variables, or other
        systemd directives not covered by module options. Values are merged
        with deep attribute-wise override (right-biased).
      '';
    };
  };

  config = mkIf cfg.enable (mkMerge [
    {
      assertions = [
        {
          assertion = cfg.package != null;
          message = ''
            services.mcp-secure-exec.package must be set when enable = true.
            This is normally handled automatically when importing the module
            from the mcp-secure-exec flake.
          '';
        }
      ];
    }

    {
      users.users.${cfg.user} = {
        inherit (cfg) group;
        isSystemUser = true;
        createHome = false;
        description = "System user for mcp-secure-exec service";
      };

      users.groups.${cfg.group} = { };

      systemd.services.mcp-secure-exec =
        let
          allCliArgs = mkCmdArgs ++ mkCliArgs ++ lib.optionals cfg.dryRun [ "--dry-run" ];
        in
        {
          description = "MCP server for secure command execution";
          after = [ "network.target" ];
          wants = mkIf (cfg.transport == "streamable-http") [ "network-online.target" ];
          wantedBy = [ "multi-user.target" ];

          path = cfg.extraPackages;

          environment = mkEnvVars;

          serviceConfig = mkMerge [
            {
              Type = "simple";
              User = cfg.user;
              Group = cfg.group;
              SupplementaryGroups = cfg.extraGroups;

              ExecStart = lib.concatStringsSep " " ([
                "${cfg.package}/bin/mcp-secure-exec"
              ] ++ allCliArgs);

              Restart = "on-failure";
              RestartSec = "5s";

              # Security hardening
              PrivateTmp = true;
              ProtectSystem = "strict";
              ProtectHome = cfg.protectHome;
              NoNewPrivileges = true;
              PrivateDevices = true;
              ProtectKernelTunables = true;
              ProtectKernelModules = true;
              ProtectControlGroups = true;
              RestrictRealtime = true;
              RestrictSUIDSGID = true;
              MemoryDenyWriteExecute = true;
              LockPersonality = true;

              # SystemCallFilter tailored for async Rust (Tokio) + process spawning
              SystemCallFilter = [
                "@system-service"
                "@io-event"
                "@sync"
                "@network-io"
                "@process"
                "~@privileged"
                "~@resources"
                "~@mount"
                "~@cpu-emulation"
                "~@debug"
                "~@obscure"
              ];
              SystemCallArchitectures = "native";

              StandardOutput = "journal";
              StandardError = "journal";
              SyslogIdentifier = "mcp-secure-exec";
            }
            mkFileSystemAccess
          ] // cfg.serviceConfig;
        };
    }

    (mkIf (cfg.openFirewall && cfg.transport == "streamable-http") {
      networking.firewall.allowedTCPPorts =
        let
          port = lib.last (lib.splitString ":" cfg.bind);
        in
        [ (lib.toInt port) ];
    })

    (mkIf cfg.dryRun {
      warnings = [ "services.mcp-secure-exec.dryRun is enabled - service will exit after validation without starting the server" ];
    })

    (mkIf (cfg.restrictFilesystem && cfg.basePath == null) {
      warnings = [
        ("services.mcp-secure-exec.restrictFilesystem is enabled but basePath is not set. " +
        "The service will have read-only access to the entire filesystem (except /tmp). " +
        "Commands requiring write access will fail unless they operate on /tmp or other naturally writable paths. " +
        "Consider setting basePath to a dedicated writable directory.")
      ];
    })

    (mkIf (cfg.protectHome && cfg.basePath != null && lib.hasPrefix "/home" (toString cfg.basePath)) {
      warnings = [
        ("services.mcp-secure-exec.protectHome is enabled but basePath points to ${toString cfg.basePath}. " +
        "Due to systemd's ProtectHome=true, the service will NOT be able to access this path. " +
        "Either disable protectHome, move basePath outside /home, or use a bind mount to expose a subdirectory.")
      ];
    })
  ]);

  meta.maintainers = [
    {
      name = "timasoft";
      github = "timasoft";
      email = "tima.klester@yandex.ru";
    }
  ];
}
