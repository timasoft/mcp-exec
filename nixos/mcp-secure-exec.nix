{ config, lib, pkgs, ... }:

let
  cfg = config.services.mcp-secure-exec;
  inherit (lib) types mkOption mkEnableOption mkIf mkMerge literalMD;

  # =============================================================================
  # Helper: Escape string for systemd ExecStart (single-quote wrapping)
  # systemd parses ExecStart similar to shell, but with its own rules.
  # Safest: wrap in single quotes, escape internal single quotes as '\''
  # =============================================================================
  escapeSystemdArg = s:
    let
      # Replace ' with '\'' (end quote, escaped quote, start quote)
      escaped = lib.replaceStrings [ "'" ] [ "'\\''" ] s;
    in
    "'${escaped}'";

  # =============================================================================
  # Escape template for --cmd argument: name|"template"
  # - Escape $ as \$ to prevent shell expansion
  # - Escape " as \" to preserve literal quotes in template
  # - Wrap entire arg in single quotes for systemd safety
  # =============================================================================
  escapeCmdArg = name: template:
    let
      # Escape $ first (before other processing)
      noDollar = lib.replaceStrings [ "$" ] [ "\\$" ] template;
      # Escape " for the inner double-quoted template
      escapedTpl = lib.replaceStrings [ "\"" ] [ "\\\"" ] noDollar;
      # Format as name|"template"
      formatted = "${name}|\"${escapedTpl}\"";
    in
    escapeSystemdArg formatted;

  # =============================================================================
  # Escape basePath for --base-path argument
  # =============================================================================
  escapePathArg = path: escapeSystemdArg (toString path);

  # =============================================================================
  # Build CLI args
  # =============================================================================
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

  # =============================================================================
  # Build --cmd arguments
  # =============================================================================
  mkCmdArgs = lib.concatMap (c: [ "--cmd" (escapeCmdArg c.name c.template) ]) cfg.commands;

  # =============================================================================
  # Auth token via env
  # =============================================================================
  mkEnvVars = mkIf (cfg.authTokenFile != null) {
    MCP_EXEC_AUTH_TOKEN = "\${file:${cfg.authTokenFile}}";
  };

  # =============================================================================
  # Filesystem access
  # =============================================================================
  mkFileSystemAccess = mkIf cfg.restrictFilesystem {
    ReadWritePaths = lib.optionals (cfg.basePath != null) [ cfg.basePath ];
  };
in
{
  options.services.mcp-secure-exec = {
    enable = mkEnableOption "Enable mcp-secure-exec MCP server service";

    package = mkOption {
      type = types.package;
      default = pkgs.mcp-secure-exec;
      defaultText = literalMD "`pkgs.mcp-secure-exec`";
      description = "The mcp-secure-exec package to use.";
    };

    commands = mkOption {
      type = types.listOf (types.submodule {
        options = {
          name = mkOption {
            type = types.strMatching "^[a-zA-Z0-9_-]+$";
            description = "Tool name (alphanumeric, underscore, dash).";
          };
          template = mkOption {
            type = types.str;
            description = ''
              Command template with {placeholder} arguments.
              Special characters ($, ", {, }, %, ') are automatically escaped for systemd.
            '';
          };
        };
      });
      default = [ ];
      example = [
        { name = "echo"; template = "echo {message}"; }
        { name = "cat"; template = "cat {path}"; }
      ];
      description = "List of command tools to register.";
    };

    transport = mkOption {
      type = types.enum [ "stdio" "streamable-http" ];
      default = "stdio";
      description = "MCP transport protocol.";
    };

    bind = mkOption {
      type = types.str;
      default = "127.0.0.1:3344";
      example = "0.0.0.0:8080";
      description = "Bind address for streamable-http transport.";
    };

    openFirewall = mkEnableOption "Open firewall ports for streamable-http transport";

    authTokenFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Path to file containing Bearer token (loaded via env).";
    };

    stateful = mkEnableOption "Enable stateful sessions for HTTP transport";

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
      description = "List of blacklisted binaries (case-insensitive).";
    };

    allowDangerous = mkEnableOption "Allow execution of blacklisted binaries (USE WITH CAUTION)";

    validatePaths = mkOption {
      type = types.bool;
      default = true;
      description = "Enable path traversal protection for {path}/{file} placeholders.";
    };

    allowMissingBinaries = mkEnableOption "Allow commands whose binaries are not in PATH at startup";

    basePath = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = ''
        Restrict path-like arguments to this directory (application-level validation only).
        Paths with spaces or special characters are automatically escaped for systemd.
        Ignored if restrictFilesystem = true.
      '';
    };

    sensitiveKeys = mkOption {
      type = types.listOf types.str;
      default = [ "password" "token" "secret" "key" "auth" "credential" ];
      description = "Argument names to mask in logs (case-insensitive).";
    };

    restrictFilesystem = mkEnableOption ''
      Delegate filesystem access control to systemd.
      If enabled: basePath is NOT passed to the binary; systemd manages read/write via ProtectSystem/ReadWritePaths.
      If disabled (default): binary runs with standard user permissions; basePath is passed for application-level validation only.
    '';

    protectHome = mkEnableOption ''
      Make /home, /root, /run/user inaccessible to the service (systemd ProtectHome=true).
      WARNING: This prevents access to user projects in /home. Disabled by default because
      MCP servers typically need to read user files. Enable only if you understand the trade-off.
    '';

    cmdTimeoutSecs = mkOption {
      type = types.ints.positive;
      default = 30;
      description = "Maximum command execution time in seconds.";
    };

    rateLimitRps = mkOption {
      type = types.ints.positive;
      default = 10;
      description = "Maximum requests per second.";
    };

    rateLimitBurst = mkOption {
      type = types.ints.positive;
      default = 20;
      description = "Burst size for rate limiting.";
    };

    maxConcurrent = mkOption {
      type = types.ints.positive;
      default = 50;
      description = "Maximum concurrent command executions.";
    };

    circuitThreshold = mkOption {
      type = types.ints.positive;
      default = 10;
      description = "Circuit breaker failure threshold.";
    };

    circuitTimeoutSecs = mkOption {
      type = types.ints.positive;
      default = 60;
      description = "Circuit breaker timeout in seconds.";
    };

    logLevel = mkOption {
      type = types.enum [ "info" "debug" "trace" "warn" "error" ];
      default = "info";
      description = "Logging verbosity level.";
    };

    dryRun = mkEnableOption "Validate configuration and exit without starting server";

    user = mkOption {
      type = types.str;
      default = "mcp-secure-exec";
      description = "User to run the service as.";
    };

    group = mkOption {
      type = types.str;
      default = "mcp-secure-exec";
      description = "Group to run the service as.";
    };

    extraGroups = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = "Additional groups for the service user.";
    };

    extraArgs = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = "Additional CLI arguments passed to mcp-secure-exec.";
    };

    serviceConfig = mkOption {
      type = types.attrs;
      default = { };
      description = "Additional systemd service options (merged with defaults).";
    };
  };

  config = mkIf cfg.enable (mkMerge [
    {
      users.users.${cfg.user} = {
        inherit (cfg) group;
        isSystemUser = true;
        createHome = false;
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

              # SystemCallFilter for async Rust (Tokio) + process spawning
              # @system-service: base set for typical services
              # @io-event: epoll, eventfd, timerfd (required by Tokio runtime)
              # @sync: futex, etc. (required for async primitives)
              # @network-io: socket operations (for streamable-http transport)
              # @process: fork, execve (required for spawning commands)
              # ~@privileged, ~@resources, ~@mount: block dangerous syscalls
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
      warnings = [ "services.mcp-secure-exec.dryRun is enabled - service will exit after validation" ];
    })

    (mkIf (cfg.restrictFilesystem && cfg.basePath == null) {
      warnings = [
        "services.mcp-secure-exec.restrictFilesystem is enabled but basePath is not set. The service will have read-only access to the entire filesystem (except /tmp). Commands requiring write access will fail unless they operate on /tmp or other naturally writable paths."
      ];
    })

    (mkIf (cfg.protectHome && cfg.basePath != null && lib.hasPrefix "/home" (toString cfg.basePath)) {
      warnings = [
        "services.mcp-secure-exec.protectHome is enabled but basePath points to ${toString cfg.basePath}. The service will NOT be able to access this path due to ProtectHome=true. Consider disabling protectHome or moving basePath outside /home."
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
