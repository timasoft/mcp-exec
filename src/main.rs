mod config;
mod error;
mod server;
mod tool;

use crate::{
    config::{Args, LogLevel, SecurityConfig, ServerLimits, Transport},
    server::ExecServer,
    tool::{CmdTool, is_sensitive_header},
};
use axum::{
    Router,
    extract::Request,
    http::{StatusCode, header},
    middleware::{self, Next},
    response::Response,
    routing::get,
};
use clap::Parser;
use rmcp::{
    service::serve_server,
    transport::{
        IntoTransport,
        streamable_http_server::{
            session::local::LocalSessionManager,
            tower::{StreamableHttpServerConfig, StreamableHttpService},
        },
    },
};
use std::{env, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{stdin, stdout},
    signal,
};
use tokio_util::sync::CancellationToken;
use tower_http::cors::CorsLayer;
use tracing::{debug, info, warn};
use tracing_subscriber::{EnvFilter, Layer, fmt, layer::SubscriberExt, util::SubscriberInitExt};

fn init_log(level: &LogLevel) {
    let filter = match level {
        LogLevel::Trace => "debug,rmcp=trace,audit=debug,mcp_exec=debug",
        LogLevel::Debug => "info,rmcp=debug,audit=info,mcp_exec=info",
        LogLevel::Info => "info,audit=info,mcp_exec=info",
        LogLevel::Warn => "warn,mcp_exec=warn",
        LogLevel::Error => "error,mcp_exec=error",
    };
    let console = fmt::layer()
        .without_time()
        .with_target(false)
        .with_filter(EnvFilter::new(filter));
    tracing_subscriber::registry().with(console).init();
}

fn dry_run(cmds: &[crate::tool::CommandDef], args: &Args) {
    println!("Dry-run: {} tools\n", cmds.len());
    let cfg = SecurityConfig::from_args(args);
    for c in cmds {
        let mut t = CmdTool::new(c.clone(), Arc::new(cfg.clone()));
        println!(
            "Tool: {}\nTemplate: {}\nBinary: {}\nPlaceholders: {:?}",
            c.name, c.template, c.binary, c.all_placeholders
        );
        match t.check_binary_startup() {
            Ok(_) => println!("  OK"),
            Err(e) => println!("  Error: {e}"),
        }
        println!();
    }
}

async fn auth_middleware(
    expected: Option<String>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let Some(exp) = expected else {
        return Ok(next.run(req).await);
    };
    match req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        Some(h) if h.starts_with("Bearer ") && h[7..] == exp => {
            debug!("Auth OK");
            Ok(next.run(req).await)
        }
        _ => {
            warn!(target: "audit", event = "auth_fail");
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

fn build_cors() -> CorsLayer {
    use tower_http::cors::Any;
    CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any)
        .expose_headers([
            header::HeaderName::from_static("mcp-session-id"),
            header::HeaderName::from_static("mcp-resume-token"),
        ])
        .max_age(Duration::from_secs(600))
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args = Args::parse();
    init_log(&args.log_level);

    if args.commands.is_empty() {
        eprintln!("No commands. Use: --cmd 'name|\"cmd {{arg}}\"'");
        std::process::exit(1);
    }

    if args.allow_missing_binaries {
        warn!(target: "audit", event = "security_warning", flag = "allow-missing-binaries", message = "Binary resolution at startup disabled - increased runtime risk");
    }

    if args.auth_token.is_some() && env::var("MCP_EXEC_AUTH_TOKEN").is_err() {
        warn!(target: "audit", event = "security_notice", message = "Auth token passed via CLI argument. Consider using MCP_EXEC_AUTH_TOKEN env var.");
    }

    if args.dry_run {
        dry_run(&args.commands, &args);
        return Ok(());
    }

    let transport = args.transport.clone();
    let bind_str = args.bind.clone();
    let auth_tok = args.auth_token.clone();
    let stateful = args.stateful;
    let log_level = args.log_level.clone();

    info!(
        "Starting mcp-exec (transport={}, tools={}, auth={})",
        transport,
        args.commands.len(),
        if auth_tok.is_some() {
            "enabled"
        } else {
            "disabled"
        }
    );

    let sec_cfg = SecurityConfig::from_args(&args);
    let cmds = args.commands.clone();
    let cfg = sec_cfg.clone();
    let limits = ServerLimits::from_args(&args);

    let server = match ExecServer::new(cmds, cfg, &limits) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("FATAL: {e}");
            std::process::exit(1);
        }
    };

    let shutdown = CancellationToken::new();
    {
        let sh = shutdown.clone();
        tokio::spawn(async move {
            if signal::ctrl_c().await.is_ok() {
                info!("Ctrl-C");
                sh.cancel();
            }
        });
    }

    match transport {
        Transport::Stdio => {
            let io = (stdin(), stdout()).into_transport();
            let svc = serve_server(server, io).await?;
            shutdown.cancelled().await;
            svc.cancel().await?;
        }
        Transport::StreamableHttp => {
            let addr: SocketAddr = bind_str
                .parse()
                .map_err(|e| anyhow::anyhow!("Invalid bind address: {}", e))?;
            info!("HTTP server on {}", addr);

            let cfg = StreamableHttpServerConfig {
                stateful_mode: stateful,
                cancellation_token: shutdown.clone(),
                ..Default::default()
            };

            let sm = Arc::new(LocalSessionManager::default());
            let svc = StreamableHttpService::new(move || Ok(server.clone()), sm, cfg);

            let health = Router::new().route("/health", get(|| async { "OK" }));
            let mut app = Router::new().merge(health).fallback_service(svc);
            app = app.layer(build_cors());

            if auth_tok.is_some() {
                let tok = auth_tok.clone();
                app = app.layer(middleware::from_fn(move |r, n| {
                    auth_middleware(tok.clone(), r, n)
                }));
            }

            if matches!(log_level, LogLevel::Debug | LogLevel::Trace) {
                app = app.layer(middleware::from_fn(|req: Request, next: Next| async move {
                    let method = req.method().clone();
                    let uri = req.uri().clone();
                    debug!("▶▶▶ {} {}", method, uri);
                    for (n, v) in req.headers() {
                        let val = if is_sensitive_header(n.as_str()) {
                            "[REDACTED]"
                        } else {
                            v.to_str().unwrap_or("<bin>")
                        };
                        debug!("  {} : {}", n, val);
                    }
                    let resp = next.run(req).await;
                    debug!("◀◀◀ {} {}", resp.status(), uri);
                    resp
                }));
            }

            let listener = tokio::net::TcpListener::bind(addr).await?;
            info!("Listening on http://{} | Health: /health", addr);
            axum::serve(listener, app)
                .with_graceful_shutdown(async move { shutdown.cancelled().await })
                .await?;
        }
    }

    info!("Shutdown complete");
    Ok(())
}
