use std::path::PathBuf;

use std::process::ExitCode;
use ziplock::{dns, proxy, sandbox};

use anyhow::{Context, Result, bail};
use clap::Parser;
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use tracing::{info, warn};

/// Default log file location: ~/.claude/ziplock.log
fn log_path() -> PathBuf {
    std::env::var_os("HOME")
        .map(|h| PathBuf::from(h).join(".claude").join("ziplock.log"))
        .unwrap_or_else(|| PathBuf::from("/tmp/ziplock.log"))
}

#[derive(Parser)]
#[command(
    name = "ziplock",
    about = "Safe --dangerously-skip-permissions for Claude Code",
    after_help = "All arguments after -- are passed to claude."
)]
struct Cli {
    /// Additional writable paths beyond CWD (repeatable)
    #[arg(long = "allow-path", value_name = "PATH")]
    allow_paths: Vec<PathBuf>,

    /// Skip DNS filtering, only sandbox filesystem
    #[arg(long = "allow-network")]
    allow_network: bool,

    /// Show sandbox/proxy activity
    #[arg(short, long)]
    verbose: bool,

    /// Arguments to pass to claude
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    claude_args: Vec<String>,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("ziplock: {e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<ExitCode> {
    let cli = Cli::parse();

    // Set up tracing — write to a file so we don't corrupt Claude's TUI on stderr
    let log_file_path = log_path();
    if let Some(parent) = log_file_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_file_path)
        .context("failed to open log file")?;

    let filter = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(filter)),
        )
        .with_target(false)
        .with_writer(std::sync::Mutex::new(log_file))
        .with_ansi(false)
        .init();

    // Pre-flight checks
    if cfg!(not(target_os = "macos")) {
        bail!("ziplock only works on macOS (requires sandbox_init)");
    }

    // Find claude binary
    let claude_path = which::which("claude").context("could not find 'claude' in PATH")?;
    info!("found claude at {}", claude_path.display());

    // Resolve paths
    let cwd = std::env::current_dir().context("could not determine CWD")?;
    let home = dirs_home().context("could not determine HOME")?;

    // Start proxy (unless --allow-network)
    let (ports, _shutdown_tx) = if !cli.allow_network {
        let resolver = dns::create_resolver()?;
        let (ports, shutdown_tx) = proxy::start(resolver).await?;
        info!(
            "proxy started: SOCKS5=127.0.0.1:{}, HTTP=127.0.0.1:{}",
            ports.socks5, ports.http
        );
        (ports, Some(shutdown_tx))
    } else {
        info!("DNS filtering disabled (--allow-network)");
        (proxy::ProxyPorts { socks5: 0, http: 0 }, None)
    };

    // Spawn claude with sandbox
    let mut child = sandbox::spawn_claude(
        &claude_path,
        &cwd,
        &home,
        &cli.claude_args,
        &cli.allow_paths,
        cli.allow_network,
        &ports,
    )?;

    let child_pid = Pid::from_raw(child.id() as i32);
    info!("claude started with PID {}", child.id());

    // Set up signal forwarding
    tokio::spawn(async move {
        signal_forward(child_pid).await;
    });

    // Wait for child to exit
    let status = tokio::task::spawn_blocking(move || child.wait())
        .await
        .context("failed to join child wait task")?
        .context("failed to wait on claude")?;

    let exit_code = status.code().unwrap_or(1) as u8;
    info!("claude exited with code {exit_code}");

    Ok(ExitCode::from(exit_code))
}

/// Forward SIGINT and SIGTERM to the child process.
async fn signal_forward(child_pid: Pid) {
    use tokio::signal::unix::{SignalKind, signal};

    let mut sigint = match signal(SignalKind::interrupt()) {
        Ok(s) => s,
        Err(e) => {
            warn!("failed to register SIGINT handler: {e}");
            return;
        }
    };
    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            warn!("failed to register SIGTERM handler: {e}");
            return;
        }
    };

    tokio::select! {
        _ = sigint.recv() => {
            info!("forwarding SIGINT to claude");
            let _ = signal::kill(child_pid, Signal::SIGINT);
        }
        _ = sigterm.recv() => {
            info!("forwarding SIGTERM to claude");
            let _ = signal::kill(child_pid, Signal::SIGTERM);
        }
    }
}

/// Get the user's home directory.
fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}
