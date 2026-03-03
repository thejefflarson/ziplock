# Ziplock

Safe `--dangerously-skip-permissions` for Claude Code.

## What it does

Wraps Claude Code in two OS-level safety layers:
1. **macOS Seatbelt Sandbox** — restricts writes to CWD/tmp/~/.claude, blocks reads to ~/Library, /Library, /System (with carve-outs for frameworks)
2. **DNS-Filtering Proxy** — SOCKS5 + HTTP CONNECT proxy resolving all DNS through Cloudflare 1.1.1.3 (blocks malware + adult content)

## Build & Run

```bash
cargo build
cargo build --release
./target/debug/ziplock            # launches claude in sandbox
./target/debug/ziplock -v         # verbose mode
./target/debug/ziplock -- -p "hello"  # pass args to claude
```

## Architecture

```
src/
├── main.rs      # CLI parsing (clap), orchestration, signal forwarding
├── sandbox.rs   # SBPL profile generation, sandbox_init() FFI
├── proxy.rs     # SOCKS5 + HTTP CONNECT proxy with DNS filtering
└── dns.rs       # Hickory resolver configured for Cloudflare 1.1.1.3
```

## Conventions

- Rust 2021 edition
- `anyhow` for error handling
- `tokio` async runtime
- `tracing` for logging (not println!)
- macOS-only (uses sandbox_init FFI)
- No `sandbox-exec` shell-out — direct FFI to `sandbox_init()`
