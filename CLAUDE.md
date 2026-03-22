# Ziplock

Safe `--dangerously-skip-permissions` for Claude Code.

## What it does

Wraps Claude Code in two OS-level safety layers:
1. **macOS Seatbelt Sandbox** — restricts writes to CWD, /tmp, and $HOME (excluding ~/Library, except ~/Library/Caches); blocks reads to ~/Library, /Library, /System (with carve-outs for frameworks, ~/Library/Preferences, and ~/Library/Caches)
2. **DNS-Filtering Proxy** — SOCKS5 + HTTP CONNECT proxy resolving all DNS via DoH (DNS-over-HTTPS) through Cloudflare 1.1.1.3 (blocks malware + adult content)

## Build & Run

```bash
cargo build
cargo build --release
./target/debug/ziplock                    # launches claude in sandbox
./target/debug/ziplock -v                 # verbose mode (logs to ~/.claude/ziplock.log)
./target/debug/ziplock -- -p "hello"      # pass args to claude
./target/debug/ziplock --allow-path /extra/dir   # grant write access to additional path
./target/debug/ziplock --dangerous-allow-network              # sandbox only, skip DNS proxy
```

## Logs

Tracing output goes to `~/.claude/ziplock.log` (never stderr — would corrupt Claude's TUI).

```bash
tail -f ~/.claude/ziplock.log
```

## Architecture

```
src/
├── main.rs      # CLI parsing (clap), orchestration, signal forwarding
├── sandbox.rs   # SBPL profile generation, sandbox_init() FFI, 1Password SSH agent detection
├── proxy.rs     # SOCKS5 + HTTP CONNECT proxy with DNS filtering and IP blocking
└── dns.rs       # Hickory resolver using Cloudflare 1.1.1.3 over DoH (https-ring feature)
```

## Conventions

- Rust 2024 edition
- `anyhow` for error handling
- `tokio` async runtime
- `tracing` for logging (not println!)
- macOS-only (uses sandbox_init FFI)
- No `sandbox-exec` shell-out — direct FFI to `sandbox_init()`

## Testing

```bash
cargo test -- --test-threads=1    # unit + integration (fork tests need single-threaded runner)
cargo test -- --test-threads=1 --ignored   # also run tests requiring outbound network / no sandbox
cargo test --test e2e_integration -- --ignored claude_version_runs_in_sandbox
```

> **Note:** Always pass `--test-threads=1`. The sandbox integration tests use `fork()` internally;
> running them in parallel threads causes intermittent deadlocks (fork + mutex contention).

Tests marked `#[ignore]`:
- `claude_version_runs_in_sandbox` / `claude_responds_in_sandbox` — require running outside any sandbox
- `sandbox_allows_cat_and_standard_unix_tools` — spawns grandchild processes; deadlocks when run inside ziplock's own sandbox (where `already_sandboxed()` falsely returns false)
- `socks5::resolves_real_domain` — requires outbound DNS to Cloudflare

## Architecture Decision Records

`docs/adr/` documents non-obvious design choices:
- **ADR 001** — two-layer sandbox + proxy architecture
- **ADR 002** — SBPL profile tuning (mach wildcards, home-wide writes, CLAUDECODE removal, logging)
- **ADR 003** — DNS-over-HTTPS and 1Password SSH agent socket detection
