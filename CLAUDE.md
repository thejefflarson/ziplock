# Ziplock

Safe `--dangerously-skip-permissions` for Claude Code.

## What it does

Wraps Claude Code in two OS-level safety layers:
1. **macOS Seatbelt Sandbox** — writes restricted to CWD, `/private/tmp`, `/private/var/folders`, `/private/var/tmp`, Homebrew prefixes (`/opt/homebrew`, `/usr/local`), and `$HOME` excluding `~/Library`. `~/Library` carve-outs cover `Caches`, `Keychains`, `Developer`, `org.swift.swiftpm`, and CLI dev tools that store config/data directly under `~/Library` instead of via cfprefsd — helm (`Preferences/helm` write + `~/Library/helm` read+write), plus read+write for `Application Support/{go,k9s,nuclei,trunk,Ollama}` and `~/Library/Jupyter`. Reads to `~/Library`, `/Library`, `/System` are denied with carve-outs for system frameworks, `/System/Library/Fonts`, and developer tooling. `--allow-path` grants read+write to any extra path (placed after the `~/Library` deny so opt-in paths under `~/Library`, e.g. another tool's data dir, actually take effect). TMPDIR is set to `/tmp/claude.<uid>` (mode 0700, ownership-verified). Mach IPC is restricted to an explicit allowlist of ~80 services (incl. `com.apple.pasteboard.1` so copy/`pbcopy` works).
2. **DNS-Filtering Proxy** — SOCKS5 + HTTP CONNECT proxy resolving all DNS via DoH (DNS-over-HTTPS) through Cloudflare 1.1.1.3 (blocks malware + adult content). **LAN/private addresses are allowed** (enabled by default): literal private IPs connect directly, domains that resolve to private IPs are permitted (incl. split-horizon names), and LAN/mDNS/router/`/etc/hosts` names Cloudflare DoH can't resolve (NXDOMAIN, plus all `*.local`) fall back to the system resolver — accepted **only if every address is private**, so a public name can't bypass the malware filter via getaddrinfo. Still enforced: direct connections to public **literal** IPs are blocked (forcing DNS), and Cloudflare's malware/adult block (`0.0.0.0`) is rejected. IPv4 is preferred when both A and AAAA records resolve. DoH lookups are retried up to 3× (linear backoff) on transient h2 connection resets — Cloudflare periodically GOAWAYs the long-lived HTTP/2 connection, and hickory fails the in-flight query rather than reconnecting; genuine NXDOMAIN is not retried (it falls back to the system resolver). Reaching localhost/LAN dev servers, a NAS, k8s/registry, Ollama, etc. by IP or name is normal developer work, so it's allowed by default.

## Permission mode

Ziplock prefers Claude Code's **auto mode** (`--permission-mode auto`) over `--dangerously-skip-permissions`. Auto mode adds a classifier-reviewed approval layer *inside* Claude Code; ziplock's OS sandbox is the second layer.

- Default: `--permission-mode auto --allow-dangerously-skip-permissions` (starts in auto; user can Shift+Tab to bypass if their plan doesn't support auto)
- Fallback: Claude Code older than v2.1.83 automatically falls back to `--dangerously-skip-permissions`
- Opt-out: pass `--no-auto-mode` to force the legacy flag (useful for Pro/Bedrock/Vertex/Foundry plans where auto isn't available)

## Build & Run

```bash
cargo build
cargo build --release
./target/debug/ziplock                    # launches claude in sandbox
./target/debug/ziplock -v                 # verbose mode (logs to ~/.claude/ziplock.log)
./target/debug/ziplock -- -p "hello"      # pass args to claude
./target/debug/ziplock --allow-path /extra/dir   # grant read+write access to additional path
./target/debug/ziplock --dangerous-allow-network              # sandbox only, skip DNS proxy
./target/debug/ziplock --no-auto-mode                         # force --dangerously-skip-permissions (plans that block auto)
```

## Logs

Tracing output goes to `~/.claude/ziplock.log` (mode 0600; never stderr — would corrupt Claude's TUI). The file is rotated to `ziplock.log.old` when it exceeds 10 MB.

```bash
tail -f ~/.claude/ziplock.log
```

## Architecture

```
src/
├── main.rs      # CLI parsing (clap), orchestration, signal forwarding, log rotation
├── sandbox.rs   # SBPL profile generation, sandbox_init() FFI, Claude version probe for
│                #   auto-mode vs. dangerously-skip-permissions, per-uid TMPDIR, 1Password
│                #   SSH agent detection
├── proxy.rs     # SOCKS5 + HTTP CONNECT proxy with DNS filtering and IP blocking
└── dns.rs       # Hickory resolver using Cloudflare 1.1.1.3 over DoH (https-aws-lc-rs feature)
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
