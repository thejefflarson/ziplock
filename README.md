# Ziplock

Safe `--dangerously-skip-permissions` for Claude Code.

Ziplock wraps Claude Code in two OS-level safety layers so you can run autonomously without worrying about prompt injection, malware downloads, or accidental `rm -rf /`.

## How it works

```
ziplock
  ├─ SOCKS5 + HTTP CONNECT proxy (localhost)
  │    └─ DNS-over-HTTPS → Cloudflare 1.1.1.3 (blocks malware + adult content)
  │
  └─ sandbox_init() → claude --dangerously-skip-permissions
       └─ writes restricted to CWD, /tmp, $HOME (excluding ~/Library)
       └─ reads blocked for ~/Library, /Library, /System
       └─ all network forced through localhost proxy
```

**Layer 1 — macOS Seatbelt Sandbox:** Applied via `sandbox_init()` FFI (not `sandbox-exec`). Claude can write to the project directory, `/tmp`, and `$HOME` (excluding `~/Library`, except `~/Library/Caches`). The broad home write access is required for Claude Code's LSP plugins (rust-analyzer, typescript, swift) which write throughout `$HOME` at startup. Reads to `~/Library` (keychains, cookies, browser data), `/Library`, and `/System` are blocked, with carve-outs for `~/Library/Caches` and `~/Library/Preferences`. Productivity credentials (`~/.ssh`, `~/.aws`) remain accessible.

**Layer 2 — DNS-Filtering Proxy:** SOCKS5 + HTTP CONNECT proxies resolve all DNS via DNS-over-HTTPS (DoH) to Cloudflare 1.1.1.3, which blocks known malware and adult content domains. DoH encrypts queries end-to-end, preventing interception. The sandbox forces all traffic through localhost — no bypass possible. Direct connections to public IPs are also blocked.

## Install

```bash
cargo install --path .
```

## Usage

```bash
# Launch Claude Code in the sandbox
ziplock

# Pass arguments to Claude
ziplock -- -p "refactor the auth module"

# Allow writes to additional paths
ziplock --allow-path /tmp/build-output

# Skip DNS filtering (filesystem sandbox only)
ziplock --allow-network

# Verbose mode — logs proxy connections, blocked domains
ziplock -v
```

## What's protected

| Attack | Mitigation |
|--------|------------|
| Write to system or sensitive home paths (`rm -rf /`, modify `~/Library`) | Sandbox blocks writes outside CWD/tmp/$HOME and to ~/Library |
| Read keychains, cookies, browser data | Sandbox blocks reads to ~/Library, /Library, /System |
| Download malware | Cloudflare 1.1.1.3 blocks known malware domains |
| Connect to C2/phishing sites | DNS filter blocks categorized threats |
| Bypass DNS via direct IP | Proxy blocks all public IP connections |
| Bypass proxy entirely | Sandbox blocks all non-localhost network |
| Escape sandbox via child process | Sandbox inherited by all children, cannot be removed |

## Comparison

| | Ziplock | Anthropic sandbox-runtime | Claude Code `/sandbox` | Docker Sandboxes | cco |
|---|---|---|---|---|---|
| **Isolation mechanism** | macOS Seatbelt (sandbox_init FFI) | Seatbelt (sandbox-exec) / bubblewrap | Seatbelt / bubblewrap | MicroVM (hypervisor) | sandbox-exec / bubblewrap / Docker |
| **Sandbox applied by** | ziplock before exec | Claude Code itself | Claude Code itself | Docker daemon | shell wrapper |
| **Escape hatch** | None | No | Yes — Claude can retry with `dangerouslyDisableSandbox` | No | No |
| **DNS malware filtering** | Yes (Cloudflare 1.1.1.3 DoH) | No | No | No | No |
| **Direct IP blocking** | Yes (public IPs blocked) | No | No | Configurable | No |
| **Network policy** | Localhost-only + filtered proxy | Domain allowlist (user-confirmed) | Domain allowlist (user-confirmed) | Allow/deny lists | On/off |
| **Single binary** | Yes (Rust) | No (npm/Node.js) | Built-in | No (Docker daemon) | No (shell + deps) |
| **macOS support** | Yes | Yes | Yes | Yes | Yes |
| **Linux support** | No | Yes (bubblewrap) | Yes (bubblewrap) | Yes | Yes |
| **VM-level isolation** | No | No | No | Yes | No |
| **Child process inheritance** | Yes (kernel-enforced) | Yes | Yes | Yes | Yes |

The main tradeoffs: Docker Sandboxes offers stronger isolation (hypervisor boundary) but requires Docker Desktop and has startup latency. Anthropic's official `/sandbox` is built-in but has an escape hatch. Ziplock is the only option with DNS-level malware filtering.

## Requirements

- macOS (uses `sandbox_init` API)
- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) installed and on `$PATH`

## License

MIT
