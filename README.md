# Ziplock

Safe `--dangerously-skip-permissions` for Claude Code.

Ziplock wraps Claude Code in two OS-level safety layers so you can run autonomously without worrying about prompt injection, malware downloads, or accidental `rm -rf /`.

## How it works

```
ziplock
  ├─ SOCKS5 + HTTP CONNECT proxy (localhost)
  │    └─ DNS via Cloudflare 1.1.1.3 (blocks malware + adult content)
  │
  └─ sandbox_init() → claude --dangerously-skip-permissions
       └─ writes restricted to CWD, /tmp, ~/.claude
       └─ reads blocked for ~/Library, /Library, /System
       └─ all network forced through localhost proxy
```

**Layer 1 — macOS Seatbelt Sandbox:** Applied via `sandbox_init()` FFI (not `sandbox-exec`). Claude can only write to the project directory, `/tmp`, and `~/.claude`. Reads to keychains, cookies, and browser data are blocked. Productivity credentials (`~/.ssh`, `~/.aws`) remain accessible.

**Layer 2 — DNS-Filtering Proxy:** SOCKS5 + HTTP CONNECT proxies resolve all DNS through Cloudflare's family DNS (1.1.1.3), which blocks known malware and adult content domains. The sandbox forces all traffic through localhost — no bypass possible. Direct connections to public IPs are also blocked.

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
| Write outside project (`rm -rf /`, modify `~/.bashrc`) | Sandbox blocks all writes outside CWD/tmp/~/.claude |
| Read keychains, cookies, browser data | Sandbox blocks reads to ~/Library, /Library, /System |
| Download malware | Cloudflare 1.1.1.3 blocks known malware domains |
| Connect to C2/phishing sites | DNS filter blocks categorized threats |
| Bypass DNS via direct IP | Proxy blocks all public IP connections |
| Bypass proxy entirely | Sandbox blocks all non-localhost network |
| Escape sandbox via child process | Sandbox inherited by all children, cannot be removed |

## Requirements

- macOS (uses `sandbox_init` API)
- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) installed and on `$PATH`

## License

MIT
