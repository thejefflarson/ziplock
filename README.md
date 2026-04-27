# Ziplock

Safe auto mode for Claude Code.

Ziplock makes auto mode safe to leave running. Even if a prompt injection slips past auto mode's classifier, the OS stops Claude from writing outside your project, reading browser cookies or app data in `~/Library`, or reaching known malware and phishing domains.

## Install

```bash
cargo install --path .
```

## Usage

```bash
ziplock                                    # launch Claude in the sandbox
ziplock -- -p "refactor the auth module"   # forward args to claude
ziplock --allow-path /tmp/build-output     # extra writable path
ziplock --dangerous-allow-network          # filesystem sandbox only, full network
ziplock --no-auto-mode                     # force --dangerously-skip-permissions
ziplock -v                                 # verbose
```

Logs go to `~/.claude/ziplock.log` (mode 0600), rotated to `.old` past 10 MB.

## How it works

```
ziplock
  ├─ SOCKS5 + HTTP CONNECT proxy (localhost)
  │    DoH → Cloudflare 1.1.1.3 (malware + adult content)
  │    IPv4 preferred; private/CGNAT/multicast/v4-mapped-v6 rejected
  │
  └─ sandbox_init() → claude --permission-mode auto --allow-dangerously-skip-permissions
       writes  → CWD, /private/{tmp,var/folders,var/tmp}, /opt/homebrew, /usr/local,
                 $HOME (less ~/Library, with carve-outs)
       reads   → block ~/Library, /Library, /System (dev-tool carve-outs)
       network → localhost only — all egress forced through the proxy
       TMPDIR  → /tmp/claude.<uid> (mode 0700, ownership-verified)
       mach    → ~80-service allowlist; pasteboard.1 and lsd.modifydb denied
```

**Permission mode.** Claude Code ≥ 2.1.83 runs with `--permission-mode auto --allow-dangerously-skip-permissions`; auto mode's classifier reviews actions, with `Shift+Tab` as a bypass. Older Claude binaries fall back to `--dangerously-skip-permissions`. Pass `--no-auto-mode` to force the legacy flag (Pro/Bedrock/Vertex/Foundry).

**`~/Library` carve-outs:**
- read+write: `Caches`, `Keychains`, `Developer`, `org.swift.swiftpm`
- read-only: `Preferences`, `Security`, `Group Containers/<1Password>` (auto-detected)
- the `~/Library` directory entry itself — `codesign` needs it readable

## Threat model

The adversary is **malicious content in Claude's context** — a prompt injection in a file, a hostile webpage, a compromised tool response. The user is trusted; ziplock protects the user from Claude.

### Blocked

| Attack | Mitigation |
|---|---|
| Overwrite system files / persist in `~/Library/LaunchAgents` | `file-write*` deny default + `~/Library` deny |
| Read browser cookies, Safari, Mail, Messages | `~/Library` read deny (only dev subtrees carved out) |
| Bypass DNS filter via raw IP | Proxy rejects literal public IPs |
| Bypass proxy via direct TCP | Sandbox restricts network to `localhost:*` |
| DNS spoofing / interception | DoH (TLS to `family.cloudflare-dns.com`) |
| SSRF to LAN/loopback (incl. v4-mapped v6, CGNAT, multicast, broadcast, class-E) | Proxy reclassifies and rejects before connect |
| DNS rebinding via mixed public+private answer | Whole lookup rejected if any address is private |
| Mach IPC sandbox escape (CVE-2018-4280 class) | ~80-service allowlist; GUI/Bluetooth/Siri/iCloud unreachable |
| Clipboard exfiltration / file-type handler hijack | `pasteboard.1`, `lsd.modifydb` not in allowlist |
| `--allow-path` symlink escape / SBPL injection | Paths canonicalized; `"`, `\`, control chars rejected |
| `/tmp/claude` symlink redirect | Per-uid TMPDIR with ownership/symlink check |
| HTTP request smuggling (CL:TE) | Conflicting `Content-Length`+`Transfer-Encoding` refused |
| Escape sandbox via child process | Inherited across `exec`; cannot be removed |

### Not blocked (accepted trade-offs)

- **Project file reads** — `~/.ssh`, `~/.aws`, `.env`, anything under `$HOME` outside `~/Library`. Distinguishing them from legitimate project access isn't feasible.
- **Keychain reads and writes** — required for Claude Code's own OAuth flow. `com.apple.SecurityServer` is in the mach allowlist, so secret *values* are accessible, not just names. Don't run with credentials you wouldn't trust the model with.
- **`signal` to user-owned processes** — required for `pkill <AppName>` in the build → kill → install → open dev loop. A prompt injection could SIGKILL your shell or editor. Cannot affect other users or escalate to root.
- **`lsopen`** — required for `open MyApp.app` and OAuth browser launch. The launched app runs under its own App Sandbox; whatever URL it points to passes through the DNS filter.
- **Docker/Podman/OrbStack daemon socket** — Unix sockets are broadly allowed for IPC. If you run a container daemon, Claude can call its API.
- **Exfiltration via uncategorized or legitimate domains** (`github.com`, `pastebin.com`, freshly registered hosts) — Cloudflare's filter is categorization-based, not an allowlist.

### Known incompatibilities

- **App-hosted `xcodebuild test`** (any target with `TEST_HOST`) hangs at "Testing started". `launchservicesd` drops the entire env dict for sandboxed callers, so the test host launches without `XCTestSessionIdentifier` and never pairs with `testmanagerd`. Run app-hosted tests outside ziplock or restructure to a library-style test bundle.
- **Xcode-managed SPM manifest evaluation** — pass `-IDEPackageSupportDisableManifestSandbox=YES` on the `xcodebuild` command line. SPM's nested sandbox-exec is already disabled via env (`XBS_DISABLE_SANDBOXED_BUILDS=1`, `SWIFTPM_SANDBOX=0`).

## Comparison

| | Ziplock | Anthropic sandbox-runtime | Claude Code `/sandbox` | Docker Sandboxes | cco |
|---|---|---|---|---|---|
| **Isolation** | Seatbelt (sandbox_init FFI) | Seatbelt / bubblewrap | Seatbelt / bubblewrap | MicroVM | sandbox-exec / bubblewrap / Docker |
| **Escape hatch** | None | No | Yes (`dangerouslyDisableSandbox`) | No | No |
| **DNS malware filter** | Yes (Cloudflare DoH) | No | No | No | No |
| **Direct IP block** | Yes | No | No | Configurable | No |
| **Network policy** | Localhost-only + filtered proxy | Domain allowlist | Domain allowlist | Allow/deny lists | On/off |
| **Single binary** | Yes (Rust) | No (Node) | Built-in | No (Docker) | No (shell) |
| **Linux** | No | Yes | Yes | Yes | Yes |
| **VM-level isolation** | No | No | No | Yes | No |

Trade-offs: Docker offers stronger isolation but needs Docker Desktop and startup latency. Anthropic's `/sandbox` is built-in but has an escape hatch. Ziplock is the only option with DNS-level malware filtering.

## Requirements

- macOS (uses `sandbox_init` API)
- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) installed and on `$PATH`

## License

MIT
