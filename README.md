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
       └─ writes restricted to CWD, /tmp, $HOME (excluding most of ~/Library)
       └─ reads blocked for ~/Library, /Library, /System (with developer tool carve-outs)
       └─ all network forced through localhost proxy
```

**Layer 1 — macOS Seatbelt Sandbox:** Applied via `sandbox_init()` FFI (not `sandbox-exec`). Claude can write to the project directory, `/tmp`, and `$HOME` (excluding `~/Library`, with carve-outs below). The broad home write access is required for Claude Code's LSP plugins (rust-analyzer, typescript, swift) which write throughout `$HOME` at startup. Reads to `~/Library`, `/Library`, and `/System` are blocked, with carve-outs for developer tooling. Paths passed via `--allow-path` are canonicalized before insertion into the profile, preventing symlink-based bypasses of the `~/Library` deny rule. Mach IPC (`mach-lookup`) is restricted to an explicit allowlist of ~65 named services — eliminating ~70 irrelevant GUI, media, Bluetooth, Siri, and iCloud services from the reachable attack surface. Two services (`pasteboard.1`, `lsd.modifydb`) are intentionally denied to block clipboard exfiltration and LaunchServices database writes.

Developer tool carve-outs (read + write unless noted):
- `~/Library/Caches` — build tool caches (Go, npm, pip, Homebrew, Xcode)
- `~/Library/Keychains` — Claude Code OAuth token storage
- `~/Library/Developer` — xcodebuild DerivedData, CoreSimulator, archives
- `~/Library/org.swift.swiftpm` — Swift Package Manager package cache
- `~/Library/Preferences` — read-only; app preference plists
- `~/Library/Security` — read-only; trust settings for codesign
- `~/Library` directory entry — read + write on the directory itself (not contents); required for codesign ancestor-directory checks
- `/Library/Developer`, `/Library/Keychains`, `/Library/Security`, system frameworks — read-only

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
ziplock --dangerous-allow-network

# Verbose mode — logs proxy connections, blocked domains
ziplock -v
```

## What's protected

| Attack | Mitigation |
|--------|------------|
| Write to system files (`rm -rf /`, `/etc`, `/bin`) | Sandbox blocks writes outside CWD/tmp/$HOME |
| Modify `~/Library` app data (cookies, Mail, Messages) | `file-write*` deny on `~/Library`; DerivedData/Caches/Keychains are the only write carve-outs |
| Persist malware in `~/Library/LaunchAgents` | Covered by `~/Library` write deny |
| Read browser cookies, app secrets, Safari data | Sandbox blocks reads to most of `~/Library`; only developer subtrees are accessible |
| Download malware | Cloudflare 1.1.1.3 blocks known malware domains |
| Connect to C2/phishing sites | DNS filter blocks categorized threats |
| Bypass DNS via direct IP | Proxy blocks all public IP connections |
| Bypass proxy entirely | Sandbox blocks all non-localhost network |
| Escape sandbox via child process | Sandbox inherited by all children, cannot be removed |

## Threat model

Ziplock is effective against **untargeted, opportunistic attacks** — the prompt-injection-downloads-malware class of threat. It provides meaningful friction against **targeted data exfiltration** via novel domains or raw IPs. It provides **no protection** against an adversary who uses allowed domains as exfil channels or who specifically targets in-scope credentials like `~/.ssh` private keys.

### Attacker model

The adversary is **malicious content in Claude's context** — a prompt injection in a file Claude reads, a hostile webpage it fetches, or a compromised tool response. The adversary controls what Claude *does*, not what runs on the machine before ziplock starts. The user is trusted; ziplock protects the user from Claude, not Claude from the user.

### What ziplock blocks

#### Filesystem

| Attack | Blocked by |
|---|---|
| Overwrite system files (`/etc`, `/bin`, `/usr`) | Seatbelt `file-write*` deny default |
| Corrupt other users' home dirs | Seatbelt write restricted to `$HOME` |
| Modify `~/Library` (cookies, app state, Mail, Messages) | Explicit `file-write*` deny on `~/Library` subpath |
| Persist malware in `~/Library/LaunchAgents` | Covered by `~/Library` write deny |
| Escape CWD via `--allow-path` symlink | Paths canonicalized before SBPL insertion |
| SBPL injection via crafted path argument | `"` and `\` rejected; null bytes caught by `CString` |

#### Network

| Attack | Blocked by |
|---|---|
| Download/execute malware from known C2 domain | Cloudflare 1.1.1.3 returns `0.0.0.0` |
| Connect to known phishing/malware IP via domain | DNS filter |
| Bypass DNS filter via raw public IP | Proxy rejects non-private literal IPs |
| Bypass proxy entirely (direct outbound TCP) | Sandbox restricts network to `localhost:*` |
| Intercept or spoof DNS queries | All DNS over DoH (TLS to `family.cloudflare-dns.com`) |
| DNS rebinding (domain → private IP after allow) | Resolved IP checked against `is_private_ip()` |

#### Process and IPC

| Attack | Blocked by |
|---|---|
| Spawn unsandboxed child process | Sandbox inherited across `exec` |
| Remove sandbox from a child process | Seatbelt cannot be removed once applied |
| Signal arbitrary other processes | `signal` restricted to `target same-sandbox` |
| Mach IPC sandbox escape via privileged service (CVE-2018-4280 class) | `mach-lookup` restricted to an explicit ~65-service allowlist; window server, Bluetooth, Siri, iCloud, media, and phone services are unreachable |
| Exfiltrate data via clipboard | `com.apple.pasteboard.1` is not in the mach allowlist; Claude cannot read or write the system clipboard |
| Hijack file type handlers via LaunchServices | `com.apple.lsd.modifydb` is not in the mach allowlist; Claude cannot register new app bundles or override file associations |
| LaunchServices app launch to arbitrary registered apps | `lsopen` is blocked; Claude cannot open the browser or launch any app via LaunchServices |

### What ziplock does not block

#### Accepted trade-offs

| Attack | Why not blocked |
|---|---|
| Read `~/Library/Keychains` (enumerate credential names) | Deliberate carve-out — required for `gh` and other developer tools |
| Write `~/Library/Keychains` (create/modify keychain entries) | Deliberate carve-out — Claude Code stores OAuth tokens in the login keychain |
| Read/write `~/Library/Developer` (Xcode DerivedData, CoreSimulator) | Required for xcodebuild to compile and sign Swift/ObjC projects |
| List `~/Library` directory contents | Deliberate carve-out — `codesign` checks read/write permission on every ancestor directory before signing; `~/Library` must be accessible or xcodebuild signing fails. Reveals which app folders exist in `~/Library`. |
| Read `~/.ssh` private keys | `~/.ssh` is under `$HOME`, which must be readable for Claude to work |
| Claude Code OAuth login flow broken inside sandbox | `lsopen` is blocked to prevent arbitrary app launch via LaunchServices. Authenticate before running ziplock, or run `ziplock --dangerous-allow-network` once to re-authenticate, then restart without that flag. |
| Connect to Docker/Podman/OrbStack socket and issue daemon API calls | Unix domain sockets are broadly allowed (required for mDNS, 1Password, and other IPC). Blocking specific container runtime sockets is impractical as new runtimes add new socket paths. **If you run Docker, Claude can call the Docker API.** |
| Read `~/.aws`, `~/.config`, `.env`, etc. | Same — Claude needs project file access; no way to distinguish |
| Exfiltrate to an *uncategorized* domain | DNS filter is Cloudflare's categorization list, not a whitelist |
| Exfiltrate via allowed domains (`github.com`, `pastebin.com`) | Legitimate domains are unblocked by design |
| Write anywhere in `$HOME` outside `~/Library` | Required for LSP plugins and build tools at startup |
| SPM and xcodebuild nested sandboxing bypassed | `XBS_DISABLE_SANDBOXED_BUILDS=1` and `SWIFTPM_SANDBOX=0` are set as environment variables, disabling nested sandbox-exec calls that would fail inside ziplock's SBPL profile. ziplock's sandbox still constrains all child processes. For Xcode-managed Package.swift manifest evaluation, set once manually: `defaults write com.apple.dt.Xcode IDEPackageSupportDisableManifestSandbox -bool YES` |
| App-hosted `xcodebuild test` targets not supported | When xcodebuild runs inside ziplock's sandbox, macOS `launchservicesd` refuses to pass `DYLD_INSERT_LIBRARIES` (and other env vars) to apps launched via LaunchServices. Without `DYLD_INSERT_LIBRARIES`, the XCTest framework is never injected into the test host app and the test runner never connects. Plain `bundle.unit-test` targets (no `TEST_HOST`) work fine. |

#### The keychain nuance

`~/Library/Keychains` is read **and write** accessible. Reads allow Claude Code to retrieve OAuth tokens via the Security framework. Writes allow Claude Code to store OAuth tokens in the login keychain — without this, re-authentication after sandbox profile changes would be broken. This means Claude can create new keychain entries or modify existing ones. Users who need stricter credential isolation should not run tools requiring keychain auth within Claude's scope.

Reading a keychain item's *value* also requires `SecItemCopyMatching`, which communicates with `com.apple.SecurityServer` via Mach IPC. `com.apple.SecurityServer` is in the `mach-lookup` allowlist (required for Claude Code's own OAuth token access), so this call succeeds. **Ziplock does not prevent Claude from reading keychain secret values.**

#### DNS filter limitations

- **Uncategorized domains:** A freshly registered exfiltration domain that Cloudflare hasn't categorized will resolve normally.
- **Steganographic exfiltration:** Data encoded in DNS query names (`data.attacker.com`) passes through to Cloudflare; query content is not inspected.
- **Allowed domains as exfil channels:** Claude can POST to `github.com`, `pastebin.com`, etc. — all legitimate, all unblocked.

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
