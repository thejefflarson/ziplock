# ADR 002: SBPL Profile Tuning for Claude Code

## Status
Accepted

## Context

After implementing the initial sandbox profile (ADR 001), running Claude Code inside the sandbox revealed several non-obvious requirements discovered through iterative debugging. The profile as initially designed was too restrictive in some ways and incorrectly specified in others.

## Decisions and Findings

### 1. Bare `(allow mach-lookup)` replaced by explicit allowlist

`(allow mach*)` is valid SBPL and does take effect, but bare `(allow mach-lookup)` exposes every Mach bootstrap service on the system (~500+ on a typical macOS install) as a potential pivot point for sandbox escape. See finding 12 for the full security rationale and the explicit allowlist.

The initial profile used bare `(allow mach-lookup)` and explicit mach operation rules:

```sbpl
(allow mach-lookup)
(allow mach-register)
(allow mach-task-name)
(allow mach-per-user-lookup)
```

This was replaced with a scoped `(allow mach-lookup (global-name "...") ...)` allowlist targeting only the ~80 services Claude Code and developer tools actually need.

### 2. File writes must cover the entire home directory

The initial write allowlist (CWD, /tmp, ~/.claude, ~/.local/share/claude) caused a hang on startup. Claude Code's bundled LSP plugins (rust-analyzer, typescript-language-server, swift-lsp) write to various locations throughout `$HOME` at startup.

**Fix:** Allow writes to all of `$HOME` and deny the sensitive subtree afterward:

```sbpl
(allow file-write*
    (subpath "{cwd}")
    (subpath "{home}")
    (subpath "/tmp")
    (subpath "/private/tmp")
    (subpath "/private/var")
    (subpath "/var"))
(deny file-write*
    (subpath "{home}/Library"))
```

**Tradeoff:** This is broader than ideal but necessary for real-world usability. The deny on `~/Library` still protects cookies and browser data. `~/Library/Keychains` is explicitly carved out (see finding 7 below).

`~/Library/Caches` is re-allowed after the deny (SBPL last-match-wins) for both reads and writes. Build tools — Go module cache, npm, pip, Homebrew, Xcode derived data — store data there and will fail or hang without it.

### 3. `(with report)` is not supported on all macOS versions

Attempting to add `(deny default (with report))` for sandbox violation logging fails with:

```
sandbox compile: report modifier does not apply to deny action
```

The `(with report)` modifier is unsupported on the user's macOS version. Sandbox violations can still be observed via `log stream --predicate 'subsystem == "com.apple.sandbox"'`.

### 5. Tracing writes to a file, not stderr

`tracing_subscriber` is configured with a `Mutex<File>` writer targeting `~/.claude/ziplock.log`. Writing to stderr corrupted Claude Code's TUI (which owns the terminal in raw mode). The log path falls back to `/tmp/ziplock.log` if `$HOME` is unset.

Verbose output (`-v` / `RUST_LOG=debug`) goes to the same file. Users can tail it with `tail -f ~/.claude/ziplock.log`.

### 6. Debug escape hatches were removed

Early development included `--no-sandbox` (skip `sandbox_init` entirely) and `--permissive` (`(allow default)` with targeted denies) flags. These were removed before the first public release to avoid providing an easy bypass vector. Sandbox violations can be diagnosed with:

```
log stream --predicate 'subsystem == "com.apple.sandbox"'
```

### 7. `~/Library/Keychains` read carve-out

The initial profile denied all reads under `~/Library`. This blocked developer tools — notably `gh` (GitHub CLI) — that retrieve tokens via the macOS Keychain API. The Keychain API sends Mach IPC to `com.apple.SecurityServer`, which reads the keychain database files under `~/Library/Keychains` from its own (unsandboxed) process. However, the Security framework in the client process also reads metadata from that path directly.

**Decision:** Add `~/Library/Keychains` as a file-read carve-out. This is a deliberate trade-off: it allows Claude Code to enumerate credential names stored in the login keychain, but actual secret values are only accessible via the Security framework through `com.apple.SecurityServer` Mach IPC (which is already allowed by the broad `mach-lookup` rule). The alternative — blocking keychain access entirely — breaks too many developer tools to be practical.

**What remains blocked:** Writes to `~/Library/Keychains` are still denied (covered by the `~/Library` write deny rule with no carve-out), so Claude cannot create or modify keychain entries.

### 10. `codesign` ancestor-directory check requires `~/Library` literal carve-out

`codesign --sign -` (ad-hoc signing) is used by xcodebuild for every binary it produces. Before signing, codesign (via AMFI — AppleMobileFileIntegrity) internally calls `sandbox_check(getpid(), op, SANDBOX_FILTER_PATH, path)` on **every ancestor directory** of the file being signed, checking both `file-read-data` and `file-write-data`. If any ancestor returns DENY for either operation, codesign exits with "Operation not permitted" — even if the target file itself has full read/write permission.

The problematic ancestor: `~/Library`. Because the profile has `(deny file-read/write* (subpath "~/Library"))`, the `~/Library` directory itself (not just its contents) appears as DENY to `sandbox_check()`. This causes codesign to fail on ANY file under `~/Library/*` — including `~/Library/Developer/DerivedData/`, `~/Library/Caches/`, etc. — even though those subdirectories have write carve-outs.

**Diagnosis:** The key insight came from using `sandbox_check(getpid(), "file-read-data", 1, "/Users/jeff/Library")` inside a sandboxed process. The correct `SANDBOX_FILTER_PATH` type value is `1` (not `3` as commonly documented). The check returned DENY for `~/Library` while `/tmp` and `~/Desktop` returned ALLOW — exactly matching the set of paths where codesign failed vs. succeeded.

**Fix:** Add two rules immediately after the deny, using `literal` instead of `subpath`:
```
(allow file-read* (literal "/Users/jeff/Library"))
(allow file-write* (literal "/Users/jeff/Library"))
```
`(literal ...)` matches only the exact path, not subdirectories. This makes `~/Library` itself appear ALLOW to codesign's ancestor check, without opening up any content within `~/Library/`. The `(deny file-read/write* (subpath "~/Library"))` rule still protects all files and subdirectories within `~/Library`.

**Security:** Allowing `file-read-data` and `file-write-data` on the `~/Library` directory entry means a process can `open("~/Library", O_RDONLY)` and `readdir()` to list `~/Library`'s direct children. This is a minor information disclosure (reveals what subdirectories exist in `~/Library`) but is acceptable since several existing carve-outs (Preferences, Caches, Developer, etc.) already allow reading those subdirectory trees.

### 9. macOS 11+ firmlinks cause `/bin/cat` (and other tools) to be "not found"

On macOS 11+, `/bin`, `/usr`, and `/sbin` are [firmlinks](https://developer.apple.com/news/wwdc2019/607/) — directory-level hard links — into the sealed system snapshot at `/System/Volumes/Root`. The kernel resolves firmlinks before evaluating sandbox `(subpath ...)` rules, so:

- Process tries to exec `/bin/cat`
- Kernel resolves `/bin/cat` → `/System/Volumes/Root/bin/cat`
- Sandbox checks: is `/System/Volumes/Root/bin/cat` a subpath of `/System`? **Yes** → deny
- Shell receives ENOENT and reports `command not found: cat`

Note: it shows as "not found" (not "permission denied") because the exec fails before the file appears to exist from the shell's perspective.

**Fix:** Add `(allow file-read* process-exec ...)` carve-outs for `/bin`, `/usr/bin`, `/usr/lib`, `/usr/libexec`, `/usr/share`, `/sbin`, `/usr/sbin` — placed after the `/System` deny rule so they win via SBPL last-match-wins semantics.

**Lesson:** The broad `(deny file-read* (subpath "/System"))` rule is dangerous on macOS 11+ because most standard Unix tooling lives in firmlinked paths that resolve into `/System/Volumes/Root`. Always add explicit carve-outs for the standard binary trees.

### 8. `--allow-path` symlink canonicalization

Paths supplied via `--allow-path` are interpolated directly into the SBPL profile as `(subpath ...)` rules. If a user passes a symlink — e.g. `--allow-path /tmp/mylink` where `mylink → ~/Library` — the kernel resolves symlinks when enforcing `(subpath ...)`, meaning the real target would become writable, bypassing the `~/Library` deny rule.

**Fix:** Call `std::fs::canonicalize()` on each `--allow-path` argument before insertion into the profile. Paths that do not exist on disk are rejected with a clear error message, since a non-existent path has no symlink to resolve and granting write access to it is almost certainly a mistake.

### 11. Security review — minimal-privilege tightening

A formal security review identified four areas where the profile granted more than the minimum required:

**`/private/var` → `/private/var/folders`:** The original write rule `(subpath "/private/var")` covered `/private/var/db`, `/private/var/log`, etc. — system paths that are root-owned in practice but unnecessarily broad. The actual requirement is `/private/var/folders`, the per-user temp directory tree (e.g. `/private/var/folders/<hash>/<rand>/T/`). Narrowed accordingly. The redundant `/tmp` and `/var` rules (which are symlinks that the kernel resolves to `/private/tmp` and `/private/var` before SBPL matching, making those rules unreachable) were also removed.

**Removed `mach-priv-host-port` and `mach-priv-task-port`:** These grant access to host-level privilege ports — more powerful than the bootstrap service lookup that developer tools actually require. `mach-lookup`, `mach-register`, `mach-task-name`, and `mach-per-user-lookup` are sufficient for keychain, launchd, and XPC service access.

**`lsopen` — initially removed, later re-added:** The security review's original position was that LaunchServices `lsopen` gives a prompt-injected Claude a weak escalation path (open a URL → browser launches → external navigation). It was removed.

In practice two workflows needed it back:
- The `open MyApp.app` dev loop (`build → pkill → install → open`) in Swift/macOS projects.
- Claude Code's own OAuth login flow, which opens a browser to the auth URL.

`lsopen` is allowed again, with the residual risk mitigated by the DNS proxy blocking malicious domains (so "open a URL" can't reach an attacker-controlled host without first surviving Cloudflare family's categorization). Any browser launched inherits its own App Sandbox, independent of ziplock's.

**`sysctl*` → `sysctl-read`:** `sysctl*` covered both reads and writes. Claude Code only needs to query kernel parameters (architecture, OS version, CPU count). `sysctl-read` expresses the actual intent and removes write access, even though sysctl writes generally require root anyway.

**`file-clone`/`file-link` scoped to write-allowed paths:** These operations are checked independently from `file-write*` by the sandbox, so a bare `(allow file-clone)` at the end of the profile bypassed the `(deny file-write* ~/Library)` rule — allowing `clonefile()` or `link()` into `~/Library/LaunchAgents` and similar protected paths. Fixed by merging all three ops into a single `(allow file-write* file-clone file-link ...)` allow/deny/carve-out structure, which is both correct and more readable.

### 12. Mach service allowlist replaces bare `(allow mach-lookup)`

**Context:** Bare `(allow mach-lookup)` exposes every Mach bootstrap service on the system (~500+ on a typical macOS install) as a potential pivot point for sandbox escape. The entire class of macOS Mach IPC privilege escalation CVEs — CVE-2018-4280 (blanket), CVE-2025-31258, Google Project Zero CVE-2024-54529, and the 10+ vulnerabilities found in [jhftss's 2024 research](https://jhftss.github.io/A-New-Era-of-macOS-Sandbox-Escapes/) — follow the same pattern:

1. Sandboxed process calls `bootstrap_lookup()` to reach a privileged service
2. The service has a vulnerability in its message handler
3. The crafted Mach message triggers privilege escalation or sandbox escape

Apple's own App Store sandbox (application.sb) uses an explicit `(allow mach-lookup (global-name "...") ...)` allowlist. Apple's own developer tool sandboxes (Xcode playground.sb on all platforms) use bare `(allow mach-lookup)` — they gave up on filtering for developer toolchains. ziplock takes the middle path: an explicit allowlist tuned to Claude Code and iOS/macOS development workflows.

**Research methodology:**
- Extracted all `global-name` entries from `/System/Library/Sandbox/Profiles/application.sb` (~120 services — the App Store baseline)
- Extracted mach services from `/System/Library/Sandbox/Profiles/appsandbox-common.sb`, `com.apple.mtlcompilerservice.sb`, and `IconServices/framework.sb`
- Extracted the embedded SwiftPM manifest sandbox from the `swift-package` binary (only 2 services: `lsd.mapdb` and `mobileassetd.v2`)
- Cross-referenced with the ~500 registered services visible via `launchctl list`
- Validated the allowlist by running the full test suite including the xcodebuild/DerivedData integration test under the real sandbox

**Services excluded (attack surface reduction):**
The ~70 excluded services include everything that Claude Code, as a CLI/TUI tool, has no reason to reach:
- Window server / CoreAnimation (`windowserver.active`, `CARenderServer`, `dock.server`, `windowmanager.*`, `frontboard.*`)
- Bluetooth (`BluetoothServices`, `server.bluetooth.*`)
- Siri / speech recognition (`assistant.*`, `speechArbitrationServer`)
- iCloud sync (`bird`, `kvsd`, `syncdefaultsd`)
- Media services (`mediaremoted.xpc`, `midiserver`, `replayd`)
- Phone / FaceTime / call services (`telephonyutilities.*`, `PurplePPTServer`)
- Photos / Maps (`photos.service`, `geoanalyticsd`)
- Screen capture (`screencapture.interactive`)

These are precisely the service categories that appear most frequently in published Mach IPC CVE exploitation chains.

**Services included (minimum required):**

| Category | Key services | Why needed |
|----------|-------------|------------|
| Core OS | `cfprefsd.*`, `distributed_notifications@*`, `logd`, `logd.events`, `FSEvents` | NSUserDefaults, framework delivery, logging, file watching, build log streaming |
| Security | `SecurityServer`, `securityd.xpc`, `ocspd`, `TrustEvaluationAgent`, `trustd.agent`, `tccd`, `security.syspolicy.exec` | Keychain (OAuth tokens), TLS cert validation, TCC checks, Gatekeeper/codesign policy |
| Directory | `opendirectoryd.*`, `DirectoryService.membership_v1`, `bsd.dirhelper` | `getpwuid()`, `NSUserName()`, group membership, per-user temp directory setup |
| Launch Services | `CoreServices.coreservicesd`, `lsd.mapdb`, `lookupd` | codesign, xcodebuild path resolution |
| Network | `configd`, `DNSConfiguration`, `nehelper` | curl, git, npm network stack |
| Fonts | `fonts`, `FontObjectsServer` | Terminal rendering |
| Developer tools | `mobileassetd.v2`, `iconservices`, `containermanagerd`, `cvmsServ`, `pluginkit.pkd` | Swift Package Manager, asset catalogs, Metal compiler, Xcode extensions |
| Simulator / device | `CoreSimulator.CoreSimulatorService`, `CoreSimulator.simdiskimaged`, `CoreSimulator.SimLaunchHost-arm64`, `CoreDevice.CoreDeviceService` | iOS/tvOS/watchOS simulator lifecycle, runtime disk images, arm64 app launch, physical device deployment (Xcode 15+) |
| Build system | `PowerManagement.control`, `backupd.sandbox.xpc` | Build activity power assertions, Time Machine exclusion of DerivedData |
| Diagnostics | `analyticsd`, `diagnosticd`, `spindump` | Apple framework requirements, xcodebuild hang detection |

**Intentional denies — blocked by design:**

Two services were confirmed to be requested by xcodebuild child processes but are intentionally not added:

- **`com.apple.pasteboard.1`** — Clipboard read/write service. Allowing this would let a prompt-injected Claude read the user's clipboard (credential exfiltration) or write to it (poisoning). The requesting process was `2.1.81` (the Claude Code Bun binary version number embedded in the process name). Claude Code does not need clipboard access for any build workflow.

- **`com.apple.lsd.modifydb`** — LaunchServices database write endpoint. `lsregister` (spawned by xcodebuild) uses this to register newly-built app bundles with the system. Allowing it would let Claude register arbitrary file type handlers or override app associations — a prompt injection could use this to hijack what application opens `.pdf`, `.url`, or any other file type. `com.apple.lsd.mapdb` (read-only lookup, already in the allowlist) is sufficient for codesign and path resolution.

**Maintaining the allowlist:** If a new tool or workflow fails with a silent hang or `EPERM` from a framework call, add the missing service with a comment explaining why. The diagnostic tool is:
```bash
# In a separate terminal (requires sudo for full sandbox log access):
sudo log stream --predicate 'eventMessage CONTAINS "deny mach-lookup"'
```
Then reproduce the failure and look for the blocked service name. Before adding any new service, consider whether the deny is a feature (pasteboard, lsd.modifydb) rather than a bug.

## Consequences

- The write policy is home-directory-wide (minus ~/Library), which is broader than the original design intended
- `~/Library/Keychains` is readable and writable; credential names and OAuth tokens are accessible to the sandboxed process
- `--allow-path` requires the target to exist at launch time; deferred path creation is not supported
- Mach IPC is restricted to an explicit service allowlist (~80 allowed, ~70 GUI/media/sync services unreachable); two services (`pasteboard.1`, `lsd.modifydb`) are intentional denies that block clipboard access and LaunchServices database writes
- Log output never reaches the terminal; users must check `~/.claude/ziplock.log` to see proxy/sandbox activity
