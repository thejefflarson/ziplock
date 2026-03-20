# ADR 002: SBPL Profile Tuning for Claude Code

## Status
Accepted

## Context

After implementing the initial sandbox profile (ADR 001), running Claude Code inside the sandbox revealed several non-obvious requirements discovered through iterative debugging. The profile as initially designed was too restrictive in some ways and incorrectly specified in others.

## Decisions and Findings

### 1. `mach*` wildcard is not valid SBPL

`(allow mach*)` looks like it should allow all Mach IPC operations but is silently ignored by the SBPL compiler. This caused Claude Code's keychain access to fail: auth tokens are stored under the service name `"Claude Code-credentials"` in `~/Library/Keychains/login.keychain-db` and read via Mach IPC to `com.apple.SecurityServer`.

**Fix:** Enumerate mach operations explicitly:

```sbpl
(allow mach-lookup)
(allow mach-register)
(allow mach-priv-host-port)
(allow mach-priv-task-port)
(allow mach-task-name)
(allow mach-per-user-lookup)
```

**Lesson:** SBPL wildcards (`op*`) are not reliably supported. When in doubt, list operations explicitly. Silently ignored rules produce no error, making this class of bug hard to diagnose.

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

**Removed `lsopen`:** LaunchServices `lsopen` allows invoking any registered application for a file/URL type (browsers, email clients, etc.). This is a weak prompt-injection escalation path — a malicious context could instruct Claude to open a URL, triggering an external app launch. Not required for Claude Code's core operation.

**`sysctl*` → `sysctl-read`:** `sysctl*` covered both reads and writes. Claude Code only needs to query kernel parameters (architecture, OS version, CPU count). `sysctl-read` expresses the actual intent and removes write access, even though sysctl writes generally require root anyway.

## Consequences

- The write policy is home-directory-wide (minus ~/Library), which is broader than the original design intended
- `~/Library/Keychains` is readable and writable; credential names and OAuth tokens are accessible to the sandboxed process
- `--allow-path` requires the target to exist at launch time; deferred path creation is not supported
- Mach IPC is open for lookup/register/task-name without service-name filters, which allows Claude Code to reach any Mach service, not just SecurityServer
- Log output never reaches the terminal; users must check `~/.claude/ziplock.log` to see proxy/sandbox activity
