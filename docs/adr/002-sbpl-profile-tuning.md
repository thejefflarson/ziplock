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

## Consequences

- The write policy is home-directory-wide (minus ~/Library), which is broader than the original design intended
- `~/Library/Keychains` is readable; credential names (but not values) are accessible to the sandboxed process
- `--allow-path` requires the target to exist at launch time; deferred path creation is not supported
- Mach IPC is fully open (`mach-lookup` etc. without service-name filters), which allows Claude Code to reach any Mach service, not just SecurityServer
- Log output never reaches the terminal; users must check `~/.claude/ziplock.log` to see proxy/sandbox activity
