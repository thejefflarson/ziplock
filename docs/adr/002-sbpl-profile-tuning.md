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

**Tradeoff:** This is broader than ideal but necessary for real-world usability. The deny on `~/Library` still protects keychains, cookies, and browser data.

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

## Consequences

- The write policy is home-directory-wide (minus ~/Library), which is broader than the original design intended
- Mach IPC is fully open (`mach-lookup` etc. without service-name filters), which allows Claude Code to reach any Mach service, not just SecurityServer
- Log output never reaches the terminal; users must check `~/.claude/ziplock.log` to see proxy/sandbox activity
