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

### 3. `CLAUDECODE` environment variable must be removed

Claude Code sets `CLAUDECODE=1` in its environment and detects this variable to refuse launching inside another Claude Code session ("Claude Code cannot be launched inside another Claude Code session").

**Fix:** `cmd.env_remove("CLAUDECODE")` before spawning the child process.

### 4. `(with report)` is not supported on all macOS versions

Attempting to add `(deny default (with report))` for sandbox violation logging fails with:

```
sandbox compile: report modifier does not apply to deny action
```

The `(with report)` modifier is unsupported on the user's macOS version. Sandbox violations can still be observed via `log stream --predicate 'subsystem == "com.apple.sandbox"'`.

### 5. Debug flags retained in release builds

Two flags are kept for production use (not stripped as debug-only):

- `--no-sandbox`: skips `sandbox_init()` entirely; useful when diagnosing whether an issue is sandbox-related
- `--permissive`: uses `(allow default)` with targeted denies; useful for narrowing which rule is causing a problem

## Consequences

- The write policy is home-directory-wide (minus ~/Library), which is broader than the original design intended
- Mach IPC is fully open (`mach-lookup` etc. without service-name filters), which allows Claude Code to reach any Mach service, not just SecurityServer
- The `CLAUDECODE` removal means ziplock can be used recursively (ziplock inside ziplock), though that scenario is not tested
