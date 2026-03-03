# ADR 001: Sandbox + DNS Proxy Architecture

## Status
Accepted

## Context
Claude Code's `--dangerously-skip-permissions` flag enables fully autonomous operation but removes all safety prompts. No existing tool combines filesystem sandboxing with DNS-level filtering.

## Decision

### Two-layer architecture

**Layer 1 — macOS Seatbelt Sandbox (via sandbox_init FFI):**
- Default deny writes, allow CWD, /tmp, and $HOME (excluding ~/Library)
- Allow reads everywhere except ~/Library, /Library, /System (with framework carve-outs)
- Force all network through localhost only
- Applied via `sandbox_init()` FFI in `pre_exec`, not `sandbox-exec`

**Layer 2 — DNS-Filtering Proxy:**
- SOCKS5 proxy for `ALL_PROXY=socks5h://` (h = proxy-side DNS)
- HTTP CONNECT proxy for `HTTP_PROXY`/`HTTPS_PROXY`
- All DNS resolved through Cloudflare 1.1.1.3 (blocks malware + adult content)
- Raw public IPs blocked; private/RFC1918 IPs allowed

### Key tradeoffs
- **Productivity credentials allowed** (~/.ssh, ~/.aws, ~/.gnupg) — blocking them makes Claude unusable for real work
- **~/Library, /Library, /System denied** (with carve-outs) — protects keychains, cookies, browser data
- **Fresh attacker domains not blocked** — accepted risk; 1.1.1.3 only covers categorized threats

## Consequences
- macOS-only (sandbox_init is a macOS API)
- Single binary, no Docker dependency
- Child processes inherit sandbox (cannot escape)
- All DNS goes through proxy (no bypass possible due to sandbox)
