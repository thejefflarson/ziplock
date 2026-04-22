# ADR 001: Sandbox + DNS Proxy Architecture

## Status
Accepted

## Context
Claude Code's `--dangerously-skip-permissions` flag enables fully autonomous operation but removes all safety prompts. No existing tool combines filesystem sandboxing with DNS-level filtering.

## Decision

### Two-layer architecture

**Layer 1 — macOS Seatbelt Sandbox (via sandbox_init FFI):**
- Default deny writes, allow CWD, `/private/tmp`, `/private/var/folders`, `/private/var/tmp`, `/opt/homebrew`, `/usr/local`, and `$HOME` excluding `~/Library` (with Caches/Keychains/Developer/org.swift.swiftpm carve-outs)
- Allow reads everywhere except `~/Library`, `/Library`, `/System` (with framework, Fonts, and developer-tool carve-outs)
- Force all network through localhost only
- Applied via `sandbox_init()` FFI in `pre_exec`, not `sandbox-exec`

**Layer 2 — DNS-Filtering Proxy:**
- SOCKS5 proxy for `ALL_PROXY=socks5h://` (h = proxy-side DNS)
- HTTP CONNECT proxy for `HTTP_PROXY`/`HTTPS_PROXY`
- All DNS resolved via DoH (DNS-over-HTTPS) to Cloudflare 1.1.1.3 — blocks malware + adult content; encrypted to prevent interception (see ADR 003)
- Raw public IPs blocked; private/loopback/link-local/CGNAT/multicast/broadcast/class-E (and their IPv4-mapped IPv6 forms) rejected as SSRF
- Mixed-answer DNS rebinding guard: if any address in the resolved set is private, the whole lookup is refused
- IPv4 tried before IPv6 so hosts without an IPv6 default route don't fail on AAAA answers

### Key tradeoffs
- **Productivity credentials allowed** (~/.ssh, ~/.aws, ~/.gnupg) — blocking them makes Claude unusable for real work
- **~/Library, /Library, /System denied** (with carve-outs) — protects keychains, cookies, browser data
- **Fresh attacker domains not blocked** — accepted risk; 1.1.1.3 only covers categorized threats

## Consequences
- macOS-only (sandbox_init is a macOS API)
- Single binary, no Docker dependency
- Child processes inherit sandbox (cannot escape)
- All DNS goes through proxy (no bypass possible due to sandbox)
