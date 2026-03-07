# ADR 003: DNS-over-HTTPS and 1Password SSH Agent

## Status
Accepted

## Context

### DNS over HTTPS

The initial DNS implementation used plain UDP/TCP to Cloudflare 1.1.1.3 on port 53. Plain DNS has two weaknesses relevant to ziplock's threat model:

1. **Interception** — DNS queries are unencrypted and can be redirected by a compromised process or network middlebox, undermining the malware-filtering guarantee.
2. **Spoofing** — An attacker who can inject DNS responses could bypass the 1.1.1.3 block list.

Since ziplock's DNS filter is a security control, not just a convenience, it should be tamper-resistant.

### 1Password SSH Agent

Users managing Git credentials via 1Password's SSH agent need the agent socket accessible inside the sandbox for operations like `git push` over SSH. The socket lives at:

```
~/Library/Group Containers/<TEAM_ID>.com.1password/t/agent.sock
```

The `<TEAM_ID>` component (`2BUA8C4S2C` for current 1Password versions) is not guaranteed to be stable across versions or enterprise deployments.

## Decisions

### DNS-over-HTTPS

Switch to `Protocol::Https` via hickory-resolver's `https-ring` feature:

- Connect to `1.1.1.3:443`
- TLS SNI: `family.cloudflare-dns.com`
- HTTP/2 endpoint: `/dns-query`

The DoH connection is made from ziplock's own (unsandboxed) process — the sandboxed claude subprocess only ever speaks to the localhost proxy, so no sandbox rule changes are needed.

**Why not DoT (DNS-over-TLS)?** DoH reuses port 443, which is harder to block selectively and benefits from HTTP/2 multiplexing. The hickory-resolver `https-ring` feature is already pulling in rustls and ring for TLS; DoT would add the same dependencies without meaningful benefit.

**Why `https-ring` over `https-aws-lc-rs`?** Both are functionally equivalent. `ring` has a longer track record on macOS and a smaller dependency footprint.

**Root certificates:** The `webpki-roots` feature is also enabled, which provides hickory's rustls TLS stack with Mozilla's bundled root CA set. Without it, rustls has no trust anchors and rejects all server certificates (`UnknownIssuer`). `webpki-roots` is preferred over `rustls-platform-verifier` (macOS Security framework) because it avoids any dependency on system APIs and is unaffected by enterprise MITM certificates that may be installed in the system trust store.

**Resolver timeout:** `ResolverOpts::timeout` is set explicitly to 5 seconds (matching hickory's internal default, but made explicit so the value is visible and intentional). If Cloudflare is unreachable, DNS resolution fails after 5 s, all non-localhost connections are denied, and Claude cannot reach the internet — a safe-fail outcome.

### 1Password SSH Agent

Scan `~/Library/Group Containers/` at startup for any directory whose name contains `1password` or `agilebits`, then check for `t/agent.sock` within it. If found:

1. Add the socket's parent directory as a file-read carve-out in the SBPL profile.
2. Set `SSH_AUTH_SOCK` in the claude subprocess environment to point to `agent.sock`.

**Why scan instead of hardcode?** The team ID prefix is an implementation detail of 1Password's macOS sandboxing and could change between major versions or in enterprise deployments. Scanning makes the detection version-agnostic.

**Why only file-read?** The agent socket is a Unix domain socket; file-read permission in the SBPL profile is what allows opening it. Write permission is not needed — the kernel handles socket communication through the `network-outbound (remote unix-socket)` rule already present in the profile.

**What if 1Password is not installed?** `find_op_agent_socket` returns `None`; no rule is added and `SSH_AUTH_SOCK` is left unchanged (inheriting whatever the parent process had).

## Consequences

- DNS queries are now encrypted and authenticated end-to-end; the malware filter cannot be bypassed by DNS spoofing.
- Adds `ring`, `rustls`, `tokio-rustls`, and `h2` as transitive dependencies (~12 new crates).
- 1Password SSH operations (e.g. `git push` via SSH) work inside the sandbox without user configuration.
- Other SSH agents (macOS launchd agent, gpg-agent) are unaffected — `SSH_AUTH_SOCK` is only overridden if the 1Password socket is found.
- The socket scan adds one `read_dir` call at startup; negligible overhead.
