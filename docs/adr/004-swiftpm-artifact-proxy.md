# ADR 004: SwiftPM Binary Artifacts and the URLSession Proxy Gap

## Status
Accepted

## Context

ziplock forces all egress through its localhost proxy by (a) blocking direct
outbound in the sandbox and (b) injecting `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`
into the child. Tools that honor those env vars (curl, git, most CLIs) reach the
network; tools that ignore them are sandbox-blocked.

SwiftPM is a partial case:

- **Git phase works.** `swift package resolve` shells out to the `git` CLI to
  clone/update dependencies. `git` honors the proxy env, so this traverses the
  ziplock proxy normally.
- **Binary-artifact download fails.** `binaryTarget` artifact bundles (e.g.
  Sparkle's `Sparkle-for-Swift-Package-Manager.zip`) are fetched by SwiftPM's
  own `URLSessionHTTPClient`, built on `URLSession`. It attempts direct egress,
  which the sandbox denies — surfacing as a download/"network connection was
  lost" error.

### Why this can't be fixed with the env proxy

Empirically verified (dead-proxy discriminator test): on macOS, `URLSession`
ignores `*_PROXY` environment variables entirely — `curl` fails against a dead
proxy in the env while `URLSession` connects directly. CFNetwork reads proxy
config only from the macOS **system** network settings, never from env vars.

This is confirmed upstream:

- SwiftPM's downloader creates its session with
  `URLSessionConfiguration.default` and never sets `connectionProxyDictionary`
  or `proxyConfigurations`
  (`Sources/Basics/HTTPClient/URLSessionHTTPClient.swift`). `.default` ignores
  env-var proxies but *inherits the system proxy settings*.
- [swift-package-manager#7470](https://github.com/swiftlang/swift-package-manager/issues/7470)
  ("SwiftPM Resolve ignore HTTP_PROXY env when fetch artifacts") is open with no
  fix as of this writing.
- Note: on Linux, swift-corelibs-foundation's `URLSession` *does* read
  `http_proxy`/`https_proxy`, so this gap is macOS-specific.

### Why seatbelt can't paper over it

Seatbelt is an allow/deny authorization layer; it has no redirect/NAT primitive,
so it cannot transparently route URLSession traffic through the proxy. A PF
(`pf.conf` `rdr-to`/`route-to`) redirect could, but it is global + root-only,
still requires the sandbox to *allow* the egress first (the `connect()` MAC
check fires before PF), and would need a new transparent-proxy mode in ziplock
(redirected raw TCP carries no CONNECT header and bypasses the DoH name filter).

### Why not set the system proxy

`URLSessionConfiguration.default` *does* honor the macOS system proxy, so setting
it would make SwiftPM artifact downloads work. Rejected anyway:

- `networksetup`/SCDynamicStore require **admin** — a sudo prompt on every launch.
- It is **global** (every app on that network service), not per-process; macOS
  has no per-process system-proxy override.
- It is a **footgun**: a crash leaves the system proxy pointed at a dead
  localhost port, breaking all machine networking until manually reset.

## Decision

Do **not** add a system-proxy mode or PF redirection. Accept the gap and rely on
SwiftPM's artifact cache, which lives at:

```
~/Library/Caches/org.swift.swiftpm/artifacts/
```

This directory is under the `~/Library/Caches` carve-out, so it is read+write
inside the sandbox. Once an artifact is cached, SwiftPM serves it from cache
("Fetching binary artifact … from cache") with zero egress.

The supported workflow when a SwiftPM binary artifact is sandbox-blocked:

1. Resolve once **with network** to populate the cache — either outside ziplock,
   or `ziplock --dangerous-allow-network` (which skips the proxy/egress block):

   ```
   swift package resolve     # in a project that depends on the artifact
   ```

2. Run normally under ziplock thereafter. `swift build` / `swift package
   resolve` read the artifact from cache; the git phase continues to work
   through the proxy. No further network access to the artifact host is needed.

## Consequences

- SwiftPM dependencies that are pure git (the common case) work under ziplock
  with no extra steps.
- SwiftPM dependencies with remote `binaryTarget` artifacts need a one-time
  networked resolve to seed the cache; thereafter they build sandboxed.
- No global/admin/footgun system-proxy behavior is introduced.
- The same limitation applies to any macOS tool built on bare `URLSession` that
  ignores env-var proxies; the cache pre-seed pattern (or `--dangerous-allow-network`
  for that step) is the general escape hatch.
