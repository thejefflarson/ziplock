use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{Context, Result};
use fast_socks5::server::Socks5ServerProtocol;
use fast_socks5::util::target_addr::TargetAddr;
use fast_socks5::{ReplyError, Socks5Command};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};
use tokio::time::{Duration, timeout};
use tracing::{debug, error, info, warn};

/// Maximum number of concurrent proxy connections (SOCKS5 + HTTP combined).
const MAX_CONNECTIONS: usize = 256;
/// Timeout for establishing an outbound TCP connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Timeout for reading HTTP request headers (slow-loris mitigation).
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(30);

use crate::dns::TokioResolver;

/// Ports assigned to the running proxy servers.
pub struct ProxyPorts {
    pub socks5: u16,
    pub http: u16,
}

/// Start both proxy servers. Returns the assigned ports and a shutdown sender.
pub async fn start(resolver: Arc<TokioResolver>) -> Result<(ProxyPorts, watch::Sender<bool>)> {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    // Shared connection semaphore: caps total concurrent connections across both listeners.
    let conn_sem = Arc::new(Semaphore::new(MAX_CONNECTIONS));

    let socks_listener = TcpListener::bind("127.0.0.1:0").await?;
    let socks_port = socks_listener.local_addr()?.port();

    let http_listener = TcpListener::bind("127.0.0.1:0").await?;
    let http_port = http_listener.local_addr()?.port();

    {
        let resolver = resolver.clone();
        let shutdown_rx = shutdown_rx.clone();
        let sem = conn_sem.clone();
        tokio::spawn(socks5_accept_loop(socks_listener, resolver, sem, shutdown_rx));
    }
    {
        let resolver = resolver.clone();
        let shutdown_rx = shutdown_rx.clone();
        tokio::spawn(http_accept_loop(http_listener, resolver, conn_sem, shutdown_rx));
    }

    info!(
        socks5_port = socks_port,
        http_port = http_port,
        "proxy started"
    );
    Ok((
        ProxyPorts {
            socks5: socks_port,
            http: http_port,
        },
        shutdown_tx,
    ))
}

/// Check if an IP is private/RFC1918/loopback/link-local/reserved/CGNAT/multicast/broadcast.
/// Covers all address ranges that should bypass DNS-based SSRF prevention.
///
/// IPv6 addresses are first unwrapped if they are IPv4-mapped (`::ffff:a.b.c.d`) — otherwise
/// an attacker-controlled AAAA record of `::ffff:127.0.0.1` would bypass the v4 classifier
/// and still reach the embedded IPv4 address when the kernel routes the v6 socket
/// (macOS defaults `IPV6_V6ONLY=0`).
pub(crate) fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_private_v4(&v4);
            }
            let s = v6.segments();
            // IPv4-translated ::ffff:0:x.x.x.x/96 (RFC 6052): NOT caught by to_ipv4_mapped().
            // On dual-stack hosts the kernel routes these to the embedded IPv4.
            if s[0] == 0 && s[1] == 0 && s[2] == 0 && s[3] == 0 && s[4] == 0xffff && s[5] == 0 {
                let embedded = std::net::Ipv4Addr::new(
                    (s[6] >> 8) as u8,
                    s[6] as u8,
                    (s[7] >> 8) as u8,
                    s[7] as u8,
                );
                return is_private_v4(&embedded);
            }
            v6.is_loopback()
                || v6.is_unspecified()
                || (s[0] & 0xfe00) == 0xfc00 // unique-local fc00::/7
                || (s[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
                || (s[0] & 0xff00) == 0xff00 // multicast ff00::/8
                || (s[0] == 0x2001 && s[1] == 0x0db8) // documentation 2001:db8::/32
                // NAT64 Well-Known Prefix 64:ff9b::/96 and local-use 64:ff9b:1::/48 (RFC 6052, 8215).
                // DoH AAAA records using these prefixes synthesize private IPv4 targets.
                || (s[0] == 0x0064 && s[1] == 0xff9b)
        }
    }
}

fn is_private_v4(v4: &Ipv4Addr) -> bool {
    let octets = v4.octets();
    v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_broadcast()
        || v4.is_multicast()
        // CGNAT: 100.64.0.0/10 (RFC 6598)
        || (octets[0] == 100 && (octets[1] & 0xc0) == 0x40)
        // Reserved / class E: 240.0.0.0/4
        || (octets[0] & 0xf0) == 0xf0
        // "This network": 0.0.0.0/8
        || octets[0] == 0
}

/// Check if a resolved IP indicates the domain was blocked (Cloudflare returns 0.0.0.0).
pub(crate) fn is_blocked_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => *v4 == Ipv4Addr::UNSPECIFIED,
        IpAddr::V6(v6) => {
            // Also catch the IPv4-mapped form ::ffff:0.0.0.0
            v6.is_unspecified()
                || v6.to_ipv4_mapped()
                    .map_or(false, |v4| v4 == Ipv4Addr::UNSPECIFIED)
        }
    }
}

/// Max DoH lookup attempts before giving up — covers a single transient h2 connection
/// reset between Cloudflare's GOAWAY and hickory establishing a fresh connection.
const DNS_MAX_ATTEMPTS: u32 = 3;

/// Retry an async operation up to `max_attempts` times, backing off linearly
/// (50ms × attempt) between tries. `is_permanent` short-circuits the retry loop for
/// errors that re-running cannot fix (e.g. NXDOMAIN); transient errors are retried.
/// `what` labels the operation in the retry log line.
async fn retry_transient<T, E, Op, Fut, Perm>(
    max_attempts: u32,
    what: &str,
    mut op: Op,
    is_permanent: Perm,
) -> Result<T, E>
where
    Op: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    Perm: Fn(&E) -> bool,
    E: std::fmt::Display,
{
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        match op().await {
            Ok(v) => return Ok(v),
            Err(e) if is_permanent(&e) || attempt >= max_attempts => return Err(e),
            Err(e) => {
                warn!("{what} failed (attempt {attempt}/{max_attempts}), retrying: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(50 * u64::from(attempt))).await;
            }
        }
    }
}

/// Resolve a hostname to a list of safe IPs to try, in connect order.
/// IPv4 addresses are preferred — networks without an IPv6 default route return
/// `EHOSTUNREACH` when connecting to AAAA results, so we try v4 first and fall
/// back to v6.
async fn resolve_host(resolver: &TokioResolver, host: &str) -> Result<Vec<IpAddr>, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        // Block direct connections to private/loopback addresses — SSRF guard.
        // Private IPs must never be reachable by supplying a literal address to
        // SOCKS5/HTTP CONNECT (bypassing DNS filtering entirely).
        if is_private_ip(&ip) {
            return Err(format!("direct private IP connections blocked: {ip}"));
        }
        return Err(format!("direct public IP connections blocked: {ip}"));
    }

    // .local domains are mDNS (Bonjour) — Cloudflare DoH has no knowledge of them.
    // Resolve via the system resolver (getaddrinfo → mDNSResponder via Unix socket, which
    // the sandbox allows via `network-outbound (remote unix-socket)`).
    if host.ends_with(".local") {
        return resolve_system_private(host).await;
    }

    // The DoH resolver holds a long-lived HTTP/2 connection to Cloudflare. Cloudflare
    // periodically sends GOAWAY / resets idle connections, and hickory fails the in-flight
    // query ("received a stream error: connection reset" / "broken pipe") rather than
    // transparently reconnecting. The next lookup re-establishes the connection, so we retry
    // transient failures. Genuine NXDOMAIN (NoRecordsFound) is permanent — fall through to
    // the system resolver, which knows LAN/router/hosts names Cloudflare cannot.
    match retry_transient(
        DNS_MAX_ATTEMPTS,
        host,
        || resolver.lookup_ip(host),
        |e| e.is_no_records_found(),
    )
    .await
    {
        Ok(response) => {
            let ips: Vec<IpAddr> = response.iter().collect();
            if ips.is_empty() {
                // DoH returned no A/AAAA — try the system resolver for LAN names.
                return resolve_system_private(host).await;
            }
            vet_doh_answer(ips, host)
        }
        // Cloudflare doesn't know this name (NXDOMAIN) — likely a LAN/router/hosts/mDNS
        // hostname. Fall back to the system resolver (LAN access is enabled).
        Err(e) if e.is_no_records_found() => resolve_system_private(host).await,
        Err(e) => Err(format!("DNS resolution failed for {host}: {e}")),
    }
}

/// Vet a non-empty DoH answer. Malware/adult blocks (Cloudflare returns 0.0.0.0) are
/// rejected. Private/RFC1918/LAN addresses are ALLOWED — LAN access is enabled by default,
/// so a domain (incl. split-horizon names) resolving to a private IP is permitted. Returns
/// the IPs ordered v4-first so boxes without an IPv6 default route don't fail EHOSTUNREACH.
fn vet_doh_answer(mut ips: Vec<IpAddr>, host: &str) -> Result<Vec<IpAddr>, String> {
    if ips.iter().any(is_blocked_ip) {
        return Err(format!("domain blocked by DNS filter: {host}"));
    }
    ips.sort_by_key(|ip| if ip.is_ipv4() { 0u8 } else { 1u8 });
    Ok(ips)
}

/// Connect to the first IP in the candidate list that accepts a TCP connection.
async fn connect_any(ips: &[IpAddr], port: u16) -> std::io::Result<TcpStream> {
    let mut last_err: Option<std::io::Error> = None;
    for &ip in ips {
        match timeout(CONNECT_TIMEOUT, TcpStream::connect((ip, port))).await {
            Ok(Ok(s)) => return Ok(s),
            Ok(Err(e)) => {
                debug!("connect {ip}:{port} failed: {e}");
                last_err = Some(e);
            }
            Err(_) => {
                debug!("connect {ip}:{port} timed out");
                last_err = Some(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "connection timed out",
                ));
            }
        }
    }
    Err(last_err.unwrap_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "no candidate IPs")
    }))
}

/// Resolve a hostname via the system resolver (getaddrinfo → mDNSResponder, the router's
/// DHCP DNS, and `/etc/hosts`). Used for LAN/mDNS names Cloudflare DoH can't resolve.
///
/// The result is accepted ONLY if every address is private. A public answer here would let
/// any caller bypass the DoH malware/adult filter by routing a public name through the
/// system resolver, so we refuse it and force such names back through DoH. Returns IPs
/// ordered v4-first.
async fn resolve_system_private(host: &str) -> Result<Vec<IpAddr>, String> {
    let addrs = tokio::net::lookup_host(format!("{host}:0"))
        .await
        .map_err(|e| format!("system DNS lookup failed for {host}: {e}"))?;

    let mut ips: Vec<IpAddr> = addrs.map(|sa| sa.ip()).collect();
    if ips.is_empty() {
        return Err(format!("no addresses found for {host}"));
    }

    if let Some(public) = ips.iter().find(|ip| !is_private_ip(ip)) {
        return Err(format!(
            "system resolver returned public IP for {host} -> {public}; refusing (public names must resolve via DoH)"
        ));
    }

    ips.sort_by_key(|ip| if ip.is_ipv4() { 0u8 } else { 1u8 });
    Ok(ips)
}

// ── SOCKS5 (using fast-socks5 for protocol handling) ────────────────────────

async fn socks5_accept_loop(
    listener: TcpListener,
    resolver: Arc<TokioResolver>,
    conn_sem: Arc<Semaphore>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, addr)) => {
                        debug!("socks5 connection from {addr}");
                        let permit = match conn_sem.clone().try_acquire_owned() {
                            Ok(p) => p,
                            Err(_) => {
                                warn!("connection limit ({MAX_CONNECTIONS}) reached, dropping socks5 connection from {addr}");
                                continue;
                            }
                        };
                        let resolver = resolver.clone();
                        tokio::spawn(async move {
                            let _permit = permit; // released when task completes
                            if let Err(e) = handle_socks5(stream, &resolver).await {
                                debug!("socks5 handler error: {e}");
                            }
                        });
                    }
                    Err(e) => error!("socks5 accept error: {e}"),
                }
            }
            _ = shutdown_rx.changed() => {
                info!("socks5 proxy shutting down");
                return;
            }
        }
    }
}

async fn handle_socks5(stream: TcpStream, resolver: &TokioResolver) -> Result<()> {
    // Use fast-socks5 for protocol handling (auth + command parsing)
    let proto = Socks5ServerProtocol::accept_no_auth(stream)
        .await
        .context("socks5 auth negotiation failed")?;

    let (proto, cmd, target_addr) = proto
        .read_command()
        .await
        .context("socks5 read command failed")?;

    if !matches!(cmd, Socks5Command::TCPConnect) {
        proto
            .reply_error(&ReplyError::CommandNotSupported)
            .await
            .ok();
        anyhow::bail!("unsupported SOCKS5 command: {cmd:?}");
    }

    // Extract host and port from target address
    let (host, port) = match target_addr {
        TargetAddr::Ip(addr) => (addr.ip().to_string(), addr.port()),
        TargetAddr::Domain(domain, port) => (domain, port),
    };

    debug!("socks5 CONNECT {host}:{port}");

    // Resolve DNS through our filtered resolver
    match resolve_host(resolver, &host).await {
        Ok(ips) => match connect_any(&ips, port).await {
            Ok(mut target_stream) => {
                let bound = target_stream
                    .local_addr()
                    .unwrap_or(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
                let mut client_stream = proto
                    .reply_success(bound)
                    .await
                    .context("socks5 reply failed")?;
                tokio::io::copy_bidirectional(&mut client_stream, &mut target_stream)
                    .await
                    .ok();
            }
            Err(e) => {
                warn!("socks5 connect to {host}:{port} failed: {e}");
                proto.reply_error(&ReplyError::HostUnreachable).await.ok();
            }
        },
        Err(reason) => {
            warn!("socks5 blocked: {reason}");
            proto
                .reply_error(&ReplyError::ConnectionNotAllowed)
                .await
                .ok();
        }
    }

    Ok(())
}

// ── HTTP CONNECT ────────────────────────────────────────────────────────────

async fn http_accept_loop(
    listener: TcpListener,
    resolver: Arc<TokioResolver>,
    conn_sem: Arc<Semaphore>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, addr)) => {
                        debug!("http proxy connection from {addr}");
                        let permit = match conn_sem.clone().try_acquire_owned() {
                            Ok(p) => p,
                            Err(_) => {
                                warn!("connection limit ({MAX_CONNECTIONS}) reached, dropping http connection from {addr}");
                                continue;
                            }
                        };
                        let resolver = resolver.clone();
                        tokio::spawn(async move {
                            let _permit = permit; // released when task completes
                            if let Err(e) = handle_http(stream, &resolver).await {
                                debug!("http proxy handler error: {e}");
                            }
                        });
                    }
                    Err(e) => error!("http proxy accept error: {e}"),
                }
            }
            _ = shutdown_rx.changed() => {
                info!("http proxy shutting down");
                return;
            }
        }
    }
}

/// Read HTTP request headers from `stream`, returning the raw bytes up to and
/// including the blank-line terminator (`\r\n\r\n`).  Capped at 8 KiB total.
async fn read_http_headers(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; 8192];
    let mut total = 0;
    loop {
        let n = stream.read(&mut buf[total..]).await?;
        if n == 0 {
            anyhow::bail!("connection closed before complete request");
        }
        total += n;
        if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if total >= buf.len() {
            anyhow::bail!("request too large");
        }
    }
    buf.truncate(total);
    Ok(buf)
}

async fn handle_http(mut stream: TcpStream, resolver: &TokioResolver) -> Result<()> {
    // Read headers with a per-connection timeout to prevent slow-loris attacks
    // (a sender that trickles one byte at a time can otherwise pin a Tokio task forever).
    let buf = match timeout(HEADER_READ_TIMEOUT, read_http_headers(&mut stream)).await {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => return Err(e),
        Err(_) => anyhow::bail!("header read timed out"),
    };
    let total = buf.len();

    let request = String::from_utf8_lossy(&buf[..total]);
    let first_line = request.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();

    if parts.len() < 3 {
        stream
            .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            .await?;
        anyhow::bail!("malformed request line: {first_line}");
    }

    let method = parts[0];
    let target = parts[1];

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = parse_host_port(target, 443)?;
        debug!("http CONNECT {host}:{port}");

        match resolve_host(resolver, &host).await {
            Ok(ips) => match connect_any(&ips, port).await {
                Ok(mut target_stream) => {
                    stream
                        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        .await?;
                    tokio::io::copy_bidirectional(&mut stream, &mut target_stream)
                        .await
                        .ok();
                }
                Err(e) => {
                    warn!("http CONNECT to {host}:{port} failed: {e}");
                    stream
                        .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                        .await?;
                }
            },
            Err(reason) => {
                warn!("http CONNECT blocked: {reason}");
                // Return a generic body — do NOT echo `reason` which contains the resolved IP.
                // Sending the resolved IP back to the sandboxed process turns the proxy into
                // a DNS oracle that lets Claude enumerate reachable private ranges.
                stream
                    .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 7\r\n\r\nBlocked")
                    .await?;
            }
        }
    } else {
        // Plain HTTP proxy: GET http://host/path HTTP/1.1
        //
        // The raw request headers are forwarded verbatim, so before forwarding
        // we reject any request that carries both Content-Length and
        // Transfer-Encoding headers — the CL:TE ambiguity is the canonical
        // request-smuggling primitive. Real clients (curl, Bun, node) don't
        // emit both; a request that does is almost certainly crafted.
        if has_cl_te_conflict(&buf[..total]) {
            warn!("http proxy rejected request with both Content-Length and Transfer-Encoding");
            stream
                .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                .await?;
            return Ok(());
        }
        if let Some(url_host) = extract_host_from_url(target) {
            let (host, port) = parse_host_port(&url_host, 80)?;
            debug!("http proxy {method} {host}:{port}");

            match resolve_host(resolver, &host).await {
                Ok(ips) => match connect_any(&ips, port).await {
                    Ok(mut target_stream) => {
                        // Rewrite the client-supplied Host header to the DNS-resolved authority.
                        // Without this, a crafted Host: header that differs from the URL host
                        // causes virtual-host confusion on shared upstream servers.
                        let rewritten = rewrite_host_header(&buf[..total], &host, port, 80);
                        target_stream.write_all(&rewritten).await?;
                        tokio::io::copy_bidirectional(&mut stream, &mut target_stream)
                            .await
                            .ok();
                    }
                    Err(e) => {
                        warn!("http proxy to {host}:{port} failed: {e}");
                        stream
                            .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                            .await?;
                    }
                },
                Err(reason) => {
                    warn!("http proxy blocked: {reason}");
                    stream.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await?;
                }
            }
        } else {
            stream
                .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                .await?;
        }
    }

    Ok(())
}

/// Parse "host:port" with a default port.
fn parse_host_port(s: &str, default_port: u16) -> Result<(String, u16)> {
    // Handle IPv6 bracket notation [::1]:port
    if let Some(rest) = s.strip_prefix('[') {
        if let Some((addr, port_str)) = rest.rsplit_once("]:") {
            // Validate that the bracket content is actually an IPv6 address.
            // Without this check, "[evil.com]:443" would extract "evil.com" as the
            // host, causing misleading audit logs and potential security bypasses in
            // code that treats bracket-extracted content as trusted IPv6 literals.
            addr.parse::<std::net::Ipv6Addr>()
                .context("bracket notation must contain a valid IPv6 address")?;
            let port = port_str.parse::<u16>().context("invalid port")?;
            return Ok((addr.to_string(), port));
        }
        if let Some(addr) = rest.strip_suffix(']') {
            addr.parse::<std::net::Ipv6Addr>()
                .context("bracket notation must contain a valid IPv6 address")?;
            return Ok((addr.to_string(), default_port));
        }
    }

    if let Some((host, port_str)) = s.rsplit_once(':')
        && let Ok(port) = port_str.parse::<u16>()
    {
        return Ok((host.to_string(), port));
    }

    Ok((s.to_string(), default_port))
}

/// Return true if the raw HTTP header block contains BOTH a `Content-Length` and a
/// `Transfer-Encoding` header — the classic CL:TE request-smuggling primitive.
/// Case-insensitive header matching; any non-empty value on either side counts.
fn has_cl_te_conflict(raw: &[u8]) -> bool {
    // Only scan header region (through the first \r\n\r\n); body bytes past that
    // are opaque and shouldn't influence the decision.
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or(raw.len());
    let headers = &raw[..end];
    let text = match std::str::from_utf8(headers) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let mut has_cl = false;
    let mut has_te = false;
    for line in text.lines().skip(1) {
        // skip request-line
        if let Some((name, _value)) = line.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            if name == "content-length" {
                has_cl = true;
            } else if name == "transfer-encoding" {
                has_te = true;
            }
        }
    }
    has_cl && has_te
}

/// Extract host:port from an absolute HTTP URL like "http://host:port/path".
///
/// Only `http://` is accepted — silently forwarding `https://` plain-text would
/// downgrade the connection without the client's knowledge.
///
/// RFC 3986 userinfo (`user:pass@host`) is stripped before returning the authority:
/// the DNS lookup and Host header are based on the hostname, not the raw authority,
/// preventing log-spoofing via `http://attacker.com@legitimate.com/path`.
fn extract_host_from_url(url: &str) -> Option<String> {
    let without_scheme = url.strip_prefix("http://")?;
    let authority = without_scheme.split('/').next()?;
    // Strip RFC 3986 userinfo (everything up to and including the last '@').
    let host_port = authority.rfind('@').map(|i| &authority[i + 1..]).unwrap_or(authority);
    Some(host_port.to_string())
}

/// Rewrite the `Host` header in a raw HTTP request to the canonical authority used for
/// DNS resolution.  This prevents virtual-host confusion where a client-supplied Host
/// header differs from the URL authority (e.g. `http://real.com/` with `Host: evil.com`).
///
/// Only the header section (before `\r\n\r\n`) is touched; the body is forwarded verbatim.
fn rewrite_host_header(raw: &[u8], canonical_host: &str, port: u16, default_port: u16) -> Vec<u8> {
    let canonical = if port == default_port {
        canonical_host.to_string()
    } else {
        format!("{canonical_host}:{port}")
    };
    // Find the blank-line separator between headers and body.
    let Some(sep) = raw.windows(4).position(|w| w == b"\r\n\r\n") else {
        return raw.to_vec();
    };
    let Ok(header_str) = std::str::from_utf8(&raw[..sep]) else {
        return raw.to_vec();
    };
    let rewritten: String = header_str
        .split("\r\n")
        .map(|line| {
            if line.to_ascii_lowercase().starts_with("host:") {
                format!("Host: {canonical}")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\r\n");
    let mut out = rewritten.into_bytes();
    out.extend_from_slice(&raw[sep..]); // includes \r\n\r\n and body
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_is_private_ip() {
        // Loopback
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(is_private_ip(&IpAddr::V6(Ipv6Addr::LOCALHOST)));

        // RFC1918
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));

        // Link-local
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(169, 254, 0, 1))));

        // IPv6 unique-local (fc00::/7)
        assert!(is_private_ip(&IpAddr::V6("fc00::1".parse().unwrap())));
        assert!(is_private_ip(&IpAddr::V6(
            "fd12:3456:789a::1".parse().unwrap()
        )));

        // IPv6 link-local (fe80::/10)
        assert!(is_private_ip(&IpAddr::V6("fe80::1".parse().unwrap())));

        // IPv6 multicast (ff00::/8)
        assert!(is_private_ip(&IpAddr::V6("ff02::1".parse().unwrap())));

        // IPv6 documentation (2001:db8::/32)
        assert!(is_private_ip(&IpAddr::V6("2001:db8::1".parse().unwrap())));
        assert!(is_private_ip(&IpAddr::V6(
            "2001:db8:dead:beef::1".parse().unwrap()
        )));

        // Public IPs should NOT be private
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))));
        assert!(!is_private_ip(&IpAddr::V6(
            "2001:4860:4860::8888".parse().unwrap()
        )));

        // IPv4-mapped IPv6 must inherit the v4 classification (SSRF bypass guard).
        assert!(is_private_ip(&IpAddr::V6(
            "::ffff:127.0.0.1".parse().unwrap()
        )));
        assert!(is_private_ip(&IpAddr::V6(
            "::ffff:192.168.1.1".parse().unwrap()
        )));
        assert!(is_private_ip(&IpAddr::V6(
            "::ffff:169.254.169.254".parse().unwrap()
        )));
        assert!(!is_private_ip(&IpAddr::V6(
            "::ffff:8.8.8.8".parse().unwrap()
        )));

        // CGNAT (100.64.0.0/10)
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(
            100, 127, 255, 254
        ))));
        // But 100.128.x is outside CGNAT and public-routable
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(100, 128, 0, 1))));

        // Multicast, broadcast, reserved class E, "this network"
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::BROADCAST)));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(240, 0, 0, 1))));
        assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(0, 0, 0, 1))));

        // IPv6 unspecified
        assert!(is_private_ip(&IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
    }

    #[test]
    fn test_is_blocked_ip() {
        assert!(is_blocked_ip(&IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        assert!(is_blocked_ip(&IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
        assert!(!is_blocked_ip(&IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))));
        assert!(!is_blocked_ip(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }

    #[test]
    fn test_parse_host_port() {
        assert_eq!(
            parse_host_port("example.com:8080", 443).unwrap(),
            ("example.com".to_string(), 8080)
        );
        assert_eq!(
            parse_host_port("example.com", 443).unwrap(),
            ("example.com".to_string(), 443)
        );
        assert_eq!(
            parse_host_port("[::1]:8080", 443).unwrap(),
            ("::1".to_string(), 8080)
        );
        assert_eq!(
            parse_host_port("[::1]", 443).unwrap(),
            ("::1".to_string(), 443)
        );
    }

    #[tokio::test]
    async fn test_system_resolver_rejects_nonexistent_name() {
        // A nonexistent LAN/mDNS name must fail via the system resolver — never via DoH.
        let result = resolve_system_private("nonexistent-device-ziplock-test.local").await;
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(
            msg.contains("system DNS lookup failed") || msg.contains("no addresses found"),
            "unexpected error: {msg}"
        );
    }

    #[tokio::test]
    async fn test_system_resolver_accepts_localhost_private() {
        // localhost resolves locally (no network) to 127.0.0.1/::1 — all private, so the
        // all-private gate accepts it and orders v4 first.
        let ips = resolve_system_private("localhost")
            .await
            .expect("localhost should resolve");
        assert!(!ips.is_empty());
        assert!(
            ips.iter().all(is_private_ip),
            "all localhost addrs must be private: {ips:?}"
        );
        assert!(ips[0].is_ipv4(), "v4 should sort first: {ips:?}");
    }

    #[test]
    fn vet_doh_answer_allows_private_blocks_filtered() {
        let private = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
        let public = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        let blocked = IpAddr::V4(Ipv4Addr::UNSPECIFIED); // 0.0.0.0 → malware/adult block

        // LAN access enabled: a private answer is now permitted.
        assert_eq!(
            vet_doh_answer(vec![private], "nas.example"),
            Ok(vec![private])
        );
        // Mixed public+private is also permitted (split-horizon names).
        assert!(vet_doh_answer(vec![public, private], "host.example").is_ok());
        // Malware/adult 0.0.0.0 block is still rejected.
        assert!(vet_doh_answer(vec![blocked], "bad.example").is_err());
        assert!(
            vet_doh_answer(vec![public, blocked], "bad.example").is_err(),
            "any 0.0.0.0 in the set blocks the domain"
        );
        // v4 is ordered ahead of v6.
        let v6: IpAddr = "2606:2800:220:1::1".parse().unwrap();
        let ordered = vet_doh_answer(vec![v6, public], "host.example").unwrap();
        assert!(ordered[0].is_ipv4(), "v4 should sort first: {ordered:?}");
    }

    #[test]
    fn cl_te_conflict_detects_both_headers() {
        let req =
            b"POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert!(has_cl_te_conflict(req));

        // Case-insensitive.
        let req =
            b"POST /x HTTP/1.1\r\nHost: x\r\nCONTENT-LENGTH: 5\r\ntransfer-encoding: chunked\r\n\r\n";
        assert!(has_cl_te_conflict(req));

        // Only one present is fine.
        let normal_cl = b"POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\n";
        assert!(!has_cl_te_conflict(normal_cl));
        let normal_te = b"POST /x HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert!(!has_cl_te_conflict(normal_te));

        // Body bytes after the header terminator don't count.
        let poisoned_body =
            b"POST /x HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nTransfer-Encoding: chunked";
        assert!(!has_cl_te_conflict(poisoned_body));
    }

    #[test]
    fn test_extract_host_from_url() {
        assert_eq!(
            extract_host_from_url("http://example.com/path"),
            Some("example.com".to_string())
        );
        assert_eq!(
            extract_host_from_url("http://example.com:8080/path"),
            Some("example.com:8080".to_string())
        );
        // https:// is rejected by the plain-HTTP proxy (would silently downgrade TLS)
        assert_eq!(extract_host_from_url("https://example.com/"), None);
        assert_eq!(extract_host_from_url("ftp://example.com"), None);
        assert_eq!(extract_host_from_url("not-a-url"), None);
        // RFC 3986 userinfo must be stripped
        assert_eq!(
            extract_host_from_url("http://user:pass@example.com/path"),
            Some("example.com".to_string())
        );
        assert_eq!(
            extract_host_from_url("http://attacker.com@legitimate.com/path"),
            Some("legitimate.com".to_string())
        );
    }

    #[tokio::test]
    async fn retry_transient_succeeds_after_transient_failures() {
        // Surface the retry warnings when run with `--nocapture` so the behavior is
        // observable; harmless no-op if a subscriber is already installed.
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_test_writer()
            .try_init();
        // Fail twice (transient), then succeed on the third attempt — mirrors a DoH
        // h2 connection reset that clears once hickory re-establishes the connection.
        let calls = std::cell::Cell::new(0u32);
        let result = retry_transient(
            3,
            "test lookup",
            || {
                let n = calls.get() + 1;
                calls.set(n);
                async move {
                    if n < 3 {
                        Err("connection reset".to_string())
                    } else {
                        Ok(42u32)
                    }
                }
            },
            |_e: &String| false, // never permanent
        )
        .await;
        assert_eq!(result, Ok(42));
        assert_eq!(
            calls.get(),
            3,
            "should have retried up to the third attempt"
        );
    }

    #[tokio::test]
    async fn retry_transient_stops_on_permanent_error() {
        // A permanent error (e.g. NXDOMAIN) must not be retried.
        let calls = std::cell::Cell::new(0u32);
        let result: Result<u32, String> = retry_transient(
            3,
            "test lookup",
            || {
                calls.set(calls.get() + 1);
                async { Err("no records found".to_string()) }
            },
            |e: &String| e.contains("no records"), // permanent
        )
        .await;
        assert_eq!(result, Err("no records found".to_string()));
        assert_eq!(calls.get(), 1, "permanent error must not be retried");
    }

    #[tokio::test]
    async fn retry_transient_gives_up_after_max_attempts() {
        // Persistent transient failure: exhaust attempts and return the last error.
        let calls = std::cell::Cell::new(0u32);
        let result: Result<u32, String> = retry_transient(
            3,
            "test lookup",
            || {
                calls.set(calls.get() + 1);
                async { Err("connection reset".to_string()) }
            },
            |_e: &String| false,
        )
        .await;
        assert_eq!(result, Err("connection reset".to_string()));
        assert_eq!(calls.get(), 3, "should stop after max attempts");
    }
}
