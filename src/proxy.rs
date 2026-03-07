use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{Context, Result};
use fast_socks5::server::Socks5ServerProtocol;
use fast_socks5::util::target_addr::TargetAddr;
use fast_socks5::{ReplyError, Socks5Command};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use crate::dns::TokioResolver;

/// Ports assigned to the running proxy servers.
pub struct ProxyPorts {
    pub socks5: u16,
    pub http: u16,
}

/// Start both proxy servers. Returns the assigned ports and a shutdown sender.
pub async fn start(resolver: Arc<TokioResolver>) -> Result<(ProxyPorts, watch::Sender<bool>)> {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let socks_listener = TcpListener::bind("127.0.0.1:0").await?;
    let socks_port = socks_listener.local_addr()?.port();

    let http_listener = TcpListener::bind("127.0.0.1:0").await?;
    let http_port = http_listener.local_addr()?.port();

    {
        let resolver = resolver.clone();
        let shutdown_rx = shutdown_rx.clone();
        tokio::spawn(socks5_accept_loop(socks_listener, resolver, shutdown_rx));
    }
    {
        let resolver = resolver.clone();
        let shutdown_rx = shutdown_rx.clone();
        tokio::spawn(http_accept_loop(http_listener, resolver, shutdown_rx));
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

/// Check if an IP is private/RFC1918/loopback/link-local.
pub(crate) fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            let s = v6.segments();
            v6.is_loopback()
                || (s[0] & 0xfe00) == 0xfc00 // unique-local fc00::/7
                || (s[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
        }
    }
}

/// Check if a resolved IP indicates the domain was blocked (Cloudflare returns 0.0.0.0).
pub(crate) fn is_blocked_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => *v4 == Ipv4Addr::UNSPECIFIED,
        IpAddr::V6(v6) => v6.is_unspecified(),
    }
}

/// Resolve a hostname using our Cloudflare family DNS resolver.
async fn resolve_host(resolver: &TokioResolver, host: &str) -> Result<IpAddr, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_private_ip(&ip) {
            return Ok(ip);
        }
        return Err(format!("direct public IP connections blocked: {ip}"));
    }

    // .local domains are mDNS (Bonjour) — Cloudflare DoH has no knowledge of them.
    // Use the system resolver (getaddrinfo → mDNSResponder via Unix socket, which the
    // sandbox allows via `network-outbound (remote unix-socket)`).
    if host.ends_with(".local") {
        return resolve_local_mdns(host).await;
    }

    let response = resolver
        .lookup_ip(host)
        .await
        .map_err(|e| format!("DNS resolution failed for {host}: {e}"))?;

    if let Some(ip) = response.iter().next() {
        if is_blocked_ip(&ip) {
            return Err(format!("domain blocked by DNS filter: {host}"));
        }
        if is_private_ip(&ip) {
            return Err(format!(
                "domain resolved to private IP, blocked: {host} -> {ip}"
            ));
        }
        return Ok(ip);
    }

    Err(format!("no addresses found for {host}"))
}

/// Resolve a `.local` mDNS hostname via the system resolver (mDNSResponder).
/// The result must be a private IP — `.local` names should never resolve to public addresses.
async fn resolve_local_mdns(host: &str) -> Result<IpAddr, String> {
    let addrs = tokio::net::lookup_host(format!("{host}:0"))
        .await
        .map_err(|e| format!("mDNS lookup failed for {host}: {e}"))?;

    let ip = addrs
        .map(|sa| sa.ip())
        .next()
        .ok_or_else(|| format!("no addresses found for {host}"))?;

    if !is_private_ip(&ip) {
        return Err(format!(
            ".local domain resolved to non-private IP (suspicious): {host} -> {ip}"
        ));
    }

    Ok(ip)
}

// ── SOCKS5 (using fast-socks5 for protocol handling) ────────────────────────

async fn socks5_accept_loop(
    listener: TcpListener,
    resolver: Arc<TokioResolver>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, addr)) => {
                        debug!("socks5 connection from {addr}");
                        let resolver = resolver.clone();
                        tokio::spawn(async move {
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
        Ok(ip) => match TcpStream::connect((ip, port)).await {
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
    mut shutdown_rx: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, addr)) => {
                        debug!("http proxy connection from {addr}");
                        let resolver = resolver.clone();
                        tokio::spawn(async move {
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

async fn handle_http(mut stream: TcpStream, resolver: &TokioResolver) -> Result<()> {
    // Read request headers
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
            Ok(ip) => match TcpStream::connect((ip, port)).await {
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
                let body = reason.as_bytes();
                let resp = format!(
                    "HTTP/1.1 403 Forbidden\r\nContent-Length: {}\r\n\r\n",
                    body.len()
                );
                stream.write_all(resp.as_bytes()).await?;
                stream.write_all(body).await?;
            }
        }
    } else {
        // Plain HTTP proxy: GET http://host/path HTTP/1.1
        if let Some(url_host) = extract_host_from_url(target) {
            let (host, port) = parse_host_port(&url_host, 80)?;
            debug!("http proxy {method} {host}:{port}");

            match resolve_host(resolver, &host).await {
                Ok(ip) => match TcpStream::connect((ip, port)).await {
                    Ok(mut target_stream) => {
                        target_stream.write_all(&buf[..total]).await?;
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
            let port = port_str.parse::<u16>().context("invalid port")?;
            return Ok((addr.to_string(), port));
        }
        if let Some(addr) = rest.strip_suffix(']') {
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

/// Extract host:port from an absolute URL like "http://host:port/path".
fn extract_host_from_url(url: &str) -> Option<String> {
    let without_scheme = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))?;
    let host_port = without_scheme.split('/').next()?;
    Some(host_port.to_string())
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

        // Public IPs should NOT be private
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))));
        assert!(!is_private_ip(&IpAddr::V6(
            "2001:4860:4860::8888".parse().unwrap()
        )));
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
    async fn test_local_mdns_resolves_via_system_resolver() {
        // localhost.local isn't a real mDNS name, but we can verify the code path
        // doesn't attempt DoH. The function should either resolve or return a DNS error —
        // what it must NOT do is route through Cloudflare.
        //
        // We verify the routing by checking the function exists and compiles; actual
        // mDNS resolution requires a live network with a .local device present.
        let result = resolve_local_mdns("nonexistent-device-ziplock-test.local").await;
        // Should fail with mDNS error, not a DoH error
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(
            msg.contains("mDNS lookup failed") || msg.contains("no addresses found"),
            "unexpected error: {msg}"
        );
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
        assert_eq!(
            extract_host_from_url("https://example.com/"),
            Some("example.com".to_string())
        );
        assert_eq!(extract_host_from_url("ftp://example.com"), None);
        assert_eq!(extract_host_from_url("not-a-url"), None);
    }
}
