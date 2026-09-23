use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use anyhow::Result;
use hickory_resolver::Resolver;
use hickory_resolver::config::{NameServerConfig, ResolveHosts, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;

/// Type alias for our tokio-based resolver.
pub type TokioResolver = Resolver<TokioRuntimeProvider>;

/// Cloudflare Family DNS-over-HTTPS endpoints.
/// 1.1.1.3 and 1.0.0.3 both provide malware + adult content blocking via DoH.
const CLOUDFLARE_FAMILY_IPS: &[IpAddr] = &[
    IpAddr::V4(Ipv4Addr::new(1, 1, 1, 3)),
    IpAddr::V4(Ipv4Addr::new(1, 0, 0, 3)),
];
const CLOUDFLARE_FAMILY_SNI: &str = "family.cloudflare-dns.com";
const DOH_ENDPOINT: &str = "/dns-query";

/// Create a DNS resolver that uses Cloudflare 1.1.1.3/1.0.0.3 over HTTPS (DoH).
/// This DNS server blocks known malware and adult content domains by returning 0.0.0.0.
/// DoH ensures DNS queries are encrypted and authenticated, preventing interception.
pub fn create_resolver() -> Result<Arc<TokioResolver>> {
    let sni: Arc<str> = Arc::from(CLOUDFLARE_FAMILY_SNI);
    let path: Arc<str> = Arc::from(DOH_ENDPOINT);

    let name_servers: Vec<NameServerConfig> = CLOUDFLARE_FAMILY_IPS
        .iter()
        .map(|&ip| NameServerConfig::https(ip, Arc::clone(&sni), Some(Arc::clone(&path))))
        .collect();

    let config = ResolverConfig::from_parts(None, vec![], name_servers);

    let mut opts = ResolverOpts::default();
    opts.use_hosts_file = ResolveHosts::Never;
    opts.num_concurrent_reqs = 2;
    opts.timeout = std::time::Duration::from_secs(5);

    let resolver = Resolver::builder_with_config(config, TokioRuntimeProvider::default())
        .with_options(opts)
        .build()?;

    Ok(Arc::new(resolver))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: the resolver must complete a DoH TLS handshake to Cloudflare
    /// and resolve a real name. This guards the trust-store choice — the pinned
    /// `webpki-roots` bundle could not verify Cloudflare's SSL.com/Comodo
    /// cross-signed `family.cloudflare-dns.com` cert, failing every lookup with
    /// `UnknownIssuer` -> `NoConnections`. Verifying via the OS trust store
    /// (`rustls-platform-verifier`) fixes it. Requires outbound network and must
    /// run outside any sandbox: `cargo test -- --ignored --test-threads=1`.
    #[tokio::test]
    #[ignore = "requires outbound network + no sandbox"]
    async fn resolver_completes_doh_and_resolves_real_name() {
        let resolver = create_resolver().expect("create_resolver");
        let lookup = resolver
            .lookup_ip("api.anthropic.com")
            .await
            .expect("DoH lookup should succeed (regression: cert trust store)");
        assert!(lookup.iter().next().is_some(), "expected at least one IP");
    }
}
