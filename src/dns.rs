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
