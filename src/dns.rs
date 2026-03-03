use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::Result;
use hickory_resolver::Resolver;
use hickory_resolver::config::{NameServerConfig, ResolveHosts, ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::xfer::Protocol;

/// Type alias for our tokio-based resolver.
pub type TokioResolver = Resolver<TokioConnectionProvider>;

/// Cloudflare Family DNS-over-HTTPS endpoint.
/// Uses 1.1.1.3 (malware + adult content blocking) with DoH for encrypted, tamper-resistant queries.
const CLOUDFLARE_FAMILY_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 3));
const CLOUDFLARE_FAMILY_SNI: &str = "family.cloudflare-dns.com";
const DOH_ENDPOINT: &str = "/dns-query";

/// Create a DNS resolver that uses Cloudflare 1.1.1.3 over HTTPS (DoH).
/// This DNS server blocks known malware and adult content domains by returning 0.0.0.0.
/// DoH ensures DNS queries are encrypted and authenticated, preventing interception.
pub fn create_resolver() -> Result<Arc<TokioResolver>> {
    let mut ns = NameServerConfig::new(
        SocketAddr::new(CLOUDFLARE_FAMILY_IP, 443),
        Protocol::Https,
    );
    ns.tls_dns_name = Some(CLOUDFLARE_FAMILY_SNI.to_string());
    ns.http_endpoint = Some(DOH_ENDPOINT.to_string());

    let mut config = ResolverConfig::new();
    config.add_name_server(ns);

    let mut opts = ResolverOpts::default();
    opts.use_hosts_file = ResolveHosts::Never;
    opts.num_concurrent_reqs = 2;

    let resolver = Resolver::builder_with_config(config, TokioConnectionProvider::default())
        .with_options(opts)
        .build();

    Ok(Arc::new(resolver))
}
