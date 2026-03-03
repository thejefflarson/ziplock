use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::Result;
use hickory_resolver::Resolver;
use hickory_resolver::config::{NameServerConfig, ResolveHosts, ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::xfer::Protocol;

/// Type alias for our tokio-based resolver.
pub type TokioResolver = Resolver<TokioConnectionProvider>;

/// Cloudflare family DNS (malware + adult content blocking).
const CLOUDFLARE_FAMILY_DNS: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 3));

/// Create a DNS resolver that uses Cloudflare 1.1.1.3 as the sole upstream.
/// This DNS server blocks known malware and adult content domains by returning 0.0.0.0.
pub fn create_resolver() -> Result<Arc<TokioResolver>> {
    let mut config = ResolverConfig::new();
    config.add_name_server(NameServerConfig::new(
        SocketAddr::new(CLOUDFLARE_FAMILY_DNS, 53),
        Protocol::Udp,
    ));
    config.add_name_server(NameServerConfig::new(
        SocketAddr::new(CLOUDFLARE_FAMILY_DNS, 53),
        Protocol::Tcp,
    ));

    let mut opts = ResolverOpts::default();
    opts.use_hosts_file = ResolveHosts::Never;
    opts.num_concurrent_reqs = 2;

    let resolver = Resolver::builder_with_config(config, TokioConnectionProvider::default())
        .with_options(opts)
        .build();

    Ok(Arc::new(resolver))
}
