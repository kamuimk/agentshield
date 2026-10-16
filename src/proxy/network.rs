//! Resolve once, validate every address, then connect only to those pinned addresses.

use std::net::{IpAddr, Ipv4Addr};
use tokio::net::{TcpStream, lookup_host};

/// Destination constraints shared by HTTP and CONNECT (including allowlist traffic).
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetworkConfig {
    /// Block loopback, LAN, link-local, multicast and other non-public addresses.
    pub block_private_networks: bool,
    /// Explicit CONNECT ports. Empty lists deny every CONNECT request.
    pub connect_ports: Vec<u16>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            block_private_networks: true,
            connect_ports: vec![443],
        }
    }
}

fn private_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || a == 0
        || a >= 240
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0 && (c == 0 || c == 2))
        || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
        || (a == 203 && b == 0 && c == 113)
}

impl NetworkConfig {
    /// Metadata/link-local addresses are never allowed, even with LAN access enabled.
    pub fn allows_ip(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => {
                !ip.is_link_local()
                    && ip.octets() != [100, 100, 100, 200]
                    && (!self.block_private_networks || !private_v4(ip))
            }
            IpAddr::V6(ip) => {
                if let Some(ip) = ip.to_ipv4_mapped() {
                    return self.allows_ip(IpAddr::V4(ip));
                }
                let [first, second, ..] = ip.segments();
                let link_local = first & 0xffc0 == 0xfe80;
                !link_local
                    && ip != "fd00:ec2::254".parse::<std::net::Ipv6Addr>().unwrap()
                    && (!self.block_private_networks
                        || !(ip.is_loopback()
                            || ip.is_unspecified()
                            || ip.is_multicast()
                            || first & 0xfe00 == 0xfc00
                            || (first == 0x2001 && second == 0xdb8)
                            || first & 0xe000 != 0x2000))
            }
        }
    }
}

/// An address-policy denial is distinct from upstream availability failures.
pub(super) enum ConnectError {
    Denied,
    Unavailable,
}

pub(super) async fn connect(
    target: &str,
    config: &NetworkConfig,
) -> Result<TcpStream, ConnectError> {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let addresses: Vec<_> = lookup_host(target)
            .await
            .map_err(|_| ConnectError::Unavailable)?
            .collect();
        if addresses.is_empty() {
            return Err(ConnectError::Unavailable);
        }
        if addresses.iter().any(|addr| !config.allows_ip(addr.ip())) {
            return Err(ConnectError::Denied);
        }
        for address in addresses {
            if let Ok(stream) = TcpStream::connect(address).await {
                return Ok(stream);
            }
        }
        Err(ConnectError::Unavailable)
    })
    .await
    .map_err(|_| ConnectError::Unavailable)?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_internal_and_metadata_including_mapped_ipv6() {
        let config = NetworkConfig::default();
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.100.100.200",
            "0.0.0.0",
            "224.0.0.1",
            "::1",
            "fd00:ec2::254",
            "fe80::1",
            "::ffff:169.254.169.254",
            "::ffff:127.0.0.1",
        ] {
            assert!(!config.allows_ip(ip.parse().unwrap()), "allowed {ip}");
        }
        for ip in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"] {
            assert!(config.allows_ip(ip.parse().unwrap()));
        }
    }

    #[test]
    fn lan_override_never_opens_link_local_metadata() {
        let config = NetworkConfig {
            block_private_networks: false,
            ..Default::default()
        };
        assert!(config.allows_ip("127.0.0.1".parse().unwrap()));
        assert!(!config.allows_ip("169.254.169.254".parse().unwrap()));
        assert!(!config.allows_ip("::ffff:169.254.169.254".parse().unwrap()));
    }

    #[tokio::test]
    async fn denied_destination_never_accepts_connection() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        assert!(matches!(
            connect(
                &listener.local_addr().unwrap().to_string(),
                &NetworkConfig::default()
            )
            .await,
            Err(ConnectError::Denied)
        ));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(25), listener.accept())
                .await
                .is_err()
        );
    }
}
