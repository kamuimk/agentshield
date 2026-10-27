use agentshield::policy::config::{AppConfig, validate_config};
use agentshield::proxy::network::NetworkConfig;

fn config(network: &str) -> AppConfig {
    toml::from_str(&format!(
        "[proxy]\nlisten=\"127.0.0.1:18080\"\n[policy]\ndefault=\"deny\"\n[network]\n{network}\n"
    ))
    .unwrap()
}

#[test]
fn loopback_is_opt_in_and_does_not_change_private_network_default() {
    let default = config("");
    assert!(default.network.block_private_networks);
    assert!(default.network.loopback_endpoint.is_none());
    let configured = config("loopback_endpoint=\"127.0.0.1:39001\"");
    assert!(configured.network.block_private_networks);
    assert_eq!(configured.network.connect_ports, [443]);
    assert!(!validate_config(&configured).has_errors());
    let roundtrip: NetworkConfig =
        toml::from_str(&toml::to_string(&configured.network).unwrap()).unwrap();
    assert_eq!(
        roundtrip.loopback_endpoint,
        configured.network.loopback_endpoint
    );
    assert!(!roundtrip.allows_ip("127.0.0.1".parse().unwrap()));
    assert!(!roundtrip.allows_ip("169.254.169.254".parse().unwrap()));
}

#[test]
fn loopback_configuration_rejects_zero_metadata_lan_and_wildcard() {
    for endpoint in [
        "127.0.0.1:0",
        "127.0.0.2:39001",
        "169.254.169.254:80",
        "10.0.0.1:39001",
        "0.0.0.0:39001",
        "100.100.100.200:80",
    ] {
        assert!(
            validate_config(&config(&format!("loopback_endpoint=\"{endpoint}\""))).has_errors(),
            "{endpoint}"
        );
    }
}

#[test]
fn loopback_configuration_has_no_dns_uri_or_ipv6_alias_form() {
    for endpoint in [
        "localhost:39001",
        "http://127.0.0.1:39001",
        "[::1]:39001",
        "[::ffff:127.0.0.1]:39001",
        "127.1:39001",
        "127.0.0.1",
    ] {
        assert!(
            toml::from_str::<NetworkConfig>(&format!("loopback_endpoint=\"{endpoint}\"")).is_err(),
            "{endpoint}"
        );
    }
}
