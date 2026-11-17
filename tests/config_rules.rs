//! The safety rails in the config: signet only, onions through Tor or your
//! own machines, at least two sources, a hard request ceiling.

use bitcoin::Network;
use trust_issues::config::{
    BLOCKSTREAM_ONION, ConfigError, MEMPOOL_ONION, Route, parse_checkpoint, parse_config,
    parse_network, route_for,
};

#[test]
fn only_signet_and_regtest_are_allowed() {
    assert_eq!(parse_network("signet").unwrap(), Network::Signet);
    assert_eq!(parse_network("Regtest").unwrap(), Network::Regtest);
    for n in ["main", "mainnet", "bitcoin", "testnet", "testnet4", ""] {
        assert!(
            matches!(parse_network(n), Err(ConfigError::UnsupportedNetwork(_))),
            "{n}"
        );
    }
    let err = parse_config("network = \"mainnet\"\n").unwrap_err();
    assert!(err.to_string().contains("signet only"));
}

#[test]
fn onions_go_through_tor_and_clearnet_is_refused() {
    let onion = format!("{MEMPOOL_ONION}/signet/api");
    assert_eq!(
        route_for(&onion, Some("127.0.0.1:9050")).unwrap(),
        Route::Tor("127.0.0.1:9050".into())
    );
    assert!(matches!(
        route_for(&onion, None),
        Err(ConfigError::NeedsTor(_))
    ));
    for u in [
        "http://mempool.space/signet/api",
        "http://8.8.8.8/api",
        "https://192.168.1.5/api",
        "ftp://127.0.0.1/api",
    ] {
        assert!(route_for(u, Some("127.0.0.1:9050")).is_err(), "{u}");
    }
    for u in [
        "http://127.0.0.1:3002/api",
        "http://localhost:3002",
        "http://192.168.1.5:3002/api",
        "http://[::1]:3002",
    ] {
        assert_eq!(route_for(u, None).unwrap(), Route::Direct, "{u}");
    }
}

#[test]
fn default_signet_config_uses_both_onions_through_tor() {
    let cfg = parse_config("network = \"signet\"\ntor_socks = \"127.0.0.1:9050\"\n").unwrap();
    assert_eq!(cfg.network, Network::Signet);
    assert_eq!(cfg.rpc_bind.to_string(), "127.0.0.1:38332");
    let urls: Vec<_> = cfg.sources.iter().map(|s| s.url.clone()).collect();
    assert_eq!(
        urls,
        vec![
            format!("{MEMPOOL_ONION}/signet/api"),
            format!("{BLOCKSTREAM_ONION}/signet/api")
        ]
    );
    assert!(
        cfg.sources
            .iter()
            .all(|s| s.route == Route::Tor("127.0.0.1:9050".into()))
    );
    // Without Tor the default onions can't be used at all.
    assert!(matches!(
        parse_config("network = \"signet\"\n"),
        Err(ConfigError::NeedsTor(_))
    ));
}

#[test]
fn needs_two_sources_and_respects_the_request_ceiling() {
    let one = "network = \"regtest\"\n[[sources]]\nname = \"a\"\nurl = \"http://127.0.0.1:3002\"\n";
    assert!(
        parse_config(one)
            .unwrap_err()
            .to_string()
            .contains("two sources")
    );
    let two = format!("{one}[[sources]]\nname = \"b\"\nurl = \"http://127.0.0.1:3003\"\n");
    assert_eq!(parse_config(&two).unwrap().sources.len(), 2);
    let greedy = format!("requests_per_sec = 10.0\n{two}");
    assert!(
        parse_config(&greedy)
            .unwrap_err()
            .to_string()
            .contains("requests_per_sec")
    );
    assert!(
        parse_config(&format!("bogus = 1\n{two}")).is_err(),
        "unknown keys are refused"
    );
}

#[test]
fn checkpoint_parses_height_and_hash() {
    let hash = "00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6";
    let (h, b) = parse_checkpoint(&format!("0:{hash}")).unwrap();
    assert_eq!(h, 0);
    assert_eq!(b.to_string(), hash);
    assert!(parse_checkpoint("12").is_err());
    assert!(parse_checkpoint("x:abc").is_err());
}
