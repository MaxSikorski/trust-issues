//! The safety rails in the config: signet only, onions through Tor or your
//! own machines, at least two sources, a hard request ceiling.

use bitcoin::Network;
use trust_issues::config::{
    BLOCKSTREAM_ONION, ConfigError, EMZY_ONION, MEMPOOL_ONION, Overrides, Route, load_config,
    parse_checkpoint, parse_config, parse_network, route_for,
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
fn default_signet_config_uses_three_independent_onions_through_tor() {
    let cfg = parse_config("network = \"signet\"\ntor_socks = \"127.0.0.1:9050\"\n").unwrap();
    assert_eq!(cfg.network, Network::Signet);
    assert_eq!(cfg.rpc_bind.to_string(), "127.0.0.1:38332");
    let urls: Vec<_> = cfg.sources.iter().map(|s| s.url.clone()).collect();
    assert_eq!(
        urls,
        vec![
            format!("{MEMPOOL_ONION}/signet/api"),
            format!("{EMZY_ONION}/signet/api"),
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

fn two_local_sources(a: &str, b: &str) -> String {
    format!(
        "network = \"regtest\"\n[[sources]]\nname = \"a\"\nurl = \"{a}\"\n[[sources]]\nname = \"b\"\nurl = \"{b}\"\n"
    )
}

#[test]
fn two_sources_on_one_host_and_port_are_one_source_in_the_file_too() {
    for (a, b) in [
        ("http://127.0.0.1:3002/api", "http://127.0.0.1:3002/api"),
        ("http://127.0.0.1:3002/api", "http://127.0.0.1:3002/api/"),
        ("http://127.0.0.1:3002/x", "http://127.0.0.1:3002/y"),
        ("http://LocalHost:3002", "http://localhost:3002"),
        ("http://127.0.0.1", "http://127.0.0.1:80"),
        ("http://localhost:3002/api", "http://127.0.0.1:3002/api"),
        ("http://127.0.0.2:3002/api", "http://127.0.0.1:3002/api"),
        ("http://[::1]:3002/api", "http://127.0.0.1:3002/api"),
        ("http://[::1]:3002/api", "http://localhost:3002/api"),
        ("http://127.1.2.3:3002/api", "http://127.0.0.1:3002/api"),
    ] {
        let err = parse_config(&two_local_sources(a, b)).unwrap_err();
        assert!(
            err.to_string().contains("same host and port"),
            "{a} {b}: {err}"
        );
    }
    let ok = two_local_sources("http://127.0.0.1:3002", "http://127.0.0.1:3003");
    assert_eq!(parse_config(&ok).unwrap().sources.len(), 2);
    let o = Overrides {
        sources: Some("a=http://10.0.0.2/api,b=http://10.0.0.2/other".into()),
        ..Overrides::default()
    };
    let err = load_config(Some("network = \"regtest\"\n"), &o).unwrap_err();
    assert!(err.to_string().contains("same host and port"), "{err}");
    // The same, spelled as a list (flag or environment variable).
    for list in [
        "a=http://localhost:3002/api,b=http://127.0.0.1:3002/api",
        "a=http://127.0.0.2:3002/api,b=http://127.0.0.1:3002/api",
        "a=http://[::1]:3002/api,b=http://127.0.0.1:3002/api",
    ] {
        let o = Overrides {
            sources: Some(list.into()),
            ..Overrides::default()
        };
        let err = load_config(Some("network = \"regtest\"\n"), &o).unwrap_err();
        assert!(
            err.to_string().contains("same host and port"),
            "{list}: {err}"
        );
    }
    // Different ports on loopback are different explorers.
    let ok = two_local_sources("http://localhost:3002", "http://[::1]:3003");
    assert_eq!(parse_config(&ok).unwrap().sources.len(), 2);
}

#[test]
fn the_unspecified_address_is_never_a_source() {
    for u in ["http://0.0.0.0:3002/api", "http://[::]:3002/api"] {
        assert!(route_for(u, None).is_err(), "{u}");
        let err = parse_config(&two_local_sources(u, "http://127.0.0.1:3003")).unwrap_err();
        assert!(err.to_string().contains("neither"), "{u}: {err}");
    }
}

#[test]
fn syntax_errors_report_only_the_position() {
    for text in [
        "network = \"signet\"\nrpc_password = \"sentinel",
        "__cookie__:sentinel",
        "network = \"signet\"\npoll_interval_secs = \"sentinel\"\n",
    ] {
        let msg = parse_config(text).unwrap_err().to_string();
        assert!(!msg.contains("sentinel"), "{msg}");
        assert!(
            msg.starts_with("config file: line ") && msg.contains(", column "),
            "{msg}"
        );
        assert!(msg.contains("wrong type or syntax"), "{msg}");
    }
    // A wrong type names the key and the expected type, never the value.
    let msg = parse_config("network = \"signet\"\npoll_interval_secs = \"sentinel\"\n")
        .unwrap_err()
        .to_string();
    assert!(msg.contains("poll_interval_secs"), "{msg}");
    assert!(msg.contains("u64"), "{msg}");
    assert!(msg.contains("line 2"), "{msg}");
    // Even a value that imitates the message never gets through.
    let msg = parse_config(
        "network = \"signet\"\npoll_interval_secs = \"sentinel, expected sentinel\"\n",
    )
    .unwrap_err()
    .to_string();
    assert!(!msg.contains("sentinel"), "{msg}");
}

#[test]
fn urls_that_cannot_be_shown_safely_are_not_shown() {
    for u in [
        "http:/reader:sentinel@localhost",
        "reader:sentinel@host",
        "http://reader:sentinel@",
        "http://reader%3Asentinel%40x@host/",
        "http://reader:sentinel%40localhost",
        "http:reader:sentinel@localhost",
        "http://u:sentinel@[::1",
    ] {
        let err = route_for(u, None).unwrap_err().to_string();
        assert!(!err.contains("sentinel"), "{u}: {err}");
        let o = Overrides {
            sources: Some(format!("a={u},b=http://127.0.0.1:3003")),
            ..Overrides::default()
        };
        let err = load_config(Some("network = \"regtest\"\n"), &o)
            .unwrap_err()
            .to_string();
        assert!(!err.contains("sentinel"), "{u}: {err}");
        assert!(err.contains("\"a\""), "names the source: {u}: {err}");
        let err = parse_config(&two_local_sources(u, "http://127.0.0.1:3003"))
            .unwrap_err()
            .to_string();
        assert!(!err.contains("sentinel"), "{u}: {err}");
    }
    // A list entry with no `=` that is really a URL with a login.
    let o = Overrides {
        sources: Some("http://reader:sentinel@host,b=http://127.0.0.1:3003".into()),
        ..Overrides::default()
    };
    let err = load_config(Some("network = \"regtest\"\n"), &o).unwrap_err();
    assert!(!err.to_string().contains("sentinel"), "{err}");
}

#[test]
fn tor_socks_must_be_host_and_port_with_no_login() {
    for bad in [
        "reader:sentinel@tor:9050",
        "sentinel@tor:9050",
        "reader:sentinel:9050",
        "socks5://tor:9050",
    ] {
        let text = format!("network = \"signet\"\ntor_socks = \"{bad}\"\n");
        let err = parse_config(&text).unwrap_err().to_string();
        assert!(err.contains("tor_socks"), "{bad}: {err}");
        assert!(!err.contains("sentinel"), "{bad}: {err}");
        let o = Overrides {
            tor_socks: Some(bad.into()),
            ..Overrides::default()
        };
        let err = load_config(Some("network = \"signet\"\n"), &o)
            .unwrap_err()
            .to_string();
        assert!(!err.contains("sentinel"), "{bad}: {err}");
    }
    for good in [
        "127.0.0.1:9050",
        "tor:9050",
        "[::1]:9050",
        "my-tor_1.lan:9050",
    ] {
        let text = format!("network = \"signet\"\ntor_socks = \"{good}\"\n");
        assert!(parse_config(&text).is_ok(), "{good}");
    }
}

#[test]
fn source_urls_with_a_login_are_refused_and_never_echoed() {
    for u in [
        "http://user:pw-sentinel@127.0.0.1:3002/api",
        "http://pw-sentinel@127.0.0.1/api",
        "http://user:pw-sentinel@[::1",
        "https://user:pw-sentinel@127.0.0.1/api",
    ] {
        let err = route_for(u, None).unwrap_err().to_string();
        assert!(!err.contains("pw-sentinel"), "{u}: {err}");
    }
    let err = route_for("http://user:pw-sentinel@127.0.0.1/api", None).unwrap_err();
    assert!(err.to_string().contains("user name or password"), "{err}");
    let o = Overrides {
        sources: Some("a=http://u:pw-sentinel@10.0.0.2,b=http://10.0.0.3".into()),
        ..Overrides::default()
    };
    let err = load_config(Some("network = \"regtest\"\n"), &o).unwrap_err();
    assert!(!err.to_string().contains("pw-sentinel"), "{err}");
    // The same goes for a malformed entry that happens to hold one.
    let o = Overrides {
        sources: Some("a=http://u:pw-sentinel@10.0.0.2 x,b=http://10.0.0.3".into()),
        ..Overrides::default()
    };
    let err = load_config(Some("network = \"regtest\"\n"), &o).unwrap_err();
    assert!(!err.to_string().contains("pw-sentinel"), "{err}");
}

#[test]
fn numbers_in_the_file_must_be_finite_and_above_the_floor() {
    let two = two_local_sources("http://127.0.0.1:3002", "http://127.0.0.1:3003");
    for line in [
        "fee_ceiling_sat_vb = inf\n",
        "fee_ceiling_sat_vb = nan\n",
        "requests_per_sec = inf\n",
        "requests_per_sec = nan\n",
        "requests_per_sec = 0.001\n",
    ] {
        let err = parse_config(&format!("{line}{two}"))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("fee_ceiling_sat_vb") || err.contains("requests_per_sec"),
            "{line}: {err}"
        );
    }
    assert!(parse_config(&format!("requests_per_sec = 0.01\n{two}")).is_ok());
}

#[test]
fn blank_string_overrides_are_refused_by_name() {
    let file = "network = \"signet\"\ntor_socks = \"127.0.0.1:9050\"\n";
    let cases: Vec<(&str, Overrides)> = vec![
        (
            "network",
            Overrides {
                network: Some(" ".into()),
                ..Default::default()
            },
        ),
        (
            "tor_socks",
            Overrides {
                tor_socks: Some("".into()),
                ..Default::default()
            },
        ),
        (
            "rpc_bind",
            Overrides {
                rpc_bind: Some("".into()),
                ..Default::default()
            },
        ),
        (
            "checkpoint",
            Overrides {
                checkpoint: Some("".into()),
                ..Default::default()
            },
        ),
        (
            "data_dir",
            Overrides {
                data_dir: Some("".into()),
                ..Default::default()
            },
        ),
        (
            "sources",
            Overrides {
                sources: Some("".into()),
                ..Default::default()
            },
        ),
    ];
    for (name, o) in cases {
        let err = load_config(Some(file), &o).unwrap_err().to_string();
        assert!(err.contains(name), "{name}: {err}");
    }
    for bad in ["tor", "tor:0", "tor:70000", ":9050", "a b:9050"] {
        let f = format!("network = \"signet\"\ntor_socks = \"{bad}\"\n");
        let err = parse_config(&f).unwrap_err().to_string();
        assert!(err.contains("tor_socks"), "{bad}: {err}");
    }
}
