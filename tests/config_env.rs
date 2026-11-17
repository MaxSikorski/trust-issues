//! Settings from flags and environment variables (for Docker), on top of the
//! config file. Each test runs the real binary's `check-config`, which only
//! reads and checks settings: no network, no server.
//! Precedence: flag, then environment variable, then file, then default.
//! Whatever the route, the same safety rails apply.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use trust_issues::config::{EMZY_ONION, MEMPOOL_ONION};

fn bin() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_trust-issues"));
    // Only the variables a test sets: nothing leaks in from the shell.
    c.env_clear();
    c
}

fn file(name: &str, text: &str) -> PathBuf {
    let p = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("config_env_{name}.toml"));
    std::fs::write(&p, text).unwrap();
    p
}

fn out(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

#[test]
fn environment_variables_alone_are_enough() {
    let o = bin()
        .arg("check-config")
        .env("TRUST_ISSUES_NETWORK", "signet")
        .env("TRUST_ISSUES_TOR_SOCKS", "tor:9050")
        .env("TRUST_ISSUES_RPC_BIND", "0.0.0.0:38332")
        .env("TRUST_ISSUES_DATA_DIR", "/data")
        .output()
        .unwrap();
    let s = out(&o);
    assert!(o.status.success(), "{s}");
    assert!(s.contains("network: signet"), "{s}");
    assert!(s.contains("rpc_bind: 0.0.0.0:38332"), "{s}");
    assert!(s.contains("data_dir: /data"), "{s}");
    // The default onions, through the Tor named in the environment.
    assert!(
        s.contains(&format!(
            "mempool.space {MEMPOOL_ONION}/signet/api via Tor at tor:9050"
        )),
        "{s}"
    );
    assert!(s.contains(EMZY_ONION), "{s}");
}

#[test]
fn flags_beat_environment_variables_which_beat_the_file() {
    let f = file(
        "precedence",
        "network = \"signet\"\ntor_socks = \"127.0.0.1:9050\"\npoll_interval_secs = 60\nrpc_bind = \"127.0.0.1:38332\"\n",
    );
    let o = bin()
        .args(["check-config", "--config"])
        .arg(&f)
        .args(["--poll-interval-secs", "20"])
        .env("TRUST_ISSUES_POLL_INTERVAL_SECS", "30")
        .env("TRUST_ISSUES_RPC_BIND", "127.0.0.1:48332")
        .output()
        .unwrap();
    let s = out(&o);
    assert!(o.status.success(), "{s}");
    assert!(s.contains("poll_interval_secs: 20"), "flag wins: {s}");
    assert!(
        s.contains("rpc_bind: 127.0.0.1:48332"),
        "env beats file: {s}"
    );
    assert!(s.contains("via Tor at 127.0.0.1:9050"), "file kept: {s}");
}

#[test]
fn neither_a_flag_nor_an_environment_variable_can_pick_mainnet() {
    let f = file(
        "signet",
        "network = \"signet\"\ntor_socks = \"127.0.0.1:9050\"\n",
    );
    for net in ["mainnet", "bitcoin", "testnet", "testnet4"] {
        let o = bin()
            .args(["check-config", "--config"])
            .arg(&f)
            .env("TRUST_ISSUES_NETWORK", net)
            .output()
            .unwrap();
        assert!(!o.status.success(), "{net} accepted: {}", out(&o));
        assert!(out(&o).contains("signet only"), "{}", out(&o));
        let o = bin()
            .args(["check-config", "--config"])
            .arg(&f)
            .args(["--network", net])
            .output()
            .unwrap();
        assert!(!o.status.success(), "{net} accepted by flag: {}", out(&o));
        assert!(out(&o).contains("signet only"), "{}", out(&o));
    }
}

#[test]
fn sources_from_the_environment_follow_the_same_rules() {
    let base = |sources: &str| {
        bin()
            .arg("check-config")
            .env("TRUST_ISSUES_NETWORK", "signet")
            .env("TRUST_ISSUES_TOR_SOCKS", "tor:9050")
            .env("TRUST_ISSUES_SOURCES", sources)
            .output()
            .unwrap()
    };
    // Clearnet explorers are refused.
    let o = base("a=http://203.0.113.5/api,b=http://192.168.1.20:3002/api");
    assert!(!o.status.success());
    assert!(out(&o).contains("neither a .onion"), "{}", out(&o));
    // One source alone could hide blocks.
    let o = base("mine=http://192.168.1.20:3002/api");
    assert!(!o.status.success());
    assert!(out(&o).contains("at least two sources"), "{}", out(&o));
    // Malformed lists are refused, not half-read. Each bad entry sits next to
    // two good ones, so only the entry check can be what refuses it.
    let good = "g1=http://10.0.0.2/api,g2=http://10.0.0.3/api";
    for list in [
        format!("just-a-url,{good}"),
        format!("a=,{good}"),
        format!("=http://10.0.0.9/api,{good}"),
        format!("{good},"),
        "g1=http://10.0.0.2/api,,g2=http://10.0.0.3/api".to_string(),
    ] {
        let o = base(&list);
        assert!(!o.status.success(), "{list:?} accepted: {}", out(&o));
        assert!(
            out(&o).contains("must look like name=url"),
            "{list:?}: {}",
            out(&o)
        );
    }
    // An onion and a machine at home: accepted, each routed its own way.
    let o = base(&format!(
        "mempool.space={MEMPOOL_ONION}/signet/api,home=http://192.168.1.20:3002/api"
    ));
    let s = out(&o);
    assert!(o.status.success(), "{s}");
    assert!(s.contains("via Tor at tor:9050"), "{s}");
    assert!(
        s.contains("home http://192.168.1.20:3002/api directly"),
        "{s}"
    );
}

#[test]
fn the_network_must_be_set_somewhere() {
    let o = bin().arg("check-config").output().unwrap();
    assert!(!o.status.success());
    assert!(out(&o).contains("network must be set"), "{}", out(&o));
}

#[test]
fn passwords_never_come_from_flags_or_the_environment() {
    // `docker inspect` and `ps` show both; the cookie file covers containers.
    for flag in ["--rpc-password", "--rpc-user"] {
        let o = bin()
            .args(["check-config", flag, "x"])
            .env("TRUST_ISSUES_NETWORK", "signet")
            .output()
            .unwrap();
        assert!(!o.status.success(), "{flag} accepted");
        assert!(
            out(&o).contains("unexpected argument"),
            "{flag}: {}",
            out(&o)
        );
    }
    let f = file(
        "password",
        "network = \"signet\"\ntor_socks = \"127.0.0.1:9050\"\nrpc_user = \"lnd\"\nrpc_password = \"generated-regtest-only\"\n",
    );
    let o = bin()
        .args(["check-config", "--config"])
        .arg(&f)
        .env("TRUST_ISSUES_RPC_PASSWORD", "from-env")
        .output()
        .unwrap();
    let s = out(&o);
    assert!(o.status.success(), "{s}");
    // Stricter than before: the user name is no longer printed at all.
    assert!(
        s.contains("rpc_auth: user and password set in the file"),
        "{s}"
    );
    assert!(!s.contains("lnd") && !s.contains("rpc_user"), "{s}");
    assert!(
        !s.contains("generated-regtest-only") && !s.contains("from-env"),
        "{s}"
    );
}

#[test]
fn the_old_command_lines_still_work() {
    // `--config <file>` and `health-check --config <file> [--synced]` as in
    // the README and systemd units. Nothing listens on port 1, so the health
    // check says so and exits 1, without touching the network.
    let f = file(
        "health",
        "network = \"signet\"\ntor_socks = \"127.0.0.1:9050\"\nrpc_bind = \"127.0.0.1:1\"\n",
    );
    for extra in [&[][..], &["--synced"][..]] {
        let o = bin()
            .args(["health-check", "--config"])
            .arg(&f)
            .args(extra)
            .output()
            .unwrap();
        assert_eq!(o.status.code(), Some(1), "{}", out(&o));
        assert!(
            out(&o).contains("not answering on 127.0.0.1:1"),
            "{}",
            out(&o)
        );
    }
}

fn base_env(c: &mut Command) -> &mut Command {
    c.env("TRUST_ISSUES_NETWORK", "signet")
        .env("TRUST_ISSUES_TOR_SOCKS", "tor:9050")
}

/// Answers `GET /health` on a loopback port, with "synced" the test can flip.
fn health_server(synced: Arc<AtomicBool>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);
            let body = format!(
                "{{\"status\":\"ok\",\"ready\":true,\"synced\":{}}}",
                synced.load(Ordering::SeqCst)
            );
            let _ = write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    port
}

#[test]
fn health_check_synced_follows_what_the_server_says() {
    let synced = Arc::new(AtomicBool::new(false));
    let port = health_server(synced.clone());
    let f = file(
        "health_server",
        &format!(
            "network = \"signet\"\ntor_socks = \"127.0.0.1:9050\"\nrpc_bind = \"127.0.0.1:{port}\"\n"
        ),
    );
    let run = |extra: &[&str]| {
        bin()
            .args(["health-check", "--config"])
            .arg(&f)
            .args(extra)
            .output()
            .unwrap()
    };
    assert_eq!(run(&[]).status.code(), Some(0));
    let o = run(&["--synced"]);
    assert_eq!(o.status.code(), Some(1), "{}", out(&o));
    assert!(out(&o).contains("not synced"), "{}", out(&o));
    synced.store(true, Ordering::SeqCst);
    assert_eq!(run(&[]).status.code(), Some(0));
    assert_eq!(run(&["--synced"]).status.code(), Some(0));
}

#[test]
fn the_bare_old_form_works_with_the_flag_on_either_side() {
    let f = file(
        "bare",
        "network = \"signet\"\ntor_socks = \"127.0.0.1:9050\"\n",
    );
    let o = bin()
        .arg("--config")
        .arg(&f)
        .arg("check-config")
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", out(&o));
    assert!(out(&o).contains("network: signet"), "{}", out(&o));
    let o = bin()
        .arg("check-config")
        .arg("--config")
        .arg(&f)
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", out(&o));
    assert!(out(&o).contains("network: signet"), "{}", out(&o));
}

#[test]
fn a_repeated_config_flag_is_refused_and_a_dash_name_is_allowed() {
    let a = file(
        "rep_a",
        "network = \"signet\"\ntor_socks = \"127.0.0.1:9050\"\n",
    );
    let b = file(
        "rep_b",
        "network = \"regtest\"\ntor_socks = \"127.0.0.1:9050\"\n",
    );
    let o = bin()
        .arg("--config")
        .arg(&a)
        .arg("check-config")
        .arg("--config")
        .arg(&b)
        .output()
        .unwrap();
    assert!(!o.status.success(), "{}", out(&o));
    assert!(out(&o).contains("more than once"), "{}", out(&o));
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    std::fs::write(
        dir.join("-dash.toml"),
        "network = \"signet\"\ntor_socks = \"127.0.0.1:9050\"\n",
    )
    .unwrap();
    let o = bin()
        .current_dir(&dir)
        .args(["check-config", "--config", "-dash.toml"])
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", out(&o));
}

#[test]
fn syntax_errors_never_echo_the_file() {
    let secret = "sentinel-secret-value";
    // An unterminated string, and a cookie file given by mistake.
    for (name, text) in [
        (
            "unterminated",
            format!("network = \"signet\"\nrpc_password = \"{secret}"),
        ),
        ("cookie", format!("__cookie__:{secret}")),
        (
            "wrong_type",
            format!("network = \"signet\"\npoll_interval_secs = \"{secret}\"\n"),
        ),
    ] {
        let f = file(name, &text);
        let o = bin()
            .args(["check-config", "--config"])
            .arg(&f)
            .output()
            .unwrap();
        assert!(!o.status.success(), "{name}");
        assert!(
            !out(&o).contains(secret),
            "{name} echoed the file: {}",
            out(&o)
        );
        assert!(
            out(&o).contains("syntax error at line"),
            "{name}: {}",
            out(&o)
        );
    }
}

#[test]
fn check_config_names_no_user_and_sources_carry_no_login() {
    let f = file(
        "auth_user_only",
        "network = \"signet\"\ntor_socks = \"127.0.0.1:9050\"\nrpc_user = \"sentinel-user\"\n",
    );
    let o = bin()
        .args(["check-config", "--config"])
        .arg(&f)
        .output()
        .unwrap();
    let s = out(&o);
    assert!(
        s.contains("rpc_auth: user set in the file (no password)"),
        "{s}"
    );
    assert!(!s.contains("sentinel-user"), "{s}");
    let o = base_env(&mut bin()).arg("check-config").output().unwrap();
    assert!(out(&o).contains("rpc_auth: cookie only"), "{}", out(&o));
    // A login inside a source URL is refused, and never echoed.
    let o = base_env(&mut bin())
        .arg("check-config")
        .env(
            "TRUST_ISSUES_SOURCES",
            "a=http://user:pw-sentinel@127.0.0.1:3002/api,b=http://127.0.0.2/api",
        )
        .output()
        .unwrap();
    assert!(!o.status.success(), "{}", out(&o));
    assert!(out(&o).contains("user name or password"), "{}", out(&o));
    assert!(!out(&o).contains("pw-sentinel"), "{}", out(&o));
    // `--help` never shows what the environment holds.
    let o = bin()
        .arg("--help")
        .env("TRUST_ISSUES_NETWORK", "sentinel-net")
        .env("TRUST_ISSUES_SOURCES", "a=http://u:pw-sentinel@h/x")
        .output()
        .unwrap();
    assert!(!out(&o).contains("sentinel"), "{}", out(&o));
}

#[test]
fn numbers_must_be_finite_and_requests_must_reach_the_limiters_floor() {
    let run = |var: &str, val: &str| {
        base_env(&mut bin())
            .arg("check-config")
            .env(var, val)
            .output()
            .unwrap()
    };
    for v in ["1e309", "inf", "nan", "0"] {
        let o = run("TRUST_ISSUES_FEE_CEILING_SAT_VB", v);
        assert!(!o.status.success(), "{v}: {}", out(&o));
        assert!(out(&o).contains("fee_ceiling_sat_vb"), "{v}: {}", out(&o));
    }
    for v in ["1e309", "inf", "nan", "0", "0.001", "0.0099", "3"] {
        let o = run("TRUST_ISSUES_REQUESTS_PER_SEC", v);
        assert!(!o.status.success(), "{v}: {}", out(&o));
        assert!(out(&o).contains("requests_per_sec"), "{v}: {}", out(&o));
    }
    assert!(out(&run("TRUST_ISSUES_REQUESTS_PER_SEC", "0.001")).contains("0.01"));
    for v in ["0.01", "2"] {
        let o = run("TRUST_ISSUES_REQUESTS_PER_SEC", v);
        assert!(o.status.success(), "{v}: {}", out(&o));
    }
    let o = run("TRUST_ISSUES_POLL_INTERVAL_SECS", "abc");
    assert!(!o.status.success());
    assert!(out(&o).contains("poll_interval_secs"), "{}", out(&o));
}

#[test]
fn a_blank_value_never_overrides_the_file_and_tor_must_be_host_and_port() {
    let f = file(
        "blank",
        "network = \"signet\"\ntor_socks = \"127.0.0.1:9050\"\n",
    );
    for setting in [
        "network",
        "tor_socks",
        "rpc_bind",
        "data_dir",
        "poll_interval_secs",
        "checkpoint",
        "requests_per_sec",
        "fee_ceiling_sat_vb",
        "sources",
    ] {
        let var = format!("TRUST_ISSUES_{}", setting.to_ascii_uppercase());
        for blank in ["", "  "] {
            let o = bin()
                .args(["check-config", "--config"])
                .arg(&f)
                .env(&var, blank)
                .output()
                .unwrap();
            assert!(!o.status.success(), "{var}={blank:?}: {}", out(&o));
            // clap itself refuses an empty path, naming the flag with a dash.
            let dashed = setting.replace('_', "-");
            assert!(
                out(&o).contains(setting) || out(&o).contains(&dashed),
                "{var}={blank:?}: {}",
                out(&o)
            );
        }
    }
    let o = bin()
        .args(["check-config", "--config"])
        .arg(&f)
        .args(["--tor-socks", ""])
        .output()
        .unwrap();
    assert!(!o.status.success(), "{}", out(&o));
    assert!(out(&o).contains("tor_socks"), "{}", out(&o));
    for bad in ["tor", "tor:0", "tor:99999", ":9050", "a b:9050", "tor:x"] {
        let o = bin()
            .args(["check-config", "--config"])
            .arg(&f)
            .env("TRUST_ISSUES_TOR_SOCKS", bad)
            .output()
            .unwrap();
        assert!(!o.status.success(), "{bad:?} accepted: {}", out(&o));
        assert!(out(&o).contains("tor_socks"), "{bad:?}: {}", out(&o));
    }
    // Stray whitespace around a good value is trimmed.
    let o = bin()
        .args(["check-config", "--config"])
        .arg(&f)
        .env("TRUST_ISSUES_TOR_SOCKS", " tor:9050\n")
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", out(&o));
    assert!(out(&o).contains("via Tor at tor:9050"), "{}", out(&o));
}

#[test]
fn only_the_winning_number_is_parsed() {
    let o = base_env(&mut bin())
        .args(["check-config", "--poll-interval-secs", "20"])
        .env("TRUST_ISSUES_POLL_INTERVAL_SECS", "30\n")
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", out(&o));
    assert!(out(&o).contains("poll_interval_secs: 20"), "{}", out(&o));
    let o = base_env(&mut bin())
        .arg("check-config")
        .env("TRUST_ISSUES_POLL_INTERVAL_SECS", "30\n")
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", out(&o));
    assert!(out(&o).contains("poll_interval_secs: 30"), "{}", out(&o));
}

#[test]
fn spaces_inside_a_sources_entry_are_refused() {
    for list in [
        "a=http://127.0.0.1:1/api,b=http://127.0.0.2/api c=http://127.0.0.3",
        "a b=http://127.0.0.1:1/api,b=http://127.0.0.2/api",
        "a=http://127.0.0.1:1/ api,b=http://127.0.0.2/api",
    ] {
        let o = base_env(&mut bin())
            .arg("check-config")
            .env("TRUST_ISSUES_SOURCES", list)
            .output()
            .unwrap();
        assert!(!o.status.success(), "{list:?}: {}", out(&o));
        assert!(out(&o).contains("whitespace"), "{list:?}: {}", out(&o));
    }
}

#[test]
fn duplicate_sources_are_refused_from_flags_and_the_environment() {
    for list in [
        "a=http://127.0.0.1:3002/api,b=http://127.0.0.1:3002/api",
        "a=http://127.0.0.1:3002/api,b=http://127.0.0.1:3002/api/",
        "a=http://127.0.0.1:3002/x,b=http://127.0.0.1:3002/y",
        "a=http://LOCALHOST:3002,b=http://localhost:3002",
        &format!("a={MEMPOOL_ONION}/signet/api,b={MEMPOOL_ONION}/signet/api"),
    ] {
        let o = base_env(&mut bin())
            .args(["check-config", "--sources", list])
            .output()
            .unwrap();
        assert!(!o.status.success(), "{list:?}: {}", out(&o));
        assert!(
            out(&o).contains("same host and port"),
            "{list:?}: {}",
            out(&o)
        );
    }
    // A different port on one machine is a different explorer.
    let o = base_env(&mut bin())
        .arg("check-config")
        .env(
            "TRUST_ISSUES_SOURCES",
            "a=http://127.0.0.1:3002/api,b=http://127.0.0.1:3003/api",
        )
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", out(&o));
}

#[test]
fn a_password_in_the_environment_is_ignored_loudly_and_never_echoed() {
    let o = base_env(&mut bin())
        .arg("check-config")
        .env("TRUST_ISSUES_RPC_PASSWORD", "pw-sentinel")
        .env("TRUST_ISSUES_RPC_USER", "user-sentinel")
        .output()
        .unwrap();
    let s = out(&o);
    assert!(o.status.success(), "{s}");
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.contains("TRUST_ISSUES_RPC_PASSWORD") && err.contains("ignored"),
        "{err}"
    );
    assert!(err.contains("TRUST_ISSUES_RPC_USER"), "{err}");
    assert!(
        !s.contains("pw-sentinel") && !s.contains("user-sentinel"),
        "{s}"
    );
}
