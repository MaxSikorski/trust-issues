//! Settings from flags and environment variables (for Docker), on top of the
//! config file. Each test runs the real binary's `check-config`, which only
//! reads and checks settings: no network, no server.
//! Precedence: flag, then environment variable, then file, then default.
//! Whatever the route, the same safety rails apply.

use std::path::PathBuf;
use std::process::{Command, Output};

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
    // Malformed lists are refused, not half-read.
    for bad in [
        "just-a-url",
        "a=",
        "=http://10.0.0.2/api",
        "a=http://10.0.0.2/api,,",
    ] {
        let o = base(bad);
        assert!(!o.status.success(), "{bad:?} accepted: {}", out(&o));
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
    assert!(out(&o).contains("network"), "{}", out(&o));
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
    assert!(
        s.contains("rpc_user: lnd (password set in the file)"),
        "{s}"
    );
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
