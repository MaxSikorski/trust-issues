//! `trust-issues [--config <file>] [flags]`: run the stand-in bitcoind.
//! `trust-issues health-check [--synced]`: ask a running one whether it's up
//! (and synced), for Docker's HEALTHCHECK and scripts.
//! `trust-issues check-config`: print the settings and exit.

use std::sync::Arc;
use std::time::Duration;

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{ArgMatches, CommandFactory, FromArgMatches, Parser, Subcommand};
use tracing::{info, warn};
use trust_issues::config::{Config, Overrides, Route, load_config};
use trust_issues::esplora::EsploraSource;
use trust_issues::limits::{DEFAULT_BURST, os_jitter};
use trust_issues::node::{Node, Settings, SystemClock};
use trust_issues::rpc::{Auth, router};
use trust_issues::source::Source;
use trust_issues::systemd;

/// Settings come from these flags, then `TRUST_ISSUES_*` variables, then the
/// config file. The RPC user and password are file-only on purpose.
#[derive(Parser)]
#[command(
    version,
    about = "A stand-in bitcoind that reads the chain from block explorers over Tor"
)]
struct Cli {
    /// signet (or regtest for tests)
    #[arg(
        long,
        global = true,
        env = "TRUST_ISSUES_NETWORK",
        hide_env_values = true
    )]
    network: Option<String>,
    /// Address of Tor's SOCKS port, like 127.0.0.1:9050
    #[arg(
        long,
        global = true,
        env = "TRUST_ISSUES_TOR_SOCKS",
        hide_env_values = true
    )]
    tor_socks: Option<String>,
    /// Where the RPC listens, like 127.0.0.1:38332
    #[arg(
        long,
        global = true,
        env = "TRUST_ISSUES_RPC_BIND",
        hide_env_values = true
    )]
    rpc_bind: Option<String>,
    /// Where the cookie file goes
    #[arg(
        long,
        global = true,
        env = "TRUST_ISSUES_DATA_DIR",
        hide_env_values = true
    )]
    data_dir: Option<PathBuf>,
    #[arg(
        long,
        global = true,
        env = "TRUST_ISSUES_POLL_INTERVAL_SECS",
        hide_env_values = true
    )]
    poll_interval_secs: Option<String>,
    /// "<height>:<block hash>"
    #[arg(
        long,
        global = true,
        env = "TRUST_ISSUES_CHECKPOINT",
        hide_env_values = true
    )]
    checkpoint: Option<String>,
    #[arg(
        long,
        global = true,
        env = "TRUST_ISSUES_REQUESTS_PER_SEC",
        hide_env_values = true
    )]
    requests_per_sec: Option<String>,
    #[arg(
        long,
        global = true,
        env = "TRUST_ISSUES_FEE_CEILING_SAT_VB",
        hide_env_values = true
    )]
    fee_ceiling_sat_vb: Option<String>,
    /// name=url,name=url (replaces the file's sources)
    #[arg(
        long,
        global = true,
        env = "TRUST_ISSUES_SOURCES",
        hide_env_values = true
    )]
    sources: Option<String>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Ask a running server whether it's up (for Docker's HEALTHCHECK)
    HealthCheck {
        /// Also require it to be synced
        #[arg(long)]
        synced: bool,
    },
    /// Read and check the settings, print them, and exit (no network)
    CheckConfig,
}

/// The `--config` flag, added to the program and to each subcommand so that
/// clap keeps what was typed in each place instead of letting the last win.
fn config_arg() -> clap::Arg {
    clap::Arg::new("config")
        .long("config")
        .value_name("CONFIG")
        .help("Optional config file (TOML)")
        .env("TRUST_ISSUES_CONFIG")
        .hide_env_values(true)
        .allow_hyphen_values(true)
        .action(clap::ArgAction::Append)
        .value_parser(clap::value_parser!(PathBuf))
}

fn command() -> clap::Command {
    Cli::command()
        .arg(config_arg())
        .mut_subcommand("check-config", |s| s.arg(config_arg()))
        .mut_subcommand("health-check", |s| s.arg(config_arg()))
}

/// The config file named on the command line, else in the environment.
/// Refuses two `--config` flags. Only the places clap parsed as the flag count,
/// so a file that is itself named `--config` is just a value.
fn config_path(m: &ArgMatches) -> Result<Option<PathBuf>> {
    let from_flag = |m: &ArgMatches| -> Vec<PathBuf> {
        if m.value_source("config") == Some(clap::parser::ValueSource::CommandLine) {
            m.get_many::<PathBuf>("config")
                .map(|v| v.cloned().collect())
                .unwrap_or_default()
        } else {
            Vec::new()
        }
    };
    let mut flags = from_flag(m);
    if let Some((_, sub)) = m.subcommand() {
        flags.extend(from_flag(sub));
    }
    if flags.len() > 1 {
        bail!("--config was given more than once; pass one config file");
    }
    Ok(flags
        .pop()
        .or_else(|| m.get_one::<PathBuf>("config").cloned()))
}

fn load(cli: &Cli, matches: &ArgMatches) -> Result<Config> {
    let text = match config_path(matches)? {
        Some(p) => {
            Some(std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?)
        }
        None => None,
    };
    let o = Overrides {
        network: cli.network.clone(),
        tor_socks: cli.tor_socks.clone(),
        rpc_bind: cli.rpc_bind.clone(),
        data_dir: cli.data_dir.clone(),
        poll_interval_secs: cli.poll_interval_secs.clone(),
        checkpoint: cli.checkpoint.clone(),
        requests_per_sec: cli.requests_per_sec.clone(),
        fee_ceiling_sat_vb: cli.fee_ceiling_sat_vb.clone(),
        sources: cli.sources.clone(),
    };
    load_config(text.as_deref(), &o).map_err(|e| anyhow::anyhow!("{e}"))
}

/// Print the settings that would be used. Never the password.
fn print_config(cfg: &Config) {
    println!("network: {}", cfg.network);
    println!("rpc_bind: {}", cfg.rpc_bind);
    println!("data_dir: {}", cfg.data_dir.display());
    println!("poll_interval_secs: {}", cfg.poll_interval_secs);
    match &cfg.checkpoint {
        Some((h, hash)) => println!("checkpoint: {h}:{hash}"),
        None => println!("checkpoint: none"),
    }
    println!("requests_per_sec: {}", cfg.requests_per_sec);
    println!("fee_ceiling_sat_vb: {}", cfg.fee_ceiling_sat_vb);
    // Whether, never who: the user name is as private as the password.
    println!(
        "rpc_auth: {}",
        match (&cfg.rpc_user, &cfg.rpc_password) {
            (Some(_), Some(_)) => "user and password set in the file",
            (Some(_), None) => "user set in the file (no password)",
            (None, Some(_)) => "password set in the file (no user)",
            (None, None) => "cookie only",
        }
    );
    println!("sources:");
    for s in &cfg.sources {
        match &s.route {
            Route::Tor(socks) => println!("  {} {} via Tor at {socks}", s.name, s.url),
            Route::Direct => println!("  {} {} directly", s.name, s.url),
        }
    }
}

/// The RPC user and password are file-only; say so if someone tried the
/// environment, which `docker inspect` would expose. Names only, never values.
fn warn_ignored_credentials() {
    for var in ["TRUST_ISSUES_RPC_PASSWORD", "TRUST_ISSUES_RPC_USER"] {
        if std::env::var_os(var).is_some() {
            eprintln!(
                "warning: {var} is ignored on purpose (the environment is visible to docker inspect); use the config file or the cookie"
            );
        }
    }
}

/// Ask the running server on this machine for `GET /health`. Exits 0 when
/// it answers (and, with `--synced`, says it's synced); 1 otherwise.
async fn health_check(bind: std::net::SocketAddr, require_synced: bool) -> ! {
    let mut addr = bind;
    if addr.ip().is_unspecified() {
        addr.set_ip(match addr {
            std::net::SocketAddr::V4(_) => std::net::Ipv4Addr::LOCALHOST.into(),
            std::net::SocketAddr::V6(_) => std::net::Ipv6Addr::LOCALHOST.into(),
        });
    }
    let answer = async {
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .map_err(|e| e.to_string())?;
        let r = client
            .get(format!("http://{addr}/health"))
            .send()
            .await
            .and_then(|r| r.error_for_status())
            .map_err(|e| e.to_string())?;
        let body = r.bytes().await.map_err(|e| e.to_string())?;
        serde_json::from_slice::<serde_json::Value>(&body).map_err(|e| e.to_string())
    }
    .await;
    match answer {
        Ok(v) => {
            let synced = v["synced"].as_bool().unwrap_or(false);
            println!("up, {}", if synced { "synced" } else { "not synced" });
            std::process::exit(if require_synced && !synced { 1 } else { 0 });
        }
        Err(e) => {
            println!("not answering on {addr}: {e}");
            std::process::exit(1);
        }
    }
}

/// Wait for Ctrl-C or SIGTERM (what systemd and Docker send to stop us).
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
    systemd::stopping();
    info!("shutting down");
}

fn status_line(node: &Node) -> String {
    format!(
        "{}, tip {}, {} healthy sources",
        if node.is_synced() {
            "synced"
        } else {
            "NOT synced"
        },
        node.with_chain(|c| c.tip_height()),
        node.healthy_count()
    )
}

fn random_hex(n: usize) -> Result<String> {
    let mut b = vec![0u8; n];
    getrandom::fill(&mut b).map_err(|e| anyhow::anyhow!("no randomness: {e}"))?;
    Ok(b.iter().map(|x| format!("{x:02x}")).collect())
}

/// Write `__cookie__:<random>` readable only by us, like bitcoind's `.cookie`.
fn write_cookie(dir: &std::path::Path, password: &str) -> Result<std::path::PathBuf> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let path = dir.join(".cookie");
    let tmp = dir.join(".cookie.tmp");
    // Created at 0600, never readable by others even for a moment (the data
    // dir may be a shared bind mount). A leftover .tmp from a crash, or
    // anything planted there, is removed and never written through.
    match std::fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("removing {}", tmp.display())),
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    {
        use std::io::Write;
        let mut f = opts
            .open(&tmp)
            .with_context(|| format!("creating {}", tmp.display()))?;
        f.write_all(format!("__cookie__:{password}").as_bytes())?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, &path)?;
    Ok(path)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let matches = command().get_matches();
    let cli = Cli::from_arg_matches(&matches)?;
    if !matches!(cli.command, Some(Command::HealthCheck { .. })) {
        warn_ignored_credentials();
    }
    let cfg = match load(&cli, &matches) {
        Ok(c) => c,
        Err(e) if matches!(cli.command, Some(Command::CheckConfig)) => {
            eprintln!("{e:#}");
            std::process::exit(2);
        }
        Err(e) => return Err(e),
    };
    match cli.command {
        Some(Command::CheckConfig) => {
            print_config(&cfg);
            return Ok(());
        }
        Some(Command::HealthCheck { synced }) => health_check(cfg.rpc_bind, synced).await,
        None => {}
    }
    if !cfg.rpc_bind.ip().is_loopback() {
        warn!(bind = %cfg.rpc_bind, "RPC is listening beyond this machine; keep it on a private network");
    }

    let mut sources: Vec<Arc<dyn Source>> = Vec::new();
    for spec in &cfg.sources {
        let s =
            EsploraSource::new(spec).map_err(|e| anyhow::anyhow!("source {}: {e}", spec.name))?;
        info!(source = %spec.name, route = ?spec.route, "source configured");
        sources.push(Arc::new(s));
    }
    if sources.len() < 2 {
        bail!("at least two sources are needed");
    }

    let node = Arc::new(Node::new(
        Settings {
            network: cfg.network,
            checkpoint: cfg.checkpoint,
            fee_ceiling_sat_vb: cfg.fee_ceiling_sat_vb,
            requests_per_sec: cfg.requests_per_sec,
            burst: DEFAULT_BURST,
            jitter: os_jitter,
        },
        sources,
        Arc::new(SystemClock),
    ));

    let cookie_password = random_hex(32)?;
    let cookie_path = write_cookie(&cfg.data_dir, &cookie_password)?;
    info!(cookie = %cookie_path.display(), "RPC cookie written");

    let poller = node.clone();
    let interval = Duration::from_secs(cfg.poll_interval_secs);
    tokio::spawn(async move {
        loop {
            poller.tick().await;
            systemd::status(&status_line(&poller));
            tokio::time::sleep(interval).await;
        }
    });

    // The watchdog pings only while the node is making progress, so a hang
    // gets us restarted instead of quietly serving an old tip.
    if let Some(every) = systemd::watchdog_interval() {
        let watched = node.clone();
        let poll_secs = cfg.poll_interval_secs;
        tokio::spawn(async move {
            let mut warned = false;
            loop {
                let idle = watched.seconds_since_progress();
                if systemd::should_ping(idle, poll_secs) {
                    systemd::notify("WATCHDOG=1");
                    warned = false;
                } else if !warned {
                    warn!(
                        idle_secs = idle,
                        "no progress: holding back the watchdog ping so systemd restarts us"
                    );
                    warned = true;
                }
                tokio::time::sleep(every).await;
            }
        });
        info!(ping_every_secs = every.as_secs(), "systemd watchdog on");
    }

    let app = router(
        node.clone(),
        Auth {
            cookie_password,
            user: cfg.rpc_user.clone(),
            password: cfg.rpc_password.clone(),
        },
    );
    let listener = tokio::net::TcpListener::bind(cfg.rpc_bind)
        .await
        .with_context(|| format!("binding {}", cfg.rpc_bind))?;
    info!(bind = %cfg.rpc_bind, network = %cfg.network, "bitcoind-compatible RPC listening");
    systemd::ready(&format!(
        "listening on {}, {}",
        cfg.rpc_bind,
        status_line(&node)
    ));
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    let _ = std::fs::remove_file(&cookie_path);
    info!("stopped");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::write_cookie;

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "trust-issues-cookie-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_cookie_is_private_from_the_start_and_replaces_a_stale_tmp() {
        let dir = scratch("stale");
        // A leftover from a crash, readable by everyone.
        std::fs::write(dir.join(".cookie.tmp"), "stale").unwrap();
        let path = write_cookie(&dir, "abc123").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "__cookie__:abc123");
        assert!(!dir.join(".cookie.tmp").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // Written again on the next start: a fresh password, still private.
        let path = write_cookie(&dir, "def456").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "__cookie__:def456");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The old code wrote through whatever sat at `.cookie.tmp`. A planted
    /// symlink must be replaced, and the file it points at left alone.
    #[cfg(unix)]
    #[test]
    fn a_planted_symlink_at_the_tmp_name_is_never_written_through() {
        let dir = scratch("symlink");
        let outside = dir.join("outside.txt");
        std::fs::write(&outside, "precious").unwrap();
        let data = dir.join("data");
        std::fs::create_dir_all(&data).unwrap();
        std::os::unix::fs::symlink(&outside, data.join(".cookie.tmp")).unwrap();
        let path = write_cookie(&data, "abc123").unwrap();
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "precious");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "__cookie__:abc123");
        assert!(
            !std::fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
