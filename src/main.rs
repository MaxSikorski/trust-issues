//! `trust-issues [--config <file>] [flags]`: run the stand-in bitcoind.
//! `trust-issues health-check [--synced]`: ask a running one whether it's up
//! (and synced), for Docker's HEALTHCHECK and scripts.
//! `trust-issues check-config`: print the settings and exit.

use std::sync::Arc;
use std::time::Duration;

use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
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
    /// Optional config file (TOML)
    #[arg(long, global = true, env = "TRUST_ISSUES_CONFIG")]
    config: Option<PathBuf>,
    /// signet (or regtest for tests)
    #[arg(long, global = true, env = "TRUST_ISSUES_NETWORK")]
    network: Option<String>,
    /// Address of Tor's SOCKS port, like 127.0.0.1:9050
    #[arg(long, global = true, env = "TRUST_ISSUES_TOR_SOCKS")]
    tor_socks: Option<String>,
    /// Where the RPC listens, like 127.0.0.1:38332
    #[arg(long, global = true, env = "TRUST_ISSUES_RPC_BIND")]
    rpc_bind: Option<String>,
    /// Where the cookie file goes
    #[arg(long, global = true, env = "TRUST_ISSUES_DATA_DIR")]
    data_dir: Option<PathBuf>,
    #[arg(long, global = true, env = "TRUST_ISSUES_POLL_INTERVAL_SECS")]
    poll_interval_secs: Option<u64>,
    /// "<height>:<block hash>"
    #[arg(long, global = true, env = "TRUST_ISSUES_CHECKPOINT")]
    checkpoint: Option<String>,
    #[arg(long, global = true, env = "TRUST_ISSUES_REQUESTS_PER_SEC")]
    requests_per_sec: Option<f64>,
    #[arg(long, global = true, env = "TRUST_ISSUES_FEE_CEILING_SAT_VB")]
    fee_ceiling_sat_vb: Option<f64>,
    /// name=url,name=url (replaces the file's sources)
    #[arg(long, global = true, env = "TRUST_ISSUES_SOURCES")]
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

fn load(cli: &Cli) -> Result<Config> {
    let text = match &cli.config {
        Some(p) => {
            Some(std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?)
        }
        None => None,
    };
    let o = Overrides {
        network: cli.network.clone(),
        tor_socks: cli.tor_socks.clone(),
        rpc_bind: cli.rpc_bind.clone(),
        data_dir: cli.data_dir.clone(),
        poll_interval_secs: cli.poll_interval_secs,
        checkpoint: cli.checkpoint.clone(),
        requests_per_sec: cli.requests_per_sec,
        fee_ceiling_sat_vb: cli.fee_ceiling_sat_vb,
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
    if let Some(user) = &cfg.rpc_user {
        let pw = if cfg.rpc_password.is_some() {
            "password set in the file"
        } else {
            "no password"
        };
        println!("rpc_user: {user} ({pw})");
    }
    println!("sources:");
    for s in &cfg.sources {
        match &s.route {
            Route::Tor(socks) => println!("  {} {} via Tor at {socks}", s.name, s.url),
            Route::Direct => println!("  {} {} directly", s.name, s.url),
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
    std::fs::write(&tmp, format!("__cookie__:{password}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
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

    let cli = Cli::parse();
    let cfg = match load(&cli) {
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
