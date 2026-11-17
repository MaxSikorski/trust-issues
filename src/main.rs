//! `trust-issues --config <file>`: run the stand-in bitcoind.
//! `trust-issues health-check --config <file> [--synced]`: ask a running one
//! whether it's up (and synced), for Docker's HEALTHCHECK and scripts.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tracing::{info, warn};
use trust_issues::config::parse_config;
use trust_issues::esplora::EsploraSource;
use trust_issues::limits::{DEFAULT_BURST, os_jitter};
use trust_issues::node::{Node, Settings, SystemClock};
use trust_issues::rpc::{Auth, router};
use trust_issues::source::Source;
use trust_issues::systemd;

fn usage() -> ! {
    eprintln!("usage: trust-issues --config <file.toml>");
    eprintln!("       trust-issues health-check --config <file.toml> [--synced]");
    std::process::exit(2);
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

    let args: Vec<String> = std::env::args().collect();
    let (path, health, require_synced) = match args.as_slice() {
        [_, flag, p] if flag == "--config" => (p.clone(), false, false),
        [_, cmd, flag, p] if cmd == "health-check" && flag == "--config" => {
            (p.clone(), true, false)
        }
        [_, cmd, flag, p, s] if cmd == "health-check" && flag == "--config" && s == "--synced" => {
            (p.clone(), true, true)
        }
        _ => usage(),
    };
    let text = std::fs::read_to_string(&path).with_context(|| format!("reading {path}"))?;
    let cfg = parse_config(&text).map_err(|e| anyhow::anyhow!("{e}"))?;
    if health {
        health_check(cfg.rpc_bind, require_synced).await;
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
