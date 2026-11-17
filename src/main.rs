//! `trust-issues --config <file>`: run the stand-in bitcoind.

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

fn usage() -> ! {
    eprintln!("usage: trust-issues --config <file.toml>");
    std::process::exit(2);
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
    let path = match args.as_slice() {
        [_, flag, p] if flag == "--config" => p.clone(),
        _ => usage(),
    };
    let text = std::fs::read_to_string(&path).with_context(|| format!("reading {path}"))?;
    let cfg = parse_config(&text).map_err(|e| anyhow::anyhow!("{e}"))?;
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
            tokio::time::sleep(interval).await;
        }
    });

    let app = router(
        node,
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
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    let _ = std::fs::remove_file(&cookie_path);
    info!("stopped");
    Ok(())
}
