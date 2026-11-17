//! Configuration, with the milestone-1 safety rails built in:
//! signet (or regtest for tests) only, and every source either an onion
//! reached through Tor or a machine on your own network.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use bitcoin::{BlockHash, Network};
use serde::Deserialize;

use crate::limits::{DEFAULT_REQUESTS_PER_SEC, HARD_MAX_REQUESTS_PER_SEC};

/// Official onion addresses, taken from each site's own `Onion-Location`
/// header (checked 2026-11-16).
pub const MEMPOOL_ONION: &str =
    "http://mempoolhqx4isw62xs7abwphsq7ldayuidyx2v2oethdhhj6mlo2r6ad.onion";
pub const BLOCKSTREAM_ONION: &str =
    "http://explorerzydxu5ecjrkwceayqybizmpjjznk5izmitf2modhcusuqlid.onion";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    UnsupportedNetwork(String),
    BadUrl(String),
    NotOnionOrLocal(String),
    NeedsTor(String),
    BadCheckpoint(String),
    BadValue(String),
    Parse(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::UnsupportedNetwork(n) => write!(
                f,
                "network {n:?} is not allowed: this milestone runs on signet only (regtest for tests). Mainnet and testnet are refused on purpose."
            ),
            ConfigError::BadUrl(u) => write!(f, "source URL {u:?} doesn't parse"),
            ConfigError::NotOnionOrLocal(u) => write!(
                f,
                "source {u:?} is neither a .onion address nor a machine on your own network; clearnet explorers are refused so your IP never meets your channel data"
            ),
            ConfigError::NeedsTor(u) => {
                write!(
                    f,
                    "source {u:?} is an onion address, so tor_socks must be set"
                )
            }
            ConfigError::BadCheckpoint(c) => {
                write!(
                    f,
                    "checkpoint {c:?} must look like \"<height>:<block hash>\""
                )
            }
            ConfigError::BadValue(v) => write!(f, "{v}"),
            ConfigError::Parse(e) => write!(f, "config file: {e}"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// How we reach one source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// Through Tor's SOCKS port (address of the port).
    Tor(String),
    /// Directly: only for loopback and private-network addresses.
    Direct,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceSpec {
    pub name: String,
    pub url: String,
    pub route: Route,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub network: Network,
    pub rpc_bind: SocketAddr,
    pub rpc_user: Option<String>,
    pub rpc_password: Option<String>,
    pub data_dir: PathBuf,
    pub poll_interval_secs: u64,
    pub checkpoint: Option<(u32, BlockHash)>,
    pub fee_ceiling_sat_vb: f64,
    pub requests_per_sec: f64,
    pub sources: Vec<SourceSpec>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    network: String,
    rpc_bind: Option<String>,
    rpc_user: Option<String>,
    rpc_password: Option<String>,
    data_dir: Option<PathBuf>,
    tor_socks: Option<String>,
    poll_interval_secs: Option<u64>,
    checkpoint: Option<String>,
    fee_ceiling_sat_vb: Option<f64>,
    requests_per_sec: Option<f64>,
    #[serde(default)]
    sources: Vec<FileSource>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileSource {
    name: String,
    url: String,
}

/// Only signet and regtest exist in this milestone.
pub fn parse_network(s: &str) -> Result<Network, ConfigError> {
    match s.trim().to_ascii_lowercase().as_str() {
        "signet" => Ok(Network::Signet),
        "regtest" => Ok(Network::Regtest),
        other => Err(ConfigError::UnsupportedNetwork(other.to_string())),
    }
}

/// Decide how a source may be reached, or refuse it.
pub fn route_for(url: &str, tor_socks: Option<&str>) -> Result<Route, ConfigError> {
    let parsed = reqwest::Url::parse(url).map_err(|_| ConfigError::BadUrl(url.to_string()))?;
    // Plain http only: onions are already encrypted end to end, and local
    // machines are on your own network. (https for local sources: later.)
    if parsed.scheme() != "http" {
        return Err(ConfigError::BadUrl(url.to_string()));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| ConfigError::BadUrl(url.to_string()))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    if host.ends_with(".onion") {
        return match tor_socks {
            Some(s) => Ok(Route::Tor(s.to_string())),
            None => Err(ConfigError::NeedsTor(url.to_string())),
        };
    }
    if host == "localhost" {
        return Ok(Route::Direct);
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) if ip.is_loopback() || ip.is_private() => Ok(Route::Direct),
        Ok(IpAddr::V6(ip)) if ip.is_loopback() || ip.is_unique_local() => Ok(Route::Direct),
        _ => Err(ConfigError::NotOnionOrLocal(url.to_string())),
    }
}

pub fn parse_checkpoint(s: &str) -> Result<(u32, BlockHash), ConfigError> {
    let bad = || ConfigError::BadCheckpoint(s.to_string());
    let (h, hash) = s.split_once(':').ok_or_else(bad)?;
    let height = h.trim().parse::<u32>().map_err(|_| bad())?;
    let hash = hash.trim().parse::<BlockHash>().map_err(|_| bad())?;
    Ok((height, hash))
}

/// The default sources: both public explorers, over their onions.
pub fn default_sources(network: Network) -> Vec<(String, String)> {
    let path = match network {
        Network::Signet => "/signet/api",
        _ => return Vec::new(),
    };
    vec![
        ("mempool.space".into(), format!("{MEMPOOL_ONION}{path}")),
        (
            "blockstream.info".into(),
            format!("{BLOCKSTREAM_ONION}{path}"),
        ),
    ]
}

pub fn parse_config(text: &str) -> Result<Config, ConfigError> {
    let file: FileConfig = toml::from_str(text).map_err(|e| ConfigError::Parse(e.to_string()))?;
    let network = parse_network(&file.network)?;
    let default_port = match network {
        Network::Signet => 38332,
        _ => 18443,
    };
    let rpc_bind: SocketAddr = file
        .rpc_bind
        .as_deref()
        .unwrap_or(&format!("127.0.0.1:{default_port}"))
        .parse()
        .map_err(|_| {
            ConfigError::BadValue("rpc_bind must be an address like 127.0.0.1:38332".into())
        })?;

    let requests_per_sec = file.requests_per_sec.unwrap_or(DEFAULT_REQUESTS_PER_SEC);
    if !(requests_per_sec > 0.0 && requests_per_sec <= HARD_MAX_REQUESTS_PER_SEC) {
        return Err(ConfigError::BadValue(format!(
            "requests_per_sec must be above 0 and at most {HARD_MAX_REQUESTS_PER_SEC}"
        )));
    }
    let fee_ceiling_sat_vb = file.fee_ceiling_sat_vb.unwrap_or(1000.0);
    if fee_ceiling_sat_vb.is_nan() || fee_ceiling_sat_vb < 1.0 {
        return Err(ConfigError::BadValue(
            "fee_ceiling_sat_vb must be at least 1".into(),
        ));
    }
    let poll_interval_secs = file.poll_interval_secs.unwrap_or(60).max(10);
    let checkpoint = file
        .checkpoint
        .as_deref()
        .map(parse_checkpoint)
        .transpose()?;

    let raw_sources: Vec<(String, String)> = if file.sources.is_empty() {
        default_sources(network)
    } else {
        file.sources.into_iter().map(|s| (s.name, s.url)).collect()
    };
    let mut sources = Vec::new();
    for (name, url) in raw_sources {
        let route = route_for(&url, file.tor_socks.as_deref())?;
        sources.push(SourceSpec {
            name,
            url: url.trim_end_matches('/').to_string(),
            route,
        });
    }
    if sources.len() < 2 {
        return Err(ConfigError::BadValue(
            "at least two sources are needed: one source alone could hide blocks from you".into(),
        ));
    }

    Ok(Config {
        network,
        rpc_bind,
        rpc_user: file.rpc_user,
        rpc_password: file.rpc_password,
        data_dir: file.data_dir.unwrap_or_else(|| PathBuf::from(".data")),
        poll_interval_secs,
        checkpoint,
        fee_ceiling_sat_vb,
        requests_per_sec,
        sources,
    })
}
