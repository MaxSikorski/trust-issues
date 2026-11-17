//! Configuration, with the milestone-1 safety rails built in:
//! signet (or regtest for tests) only, and every source either an onion
//! reached through Tor or a machine on your own network.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

use bitcoin::{BlockHash, Network};
use serde::Deserialize;

use crate::limits::{DEFAULT_REQUESTS_PER_SEC, HARD_MAX_REQUESTS_PER_SEC, MIN_REQUESTS_PER_SEC};

/// Official onion addresses, taken from each site's own `Onion-Location`
/// header (mempool.space and blockstream.info checked 2026-11-16,
/// mempool.emzy.de 2026-11-17).
pub const MEMPOOL_ONION: &str =
    "http://mempoolhqx4isw62xs7abwphsq7ldayuidyx2v2oethdhhj6mlo2r6ad.onion";
pub const BLOCKSTREAM_ONION: &str =
    "http://explorerzydxu5ecjrkwceayqybizmpjjznk5izmitf2modhcusuqlid.onion";
/// Emzy's community mempool instance: separate operator and servers from
/// mempool.space, so it counts as an independent source.
pub const EMZY_ONION: &str =
    "http://mempool4t6mypeemozyterviq3i5de4kpoua65r3qkn5i3kknu5l2cad.onion";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    UnsupportedNetwork(String),
    BadUrl(String),
    UrlHasLogin(String),
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
            ConfigError::UrlHasLogin(u) => write!(
                f,
                "source {u:?} has a user name or password in the URL; explorers don't need one, and it would end up in logs"
            ),
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
    network: Option<String>,
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
    let shown = redact(url);
    let parsed = reqwest::Url::parse(url).map_err(|_| ConfigError::BadUrl(shown.clone()))?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(ConfigError::UrlHasLogin(shown));
    }
    // Plain http only: onions are already encrypted end to end, and local
    // machines are on your own network. (https for local sources: later.)
    if parsed.scheme() != "http" {
        return Err(ConfigError::BadUrl(shown));
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| ConfigError::BadUrl(shown.clone()))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    if host.ends_with(".onion") {
        return match tor_socks {
            Some(s) => Ok(Route::Tor(s.to_string())),
            None => Err(ConfigError::NeedsTor(shown)),
        };
    }
    if host == "localhost" {
        return Ok(Route::Direct);
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) if ip.is_loopback() || ip.is_private() => Ok(Route::Direct),
        Ok(IpAddr::V6(ip)) if ip.is_loopback() || ip.is_unique_local() => Ok(Route::Direct),
        _ => Err(ConfigError::NotOnionOrLocal(shown)),
    }
}

/// The text with any `user:password@` after `://` replaced, so error messages
/// and logs never carry a login.
fn redact(s: &str) -> String {
    let Some(start) = s.find("://").map(|i| i + 3) else {
        return s.to_string();
    };
    let end = s[start..]
        .find(['/', '?', '#'])
        .map_or(s.len(), |i| start + i);
    match s[start..end].rfind('@') {
        Some(at) => format!("{}***@{}", &s[..start], &s[start + at + 1..]),
        None => s.to_string(),
    }
}

/// Host (lowercase) and port of a source URL, defaults filled in.
fn host_port(url: &str) -> Option<(String, u16)> {
    let u = reqwest::Url::parse(url).ok()?;
    Some((
        u.host_str()?.to_ascii_lowercase(),
        u.port_or_known_default()?,
    ))
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
    // Blockstream's keyless onion is rate-limited almost all the time
    // (shared by every Tor user), so Emzy's makes sure two can answer.
    vec![
        ("mempool.space".into(), format!("{MEMPOOL_ONION}{path}")),
        ("mempool.emzy.de".into(), format!("{EMZY_ONION}{path}")),
        (
            "blockstream.info".into(),
            format!("{BLOCKSTREAM_ONION}{path}"),
        ),
    ]
}

/// Settings given on the command line or in the environment. Each one, when
/// present, beats the config file. The RPC user and password are missing on
/// purpose: `ps` and `docker inspect` would show them.
#[derive(Debug, Default, Clone)]
pub struct Overrides {
    pub network: Option<String>,
    pub tor_socks: Option<String>,
    pub rpc_bind: Option<String>,
    pub data_dir: Option<PathBuf>,
    /// The numbers arrive as text and are parsed only once they have won.
    pub poll_interval_secs: Option<String>,
    pub checkpoint: Option<String>,
    pub requests_per_sec: Option<String>,
    pub fee_ceiling_sat_vb: Option<String>,
    /// `name=url,name=url`; replaces the file's sources entirely.
    pub sources: Option<String>,
}

/// Strict on purpose: a half-read list could silently drop a source.
fn parse_sources_list(s: &str) -> Result<Vec<(String, String)>, ConfigError> {
    if s.trim().is_empty() {
        return Err(blank("sources"));
    }
    let bad = |entry: &str| {
        ConfigError::BadValue(format!(
            "sources entry {:?} must look like name=url (no empty entries)",
            redact(entry)
        ))
    };
    s.split(',')
        .map(|entry| {
            let (name, url) = entry.split_once('=').ok_or_else(|| bad(entry))?;
            let (name, url) = (name.trim(), url.trim());
            if name.is_empty() || url.is_empty() {
                return Err(bad(entry));
            }
            no_whitespace(name, url)?;
            Ok((name.to_string(), url.to_string()))
        })
        .collect()
}

fn no_whitespace(name: &str, url: &str) -> Result<(), ConfigError> {
    if name.contains(char::is_whitespace) || url.contains(char::is_whitespace) {
        return Err(ConfigError::BadValue(format!(
            "the source {name:?} has whitespace inside its name or URL; separate entries with commas"
        )));
    }
    Ok(())
}

fn blank(setting: &str) -> ConfigError {
    ConfigError::BadValue(format!(
        "{setting} must not be empty or blank (an empty value does not mean \"use the default\"; leave it unset instead)"
    ))
}

/// The winning value for a text setting: override, else file. Trimmed, and
/// never blank, so an empty variable can't quietly replace a good file value.
fn text_setting(
    setting: &str,
    over: Option<&str>,
    file: Option<&str>,
) -> Result<Option<String>, ConfigError> {
    match over.or(file).map(str::trim) {
        Some("") => Err(blank(setting)),
        other => Ok(other.map(str::to_string)),
    }
}

/// `host:port`, with a non-empty host without whitespace and a port 1-65535.
fn check_socks_address(s: &str) -> Result<(), ConfigError> {
    let ok = s.rsplit_once(':').is_some_and(|(host, port)| {
        !host.is_empty()
            && !host.contains(char::is_whitespace)
            && port.parse::<u16>().is_ok_and(|p| p >= 1)
    });
    if ok {
        Ok(())
    } else {
        Err(ConfigError::BadValue(
            "tor_socks must look like host:port, for example 127.0.0.1:9050".into(),
        ))
    }
}

fn number_error(setting: &str) -> ConfigError {
    ConfigError::BadValue(format!("{setting} is not a valid number"))
}

pub fn parse_config(text: &str) -> Result<Config, ConfigError> {
    load_config(Some(text), &Overrides::default())
}

/// Merge the optional file with the overrides (override, then file, then
/// default) and run every safety check on the result.
pub fn load_config(file_text: Option<&str>, o: &Overrides) -> Result<Config, ConfigError> {
    let text = file_text.unwrap_or("");
    // Never the toml message: it can quote the line, and the line may hold a
    // password (or the file may be the cookie by mistake).
    let file: FileConfig = toml::from_str(text).map_err(|e| {
        ConfigError::Parse(match e.span() {
            Some(span) => {
                let before = &text[..span.start.min(text.len())];
                let line = before.matches('\n').count() + 1;
                let col = before.rsplit('\n').next().map_or(0, |l| l.chars().count()) + 1;
                format!("syntax error at line {line}, column {col}")
            }
            None => "syntax error".to_string(),
        })
    })?;
    let network_name = text_setting("network", o.network.as_deref(), file.network.as_deref())?
        .ok_or_else(|| {
            ConfigError::BadValue("network must be set: signet (or regtest for tests)".into())
        })?;
    let network = parse_network(&network_name)?;
    let default_port = match network {
        Network::Signet => 38332,
        _ => 18443,
    };
    let rpc_bind: SocketAddr =
        text_setting("rpc_bind", o.rpc_bind.as_deref(), file.rpc_bind.as_deref())?
            .unwrap_or_else(|| format!("127.0.0.1:{default_port}"))
            .parse()
            .map_err(|_| {
                ConfigError::BadValue("rpc_bind must be an address like 127.0.0.1:38332".into())
            })?;

    let requests_per_sec = match o.requests_per_sec.as_deref().map(str::trim) {
        Some("") => return Err(blank("requests_per_sec")),
        Some(t) => t
            .parse::<f64>()
            .map_err(|_| number_error("requests_per_sec"))?,
        None => file.requests_per_sec.unwrap_or(DEFAULT_REQUESTS_PER_SEC),
    };
    if !(MIN_REQUESTS_PER_SEC..=HARD_MAX_REQUESTS_PER_SEC).contains(&requests_per_sec) {
        return Err(ConfigError::BadValue(format!(
            "requests_per_sec must be between {MIN_REQUESTS_PER_SEC} and {HARD_MAX_REQUESTS_PER_SEC}"
        )));
    }
    let fee_ceiling_sat_vb = match o.fee_ceiling_sat_vb.as_deref().map(str::trim) {
        Some("") => return Err(blank("fee_ceiling_sat_vb")),
        Some(t) => t
            .parse::<f64>()
            .map_err(|_| number_error("fee_ceiling_sat_vb"))?,
        None => file.fee_ceiling_sat_vb.unwrap_or(1000.0),
    };
    if !fee_ceiling_sat_vb.is_finite() || fee_ceiling_sat_vb < 1.0 {
        return Err(ConfigError::BadValue(
            "fee_ceiling_sat_vb must be a finite number, at least 1".into(),
        ));
    }
    let poll_interval_secs = match o.poll_interval_secs.as_deref().map(str::trim) {
        Some("") => return Err(blank("poll_interval_secs")),
        Some(t) => t
            .parse::<u64>()
            .map_err(|_| number_error("poll_interval_secs"))?,
        None => file.poll_interval_secs.unwrap_or(60),
    }
    .max(10);
    let checkpoint = text_setting(
        "checkpoint",
        o.checkpoint.as_deref(),
        file.checkpoint.as_deref(),
    )?
    .as_deref()
    .map(parse_checkpoint)
    .transpose()?;
    let tor_socks = text_setting(
        "tor_socks",
        o.tor_socks.as_deref(),
        file.tor_socks.as_deref(),
    )?;
    if let Some(t) = &tor_socks {
        check_socks_address(t)?;
    }
    let tor_socks = tor_socks.as_deref();
    let data_dir = match &o.data_dir {
        Some(p) if p.to_string_lossy().trim().is_empty() => return Err(blank("data_dir")),
        Some(p) => p.clone(),
        None => match file.data_dir {
            Some(p) if p.to_string_lossy().trim().is_empty() => return Err(blank("data_dir")),
            Some(p) => p,
            None => PathBuf::from(".data"),
        },
    };

    let raw_sources: Vec<(String, String)> = if let Some(list) = &o.sources {
        parse_sources_list(list)?
    } else if file.sources.is_empty() {
        default_sources(network)
    } else {
        let mut v = Vec::new();
        for s in file.sources {
            let (name, url) = (s.name.trim().to_string(), s.url.trim().to_string());
            no_whitespace(&name, &url)?;
            v.push((name, url));
        }
        v
    };
    let mut sources: Vec<SourceSpec> = Vec::new();
    for (name, url) in raw_sources {
        let route = route_for(&url, tor_socks)?;
        // One explorer listed twice would get two request budgets and count as
        // two opinions, so the same machine can only be a source once.
        let key = host_port(&url);
        if let Some(prev) = sources.iter().find(|p| host_port(&p.url) == key) {
            return Err(ConfigError::BadValue(format!(
                "sources {:?} and {name:?} use the same host and port; one explorer can only be one source",
                prev.name
            )));
        }
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
        data_dir,
        poll_interval_secs,
        checkpoint,
        fee_ceiling_sat_vb,
        requests_per_sec,
        sources,
    })
}
