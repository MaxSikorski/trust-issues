//! trust-issues: a stand-in bitcoind for Lightning nodes that reads the
//! chain from several block explorers over Tor, checks everything it can
//! prove, cross-checks what it can't, and broadcasts to every source at once.
//!
//! Milestone 1 runs on signet only (regtest for tests).

pub mod chain;
pub mod demo;
pub mod fees;
pub mod limits;
pub mod node;
pub mod proof;
pub mod source;
pub mod time;

#[cfg(feature = "server")]
pub mod config;
#[cfg(feature = "server")]
pub mod esplora;
#[cfg(feature = "server")]
pub mod rpc;
#[cfg(feature = "server")]
pub mod systemd;

#[cfg(target_arch = "wasm32")]
mod wasm;
