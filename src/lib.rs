//! trust-issues: a stand-in bitcoind for Lightning nodes that reads the
//! chain from several block explorers over Tor, checks everything it can
//! prove, cross-checks what it can't, and broadcasts to every source at once.
//!
//! Milestone 1 runs on signet only (regtest for tests).

pub mod chain;
pub mod config;
pub mod esplora;
pub mod fees;
pub mod limits;
pub mod node;
pub mod proof;
pub mod rpc;
pub mod source;
