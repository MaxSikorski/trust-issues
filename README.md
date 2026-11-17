# Trust Issues

**Not a node. Just a chorus of block explorers it doesn't believe.**

Trust Issues stands in for `bitcoind` under a home Lightning node. Instead of downloading the whole blockchain, it reads the chain from several block explorers over Tor, and it doesn't take any of them at their word:
- it **checks everything it can prove**: proof of work on every header, block hashes, merkle roots;
- it **cross-checks what it can't**: fees, "unspent", the newest tip;
- it **broadcasts every transaction to every explorer at once**, so nobody can quietly drop your channel close.

LND and Core Lightning talk to it as if it were bitcoind.

> **Status: milestone 1, signet only.** Mainnet and testnet are refused in code. Please don't use it with real money. [What's unsafe](#whats-unsafe-for-real-money) says why.

## Why I built this

A full node is still the best way to run Lightning, and if you can, run one. But it's 700+ GB and about a week of syncing, and plenty of people setting up a node at home just don't have that. The usual shortcut is to point your node at one block explorer. Then you're trusting that one company to show you every block, on time, forever.

That worries me, because Lightning's safety depends on it. If someone closes a channel with an old state, you have a fixed window to notice and broadcast the penalty transaction. An explorer that hides that one block, or quietly drops your penalty transaction, can make you miss it.

So I wanted the light setup without the blind trust. Ask several explorers over Tor. Prove everything that can be proven. Treat everything else as a claim to cross-check. And if the chain goes quiet for too long, say so loudly.

Credit where it's due: [trustedcoin](https://github.com/nbd-wtf/trustedcoin) showed that Core Lightning can run on explorers. Neutrino showed how far light clients can go. Blockstream's Esplora API and [mempool.space](https://mempool.space) make all of this possible, and they do it for free. Thank you!

## Watch it catch a liar (60 seconds, no setup)

```bash
cargo run --locked --example liar
```

We set up three fake explorers on a made-up chain: alice and bob are honest, mallory lies. In five scenes she:
1. hides blocks;
2. forges a block;
3. says a closed channel is still open;
4. drops a penalty transaction;
5. and finally, every explorer goes quiet.

You watch the real code catch each lie. There's no Tor, no network and no coins. Add `--fast` to skip the pauses. If a check ever fails to catch a lie, the demo says so and exits with an error. I'd rather it tell on itself than look good.

**Or in your browser.** [`docs/`](docs/) has a web version of the same five scenes. It's the real Rust code compiled to WebAssembly (about 470 KB, no imports, no network), so the checks run on your own machine, and the page just replays them slowly. To try it locally:

```bash
uv run --no-project python -m http.server 8765 -d docs
```

Then open http://localhost:8765. `docs/build.sh` rebuilds the WebAssembly file from source.

## What milestone 1 does
- **Headers:** we follow the chain from a checkpoint and take the **valid chain with the most work** that any explorer shows. Proof of work, links, difficulty rules and timestamps are checked on every header. It's proof, not a vote: one honest explorer is enough.
- **"Synced":** only when **at least two explorers** are healthy and the tip isn't stale.
- **Blocks and transactions:** fetched from one explorer at a time and verified (hash, merkle root, witness commitment, txid, merkle proofs against our own headers). An explorer caught serving bad data is ignored for 24 hours, and an alarm goes off.
- **`gettxout`:** says "unspent" only when two explorers agree *and* the funding transaction is proven confirmed. A proven spend always wins. Anything uncertain answers null, so it fails closed.
- **Fees:** the median of the explorers for normal targets, and the highest for 6 blocks or sooner, clamped between 1 sat/vB and a ceiling. An alarm goes off if they differ by more than 2×.
- **Broadcasts:** sent to every explorer in parallel, each on a fresh Tor circuit. If one forgets your transaction, we send it again. If fewer than two can see it after 5 minutes, an alarm goes off.
- **Being polite:** at most 1 request a second per explorer (hard ceiling 2), backing off with jitter on 429 or 5xx, and honouring `Retry-After`. These services are free, so let's not hammer them.
- **Alarms:**
  - the tip stale for 90 minutes (warning) or 3 hours (critical, and we stop saying "synced");
  - an explorer lagging, lying, or on the wrong network;
  - too few explorers;
  - fees that disagree;
  - a broadcast nobody can see.

  You can read them at `GET /status`, which needs the same login as the RPC.
- **No wallet calls, no keys, no funds.** The supported RPC list is in `src/rpc.rs` (`SUPPORTED`).

## Run it on signet
You'll need Tor running locally (its SOCKS port), and Rust from `rust-toolchain.toml`.

```bash
cargo build --locked --release
```

```bash
./target/release/trust-issues --config examples/signet.toml
```

Then point LND (`bitcoind.rpchost=127.0.0.1:38332`, `bitcoind.rpccookie=<data_dir>/.cookie`, `bitcoind.rpcpolling=true`) or Core Lightning (`bitcoin-rpcconnect`, `bitcoin-rpcport=38332`, `bitcoin-datadir`) at it. To be honest, **I haven't run either of them against it yet.** That's the next milestone.

**One heads-up before you try:** Blockstream's keyless API now allows 700 requests an hour per IP. Through their onion, every Tor user shares that limit, so that source is rate-limited almost all the time. For now, add a self-hosted Esplora on your own network as a second source. Otherwise Trust Issues will follow the chain but, correctly, never say "synced".

## What's unsafe for real money
Signet and regtest are what it's for right now. With real money, these are unsafe:
- **Only one explorer.** One source can hide a cheating close until your penalty window passes.
- **Large channels.** Even at its best, this is light-client (SPV) security, the same level as Neutrino. It trusts that miners only build on valid blocks, and it trusts the explorers' fee estimates. Only put in what you'd keep on a phone wallet.
- **No watchtower.** A second, independent watcher covers the case where every explorer hides a block.
- **Short CSV delays.** Ask your peers for a long `to_self_delay` (for example 2016 blocks), so the tip-lag alarm has days, not hours, to fire.
- **Clearnet.** It ties your home IP to your channel outputs.

Mainnet stays off until someone outside the project has reviewed it. Even then, it'll be small amounts only. Do your own research.

## Checks

```bash
cargo fmt --all --check && cargo clippy --locked --all-targets -- -D warnings && cargo test --locked && cargo deny --locked check
```

All 53 tests are deterministic: fake explorers, a hand-set clock, no network. Every one is listed in [tests/README.md](tests/README.md).

## Found a problem?
If it's a security issue, please report it privately. [SECURITY.md](SECURITY.md) says how. For anything else, open an issue. I'd especially love to hear where you think the threat model is wrong.

## Licence
Apache-2.0 ([LICENSE](LICENSE)). It's free to use, change and share, and it includes a patent grant. Dependencies are permissive only, checked by `cargo deny`.
