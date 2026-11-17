# Security policy

Trust Issues stands in for bitcoind under a Lightning node. If it misses a block or drops a broadcast, someone could lose a channel balance. So I take reports about it very seriously, even while it's signet only.

## Reporting a vulnerability

Please **do not** open a public issue. Use GitHub's private vulnerability reporting on this repository: the **Security** tab, then **Report a vulnerability**.

Please include what you found, how to reproduce it, and what an attacker could do with it. I'll acknowledge the report within 7 days, keep you updated, and credit you in the advisory unless you'd rather I didn't.

## In scope

- The code in this repository, and especially anything that lets a source:
  - hide a block or hold back the tip without an alarm;
  - get a fake block, transaction or merkle proof accepted;
  - make `gettxout` say "unspent" for a spent output;
  - make a broadcast quietly fail.
- The RPC server: the cookie, logins, and anything that leaks a password, the cookie or transaction hex.
- Anything that gets past the signet-only network check.

## Out of scope

- Bugs in the explorers themselves (mempool.space, Blockstream's Esplora), in Tor, or in LND and Core Lightning. Please report those to their maintainers.
- Rate limits on public explorers. That's a known limit, described in the README.

## Good-faith research

I won't take legal action against good-faith security research that follows this policy, uses signet or regtest only, never touches anyone's real funds, and gives me reasonable time to fix the problem before anything is disclosed.

## Current status

Milestone 1, signet only. Mainnet and testnet are refused in code. There are no releases, and it must not be used with real money.
