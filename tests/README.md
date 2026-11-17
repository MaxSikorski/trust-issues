# Tests

All tests are deterministic. They use generated regtest chains and scripted fake explorers (`tests/common/mod.rs`), with no network, a hand-set clock, and tokio's paused time where waits matter. Run them with `cargo test --locked`.

Two examples are not tests:
- `examples/liar.rs` (`cargo run --example liar`) is a demo that replays five of these scenarios with the same fake explorers. It exits with an error if any lie isn't caught.
- `examples/socks_probe.rs` checks the SOCKS path to a real onion through your Tor.

## chain_rules.rs: the header chain (9)
| Test | Checks |
|---|---|
| valid_chain_extends_from_checkpoint | A valid run of headers extends the chain; heights, confirmations, next block |
| checkpoint_above_genesis_hides_older_heights_except_genesis | Below the checkpoint only genesis is answerable |
| rejects_header_failing_proof_of_work | A header missing its target is refused, and nothing from that batch is kept |
| rejects_target_easier_than_the_network_allows | A target above the network's limit is refused |
| rejects_difficulty_change_where_none_is_allowed | `bits` may only change at a retarget boundary (and never on regtest) |
| rejects_header_more_than_two_hours_in_the_future | Bitcoin's 2-hour future rule |
| rejects_unknown_parent_and_broken_links | Headers must connect to what we know and to each other |
| switches_to_a_fork_with_more_work_and_reports_reorg_depth | The most-work branch wins; reorg depth is reported |
| ignores_a_fork_with_less_work | A lower-work branch is kept aside, not followed |

## proofs_fees_limits.rs: proofs, fees, politeness (8)
| Test | Checks |
|---|---|
| verified_block_must_match_hash_and_merkle_root | Wrong hash, edited transaction, garbage: all refused |
| verified_tx_must_match_txid_and_not_be_64_bytes | Wrong txid refused; 64-byte transactions refused |
| merkle_branch_checks_every_position_and_rejects_tampering | Electrum-style proofs at every position; flipped bits and edited nodes fail |
| fee_pick_uses_the_nearest_target_that_is_not_slower | Choosing a source's estimate for a target |
| fees_use_median_normally_and_highest_when_urgent_and_are_clamped | Median, max for 6 blocks or sooner, floor and ceiling |
| fee_disagreement_is_more_than_double | The 2× alarm threshold |
| token_bucket_allows_a_burst_then_the_rate | Burst then rate; asking for more than 2/s is clamped |
| backoff_doubles_from_five_seconds_to_a_ten_minute_cap | 5, 10, 20 … 600 s, plus jitter |

## config_rules.rs: safety rails (5)
| Test | Checks |
|---|---|
| only_signet_and_regtest_are_allowed | Mainnet, testnet and testnet4 are refused |
| onions_go_through_tor_and_clearnet_is_refused | Onions need Tor; public hosts and https are refused; local hosts go direct |
| default_signet_config_uses_both_onions_through_tor | The defaults are the two onions, both via Tor |
| needs_two_sources_and_respects_the_request_ceiling | At least two sources; no more than 2 requests/s; unknown keys refused |
| checkpoint_parses_height_and_hash | `height:hash` format |

## adversarial.rs: lying, hiding and failing sources (16)
| Test | Checks |
|---|---|
| two_honest_sources_mean_synced_at_their_tip | The happy path, no alarms |
| one_reachable_source_is_never_enough_to_be_synced | One source: follows the chain, but not "synced", with an alarm |
| one_honest_source_beats_a_withholding_one_and_the_withholder_is_flagged | Most work beats a vote; a lagging source is flagged after 30 min and stops counting |
| when_every_source_hides_blocks_the_tip_alarm_fires_and_sync_is_dropped | Warning at 90 min, critical and not synced at 3 h |
| a_source_serving_a_header_without_proof_of_work_is_marked_bad | Liar ignored and alarmed; honest progress continues |
| a_header_that_does_not_hash_to_what_was_asked_is_a_lie | Substituted header means bad |
| a_lower_work_fork_is_ignored_without_blaming_the_source | Forks aren't lies |
| a_tampered_block_is_refused_and_fetched_from_another_source | Edited blocks are never served; the true copy comes from another source |
| a_source_on_another_network_is_never_used | Wrong genesis: alarm, never asked again |
| bootstrap_needs_two_sources_agreeing_six_blocks_down | Starts 6 below the agreed tip; refuses when sources disagree |
| unspent_needs_two_agreeing_sources_and_a_proven_confirmation | `gettxout` answers only with two votes and a merkle proof |
| a_proven_spend_beats_any_number_of_unspent_claims | One proven spend outweighs two liars |
| a_false_spent_claim_marks_the_liar_bad | A made-up spender is caught |
| an_unconfirmed_output_is_answered_as_null | Fail closed on unconfirmed funding |
| fees_combine_across_sources_and_disagreement_raises_an_alarm | Median, max when urgent, alarm above 2× |
| a_rate_limited_source_cools_off_while_the_others_carry_on | 429 + Retry-After: no requests while cooling, back afterwards |

## broadcast_and_rpc.rs: broadcasts and the bitcoind RPC (12)
| Test | Checks |
|---|---|
| broadcast_goes_to_every_source_and_succeeds_if_any_accepts | Every source is sent it; one acceptance is success |
| when_every_source_rejects_the_error_is_bitcoinds_own | bitcoind's error code and message come through; bad hex is -22 |
| a_source_that_forgets_a_broadcast_gets_it_again | Re-sent after the 60 s check |
| too_few_sources_seeing_a_broadcast_raises_a_critical_alarm | Fewer than two after 5 min means an alarm |
| a_confirmed_broadcast_is_forgotten_once_proven | Dropped from our mempool once its merkle proof checks |
| test_accept_refuses_a_spent_input_and_allows_a_fresh_one | `testmempoolaccept` from local checks |
| before_a_checkpoint_chain_calls_answer_warming_up | -28 until started; `getnetworkinfo` reports a version LND and CLN accept |
| getblockchaininfo_looks_like_a_synced_unpruned_bitcoind | `pruned=false`, not in IBD, progress 1.0 |
| blocks_headers_and_hashes_over_rpc | `getblockhash`, `getblockheader` (both forms), `getblock` 0 and 1 |
| batches_unknown_methods_and_fees_over_rpc | Batches, -32601 for wallet calls, `estimatesmartfee`, parse errors |
| send_then_see_it_in_our_mempool_and_spending_lookup | `sendrawtransaction`, `getrawmempool`, `gettxspendingprevout`, `getrawtransaction` |
| the_http_server_requires_the_cookie_or_rpc_password | 401 without the right login; cookie and user/password both work; `/status` |

**Total: 50 tests.**
