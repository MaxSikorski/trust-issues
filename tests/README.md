# Tests

All tests are deterministic. They use generated regtest chains and scripted fake explorers (`src/demo/fakes.rs`, shared with the demo through `tests/common/mod.rs`), with no network, a hand-set clock, and tokio's paused time where waits matter. Run them with `cargo test --locked`.

Two examples are not tests:
- `examples/liar.rs` (`cargo run --example liar`) prints the five demo scenes from `src/demo/`. The browser version in `docs/` animates the same scenes from a WebAssembly build (`docs/build.sh`). Both refuse to say "caught" unless the code really caught it, and `demo.rs` below checks all five.
- `examples/socks_probe.rs` checks the SOCKS path to a real onion through your Tor.

## demo.rs: the liar demo (3)
| Test | Checks |
|---|---|
| the_demo_catches_all_five_lies | Five scenes, five catches, nothing missed |
| the_demo_ends_not_synced_with_a_critical_tip_alarm | The last scene drops "synced" and raises the critical tip alarm |
| the_demo_events_serialize_for_the_browser | The events become the JSON the web page reads |

## service.rs: running as a service (5)
| Test | Checks |
|---|---|
| health_needs_no_login_and_says_only_up_and_synced | `/health` answers without a login with only up/ready/synced; `/status` still needs it; a source down 5+ minutes drops "synced" |
| progress_resets_on_every_poll_even_when_every_source_fails | The watchdog's progress clock resets every poll, even with every explorer down (down isn't hung) |
| the_watchdog_pings_only_while_the_node_makes_progress | No ping once progress is older than one poll interval plus 180 s |
| watchdog_settings_are_read_like_systemd_means_them | `WATCHDOG_USEC` halved; `WATCHDOG_PID` must be ours; bad values mean no watchdog |
| notify_sends_one_datagram_to_the_socket | One datagram to the socket; abstract `@` sockets refused |

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

## config_rules.rs: safety rails (10)
| Test | Checks |
|---|---|
| only_signet_and_regtest_are_allowed | Mainnet, testnet and testnet4 are refused |
| onions_go_through_tor_and_clearnet_is_refused | Onions need Tor; public hosts and https are refused; local hosts go direct |
| default_signet_config_uses_three_independent_onions_through_tor | The defaults are three onions (mempool.space, Emzy, Blockstream), all via Tor |
| needs_two_sources_and_respects_the_request_ceiling | At least two sources; no more than 2 requests/s; unknown keys refused |
| checkpoint_parses_height_and_hash | `height:hash` format |
| two_sources_on_one_host_and_port_are_one_source_in_the_file_too | Two sources on the same host and port (any path, slash, case, default port) are refused, from the file and from the list |
| syntax_errors_report_only_the_position | A broken config file is reported as line and column, never its text |
| source_urls_with_a_login_are_refused_and_never_echoed | `user:password@` in a source URL is refused and never shown in an error |
| numbers_in_the_file_must_be_finite_and_above_the_floor | `inf`, `nan` and a request rate under 0.01/s are refused |
| blank_string_overrides_are_refused_by_name | A blank override is an error naming the setting; `tor_socks` must be `host:port` |

## config_env.rs: settings from flags and environment variables (18)
| Test | Checks |
|---|---|
| environment_variables_alone_are_enough | No file needed: network, Tor, bind and data dir from the environment, default onion sources |
| flags_beat_environment_variables_which_beat_the_file | Precedence: flag, then environment variable, then file |
| neither_a_flag_nor_an_environment_variable_can_pick_mainnet | Mainnet and testnets are refused from both routes |
| sources_from_the_environment_follow_the_same_rules | Clearnet, a single source and malformed entries (each next to two good ones) are refused; onion plus a home machine is routed correctly |
| the_network_must_be_set_somewhere | No network anywhere is an error ("network must be set") |
| passwords_never_come_from_flags_or_the_environment | `--rpc-user`/`--rpc-password` are clap's unexpected arguments, the env var is ignored, `rpc_auth` never names the user or shows the password |
| the_old_command_lines_still_work | `health-check --config F [--synced]` still works |
| health_check_synced_follows_what_the_server_says | Against a loopback `/health`: not synced means `--synced` exits 1, plain exits 0; synced means both exit 0 |
| the_bare_old_form_works_with_the_flag_on_either_side | `--config F check-config` and `check-config --config F` |
| a_repeated_config_flag_is_refused_and_a_dash_name_is_allowed | Two `--config` flags are refused; a file named `-dash.toml` works |
| syntax_errors_never_echo_the_file | An unterminated password, a cookie file and a wrong type never appear in the error |
| check_config_names_no_user_and_sources_carry_no_login | `rpc_auth` line without the user name; logins in source URLs refused; `--help` shows no environment values |
| numbers_must_be_finite_and_requests_must_reach_the_limiters_floor | `1e309`, `inf`, `nan`, rates under 0.01 or over 2 refused, with the setting named |
| a_blank_value_never_overrides_the_file_and_tor_must_be_host_and_port | Empty or blank values for every setting are errors; bad `tor_socks` refused; stray whitespace trimmed |
| only_the_winning_number_is_parsed | A bad environment number doesn't break a flag that beats it |
| spaces_inside_a_sources_entry_are_refused | Whitespace in a name or URL is an error, not folded into the URL |
| duplicate_sources_are_refused_from_flags_and_the_environment | The same host and port twice is refused; another port is fine |
| a_password_in_the_environment_is_ignored_loudly_and_never_echoed | Warning on stderr naming the variable, never its value |

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

## broadcast_and_rpc.rs: broadcasts and the bitcoind RPC (21)
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
| deployment_info_says_taproot_like_bitcoin_core | `getdeploymentinfo` lists taproot (and the `TAPROOT` script flag), which LND v0.21 requires |
| old_blocks_below_the_checkpoint_are_answered_when_sources_agree | `getblockhash`, `getblockheader` and `getblock` below the checkpoint (LND's birthday search); 0 confirmations; genesis header |
| old_blocks_fail_closed_when_sources_disagree_or_only_one_answers | Disagreement refuses and raises an alarm, which clears once they agree; one answer is never enough |
| old_block_lookups_ask_two_sources_once_even_when_asked_twice_at_once | Two hash answers and one header per old height; concurrent requests share it |
| a_bad_old_header_marks_its_source_and_the_honest_copy_is_used | A header that doesn't hash to the agreed block marks its source bad |
| a_lone_dissenter_is_outvoted_for_old_blocks_but_reported | Two votes and a strict majority win; the dissent is still reported |
| a_chain_block_offered_as_an_old_one_is_refused | A block on our proven chain can't be served as an older height |
| an_old_answer_that_contradicts_the_checkpoint_is_refused | The block below the checkpoint must be the checkpoint's parent |
| amounts_are_written_with_eight_decimals_like_bitcoin_core | Amounts go out as `0.00001000`, which Core Lightning's `bcli` requires |

**Total: 90 tests.**
