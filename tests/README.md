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

## chain_rules.rs: the header chain (17)
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
| rejects_header_not_later_than_the_median_of_the_last_eleven | A header's time must be later than the median of the 11 before it, inside one batch too |
| the_median_time_rule_waits_for_eleven_known_headers_above_a_checkpoint | Skipped until 11 earlier headers are known (fewer could refuse an honest header); applies after |
| at_a_retarget_the_bits_must_be_exactly_what_core_computes | With a 4-block test interval: at a retarget only Core's exact `bits` pass (one unit harder or easier, or unchanged, is refused); between retargets nothing may change |
| an_honest_four_times_harder_retarget_survives_compact_rounding | A 4x-harder retarget that rounds just under a strict quarter is accepted, with the period known and from a checkpoint inside it (the period's first header given separately); one unit harder is refused |
| the_retarget_matches_real_signet_and_cores_rounding | Real signet block 330624 (0x1d14cd85 to 0x1d14fcee) computed exactly; 0x1d14fcee to 0x1d053f3b; time running backwards; the cap at signet's limit |
| a_retarget_just_above_a_checkpoint_needs_the_periods_first_header | From a checkpoint inside a period, no retarget passes until the period's first header is given (one unit harder passed Core's permitted range on 5f78d99); a wrong first header is refused; then only the exact bits pass |
| bits_that_overflow_or_go_negative_are_refused_like_core | Core's `SetCompact` rules (negative, zero, overflow) on a table of `bits`; an overflowing 0x3f3fffff that wraps to the expected target is refused at a retarget (5f78d99 took it) |
| the_real_retarget_at_330624_is_exact_from_a_checkpoint_inside_its_period | Real headers 330623, 328608 and 330624: waits for 328608, then 0x1d14fced and 0x3d14fcee are refused and the real header is followed |

## signet_signatures.rs: signet block signatures, BIP325 (21)
Real standard-signet blocks in `tests/fixtures/` (read once from a local node: 330624, 331301, 331313, 331314, 331280 to 331282, and the headers 328608, 330623, 331279, 331300, 331312 and 331313), plus two altered copies of block 331314 with their proof of work ground again: one with a signature bit flipped, one with `OP_NOP` in front of its solution.

| Test | Checks |
|---|---|
| real_signet_blocks_carry_valid_signatures | Blocks 331314 and 331301 pass, and fail with one signature bit changed; genesis needs no signature |
| a_flipped_bit_in_the_signature_or_the_signed_header_fails | A flipped signature bit, a changed time or reordered transactions all fail |
| a_missing_or_moved_solution_fails | No solution, one in another output or an earlier commitment, a bare header, leftover bytes, no commitment: all refused; a moved solution isn't even found (`find_solution`), the real one is |
| the_solution_is_judged_like_bitcoin_cores_interpreter | Equivalent scriptSigs pass, and fail with a signature bit flipped; a non-empty dummy, missing dummy, loose DER (including a padded signature the lenient parser reads as the real one), empty signature, other sighash byte or a witness fail; non-push opcodes are refused by name |
| only_the_standard_signet_challenge_is_accepted | Any other challenge (OP_TRUE, swapped keys) is refused, saying why |
| the_forged_fixture_is_the_real_block_with_one_bit_flipped | The forged fixture differs by one bit, inside the signature's DER body, commits to it honestly and meets the real target |
| a_valid_pow_header_without_a_valid_signature_marks_its_source_bad | Fake explorers on signet: the forger is marked bad, the real block is followed, `getblock` is served from the cache with no extra requests |
| regtest_blocks_need_no_signature | Regtest skips the check and its chains run as before |
| malleated_copies_of_a_real_block_are_refused | 331314 with its witnesses stripped or its last transaction repeated keeps its header and signature but is refused; so are a missing or short reserved value, a changed witness, and witness data with no commitment; the real block and a witness-free block without a commitment pass |
| a_malleated_body_never_reaches_the_cache_and_the_honest_copy_is_served | Fake explorers: the malleator is marked bad, the real body is followed and served, and an honest explorer answering later isn't blamed |
| a_solution_we_dont_model_is_refused_without_blaming_anyone | The `OP_NOP` block isn't followed or served (tip and `getblock` of an old block), nobody is marked bad, a warning says why, and it isn't downloaded again |
| the_nop_fixture_is_the_real_block_with_one_opcode_added | The `OP_NOP` fixture differs from 331314 only by that opcode, commits to it honestly and meets the real target |
| bootstrap_refuses_a_checkpoint_from_another_signet | Two explorers agreeing on a starting block that isn't signed for our signet: no start; with the real block it starts |
| bootstrap_checks_the_height_proof_of_work_and_genesis | The automatic start refuses block 331314 offered at height 1 (BIP34), a signed copy missing its target, and genesis at height 1; old-block lookups refuse genesis above height 0 (all taken on 5f78d99) |
| a_retarget_above_the_checkpoint_waits_for_the_periods_first_header_without_blame | Real 330623 to 330624: while no two explorers give block 328608 the retarget waits, with a warning and no blame; once they agree it's checked exactly and followed (5f78d99 followed it at once) |
| the_first_transaction_must_be_the_only_coinbase | A regtest block whose first transaction spends an ordinary output but carries a matching witness commitment, or one with two coinbases, is refused (5f78d99 took the first) |
| the_unsupported_solution_warning_stays_until_that_block_is_superseded | Catching up past 331313 to the `OP_NOP` 331314: the warning stays (5f78d99 cleared it), also when refused again from the cache, and goes when the real 331314 wins |
| a_stalled_download_doesnt_hold_up_a_ready_source | Paused time: one explorer stalls on the download, the other has the block followed within the 10 s wait plus a second, one download each (5f78d99 waited on the stalled one) |
| a_cancelled_download_leaves_no_slot_behind | Downloads given up by their callers, and a waiter giving up, leave no download slot behind (5f78d99 left two) |
| a_new_block_is_downloaded_once_however_many_sources_offer_it | Two explorers, a slow download: the block is fetched once |
| a_withheld_block_stops_the_run_there_without_blame | Three new headers, the third block withheld: two are followed, nobody is blamed, the tip moves once it's served |

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

## config_rules.rs: safety rails (13)
| Test | Checks |
|---|---|
| only_signet_and_regtest_are_allowed | Mainnet, testnet and testnet4 are refused |
| onions_go_through_tor_and_clearnet_is_refused | Onions need Tor; public hosts and https are refused; local hosts go direct |
| default_signet_config_uses_three_independent_onions_through_tor | The defaults are three onions (mempool.space, Emzy, Blockstream), all via Tor |
| needs_two_sources_and_respects_the_request_ceiling | At least two sources; no more than 2 requests/s; unknown keys refused |
| checkpoint_parses_height_and_hash | `height:hash` format |
| two_sources_on_one_host_and_port_are_one_source_in_the_file_too | Two sources on the same host and port (any path, slash, case, default port, and every loopback spelling: localhost, 127.x.x.x, `[::1]`) are refused, from the file and from the list |
| syntax_errors_report_only_the_position | A broken config file is reported as line, column and "wrong type or syntax", never its text; a wrong type also names the key and expected type, never the value |
| the_unspecified_address_is_never_a_source | `0.0.0.0` and `[::]` are refused as sources |
| urls_that_cannot_be_shown_safely_are_not_shown | Single slash, no scheme, no host, percent-encoded `@`: the URL is never echoed, the source name is |
| tor_socks_must_be_host_and_port_with_no_login | `user:pw@host:port`, schemes and extra colons are refused without echo; plain hosts and `[::1]` work |
| source_urls_with_a_login_are_refused_and_never_echoed | `user:password@` in a source URL is refused and never shown in an error |
| numbers_in_the_file_must_be_finite_and_above_the_floor | `inf`, `nan` and a request rate under 0.01/s are refused |
| blank_string_overrides_are_refused_by_name | A blank override is an error naming the setting; `tor_socks` must be `host:port` |

## config_env.rs: settings from flags and environment variables (20)
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
| a_repeated_config_flag_is_refused_and_a_dash_name_is_allowed | Two real `--config` flags (either form, either side of the subcommand) are refused; files named `-dash.toml` or `--config` work |
| syntax_errors_never_echo_the_file | An unterminated password, a cookie file and a wrong type never appear in the error |
| check_config_names_no_user_and_sources_carry_no_login | `rpc_auth` line without the user name; logins in source URLs refused; `--help` shows no environment values |
| numbers_must_be_finite_and_requests_must_reach_the_limiters_floor | `1e309`, `inf`, `nan`, rates under 0.01 or over 2 refused, with the setting named |
| a_blank_value_never_overrides_the_file_and_tor_must_be_host_and_port | Empty or blank values for every setting are errors; bad `tor_socks` refused; stray whitespace trimmed |
| only_the_winning_number_is_parsed | A bad environment number doesn't break a flag that beats it |
| spaces_inside_a_sources_entry_are_refused | Whitespace in a name or URL is an error, not folded into the URL |
| duplicate_sources_are_refused_from_flags_and_the_environment | The same host and port twice is refused; another port is fine |
| a_password_in_the_environment_is_ignored_loudly_and_never_echoed | Warning on stderr naming the variable, never its value |
| a_url_that_cannot_be_shown_safely_is_never_echoed | Malformed source URLs with a login (env and file) never appear in the output |
| a_tor_address_with_a_login_is_refused_and_never_printed | `tor_socks` with `user:pw@` is refused from env and file, never printed |

## adversarial.rs: lying, hiding and failing sources (20)
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
| clean_text_removes_ascii_and_c1_controls | Control characters, escape bytes and U+0085 are dropped |
| clean_text_removes_unicode_line_and_paragraph_separators | U+2028 and U+2029 are dropped |
| clean_text_removes_bidi_overrides_and_isolates | U+202A-202E, U+2066-2069 and direction marks are dropped |
| clean_text_removes_zero_width_and_invisible_format_characters | Zero-width and invisible format characters are dropped; ordinary text survives |

## broadcast_and_rpc.rs: broadcasts and the bitcoind RPC (40)
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
| a_missed_old_block_lookup_is_retried_once_after_its_backoff | A source that misses once (Tor) is asked again after its own backoff, not sooner; the lookup is answered |
| an_old_block_lookup_is_retried_only_once_then_fails_closed | A source that misses twice: one retry, then a refusal (one answer is never enough) |
| a_long_retry_after_is_respected_and_not_waited_out | A 10-minute `Retry-After` is honoured: no second request, and the RPC call isn't held open |
| a_retry_after_of_exactly_the_cap_is_waited_out_then_retried | A 15 s `Retry-After` (the cap) is waited out, then the source is asked again |
| two_of_four_is_not_a_majority_for_old_blocks | A 2-1-1 split is refused: two votes must also be more than half |
| retries_arent_cut_short_while_an_answer_could_still_change_the_outcome | The retry round only stops early when the answers still out can't change the result (2-2 is refused, not 2-1 taken too soon) |
| sources_that_stop_answering_dont_clear_a_disagreement_alarm | Only agreement clears the alarm, never silence |
| not_found_for_an_old_block_is_an_answer_and_not_retried | "Not found" is an answer, not a miss: no retry |
| a_bad_old_header_marks_its_source_and_the_honest_copy_is_used | A header that doesn't hash to the agreed block marks its source bad |
| a_lone_dissenter_is_outvoted_for_old_blocks_but_reported | Two votes and a strict majority win; the dissent is still reported |
| a_chain_block_offered_as_an_old_one_is_refused | A block on our proven chain can't be served as an older height |
| an_old_answer_that_contradicts_the_checkpoint_is_refused | The block below the checkpoint must be the checkpoint's parent |
| amounts_are_written_with_eight_decimals_like_bitcoin_core | Amounts go out as `0.00001000`, which Core Lightning's `bcli` requires |
| an_unknown_method_is_listed_once_on_status_and_still_answers_not_found | An unsupported method still gets -32601; `/status` lists each name once, sorted, batches included |
| known_methods_never_appear_in_the_unsupported_list | Supported methods are never listed as unsupported |
| a_dirty_long_method_name_is_cleaned_and_truncated_in_the_list | Control characters are stripped and names cut to 200 characters |
| the_unsupported_list_is_capped | At most 64 distinct names are kept |
| params_never_appear_on_status | Request params never reach `/status` |
| an_oversize_batch_gets_one_error_and_nothing_is_processed_or_listed | A batch over 256 requests gets one -32600 error and nothing is run or listed; 256 still works |
| unsupported_means_not_in_our_list_whatever_the_answer_was | A supported method with an upstream -32601 isn't listed; an unknown one asked during warm-up (-28) is |
| the_log_names_the_method_but_never_the_params | Captured logs contain the method name and never the params |
| a_full_unsupported_list_warns_once | Reaching 64 names logs one "list is full" warning; the list never grows past 64 |
| an_unauthenticated_unknown_method_gets_401_and_is_not_listed | Over HTTP, no or wrong login gets 401 and the name isn't listed; a good login lists it |
| every_supported_method_is_known_to_the_dispatcher | Every name in `SUPPORTED` is dispatched (never -32601) |

## src/main.rs: the program itself (2)
| Test | Checks |
|---|---|
| the_cookie_is_private_from_the_start_and_replaces_a_stale_tmp | The RPC cookie is created at 0600 (never readable by others, even for a moment) and a leftover `.cookie.tmp` is replaced; cleans up after itself |
| a_planted_symlink_at_the_tmp_name_is_never_written_through | A symlink planted at `.cookie.tmp` is replaced and the file it points at stays untouched |

## src/esplora.rs: unit tests (2)
| Test | Checks |
|---|---|
| retry_after_on_a_503_is_a_rate_limit | A 503 with `Retry-After` is a slow-down like a 429; a bare 503 stays a server error |
| a_chunked_answer_is_cut_off_at_the_limit_while_streaming | A loopback HTTP server streams 64 MiB chunked with no length: refused as too large, and reading stops within one 64 KiB chunk past 8 MiB (counted on our side) |

## src/node.rs: unit tests (1, plus 1 in the browser build)
| Test | Checks |
|---|---|
| with_the_signet_check_feature_signet_runs | With the checker built in, a signet node starts and signet's genesis passes |
| without_the_signet_check_feature_signet_is_refused | Only in `cargo test --lib --no-default-features` (the browser build, as CI runs it): every signet block is refused, a signet node never starts and raises a critical alarm; regtest still works |

**Total: 152 tests** (`cargo test --locked`), plus 1 in the browser build (`cargo test --locked --lib --no-default-features`).
