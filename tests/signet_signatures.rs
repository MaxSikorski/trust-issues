//! Signet block signatures (BIP325), checked against real signet blocks.
//!
//! The fixtures in `tests/fixtures/` are real standard-signet blocks, read
//! once from a local Bitcoin Core-compatible node (`getblock <hash> 0`):
//! - `signet-331313-header.hex`: the header at height 331313 (a checkpoint);
//! - `signet-331314-block.hex`: the whole block at 331314 (3 transactions);
//! - `signet-331301-block.hex`: the whole block at 331301 (a bigger one);
//! - `signet-331314-forged.hex`: block 331314 with one bit of its signet
//!   signature flipped, its merkle root recomputed and its nonce ground
//!   until it meets the real target again. So it has valid proof of work
//!   but no valid signature: what another signet, or a liar with a little
//!   hash power, could serve. `the_forged_fixture_is_the_real_block_with_one_bit_flipped`
//!   proves it is exactly that.

mod common;

use std::sync::Arc;

use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hex::FromHex;
use bitcoin::{Block, BlockHash, Network, ScriptBuf, TxOut, Witness};
use common::*;
use trust_issues::node::{ManualClock, Node, Settings};
use trust_issues::proof::{ProofError, verify_block_for};
use trust_issues::signet::{
    SIGNET_HEADER, STANDARD_SIGNET_CHALLENGE, SignetError, check_block_solution,
};
use trust_issues::source::Source;

fn block(hex: &str) -> Block {
    deserialize(&Vec::<u8>::from_hex(hex.trim()).unwrap()).unwrap()
}

fn block_314() -> Block {
    block(include_str!("fixtures/signet-331314-block.hex"))
}

fn block_301() -> Block {
    block(include_str!("fixtures/signet-331301-block.hex"))
}

fn forged_314() -> Block {
    block(include_str!("fixtures/signet-331314-forged.hex"))
}

fn header_313() -> bitcoin::block::Header {
    deserialize(
        &Vec::<u8>::from_hex(include_str!("fixtures/signet-331313-header.hex").trim()).unwrap(),
    )
    .unwrap()
}

fn challenge() -> Vec<u8> {
    Vec::from_hex(STANDARD_SIGNET_CHALLENGE).unwrap()
}

fn check(b: &Block) -> Result<(), SignetError> {
    check_block_solution(b, &challenge())
}

/// The coinbase output holding the signet solution, and where the solution
/// (the bytes after the 4-byte header) starts in its script.
fn solution_at(b: &Block) -> (usize, usize) {
    for (i, out) in b.txdata[0].output.iter().enumerate() {
        let s = out.script_pubkey.as_bytes();
        if let Some(p) = s.windows(4).position(|w| w == SIGNET_HEADER) {
            return (i, p + 4);
        }
    }
    panic!("no signet solution in this block");
}

/// The witness commitment (`6a24aa21a9ed` + 32 bytes) followed by a push
/// of the signet header and `solution`, or by nothing.
fn commitment_with(b: &Block, solution: Option<&[u8]>) -> ScriptBuf {
    let (i, _) = solution_at(b);
    let mut s = b.txdata[0].output[i].script_pubkey.as_bytes()[..38].to_vec();
    if let Some(sol) = solution {
        let mut data = SIGNET_HEADER.to_vec();
        data.extend(sol);
        assert!(data.len() <= 0xff);
        s.extend([0x4c, data.len() as u8]);
        s.extend(data);
    }
    ScriptBuf::from_bytes(s)
}

/// The real solution's signature (with its sighash byte).
fn real_signature(b: &Block) -> Vec<u8> {
    let (i, start) = solution_at(b);
    let s = b.txdata[0].output[i].script_pubkey.as_bytes();
    // Solution = <scriptSig length> OP_0 <push length> <signature> <witness count 0>.
    let sig_len = usize::from(s[start + 2]);
    s[start + 3..start + 3 + sig_len].to_vec()
}

/// `block` with its solution replaced by `script_sig` (and an empty witness).
fn with_script_sig(b: &Block, script_sig: &[u8]) -> Block {
    let mut sol = serialize(&ScriptBuf::from_bytes(script_sig.to_vec()));
    sol.extend(serialize(&Witness::new()));
    let mut out = b.clone();
    let (i, _) = solution_at(b);
    out.txdata[0].output[i].script_pubkey = commitment_with(b, Some(&sol));
    out
}

#[test]
fn real_signet_blocks_carry_valid_signatures() {
    for b in [block_314(), block_301()] {
        assert_eq!(check(&b), Ok(()));
        let raw = serialize(&b);
        assert!(verify_block_for(Network::Signet, &raw, b.block_hash()).is_ok());
    }
    // The genesis block needs no signature, as in Bitcoin Core.
    assert_eq!(
        check(&bitcoin::constants::genesis_block(Network::Signet)),
        Ok(())
    );
}

#[test]
fn a_flipped_bit_in_the_signature_or_the_signed_header_fails() {
    let b = block_314();
    let (i, start) = solution_at(&b);
    // Flip one bit inside the DER signature (well past its length bytes).
    let mut bad = b.clone();
    let mut s = bad.txdata[0].output[i].script_pubkey.to_bytes();
    s[start + 3 + 40] ^= 0x01;
    bad.txdata[0].output[i].script_pubkey = ScriptBuf::from_bytes(s);
    assert_eq!(check(&bad), Err(SignetError::BadSignature));

    // The signature covers the header's version, parent, merkle root (with
    // the solution taken out) and time: changing any of them breaks it.
    let mut later = b.clone();
    later.header.time += 1;
    assert_eq!(check(&later), Err(SignetError::BadSignature));
    let mut other_tx = b.clone();
    other_tx.txdata.swap(1, 2);
    assert_eq!(check(&other_tx), Err(SignetError::BadSignature));

    // Through the full block check too (the merkle root no longer matches
    // the forged coinbase, so the forged fixture is the honest test of that:
    // see below).
    let raw = serialize(&forged_314());
    assert!(matches!(
        verify_block_for(Network::Signet, &raw, forged_314().block_hash()),
        Err(ProofError::BadSignetSignature(SignetError::BadSignature))
    ));
}

#[test]
fn a_missing_or_moved_solution_fails() {
    let b = block_314();
    let (i, start) = solution_at(&b);
    let solution = b.txdata[0].output[i].script_pubkey.as_bytes()[start..].to_vec();

    // Missing: the commitment without the signet push.
    let mut missing = b.clone();
    missing.txdata[0].output[i].script_pubkey = commitment_with(&b, None);
    assert_eq!(check(&missing), Err(SignetError::BadSignature));

    // Moved to its own OP_RETURN output: only the witness commitment counts.
    let mut moved = missing.clone();
    let mut s = vec![0x6a, 0x4c, (solution.len() + 4) as u8];
    s.extend(SIGNET_HEADER);
    s.extend(&solution);
    moved.txdata[0].output.push(TxOut {
        value: bitcoin::Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(s),
    });
    assert_eq!(check(&moved), Err(SignetError::BadSignature));

    // Moved to an earlier commitment-looking output: only the last one counts.
    let mut early = missing.clone();
    early.txdata[0]
        .output
        .insert(0, b.txdata[0].output[i].clone());
    assert_eq!(check(&early), Err(SignetError::BadSignature));

    // The header alone, with nothing after it, isn't a solution.
    let mut bare = b.clone();
    bare.txdata[0].output[i].script_pubkey = commitment_with(&b, Some(&[]));
    let mut s = bare.txdata[0].output[i].script_pubkey.to_bytes();
    s.truncate(38);
    s.extend([0x04]);
    s.extend(SIGNET_HEADER);
    bare.txdata[0].output[i].script_pubkey = ScriptBuf::from_bytes(s);
    assert_eq!(check(&bare), Err(SignetError::BadSignature));

    // A byte left over after the witness, or a solution that doesn't decode.
    let mut extra = solution.clone();
    extra.push(0x00);
    let mut b2 = b.clone();
    b2.txdata[0].output[i].script_pubkey = commitment_with(&b, Some(&extra));
    assert_eq!(check(&b2), Err(SignetError::MalformedSolution));
    b2.txdata[0].output[i].script_pubkey = commitment_with(&b, Some(&solution[..10]));
    assert_eq!(check(&b2), Err(SignetError::MalformedSolution));

    // No witness commitment at all.
    let mut none = b.clone();
    none.txdata[0].output.remove(i);
    assert_eq!(check(&none), Err(SignetError::NoWitnessCommitment));
}

#[test]
fn the_solution_is_judged_like_bitcoin_cores_interpreter() {
    let b = block_314();
    let sig = real_signature(&b);
    let push = |data: &[u8]| {
        let mut v = vec![data.len() as u8];
        v.extend(data);
        v
    };
    // The real form, rebuilt: OP_0 <sig>.
    let mut ok = vec![0x00];
    ok.extend(push(&sig));
    assert_eq!(check(&with_script_sig(&b, &ok)), Ok(()));
    // Not changing what was signed: the solution is cut out before signing,
    // so these equivalent forms pass too. A non-minimal push (MINIMALDATA
    // isn't a signet flag) and an extra item below the dummy (nor is
    // CLEANSTACK).
    let mut pushdata1 = vec![0x00, 0x4c, sig.len() as u8];
    pushdata1.extend(&sig);
    assert_eq!(check(&with_script_sig(&b, &pushdata1)), Ok(()));
    let mut extra_below = vec![0x51, 0x00];
    extra_below.extend(push(&sig));
    assert_eq!(check(&with_script_sig(&b, &extra_below)), Ok(()));

    // NULLDUMMY: the dummy must be empty.
    let mut dummy = vec![0x51];
    dummy.extend(push(&sig));
    assert_eq!(
        check(&with_script_sig(&b, &dummy)),
        Err(SignetError::BadSignature)
    );
    // No dummy at all.
    assert_eq!(
        check(&with_script_sig(&b, &push(&sig))),
        Err(SignetError::BadSignature)
    );
    // DERSIG: a signature that isn't strict DER is refused.
    let mut loose = sig.clone();
    loose[1] += 1;
    let mut s = vec![0x00];
    s.extend(push(&loose));
    assert_eq!(
        check(&with_script_sig(&b, &s)),
        Err(SignetError::BadSignature)
    );
    // An empty signature never verifies.
    assert_eq!(
        check(&with_script_sig(&b, &[0x00, 0x00])),
        Err(SignetError::BadSignature)
    );
    // A different sighash byte changes the signed hash.
    let mut other_type = sig.clone();
    *other_type.last_mut().unwrap() = 0x81;
    let mut s = vec![0x00];
    s.extend(push(&other_type));
    assert_eq!(
        check(&with_script_sig(&b, &s)),
        Err(SignetError::BadSignature)
    );

    // Non-push opcodes: we don't model them, so they're refused by name.
    let mut nop = vec![0x61, 0x00];
    nop.extend(push(&sig));
    assert_eq!(
        check(&with_script_sig(&b, &nop)),
        Err(SignetError::UnsupportedSolution)
    );

    // A witness is unexpected for a bare-multisig challenge.
    let mut sol = serialize(&ScriptBuf::from_bytes(ok.clone()));
    let mut w = Witness::new();
    w.push([0x01]);
    sol.extend(serialize(&w));
    let mut with_witness = b.clone();
    let (i, _) = solution_at(&b);
    with_witness.txdata[0].output[i].script_pubkey = commitment_with(&b, Some(&sol));
    assert_eq!(check(&with_witness), Err(SignetError::BadSignature));
}

#[test]
fn only_the_standard_signet_challenge_is_accepted() {
    let b = block_314();
    // OP_TRUE (an open signet), and the standard keys in the other order.
    let mut swapped = challenge();
    let (k1, k2) = (swapped[1..35].to_vec(), swapped[35..69].to_vec());
    swapped[1..35].copy_from_slice(&k2);
    swapped[35..69].copy_from_slice(&k1);
    for other in [vec![0x51], swapped] {
        let e = check_block_solution(&b, &other).unwrap_err();
        assert_eq!(e, SignetError::UnsupportedChallenge);
        assert!(e.to_string().contains("standard signet"), "{e}");
    }
}

#[test]
fn the_forged_fixture_is_the_real_block_with_one_bit_flipped() {
    let real = block_314();
    let forged = forged_314();
    // Same transactions except one bit in the coinbase's signet signature.
    let (a, b) = (serialize(&real.txdata[0]), serialize(&forged.txdata[0]));
    assert_eq!(a.len(), b.len());
    let diff: u32 = a.iter().zip(&b).map(|(x, y)| (x ^ y).count_ones()).sum();
    assert_eq!(diff, 1);
    assert_eq!(real.txdata[1..], forged.txdata[1..]);
    // A header that honestly commits to that and meets the real target.
    assert!(forged.check_merkle_root() && forged.check_witness_commitment());
    assert_eq!(forged.header.prev_blockhash, real.header.prev_blockhash);
    assert_eq!(
        (
            forged.header.time,
            forged.header.bits,
            forged.header.version
        ),
        (real.header.time, real.header.bits, real.header.version)
    );
    assert!(forged.header.validate_pow(forged.header.target()).is_ok());
    assert_eq!(check(&forged), Err(SignetError::BadSignature));
}

fn signet_settings(checkpoint: (u32, BlockHash)) -> Settings {
    Settings {
        network: Network::Signet,
        checkpoint: Some(checkpoint),
        fee_ceiling_sat_vb: 1000.0,
        requests_per_sec: 2.0,
        burst: 1_000_000.0,
        jitter: fixed_jitter,
    }
}

/// A fake explorer on signet serving the checkpoint (height 331313) and
/// then `next`. The fakes index blocks by position, not height, which is
/// fine here: the node walks headers by hash from the tip and only asks
/// for height 0, to check the network.
fn signet_source(name: &str, next: &Block) -> Arc<FakeSource> {
    let checkpoint = Block {
        header: header_313(),
        txdata: Vec::new(),
    };
    let s = FakeSource::honest(name, &[checkpoint, next.clone()]);
    s.with(|st| {
        st.genesis_override = Some(bitcoin::constants::genesis_block(Network::Signet).block_hash())
    });
    s
}

#[tokio::test]
async fn a_valid_pow_header_without_a_valid_signature_marks_its_source_bad() {
    let real = block_314();
    let forged = forged_314();
    let liar = signet_source("liar", &forged);
    let honest = signet_source("honest", &real);
    let clock = Arc::new(ManualClock::new(u64::from(real.header.time) + 60));
    let dyns: Vec<Arc<dyn Source>> = vec![liar.clone(), honest.clone()];
    let node = Node::new(
        signet_settings((331_313, header_313().block_hash())),
        dyns,
        clock,
    );
    node.start().await.expect("start");
    node.tick().await;

    assert_eq!(node.with_chain(|c| c.tip_hash()), real.block_hash());
    assert!(!node.with_chain(|c| c.contains(&forged.block_hash())));
    let alarms = node.alarms();
    let bad = &alarms["source-bad:liar"];
    assert!(bad.message.contains("signet signature"), "{}", bad.message);
    assert!(!alarms.contains_key("source-bad:honest"), "{alarms:?}");

    // The block was fetched once to check its signature and is served from
    // the cache afterwards: checking costs no extra requests overall.
    let before = honest.with(|s| s.calls) + liar.with(|s| s.calls);
    let raw = node.get_block(real.block_hash()).await.expect("block");
    assert_eq!(*raw, serialize(&real));
    assert_eq!(honest.with(|s| s.calls) + liar.with(|s| s.calls), before);

    // The liar isn't asked again; the next round is quiet.
    let liar_calls = liar.with(|s| s.calls);
    node.tick().await;
    assert_eq!(liar.with(|s| s.calls), liar_calls);
}

#[tokio::test]
async fn regtest_blocks_need_no_signature() {
    // Regtest has no block signatures: the same check is skipped there, so
    // the existing regtest chains (whose coinbases carry none) still work.
    let blocks = build_chain(3, 1);
    let raw = serialize(&blocks[3]);
    assert!(verify_block_for(Network::Regtest, &raw, blocks[3].block_hash()).is_ok());
    assert!(matches!(
        verify_block_for(Network::Signet, &raw, blocks[3].block_hash()),
        Err(ProofError::BadSignetSignature(
            SignetError::NoWitnessCommitment
        ))
    ));
    let a = FakeSource::honest("a", &blocks);
    let b = FakeSource::honest("b", &blocks);
    let (node, _) = started_node(&[a.clone(), b], &blocks).await;
    assert_eq!(node.with_chain(|c| c.tip_height()), 3);
    assert!(alarm_codes(&node).is_empty(), "{:?}", alarm_codes(&node));
    assert!(node.get_block(blocks[3].block_hash()).await.is_ok());
}
