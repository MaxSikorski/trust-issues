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
//!   proves it is exactly that;
//! - `signet-331314-nop.hex`: block 331314 with `OP_NOP` put in front of
//!   its solution's scriptSig, the merkle root recomputed and the nonce
//!   ground again. Bitcoin Core accepts that solution (the scriptSig needn't
//!   be push-only), but our checker doesn't model it;
//!   `the_nop_fixture_is_the_real_block_with_one_opcode_added` proves what
//!   it is;
//! - `signet-331279-header.hex` and `signet-331280-block.hex` to
//!   `signet-331282-block.hex`: a checkpoint and the three small blocks
//!   after it, for following more than one new block.
//! - `signet-328608-header.hex`, `signet-330623-header.hex` and
//!   `signet-330624-block.hex`: the first and last headers of a retarget
//!   period and the retarget block after it;
//! - `signet-331312-header.hex` and `signet-331313-block.hex`: the
//!   checkpoint and block before 331314, for catching up to it.

mod common;

use std::sync::Arc;

use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::hex::FromHex;
use bitcoin::{Block, BlockHash, Network, ScriptBuf, TxOut, Witness};
use common::*;
use trust_issues::node::{AlarmLevel, ManualClock, Node, Settings};
use trust_issues::proof::{ProofError, verify_block, verify_block_for};
use trust_issues::signet::{
    SIGNET_HEADER, STANDARD_SIGNET_CHALLENGE, SignetError, check_block_solution, find_solution,
};
use trust_issues::source::{Source, SourceError};

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
/// (the bytes after the 4-byte header) starts in its script. Checked
/// against what the checker itself finds (`find_solution`), so tests that
/// place or change bytes here are placing them where the real code looks.
fn solution_at(b: &Block) -> (usize, usize) {
    for (i, out) in b.txdata[0].output.iter().enumerate() {
        let s = out.script_pubkey.as_bytes();
        if let Some(p) = s.windows(4).position(|w| w == SIGNET_HEADER) {
            if let Ok(Some((script_sig, witness))) = find_solution(b) {
                let mut found = serialize(&script_sig);
                found.extend(serialize(&witness));
                assert_eq!(&s[p + 4..], found.as_slice(), "the checker's solution");
            }
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

/// The real solution's signature (with its sighash byte), taken from the
/// solution the checker itself finds: its scriptSig is `OP_0 <signature>`.
fn real_signature(b: &Block) -> Vec<u8> {
    use bitcoin::script::Instruction;
    let (script_sig, witness) = find_solution(b).unwrap().expect("a solution");
    assert!(witness.is_empty());
    let pushes: Vec<Instruction> = script_sig.instructions().collect::<Result<_, _>>().unwrap();
    match pushes.as_slice() {
        [Instruction::PushBytes(dummy), Instruction::PushBytes(sig)] if dummy.is_empty() => {
            sig.as_bytes().to_vec()
        }
        other => panic!("not OP_0 <signature>: {other:?}"),
    }
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
        // The negative counterpart, so a checker that accepts everything
        // can't pass: the same block with its signature's last DER byte
        // changed fails.
        let sig = real_signature(&b);
        let mut broken = sig.clone();
        let last_der = broken.len() - 2;
        broken[last_der] ^= 0x01;
        let mut ss = vec![0x00, broken.len() as u8];
        ss.extend(&broken);
        assert_eq!(
            check(&with_script_sig(&b, &ss)),
            Err(SignetError::BadSignature)
        );
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

    // Those fail for the right reason: moving the solution also changes the
    // signed coinbase, so the signature would fail anyway. What matters is
    // that the checker never even finds a solution there...
    let real = find_solution(&b).unwrap().expect("the real solution");
    assert_eq!(find_solution(&missing), Ok(None));
    assert_eq!(find_solution(&moved), Ok(None));
    assert_eq!(find_solution(&early), Ok(None));
    // ...while it does find the real one in the last commitment, even with
    // a solution-less commitment-looking output before it.
    let mut late = b.clone();
    late.txdata[0]
        .output
        .insert(0, missing.txdata[0].output[i].clone());
    assert_eq!(find_solution(&late), Ok(Some(real.clone())));
    assert_eq!(real.0.as_bytes()[0], 0x00, "OP_0 then the signature");
    assert!(real.1.is_empty());

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
    // Negative counterparts of those three (a checker that accepts every
    // well-formed solution would pass the lines above): the same forms
    // with one bit of the signature's S value flipped all fail.
    let mut flipped = sig.clone();
    let at = flipped.len() - 2;
    flipped[at] ^= 0x01;
    for form in [ok.clone(), pushdata1.clone(), extra_below.clone()] {
        let pos = form
            .windows(sig.len())
            .position(|w| w == sig.as_slice())
            .unwrap();
        let mut f = form.clone();
        f[pos..pos + sig.len()].copy_from_slice(&flipped);
        assert_eq!(
            check(&with_script_sig(&b, &f)),
            Err(SignetError::BadSignature)
        );
    }

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
    // DERSIG: a signature that isn't strict DER is refused, even one the
    // lenient parser reads as the very same valid signature (R padded with
    // a needless zero byte). Without the strict-DER rule it would verify,
    // so this fails if that rule is ever lost. (5449651 had the rule too:
    // this guards against losing it, it didn't catch a bug.)
    let padded = {
        let len_r = usize::from(sig[3]);
        let mut p = vec![0x30, sig[1] + 1, 0x02, sig[3] + 1, 0x00];
        p.extend(&sig[4..4 + len_r]);
        p.extend(&sig[4 + len_r..]);
        p
    };
    let der = |s: &[u8]| s[..s.len() - 1].to_vec();
    assert_eq!(
        bitcoin::secp256k1::ecdsa::Signature::from_der_lax(&der(&padded)).unwrap(),
        bitcoin::secp256k1::ecdsa::Signature::from_der_lax(&der(&sig)).unwrap()
    );
    let mut s = vec![0x00];
    s.extend(push(&padded));
    assert_eq!(
        check(&with_script_sig(&b, &s)),
        Err(SignetError::BadSignature)
    );
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
    // And that bit is inside the signature's DER bytes (not its length,
    // its sighash byte or anything else in the coinbase).
    let at = a.iter().zip(&b).position(|(x, y)| x != y).unwrap();
    let sig = real_signature(&real);
    let der = &sig[..sig.len() - 1];
    let der_at = a.windows(der.len()).position(|w| w == der).unwrap();
    assert_eq!(
        a.windows(der.len()).filter(|w| *w == der).count(),
        1,
        "the signature appears once"
    );
    assert!(
        (der_at + 2..der_at + der.len()).contains(&at),
        "byte {at} isn't inside the signature's DER body at {der_at}..{}",
        der_at + der.len()
    );
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

// ---------- review findings (2026-11-17) ----------

fn hex_block(hex: &str) -> Block {
    block(hex)
}

fn header_279() -> bitcoin::block::Header {
    deserialize(
        &Vec::<u8>::from_hex(include_str!("fixtures/signet-331279-header.hex").trim()).unwrap(),
    )
    .unwrap()
}

/// A fake explorer on signet serving `checkpoint` and then `next` (by
/// position; see [`signet_source`]).
fn signet_source_on(
    name: &str,
    checkpoint: bitcoin::block::Header,
    next: &[Block],
) -> Arc<FakeSource> {
    let mut blocks = vec![Block {
        header: checkpoint,
        txdata: Vec::new(),
    }];
    blocks.extend(next.iter().cloned());
    let s = FakeSource::honest(name, &blocks);
    s.with(|st| {
        st.genesis_override = Some(bitcoin::constants::genesis_block(Network::Signet).block_hash())
    });
    s
}

fn signet_node(sources: &[Arc<FakeSource>], checkpoint: (u32, BlockHash), now: u32) -> Node {
    let dyns: Vec<Arc<dyn Source>> = sources
        .iter()
        .map(|s| s.clone() as Arc<dyn Source>)
        .collect();
    Node::new(
        signet_settings(checkpoint),
        dyns,
        Arc::new(ManualClock::new(u64::from(now) + 60)),
    )
}

/// Block 331314 with every witness taken out (the coinbase's reserved
/// value too). Same txids, so the same header and signet signature.
fn stripped_314() -> Block {
    let mut b = block_314();
    for tx in &mut b.txdata {
        for input in &mut tx.input {
            input.witness = Witness::new();
        }
    }
    b
}

/// Block 331314 with its last transaction listed twice: the merkle tree
/// pads an odd level by repeating the last node, so the root is the same
/// (CVE-2012-2459).
fn padded_314() -> Block {
    let mut b = block_314();
    let last = b.txdata.last().unwrap().clone();
    b.txdata.push(last);
    b
}

#[test]
fn malleated_copies_of_a_real_block_are_refused() {
    let real = block_314();
    for (bad, why) in [
        (stripped_314(), ProofError::BadWitnessCommitment),
        (padded_314(), ProofError::DuplicateTransactions),
    ] {
        // The malleation keeps the header and the signature...
        assert_eq!(bad.block_hash(), real.block_hash());
        assert_eq!(check(&bad), Ok(()));
        assert!(bad.check_merkle_root());
        assert_ne!(serialize(&bad), serialize(&real));
        // ...but the body isn't the block.
        let raw = serialize(&bad);
        assert_eq!(
            verify_block_for(Network::Signet, &raw, real.block_hash()).unwrap_err(),
            why
        );
        assert!(!why.to_string().is_empty() && why.proves_a_lie());
    }
    // Bitcoin Core's other witness rules (`CheckWitnessMalleation`):
    let reserved = real.txdata[0].input[0].witness.clone();
    assert_eq!((reserved.len(), reserved.nth(0).unwrap().len()), (1, 32));
    let refused = |b: &Block| verify_block(&serialize(b), b.block_hash()).unwrap_err();
    // the commitment's reserved value is missing (other witnesses kept)...
    let mut no_reserved = real.clone();
    no_reserved.txdata[0].input[0].witness = Witness::new();
    assert_eq!(refused(&no_reserved), ProofError::BadWitnessCommitment);
    // ...or isn't 32 bytes...
    let mut short = real.clone();
    short.txdata[0].input[0].witness = Witness::from_slice(&[[0u8; 31]]);
    assert_eq!(refused(&short), ProofError::BadWitnessCommitment);
    // ...or a witness was changed...
    let mut changed = real.clone();
    let tx = changed
        .txdata
        .iter_mut()
        .skip(1)
        .find(|t| !t.input[0].witness.is_empty());
    let tx = tx.expect("a segwit spend in 331314");
    let mut items: Vec<Vec<u8>> = tx.input[0].witness.iter().map(<[u8]>::to_vec).collect();
    items[0][5] ^= 0x01;
    tx.input[0].witness = Witness::from_slice(&items);
    assert_eq!(refused(&changed), ProofError::BadWitnessCommitment);
    // ...or there's witness data with no commitment at all (a new header,
    // since dropping the commitment output changes the coinbase).
    let (i, _) = solution_at(&real);
    let mut no_commitment = real.clone();
    no_commitment.txdata[0].output.remove(i);
    no_commitment.header.merkle_root = no_commitment.compute_merkle_root().unwrap();
    assert_eq!(refused(&no_commitment), ProofError::BadWitnessCommitment);
    // Counterparts that pass: no commitment and no witness data at all, and
    // the real block itself.
    for tx in &mut no_commitment.txdata {
        for input in &mut tx.input {
            input.witness = Witness::new();
        }
    }
    no_commitment.header.merkle_root = no_commitment.compute_merkle_root().unwrap();
    let raw = serialize(&no_commitment);
    assert!(verify_block(&raw, no_commitment.block_hash()).is_ok());
    assert!(verify_block(&serialize(&real), real.block_hash()).is_ok());
}

#[tokio::test]
async fn a_malleated_body_never_reaches_the_cache_and_the_honest_copy_is_served() {
    let real = block_314();
    for bad in [stripped_314(), padded_314()] {
        let liar = signet_source("liar", &bad);
        let honest = signet_source("honest", &real);
        let node = signet_node(
            &[liar.clone(), honest.clone()],
            (331_313, header_313().block_hash()),
            real.header.time,
        );
        node.start().await.expect("start");
        node.tick().await;
        assert_eq!(node.with_chain(|c| c.tip_hash()), real.block_hash());
        let raw = node.get_block(real.block_hash()).await.expect("block");
        assert_eq!(*raw, serialize(&real));
        let alarms = node.alarms();
        assert!(alarms.contains_key("source-bad:liar"), "{alarms:?}");
        assert!(!alarms.contains_key("source-bad:honest"), "{alarms:?}");
    }

    // With only the malleator answering, nothing is followed or cached; an
    // honest source that answers later is used and not blamed.
    for bad in [stripped_314(), padded_314()] {
        let liar = signet_source("liar", &bad);
        let honest = signet_source("honest", &real);
        let node = signet_node(
            &[liar.clone(), honest.clone()],
            (331_313, header_313().block_hash()),
            real.header.time,
        );
        node.start().await.expect("start");
        honest.with(|s| s.fail = Some(SourceError::NotFound));
        node.tick().await;
        assert_eq!(node.with_chain(|c| c.tip_height()), 331_313);
        honest.with(|s| s.fail = None);
        node.tick().await;
        assert_eq!(node.with_chain(|c| c.tip_hash()), real.block_hash());
        let raw = node.get_block(real.block_hash()).await.expect("block");
        assert_eq!(*raw, serialize(&real));
        // The honest copy was downloaded (nothing stale stood in for it).
        assert_eq!(honest.with(|s| s.raw_block_calls), 1);
        let alarms = node.alarms();
        assert!(alarms.contains_key("source-bad:liar"), "{alarms:?}");
        assert!(!alarms.contains_key("source-bad:honest"), "{alarms:?}");
    }
}

fn nop_314() -> Block {
    block(include_str!("fixtures/signet-331314-nop.hex"))
}

#[tokio::test]
async fn a_solution_we_dont_model_is_refused_without_blaming_anyone() {
    let nop = nop_314();
    assert_eq!(check(&nop), Err(SignetError::UnsupportedSolution));
    let a = signet_source("a", &nop);
    let b = signet_source("b", &nop);
    let node = signet_node(
        &[a.clone(), b.clone()],
        (331_313, header_313().block_hash()),
        nop.header.time,
    );
    node.start().await.expect("start");
    node.tick().await;
    // Not followed (fail closed)...
    assert_eq!(node.with_chain(|c| c.tip_height()), 331_313);
    // ...but nobody is called a liar: Core may well accept this block.
    let alarms = node.alarms();
    assert!(
        !alarms.keys().any(|k| k.starts_with("source-bad:")),
        "{alarms:?}"
    );
    assert!(
        alarms.values().all(|a| a.level == AlarmLevel::Warning),
        "{alarms:?}"
    );
    assert!(
        alarms.values().any(|a| a.message.contains("doesn't model")),
        "{alarms:?}"
    );
    // The block isn't downloaded again every round.
    let downloads = a.with(|s| s.raw_block_calls) + b.with(|s| s.raw_block_calls);
    node.tick().await;
    assert_eq!(
        a.with(|s| s.raw_block_calls) + b.with(|s| s.raw_block_calls),
        downloads
    );
    assert!(node.get_block(nop.block_hash()).await.is_err());

    // The same through `getblock` for an old block below the checkpoint
    // (the fakes answer height 1 with this block): refused, nobody blamed.
    let a = signet_source("a", &nop);
    let b = signet_source("b", &nop);
    let node = signet_node(
        &[a.clone(), b.clone()],
        (331_313, header_313().block_hash()),
        nop.header.time,
    );
    node.start().await.expect("start");
    assert_eq!(node.deep_hash_at(1).await, Ok(nop.block_hash()));
    let err = node.get_block(nop.block_hash()).await.unwrap_err();
    assert!(err.message.contains("doesn't model"), "{err:?}");
    let alarms = node.alarms();
    assert!(
        !alarms.keys().any(|k| k.starts_with("source-bad:")),
        "{alarms:?}"
    );
    assert!(
        alarms.values().any(|a| a.message.contains("doesn't model")),
        "{alarms:?}"
    );
}

#[test]
fn the_nop_fixture_is_the_real_block_with_one_opcode_added() {
    let real = block_314();
    let nop = nop_314();
    assert_eq!(real.txdata[1..], nop.txdata[1..]);
    // The only change: OP_NOP (0x61) in front of the solution's scriptSig
    // (so the scriptSig, the solution and the push each grow by a byte).
    let (i, start) = solution_at(&real);
    let r = real.txdata[0].output[i].script_pubkey.as_bytes();
    let n = nop.txdata[0].output[i].script_pubkey.as_bytes();
    assert_eq!(&n[..38], &r[..38]);
    assert_eq!((r[38], n[38]), (0x4c, 0x4c));
    assert_eq!(n[39], r[39] + 1);
    assert_eq!(&n[40..start], &r[40..start]);
    assert_eq!(n[start], r[start] + 1);
    assert_eq!(n[start + 1], 0x61);
    assert_eq!(&n[start + 2..], &r[start + 1..]);
    let mut coinbase = nop.txdata[0].clone();
    coinbase.output[i] = real.txdata[0].output[i].clone();
    assert_eq!(coinbase, real.txdata[0]);
    // A header that commits to it honestly and meets the real target.
    assert!(nop.check_merkle_root() && nop.check_witness_commitment());
    assert_eq!(
        (nop.header.prev_blockhash, nop.header.time, nop.header.bits),
        (
            real.header.prev_blockhash,
            real.header.time,
            real.header.bits
        )
    );
    assert!(nop.header.validate_pow(nop.header.target()).is_ok());
}

#[tokio::test]
async fn bootstrap_refuses_a_checkpoint_from_another_signet() {
    // Two explorers agree on a chain whose block 6 below their tip has
    // valid proof of work but isn't signed for our signet.
    // The candidate sits at 331314 (its real height), six blocks below the
    // explorers' tip.
    let fillers = build_chain(6, 1);
    let make = |name: &str, first: &Block| {
        let mut blocks = vec![first.clone()];
        blocks.extend(fillers[1..].iter().cloned());
        let s = FakeSource::honest(name, &blocks);
        s.with(|st| {
            st.height_offset = 331_314;
            st.genesis_override =
                Some(bitcoin::constants::genesis_block(Network::Signet).block_hash())
        });
        s
    };
    let mut settings = signet_settings((0, BlockHash::all_zeros()));
    settings.checkpoint = None;
    let forged = forged_314();
    let srcs = [make("a", &forged), make("b", &forged)];
    let dyns: Vec<Arc<dyn Source>> = srcs.iter().map(|s| s.clone() as Arc<dyn Source>).collect();
    let node = Node::new(
        settings,
        dyns,
        Arc::new(ManualClock::new(u64::from(forged.header.time) + 60)),
    );
    assert!(node.start().await.is_err());
    assert!(!node.is_ready());

    // The same with the real block: it bootstraps from it.
    let real = block_314();
    let srcs = [make("a", &real), make("b", &real)];
    let dyns: Vec<Arc<dyn Source>> = srcs.iter().map(|s| s.clone() as Arc<dyn Source>).collect();
    let mut settings = signet_settings((0, BlockHash::all_zeros()));
    settings.checkpoint = None;
    let node = Node::new(
        settings,
        dyns,
        Arc::new(ManualClock::new(u64::from(real.header.time) + 60)),
    );
    node.start().await.expect("start");
    assert_eq!(node.with_chain(|c| c.tip_hash()), real.block_hash());
}

#[tokio::test(start_paused = true)]
async fn a_new_block_is_downloaded_once_however_many_sources_offer_it() {
    let real = block_314();
    let a = signet_source("a", &real);
    let b = signet_source("b", &real);
    for s in [&a, &b] {
        s.with(|st| st.raw_block_delay = Some(std::time::Duration::from_secs(2)));
    }
    let node = signet_node(
        &[a.clone(), b.clone()],
        (331_313, header_313().block_hash()),
        real.header.time,
    );
    node.start().await.expect("start");
    node.tick().await;
    assert_eq!(node.with_chain(|c| c.tip_hash()), real.block_hash());
    assert_eq!(
        a.with(|s| s.raw_block_calls) + b.with(|s| s.raw_block_calls),
        1
    );
    assert!(!node.alarms().keys().any(|k| k.starts_with("source-bad:")));
}

#[tokio::test]
async fn a_withheld_block_stops_the_run_there_without_blame() {
    let blocks = [
        hex_block(include_str!("fixtures/signet-331280-block.hex")),
        hex_block(include_str!("fixtures/signet-331281-block.hex")),
        hex_block(include_str!("fixtures/signet-331282-block.hex")),
    ];
    let s = signet_source_on("s", header_279(), &blocks);
    s.with(|st| {
        st.withheld_blocks.insert(blocks[2].block_hash());
    });
    let node = signet_node(
        std::slice::from_ref(&s),
        (331_279, header_279().block_hash()),
        blocks[2].header.time,
    );
    node.start().await.expect("start");
    node.tick().await;
    // The two proven blocks are followed; the withheld one waits.
    assert_eq!(node.with_chain(|c| c.tip_height()), 331_281);
    assert_eq!(node.with_chain(|c| c.tip_hash()), blocks[1].block_hash());
    assert!(
        !node.alarms().keys().any(|k| k.starts_with("source-bad:")),
        "{:?}",
        node.alarms()
    );
    // Served at last: the tip moves on.
    s.with(|st| st.withheld_blocks.clear());
    node.tick().await;
    assert_eq!(node.with_chain(|c| c.tip_hash()), blocks[2].block_hash());
    assert!(node.alarms().keys().all(|k| !k.starts_with("source-bad:")));
}

// ---------- second review (2026-11-17) ----------

fn header_hex(hex: &str) -> bitcoin::block::Header {
    deserialize(&Vec::<u8>::from_hex(hex.trim()).unwrap()).unwrap()
}

fn header_only(h: bitcoin::block::Header) -> Block {
    Block {
        header: h,
        txdata: Vec::new(),
    }
}

/// A fake signet explorer whose `blocks[i]` sits at height `offset + i`.
fn signet_source_at(name: &str, offset: u32, blocks: &[Block]) -> Arc<FakeSource> {
    let s = FakeSource::honest(name, blocks);
    s.with(|st| {
        st.height_offset = offset;
        st.genesis_override = Some(bitcoin::constants::genesis_block(Network::Signet).block_hash());
    });
    s
}

fn bootstrap_node(sources: &[Arc<FakeSource>], now: u32) -> Node {
    let dyns: Vec<Arc<dyn Source>> = sources
        .iter()
        .map(|s| s.clone() as Arc<dyn Source>)
        .collect();
    let mut settings = signet_settings((0, BlockHash::all_zeros()));
    settings.checkpoint = None;
    Node::new(
        settings,
        dyns,
        Arc::new(ManualClock::new(u64::from(now) + 60)),
    )
}

#[tokio::test]
async fn a_retarget_above_the_checkpoint_waits_for_the_periods_first_header_without_blame() {
    let h608 = header_hex(include_str!("fixtures/signet-328608-header.hex"));
    let h623 = header_hex(include_str!("fixtures/signet-330623-header.hex"));
    let b624 = hex_block(include_str!("fixtures/signet-330624-block.hex"));
    let make = |name: &str| {
        signet_source_at(
            name,
            0,
            &[header_only(h608), header_only(h623), b624.clone()],
        )
    };
    let (a, b) = (make("a"), make("b"));
    let node = signet_node(
        &[a.clone(), b.clone()],
        (330_623, h623.block_hash()),
        b624.header.time,
    );
    node.start().await.expect("start");

    // Neither explorer has the headers below the checkpoint, so the walk
    // back can't reach 328608 (the period's first): the retarget header
    // isn't followed, and nobody is blamed.
    node.tick().await;
    assert_eq!(node.with_chain(|c| c.tip_height()), 330_623);
    let alarms = node.alarms();
    assert!(
        !alarms.keys().any(|k| k.starts_with("source-bad:")),
        "{alarms:?}"
    );
    assert!(
        alarms
            .values()
            .any(|a| a.level == AlarmLevel::Warning && a.message.contains("328608")),
        "{alarms:?}"
    );

    // Once they serve them, the walk proves each by its hash down to
    // 328608; then the exact retarget is checked and followed.
    let hs = period_headers();
    assert_eq!(hs[0], h608);
    for s in [&a, &b] {
        s.with(|st| {
            st.extra_headers = hs[..2015].iter().map(|h| (h.block_hash(), *h)).collect();
        });
    }
    let followed = tick_until(&node, 60, |n| {
        n.with_chain(|c| c.tip_hash()) == b624.block_hash()
    })
    .await;
    assert!(followed, "{:?}", node.alarms());
    let alarms = node.alarms();
    assert!(
        !alarms.values().any(|a| a.message.contains("328608")),
        "{alarms:?}"
    );
    assert!(
        !alarms.keys().any(|k| k.starts_with("source-bad:")),
        "{alarms:?}"
    );
}

/// Block 331314 with a nonce that misses its target (the signature
/// doesn't cover the nonce, so it still verifies).
fn unmined_314() -> Block {
    let mut b = block_314();
    while b.header.validate_pow(b.header.target()).is_ok() {
        b.header.nonce = b.header.nonce.wrapping_add(1);
    }
    b
}

#[tokio::test]
async fn bootstrap_checks_the_height_proof_of_work_and_genesis() {
    let genesis = bitcoin::constants::genesis_block(Network::Signet);
    let fillers = build_chain(6, 1);
    let real = block_314();

    // The real block at its real height (BIP34 matches): it starts.
    let at = |name: &str, offset: u32, first: &Block| {
        let mut blocks = vec![first.clone()];
        blocks.extend(fillers[1..].iter().cloned());
        signet_source_at(name, offset, &blocks)
    };
    let node = bootstrap_node(
        &[at("a", 331_314, &real), at("b", 331_314, &real)],
        real.header.time,
    );
    node.start().await.expect("start");
    assert_eq!(node.with_chain(|c| c.tip_height()), 331_314);

    // The same block claimed at height 1: its coinbase says 331314.
    let node = bootstrap_node(&[at("a", 1, &real), at("b", 1, &real)], real.header.time);
    assert!(node.start().await.is_err());
    assert!(!node.is_ready());

    // Signed, at its real height, but its header misses its target.
    let unmined = unmined_314();
    assert_eq!(check(&unmined), Ok(()));
    let node = bootstrap_node(
        &[at("a", 331_314, &unmined), at("b", 331_314, &unmined)],
        real.header.time,
    );
    assert!(node.start().await.is_err());
    assert!(!node.is_ready());

    // The genesis block (which needs no signature) claimed at height 1.
    let node = bootstrap_node(
        &[at("a", 1, &genesis), at("b", 1, &genesis)],
        real.header.time,
    );
    assert!(node.start().await.is_err());
    assert!(!node.is_ready());

    // Nor is genesis taken as an old block at any other height.
    let a = signet_source_on("a", header_313(), std::slice::from_ref(&genesis));
    let b = signet_source_on("b", header_313(), std::slice::from_ref(&genesis));
    let node = signet_node(
        &[a, b],
        (331_313, header_313().block_hash()),
        real.header.time,
    );
    node.start().await.expect("start");
    assert!(node.deep_hash_at(1).await.is_err());
}

#[test]
fn the_first_transaction_must_be_the_only_coinbase() {
    use bitcoin::block::{Header, Version as BlockVersion};
    use bitcoin::{CompactTarget, TxMerkleNode};

    let blocks = build_chain(1, 1);
    let mined = |prev: &Header, txdata: Vec<bitcoin::Transaction>| {
        let mut b = Block {
            header: Header {
                version: BlockVersion::from_consensus(0x2000_0000),
                prev_blockhash: prev.block_hash(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: prev.time + 600,
                bits: CompactTarget::from_consensus(REGTEST_BITS),
                nonce: 0,
            },
            txdata,
        };
        b.header.merkle_root = b.compute_merkle_root().unwrap();
        while b.header.validate_pow(b.header.target()).is_err() {
            b.header.nonce += 1;
        }
        b
    };
    // A first transaction spending an ordinary output, dressed like a
    // coinbase: a 32-byte reserved value and a matching witness commitment.
    let mut first = spend(&blocks[1].txdata[0], 0, 1000, 7);
    first.input[0].witness = Witness::from_slice(&[[0u8; 32]]);
    let draft = Block {
        header: blocks[1].header,
        txdata: vec![first.clone()],
    };
    let commitment = Block::compute_witness_commitment(&draft.witness_root().unwrap(), &[0u8; 32]);
    let mut script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    script.extend(commitment.to_byte_array());
    first.output.push(TxOut {
        value: bitcoin::Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(script),
    });
    let fake = mined(&blocks[1].header, vec![first]);
    assert!(!fake.txdata[0].is_coinbase());
    let raw = serialize(&fake);
    assert_eq!(
        verify_block_for(Network::Regtest, &raw, fake.block_hash()).unwrap_err(),
        ProofError::BadCoinbase
    );
    // A second coinbase after the first.
    let two = mined(&blocks[1].header, vec![coinbase(2, 1), coinbase(2, 2)]);
    assert_eq!(
        verify_block(&serialize(&two), two.block_hash()).unwrap_err(),
        ProofError::BadCoinbase
    );
    // The counterpart: one coinbase, first, passes.
    let one = mined(&blocks[1].header, vec![coinbase(2, 1)]);
    assert!(verify_block(&serialize(&one), one.block_hash()).is_ok());
}

#[tokio::test]
async fn the_unsupported_solution_warning_stays_until_that_block_is_superseded() {
    let h312 = header_hex(include_str!("fixtures/signet-331312-header.hex"));
    let b313 = hex_block(include_str!("fixtures/signet-331313-block.hex"));
    assert_eq!(b313.block_hash(), header_313().block_hash());
    let nop = nop_314();
    let make =
        |name: &str| signet_source_at(name, 0, &[header_only(h312), b313.clone(), nop.clone()]);
    let (a, b) = (make("a"), make("b"));
    let node = signet_node(
        &[a.clone(), b.clone()],
        (331_312, h312.block_hash()),
        nop.header.time,
    );
    node.start().await.expect("start");
    let unjudged = |node: &Node| {
        node.alarms()
            .values()
            .any(|a| a.level == AlarmLevel::Warning && a.message.contains("doesn't model"))
    };

    // Catching up: 331313 is followed, the OP_NOP block after it isn't, and
    // the warning stays up (5f78d99 cleared it when 331313 connected).
    node.tick().await;
    assert_eq!(node.with_chain(|c| c.tip_hash()), b313.block_hash());
    assert!(unjudged(&node), "{:?}", node.alarms());
    // Still refused next round, from the cache: still warned about.
    node.tick().await;
    assert_eq!(node.with_chain(|c| c.tip_hash()), b313.block_hash());
    assert!(unjudged(&node), "{:?}", node.alarms());

    // The explorers move to the real 331314 (as much work as the refused
    // block): it's superseded, so the warning goes.
    for s in [&a, &b] {
        s.set_chain(&[header_only(h312), b313.clone(), block_314()]);
    }
    node.tick().await;
    assert_eq!(node.with_chain(|c| c.tip_hash()), block_314().block_hash());
    assert!(!unjudged(&node), "{:?}", node.alarms());
    assert!(
        !node.alarms().keys().any(|k| k.starts_with("source-bad:")),
        "{:?}",
        node.alarms()
    );
}

#[tokio::test(start_paused = true)]
async fn a_stalled_download_doesnt_hold_up_a_ready_source() {
    let real = block_314();
    let stalled = signet_source("stalled", &real);
    let ready = signet_source("ready", &real);
    stalled.with(|st| st.raw_block_delay = Some(std::time::Duration::from_secs(1000)));
    let node = Arc::new(signet_node(
        &[stalled.clone(), ready.clone()],
        (331_313, header_313().block_hash()),
        real.header.time,
    ));
    node.start().await.expect("start");
    let n = node.clone();
    let round = tokio::spawn(async move { n.tick().await });
    // Within the waiting bound (plus a second), the ready explorer has
    // fetched and proven the block itself.
    tokio::time::sleep(trust_issues::node::IN_FLIGHT_WAIT + std::time::Duration::from_secs(1))
        .await;
    assert_eq!(node.with_chain(|c| c.tip_hash()), real.block_hash());
    // The stalled one held the slot (one download each): the ready one
    // waited, gave up waiting, then downloaded once.
    assert_eq!(stalled.with(|s| s.raw_block_calls), 1);
    assert_eq!(ready.with(|s| s.raw_block_calls), 1);
    round.await.unwrap();
    assert!(!node.alarms().keys().any(|k| k.starts_with("source-bad:")));
    assert_eq!(node.in_flight_len(), 0);
}

#[tokio::test(start_paused = true)]
async fn a_cancelled_download_leaves_no_slot_behind() {
    let blocks = build_chain(3, 1);
    let a = FakeSource::honest("a", &blocks);
    let (node, _) = started_node(std::slice::from_ref(&a), &blocks).await;
    a.with(|st| st.raw_block_delay = Some(std::time::Duration::from_secs(100)));
    let second = std::time::Duration::from_secs(1);
    // Two distinct blocks, each download given up by its caller.
    for h in [2, 3] {
        let fetch = node.get_block(blocks[h].block_hash());
        assert!(tokio::time::timeout(second, fetch).await.is_err());
    }
    assert_eq!(node.in_flight_len(), 0);
    // A waiter that gives up while another download holds the slot.
    let n = node.clone();
    let hash = blocks[1].block_hash();
    let holder = tokio::spawn(async move { n.get_block(hash).await });
    tokio::task::yield_now().await;
    assert!(
        tokio::time::timeout(second, node.get_block(hash))
            .await
            .is_err()
    );
    assert!(holder.await.unwrap().is_ok());
    assert_eq!(node.in_flight_len(), 0);
}

// ---------- third review (2026-11-17) ----------
//
// More fixtures, also real standard-signet data:
// - `signet-328608-to-330623-headers.bin`: every header of the retarget
//   period 328608..330623, oldest first, 80 bytes each (read from an
//   explorer's Esplora API, each checked against its hash and its parent);
// - `signet-331315-on-nop-header.hex`: a header on top of the OP_NOP block
//   331314 (merkle root all zeros, its nonce ground to meet the real
//   target), a second block on that refused branch.

/// Real signet headers 328608..330623, oldest first.
fn period_headers() -> Vec<bitcoin::block::Header> {
    include_bytes!("fixtures/signet-328608-to-330623-headers.bin")
        .chunks(80)
        .map(|c| deserialize(c).unwrap())
        .collect()
}

/// A fake signet explorer showing the checkpoint 330623 and then `next`.
/// Like a real one, it also serves the 2015 headers below the checkpoint
/// (328608..330622) by hash.
fn period_source(name: &str, next: &[Block]) -> Arc<FakeSource> {
    let hs = period_headers();
    let mut blocks = vec![header_only(hs[2015])];
    blocks.extend(next.iter().cloned());
    let s = signet_source_at(name, 330_623, &blocks);
    s.with(|st| {
        st.extra_headers = hs[..2015].iter().map(|h| (h.block_hash(), *h)).collect();
    });
    s
}

fn b624() -> Block {
    hex_block(include_str!("fixtures/signet-330624-block.hex"))
}

/// Tick until `done` holds, at most `ticks` times; whether it came to hold.
async fn tick_until(node: &Node, ticks: usize, done: impl Fn(&Node) -> bool) -> bool {
    for _ in 0..ticks {
        if done(node) {
            return true;
        }
        node.tick().await;
    }
    done(node)
}

fn bad_sources(node: &Node) -> Vec<String> {
    node.alarms()
        .keys()
        .filter(|k| k.starts_with("source-bad:"))
        .cloned()
        .collect()
}

#[tokio::test]
async fn one_honest_explorer_is_enough_to_prove_the_periods_first_header() {
    let b624 = b624();
    let s = period_source("only", std::slice::from_ref(&b624));
    let node = signet_node(
        std::slice::from_ref(&s),
        (330_623, period_headers()[2015].block_hash()),
        b624.header.time,
    );
    node.start().await.expect("start");
    // d2097ae needed two explorers to vote on the block at 328608, so with
    // one it held the retarget forever. Walking back by hash needs one.
    let followed = tick_until(&node, 60, |n| {
        n.with_chain(|c| c.tip_hash()) == b624.block_hash()
    })
    .await;
    assert!(followed, "{:?}", node.alarms());
    assert!(bad_sources(&node).is_empty(), "{:?}", node.alarms());
    assert!(!node.alarms().contains_key("retarget-held"));
}

#[tokio::test]
async fn an_explorer_lying_about_a_walked_header_is_caught_and_the_walk_goes_on() {
    let b624 = b624();
    let hs = period_headers();
    let liar = period_source("liar", std::slice::from_ref(&b624));
    // Every header it serves below the checkpoint is a real one, from
    // another height: right proof of work, right bits, wrong hash.
    liar.with(|st| {
        st.extra_headers = (0..2015)
            .map(|i| (hs[i].block_hash(), hs[(i + 1) % 2015]))
            .collect();
    });
    let honest = period_source("honest", std::slice::from_ref(&b624));
    let node = signet_node(
        &[liar.clone(), honest.clone()],
        (330_623, hs[2015].block_hash()),
        b624.header.time,
    );
    node.start().await.expect("start");
    let followed = tick_until(&node, 60, |n| {
        n.with_chain(|c| c.tip_hash()) == b624.block_hash()
    })
    .await;
    assert!(followed, "{:?}", node.alarms());
    assert_eq!(bad_sources(&node), vec!["source-bad:liar".to_string()]);
    assert!(
        node.alarms()["source-bad:liar"]
            .message
            .contains("doesn't hash to"),
        "{:?}",
        node.alarms()
    );
}

#[tokio::test]
async fn two_explorers_agreeing_on_a_wrong_period_start_change_nothing() {
    let b624 = b624();
    let hs = period_headers();
    // Both name 330622 (same period: valid proof of work and the same
    // bits) as the block at 328608. d2097ae took that vote, computed the
    // wrong target for 330624 and held the honest chain back for good.
    let make = |name: &str| {
        let s = period_source(name, std::slice::from_ref(&b624));
        s.with(|st| {
            st.at_height.insert(328_608, hs[2014].block_hash());
        });
        s
    };
    let (a, b) = (make("a"), make("b"));
    let node = signet_node(&[a, b], (330_623, hs[2015].block_hash()), b624.header.time);
    node.start().await.expect("start");
    let followed = tick_until(&node, 60, |n| {
        n.with_chain(|c| c.tip_hash()) == b624.block_hash()
    })
    .await;
    assert!(followed, "{:?}", node.alarms());
    assert!(bad_sources(&node).is_empty(), "{:?}", node.alarms());
    assert!(!node.alarms().contains_key("retarget-held"));
}

#[tokio::test]
async fn a_wrong_bits_sibling_after_the_retarget_doesnt_reopen_the_hold() {
    let b624 = b624();
    let hs = period_headers();
    let make = |name: &str| {
        let s = period_source(name, std::slice::from_ref(&b624));
        // (d2097ae found the period's first header by this vote.)
        s.with(|st| {
            st.at_height.insert(328_608, hs[0].block_hash());
        });
        s
    };
    let (a, b, sib) = (make("a"), make("b"), make("sib"));
    let node = signet_node(
        &[a, b, sib.clone()],
        (330_623, hs[2015].block_hash()),
        b624.header.time,
    );
    node.start().await.expect("start");
    let followed = tick_until(&node, 60, |n| {
        n.with_chain(|c| c.tip_hash()) == b624.block_hash()
    })
    .await;
    assert!(followed, "{:?}", node.alarms());
    assert!(!node.alarms().contains_key("retarget-held"));

    // One explorer now offers a sibling of 330624 one unit harder than
    // Core computes (the bits are checked before the proof of work).
    let mut sibling = b624.header;
    sibling.bits = bitcoin::CompactTarget::from_consensus(0x1d14_fced);
    sib.set_chain(&[header_only(hs[2015]), header_only(sibling)]);
    node.tick().await;
    assert_eq!(node.with_chain(|c| c.tip_hash()), b624.block_hash());
    // Our best chain is past the retarget: nothing is held.
    assert!(
        !node.alarms().contains_key("retarget-held"),
        "{:?}",
        node.alarms()
    );
}

#[tokio::test]
async fn the_unsupported_solution_warning_counts_the_whole_competing_branch() {
    let h312 = header_hex(include_str!("fixtures/signet-331312-header.hex"));
    let b313 = hex_block(include_str!("fixtures/signet-331313-block.hex"));
    let nop = nop_314();
    let child = header_hex(include_str!("fixtures/signet-331315-on-nop-header.hex"));
    assert_eq!(child.prev_blockhash, nop.block_hash());
    assert!(child.validate_pow(child.target()).is_ok());
    let make = |name: &str| {
        signet_source_at(
            name,
            331_312,
            &[
                header_only(h312),
                b313.clone(),
                nop.clone(),
                header_only(child),
            ],
        )
    };
    let (a, b) = (make("a"), make("b"));
    let node = signet_node(
        &[a.clone(), b.clone()],
        (331_312, h312.block_hash()),
        child.time,
    );
    node.start().await.expect("start");
    let unjudged = |node: &Node| node.alarms().contains_key("signet-unjudged");
    node.tick().await;
    assert_eq!(node.with_chain(|c| c.tip_hash()), b313.block_hash());
    assert!(unjudged(&node), "{:?}", node.alarms());

    // The real 331314 has as much work as the refused block, but the
    // refused branch already shows a block after it: it could still be
    // the best chain, so the warning stays (d2097ae cleared it).
    for s in [&a, &b] {
        s.set_chain(&[header_only(h312), b313.clone(), block_314()]);
    }
    node.tick().await;
    assert_eq!(node.with_chain(|c| c.tip_hash()), block_314().block_hash());
    assert!(unjudged(&node), "{:?}", node.alarms());
    assert!(bad_sources(&node).is_empty(), "{:?}", node.alarms());
}

#[tokio::test(start_paused = true)]
async fn many_waiting_callers_start_at_most_one_extra_download() {
    let blocks = build_chain(3, 1);
    let a = FakeSource::honest("a", &blocks);
    let (node, _) = started_node(std::slice::from_ref(&a), &blocks).await;
    a.with(|st| {
        st.raw_block_calls = 0;
        st.raw_block_delay = Some(std::time::Duration::from_secs(15));
    });
    let hash = blocks[2].block_hash();
    let calls: Vec<_> = (0..20)
        .map(|_| {
            let n = node.clone();
            tokio::spawn(async move { n.get_block(hash).await })
        })
        .collect();
    for c in calls {
        assert!(c.await.unwrap().is_ok());
    }
    // The first download, and one fallback after IN_FLIGHT_WAIT; the
    // other 18 waited for whichever finished (d2097ae: 20 downloads).
    assert!(
        a.with(|s| s.raw_block_calls) <= 2,
        "{}",
        a.with(|s| s.raw_block_calls)
    );
    assert_eq!(node.in_flight_len(), 0);
}

#[tokio::test(start_paused = true)]
async fn one_explorer_gets_at_most_two_block_downloads_at_once() {
    let blocks = build_chain(20, 1);
    let a = FakeSource::honest("a", &blocks);
    let (node, _) = started_node(std::slice::from_ref(&a), &blocks).await;
    a.with(|st| {
        st.raw_block_calls = 0;
        st.raw_block_delay = Some(std::time::Duration::from_secs(15));
    });
    let calls: Vec<_> = (1..=20)
        .map(|h| {
            let n = node.clone();
            let hash = blocks[h].block_hash();
            tokio::spawn(async move { n.get_block(hash).await })
        })
        .collect();
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    assert_eq!(a.with(|s| s.raw_block_calls), 2);
    for c in calls {
        assert!(c.await.unwrap().is_ok());
    }
    assert_eq!(a.with(|s| s.raw_block_calls), 20);
    assert_eq!(node.in_flight_len(), 0);
}
