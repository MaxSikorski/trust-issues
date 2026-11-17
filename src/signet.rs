//! Signet block signatures (BIP325).
//!
//! Every signet (the standard one, Mutinynet, others) shares one genesis
//! block; what tells them apart is the "challenge", a script each block must
//! satisfy with a signature hidden in its coinbase. Proof of work on signet is
//! cheap, so without this check a source following *another* signet, or
//! anyone who can grind a little work, could hand us valid-looking headers.
//!
//! This follows Bitcoin Core's `src/signet.cpp` step by step:
//! 1. find the coinbase's witness-commitment output (the last one that
//!    starts `6a24aa21a9ed`) and, inside it, the first push that starts with
//!    the 4-byte signet header `ecc7daa2` and has more after it. Those extra
//!    bytes are the "solution": a scriptSig and a witness stack;
//! 2. rebuild that output with the solution cut off, and recompute the
//!    block's merkle root with this modified coinbase. That's what was signed
//!    (the signature can't sign itself);
//! 3. build two virtual transactions: `to_spend`, whose output is the
//!    challenge and whose input commits to the block (version, previous hash,
//!    modified merkle root, time), and `to_sign`, which spends it using the
//!    solution;
//! 4. run the solution against the challenge.
//!
//! Step 4 needs a script interpreter, and rust-bitcoin doesn't have one. We
//! only support the standard signet's challenge, a 1-of-2 bare multisig, and
//! check it exactly the way Core's interpreter would with signet's flags
//! (P2SH, WITNESS, DERSIG, NULLDUMMY). Any other challenge is refused. The
//! one thing we don't model is a solution scriptSig with non-push opcodes:
//! Core could accept some of those, but no signet signer produces them, so
//! we refuse them with their own error rather than guess.

use bitcoin::consensus::encode::Decodable;
use bitcoin::hashes::Hash;
use bitcoin::hex::FromHex;
use bitcoin::secp256k1::{Message, PublicKey, Secp256k1, ecdsa};
use bitcoin::sighash::SighashCache;
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, Block, OutPoint, Script, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};

/// The 4 bytes that mark the signet solution inside the witness commitment.
pub const SIGNET_HEADER: [u8; 4] = [0xec, 0xc7, 0xda, 0xa2];

/// The standard (default) signet's challenge: `OP_1 <key1> <key2> OP_2
/// OP_CHECKMULTISIG`, from Bitcoin Core's chainparams. Our config only
/// allows the standard signet, so this is the only challenge we check.
pub const STANDARD_SIGNET_CHALLENGE: &str = "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae";

// Script limits Core's interpreter enforces (script/script.h).
const MAX_SCRIPT_SIZE: usize = 10_000;
const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;
const MAX_STACK_SIZE: usize = 1000;
const OP_PUSHDATA1: u8 = 0x4c;
const OP_PUSHDATA2: u8 = 0x4d;
const OP_PUSHDATA4: u8 = 0x4e;
const OP_1NEGATE: u8 = 0x4f;
const OP_1: u8 = 0x51;
const OP_16: u8 = 0x60;
const OP_RETURN: u8 = 0x6a;

/// Why a block's signet signature was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignetError {
    /// We only check the standard signet's challenge.
    UnsupportedChallenge,
    NoCoinbase,
    NoWitnessCommitment,
    /// The solution doesn't decode as a scriptSig plus witness, or has
    /// bytes left over.
    MalformedSolution,
    /// The solution's scriptSig uses opcodes other than pushes. Core might
    /// accept some of these; we don't model them, so we fail closed.
    UnsupportedSolution,
    /// The solution doesn't satisfy the challenge (including no solution at
    /// all: the standard challenge needs a signature).
    BadSignature,
}

impl std::fmt::Display for SignetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            SignetError::UnsupportedChallenge => {
                "only the standard signet's challenge is supported (the config allows no other signet)"
            }
            SignetError::NoCoinbase => "block has no coinbase",
            SignetError::NoWitnessCommitment => {
                "coinbase has no witness commitment to hold a signet signature"
            }
            SignetError::MalformedSolution => "signet solution doesn't decode",
            SignetError::UnsupportedSolution => {
                "signet solution uses opcodes this checker doesn't model; refused to be safe"
            }
            SignetError::BadSignature => "signet signature doesn't satisfy the challenge",
        };
        f.write_str(s)
    }
}

impl std::error::Error for SignetError {}

/// Check a block's signet solution against `challenge` (the challenge
/// script's bytes). The genesis block needs none, as in Core.
pub fn check_block_solution(block: &Block, challenge: &[u8]) -> Result<(), SignetError> {
    let standard = Vec::<u8>::from_hex(STANDARD_SIGNET_CHALLENGE).expect("constant is hex");
    if challenge != standard.as_slice() {
        return Err(SignetError::UnsupportedChallenge);
    }
    if block.block_hash()
        == bitcoin::constants::genesis_block(bitcoin::Network::Signet).block_hash()
    {
        return Ok(());
    }
    let (to_spend, to_sign) = signet_txs(block, challenge)?;
    if !to_sign.input[0].witness.is_empty() {
        // The challenge isn't a witness program, so with the WITNESS flag any
        // witness data is an error (SCRIPT_ERR_WITNESS_UNEXPECTED).
        return Err(SignetError::BadSignature);
    }
    let stack = push_only_stack(&to_sign.input[0].script_sig)?;
    if check_multisig_1_of_2(
        &stack,
        &to_sign,
        &to_spend.output[0].script_pubkey,
        challenge,
    ) {
        Ok(())
    } else {
        Err(SignetError::BadSignature)
    }
}

/// Build Core's `to_spend` and `to_sign` virtual transactions
/// (`SignetTxs::Create`).
fn signet_txs(block: &Block, challenge: &[u8]) -> Result<(Transaction, Transaction), SignetError> {
    let coinbase = block.txdata.first().ok_or(SignetError::NoCoinbase)?;
    let cidx = witness_commitment_index(coinbase).ok_or(SignetError::NoWitnessCommitment)?;

    let mut modified_cb = coinbase.clone();
    let commitment = modified_cb.output[cidx].script_pubkey.as_bytes();
    let mut script_sig = ScriptBuf::new();
    let mut witness = Witness::new();
    if let Some((replacement, solution)) = fetch_and_clear_commitment_section(commitment) {
        modified_cb.output[cidx].script_pubkey = ScriptBuf::from_bytes(replacement);
        let mut r = solution.as_slice();
        script_sig =
            ScriptBuf::consensus_decode(&mut r).map_err(|_| SignetError::MalformedSolution)?;
        witness = Witness::consensus_decode(&mut r).map_err(|_| SignetError::MalformedSolution)?;
        if !r.is_empty() {
            return Err(SignetError::MalformedSolution);
        }
    }
    // No solution is allowed by Core (for an OP_TRUE challenge); with ours it
    // simply fails the signature check below.

    let leaves = std::iter::once(modified_cb.compute_txid())
        .chain(block.txdata[1..].iter().map(Transaction::compute_txid));
    let signet_merkle =
        bitcoin::merkle_tree::calculate_root(leaves).expect("at least the coinbase");

    let mut block_data = Vec::with_capacity(72);
    block_data.extend(block.header.version.to_consensus().to_le_bytes());
    block_data.extend(block.header.prev_blockhash.to_byte_array());
    block_data.extend(signet_merkle.to_byte_array());
    block_data.extend(block.header.time.to_le_bytes());
    // `CScript(OP_0) << block_data`: 72 bytes is a direct push.
    let mut to_spend_sig = vec![0x00, block_data.len() as u8];
    to_spend_sig.extend(block_data);

    let to_spend = Transaction {
        version: Version(0),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(to_spend_sig),
            sequence: Sequence::ZERO,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(challenge.to_vec()),
        }],
    };
    let to_sign = Transaction {
        version: Version(0),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: to_spend.compute_txid(),
                vout: 0,
            },
            script_sig,
            sequence: Sequence::ZERO,
            witness,
        }],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(vec![OP_RETURN]),
        }],
    };
    Ok((to_spend, to_sign))
}

/// Core's `GetWitnessCommitmentIndex`: the last coinbase output that is at
/// least 38 bytes and starts `OP_RETURN 0x24 aa21a9ed`.
fn witness_commitment_index(coinbase: &Transaction) -> Option<usize> {
    coinbase.output.iter().rposition(|o| {
        let s = o.script_pubkey.as_bytes();
        s.len() >= 38 && s[..6] == [OP_RETURN, 0x24, 0xaa, 0x21, 0xa9, 0xed]
    })
}

/// One script operation as Core's `GetScriptOp` reads it: the opcode and,
/// for pushes, the data. `None` at the end or on a truncated push.
fn get_op(script: &[u8], pc: &mut usize) -> Option<(u8, Vec<u8>)> {
    let opcode = *script.get(*pc)?;
    *pc += 1;
    if opcode > OP_PUSHDATA4 {
        return Some((opcode, Vec::new()));
    }
    let len = match opcode {
        OP_PUSHDATA1 => {
            let b = script.get(*pc..*pc + 1)?;
            *pc += 1;
            usize::from(b[0])
        }
        OP_PUSHDATA2 => {
            let b = script.get(*pc..*pc + 2)?;
            *pc += 2;
            usize::from(u16::from_le_bytes([b[0], b[1]]))
        }
        OP_PUSHDATA4 => {
            let b = script.get(*pc..*pc + 4)?;
            *pc += 4;
            u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize
        }
        n => usize::from(n),
    };
    let data = script.get(*pc..pc.checked_add(len)?)?.to_vec();
    *pc += len;
    Some((opcode, data))
}

/// `CScript << data`: the shortest push opcode for the length, then the data.
fn push_data(out: &mut Vec<u8>, data: &[u8]) {
    let n = data.len();
    if n < usize::from(OP_PUSHDATA1) {
        out.push(n as u8);
    } else if n <= 0xff {
        out.extend([OP_PUSHDATA1, n as u8]);
    } else if n <= 0xffff {
        out.push(OP_PUSHDATA2);
        out.extend((n as u16).to_le_bytes());
    } else {
        out.push(OP_PUSHDATA4);
        out.extend((n as u32).to_le_bytes());
    }
    out.extend(data);
}

/// Core's `FetchAndClearCommitmentSection`. Returns the rebuilt script (the
/// solution cut off and every push re-encoded the way Core rebuilds it) and
/// the solution, or `None` if there is no solution. Like Core, a malformed
/// op ends the walk and anything after it is dropped from the rebuilt script.
fn fetch_and_clear_commitment_section(script: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut replacement = Vec::with_capacity(script.len());
    let mut solution = None;
    let mut pc = 0;
    while let Some((opcode, mut data)) = get_op(script, &mut pc) {
        if data.is_empty() {
            replacement.push(opcode);
            continue;
        }
        if solution.is_none()
            && data.len() > SIGNET_HEADER.len()
            && data.starts_with(&SIGNET_HEADER)
        {
            solution = Some(data.split_off(SIGNET_HEADER.len()));
        }
        push_data(&mut replacement, &data);
    }
    solution.map(|s| (replacement, s))
}

/// Run a scriptSig that may only push data, the way Core's interpreter
/// would, and return the stack. Non-push opcodes are refused as unsupported.
fn push_only_stack(script_sig: &Script) -> Result<Vec<Vec<u8>>, SignetError> {
    let bytes = script_sig.as_bytes();
    if bytes.len() > MAX_SCRIPT_SIZE {
        return Err(SignetError::BadSignature);
    }
    let mut stack = Vec::new();
    let mut pc = 0;
    while pc < bytes.len() {
        // A truncated push is a script error in Core (SCRIPT_ERR_BAD_OPCODE).
        let (opcode, data) = get_op(bytes, &mut pc).ok_or(SignetError::BadSignature)?;
        let item = match opcode {
            0..=OP_PUSHDATA4 => {
                if data.len() > MAX_SCRIPT_ELEMENT_SIZE {
                    return Err(SignetError::BadSignature);
                }
                data
            }
            OP_1NEGATE => vec![0x81],
            OP_1..=OP_16 => vec![opcode - OP_1 + 1],
            _ => return Err(SignetError::UnsupportedSolution),
        };
        stack.push(item);
        if stack.len() > MAX_STACK_SIZE {
            return Err(SignetError::BadSignature);
        }
    }
    Ok(stack)
}

/// `OP_1 <key1> <key2> OP_2 OP_CHECKMULTISIG` run on `stack`, with Core's
/// rules for these flags: the challenge pushes four items (so the stack must
/// stay within 1000); CHECKMULTISIG takes the signature from the top and
/// one extra "dummy" item below it, which NULLDUMMY says must be empty;
/// anything below the dummy is left alone (CLEANSTACK isn't a signet flag).
/// A non-empty signature must be strict DER (DERSIG); then the keys are
/// tried in Core's order, last pushed first, and one match is enough.
fn check_multisig_1_of_2(
    stack: &[Vec<u8>],
    to_sign: &Transaction,
    script_code: &Script,
    challenge: &[u8],
) -> bool {
    if stack.len() + 4 > MAX_STACK_SIZE || stack.len() < 2 {
        return false;
    }
    let sig = &stack[stack.len() - 1];
    let dummy = &stack[stack.len() - 2];
    if !dummy.is_empty() {
        return false;
    }
    if sig.is_empty() {
        // Allowed by DERSIG, but an empty signature never verifies.
        return false;
    }
    if !is_valid_signature_encoding(sig) {
        return false;
    }
    // The standard challenge: 0x51, 0x21 <33-byte key1>, 0x21 <33-byte key2>, 0x52, 0xae.
    let key1 = &challenge[2..35];
    let key2 = &challenge[36..69];
    [key2, key1]
        .iter()
        .any(|key| check_ecdsa(sig, key, to_sign, script_code))
}

/// Core's `CheckECDSASignature` for input 0 with legacy (pre-segwit)
/// signature hashing: the last byte is the sighash type, the rest is parsed
/// leniently and normalised to low S before verifying, as Core does.
fn check_ecdsa(sig: &[u8], key: &[u8], to_sign: &Transaction, script_code: &Script) -> bool {
    let Some((&hash_type, der)) = sig.split_last() else {
        return false;
    };
    let Ok(pubkey) = PublicKey::from_slice(key) else {
        return false;
    };
    let Ok(sighash) =
        SighashCache::new(to_sign).legacy_signature_hash(0, script_code, u32::from(hash_type))
    else {
        return false;
    };
    let Ok(mut signature) = ecdsa::Signature::from_der_lax(der) else {
        return false;
    };
    signature.normalize_s();
    let msg = Message::from_digest(sighash.to_byte_array());
    Secp256k1::verification_only()
        .verify_ecdsa(&msg, &signature, &pubkey)
        .is_ok()
}

/// BIP66 strict DER, including the trailing sighash byte (Core's
/// `IsValidSignatureEncoding`).
fn is_valid_signature_encoding(sig: &[u8]) -> bool {
    let n = sig.len();
    if !(9..=73).contains(&n) || sig[0] != 0x30 || usize::from(sig[1]) != n - 3 {
        return false;
    }
    let len_r = usize::from(sig[3]);
    if 5 + len_r >= n {
        return false;
    }
    let len_s = usize::from(sig[5 + len_r]);
    if len_r + len_s + 7 != n {
        return false;
    }
    if sig[2] != 0x02 || len_r == 0 || sig[4] & 0x80 != 0 {
        return false;
    }
    if len_r > 1 && sig[4] == 0x00 && sig[5] & 0x80 == 0 {
        return false;
    }
    if sig[len_r + 4] != 0x02 || len_s == 0 || sig[len_r + 6] & 0x80 != 0 {
        return false;
    }
    if len_s > 1 && sig[len_r + 6] == 0x00 && sig[len_r + 7] & 0x80 == 0 {
        return false;
    }
    true
}
