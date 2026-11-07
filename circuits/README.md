# BitVM Circuits

## Overview

The initial trust anchor is a GOAT snapshot containing the sequencer set and EVM block hash.
For Bitcoin transaction wiring and signature types, see the [transaction graph](../transaction-graph.svg).

Main components:

* BTC Header Chain: the bitcoin header chain
* Commit Chain: the sequencer set commitment, where each commitment creates a block
* State Chain: the EVM state transition, each block contains a EVM block, the withdrawals and a cosmos light block

Circuits:

* Watchtower proof(latest_sequencer_commit_txid, genesis_sequencer_commit_txid, header_chain_proof, commit_chain_proof, state_chain_proof, SPV)

> * Constraints:
>>
>> * The latest_sequencer_commit_txid is included in the header chain proof
>> * The latest_sequencer_commit_txid is the latest commit txn in the commit chain
>> * The state chain's latest block(EVM block) is signed by the sequencer set in the latest block of commit chain
>>
> * Outputs: total_work, the bitcoin block height that includes the latest sequencer set commitment

* Operator proof:

> * Constraints:

>> * The latest_sequencer_commit_txid is included in the header chain proof
>> * The latest_sequencer_commit_txid is the latest commit txn in the commit chain
>> * The state chain's latest block(EVM block) is signed by the sequencer set in the latest block of commit chain
>> * For each included Watchtower proof,

>>> * The watchtower challenge transaction is valid
>>> * The proof is valid
>>> * The graph is as same as the operator's graph id
>>> * For claims from the same genesis, the operator's total work is at least the Watchtower's
>>> * The operator's commitment inclusion height is at least the watchtower's for a claim from the same genesis

>> * Verify that the withdrawal state change in the Gateway contract is correct

> * Outputs: latest block hash of the header chain, hash(graph_id, operator's genesis sequencer commit transaction id, included_watchtowers)

## Circuit Upgrade

Given that the interval between Peg-in and Peg-out may extend over several months, two types of upgrades require separate consideration:

1. Proof system upgrades (Ziren): Result in a different recursion verification key.  

2. Modifications of guest program: Arise from protocol changes in Bitcoin, Cosmos, or Geth, result in different ELF and guest verification key.

For case 1, Ziren's proof network can keep multiple recursion verification keys, and load the correct key with respect to the version in the proof.

For case 2,

> * If there is no Ziren upgrade during this interval, and the inputs of the proof aggregation are compressed proofs, but with different `start_pc`, `pc`, etc.
> * If there is some Ziren upgrades during this interval, once we support the multiple verification keys in Ziren, this problem can be reduced to the former one.

With multiple proof recursions, we generate a Groth16 proof, and verify with `Groth16Verifier::verify_by_imm_groth16_vk(proof, zkm_public_values, zkm_vk_hash, groth16_vk, part_stark_vk)`.

Ziren 2.0 (circuit version `v2.0.0`) changed the wrap circuit itself: its public inputs are
`[vkey_hash, committed_values_digest, vk_root]`, where `vk_root` is the root of the recursion verifying-key
allowlist, so the immutable Groth16 vk differs from the 1.2.x one. A 1.2.x Groth16 proof does not verify
under 2.0, so the header, commit and state chain proofs restart from genesis at the 2.0 cut-over. The
BABE garbled-circuit verifier treats `vkey_hash` and `vk_root` as static inputs and `committed_values_digest`
as the dynamic one.

## Build inputs

Build all five guest programs with the same `BITCOIN_NETWORK` and
`ZKM_IMM_WRAP_VK` settings used by the nodes and Proof Builder. Program or proof
system changes require matching verification keys and proof artifacts.

## Preparation

Run the proof examples from `circuits/`. The host binaries load `.env` there;
export the same configuration before running the helper scripts.

```bash
mkdir -p data/header-chain
mkdir -p data/commit-chain
mkdir -p data/state-chain
mkdir -p data/watchtower
mkdir -p data/operator
```

if `Network Prover` is used, see [this](https://docs.zkm.io/dev/prover.html#network-prover) for more details.

Launch the Regtest.

```bash
(cd ../scripts && docker compose up -d)
```

## Bitcoin Header Chain

```
# regtest 
# export BITCOIN_NETWORK=regtest

# testnet
# export BITCOIN_NETWORK=testnet4
# export ESPLORA_URL=https://mempool.space/testnet4/api


bash cron-header-chain-proof.sh $start $batch
```

## Sequencer Set Commit Chain

* Publish sequencer set commitment with correct envs `BITCOIN_NETWORK` and `ESPLORA_URL`.

Example:

```bash
cd ../node
GOAT_BLOCK_NUMBER=9511050 bash -x ssp-ci.sh
cd ../circuits
```

This publication script is a Regtest fixture with hardcoded publishers. In the `ssp-ci.sh`, we simulate 2-round publisher rotations.
`GOAT_BLOCK_NUMBER` is the GOAT's current block number, which is used as the key to fetch sequencer set commitment.

Deploy the SequencerSetPublisher contract before publishing the sequencer set.

Then setup the correct contract address in your `.env`.

```
GOAT_SEQUENCER_SET_PUBLISHER_CONTRACT_ADDRESS=0x...
ENV_GOAT_SEQUENCER_SET_MULTI_SIG_VERIFIER_ADDRESS=0x...
```

After publishing, a `commit_info.json` of format as below will be generated.

```
[
  {
    "txid": "dcadccc909994689e9f3a36c9d349e89f0cb96764f6d8f4d9632e0f76b0ec84e",
    "threshold": 4,
    "publisher_public_keys": [
      "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
      "024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766",
      "02531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337",
      "03462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b",
      "0362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f7"
    ],
    "sequencers": [...]
  }
]
```

* txid: the publisher's commitment transaction of Cosmos sequencer set.
* threshold: the number of publisher's signature
* publisher_public_keys: the publisher's compressed public keys
* sequencers: sequencer's public keys, obtained from cosmos's `/validators`.

Generate the proof:

```
# Genesis
RUST_LOG=info cargo run --package commit-chain-proof --bin commit-chain-proof -r -- --init-input --output-proof "data/commit-chain/0-1.bin" --commit-info ./data/commit-chain/commit_info.json.0 --commits data/commit-chain/0-1.bin.commits

# Regular proof
RUST_LOG=info cargo run --package commit-chain-proof --bin commit-chain-proof -r -- --input-proof "data/commit-chain/0-1.bin" --output-proof "data/commit-chain/1-1.bin" --commit-info ./data/commit-chain/commit_info.json.1 --commits data/commit-chain/1-1.bin.commits

RUST_LOG=info cargo run --package commit-chain-proof --bin commit-chain-proof -r -- --input-proof "data/commit-chain/1-1.bin" --output-proof "data/commit-chain/2-1.bin" --commit-info ./data/commit-chain/commit_info.json.2 --commits data/commit-chain/2-1.bin.commits
```

## State Chain

State Chain represents the L2's state transition, which checks the EVM's execution, withdrawal transaction inclusion and sequencers' agreement.

We generate `state-chain-proof` periodically, like by 5 GOAT EVM blocks. Optionally, the block may contain a `proceedWithdraw` transaction.

* Submit the `proceedWithdraw` transaction on GOAT Network.
* Generate state-chain proof.

```
export BATCH_SIZE=10
export L2_CONTRACT_ADDRESSES="$GOAT_GATEWAY_CONTRACT_ADDRESS"

export EL_START_BLOCK_NUMBER=10346748
export start=$EL_START_BLOCK_NUMBER
bash cron-state-chain-proof.sh $start $BATCH_SIZE
```

## Watchtower proof

When a challenge occurs, each Watchtower can publish a `watchtower-challenge-tx`
containing its proof commitment.

* Generate proofs

```
export BITCOIN_NETWORK=regtest
export GENESIS_SEQUENCER_COMMIT_TXID=$(cat ./data/commit-chain/commit_info.json.0 | jq -r .genesis_txid)
export LATEST_SEQUENCER_COMMIT_TXID=$(cat ./data/commit-chain/commit_info.json.0 | jq -r .txid)
export HEADER_CHAIN_INPUT_PROOF="data/header-chain/0-116000.bin"
export COMMIT_CHAIN_INPUT_PROOF="data/commit-chain/0-1.bin"
export STATE_CHAIN_INPUT_PROOF="data/state-chain/9511050-10.bin"

RUST_LOG=info cargo run --package watchtower-proof --bin watchtower-proof -r -- --output "data/watchtower/output.bin"

export LATEST_SEQUENCER_COMMIT_TXID=$(cat ./data/commit-chain/commit_info.json.1 | jq -r .txid)
export COMMIT_CHAIN_INPUT_PROOF="data/commit-chain/1-1.bin"
RUST_LOG=info cargo run --package watchtower-proof --bin watchtower-proof -r -- --output "data/watchtower/output2.bin"

export LATEST_SEQUENCER_COMMIT_TXID=$(cat ./data/commit-chain/commit_info.json.2 | jq -r .txid)
export COMMIT_CHAIN_INPUT_PROOF="data/commit-chain/2-1.bin"
RUST_LOG=info cargo run --package watchtower-proof --bin watchtower-proof -r -- --output "data/watchtower/output3.bin"
```

* latest-sequencer-commit-txid: the latest publisher's commitment Bitcoin transaction id
* header-chain-input-proof: the header chain's proof, input and vk.
* commit-chain-input-proof: the commit chain's proof, input and vk.

## Operator proof

* Simulate a withdraw challenge

```bash
(cd .. && cargo test -r -p bitvm-gc --test regtest regtest_take2_flow -- --ignored)
```

Fund the Operator on Regtest and obtain the graph ID, Watchtower-Challenge-Init
transaction ID, and indexed Watchtower transactions and public keys from that run.

* Generate proofs

After `proceedWithdraw`, generate the Operator proof for the corresponding graph
and withdrawal block. Use values from the same graph and proof-chain history.

```bash
export BITCOIN_NETWORK=regtest
export HEADER_CHAIN_INPUT_PROOF="data/header-chain/header.bin"
export COMMIT_CHAIN_INPUT_PROOF="data/commit-chain/commit.bin"
export STATE_CHAIN_INPUT_PROOF="data/state-chain/state.bin"

export GENESIS_SEQUENCER_COMMIT_TXID="${GENESIS_SEQUENCER_COMMIT_TXID:?Set the genesis commitment transaction ID}"
export LATEST_SEQUENCER_COMMIT_TXID="${LATEST_SEQUENCER_COMMIT_TXID:?Set the latest commitment transaction ID}"
export OPERATOR_COMMITTED_BLOCKHASH="${OPERATOR_COMMITTED_BLOCKHASH:?Set the committed Bitcoin block hash}"
export GRAPH_ID="${GRAPH_ID:?Set the graph ID as 32 hexadecimal characters}"
export EXECUTION_LAYER_BLOCK_NUMBER="${EXECUTION_LAYER_BLOCK_NUMBER:?Set the withdrawal block height}"
export INCLUDED_WATCHTOWERS="${INCLUDED_WATCHTOWERS:?Set the Watchtower inclusion bitmask}"
export WATCHTOWER_PUBLIC_KEYS="${WATCHTOWER_PUBLIC_KEYS:?Set the indexed public-key list}"
export WATCHTOWER_CHALLENGE_TXIDS="${WATCHTOWER_CHALLENGE_TXIDS:?Set the indexed transaction-ID list}"
export WATCHTOWER_CHALLENGE_INIT_TXID="${WATCHTOWER_CHALLENGE_INIT_TXID:?Set the challenge-init transaction ID}"

RUST_LOG=info cargo run --package operator-proof --bin operator-proof -r -- --output "data/operator/output.bin"
```

The operator proof is consumed directly by the Assert flow. BABE setup binds its static public
input, while the dynamic public input is committed after the watchtower challenge set is known.

* latest-sequencer-commit-txid: the latest publisher's commitment Bitcoin transaction id
* header-chain-input-proof: the header chain's proof, input and vk.
* commit-chain-input-proof: the commit chain's proof, input and vk.
* included-watchtower: a 256-bit bitmask; each bit flags a valid watchtower inside operator proof.
* execution-layer-block-number: the block number that including `proceedWithdraw`(Peg-out) transaction of GOAT Network's execution layer(Geth).
* watchtower-challenge-txids and watchtower-public-keys: comma-separated lists in graph slot order. The inclusion bitmask uses the same indices.
* watchtower-challenge-init-txid: the watchtower challenge init transaction id in GOAT's BitVM graph.
