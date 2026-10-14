# Proof Builder RPC

## Build

Use the following command to build the project:

```
BITCOIN_NETWORK=testnet4 cargo build -r
```

## Deployment

Initial parameters are read from `proof-builder.toml` (see
[proof-builder.toml.example](./proof-builder.toml.example)). After that, they will be loaded from
the database.

Field descriptions for the configuration are available in the circuits documentation: [circuits README](../circuits/README.md).

The four Operator/Watchtower task endpoints require signed requests and live GOAT contract
authorization. Configure the read-only GOAT connection before startup:

```dotenv
GOAT_NETWORK=test
GOAT_CHAIN_URL=https://rpc.testnet3.goat.network
GOAT_GATEWAY_CONTRACT_ADDRESS=<gateway-address-1>,<gateway-address-2>
```

Proof Builder accepts one or more comma-separated Gateway addresses. All configured Gateways use
the same GOAT network and RPC. It discovers the CommitteeManagement contract through each Gateway
and exits if any configured contract set cannot be initialized. Operator requests require graph
ownership and a matching instance/graph relation. Operator registration and stake are enforced
when graphs are admitted and are not rechecked for existing proof tasks.
Watchtower requests require membership in the current global Watchtower registry and the request
public key must match the authenticated signer. Contract authorization is queried for every
request; failures return HTTP 503 rather than falling back to stale authorization data.

Each authenticated request selects a configured deployment with the signed `gateway_address`
field. For staged upgrades, the field may be omitted while Proof Builder has exactly one Gateway;
it is required when multiple Gateways are configured. Nodes continue to use one
`GOAT_GATEWAY_CONTRACT_ADDRESS` value and add it to every Operator/Watchtower proof request.

Nodes sign requests with their existing `BITVM_SECRET`; no GOAT or Bitcoin private key is
configured on the Proof Builder. Deploy signing-capable nodes before enabling the authenticated
Proof Builder so that in-flight proof polling is not rejected.

Authenticated requests carry `x-proof-auth-timestamp`, `x-proof-auth-nonce`,
`x-proof-auth-public-key`, and `x-proof-auth-signature`. The signature binds the caller role,
HTTP method, route, timestamp, nonce, and canonical JSON body. Rust callers should use
`proof_builder::api_auth::sign_proof_builder_request`; each retry must generate a new nonce.

To enable multiple Gateways without interrupting proof polling, first upgrade Proof Builder with a
single Gateway, then upgrade all Nodes to send `gateway_address`, and finally configure the
comma-separated Gateway list.

## Fleet app worker mode

Proof Builder can run as a zkm-fleet integrated app worker. Fleet starts a dedicated Ziren GPU
server for the app and launches `proof-builder-rpc` beside it. The
worker proves directly against that loopback server instead of submitting through the SDK
network prover and the Fleet gateway. The HTTP API and node configuration are unchanged.

Fleet mode starts when Fleet supplies its worker environment. Any partial Fleet environment is a
startup error. Without these variables the SDK network prover (`ZKM_PROVER=network`) is used as
before, which is how operators fall back explicitly.

| Variable | Source | Meaning |
|---|---|---|
| `FLEET_GPU_ENDPOINT` | Fleet | Loopback URL of the replica's GPU server |
| `FLEET_APP_STORAGE_ROOT` | Fleet | Durable app storage (`proof_storage_root`) |
| `FLEET_APP_ELF_ID` | Fleet | App id: the SHA-256 of the program bundle manifest |
| `FLEET_APP_NAMESPACE`, `FLEET_APP_TENANT` | Fleet | App identity |
| `FLEET_EXIT_WITH_PARENT` | Fleet | Exit with the Fleet actor (Linux `PR_SET_PDEATHSIG`) |
| `PROOF_BUILDER_PROGRAMS_FILE` | worker env file | `programs.json` from the package |

The app id covers all five guests. Each line is `<name> <ELF SHA-256>`, sorted by name
(commit-chain, header-chain, operator, state-chain, watchtower), and the id is the SHA-256 of
those lines. `proof-builder-rpc --print-programs` sets every program up on the CPU prover and
prints the ELF digests, program IDs, verifying-key hashes, wrap mode and app id as JSON; package
that output as `programs.json`. At startup the worker checks that the embedded programs, the
programs file and `ZKM_IMM_WRAP_VK` match the Fleet app id. After each GPU setup it also checks
the verifying key.

Startup also requires the following:

- The working directory (`worker_workdir`) and the sqlite database must be inside the storage
  root, and the worker takes an exclusive lock on `<root>/proof-builder.lock`.
- Use `<root>/run` as the working directory so that relative `../circuits/data/...` paths
  resolve to `<root>/circuits/data/...`.
- Groth16 wrapping runs on the worker's CPU. Pre-install the Groth16 circuit artifacts for the
  Fleet execution user before enabling the app.

Proving behaviour in Fleet mode:

- The GPU server runs one proof at a time. Builder setup and every proving unit (prove, publish
  and database commit) pass through a FIFO gate.
- An operator or watchtower task stays `New` while it queues and proves. Its result is written
  only while it is still `New`, so a timeout request that arrives in the meantime wins.
- If the GPU server stops reporting ready, or a proof cannot be published, the task stays
  pending and the worker exits. Fleet then restarts the GPU server and the worker.
- Otherwise a failed prover call is replayed by executing its guest on the CPU. GPU RPC
  errors do not distinguish transport failures from rejected inputs. If the guest executes,
  the prover or its transport failed; the proof is retried in place and the failure does not
  count as an attempt.
- A proof that fails because the guest rejects its input, or because the result does not
  verify, marks the task `Failed` after `--max-proof-attempts` consecutive failures
  (default 2).
- On SIGTERM or a task failure the worker starts no new proof. It waits up to
  `--drain-timeout-secs` for the proof in progress to be published and committed, then exits.
  A proof still running at the timeout does not delay the exit; it is retried after restart.
  Keep that value below the service's `worker_stop_timeout_s`. Exit codes: 0 after a clean stop,
  1 after a task failure or an abandoned proof, 101 after a panic.
- Proofs and their sidecars are published through synced temporary files and atomic renames.
  A `<proof>.manifest.json` written last marks a complete set. State-chain `.args`/`.ctx`
  snapshots are written atomically as well.
- The state-chain context builder prepares at most `--state-chain-max-pending-batches`
  unproved batches (default 2; 0 means unlimited).

Before migrating data into a storage root, and before every Fleet enable, run the read-only
storage check from the working directory with the worker's config and `DATABASE_URL`:

```bash
proof-builder-rpc --config proof-builder.toml --check-storage /srv/zkm-fleet/apps/goat
```

It reports every recorded proof, config path and pending state-chain snapshot that is missing,
outside the root, or inconsistent with its manifest. It exits non-zero on any error. Proofs
written before atomic publication are reported as `legacy`.

## Metrics

Prometheus metrics use a dedicated listener and are disabled unless `--metrics-addr` is set. The
business RPC listener does not serve metrics, so `GET /metrics` on `--rpc-addr` returns `404`.

```bash
proof-builder-rpc \
  --rpc-addr 0.0.0.0:7777 \
  --metrics-addr 10.42.0.8:9109 \
  --config proof-builder.toml
```

The dedicated listener serves only `/metrics`. Bind it to a private interface and allow only the
Prometheus source network to reach it. The listener does not provide TLS or authentication and
should not be exposed directly to the public internet. An unavailable metrics port causes startup
to fail.

## Failure recovery

Long-running proof tasks (stored in the `long_running_task_proof` table) — such as header-chain, commit-chain, and state-chain proofs — can be recovered from the database. Recovery notes:

- **Header Chain**: A newly confirmed block (>=1) must wait for the configured number of confirmations before being included in a proof. If the confirmation count is insufficient, delete the corresponding entries from the `long_running_task_proof` table; proof generation will resume from the database state.

- **Commit Chain**: The `sequencer-set-publish` process is manual. When a new publish is required, run the publication script with the appropriate `GOAT_BLOCK_NUMBER` to create a sequencer-set commitment. Example invocation:

```bash
GOAT_BLOCK_NUMBER=${THE_GOAT_BLOCK_NUMBER} bash -x scp.sh
```

Example `scp.sh` used for Regtest integration tests, remember to set the `OPERATOR_VK_HASH` environment variable before running:

```bash
#!/bin/bash
set -e
source .env

DIR="$( cd "$( dirname "$0" )" && pwd )"

if [ -f $OUTPUT_FILE ]; then
    cp $OUTPUT_FILE ${OUTPUT_FILE}.bk 
fi 

cargo build -r --bin sequencer-set-publish
export RUST_LOG=info
CMD="../target/release/sequencer-set-publish"

echo "Recovering publisher set: next_publishers => publishers"
$CMD payfee --total 3

$CMD sign-seq --owner-btc-key-wif $PUBLISHER1 --goat-block-number $GOAT_BLOCK_NUMBER \ --next-publisher-btc-pubkeys=$PUBLISHER_BTC_PUBKEYS --publisher-btc-pubkeys=$NEXT_PUBLISHER_BTC_PUBKEYS 
$CMD sign-seq --owner-btc-key-wif $PUBLISHER2 --goat-block-number $GOAT_BLOCK_NUMBER \ --next-publisher-btc-pubkeys=$PUBLISHER_BTC_PUBKEYS --publisher-btc-pubkeys=$NEXT_PUBLISHER_BTC_PUBKEYS 
$CMD sign-seq --owner-btc-key-wif $PUBLISHER3 --goat-block-number $GOAT_BLOCK_NUMBER \ --next-publisher-btc-pubkeys=$PUBLISHER_BTC_PUBKEYS --publisher-btc-pubkeys=$NEXT_PUBLISHER_BTC_PUBKEYS 

# broadcast publisher changes to Bitcoin
$CMD push-seq --goat-block-number $GOAT_BLOCK_NUMBER --next-publisher-btc-pubkeys=$PUBLISHER_BTC_PUBKEYS --publisher-btc-pubkeys=$NEXT_PUBLISHER_BTC_PUBKEYS  --commit-info="${DIR}/../circuits/data/commit-chain/commit_info.json.latest"
```

- **State Chain**: For sequencer-set genesis commitments or when re-anchoring the state chain, modify the latest record of state chain in `long_running_task_proof` with `block_end = 0` and `proof_state = 'Failed'` to trigger recovery handling.
