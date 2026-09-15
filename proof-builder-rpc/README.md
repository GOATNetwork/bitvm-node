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
