Broadcast a Challenge transaction for a graph via the `challenge` binary.

The challenge binary calls the node's REST API, so a **Verifier node** built with the `rpc-debug-endpoints` feature must be running and reachable. Release binaries are built without that feature: they serve no challenge endpoint and ship no `challenge` binary.

## Prerequisites — Running a Verifier Node

Before using this command, ensure a Verifier role node (`ACTOR=Verifier`) built with `rpc-debug-endpoints` is running.

Use the `/run-challenger-node` skill to start one, or see `deployment/README.md` for full details.

## Instructions

1. Ask the user for the following parameters (skip any already provided as arguments: $ARGUMENTS):
   - **graph_id**: Required. Graph UUID to challenge
   - **rpc_url**: Node API base URL. Default: `http://localhost:8080`

2. **Check that `BITVM_SECRET` is set** in the current shell environment. The binary uses this key to sign the request — it must match the secret configured on the target node.
   ```bash
   echo "BITVM_SECRET is ${BITVM_SECRET:+set}"
   ```
   If it is not set, ask the user to export it before continuing.

3. Confirm that the Verifier node is running and reachable at the given `rpc_url`. If the user hasn't started a node yet, walk them through the `/run-challenger-node` skill.

4. **Verify the graph is synced** on the local Verifier node. The node syncs graph data via P2P from other nodes, so the target graph must exist locally before a challenge can be sent. Check by calling:
   ```bash
   curl -s <rpc_url>/v1/graphs/<graph_id> | jq .
   ```
   - If the response contains a non-null `"graph"` field, the graph is synced and ready.
   - If `"graph"` is null or the request fails, the node has not yet synced this graph. Ask the user to wait for P2P sync to complete and retry. The node must be connected to the network (correct `BOOTNODES`, `PROTO_NAME`) and the graph must exist on peer nodes.

5. Check if the `challenge` binary exists at `./bin/challenge`. If not, build it, and the node it talks to, from source with the debug endpoints:
   ```bash
   source ~/.zkm-toolchain/env
   cargo build -r -p bitvm-noded --features rpc-debug-endpoints --bin challenge --bin bitvm-noded
   mkdir -p bin && cp target/release/challenge target/release/bitvm-noded bin/
   ```

6. Run the command using the pre-built binary:

```bash
./bin/challenge --graph-id <UUID> [--rpc-url <URL>]
```

### Example commands

```bash
# Default API URL (http://localhost:8080)
./bin/challenge --graph-id 6ba7b810-9dad-11d1-80b4-00c04fd430c8

# Custom API URL (e.g. Verifier node on port 8906)
./bin/challenge --graph-id 6ba7b810-9dad-11d1-80b4-00c04fd430c8 --rpc-url http://127.0.0.1:8906
```
