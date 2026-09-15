Run a BitVM Operator node locally.

The Operator manages bridge operations, kickoff processing, and pegout (Gateway.initWithdraw).

## Instructions

1. Ask the user for the following parameters (skip any already provided as arguments: $ARGUMENTS):
   - **network**: Which network? `testnet4` or `regtest`
   - **rpc_addr**: RPC listen address. Default: `127.0.0.1:8902`
   - **metrics_addr**: Prometheus listen address. Default: `127.0.0.1:9903`
   - **p2p_port**: P2P listen port. Default: `8445` (testnet4) or `8446` (regtest)
   - **db_path**: SQLite database path. Default: `sqlite:$PWD/bitvm-node.db`

2. Ensure the `.env` file exists in the working directory. Template configs are at:
   - **testnet4**: `deployment/testnet4/bitvm-noded/operator_0/.env.operator_0`
   - **regtest**: `deployment/regtest/bitvm-noded/operator_0/.env.operator_0`

   The user **must** fill in these required secrets:
   - `BITVM_SECRET` - Operator BTC private key (hex)
   - `GOAT_ADDRESS` - Operator's EVM address
   - `PEER_KEY` - libp2p private key for node identity

   For pegout operations, the node also needs:
   - `GOAT_PRIVATE_KEY` - Operator's GoatNetwork private key (for signing initWithdraw)

   Copy the template if needed:
   ```bash
   cp deployment/<network>/bitvm-noded/operator_0/.env.operator_0 .env
   ```

3. Check if the `bitvm-noded` binary exists at `./bin/bitvm-noded`. If not, run:
   ```bash
   .claude/commands/install-bitvm.sh install
   ```

4. Start the operator node:

```bash
./bin/bitvm-noded --rpc-addr <rpc_addr> --metrics-addr <metrics_addr> --db-path <db_path> --p2p-port <p2p_port> --bootnodes "$BOOTNODES"
```

To run in the background:
```bash
nohup ./bin/bitvm-noded --rpc-addr <rpc_addr> --metrics-addr <metrics_addr> --db-path <db_path> --p2p-port <p2p_port> --bootnodes "$BOOTNODES" >operator_$(date +'%Y%m%d').log 2>&1 &
```

5. Verify the node is running:
```bash
curl -s http://<rpc_addr>/
curl -s http://<metrics_addr>/metrics
```
The first request should return `Hello, World!`; the second should return
Prometheus metrics in OpenMetrics text format.

### Example (testnet4)

```bash
cp deployment/testnet4/bitvm-noded/operator_0/.env.operator_0 .env
# Edit .env to fill in BITVM_SECRET, GOAT_ADDRESS, PEER_KEY, GOAT_PRIVATE_KEY
./bin/bitvm-noded --rpc-addr 127.0.0.1:8902 --metrics-addr 127.0.0.1:9903 --db-path sqlite:$PWD/bitvm-node.db --p2p-port 8445 --bootnodes /ip4/34.215.238.232/tcp/8445/p2p/12D3KooWCrPTAmhFdC5DBGgkxZvJi6iuSeiDWKRL87isrt4iMHXv
```

For full deployment documentation, see `deployment/README.md` (section **Operator**).
