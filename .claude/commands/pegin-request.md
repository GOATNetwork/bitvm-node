Send a pegin request to GoatChain via the `pegin-request` binary.

## Instructions

1. Ask the user for the following parameters (skip any already provided as arguments: $ARGUMENTS):
   - **subcommand**: Which action to perform? One of:
     - `request` - Post a pegin request to GoatChain
     - `prepare` - Build, sign and broadcast the pegin deposit tx on Bitcoin
     - `request-prepare` - Request then auto-prepare after waiting ~12 minutes
     - `cancel` - Build, sign and broadcast the pegin refund tx on Bitcoin
   - **network**: Bitcoin network (`bitcoin`, `testnet4`, `signet`, `regtest`). Default: `BITCOIN_NETWORK`, or `testnet4`. Must match `BITCOIN_NETWORK` when both are set
   - **esplora_url**: Esplora API URL. Default: `https://mempool.space/testnet4/api`
   - For `request` / `request-prepare`:
     - **pegin_amount_sats**: Amount in satoshis. Default: `1000000` (0.01 BTC)
     - **instance_id**: Optional UUID (auto-generated if omitted)
     - **fee_rate**: Optional fee rate in sat/vbyte (fetched from API if omitted)
     - **receiver_evm_address**: Optional EVM address (read from `GOAT_ADDRESS` env if omitted)
   - For `prepare` / `cancel`:
     - **instance_id**: Required UUID from a previous request

2. Ensure the `.env` file (in `node/` directory) has the required environment variables:
   - `BITVM_SECRET` - Node BTC private key (hex or `seed:...`)
   - `GOAT_PRIVATE_KEY` - Node GoatNetwork private key
   - `BITCOIN_NETWORK` - Bitcoin network name
   - `GOAT_CHAIN_URL` - GoatNetwork RPC URL
   - `GOAT_GATEWAY_CONTRACT_ADDRESS` - Gateway contract address

3. Check if the `pegin-request` binary exists at `./bin/pegin-request`. If not, run the install script to download it:
   ```bash
   .claude/commands/install-bitvm.sh install
   ```
   To upgrade to the latest version:
   ```bash
   .claude/commands/install-bitvm.sh upgrade
   ```
   The script auto-detects the platform (x86_64-linux / aarch64-macos), downloads from GitHub Releases, verifies the sha256 checksum, and installs all binaries to `./bin/`.

4. Run the command using the pre-built binary:

```bash
./bin/pegin-request <subcommand> [options]
```

### Example commands

Request:
```bash
./bin/pegin-request --network testnet4 --esplora-url https://mempool.space/testnet4/api request --pegin-amount-sats 1000000
```

Prepare (after request):
```bash
./bin/pegin-request --network testnet4 prepare --instance-id <UUID>
```

Request + auto-prepare:
```bash
./bin/pegin-request --network testnet4 request-prepare --pegin-amount-sats 1000000 --wait-minutes 12
```

Cancel:
```bash
./bin/pegin-request --network testnet4 cancel --instance-id <UUID>
```
