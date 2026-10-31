#!/usr/bin/env bash
# =============================================================================
# deploy-local.sh -- deploy + configure the BitVM2 L2 contracts on the localnet anvil.
#
# Each run deploys a FRESH stack with one forge script (script/DeployLocal.sol, run inside the
# foundry container by tools/forge.sh): MockWGBTC, MockBitcoinSPV, GatewayLocal impl+proxy, PegBTC,
# CommitteeManagement impl+proxy, StakeManagement impl+proxy, then every registration the five
# node roles need, then writes $LOCALNET_DATA/state/contracts.json. Meant for a FRESH anvil, but a
# re-run on a live one simply deploys a second, independent stack (nonces never clash).
#
# Reads identities from state/keys.env. Faucet = anvil dev account 0 (gas only).
# Env overrides: RPC, OUT_FILE (dry-run target), STAKE_AMOUNT_WEI, LOCK_AMOUNT_WEI, GAS_TOPUP_ETHER,
#                VERIFIER_NONCE, RESPONSE_WINDOW_BLOCKS
# =============================================================================
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
source "$ROOT/scripts/localnet.env"

RPC=${RPC:-$GOAT_CHAIN_URL}
STAKE_AMOUNT_WEI=${STAKE_AMOUNT_WEI:-100000000000000000}   # 0.1 WGBTC (min on-chain stake is 0.06)
LOCK_AMOUNT_WEI=${LOCK_AMOUNT_WEI:-100000000000000000}     # lock the whole stake
GAS_TOPUP_ETHER=${GAS_TOPUP_ETHER:-100}
VERIFIER_NONCE=${VERIFIER_NONCE:-1}
FORGE_DIR="$LOCALNET_DATA/forge"

mkdir -p "$LOGS_DIR" "$STATE_DIR" "$FORGE_DIR"

log(){ echo "[$(date +%H:%M:%S)] $*"; }
die(){ echo "ERROR: $*" >&2; exit 1; }
cast(){ "$CAST" "$@"; }

[ -f "$STATE_DIR/keys.env" ] || die "missing $STATE_DIR/keys.env (run tools/gen-keys.sh first)"
set -a; source "$STATE_DIR/keys.env"; set +a

CID=$(cast chain-id --rpc-url "$RPC") || die "cannot reach anvil at $RPC"
[ "$CID" = "$ANVIL_CHAIN_ID" ] || die "anvil chain id is $CID, expected ANVIL_CHAIN_ID=$ANVIL_CHAIN_ID"
log "anvil chain id $CID, block $(cast block-number --rpc-url "$RPC")"

# -----------------------------------------------------------------------------
# 1. Fund every GOAT (EVM) address with gas from the faucet (idempotent)
# -----------------------------------------------------------------------------
fund_gas(){ # $1 = address
  local addr=$1 bal; bal=$(cast balance "$addr" --rpc-url "$RPC")
  if [ "$(python3 -c "print(1 if int('$bal') < 50000000000000000000 else 0)")" = "1" ]; then
    cast send "$addr" --value "${GAS_TOPUP_ETHER}ether" --private-key "$ANVIL_FAUCET_KEY" --rpc-url "$RPC" >/dev/null
    log "funded $addr with ${GAS_TOPUP_ETHER} ETH gas"
  else
    log "gas ok for $addr"
  fi
}
log "== funding GOAT addresses with gas =="
for A in "$DEPLOYER_GOAT_ADDRESS" "$C0_GOAT_ADDRESS" "$C1_GOAT_ADDRESS" "$OP0_GOAT_ADDRESS" \
         "$VF0_GOAT_ADDRESS" "$WT0_GOAT_ADDRESS" "$USER0_GOAT_ADDRESS"; do
  fund_gas "$A"
done

# -----------------------------------------------------------------------------
# 2. Deploy the whole stack (mocks + GatewayLocal + CommitteeManagement + StakeManagement)
# -----------------------------------------------------------------------------
PRE_DEPLOY_BLOCK=$(cast block-number --rpc-url "$RPC")
log "== forge script DeployLocal (container) =="
DEPLOY_LOG=$LOGS_DIR/deploy-stack.log
PRIVATE_KEY=$DEPLOYER_GOAT_PRIVATE_KEY \
COMMITTEE_0=$C0_GOAT_ADDRESS \
COMMITTEE_1=$C1_GOAT_ADDRESS \
WATCHTOWER_0=$WT0_BTC_PUBKEY_XONLY_0X \
  "$FORGE" script contracts-local/script/DeployLocal.sol:DeployLocal --rpc-url "$RPC" --broadcast --slow -vvv >"$DEPLOY_LOG" 2>&1 \
  || { tail -40 "$DEPLOY_LOG"; die "forge script deploy failed (log: $DEPLOY_LOG)"; }

grep_addr(){ grep -F "$1" "$DEPLOY_LOG" | tail -1 | grep -oE '0x[0-9a-fA-F]{40}' | tail -1; }
WGBTC=$(grep_addr "MockWGBTC contract address:")
SPV=$(grep_addr "MockBitcoinSPV contract address:")
GATEWAY_IMPL=$(grep_addr "Gateway implementation contract address:")
GATEWAY=$(grep_addr "Gateway proxy contract address:")
PEGBTC=$(grep_addr "PegBTC contract address:")
COMMITTEE_IMPL=$(grep_addr "CommitteeManagement implementation contract address:")
COMMITTEE=$(grep_addr "CommitteeManagement proxy contract address:")
STAKE_IMPL=$(grep_addr "StakeManagement implementation contract address:")
STAKE=$(grep_addr "StakeManagement proxy contract address:")
for v in WGBTC SPV GATEWAY_IMPL GATEWAY PEGBTC COMMITTEE_IMPL COMMITTEE STAKE_IMPL STAKE; do
  [ -n "${!v}" ] || { tail -60 "$DEPLOY_LOG"; die "could not parse $v from deploy log"; }
done
log "MockWGBTC                = $WGBTC"
log "MockBitcoinSPV           = $SPV (initialHeight=0, openPosting=true)"
log "GatewayLocal impl        = $GATEWAY_IMPL"
log "Gateway proxy            = $GATEWAY"
log "PegBTC                   = $PEGBTC"
log "CommitteeMgmt impl       = $COMMITTEE_IMPL"
log "CommitteeManagement proxy= $COMMITTEE"
log "StakeMgmt impl           = $STAKE_IMPL"
log "StakeManagement proxy    = $STAKE"

# Cross-check the gateway is fully wired (these are the exact getters the node calls at startup).
GW_CM=$(cast call "$GATEWAY" "committeeManagement()(address)" --rpc-url "$RPC")
GW_SM=$(cast call "$GATEWAY" "stakeManagement()(address)"     --rpc-url "$RPC")
GW_SPV=$(cast call "$GATEWAY" "bitcoinSPV()(address)"         --rpc-url "$RPC")
GW_PB=$(cast call "$GATEWAY" "pegBTC()(address)"              --rpc-url "$RPC")
lc(){ echo "$1" | tr 'A-Z' 'a-z'; }
[ "$(lc "$GW_CM")"  = "$(lc "$COMMITTEE")" ] || die "gateway.committeeManagement mismatch ($GW_CM)"
[ "$(lc "$GW_SM")"  = "$(lc "$STAKE")" ]     || die "gateway.stakeManagement mismatch ($GW_SM)"
[ "$(lc "$GW_SPV")" = "$(lc "$SPV")" ]       || die "gateway.bitcoinSPV mismatch ($GW_SPV)"
[ "$(lc "$GW_PB")"  = "$(lc "$PEGBTC")" ]    || die "gateway.pegBTC mismatch ($GW_PB)"
log "gateway wiring verified (committee/stake/spv/pegBTC)"

# ProxyAdmin of the gateway proxy (informational; ERC1967 admin slot)
ADMIN_SLOT=0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103
PROXYADMIN=$(cast parse-bytes32-address "$(cast storage "$GATEWAY" "$ADMIN_SLOT" --rpc-url "$RPC")")

# Gateway proxy creation block, from the broadcast receipts (canonical subgraph startBlock).
RUN_JSON=$FORGE_DIR/broadcast/DeployLocal.sol/$CID/run-latest.json
GATEWAY_DEPLOY_BLOCK=$(python3 - "$RUN_JSON" "$GATEWAY" <<'PY'
import sys,json
try:
    run=json.load(open(sys.argv[1]))
except Exception:
    sys.exit(0)
gw=sys.argv[2].lower(); tx_hash=None
for t in run.get("transactions",[]):
    if (t.get("contractAddress") or "").lower()==gw:
        tx_hash=(t.get("hash") or "").lower()
for r in run.get("receipts",[]):
    if (r.get("transactionHash") or "").lower()==tx_hash:
        print(int(r["blockNumber"],16)); break
PY
)
[ -n "$GATEWAY_DEPLOY_BLOCK" ] || GATEWAY_DEPLOY_BLOCK=$PRE_DEPLOY_BLOCK
log "gateway proxy creation block = $GATEWAY_DEPLOY_BLOCK (pre-deploy block was $PRE_DEPLOY_BLOCK)"

# -----------------------------------------------------------------------------
# 3. Local policy: shorter committee answer window (committee-only setter of GatewayLocal)
# -----------------------------------------------------------------------------
cast send "$GATEWAY" "debugSetResponseWindowBlocks(uint256)" "$RESPONSE_WINDOW_BLOCKS" \
  --private-key "$C0_GOAT_PRIVATE_KEY" --rpc-url "$RPC" >/dev/null
log "responseWindowBlocks = $(cast call "$GATEWAY" "responseWindowBlocks()(uint256)" --rpc-url "$RPC")"

# -----------------------------------------------------------------------------
# 4. Registrations
# -----------------------------------------------------------------------------
log "== register committee peer ids =="
cast send "$COMMITTEE" "registerPeerId(bytes)" "$C0_PEER_ID_BYTES" \
  --private-key "$C0_GOAT_PRIVATE_KEY" --rpc-url "$RPC" >/dev/null
cast send "$COMMITTEE" "registerPeerId(bytes)" "$C1_PEER_ID_BYTES" \
  --private-key "$C1_GOAT_PRIVATE_KEY" --rpc-url "$RPC" >/dev/null
log "registered committee_0 + committee_1 peer ids"

log "== register verifier (2-of-2 committee signatures) =="
VDIGEST=$(cast call "$COMMITTEE" "getAddVerifierDigestNonced(bytes,uint256)(bytes32)" \
  "$VF0_PEER_ID_BYTES" "$VERIFIER_NONCE" --rpc-url "$RPC")
VS0=$(cast wallet sign --no-hash --private-key "$C0_GOAT_PRIVATE_KEY" "$VDIGEST")
VS1=$(cast wallet sign --no-hash --private-key "$C1_GOAT_PRIVATE_KEY" "$VDIGEST")
cast send "$COMMITTEE" "addVerifier(bytes,uint256,bytes[])" \
  "$VF0_PEER_ID_BYTES" "$VERIFIER_NONCE" "[$VS0,$VS1]" \
  --private-key "$DEPLOYER_GOAT_PRIVATE_KEY" --rpc-url "$RPC" >/dev/null
log "registered verifier_0 peer id (nonce $VERIFIER_NONCE)"

log "== register operator pubkey =="
# StakeManagement.getRegisterPubkeyDigest binds address(this)+chainid+operator; sign with the operator's
# BTC key (BITVM_SECRET). msg.sender must be OP0_GOAT_ADDRESS so pubkeyToAddress==the staker.
ODIGEST=$(cast call "$STAKE" "getRegisterPubkeyDigest(address)(bytes32)" "$OP0_GOAT_ADDRESS" --rpc-url "$RPC")
OSIG=$(cast wallet sign --no-hash --private-key "0x$OP0_BITVM_SECRET" "$ODIGEST")   # 65 bytes r||s||v
OSIG64=${OSIG:0:130}                                                               # first 64 bytes r||s
cast send "$STAKE" "registerPubkey(bytes32,bytes1,bytes)" \
  "$OP0_BTC_PUBKEY_XONLY_0X" "$OP0_BTC_PUBKEY_PREFIX" "$OSIG64" \
  --private-key "$OP0_GOAT_PRIVATE_KEY" --rpc-url "$RPC" >/dev/null
log "registered operator x-only pubkey -> $OP0_GOAT_ADDRESS"

log "== operator stake + lock =="
cast send "$WGBTC" "mint(address,uint256)" "$OP0_GOAT_ADDRESS" "$STAKE_AMOUNT_WEI" \
  --private-key "$DEPLOYER_GOAT_PRIVATE_KEY" --rpc-url "$RPC" >/dev/null
cast send "$WGBTC" "approve(address,uint256)" "$STAKE" "$STAKE_AMOUNT_WEI" \
  --private-key "$OP0_GOAT_PRIVATE_KEY" --rpc-url "$RPC" >/dev/null
cast send "$STAKE" "stake(uint256)" "$STAKE_AMOUNT_WEI" \
  --private-key "$OP0_GOAT_PRIVATE_KEY" --rpc-url "$RPC" >/dev/null
cast send "$STAKE" "lockStake(address,uint256)" "$OP0_GOAT_ADDRESS" "$LOCK_AMOUNT_WEI" \
  --private-key "$OP0_GOAT_PRIVATE_KEY" --rpc-url "$RPC" >/dev/null
log "operator staked $STAKE_AMOUNT_WEI, locked $LOCK_AMOUNT_WEI"

log "== authorize committee_0 as SPV poster =="
# openPosting is already true, but whitelist committee_0's GOAT address explicitly (it runs
# ENABLE_UPDATE_SPV_CONTRACT=true and posts block hashes from its GOAT_PRIVATE_KEY).
cast send "$SPV" "setPoster(address,bool)" "$C0_GOAT_ADDRESS" true \
  --private-key "$DEPLOYER_GOAT_PRIVATE_KEY" --rpc-url "$RPC" >/dev/null
log "committee_0 whitelisted on MockBitcoinSPV"

# -----------------------------------------------------------------------------
# 5. Write state/contracts.json
# -----------------------------------------------------------------------------
OUT=${OUT_FILE:-$STATE_DIR/contracts.json}   # OUT_FILE overrides for throwaway/dry-run deploys
python3 - "$OUT" <<PY
import json,datetime
d={
 "_note":"TEST-ONLY local contract deployment for the BitVM2 localnet (anvil chain id $CID). Generated by localnet/contracts-local/deploy-local.sh.",
 "generated_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),
 "rpc":"$RPC",
 "chain_id":$CID,
 "deploy_start_block":$PRE_DEPLOY_BLOCK,
 "gateway_deploy_block":$GATEWAY_DEPLOY_BLOCK,
 "subgraph_start_block":$GATEWAY_DEPLOY_BLOCK,
 "goat_gateway_event_filter_from":$GATEWAY_DEPLOY_BLOCK,
 "response_window_blocks":$RESPONSE_WINDOW_BLOCKS,
 "deployer":"$DEPLOYER_GOAT_ADDRESS",
 "addresses":{
   "gateway_proxy":"$GATEWAY",
   "gateway_impl":"$GATEWAY_IMPL",
   "committee_management_proxy":"$COMMITTEE",
   "committee_management_impl":"$COMMITTEE_IMPL",
   "stake_management_proxy":"$STAKE",
   "stake_management_impl":"$STAKE_IMPL",
   "peg_btc":"$PEGBTC",
   "bitcoin_spv":"$SPV",
   "stake_token_wgbtc":"$WGBTC",
   "proxy_admin":"$PROXYADMIN",
   "swap_contract":"0x000000000000000000000000000000000000dEaD"
 },
 "node_env":{
   "GOAT_CHAIN_URL":"$RPC",
   "GOAT_GATEWAY_CONTRACT_ADDRESS":"$GATEWAY",
   "GOAT_SWAP_CONTRACT_ADDRESS":"0x000000000000000000000000000000000000dEaD",
   "GOAT_GATEWAY_EVENT_FILTER_FROM":$GATEWAY_DEPLOY_BLOCK
 }
}
json.dump(d,open("$OUT","w"),indent=2); open("$OUT","a").write("\n")
print("wrote","$OUT")
PY
chmod 600 "$OUT"
log "DONE."
