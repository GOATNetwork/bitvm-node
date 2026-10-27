#!/usr/bin/env bash
# Fund every role on BTC regtest (P2WSH funding address) and on GOAT (anvil).
# Idempotent: skips a role already funded above its threshold. Mines 1 block to
# confirm the BTC sends. GOAT registrations/stake are done by the contracts agent;
# this only tops up gas + BTC spending funds.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
source "$ROOT/scripts/localnet.env"
set -a; source "$STATE_DIR/keys.env"; set +a

RPC="$GOAT_CHAIN_URL"

btc_utxos() { curl -s --max-time 5 "$BTC_CHAIN_URL/address/$1/utxo"; }
btc_count() { btc_utxos "$1" | jq 'length' 2>/dev/null || echo 0; }
btc_sats()  { btc_utxos "$1" | jq '[.[].value] | add // 0' 2>/dev/null || echo 0; }

echo "==== GOAT funding (faucet = anvil acct0) ===="
for name in DEPLOYER C0 C1 OP0 VF0 WT0 USER0; do
  var="${name}_GOAT_ADDRESS"; addr="${!var}"
  wei=$($CAST balance "$addr" --rpc-url "$RPC" 2>/dev/null || echo 0)
  eth=$($CAST from-wei "${wei:-0}")
  if awk "BEGIN{exit !(${eth%%.*}+0 < $GOAT_FUND_MIN_ETH)}"; then
    $CAST send "$addr" --value "${GOAT_FUND_ETH}ether" --private-key "$ANVIL_FAUCET_KEY" --rpc-url "$RPC" >/dev/null
    echo "  funded $name $addr  (+${GOAT_FUND_ETH} ETH)"
  else
    echo "  skip   $name $addr  (${eth} ETH)"
  fi
done

echo "==== BTC funding (miner wallet -> P2WSH funding addresses) ===="
BTCLI="$BCLI -rpcwallet=$BTC_RPC_WALLET"
sent=0

fund_btc() { # $1 addr  $2 amount(btc)  $3 label
  $BTCLI sendtoaddress "$1" "$2" >/dev/null && { echo "  sent $2 BTC -> $3 ($1)"; sent=1; }
}

# operator: OP_BTC_UTXOS separate UTXOs of OP_BTC_EACH
opc=$(btc_count "$OP0_BTC_FUNDING_ADDRESS_REGTEST")
if (( opc < OP_BTC_UTXOS )); then
  for _ in $(seq 1 $((OP_BTC_UTXOS - opc))); do fund_btc "$OP0_BTC_FUNDING_ADDRESS_REGTEST" "$OP_BTC_EACH" operator_0; done
else echo "  skip operator_0 (already $opc UTXOs)"; fi

fund_role_min() { # $1 addr  $2 min(btc)  $3 label
  local sats; sats=$(btc_sats "$1"); local need; need=$(awk "BEGIN{print int($2*100000000)}")
  if (( sats < need )); then fund_btc "$1" "$2" "$3"; else echo "  skip $3 (already $sats sats)"; fi
}
fund_role_min "$VF0_BTC_FUNDING_ADDRESS_REGTEST"  "$VF_BTC"   verifier_0
fund_role_min "$WT0_BTC_FUNDING_ADDRESS_REGTEST"  "$WT_BTC"   watchtower_0
fund_role_min "$USER0_BTC_FUNDING_ADDRESS_REGTEST" "$USER_BTC" user_0
# committee_0/1 need no BTC.

if (( sent )); then
  ADDR=$($BTCLI getnewaddress bvlocal-miner bech32); $BCLI generatetoaddress 1 "$ADDR" >/dev/null
  echo "  mined 1 block to confirm; height=$($BCLI getblockcount)"
fi

echo "==== balances ===="
for pair in "OP0:operator_0" "VF0:verifier_0" "WT0:watchtower_0" "USER0:user_0"; do
  p="${pair%%:*}"; role="${pair##*:}"; var="${p}_BTC_FUNDING_ADDRESS_REGTEST"; a="${!var}"
  printf '  %-13s %s sats in %s UTXOs\n' "$role" "$(btc_sats "$a")" "$(btc_count "$a")"
done
