#!/usr/bin/env bash
# Helpers sourced by the e2e flow / scenario scripts. Everything about *this* localnet comes from
# scripts/localnet.env (code root, data root, ports) and $LOCALNET_DATA/state (keys, contracts, subgraph).
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source "$ROOT/scripts/localnet.env"
set -a; source "$STATE_DIR/keys.env"; set +a
GW=$(jq -r '.addresses.gateway_proxy' "$STATE_DIR/contracts.json")
PEG=$(jq -r '.addresses.peg_btc' "$STATE_DIR/contracts.json")
SUBGRAPH_URL=$(jq -r '.query_url' "$STATE_DIR/subgraph.json")
CLI_ENV="$STATE_DIR/cli"                       # user.env / operator.env / verifier.env (gen-node-envs.sh)
E2E_RUN="$RUN_DIR/e2e"; mkdir -p "$E2E_RUN"     # inst.txt / graph.txt / last-*.out scratch of the flows
ROLES=(committee_0 committee_1 operator_0 verifier_0 watchtower_0)
NODES=(); for _i in "${!ROLES[@]}"; do NODES+=("${ROLES[$_i]}:$((RPC_PORT_BASE + _i))"); done
role_idx() { local i=0; for n in "${NODES[@]}"; do [[ ${n%%:*} == "$1" ]] && { echo $i; return; }; i=$((i+1)); done; echo 0; }
rpc_url() { echo "http://127.0.0.1:$((RPC_PORT_BASE + $(role_idx "$1")))"; }
metrics_url() { echo "http://127.0.0.1:$((METRICS_PORT_BASE + $(role_idx "$1")))/metrics"; }
CHAOS_CTRL="http://127.0.0.1:$CHAOS_CTRL_PORT"
# nodes.sh must not inherit a CLI identity sourced by a flow
NODES_SH() { env -u BITVM_SECRET -u GOAT_PRIVATE_KEY -u GOAT_ADDRESS "$ROOT/scripts/nodes.sh" "$@"; }
POLL=${E2E_POLL_SECS:-2}                        # seconds between status / log / mempool polls
ts() { date -u +%H:%M:%S; }
log() { echo "[$(ts)] $*"; }
tip() { $BCLI getblockcount; }
mine() { local n=${1:-1}; local addr; addr=$($BCLI -rpcwallet="$BTC_RPC_WALLET" getnewaddress bvlocal-miner bech32); $BCLI generatetoaddress "$n" "$addr" >/dev/null; log "mined $n -> tip $(tip)"; }
mempool() { $BCLI getrawmempool | python3 -c 'import sys,json; print(" ".join(x[:8] for x in json.load(sys.stdin)))'; }
inst_status() { curl -s --max-time 5 "http://127.0.0.1:$2/v1/instances/$1" | python3 -c 'import sys,json
try: print(json.load(sys.stdin)["instance_wrap"]["instance"]["status"])
except Exception: print("?")' 2>/dev/null; }
graph_status() { curl -s --max-time 5 "http://127.0.0.1:$2/v1/graphs/$1" | python3 -c 'import sys,json
try: print(json.load(sys.stdin)["graph"]["status"])
except Exception: print("?")' 2>/dev/null; }
all_inst() { local out=""; for n in "${NODES[@]}"; do out+="${n%%:*}=$(inst_status "$1" "${n##*:}") "; done; echo "$out"; }
all_graph() { local out=""; for n in "${NODES[@]}"; do out+="${n%%:*}=$(graph_status "$1" "${n##*:}") "; done; echo "$out"; }
# wait_all kind id status timeout -> 0 when every node reports the status
wait_all() { local kind=$1 id=$2 want=$3 timeout=${4:-300} t=0 line
  while :; do
    if [[ $kind == inst ]]; then line=$(all_inst "$id"); else line=$(all_graph "$id"); fi
    if [[ $(grep -o "=$want " <<<"$line " | wc -l) -eq ${#NODES[@]} ]]; then log "$kind $id: all $want"; return 0; fi
    if (( t >= timeout )); then log "TIMEOUT waiting $kind $id -> $want after ${timeout}s: $line"; return 1; fi
    sleep "$POLL"; t=$((t+POLL))
  done; }
wait_any() { local kind=$1 id=$2 want=$3 timeout=${4:-300} t=0 line
  while :; do
    if [[ $kind == inst ]]; then line=$(all_inst "$id"); else line=$(all_graph "$id"); fi
    if [[ "$line " == *"=$want "* ]]; then log "$kind $id: some node $want ($line)"; return 0; fi
    if (( t >= timeout )); then log "TIMEOUT waiting $kind $id -> any $want after ${timeout}s: $line"; return 1; fi
    sleep "$POLL"; t=$((t+POLL))
  done; }
wait_mempool() { local timeout=${1:-120} t=0 m
  while :; do m=$(mempool); if [[ -n "$m" ]]; then log "mempool: $m"; return 0; fi
    if (( t >= timeout )); then log "TIMEOUT: mempool still empty after ${timeout}s"; return 1; fi; sleep "$POLL"; t=$((t+POLL)); done; }
# One log file per boot (logs/nodes/<role>/<utc>.log, `current` -> newest). Only lines written after this
# helper was sourced count; a node restarted mid-flow continues in a newer file, which is read whole.
declare -A LOG_START LOG_FILE
for _n in "${NODES[@]}"; do _r=${_n%%:*}; LOG_FILE[$_r]=$(readlink -f "$LOGS_DIR/nodes/$_r/current" 2>/dev/null || echo ""); LOG_START[$_r]=$(wc -l < "${LOG_FILE[$_r]:-/dev/null}" 2>/dev/null || echo 0); done
fresh_log() { local d="$LOGS_DIR/nodes/$1" f
  for f in "$d"/*.log; do
    [[ -f $f ]] || continue
    if [[ $f == "${LOG_FILE[$1]}" ]]; then tail -n "+$(( ${LOG_START[$1]:-0} + 1 ))" "$f"
    elif [[ $f > "${LOG_FILE[$1]}" ]]; then cat "$f"; fi
  done; }
# wait_log role pattern timeout
wait_log() { local role=$1 pat=$2 timeout=${3:-120} t=0
  while :; do local hit; hit=$(fresh_log "$role" | grep -a -- "$pat" | tail -1); if [[ -n $hit ]]; then log "$role log: $(cut -c1-220 <<<"$hit")"; return 0; fi
    if (( t >= timeout )); then log "TIMEOUT: no '$pat' in $role log after ${timeout}s"; return 1; fi; sleep "$POLL"; t=$((t+POLL)); done; }
engine_summary() { for n in "${NODES[@]}"; do curl -s --max-time 5 "http://127.0.0.1:${n##*:}/v1/debug/engine" | python3 -c '
import sys,json
d=json.load(sys.stdin); c={(x["table"],x["state"]):x["count"] for x in d["counts"]}
print("  %-12s inbox Pending=%d Failed=%d Poisoned=%d waiting=%d poisoned_actions=%d jobs Pending=%d Running=%d Failed=%d Poisoned=%d" % ("'"${n%%:*}"'", c.get(("inbox","Pending"),0), c.get(("inbox","Failed"),0), c.get(("inbox","Poisoned"),0), len(d["waiting"]), len(d["poisoned"]), c.get(("job","Pending"),0), c.get(("job","Running"),0), c.get(("job","Failed"),0), c.get(("job","Poisoned"),0)))
for w in d["waiting"]: print("     waiting:", w["aggregate_kind"], w["aggregate_id"][:8], w["kind"], w.get("waiting_ref"), (w.get("waiting_detail") or "")[:80])
for p in d["poisoned"]: print("     POISONED:", p["aggregate_kind"], p["aggregate_id"][:8], p["action"], "count=%d blocked_until=%d" % (p["poison_count"], p["blocked_until"]), (p.get("reason") or "")[:80])' 2>/dev/null || echo "  ${n%%:*}: engine endpoint unavailable"; done; }
# alerts role -> instance alert counters of one node (metrics)
alerts() { curl -s --max-time 5 "$(metrics_url "$1")" | grep '^bitvm_node_instance_alerts' | sed 's/^/     /'; }
# db role "sql"
db() { sqlite3 -noheader -list -cmd ".timeout 8000" "$NODES_DIR/$1/bitvm-node.db" "$2"; }
# warn_summary role -> new WARN/ERROR lines since the script started, grouped by event/outcome
warn_summary() { fresh_log "$1" | grep -E ' (WARN|ERROR) ' | sed -E 's/\x1b\[[0-9;]*m//g' | grep -oE 'event=[a-z_]+( outcome=[a-z_]+)?|(WARN|ERROR) [^ ]+' | sort | uniq -c | sort -rn | head -20 | sed 's/^/     /'; }
graphs_on() { curl -s --max-time 5 "$(rpc_url "$1")/v1/graphs?limit=200" | python3 -c '
import sys,json
try:
    for g in json.load(sys.stdin)["graphs"]:
        g=g["graph"]
        if g["instance_id"]=="'"$2"'": print(g["graph_id"])
except Exception: pass'; }
graph_of_instance() { curl -s --max-time 5 "$(rpc_url committee_0)/v1/graphs?limit=200" | python3 -c '
import sys,json
for g in json.load(sys.stdin)["graphs"]:
    g=g["graph"]
    if g["instance_id"]=="'"$1"'": print(g["graph_id"], g["kickoff_index"], g["status"])'; }
pegbtc_sats() { $CAST call $PEG "balanceOf(address)(uint256)" "$OP0_GOAT_ADDRESS" --rpc-url "$GOAT_CHAIN_URL" | awk '{printf "%d\n", $1/1e10}'; }
topup_pegbtc() { # ensure the operator holds >= 1_100_000 sats of pegBTC
  local have; have=$(pegbtc_sats); if (( have < 1100000 )); then
    $CAST send $GW "debugMintPegBTC(address,uint256)" "$OP0_GOAT_ADDRESS" $(( (1100000 - have) * 10000000000 )) --private-key "$C0_GOAT_PRIVATE_KEY" --rpc-url "$GOAT_CHAIN_URL" >/dev/null && log "pegBTC topped up: $have -> $(pegbtc_sats) sats"; else log "pegBTC $have sats, no top-up"; fi; }

# ---- chaos / backend helpers ----
CHAOS="$ROOT/scripts/chaos.sh"
chaos_state() { "$CHAOS" status | sed 's/^/     /'; }
proxy_stats() { curl -s --max-time 5 "$CHAOS_CTRL/stats" | python3 -c '
import sys,json
for k,v in json.load(sys.stdin).items():
    if v["requests"]: print("     %-20s req=%-6d fwd=%-6d err=%-4d active=%d faulted=%s" % (k, v["requests"], v["forwarded"], v["errors"], v["active"], v["faulted"] or ""))'; }
# backend_probe role -> ready bit, backend request counters by outcome, last-success ages
backend_probe() { local m now; m=$(curl -s --max-time 5 "$(metrics_url "$1")"); now=$(date +%s)
  echo "     $1 ready=$(awk '/^bitvm_node_ready /{print $2}' <<<"$m") event_watch_ready=$(awk '/^bitvm_node_event_watch_ready /{print $2}' <<<"$m") $(grep -E '^bitvm_node_(btc|goat)_backend_requests_total' <<<"$m" | sed -E 's/bitvm_node_//; s/_backend_requests_total//' | tr '\n' ' ')"
  grep -E '_last_success_timestamp_seconds' <<<"$m" | awk -v now="$now" '{n=$1; sub(/bitvm_node_/,"",n); printf "     %s age=%ds\n", n, now-$2}'; }
# warn_delta role -> WARN/ERROR lines since the script started, grouped by event/outcome (or message prefix)
warn_delta() { fresh_log "$1" | jq -r 'select(.level=="WARN" or .level=="ERROR") | [.level, (.event // "-"), (.outcome // "-"), (.message[0:60])] | @tsv' 2>/dev/null | sort | uniq -c | sort -rn | head -15 | sed 's/^/     /'; }
# snapshot_heights -> truth heights for the scenario log
snapshot_heights() { echo "     tip=$(tip) anvil=$($CAST block-number --rpc-url "$GOAT_CHAIN_URL" 2>/dev/null) subgraph=$(curl -s --max-time 5 -XPOST -H 'content-type: application/json' -d '{"query":"{_meta{block{number}}}"}' "$SUBGRAPH_URL" | jq -r .data._meta.block.number)"; }
scenario_begin() { log "=== SCENARIO $* BEGIN"; snapshot_heights; chaos_state; }
scenario_end() { log "=== SCENARIO $1 END"; snapshot_heights; engine_summary; local r; for r in committee_0 committee_1 operator_0 verifier_0 watchtower_0; do echo "  $r warn/error:"; warn_delta "$r"; done; proxy_stats; chaos_state; }

# ---- e2e helpers ----
# next_posted_graph -> lowest-slot graph still L2Recorded on the operator (peg-outs go in slot order)
next_posted_graph() { curl -s --max-time 5 "$(rpc_url operator_0)/v1/graphs?limit=500" | python3 -c '
import sys,json
gs=[g["graph"] for g in json.load(sys.stdin)["graphs"] if g["graph"]["status"]=="L2Recorded"]
gs.sort(key=lambda g: g["kickoff_index"])
print(gs[0]["graph_id"] if gs else "")'; }
# set_tuning VAR VALUE / clear_tuning VAR -> runtime override of one MOCK_* knob in run/tuning.env (sourced by
# nodes.sh at launch, so it takes effect on the next (re)start of a node; localnet.env itself is never edited)
set_tuning() { local f="$RUN_DIR/tuning.env"; touch "$f"; sed -i "/^export $1=/d" "$f"; echo "export $1=$2" >> "$f"; }
clear_tuning() { [[ -f "$RUN_DIR/tuning.env" ]] && sed -i "/^export $1=/d" "$RUN_DIR/tuning.env"; true; }
# tuning_get VAR -> the value a (re)started node would see: run/tuning.env first, then localnet.env
tuning_get() { local v; v=$(grep -h "^export $1=" "$RUN_DIR/tuning.env" 2>/dev/null | tail -1 | cut -d= -f2-); [[ -n $v ]] && echo "$v" || echo "${!1}"; }
current_verdict() { { grep -h '^export MOCK_GC_PROOF_VERDICT=' "$RUN_DIR/tuning.env" 2>/dev/null || echo "export MOCK_GC_PROOF_VERDICT=$MOCK_GC_PROOF_VERDICT"; } | tail -1 | cut -d= -f2; }
# set_verdict valid|always-invalid -> override the verdict and restart operator_0 + verifier_0
set_verdict() { if [[ $1 == valid ]]; then clear_tuning MOCK_GC_PROOF_VERDICT; else set_tuning MOCK_GC_PROOF_VERDICT "$1"; fi
  NODES_SH restart operator_0 verifier_0 >/dev/null 2>&1; sleep 10; log "verdict=$1, operator_0 + verifier_0 restarted"; }
# wait_ready secs -> every node reports bitvm_node_ready 1 (or timeout)
wait_ready() { local t=0 ok; while :; do ok=1; for n in "${NODES[@]}"; do [[ "$(curl -s --max-time 3 "$(metrics_url "${n%%:*}")" | awk '/^bitvm_node_ready /{print $2}')" == 1 ]] || ok=0; done
  (( ok )) && return 0; (( t >= ${1:-180} )) && { log "TIMEOUT: nodes not ready after ${1:-180}s"; return 1; }; sleep "$POLL"; t=$((t+POLL)); done; }
# engine_snapshot -> remember every node's Failed job ids (taken by the runner's pre-check); engine_clean then
# rejects any Failed job that is not in that snapshot, so an old failure (e.g. a give-up test on a long-lived
# localnet) is tolerated by identity, never by count. Nonzero (and the reason on stdout) when a query fails.
engine_snapshot() { local r out; for r in "${ROLES[@]}"; do
    out=$(db "$r" "select job_id from engine_job where state='Failed' order by 1" 2>&1) || { echo "  engine snapshot: query failed on $r: ${out:0:160}"; return 1; }
    sed '/^$/d' <<<"$out" > "$E2E_RUN/failed-before.$r"; done; }
# new_failed_jobs -> "role action aggregate8 job_id" for every Failed job absent from the snapshot; a failed query
# prints "role QUERY-FAILED <error>" and makes the function return 1
new_failed_jobs() { local r j a g out rc=0; for r in "${ROLES[@]}"; do
    out=$(db "$r" "select job_id||'|'||action||'|'||aggregate_id from engine_job where state='Failed'" 2>&1) || { echo "$r QUERY-FAILED ${out:0:160}"; rc=1; continue; }
    while IFS='|' read -r j a g; do [[ -n $j ]] || continue; grep -qx "$j" "$E2E_RUN/failed-before.$r" 2>/dev/null || echo "$r $a ${g:0:8} $j"; done <<<"$out"
  done; return $rc; }
# engine_clean -> 0 when no node has Failed/Poisoned/waiting/Running inbox or job rows, no Failed job is new (DB, by
# job_id) and the debug endpoint reports no more Failed jobs than the snapshot holds (independent of the DB query)
engine_clean() { local bad=0 n r d nf snap; for n in "${NODES[@]}"; do r=${n%%:*}
  d=$(curl -s --max-time 5 "http://127.0.0.1:${n##*:}/v1/debug/engine") || { echo "  $r: debug endpoint unreachable"; bad=1; continue; }
  snap=$(grep -c . "$E2E_RUN/failed-before.$r" 2>/dev/null); snap=${snap:-0}
  python3 -c '
import sys,json
d=json.load(sys.stdin); c={(x["table"],x["state"]):x["count"] for x in d["counts"]}
bad = c.get(("inbox","Failed"),0)+c.get(("inbox","Poisoned"),0)+len(d["waiting"])+len(d["poisoned"])+c.get(("job","Running"),0)+c.get(("job","Poisoned"),0)
extra = c.get(("job","Failed"),0) - int(sys.argv[1])
if extra > 0: print("  %s: %d more Failed job(s) than before the case" % (sys.argv[2], extra))
sys.exit(1 if bad or extra > 0 else 0)' "$snap" "$r" <<<"$d" || bad=1; done
  nf=$(new_failed_jobs) || bad=1
  [[ -n $nf ]] && { echo "  new Failed jobs / failed queries: $(tr '\n' ';' <<<"$nf")"; bad=1; }
  return $bad; }
# ensure_operator_stake -> top the operator's locked stake back up to STAKE_TARGET_WEI (0.1 WGBTC) when a
# Disprove slash pushed it under the gateway minimum (an unstaked operator is silently ignored by every peer).
ensure_operator_stake() { local sm w locked min target=${STAKE_TARGET_WEI:-100000000000000000} h
  sm=$(jq -r '.addresses.stake_management_proxy' "$STATE_DIR/contracts.json"); w=$(jq -r '.addresses.stake_token_wgbtc' "$STATE_DIR/contracts.json")
  locked=$($CAST call "$sm" "lockedStakeOf(address)(uint256)" "$OP0_GOAT_ADDRESS" --rpc-url "$GOAT_CHAIN_URL" | awk '{print $1}')
  min=$($CAST call "$GW" "minStakeAmount()(uint256)" --rpc-url "$GOAT_CHAIN_URL" | awk '{print $1}')
  if (( locked >= min )); then log "operator locked stake $locked >= min $min"; return 0; fi
  log "operator locked stake $locked < min $min: topping up $target"
  local tx; for tx in "$w mint(address,uint256) $OP0_GOAT_ADDRESS $target" "$w approve(address,uint256) $sm $target" "$sm stake(uint256) $target" "$sm lockStake(address,uint256) $OP0_GOAT_ADDRESS $target"; do
    set -- $tx; local key=$OP0_GOAT_PRIVATE_KEY; [[ $2 == mint* ]] && key=$DEPLOYER_GOAT_PRIVATE_KEY
    h=$($CAST send "$@" --private-key "$key" --rpc-url "$GOAT_CHAIN_URL" --async 2>&1) || { log "stake top-up: $2 failed: $h"; return 1; }
    local i; for i in 1 2 3 4 5 6; do sleep 2; $CAST receipt "$h" --rpc-url "$GOAT_CHAIN_URL" 2>/dev/null | grep -q '^status *1' && break; done
  done
  locked=$($CAST call "$sm" "lockedStakeOf(address)(uint256)" "$OP0_GOAT_ADDRESS" --rpc-url "$GOAT_CHAIN_URL" | awk '{print $1}'); log "operator locked stake now $locked"; (( locked >= min )); }
