#!/usr/bin/env bash
# One-screen "why is this node unhealthy" view of a single bitvm-noded.
#   triage.sh [-r http://host:rpc] [-m http://host:metrics] [-f <log file>] [-p <pid>] [-s 10m]
# Defaults come from NODE_RPC (http://127.0.0.1:8080), NODE_METRICS (http://127.0.0.1:9090), NODE_LOG, NODE_PID.
# Reads GET /v1/health, GET /metrics, GET /v1/debug/status + /v1/debug/engine when the debug feature is on,
# and the log's WARN/ERROR lines of the last window grouped by event/outcome.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
rpc=${NODE_RPC:-http://127.0.0.1:8080} met=${NODE_METRICS:-http://127.0.0.1:9090} log=${NODE_LOG:-} pid=${NODE_PID:-} since=10m
while getopts 'r:m:f:p:s:' o; do case $o in r) rpc=$OPTARG;; m) met=$OPTARG;; f) log=$OPTARG;; p) pid=$OPTARG;; s) since=$OPTARG;; *) exit 2;; esac; done
now=$(date +%s)
metric() { awk -v k="$1" '$1==k{print $2; exit}' <<<"$2"; }
age() { local t=$1; [[ -z $t || $t == 0 ]] && echo "never" || echo "$(( now - t ))s"; }

if [[ -n $pid && -d /proc/$pid ]]; then
  echo "process: pid=$pid up=$(ps -o etimes= -p "$pid" | tr -d ' ')s rss=$(awk '/VmRSS/{printf "%dMB",$2/1024}' "/proc/$pid/status") fds=$(ls "/proc/$pid/fd" 2>/dev/null | wc -l)"
fi
h=$(curl -s --max-time 5 "$rpc/v1/health")
if [[ -n $h ]]; then
  jq -r '"health: ready=\(.ready) startup=\(.components.startup) database=\(.components.database) backend=\(.components.backend) event_watcher=\(.components.event_watcher) role=\(.role) version=\(.version) uptime=\(.uptime_secs)s spv_lag=\(.spv_lag_blocks)",
         (.backends[] | "  backend \(.backend): up=\(.up)\(if .unavailable_since then " unavailable_since=\(.unavailable_since)" else "" end) consecutive_failures=\(.consecutive_failures)\(if .last_error then " last_error=\(.last_error[0:100])" else "" end)"),
         "  event_watch: state=\(.event_watch.state) lag_blocks=\(.event_watch.lag_blocks) last_success=\(.event_watch.last_success_timestamp)"' <<<"$h" 2>/dev/null || echo "health: unparseable: ${h:0:200}"
else echo "health: $rpc/v1/health UNREACHABLE"; fi
m=$(curl -s --max-time 5 "$met/metrics")
if [[ -n $m ]]; then
  echo "metrics: ready=$(metric bitvm_node_ready "$m") p2p_peers=$(metric bitvm_node_p2p_connected_peers "$m") topics_healthy=$(metric bitvm_node_p2p_required_topics_healthy "$m") event_watch_lag=$(metric bitvm_node_event_watch_lag_blocks "$m") spv_lag=$(metric bitvm_node_spv_lag_blocks "$m") gas_wei=$(metric bitvm_node_goat_gas_balance_wei "$m") fee_sats=$(metric bitvm_node_fee_wallet_balance_sats "$m")"
  echo "  backend probes: $(grep -E '^bitvm_node_(btc|goat)_backend_requests_total' <<<"$m" | sed -E 's/bitvm_node_(btc|goat)_backend_requests_total\{outcome="([a-z]+)"\} ([0-9]+)/\1.\2=\3/' | tr '\n' ' ') btc_last_ok=$(age "$(metric bitvm_node_btc_backend_last_success_timestamp_seconds "$m")") goat_last_ok=$(age "$(metric bitvm_node_goat_backend_last_success_timestamp_seconds "$m")")"
  echo "  backend_up: $(grep '^bitvm_node_backend_up' <<<"$m" | sed -E 's/.*backend="([a-z]+)"\} ([0-9]+)/\1=\2/' | tr '\n' ' ')"
  stale=$(grep '^bitvm_node_task_last_success_timestamp_seconds' <<<"$m" | awk -v now="$now" -F'[{}" ]+' '{a=now-$NF; if (a>90) printf "%s=%ds ", $3, a}')
  echo "  stale tasks (>90s): ${stale:-none}"
  al=$(grep '^bitvm_node_instance_alerts_total' <<<"$m" | sed -E 's/.*alert="([a-z_]+)"\} ([0-9]+)/\1=\2/' | tr '\n' ' '); [[ -n $al ]] && echo "  alerts: $al"
else echo "metrics: $met/metrics UNREACHABLE"; fi
d=$(curl -s --max-time 6 "$rpc/v1/debug/status")
if [[ -n $d ]] && jq -e .bitcoin_height >/dev/null 2>&1 <<<"$d"; then
  echo "debug status: $(jq -r '"btc=\(.bitcoin_height // "null") goat=\(.goat_height // "null") spv=\(.goat_spv_height // "null")"' <<<"$d") engine=$(jq -c '.engine // {}' <<<"$d" | cut -c1-220)"
  e=$(curl -s --max-time 6 "$rpc/v1/debug/engine")
  [[ -n $e ]] && jq -r '(.waiting[]? | "  WAITING \(.aggregate_kind) \(.aggregate_id[0:8]) \(.kind) \(.waiting_ref // "") \((.waiting_detail // "")[0:80])"), (.poisoned[]? | "  POISONED \(.aggregate_kind) \(.aggregate_id[0:8]) \(.action) count=\(.poison_count) blocked_until=\(.blocked_until) \((.reason // "")[0:80])")' <<<"$e" 2>/dev/null
fi
if [[ -n $log && -r $log ]]; then
  echo "log $log, WARN/ERROR last $since (top 10 by level/event/outcome):"
  "$HERE/logq.sh" -f "$log" -s "$since" -l WARN | awk '{printf "%s %s %s\n", $2, $4, $5}' | sort | uniq -c | sort -rn | head -10 | sed 's/^/  /'
  le=$("$HERE/logq.sh" -f "$log" -s "$since" -l ERROR -n 1); [[ -n $le ]] && echo "  last ERROR: $le"
fi
exit 0
