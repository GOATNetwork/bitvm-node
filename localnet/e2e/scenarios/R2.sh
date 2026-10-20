#!/usr/bin/env bash
# R2: restart a node while its Goat RPC (then esplora, then subgraph) is unreachable. Passes only when the node
# survives each outage in the process it was started as, and that same process is ready again within 240 s of the
# outage ending (the pre-check's ready window; a plain restart takes 60-120 s to ready on a busy host).
# A death is still cleaned up (the node is started again) so later cases run, but the scenario then fails.
source "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"
role=${1:-watchtower_0}
pidf="$RUN_DIR/nodes/$role.pid"
ready_of() { curl -s --max-time 3 "$(metrics_url "$role")" | awk '/^bitvm_node_ready /{print $2}'; }
scenario_begin R2 boot-with-backend-down "$role"
fail=0
for b in goat btc graph; do
  "$CHAOS" fault "$role" "$b" down --ttl 120
  NODES_SH restart "$role" | tail -1
  pid0=$(cat "$pidf" 2>/dev/null)
  sleep 25
  if [[ -n $pid0 && -d /proc/$pid0 && "$(cat "$pidf" 2>/dev/null)" == "$pid0" ]]; then st=alive; else st=DEAD; fi
  log "$b down: $role (pid $pid0) $st after 25 s; last log lines:"; tail -n 3 "$LOGS_DIR/nodes/$role/current" | jq -r '"     \(.timestamp[11:19]) \(.level) \(.message[0:150])"' 2>/dev/null || tail -n 3 "$LOGS_DIR/nodes/$role/current" | cut -c1-200 | sed 's/^/     /'
  "$CHAOS" clear "$role" "$b"
  if [[ $st == DEAD ]]; then
    log "FAIL: $role died while $b was down; starting it again for the later cases"; fail=1
    NODES_SH start "$role" | tail -1; sleep 30; continue
  fi
  ok=0; for i in $(seq 1 120); do
    [[ "$(cat "$pidf" 2>/dev/null)" == "$pid0" && -d /proc/$pid0 ]] || break
    [[ "$(ready_of)" == 1 ]] && { ok=1; break; }; sleep 2; done
  if (( ok )); then log "$b restored: $role pid $pid0 ready after $((i*2)) s, peers=$(curl -s "$(metrics_url "$role")" | awk '/^bitvm_node_p2p_connected_peers/{print $2}')"
  else log "FAIL: $role pid $pid0 not ready (or gone) within 240 s of $b coming back"; fail=1; fi
done
scenario_end R2; log "R2 rc=$fail"
exit $fail
