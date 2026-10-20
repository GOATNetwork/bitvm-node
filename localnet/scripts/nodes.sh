#!/usr/bin/env bash
# Manage the 5 bitvm-noded processes of the localnet.
#   scripts/nodes.sh start|stop|restart|status [role...]
# roles: committee_0 committee_1 operator_0 verifier_0 watchtower_0 (default: all)
#
# Safety: only ever signals a PID recorded in run/nodes/<role>.pid whose /proc
# cmdline actually points at $BIN_DIR/bitvm-noded -- never a stray bitvm-noded of
# another user. Graceful SIGTERM, wait, then SIGKILL as a last resort.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
source "$ROOT/scripts/localnet.env"

ROLES=(committee_0 committee_1 operator_0 verifier_0 watchtower_0)
PIDDIR="$RUN_DIR/nodes"; mkdir -p "$PIDDIR" "$LOGS_DIR/nodes"
NODE_BIN="$BIN_DIR/bitvm-noded"
TERM_WAIT=25   # seconds to wait for graceful shutdown before SIGKILL

role_index() { local r="$1" i; for i in "${!ROLES[@]}"; do [[ "${ROLES[$i]}" == "$r" ]] && { echo "$i"; return; }; done; echo -1; }
rpc_port()    { echo $((RPC_PORT_BASE + $(role_index "$1"))); }
p2p_port()    { echo $((P2P_PORT_BASE + $(role_index "$1"))); }
metrics_port(){ echo $((METRICS_PORT_BASE + $(role_index "$1"))); }

peer_id() { jq -r ".roles.$1.peer_id" "$STATE_DIR/keys.json"; }

bootnodes_for() { # echo repeated --bootnodes flags for a role
  local role="$1"; local c0 c1
  c0="/ip4/127.0.0.1/tcp/$((P2P_PORT_BASE+0))/p2p/$(peer_id committee_0)"
  c1="/ip4/127.0.0.1/tcp/$((P2P_PORT_BASE+1))/p2p/$(peer_id committee_1)"
  case "$role" in
    committee_0) : ;;                                   # bootnode: none
    committee_1) printf ' --bootnodes %s' "$c0" ;;
    *)           printf ' --bootnodes %s --bootnodes %s' "$c0" "$c1" ;;
  esac
}

pid_of() { local f="$PIDDIR/$1.pid"; [[ -f "$f" ]] && cat "$f" || echo ""; }

is_ours() { # $1 pid -> 0 if a live bitvm-noded launched from our BIN_DIR
  local pid="$1"
  [[ -n "$pid" && -d "/proc/$pid" ]] || return 1
  tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | grep -q "$NODE_BIN" || return 1
  return 0
}

running() { local pid; pid=$(pid_of "$1"); is_ours "$pid"; }

start_one() {
  local role="$1"
  if running "$role"; then echo "  $role already running (pid $(pid_of "$role"))"; return; fi
  [[ -f "$NODES_DIR/$role/.env" ]] || { echo "  $role: missing nodes/$role/.env (run scripts/gen-node-envs.sh)" >&2; return 1; }
  [[ -x "$NODE_BIN" ]] || { echo "  $NODE_BIN missing (run scripts/install-bins.sh)" >&2; return 1; }
  local rpc p2p met; rpc=$(rpc_port "$role"); p2p=$(p2p_port "$role"); met=$(metrics_port "$role")
  local boots; boots=$(bootnodes_for "$role")
  # One log file per boot: logs/nodes/<role>/<utc>.log, with logs/nodes/<role>/current
  # (and the legacy logs/nodes/<role>.log) pointing at the newest one.
  local logdir="$LOGS_DIR/nodes/$role"; mkdir -p "$logdir"
  local log="$logdir/$(date -u +%Y%m%dT%H%M%SZ).log"
  : > "$log"; ln -sfn "$log" "$logdir/current"; ln -sfn "$role/current" "$LOGS_DIR/nodes/$role.log"
  # MOCK_* + RUST_LOG come from the sourced localnet.env (process env wins over .env),
  # so tuning localnet.env + restart applies without regenerating .env.
  # run/tuning.env (written by the e2e suite, e2e/lib.sh set_tuning) overrides single MOCK_* knobs;
  # run/overrides/<role>.env (written by scripts/chaos.sh attach) is sourced LAST so a
  # single role can be pointed at the fault proxies.
  ( cd "$NODES_DIR/$role"
    if [[ -f "$RUN_DIR/tuning.env" ]]; then set -a; source "$RUN_DIR/tuning.env"; set +a; fi
    if [[ -f "$RUN_DIR/overrides/$role.env" ]]; then set -a; source "$RUN_DIR/overrides/$role.env"; set +a; fi
    # shellcheck disable=SC2086
    nohup "$NODE_BIN" \
      --rpc-addr "127.0.0.1:$rpc" \
      --metrics-addr "127.0.0.1:$met" \
      --db-path "sqlite:$NODES_DIR/$role/bitvm-node.db" \
      --p2p-port "$p2p" $boots \
      >> "$log" 2>&1 &
    echo $! > "$PIDDIR/$role.pid" )
  sleep 0.5
  if running "$role"; then
    echo "  started $role  pid=$(pid_of "$role")  rpc=127.0.0.1:$rpc p2p=$p2p metrics=$met"
  else
    echo "  FAILED  $role (see $log)"; tail -3 "$log" 2>/dev/null | sed 's/^/      /'
  fi
}

stop_one() {
  local role="$1" pid; pid=$(pid_of "$role")
  if ! is_ours "$pid"; then echo "  $role not running"; rm -f "$PIDDIR/$role.pid"; return; fi
  echo "  stopping $role (pid $pid) ..."
  kill -TERM "$pid" 2>/dev/null || true
  local i=0
  while (( i < TERM_WAIT )) && is_ours "$pid"; do sleep 1; i=$((i + 1)); done
  if is_ours "$pid"; then
    echo "    still alive after ${TERM_WAIT}s, SIGKILL"; kill -KILL "$pid" 2>/dev/null || true; sleep 1
  fi
  rm -f "$PIDDIR/$role.pid"
  echo "    $role stopped"
}

status_one() {
  local role="$1" pid rpc met; pid=$(pid_of "$role"); rpc=$(rpc_port "$role"); met=$(metrics_port "$role")
  local state="DOWN" peers="-" topics="-" bh="-" gh="-" spv="-" ready="-" ovr=""
  [[ -f "$RUN_DIR/overrides/$role.env" ]] && ovr=" [proxied]"
  if is_ours "$pid"; then
    state="up(pid $pid)"
    local m; m=$(curl -s --max-time 3 "http://127.0.0.1:$met/metrics" 2>/dev/null || true)
    if [[ -n "$m" ]]; then
      peers=$(awk '/^bitvm_node_p2p_connected_peers/{print $2; exit}' <<<"$m"); peers=${peers:-?}
      topics=$(awk '/^bitvm_node_p2p_required_topics_healthy/{print $2; exit}' <<<"$m"); topics=${topics:-?}
      ready=$(awk '/^bitvm_node_ready /{print $2; exit}' <<<"$m"); ready=${ready:-?}
    fi
    local d; d=$(curl -s --max-time 3 "http://127.0.0.1:$rpc/v1/debug/status" 2>/dev/null || true)
    if [[ -n "$d" ]]; then
      bh=$(jq -r '.bitcoin_height // .data.bitcoin_height // "?"' <<<"$d" 2>/dev/null || echo "?")
      gh=$(jq -r '.goat_height // .data.goat_height // "?"' <<<"$d" 2>/dev/null || echo "?")
      spv=$(jq -r '.goat_spv_height // .data.goat_spv_height // "?"' <<<"$d" 2>/dev/null || echo "?")
    fi
  fi
  printf '  %-13s %-14s ready=%-2s peers=%-3s topics_healthy=%-3s btc_h=%-5s goat_h=%-7s spv_h=%-5s%s\n' \
    "$role" "$state" "$ready" "$peers" "$topics" "$bh" "$gh" "$spv" "$ovr"
}

targets() { if [[ $# -gt 0 ]]; then printf '%s\n' "$@"; else printf '%s\n' "${ROLES[@]}"; fi; }

cmd="${1:-status}"; shift || true
case "$cmd" in
  start)   echo "starting nodes:";   for r in $(targets "$@"); do start_one "$r"; sleep 1.5; done ;;
  stop)    echo "stopping nodes:";   for r in $(targets "$@"); do stop_one  "$r"; done ;;
  restart) for r in $(targets "$@"); do stop_one "$r"; done; echo "---"; for r in $(targets "$@"); do start_one "$r"; sleep 1.5; done ;;
  status)  echo "node status:";      for r in $(targets "$@"); do status_one "$r"; done ;;
  *) echo "usage: $0 start|stop|restart|status [role...]" >&2; exit 2 ;;
esac
