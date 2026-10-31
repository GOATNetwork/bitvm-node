#!/usr/bin/env bash
# Background regtest miner: mines 1 block every MINE_INTERVAL_SECS to the miner
# wallet. scripts/miner.sh start|stop|status|once
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
source "$ROOT/scripts/localnet.env"
PIDF="$RUN_DIR/miner.pid"; LOG="$LOGS_DIR/miner.log"; mkdir -p "$RUN_DIR"
LOOP="$ROOT/scripts/_miner-loop.sh"

is_ours() { local pid="$1"; [[ -n "$pid" && -d "/proc/$pid" ]] &&
  tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | grep -q "_miner-loop.sh"; }
pid_of() { [[ -f "$PIDF" ]] && cat "$PIDF" || echo ""; }

case "${1:-status}" in
  start)
    pid=$(pid_of); if is_ours "$pid"; then echo "miner already running (pid $pid)"; exit 0; fi
    nohup bash "$LOOP" >> "$LOG" 2>&1 &
    echo $! > "$PIDF"; sleep 1
    pid=$(pid_of)
    if is_ours "$pid"; then echo "miner started (pid $pid, every ${MINE_INTERVAL_SECS}s) -> $LOG"
    else echo "miner FAILED to start (see $LOG)"; tail -3 "$LOG" 2>/dev/null; exit 1; fi ;;
  stop)
    pid=$(pid_of)
    if is_ours "$pid"; then kill -TERM "$pid" 2>/dev/null || true; sleep 1
      is_ours "$pid" && kill -KILL "$pid" 2>/dev/null || true; echo "miner stopped"
    else echo "miner not running"; fi
    rm -f "$PIDF" ;;
  once)
    ADDR=$($BCLI -rpcwallet="$BTC_RPC_WALLET" getnewaddress bvlocal-miner bech32)
    $BCLI generatetoaddress "${2:-1}" "$ADDR" >/dev/null
    echo "mined ${2:-1} block(s); height=$($BCLI getblockcount)" ;;
  status)
    pid=$(pid_of)
    if is_ours "$pid"; then echo "miner up (pid $pid), tip=$($BCLI getblockcount 2>/dev/null)"
    else echo "miner down, tip=$($BCLI getblockcount 2>/dev/null)"; fi ;;
  *) echo "usage: $0 start|stop|status|once [n]" >&2; exit 2 ;;
esac
