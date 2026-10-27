#!/usr/bin/env bash
# Start/stop the mock-proof-builder (serves the operator/watchtower proof HTTP API
# the Operator and Watchtower nodes call). scripts/proof-builder.sh start|stop|status
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
source "$ROOT/scripts/localnet.env"     # exports GENESIS_SEQUENCER_COMMIT_TXID + MOCK_PROOF_* + PROOF_BUILDER_ADDR
PIDF="$RUN_DIR/proof-builder.pid"; LOG="$LOGS_DIR/proof-builder.log"; mkdir -p "$RUN_DIR"
BIN="$BIN_DIR/mock-proof-builder"

is_ours() { local pid="$1"; [[ -n "$pid" && -d "/proc/$pid" ]] &&
  tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | grep -q "$BIN"; }
pid_of() { [[ -f "$PIDF" ]] && cat "$PIDF" || echo ""; }

case "${1:-status}" in
  start)
    pid=$(pid_of); if is_ours "$pid"; then echo "proof-builder already running (pid $pid)"; exit 0; fi
    [[ -x "$BIN" ]] || { echo "$BIN missing (run scripts/install-bins.sh)" >&2; exit 1; }
    # run/tuning.env (e2e delay tier) overrides the MOCK_PROOF_* knobs of localnet.env
    if [[ -f "$RUN_DIR/tuning.env" ]]; then set -a; source "$RUN_DIR/tuning.env"; set +a; fi
    nohup "$BIN" --listen "$PROOF_BUILDER_ADDR" >> "$LOG" 2>&1 &
    echo $! > "$PIDF"; sleep 1
    pid=$(pid_of)
    if is_ours "$pid"; then
      hello=$(curl -s --max-time 3 "http://$PROOF_BUILDER_ADDR/" || true)
      echo "proof-builder started (pid $pid) on $PROOF_BUILDER_ADDR  GET/=\"$hello\""
    else echo "proof-builder FAILED (see $LOG)"; tail -5 "$LOG" 2>/dev/null; exit 1; fi ;;
  stop)
    pid=$(pid_of)
    if is_ours "$pid"; then kill -TERM "$pid" 2>/dev/null || true; sleep 1
      is_ours "$pid" && kill -KILL "$pid" 2>/dev/null || true; echo "proof-builder stopped"
    else echo "proof-builder not running"; fi
    rm -f "$PIDF" ;;
  status)
    pid=$(pid_of)
    if is_ours "$pid"; then
      hello=$(curl -s --max-time 3 "http://$PROOF_BUILDER_ADDR/" || echo "<no response>")
      echo "proof-builder up (pid $pid) on $PROOF_BUILDER_ADDR  GET/=\"$hello\""
    else echo "proof-builder down"; fi ;;
  *) echo "usage: $0 start|stop|status" >&2; exit 2 ;;
esac
