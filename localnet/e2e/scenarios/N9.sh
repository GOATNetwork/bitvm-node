#!/usr/bin/env bash
# N9: subgraph latency 8 s (< 10 s timeout) on every node for a full peg-in. Exits with the peg-in flow's status.
source "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"
scenario_begin N9 subgraph-latency-8s pegin
"$CHAOS" fault all graph latency 8000 --ttl 2400
"$ROOT/e2e/flows/pegin.sh"; rc=$?
log "event watcher lag/ages:"; for r in committee_0 operator_0; do backend_probe "$r" | grep -E 'event_watch|ready'; done
"$CHAOS" clear all graph
scenario_end N9; log "N9 rc=$rc"
exit $rc
