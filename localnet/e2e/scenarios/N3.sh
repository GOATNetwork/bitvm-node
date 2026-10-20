#!/usr/bin/env bash
# N3: Goat RPC flaky for the whole peg-out (50% HTTP 502 + 10% mid-response RST on every node), injected right after
# the initWithdraw CLI call returned (the CLI goes through the operator's RPC and fails fast on a 502 otherwise).
source "$(cd "$(dirname "$0")/.." && pwd)/lib.sh"
gid=${1:?graph id}
scenario_begin N3 goat-flaky pegout "$gid"
"$ROOT/e2e/flows/pegout.sh" "$gid" > "$E2E_RUN/last-N3-pegout.out" 2>&1 &
flow=$!
for i in $(seq 1 60); do grep -q 'initWithdraw submitted' "$E2E_RUN/last-N3-pegout.out" && break; sleep 2; done
"$CHAOS" fault all goat http 502 0.5 --ttl 1500
"$CHAOS" fault all goat cut 0.1 --ttl 1500
wait $flow; rc=$?
"$CHAOS" clear all goat
grep -v '^\s*$' "$E2E_RUN/last-N3-pegout.out" | grep '^\[' | cut -c1-120
scenario_end N3; log "N3 rc=$rc"
