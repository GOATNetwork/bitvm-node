#!/bin/bash

args=(--rpc-addr 0.0.0.0:9100 --db-path /var/data/bitvm-node-0.db --p2p-port 8443)

if [ -n "${BOOTNODES:-}" ]; then
    args+=(--bootnodes "$BOOTNODES")
fi

if [ -n "${METRICS_ADDR:-}" ]; then
    args+=(--metrics-addr "$METRICS_ADDR")
fi

exec bitvm-noded "${args[@]}"
