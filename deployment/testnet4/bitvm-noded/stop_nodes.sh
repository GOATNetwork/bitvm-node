#!/bin/sh
# SIGTERM lets the node release its queue claims and finish in-flight writes.
# Wait for the processes to exit before returning, so a start_nodes.sh that
# follows does not race a node that is still shutting down.
killall -TERM bitvm-noded 2>/dev/null
for _ in $(seq 1 60); do
    pgrep -x bitvm-noded >/dev/null 2>&1 || exit 0
    sleep 1
done
echo "bitvm-noded did not exit within 60s; sending SIGKILL" >&2
killall -KILL bitvm-noded 2>/dev/null
