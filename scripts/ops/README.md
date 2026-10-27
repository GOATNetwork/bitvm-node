# Node ops scripts

Three read-only helpers for one running `bitvm-noded`. They need `bash`, `jq`, `curl`; `trace.sh` also needs
`sqlite3`. Defaults come from the environment, flags override them:

| Variable | Meaning | Default |
|---|---|---|
| `NODE_RPC` | the node's RPC base URL (`--rpc-addr`) | `http://127.0.0.1:8080` |
| `NODE_METRICS` | the metrics listener base URL (`--metrics-addr`) | `http://127.0.0.1:9090` |
| `NODE_LOG` | the node's JSON log file (stdout of `bitvm-noded`) | none |
| `NODE_DB` | the node's SQLite file (the `--db-path` without `sqlite:`) | none |
| `NODE_PID` | the node's pid, for process stats in `triage.sh` | none |

## `triage.sh` — one screen: is this node healthy, and if not, where

```
scripts/ops/triage.sh [-r RPC] [-m METRICS] [-f LOG] [-p PID] [-s 10m]
```

Prints `GET /v1/health` (readiness bits, each backend's availability with its last error, event watcher state),
the key gauges from `/metrics` (peers, lags, balances, backend probe counters, tasks whose last success is older
than 90 s, alert counters), `/v1/debug/status` and the parked / poisoned engine rows when the node was built with
`rpc-debug-endpoints`, and the WARN/ERROR lines of the last window grouped by event and outcome when a log file is
given. First thing to run when a node looks stuck.

## `logq.sh` — query the JSON log

```
scripts/ops/logq.sh [-f LOG] [-s 10m|2h|1d|2026-10-15T08:00:00] [-l INFO|WARN|ERROR] [-e EVENT] [-g SUBSTRING] [-n N] [-j]
```

One compact line per record: `time level role event-or-target outcome message extra=fields`. `-l WARN` includes
ERROR; `-e` matches the structured `event` field exactly (`maintenance_tick_result`, `engine_jobs`,
`backend_availability`, ...); `-g` is a plain substring filter applied before parsing, so an instance id, graph id
or txid is cheap even on a large file; `-j` prints the raw JSON lines. Reads stdin when no file is given, so it
composes with `journalctl -o cat` or `docker logs`.

Useful queries:

```
logq.sh -f node.log -s 30m -l WARN                       # everything that went wrong in the last half hour
logq.sh -f node.log -s 1h -e backend_availability        # when did a backend go down / come back
logq.sh -f node.log -s 2h -e engine_jobs -l WARN         # job attempts that failed on an error path
logq.sh -f node.log -s 1d -g 475a4574                    # every line naming an instance / graph / tx
```

## `trace.sh` — timeline of one peg-in instance or graph

```
scripts/ops/trace.sh <instance_id|graph_id> [-r RPC] [-d DB] [-f LOG] [-s 6h] [-n 300]
```

Resolves the related ids (the graphs of an instance, the instance of a graph), prints the RPC status, the
database rows that drive the flow (instance, graphs, `pending_graph_init`, the engine aggregate, every job with its
state / attempts / lease / last error, parked inbox events, poison rows) and the log lines naming any of the ids,
oldest first. Give it the same node's database and log; for several nodes run it once per node and compare the
`graph` and `job` lines.

## Notes

- All three only read: no RPC that changes state, the database is opened read-only.
- The log format is the node's JSON output (`tracing_subscriber` JSON with top-level `event` / `outcome` fields).
- `/v1/health` returns 503 while the node is not ready; `triage.sh` still prints its body.
- `logq.sh` skips lines that are not JSON (panic messages, stray stderr output) instead of stopping there.
