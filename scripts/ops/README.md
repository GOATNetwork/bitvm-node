# Operator tools

Three read-only helpers inspect a running node. They query health and progress,
read structured logs, and trace an instance or graph without changing its state.

## Health overview

```bash
scripts/ops/triage.sh
```

Start here when a node appears stalled. The overview combines readiness,
backend availability, peer and chain progress, and recent warnings.

## Log queries

```bash
scripts/ops/logq.sh -s 30m -l WARN
```

The log query helper reads standard input and filters by time, severity, event,
or a plain-text match. It skips non-JSON lines and can emit raw matching records.

## Instance and graph tracing

```bash
scripts/ops/trace.sh 'instance-or-graph-id'
```

Replace the example identifier with the instance or graph being investigated.
The trace combines related protocol state, work progress, and a chronological
view of relevant events. Inspect each participant separately when comparing
behavior across nodes.

See the [node guide](../../node/README.md) for roles and execution, and the
[transaction graph](../../transaction-graph.svg) for Bitcoin claim and dispute paths.
