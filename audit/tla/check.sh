#!/usr/bin/env bash
# Check timing and protocol safety. Every nonzero TLC exit is a failure.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
JAR=${TLA2TOOLS:-$HOME/.local/share/tlaplus/tla2tools.jar}
[[ -f "$JAR" ]] || { echo "tla2tools.jar not found: run make tla-setup" >&2; exit 2; }
# Keep generated states and traces outside the repository, including on failure.
RUN=$(mktemp -d "${TMPDIR:-/tmp}/bitvm-tla.XXXXXXXX")
trap 'rm -rf "$RUN"' EXIT
cp "$HERE/TransactionGraph.tla" "$HERE/TransactionGraph.cfg" \
  "$HERE/BridgeSafety.tla" "$HERE/BridgeSafety.cfg" "$HERE/ShippedTimelockValues.tla" "$RUN/"
cd "$RUN"
# TLC_OPTS is an optional whitespace-separated list of TLC arguments.
read -r -a options <<< "${TLC_OPTS:-}"
for model in TransactionGraph BridgeSafety; do
  java -XX:+UseParallelGC -Djava.io.tmpdir="$RUN" -jar "$JAR" "${options[@]}" \
    -metadir "$RUN/states/$model" -config "$model.cfg" "$model.tla"
done
