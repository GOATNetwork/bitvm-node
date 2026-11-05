#!/usr/bin/env bash
# Check timing and protocol safety. Every nonzero TLC exit is a failure.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
JAR=${TLA2TOOLS:-$HOME/.local/share/tlaplus/tla2tools.jar}
[[ -f "$JAR" ]] || { echo "tla2tools.jar not found: run make tla-setup" >&2; exit 2; }
# Keep generated states and traces outside the repository, including on failure.
RUN=$(mktemp -d "${TMPDIR:-/tmp}/bitvm-tla.XXXXXXXX")
trap 'rm -rf "$RUN"' EXIT
cp "$HERE"/*.tla "$HERE"/*.cfg "$RUN/"
cd "$RUN"
# TLC_OPTS is an optional whitespace-separated list of TLC arguments.
read -r -a options <<< "${TLC_OPTS:-}"
# Every <Model>.cfg is checked against <Model>.tla; one failure does not hide
# the results of the others.
failed=()
for cfg in "$HERE"/*.cfg; do
  model=$(basename "$cfg" .cfg)
  java -XX:+UseParallelGC -Djava.io.tmpdir="$RUN" -jar "$JAR" "${options[@]}" \
    -metadir "$RUN/states/$model" -config "$model.cfg" "$model.tla" || failed+=("$model")
done
if ((${#failed[@]})); then
  echo "TLC failed: ${failed[*]}" >&2
  exit 1
fi
