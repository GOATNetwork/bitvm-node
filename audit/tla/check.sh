#!/usr/bin/env bash
# Run the TLA+ spec table (specs.txt) through TLC and check every result
# against its tier. Used by CI (.github/workflows/ci.yml) and `make tla`.
#
#   audit/tla/check.sh                 every row
#   audit/tla/check.sh Foo.cfg         only that config
#   audit/tla/check.sh Foo.tla         every config of that spec
#
# Tiers (specs.txt):
#   pass       - a fix/baseline design; must verify, else the design regressed.
#   historical - a bug already fixed in the code; the frozen spec must still
#                reproduce its counterexample. An unexpected pass means the
#                spec drifted or the fix was reverted.
#   live       - a known, unfixed bug; while it reproduces it fails the run
#                (and blocks merge in CI). Fix the code, then move the row to
#                `historical` - the frozen spec cannot see the code fix itself.
# A run on which TLC does not finish (parse error, missing file, JVM problem)
# fails in every tier: the outcome is TLC's exit status, so a broken spec can
# never pass as "reproduces".
#
# TLA2TOOLS overrides the jar path; TLC_OPTS adds TLC flags (e.g. -workers auto).
set -u
cd "$(dirname "$0")"
JAR=${TLA2TOOLS:-$HOME/.local/share/tlaplus/tla2tools.jar}
FILTER=${1:-}
[ -f "$JAR" ] || { echo "tla2tools.jar not found at $JAR (run \`make tla-setup\`)" >&2; exit 2; }

SUMMARY=${GITHUB_STEP_SUMMARY:-/dev/null}
annotate() { [ -n "${GITHUB_ACTIONS:-}" ] && echo "::$1::$2"; return 0; }

hard_fail=0
live_open=0
matched=0
{
  echo "## TLA+ formal verification"
  echo
  echo "Every spec is run and its live TLC result reported below. Tiers:"
  echo "**pass** must verify; **historical** (fixed bug) must still reproduce"
  echo "its counterexample; **live** (unfixed bug) blocks merge while it does."
  echo "A run on which TLC does not finish fails whatever the tier."
  echo
  echo "| Spec | Tier | TLC result | Status |"
  echo "|---|---|---|---|"
} >> "$SUMMARY"

# 0 = the spec holds, 10-14 = a violation (assumption/deadlock/safety/liveness/
# assert), anything else = TLC did not finish. TLC names its state directory by
# the current second, so each run gets its own parent under states/.
run_tlc() {
  local rc=0
  # shellcheck disable=SC2086
  java -jar "$JAR" ${TLC_OPTS:-} -metadir "states/$1" -config "$1" "$2" > tlc.log 2>&1 || rc=$?
  case $rc in
    0) outcome=verified ;;
    1[0-4]) outcome=counterexample ;;
    *) outcome=failed ;;
  esac
}

while IFS='|' read -r tier cfg tla desc; do
  tier="$(echo "$tier" | tr -d '[:space:]')"
  cfg="$(echo "$cfg" | tr -d '[:space:]')"
  tla="$(echo "$tla" | tr -d '[:space:]')"
  desc="$(echo "$desc" | sed 's/^ *//; s/ *$//')"
  [ -z "$tier" ] && continue
  case "$tier" in \#*) continue ;; esac
  if [ -n "$FILTER" ] && [ "$FILTER" != "$cfg" ] && [ "$FILTER" != "$tla" ]; then continue; fi
  matched=$((matched+1))
  repro="cd audit/tla && java -jar ~/.local/share/tlaplus/tla2tools.jar -config $cfg $tla"
  run_tlc "$cfg" "$tla"
  case "$outcome" in
    verified)       tlc="verified (no violation)"; ok=1 ;;
    counterexample) tlc="counterexample found";    ok=0 ;;
    *)              tlc="TLC did not finish";      ok="" ;;
  esac
  if [ -z "$ok" ]; then
    status="TOOL FAILURE"; hard_fail=$((hard_fail+1))
    annotate error "[$tier] $cfg / $tla: TLC did not finish ($desc). Repro: $repro"
    tail -n 20 tlc.log
  else
    case "$tier" in
      pass)
        if [ "$ok" = 1 ]; then status="OK"; else
          status="REGRESSED - fix/baseline no longer verifies"; hard_fail=$((hard_fail+1))
          annotate error "[pass] $cfg / $tla did NOT verify ($desc). Repro: $repro"
        fi ;;
      historical)
        if [ "$ok" = 0 ]; then status="OK - reproduces (regression record)"; else
          status="DRIFT - no longer reproduces (spec edited or fix reverted)"; hard_fail=$((hard_fail+1))
          annotate error "[historical] $cfg / $tla unexpectedly verified ($desc) - investigate drift/revert. Repro: $repro"
        fi ;;
      live)
        if [ "$ok" = 0 ]; then
          status="OPEN - blocks merge"; live_open=$((live_open+1)); hard_fail=$((hard_fail+1))
          annotate error "OPEN BUG (blocks merge): $desc. Repro: $repro"
        else
          status="review - no longer reproduces; if fixed, move tier to historical"
          annotate warning "[live] $cfg / $tla no longer reproduces ($desc) - move its tier to 'historical' if the code is fixed. Repro: $repro"
        fi ;;
      *) status="UNKNOWN TIER"; hard_fail=$((hard_fail+1)); annotate error "unknown tier '$tier' for $cfg (use pass|historical|live)" ;;
    esac
  fi
  printf '%-10s %-44s %-24s %s\n' "$tier" "$cfg" "$tlc" "$status"
  echo "| \`$tla\` (\`$cfg\`) | $tier | $tlc | $status - $desc |" >> "$SUMMARY"
done < specs.txt
rm -f tlc.log

if [ -n "$FILTER" ] && [ "$matched" -eq 0 ]; then
  echo "no row in specs.txt matches '$FILTER'" >&2
  exit 2
fi
{
  echo
  echo "**Result: $hard_fail check(s) failing, $live_open live bug(s) open.**"
} >> "$SUMMARY"
echo "$matched run, $hard_fail failing, $live_open live bug(s) open"
if [ "$hard_fail" -gt 0 ]; then
  annotate error "$hard_fail TLA+ check(s) failed ($live_open live bug(s) block merge). See the result table in the job summary."
  exit 1
fi
