#!/usr/bin/env bash
# Run the TLA+ check table (checks.txt) through TLC and judge every result
# against its tier. Used by CI (.github/workflows/ci.yml) and `make tla`.
#
#   audit/tla/check.sh                                  every row
#   audit/tla/check.sh crates/engine                    every config under a code area
#   audit/tla/check.sh DisputeObligations               every config of one spec
#   audit/tla/check.sh DisputeObligations/C1.cfg        one config (or its full path)
#
# Layout: specs/<area>/<Spec>.tla holds the modules, laid out like the code
# they model; configs/<area>/<Spec>/<Name>.cfg holds that spec's configs.
# TLC only resolves EXTENDS in the spec's own directory, so every module is
# copied into one flat directory (states/lib) and run from there; module
# names are unique across specs/.
#
# Tiers (checks.txt). Only the current code is checked: no row models old,
# pre-fix code.
#   pass       - models the current code; must verify. A fixed bug's check
#                lives here, so a regression fails the run.
#   live       - models the current code with a known, unfixed bug; fails the
#                run (and blocks merge in CI) while it reproduces. When the code
#                is fixed, change the config to model the fix and make it `pass`.
#                A live row that stops reproducing without that is an error too
#                (the model drifted from the code).
#   design     - a proposed fix for a live bug, not in the code yet; must
#                verify. Becomes the `pass` row once the fix lands.
#   boundary   - a fix design outside its `ParamsOK` condition, or an
#                insufficient fix; must find a counterexample, showing the
#                condition (or the missing part) is necessary.
# A run on which TLC does not finish (parse error, missing file, JVM problem)
# fails in every tier: the outcome is TLC's exit status, so a broken spec can
# never pass as "reproduces".
#
# TLA2TOOLS overrides the jar path; TLC_OPTS adds TLC flags (e.g. -workers auto).
set -u
cd "$(dirname "$0")"
HERE=$PWD
JAR=${TLA2TOOLS:-$HOME/.local/share/tlaplus/tla2tools.jar}
FILTER=${1:-}
FILTER=${FILTER#configs/}
[ -f "$JAR" ] || { echo "tla2tools.jar not found at $JAR (run \`make tla-setup\`)" >&2; exit 2; }

# Flat module directory. A duplicate module name would make the run ambiguous.
LIB=states/lib
rm -rf "$LIB" && mkdir -p "$LIB" states/tmp
dups=$(find specs -name '*.tla' -printf '%f\n' | sort | uniq -d)
[ -z "$dups" ] || { echo "duplicate module names under specs/: $dups" >&2; exit 2; }
find specs -name '*.tla' -exec cp {} "$LIB/" \;

SUMMARY=${GITHUB_STEP_SUMMARY:-/dev/null}
annotate() { [ -n "${GITHUB_ACTIONS:-}" ] && echo "::$1::$2"; return 0; }

hard_fail=0
live_open=0
matched=0
{
  echo "## TLA+ formal verification"
  echo
  echo "Every spec models the current code (or a proposed fix) and is run here."
  echo "Tiers: **pass** (current code) and **design** (proposed fix) must verify;"
  echo "**live** (unfixed bug in the current code) blocks merge while it reproduces;"
  echo "**boundary** (fix outside its parameter condition, or insufficient) must fail."
  echo
  echo "| Config | Tier | TLC result | Status |"
  echo "|---|---|---|---|"
} >> "$SUMMARY"

# 0 = the spec holds, 10-14 = a violation (assumption/deadlock/safety/liveness/
# assert), anything else = TLC did not finish. TLC names its state directory by
# the current second, so each config gets its own parent under states/run/.
# java.io.tmpdir is private: TLC unpacks its standard modules there, and a
# shared /tmp breaks parallel runs.
run_tlc() {
  local rc=0
  # shellcheck disable=SC2086
  java -XX:+UseParallelGC -Djava.io.tmpdir="$HERE/states/tmp" -jar "$JAR" ${TLC_OPTS:-} \
    -metadir "$HERE/states/run/$1" -config "$HERE/configs/$1" "$LIB/$2.tla" > states/tlc.log 2>&1 || rc=$?
  case $rc in
    0) outcome=verified ;;
    1[0-4]) outcome=counterexample ;;
    *) outcome=failed ;;
  esac
}

while IFS='|' read -r tier cfg desc; do
  tier="$(echo "$tier" | tr -d '[:space:]')"
  cfg="$(echo "$cfg" | tr -d '[:space:]')"
  desc="$(echo "$desc" | sed 's/^ *//; s/ *$//')"
  [ -z "$tier" ] && continue
  case "$tier" in \#*) continue ;; esac
  spec=$(basename "$(dirname "$cfg")")
  area=$(dirname "$(dirname "$cfg")")
  short="$spec/$(basename "$cfg")"
  if [ -n "$FILTER" ]; then
    case "$FILTER" in
      "$cfg" | "$short" | "$spec" | "$spec.tla" | "${area}" | "${area}/") ;;
      *) case "$cfg" in "${FILTER%/}"/*) ;; *) continue ;; esac ;;
    esac
  fi
  matched=$((matched+1))
  repro="make tla SPEC=$short"
  if [ ! -f "configs/$cfg" ] || [ ! -f "specs/$area/$spec.tla" ]; then
    outcome=failed; echo "missing configs/$cfg or specs/$area/$spec.tla" > states/tlc.log
  else
    run_tlc "$cfg" "$spec"
  fi
  case "$outcome" in
    verified)       tlc="verified (no violation)"; ok=1 ;;
    counterexample) tlc="counterexample found";    ok=0 ;;
    *)              tlc="TLC did not finish";      ok="" ;;
  esac
  if [ -z "$ok" ]; then
    status="TOOL FAILURE"; hard_fail=$((hard_fail+1))
    annotate error "[$tier] $cfg: TLC did not finish ($desc). Repro: $repro"
    tail -n 20 states/tlc.log
  else
    case "$tier" in
      pass|design)
        if [ "$ok" = 1 ]; then status="OK"; else
          status="REGRESSED - no longer verifies"; hard_fail=$((hard_fail+1))
          annotate error "[$tier] $cfg did NOT verify ($desc). Repro: $repro"
        fi ;;
      boundary)
        if [ "$ok" = 0 ]; then status="OK - violated as required (condition is necessary)"; else
          status="LOOSE - holds outside its condition; tighten it"; hard_fail=$((hard_fail+1))
          annotate error "[boundary] $cfg verified ($desc) - the condition is looser than modeled. Repro: $repro"
        fi ;;
      live)
        if [ "$ok" = 0 ]; then
          status="OPEN - blocks merge"; live_open=$((live_open+1)); hard_fail=$((hard_fail+1))
          annotate error "OPEN BUG (blocks merge): $desc. Repro: $repro"
        else
          status="DRIFT - no longer reproduces; if the code is fixed, model the fix and make it pass"
          hard_fail=$((hard_fail+1))
          annotate error "[live] $cfg no longer reproduces ($desc) - if the code is fixed, change the config to model the fix and move the row to 'pass'; otherwise the model drifted. Repro: $repro"
        fi ;;
      *) status="UNKNOWN TIER"; hard_fail=$((hard_fail+1)); annotate error "unknown tier '$tier' for $cfg (use pass|live|design|boundary)" ;;
    esac
  fi
  printf '%-10s %-66s %-24s %s\n' "$tier" "$cfg" "$tlc" "$status"
  echo "| \`$cfg\` | $tier | $tlc | $status - $desc |" >> "$SUMMARY"
done < checks.txt
rm -f states/tlc.log

if [ -n "$FILTER" ] && [ "$matched" -eq 0 ]; then
  echo "no row in checks.txt matches '$FILTER'" >&2
  exit 2
fi
# every config file must be in the table, so none silently stops being checked
unlisted=$(cd configs && find . -name '*.cfg' | sed 's|^\./||' | sort | comm -23 - <(grep -vE '^\s*(#|$)' ../checks.txt | awk -F'|' '{gsub(/ /,"",$2); print $2}' | sort))
if [ -z "$FILTER" ] && [ -n "$unlisted" ]; then
  echo "configs not listed in checks.txt:" >&2; echo "$unlisted" >&2
  annotate error "configs not listed in checks.txt: $(echo $unlisted)"
  hard_fail=$((hard_fail+1))
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
