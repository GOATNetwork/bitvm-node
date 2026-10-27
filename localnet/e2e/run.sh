#!/usr/bin/env bash
# On-demand end-to-end regression of the node on the localnet (localnet/scripts/up.sh or reset.sh first):
#   e2e/run.sh                 # every case, in order
#   e2e/run.sh --list
#   e2e/run.sh pegin_happy pegout_happy challenge_take2
#   e2e/run.sh --stop-on-fail ...
# Env: E2E_CASE_TIMEOUT (seconds per case, default 1200), E2E_DELAY_TIER=fast|default (mock delays applied to the
# nodes + proof builder for the run through run/tuning.env, default fast = 2 s GC / 5 s proof; localnet.env keeps the
# manual 15/30 s), E2E_POLL_SECS (default 2).
# Each case: fresh scratch (run/e2e), pre-check (nodes ready, no chaos injection, operator stake, snapshot of the
# Failed jobs), the flow, post-check (engine clean on every node and no new Failed job, chaos status empty). run/tuning.env
# is saved before every case and restored after it on every path (pass, fail, timeout, interrupt); a restore that
# had to change something restarts the nodes and is noted in the report. Results in $LOCALNET_DATA/results/<run>/: <case>.log, report.md, report.json, logs.tar.gz
# (every node/support log written during the run); results/latest -> newest run. Exit code 0 only when nothing failed
# (a SKIP is not a failure).
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
source "$ROOT/e2e/lib.sh" >/dev/null 2>&1
E="$ROOT/e2e"; CHAOS="$ROOT/scripts/chaos.sh"
CASE_TIMEOUT=${E2E_CASE_TIMEOUT:-1200}
TIER=${E2E_DELAY_TIER:-fast}
RUN_ID=$(date -u +%Y%m%dT%H%M%SZ); RUN="$RESULTS_DIR/$RUN_ID"; mkdir -p "$RUN"; touch "$RUN/.start"
CASES_ALL=(pegin_happy pegout_happy challenge_take2 dispute_disprove backtoback pegin_restart_committee0 pegin_restart_operator pegin_restart_verifier
           goat_timeout_at_kickoff subgraph_latency proof_builder_blackhole p2p_isolate_operator boot_with_goat_down)
STOP_ON_FAIL=0; CASES=()
for a in "$@"; do case $a in --list) printf '%s\n' "${CASES_ALL[@]}"; exit 0;; --stop-on-fail) STOP_ON_FAIL=1;; *) CASES+=("$a");; esac; done
[[ ${#CASES[@]} -eq 0 ]] && CASES=("${CASES_ALL[@]}")
for c in "${CASES[@]}"; do [[ " ${CASES_ALL[*]} " == *" $c "* ]] || { echo "unknown case: $c (see --list)" >&2; rm -rf "$RUN"; exit 2; }; done

# ---- cases: each returns 0 on pass; graph ids for peg-out cases come from the lowest posted slot ----
need_graph() { local g; g=$(next_posted_graph); if [[ -z $g ]]; then log "no posted graph; running a peg-in first" >&2; "$E/flows/pegin.sh" >&2 || return 1; g=$(cat "$E2E_RUN/graph.txt"); fi; echo "$g"; }
case_pegin_happy() { "$E/flows/pegin.sh"; }
case_pegout_happy() { local g; g=$(need_graph) || return 1; "$E/flows/pegout.sh" "$g"; }
case_challenge_take2() { local g; g=$(need_graph) || return 1; "$E/flows/challenge.sh" "$g" valid; }
case_dispute_disprove() { local g rc; g=$(need_graph) || return 1; set_verdict always-invalid; "$E/flows/challenge.sh" "$g" invalid; rc=$?; set_verdict valid; return $rc; }
case_backtoback() { "$E/flows/backtoback.sh"; }
case_pegin_restart_committee0() { "$E/flows/pegin-restart.sh" committee_0; }
case_pegin_restart_operator() { "$E/flows/pegin-restart.sh" operator_0; }
case_pegin_restart_verifier() { # a 20 s solder keeps the verifier's ceremony job running long enough to be caught
  local rc before; before=$(tuning_get MOCK_GC_SOLDER_DELAY_SECS); set_tuning MOCK_GC_SOLDER_DELAY_SECS 20; NODES_SH restart verifier_0 >/dev/null 2>&1
  if wait_ready 300; then RESTART_ON_ACTION=verifier_solder "$E/flows/pegin-restart.sh" verifier_0; rc=$?; else rc=1; fi
  set_tuning MOCK_GC_SOLDER_DELAY_SECS "$before"; NODES_SH restart verifier_0 >/dev/null 2>&1; return $rc; }
case_goat_timeout_at_kickoff() { local g; g=$(need_graph) || return 1; "$E/scenarios/N2.sh" "$g"; }
case_subgraph_latency() { "$E/scenarios/N9.sh"; }
case_proof_builder_blackhole() { # the challenge flow times out while the proof is black-holed; the case passes when the graph settles in Take-2 afterwards
  local g; g=$(need_graph) || return 1; "$E/scenarios/N10.sh" "$g" || return 1; wait_log operator_0 "Prover-Assert broadcast.*$g\|$g.*Prover-Assert broadcast" 600 || return 1
  [[ -n "$(mempool)" ]] && mine 1; "$E/flows/take2.sh" "$g"; }
case_p2p_isolate_operator() { "$E/scenarios/P2.sh" && [[ "$(all_inst "$(cat "$E2E_RUN/inst.txt")")" == *"watchtower_0=RelayerL2Minted"* ]]; }
case_boot_with_goat_down() { "$E/scenarios/R2.sh" watchtower_0 && wait_ready 180; }

needs_proxy() { case $1 in goat_timeout_at_kickoff|subgraph_latency|proof_builder_blackhole|boot_with_goat_down) return 0;; *) return 1;; esac; }
needs_sudo() { case $1 in p2p_isolate_operator) return 0;; *) return 1;; esac; }
precheck() { local st; engine_snapshot || return 1; "$CHAOS" reset >/dev/null 2>&1
  if ls "$RUN_DIR/overrides"/*.env >/dev/null 2>&1 && ! "$CHAOS" proxy status 2>/dev/null | grep -q 'proxy up'; then # attached nodes need it
    "$CHAOS" proxy start >/dev/null; NODES_SH start >/dev/null 2>&1; fi
  wait_ready 240 || return 1; ensure_operator_stake || return 1
  if needs_proxy "$1"; then st=$("$CHAOS" proxy status 2>/dev/null); grep -q 'proxy up' <<<"$st" || "$CHAOS" proxy start >/dev/null
    ls "$RUN_DIR/overrides"/*.env >/dev/null 2>&1 || { "$CHAOS" attach all >/dev/null; wait_ready 240; }; fi; return 0; }
postcheck() { local ok=0 st; engine_clean || { echo "  engine not clean"; ok=1; }; st=$("$CHAOS" status 2>/dev/null)
  grep -qE 'faults: none|proxy: DOWN' <<<"$st" || { echo "  chaos faults left"; ok=1; }; grep -q 'rules: 0' <<<"$st" || { echo "  iptables rules left"; ok=1; }; return $ok; }

# ---- delay tier: written to run/tuning.env, applied by restarting the nodes + proof builder ----
TIER_VARS=(MOCK_GC_SETUP_DELAY_SECS MOCK_GC_SOLDER_DELAY_SECS MOCK_GC_VERIFY_DELAY_SECS MOCK_PROOF_OPERATOR_DELAY_SECS MOCK_PROOF_WATCHTOWER_DELAY_SECS)
tier_values() { case $1 in fast) echo "2 2 2 5 5";; default) echo "$MOCK_GC_SETUP_DELAY_SECS $MOCK_GC_SOLDER_DELAY_SECS $MOCK_GC_VERIFY_DELAY_SECS $MOCK_PROOF_OPERATOR_DELAY_SECS $MOCK_PROOF_WATCHTOWER_DELAY_SECS";; *) echo "unknown E2E_DELAY_TIER $1" >&2; exit 2;; esac; }
apply_tier() { # $1 tier -> 0 when something changed (callers restart)
  local want i changed=0; read -ra want <<<"$(tier_values "$1")"
  for i in "${!TIER_VARS[@]}"; do [[ "$(tuning_get "${TIER_VARS[$i]}")" == "${want[$i]}" ]] || { set_tuning "${TIER_VARS[$i]}" "${want[$i]}"; changed=1; }; done
  (( changed )) || return 1; return 0; }
restart_all() { "$ROOT/scripts/proof-builder.sh" stop >/dev/null 2>&1; "$ROOT/scripts/proof-builder.sh" start >/dev/null 2>&1; NODES_SH restart >/dev/null 2>&1; }

# ---- run/tuning.env around each case: saved before, restored after on every path ----
tuning_save() { sort "$RUN_DIR/tuning.env" 2>/dev/null > "$RUN/.tuning-before" || :; }
tuning_restore() { # prints a note when something had to be restored; nonzero when the restore itself failed
  local now; now=$(sort "$RUN_DIR/tuning.env" 2>/dev/null)
  [[ "$now" == "$(cat "$RUN/.tuning-before" 2>/dev/null)" ]] && return 0
  echo "tuning restored: $(diff <(echo "$now") "$RUN/.tuning-before" | grep '^[<>]' | tr '\n' ' ')"
  cp "$RUN/.tuning-before" "$RUN_DIR/tuning.env" || return 1
  restart_all; wait_ready 300 >/dev/null || { echo "nodes not ready after the tuning restore"; return 1; }; }
CASE_PID=""
on_interrupt() { [[ -n $CASE_PID ]] && kill -TERM $(descendants "$CASE_PID") "$CASE_PID" 2>/dev/null
  [[ -f "$RUN/.tuning-before" ]] && tuning_restore >/dev/null 2>&1; "$CHAOS" reset >/dev/null 2>&1; echo "interrupted" >&2; exit 130; }
trap on_interrupt INT TERM

# ---- per-case timeout: the case runs in a subshell; on expiry its whole process tree is killed ----
descendants() { local p; for p in $(ps -o pid= --ppid "$1" 2>/dev/null); do descendants "$p"; echo "$p"; done; }
run_case() { # $1 case $2 log -> rc (124 = timeout)
  local c=$1 logf=$2 pid t=0 rc
  rm -f "$E2E_RUN"/*.txt "$E2E_RUN"/last-*.out "$E2E_RUN"/failed-before.*   # nothing carries over from an earlier case
  { precheck "$c" && "case_$c"; } > "$logf" 2>&1 &
  pid=$!; CASE_PID=$pid
  while kill -0 "$pid" 2>/dev/null; do
    if (( t >= CASE_TIMEOUT )); then
      echo "[$(date -u +%H:%M:%S)] TIMEOUT: case exceeded ${CASE_TIMEOUT}s, killing it" >> "$logf"
      kill -TERM $(descendants "$pid") "$pid" 2>/dev/null; sleep 3; kill -KILL $(descendants "$pid") "$pid" 2>/dev/null
      wait "$pid" 2>/dev/null; CASE_PID=""; return 124
    fi
    sleep 5; t=$((t+5))
  done
  wait "$pid"; rc=$?; CASE_PID=""; return $rc; }

BUILD=$(git -C "$REPO_ROOT" log --oneline -1 2>/dev/null || echo "?")
T_RUN0=$(date +%s)
if apply_tier "$TIER"; then echo "applying the $TIER delay tier (restart nodes + proof builder)"; restart_all; wait_ready 300 || echo "WARN: nodes not ready after the tier restart"; fi
printf '# e2e run %s\n\nbuild: %s  tier: %s  case timeout: %ss\n\n| case | result | duration | notes |\n|---|---|---|---|\n' "$RUN_ID" "$BUILD" "$TIER" "$CASE_TIMEOUT" > "$RUN/report.md"
: > "$RUN/cases.tsv"
pass=0; fail=0; skip=0
for c in "${CASES[@]}"; do
  declare -F "case_$c" >/dev/null || { echo "unknown case $c"; continue; }
  t0=$(date +%s); echo "=== $c ($(date -u +%T))"
  if needs_sudo "$c" && ! sudo -n true 2>/dev/null; then
    res=SKIP; rc=0; prc=0; post=""; note="needs passwordless sudo (iptables)"; skip=$((skip+1)); echo "$note" > "$RUN/$c.log"
  else
    tuning_save
    run_case "$c" "$RUN/$c.log"; rc=$?
    if (( rc == 124 )); then "$CHAOS" reset >/dev/null 2>&1; NODES_SH start >/dev/null 2>&1; fi
    tnote=$(tuning_restore 2>&1); trc=$?
    post=$(postcheck 2>&1); prc=$?
    [[ -n $tnote ]] && post="$post${post:+;}$tnote"; (( trc != 0 )) && prc=1
    note=$(grep -oE 'instance=[0-9a-f-]{8}|graph=[0-9a-f-]{8}|TIMEOUT[^|]{0,60}' "$RUN/$c.log" | sort -u | tr '\n' ' ' | cut -c1-120)
    if (( rc == 0 && prc == 0 )); then res=PASS; pass=$((pass+1)); else res=FAIL; fail=$((fail+1)); fi
  fi
  "$ROOT/scripts/miner.sh" start >/dev/null 2>&1
  dur=$(( $(date +%s) - t0 ))
  printf '| %s | %s | %dm%02ds | %s %s |\n' "$c" "$res" $((dur/60)) $((dur%60)) "$note" "$(tr '\n' ';' <<<"$post")" >> "$RUN/report.md"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$c" "$res" "$dur" "$rc" "$prc" "$note" "$(tr '\n' ';' <<<"$post")" >> "$RUN/cases.tsv"
  echo "    $res in ${dur}s rc=$rc post=$prc $note"
  if [[ $res == FAIL ]] && (( STOP_ON_FAIL )); then break; fi
done
if [[ $TIER != default ]]; then
  if apply_tier default; then echo "restoring the default delay tier (restart nodes + proof builder)"; restart_all; fi
fi
TOTAL=$(( $(date +%s) - T_RUN0 ))
printf '\n%d passed, %d failed, %d skipped. tip %s. total %dm%02ds.\n' "$pass" "$fail" "$skip" "$(tip)" $((TOTAL/60)) $((TOTAL%60)) >> "$RUN/report.md"
python3 - "$RUN" "$RUN_ID" "$BUILD" "$TIER" "$CASE_TIMEOUT" "$T_RUN0" "$TOTAL" "$pass" "$fail" "$skip" <<'PY'
import json, sys, datetime
run, rid, build, tier, ct, t0, total, p, f, s = sys.argv[1:]
cases = []
for line in open(f"{run}/cases.tsv"):
    c, res, dur, rc, prc, note, post = (line.rstrip("\n").split("\t") + [""] * 7)[:7]
    cases.append({"case": c, "result": res, "duration_secs": int(dur), "rc": int(rc), "postcheck_rc": int(prc), "notes": note.strip(), "postcheck": post.strip(), "log": f"{c}.log"})
doc = {"run": rid, "build": build, "tier": tier, "case_timeout_secs": int(ct),
       "started": datetime.datetime.fromtimestamp(int(t0), datetime.timezone.utc).isoformat(), "total_secs": int(total),
       "passed": int(p), "failed": int(f), "skipped": int(s), "cases": cases}
json.dump(doc, open(f"{run}/report.json", "w"), indent=2); open(f"{run}/report.json", "a").write("\n")
PY
rm -f "$RUN/cases.tsv"
# every node / support log written during the run, relative to logs/
( cd "$LOGS_DIR" && find . -type f -name '*.log' -newer "$RUN/.start" | sed 's#^\./##' | tar -czf "$RUN/logs.tar.gz" -T - 2>/dev/null ) || true
rm -f "$RUN/.start"
cat "$RUN/report.md"; ln -sfn "$RUN" "$RESULTS_DIR/latest"
(( fail == 0 ))
