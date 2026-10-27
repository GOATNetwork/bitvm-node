#!/usr/bin/env bash
# Query the JSON node logs (one file per boot under logs/nodes/<role>/).
#   scripts/logq.sh [-r role|all] [-s 10m|2h|1d|<ISO-UTC>] [-l INFO|WARN|ERROR] [-e event] [-g substring] [-n N] [-a] [-j]
#     -r  role (default all)          -s  since (default 10m; WARN includes ERROR)
#     -e  exact `event` field         -g  substring anywhere in the JSON line (ids, txids, ...)
#     -n  keep the last N lines       -a  all boot files of the role, not only `current`
#     -j  raw JSON lines instead of the compact form
# Output: time level role event/target outcome message extra-fields, merged across roles by time.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
source "$ROOT/scripts/localnet.env"
ROLES=(committee_0 committee_1 operator_0 verifier_0 watchtower_0)
role=all since=10m level="" event="" grep_="" n="" all=0 raw=0
while getopts 'r:s:l:e:g:n:aj' o; do case $o in r) role=$OPTARG;; s) since=$OPTARG;; l) level=${OPTARG^^};; e) event=$OPTARG;; g) grep_=$OPTARG;; n) n=$OPTARG;; a) all=1;; j) raw=1;; *) exit 2;; esac; done
case $since in
  *s) SINCE=$(date -u -d "-${since%s} sec" +%Y-%m-%dT%H:%M:%S) ;;  *m) SINCE=$(date -u -d "-${since%m} min" +%Y-%m-%dT%H:%M:%S) ;;
  *h) SINCE=$(date -u -d "-${since%h} hour" +%Y-%m-%dT%H:%M:%S) ;; *d) SINCE=$(date -u -d "-${since%d} day" +%Y-%m-%dT%H:%M:%S) ;;
  *) SINCE=$since ;;
esac
files_of() { local d="$LOGS_DIR/nodes/$1"; if (( all )); then ls "$d"/*.log 2>/dev/null; else readlink -f "$d/current" 2>/dev/null; fi; }
targets=("${ROLES[@]}"); [[ $role != all ]] && targets=("$role")
{
for r in "${targets[@]}"; do
  for f in $(files_of "$r"); do
    [[ -n $grep_ ]] && src="grep -F -- \"$grep_\" \"$f\"" || src="cat \"$f\""
    eval "$src" | jq -R -r --arg since "$SINCE" --arg lv "$level" --arg e "$event" --arg role "$r" --argjson raw "$raw" '
      (try fromjson catch empty)
    | select(type=="object" and (.timestamp // "") >= $since)
      | select($lv=="" or ($lv=="WARN" and (.level=="WARN" or .level=="ERROR")) or .level==$lv)
      | select($e=="" or .event==$e)
      | if $raw==1 then tostring else
        [ .timestamp, .level, $role, (.event // ((.target // "?")|split("::")|last)), (.outcome // "-"), (.message // ""),
          ( to_entries | map(select(.key|IN("timestamp","level","message","target","span","spans","event","outcome")|not))
            | map("\(.key)=\(.value|tostring|.[0:80])") | join(" ") ) ] | @tsv end' 2>/dev/null
  done
done
} | sort | { if [[ -n $n ]]; then tail -n "$n"; else cat; fi; } | { if (( raw )); then cat; else awk -F'\t' '{printf "%s %-5s %-12s %-28s %-12s %s  %s\n", substr($1,12,12), $2, $3, substr($4,1,28), $5, $6, $7}'; fi; }
