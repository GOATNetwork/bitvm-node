#!/usr/bin/env bash
# Query a bitvm-noded JSON log (one node): time window, level, event, substring; compact one-line output.
#   logq.sh [-f <log file>] [-s 10m|2h|1d|<ISO UTC>] [-l INFO|WARN|ERROR] [-e <event>] [-g <substring>] [-n N] [-j]
#     -f  log file (default: $NODE_LOG, else stdin)     -s  since (default 10m; WARN includes ERROR)
#     -e  exact `event` field                           -g  substring anywhere in the line (ids, txids, ...)
#     -n  keep only the last N lines                    -j  raw JSON lines instead of the compact form
# Output columns: time level role event-or-target outcome message extra-fields.
set -uo pipefail
file=${NODE_LOG:-} since=10m level="" event="" grep_="" n="" raw=0
while getopts 'f:s:l:e:g:n:j' o; do case $o in f) file=$OPTARG;; s) since=$OPTARG;; l) level=${OPTARG^^};; e) event=$OPTARG;; g) grep_=$OPTARG;; n) n=$OPTARG;; j) raw=1;; *) exit 2;; esac; done
case $since in
  *s) SINCE=$(date -u -d "-${since%s} sec" +%Y-%m-%dT%H:%M:%S) ;;  *m) SINCE=$(date -u -d "-${since%m} min" +%Y-%m-%dT%H:%M:%S) ;;
  *h) SINCE=$(date -u -d "-${since%h} hour" +%Y-%m-%dT%H:%M:%S) ;; *d) SINCE=$(date -u -d "-${since%d} day" +%Y-%m-%dT%H:%M:%S) ;;
  *) SINCE=$since ;;
esac
src() { if [[ -n $file ]]; then cat -- "$file"; else cat; fi; }
{ if [[ -n $grep_ ]]; then src | grep -F -- "$grep_"; else src; fi; } \
| jq -R -r --arg since "$SINCE" --arg lv "$level" --arg e "$event" --argjson raw "$raw" '
    (try fromjson catch empty)
    | select(type=="object" and (.timestamp // "") >= $since)
    | select($lv=="" or ($lv=="WARN" and (.level=="WARN" or .level=="ERROR")) or .level==$lv)
    | select($e=="" or .event==$e)
    | if $raw==1 then tostring else
      [ .timestamp, .level, (.span.role // "-"), (.event // ((.target // "?")|split("::")|last)), (.outcome // "-"), (.message // ""),
        ( to_entries | map(select(.key|IN("timestamp","level","message","target","span","spans","event","outcome")|not))
          | map("\(.key)=\(.value|tostring|.[0:80])") | join(" ") ) ] | @tsv end' 2>/dev/null \
| { if [[ -n $n ]]; then tail -n "$n"; else cat; fi; } \
| { if (( raw )); then cat; else awk -F'\t' '{printf "%s %-5s %-10s %-28s %-12s %s  %s\n", substr($1,1,23), $2, $3, substr($4,1,28), $5, $6, $7}'; fi; }
