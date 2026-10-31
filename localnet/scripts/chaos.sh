#!/usr/bin/env bash
# Fault injection for the localnet.
#   proxy start|stop|status                 fault proxy (tools/faultproxy.py, ports PROXY_PORT_BASE+0..19, control CHAOS_CTRL_PORT)
#   attach <role|all> | detach <role|all>   point a role's backend URLs at its proxies (run/overrides/<role>.env) + restart it
#   fault <role|all> <btc|goat|graph|proof> <type> [args] [--ttl N]
#         latency <ms> [jitter] | down | blackhole [secs] | cut <p> | http <code> [p] | slow <ms_per_kb>
#         | stall [secs] | corrupt [p] | flap <on> <off>
#   clear [role] [backend] [type]           clear proxy faults
#   p2p cut <roleA> <roleB> | isolate <role> | heal | show
#         iptables chain <COMPOSE_PROJECT>_CHAOS on INPUT -i lo, rules only on this localnet's p2p port pairs
#   freeze <role> [secs] | thaw <role>      SIGSTOP / SIGCONT (secs: auto-thaw from a detached timer)
#   infra pause|unpause <anvil|electrs|graph-node>
#   status                                  everything currently injected (must be empty between scenarios)
#   reset                                   clear + heal + thaw all + unpause all
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
source "$ROOT/scripts/localnet.env"
ROLES=(committee_0 committee_1 operator_0 verifier_0 watchtower_0)
BACKENDS=(btc goat graph proof)
CTRL=http://127.0.0.1:$CHAOS_CTRL_PORT
PIDF="$RUN_DIR/faultproxy.pid"; LOG="$LOGS_DIR/faultproxy.log"; OVR="$RUN_DIR/overrides"
CHAIN=${COMPOSE_PROJECT^^}_CHAOS
mkdir -p "$RUN_DIR" "$OVR" "$LOGS_DIR"

die() { echo "chaos: $*" >&2; exit 2; }
role_idx() { local i; for i in "${!ROLES[@]}"; do [[ ${ROLES[$i]} == "$1" ]] && { echo "$i"; return; }; done; die "unknown role $1"; }
backend_idx() { local i; for i in "${!BACKENDS[@]}"; do [[ ${BACKENDS[$i]} == "$1" ]] && { echo "$i"; return; }; done; die "unknown backend $1"; }
proxy_port() { echo $((PROXY_PORT_BASE + $(role_idx "$1") * 4 + $(backend_idx "$2"))); }
p2p_port() { echo $((P2P_PORT_BASE + $(role_idx "$1"))); }
node_pid() { local f="$RUN_DIR/nodes/$1.pid"; [[ -f $f ]] && cat "$f"; }
roles_of() { if [[ $1 == all ]]; then printf '%s\n' "${ROLES[@]}"; else role_idx "$1" >/dev/null && echo "$1"; fi; }
ctl() { curl -s --max-time 5 -X "$1" "$CTRL$2" ${3:+-d "$3"} -H 'content-type: application/json'; }

proxy_pid() { [[ -f $PIDF ]] && cat "$PIDF"; }
proxy_alive() { local p; p=$(proxy_pid); [[ -n $p && -d /proc/$p ]] && tr '\0' ' ' < "/proc/$p/cmdline" | grep -q faultproxy.py; }

cmd_proxy() {
  case "${1:-status}" in
    start) if proxy_alive; then echo "proxy already running (pid $(proxy_pid))"; return; fi
           PORT_BASE="$PORT_BASE" nohup python3 "$ROOT/tools/faultproxy.py" >> "$LOG" 2>&1 & echo $! > "$PIDF"; sleep 1
           proxy_alive && echo "proxy started (pid $(proxy_pid)): $(ctl GET /health)" || { echo "proxy FAILED"; tail -3 "$LOG"; return 1; } ;;
    stop)  if proxy_alive; then kill -TERM "$(proxy_pid)"; sleep 1; echo "proxy stopped"; else echo "proxy not running"; fi; rm -f "$PIDF" ;;
    status) if proxy_alive; then echo "proxy up (pid $(proxy_pid)) $(ctl GET /health)"; else echo "proxy DOWN"; fi ;;
    *) die "proxy start|stop|status" ;;
  esac
}

write_override() { # role
  local r=$1 env="$NODES_DIR/$r/.env" gw sw
  gw=$(grep '^GOAT_GATEWAY_EVENT_THE_GRAPH_URL=' "$env" | cut -d= -f2- | sed -E "s#http://127.0.0.1:[0-9]+#http://127.0.0.1:$(proxy_port "$r" graph)#")
  sw=$(grep '^GOAT_SWAP_EVENT_THE_GRAPH_URL=' "$env" | cut -d= -f2- | sed -E "s#http://127.0.0.1:[0-9]+#http://127.0.0.1:$(proxy_port "$r" graph)#")
  cat > "$OVR/$r.env" <<EOT
# written by scripts/chaos.sh attach -- backend URLs of $r go through tools/faultproxy.py
BTC_CHAIN_URL=http://127.0.0.1:$(proxy_port "$r" btc)
GOAT_CHAIN_URL=http://127.0.0.1:$(proxy_port "$r" goat)
GOAT_GATEWAY_EVENT_THE_GRAPH_URL=$gw
GOAT_SWAP_EVENT_THE_GRAPH_URL=$sw
GOAT_PROOF_BUILD_URL=http://127.0.0.1:$(proxy_port "$r" proof)
EOT
}

cmd_attach() { proxy_alive || die "start the proxy first"; local r; for r in $(roles_of "${1:?role|all}"); do write_override "$r"; done
               "$ROOT/scripts/nodes.sh" restart $(roles_of "$1"); }
cmd_detach() { local r; for r in $(roles_of "${1:?role|all}"); do rm -f "$OVR/$r.env"; done; "$ROOT/scripts/nodes.sh" restart $(roles_of "$1"); }

cmd_fault() {
  local role=${1:?role|all} backend=${2:?backend} type=${3:?type}; shift 3
  local ttl=600 params='{}'
  local args=(); while [[ $# -gt 0 ]]; do if [[ $1 == --ttl ]]; then ttl=$2; shift 2; else args+=("$1"); shift; fi; done
  case $type in
    latency) params="{\"ms\":${args[0]:?ms},\"jitter\":${args[1]:-0}}" ;;
    down) ;;
    blackhole) [[ -n ${args[0]:-} ]] && params="{\"secs\":${args[0]}}" ;;
    cut) params="{\"p\":${args[0]:?p}}" ;;
    http) params="{\"code\":${args[0]:?code},\"p\":${args[1]:-1}}" ;;
    slow) params="{\"ms_per_kb\":${args[0]:?ms_per_kb}}" ;;
    stall) [[ -n ${args[0]:-} ]] && params="{\"secs\":${args[0]}}" ;;
    corrupt) params="{\"p\":${args[0]:-1}}" ;;
    flap) params="{\"on\":${args[0]:?on},\"off\":${args[1]:?off}}" ;;
    *) die "unknown fault type $type" ;;
  esac
  [[ $role == all ]] || role_idx "$role" >/dev/null; backend_idx "$backend" >/dev/null
  echo "fault $role/$backend $type $params ttl=$ttl -> $(ctl POST /fault "{\"role\":\"$role\",\"backend\":\"$backend\",\"type\":\"$type\",\"params\":$params,\"ttl\":$ttl}")"
}
cmd_clear() { local b="{"; [[ -n ${1:-} ]] && b+="\"role\":\"$1\","; [[ -n ${2:-} ]] && b+="\"backend\":\"$2\","; [[ -n ${3:-} ]] && b+="\"type\":\"$3\","; b="${b%,}}"
              echo "clear -> $(ctl POST /clear "$b")"; }

ipt() { sudo -n iptables "$@"; }
chain_ensure() { ipt -N $CHAIN 2>/dev/null || true; ipt -C INPUT -i lo -j $CHAIN 2>/dev/null || ipt -I INPUT 1 -i lo -j $CHAIN; }
cut_pair() { # pa pb : drop both directions + kill established
  local pa=$1 pb=$2
  ipt -C $CHAIN -p tcp --sport "$pa" --dport "$pb" -j DROP 2>/dev/null || ipt -A $CHAIN -p tcp --sport "$pa" --dport "$pb" -j DROP
  ipt -C $CHAIN -p tcp --sport "$pb" --dport "$pa" -j DROP 2>/dev/null || ipt -A $CHAIN -p tcp --sport "$pb" --dport "$pa" -j DROP
  sudo -n ss -K -tn "sport = :$pa and dport = :$pb" >/dev/null 2>&1 || true
  sudo -n ss -K -tn "sport = :$pb and dport = :$pa" >/dev/null 2>&1 || true
}
cmd_p2p() {
  case "${1:-show}" in
    cut) chain_ensure; cut_pair "$(p2p_port "${2:?roleA}")" "$(p2p_port "${3:?roleB}")"; echo "p2p cut $2 <-> $3"; ipt -S $CHAIN ;;
    isolate) chain_ensure; local r; for r in "${ROLES[@]}"; do [[ $r == "$2" ]] || cut_pair "$(p2p_port "${2:?role}")" "$(p2p_port "$r")"; done; echo "p2p isolated $2"; ipt -S $CHAIN ;;
    heal) ipt -F $CHAIN 2>/dev/null; ipt -D INPUT -i lo -j $CHAIN 2>/dev/null; ipt -X $CHAIN 2>/dev/null; echo "p2p healed (chain $CHAIN removed)" ;;
    show) ipt -S $CHAIN 2>/dev/null || echo "p2p: no $CHAIN chain" ;;
    *) die "p2p cut|isolate|heal|show" ;;
  esac
}

cmd_freeze() { local r=${1:?role} secs=${2:-} pid; pid=$(node_pid "$r"); [[ -n $pid && -d /proc/$pid ]] || die "$r not running"
  kill -STOP "$pid" && echo "$r (pid $pid) FROZEN${secs:+ for ${secs}s}"
  [[ -n $secs ]] && nohup bash -c "sleep $secs; kill -CONT $pid 2>/dev/null" >/dev/null 2>&1 & true; }
cmd_thaw() { local pid; pid=$(node_pid "${1:?role}"); [[ -n $pid ]] && kill -CONT "$pid" 2>/dev/null && echo "$1 thawed"; }
cmd_infra() { docker "${1:?pause|unpause}" "$COMPOSE_PROJECT-${2:?name}" >/dev/null && echo "$COMPOSE_PROJECT-$2 ${1}d"; }

cmd_status() {
  echo "--- chaos status ---"
  if proxy_alive; then local f; f=$(ctl GET /faults); echo "  proxy faults: $([[ $f == '{}' ]] && echo none || echo "$f")"; else echo "  proxy: DOWN"; fi
  local rules; rules=$(ipt -S $CHAIN 2>/dev/null | grep -c -- '-A') ; echo "  iptables $CHAIN rules: ${rules:-0}"; ipt -S $CHAIN 2>/dev/null | grep -- '-A' | sed 's/^/     /'
  local r pid st; for r in "${ROLES[@]}"; do pid=$(node_pid "$r"); [[ -n $pid && -f /proc/$pid/status ]] && { st=$(awk '/^State:/{print $2}' "/proc/$pid/status"); [[ $st == T ]] && echo "  FROZEN: $r (pid $pid)"; }; done
  local paused; paused=$(docker ps --filter status=paused --format '{{.Names}}' | grep "^$COMPOSE_PROJECT-" || true); [[ -n $paused ]] && echo "  paused containers: $paused"
  echo "  overrides: $(ls "$OVR" 2>/dev/null | tr '\n' ' ')"
}
cmd_reset() { proxy_alive && cmd_clear; cmd_p2p heal; local r; for r in "${ROLES[@]}"; do cmd_thaw "$r" >/dev/null; done
              docker ps --filter status=paused --format '{{.Names}}' | grep "^$COMPOSE_PROJECT-" | xargs -r docker unpause >/dev/null; cmd_status; }

cmd=${1:-status}; shift || true
case $cmd in
  proxy) cmd_proxy "$@" ;; attach) cmd_attach "$@" ;; detach) cmd_detach "$@" ;;
  fault) cmd_fault "$@" ;; clear) cmd_clear "$@" ;; p2p) cmd_p2p "$@" ;;
  freeze) cmd_freeze "$@" ;; thaw) cmd_thaw "$@" ;; infra) cmd_infra "$@" ;;
  status) cmd_status ;; reset) cmd_reset ;;
  *) sed -n '2,16p' "$0"; exit 2 ;;
esac
