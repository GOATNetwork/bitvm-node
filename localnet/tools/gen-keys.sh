#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Generate every identity of the localnet and write
#   $LOCALNET_DATA/state/keys.json   (machine readable, source of truth)
#   $LOCALNET_DATA/state/keys.env    (shell-sourceable convenience export)
#   $LOCALNET_DATA/state/master-seed.txt (chmod 600)
#
# TEST-ONLY KEYS. Everything here is for an isolated regtest/anvil sandbox.
#
# Deterministic: every secret is  sha256("bvlocal-localnet-keys-v1|<role>|<purpose>|<ctr>|<master seed>").
# Needs the node binary in $BIN_DIR (scripts/install-bins.sh) and cast.
#   ./gen-keys.sh                  -> reuse state/master-seed.txt if present, else create a new random one
#   MASTER_SEED=<64hex> ./gen-keys.sh --force   -> recreate an exact earlier key set
#   ./gen-keys.sh --force          -> overwrite state/keys.json with the same seed
#   NEW_SEED=1 ./gen-keys.sh --force            -> brand new random seed (all identities change)
#
# Verification (always run, the script exits non-zero on any mismatch):
#   * BTC pubkey / funding address  vs  `bitvm-noded key funding-address` (the node's own code path)
#   * BTC pubkey                    vs  `cast wallet public-key`
#   * GOAT address                  vs  `cast wallet address`
#   * PEER_KEY/PeerId encoding      vs  a fresh `bitvm-noded key peer` sample re-derived from its seed
# ---------------------------------------------------------------------------
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
source "$ROOT/scripts/localnet.env"
TOOLS=$ROOT/tools
STATE=$STATE_DIR
NODE_BIN=$BIN_DIR/bitvm-noded
[[ -x "$NODE_BIN" ]] || { echo "missing $NODE_BIN (run scripts/install-bins.sh)" >&2; exit 1; }
mkdir -p "$TMP_DIR"
FORCE=0
[[ "${1:-}" == "--force" ]] && FORCE=1

mkdir -p "$STATE"
if [[ -f "$STATE/keys.json" && $FORCE -eq 0 ]]; then
  echo "state/keys.json already exists - refusing to overwrite (use --force)" >&2
  exit 1
fi

# --- master seed -----------------------------------------------------------
if [[ -n "${MASTER_SEED:-}" ]]; then
  SEED="$MASTER_SEED"
elif [[ -f "$STATE/master-seed.txt" && "${NEW_SEED:-0}" != "1" ]]; then
  SEED=$(tr -d '[:space:]' < "$STATE/master-seed.txt")
else
  SEED=$(openssl rand -hex 32)
fi
[[ ${#SEED} -eq 64 ]] || { echo "MASTER_SEED must be 64 hex chars" >&2; exit 1; }
printf '%s\n' "$SEED" > "$STATE/master-seed.txt"
chmod 600 "$STATE/master-seed.txt"

# --- a fresh node-generated peer key, used only to validate our encoder ----
PEER_SAMPLE=$("$NODE_BIN" key peer)

MASTER_SEED="$SEED" PEER_SAMPLE="$PEER_SAMPLE" TOOLS="$TOOLS" ANVIL_CHAIN_ID="$ANVIL_CHAIN_ID" python3 - "$STATE" <<'PYEOF'
import base64, datetime, json, os, sys
sys.path.insert(0, os.environ["TOOLS"])
from keyderive import (derive_secret, evm_address, libp2p_peer_key, p2wsh_funding_address,
                       peer_id_to_bytes, secp_pubkey, selftest, wif)

selftest()
state = sys.argv[1]
seed = os.environ["MASTER_SEED"]

# sanity: our libp2p encoder must reproduce a key the node itself generated
lines = dict(l.split("=", 1) for l in os.environ["PEER_SAMPLE"].strip().splitlines())
sample_seed = base64.b64decode(lines["PEER_KEY"])[4:36]
pk, pid, _, _ = libp2p_peer_key(sample_seed)
assert pk == lines["PEER_KEY"], "PEER_KEY encoding mismatch vs bitvm-noded key peer"
assert pid == lines["PEER_ID"], "PeerId encoding mismatch vs bitvm-noded key peer"

# role -> (wants btc key, wants peer key, wants goat key)
ROLES = [
    ("deployer",     False, False, True),
    ("committee_0",  True,  True,  True),
    ("committee_1",  True,  True,  True),
    ("operator_0",   True,  True,  True),
    ("verifier_0",   True,  True,  True),
    ("watchtower_0", True,  True,  True),
    ("user_0",       True,  False, True),
]

out = {
    "_note": ("TEST-ONLY KEYS for the isolated BitVM2 localnet (bitcoin regtest + local anvil, "
              "all endpoints on 127.0.0.1). They control nothing of value "
              "and must never be reused on any public network."),
    "_generated_by": "localnet/tools/gen-keys.sh (deterministic from master_seed)",
    "_generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    "master_seed": seed,
    "derivation": {
        "scheme": "sha256(\"bvlocal-localnet-keys-v1|<role>|<purpose>|<counter>|<master_seed_bytes>\")",
        "purposes": {"bitvm": "BITVM_SECRET (secp256k1)",
                     "goat": "GOAT_PRIVATE_KEY (secp256k1/EVM)",
                     "peer": "ed25519 seed for PEER_KEY"},
    },
    "bitcoin_network": "regtest",
    "goat_chain_id": int(os.environ["ANVIL_CHAIN_ID"]),
    "roles": {},
}

for role, want_btc, want_peer, want_goat in ROLES:
    entry = {}
    if want_btc:
        sk = derive_secret(seed, role, "bitvm")
        comp, xonly, uncomp, prefix = secp_pubkey(sk)
        entry["BITVM_SECRET"] = sk                      # 64 hex, NO 0x  (node/src/env.rs get_bitvm_secret)
        entry["btc_pubkey_compressed"] = comp           # 33 B, node_pubkey / NodeInfo.btc_pub_key
        entry["btc_pubkey_xonly"] = xonly               # 32 B, no 0x
        entry["btc_pubkey_xonly_0x"] = "0x" + xonly     # bytes32 form for the contracts
        entry["btc_pubkey_prefix"] = "0x" + prefix      # registerPubkey(bytes1 pubkeyPrefix)
        entry["btc_pubkey_uncompressed_xy"] = "0x" + uncomp
        entry["btc_key_evm_address"] = evm_address(uncomp)  # what ecrecover must return in registerPubkey
        entry["btc_funding_address_regtest"] = p2wsh_funding_address(comp, "bcrt")
        entry["btc_wif_regtest"] = wif(sk)
    if want_peer:
        pseed = derive_secret(seed, role, "peer")
        peer_key, peer_id, peer_bytes, ed_pub = libp2p_peer_key(bytes.fromhex(pseed))
        entry["PEER_KEY"] = peer_key
        entry["peer_id"] = peer_id
        entry["peer_id_bytes"] = peer_bytes             # CommitteeManagement.registerPeerId / isVerifier
        entry["peer_ed25519_pubkey"] = "0x" + ed_pub
        assert peer_id_to_bytes(peer_id) == peer_bytes
    if want_goat:
        gsk = derive_secret(seed, role, "goat")
        _, _, guncomp, _ = secp_pubkey(gsk)
        entry["GOAT_PRIVATE_KEY"] = "0x" + gsk          # alloy PrivateKeySigner, 0x optional
        entry["goat_address"] = evm_address(guncomp)    # GOAT_ADDRESS / EVM address
    out["roles"][role] = entry

with open(os.path.join(state, "keys.json"), "w") as f:
    json.dump(out, f, indent=2)
    f.write("\n")

# shell-sourceable form: <ROLE>_<FIELD>
ABBR = {"deployer": "DEPLOYER", "committee_0": "C0", "committee_1": "C1", "operator_0": "OP0",
        "verifier_0": "VF0", "watchtower_0": "WT0", "user_0": "USER0"}
with open(os.path.join(state, "keys.env"), "w") as f:
    f.write("# TEST-ONLY keys for the localnet - generated by localnet/tools/gen-keys.sh\n")
    f.write("# source this file, then use e.g. $C0_BITVM_SECRET, $OP0_GOAT_ADDRESS\n")
    for role, entry in out["roles"].items():
        p = ABBR[role]
        f.write(f"\n# ---- {role} ----\n")
        for k, v in entry.items():
            f.write(f'export {p}_{k.upper()}="{v}"\n')
print("wrote state/keys.json and state/keys.env")
PYEOF

chmod 600 "$STATE/keys.json" "$STATE/keys.env"

# --- verification against the node binary and cast -------------------------
echo "--- verification ---"
FAIL=0
verify_role() {
  local role=$1
  local sk pub_expect addr_expect comp xonly goat_sk goat_addr
  sk=$(python3 -c "import json;d=json.load(open('$STATE/keys.json'));print(d['roles']['$role'].get('BITVM_SECRET',''))")
  if [[ -n "$sk" ]]; then
    comp=$(python3 -c "import json;d=json.load(open('$STATE/keys.json'));print(d['roles']['$role']['btc_pubkey_compressed'])")
    addr_expect=$(python3 -c "import json;d=json.load(open('$STATE/keys.json'));print(d['roles']['$role']['btc_funding_address_regtest'])")
    # (1) node's own code path: BITVM_SECRET -> get_node_pubkey -> node_p2wsh_address
    got=$(cd "$TMP_DIR" && ACTOR=Verifier BITCOIN_NETWORK=regtest BITVM_SECRET="$sk" \
          "$NODE_BIN" key funding-address | sed 's/.*: //')
    if [[ "$got" != "$addr_expect" ]]; then
      echo "FAIL $role funding address: node=$got json=$addr_expect"; FAIL=1
    else
      echo "ok   $role funding-address (bitvm-noded)  $got"
    fi
    # (2) cast: BITVM_SECRET -> secp256k1 pubkey
    raw=$("$CAST" wallet public-key --raw-private-key "0x$sk")
    x=${raw:2:64}; y=${raw:66:64}
    if [[ $((16#${y: -1} % 2)) -eq 0 ]]; then pfx=02; else pfx=03; fi
    if [[ "$pfx$x" != "$comp" ]]; then echo "FAIL $role btc pubkey vs cast"; FAIL=1;
    else echo "ok   $role btc pubkey       (cast)      $comp"; fi
  fi
  goat_sk=$(python3 -c "import json;d=json.load(open('$STATE/keys.json'));print(d['roles']['$role'].get('GOAT_PRIVATE_KEY',''))")
  if [[ -n "$goat_sk" ]]; then
    goat_addr=$(python3 -c "import json;d=json.load(open('$STATE/keys.json'));print(d['roles']['$role']['goat_address'])")
    got=$("$CAST" wallet address --private-key "$goat_sk")
    if [[ "$got" != "$goat_addr" ]]; then echo "FAIL $role goat address: cast=$got json=$goat_addr"; FAIL=1;
    else echo "ok   $role goat address     (cast)      $got"; fi
  fi
}
for r in deployer committee_0 committee_1 operator_0 verifier_0 watchtower_0 user_0; do verify_role "$r"; done

# (3) PEER_KEY -> PeerId through the node's own libp2p code path.
#     The node is started with a dead GOAT RPC so it prints `local_peer_id` and then
#     panics at env.rs `cannot get chain_id` long before it binds any port.
verify_peer_id() {
  local role=$1 pk pid got tmpdb
  pk=$(python3 -c "import json;d=json.load(open('$STATE/keys.json'));print(d['roles']['$role'].get('PEER_KEY',''))")
  [[ -z "$pk" ]] && return 0
  pid=$(python3 -c "import json;d=json.load(open('$STATE/keys.json'));print(d['roles']['$role']['peer_id'])")
  tmpdb=$(mktemp -p "$TMP_DIR" peerverify-XXXXXX.db)
  rm -f "$tmpdb"
  got=$( (cd "$TMP_DIR" && RUST_LOG=info ACTOR=Committee BITCOIN_NETWORK=regtest \
          BITVM_SECRET=$(python3 -c "print('11'*32)") PEER_KEY="$pk" GOAT_CHAIN_URL=http://127.0.0.1:1 \
          timeout 60 "$NODE_BIN" --rpc-addr 127.0.0.1:$KEYCHECK_PORT --p2p-port $KEYCHECK_PORT \
          --db-path "sqlite:$tmpdb" 2>/dev/null || true) | grep -o '"local_peer_id":"[^"]*"' | head -1 | cut -d'"' -f4)
  rm -f "$tmpdb" "$tmpdb"-shm "$tmpdb"-wal
  if [[ "$got" != "$pid" ]]; then echo "FAIL $role peer id: node=$got json=$pid"; FAIL=1;
  else echo "ok   $role peer id        (bitvm-noded) $got"; fi
}
if [[ "${SKIP_PEER_ID_VERIFY:-0}" != "1" ]]; then
  for r in committee_0 committee_1 operator_0 verifier_0 watchtower_0; do verify_peer_id "$r"; done
fi
if [[ $FAIL -ne 0 ]]; then echo "VERIFICATION FAILED"; exit 1; fi
echo "--- all identities verified ---"
