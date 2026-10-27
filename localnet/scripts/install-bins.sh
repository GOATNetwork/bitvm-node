#!/usr/bin/env bash
# Copy the freshly built (mock-enabled) release binaries into $LOCALNET_DATA/bin
# so a later rebuild in target/release never swaps the binary under a running node.
# Nodes/scripts always exec from $BIN_DIR, never from target/release.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
source "$ROOT/scripts/localnet.env"

SRC="${CARGO_TARGET_DIR:-$REPO_ROOT/target}/release"
mkdir -p "$BIN_DIR"

BINS=(bitvm-noded mock-proof-builder rpc-sign pegin-request pegout challenge verifier-challenge)

missing=0
for b in "${BINS[@]}"; do
  if [[ ! -x "$SRC/$b" ]]; then
    echo "MISSING: $SRC/$b (run localnet/build.sh)" >&2
    missing=1
  fi
done
[[ $missing -eq 0 ]] || { echo "Refusing to install: binaries missing." >&2; exit 1; }

for b in "${BINS[@]}"; do
  # Copy to a temp name then atomic-rename, so a running node keeps its old inode.
  cp -f "$SRC/$b" "$BIN_DIR/.$b.new"
  chmod +x "$BIN_DIR/.$b.new"
  mv -f "$BIN_DIR/.$b.new" "$BIN_DIR/$b"
  printf '  installed %-20s <- %s\n' "$b" "$(stat -c '%y' "$SRC/$b" | cut -d. -f1)"
done

echo "Installed ${#BINS[@]} binaries into $BIN_DIR"
"$BIN_DIR/bitvm-noded" --help >/dev/null 2>&1 && echo "bitvm-noded runs OK" || echo "WARN: bitvm-noded --help failed" >&2
