# Load this node's settings, including BOOTNODES.
set -a; . ./.env.operator_0; set +a
nohup ../bitvm-noded  --rpc-addr 127.0.0.1:8902 --metrics-addr 127.0.0.1:9903 --db-path sqlite:$PWD/bitvm-node.db --p2p-port 8446 >$PWD/$(date +'%Y%m%d').log 2>&1 &
