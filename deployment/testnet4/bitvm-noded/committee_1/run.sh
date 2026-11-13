# Load this node's settings, including BOOTNODES.
set -a; . ./.env.committee_1; set +a
nohup ../bitvm-noded  --rpc-addr 127.0.0.1:8901 --metrics-addr 127.0.0.1:9901 --db-path sqlite:$PWD/bitvm-node.db --p2p-port 8444 >$PWD/$(date +'%Y%m%d').log 2>&1 &
