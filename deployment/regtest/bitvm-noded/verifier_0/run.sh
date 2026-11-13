# Load this node's settings, including BOOTNODES.
set -a; . ./.env.verifier_0; set +a
nohup ../bitvm-noded  --rpc-addr 127.0.0.1:8906 --metrics-addr 127.0.0.1:9902 --db-path sqlite:$PWD/bitvm-node.db --p2p-port 8450 >$PWD/$(date +'%Y%m%d').log 2>&1 &
