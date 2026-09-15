nohup ../bitvm-noded  --rpc-addr 127.0.0.1:8904 --metrics-addr 127.0.0.1:9904 --db-path sqlite:$PWD/bitvm-node.db --p2p-port 8447  --bootnodes $bootnode_urls  >$PWD/$(date +'%Y%m%d').log 2>&1 &
