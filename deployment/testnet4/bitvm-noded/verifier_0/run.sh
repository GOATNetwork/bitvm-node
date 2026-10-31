nohup ../bitvm-noded  --rpc-addr 127.0.0.1:8906 --metrics-addr 127.0.0.1:9902 --db-path sqlite:$PWD/bitvm-node.db --p2p-port 8449  --bootnodes $bootnode_urls  >$PWD/$(date +'%Y%m%d').log 2>&1 &
