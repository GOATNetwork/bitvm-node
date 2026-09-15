nohup ../bitvm-noded  --rpc-addr 0.0.0.0:8900 --metrics-addr 127.0.0.1:9900  --db-path sqlite:$PWD/bitvm-node.db --p2p-port 8444   >$PWD/$(date +'%Y%m%d').log 2>&1 &
