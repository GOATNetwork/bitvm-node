nohup ../bitvm-noded  --rpc-addr 127.0.0.1:8902 --metrics-addr 127.0.0.1:9900  --db-path sqlite:$PWD/bitvm-node.db --p2p-port 8445   >$PWD/$(date +'%Y%m%d').log 2>&1 &
