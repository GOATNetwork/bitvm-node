# Repo-level shortcuts for the local mock testnet under localnet/ (see localnet/README.md).
# Every target honours LOCALNET_DATA, PORT_BASE and COMPOSE_PROJECT from the environment, e.g.
#   LOCALNET_DATA=/tmp/bv2 PORT_BASE=23000 COMPOSE_PROJECT=bvlocal2 make localnet-reset
LOCALNET := localnet

.PHONY: localnet-build localnet-up localnet-down localnet-reset localnet-status e2e-smoke e2e

localnet-build:        ## build the mock-gc node + helper binaries into the repo target
	$(LOCALNET)/build.sh

localnet-up:           ## adopt / start an existing localnet (infra, miner, proof builder, 5 nodes)
	$(LOCALNET)/scripts/up.sh

localnet-down:         ## stop nodes + support processes (infra keeps running; `scripts/down.sh infra` stops it too)
	$(LOCALNET)/scripts/down.sh

localnet-reset:        ## DESTRUCTIVE: wipe $(LOCALNET_DATA) and rebuild chains, contracts, subgraph, nodes
	$(LOCALNET)/scripts/reset.sh --yes

localnet-status:
	$(LOCALNET)/scripts/status.sh

e2e-smoke:             ## peg-in, peg-out and challenge/take-2 happy paths (~20 min)
	$(LOCALNET)/e2e/run.sh pegin_happy pegout_happy challenge_take2

e2e:                   ## the whole suite (~110 min)
	$(LOCALNET)/e2e/run.sh
