# Repo-level shortcuts for the local mock testnet under localnet/ (see localnet/README.md).
# Every target honours LOCALNET_DATA, PORT_BASE and COMPOSE_PROJECT from the environment, e.g.
#   LOCALNET_DATA=/tmp/bv2 PORT_BASE=23000 COMPOSE_PROJECT=bvlocal2 make localnet-reset
LOCALNET := localnet
# TLA+ specs (audit/tla, see README.md "Formal verification (TLA+)"). TLA2TOOLS and TLC_OPTS
# are passed through to audit/tla/check.sh.
TLA2TOOLS ?= $(HOME)/.local/share/tlaplus/tla2tools.jar
TLA2TOOLS_URL := https://github.com/tlaplus/tlaplus/releases/latest/download/tla2tools.jar
export TLA2TOOLS TLC_OPTS

.PHONY: localnet-build localnet-up localnet-down localnet-reset localnet-status e2e-smoke e2e tla-setup tla

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

tla-setup:             ## download tla2tools.jar to $(TLA2TOOLS) (needs a JRE 11+ to run)
	@mkdir -p $(dir $(TLA2TOOLS))
	curl -fsSL -o $(TLA2TOOLS) $(TLA2TOOLS_URL)

tla:                   ## run audit/tla/specs.txt through TLC; fails while a live bug reproduces (SPEC=<cfg|tla> for one)
	audit/tla/check.sh $(SPEC)
