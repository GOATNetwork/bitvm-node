// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {GatewayUpgradeable} from "bitvm-l2/Gateway.sol";

/// @title GatewayLocal
/// @notice The upstream Gateway plus the two committee-only knobs the localnet needs. Nothing else
///         differs, so the node talks to the genuine Gateway code paths.
///         - debugMintPegBTC: pegBTC faucet (the e2e peg-out cases need the operator to hold pegBTC
///           without running a peg-in first).
///         - debugSetResponseWindowBlocks: shrink the committee answer window the initializer fixes
///           at 200 goat blocks (~400 s on 2 s anvil blocks, during which peg-ins stall).
contract GatewayLocal is GatewayUpgradeable {
    function debugMintPegBTC(address to, uint256 amount) external onlyCommittee {
        pegBTC.mint(to, amount);
    }

    function debugSetResponseWindowBlocks(uint256 blocks_) external onlyCommittee {
        responseWindowBlocks = blocks_;
    }
}
