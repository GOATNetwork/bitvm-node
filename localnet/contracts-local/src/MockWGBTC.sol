// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @title MockWGBTC
/// @notice Local-only WETH9-style ERC20 stake token used by StakeManagement on the localnet.
///         Stands in for GOAT's "Wrapped Goat Bitcoin" (WGBTC) predeploy
///         (0xbC10000000000000000000000000000000000000), which does not exist on anvil.
///         StakeManagement only uses ERC20 transfer/transferFrom/approve/balanceOf; the operator obtains
///         tokens via deposit()/mint() then approves + stakes + locks (see deploy-local.sh).
///
///         18 decimals (matches the on-chain policy amounts: minStakeAmount = 6e16 wei = 0.06 WGBTC).
contract MockWGBTC is ERC20 {
    event Deposit(address indexed dst, uint256 wad);
    event Withdrawal(address indexed src, uint256 wad);

    constructor() ERC20("Wrapped Goat Bitcoin (mock)", "WGBTC") {}

    /// @notice Wrap native anvil ETH 1:1 into WGBTC (WETH9-style).
    function deposit() external payable {
        _mint(msg.sender, msg.value);
        emit Deposit(msg.sender, msg.value);
    }

    /// @notice Unwrap WGBTC back to native ETH 1:1.
    function withdraw(uint256 wad) external {
        _burn(msg.sender, wad);
        (bool ok,) = msg.sender.call{value: wad}("");
        require(ok, "WGBTC: ETH transfer failed");
        emit Withdrawal(msg.sender, wad);
    }

    /// @notice Open faucet mint (no native ETH backing) — convenience for funding operator stake locally.
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    receive() external payable {
        _mint(msg.sender, msg.value);
        emit Deposit(msg.sender, msg.value);
    }
}
