// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Script, console} from "forge-std/Script.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {IPegBTC} from "bitvm-l2/interfaces/IPegBTC.sol";
import {IBitcoinSPV} from "bitvm-l2/interfaces/IBitcoinSPV.sol";
import {ICommitteeManagement} from "bitvm-l2/interfaces/ICommitteeManagement.sol";
import {IStakeManagement} from "bitvm-l2/interfaces/IStakeManagement.sol";
import {CommitteeManagement} from "bitvm-l2/CommitteeManagement.sol";
import {StakeManagement} from "bitvm-l2/StakeManagement.sol";
import {PegBTC} from "bitvm-l2/PegBTC.sol";
import {UpgradeableProxy} from "bitvm-l2/UpgradeableProxy.sol";

import {GatewayLocal} from "../src/GatewayLocal.sol";
import {MockBitcoinSPV} from "../src/MockBitcoinSPV.sol";
import {MockWGBTC} from "../src/MockWGBTC.sol";

/*
    Deploy the whole localnet stack in one broadcast: the two mocks, then the upstream stack
    exactly as script/DeployGateway.sol in ../contracts does it, with GatewayLocal as the
    gateway implementation. Env:
    - PRIVATE_KEY:   deployer
    - COMMITTEE_<i>: committee member addresses (sequential from 0)
    - WATCHTOWER_<i>: watchtower x-only pubkeys (bytes32, sequential from 0)
    The console lines are parsed by deploy-local.sh; keep their labels.
*/
contract DeployLocal is Script {
    address public deployer;

    function run() public {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        deployer = vm.createWallet(deployerPrivateKey).addr;
        console.log("deployer address: ", deployer);
        vm.startBroadcast(deployerPrivateKey);
        deploy();
        vm.stopBroadcast();
    }

    function deploy() public {
        MockWGBTC wgbtc = new MockWGBTC();
        console.log("MockWGBTC contract address: ", address(wgbtc));
        MockBitcoinSPV spv = new MockBitcoinSPV(0, true);
        console.log("MockBitcoinSPV contract address: ", address(spv));

        GatewayLocal gatewayImpl = new GatewayLocal();
        console.log("Gateway implementation contract address: ", address(gatewayImpl));
        UpgradeableProxy gatewayProxy = new UpgradeableProxy(address(gatewayImpl), deployer, "");
        console.log("Gateway proxy contract address: ", address(gatewayProxy));
        GatewayLocal gateway = GatewayLocal(payable(gatewayProxy));

        PegBTC pegBTC = new PegBTC(address(gateway));
        console.log("PegBTC contract address: ", address(pegBTC));

        address[] memory initialMembers = _readSequentialAddresses("COMMITTEE");
        uint256 initialRequired = (initialMembers.length * 2 + 2) / 3;
        bytes32[] memory initialWatchtowers = _readSequentialBytes32("WATCHTOWER");
        require(initialMembers.length > 0, "COMMITTEE list empty");
        require(initialWatchtowers.length > 0, "WATCHTOWER list empty");
        address[] memory initialAuthorizedCallers = new address[](1);
        initialAuthorizedCallers[0] = address(gateway);

        CommitteeManagement committeeImpl = new CommitteeManagement();
        console.log("CommitteeManagement implementation contract address: ", address(committeeImpl));
        bytes memory committeeInitData = abi.encodeWithSelector(
            CommitteeManagement.initialize.selector,
            initialMembers,
            initialRequired,
            initialAuthorizedCallers,
            initialWatchtowers
        );
        UpgradeableProxy committeeProxy = new UpgradeableProxy(address(committeeImpl), deployer, committeeInitData);
        console.log("CommitteeManagement proxy contract address: ", address(committeeProxy));

        StakeManagement stakeImpl = new StakeManagement();
        console.log("StakeManagement implementation contract address: ", address(stakeImpl));
        bytes memory stakeInitData =
            abi.encodeWithSelector(StakeManagement.initialize.selector, IERC20(address(wgbtc)), address(gateway));
        UpgradeableProxy stakeProxy = new UpgradeableProxy(address(stakeImpl), deployer, stakeInitData);
        console.log("StakeManagement proxy contract address: ", address(stakeProxy));

        gateway.initialize(
            IPegBTC(address(pegBTC)),
            IBitcoinSPV(address(spv)),
            ICommitteeManagement(address(committeeProxy)),
            IStakeManagement(address(stakeProxy))
        );
    }

    function _readSequentialAddresses(string memory baseKey) internal view returns (address[] memory out) {
        uint256 count = 0;
        while (vm.envOr(string(abi.encodePacked(baseKey, "_", vm.toString(count))), address(0)) != address(0)) {
            count++;
        }
        out = new address[](count);
        for (uint256 i = 0; i < count; i++) {
            out[i] = vm.envAddress(string(abi.encodePacked(baseKey, "_", vm.toString(i))));
        }
    }

    function _readSequentialBytes32(string memory baseKey) internal view returns (bytes32[] memory out) {
        uint256 count = 0;
        while (vm.envOr(string(abi.encodePacked(baseKey, "_", vm.toString(count))), bytes32(0)) != bytes32(0)) {
            count++;
        }
        out = new bytes32[](count);
        for (uint256 i = 0; i < count; i++) {
            out[i] = vm.envBytes32(string(abi.encodePacked(baseKey, "_", vm.toString(i))));
        }
    }
}
