// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AgentVault} from "../src/AgentVault.sol";
import {GuardModule} from "../src/GuardModule.sol";
import {EcdsaVerifier} from "../src/EcdsaVerifier.sol";

interface VmDeploy {
    function envUint(string calldata name) external view returns (uint256);
    function envAddress(string calldata name) external view returns (address);
    function addr(uint256 privateKey) external returns (address);
    function startBroadcast(uint256 privateKey) external;
    function stopBroadcast() external;
}

contract DeployAevumaegis {
    VmDeploy private constant vm = VmDeploy(address(uint160(uint256(keccak256("hevm cheat code")))));

    event Deployment(address vault, address guard, address verifier, address token, address sessionKey);

    function run() external {
        require(block.chainid == 44_005, "DeployAevumaegis: wrong chain, expected Aevum 44005");

        uint256 deployerKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address ownerOne = vm.addr(deployerKey);
        address ownerTwo = vm.envAddress("OWNER_TWO");
        address ownerThree = vm.envAddress("OWNER_THREE");
        address sentinel = vm.envAddress("SENTINEL");
        address sessionKey = vm.envAddress("SESSION_KEY");
        address token = vm.envAddress("TUSD8_ADDRESS");

        vm.startBroadcast(deployerKey);
        EcdsaVerifier verifier = new EcdsaVerifier();
        AgentVault vault = new AgentVault(token, ownerOne, sessionKey);

        address[] memory owners = new address[](3);
        owners[0] = ownerOne;
        owners[1] = ownerTwo;
        owners[2] = ownerThree;

        GuardModule.Policy memory initialPolicy = GuardModule.Policy({
            maxTransactionsPerWindow: 3,
            windowSeconds: 10,
            throttleSeconds: 60,
            noveltyAmountThreshold: 10_000_000,
            noveltyFractionThresholdWad: 5e17,
            zScoreThresholdWad: 4e18,
            drawdownLimit: 100_000_000,
            cadenceWarmupTransactions: 8,
            throttleThreatScore: 2,
            freezeThreatScore: 3
        });

        GuardModule guard = new GuardModule(
            address(vault),
            sentinel,
            address(verifier),
            owners,
            2,
            1 days,
            initialPolicy
        );
        vault.configureGuard(address(guard));
        vm.stopBroadcast();

        emit Deployment(address(vault), address(guard), address(verifier), token, sessionKey);
    }
}
