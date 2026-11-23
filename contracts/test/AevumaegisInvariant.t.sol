// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AgentVault} from "../src/AgentVault.sol";
import {GuardModule} from "../src/GuardModule.sol";
import {EcdsaVerifier} from "../src/EcdsaVerifier.sol";

interface VmInvariant {
    struct FuzzSelector {
        address addr;
        bytes4[] selectors;
    }

    function targetSelector(FuzzSelector calldata selector) external;
    function warp(uint256 timestamp) external;
}

interface IERC20Invariant {
    function balanceOf(address account) external view returns (uint256);
}

contract InvariantToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(allowance[from][msg.sender] >= amount, "allowance");
        require(balanceOf[from] >= amount, "balance");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract GuardInvariantHandler {
    AgentVault public vault;
    GuardModule public guard;
    IERC20Invariant public token;
    bool public invariantViolated;

    function configure(AgentVault vaultAddress, GuardModule guardAddress, IERC20Invariant tokenAddress) external {
        vault = vaultAddress;
        guard = guardAddress;
        token = tokenAddress;
    }

    function attempt(address recipient, uint96 rawAmount, uint32 elapsedSeconds) external {
        vmInvariant().warp(block.timestamp + uint256(elapsedSeconds) % 3_600);
        uint256 amount = uint256(rawAmount) % 20_000_000 + 1;
        uint256 beforeBalance = token.balanceOf(recipient);
        bool allowed = vault.pay(recipient, amount);
        uint256 afterBalance = token.balanceOf(recipient);

        uint256 expectedBalance = recipient == address(vault) ? beforeBalance : beforeBalance + amount;
        if (allowed && afterBalance != expectedBalance) invariantViolated = true;
        if (!allowed && afterBalance != beforeBalance) invariantViolated = true;
        GuardModule.SessionStats memory stats = guard.getSessionStats(address(this));
        if (stats.cumulativeSpend > 100_000_000) invariantViolated = true;
        if (stats.state == GuardModule.GuardState.FROZEN && (allowed || afterBalance != beforeBalance)) {
            invariantViolated = true;
        }
    }

    function vmInvariant() private pure returns (VmInvariant) {
        return VmInvariant(address(uint160(uint256(keccak256("hevm cheat code")))));
    }
}

contract AevumaegisInvariantTest {
    VmInvariant private constant vm = VmInvariant(address(uint160(uint256(keccak256("hevm cheat code")))));

    InvariantToken private token;
    AgentVault private vault;
    GuardModule private guard;
    GuardInvariantHandler private handler;

    function setUp() public {
        token = new InvariantToken();
        handler = new GuardInvariantHandler();
        vault = new AgentVault(address(token), address(this), address(handler));
        EcdsaVerifier verifier = new EcdsaVerifier();

        address[] memory owners = new address[](3);
        owners[0] = address(this);
        owners[1] = address(0xA11CE);
        owners[2] = address(0xB0B);

        GuardModule.Policy memory initialPolicy = GuardModule.Policy({
            maxTransactionsPerWindow: 5,
            windowSeconds: 10,
            throttleSeconds: 60,
            noveltyAmountThreshold: 10_000_000,
            zScoreThresholdWad: 4e18,
            drawdownLimit: 100_000_000,
            cadenceWarmupTransactions: 8,
            throttleThreatScore: 2,
            freezeThreatScore: 3
        });

        guard = new GuardModule(
            address(vault), address(0x515E), address(verifier), owners, 2, 1 days, initialPolicy
        );
        vault.configureGuard(address(guard));
        handler.configure(vault, guard, IERC20Invariant(address(token)));
        token.mint(address(this), 1_000_000_000);
        token.approve(address(vault), type(uint256).max);
        vault.deposit(500_000_000);
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = GuardInvariantHandler.attempt.selector;
        vm.targetSelector(VmInvariant.FuzzSelector({addr: address(handler), selectors: selectors}));
    }

    function invariant_payment_decisions_match_token_movements() public view {
        require(!handler.invariantViolated(), "guard decision and token movement diverged");
    }
}
