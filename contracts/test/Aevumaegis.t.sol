// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {AgentVault} from "../src/AgentVault.sol";
import {GuardModule} from "../src/GuardModule.sol";
import {EcdsaVerifier} from "../src/EcdsaVerifier.sol";
import {HybridVerifier} from "../src/HybridVerifier.sol";

interface Vm {
    function addr(uint256 privateKey) external returns (address);
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
    function prank(address sender) external;
    function warp(uint256 timestamp) external;
    function expectRevert(bytes calldata reason) external;
}

contract TestToken {
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

contract AevumaegisTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 private constant OWNER_ONE_KEY = 0xA11CE;
    uint256 private constant OWNER_TWO_KEY = 0xB0B;
    uint256 private constant OWNER_THREE_KEY = 0xCAFE;

    TestToken private token;
    AgentVault private vault;
    GuardModule private guard;
    EcdsaVerifier private verifier;
    address private ownerOne;
    address private ownerTwo;
    address private ownerThree;
    address private sentinel;
    address private sessionKey;
    address private supplier;

    function setUp() public {
        ownerOne = vm.addr(OWNER_ONE_KEY);
        ownerTwo = vm.addr(OWNER_TWO_KEY);
        ownerThree = vm.addr(OWNER_THREE_KEY);
        sentinel = address(0x515E);
        sessionKey = address(0xA63E17);
        supplier = address(0x5150);

        token = new TestToken();
        verifier = new EcdsaVerifier();
        vault = new AgentVault(address(token), ownerOne, sessionKey);

        address[] memory owners = new address[](3);
        owners[0] = ownerOne;
        owners[1] = ownerTwo;
        owners[2] = ownerThree;

        GuardModule.Policy memory initialPolicy = GuardModule.Policy({
            maxTransactionsPerWindow: 3,
            windowSeconds: 10,
            throttleSeconds: 60,
            noveltyAmountThreshold: 10_000_000,
            zScoreThresholdWad: 4e18,
            drawdownLimit: 100_000_000,
            cadenceWarmupTransactions: 100,
            throttleThreatScore: 2,
            freezeThreatScore: 3
        });

        guard = new GuardModule(
            address(vault), sentinel, address(verifier), owners, 2, 1 days, initialPolicy
        );
        vault.configureGuard(address(guard));
        token.mint(ownerOne, 1_000_000_000);
        token.approve(address(vault), type(uint256).max);
        vault.deposit(500_000_000);
    }

    function testHybridVerifierFailsClosedUntilPostQuantumSupportExists() public {
        HybridVerifier hybridVerifier = new HybridVerifier();
        vm.expectRevert(abi.encodeWithSignature(
            "Error(string)", "HybridVerifier: awaiting PQ precompile"
        ));
        hybridVerifier.verify(bytes32(uint256(1)), ownerOne, hex"01");
    }

    function testEwmaMeanAndVarianceUpdate() public {
        vm.prank(sessionKey);
        require(vault.pay(supplier, 1_000_000), "first baseline payment blocked");
        vm.prank(sessionKey);
        require(vault.pay(supplier, 2_000_000), "second baseline payment blocked");

        GuardModule.SessionStats memory stats = guard.getSessionStats(sessionKey);
        require(stats.baselineMean == 1_125_000, "EWMA mean mismatch");
        require(stats.baselineVariance == 125_000_000_000, "EWMA variance mismatch");
    }

    function testCadenceDeviationContributesToThreatScore() public {
        GuardModule.Policy memory nextPolicy = guard.getPolicy();
        nextPolicy.cadenceWarmupTransactions = 1;
        nextPolicy.throttleThreatScore = 1;
        bytes32 policyHash = keccak256(abi.encode(nextPolicy));
        bytes32 digest = keccak256(
            abi.encode(address(guard), block.chainid, "AEVUMAEGIS_POLICY", guard.governanceNonce(), policyHash)
        );
        guard.updatePolicy(nextPolicy, _signQuorum(digest));

        vm.prank(sessionKey);
        require(vault.pay(supplier, 1_000_000), "baseline payment blocked");
        vm.warp(block.timestamp + 4 hours);
        vm.prank(sessionKey);
        require(!vault.pay(supplier, 1_000_000), "unobserved cadence bucket was allowed");

        GuardModule.SessionStats memory stats = guard.getSessionStats(sessionKey);
        require(stats.lastThreatScore == 1, "cadence threat score mismatch");
        require(stats.state == GuardModule.GuardState.THROTTLED, "cadence deviation did not throttle");
    }

    function testLegitimatePaymentsAreAllowedAndRecorded() public {
        for (uint256 i; i < 3; ++i) {
            vm.prank(sessionKey);
            require(vault.pay(supplier, 1_000_000), "legitimate payment blocked");
        }
        GuardModule.SessionStats memory stats = guard.getSessionStats(sessionKey);
        require(stats.actionCount == 3, "action count mismatch");
        require(stats.rollingHash != bytes32(0), "hash chain did not advance");
        require(token.balanceOf(supplier) == 3_000_000, "supplier balance mismatch");
    }

    function testVelocityThrottlesWithoutLosingEvidence() public {
        for (uint256 i; i < 3; ++i) {
            vm.prank(sessionKey);
            require(vault.pay(supplier, 1_000_000), "initial payment blocked");
        }
        vm.prank(sessionKey);
        require(!vault.pay(supplier, 1_000_000), "velocity breach was allowed");

        GuardModule.SessionStats memory stats = guard.getSessionStats(sessionKey);
        require(stats.state == GuardModule.GuardState.THROTTLED, "session was not throttled");
        require(stats.actionCount == 4, "blocked action was not recorded");
        require(token.balanceOf(supplier) == 3_000_000, "blocked payment moved funds");
    }

    function testNovelRecipientAboveThresholdThrottles() public {
        vm.prank(sessionKey);
        require(!vault.pay(address(0xD00D), 11_000_000), "novel recipient was allowed");
        GuardModule.SessionStats memory stats = guard.getSessionStats(sessionKey);
        require(stats.state == GuardModule.GuardState.THROTTLED, "novel recipient did not throttle");
        require(token.balanceOf(address(0xD00D)) == 0, "blocked payment moved funds");
    }

    function testKnownRecipientAnomalyFreezes() public {
        for (uint256 i; i < 3; ++i) {
            vm.prank(sessionKey);
            require(vault.pay(supplier, 1_000_000), "baseline payment blocked");
        }
        vm.prank(sessionKey);
        require(!vault.pay(supplier, 20_000_000), "anomalous payment was allowed");
        require(
            guard.getSessionStats(sessionKey).state == GuardModule.GuardState.FROZEN,
            "anomaly did not freeze"
        );
    }

    function testCumulativeDrawdownFreezes() public {
        for (uint256 i; i < 21; ++i) {
            if (i > 0 && i % 3 == 0) vm.warp(block.timestamp + 11);
            vm.prank(sessionKey);
            bool allowed = vault.pay(supplier, 5_000_000);
            if (i < 20) {
                require(allowed, "payment blocked before drawdown ceiling");
            } else {
                require(!allowed, "drawdown breach was allowed");
            }
        }
        require(
            guard.getSessionStats(sessionKey).state == GuardModule.GuardState.FROZEN,
            "drawdown did not freeze"
        );
    }

    function testAnyAttemptDuringThrottleEscalatesToFreeze() public {
        for (uint256 i; i < 3; ++i) {
            vm.prank(sessionKey);
            vault.pay(supplier, 1_000_000);
        }
        vm.prank(sessionKey);
        require(!vault.pay(supplier, 1_000_000), "velocity breach was allowed");
        vm.prank(sessionKey);
        require(!vault.pay(supplier, 1_000_000), "throttled session was allowed to pay");
        require(
            guard.getSessionStats(sessionKey).state == GuardModule.GuardState.FROZEN,
            "throttled session did not escalate"
        );
    }

    function testVelocityFollowedByAnotherViolationFreezes() public {
        for (uint256 i; i < 3; ++i) {
            vm.prank(sessionKey);
            vault.pay(supplier, 1_000_000);
        }
        vm.prank(sessionKey);
        vault.pay(supplier, 1_000_000);
        vm.prank(sessionKey);
        vault.pay(address(0xD00D), 20_000_000);

        GuardModule.SessionStats memory stats = guard.getSessionStats(sessionKey);
        require(stats.state == GuardModule.GuardState.FROZEN, "second violation did not freeze");
        require(stats.finalForensicHash == stats.rollingHash, "forensic hash mismatch");
    }

    function testUnfreezeRequiresQuorumAndCooldownAndAllowsSentinelVeto() public {
        _freezeSession();
        address replacementSessionKey = address(0xA63E18);
        bytes32 digest = _unfreezeDigest(replacementSessionKey);
        bytes[] memory signatures = _signQuorum(digest);
        guard.requestUnfreeze(replacementSessionKey, signatures);

        vm.prank(sentinel);
        guard.vetoUnfreeze();
        require(!guard.unfreezePending(), "veto did not clear request");

        digest = _unfreezeDigest(replacementSessionKey);
        signatures = _signQuorum(digest);
        guard.requestUnfreeze(replacementSessionKey, signatures);
        vm.expectRevert(abi.encodeWithSelector(GuardModule.CooldownActive.selector));
        guard.executeUnfreeze();

        vm.warp(block.timestamp + 1 days);
        guard.executeUnfreeze();
        require(vault.sessionKey() == replacementSessionKey, "session key was not rotated");
        GuardModule.SessionStats memory oldStats = guard.getSessionStats(sessionKey);
        require(oldStats.state == GuardModule.GuardState.FROZEN, "old session history was discarded");
        require(
            guard.getSessionStats(replacementSessionKey).state == GuardModule.GuardState.ACTIVE,
            "replacement session did not start active"
        );
    }

    function testSingleOwnerSignatureCannotRearm() public {
        _freezeSession();
        address replacementSessionKey = address(0xA63E18);
        bytes32 digest = _unfreezeDigest(replacementSessionKey);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_ONE_KEY, digest);
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = abi.encodePacked(r, s, v);
        vm.expectRevert(abi.encodeWithSelector(GuardModule.InvalidQuorum.selector));
        guard.requestUnfreeze(replacementSessionKey, signatures);
    }

    function testFuzzPaymentsNeverTransferWhenGuardReturnsFalse(uint96 rawAmount) public {
        uint256 amount = uint256(rawAmount) % 20_000_000 + 1;
        vm.prank(sessionKey);
        bool allowed = vault.pay(supplier, amount);
        if (!allowed) {
            require(token.balanceOf(supplier) == 0, "blocked payment transferred tokens");
        }
    }

    function _freezeSession() private {
        for (uint256 i; i < 3; ++i) {
            vm.prank(sessionKey);
            vault.pay(supplier, 1_000_000);
        }
        vm.prank(sessionKey);
        vault.pay(supplier, 1_000_000);
        vm.prank(sessionKey);
        vault.pay(address(0xD00D), 20_000_000);
        require(
            guard.getSessionStats(sessionKey).state == GuardModule.GuardState.FROZEN,
            "setup did not freeze"
        );
    }

    function _unfreezeDigest(address newSessionKey) private view returns (bytes32) {
        return keccak256(
            abi.encode(
                address(guard),
                block.chainid,
                "AEVUMAEGIS_UNFREEZE",
                guard.governanceNonce(),
                guard.unfreezeRequestedAt(),
                newSessionKey
            )
        );
    }

    function _signQuorum(bytes32 digest) private returns (bytes[] memory signatures) {
        signatures = new bytes[](2);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(OWNER_ONE_KEY, digest);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(OWNER_TWO_KEY, digest);
        signatures[0] = abi.encodePacked(r1, s1, v1);
        signatures[1] = abi.encodePacked(r2, s2, v2);
    }
}
