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
    uint256 private constant SESSION_KEY_PRIVATE_KEY = 0xA63E17;
    bytes32 private constant PAYMENT_PURPOSE = keccak256("invoice:demo-001");

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
    uint256 private intentNonce;

    function setUp() public {
        ownerOne = vm.addr(OWNER_ONE_KEY);
        ownerTwo = vm.addr(OWNER_TWO_KEY);
        ownerThree = vm.addr(OWNER_THREE_KEY);
        sentinel = address(0x515E);
        sessionKey = vm.addr(SESSION_KEY_PRIVATE_KEY);
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
            noveltyFractionThresholdWad: 5e17,
            zScoreThresholdWad: 4e18,
            drawdownLimit: 100_000_000,
            cadenceWarmupTransactions: 100,
            throttleThreatScore: 2,
            freezeThreatScore: 3
        });

        guard = new GuardModule(
            address(vault), sentinel, address(verifier), owners, 2, 1 days, initialPolicy
        );
        vm.prank(ownerOne);
        vault.configureGuard(address(guard));
        _authorizeRecipient(supplier, true);
        _authorizeRecipient(address(0xD00D), true);
        token.mint(ownerOne, 1_000_000_000);
        vm.prank(ownerOne);
        token.approve(address(vault), type(uint256).max);
        vm.prank(ownerOne);
        vault.deposit(500_000_000);
    }

    function testEcdsaVerifierRejectsHighSVariant() public {
        bytes32 digest = keccak256("high-s regression");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SESSION_KEY_PRIVATE_KEY, digest);
        uint256 curveOrder = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        bytes32 highS = bytes32(curveOrder - uint256(s));
        uint8 flippedV = v == 27 ? 28 : 27;
        require(!verifier.verify(digest, sessionKey, abi.encodePacked(r, highS, flippedV)), "high-s signature accepted");
    }

    function testVaultRejectsTokenAddressWithoutCode() public {
        vm.expectRevert(abi.encodeWithSelector(AgentVault.InvalidAddress.selector));
        new AgentVault(address(0xBEEF), ownerOne, sessionKey);
    }

    function testVaultRejectsGuardBoundToAnotherVault() public {
        AgentVault unconfiguredVault = new AgentVault(address(token), ownerOne, sessionKey);
        AgentVault otherVault = new AgentVault(address(token), ownerOne, sessionKey);
        GuardModule otherGuard = new GuardModule(
            address(otherVault),
            sentinel,
            address(verifier),
            guard.getOwners(),
            2,
            1 days,
            guard.getPolicy()
        );
        vm.expectRevert(abi.encodeWithSelector(AgentVault.InvalidGuard.selector));
        vm.prank(ownerOne);
        unconfiguredVault.configureGuard(address(otherGuard));
    }

    function testHybridVerifierFailsClosedUntilPostQuantumSupportExists() public {
        HybridVerifier hybridVerifier = new HybridVerifier();
        vm.expectRevert(abi.encodeWithSignature(
            "Error(string)", "HybridVerifier: awaiting PQ precompile"
        ));
        hybridVerifier.verify(bytes32(uint256(1)), ownerOne, hex"01");
    }

    function testValidSignedIntentExecutesAndConsumesNonce() public {
        GuardModule.PaymentIntent memory intent = _newIntent(supplier, 1_000_000, 77);
        bytes memory signature = _signIntent(intent);
        vm.prank(sessionKey);
        require(vault.pay(intent, signature), "valid signed intent blocked");
        require(guard.usedIntentNonce(sessionKey, 77), "intent nonce was not consumed");
        require(token.balanceOf(supplier) == 1_000_000, "intent payment did not transfer");
    }

    function testIntentNonceCannotBeReplayed() public {
        GuardModule.PaymentIntent memory intent = _newIntent(supplier, 1_000_000, 78);
        bytes memory signature = _signIntent(intent);
        vm.prank(sessionKey);
        require(vault.pay(intent, signature), "initial intent blocked");
        vm.expectRevert(abi.encodeWithSelector(GuardModule.IntentNonceAlreadyUsed.selector));
        vm.prank(sessionKey);
        vault.pay(intent, signature);
    }

    function testExpiredIntentIsRejected() public {
        GuardModule.PaymentIntent memory intent = _newIntent(supplier, 1_000_000, 79);
        intent.expiry = block.timestamp - 1;
        bytes memory signature = _signIntent(intent);
        vm.expectRevert(abi.encodeWithSelector(GuardModule.PaymentIntentExpired.selector));
        vm.prank(sessionKey);
        vault.pay(intent, signature);
    }

    function testUnauthorizedCounterpartyIsRejected() public {
        GuardModule.PaymentIntent memory intent = _newIntent(address(0xBAD), 1_000_000, 80);
        bytes memory signature = _signIntent(intent);
        vm.expectRevert(abi.encodeWithSelector(GuardModule.UnauthorizedRecipient.selector));
        vm.prank(sessionKey);
        vault.pay(intent, signature);
    }

    function testIntentSignatureIsBoundToVaultAndChain() public {
        GuardModule.PaymentIntent memory intent = _newIntent(supplier, 1_000_000, 83);
        bytes32 wrongDomainDigest = keccak256(
            abi.encode(
                guard.PAYMENT_INTENT_TYPEHASH(),
                address(0xBEEF),
                block.chainid + 1,
                sessionKey,
                intent.recipient,
                intent.amount,
                intent.purposeHash,
                intent.nonce,
                intent.expiry
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SESSION_KEY_PRIVATE_KEY, wrongDomainDigest);
        vm.expectRevert(abi.encodeWithSelector(GuardModule.InvalidSignature.selector));
        vm.prank(sessionKey);
        vault.pay(intent, abi.encodePacked(r, s, v));
    }

    function testUnauthorizedPurposeHashIsRejected() public {
        bytes32 unapprovedPurpose = keccak256("invoice:unapproved");
        GuardModule.PaymentIntent memory intent = _newIntent(supplier, 1_000_000, 86);
        intent.purposeHash = unapprovedPurpose;
        bytes memory signature = _signIntent(intent);
        vm.expectRevert(abi.encodeWithSelector(GuardModule.UnauthorizedPurpose.selector));
        vm.prank(sessionKey);
        vault.pay(intent, signature);
    }

    function testRecipientReauthorizationDoesNotRestoreOldPurposeApproval() public {
        bytes32 revokeDigest = keccak256(
            abi.encode(
                address(guard),
                block.chainid,
                "AEVUMAEGIS_RECIPIENT",
                guard.governanceNonce(),
                supplier,
                false
            )
        );
        guard.setRecipientAuthorization(supplier, false, _signQuorum(revokeDigest));

        bytes32 restoreDigest = keccak256(
            abi.encode(
                address(guard),
                block.chainid,
                "AEVUMAEGIS_RECIPIENT",
                guard.governanceNonce(),
                supplier,
                true
            )
        );
        guard.setRecipientAuthorization(supplier, true, _signQuorum(restoreDigest));
        require(!guard.authorizedPurposeHash(supplier, PAYMENT_PURPOSE), "old purpose approval was restored");

        GuardModule.PaymentIntent memory intent = _newIntent(supplier, 1_000_000, 87);
        bytes memory signature = _signIntent(intent);
        vm.expectRevert(abi.encodeWithSelector(GuardModule.UnauthorizedPurpose.selector));
        vm.prank(sessionKey);
        vault.pay(intent, signature);
    }

    function testPurposeAmountCannotExceedGovernedCap() public {
        uint256 maxAmount = 1_000_000;
        bytes32 digest = keccak256(
            abi.encode(
                address(guard),
                block.chainid,
                "AEVUMAEGIS_PURPOSE",
                guard.governanceNonce(),
                supplier,
                PAYMENT_PURPOSE,
                maxAmount,
                true
            )
        );
        guard.setPurposeAuthorization(supplier, PAYMENT_PURPOSE, maxAmount, true, _signQuorum(digest));

        GuardModule.PaymentIntent memory intent = _newIntent(supplier, maxAmount + 1, 88);
        bytes memory signature = _signIntent(intent);
        vm.expectRevert(abi.encodeWithSelector(GuardModule.PurposeAmountExceeded.selector));
        vm.prank(sessionKey);
        vault.pay(intent, signature);
        require(!guard.usedIntentNonce(sessionKey, intent.nonce), "cap rejection consumed nonce");
    }

    function testPurposeAuthorizationRequiresQuorum() public {
        bytes32 purposeHash = keccak256("invoice:second-purpose");
        bytes32 digest = keccak256(
            abi.encode(
                address(guard),
                block.chainid,
                "AEVUMAEGIS_PURPOSE",
                guard.governanceNonce(),
                supplier,
                purposeHash,
                uint256(1_000_000),
                true
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_ONE_KEY, digest);
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = abi.encodePacked(r, s, v);
        vm.expectRevert(abi.encodeWithSelector(GuardModule.InvalidQuorum.selector));
        guard.setPurposeAuthorization(supplier, purposeHash, uint256(1_000_000), true, signatures);
    }

    function testIntentAboveTrackedAmountLimitIsRejected() public {
        GuardModule.PaymentIntent memory intent =
            _newIntent(supplier, 1e18 + 1, 85);
        bytes memory signature = _signIntent(intent);
        vm.expectRevert(abi.encodeWithSelector(GuardModule.InvalidPaymentIntent.selector));
        vm.prank(sessionKey);
        vault.pay(intent, signature);
    }

    function testZeroPurposeHashIsRejected() public {
        GuardModule.PaymentIntent memory intent = _newIntent(supplier, 1_000_000, 82);
        intent.purposeHash = bytes32(0);
        bytes memory signature = _signIntent(intent);
        vm.expectRevert(abi.encodeWithSelector(GuardModule.InvalidPaymentIntent.selector));
        vm.prank(sessionKey);
        vault.pay(intent, signature);
    }

    function testDuplicateOwnerSignatureCannotSatisfyQuorum() public {
        address recipient = address(0xBADD);
        bytes32 digest = keccak256(
            abi.encode(
                address(guard),
                block.chainid,
                "AEVUMAEGIS_RECIPIENT",
                guard.governanceNonce(),
                recipient,
                true
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_ONE_KEY, digest);
        bytes[] memory signatures = new bytes[](2);
        signatures[0] = abi.encodePacked(r, s, v);
        signatures[1] = abi.encodePacked(r, s, v);
        vm.expectRevert(abi.encodeWithSelector(GuardModule.InvalidSignature.selector));
        guard.setRecipientAuthorization(recipient, true, signatures);
    }

    function testPolicyRejectsThreatThresholdAboveMaximumScore() public {
        GuardModule.Policy memory nextPolicy = guard.getPolicy();
        nextPolicy.freezeThreatScore = 12;
        bytes32 policyHash = keccak256(abi.encode(nextPolicy));
        bytes32 digest = keccak256(
            abi.encode(address(guard), block.chainid, "AEVUMAEGIS_POLICY", guard.governanceNonce(), policyHash)
        );
        vm.expectRevert(abi.encodeWithSelector(GuardModule.InvalidConfiguration.selector));
        guard.updatePolicy(nextPolicy, _signQuorum(digest));
    }

    function testRecipientAuthorizationRequiresQuorum() public {
        address recipient = address(0xBADD);
        bytes32 digest = keccak256(
            abi.encode(
                address(guard),
                block.chainid,
                "AEVUMAEGIS_RECIPIENT",
                guard.governanceNonce(),
                recipient,
                true
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_ONE_KEY, digest);
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = abi.encodePacked(r, s, v);
        vm.expectRevert(abi.encodeWithSelector(GuardModule.InvalidQuorum.selector));
        guard.setRecipientAuthorization(recipient, true, signatures);
    }

    function testInvalidIntentSignatureIsRejected() public {
        GuardModule.PaymentIntent memory intent = _newIntent(supplier, 1_000_000, 81);
        vm.expectRevert(abi.encodeWithSelector(GuardModule.InvalidSignature.selector));
        vm.prank(sessionKey);
        vault.pay(intent, hex"01");
        require(!guard.usedIntentNonce(sessionKey, intent.nonce), "invalid signature consumed nonce");
    }

    function testEwmaMeanAndVarianceUpdate() public {
        require(_pay(supplier, 1_000_000), "first baseline payment blocked");
        require(_pay(supplier, 2_000_000), "second baseline payment blocked");

        GuardModule.SessionStats memory stats = guard.getSessionStats(sessionKey);
        require(stats.baselineMean == 1_125_000, "EWMA mean mismatch");
        require(stats.baselineVariance == 125_000_000_000, "EWMA variance mismatch");
    }

    function testCadenceBucketExpiresAfterItsTwentyFourHourRotation() public {
        GuardModule.Policy memory nextPolicy = guard.getPolicy();
        nextPolicy.cadenceWarmupTransactions = 1;
        nextPolicy.throttleThreatScore = 1;
        bytes32 policyHash = keccak256(abi.encode(nextPolicy));
        bytes32 digest = keccak256(
            abi.encode(address(guard), block.chainid, "AEVUMAEGIS_POLICY", guard.governanceNonce(), policyHash)
        );
        guard.updatePolicy(nextPolicy, _signQuorum(digest));

        require(_pay(supplier, 1_000_000), "initial cadence payment blocked");
        vm.warp(block.timestamp + 24 hours);
        require(!_pay(supplier, 1_000_000), "stale cadence bucket was treated as current");
        require(
            guard.getSessionStats(sessionKey).state == GuardModule.GuardState.THROTTLED,
            "expired cadence bucket did not trigger a throttle"
        );
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

        require(_pay(supplier, 1_000_000), "baseline payment blocked");
        vm.warp(block.timestamp + 4 hours);
        require(!_pay(supplier, 1_000_000), "unobserved cadence bucket was allowed");

        GuardModule.SessionStats memory stats = guard.getSessionStats(sessionKey);
        require(stats.lastThreatScore == 1, "cadence threat score mismatch");
        require(stats.state == GuardModule.GuardState.THROTTLED, "cadence deviation did not throttle");
    }

    function testLegitimatePaymentsAreAllowedAndRecorded() public {
        for (uint256 i; i < 3; ++i) {
            require(_pay(supplier, 1_000_000), "legitimate payment blocked");
        }
        GuardModule.SessionStats memory stats = guard.getSessionStats(sessionKey);
        require(stats.actionCount == 3, "action count mismatch");
        require(stats.rollingHash != bytes32(0), "hash chain did not advance");
        require(token.balanceOf(supplier) == 3_000_000, "supplier balance mismatch");
    }

    function testVelocityUsesASlidingWindowAcrossWindowBoundaries() public {
        GuardModule.Policy memory nextPolicy = guard.getPolicy();
        nextPolicy.maxTransactionsPerWindow = 2;
        bytes32 policyHash = keccak256(abi.encode(nextPolicy));
        bytes32 digest = keccak256(
            abi.encode(address(guard), block.chainid, "AEVUMAEGIS_POLICY", guard.governanceNonce(), policyHash)
        );
        guard.updatePolicy(nextPolicy, _signQuorum(digest));

        require(_pay(supplier, 1_000_000), "first payment blocked");
        vm.warp(block.timestamp + 9);
        require(_pay(supplier, 1_000_000), "second payment blocked");
        vm.warp(block.timestamp + 1);
        require(_pay(supplier, 1_000_000), "expired first payment was still counted");
        vm.warp(block.timestamp + 1);
        require(!_pay(supplier, 1_000_000), "sliding-window velocity breach was allowed");
        require(
            guard.getSessionStats(sessionKey).state == GuardModule.GuardState.THROTTLED,
            "sliding-window breach did not throttle"
        );
    }

    function testVelocityWindowResetsAtExactBoundary() public {
        for (uint256 i; i < 3; ++i) {
            require(_pay(supplier, 1_000_000), "initial window payment blocked");
        }
        vm.warp(block.timestamp + 10);
        require(_pay(supplier, 1_000_000), "payment at exact window boundary was blocked");
    }

    function testVelocityThrottlesWithoutLosingEvidence() public {
        for (uint256 i; i < 3; ++i) {
            require(_pay(supplier, 1_000_000), "initial payment blocked");
        }
        require(!_pay(supplier, 1_000_000), "velocity breach was allowed");

        GuardModule.SessionStats memory stats = guard.getSessionStats(sessionKey);
        require(stats.state == GuardModule.GuardState.THROTTLED, "session was not throttled");
        require(stats.actionCount == 4, "blocked action was not recorded");
        require(token.balanceOf(supplier) == 3_000_000, "blocked payment moved funds");
    }

    function testNoveltyFractionThrottlesAfterWarmup() public {
        GuardModule.Policy memory nextPolicy = guard.getPolicy();
        nextPolicy.cadenceWarmupTransactions = 2;
        nextPolicy.noveltyFractionThresholdWad = 5e17;
        bytes32 policyHash = keccak256(abi.encode(nextPolicy));
        bytes32 digest = keccak256(
            abi.encode(address(guard), block.chainid, "AEVUMAEGIS_POLICY", guard.governanceNonce(), policyHash)
        );
        guard.updatePolicy(nextPolicy, _signQuorum(digest));
        _authorizeRecipient(address(0xABCD), true);

        require(_pay(supplier, 1_000_000), "first supplier payment blocked");
        require(_pay(supplier, 1_000_000), "second supplier payment blocked");
        require(!_pay(address(0xABCD), 1_000_000), "novel-recipient fraction was ignored");

        GuardModule.SessionStats memory stats = guard.getSessionStats(sessionKey);
        require(stats.lastThreatScore == 2, "novelty fraction score mismatch");
        require(stats.state == GuardModule.GuardState.THROTTLED, "novelty fraction did not throttle");
        require(guard.distinctRecipientCount(sessionKey) == 2, "distinct recipient count mismatch");
    }

    function testNovelRecipientAboveThresholdThrottles() public {
        require(!_pay(address(0xD00D), 11_000_000), "novel recipient was allowed");
        GuardModule.SessionStats memory stats = guard.getSessionStats(sessionKey);
        require(stats.state == GuardModule.GuardState.THROTTLED, "novel recipient did not throttle");
        require(token.balanceOf(address(0xD00D)) == 0, "blocked payment moved funds");
    }

    function testBehaviorallyBlockedIntentConsumesItsNonce() public {
        GuardModule.PaymentIntent memory intent = _newIntent(address(0xD00D), 11_000_000, 84);
        bytes memory signature = _signIntent(intent);
        vm.prank(sessionKey);
        require(!vault.pay(intent, signature), "novel large payment was allowed");
        require(guard.usedIntentNonce(sessionKey, intent.nonce), "blocked intent nonce was not consumed");
        vm.expectRevert(abi.encodeWithSelector(GuardModule.IntentNonceAlreadyUsed.selector));
        vm.prank(sessionKey);
        vault.pay(intent, signature);
    }

    function testKnownRecipientAnomalyFreezes() public {
        for (uint256 i; i < 3; ++i) {
            require(_pay(supplier, 1_000_000), "baseline payment blocked");
        }
        require(!_pay(supplier, 20_000_000), "anomalous payment was allowed");
        require(
            guard.getSessionStats(sessionKey).state == GuardModule.GuardState.FROZEN,
            "anomaly did not freeze"
        );
    }

    function testCumulativeDrawdownFreezes() public {
        for (uint256 i; i < 21; ++i) {
            if (i > 0 && i % 3 == 0) vm.warp(block.timestamp + 11);
            bool allowed = _pay(supplier, 5_000_000);
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

    function testCompliantAttemptDuringThrottleDoesNotEscalate() public {
        for (uint256 i; i < 3; ++i) {
            require(_pay(supplier, 1_000_000), "initial payment blocked");
        }
        require(!_pay(supplier, 1_000_000), "velocity breach was allowed");
        vm.warp(block.timestamp + 11);
        require(!_pay(supplier, 1_000_000), "throttled session payment was allowed");

        GuardModule.SessionStats memory stats = guard.getSessionStats(sessionKey);
        require(stats.state == GuardModule.GuardState.THROTTLED, "compliant retry escalated to freeze");
        require(stats.actionCount == 5, "throttled retry was not recorded");
        require(token.balanceOf(supplier) == 3_000_000, "throttled retry moved funds");
    }

    function testFurtherVelocityViolationDuringThrottleEscalatesToFreeze() public {
        for (uint256 i; i < 3; ++i) {
            _pay(supplier, 1_000_000);
        }
        require(!_pay(supplier, 1_000_000), "velocity breach was allowed");
        require(!_pay(supplier, 1_000_000), "throttled session was allowed to pay");
        require(
            guard.getSessionStats(sessionKey).state == GuardModule.GuardState.FROZEN,
            "throttled session did not escalate"
        );
    }

    function testVelocityFollowedByAnotherViolationFreezes() public {
        for (uint256 i; i < 3; ++i) {
            _pay(supplier, 1_000_000);
        }
        _pay(supplier, 1_000_000);
        _pay(address(0xD00D), 20_000_000);

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
        bool allowed = _pay(supplier, amount);
        if (!allowed) {
            require(token.balanceOf(supplier) == 0, "blocked payment transferred tokens");
        }
    }

    function _pay(address recipient, uint256 amount) private returns (bool allowed) {
        GuardModule.PaymentIntent memory intent = _newIntent(recipient, amount, intentNonce++);
        bytes memory signature = _signIntent(intent);
        vm.prank(sessionKey);
        return vault.pay(intent, signature);
    }

    function _newIntent(address recipient, uint256 amount, uint256 nonce)
        private
        view
        returns (GuardModule.PaymentIntent memory)
    {
        return GuardModule.PaymentIntent({
            recipient: recipient,
            amount: amount,
            purposeHash: PAYMENT_PURPOSE,
            nonce: nonce,
            expiry: block.timestamp + 1 days
        });
    }

    function _signIntent(GuardModule.PaymentIntent memory intent)
        private
        returns (bytes memory signature)
    {
        bytes32 digest = keccak256(
            abi.encode(
                guard.PAYMENT_INTENT_TYPEHASH(),
                address(vault),
                block.chainid,
                sessionKey,
                intent.recipient,
                intent.amount,
                intent.purposeHash,
                intent.nonce,
                intent.expiry
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SESSION_KEY_PRIVATE_KEY, digest);
        return abi.encodePacked(r, s, v);
    }

    function _authorizeRecipient(address recipient, bool authorized) private {
        bytes32 digest = keccak256(
            abi.encode(
                address(guard),
                block.chainid,
                "AEVUMAEGIS_RECIPIENT",
                guard.governanceNonce(),
                recipient,
                authorized
            )
        );
        guard.setRecipientAuthorization(recipient, authorized, _signQuorum(digest));
        bytes32 purposeDigest = keccak256(
            abi.encode(
                address(guard),
                block.chainid,
                "AEVUMAEGIS_PURPOSE",
                guard.governanceNonce(),
                recipient,
                PAYMENT_PURPOSE,
                authorized ? uint256(1_000_000_000_000_000_000) : uint256(0),
                authorized
            )
        );
        guard.setPurposeAuthorization(
            recipient,
            PAYMENT_PURPOSE,
            authorized ? uint256(1_000_000_000_000_000_000) : uint256(0),
            authorized,
            _signQuorum(purposeDigest)
        );
    }

    function _freezeSession() private {
        for (uint256 i; i < 3; ++i) {
            _pay(supplier, 1_000_000);
        }
        _pay(supplier, 1_000_000);
        _pay(address(0xD00D), 20_000_000);
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
