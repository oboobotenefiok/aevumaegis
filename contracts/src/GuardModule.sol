// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ISignatureVerifier} from "./ISignatureVerifier.sol";

interface IAgentVaultControl {
    function owner() external view returns (address);
    function sessionKey() external view returns (address);
    function rotateSessionKey(address newSessionKey) external;
}

/// @title GuardModule
/// @notice On-chain behavioral circuit breaker and tamper-evident action recorder.
/// @dev An authenticated payment blocked by behavioral policy returns false rather
///      than reverting, preserving the state transition and forensic events. Invalid
///      intents revert before they enter the behavioral action history.
contract GuardModule {
    enum GuardState {
        ACTIVE,
        THROTTLED,
        FROZEN
    }

    enum ActionKind {
        PAYMENT,
        BLOCKED_PAYMENT
    }

    bytes32 public constant REASON_VELOCITY = keccak256("VELOCITY_LIMIT");
    bytes32 public constant REASON_NOVEL_RECIPIENT = keccak256("NOVEL_RECIPIENT");
    bytes32 public constant REASON_ANOMALY = keccak256("ANOMALY_Z_SCORE");
    bytes32 public constant REASON_DRAWDOWN = keccak256("DRAWDOWN_LIMIT");
    bytes32 public constant REASON_CADENCE = keccak256("CADENCE_DEVIATION");
    bytes32 public constant REASON_NOVEL_RECIPIENT_LARGE_AMOUNT = keccak256("NOVEL_RECIPIENT_LARGE_AMOUNT");
    bytes32 public constant REASON_COMPOSITE_SCORE = keccak256("COMPOSITE_THREAT_SCORE");
    bytes32 public constant REASON_THROTTLE_ACTIVE = keccak256("THROTTLE_STILL_ACTIVE");

    uint256 private constant EWMA_PERIOD = 8;
    uint256 private constant WAD = 1e18;
    uint256 private constant MAX_TRACKED_AMOUNT = 1e18;
    uint256 private constant BUCKET_COUNT = 6;
    uint256 private constant BUCKET_DURATION = 4 hours;
    uint8 private constant VELOCITY_HISTORY_CAPACITY = 64;
    uint8 private constant MAX_THREAT_SCORE = 11;

    struct Policy {
        uint32 maxTransactionsPerWindow;
        uint32 windowSeconds;
        uint32 throttleSeconds;
        uint64 noveltyAmountThreshold;
        uint64 noveltyFractionThresholdWad;
        uint64 zScoreThresholdWad;
        uint64 drawdownLimit;
        uint32 cadenceWarmupTransactions;
        uint8 throttleThreatScore;
        uint8 freezeThreatScore;
    }

    struct PaymentIntent {
        address recipient;
        uint256 amount;
        bytes32 purposeHash;
        uint256 nonce;
        uint256 expiry;
    }

    bytes32 public constant PAYMENT_INTENT_TYPEHASH = keccak256(
        "PaymentIntent(address vault,uint256 chainId,address sessionKey,address recipient,uint256 amount,bytes32 purposeHash,uint256 nonce,uint256 expiry)"
    );

    struct SessionStats {
        GuardState state;
        uint64 throttleUntil;
        uint256 actionCount;
        uint64 cumulativeSpend;
        uint64 baselineMean;
        uint128 baselineVariance;
        uint32 totalObservedTransactions;
        uint8 lastThreatScore;
        bytes32 rollingHash;
        bytes32 finalForensicHash;
        bytes32 freezeReason;
        bool hasBaseline;
    }

    address public immutable vault;
    address public immutable sentinel;
    ISignatureVerifier public signatureVerifier;
    Policy public policy;
    uint256 public immutable unfreezeCooldown;
    uint256 public governanceNonce;
    uint256 public unfreezeRequestedAt;
    uint256 public immutable requiredOwnerSignatures;
    address public pendingSessionKey;
    bool public unfreezePending;

    address[] private owners;
    mapping(address => bool) public isOwner;
    mapping(address => bool) public usedSessionKeys;
    mapping(address => mapping(address => bool)) public seenRecipient;
    mapping(address => mapping(address => bool)) public recipientObserved;
    mapping(address => uint32) public distinctRecipientCount;
    mapping(address => bool) public authorizedRecipient;
    mapping(address => uint256) public recipientAuthorizationEpoch;
    mapping(address => mapping(bytes32 => uint256)) private purposeAuthorizationEpoch;
    mapping(address => mapping(bytes32 => uint256)) private purposeAuthorizationMaxAmount;
    mapping(address => mapping(uint256 => bool)) public usedIntentNonce;
    mapping(address => mapping(uint8 => uint32)) public cadenceBucketCounts;
    mapping(address => mapping(uint8 => uint64)) public cadenceBucketEpochs;
    mapping(address => mapping(uint8 => uint64)) private velocityTimestamps;
    mapping(address => uint8) private velocityHead;
    mapping(address => uint8) private velocityTail;
    mapping(address => uint8) private velocityCount;
    mapping(address => mapping(uint8 => bool)) private velocityNoveltyFlags;
    mapping(address => uint8) private velocityNoveltyCount;
    mapping(address => SessionStats) private sessionStats;

    event ActionRecorded(uint256 indexed index, bytes32 indexed actionHash, ActionKind kind, bytes32 intentHash);
    event RecipientAuthorizationUpdated(address indexed recipient, bool authorized, uint256 governanceNonce);
    event PurposeAuthorizationUpdated(
        address indexed recipient,
        bytes32 indexed purposeHash,
        uint256 maxAmount,
        bool authorized,
        uint256 governanceNonce
    );
    event PaymentIntentAuthenticated(
        address indexed sessionKey,
        address indexed recipient,
        uint256 amount,
        bytes32 purposeHash,
        uint256 nonce,
        uint256 expiry,
        bytes32 intentHash
    );
    event ForensicCommitment(bytes32 indexed finalHash, uint256 actionCount, bytes32 reasonCode);
    event SessionKeyThrottled(address indexed sessionKey, bytes32 reasonCode, uint256 untilTimestamp);
    event SessionKeyFrozen(address indexed sessionKey, bytes32 reasonCode, bytes32 finalHash);
    event PaymentDecision(address indexed sessionKey, address indexed recipient, uint256 amount, bool allowed);
    event ThreatScoreUpdated(address indexed sessionKey, uint8 score);
    event UnfreezeRequested(bytes32 indexed digest, address indexed newSessionKey, uint256 executableAt);
    event UnfreezeExecuted(address indexed previousSessionKey, address indexed newSessionKey, uint256 timestamp);
    event UnfreezeVetoed(address indexed sentinel, uint256 timestamp);
    event PolicyUpdated(bytes32 indexed policyHash, uint256 governanceNonce);
    event SignatureVerifierUpdated(address indexed verifier);

    error OnlyVault();
    error InvalidConfiguration();
    error InvalidQuorum();
    error InvalidSignature();
    error NotSentinel();
    error NoPendingUnfreeze();
    error CooldownActive();
    error SessionNotFrozen();
    error UnfreezeAlreadyPending();
    error VetoWindowExpired();
    error InvalidPaymentIntent();
    error PaymentIntentExpired();
    error UnauthorizedRecipient();
    error UnauthorizedPurpose();
    error PurposeAmountExceeded();
    error IntentNonceAlreadyUsed();

    modifier onlyVault() {
        if (msg.sender != vault) revert OnlyVault();
        _;
    }

    constructor(
        address vaultAddress,
        address sentinelAddress,
        address verifierAddress,
        address[] memory ownerAddresses,
        uint256 requiredSignatures,
        uint256 cooldownSeconds,
        Policy memory initialPolicy
    ) {
        if (
            vaultAddress == address(0) || vaultAddress.code.length == 0 ||
            sentinelAddress == address(0) || sentinelAddress.code.length != 0 ||
            verifierAddress == address(0) || verifierAddress.code.length == 0 || ownerAddresses.length == 0 ||
            requiredSignatures == 0 || requiredSignatures > ownerAddresses.length ||
            initialPolicy.maxTransactionsPerWindow == 0 ||
            initialPolicy.maxTransactionsPerWindow >= VELOCITY_HISTORY_CAPACITY ||
            initialPolicy.windowSeconds == 0 ||
            initialPolicy.throttleSeconds == 0 || initialPolicy.zScoreThresholdWad == 0 ||
            initialPolicy.drawdownLimit == 0 || initialPolicy.noveltyAmountThreshold == 0 ||
            initialPolicy.noveltyFractionThresholdWad == 0 ||
            initialPolicy.noveltyFractionThresholdWad > WAD ||
            initialPolicy.cadenceWarmupTransactions == 0 || initialPolicy.throttleThreatScore == 0 ||
            initialPolicy.freezeThreatScore <= initialPolicy.throttleThreatScore ||
            initialPolicy.freezeThreatScore > MAX_THREAT_SCORE || cooldownSeconds == 0 ||
            ownerAddresses.length > 10
        ) revert InvalidConfiguration();

        vault = vaultAddress;
        address initialSessionKey = IAgentVaultControl(vaultAddress).sessionKey();
        if (
            initialSessionKey == address(0) || initialSessionKey == sentinelAddress ||
            initialSessionKey.code.length != 0
        ) {
            revert InvalidConfiguration();
        }
        usedSessionKeys[initialSessionKey] = true;
        sentinel = sentinelAddress;
        signatureVerifier = ISignatureVerifier(verifierAddress);
        unfreezeCooldown = cooldownSeconds;
        requiredOwnerSignatures = requiredSignatures;
        policy = initialPolicy;

        for (uint256 i; i < ownerAddresses.length; ++i) {
            address ownerAddress = ownerAddresses[i];
            if (
                ownerAddress == address(0) || ownerAddress.code.length != 0 ||
                ownerAddress == sentinelAddress || ownerAddress == initialSessionKey || isOwner[ownerAddress]
            ) revert InvalidConfiguration();
            isOwner[ownerAddress] = true;
            owners.push(ownerAddress);
        }
        if (!isOwner[IAgentVaultControl(vaultAddress).owner()]) revert InvalidConfiguration();
    }

    function ownerCount() external view returns (uint256) {
        return owners.length;
    }

    function getOwners() external view returns (address[] memory) {
        return owners;
    }

    function getSessionStats(address sessionKey) external view returns (SessionStats memory) {
        return sessionStats[sessionKey];
    }

    function getSessionState(address sessionKey) external view returns (GuardState) {
        return sessionStats[sessionKey].state;
    }

    function getActionCount(address sessionKey) external view returns (uint256) {
        return sessionStats[sessionKey].actionCount;
    }

    function getFinalForensicHash(address sessionKey) external view returns (bytes32) {
        return sessionStats[sessionKey].finalForensicHash;
    }

    function getPolicy() external view returns (Policy memory) {
        return policy;
    }

    /// @notice Evaluates a proposed transfer and records its action before returning.
    /// @return allowed True only when Vault may transfer the token.
    function evaluatePayment(
        address sessionKey,
        PaymentIntent calldata intent,
        bytes calldata signature
    ) external onlyVault returns (bool allowed) {
        if (
            intent.recipient == address(0) || intent.amount == 0 ||
            intent.amount > MAX_TRACKED_AMOUNT || intent.purposeHash == bytes32(0)
        ) revert InvalidPaymentIntent();
        if (intent.expiry < block.timestamp) revert PaymentIntentExpired();
        if (!authorizedRecipient[intent.recipient]) revert UnauthorizedRecipient();
        uint256 purposeMaxAmount = authorizedPurposeAmount(intent.recipient, intent.purposeHash);
        if (purposeMaxAmount == 0) revert UnauthorizedPurpose();
        if (intent.amount > purposeMaxAmount) revert PurposeAmountExceeded();
        if (usedIntentNonce[sessionKey][intent.nonce]) revert IntentNonceAlreadyUsed();

        bytes32 intentDigest = keccak256(
            abi.encode(
                PAYMENT_INTENT_TYPEHASH,
                vault,
                block.chainid,
                sessionKey,
                intent.recipient,
                intent.amount,
                intent.purposeHash,
                intent.nonce,
                intent.expiry
            )
        );
        if (!signatureVerifier.verify(intentDigest, sessionKey, signature)) revert InvalidSignature();
        usedIntentNonce[sessionKey][intent.nonce] = true;
        emit PaymentIntentAuthenticated(
            sessionKey,
            intent.recipient,
            intent.amount,
            intent.purposeHash,
            intent.nonce,
            intent.expiry,
            intentDigest
        );

        SessionStats storage stats = sessionStats[sessionKey];
        if (stats.state == GuardState.FROZEN) {
            _recordAction(
                stats,
                sessionKey,
                intent.recipient,
                intent.amount,
                ActionKind.BLOCKED_PAYMENT,
                intentDigest
            );
            stats.finalForensicHash = stats.rollingHash;
            emit ForensicCommitment(stats.finalForensicHash, stats.actionCount, stats.freezeReason);
            emit PaymentDecision(sessionKey, intent.recipient, intent.amount, false);
            return false;
        }

        if (stats.state == GuardState.THROTTLED && block.timestamp >= stats.throttleUntil) {
            stats.state = GuardState.ACTIVE;
        }

        bytes32 violation = _evaluateBehavior(sessionKey, intent.recipient, intent.amount, stats);
        ActionKind actionKind = violation == bytes32(0)
            ? ActionKind.PAYMENT
            : ActionKind.BLOCKED_PAYMENT;
        _recordAction(stats, sessionKey, intent.recipient, intent.amount, actionKind, intentDigest);

        if (violation == REASON_THROTTLE_ACTIVE) {
            emit PaymentDecision(sessionKey, intent.recipient, intent.amount, false);
            return false;
        }

        if (violation != bytes32(0)) {
            bool hardFreeze =
                violation == REASON_ANOMALY || violation == REASON_DRAWDOWN ||
                violation == REASON_COMPOSITE_SCORE;
            if (stats.state == GuardState.THROTTLED || hardFreeze) {
                _freeze(sessionKey, stats, violation);
            } else {
                stats.state = GuardState.THROTTLED;
                stats.throttleUntil = uint64(block.timestamp + policy.throttleSeconds);
                emit SessionKeyThrottled(sessionKey, violation, stats.throttleUntil);
            }
            emit PaymentDecision(sessionKey, intent.recipient, intent.amount, false);
            return false;
        }

        stats.cumulativeSpend += uint64(intent.amount);
        _updateBaseline(stats, intent.amount);
        _recordCadence(sessionKey);
        seenRecipient[sessionKey][intent.recipient] = true;
        emit PaymentDecision(sessionKey, intent.recipient, intent.amount, true);
        return true;
    }

    function _recordAction(
        SessionStats storage stats,
        address sessionKey,
        address recipient,
        uint256 amount,
        ActionKind kind,
        bytes32 intentHash
    ) private {
        uint256 actionIndex = stats.actionCount + 1;
        bytes32 actionHash = keccak256(
            abi.encode(
                stats.rollingHash,
                sessionKey,
                recipient,
                amount,
                block.timestamp,
                actionIndex,
                kind,
                intentHash
            )
        );
        stats.rollingHash = actionHash;
        stats.actionCount = actionIndex;
        emit ActionRecorded(actionIndex, actionHash, kind, intentHash);
    }

    function requestUnfreeze(address newSessionKey, bytes[] calldata signatures) external {
        if (unfreezePending) revert UnfreezeAlreadyPending();
        if (!_sessionStateIsFrozen()) revert SessionNotFrozen();
        if (
            newSessionKey == address(0) || newSessionKey.code.length != 0 ||
            newSessionKey == sentinel || isOwner[newSessionKey] || usedSessionKeys[newSessionKey]
        ) revert InvalidConfiguration();
        bytes32 digest = keccak256(
            abi.encode(
                address(this),
                block.chainid,
                "AEVUMAEGIS_UNFREEZE",
                governanceNonce,
                unfreezeRequestedAt,
                newSessionKey
            )
        );
        _verifyQuorum(digest, signatures);
        unfreezePending = true;
        pendingSessionKey = newSessionKey;
        unfreezeRequestedAt = block.timestamp;
        emit UnfreezeRequested(digest, newSessionKey, block.timestamp + unfreezeCooldown);
    }

    function vetoUnfreeze() external {
        if (msg.sender != sentinel) revert NotSentinel();
        if (!unfreezePending) revert NoPendingUnfreeze();
        if (block.timestamp >= unfreezeRequestedAt + unfreezeCooldown) revert VetoWindowExpired();
        unfreezePending = false;
        pendingSessionKey = address(0);
        unfreezeRequestedAt = 0;
        ++governanceNonce;
        emit UnfreezeVetoed(msg.sender, block.timestamp);
    }

    function executeUnfreeze() external {
        if (!unfreezePending) revert NoPendingUnfreeze();
        if (block.timestamp < unfreezeRequestedAt + unfreezeCooldown) revert CooldownActive();
        address previousKey = _vaultSessionKey();
        address newSessionKey = pendingSessionKey;
        if (sessionStats[previousKey].state != GuardState.FROZEN) revert SessionNotFrozen();
        if (
            newSessionKey == address(0) || newSessionKey.code.length != 0 ||
            newSessionKey == sentinel || isOwner[newSessionKey] || usedSessionKeys[newSessionKey]
        ) revert InvalidConfiguration();

        usedSessionKeys[newSessionKey] = true;
        IAgentVaultControl(vault).rotateSessionKey(newSessionKey);
        unfreezePending = false;
        pendingSessionKey = address(0);
        unfreezeRequestedAt = 0;
        ++governanceNonce;
        emit UnfreezeExecuted(previousKey, newSessionKey, block.timestamp);
    }

    function setRecipientAuthorization(
        address recipient,
        bool authorized,
        bytes[] calldata signatures
    ) external {
        if (recipient == address(0) || recipient == vault) revert InvalidConfiguration();
        bytes32 digest = keccak256(
            abi.encode(
                address(this),
                block.chainid,
                "AEVUMAEGIS_RECIPIENT",
                governanceNonce,
                recipient,
                authorized
            )
        );
        _verifyQuorum(digest, signatures);
        if (authorizedRecipient[recipient] != authorized) {
            ++recipientAuthorizationEpoch[recipient];
        }
        authorizedRecipient[recipient] = authorized;
        ++governanceNonce;
        emit RecipientAuthorizationUpdated(recipient, authorized, governanceNonce);
    }

    function setPurposeAuthorization(
        address recipient,
        bytes32 purposeHash,
        uint256 maxAmount,
        bool authorized,
        bytes[] calldata signatures
    ) external {
        if (
            recipient == address(0) || recipient == address(vault) || purposeHash == bytes32(0) ||
            (authorized && (maxAmount == 0 || maxAmount > MAX_TRACKED_AMOUNT)) ||
            (!authorized && maxAmount != 0)
        ) revert InvalidConfiguration();

        bytes32 digest = keccak256(
            abi.encode(
                address(this),
                block.chainid,
                "AEVUMAEGIS_PURPOSE",
                governanceNonce,
                recipient,
                purposeHash,
                maxAmount,
                authorized
            )
        );
        _verifyQuorum(digest, signatures);
        if (authorized && !authorizedRecipient[recipient]) revert UnauthorizedRecipient();
        purposeAuthorizationEpoch[recipient][purposeHash] =
            authorized ? recipientAuthorizationEpoch[recipient] : 0;
        purposeAuthorizationMaxAmount[recipient][purposeHash] = authorized ? maxAmount : 0;
        ++governanceNonce;
        emit PurposeAuthorizationUpdated(recipient, purposeHash, maxAmount, authorized, governanceNonce);
    }

    function authorizedPurposeHash(address recipient, bytes32 purposeHash)
        public
        view
        returns (bool)
    {
        uint256 currentEpoch = recipientAuthorizationEpoch[recipient];
        return
            authorizedRecipient[recipient] && currentEpoch != 0 &&
            purposeAuthorizationEpoch[recipient][purposeHash] == currentEpoch &&
            purposeAuthorizationMaxAmount[recipient][purposeHash] != 0;
    }

    function authorizedPurposeAmount(address recipient, bytes32 purposeHash)
        public
        view
        returns (uint256)
    {
        if (!authorizedPurposeHash(recipient, purposeHash)) return 0;
        return purposeAuthorizationMaxAmount[recipient][purposeHash];
    }

    function updatePolicy(Policy calldata newPolicy, bytes[] calldata signatures) external {
        if (
            newPolicy.maxTransactionsPerWindow == 0 ||
            newPolicy.maxTransactionsPerWindow >= VELOCITY_HISTORY_CAPACITY ||
            newPolicy.windowSeconds == 0 ||
            newPolicy.throttleSeconds == 0 || newPolicy.zScoreThresholdWad == 0 ||
            newPolicy.drawdownLimit == 0 || newPolicy.noveltyAmountThreshold == 0 ||
            newPolicy.noveltyFractionThresholdWad == 0 ||
            newPolicy.noveltyFractionThresholdWad > WAD ||
            newPolicy.cadenceWarmupTransactions == 0 || newPolicy.throttleThreatScore == 0 ||
            newPolicy.freezeThreatScore <= newPolicy.throttleThreatScore ||
            newPolicy.freezeThreatScore > MAX_THREAT_SCORE
        ) revert InvalidConfiguration();
        bytes32 policyHash = keccak256(abi.encode(newPolicy));
        bytes32 digest = keccak256(
            abi.encode(address(this), block.chainid, "AEVUMAEGIS_POLICY", governanceNonce, policyHash)
        );
        _verifyQuorum(digest, signatures);
        policy = newPolicy;
        ++governanceNonce;
        emit PolicyUpdated(policyHash, governanceNonce);
    }

    function updateSignatureVerifier(address newVerifier, bytes[] calldata signatures) external {
        if (newVerifier == address(0) || newVerifier.code.length == 0) revert InvalidConfiguration();
        bytes32 digest = keccak256(
            abi.encode(address(this), block.chainid, "AEVUMAEGIS_VERIFIER", governanceNonce, newVerifier)
        );
        _verifyQuorum(digest, signatures);
        signatureVerifier = ISignatureVerifier(newVerifier);
        ++governanceNonce;
        emit SignatureVerifierUpdated(newVerifier);
    }

    function _evaluateBehavior(
        address sessionKey,
        address recipient,
        uint256 amount,
        SessionStats storage stats
    ) private returns (bytes32) {
        bool isNewRecipient = !recipientObserved[sessionKey][recipient];
        if (isNewRecipient) {
            recipientObserved[sessionKey][recipient] = true;
            ++distinctRecipientCount[sessionKey];
        }
        (bool velocityExceeded, uint256 noveltyFractionWad) =
            _recordVelocity(sessionKey, isNewRecipient);
        bool noveltyFractionExceeded =
            stats.totalObservedTransactions >= policy.cadenceWarmupTransactions &&
            noveltyFractionWad >= policy.noveltyFractionThresholdWad;

        bool anomalous;
        if (stats.hasBaseline) {
            uint256 mean = stats.baselineMean;
            uint256 delta = amount > mean ? amount - mean : mean - amount;
            uint256 standardDeviation = _sqrt(uint256(stats.baselineVariance));
            if (standardDeviation == 0) {
                anomalous = delta > 0 && amount > policy.noveltyAmountThreshold;
            } else {
                anomalous = delta * WAD / standardDeviation > policy.zScoreThresholdWad;
            }
        }

        bool novelLarge = !seenRecipient[sessionKey][recipient] && amount > policy.noveltyAmountThreshold;
        bool drawdownExceeded = stats.cumulativeSpend + amount > policy.drawdownLimit;
        uint64 bucketEpoch = uint64(block.timestamp / BUCKET_DURATION);
        uint8 bucket = uint8(bucketEpoch % BUCKET_COUNT);
        bool cadenceDeviation = stats.totalObservedTransactions >= policy.cadenceWarmupTransactions &&
            (cadenceBucketEpochs[sessionKey][bucket] != bucketEpoch ||
                cadenceBucketCounts[sessionKey][bucket] == 0);

        uint8 score;
        if (velocityExceeded) score += 2;
        if (novelLarge || noveltyFractionExceeded) score += 2;
        if (anomalous) score += 3;
        if (drawdownExceeded) score += 3;
        if (cadenceDeviation) score += 1;
        stats.lastThreatScore = score;
        emit ThreatScoreUpdated(sessionKey, score);

        if (stats.state == GuardState.THROTTLED && novelLarge) {
            return REASON_NOVEL_RECIPIENT_LARGE_AMOUNT;
        }
        if (anomalous) return REASON_ANOMALY;
        if (drawdownExceeded) return REASON_DRAWDOWN;
        if (stats.state == GuardState.THROTTLED) {
            if (noveltyFractionExceeded) return REASON_NOVEL_RECIPIENT;
            if (velocityExceeded) return REASON_VELOCITY;
            if (cadenceDeviation) return REASON_CADENCE;
            return REASON_THROTTLE_ACTIVE;
        }
        if (score >= policy.freezeThreatScore) return REASON_COMPOSITE_SCORE;
        if (score >= policy.throttleThreatScore) {
            if (novelLarge || noveltyFractionExceeded) return REASON_NOVEL_RECIPIENT;
            if (velocityExceeded) return REASON_VELOCITY;
            if (cadenceDeviation) return REASON_CADENCE;
        }

        return bytes32(0);
    }

    function _updateBaseline(SessionStats storage stats, uint256 amount) private {
        if (!stats.hasBaseline) {
            stats.baselineMean = uint64(amount);
            stats.baselineVariance = 0;
            stats.hasBaseline = true;
        } else {
            uint256 oldMean = stats.baselineMean;
            uint256 delta = amount > oldMean ? amount - oldMean : oldMean - amount;
            uint256 variance = (uint256(stats.baselineVariance) * (EWMA_PERIOD - 1) + delta * delta) / EWMA_PERIOD;
            stats.baselineVariance = uint128(variance);
            stats.baselineMean = uint64((oldMean * (EWMA_PERIOD - 1) + amount) / EWMA_PERIOD);
        }
        ++stats.totalObservedTransactions;
    }

    function _recordVelocity(address sessionKey, bool isNewRecipient)
        private
        returns (bool exceeded, uint256 noveltyFractionWad)
    {
        uint8 head = velocityHead[sessionKey];
        uint8 count = velocityCount[sessionKey];
        uint8 novelCount = velocityNoveltyCount[sessionKey];

        while (count > 0) {
            uint64 oldestTimestamp = velocityTimestamps[sessionKey][head];
            if (
                block.timestamp < oldestTimestamp ||
                block.timestamp - oldestTimestamp < policy.windowSeconds
            ) break;

            if (velocityNoveltyFlags[sessionKey][head]) --novelCount;
            head = uint8((uint256(head) + 1) % VELOCITY_HISTORY_CAPACITY);
            --count;
        }

        velocityHead[sessionKey] = head;
        exceeded = uint256(count) + 1 > policy.maxTransactionsPerWindow;

        // Keep the newest 64 actions. The configured threshold is capped at 63,
        // so dropping the oldest entry cannot hide a threshold breach.
        if (count == VELOCITY_HISTORY_CAPACITY) {
            if (velocityNoveltyFlags[sessionKey][head]) --novelCount;
            head = uint8((uint256(head) + 1) % VELOCITY_HISTORY_CAPACITY);
            --count;
            velocityHead[sessionKey] = head;
        }

        uint8 tail = velocityTail[sessionKey];
        velocityTimestamps[sessionKey][tail] = uint64(block.timestamp);
        velocityNoveltyFlags[sessionKey][tail] = isNewRecipient;
        velocityTail[sessionKey] = uint8((uint256(tail) + 1) % VELOCITY_HISTORY_CAPACITY);
        if (isNewRecipient) ++novelCount;
        ++count;
        velocityCount[sessionKey] = count;
        velocityNoveltyCount[sessionKey] = novelCount;
        noveltyFractionWad = uint256(novelCount) * WAD / count;
    }

    function _recordCadence(address sessionKey) private {
        uint64 bucketEpoch = uint64(block.timestamp / BUCKET_DURATION);
        uint8 bucket = uint8(bucketEpoch % BUCKET_COUNT);
        if (cadenceBucketEpochs[sessionKey][bucket] != bucketEpoch) {
            cadenceBucketEpochs[sessionKey][bucket] = bucketEpoch;
            cadenceBucketCounts[sessionKey][bucket] = 0;
        }
        ++cadenceBucketCounts[sessionKey][bucket];
    }

    function _freeze(address sessionKey, SessionStats storage stats, bytes32 reasonCode) private {
        stats.state = GuardState.FROZEN;
        stats.freezeReason = reasonCode;
        stats.finalForensicHash = stats.rollingHash;
        unfreezePending = false;
        pendingSessionKey = address(0);
        unfreezeRequestedAt = 0;
        emit SessionKeyFrozen(sessionKey, reasonCode, stats.finalForensicHash);
        emit ForensicCommitment(stats.finalForensicHash, stats.actionCount, reasonCode);
    }

    function _verifyQuorum(bytes32 digest, bytes[] calldata signatures) private view {
        uint256 sigLen = signatures.length;
        if (sigLen < requiredOwnerSignatures || sigLen > owners.length) revert InvalidQuorum();

        uint256 validSignatures;
        // Track used owner indices with a bitmask (owners.length <= 10 per constructor).
        uint256 usedMask;

        for (uint256 i; i < sigLen; ++i) {
            bytes calldata sig = signatures[i];
            for (uint256 j; j < owners.length; ++j) {
                if ((usedMask & (1 << j)) != 0) continue;
                address candidate = owners[j];
                if (signatureVerifier.verify(digest, candidate, sig)) {
                    usedMask |= (1 << j);
                    ++validSignatures;
                    break;
                }
            }
        }
        if (validSignatures < requiredOwnerSignatures) revert InvalidSignature();
    }

    function _sessionStateIsFrozen() private view returns (bool) {
        // This module is bound to one Vault. The Vault exposes its active session key.
        return sessionStats[_vaultSessionKey()].state == GuardState.FROZEN;
    }

    function _vaultSessionKey() private view returns (address) {
        return IAgentVaultControl(vault).sessionKey();
    }

    function _sqrt(uint256 value) private pure returns (uint256) {
        if (value == 0) return 0;

        uint256 x = value;
        uint256 log2;
        if ((x >> 128) > 0) { x >>= 128; log2 += 128; }
        if ((x >> 64) > 0) { x >>= 64; log2 += 64; }
        if ((x >> 32) > 0) { x >>= 32; log2 += 32; }
        if ((x >> 16) > 0) { x >>= 16; log2 += 16; }
        if ((x >> 8) > 0) { x >>= 8; log2 += 8; }
        if ((x >> 4) > 0) { x >>= 4; log2 += 4; }
        if ((x >> 2) > 0) { log2 += 2; }
        if ((x >> 1) > 0) { log2 += 1; }

        uint256 estimate = uint256(1) << (log2 >> 1);
        for (uint256 i; i < 7; ++i) {
            estimate = (estimate + value / estimate) >> 1;
        }
        uint256 roundedDown = value / estimate;
        return estimate < roundedDown ? estimate : roundedDown;
    }
}
