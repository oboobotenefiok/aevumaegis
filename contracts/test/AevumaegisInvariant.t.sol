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
    function addr(uint256 privateKey) external returns (address);
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
    function prank(address sender) external;
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
    uint256 public trackedSpend;
    address private sessionKey;
    uint256 private nonce;
    uint256 private constant SESSION_KEY_PRIVATE_KEY = 0xBADC0DE;
    uint256 private constant OWNER_ONE_KEY = 0xA11CE;
    uint256 private constant OWNER_TWO_KEY = 0xB0B;
    bytes32 private constant PURPOSE_HASH = keccak256("invariant-payment-purpose");

    function configure(
        AgentVault vaultAddress,
        GuardModule guardAddress,
        IERC20Invariant tokenAddress,
        address sessionKeyAddress
    ) external {
        vault = vaultAddress;
        guard = guardAddress;
        token = tokenAddress;
        sessionKey = sessionKeyAddress;
        for (uint160 recipientOffset; recipientOffset < 16; ++recipientOffset) {
            _authorizeRecipient(address(uint160(0x1000) + recipientOffset));
        }
    }

    function attempt(address rawRecipient, uint96 rawAmount, uint32 elapsedSeconds) external {
        vmInvariant().warp(block.timestamp + uint256(elapsedSeconds) % 3_600);
        uint256 amount = uint256(rawAmount) % 20_000_000 + 1;
        uint160 recipientOffset = uint160(uint256(uint160(rawRecipient)) % 16);
        address recipient = address(uint160(0x1000) + recipientOffset);
        GuardModule.PaymentIntent memory intent = GuardModule.PaymentIntent({
            recipient: recipient,
            amount: amount,
            purposeHash: PURPOSE_HASH,
            nonce: nonce++,
            expiry: block.timestamp + 1 days
        });
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
        (uint8 v, bytes32 r, bytes32 s) = vmInvariant().sign(SESSION_KEY_PRIVATE_KEY, digest);
        bytes memory signature = abi.encodePacked(r, s, v);
        uint256 beforeBalance = token.balanceOf(recipient);
        uint256 beforeVaultBalance = token.balanceOf(address(vault));
        vmInvariant().prank(sessionKey);
        bool allowed = vault.pay(intent, signature);
        uint256 afterBalance = token.balanceOf(recipient);
        uint256 afterVaultBalance = token.balanceOf(address(vault));

        if (allowed) {
            trackedSpend += amount;
            if (afterBalance != beforeBalance + amount || afterVaultBalance + amount != beforeVaultBalance) {
                invariantViolated = true;
            }
        } else if (afterBalance != beforeBalance || afterVaultBalance != beforeVaultBalance) {
            invariantViolated = true;
        }

        GuardModule.SessionStats memory stats = guard.getSessionStats(sessionKey);
        GuardModule.Policy memory activePolicy = guard.getPolicy();
        if (
            stats.cumulativeSpend != trackedSpend || stats.cumulativeSpend > activePolicy.drawdownLimit ||
            guard.distinctRecipientCount(sessionKey) > 16
        ) {
            invariantViolated = true;
        }
        if (stats.state == GuardModule.GuardState.FROZEN && (allowed || afterBalance != beforeBalance)) {
            invariantViolated = true;
        }
    }

    function _authorizeRecipient(address recipient) private {
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
        guard.setRecipientAuthorization(recipient, true, _signQuorum(digest));
        bytes32 purposeDigest = keccak256(
            abi.encode(
                address(guard),
                block.chainid,
                "AEVUMAEGIS_PURPOSE",
                guard.governanceNonce(),
                recipient,
                PURPOSE_HASH,
                uint256(20_000_000),
                true
            )
        );
        bytes[] memory purposeSignatures = _signQuorum(purposeDigest);
        guard.setPurposeAuthorization(
            recipient, PURPOSE_HASH, uint256(20_000_000), true, purposeSignatures
        );
    }

    function _signQuorum(bytes32 digest) private returns (bytes[] memory signatures) {
        (uint8 v1, bytes32 r1, bytes32 s1) = vmInvariant().sign(OWNER_ONE_KEY, digest);
        (uint8 v2, bytes32 r2, bytes32 s2) = vmInvariant().sign(OWNER_TWO_KEY, digest);
        signatures = new bytes[](2);
        signatures[0] = abi.encodePacked(r1, s1, v1);
        signatures[1] = abi.encodePacked(r2, s2, v2);
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
        uint256 sessionPrivateKey = 0xBADC0DE;
        address sessionKey = vm.addr(sessionPrivateKey);
        address ownerOne = vm.addr(0xA11CE);
        vault = new AgentVault(address(token), ownerOne, sessionKey);
        EcdsaVerifier verifier = new EcdsaVerifier();

        address[] memory owners = new address[](3);
        owners[0] = ownerOne;
        owners[1] = vm.addr(0xB0B);
        owners[2] = vm.addr(0xCAFE);

        GuardModule.Policy memory initialPolicy = GuardModule.Policy({
            maxTransactionsPerWindow: 5,
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

        guard = new GuardModule(
            address(vault), address(0x515E), address(verifier), owners, 2, 1 days, initialPolicy
        );
        vm.prank(ownerOne);
        vault.configureGuard(address(guard));
        handler.configure(vault, guard, IERC20Invariant(address(token)), sessionKey);
        token.mint(ownerOne, 1_000_000_000);
        vm.prank(ownerOne);
        token.approve(address(vault), type(uint256).max);
        vm.prank(ownerOne);
        vault.deposit(500_000_000);
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = GuardInvariantHandler.attempt.selector;
        vm.targetSelector(VmInvariant.FuzzSelector({addr: address(handler), selectors: selectors}));
    }

    function invariant_payment_decisions_match_token_movements() public view {
        require(!handler.invariantViolated(), "guard decision and token movement diverged");
    }
}
