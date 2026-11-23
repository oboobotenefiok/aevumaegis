// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {GuardModule} from "./GuardModule.sol";

interface IERC20Minimal {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

/// @title AgentVault
/// @notice Holds stablecoins and only lets its delegated session key pay through GuardModule.
contract AgentVault {
    address public immutable owner;
    IERC20Minimal public immutable token;
    address public sessionKey;
    GuardModule public guard;
    bool public guardConfigured;
    bool private entered;

    event Deposited(address indexed from, uint256 amount);
    event PaymentExecuted(address indexed recipient, uint256 amount);
    event PaymentBlocked(address indexed recipient, uint256 amount);
    event GuardConfigured(address indexed guardAddress);
    event SessionKeyRotated(address indexed previousKey, address indexed newKey);

    error OnlyOwner();
    error OnlySessionKey();
    error GuardAlreadyConfigured();
    error InvalidAddress();
    error TokenTransferFailed();
    error OnlyGuard();

    modifier onlyOwner() {
        if (msg.sender != owner) revert OnlyOwner();
        _;
    }

    modifier nonReentrant() {
        require(!entered, "AgentVault: reentrant call");
        entered = true;
        _;
        entered = false;
    }

    constructor(address tokenAddress, address ownerAddress, address initialSessionKey) {
        if (tokenAddress == address(0) || ownerAddress == address(0) || initialSessionKey == address(0)) {
            revert InvalidAddress();
        }
        token = IERC20Minimal(tokenAddress);
        owner = ownerAddress;
        sessionKey = initialSessionKey;
    }

    function configureGuard(address guardAddress) external onlyOwner {
        if (guardConfigured) revert GuardAlreadyConfigured();
        if (guardAddress == address(0)) revert InvalidAddress();
        guard = GuardModule(guardAddress);
        guardConfigured = true;
        emit GuardConfigured(guardAddress);
    }

    function rotateSessionKey(address newSessionKey) external {
        if (!guardConfigured || msg.sender != address(guard)) revert OnlyGuard();
        if (newSessionKey == address(0) || newSessionKey == sessionKey) revert InvalidAddress();
        address previousKey = sessionKey;
        sessionKey = newSessionKey;
        emit SessionKeyRotated(previousKey, newSessionKey);
    }

    function deposit(uint256 amount) external nonReentrant {
        if (!token.transferFrom(msg.sender, address(this), amount)) revert TokenTransferFailed();
        emit Deposited(msg.sender, amount);
    }

    function pay(address recipient, uint256 amount) external nonReentrant returns (bool allowed) {
        if (msg.sender != sessionKey) revert OnlySessionKey();
        if (!guardConfigured) revert InvalidAddress();

        allowed = guard.evaluatePayment(msg.sender, recipient, amount);
        if (!allowed) {
            emit PaymentBlocked(recipient, amount);
            return false;
        }
        if (!token.transfer(recipient, amount)) revert TokenTransferFailed();
        emit PaymentExecuted(recipient, amount);
    }


}
