// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ISignatureVerifier} from "./ISignatureVerifier.sol";

/// @notice Reserved adapter for QDay's future hybrid ECDSA + ML-DSA verifier.
/// @dev This deliberately fails closed until the network exposes a supported PQ precompile.
contract HybridVerifier is ISignatureVerifier {
    function verify(
        bytes32,
        address,
        bytes calldata
    ) external pure override returns (bool) {
        revert("HybridVerifier: awaiting PQ precompile");
    }
}
