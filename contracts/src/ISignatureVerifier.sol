// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ISignatureVerifier {
    function verify(
        bytes32 digest,
        address signer,
        bytes calldata signature
    ) external view returns (bool);
}
