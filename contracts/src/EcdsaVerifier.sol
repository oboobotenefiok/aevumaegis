// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ISignatureVerifier} from "./ISignatureVerifier.sol";

contract EcdsaVerifier is ISignatureVerifier {
    function verify(
        bytes32 digest,
        address signer,
        bytes calldata signature
    ) external pure override returns (bool) {
        if (signature.length != 65) return false;

        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly ("memory-safe") {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }

        if (v < 27) v += 27;
        if (v != 27 && v != 28) return false;
        if (uint256(s) > 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0) return false;

        address recovered = ecrecover(digest, v, r, s);
        return recovered != address(0) && recovered == signer;
    }
}
