// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/**
 * @dev A simple mock that can be toggled to return true or false from `verifyProof`.
 */
contract VerifierMock {
    bool public shouldVerify = true;

    function setShouldVerify(bool _value) external {
        shouldVerify = _value;
    }

    // Must match the signature the wallet expects
    function verifyProof(
        uint256[2] memory,  // a
        uint256[2][2] memory, // b
        uint256[2] memory,  // c
        uint256[5] memory   // input
    ) external view returns (bool) {
        return shouldVerify;
    }
}
