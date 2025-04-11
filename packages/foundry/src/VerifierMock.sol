// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/**
 * @dev A mock verifier that can be toggled to return true or false in `verifyProof`.
 */
contract VerifierMock {
    bool public shouldVerify = true;

    function setShouldVerify(bool _val) external {
        shouldVerify = _val;
    }

    // Must match the signature that zkOTPWallet expects
    function verifyProof(
        uint256[2] memory,
        uint256[2][2] memory,
        uint256[2] memory,
        uint256[5] memory
    ) external view returns (bool) {
        return shouldVerify;
    }
}
