// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "./IVerifier.sol";

/**
 * @title TrafficLightZkOTP
 * @notice A minimal contract demonstrating how a zkOTP proof can be used
 *         to restrict toggling a boolean "traffic light" (off = red, on = green).
 *
 * Anyone who provides a valid OTP proof (verified by the on-chain verifier)
 * can switch the light from off to on or on to off.
 */
contract TrafficLightZkOTP {
    /// @notice The traffic light state: false = off/red, true = on/green.
    bool public isLightOn;

    /// @notice The verifier contract (Groth16 or Plonk).
    IVerifier public verifier;

    /// @notice Emitted when the light state changes.
    event LightToggled(bool indexed newState);

    /**
     * @param _verifier The address of the deployed verifier contract.
     *                            to ensure the user proving they know that secret.
     */
    constructor(address _verifier) {
        require(_verifier != address(0), "Invalid verifier");
        verifier = IVerifier(_verifier);
    }

    /**
     * @notice Turns the light on (green) if a valid ZK proof is provided.
     * @param a Part of the Groth16 proof.
     * @param b Part of the Groth16 proof.
     * @param c Part of the Groth16 proof.
     * @param input The public inputs array from your OTP circuit (size depends on your circuit).
     */
    function turnOn(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[5] memory input
    ) external {
        // 1) Verify the proof against the on-chain verifier
        bool ok = verifier.verifyProof(a, b, c, input);
        require(ok, "Invalid ZK proof");

        // 3) Toggle the light
        isLightOn = true;
        emit LightToggled(true);
    }

    /**
     * @notice Turns the light off (red) if a valid ZK proof is provided.
     * @param a Part of the Groth16 proof.
     * @param b Part of the Groth16 proof.
     * @param c Part of the Groth16 proof.
     * @param input The public inputs array from your OTP circuit (size depends on your circuit).
     */
    function turnOff(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[5] memory input
    ) external {
        bool ok = verifier.verifyProof(a, b, c, input);
        require(ok, "Invalid ZK proof");

        isLightOn = false;
        emit LightToggled(false);
    }
}
