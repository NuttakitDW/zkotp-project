// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "forge-std/Test.sol";
import "../src/TrafficLightZkOTP.sol";
import "../src/VerifierMock.sol";
/**
 * @dev Foundry test suite for TrafficLightZkOTP
 */
contract TrafficLightZkOTPTest is Test {
    TrafficLightZkOTP public trafficLight;
    VerifierMock public verifierMock;

    // Example addresses to simulate calls
    address alice = address(0xA11CE);
    address bob = address(0xB0B);

    function setUp() public {
        // 1) Deploy mock verifier
        verifierMock = new VerifierMock();

        // 2) Deploy the TrafficLightZkOTP, passing the mock verifier
        trafficLight = new TrafficLightZkOTP(address(verifierMock));
    }

    // ─────────────────────────────────────────────────────────────────
    // Constructor Tests
    // ─────────────────────────────────────────────────────────────────
    function testConstructor() public view {
        // Verifier is set properly
        assertEq(
            address(trafficLight.verifier()),
            address(verifierMock),
            "Verifier not set"
        );
        // Light should start off
        assertFalse(trafficLight.isLightOn(), "Light should start off");
    }

    // ─────────────────────────────────────────────────────────────────
    // turnOn() Tests
    // ─────────────────────────────────────────────────────────────────
    function testTurnOnSuccess() public {
        // Make sure the mock verifier returns true
        verifierMock.setShouldVerify(true);

        // We'll call the function with dummy data
        uint256[2] memory a = [uint256(1), uint256(2)];
        uint256[2][2] memory b = [
            [uint256(3), uint256(4)],
            [uint256(5), uint256(6)]
        ];
        uint256[2] memory c = [uint256(7), uint256(8)];
        uint256[5] memory input = [uint256(9999), 0, 0, 0, 42];

        // Call turnOn with dummy proof
        vm.prank(alice); // simulate call from `alice`
        trafficLight.turnOn(a, b, c, input);

        // Now the light should be on
        assertTrue(trafficLight.isLightOn(), "Light should be on after turnOn");
    }

    function testTurnOnInvalidProof() public {
        // Set mock to return false => invalid proof
        verifierMock.setShouldVerify(false);

        // We'll call the function with dummy data
        uint256[2] memory a = [uint256(1), uint256(2)];
        uint256[2][2] memory b = [
            [uint256(3), uint256(4)],
            [uint256(5), uint256(6)]
        ];
        uint256[2] memory c = [uint256(7), uint256(8)];
        uint256[5] memory input = [uint256(9999), 0, 0, 0, 42];

        // Expect revert with "Invalid ZK proof"
        vm.expectRevert(bytes("Invalid ZK proof"));

        vm.prank(bob);
        trafficLight.turnOn(a, b, c, input);
    }

    // ─────────────────────────────────────────────────────────────────
    // turnOff() Tests
    // ─────────────────────────────────────────────────────────────────
    function testTurnOffSuccess() public {
        // We'll call the function with dummy data
        uint256[2] memory a = [uint256(1), uint256(2)];
        uint256[2][2] memory b = [
            [uint256(3), uint256(4)],
            [uint256(5), uint256(6)]
        ];
        uint256[2] memory c = [uint256(7), uint256(8)];
        uint256[5] memory input = [uint256(9999), 0, 0, 0, 42];
        // Turn the light on first
        verifierMock.setShouldVerify(true);
        vm.prank(alice);
        trafficLight.turnOn(a, b, c, input);
        assertTrue(trafficLight.isLightOn());

        // Now turn it off
        vm.prank(alice);
        trafficLight.turnOff(a, b, c, input);
        assertFalse(
            trafficLight.isLightOn(),
            "Light should be off after turnOff"
        );
    }

    function testTurnOffInvalidProof() public {
        // We'll call the function with dummy data
        uint256[2] memory a = [uint256(1), uint256(2)];
        uint256[2][2] memory b = [
            [uint256(3), uint256(4)],
            [uint256(5), uint256(6)]
        ];
        uint256[2] memory c = [uint256(7), uint256(8)];
        uint256[5] memory input = [uint256(9999), 0, 0, 0, 42];
        // If mock returns false => revert
        verifierMock.setShouldVerify(false);

        vm.expectRevert(bytes("Invalid ZK proof"));
        vm.prank(bob);
        trafficLight.turnOff(a, b, c, input);
    }
}
