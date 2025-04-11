// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "forge-std/Test.sol";
import "../src/zkOTPWallet.sol";
import "../src/VerifierMock.sol";

contract ZkOTPWalletTest is Test {
    zkOTPWallet public wallet;
    VerifierMock public verifierMock;

    address owner = address(0x1111);
    address admin = address(0x2222);
    address someUser = address(0x3333);

    function setUp() public {
        // Deploy the verifier mock
        verifierMock = new VerifierMock();

        // Deploy wallet with owner=0x1111, admin=0x2222, verifier=verifierMock
        wallet = new zkOTPWallet(owner, admin, address(verifierMock));
    }

    function testConstructor() public view {
        assertEq(wallet.owner(), owner, "Wrong owner");
        assertEq(wallet.admin(), admin, "Wrong admin");
        assertEq(
            address(wallet.verifier()),
            address(verifierMock),
            "Wrong verifier"
        );
    }

    // ─────────────────────────────
    // Owner/Admin tests
    // ─────────────────────────────
    function testOwnerCanChangeOwner() public {
        // Switch msg.sender to owner
        vm.prank(owner);
        wallet.setOwner(someUser);
        assertEq(wallet.owner(), someUser, "Owner not updated");
    }

    function test_RevertWhen_NotOwnerChangeOwner() public {
        // If someUser tries, it should revert with "Not owner"
        vm.prank(someUser);
        vm.expectRevert(bytes("Not owner"));
        wallet.setOwner(address(0x9999)); // This will revert
    }

    function testAdminCanChangeAdmin() public {
        vm.prank(admin);
        wallet.setAdmin(someUser);
        assertEq(wallet.admin(), someUser, "Admin not updated");
    }

    function test_RevertWhenNotOwnerChangesAdmin() public {
        vm.prank(someUser);
        vm.expectRevert(bytes("Not admin"));
        wallet.setAdmin(address(0x9999));
    }

    // ─────────────────────────────
    // HashedSecretConfig tests
    // ─────────────────────────────
    function testOwnerCanSetHashedSecretConfig() public {
        // Since there's no public getter, let's rely on the event or do a small check
        vm.prank(owner);
        wallet.setHashedSecretConfig(123);

        // We can check the logs or just trust it. If you want to verify the event, do:
        // (We can't do it after the fact because we already called the function)
    }

    function test_RevertWhenNotOwnerSetsHashedSecretConfig() public {
        // Set the next call to come from `someUser`
        vm.prank(someUser);

        // We expect a revert with "Not owner"
        vm.expectRevert(bytes("Not owner"));

        // Now the call should revert since `someUser` is not the owner
        wallet.setHashedSecretConfig(999);
    }

    // ─────────────────────────────
    // execute() tests
    // ─────────────────────────────
    function testExecuteInvalidProof() public {
        // By default, VerifierMock.shouldVerify = true, let's set it false
        verifierMock.setShouldVerify(false);

        // We'll call the function with dummy data
        uint256[2] memory a = [uint256(1), uint256(2)];
        uint256[2][2] memory b = [
            [uint256(3), uint256(4)],
            [uint256(5), uint256(6)]
        ];
        uint256[2] memory c = [uint256(7), uint256(8)];
        uint256[5] memory input = [uint256(9999), 0, 0, 0, 42];

        vm.prank(someUser);
        vm.expectRevert(bytes("Invalid ZK proof"));
        wallet.execute(someUser, 0, "", a, b, c, input);
    }

    function testExecuteNonceReplay() public {
        // Make the VerifierMock always return 'true' for verifyProof
        verifierMock.setShouldVerify(true);

        // Prepare dummy proof data
        uint256[2] memory a = [uint256(1), uint256(2)];
        uint256[2][2] memory b = [
            [uint256(3), uint256(4)],
            [uint256(5), uint256(6)]
        ];
        uint256[2] memory c = [uint256(7), uint256(8)];

        // We want to execute a call to (someUser, value=0, data="")
        // The contract does: keccak256(abi.encodePacked(_to, _value, _data))
        address to = someUser;
        uint256 value = 0;
        bytes memory data = "";

        // Compute the correct action hash
        bytes32 computedActionHash = keccak256(
            abi.encodePacked(to, value, data)
        );
        uint256 computedActionHashField = uint256(computedActionHash);

        // Our input[3] must match computedActionHashField
        // input = [hashedSecret, unused1, unused2, action_hash, tx_nonce]
        uint256[5] memory input = [
            uint256(9999),
            0,
            0,
            computedActionHashField,
            999
        ];

        // First call uses nonce=999, should succeed
        vm.prank(someUser);
        wallet.execute(to, value, data, a, b, c, input);

        // Second call with the same nonce=999 must revert
        vm.prank(someUser);
        vm.expectRevert(bytes("Nonce already used"));
        wallet.execute(to, value, data, a, b, c, input);
    }

    function testExecuteHashedSecretCheck() public {
        verifierMock.setShouldVerify(true);

        // set hashedSecretConfig = 777
        vm.prank(owner);
        wallet.setHashedSecretConfig(777);

        // If input[0] = hashedSecret = 777, it reverts "Invalid hashed secret"
        uint256[5] memory input = [uint256(777), 0, 0, 1000, 42];

        uint256[2] memory a; // all zeros
        uint256[2][2] memory b;
        uint256[2] memory c;

        vm.prank(someUser);
        vm.expectRevert(bytes("Invalid hashed secret"));
        wallet.execute(someUser, 0, "", a, b, c, input);
    }

    function testExecuteActionHashMismatch() public {
        verifierMock.setShouldVerify(true);

        // hashedSecret != hashedSecretConfig
        vm.prank(owner);
        wallet.setHashedSecretConfig(1234);
        // input[0] = 9999 => that passes

        // The contract does: keccak256(abi.encodePacked(_to, _value, _data))
        // We'll intentionally mismatch actionHash
        uint256[5] memory input = [uint256(9999), 0, 0, 999999, 42];

        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;

        vm.prank(someUser);
        vm.expectRevert(bytes("Action hash mismatch"));
        wallet.execute(someUser, 100, "0xabcdef", a, b, c, input);
    }

    function testExecuteSuccess() public {
        verifierMock.setShouldVerify(true);

        // set hashedSecretConfig = something that won't match input
        vm.prank(owner);
        wallet.setHashedSecretConfig(1000);
        // We'll use hashedSecret=2000 => no revert

        vm.deal(address(wallet), 1 ether);

        // Next, we compute the real actionHash for (to=someUser, value=100, data="0xabc123")
        address to = someUser;
        uint256 val = 100;
        bytes memory data = hex"abc123";

        // The contract does: keccak256(abi.encodePacked(_to, _value, _data))
        bytes32 realActionHash = keccak256(abi.encodePacked(to, val, data));
        uint256 realActionHashField = uint256(realActionHash);

        // Build the input array:
        // [ hashed_secret, X, X, action_hash, tx_nonce ]
        uint256[5] memory input = [
            uint256(2000),
            0,
            0,
            realActionHashField,
            777
        ];

        uint256[2] memory a;
        uint256[2][2] memory b;
        uint256[2] memory c;

        vm.prank(someUser);
        // No revert expected
        wallet.execute(to, val, data, a, b, c, input);
    }
}
