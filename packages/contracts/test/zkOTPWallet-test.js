const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("zkOTPWallet", function () {
    let deployer, owner, admin, user;
    let walletContract;    // instance of zkOTPWallet
    let verifierMock;      // instance of VerifierMock
    const ZERO_ADDRESS = ethers.constants.AddressZero;

    before(async () => {
        [deployer, owner, admin, user] = await ethers.getSigners();
    });

    beforeEach(async () => {
        // 1) Deploy VerifierMock
        const VerifierMock = await ethers.getContractFactory("VerifierMock");
        verifierMock = await VerifierMock.connect(deployer).deploy();
        await verifierMock.deployed();

        // 2) Deploy zkOTPWallet
        const zkOTPWallet = await ethers.getContractFactory("zkOTPWallet");
        walletContract = await zkOTPWallet
            .connect(deployer)
            .deploy(owner.address, admin.address, verifierMock.address);
        await walletContract.deployed();
    });

    //
    // ──────────────────────────────────────────────────────────────────────────────
    //   1. Deployment
    // ──────────────────────────────────────────────────────────────────────────────
    //
    it("should set the correct owner, admin, and verifier", async () => {
        expect(await walletContract.owner()).to.equal(owner.address);
        expect(await walletContract.admin()).to.equal(admin.address);
        expect(await walletContract.verifier()).to.equal(verifierMock.address);
    });

    //
    // ──────────────────────────────────────────────────────────────────────────────
    //   2. Ownership / Admin
    // ──────────────────────────────────────────────────────────────────────────────
    //
    it("should allow owner to change the owner", async () => {
        await walletContract.connect(owner).setOwner(user.address);
        expect(await walletContract.owner()).to.equal(user.address);
    });

    it("should revert if non-owner tries to change the owner", async () => {
        await expect(
            walletContract.connect(admin).setOwner(user.address)
        ).to.be.revertedWith("Not owner");
    });

    it("should allow owner to change the admin", async () => {
        await walletContract.connect(owner).setAdmin(user.address);
        expect(await walletContract.admin()).to.equal(user.address);
    });

    it("should revert if non-owner tries to change the admin", async () => {
        await expect(
            walletContract.connect(admin).setAdmin(user.address)
        ).to.be.revertedWith("Not owner");
    });

    //
    // ──────────────────────────────────────────────────────────────────────────────
    //   3. HashedSecretConfig
    // ──────────────────────────────────────────────────────────────────────────────
    //
    it("should allow owner to setHashedSecretConfig", async () => {
        const tx = await walletContract.connect(owner).setHashedSecretConfig(1234);
        await tx.wait();
        // hashedSecretConfig is not public in your contract, so we can't read it directly.
        // You can check the event if you want:
        await expect(tx)
            .to.emit(walletContract, "HashedSecretConfigChanged")
            .withArgs(1234, 1234);
    });

    it("should revert if non-owner tries to setHashedSecretConfig", async () => {
        await expect(
            walletContract.connect(admin).setHashedSecretConfig(9999)
        ).to.be.revertedWith("Not owner");
    });

    //
    // ──────────────────────────────────────────────────────────────────────────────
    //   4. execute() with mock proof
    // ──────────────────────────────────────────────────────────────────────────────
    //
    describe("execute() function", function () {
        // We'll define some dummy proof data
        let a, b, c, input;

        beforeEach(() => {
            // Some placeholders
            a = [1, 2];
            b = [
                [3, 4],
                [5, 6]
            ];
            c = [7, 8];

            // input[0] = hashed_secret
            // input[1] = hashed_otp
            // input[2] = time_step
            // input[3] = action_hash
            // input[4] = tx_nonce
            input = [9999, 0, 0, 0, 42];
        });

        it("should revert if verifier returns false (invalid proof)", async () => {
            // Make sure the mock returns false
            await verifierMock.setShouldVerify(false);

            await expect(
                walletContract.connect(user).execute(
                    user.address,
                    0,
                    "0x",
                    a,
                    b,
                    c,
                    input
                )
            ).to.be.revertedWith("Invalid ZK proof");
        });

        it("should revert if nonce already used", async () => {
            // Let the verifier return true so we can pass the proof check
            await verifierMock.setShouldVerify(true);

            // We'll skip some checks for hashedSecret and actionHash for now

            // 1) first call
            await walletContract.connect(user).execute(
                user.address,
                0,
                "0x",
                a,
                b,
                c,
                input // tx_nonce = 42
            );

            // 2) second call with same nonce
            await expect(
                walletContract.connect(user).execute(
                    user.address,
                    0,
                    "0x",
                    a,
                    b,
                    c,
                    input
                )
            ).to.be.revertedWith("Nonce already used");
        });

        it("should revert if hashedSecret = hashedSecretConfig", async () => {
            await verifierMock.setShouldVerify(true);

            // Let's set hashedSecretConfig = 9999
            await walletContract.connect(owner).setHashedSecretConfig(9999);

            // Now input[0] = hashed_secret is 9999
            // That will revert with "Invalid hashed secret"
            await expect(
                walletContract.execute(
                    user.address,
                    0,
                    "0x",
                    a,
                    b,
                    c,
                    input
                )
            ).to.be.revertedWith("Invalid hashed secret");
        });

        it("should revert if action_hash mismatch", async () => {
            await verifierMock.setShouldVerify(true);

            // We'll keep hashedSecret != hashedSecretConfig
            await walletContract.connect(owner).setHashedSecretConfig(1234);
            input[0] = 9999; // hashedSecret

            // The contract does:
            //  computedActionHash = keccak256(abi.encodePacked(_to, _value, _data))
            //  require(computedActionHashField == actionHashField, ...)
            // we have input[3] = actionHashField
            // Let's produce a real match if we want success, or mismatch if we want revert

            // We'll intentionally mismatch. e.g. actionHashField = 7777
            input[3] = 7777;

            await expect(
                walletContract.execute(
                    user.address,
                    100,
                    "0xabcdef",
                    a,
                    b,
                    c,
                    input
                )
            ).to.be.revertedWith("Action hash mismatch");
        });

        it("should succeed if proof is valid, hashedSecret != config, nonce unused, and action_hash matches", async () => {
            await verifierMock.setShouldVerify(true);

            // 1) Set hashedSecretConfig to something different from input[0]
            await walletContract.connect(owner).setHashedSecretConfig(1234);
            input[0] = 9999; // hashedSecret

            // 2) We'll compute the real action hash for: (to=user.address, value=100, data="0xabc123")
            const to = user.address;
            const val = 100;
            const data = "0xabc123";

            // the contract does: keccak256(abi.encodePacked(_to, _value, _data))
            const computedHash = ethers.utils.keccak256(
                ethers.utils.defaultAbiCoder.encode(["address", "uint256", "bytes"], [to, val, data])
            );
            // convert to BigNumber => string
            const computedHashBN = ethers.BigNumber.from(computedHash);

            // 3) put that in input[3]
            input[3] = computedHashBN.toString();

            // 4) tx_nonce = 42 => already set in input
            // 5) call the function
            const tx = await walletContract.execute(
                to,
                val,
                data,
                a,
                b,
                c,
                input
            );

            await expect(tx).to.not.be.reverted;

            // (Optional) check some result if calling a specific function in another contract or transferring ETH, etc.
        });
    });
});
