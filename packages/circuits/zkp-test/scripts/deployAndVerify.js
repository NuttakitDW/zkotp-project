// scripts/testProof.js
const { ethers } = require("hardhat");

async function main() {
    // ---------------------------------------------------
    // 1) (Option A) DEPLOY a fresh Verifier contract
    // ---------------------------------------------------
    // If you already have a deployed verifier, skip this part
    // and just do: const verifier = Verifier.attach("0xYourVerifierAddress");
    const Verifier = await ethers.getContractFactory("Groth16Verifier");
    const verifier = await Verifier.deploy();
    await verifier.deployed();
    console.log("Verifier deployed to:", verifier.address);

    // ---------------------------------------------------
    // 2) DEFINE YOUR PROOF ARRAYS
    // ---------------------------------------------------
    // a (2 elements)
    const a = [
        "0x1b23fcf4578d5e78f9bdc98eb91dc53e545af8669cc88a44dda1acee08d7a23a",
        "0x1e1ccd67f110aa9a3c5f125b08d6db8d560a39136ad7e6121e81a2068accf9d6"
    ];

    // b (2x2)
    const b = [
        [
            "0x226ae2abfbb2127eb66f4130ad72830974ab9b01cc46a68e413ed19c11f92265",
            "0x12bcc33413920e6496e9db840ae1b5b6eb6bd1e3e669f74952684c38e858ee1f"
        ],
        [
            "0x2db2d78eb367f88532fb9919ac2cc3b50f6a92a2bc9b61930509846a45344c1c",
            "0x18e746d3bebc05911ec9639b1cc3140509e5bc1f8bb0d24549ee4070141c19c2"
        ]
    ];

    // c (2 elements)
    const c = [
        "0x30396ef03d3a044ede44e75c989ba25fd0dc5c790a36ed570468e1b53b44151e",
        "0x023dc5ac845c34bc45921780ea19fd7250f1ea36555bd745855963b104b53c66"
    ];

    // public inputs (5 elements)
    const input = [
        "0x22781327f680f1ab32f7340a9d2b80d6302021f28998733b3b86a97d03d02677",
        "0x148dd7c0db441f55f3b8220d11f18f3372a689cdd1d10364772e1f03685ae6be",
        "0x000000000000000000000000000000000000000000000000000000000376f943",
        "0x0000000000000000000000000000000000000000000000000000000000000000",
        "0x0000000000000000000000000000000000000000000000000000000000000000"
    ];

    // ---------------------------------------------------
    // 3) CALL THE VERIFIER WITH THE PROOF DATA
    // ---------------------------------------------------
    const isValid = await verifier.verifyProof(a, b, c, input);

    console.log("Proof valid?", isValid);
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
