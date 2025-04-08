// scripts/deployFromFiles.js
const fs = require("fs");
const { ethers } = require("hardhat");

async function main() {
    // 1) Read Proof & Public Inputs from JSON
    const proofData = JSON.parse(fs.readFileSync("scripts/proof.json", "utf-8"));
    const publicInputs = JSON.parse(fs.readFileSync("scripts/public.json", "utf-8"));

    // proof.json typically has pi_a (3 elems), pi_b (3x2 elems), pi_c (3 elems)
    // We only want the affine x & y for pi_a and pi_c, and the first 2 rows for pi_b.

    // pi_a = [x, y, z], remove z
    const a = [proofData.pi_a[0], proofData.pi_a[1]];

    // pi_b = [[x1, y1], [x2, y2], [1,0]], remove the last row
    const b = [
        [proofData.pi_b[0][0], proofData.pi_b[0][1]],
        [proofData.pi_b[1][0], proofData.pi_b[1][1]]
    ];

    // pi_c = [x, y, z], remove z
    const c = [proofData.pi_c[0], proofData.pi_c[1]];

    // If your circuit uses decimal strings, this is usually fine.
    // Optionally, convert them to BigNumber:
    const aBN = a.map(x => ethers.BigNumber.from(x));
    const bBN = b.map(pair => pair.map(x => ethers.BigNumber.from(x)));
    const cBN = c.map(x => ethers.BigNumber.from(x));
    const inputBN = publicInputs.map(x => ethers.BigNumber.from(x));

    // 2) Deploy the Verifier Contract
    const Verifier = await ethers.getContractFactory("Groth16Verifier");
    const verifier = await Verifier.deploy();
    await verifier.deployed();
    console.log("Verifier deployed at:", verifier.address);

    // 3) Call verifyProof with the proof data
    const result = await verifier.verifyProof(aBN, bBN, cBN, inputBN);
    console.log("Verification result:", result);
}

main().catch((err) => {
    console.error(err);
    process.exitCode = 1;
});
