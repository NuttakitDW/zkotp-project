import * as circomlibjs from "circomlibjs";
import { ethers } from "ethers";
import crypto from "crypto";
const snarkjs = require('snarkjs')



/**
 * Computes the Poseidon hash of the given input field.
 * Poseidon is a cryptographic hash function optimized for zero-knowledge proofs.
 *
 * @param {number | string | bigint} xField - The input field to hash. Can be a number, string, or bigint.
 * @returns {Promise<string>} - A promise that resolves to the Poseidon hash as a string.
 */
export async function computePoseidonHash(xField) {
    const poseidon = await circomlibjs.buildPoseidon();
    const hVal = poseidon([xField]);
    const hBig = poseidon.F.toObject(hVal);
    return hBig.toString();
}

/**
 * Computes the action hash by tightly packing the input parameters and hashing them using keccak256.
 * Mimics the behavior of Solidity's `abi.encodePacked` and `keccak256`.
 *
 * @param {string} to - The recipient address (in hexadecimal format).
 * @param {string | number} value - The value to be sent (in wei or as a number).
 * @param {string} data - The calldata or additional data (in hexadecimal format).
 * @returns {string} - The keccak256 hash of the packed parameters as a hexadecimal string.
 */
export function computeActionHash(to, value, data) {
    // Use ethers.utils.solidityPack to mimic abi.encodePacked
    const encoded = ethers.utils.solidityPack(
        ["address", "uint256", "bytes"],
        [to, value, data]
    );

    // Compute the keccak256 hash of the encoded data
    const actionHash = ethers.utils.keccak256(encoded);

    return actionHash;
}

/**
 * Encrypts data with a salt.
 * @param {string} data - The data to encrypt.
 * @param {string} salt - The salt to use for encryption.
 * @returns {string} - The encrypted data in base64 format.
 */
export function encryptWithSalt(data, salt) {
    const iv = crypto.randomBytes(IV_LENGTH); // Generate a random IV
    const key = crypto.pbkdf2Sync(KEY, salt, 100000, 32, "sha256"); // Derive a key using the salt

    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    let encrypted = cipher.update(data, "utf8", "base64");
    encrypted += cipher.final("base64");

    return `${iv.toString("base64")}:${encrypted}`; // Return IV and encrypted data
}

/**
 * Decrypts data with a salt.
 * @param {string} encryptedData - The encrypted data in base64 format.
 * @param {string} salt - The salt used for encryption.
 * @returns {string} - The decrypted data.
 */
export function decryptWithSalt(encryptedData, salt) {
    const [ivBase64, encrypted] = encryptedData.split(":");
    const iv = Buffer.from(ivBase64, "base64");
    const key = crypto.pbkdf2Sync(KEY, salt, 100000, 32, "sha256"); // Derive the key using the salt

    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    let decrypted = decipher.update(encrypted, "base64", "utf8");
    decrypted += decipher.final("utf8");

    return decrypted;
}

/**
 * Pads a Base32 string with the required number of "=" characters to make its length a multiple of 8.
 *
 * @param {string} s - The Base32 string to pad.
 * @returns {string} - The padded Base32 string.
 */
export function padBase32(s) {
    const missing = (8 - (s.length % 8)) % 8;
    return s + "=".repeat(missing);
}

import crypto from "crypto";

/**
 * Computes a 6-digit TOTP (Time-based One-Time Password) using the given secret bytes and time step.
 *
 * @param {Buffer} secretBytes - The secret key in byte format.
 * @param {number} timeStep - The time step (e.g., derived from the current timestamp divided by an interval).
 * @returns {number} - The 6-digit TOTP code.
 */
export function computeTOTP6(secretBytes, timeStep) {
    // Create an 8-byte buffer for the time step
    const msg = Buffer.alloc(8);
    msg.writeBigUInt64BE(BigInt(timeStep), 0);

    // Generate HMAC-SHA1 digest using the secret bytes and time step
    const digest = crypto.createHmac("sha1", secretBytes).update(msg).digest();

    // Extract the dynamic offset from the last byte of the digest
    const offset = digest[19] & 0x0f;

    // Compute the binary code from the digest using the offset
    const binCode =
        ((digest[offset] & 0x7f) << 24) |
        ((digest[offset + 1] & 0xff) << 16) |
        ((digest[offset + 2] & 0xff) << 8) |
        (digest[offset + 3] & 0xff);

    // Return the 6-digit TOTP code
    return binCode % 1000000;
}

/**
 * Generates a proof object from the given input parameters.
 *
 * @param {Object} input - The input object containing the required fields.
 * @param {string} input.secret - The secret key.
 * @param {number} input.computedOtp - The computed OTP.
 * @param {string} input.hashedSecret - The hashed secret.
 * @param {string} input.hashedOtp - The hashed OTP.
 * @param {number} input.timeStep - The time step used for OTP generation.
 * @param {string} input.actionHash - The action hash.
 * @param {number} input.txNonce - The transaction nonce.
 * @returns {Object} - The proof object containing the input fields.
 */
export async function generateProof(input) {

    // Validate required fields from input
    if (!input.secret || !input.computedOtp || !input.hashedSecret || !input.hashedOtp || !input.timeStep || !input.actionHash || !input.txNonce) {
        throw new Error("Missing required fields in input");
    }

    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        input,
        "../circuits/totp_js/totp.wasm",
        "../circuits/zkey/cardSetup/cardSetup00.zkey"
    );

    const a = [
        decToHex(proof.pi_a[0]),
        decToHex(proof.pi_a[1])
    ];

    const b = [
        [decToHex(proof.pi_b[0][0]), decToHex(proof.pi_b[0][1])],
        [decToHex(proof.pi_b[1][0]), decToHex(proof.pi_b[1][1])]
    ];

    const c = [
        decToHex(proof.pi_c[0]),
        decToHex(proof.pi_c[1])
    ];

    const input = pub.map(decToHex);

    const finalProofObject = {
        a,
        b,
        c,
        input
    };


    return finalProofObject;
}