import * as circomlibjs from "circomlibjs";
import { ethers } from "ethers";
import * as snarkjs from 'snarkjs';
import fs from 'fs';


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
 * @param {string} input.computedOtp - The computed OTP.
 * @param {string} input.hashedSecret - The hashed secret.
 * @param {string} input.hashedOtp - The hashed OTP.
 * @param {string} input.timeStep - The time step used for OTP generation.
 * @param {string} input.actionHash - The action hash.
 * @param {string} input.txNonce - The transaction nonce.
 * @returns {Object} - The proof object containing the input fields.
 */
export async function generateProof(input) {

    // Validate required fields from input
    if (!input.secret || !input.computedOtp || !input.hashedSecret || !input.hashedOtp || !input.timeStep || !input.actionHash || !input.txNonce) {
        throw new Error("Missing required fields in input");
    }

    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        {
            secret: input.secret,
            otp_code: input.computedOtp,
            hashed_secret: input.hashedSecret,
            hashed_otp: input.hashedOtp,
            time_step: input.timeStep,
            action_hash: input.actionHash,
            tx_nonce: input.txNonce
        },
        "../../circuits/totp_js/totp.wasm",
        "../../circuits/totp_0001.zkey"
    );

    await verifyProof(proof, publicSignals);

    const solidityCalldata = await snarkjs.groth16.exportSolidityCallData(proof, publicSignals)
    const finalProofObject = parseSolidityCallData(solidityCalldata);

    return finalProofObject;
}

/**
 * Decrypts an encrypted secret using a salt.
 * This function assumes the secret was encrypted using AES-256-CBC with a derived key.
 *
 * @param {string} encryptedSecret - The encrypted secret in base64 format (format: "IV:encryptedData").
 * @param {string} salt - The salt used during encryption to derive the key.
 * @returns {string} - The decrypted secret as a UTF-8 string.
 */
export function decryptSecret(encryptedSecret, salt) {
    // Split the encrypted secret into IV and encrypted data
    const [ivBase64, encryptedData] = encryptedSecret.split(":");
    if (!ivBase64 || !encryptedData) {
        throw new Error("Invalid encrypted secret format");
    }

    // Convert IV from base64 to a Buffer
    const iv = Buffer.from(ivBase64, "base64");

    // Derive the encryption key using PBKDF2 with the provided salt
    const key = crypto.pbkdf2Sync(process.env.ENCRYPTION_KEY, salt, 100000, 32, "sha256");

    // Create a decipher instance with AES-256-CBC
    const decipher = crypto.createDecipheriv("aes-256-cbc", key, iv);

    // Decrypt the data
    let decrypted = decipher.update(encryptedData, "base64", "utf8");
    decrypted += decipher.final("utf8");

    return decrypted;
}

// Function to verify the proof
async function verifyProof(proof, publicSignals) {
    try {
        // Read the verification key from a JSON file
        const verificationKeyFile = '../../circuits/verification_key.json'; // Path to your verification key file
        const verificationKey = JSON.parse(fs.readFileSync(verificationKeyFile, 'utf8'));

        // Use snarkjs to verify the proof
        const isValid = await snarkjs.groth16.verify(verificationKey, publicSignals, proof);

        if (isValid) {
            console.log("Proof is valid!");
        } else {
            console.log("Proof is invalid.");
        }
    } catch (error) {
        console.error("Error in Verification Phase:", error);
    }
}


function parseSolidityCallData(calldataString) {
    // e.g. "[\"0xabc\",\"0xdef\"],[[\"0x...\",\"0x...\"],[\"0x...\",\"0x...\"]],[\"0x...\",\"0x...\"],[\"0x...\",\"0x...\", ...]"
    // 1) Remove brackets, quotes, spaces
    const flat = calldataString.replace(/["[\]\s]/g, "");
    // 2) Split by comma
    const tokens = flat.split(",");

    // The order is: a0, a1, b00, b01, b10, b11, c0, c1, ... public signals ...
    // 3) Extract a, b, c
    const a = [tokens[0], tokens[1]];
    const b = [
        [tokens[2], tokens[3]],
        [tokens[4], tokens[5]]
    ];
    const c = [tokens[6], tokens[7]];

    // 4) The rest are public signals
    const publicInput = tokens.slice(8);

    // 5) Build a final object
    return { a, b, c, publicInput };
}
