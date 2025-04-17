import * as circomlibjs from "circomlibjs";
import { ethers } from "ethers";
import * as snarkjs from 'snarkjs';
import fs from 'fs';
import base32 from "base32.js";
import path from "path";
import { fileURLToPath } from "url";

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

    if (!ethers.utils.isAddress(to)) {
        throw new Error(`Invalid Ethereum address: ${to}`);
    }

    if (typeof value !== "string" && typeof value !== "number") {
        throw new Error(`Invalid value type: ${typeof value}. Expected string or number.`);
    }

    const encoded = ethers.utils.solidityPack(
        ["address", "uint256", "bytes"],
        [to, value, data]
    );

    // Compute the keccak256 hash of the encoded data
    const actionHash = ethers.utils.keccak256(encoded);

    return actionHash;
}

/**
 * Encrypts the given plaintext using:
 *   - process.env.ENCRYPTION_WORD (the "password")
 *   - a 'salt' (Buffer or string)
 *   - AES-GCM (or another algorithm specified by process.env.ENCRYPTION_ALGORITHM)
 *   - PBKDF2 (100000 iterations, 32-byte key length, sha256)
 *
 * Returns a single string containing:
 *   "IV(base64):ciphertext(base64):authTag(base64)"
 */
export function encryptWithSalt(plaintext, salt) {
    // 1) Check required ENV variables
    const password = process.env.ENCRYPTION_WORD;
    if (!password) {
        throw new Error("ENCRYPTION_WORD is not defined in the environment variables");
    }

    const algorithm = process.env.ENCRYPTION_ALGORITHM;
    if (!algorithm) {
        throw new Error("ENCRYPTION_ALGORITHM is not defined in the environment variables");
    }

    // 2) Validate plaintext
    if (typeof plaintext !== "string" || plaintext.length === 0) {
        throw new TypeError("The 'plaintext' argument must be a non-empty string.");
    }

    // 3) Normalize salt
    // If salt is a string, convert it to a Buffer. Otherwise, assume it's already a Buffer.
    const saltBuffer = Buffer.isBuffer(salt) ? salt : Buffer.from(salt, 'utf8');

    // 4) Derive key using PBKDF2
    //  - 100000 iterations, 32 bytes, sha256
    const key = crypto.pbkdf2Sync(password, saltBuffer, 100000, 32, 'sha256');

    // 5) Generate a random IV
    //  - For AES-GCM, 12 bytes is typical
    const iv = crypto.randomBytes(12);

    // 6) Create the Cipher
    const cipher = crypto.createCipheriv(algorithm, key, iv);

    // 7) Encrypt
    let encrypted = cipher.update(plaintext, 'utf8', 'base64');
    encrypted += cipher.final('base64');

    // 8) Get auth tag (required for AES-GCM)
    //  - If you use AES-CBC or another non-AEAD mode, there's no authTag
    let authTag = '';
    if (algorithm.includes('gcm')) {
        authTag = cipher.getAuthTag().toString('base64');
    }

    // 9) Return a single string with IV, ciphertext, and tag
    //    If you don't store the tag, GCM decryption won't work
    return `${iv.toString('base64')}:${encrypted}:${authTag}`;
}

/**
 * Decrypts data produced by encryptWithSalt(), reconstructing the same key from:
 *   - process.env.ENCRYPTION_WORD (the "password")
 *   - the same 'salt'
 *   - the same PBKDF2 parameters
 *   - the same algorithm (e.g., aes-256-gcm)
 *
 * Expects 'encryptedString' in the format "IV:ciphertext:authTag" (all base64).
 *
 * Returns the original plaintext as a UTF-8 string.
 */
export function decryptWithSalt(encryptedString, salt) {
    // 1) Check required ENV variables
    const password = process.env.ENCRYPTION_WORD;
    if (!password) {
        throw new Error("ENCRYPTION_WORD is not defined in the environment variables");
    }

    const algorithm = process.env.ENCRYPTION_ALGORITHM;
    if (!algorithm) {
        throw new Error("ENCRYPTION_ALGORITHM is not defined in the environment variables");
    }

    // 2) Validate input string
    if (typeof encryptedString !== 'string' || encryptedString.length === 0) {
        throw new TypeError("The 'encryptedString' argument must be a non-empty string.");
    }

    // 3) Split into parts: IV, ciphertext, authTag
    const parts = encryptedString.split(':');
    if (parts.length < 2) {
        throw new Error("Encrypted string format invalid. Expected 'IV:ciphertext[:authTag]'.");
    }

    const [ivBase64, ciphertextBase64, authTagBase64 = ''] = parts;

    // 4) Normalize salt
    const saltBuffer = Buffer.isBuffer(salt) ? salt : Buffer.from(salt, 'utf8');

    // 5) Derive the same key (PBKDF2)
    const key = crypto.pbkdf2Sync(password, saltBuffer, 100000, 32, 'sha256');

    // 6) Convert IV from base64 to Buffer
    const iv = Buffer.from(ivBase64, 'base64');

    // 7) Create the Decipher
    const decipher = crypto.createDecipheriv(algorithm, key, iv);

    // 8) If using GCM, set the auth tag
    if (algorithm.includes('gcm')) {
        if (!authTagBase64) {
            throw new Error("No authTag provided for GCM decryption.");
        }
        const authTag = Buffer.from(authTagBase64, 'base64');
        decipher.setAuthTag(authTag);
    }

    // 9) Decrypt
    let decrypted = decipher.update(ciphertextBase64, 'base64', 'utf8');
    decrypted += decipher.final('utf8');

    // 10) Return plaintext
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
 * Converts a byte array to a BigInt using big-endian encoding.
 *
 * @param {Uint8Array} bytes - The byte array to convert.
 * @returns {bigint} - The resulting BigInt.
 */
export function bytesToBigIntBE(bytes) {
    let x = 0n;
    for (const b of bytes) {
        x = (x << 8n) + BigInt(b);
    }
    return x;
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
export async function generateZKProof(input) {

    // Validate required fields from input
    if (!input.secret || !input.computedOtp || !input.hashedSecret || !input.hashedOtp || !input.timeStep || !input.actionHash || !input.txNonce) {
        throw new Error("Missing required fields in input");
    }

    const __filename = fileURLToPath(import.meta.url);
    const __dirname = path.dirname(__filename);

    // This will resolve to /usr/src/app/utils/totp.wasm inside the container
    const wasmPath = path.join(__dirname, "totp.wasm");
    const zkeyPath = path.join(__dirname, "totp_0001.zkey");

    let proof, publicSignals;
    try {
        const result = await snarkjs.groth16.fullProve(
            {
                secret: input.secret,
                otp_code: input.computedOtp,
                hashed_secret: input.hashedSecret,
                hashed_otp: input.hashedOtp,
                time_step: input.timeStep,
                action_hash: input.actionHash,
                tx_nonce: input.txNonce
            },
            wasmPath,
            zkeyPath
        );
        proof = result.proof;
        publicSignals = result.publicSignals;
    } catch (error) {
        console.error("Error during proof generation in 'snarkjs.groth16.fullProve':", error);
        throw new Error(`Proof generation failed in 'snarkjs.groth16.fullProve': ${error.message}`);
    }

    const isValid = await verifyProof(proof, publicSignals);
    if (!isValid) {
        throw new Error("Proof verification failed.");
    }

    const solidityCalldata = await snarkjs.groth16.exportSolidityCallData(proof, publicSignals)
    const finalProofObject = parseSolidityCallData(solidityCalldata);

    return finalProofObject;
}

// Function to verify the proof
async function verifyProof(proof, publicSignals) {
    // Read the verification key from a JSON file
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = path.dirname(__filename);

    // This will resolve to /usr/src/app/utils/totp.wasm inside the container
    const verificationKeyPath = path.join(__dirname, "verification_key.json");
    const verificationKey = JSON.parse(fs.readFileSync(verificationKeyPath, 'utf8'));

    // Use snarkjs to verify the proof
    const isValid = await snarkjs.groth16.verify(verificationKey, publicSignals, proof);
    return isValid;
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

/**
 * Decodes a Base32-encoded string into a Uint8Array.
 *
 * @param {string} b32str - The Base32-encoded string to decode.
 * @returns {Uint8Array} - The decoded data as a Uint8Array.
 */
export function base32Decode(b32str) {
    const decoder = new base32.Decoder();
    return new Uint8Array(decoder.write(b32str).finalize());
}

