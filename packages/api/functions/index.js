import { initializeApp } from "firebase-admin/app";
import { onRequest } from "firebase-functions/v2/https";
import { setGlobalOptions } from "firebase-functions/v2";
import { generateZKProof, computeTOTP6, bytesToBigIntBE, base32Decode, encryptWithSalt, decryptWithSalt, padBase32, computePoseidonHash, computeActionHash } from "./utils/utils.js";
import { getFirestore } from "firebase-admin/firestore";
import dotenv from "dotenv";
import { logger } from "firebase-functions";


// Initialize Firebase Admin if needed
initializeApp();

// Set global region (and optionally other options)
setGlobalOptions({
    region: "asia-southeast1",
});

/**
 * Registers a new user by storing their encrypted secret in the Firestore database.
 *
 * @async
 * @function registerUser
 * @param {Object} req - The HTTP request object.
 * @param {Object} req.body - The body of the request containing user data.
 * @param {string} req.body.uid - The unique identifier for the user.
 * @param {string} req.body.secret - The secret to be encrypted and stored.
 * @param {Object} res - The HTTP response object.
 * @returns {void} Sends an HTTP response indicating the result of the operation.
 *
 * @throws {Error} If the server configuration is missing the SALT environment variable.
 * @throws {Error} If the user already exists in the database.
 */
export const registerUser = onRequest(async (req, res) => {
    const { uid, secret } = req.body;
    const db = getFirestore();

    const encryptedSecret = encryptWithSalt(secret, uid);

    // Check if user already exists
    const userDoc = await db.collection("users").doc(uid).get();
    if (userDoc.exists) {
        res.status(400).send("User already exists");
        return;
    }

    // Create new user document
    await db.collection("users").doc(uid).set({ encryptedSecret });
    res.status(200).send("User registered successfully");
});

/**
 * Cloud Function to generate a cryptographic proof for a user action.
 * 
 * @async
 * @function generateProof
 * @param {Object} req - The HTTP request object.
 * @param {Object} req.body - The request body containing user data.
 * @param {string} req.body.uid - The unique identifier of the user.
 * @param {number} req.body.otp - The one-time password provided by the user.
 * @param {string} req.body.to - The recipient of the action.
 * @param {number} req.body.value - The value associated with the action.
 * @param {string} req.body.data - Additional data related to the action.
 * @param {Object} res - The HTTP response object.
 * @returns {void} Sends a response with the generated proof or an error message.
 * 
 * @throws {Error} If the user is not found in the database.
 * @throws {Error} If the server configuration is missing the SALT environment variable.
 * 
 * @description
 * This function retrieves the user's encrypted secret from Firestore, decrypts it using
 * a server-side salt, and computes cryptographic hashes and proofs based on the provided
 * input. It generates a zk-SNARK proof for the action and sends it back in the response.
 */
export const generateProof = onRequest(async (req, res) => {
    const { uid, otp, to, value, data } = req.body;
    const db = getFirestore();
    const userDoc = await db.collection("users").doc(uid).get();

    if (!userDoc.exists) {
        res.status(404).send("User not found");
        return;
    }

    const encryptedSecret = userDoc.data().encryptedSecret;
    dotenv.config();
    const decryptedSecret = decryptWithSalt(encryptedSecret, uid);
    const padBase32Secret = padBase32(decryptedSecret);
    const secretBytes = base32Decode(padBase32Secret);
    const secretIntOrig = bytesToBigIntBE(secretBytes);
    const BN254_PRIME = BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617");
    const secretIntMod = secretIntOrig % BN254_PRIME;

    const secret = secretIntMod.toString();
    const timeStep = Math.floor(Date.now() / 30000);
    const computedOtp = computeTOTP6(secretBytes, timeStep);
    const hashedSecret = await computePoseidonHash(secretIntMod);
    const hashedOtp = await computePoseidonHash(otp);
    const actionHash = computeActionHash(to, value, data);
    const txNonce = Math.floor(Math.random() * 1000000);

    const input = {
        secret: secret.toString(),
        computedOtp: computedOtp.toString(),
        hashedSecret: hashedSecret.toString(),
        hashedOtp: hashedOtp.toString(),
        timeStep: timeStep.toString(),
        actionHash: actionHash.toString(),
        txNonce: txNonce.toString(),
    };

    try {
        const proof = await generateZKProof(input);
        res.status(200).send({ status: "ok", proof });
    } catch (error) {
        logger.error("Failed to generate proof:", error);
        res.status(400).send({ status: "error", message: "Invalid OTP provided. Please check and try again." });
    }
});
