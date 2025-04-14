/***************************************
 * app.js 
 **************************************/
import express from "express";
import dotenv from "dotenv";
import admin from "firebase-admin";
import { Firestore } from "@google-cloud/firestore"
import speakeasy from "speakeasy";

import {
    encryptWithSalt,
    decryptWithSalt,
    padBase32,
    base32Decode,
    bytesToBigIntBE,
    computePoseidonHash,
    computeActionHash,
    computeTOTP6,
    generateZKProof,
} from "./utils/utils.js";

// Load environment variables
dotenv.config();

// Initialize Firebase Admin SDK
admin.initializeApp({
    credential: admin.credential.applicationDefault(),
});
const db = new Firestore({
    projectId: process.env.GCLOUD_PROJECT,
});

// 1) Create Express app
const app = express();
app.use(express.json()); // parse JSON bodies

console.info("Express app initialized.");

//=============================
//  USER
//=============================
app.get("/user/check", async (req, res) => {
    console.info("Received request to /checkUser");
    try {
        const { uid } = req.query;

        if (!uid) {
            console.warn("Missing uid in request query.");
            return res.status(400).json({ error: "Missing uid" });
        }

        // Check if user exists in Firestore
        const userDoc = await db.collection("users").doc(uid).get();
        if (userDoc.exists) {
            console.info("User found:", uid);
            return res.status(200).json({ uid: uid, user_doc: userDoc.data(), registered: true });
        } else {
            console.info("User not found:", uid);
            return res.status(404).json({ registered: false });
        }
    } catch (err) {
        console.error("Error in /user/check:", err);
        return res.status(500).json({ error: "Internal Server Error" });
    }
});

app.post("/user/register", async (req, res) => {
    console.info("Received request to /registerUser");
    try {
        const { uid, secret } = req.body;

        if (!uid || !secret) {
            console.warn("Missing uid or secret in request body.");
            return res.status(400).json({ error: "Missing uid or secret" });
        }

        // Encrypt the secret
        const encrypted_secret = encryptWithSalt(secret, uid);

        // Store encrypted_secret in Firestore
        await db.collection("users").doc(uid).set({ encrypted_secret });

        console.info("User registered successfully:", uid);
        return res.status(200).json({ message: "User registered successfully" });
    } catch (err) {
        console.error("Error in /user/register:", err);
        return res.status(500).json({ error: "Internal Server Error" });
    }
});

//=============================
//  GENERATE PROOF
//=============================
app.post("/proof/generate", async (req, res) => {
    console.info("Received request to /proof/generate");
    try {
        const { uid, otp, to, value, data } = req.body;

        if (!uid || otp == null || !to || value == null || data == null) {
            console.warn("Missing required fields in request body.");
            return res.status(400).json({ error: "Missing required fields" });
        }

        // Fetch encrypted_secret from Firestore
        const userDoc = await db.collection("users").doc(uid).get();
        if (!userDoc.exists) {
            console.warn("User not found:", uid);
            return res.status(404).json({ error: "User not found" });
        }
        const { encrypted_secret } = userDoc.data();

        // Decrypt the secret
        const decryptedSecret = decryptWithSalt(encrypted_secret, uid);

        // Prepare secret bytes
        console.info("Preparing secret bytes...");
        const padBase32Secret = padBase32(decryptedSecret);
        const secretBytes = base32Decode(padBase32Secret);
        const secretIntOrig = bytesToBigIntBE(secretBytes);

        // BN254 prime for mod
        const BN254_PRIME = BigInt(
            "21888242871839275222246405745257275088548364400416034343698204186575808495617"
        );
        const secretIntMod = secretIntOrig % BN254_PRIME;
        const secret = secretIntMod.toString();

        // Compute TOTP
        console.info("Computing TOTP...");
        const timeStep = Math.floor(Date.now() / 30000);
        const computedOtp = computeTOTP6(secretBytes, timeStep);

        // Poseidon hashes
        console.info("Computing Poseidon hashes...");
        const hashedSecret = await computePoseidonHash(secretIntMod);
        const hashedOtp = await computePoseidonHash(BigInt(otp));
        const actionHash = computeActionHash(to, value, data);
        const txNonce = Math.floor(Math.random() * 1000000);

        const input = {
            secret: secret,
            computedOtp: computedOtp.toString(),
            hashedSecret: hashedSecret.toString(),
            hashedOtp: hashedOtp.toString(),
            timeStep: timeStep.toString(),
            actionHash: actionHash.toString(),
            txNonce: txNonce.toString(),
        };

        // Generate ZK proof
        try {
            const proof = await generateZKProof(input);
            console.info("ZK proof generated successfully.");
            return res.status(200).json({ status: "ok", proof });
        } catch (error) {
            console.error("Failed to generate proof:", error);
            return res
                .status(400)
                .json({ status: "error", message: "Invalid OTP or proof generation failed." });
        }
    } catch (err) {
        console.error("Error in /proof/generate:", err);
        return res.status(500).json({ error: "Internal Server Error" });
    }
});


//=============================
//  OTP
//=============================
app.post("/otp/secret/generate", (req, res) => {
    console.info("Received request to /otp/generate-secret");
    try {

        if (!name) {
            console.warn("Missing name in request body.");
            return res.status(400).json({ error: "Missing name" });
        }

        const secret = speakeasy.generateSecret({
            name: `zkotp`,
        });

        console.info("Secret generated successfully.");
        return res.status(200).json({
            base32: secret.base32,
            otpauth_url: secret.otpauth_url,
        });
    } catch (err) {
        console.error("Error in /otp/generate-secret:", err);
        return res.status(500).json({ error: "Internal Server Error" });
    }
});

app.post("/otp/verify", async (req, res) => {
    console.info("Received request to /otp/verify");
    try {
        const { uid, otp } = req.body;

        if (otp == null) {
            console.warn("Missing required fields in request body.");
            return res.status(400).json({ error: "Missing required fields" });
        }

        // Fetch encrypted_secret from Firestore
        const userDoc = await db.collection("users").doc(uid).get();
        if (!userDoc.exists) {
            console.warn("User not found:", uid);
            return res.status(404).json({ error: "User not found" });
        }
        const { encrypted_secret } = userDoc.data();

        // Decrypt the secret
        const secret = decryptWithSalt(encrypted_secret, uid);

        // Use speakeasy to verify
        const match = speakeasy.totp.verify({
            secret: secret,
            encoding: "base32",
            token: otp,
            window: 1,
        });

        if (match) {
            return res.status(200).json({ match: true });
        } else {
            return res.status(401).json({ match: false, error: "Invalid OTP code" });
        }

    } catch (err) {
        console.error("Error in /otp/verify:", err);
        return res.status(500).json({ error: "Internal Server Error" });
    }
});


//=============================
//  START SERVER
//=============================
const PORT = process.env.PORT || 8080; // Use port 8080 for Google Cloud Run
app.listen(PORT, () => {
    console.info(`App listening on port ${PORT}`);
});

