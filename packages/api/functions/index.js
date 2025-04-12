import { initializeApp } from "firebase-admin/app";
import { onRequest } from "firebase-functions/v2/https";
import { setGlobalOptions } from "firebase-functions/v2";
import { padBase32, computePoseidonHash, computeActionHash } from "./utils/utils.js";
import { getFirestore } from "firebase-admin/firestore";
import { decryptSecret } from "./utils/utils.js";
import dotenv from "dotenv";



// Initialize Firebase Admin if needed
initializeApp();

// Set global region (and optionally other options)
setGlobalOptions({
    region: "asia-southeast1",
});

// Example: An HTTPS function
export const helloWorld = onRequest((req, res) => {
    res.send("Hello from Singapore region!");
});

// generate proof function
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

    const salt = process.env.SALT;
    if (!salt) {
        res.status(500).send("Server configuration error: SALT is missing");
        return;
    }

    const decryptedSecret = decryptSecret(encryptedSecret, salt);
    const padBase32Secret = padBase32(decryptedSecret);
    const secretBytes = base32Decode(padBase32Secret);
    const secretIntOrig = bytesToBigIntBE(secret_bytes);
    const BN254_PRIME = BigInt("21888242871839275222246405745257275088548364400416034343698204186575808495617");
    const secretIntMod = secretIntOrig % BN254_PRIME;

    const secret = secretIntMod.toString();
    const computedOtp = computeTOTP6(secretBytes, timeStep);
    const hashedSecret = await computePoseidonHash(secretIntMod);
    const hashedOtp = await computePoseidonHash(otp);
    const timeStep = Math.floor(Date.now() / 30000);
    const actionHash = computeActionHash(to, value, data);
    const txNonce = Math.floor(Math.random() * 1000000);

    const input = {
        secret,
        computedOtp,
        hashedSecret,
        hashedOtp,
        timeStep,
        actionHash,
        txNonce,
    };

    const proof = await generateProof(input);
    res.status(200).send({ status: "ok", proof });
});
