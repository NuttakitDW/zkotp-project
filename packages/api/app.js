/***************************************
 * app.js 
 **************************************/
import express from "express";
import dotenv from "dotenv";
import { createClient } from "@supabase/supabase-js";
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

// Load environment variables (SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, etc.)
dotenv.config();

// 1) Initialize Supabase client
// For secure, full read/write, you might use the "service role" key on your server:
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!supabaseUrl || !supabaseServiceKey) {
    throw new Error("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY in .env");
}

const supabase = createClient(supabaseUrl, supabaseServiceKey);

// 2) Create Express app
const app = express();
app.use(express.json()); // parse JSON bodies

//=============================
//  REGISTER USER
//=============================
app.post("/registerUser", async (req, res) => {
    try {
        const { uid, secret } = req.body;
        if (!uid || !secret) {
            return res.status(400).json({ error: "Missing uid or secret" });
        }

        // Check if user already exists
        const { data: existingUsers, error: selectError } = await supabase
            .from("users")
            .select("*")
            .eq("uid", uid);

        if (selectError) {
            throw selectError; // let our catch block handle it
        }
        if (existingUsers.length > 0) {
            return res.status(400).json({ error: "User already exists" });
        }

        // Encrypt user secret
        const encrypted_secret = encryptWithSalt(secret, uid);

        // Insert new user
        const { error: insertError } = await supabase
            .from("users")
            .insert([{ uid, encrypted_secret }]);

        if (insertError) {
            throw insertError;
        }

        return res.status(200).json({ message: "User registered successfully" });
    } catch (err) {
        console.error("Error in /registerUser:", err);
        return res.status(500).json({ error: "Internal Server Error" });
    }
});

//=============================
//  GENERATE PROOF
//=============================
app.post("/generateProof", async (req, res) => {
    try {
        const { uid, otp, to, value, data } = req.body;
        if (!uid || otp == null || !to || value == null || data == null) {
            return res.status(400).json({ error: "Missing required fields" });
        }

        // Fetch user
        const { data: foundUsers, error: userError } = await supabase
            .from("users")
            .select("*")
            .eq("uid", uid)
            .single();

        if (userError) {
            throw userError;
        }
        if (!foundUsers) {
            return res.status(404).json({ error: "User not found" });
        }

        const { encrypted_secret } = foundUsers;
        const encryptedSecret = encrypted_secret;

        // Decrypt user secret
        const decryptedSecret = decryptWithSalt(encryptedSecret, uid);

        // Prepare secret bytes
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
        const timeStep = Math.floor(Date.now() / 30000);
        const computedOtp = computeTOTP6(secretBytes, timeStep);

        // Poseidon hashes
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
            return res.status(200).json({ status: "ok", proof });
        } catch (error) {
            console.error("Failed to generate proof:", error);
            return res
                .status(400)
                .json({ status: "error", message: "Invalid OTP or proof generation failed." });
        }
    } catch (err) {
        console.error("Error in /generateProof:", err);
        return res.status(500).json({ error: "Internal Server Error" });
    }
});

//=============================
//  START SERVER
//=============================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Supabase-based app listening on port ${PORT}`);
});
