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
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!supabaseUrl || !supabaseServiceKey) {
    throw new Error("Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY in .env");
}

console.info("Initializing Supabase client...");
const supabase = createClient(supabaseUrl, supabaseServiceKey);

// 2) Create Express app
const app = express();
app.use(express.json()); // parse JSON bodies

console.info("Express app initialized.");

//=============================
//  REGISTER USER
//=============================
app.post("/registerUser", async (req, res) => {
    console.info("Received request to /registerUser");
    try {
        const { uid, secret } = req.body;
        console.info("Request body:", { uid, secret: secret ? "provided" : "not provided" });

        if (!uid || !secret) {
            console.warn("Missing uid or secret in request body.");
            return res.status(400).json({ error: "Missing uid or secret" });
        }

        // Check if user already exists
        console.info("Checking if user already exists...");
        const { data: existingUsers, error: selectError } = await supabase
            .from("users")
            .select("*")
            .eq("uid", uid);

        if (selectError) {
            console.error("Error querying existing users:", selectError);
            throw selectError;
        }
        if (existingUsers.length > 0) {
            console.warn("User already exists:", uid);
            return res.status(400).json({ error: "User already exists" });
        }

        // Encrypt user secret
        console.info("Encrypting user secret...");
        const encrypted_secret = encryptWithSalt(secret, uid);

        // Insert new user
        console.info("Inserting new user into database...");
        const { error: insertError } = await supabase
            .from("users")
            .insert([{ uid, encrypted_secret }]);

        if (insertError) {
            console.error("Error inserting new user:", insertError);
            throw insertError;
        }

        console.info("User registered successfully:", uid);
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
    console.info("Received request to /generateProof");
    try {
        const { uid, otp, to, value, data } = req.body;
        console.info("Request body:", { uid, otp, to, value, data });

        if (!uid || otp == null || !to || value == null || data == null) {
            console.warn("Missing required fields in request body.");
            return res.status(400).json({ error: "Missing required fields" });
        }

        // Fetch user
        console.info("Fetching user from database...");
        const { data: foundUsers, error: userError } = await supabase
            .from("users")
            .select("*")
            .eq("uid", uid)
            .single();

        if (userError) {
            console.error("Error fetching user:", userError);
            throw userError;
        }
        if (!foundUsers) {
            console.warn("User not found:", uid);
            return res.status(404).json({ error: "User not found" });
        }

        const { encrypted_secret } = foundUsers;
        console.info("User found. Decrypting secret...");
        const encryptedSecret = encrypted_secret;

        // Decrypt user secret
        const decryptedSecret = decryptWithSalt(encryptedSecret, uid);

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
        console.error("Error in /generateProof:", err);
        return res.status(500).json({ error: "Internal Server Error" });
    }
});

//=============================
//  START SERVER
//=============================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.info(`Supabase-based app listening on port ${PORT}`);
});
