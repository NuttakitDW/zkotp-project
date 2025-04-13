// src/lib/totp.js
import speakeasy from "speakeasy";
import { ethers } from "ethers";

// src/lib/api.js
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:3000';

const userRegistrationCache = {};

/**
 * checkUser(uid) => returns an object like:
 *   {
 *     uid: string,
 *     user_doc: { ...any Firestore data... },
 *     registered: boolean
 *   }
 *
 * If user is not found (HTTP 404), returns { registered: false }
 * If there's an error, returns { registered: false, error: "..." }
 */
export async function checkUser(uid) {
    // If no uid provided, just return a default shape
    if (!uid) {
        return { registered: false };
    }

    // Check our in-memory cache
    if (userRegistrationCache[uid]) {
        console.log(`Using cached user info for uid: ${uid}`);
        return userRegistrationCache[uid];
    }

    try {
        // e.g. "http://localhost:3000/user/check?uid=0x1234"
        const response = await fetch(`${API_BASE_URL}/user/check?uid=${uid}`);

        if (response.ok) {
            // 200 => parse JSON => { uid, user_doc, registered: true }
            const data = await response.json();
            userRegistrationCache[uid] = data; // store the entire object
            return data;
        } else if (response.status === 404) {
            // user not found => { registered: false }
            const notFoundObj = { registered: false };
            userRegistrationCache[uid] = notFoundObj;
            return notFoundObj;
        } else {
            // Some other error code
            console.error("checkUser failed with status:", response.status);
            return { registered: false, error: `HTTP ${response.status}` };
        }
    } catch (err) {
        console.error("Error in checkUser:", err);
        return { registered: false, error: err.message };
    }
}



export async function registerUser(uid, secret) {
    try {
        const response = await fetch(`${API_BASE_URL}/user/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ uid, secret })
        });

        if (!response.ok) {
            console.error("Register user failed with status:", response.status);
            return false;
        }

        // Optionally parse JSON if needed
        const data = await response.json();
        console.log("Register user success:", data);
        return true;
    } catch (err) {
        console.error("Error registering user:", err);
        return false;
    }
}

export function generateGoogleAuthSecret(appName = "ZK-OTP Demo") {
    const secret = speakeasy.generateSecret({
        name: appName,
    });
    return {
        base32: secret.base32,
        otpauthUrl: secret.otpauth_url
    };
}

export async function getWalletAddress() {
    // Ensure that MetaMask (window.ethereum) is available
    if (typeof window === "undefined" || !window.ethereum) {
        throw new Error("MetaMask not found.");
    }

    // Create a provider
    const provider = new ethers.BrowserProvider(window.ethereum);

    // Request account access (if not already granted)
    const accounts = await provider.send("eth_requestAccounts", []);

    // The first account in `accounts` is the primary signer
    const userAddress = accounts[0];
    return userAddress;
}

export async function verifyOtp(uid, otp) {
    const response = await fetch(`${API_BASE_URL}/otp/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ uid, otp })
    });
    const data = await response.json();
    return data.match; // true/false
}