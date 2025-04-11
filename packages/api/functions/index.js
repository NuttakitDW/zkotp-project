import { initializeApp } from "firebase-admin/app";
import { onRequest } from "firebase-functions/v2/https";
import { setGlobalOptions } from "firebase-functions/v2";

// Initialize Firebase Admin if needed
initializeApp();

// Set global region (and optionally other options)
setGlobalOptions({
    region: "asia-southeast1",
    // e.g. memory: "512MiB",
    // e.g. timeoutSeconds: 60,
});

// Example: An HTTPS function
export const helloWorld = onRequest((req, res) => {
    res.send("Hello from Singapore region!");
});
