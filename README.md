# ZKOTP-PROJECT
DEMO: https://www.zksolutions.org/

ZKOTP Traffic Light Project
This project demonstrates how to securely control an on-chain “traffic light” using a Zero-Knowledge One-Time Password (ZKOTP) system. By leveraging TOTP (e.g., Google Authenticator) and zero-knowledge proofs, users can prove they hold a valid one-time password without revealing the actual secret.

Highlights
On-Chain State Control: The traffic light color is stored in a smart contract.

Privacy-Preserving Authentication: ZK proofs ensure only those with a valid OTP can update the light’s state.

TOTP Integration: Easily generate OTPs using standard apps like Google Authenticator.
