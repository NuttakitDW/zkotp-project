#!/bin/bash

# 1) Compile
circom totp.circom --r1cs --wasm --sym

# 2) Powers of Tau - Phase 1
snarkjs powersoftau new bn128 12 pot12_0000.ptau -v
snarkjs powersoftau contribute pot12_0000.ptau pot12_0001.ptau --name="First contribution" -v

# 3) Powers of Tau - Phase 2
snarkjs powersoftau prepare phase2 pot12_0001.ptau pot12_0002.ptau -v

# 4) Groth16 Setup
snarkjs groth16 setup totp.r1cs pot12_0002.ptau totp_0000.zkey
snarkjs zkey contribute totp_0000.zkey totp_0001.zkey --name="Second contribution" -v
snarkjs zkey export verificationkey totp_0001.zkey verification_key.json

# 5) Generate witness
cd totp_js
node generate_witness.js totp.wasm ../input.json ../witness.wtns
cd ..

# 6) Prove
snarkjs groth16 prove totp_0001.zkey witness.wtns proof.json public.json

# 7) Verify
snarkjs groth16 verify verification_key.json public.json proof.json
