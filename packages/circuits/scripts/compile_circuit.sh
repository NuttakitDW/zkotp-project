#!/usr/bin/env bash
circom ./src/OtpCircuit.circom --r1cs --wasm --sym -o build/

# Setup for groth16
snarkjs groth16 setup build/OtpCircuit.r1cs potXX_final.ptau build/circuit_0000.zkey
snarkjs zkey contribute build/circuit_0000.zkey build/circuit_final.zkey
snarkjs zkey export verificationkey build/circuit_final.zkey build/verification_key.json

# Generate solidity verifier
snarkjs zkey export solidityverifier build/circuit_final.zkey Verifier.sol

# Then copy Verifier.sol to contracts
cp Verifier.sol ../contracts/src/
