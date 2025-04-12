pragma circom 2.0.0;
include "./node_modules/circomlib/circuits/poseidon.circom";

template TOTPCircuit() {
    // All inputs (treated as private by default)
    signal input secret;
    signal input otp_code;
    signal input hashed_secret;
    signal input hashed_otp;
    signal input time_step;
    signal input action_hash;
    signal input tx_nonce;

    // Poseidon components
    component poseidonSecret = Poseidon(1);
    component poseidonOtp    = Poseidon(1);

    poseidonSecret.inputs[0] <== secret;
    poseidonOtp.inputs[0]    <== otp_code;

    // Constraints
    poseidonSecret.out === hashed_secret;
    poseidonOtp.out === hashed_otp;

    // If you want these to appear in public.json, define them as outputs:
    signal output outHashedSecret;
    signal output outHashedOtp;
    signal output outTimeStep;
    signal output outActionHash;
    signal output outTxNonce;

    outHashedSecret <== hashed_secret;
    outHashedOtp <== hashed_otp;
    outTimeStep <== time_step;
    outActionHash <== action_hash;
    outTxNonce <== tx_nonce;
}

component main = TOTPCircuit();
