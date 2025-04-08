pragma circom 2.0.0;
include "./node_modules/circomlib/circuits/poseidon.circom";

template TOTPCircuit() {
    // Private
    signal input secret;       // private
    signal input otp_code;     // private

    // Public
    signal public input hashed_secret;
    signal public input hashed_otp;
    signal public input time_step;
    signal public input action_hash;
    signal public input tx_nonce;

    component poseidonSecret = Poseidon(1);
    component poseidonOtp    = Poseidon(1);

    poseidonSecret.inputs[0] <== secret;
    poseidonOtp.inputs[0]    <== otp_code;

    poseidonSecret.out === hashed_secret;
    poseidonOtp.out === hashed_otp;
}

component main = TOTPCircuit();
