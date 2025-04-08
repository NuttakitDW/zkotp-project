pragma circom 2.0.0;
include "./node_modules/circomlib/circuits/poseidon.circom";

template TOTPCircuit() {
    signal input secret;
    signal input otp_code;
    signal input hashed_secret;
    signal input hashed_otp;
    signal input time_step;
    signal input action_hash;
    signal input tx_nonce;

    // For example, if the Poseidon template is Poseidon(nInputs)
    component poseidonSecret = Poseidon(1);
    component poseidonOtp    = Poseidon(1);

    // Replace 'in' with 'inputs'
    poseidonSecret.inputs[0] <== secret;
    poseidonOtp.inputs[0]    <== otp_code;

    poseidonSecret.out === hashed_secret;
    poseidonOtp.out === hashed_otp;
}

component main = TOTPCircuit();
