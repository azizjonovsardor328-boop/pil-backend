pragma circom 2.0.0;

include "node_modules/circomlib/circuits/poseidon.circom";

template Identity() {
    signal input secret_key;
    signal input public_hash;

    component poseidon = Poseidon(1);
    poseidon.inputs[0] <== secret_key;

    public_hash === poseidon.out;
}

component main {public [public_hash]} = Identity();
