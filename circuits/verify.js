const snarkjs = require("snarkjs");
const fs = require("fs");
const path = require("path");

async function main() {
    try {
        const proof = JSON.parse(process.argv[2]);
        const publicSignals = JSON.parse(process.argv[3]);
        
        const vKeyPath = path.join(__dirname, "verification_key.json");
        const vKey = JSON.parse(fs.readFileSync(vKeyPath, "utf-8"));

        const res = await snarkjs.groth16.verify(vKey, publicSignals, proof);
        if (res === true) {
            console.log("OK");
            process.exit(0);
        } else {
            console.log("FAIL");
            process.exit(1);
        }
    } catch (e) {
        console.error("Verification error:", e);
        process.exit(1);
    }
}

main();
