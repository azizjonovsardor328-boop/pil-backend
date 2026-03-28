const { buildPoseidon } = require("circomlibjs");
const crypto = require("crypto");

async function main() {
    try {
        const poseidon = await buildPoseidon();
        // Generate a random 256-bit scalar within the bn128 field
        const bytes = crypto.randomBytes(31);
        const secret = BigInt("0x" + bytes.toString('hex'));
        
        // Compute Poseidon hash
        const hash = poseidon([secret]);
        const hashStr = poseidon.F.toString(hash);
        
        console.log(JSON.stringify({
            secret_key: secret.toString(),
            public_hash: hashStr
        }));
    } catch (e) {
        console.error(e);
        process.exit(1);
    }
}

main();
