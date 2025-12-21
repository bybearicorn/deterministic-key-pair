import { getKeyPairFromMnemonic } from "./src/index.js";

const instance = getKeyPairFromMnemonic({
  mnemonic:
    "divert rule embody mystery direct develop quality injury miracle only member voyage",
});

console.info("private key in hex", instance.privateKey);
console.info("public key in hex", instance.publicKey);
