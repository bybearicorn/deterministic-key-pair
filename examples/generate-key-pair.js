import { secureGenerateKeyGen } from "./src/index.js";

const instance = secureGenerateKeyGen({
  passphrase: "Hello World",
  mnemonicLength: 12,
  ownEnthropyString: Math.random() + "",
});

console.info("12 words", instance.mnemonicString);
console.info("hex seed", instance.seed);
console.info("private key in hex", instance.privateKey);
console.info("public key in hex", instance.publicKey);
