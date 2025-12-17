import { getRandomMnemonic } from "./src/shuffle.js";
import { pbkdf2Hmac } from "./src/pbkdf2.js";
import { hmac as hmacSha512 } from "./src/sha512.js";

const mnemonicWords = getRandomMnemonic(12);
const mnemonic = mnemonicWords.join(" ");
console.info("mnemonic:", mnemonic);

const passphrase = "asd";
const password = mnemonic.normalize("NFKD");
const salt = ("mnemonic" + passphrase).normalize("NFKD");

const seed = pbkdf2Hmac({
  hmac: (key, msg) => hmacSha512(key, msg),
  hashLen: 64, // SHA-512 output bytes
  password,
  salt,
  iterations: 2048,
  dkLen: 64, // BIP39 seed length
});

const seedHex = [...seed].map((b) => b.toString(16).padStart(2, "0")).join("");
console.info("seed(hex):", seedHex);
