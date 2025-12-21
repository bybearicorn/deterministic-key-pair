#!/usr/bin/env node

import { getRandomMnemonic } from "./shuffle.js";
import { pbkdf2Hmac } from "./pbkdf2.js";
import { hmac as hmacSha512 } from "./sha512.js";
import { keypairFromSeed } from "./key.js";

const mnemonicWords = getRandomMnemonic(12);
const exportMnemonic = mnemonicWords.join(" ");

const password = exportMnemonic.normalize("NFKD");

const passphrase = "secret password required by user";
const salt = ("mnemonic" + passphrase).normalize("NFKD");

const seed = pbkdf2Hmac({
  hmac: (key, msg) => hmacSha512(key, msg),
  hashLen: 64, // SHA-512 output bytes
  password,
  salt,
  iterations: 2048,
  dkLen: 64, // BIP39 seed length
});

const exportSeedAsHex = [...seed]
  .map((b) => b.toString(16).padStart(2, "0"))
  .join("");

const { privateKey, publicKey } = keypairFromSeed(seed, "app:v1:encryption");

const exportPrivateKey = [...privateKey]
  .map((b) => b.toString(16).padStart(2, "0"))
  .join("");

const exportPublicKey = [...publicKey]
  .map((b) => b.toString(16).padStart(2, "0"))
  .join("");

export function secureGenerateKeyGen(
  passphrase = "",
  mnemonicLength = 12,
  ownEntropyString = undefined,
) {
  // allow only valid BIP39 sizes (optional but strongly recommended)
  const allowedMnemonicLengths = [12, 15, 18, 21, 24];
  if (
    !Number.isInteger(mnemonicLength) ||
    !allowedMnemonicLengths.includes(mnemonicLength)
  ) {
    throw new TypeError("mnemonicLength must be one of 12, 15, 18, 21, 24");
  }

  // passphrase: must be a primitive string
  if (typeof passphrase !== "string") {
    throw new TypeError("passphrase must be a string");
  }

  // ownEntropyString: optional; if provided must be non-empty string
  if (
    ownEntropyString !== undefined &&
    (typeof ownEntropyString !== "string" || ownEntropyString.length === 0)
  ) {
    throw new TypeError(
      "ownEntropyString must be a non-empty string if provided",
    );
  }

  return {
    mnemonic: exportMnemonic,
    seed: exportSeedAsHex,
    privateKey: exportPrivateKey,
    publicKey: exportPublicKey,
  };
}
