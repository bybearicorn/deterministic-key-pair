import { getMnemonic } from "./libs/mnemonic.js";
import { secureGenerateKeyGen } from "./keygen.js";

const mnemonic = getMnemonic();

export function generateMnemonic() {
  return mnemonic;
}

export function getKeypairFromMnemonic() {
  return secureGenerateKeyGen({ mnemonic });
}

console.info(secureGenerateKeyGen({ mnemonic }));
