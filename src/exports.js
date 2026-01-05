import { getMnemonic } from "./libs/mnemonic.js";
import { getKeyGen, getKeyGenFromSeed } from "./keygen.js";

export function generateMnemonic({ length = 12 } = {}) {
  return getMnemonic(length);
}

export function generateKeyPairFromMnemonic({ mnemonic, passphrase }) {
  return getKeyGen({ mnemonic, passphrase });
}

export function generateKeyPairFromSeed({ hexSeed }) {
  return getKeyGenFromSeed({ hexSeed });
}
