import { getMnemonic } from "./libs/mnemonic.js";
import {
  secureGenerateKeyGen,
  secureGenerateKeyGenFromSeed,
} from "./keygen.js";

export function generateMnemonic({ length = 12 } = {}) {
  return getMnemonic(length);
}

export function generateKeyPairFromMnemonic({ mnemonic, passphrase }) {
  return secureGenerateKeyGen({ mnemonic, passphrase });
}

console.info(
  generateKeyPairFromMnemonic({
    mnemonic: [
      "antenna",
      "clay",
      "silly",
      "page",
      "mesh",
      "dizzy",
      "devote",
      "venture",
      "logic",
      "tornado",
      "mouse",
      "athlete",
    ],
  }),
);

export function getKeyPairFromSeed({ seed }) {
  return secureGenerateKeyGenFromSeed({ seed });
}
