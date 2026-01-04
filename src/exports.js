import { getMnemonic } from "./libs/mnemonic.js";
import { secureGenerateKeyGen } from "./keygen.js";

// different package
// export function generateMnemonic() {
//   return mnemonic;
// }

export function generateKeyPairFromMnemonic({ mnemonic, passphrase }) {
  if (!mnemonic) {
    mnemonic = getMnemonic();
  }
  return secureGenerateKeyGen({ mnemonic, passphrase });
}
