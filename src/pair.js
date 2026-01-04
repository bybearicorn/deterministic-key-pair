import { getMnemonic } from "./libs/shuffle.js";

const mnemonic = getMnemonic();

export function generateMnemonic() {
  return mnemonic;
}

export function generateMnemonicAsPaddedString() {
  return mnemonic.join(" ").normalize("NFKD");
}

console.info(generateMnemonic());
console.info(generateMnemonicAsPaddedString());
