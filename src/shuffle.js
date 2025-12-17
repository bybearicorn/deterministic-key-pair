import { words } from "./wordlist.js";
import { sha256 } from "./sha256.js";

const ENTROPY_BITS_BY_WORDS = {
  12: 128,
  15: 160,
  18: 192,
  21: 224,
  24: 256,
};

function bytesToBinary(u8) {
  let out = "";
  for (let i = 0; i < u8.length; i++) out += u8[i].toString(2).padStart(8, "0");
  return out;
}

function deriveChecksumBits(entropyU8) {
  const entropyBits = entropyU8.length * 8;
  const csLen = entropyBits / 32; // BIP-39 checksum length
  const hashBytes = sha256.array(entropyU8); // 32 bytes (Array<number>)
  const hashBits = bytesToBinary(Uint8Array.from(hashBytes));
  return hashBits.slice(0, csLen);
}

export function entropyToMnemonic(entropyU8) {
  if (!(entropyU8 instanceof Uint8Array))
    throw new TypeError("entropy must be Uint8Array");

  const entropyBits = entropyU8.length * 8;
  if (entropyBits % 32 !== 0 || entropyBits < 128 || entropyBits > 256) {
    throw new Error(
      "invalid entropy length (must be 128..256 bits, multiple of 32)",
    );
  }
  if (!Array.isArray(words) || words.length !== 2048) {
    throw new Error("wordlist must contain exactly 2048 words");
  }

  const bits = bytesToBinary(entropyU8) + deriveChecksumBits(entropyU8);

  const chunks = bits.match(/.{11}/g);
  if (!chunks) throw new Error("failed to split into 11-bit chunks");

  return chunks.map((bin) => words[parseInt(bin, 2)]);
}

function randomEntropyBytes(byteLen) {
  const c = globalThis.crypto;
  if (!c || typeof c.getRandomValues !== "function") {
    throw new Error("Secure RNG not available: crypto.getRandomValues missing");
  }
  const out = new Uint8Array(byteLen);
  c.getRandomValues(out);
  return out;
}

export function getRandomMnemonic(take = 12) {
  const wc = Number(take);
  const entropyBits = ENTROPY_BITS_BY_WORDS[wc];
  if (!entropyBits) throw new Error("take must be one of: 12, 15, 18, 21, 24");

  const entropyU8 = randomEntropyBytes(entropyBits / 8);
  return entropyToMnemonic(entropyU8);
}
