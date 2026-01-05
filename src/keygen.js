import { pbkdf2Hmac } from "./libs/pbkdf2.js";
import { hmac as hmacSha512 } from "./libs/sha512.js";
import { getPublicKey, CURVE_N } from "./libs/secp256k1.js";
import { convertUint8ToHex, convertHexToUint8 } from "./libs/convert.js";

export function getKeyGen({ passphrase = "", mnemonic = null }) {
  if (!mnemonic) {
    throw new Error("Mnemonic is required for using getKeyGen");
  }

  if (typeof passphrase !== "string") {
    throw new TypeError("Passphrase must be a string");
  }

  const salt = ("mnemonic" + passphrase).normalize("NFKD");

  const joinedMnemonic = mnemonic.join(" ").normalize("NFKD");

  const seedAsUint8 = pbkdf2Hmac({
    hmac: (key, msg) => hmacSha512(key, msg),
    hashLen: 64, // SHA-512 output bytes
    password: joinedMnemonic,
    salt,
    iterations: 2048,
    dkLen: 64, // BIP39 seed length
  });

  const hexSeed = convertUint8ToHex(seedAsUint8);

  return {
    mnemonic,
    ...getKeyGenFromSeed({ hexSeed }),
  };
}

export function getKeyGenFromSeed({ hexSeed }) {
  if (typeof hexSeed !== "string" || !/^[0-9a-fA-F]{128}$/.test(hexSeed)) {
    throw new Error("hexSeed must be a 64-byte hex string (128 hex chars)");
  }

  const { privateKey, publicKey } = keypairFromSeed(hexSeed, "app:v1:encryption");

  return {
    seed: hexSeed,
    privateKey: convertUint8ToHex(privateKey),
    publicKey: convertUint8ToHex(publicKey),
  };
}

function bytesToBigInt(b) {
  let x = 0n;
  for (let i = 0; i < b.length; i++) x = (x << 8n) | BigInt(b[i]);
  return x;
}

function bigIntTo32Bytes(x) {
  const out = new Uint8Array(32);
  let v = x;
  for (let i = 31; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function utf8Bytes(s) {
  const out = [];
  for (let i = 0; i < s.length; i++) out.push(s.charCodeAt(i) & 0xff);
  return new Uint8Array(out);
}

function keypairFromSeed(seedAsHex, context = "app:v1:asym-ec-secp256k1") {
  const seedAsUint8 = convertHexToUint8(seedAsHex);
  const label = utf8Bytes(context);

  const I = hmacSha512(label, seedAsUint8); // 64B
  const k0 = bytesToBigInt(I.slice(0, 32));

  const n = CURVE_N;
  const k = (k0 % (n - 1n)) + 1n;

  const priv = bigIntTo32Bytes(k);
  const pub = getPublicKey(priv, true);

  return { privateKey: priv, publicKey: pub };
}
