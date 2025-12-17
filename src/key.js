import { hmac as hmacSha512 } from "./sha512.js";
import { getPublicKey, CURVE_N } from "./secp256k1.js";

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

export function keypairFromSeed(seed64, context = "app:v1:asym-ec-secp256k1") {
  if (!(seed64 instanceof Uint8Array) || seed64.length !== 64) {
    throw new Error("seed64 must be Uint8Array(64)");
  }

  const label = utf8Bytes(context);

  const I = hmacSha512(label, seed64); // 64B
  const k0 = bytesToBigInt(I.slice(0, 32));

  const n = CURVE_N;
  const k = (k0 % (n - 1n)) + 1n;

  const priv = bigIntTo32Bytes(k);
  const pub = getPublicKey(priv, true);

  return { privateKey: priv, publicKey: pub };
}
