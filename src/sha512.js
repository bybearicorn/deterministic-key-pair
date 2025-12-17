// sha512.js (BIP-39/PBKDF2 kompatibilné, čisté JS, synchronné)
// Pozn.: potrebuje BigInt (Node >=10+, moderné browsre, Expo/Hermes s BigInt).

const MASK_64 = (1n << 64n) - 1n;

const K = [
  0x428a2f98d728ae22n,
  0x7137449123ef65cdn,
  0xb5c0fbcfec4d3b2fn,
  0xe9b5dba58189dbbcn,
  0x3956c25bf348b538n,
  0x59f111f1b605d019n,
  0x923f82a4af194f9bn,
  0xab1c5ed5da6d8118n,
  0xd807aa98a3030242n,
  0x12835b0145706fben,
  0x243185be4ee4b28cn,
  0x550c7dc3d5ffb4e2n,
  0x72be5d74f27b896fn,
  0x80deb1fe3b1696b1n,
  0x9bdc06a725c71235n,
  0xc19bf174cf692694n,
  0xe49b69c19ef14ad2n,
  0xefbe4786384f25e3n,
  0x0fc19dc68b8cd5b5n,
  0x240ca1cc77ac9c65n,
  0x2de92c6f592b0275n,
  0x4a7484aa6ea6e483n,
  0x5cb0a9dcbd41fbd4n,
  0x76f988da831153b5n,
  0x983e5152ee66dfabn,
  0xa831c66d2db43210n,
  0xb00327c898fb213fn,
  0xbf597fc7beef0ee4n,
  0xc6e00bf33da88fc2n,
  0xd5a79147930aa725n,
  0x06ca6351e003826fn,
  0x142929670a0e6e70n,
  0x27b70a8546d22ffcn,
  0x2e1b21385c26c926n,
  0x4d2c6dfc5ac42aedn,
  0x53380d139d95b3dfn,
  0x650a73548baf63den,
  0x766a0abb3c77b2a8n,
  0x81c2c92e47edaee6n,
  0x92722c851482353bn,
  0xa2bfe8a14cf10364n,
  0xa81a664bbc423001n,
  0xc24b8b70d0f89791n,
  0xc76c51a30654be30n,
  0xd192e819d6ef5218n,
  0xd69906245565a910n,
  0xf40e35855771202an,
  0x106aa07032bbd1b8n,
  0x19a4c116b8d2d0c8n,
  0x1e376c085141ab53n,
  0x2748774cdf8eeb99n,
  0x34b0bcb5e19b48a8n,
  0x391c0cb3c5c95a63n,
  0x4ed8aa4ae3418acbn,
  0x5b9cca4f7763e373n,
  0x682e6ff3d6b2b8a3n,
  0x748f82ee5defb2fcn,
  0x78a5636f43172f60n,
  0x84c87814a1f0ab72n,
  0x8cc702081a6439ecn,
  0x90befffa23631e28n,
  0xa4506cebde82bde9n,
  0xbef9a3f7b2c67915n,
  0xc67178f2e372532bn,
  0xca273eceea26619cn,
  0xd186b8c721c0c207n,
  0xeada7dd6cde0eb1en,
  0xf57d4f7fee6ed178n,
  0x06f067aa72176fban,
  0x0a637dc5a2c898a6n,
  0x113f9804bef90daen,
  0x1b710b35131c471bn,
  0x28db77f523047d84n,
  0x32caab7b40c72493n,
  0x3c9ebe0a15c9bebcn,
  0x431d67c49c100d4cn,
  0x4cc5d4becb3e42b6n,
  0x597f299cfc657e2an,
  0x5fcb6fab3ad6faecn,
  0x6c44198c4a475817n,
];

function rotr(x, n) {
  return ((x >> BigInt(n)) | (x << BigInt(64 - n))) & MASK_64;
}
function shr(x, n) {
  return x >> BigInt(n);
}

function Ch(x, y, z) {
  return (x & y) ^ (~x & z);
}
function Maj(x, y, z) {
  return (x & y) ^ (x & z) ^ (y & z);
}
function Sigma0(x) {
  return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39);
}
function Sigma1(x) {
  return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41);
}
function sigma0(x) {
  return rotr(x, 1) ^ rotr(x, 8) ^ shr(x, 7);
}
function sigma1(x) {
  return rotr(x, 19) ^ rotr(x, 61) ^ shr(x, 6);
}

function add64(...xs) {
  let s = 0n;
  for (const x of xs) s = (s + x) & MASK_64;
  return s;
}

function utf8Encode(str) {
  // bez TextEncoder fallback
  const out = [];
  for (let i = 0; i < str.length; i++) {
    let c = str.charCodeAt(i);
    if (c < 0x80) out.push(c);
    else if (c < 0x800) {
      out.push(0xc0 | (c >> 6), 0x80 | (c & 0x3f));
    } else if (c >= 0xd800 && c <= 0xdbff) {
      // surrogate pair
      const c2 = str.charCodeAt(++i);
      const cp = 0x10000 + ((c - 0xd800) << 10) + (c2 - 0xdc00);
      out.push(
        0xf0 | (cp >> 18),
        0x80 | ((cp >> 12) & 0x3f),
        0x80 | ((cp >> 6) & 0x3f),
        0x80 | (cp & 0x3f),
      );
    } else {
      out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 0x3f), 0x80 | (c & 0x3f));
    }
  }
  return new Uint8Array(out);
}

function toBytes(msg) {
  if (msg instanceof Uint8Array) return msg;
  if (typeof msg === "string") return utf8Encode(msg);
  throw new TypeError("sha512: msg must be string or Uint8Array");
}

function readUint64BE(bytes, off) {
  let x = 0n;
  for (let i = 0; i < 8; i++) x = (x << 8n) | BigInt(bytes[off + i]);
  return x;
}

function writeUint64BE(bytes, off, x) {
  for (let i = 7; i >= 0; i--) {
    bytes[off + i] = Number(x & 0xffn);
    x >>= 8n;
  }
}

export function sha512(msg) {
  const m = toBytes(msg);
  const bitLen = BigInt(m.length) * 8n;

  // padding: 1 bit + zeros until len ≡ 896 mod 1024, then 128-bit length
  const withOneLen = m.length + 1;
  const mod = withOneLen % 128;
  const padZeros = mod <= 112 ? 112 - mod : 112 + (128 - mod);
  const totalLen = withOneLen + padZeros + 16;

  const data = new Uint8Array(totalLen);
  data.set(m, 0);
  data[m.length] = 0x80;

  // length as 128-bit big-endian: high 64 then low 64
  const hi = (bitLen >> 64n) & MASK_64;
  const lo = bitLen & MASK_64;
  writeUint64BE(data, totalLen - 16, hi);
  writeUint64BE(data, totalLen - 8, lo);

  let H0 = 0x6a09e667f3bcc908n;
  let H1 = 0xbb67ae8584caa73bn;
  let H2 = 0x3c6ef372fe94f82bn;
  let H3 = 0xa54ff53a5f1d36f1n;
  let H4 = 0x510e527fade682d1n;
  let H5 = 0x9b05688c2b3e6c1fn;
  let H6 = 0x1f83d9abfb41bd6bn;
  let H7 = 0x5be0cd19137e2179n;

  const W = new Array(80).fill(0n);

  for (let off = 0; off < data.length; off += 128) {
    for (let t = 0; t < 16; t++) W[t] = readUint64BE(data, off + t * 8);
    for (let t = 16; t < 80; t++) {
      W[t] = add64(sigma1(W[t - 2]), W[t - 7], sigma0(W[t - 15]), W[t - 16]);
    }

    let a = H0,
      b = H1,
      c = H2,
      d = H3,
      e = H4,
      f = H5,
      g = H6,
      h = H7;

    for (let t = 0; t < 80; t++) {
      const T1 = add64(h, Sigma1(e), Ch(e, f, g), K[t], W[t]);
      const T2 = add64(Sigma0(a), Maj(a, b, c));
      h = g;
      g = f;
      f = e;
      e = add64(d, T1);
      d = c;
      c = b;
      b = a;
      a = add64(T1, T2);
    }

    H0 = add64(H0, a);
    H1 = add64(H1, b);
    H2 = add64(H2, c);
    H3 = add64(H3, d);
    H4 = add64(H4, e);
    H5 = add64(H5, f);
    H6 = add64(H6, g);
    H7 = add64(H7, h);
  }

  const out = new Uint8Array(64);
  writeUint64BE(out, 0, H0);
  writeUint64BE(out, 8, H1);
  writeUint64BE(out, 16, H2);
  writeUint64BE(out, 24, H3);
  writeUint64BE(out, 32, H4);
  writeUint64BE(out, 40, H5);
  writeUint64BE(out, 48, H6);
  writeUint64BE(out, 56, H7);
  return out;
}

export function hmac(key, message) {
  const k = toBytes(key);
  const m = toBytes(message);

  const blockSize = 128;
  let keyBlock = k;

  if (keyBlock.length > blockSize) keyBlock = sha512(keyBlock);
  if (keyBlock.length < blockSize) {
    const tmp = new Uint8Array(blockSize);
    tmp.set(keyBlock);
    keyBlock = tmp;
  }

  const oKeyPad = new Uint8Array(blockSize);
  const iKeyPad = new Uint8Array(blockSize);
  for (let i = 0; i < blockSize; i++) {
    oKeyPad[i] = keyBlock[i] ^ 0x5c;
    iKeyPad[i] = keyBlock[i] ^ 0x36;
  }

  const inner = new Uint8Array(blockSize + m.length);
  inner.set(iKeyPad, 0);
  inner.set(m, blockSize);

  const innerHash = sha512(inner);

  const outer = new Uint8Array(blockSize + innerHash.length);
  outer.set(oKeyPad, 0);
  outer.set(innerHash, blockSize);

  return sha512(outer);
}
