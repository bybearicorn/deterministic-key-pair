const K = [
  0x428a2f98, 0xd728ae22, 0x71374491, 0x23ef65cd, 0xb5c0fbcf, 0xec4d3b2f,
  0xe9b5dba5, 0x8189dbbc, 0x3956c25b, 0xf348b538, 0x59f111f1, 0xb605d019,
  0x923f82a4, 0xaf194f9b, 0xab1c5ed5, 0xda6d8118, 0xd807aa98, 0xa3030242,
  0x12835b01, 0x45706fbe, 0x243185be, 0x4ee4b28c, 0x550c7dc3, 0xd5ffb4e2,
  0x72be5d74, 0xf27b896f, 0x80deb1fe, 0x3b1696b1, 0x9bdc06a7, 0x25c71235,
  0xc19bf174, 0xcf692694, 0xe49b69c1, 0x9ef14ad2, 0xefbe4786, 0x384f25e3,
  0x0fc19dc6, 0x8b8cd5b5, 0x240ca1cc, 0x77ac9c65, 0x2de92c6f, 0x592b0275,
  0x4a7484aa, 0x6ea6e483, 0x5cb0a9dc, 0xbd41fbd4, 0x76f988da, 0x831153b5,
  0x983e5152, 0xee66dfab, 0xa831c66d, 0x2db43210, 0xb00327c8, 0x98fb213f,
  0xbf597fc7, 0xbeef0ee4, 0xc6e00bf3, 0x3da88fc2, 0xd5a79147, 0x930aa725,
  0x06ca6351, 0xe003826f, 0x14292967, 0x0a0e6e70, 0x27b70a85, 0x46d22ffc,
  0x2e1b2138, 0x5c26c926, 0x4d2c6dfc, 0x5ac42aed, 0x53380d13, 0x9d95b3df,
  0x650a7354, 0x8baf63de, 0x766a0abb, 0x3c77b2a8, 0x81c2c92e, 0x47edaee6,
  0x92722c85, 0x1482353b, 0xa2bfe8a1, 0x4cf10364, 0xa81a664b, 0xbc423001,
  0xc24b8b70, 0xd0f89791, 0xc76c51a3, 0x0654be30, 0xd192e819, 0xd6ef5218,
  0xd6990624, 0x5565a910, 0xf40e3585, 0x5771202a, 0x106aa070, 0x32bbd1b8,
  0x19a4c116, 0xb8d2d0c8, 0x1e376c08, 0x5141ab53, 0x2748774c, 0xdf8eeb99,
  0x34b0bcb5, 0xe19b48a8, 0x391c0cb3, 0xc5c95a63, 0x4ed8aa4a, 0xe3418acb,
  0x5b9cca4f, 0x7763e373, 0x682e6ff3, 0xd6b2b8a3, 0x748f82ee, 0x5defb2fc,
  0x78a5636f, 0x43172f60, 0x84c87814, 0xa1f0ab72, 0x8cc70208, 0x1a6439ec,
  0x90befffa, 0x23631e28, 0xa4506ceb, 0xde82bde9, 0xbef9a3f7, 0xb2c67915,
  0xc67178f2, 0xe372532b,
];

const HINIT = [
  0x6a09e667, 0xf3bcc908, 0xbb67ae85, 0x84caa73b, 0x3c6ef372, 0xfe94f82b,
  0xa54ff53a, 0x5f1d36f1, 0x510e527f, 0xade682d1, 0x9b05688c, 0x2b3e6c1f,
  0x1f83d9ab, 0xfb41bd6b, 0x5be0cd19, 0x137e2179,
];

function utf8ToBytes(str) {
  return new TextEncoder().encode(str);
}
function toBytes(x) {
  if (x instanceof Uint8Array) return x;
  if (typeof x === "string") return utf8ToBytes(x);
  throw new Error("Expected string or Uint8Array");
}
function concat(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

// 64-bit helpers using (hi, lo) 32-bit unsigned
function add64(ah, al, bh, bl) {
  const lo = (al + bl) >>> 0;
  const carry = lo < al ? 1 : 0;
  const hi = (ah + bh + carry) >>> 0;
  return [hi, lo];
}
function add64_4(aH, aL, bH, bL, cH, cL, dH, dL) {
  let hi = aH,
    lo = aL;
  [hi, lo] = add64(hi, lo, bH, bL);
  [hi, lo] = add64(hi, lo, cH, cL);
  [hi, lo] = add64(hi, lo, dH, dL);
  return [hi, lo];
}
function add64_5(aH, aL, bH, bL, cH, cL, dH, dL, eH, eL) {
  let hi = aH,
    lo = aL;
  [hi, lo] = add64(hi, lo, bH, bL);
  [hi, lo] = add64(hi, lo, cH, cL);
  [hi, lo] = add64(hi, lo, dH, dL);
  [hi, lo] = add64(hi, lo, eH, eL);
  return [hi, lo];
}
function rotr64(h, l, n) {
  n &= 63;
  if (n === 0) return [h, l];
  if (n < 32) {
    return [
      ((h >>> n) | (l << (32 - n))) >>> 0,
      ((l >>> n) | (h << (32 - n))) >>> 0,
    ];
  }
  if (n === 32) return [l, h];
  n -= 32;
  return [
    ((l >>> n) | (h << (32 - n))) >>> 0,
    ((h >>> n) | (l << (32 - n))) >>> 0,
  ];
}
function shr64(h, l, n) {
  if (n === 0) return [h, l];
  if (n < 32) return [h >>> n, ((l >>> n) | (h << (32 - n))) >>> 0];
  if (n === 32) return [0, h];
  return [0, h >>> (n - 32)];
}

function Ch(eH, eL, fH, fL, gH, gL) {
  return [((eH & fH) ^ (~eH & gH)) >>> 0, ((eL & fL) ^ (~eL & gL)) >>> 0];
}
function Maj(aH, aL, bH, bL, cH, cL) {
  return [
    ((aH & bH) ^ (aH & cH) ^ (bH & cH)) >>> 0,
    ((aL & bL) ^ (aL & cL) ^ (bL & cL)) >>> 0,
  ];
}
function Sigma0(aH, aL) {
  const [r28H, r28L] = rotr64(aH, aL, 28);
  const [r34H, r34L] = rotr64(aH, aL, 34);
  const [r39H, r39L] = rotr64(aH, aL, 39);
  return [(r28H ^ r34H ^ r39H) >>> 0, (r28L ^ r34L ^ r39L) >>> 0];
}
function Sigma1(eH, eL) {
  const [r14H, r14L] = rotr64(eH, eL, 14);
  const [r18H, r18L] = rotr64(eH, eL, 18);
  const [r41H, r41L] = rotr64(eH, eL, 41);
  return [(r14H ^ r18H ^ r41H) >>> 0, (r14L ^ r18L ^ r41L) >>> 0];
}
function sigma0(wH, wL) {
  const [r1H, r1L] = rotr64(wH, wL, 1);
  const [r8H, r8L] = rotr64(wH, wL, 8);
  const [s7H, s7L] = shr64(wH, wL, 7);
  return [(r1H ^ r8H ^ s7H) >>> 0, (r1L ^ r8L ^ s7L) >>> 0];
}
function sigma1(wH, wL) {
  const [r19H, r19L] = rotr64(wH, wL, 19);
  const [r61H, r61L] = rotr64(wH, wL, 61);
  const [s6H, s6L] = shr64(wH, wL, 6);
  return [(r19H ^ r61H ^ s6H) >>> 0, (r19L ^ r61L ^ s6L) >>> 0];
}

export function sha512(msg) {
  const m = toBytes(msg);

  // padding
  const bitLen = m.length * 8;
  const padded = new Uint8Array(((m.length + 17 + 127) >> 7) << 7);
  padded.set(m);
  padded[m.length] = 0x80;

  const dv = new DataView(padded.buffer);
  // high 64 bits of length = 0 for typical inputs
  dv.setUint32(padded.length - 16, 0, false);
  dv.setUint32(padded.length - 12, 0, false);
  dv.setUint32(padded.length - 8, Math.floor(bitLen / 0x100000000), false);
  dv.setUint32(padded.length - 4, bitLen >>> 0, false);

  // state
  const H = HINIT.slice();

  const W = new Uint32Array(160); // 80 * 2 (hi,lo)

  for (let i = 0; i < padded.length; i += 128) {
    // init W[0..15]
    for (let t = 0; t < 16; t++) {
      const off = i + t * 8;
      W[t * 2] = dv.getUint32(off, false);
      W[t * 2 + 1] = dv.getUint32(off + 4, false);
    }
    // extend W[16..79]
    for (let t = 16; t < 80; t++) {
      const w15H = W[(t - 15) * 2],
        w15L = W[(t - 15) * 2 + 1];
      const w2H = W[(t - 2) * 2],
        w2L = W[(t - 2) * 2 + 1];
      const w16H = W[(t - 16) * 2],
        w16L = W[(t - 16) * 2 + 1];
      const w7H = W[(t - 7) * 2],
        w7L = W[(t - 7) * 2 + 1];

      const [s0H, s0L] = sigma0(w15H, w15L);
      const [s1H, s1L] = sigma1(w2H, w2L);

      let [tmpH, tmpL] = add64_4(w16H, w16L, s0H, s0L, w7H, w7L, s1H, s1L);
      W[t * 2] = tmpH;
      W[t * 2 + 1] = tmpL;
    }

    // working vars a..h (each hi,lo)
    let aH = H[0],
      aL = H[1];
    let bH = H[2],
      bL = H[3];
    let cH = H[4],
      cL = H[5];
    let dH = H[6],
      dL = H[7];
    let eH = H[8],
      eL = H[9];
    let fH = H[10],
      fL = H[11];
    let gH = H[12],
      gL = H[13];
    let hH = H[14],
      hL = H[15];

    for (let t = 0; t < 80; t++) {
      const [S1H, S1L] = Sigma1(eH, eL);
      const [chH, chL] = Ch(eH, eL, fH, fL, gH, gL);

      const kH = K[t * 2],
        kL = K[t * 2 + 1];
      const wH = W[t * 2],
        wL = W[t * 2 + 1];

      const [t1H, t1L] = add64_5(hH, hL, S1H, S1L, chH, chL, kH, kL, wH, wL);

      const [S0H, S0L] = Sigma0(aH, aL);
      const [majH, majL] = Maj(aH, aL, bH, bL, cH, cL);
      const [t2H, t2L] = add64(S0H, S0L, majH, majL);

      hH = gH;
      hL = gL;
      gH = fH;
      gL = fL;
      fH = eH;
      fL = eL;

      [eH, eL] = add64(dH, dL, t1H, t1L);

      dH = cH;
      dL = cL;
      cH = bH;
      cL = bL;
      bH = aH;
      bL = aL;

      [aH, aL] = add64(t1H, t1L, t2H, t2L);
    }

    // add to state
    [H[0], H[1]] = add64(H[0], H[1], aH, aL);
    [H[2], H[3]] = add64(H[2], H[3], bH, bL);
    [H[4], H[5]] = add64(H[4], H[5], cH, cL);
    [H[6], H[7]] = add64(H[6], H[7], dH, dL);
    [H[8], H[9]] = add64(H[8], H[9], eH, eL);
    [H[10], H[11]] = add64(H[10], H[11], fH, fL);
    [H[12], H[13]] = add64(H[12], H[13], gH, gL);
    [H[14], H[15]] = add64(H[14], H[15], hH, hL);
  }

  // output
  const out = new Uint8Array(64);
  const ov = new DataView(out.buffer);
  for (let i = 0; i < 16; i++) ov.setUint32(i * 4, H[i], false);
  return out;
}

export function hmac(key, message) {
  const blockSize = 128;
  let keyBytes = toBytes(key);
  const msgBytes = toBytes(message);

  if (keyBytes.length > blockSize) keyBytes = sha512(keyBytes);

  const oKeyPad = new Uint8Array(blockSize);
  const iKeyPad = new Uint8Array(blockSize);

  for (let i = 0; i < blockSize; i++) {
    const b = keyBytes[i] || 0;
    iKeyPad[i] = b ^ 0x36;
    oKeyPad[i] = b ^ 0x5c;
  }

  const inner = sha512(concat(iKeyPad, msgBytes));
  return sha512(concat(oKeyPad, inner));
}

hmac.array = (k, m) => Array.from(hmac(k, m));
hmac.hex = (k, m) =>
  Array.from(hmac(k, m))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

export default sha512;
