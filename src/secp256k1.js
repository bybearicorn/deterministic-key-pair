const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const Gx =
  55066263022277343669578718895168534326250603453777594175500187360389116729240n;
const Gy =
  32670510020758816978083085130507043184471273380659243275938904335757337482424n;

const mod = (a, m = P) => {
  const r = a % m;
  return r >= 0n ? r : r + m;
};

const powMod = (a, e, m = P) => {
  let r = 1n,
    x = mod(a, m),
    k = e;
  while (k > 0n) {
    if (k & 1n) r = mod(r * x, m);
    x = mod(x * x, m);
    k >>= 1n;
  }
  return r;
};

const invMod = (a) => {
  if (a === 0n) throw new Error("inv(0)");
  return powMod(a, P - 2n, P);
};

const isInf = (pt) => pt.Z === 0n;

const toJacobian = (x, y) => ({ X: x, Y: y, Z: 1n });
const INF = { X: 0n, Y: 1n, Z: 0n };

const jacobianDouble = (p) => {
  if (isInf(p) || p.Y === 0n) return INF;

  const { X, Y, Z } = p;
  const YY = mod(Y * Y);
  const YYYY = mod(YY * YY);
  const XX = mod(X * X);
  const S = mod(4n * X * YY);
  const M = mod(3n * XX); // a=0 for secp256k1
  const X3 = mod(M * M - 2n * S);
  const Y3 = mod(M * (S - X3) - 8n * YYYY);
  const Z3 = mod(2n * Y * Z);
  return { X: X3, Y: Y3, Z: Z3 };
};

const jacobianAdd = (p, q) => {
  if (isInf(p)) return q;
  if (isInf(q)) return p;

  const Z1Z1 = mod(p.Z * p.Z);
  const Z2Z2 = mod(q.Z * q.Z);
  const U1 = mod(p.X * Z2Z2);
  const U2 = mod(q.X * Z1Z1);
  const S1 = mod(p.Y * q.Z * Z2Z2);
  const S2 = mod(q.Y * p.Z * Z1Z1);

  if (U1 === U2) {
    if (S1 !== S2) return INF;
    return jacobianDouble(p);
  }

  const H = mod(U2 - U1);
  const HH = mod(H * H);
  const HHH = mod(H * HH);
  const R = mod(S2 - S1);
  const V = mod(U1 * HH);

  const X3 = mod(R * R - HHH - 2n * V);
  const Y3 = mod(R * (V - X3) - S1 * HHH);
  const Z3 = mod(H * p.Z * q.Z);
  return { X: X3, Y: Y3, Z: Z3 };
};

const jacobianToAffine = (p) => {
  if (isInf(p)) return null;
  const zInv = invMod(p.Z);
  const zInv2 = mod(zInv * zInv);
  const zInv3 = mod(zInv2 * zInv);
  const x = mod(p.X * zInv2);
  const y = mod(p.Y * zInv3);
  return { x, y };
};

const bytesToBigInt = (b) => {
  let x = 0n;
  for (let i = 0; i < b.length; i++) x = (x << 8n) | BigInt(b[i]);
  return x;
};

const bigIntToBytes = (x, len) => {
  const out = new Uint8Array(len);
  let v = x;
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
};

const bytesToBigIntBE = bytesToBigInt; // už máš

const isOnCurve = (x, y) => mod(y * y) === mod(x * x * x + 7n);

const sqrtMod = (a) => {
  // p % 4 == 3 => sqrt = a^((p+1)/4) mod p
  return powMod(a, (P + 1n) / 4n, P);
};

const parsePublicKey = (pub) => {
  if (!(pub instanceof Uint8Array))
    throw new Error("pubkey must be Uint8Array");
  if (pub.length === 33 && (pub[0] === 0x02 || pub[0] === 0x03)) {
    const x = bytesToBigIntBE(pub.slice(1));
    if (x <= 0n || x >= P) throw new Error("invalid x");

    const y2 = mod(x * x * x + 7n);
    let y = sqrtMod(y2);

    const isOdd = (y & 1n) === 1n;
    const wantOdd = pub[0] === 0x03;
    if (isOdd !== wantOdd) y = mod(P - y);

    if (!isOnCurve(x, y)) throw new Error("pubkey not on curve");
    return toJacobian(x, y);
  }

  if (pub.length === 65 && pub[0] === 0x04) {
    const x = bytesToBigIntBE(pub.slice(1, 33));
    const y = bytesToBigIntBE(pub.slice(33, 65));
    if (!isOnCurve(x, y)) throw new Error("pubkey not on curve");
    return toJacobian(x, y);
  }

  throw new Error("unsupported pubkey format");
};

const scalarMult = (k, point) => {
  let n = k;
  let Q = INF;
  let Pp = point;
  while (n > 0n) {
    if (n & 1n) Q = jacobianAdd(Q, Pp);
    Pp = jacobianDouble(Pp);
    n >>= 1n;
  }
  return Q;
};

export function getPublicKey(privateKey32, compressed = true) {
  if (!(privateKey32 instanceof Uint8Array) || privateKey32.length !== 32) {
    throw new Error("privateKey must be Uint8Array(32)");
  }
  const k = bytesToBigInt(privateKey32);
  if (k <= 0n || k >= N) throw new Error("Invalid secp256k1 private key");

  const G = toJacobian(Gx, Gy);
  const Rj = scalarMult(k, G);
  const Ra = jacobianToAffine(Rj);
  if (!Ra) throw new Error("Point at infinity");

  const xBytes = bigIntToBytes(Ra.x, 32);
  if (!compressed) {
    const yBytes = bigIntToBytes(Ra.y, 32);
    const out = new Uint8Array(65);
    out[0] = 0x04;
    out.set(xBytes, 1);
    out.set(yBytes, 33);
    return out;
  } else {
    const out = new Uint8Array(33);
    out[0] = (Ra.y & 1n) === 0n ? 0x02 : 0x03;
    out.set(xBytes, 1);
    return out;
  }
}

export const CURVE_N = N;

export function ecdh(privateKey32, publicKeyBytes) {
  if (!(privateKey32 instanceof Uint8Array) || privateKey32.length !== 32) {
    throw new Error("privateKey must be Uint8Array(32)");
  }
  const k = bytesToBigInt(privateKey32);
  if (k <= 0n || k >= N) throw new Error("Invalid secp256k1 private key");

  const Pj = parsePublicKey(publicKeyBytes);
  const Rj = scalarMult(k, Pj);
  const Ra = jacobianToAffine(Rj);
  if (!Ra) throw new Error("ecdh: point at infinity");

  // shared secret material = X coordinate (32 bytes)
  return bigIntToBytes(Ra.x, 32);
}
