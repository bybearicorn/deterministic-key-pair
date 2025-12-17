export function pbkdf2Hmac({
  hmac,
  hashLen,
  password,
  salt,
  iterations,
  dkLen,
}) {
  if (typeof hmac !== "function") throw new Error("hmac must be a function");
  if (!Number.isInteger(hashLen) || hashLen <= 0)
    throw new Error("hashLen must be > 0");
  if (!Number.isInteger(iterations) || iterations <= 0)
    throw new Error("iterations must be > 0");
  if (!Number.isInteger(dkLen) || dkLen <= 0)
    throw new Error("dkLen must be > 0");

  const P = toBytes(password);
  const S = toBytes(salt);

  const l = Math.ceil(dkLen / hashLen);
  const r = dkLen - (l - 1) * hashLen;

  const DK = new Uint8Array(dkLen);
  let dkPos = 0;

  for (let i = 1; i <= l; i++) {
    const INTi = int32be(i);

    let U = hmac(P, concatBytes(S, INTi)); // U1
    let T = U.slice();

    for (let j = 2; j <= iterations; j++) {
      U = hmac(P, U);
      xorInto(T, U);
    }

    const take = i === l ? r : hashLen;
    DK.set(T.subarray(0, take), dkPos);
    dkPos += take;
  }

  return DK;
}

// -------- internal utils --------

function int32be(i) {
  return new Uint8Array([
    (i >>> 24) & 0xff,
    (i >>> 16) & 0xff,
    (i >>> 8) & 0xff,
    i & 0xff,
  ]);
}

function xorInto(dst, src) {
  for (let i = 0; i < dst.length; i++) dst[i] ^= src[i];
}

function concatBytes(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function toBytes(input) {
  if (input instanceof Uint8Array) return input;
  if (typeof input === "string") return utf8ToBytes(input);
  throw new Error("password/salt must be string or Uint8Array");
}

function utf8ToBytes(str) {
  const out = [];
  for (let i = 0; i < str.length; i++) {
    let c = str.charCodeAt(i);

    if (c >= 0xd800 && c <= 0xdbff && i + 1 < str.length) {
      const d = str.charCodeAt(i + 1);
      if (d >= 0xdc00 && d <= 0xdfff) {
        c = ((c - 0xd800) << 10) + (d - 0xdc00) + 0x10000;
        i++;
      }
    }

    if (c <= 0x7f) out.push(c);
    else if (c <= 0x7ff) {
      out.push(0xc0 | (c >>> 6), 0x80 | (c & 0x3f));
    } else if (c <= 0xffff) {
      out.push(0xe0 | (c >>> 12), 0x80 | ((c >>> 6) & 0x3f), 0x80 | (c & 0x3f));
    } else {
      out.push(
        0xf0 | (c >>> 18),
        0x80 | ((c >>> 12) & 0x3f),
        0x80 | ((c >>> 6) & 0x3f),
        0x80 | (c & 0x3f),
      );
    }
  }
  return new Uint8Array(out);
}
