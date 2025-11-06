import forge from "node-forge";
import { words } from "./wordlist.js";

function getRandomBytes(n = 32) {
  return forge.random.getBytesSync(n);
}

function bytesToUint32(bytes, offset = 0) {
  const b0 = bytes.charCodeAt(offset);
  const b1 = bytes.charCodeAt(offset + 1);
  const b2 = bytes.charCodeAt(offset + 2);
  const b3 = bytes.charCodeAt(offset + 3);
  let value = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
  return value >>> 0;
}

function secureRandomInt(max, bytePool = { pool: "", offset: 0 }) {
  if (max < 0) throw new Error("max must be >= 0");
  const range = max + 1;
  if (range === 1) return 0;

  const UINT32_MAX = 0x100000000;
  const threshold = Math.floor(UINT32_MAX / range) * range;

  while (true) {
    if (bytePool.pool.length - bytePool.offset < 4) {
      bytePool.pool = bytePool.pool.slice(bytePool.offset) + getRandomBytes(32);
      bytePool.offset = 0;
    }

    const r = bytesToUint32(bytePool.pool, bytePool.offset);
    bytePool.offset += 4;

    if (r < threshold) {
      return r % range;
    }
  }
}

export function getRandomMnemonic(take = 12) {
  const arr = [...words];
  const bytePool = { pool: "", offset: 0 };

  for (let i = arr.length - 1; i > 0; i--) {
    const j = secureRandomInt(i, bytePool);
    const tmp = arr[i];
    arr[i] = arr[j];
    arr[j] = tmp;
  }

  return typeof take === "number" ? arr.slice(0, take) : arr;
}
