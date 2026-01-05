import assert from "node:assert/strict";
import crypto from "node:crypto";

async function importFirst(paths) {
  let lastErr;
  for (const p of paths) {
    try {
      return await import(p);
    } catch (e) {
      lastErr = e;
    }
  }
  throw lastErr;
}

function hex(u8) {
  return Buffer.from(u8).toString("hex");
}

function u8FromHex(h) {
  return Uint8Array.from(Buffer.from(h, "hex"));
}

function normalizeNFKD(s) {
  return s.normalize("NFKD");
}

// Resolve your modules whether they live in ./src or project root
const sha512Mod = await importFirst(["../src/sha512.js", "../sha512.js"]);
const sha256Mod = await importFirst(["../src/sha256.js", "../sha256.js"]);
const pbkdf2Mod = await importFirst(["../src/pbkdf2.js", "../pbkdf2.js"]);
const secpMod = await importFirst(["../src/secp256k1.js", "../secp256k1.js"]);
const wordsMod = await importFirst(["../src/wordlist.js", "../wordlist.js"]);

// Optional: validateMnemonic may exist depending on where you put it
let validateMnemonic = null;
try {
  const shuffleMod = await importFirst(["../src/shuffle.js", "../shuffle.js"]);
  if (typeof shuffleMod.validateMnemonic === "function") {
    validateMnemonic = shuffleMod.validateMnemonic;
  }
} catch {
  // ignore
}

const { sha512, hmac: hmacSha512 } = sha512Mod;
const { sha256 } = sha256Mod;
const { pbkdf2Hmac } = pbkdf2Mod;
const { getPublicKey, ecdh } = secpMod;
const { words } = wordsMod;

function test(name, fn) {
  try {
    fn();
    console.log(`ok - ${name}`);
  } catch (e) {
    console.error(`FAIL - ${name}`);
    console.error(e?.stack || e);
    process.exitCode = 1;
  }
}

// ---------- SHA-512 ----------
test("sha512('abc') matches known vector", () => {
  const out = sha512("abc");
  const expected = "ddaf35a193617abacc417349ae204131" + "12e6fa4e89a97ea20a9eeee64b55d39a" + "2192992a274fc1a836ba3c23a3feebbd" + "454d4423643ce80e2a9ac94fa54ca49f";
  assert.equal(hex(out), expected);
});

test("hmac-sha512 RFC 4231 test case 1", () => {
  // key = 0x0b repeated 20 times
  const key = new Uint8Array(20).fill(0x0b);
  const msg = "Hi There";
  const out = hmacSha512(key, msg);
  const expected = "87aa7cdea5ef619d4ff0b4241a1d6cb0" + "2379f4e2ce4ec2787ad0b30545e17cde" + "daa833b7d6b8a702038b274eaea3f4e4" + "be9d914eeb61f1702e696c203a126854";
  assert.equal(hex(out), expected);
});

// ---------- SHA-256 ----------

// ---------- PBKDF2-HMAC-SHA512 ----------
test("pbkdf2Hmac matches node:crypto.pbkdf2Sync (sha512)", () => {
  const password = "password";
  const salt = "salt";
  const iterations = 2048;
  const dkLen = 64;

  const ours = pbkdf2Hmac({
    hmac: (k, m) => hmacSha512(k, m),
    hashLen: 64,
    password,
    salt,
    iterations,
    dkLen,
  });

  const node = crypto.pbkdf2Sync(password, salt, iterations, dkLen, "sha512");
  assert.equal(hex(ours), node.toString("hex"));
});

// ---------- BIP39 Mnemonic checksum + seed ----------
function validateMnemonicLocal(mnemonic) {
  const list = mnemonic.trim().split(/\s+/);
  if (![12, 15, 18, 21, 24].includes(list.length)) return false;
  if (!Array.isArray(words) || words.length !== 2048) {
    throw new Error("wordlist must be 2048 words");
  }

  // word -> index -> 11-bit
  const bits = list
    .map((w) => {
      const idx = words.indexOf(w);
      if (idx === -1) throw new Error(`unknown word: ${w}`);
      return idx.toString(2).padStart(11, "0");
    })
    .join("");

  const ENT = Math.floor((bits.length * 32) / 33);
  const CS = bits.length - ENT;

  const entropyBits = bits.slice(0, ENT);
  const checksumBits = bits.slice(ENT);

  // entropy bits -> bytes
  const entropy = new Uint8Array(entropyBits.length / 8);
  for (let i = 0; i < entropy.length; i++) {
    entropy[i] = parseInt(entropyBits.slice(i * 8, i * 8 + 8), 2);
  }

  const hashBytes = Uint8Array.from(sha256.array(entropy));
  const hashBits = Array.from(hashBytes)
    .map((b) => b.toString(2).padStart(8, "0"))
    .join("");

  const expected = hashBits.slice(0, CS);
  return checksumBits === expected;
}

test("mnemonic checksum validates (local implementation)", () => {
  const mnemonic = "chief junk economy shrimp drill leg brick ice laundry author phone solar";
  assert.equal(validateMnemonicLocal(mnemonic), true);
});

test("mnemonic checksum validates (project validateMnemonic if present)", () => {
  if (!validateMnemonic) return; // skip if not implemented in project
  const mnemonic = "chief junk economy shrimp drill leg brick ice laundry author phone solar";
  assert.equal(validateMnemonic(mnemonic), true);
});

test("BIP39 seed (empty passphrase) matches node:crypto", () => {
  const mnemonic = "chief junk economy shrimp drill leg brick ice laundry author phone solar";
  const passphrase = ""; // MUST match what you enter in wallets

  const password = normalizeNFKD(mnemonic);
  const salt = normalizeNFKD("mnemonic" + passphrase);

  const ours = pbkdf2Hmac({
    hmac: (k, m) => hmacSha512(k, m),
    hashLen: 64,
    password,
    salt,
    iterations: 2048,
    dkLen: 64,
  });

  const node = crypto.pbkdf2Sync(password, salt, 2048, 64, "sha512");
  assert.equal(hex(ours), node.toString("hex"));
});

// ---------- secp256k1 ----------
test("secp256k1 getPublicKey(priv=1) compressed equals generator point", () => {
  const priv = u8FromHex("0000000000000000000000000000000000000000000000000000000000000001");
  const pub = getPublicKey(priv, true);
  const expected = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
  assert.equal(hex(pub), expected);
});

test("secp256k1 getPublicKey(priv=2) compressed known vector", () => {
  const priv = u8FromHex("0000000000000000000000000000000000000000000000000000000000000002");
  const pub = getPublicKey(priv, true);
  const expected = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
  assert.equal(hex(pub), expected);
});

test("secp256k1 ecdh symmetry: ecdh(a, Pub(b)) == ecdh(b, Pub(a))", () => {
  const a = u8FromHex("0000000000000000000000000000000000000000000000000000000000000003");
  const b = u8FromHex("0000000000000000000000000000000000000000000000000000000000000007");

  const A = getPublicKey(a, true);
  const B = getPublicKey(b, true);

  const s1 = ecdh(a, B);
  const s2 = ecdh(b, A);
  assert.equal(hex(s1), hex(s2));
});

// ---------- Done ----------
if (!process.exitCode) {
  console.log("All tests passed.");
} else {
  console.error("Some tests failed.");
}
