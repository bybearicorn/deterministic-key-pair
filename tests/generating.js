import assert from "node:assert/strict";
import { getKeyPairFromSeed } from "../src/exports.js";

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

test("verify whenever generating keypair works fine", () => {
  const mnemonic = [
    "antenna",
    "clay",
    "silly",
    "page",
    "mesh",
    "dizzy",
    "devote",
    "venture",
    "logic",
    "tornado",
    "mouse",
    "athlete",
  ];
  const out = getKeyPairFromSeed({ mnemonic, passphrase: "samko" });

  assert.equal(
    out.seed,
    "92312adf2ef0201a614866af3a47832a2a5a28c5dc7457c5b0d82af7f7af3986406906e53b51bd7df68de766f14e7f887da7bd78c7739e062e6ae104b6fd14e6",
  );

  assert.equal(
    out.privateKey,
    "55a17f65049ce884edc005e7d32d0171babc5f4036dae1fe88a85cb3d534da30",
  );

  assert.equal(
    out.publicKey,
    "02f168e51a86f5fcb608c3e21c112c456fb486a974978055b288cb7f019e3b75f1",
  );
});

test("verify whenever generating keypair works fine", () => {
  const mnemonic = [
    "antenna",
    "clay",
    "silly",
    "page",
    "mesh",
    "dizzy",
    "devote",
    "venture",
    "logic",
    "tornado",
    "mouse",
    "athlete",
  ];
  const out = generateKeyPairFromMnemonic({ mnemonic });

  assert.equal(
    out.seed,
    "0e4df974bd8e12432f95e9a0e513eb7a1515e505d1c9a007c6005290875a777d30f27c2417cfc53a0184c1370583ffeac71696fbf64aadfdd19f6e78e68db33f",
  );

  assert.equal(
    out.privateKey,
    "031c8a5aa42d22e15bcc6d77d98b72f4b75b6abcbe852576f6450517bdc1ee67",
  );

  assert.equal(
    out.publicKey,
    "03ddc239681a8db46e475b2e9a206dba38dc48eeb1c6aaf891e27fd890974fc6e7",
  );
});

if (!process.exitCode) {
  console.log("All tests passed.");
} else {
  console.error("Some tests failed.");
}
