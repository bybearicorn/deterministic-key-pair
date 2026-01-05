import assert from "node:assert/strict";
import { generateKeyPairFromMnemonic } from "../src/exports.js";
import { test, validate } from "./_util.js";

test("generating key pair from mnemonic of 12 without passphrase", () => {
  const mnemonic = ["live", "devote", "dice", "blast", "slot", "venture", "space", "people", "enroll", "network", "tool", "exercise"];
  const out = generateKeyPairFromMnemonic({ mnemonic });
  assert.equal(out.seed, "aa9095f3e881b6018599f6af43c461084e6909c41346f83c7bb8ab55d3f5f3a01c344e5d1bb4381c51f6d5ba221316662b7df101ea3ca44ca2d6ff4ba4b7a952");
  assert.equal(out.privateKey, "22d2860f6c4ff4b020c31d55f42bb80c9a8e7a137737d708caf24c4284ab835a");
  assert.equal(out.publicKey, "0303c925dc73220d9d8770a3fa0d7bad3fda848f702ccb7ff9b1005ff4d32896cb");
});

test("generating key pair from mnemonic of 12 with passphrase", () => {
  const passphrase = "helloworld";
  const mnemonic = ["live", "devote", "dice", "blast", "slot", "venture", "space", "people", "enroll", "network", "tool", "exercise"];
  const out = generateKeyPairFromMnemonic({ mnemonic, passphrase });
  assert.equal(out.seed, "5396def4dd1839bc32c5c2a3b2ce523eb9df4da021c3629e6ef8787618c1cfa6b9061f9febdc6bfabe69555badad1eb98de0c7f5459050e62b80a781ca9b66cc");
  assert.equal(out.privateKey, "7cd892a64d47374c99070228beca23bc8002b8b09ea395187c73ab34172a2f85");
  assert.equal(out.publicKey, "02752c860017426bb3e3c11084cc3eefd5fc42e22a4ba1460ea2d0a71424dd3439");
});

test("generating key pair from mnemonic of 15 without passphrase", () => {
  const mnemonic = ["false", "face", "cherry", "illegal", "brush", "when", "balcony", "price", "bracket", "quality", "praise", "lucky", "rough", "emerge", "danger"];
  const out = generateKeyPairFromMnemonic({ mnemonic });
  assert.equal(out.seed, "38e5750c34d6d579da0546d66383e290d4a1a4ec57005dd505b8d8296e49dfc74016255e897be63f52a996d23188d39e81092425c592aee1234fdddad197526e");
  assert.equal(out.privateKey, "7955a60b8fb5716438c500bf8d75266062d3ca8a4c8f900e1dcdcc5798851ad9");
  assert.equal(out.publicKey, "029577f327383a26b5b63d5f95d795e80c501fd471475c77792e4f20f2e1f7dbf3");
});

test("generating key pair from mnemonic of 15 with passphrase", () => {
  const passphrase = "helloworld";
  const mnemonic = ["false", "face", "cherry", "illegal", "brush", "when", "balcony", "price", "bracket", "quality", "praise", "lucky", "rough", "emerge", "danger"];
  const out = generateKeyPairFromMnemonic({ mnemonic, passphrase });
  assert.equal(out.seed, "212899a817e4669c1b4d1015d29ae3b9520c6a41f710e065c9b3bb275f282e742a1e7e01e19bc87786af778509dca8b23c5aa30cd589ce9f6c54c0ad282b46d2");
  assert.equal(out.privateKey, "19d8e5db23fe574dfb4ccdb74425f9d1e88921a0491a36b1fd3a467bea09d3bb");
  assert.equal(out.publicKey, "0254edd04aec3d97a9366192cb695ffa90a5bd226738e7c1fb8c5287aec8354286");
});

test("generating key pair from mnemonic of 18 without passphrase", () => {
  const mnemonic = ["test", "suit", "rice", "cinnamon", "possible", "deposit", "harsh", "wage", "cannon", "noble", "equip", "exotic", "mother", "august", "flower", "until", "vacant", "sell"];
  const out = generateKeyPairFromMnemonic({ mnemonic });
  assert.equal(out.seed, "f35941fa80d362d45f2b3ec768677658c10b2d74368a046be14dc6719cd5d24d88c96b004fd856212900f5741e014b3b0037b8df1bb3eb4b5d9f078473499705");
  assert.equal(out.privateKey, "404271f28abcd082b01480778e47ae74094e8448fed10cbeae38b22b2e334ee3");
  assert.equal(out.publicKey, "021ae759f6b481ee8272da110a9321202789d8921135e66b3a81c1892c0331488c");
});

test("generating key pair from mnemonic of 18 with passphrase", () => {
  const passphrase = "helloworld";
  const mnemonic = ["test", "suit", "rice", "cinnamon", "possible", "deposit", "harsh", "wage", "cannon", "noble", "equip", "exotic", "mother", "august", "flower", "until", "vacant", "sell"];
  const out = generateKeyPairFromMnemonic({ mnemonic, passphrase });
  assert.equal(out.seed, "0b873cea1270d0bb57efb94f5126eca485e9b0eb1ebcbb1cca89aa9a7dadd3d80c262d248e47c649d859f6faa442a2a567acf980c624e711e6deaf3fcd7cb40a");
  assert.equal(out.privateKey, "8cebb31bda2db69921814b3ae9a5a9cd545021b25b291c2444fb423a3f682f21");
  assert.equal(out.publicKey, "03a38fcf26b071fb4c0d28338a2e2ba396beb92594fff30925ca41b97d1eaab31f");
});

test("generating key pair from mnemonic of 21 without passphrase", () => {
  const mnemonic = ["course", "impulse", "enlist", "razor", "pause", "seminar", "hospital", "shell", "garbage", "state", "acquire", "thank", "place", "usual", "fury", "beef", "faith", "secret", "diary", "cinnamon", "guilt"];
  const out = generateKeyPairFromMnemonic({ mnemonic });
  assert.equal(out.seed, "779ca1d59a95ce021c2bd4e3b37e1003852ab1c50c8975ee6350719b54cc353a5f21aff776ea2257c708e4320e0d29c2369febb24be43ca76a0c8f757aa0649a");
  assert.equal(out.privateKey, "f05806116112fbbb690cebcd7fe33064a4062379f20de5a14f22b6e6131eae44");
  assert.equal(out.publicKey, "03d871e34ed1eda6e553f093d379b88f5d8c507bc55b39b384c904995cf9f889e4");
});

test("generating key pair from mnemonic of 21 with passphrase", () => {
  const passphrase = "helloworld";
  const mnemonic = ["course", "impulse", "enlist", "razor", "pause", "seminar", "hospital", "shell", "garbage", "state", "acquire", "thank", "place", "usual", "fury", "beef", "faith", "secret", "diary", "cinnamon", "guilt"];
  const out = generateKeyPairFromMnemonic({ mnemonic, passphrase });
  assert.equal(out.seed, "6c4aa2b4a1218709d6c79d3be223b77ed1fa7e7375505e3022164d0e689ef2920a376963c3d14c64407cd575bc1dfb58e96af26cff6295cb254343fd771a856d");
  assert.equal(out.privateKey, "21dc4e1de9f4a945f291c2886ece45a165b5eb17fb74407819a1201de374c90e");
  assert.equal(out.publicKey, "02d349d32bcf839e84f9c2d84fade098903be6ad73d581a96ef6c8747731135fec");
});

test("generating key pair from mnemonic of 24 without passphrase", () => {
  const mnemonic = ["disorder", "wear", "puzzle", "cash", "satoshi", "address", "usage", "question", "enemy", "fabric", "casual", "fade", "where", "sadness", "muffin", "fat", "answer", "chaos", "bachelor", "frequent", "spirit", "review", "portion", "cage"];
  const out = generateKeyPairFromMnemonic({ mnemonic });
  assert.equal(out.seed, "ed24d8db81f57e683acc5f37a823a5dad3ea2f18ebe533508e683428c6d3b1fee66cc28721d89ff7d770697707c68bb52da51da159344f0d6f74e8551b4b8df4");
  assert.equal(out.privateKey, "73341f33a51c5b74993f612d5fc28f5fc9a4857e9c2108bb0fc232efe91dbd66");
  assert.equal(out.publicKey, "03a2f47e2251a1523c906d85b0a87ce50718e2ab742109f3d8776654c9a34384f5");
});

test("generating key pair from mnemonic of 24 with passphrase", () => {
  const passphrase = "helloworld";
  const mnemonic = ["disorder", "wear", "puzzle", "cash", "satoshi", "address", "usage", "question", "enemy", "fabric", "casual", "fade", "where", "sadness", "muffin", "fat", "answer", "chaos", "bachelor", "frequent", "spirit", "review", "portion", "cage"];
  const out = generateKeyPairFromMnemonic({ mnemonic, passphrase });
  assert.equal(out.seed, "a521e184c5e0a16fcafbf71cee00bbfdc3f5eb3b257e3b7e93eb3451580298159efde7a6eb1978562e06dee30163205e064d75d7626d39ff94f0b92ed642ca66");
  assert.equal(out.privateKey, "1572108e44944ca8a545cca9c2cf3a52baddb63973afdf326b96689125d5098f");
  assert.equal(out.publicKey, "03f4096e187984b70e5ca5bf9daea7dd831d3520e68e043b17c0426aa4361f0bfd");
});

validate();
