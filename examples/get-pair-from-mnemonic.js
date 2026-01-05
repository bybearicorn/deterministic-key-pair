import { generateKeyPairFromMnemonic } from "../src/exports.js";

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

const instance = generateKeyPairFromMnemonic({ mnemonic });

console.log(instance);

// {
//   mnemonic: [
//     'antenna', 'clay',
//     'silly',   'page',
//     'mesh',    'dizzy',
//     'devote',  'venture',
//     'logic',   'tornado',
//     'mouse',   'athlete'
//   ],
//   seed: '92312adf2ef0201a614866af3a47832a2a5a28c5dc7457c5b0d82af7f7af3986406906e53b51bd7df68de766f14e7f887da7bd78c7739e062e6ae104b6fd14e6',
//   privateKey: '55a17f65049ce884edc005e7d32d0171babc5f4036dae1fe88a85cb3d534da30',
//   publicKey: '02f168e51a86f5fcb608c3e21c112c456fb486a974978055b288cb7f019e3b75f1'
// }
