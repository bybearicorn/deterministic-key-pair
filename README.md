State of implementation:
 - In Progress, last update Dec 2025

Estimated finished package:
 - February 2026


Run
```node
import { secureGenerateKeyGen } from "deterministic-key-pair";

const instance = secureGenerateKeyGen();

console.info("12 words", instance.mnemonic);
// divert rule embody mystery direct develop quality injury miracle only member voyage

console.info("hex seed", instance.seed);
// 4f47074d6cbe3a363c756f2d2b84a8e2063ffd4513e30a5e53f93b1a30d976d1ff06246728b525ecac93ed46790f7b4fc35046105d5c396c88c9f123c4ce8511

console.info("private key in hex", instance.privateKey);
// 38c450b392bce2e8f40eaf5f002edba0ca0f619a90e2d6bc4f440efc1b60c2ab

console.info("public key in hex", instance.publicKey);
// 02898c337e083223a9e3dea3d8209ff407b327e73693cdf08ae2ca0edee0204153
```

Options
```node
const instance = secureGenerateKeyGen({
  passphrase: "Hello World", // works as 13th word of mnemonic
  mnemonicLength: 12, // 12, 15, 18, 21, 24
  ownEnthropyString: Math.random() + "", // more entropy you pass, better randomness you get
});
```

### The goal of this package is to define a **deterministic and reproducible method for generating cryptographic key pairs** that is suitable for long-term offline storage and later recovery.

Standard key generation relies on randomness at creation time, which is cryptographically sound but operationally fragile when keys must be recreated or stored outside digital systems. Storing raw private keys in textual or visual form is highly error-prone. A single missing or altered character in a hexadecimal string renders the key unusable. Visual encodings such as QR codes offer limited error correction but are not designed for archival storage under physical degradation or partial loss.

This problem has already been addressed effectively in the Bitcoin ecosystem through **BIP39 mnemonic encoding**. BIP39 represents 128–256 bits of entropy as 12 or 24 human-readable words and includes a checksum to detect transcription errors. The wordlist is designed so that each word is uniquely identifiable by its first four letters, significantly reducing ambiguity during manual recovery. Importantly, the mnemonic does not encode a private key directly; it encodes entropy that is deterministically expanded into a cryptographic seed using a well-defined key-derivation function.

By building on the BIP39 standard, this package deliberately reuses a **widely reviewed, battle-tested, and conservative mechanism** rather than introducing a new encoding or derivation scheme. This provides immediate compatibility with a large ecosystem of existing offline storage solutions such as hardware wallets, air-gapped devices, metal backups, and established recovery procedures.

The resulting key pairs are **deterministically recreatable**, resistant to human transcription errors, and suitable for long-term offline storage without reducing cryptographic strength. When combined with high-quality entropy, fixed derivation parameters, and optional passphrases, the security level is bounded by 128–256 bits of entropy, which is sufficient even for high-assurance environments such as defense or critical infrastructure.

Criteria:
- Zero dependencies
- Well tested
- Compatibile with crypto cold storage wallets
- Post-quantum ready
- Prefers 512 bits of entropy
