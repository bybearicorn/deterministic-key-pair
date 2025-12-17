import forge from "node-forge";

const generateDeterministicRSAKeyPair = (seed) => {
  const prng = forge.random.createInstance();
  prng.seedFileSync = () => seed.toString("binary");

  const keypair = forge.pki.rsa.generateKeyPair({ bits: 2048, prng });

  const pkcs1Asn1 = forge.pki.privateKeyToAsn1(keypair.privateKey); //need to conver pkcs1 to pkcs8
  const pkcs8Asn1 = forge.pki.wrapRsaPrivateKey(pkcs1Asn1);
  const derBytes = forge.asn1.toDer(pkcs8Asn1).getBytes();
  const base64 = forge.util.encode64(derBytes);
  const privateKeyPem = `-----BEGIN PRIVATE KEY-----\n${base64.match(/.{1,64}/g).join("\n")}\n-----END PRIVATE KEY-----`;

  return {
    privateKeyPem,
    publicKeyPem: forge.pki.publicKeyToPem(keypair.publicKey),
  };
};

const sha512 = (string) => {
  var md = forge.md.sha512.create();
  md.update(string);
  return md.digest().toHex();
};

export const keysFromMnemonic = (mnemonic) => {
  const hash = sha512(mnemonic);
  const { privateKeyPem, publicKeyPem } = generateDeterministicRSAKeyPair(hash);

  return {
    privateKey: privateKeyPem,
    publicKey: publicKeyPem,
    privateKeyChecksum: sha512(privateKeyPem),
  };
};
