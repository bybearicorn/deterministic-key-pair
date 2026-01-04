export function randomEntropyBytes(byteLength) {
  if (!Number.isInteger(byteLength) || byteLength < 0) {
    throw new TypeError("byteLength must be a non-negative integer");
  }

  // browser or any environment that provides webcrypto
  const context = globalThis.crypto;
  if (context?.getRandomValues) {
    const out = new Uint8Array(byteLength);
    context.getRandomValues(out);
    return out;
  }

  // Node
  try {
    // Creates a function at runtime.
    const req = Function(
      "return typeof require==='function' ? require : null",
    )();

    const nodeCrypto = req && (req("node:crypto") || req("crypto"));

    if (nodeCrypto?.randomBytes) {
      const buf = nodeCrypto.randomBytes(byteLength);
      return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
    }

    if (nodeCrypto?.webcrypto?.getRandomValues) {
      const out = new Uint8Array(byteLength);
      nodeCrypto.webcrypto.getRandomValues(out);
      return out;
    }
  } catch {}

  // expo or react native witohut a pollyfill lands here
  throw new Error(
    "Secure random generator is not available, In Expo/React Native native you need a polyfill/native module (e.g. expo-crypto or react-native-get-random-values), or ensure your runtime provides crypto.getRandomValues.",
  );
}
