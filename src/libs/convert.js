export function convertUint8ToHex(uint8) {
  return [...uint8].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function convertHexToUint8(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function isUint8(instance) {
  return instance instanceof Uint8Array;
}
