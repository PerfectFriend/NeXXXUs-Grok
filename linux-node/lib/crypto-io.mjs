import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { randomBytes, bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";

export const CHUNK_BYTES = 16 * 1024;
export const NONCE_BYTES = 24;

export function encrypt(key, plain) {
  const nonce = randomBytes(NONCE_BYTES);
  const ct = xchacha20poly1305(key, nonce).encrypt(plain);
  const out = new Uint8Array(nonce.length + ct.length);
  out.set(nonce, 0);
  out.set(ct, nonce.length);
  return out;
}

export function decrypt(key, packed) {
  if (packed.length < NONCE_BYTES + 16) throw new Error("short ciphertext");
  const nonce = packed.subarray(0, NONCE_BYTES);
  const ct = packed.subarray(NONCE_BYTES);
  return xchacha20poly1305(key, nonce).decrypt(ct);
}

export function hashBytes(data) {
  return bytesToHex(sha256(data));
}

export function encodeFrame(key, obj) {
  const plain = new TextEncoder().encode(JSON.stringify(obj));
  return encrypt(key, plain);
}

export function decodeFrame(key, packed) {
  const plain = decrypt(key, packed);
  return JSON.parse(new TextDecoder().decode(plain));
}

export function toB64(bytes) {
  return Buffer.from(bytes).toString("base64");
}

export function fromB64(b64) {
  return new Uint8Array(Buffer.from(b64, "base64"));
}

export { hexToBytes, bytesToHex };
