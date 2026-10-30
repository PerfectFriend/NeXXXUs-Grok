import { x25519 } from "@noble/curves/ed25519.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, randomBytes, utf8ToBytes } from "@noble/hashes/utils.js";

const INFO = utf8ToBytes("nexxus-smp-v1");

export function createQueueKey() {
  const priv = x25519.utils.randomSecretKey();
  return { priv, pub: x25519.getPublicKey(priv), pubHex: bytesToHex(x25519.getPublicKey(priv)) };
}

function sealKey(priv, pub) {
  return hkdf(sha256, x25519.getSharedSecret(priv, pub), new Uint8Array(0), INFO, 32);
}

export function sealQueue(recipientPub, plain) {
  const ephPriv = x25519.utils.randomSecretKey();
  const ephPub = x25519.getPublicKey(ephPriv);
  const key = sealKey(ephPriv, recipientPub);
  const nonce = randomBytes(24);
  const ct = xchacha20poly1305(key, nonce).encrypt(plain);
  return { eph: bytesToHex(ephPub), nonce: bytesToHex(nonce), ct: bytesToHex(ct) };
}

export function openQueue(recipientPriv, message) {
  const key = sealKey(recipientPriv, hexToBytes(message.eph));
  return xchacha20poly1305(key, hexToBytes(message.nonce)).decrypt(hexToBytes(message.ct));
}
