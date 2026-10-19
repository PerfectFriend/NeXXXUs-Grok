import { generateMnemonic, mnemonicToSeedSync, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes } from "@noble/hashes/utils.js";

const te = utf8ToBytes;

export function normalizeMnemonic(phrase) {
  return phrase.trim().toLowerCase().split(/\s+/).filter(Boolean).join(" ");
}

export function createMnemonic() {
  return generateMnemonic(wordlist, 128);
}

export function isMnemonicValid(phrase) {
  const n = normalizeMnemonic(phrase);
  return n.split(" ").length === 12 && validateMnemonic(n, wordlist);
}

export function isPubHex(s, bytes = 32) {
  return typeof s === "string" && new RegExp(`^[a-f0-9]{${bytes * 2}}$`, "i").test(s);
}

/** Fingerprint is bound to the X25519 public key, not the BIP39 seed. */
export function fingerprintFromPub(pub) {
  const bytes = typeof pub === "string" ? hexToBytes(pub) : pub;
  return `nxx1${bytesToHex(sha256(bytes)).slice(0, 16)}`;
}

export function deriveIdentity(mnemonic) {
  const phrase = normalizeMnemonic(mnemonic);
  const seed = mnemonicToSeedSync(phrase);
  const xPriv = hkdf(sha256, seed, te("nexxus-x25519"), te("v1"), 32);
  const xPub = x25519.getPublicKey(xPriv);
  const edPriv = hkdf(sha256, seed, te("nexxus-ed25519"), te("v1"), 32);
  const edPub = ed25519.getPublicKey(edPriv);
  const vaultKey = hkdf(sha256, seed, te("nexxus-vault"), te("v1"), 32);
  return {
    mnemonic: phrase,
    seed,
    xPriv,
    xPub,
    edPriv,
    edPub,
    vaultKey,
    fingerprint: fingerprintFromPub(xPub),
    pubHex: bytesToHex(xPub),
    edHex: bytesToHex(edPub),
  };
}

export function generateEph() {
  const secretKey = x25519.utils.randomSecretKey();
  const publicKey = x25519.getPublicKey(secretKey);
  return { secretKey, publicKey, pubHex: bytesToHex(publicKey) };
}

export function deriveSessionKey({
  myStaticPriv,
  myStaticPub,
  myEphPriv,
  theirStaticPub,
  theirEphPub,
  initiator,
}) {
  const ss = x25519.getSharedSecret(myStaticPriv, theirStaticPub);
  const ee = x25519.getSharedSecret(myEphPriv, theirEphPub);
  const es = initiator
    ? x25519.getSharedSecret(myEphPriv, theirStaticPub)
    : x25519.getSharedSecret(myStaticPriv, theirEphPub);
  const se = initiator
    ? x25519.getSharedSecret(myStaticPriv, theirEphPub)
    : x25519.getSharedSecret(myEphPriv, theirStaticPub);
  const ikm = concatBytes(ss, ee, es, se);
  const a = bytesToHex(myStaticPub);
  const b = bytesToHex(theirStaticPub);
  const [p1, p2] = a < b ? [myStaticPub, theirStaticPub] : [theirStaticPub, myStaticPub];
  const salt = concatBytes(te("nexxus-session"), p1, p2);
  return hkdf(sha256, ikm, salt, te("nxxp2"), 32);
}

function helloCanon(msg) {
  return te(
    [msg.v, msg.t, msg.fp, msg.pub, msg.eph, msg.ed, msg.name ?? "", msg.host ?? "", String(msg.port ?? 0)].join("|"),
  );
}

export function signHello(identity, fields) {
  const body = {
    v: 3,
    t: "hello",
    fp: identity.fingerprint,
    pub: identity.pubHex,
    eph: fields.eph,
    ed: identity.edHex,
    name: fields.name ?? "",
    host: fields.host ?? "",
    port: fields.port ?? 0,
  };
  return { ...body, sig: bytesToHex(ed25519.sign(helloCanon(body), identity.edPriv)) };
}

export function verifyHello(msg) {
  if (!msg || msg.t !== "hello") throw new Error("нет hello");
  if (msg.v !== 3) throw new Error("нужна нода 0.1.2 (рукопожатие v3)");
  if (!isPubHex(msg.pub) || !isPubHex(msg.eph) || !isPubHex(msg.ed) || !isPubHex(msg.sig, 64)) {
    throw new Error("битые поля hello");
  }
  if (fingerprintFromPub(msg.pub) !== String(msg.fp).toLowerCase()) {
    throw new Error("отпечаток не от этого X25519 ключа");
  }
  if (!ed25519.verify(hexToBytes(msg.sig), helloCanon(msg), hexToBytes(msg.ed))) {
    throw new Error("подпись hello не сходится");
  }
}

export function formatContact({ fingerprint, pubHex, host, port }) {
  return `nexxus:1:${fingerprint}:${pubHex}@${host}:${port}`;
}

export function parseContact(uri) {
  const raw = String(uri ?? "").trim();
  const m = raw.match(/^nexxus:1:(nxx1[a-f0-9]+):([a-f0-9]{64})@([^:@\s]+):(\d{1,5})$/i);
  if (!m) {
    throw new Error("Контакт должен выглядеть как nexxus:1:nxx1…:ключ@хост:порт");
  }
  const port = Number(m[4]);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("Некорректный порт в контакте.");
  }
  const fingerprint = m[1].toLowerCase();
  const pubHex = m[2].toLowerCase();
  if (fingerprintFromPub(pubHex) !== fingerprint) {
    throw new Error("Отпечаток не совпадает с публичным ключом.");
  }
  return { fingerprint, pubHex, host: m[3], port };
}

export { x25519, ed25519, hexToBytes, bytesToHex };