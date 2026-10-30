import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, hexToBytes, randomBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { hashBytes } from "./crypto-io.mjs";
import { CHUNK_BYTES } from "./crypto-io.mjs";
import { openChunk, padChunk, sealChunk } from "./vault.mjs";

function canon(value) {
  if (Array.isArray(value)) return `[${value.map(canon).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canon(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function signDesc(desc, edPriv) {
  const body = { ...desc };
  delete body.sig;
  return bytesToHex(ed25519.sign(utf8ToBytes(`nexxus-xftp-v1|${canon(body)}`), edPriv));
}

export function verifyDesc(desc) {
  if (!desc || desc.v !== 1 || desc.host || desc.port) return false;
  if (!Array.isArray(desc.cids) || !desc.cids.length || desc.cids.length > 4096) return false;
  if (typeof desc.sig !== "string" || typeof desc.pub !== "string") return false;
  const body = { ...desc };
  delete body.sig;
  try {
    return ed25519.verify(hexToBytes(desc.sig), utf8ToBytes(`nexxus-xftp-v1|${canon(body)}`), hexToBytes(desc.pub));
  } catch {
    return false;
  }
}

export function packXftp({ name, bytes, edPriv, edPub }) {
  const fileKey = randomBytes(32);
  const prefix = randomBytes(16);
  const chunks = Math.max(1, Math.ceil(bytes.length / CHUNK_BYTES));
  const cids = [];
  const bodies = [];
  for (let i = 0; i < chunks; i++) {
    const slice = bytes.subarray(i * CHUNK_BYTES, Math.min(bytes.length, (i + 1) * CHUNK_BYTES));
    const sealed = sealChunk(fileKey, padChunk(slice), prefix, i, 0);
    cids.push(sealed.cid);
    bodies.push(sealed.ct);
  }
  const desc = {
    v: 1,
    name,
    size: bytes.length,
    hash: hashBytes(bytes),
    fileKey: bytesToHex(fileKey),
    prefix: bytesToHex(prefix),
    cids,
    pub: bytesToHex(edPub),
  };
  desc.sig = signDesc(desc, edPriv);
  return { desc, bodies };
}

export function unpackXftp(desc, bodies) {
  if (!verifyDesc(desc)) throw new Error("описание XFTP не сошлось");
  if (bodies.length !== desc.cids.length) throw new Error("не все чанки описания на месте");
  const parts = [];
  for (let i = 0; i < desc.cids.length; i++) {
    if (hashBytes(bodies[i]) !== desc.cids[i]) throw new Error("чанк не совпал с описанием");
    const plain = openChunk(hexToBytes(desc.fileKey), bodies[i], desc.prefix, i, 0);
    const take = i === desc.cids.length - 1 ? desc.size - i * CHUNK_BYTES : CHUNK_BYTES;
    parts.push(plain.subarray(0, take));
  }
  const out = new Uint8Array(desc.size);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  if (hashBytes(out) !== desc.hash) throw new Error("хеш XFTP не сошёлся");
  return out;
}
