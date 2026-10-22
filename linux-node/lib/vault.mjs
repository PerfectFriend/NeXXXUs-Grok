import path from "node:path";
import { ed25519 } from "@noble/curves/ed25519.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes, utf8ToBytes, concatBytes, randomBytes } from "@noble/hashes/utils.js";
import { CHUNK_BYTES, encrypt, decrypt, hashBytes } from "./crypto-io.mjs";
import { ensureDir, readFile, writeBytes, writeJson, exists, rm } from "./disk.mjs";

const TEXT = new TextEncoder();
const FOREIGN_CAP = 64 * 1024 * 1024;

function canon(value) {
  if (Array.isArray(value)) return `[${value.map(canon).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canon(value[k])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

export function replicaNonce(prefix16, index, slot) {
  if (prefix16.length !== 16) throw new Error("префикс nonce должен быть 16 байт");
  const nonce = new Uint8Array(24);
  nonce.set(prefix16, 0);
  new DataView(nonce.buffer).setUint32(16, index);
  new DataView(nonce.buffer).setUint32(20, slot);
  return nonce;
}

export function sealChunk(fileKey, padded, prefix16, index, slot) {
  const nonce = replicaNonce(prefix16, index, slot);
  const ct = xchacha20poly1305(fileKey, nonce).encrypt(padded);
  return { cid: bytesToHex(sha256(ct)), ct };
}

export function openChunk(fileKey, ct, prefixHex, index, slot) {
  const nonce = replicaNonce(hexToBytes(prefixHex), index, slot);
  return xchacha20poly1305(fileKey, nonce).decrypt(ct);
}

function padChunk(slice) {
  const out = new Uint8Array(CHUNK_BYTES);
  if (slice.length) out.set(slice, 0);
  return out;
}

function certMessage(devicePub) {
  return concatBytes(utf8ToBytes("nexxus-device-cert-v1|"), devicePub);
}

function opMessage(op) {
  return utf8ToBytes(`nexxus-map-op-v1|${canon(op)}`);
}

function signOp(op, devicePriv) {
  const body = { ...op };
  delete body.sig;
  return { ...body, sig: bytesToHex(ed25519.sign(opMessage(body), devicePriv)) };
}

function verifyOp(op, devices, nodeEdPub) {
  if (!op || typeof op.sig !== "string" || !op.dev) return false;
  const device = devices.find((d) => d.pub === op.dev);
  if (!device || !verifyCert(device, nodeEdPub)) return false;
  const body = { ...op };
  delete body.sig;
  return ed25519.verify(hexToBytes(op.sig), opMessage(body), hexToBytes(device.pub));
}

function verifyCert(device, nodeEdPub) {
  try {
    return ed25519.verify(hexToBytes(device.cert), certMessage(hexToBytes(device.pub)), nodeEdPub);
  } catch {
    return false;
  }
}

function enroll(journal, identity) {
  const pub = bytesToHex(identity.device.edPub);
  if (journal.devices.some((d) => d.pub === pub)) return;
  journal.devices.push({
    pub,
    cert: bytesToHex(ed25519.sign(certMessage(identity.device.edPub), identity.edPriv)),
  });
}

export function foldJournal(journal, nodeEdPub) {
  const files = new Map();
  for (const op of journal.ops) {
    if (!verifyOp(op, journal.devices, nodeEdPub)) throw new Error("подпись журнала не сходится");
    if (op.op === "add") {
      files.set(op.id, {
        id: op.id,
        name: op.name,
        size: op.size,
        hash: op.hash,
        fileKey: op.fileKey,
        localPrefix: op.localPrefix,
        chunks: op.chunks,
        replicas: [],
        at: op.at,
      });
    } else if (op.op === "pin") {
      const file = files.get(op.id);
      if (!file) continue;
      file.replicas = file.replicas.filter((r) => r.slot !== op.slot);
      file.replicas.push({ slot: op.slot, prefix: op.prefix, cids: op.cids, holder: op.holder });
    } else if (op.op === "drop") {
      files.delete(op.id);
    }
  }
  return files;
}

function blobPath(root, cid) {
  return path.join(root, cid.slice(0, 2), cid);
}

export async function openVault({ dataDir, identity }) {
  const root = path.join(dataDir, "blobs");
  const foreignRoot = path.join(dataDir, "blobs-net");
  const mapPath = path.join(dataDir, "map.bin");
  await ensureDir(root);
  await ensureDir(foreignRoot);
  let journal = { v: 1, devices: [], ops: [] };
  if (exists(mapPath)) {
    const packed = new Uint8Array(await readFile(mapPath));
    journal = JSON.parse(new TextDecoder().decode(decrypt(identity.vaultKey, packed)));
    if (journal.v !== 1 || !Array.isArray(journal.ops) || !Array.isArray(journal.devices)) {
      throw new Error("журнал карты повреждён");
    }
  }
  enroll(journal, identity);
  foldJournal(journal, identity.edPub);
  let chain = Promise.resolve();
  const lock = (fn) => {
    const run = chain.then(fn, fn);
    chain = run.then(
      () => {},
      () => {},
    );
    return run;
  };

  async function save() {
    const packed = encrypt(identity.vaultKey, TEXT.encode(JSON.stringify(journal)));
    await writeBytes(mapPath, Buffer.from(packed), 0o600);
  }

  function view() {
    return foldJournal(journal, identity.edPub);
  }

  async function putBlob(dir, cid, ct) {
    if (hashBytes(ct) !== cid) throw new Error("идентификатор чанка не совпал с шифртекстом");
    await writeBytes(blobPath(dir, cid), Buffer.from(ct), 0o600);
  }

  async function addFile({ id, name, bytes }) {
    return lock(async () => {
      const size = bytes.length;
      const chunks = Math.max(1, Math.ceil(size / CHUNK_BYTES));
      if (chunks > 4096) throw new Error("файл больше 64 МБ");
      const fileKey = randomBytes(32);
      const prefix = randomBytes(16);
      const chunkIds = [];
      for (let i = 0; i < chunks; i++) {
        const slice = bytes.subarray(i * CHUNK_BYTES, Math.min(size, (i + 1) * CHUNK_BYTES));
        const sealed = sealChunk(fileKey, padChunk(slice), prefix, i, 0);
        await putBlob(root, sealed.cid, sealed.ct);
        chunkIds.push(sealed.cid);
      }
      const op = signOp(
        {
          op: "add",
          id,
          name,
          size,
          hash: hashBytes(bytes),
          fileKey: bytesToHex(fileKey),
          localPrefix: bytesToHex(prefix),
          chunks: chunkIds,
          dev: bytesToHex(identity.device.edPub),
          at: Date.now(),
        },
        identity.device.edPriv,
      );
      journal.ops.push(op);
      await save();
      return publicRec(view().get(id));
    });
  }

  async function readPlain(id) {
    const file = view().get(id);
    if (!file) throw new Error("Файл не найден.");
    const key = hexToBytes(file.fileKey);
    const parts = [];
    for (let i = 0; i < file.chunks.length; i++) {
      const ct = new Uint8Array(await readFile(blobPath(root, file.chunks[i])));
      if (hashBytes(ct) !== file.chunks[i]) throw new Error("локальный чанк подменён");
      const padded = openChunk(key, ct, file.localPrefix, i, 0);
      const take = i === file.chunks.length - 1 ? file.size - i * CHUNK_BYTES : CHUNK_BYTES;
      parts.push(padded.subarray(0, take));
    }
    const out = new Uint8Array(file.size);
    let o = 0;
    for (const part of parts) {
      out.set(part, o);
      o += part.length;
    }
    if (hashBytes(out) !== file.hash) throw new Error("хеш файла не сошёлся");
    return { rec: publicRec(file), bytes: out };
  }

  function publicRec(file) {
    return {
      id: file.id,
      name: file.name,
      size: file.size,
      hash: file.hash,
      chunks: file.chunks.length,
      copies: file.replicas.length,
      holders: file.replicas.map((replica) => replica.holder),
      state: file.replicas.length >= 3 ? "placed" : "local",
      at: file.at,
      v: 2,
    };
  }

  function list() {
    return [...view().values()].map(publicRec).sort((a, b) => b.at - a.at);
  }

  async function planReplica(id, slot) {
    return lock(async () => {
      const file = view().get(id);
      if (!file) throw new Error("Файл не найден.");
      if (file.replicas.some((r) => r.slot === slot)) return null;
      const { bytes } = await readPlain(id);
      const prefix = randomBytes(16);
      const key = hexToBytes(file.fileKey);
      const cids = [];
      const bodies = [];
      for (let i = 0; i < file.chunks.length; i++) {
        const slice = bytes.subarray(i * CHUNK_BYTES, Math.min(bytes.length, (i + 1) * CHUNK_BYTES));
        const sealed = sealChunk(key, padChunk(slice), prefix, i, slot);
        cids.push(sealed.cid);
        bodies.push(sealed.ct);
      }
      return { slot, prefix: bytesToHex(prefix), cids, bodies };
    });
  }

  async function pinReplica(id, planned, holder) {
    return lock(async () => {
      const op = signOp(
        {
          op: "pin",
          id,
          slot: planned.slot,
          prefix: planned.prefix,
          cids: planned.cids,
          holder,
          dev: bytesToHex(identity.device.edPub),
          at: Date.now(),
        },
        identity.device.edPriv,
      );
      journal.ops.push(op);
      await save();
      return publicRec(view().get(id));
    });
  }

  async function dropFile(id) {
    return lock(async () => {
      const file = view().get(id);
      if (!file) return { holders: [] };
      const holders = file.replicas.map((r) => ({ holder: r.holder, cids: r.cids }));
      for (const cid of file.chunks) {
        await rm(blobPath(root, cid), { force: true });
      }
      journal.ops.push(
        signOp(
          { op: "drop", id, dev: bytesToHex(identity.device.edPub), at: Date.now() },
          identity.device.edPriv,
        ),
      );
      await save();
      return { holders };
    });
  }

  async function storeForeign(cid, ct) {
    if (ct.length !== CHUNK_BYTES + 16) return false;
    if (hashBytes(ct) !== cid) return false;
    const file = blobPath(foreignRoot, cid);
    if (exists(file)) return true;
    const used = await foreignBytes();
    if (used + ct.length > FOREIGN_CAP) return false;
    await putBlob(foreignRoot, cid, ct);
    return true;
  }

  async function foreignBytes() {
    const { readdir, stat } = await import("node:fs/promises");
    let n = 0;
    if (!exists(foreignRoot)) return 0;
    const dirs = await readdir(foreignRoot);
    for (const dir of dirs) {
      const full = path.join(foreignRoot, dir);
      const st = await stat(full);
      if (!st.isDirectory()) continue;
      for (const name of await readdir(full)) {
        n += (await stat(path.join(full, name))).size;
      }
    }
    return n;
  }

  async function dropForeign(cids) {
    for (const cid of cids) {
      if (!/^[a-f0-9]{64}$/.test(cid)) continue;
      await rm(blobPath(foreignRoot, cid), { force: true });
    }
  }

  if (exists(mapPath) || journal.devices.length) await save();

  return {
    addFile,
    readPlain,
    list,
    planReplica,
    pinReplica,
    dropFile,
    storeForeign,
    dropForeign,
    has: (id) => view().has(id),
    mapPath,
  };
}

export { writeJson };
