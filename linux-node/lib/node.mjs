import os from "node:os";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { createMnemonic, deriveIdentity, formatContact, parseContact, isMnemonicValid } from "./identity.mjs";
import { CHUNK_BYTES, encrypt, decrypt, hashBytes, fromB64, toB64 } from "./crypto-io.mjs";
import { createMesh } from "./mesh.mjs";
import { ensureDir, readJson, writeJson, readFile, writeFile, writeBytes, exists, rm } from "./disk.mjs";
import { randomBytes } from "@noble/hashes/utils.js";

function lanIPv4() {
  const ifs = os.networkInterfaces();
  for (const list of Object.values(ifs)) {
    for (const n of list ?? []) {
      if (n.family === "IPv4" && !n.internal) return n.address;
    }
  }
  return "127.0.0.1";
}

function safeName(name) {
  const base = String(name ?? "")
    .replace(/[/\\]/g, "")
    .replace(/\0/g, "")
    .trim()
    .slice(0, 180);
  return base || "file.bin";
}

export function parseArgs(argv) {
  const args = {
    cmd: "start",
    data: path.join(os.homedir(), ".nexxus"),
    port: 4377,
    http: 4378,
    host: "0.0.0.0",
    httpHost: "127.0.0.1",
    advertise: "",
    name: "",
    mnemonic: "",
  };
  const rest = argv.slice(2);
  if (rest[0] && !rest[0].startsWith("-")) args.cmd = rest.shift();
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    const next = rest[i + 1];
    if (a === "--data") args.data = next, i++;
    else if (a === "--port") args.port = Number(next), i++;
    else if (a === "--http") args.http = Number(next), i++;
    else if (a === "--host") args.host = next, i++;
    else if (a === "--http-host") args.httpHost = next, i++;
    else if (a === "--advertise") args.advertise = next, i++;
    else if (a === "--name") args.name = next, i++;
    else if (a === "--mnemonic") args.mnemonic = next, i++;
  }
  return args;
}

export async function createNode(opts) {
  const dataDir = path.resolve(opts.data);
  await ensureDir(dataDir);

  const keyPath = path.join(dataDir, "machine.key");
  const encPath = path.join(dataDir, "identity.bin");
  const legacyPath = path.join(dataDir, "identity.json");

  let machineKey;
  if (exists(keyPath)) {
    machineKey = new Uint8Array(await readFile(keyPath));
    if (machineKey.length !== 32) throw new Error("machine.key повреждён.");
  } else {
    machineKey = randomBytes(32);
    await writeBytes(keyPath, Buffer.from(machineKey), 0o600);
  }

  let mnemonic;
  let fresh = false;
  if (exists(encPath)) {
    const packed = new Uint8Array(await readFile(encPath));
    const saved = JSON.parse(new TextDecoder().decode(decrypt(machineKey, packed)));
    mnemonic = saved.mnemonic;
  } else if (exists(legacyPath)) {
    const saved = await readJson(legacyPath, null);
    mnemonic = saved?.mnemonic;
  } else if (opts.mnemonic) {
    if (!isMnemonicValid(opts.mnemonic)) throw new Error("Фраза BIP39 невалидна.");
    mnemonic = opts.mnemonic;
    fresh = true;
  } else {
    mnemonic = createMnemonic();
    fresh = true;
  }
  if (!mnemonic) throw new Error("Нет ключа ноды.");
  const identity = deriveIdentity(mnemonic);
  const blob = encrypt(
    machineKey,
    new TextEncoder().encode(JSON.stringify({ mnemonic: identity.mnemonic, fingerprint: identity.fingerprint, pubHex: identity.pubHex })),
  );
  await writeBytes(encPath, Buffer.from(blob), 0o600);
  if (exists(legacyPath)) await rm(legacyPath, { force: true });

  const advertiseHost = opts.advertise || lanIPv4();
  const name = opts.name || `linux-${os.hostname().slice(0, 18)}`;
  const contact = formatContact({
    fingerprint: identity.fingerprint,
    pubHex: identity.pubHex,
    host: advertiseHost,
    port: opts.port,
  });

  let contacts = await readJson(path.join(dataDir, "contacts.json"), []);
  let messages = await readJson(path.join(dataDir, "messages.json"), []);
  let files = await readJson(path.join(dataDir, "files.json"), []);
  let log = await readJson(path.join(dataDir, "log.json"), []);
  const online = new Map();
  const listeners = new Set();

  const pushLog = (text) => {
    log = [{ id: randomUUID(), at: Date.now(), text }, ...log].slice(0, 80);
    void writeJson(path.join(dataDir, "log.json"), log);
    emit();
  };

  const emit = () => {
    const snap = snapshot();
    for (const fn of listeners) fn(snap);
  };

  const snapshot = () => ({
    identity: {
      fingerprint: identity.fingerprint,
      pubHex: identity.pubHex,
      contact,
      name,
    },
    listen: { host: opts.host, port: opts.port, http: opts.http, advertise: advertiseHost },
    contacts: contacts.map((c) => ({
      ...c,
      online: online.get(c.fingerprint) === true,
    })),
    messages,
    files: files.map(({ stored, ...rest }) => rest),
    log,
    fresh,
    mnemonic: fresh ? identity.mnemonic : null,
  });

  const incomingFiles = new Map();

  const mesh = createMesh({
    identity,
    advertise: { host: advertiseHost, name },
    listenHost: opts.host,
    listenPort: opts.port,
    onEvent: (ev) => {
      if (ev.kind === "log") pushLog(ev.text);
      if (ev.kind === "peer") {
        online.set(ev.fp, !!ev.online);
        if (ev.remote) {
          const i = contacts.findIndex((c) => c.fingerprint === ev.fp);
          const row = {
            fingerprint: ev.remote.fingerprint,
            pubHex: ev.remote.pubHex,
            host: ev.remote.host,
            port: ev.remote.port,
            name: ev.remote.name,
            addedAt: Date.now(),
          };
          if (i >= 0) contacts[i] = { ...contacts[i], ...row };
          else contacts = [row, ...contacts];
          void writeJson(path.join(dataDir, "contacts.json"), contacts);
        }
        emit();
      }
    },
    onPacket: (fp, obj) => {
      if (obj.t === "chat") {
        messages = [
          ...messages,
          { id: obj.id, fp, fromMe: false, text: String(obj.text ?? ""), at: obj.ts || Date.now() },
        ].slice(-400);
        void writeJson(path.join(dataDir, "messages.json"), messages);
        emit();
      } else if (obj.t === "file_meta") {
        const chunks = Number(obj.chunks);
        const name = safeName(obj.name);
        if (!obj.id || !Number.isInteger(chunks) || chunks < 1 || chunks > 4096) return;
        incomingFiles.set(obj.id, { id: obj.id, name, chunks, fp, bufs: [] });
        pushLog(`Входящий файл ${name} (${chunks} чанков) от ${fp}`);
      } else if (obj.t === "chunk") {
        void receiveChunk(fp, obj);
      } else if (obj.t === "ping") {
        try {
          mesh.send(fp, { t: "pong", ts: Date.now() });
        } catch {
          /* ignore */
        }
      }
    },
  });

  async function receiveChunk(fp, obj) {
    const meta = incomingFiles.get(obj.id);
    if (!meta) return;
    const i = Number(obj.i);
    if (!Number.isInteger(i) || i < 0 || i >= meta.chunks) return;
    if (typeof obj.data !== "string" || obj.data.length > 120_000) return;
    const link = mesh.links.get(fp);
    if (!link) return;
    const raw = decrypt(link.key, fromB64(obj.data));
    if (raw.length > CHUNK_BYTES + 64) return;
    meta.bufs[i] = raw;
    const got = meta.bufs.filter(Boolean).length;
    if (got < meta.chunks) return;
    const total = meta.bufs.reduce((n, b) => n + b.length, 0);
    const plain = new Uint8Array(total);
    let o = 0;
    for (const b of meta.bufs) {
      plain.set(b, o);
      o += b.length;
    }
    incomingFiles.delete(obj.id);
    await storePlainFile({ id: obj.id, name: meta.name, bytes: plain, from: fp });
    pushLog(`Файл ${meta.name} принят и записан в сейф.`);
  }

  async function storePlainFile({ id, name, bytes, from }) {
    const fileId = String(id || randomUUID()).replace(/[^a-zA-Z0-9._-]/g, "").slice(0, 80) || randomUUID();
    const dir = path.join(dataDir, "vault", fileId);
    await ensureDir(dir);
    const hash = hashBytes(bytes);
    const chunks = Math.max(1, Math.ceil(bytes.length / CHUNK_BYTES));
    for (let i = 0; i < chunks; i++) {
      const slice = bytes.subarray(i * CHUNK_BYTES, (i + 1) * CHUNK_BYTES);
      const packed = encrypt(identity.vaultKey, slice);
      await writeFile(path.join(dir, `c-${String(i).padStart(5, "0")}.bin`), packed);
    }
    const rec = {
      id: fileId,
      name: safeName(name),
      size: bytes.length,
      hash,
      chunks,
      at: Date.now(),
      from: from ?? null,
    };
    files = [rec, ...files.filter((f) => f.id !== fileId)];
    await writeJson(path.join(dataDir, "files.json"), files);
    emit();
    return rec;
  }

  async function loadPlainFile(id) {
    const rec = files.find((f) => f.id === id);
    if (!rec) throw new Error("Файл не найден.");
    const dir = path.join(dataDir, "vault", id);
    const parts = [];
    for (let i = 0; i < rec.chunks; i++) {
      const packed = new Uint8Array(await readFile(path.join(dir, `c-${String(i).padStart(5, "0")}.bin`)));
      parts.push(decrypt(identity.vaultKey, packed));
    }
    const total = parts.reduce((n, b) => n + b.length, 0);
    const out = new Uint8Array(total);
    let o = 0;
    for (const p of parts) {
      out.set(p, o);
      o += p.length;
    }
    return { rec, bytes: out };
  }

  async function addContact(uri) {
    const spec = parseContact(uri);
    if (spec.fingerprint === identity.fingerprint) throw new Error("Это ваш собственный контакт.");
    const row = { ...spec, name: spec.fingerprint, addedAt: Date.now() };
    const i = contacts.findIndex((c) => c.fingerprint === spec.fingerprint);
    if (i >= 0) contacts[i] = { ...contacts[i], ...row };
    else contacts = [row, ...contacts];
    await writeJson(path.join(dataDir, "contacts.json"), contacts);
    emit();
    mesh.dial(spec);
    return row;
  }

  function sendChat(fp, text) {
    const trimmed = String(text ?? "").trim();
    if (!trimmed) throw new Error("Пустое сообщение.");
    const msg = { id: randomUUID(), fp, fromMe: true, text: trimmed, at: Date.now() };
    mesh.send(fp, { t: "chat", id: msg.id, text: trimmed, ts: msg.at });
    messages = [...messages, msg].slice(-400);
    void writeJson(path.join(dataDir, "messages.json"), messages);
    emit();
    return msg;
  }

  async function sendFile(fp, id) {
    const { rec, bytes } = await loadPlainFile(id);
    const link = mesh.links.get(fp);
    if (!link) throw new Error("Нет канала с этим контактом.");
    mesh.send(fp, {
      t: "file_meta",
      id: rec.id,
      name: rec.name,
      size: rec.size,
      hash: rec.hash,
      chunks: rec.chunks,
    });
    for (let i = 0; i < rec.chunks; i++) {
      const slice = bytes.subarray(i * CHUNK_BYTES, (i + 1) * CHUNK_BYTES);
      const packed = encrypt(link.key, slice);
      mesh.send(fp, { t: "chunk", id: rec.id, i, data: toB64(packed) });
    }
    pushLog(`${rec.name}: ${rec.chunks} чанков ушли на ${fp}`);
  }

  async function removeFile(id) {
    files = files.filter((f) => f.id !== id);
    await writeJson(path.join(dataDir, "files.json"), files);
    await rm(path.join(dataDir, "vault", id), { recursive: true, force: true });
    emit();
  }

  const reconnect = setInterval(() => {
    for (const c of contacts) {
      if (!mesh.isOnline(c.fingerprint) && c.host && c.port) {
        try {
          mesh.dial(c);
        } catch {
          /* ignore */
        }
      }
    }
    for (const [fp, on] of online) {
      if (on) {
        try {
          mesh.send(fp, { t: "ping", ts: Date.now() });
        } catch {
          /* ignore */
        }
      }
    }
  }, 8000);

  await mesh.listen();
  for (const c of contacts) {
    try {
      mesh.dial(c);
    } catch {
      /* ignore */
    }
  }
  pushLog(fresh ? "Нода создана. Сохраните фразу BIP39 — она больше не показывается." : "Нода поднята.");
  pushLog(`Контакт: ${contact}`);

  return {
    identity,
    contact,
    fresh,
    mnemonic: fresh ? identity.mnemonic : null,
    snapshot,
    subscribe(fn) {
      listeners.add(fn);
      return () => listeners.delete(fn);
    },
    addContact,
    sendChat,
    sendFile,
    storePlainFile,
    loadPlainFile,
    removeFile,
    async stop() {
      clearInterval(reconnect);
      await mesh.stop();
    },
  };
}
