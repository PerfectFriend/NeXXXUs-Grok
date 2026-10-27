import os from "node:os";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { createMnemonic, deriveIdentity, deriveDevice, formatContact, parseContact, isMnemonicValid } from "./identity.mjs";
import { CHUNK_BYTES, encrypt, decrypt, hashBytes, fromB64, toB64, hexToBytes } from "./crypto-io.mjs";
import { createMesh } from "./mesh.mjs";
import { ensureDir, readJson, writeJson, readFile, writeFile, writeBytes, exists, rm } from "./disk.mjs";
import { openVault, mapLocator, auditProof } from "./vault.mjs";
import { bytesToHex, randomBytes } from "@noble/hashes/utils.js";

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
    graceMs: 24 * 60 * 60 * 1000,
    penaltyMs: 30 * 24 * 60 * 60 * 1000,
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
    else if (a === "--grace-ms") args.graceMs = Number(next), i++;
    else if (a === "--penalty-ms") args.penaltyMs = Number(next), i++;
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
  let deviceId;
  let fresh = false;
  if (exists(encPath)) {
    const packed = new Uint8Array(await readFile(encPath));
    const saved = JSON.parse(new TextDecoder().decode(decrypt(machineKey, packed)));
    mnemonic = saved.mnemonic;
    deviceId = saved.deviceId;
  } else if (exists(legacyPath)) {
    const saved = await readJson(legacyPath, null);
    mnemonic = saved?.mnemonic;
    deviceId = saved?.deviceId;
  } else if (opts.mnemonic) {
    if (!isMnemonicValid(opts.mnemonic)) throw new Error("Фраза BIP39 невалидна.");
    mnemonic = opts.mnemonic;
    fresh = true;
  } else {
    mnemonic = createMnemonic();
    fresh = true;
  }
  if (!mnemonic) throw new Error("Нет ключа ноды.");
  if (!deviceId) deviceId = bytesToHex(randomBytes(16));
  const identity = deriveIdentity(mnemonic);
  identity.device = deriveDevice(identity.seed, deviceId);
  const blob = encrypt(
    machineKey,
    new TextEncoder().encode(
      JSON.stringify({
        mnemonic: identity.mnemonic,
        fingerprint: identity.fingerprint,
        pubHex: identity.pubHex,
        deviceId,
      }),
    ),
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
  let reputation = await readJson(path.join(dataDir, "reputation.json"), {});
  const online = new Map();
  const listeners = new Set();
  let mesh = null;
  const vault = await openVault({
    dataDir,
    identity,
    onSave() {
      if (mesh) publishMap();
    },
  });
  const pendingBlobs = new Map();
  const pendingGets = new Map();
  const pendingAudits = new Map();
  const replicating = new Set();
  let foreign = 0;

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
      blockedUntil: reputation[c.fingerprint]?.until > Date.now() ? reputation[c.fingerprint].until : 0,
    })),
    messages,
    files: fileIndex(),
    foreign,
    log,
    fresh,
    mnemonic: fresh ? identity.mnemonic : null,
  });

  const incomingFiles = new Map();

  mesh = createMesh({
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
      if (ev.kind === "peer" && ev.online) {
        publishMap();
        requestMap(ev.fp);
        for (const file of vault.list()) {
          if (file.copies < 3) void replicateFile(file.id);
        }
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
      } else if (obj.t === "blob_put") {
        void acceptBlob(fp, obj);
      } else if (obj.t === "blob_ack") {
        const pending = pendingBlobs.get(obj.cid);
        if (pending) {
          clearTimeout(pending.timer);
          pendingBlobs.delete(obj.cid);
          pending.resolve(true);
        }
      } else if (obj.t === "blob_drop") {
        if (Array.isArray(obj.cids)) void vault.dropForeign(obj.cids.slice(0, 4096));
      } else if (obj.t === "blob_get") {
        void serveBlob(fp, obj.cid);
      } else if (obj.t === "blob_data") {
        const pending = pendingGets.get(obj.cid);
        if (pending && typeof obj.data === "string" && obj.data.length <= 80_000) {
          clearTimeout(pending.timer);
          pendingGets.delete(obj.cid);
          pending.resolve(fromB64(obj.data));
        }
      } else if (obj.t === "blob_miss") {
        const pending = pendingGets.get(obj.cid);
        if (pending) {
          clearTimeout(pending.timer);
          pendingGets.delete(obj.cid);
          pending.resolve(null);
        }
      } else if (obj.t === "map_put") {
        void acceptMap(fp, obj);
      } else if (obj.t === "map_get") {
        void serveMap(fp, obj.loc);
      } else if (obj.t === "map_data") {
        void adoptMap(obj);
      } else if (obj.t === "audit") {
        void answerAudit(fp, obj);
      } else if (obj.t === "audit_ok" || obj.t === "audit_miss") {
        const key = `${obj.cid}:${obj.challenge}`;
        const pending = pendingAudits.get(key);
        if (pending) {
          clearTimeout(pending.timer);
          pendingAudits.delete(key);
          pending.resolve(obj.t === "audit_miss" ? "miss" : obj.proof);
        }
      } else if (obj.t === "ping") {
        try {
          mesh.send(fp, { t: "pong", ts: Date.now() });
        } catch {
          /* ignore */
        }
      }
    },
  });

  function fileIndex() {
    const modern = vault.list();
    const ids = new Set(modern.map((file) => file.id));
    const legacy = files
      .filter((file) => !ids.has(file.id))
      .map(({ stored, ...rest }) => ({ ...rest, copies: 0, state: "legacy", v: 1 }));
    return [...modern, ...legacy];
  }

  function expectAck(cid) {
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        pendingBlobs.delete(cid);
        resolve(false);
      }, 8000);
      pendingBlobs.set(cid, { resolve, timer });
    });
  }

  function expectGet(cid) {
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        pendingGets.delete(cid);
        resolve(null);
      }, 8000);
      pendingGets.set(cid, { resolve, timer });
    });
  }

  function publishMap() {
    const loc = mapLocator(identity.vaultKey);
    const data = toB64(vault.packed());
    for (const peer of contacts) {
      if (!mesh.isOnline(peer.fingerprint)) continue;
      try {
        mesh.send(peer.fingerprint, { t: "map_put", loc, data });
      } catch {
        /* offline */
      }
    }
  }

  function requestMap(fp) {
    const loc = mapLocator(identity.vaultKey);
    try {
      mesh.send(fp, { t: "map_get", loc });
    } catch {
      /* offline */
    }
  }

  async function acceptMap(fp, obj) {
    if (!/^[a-f0-9]{64}$/.test(obj.loc) || typeof obj.data !== "string") return;
    const body = fromB64(obj.data);
    if (body.length < 24 || body.length > 2_000_000) return;
    const dir = path.join(dataDir, "maps");
    await ensureDir(dir);
    const mark = path.join(dir, `${obj.loc}.fp`);
    if (exists(mark)) {
      const prev = String(await readFile(mark, "utf8")).trim();
      if (prev && prev !== fp) return;
    }
    await writeBytes(path.join(dir, `${obj.loc}.bin`), Buffer.from(body), 0o600);
    await writeFile(mark, fp, { mode: 0o600 });
  }

  async function serveMap(fp, loc) {
    if (!/^[a-f0-9]{64}$/.test(loc)) return;
    const dir = path.join(dataDir, "maps");
    const mark = path.join(dir, `${loc}.fp`);
    const bin = path.join(dir, `${loc}.bin`);
    if (!exists(mark) || !exists(bin)) return;
    const prev = String(await readFile(mark, "utf8")).trim();
    if (prev !== fp) return;
    try {
      mesh.send(fp, { t: "map_data", loc, data: toB64(new Uint8Array(await readFile(bin))) });
    } catch {
      /* offline */
    }
  }

  async function adoptMap(obj) {
    if (obj.loc !== mapLocator(identity.vaultKey) || typeof obj.data !== "string") return;
    const body = fromB64(obj.data);
    if (body.length > 2_000_000) return;
    const adopted = await vault.importPacked(body);
    if (adopted) {
      pushLog("Журнал подтянут с чужой ноды.");
      emit();
    }
  }

  async function serveBlob(fp, cid) {
    const ct = await vault.foreignCipher(String(cid ?? ""));
    try {
      if (!ct) mesh.send(fp, { t: "blob_miss", cid });
      else mesh.send(fp, { t: "blob_data", cid, data: toB64(ct) });
    } catch {
      /* offline */
    }
  }

  async function answerAudit(fp, obj) {
    if (typeof obj.cid !== "string" || typeof obj.challenge !== "string" || obj.challenge.length !== 64) return;
    const ct = await vault.foreignCipher(obj.cid);
    try {
      if (!ct) {
        mesh.send(fp, { t: "audit_miss", cid: obj.cid, challenge: obj.challenge });
        return;
      }
      mesh.send(fp, {
        t: "audit_ok",
        cid: obj.cid,
        challenge: obj.challenge,
        proof: auditProof(ct, hexToBytes(obj.challenge)),
      });
    } catch {
      /* offline */
    }
  }

  async function fetchCipher(cid, replica) {
    if (!mesh.isOnline(replica.holder) && replica.host && replica.port && replica.pubHex) {
      try {
        mesh.dial({
          fingerprint: replica.holder,
          pubHex: replica.pubHex,
          host: replica.host,
          port: replica.port,
        });
      } catch {
        return null;
      }
      const start = Date.now();
      while (!mesh.isOnline(replica.holder) && Date.now() - start < 2500) {
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
    }
    if (!mesh.isOnline(replica.holder)) return null;
    const pending = expectGet(cid);
    try {
      mesh.send(replica.holder, { t: "blob_get", cid });
    } catch {
      return null;
    }
    return pending;
  }

  async function auditNow() {
    for (const target of vault.auditTargets()) {
      if (!mesh.isOnline(target.holder)) continue;
      const challenge = bytesToHex(randomBytes(32));
      let expected;
      try {
        expected = await vault.proofFor(target.id, target.slot, target.index, hexToBytes(challenge));
      } catch (err) {
        pushLog(`Проверка ${target.name} не посчитана: ${err.message}`);
        continue;
      }
      const verdict = await new Promise((resolve) => {
        const key = `${target.cid}:${challenge}`;
        const timer = setTimeout(() => {
          pendingAudits.delete(key);
          resolve("timeout");
        }, 4000);
        pendingAudits.set(key, { resolve, timer });
        try {
          mesh.send(target.holder, { t: "audit", cid: target.cid, challenge });
        } catch {
          clearTimeout(timer);
          pendingAudits.delete(key);
          resolve("timeout");
        }
      });
      const bad = verdict === "miss" || (verdict !== "timeout" && verdict !== expected);
      if (!bad) {
        await vault.noteSeen(target.id, target.slot);
        continue;
      }
      await vault.unpinReplica(target.id, target.slot);
      await noteFail(target.holder);
      pushLog(`${target.name}: копия ${target.slot} снята, нода не держит чанк.`);
      emit();
      void replicateFile(target.id);
    }
    const graceMs = Number.isFinite(opts.graceMs) ? opts.graceMs : 24 * 60 * 60 * 1000;
    for (const stale of vault.staleReplicas(graceMs)) {
      await vault.unpinReplica(stale.id, stale.slot);
      await noteFail(stale.holder);
      pushLog(`${stale.name}: копия ${stale.slot} снята, нет ответа дольше льготного срока.`);
      emit();
      void replicateFile(stale.id);
    }
  }

  function penaltyMs() {
    return Number.isFinite(opts.penaltyMs) ? opts.penaltyMs : 30 * 24 * 60 * 60 * 1000;
  }

  function blocked(fp, now = Date.now()) {
    return (reputation[fp]?.until ?? 0) > now;
  }

  async function noteFail(fp) {
    const now = Date.now();
    reputation[fp] = { fails: (reputation[fp]?.fails ?? 0) + 1, until: now + penaltyMs(), at: now };
    await writeJson(path.join(dataDir, "reputation.json"), reputation);
    pushLog(`${fp}: новые чанки не кладём до конца штрафа.`);
  }

  async function acceptBlob(fp, obj) {
    if (typeof obj.cid !== "string" || typeof obj.data !== "string") return;
    if (obj.data.length > 80_000) return;
    const ct = fromB64(obj.data);
    const ok = await vault.storeForeign(obj.cid, ct);
    if (!ok) return;
    foreign += 1;
    try {
      mesh.send(fp, { t: "blob_ack", cid: obj.cid });
    } catch {
      /* peer left */
    }
    emit();
  }

  async function replicateFile(id) {
    if (replicating.has(id) || !vault.has(id)) return;
    replicating.add(id);
    try {
      const peers = contacts.filter((c) => c.fingerprint !== identity.fingerprint && mesh.isOnline(c.fingerprint));
      let guard = 0;
      while (guard++ < 3) {
        const current = vault.list().find((file) => file.id === id);
        if (!current || current.copies >= 3) return;
        const peer = peers.find(
          (c) =>
            mesh.isOnline(c.fingerprint) &&
            !(current.holders || []).includes(c.fingerprint) &&
            !blocked(c.fingerprint),
        );
        if (!peer) return;
        const taken = new Set(current.slots || []);
        let slot = 0;
        for (let s = 1; s <= 3; s++) {
          if (!taken.has(s)) {
            slot = s;
            break;
          }
        }
        if (!slot) return;
        let planned;
        try {
          planned = await vault.planReplica(id, slot);
        } catch (err) {
          pushLog(`Реплика ${id} не собрана: ${err.message}`);
          return;
        }
        if (!planned) return;
        const waits = planned.cids.map((cid) => expectAck(cid));
        try {
          for (let i = 0; i < planned.cids.length; i++) {
            mesh.send(peer.fingerprint, {
              t: "blob_put",
              cid: planned.cids[i],
              data: toB64(planned.bodies[i]),
            });
          }
        } catch (err) {
          pushLog(`Реплика не ушла: ${err.message}`);
          return;
        }
        const acks = await Promise.all(waits);
        if (!acks.every(Boolean)) {
          pushLog(`Копия ${slot}/3 для ${current.name} не подтвердилась.`);
          return;
        }
        await vault.pinReplica(id, planned, peer);
        peers.splice(peers.indexOf(peer), 1);
        pushLog(`${current.name}: копия ${slot}/3 на ${peer.fingerprint}`);
        emit();
      }
    } finally {
      replicating.delete(id);
    }
  }
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
    const rec = await vault.addFile({ id: fileId, name: safeName(name), bytes });
    if (from) rec.from = from;
    emit();
    void replicateFile(fileId).catch((err) => pushLog(String(err.message ?? err)));
    return rec;
  }

  async function loadPlainFile(id) {
    if (vault.has(id)) return vault.readPlain(id, fetchCipher);
    const rec = files.find((file) => file.id === id);
    if (!rec) throw new Error("Файл не найден.");
    const dir = path.join(dataDir, "vault", id);
    const parts = [];
    for (let i = 0; i < rec.chunks; i++) {
      const packed = new Uint8Array(await readFile(path.join(dir, `c-${String(i).padStart(5, "0")}.bin`)));
      parts.push(decrypt(identity.vaultKey, packed));
    }
    const total = parts.reduce((n, part) => n + part.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const part of parts) {
      out.set(part, offset);
      offset += part.length;
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
    if (vault.has(id)) {
      const dropped = await vault.dropFile(id);
      for (const replica of dropped.holders) {
        try {
          mesh.send(replica.holder, { t: "blob_drop", cids: replica.cids });
        } catch {
          /* peer offline */
        }
      }
    }
    files = files.filter((file) => file.id !== id);
    await writeJson(path.join(dataDir, "files.json"), files);
    await rm(path.join(dataDir, "vault", id), { recursive: true, force: true });
    emit();
  }

  const auditTimer = setInterval(() => {
    void auditNow().catch((err) => pushLog(String(err.message ?? err)));
  }, 60_000);

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
    auditNow,
    async stop() {
      clearInterval(reconnect);
      clearInterval(auditTimer);
      await mesh.stop();
    },
  };
}
