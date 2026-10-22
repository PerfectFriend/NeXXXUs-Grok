import { mkdtemp, rm, cp, readdir } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createNode } from "./lib/node.mjs";

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function until(fn, label, tries = 50) {
  for (let i = 0; i < tries; i++) {
    const value = fn();
    if (value) return value;
    await wait(100);
  }
  throw new Error(`timeout: ${label}`);
}

async function cids(dir) {
  const found = [];
  const walk = async (current) => {
    let entries = [];
    try {
      entries = await readdir(current, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) await walk(full);
      else if (/^[a-f0-9]{64}$/.test(entry.name)) found.push(entry.name);
    }
  };
  await walk(dir);
  return found;
}

const phrase =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const dirA = await mkdtemp(path.join(os.tmpdir(), "nxx-vault-a-"));
const nodeA = await createNode({
  data: dirA,
  port: 18111,
  http: 18112,
  host: "127.0.0.1",
  advertise: "127.0.0.1",
  name: "vault-a",
  mnemonic: phrase,
});

const payload = new Uint8Array(20 * 1024);
for (let i = 0; i < payload.length; i++) payload[i] = i % 251;
payload.set(new TextEncoder().encode("nexxus-vault"), 0);

try {
  const rec = await nodeA.storePlainFile({ name: "blob.bin", bytes: payload });
  if (rec.chunks !== 2) throw new Error(`chunks ${rec.chunks}`);
  if (rec.state !== "local" || rec.copies !== 0) throw new Error("свежий файл уже размечён");
  const loaded = await nodeA.loadPlainFile(rec.id);
  if (Buffer.compare(loaded.bytes, payload) !== 0) throw new Error("локальная копия не сошлась");
  await nodeA.stop();

  const dirB = await mkdtemp(path.join(os.tmpdir(), "nxx-vault-b-"));
  await cp(path.join(dirA, "map.bin"), path.join(dirB, "map.bin"));
  await cp(path.join(dirA, "blobs"), path.join(dirB, "blobs"), { recursive: true });
  const nodeB = await createNode({
    data: dirB,
    port: 18121,
    http: 18122,
    host: "127.0.0.1",
    advertise: "127.0.0.1",
    name: "vault-b",
    mnemonic: phrase,
  });
  try {
    const again = await nodeB.loadPlainFile(rec.id);
    if (Buffer.compare(again.bytes, payload) !== 0) throw new Error("журнал не поднялся со вторым устройством");
    const localIds = await cids(path.join(dirB, "blobs"));
    const blobFile = path.join(dirB, "blobs", localIds[0].slice(0, 2), localIds[0]);
    const { readFile, writeFile } = await import("node:fs/promises");
    const raw = await readFile(blobFile);
    raw[raw.length - 1] ^= 0xff;
    await writeFile(blobFile, raw);
    let rejected = false;
    try {
      await nodeB.loadPlainFile(rec.id);
    } catch {
      rejected = true;
    }
    if (!rejected) throw new Error("подмена чанка не замечена");
  } finally {
    await nodeB.stop();
    await rm(dirB, { recursive: true, force: true });
  }

  const leftDir = await mkdtemp(path.join(os.tmpdir(), "nxx-vault-l-"));
  const rightDir = await mkdtemp(path.join(os.tmpdir(), "nxx-vault-r-"));
  const left = await createNode({
    data: leftDir,
    port: 18131,
    http: 18132,
    host: "127.0.0.1",
    advertise: "127.0.0.1",
    name: "left",
  });
  const right = await createNode({
    data: rightDir,
    port: 18141,
    http: 18142,
    host: "127.0.0.1",
    advertise: "127.0.0.1",
    name: "right",
  });
  try {
    await right.addContact(left.contact);
    await until(
      () => right.snapshot().contacts.some((c) => c.online) && left.snapshot().contacts.some((c) => c.online),
      "link",
    );
    const sent = await left.storePlainFile({ name: "net.bin", bytes: payload });
    const placed = await until(
      () => left.snapshot().files.find((file) => file.id === sent.id && file.copies >= 1),
      "replica ack",
      80,
    );
    if (placed.copies !== 1) throw new Error(`copies ${placed.copies}`);
    const own = await cids(path.join(leftDir, "blobs"));
    const remote = await cids(path.join(rightDir, "blobs-net"));
    if (remote.length !== 2) throw new Error(`foreign blobs ${remote.length}`);
    if (remote.some((cid) => own.includes(cid))) throw new Error("чужая копия совпала с локальным шифртекстом");
    console.log("VAULT OK");
  } finally {
    await left.stop();
    await right.stop();
    await rm(leftDir, { recursive: true, force: true });
    await rm(rightDir, { recursive: true, force: true });
  }
} finally {
  await rm(dirA, { recursive: true, force: true });
}
