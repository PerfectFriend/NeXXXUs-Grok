import { mkdtemp, rm, readdir } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createNode } from "./lib/node.mjs";

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function until(fn, label, tries = 80) {
  for (let i = 0; i < tries; i++) {
    const value = await fn();
    if (value) return value;
    await wait(100);
  }
  throw new Error(`timeout: ${label}`);
}

async function foreignCount(dir) {
  const root = path.join(dir, "blobs-net");
  let n = 0;
  const walk = async (current) => {
    let entries = [];
    try {
      entries = await readdir(current, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry.isDirectory()) await walk(path.join(current, entry.name));
      else if (/^[a-f0-9]{64}$/.test(entry.name)) n += 1;
    }
  };
  await walk(root);
  return n;
}

const liarDir = await mkdtemp(path.join(os.tmpdir(), "nxx-liar-"));
const ownerDir = await mkdtemp(path.join(os.tmpdir(), "nxx-rate-"));
const liar = await createNode({
  data: liarDir,
  port: 18511,
  http: 18512,
  host: "127.0.0.1",
  advertise: "127.0.0.1",
  name: "liar",
});
const owner = await createNode({
  data: ownerDir,
  port: 18521,
  http: 18522,
  host: "127.0.0.1",
  advertise: "127.0.0.1",
  name: "owner",
  penaltyMs: 60_000,
});

try {
  await owner.addContact(liar.contact);
  await until(
    () => owner.snapshot().contacts.some((c) => c.online) && liar.snapshot().contacts.some((c) => c.online),
    "link",
  );
  const sent = await owner.storePlainFile({
    name: "rate.bin",
    bytes: new TextEncoder().encode("rating-ban"),
  });
  await until(
    () => owner.snapshot().files.find((file) => file.id === sent.id && file.copies >= 1),
    "placed",
  );
  await rm(path.join(liarDir, "blobs-net"), { recursive: true, force: true });
  await owner.auditNow();
  await wait(400);
  const stuck = owner.snapshot().files.find((file) => file.id === sent.id);
  if (!stuck || stuck.copies !== 0) throw new Error(`копия вернулась на ту же ноду: ${stuck?.copies}`);
  const ban = owner.snapshot().contacts.find((c) => c.fingerprint === liar.identity.fingerprint);
  if (!ban?.blockedUntil || ban.blockedUntil <= Date.now()) throw new Error("штраф не записан");
  if ((await foreignCount(liarDir)) !== 0) throw new Error("проштрафившаяся нода снова получила чанки");

  const spareDir = await mkdtemp(path.join(os.tmpdir(), "nxx-rate-spare-"));
  const spare = await createNode({
    data: spareDir,
    port: 18531,
    http: 18532,
    host: "127.0.0.1",
    advertise: "127.0.0.1",
    name: "spare",
  });
  try {
    await owner.addContact(spare.contact);
    await until(() => {
      const file = owner.snapshot().files.find((item) => item.id === sent.id);
      return file && file.holders.length === 1 && file.holders[0] === spare.identity.fingerprint;
    }, "spare took the copy");
    if ((await foreignCount(liarDir)) !== 0) throw new Error("после появления запасной ноды чанки снова легли на оштрафованную");
    console.log("RATING OK");
  } finally {
    await spare.stop();
    await rm(spareDir, { recursive: true, force: true });
  }
} finally {
  await liar.stop();
  await owner.stop();
  await rm(liarDir, { recursive: true, force: true });
  await rm(ownerDir, { recursive: true, force: true });
}
