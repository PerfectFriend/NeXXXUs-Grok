import { mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createNode } from "./lib/node.mjs";

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function until(fn, label, tries = 50) {
  for (let i = 0; i < tries; i++) {
    if (fn()) return;
    await wait(100);
  }
  throw new Error(`timeout: ${label}`);
}

const dirs = await Promise.all([0, 1, 2].map(() => mkdtemp(path.join(os.tmpdir(), "nxx-smp-"))));
const relay = await createNode({ data: dirs[0], port: 18911, http: 18912, host: "127.0.0.1", advertise: "127.0.0.1", name: "relay" });
const alice = await createNode({ data: dirs[1], port: 18921, http: 18922, host: "127.0.0.1", advertise: "127.0.0.1", name: "alice" });
const bob = await createNode({ data: dirs[2], port: 18931, http: 18932, host: "127.0.0.1", advertise: "127.0.0.1", name: "bob" });

try {
  await alice.addContact(relay.contact);
  await bob.addContact(relay.contact);
  await until(() => alice.snapshot().contacts.some((c) => c.online) && bob.snapshot().contacts.some((c) => c.online), "links");
  const inbox = await alice.openInbox(relay.identity.fingerprint);
  const secret = "секрет очереди";
  await bob.sendSealed(relay.identity.fingerprint, { ...inbox, pub: inbox.pub }, secret);
  const stored = await readFile(path.join(dirs[0], "smp.json"), "utf8");
  if (stored.includes(secret)) throw new Error("релей увидел открытый текст");
  const record = relay.queueRecord(inbox.id);
  if (!record || record.owner !== alice.identity.fingerprint) throw new Error("очередь записана не на владельца");
  if (JSON.stringify(record).includes(secret)) throw new Error("запись очереди содержит текст");
  let denied = false;
  try {
    await bob.pullSealed({ id: inbox.id, host: relay.identity.fingerprint, priv: inbox.priv });
  } catch (err) {
    denied = String(err.message).includes("не ответила");
  }
  if (!denied) throw new Error("чужой забрал очередь");
  const got = await alice.pullSealed(inbox);
  if (got.length !== 1 || new TextDecoder().decode(got[0]) !== secret) throw new Error("получатель не открыл сообщение");
  console.log("SMP OK");
} finally {
  await relay.stop();
  await alice.stop();
  await bob.stop();
  await Promise.all(dirs.map((dir) => rm(dir, { recursive: true, force: true })));
}
