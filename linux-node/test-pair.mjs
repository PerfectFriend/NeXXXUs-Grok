import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createNode } from "./lib/node.mjs";

function wait(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function until(fn, label, tries = 40) {
  for (let i = 0; i < tries; i++) {
    const v = fn();
    if (v) return v;
    await wait(100);
  }
  throw new Error(`timeout: ${label}`);
}

const d1 = await mkdtemp(path.join(os.tmpdir(), "nxx-a-"));
const d2 = await mkdtemp(path.join(os.tmpdir(), "nxx-b-"));

const n1 = await createNode({
  data: d1,
  port: 18011,
  http: 18012,
  host: "127.0.0.1",
  advertise: "127.0.0.1",
  name: "alpha",
});
const n2 = await createNode({
  data: d2,
  port: 18021,
  http: 18022,
  host: "127.0.0.1",
  advertise: "127.0.0.1",
  name: "beta",
});

try {
  await n2.addContact(n1.contact);
  await until(
    () => n2.snapshot().contacts.some((c) => c.fingerprint === n1.identity.fingerprint && c.online),
    "n2 online to n1",
  );
  await until(
    () => n1.snapshot().contacts.some((c) => c.fingerprint === n2.identity.fingerprint && c.online),
    "n1 saw inbound n2",
  );

  n2.sendChat(n1.identity.fingerprint, "привет от beta");
  await until(
    () => n1.snapshot().messages.some((m) => m.text === "привет от beta" && !m.fromMe),
    "chat arrived",
  );

  const rec = await n2.storePlainFile({
    name: "hello.txt",
    bytes: new TextEncoder().encode("nexxus-payload-ok"),
  });
  await n2.sendFile(n1.identity.fingerprint, rec.id);
  const got = await until(
    () => n1.snapshot().files.find((f) => f.name === "hello.txt"),
    "file arrived",
    50,
  );
  const loaded = await n1.loadPlainFile(got.id);
  const text = new TextDecoder().decode(loaded.bytes);
  if (text !== "nexxus-payload-ok") throw new Error(`payload ${text}`);

  console.log("PAIR OK");
  console.log("A", n1.identity.fingerprint);
  console.log("B", n2.identity.fingerprint);
} finally {
  await n1.stop();
  await n2.stop();
  await rm(d1, { recursive: true, force: true });
  await rm(d2, { recursive: true, force: true });
}
