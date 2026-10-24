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

function payload() {
  const bytes = new Uint8Array(20 * 1024);
  for (let i = 0; i < bytes.length; i++) bytes[i] = (i * 17) % 251;
  bytes.set(new TextEncoder().encode("recover-me"), 0);
  return bytes;
}

const body = payload();
const holderDir = await mkdtemp(path.join(os.tmpdir(), "nxx-hold-"));
const ownerDir = await mkdtemp(path.join(os.tmpdir(), "nxx-own-"));
const holder = await createNode({
  data: holderDir,
  port: 18311,
  http: 18312,
  host: "127.0.0.1",
  advertise: "127.0.0.1",
  name: "holder",
});
const owner = await createNode({
  data: ownerDir,
  port: 18321,
  http: 18322,
  host: "127.0.0.1",
  advertise: "127.0.0.1",
  name: "owner",
});

try {
  await owner.addContact(holder.contact);
  await until(
    () => owner.snapshot().contacts.some((c) => c.online) && holder.snapshot().contacts.some((c) => c.online),
    "link",
  );
  const sent = await owner.storePlainFile({ name: "keep.bin", bytes: body });
  await until(
    () => owner.snapshot().files.find((file) => file.id === sent.id && file.copies >= 1),
    "placed",
  );
  await owner.auditNow();
  if (owner.snapshot().log.some((line) => line.text.includes("снята"))) {
    throw new Error("проверка сняла живую копию");
  }

  await rm(path.join(holderDir, "blobs-net"), { recursive: true, force: true });
  await owner.auditNow();
  if (!owner.snapshot().log.some((line) => line.text.includes("снята"))) {
    throw new Error("пропавший чанк не снят");
  }
  await until(
    () => owner.snapshot().files.find((file) => file.id === sent.id && file.copies >= 1),
    "replaced",
  );
  await until(async () => {
    const names = await readdir(path.join(holderDir, "maps")).catch(() => []);
    return names.some((name) => name.endsWith(".bin"));
  }, "map stored");

  const phrase = owner.mnemonic;
  if (!phrase) throw new Error("фраза владельца не сохранилась для второго устройства");
  await owner.stop();

  const restoredDir = await mkdtemp(path.join(os.tmpdir(), "nxx-rest-"));
  const restored = await createNode({
    data: restoredDir,
    port: 18331,
    http: 18332,
    host: "127.0.0.1",
    advertise: "127.0.0.1",
    name: "restored",
    mnemonic: phrase,
  });
  try {
    await restored.addContact(holder.contact);
    await until(
      () => restored.snapshot().files.some((file) => file.name === "keep.bin"),
      "map fetched",
    );
    const loaded = await restored.loadPlainFile(sent.id);
    if (Buffer.compare(loaded.bytes, body) !== 0) throw new Error("файл из сети не сошёлся");
    console.log("RECOVER OK");
  } finally {
    await restored.stop();
    await rm(restoredDir, { recursive: true, force: true });
  }
} finally {
  await holder.stop();
  await owner.stop().catch(() => {});
  await rm(holderDir, { recursive: true, force: true });
  await rm(ownerDir, { recursive: true, force: true });
}
