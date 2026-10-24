import { mkdtemp, rm } from "node:fs/promises";
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

const graceMs = 5000;
const holderDir = await mkdtemp(path.join(os.tmpdir(), "nxx-grace-h-"));
const ownerDir = await mkdtemp(path.join(os.tmpdir(), "nxx-grace-o-"));
const holder = await createNode({
  data: holderDir,
  port: 18411,
  http: 18412,
  host: "127.0.0.1",
  advertise: "127.0.0.1",
  name: "holder",
});
const owner = await createNode({
  data: ownerDir,
  port: 18421,
  http: 18422,
  host: "127.0.0.1",
  advertise: "127.0.0.1",
  name: "owner",
  graceMs,
});

try {
  await owner.addContact(holder.contact);
  await until(
    () => owner.snapshot().contacts.some((c) => c.online) && holder.snapshot().contacts.some((c) => c.online),
    "link",
  );
  const sent = await owner.storePlainFile({
    name: "quiet.bin",
    bytes: new TextEncoder().encode("grace-period"),
  });
  const placed = await until(
    () => owner.snapshot().files.find((file) => file.id === sent.id && file.copies >= 1),
    "placed",
  );
  await owner.auditNow();
  if (owner.snapshot().log.some((line) => line.text.includes("льготного"))) {
    throw new Error("живое соединение попало под льготу");
  }
  if (placed.copies < 1 && !owner.snapshot().files.find((file) => file.id === sent.id && file.copies >= 1)) {
    throw new Error("проверка сняла копию до тишины");
  }
  await holder.stop();
  await until(() => owner.snapshot().contacts.every((contact) => !contact.online), "offline", 30);
  await owner.auditNow();
  const still = owner.snapshot().files.find((file) => file.id === sent.id);
  if (!still || still.copies < 1) throw new Error("копия снята внутри льготного срока");
  if (owner.snapshot().log.some((line) => line.text.includes("льготного"))) {
    throw new Error("льгота сработала сразу после обрыва");
  }
  await wait(graceMs);
  await owner.auditNow();
  const after = owner.snapshot().files.find((file) => file.id === sent.id);
  if (!after || after.copies !== 0) throw new Error(`после льготы copies=${after?.copies}`);
  if (!owner.snapshot().log.some((line) => line.text.includes("льготного срока"))) {
    throw new Error("нет записи о льготном снятии");
  }
  console.log("GRACE OK");
} finally {
  await holder.stop().catch(() => {});
  await owner.stop();
  await rm(holderDir, { recursive: true, force: true });
  await rm(ownerDir, { recursive: true, force: true });
}
