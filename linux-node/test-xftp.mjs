import { mkdtemp, rm } from "node:fs/promises";
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

const aDir = await mkdtemp(path.join(os.tmpdir(), "nxx-xftp-a-"));
const bDir = await mkdtemp(path.join(os.tmpdir(), "nxx-xftp-b-"));
const a = await createNode({ data: aDir, port: 18941, http: 18942, host: "127.0.0.1", advertise: "127.0.0.1", name: "xa" });
const b = await createNode({ data: bDir, port: 18951, http: 18952, host: "127.0.0.1", advertise: "127.0.0.1", name: "xb" });

try {
  await a.addContact(b.contact);
  await until(() => a.snapshot().contacts.some((c) => c.online) && b.snapshot().contacts.some((c) => c.online), "link");
  const payload = new TextEncoder().encode("xftp-without-addresses");
  const desc = await a.xftpSend(b.identity.fingerprint, "pack.bin", payload);
  if (desc.host || desc.port) throw new Error("в описании есть адрес");
  if (!desc.cids?.length || !desc.sig) throw new Error("описание без чанков или подписи");
  const got = await until(() => b.snapshot().files.find((file) => file.name === "pack.bin"), "assembled");
  const loaded = await b.loadPlainFile(got.id);
  if (new TextDecoder().decode(loaded.bytes) !== "xftp-without-addresses") throw new Error("собран не тот файл");
  console.log("XFTP OK");
} finally {
  await a.stop();
  await b.stop();
  await rm(aDir, { recursive: true, force: true });
  await rm(bDir, { recursive: true, force: true });
}
