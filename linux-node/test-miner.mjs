import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createNode } from "./lib/node.mjs";

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function until(fn, label, tries = 80) {
  for (let i = 0; i < tries; i++) {
    const value = fn();
    if (value) return value;
    await wait(100);
  }
  throw new Error(`timeout: ${label}`);
}

const minerDir = await mkdtemp(path.join(os.tmpdir(), "nxx-miner-"));
const userDir = await mkdtemp(path.join(os.tmpdir(), "nxx-user-"));
const miner = await createNode({
  data: minerDir,
  port: 18961,
  http: 18962,
  host: "127.0.0.1",
  advertise: "127.0.0.1",
  name: "miner",
  miner: true,
});
const user = await createNode({
  data: userDir,
  port: 18971,
  http: 18972,
  host: "127.0.0.1",
  advertise: "127.0.0.1",
  name: "user",
});

try {
  await user.addContact(miner.contact);
  await until(() => user.snapshot().contacts.some((c) => c.online && c.miner && c.supply > 0), "miner ad");
  const own = await miner.storePlainFile({ name: "rent.bin", bytes: new TextEncoder().encode("not-free") });
  await wait(400);
  const stayed = miner.snapshot().files.find((file) => file.id === own.id);
  if (!stayed || stayed.copies !== 0) throw new Error(`майнер отдал свой файл в сеть: ${stayed?.copies}`);
  const shared = await user.storePlainFile({ name: "keep.bin", bytes: new TextEncoder().encode("user-file") });
  await until(() => user.snapshot().files.find((file) => file.id === shared.id && file.copies >= 1), "user replica");
  console.log("MINER OK");
} finally {
  await miner.stop();
  await user.stop();
  await rm(minerDir, { recursive: true, force: true });
  await rm(userDir, { recursive: true, force: true });
}
